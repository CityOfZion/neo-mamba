import asynctest
import asyncio
from neo3.network import convenience, node
from neo3 import network_logger, blockchain
from neo3.core import msgrouter
from datetime import datetime


class SyncManagerUtilitiesTestCase(asynctest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.syncmgr = convenience.SyncManager()

    def setUp(self) -> None:
        self.syncmgr._reset_for_test()

    def test_get_best_stored_block_height_with_empty_cache(self):
        # should take the ledger height as highest value
        with asynctest.patch.object(self.syncmgr, 'ledger') as ledger_mock:
            ledger_mock.height = 1
            best_height = self.syncmgr._get_best_stored_block_height()
            self.assertEqual(1, best_height)

    def test_get_best_stored_block_height_with_items_in_cache(self):
        # should take the cache height as highest value
        block2 = asynctest.MagicMock()
        block2.index = 2
        block3 = asynctest.MagicMock()
        block3.index = 3

        # intentionally putting blocks out of order, so also validate sorting
        self.syncmgr.block_cache = [block3, block2]
        with asynctest.patch.object(self.syncmgr, 'ledger') as ledger_mock:
            ledger_mock.height = 1
            best_height = self.syncmgr._get_best_stored_block_height()
            self.assertEqual(3, best_height)

    def test_add_block_flight_info(self):
        # first test creation of a new item
        self.syncmgr.block_requests = {}
        target_height = 1
        self.syncmgr._add_block_flight_info(nodeid=123, height=target_height)
        self.assertIn(target_height, self.syncmgr.block_requests)
        self.assertIsInstance(self.syncmgr.block_requests[target_height], convenience.RequestInfo)
        flights = self.syncmgr.block_requests[target_height].flights
        self.assertEqual(1, len(flights))

        # now test updating with a new flight
        self.syncmgr._add_block_flight_info(nodeid=456, height=target_height)
        flights = self.syncmgr.block_requests[target_height].flights
        self.assertEqual(2, len(flights))

    def test_is_in_blockcache(self):
        block = asynctest.MagicMock()
        block.index = 2
        self.syncmgr.block_cache = [block]

        found = self.syncmgr._is_in_blockcache(block_height=3)
        self.assertFalse(found)
        found = self.syncmgr._is_in_blockcache(block_height=2)
        self.assertTrue(found)


class SyncManagerSyncBlocksTestCase(asynctest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.syncmgr = convenience.SyncManager()
        cls.nodemgr = convenience.NodeManager()

    def setUp(self) -> None:
        self.syncmgr._reset_for_test()
        self.nodemgr._reset_for_test()
        node.NeoNode._reset_for_test()

    async def test_sync_blocks_outstanding_requests(self):
        self.syncmgr.block_requests.update({'1': object()})
        self.assertEqual(-1, await self.syncmgr._sync_blocks())

    async def test_sync_blocks_cache_full(self):
        self.syncmgr.block_cache = self.syncmgr.BLOCK_MAX_CACHE_SIZE * [None]
        self.assertEqual(-2, await self.syncmgr._sync_blocks())

    async def test_sync_blocks_no_nodes(self):
        self.assertEqual(-3, await self.syncmgr._sync_blocks())

    # async def test_sync_blocks_no_nodes_with_required_height(self):
    #     mock_node = asynctest.MagicMock()
    #     mock_node.best_height = 1
    #     self.nodemgr.nodes = [mock_node]
    #     with asynctest.patch.object(self.nodemgr, 'get_node_with_height', return_value=None):
    #         self.assertEqual(-4, await self.syncmgr._sync_blocks())

    async def test_sync_blocks_get_1_block(self):
        # scenario
        # - cache has 2 spot available
        # - the connected nodes best_height can only fill 1 of the spots
        # expected result: 1 flight added

        self.syncmgr.block_cache = (self.syncmgr.BLOCK_MAX_CACHE_SIZE - 2) * [None]
        mock_node = node.NeoNode(protocol=object())
        mock_node.best_height = 2
        mock_node.request_block_data = asynctest.CoroutineMock()
        self.nodemgr.nodes = [mock_node]

        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            with asynctest.patch.object(self.syncmgr, '_get_best_stored_block_height', return_value=1):
                with asynctest.patch.object(self.syncmgr, '_add_block_flight_info') as mocked_add_flight_info:
                    await self.syncmgr._sync_blocks()
        mocked_add_flight_info.assert_called_once()
        self.assertIn("Asking for blocks 2 - 2", log_context.output[0])


class SyncManagerCheckTimeoutTestCase(asynctest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.syncmgr = convenience.SyncManager()
        cls.nodemgr = convenience.NodeManager()

    def setUp(self) -> None:
        self.syncmgr._reset_for_test()
        self.nodemgr._reset_for_test()
        node.NeoNode._reset_for_test()

    async def test_no_outstanding_request(self):
        self.assertEqual(-1, await self.syncmgr._check_timeout())

    async def test_no_flights_timedout(self):
        target_height = 1
        request_info = convenience.RequestInfo(target_height)
        request_info.add_new_flight(convenience.FlightInfo(node_id=123, height=target_height))
        self.syncmgr.block_requests[1] = request_info

        # a recently recreated flight should not have timed out
        self.assertEqual(-2, await self.syncmgr._check_timeout())

    async def test_flights_timed_out(self):
        # scenario: have 2 outstanding flights that timed out
        # - 1 flight for a request that is still is not completed
        # - 1 flight has been made obsolete by a secondary for the same request_info and is still in cache waiting to be processed

        # construct flight 1 - request not yet satisfied
        target_height = 2
        node1_id = 123
        request_info = convenience.RequestInfo(target_height)
        request_info.mark_failed_node = asynctest.MagicMock()
        flight_info = convenience.FlightInfo(node_id=node1_id, height=target_height)
        # reduce start time to enforce exceeding timeout treshold
        flight_info.start_time -= self.syncmgr.BLOCK_REQUEST_TIMEOUT + 1
        request_info.add_new_flight(flight_info)
        self.syncmgr.block_requests[target_height] = request_info

        # construct flight 2 - request already satisfied
        target_height2 = 1
        node2_id = 456
        request_info2 = convenience.RequestInfo(target_height2)
        flight_info2 = convenience.FlightInfo(node_id=node2_id, height=target_height2)
        flight_info2.start_time -= self.syncmgr.BLOCK_REQUEST_TIMEOUT + 1
        request_info2.add_new_flight(flight_info2)
        self.syncmgr.block_requests[target_height2] = request_info2

        # we patch '_get_best_stored_block_height' to return `target_height2` as a way of saying;
        # either the chain or cache already has the data for this height
        with asynctest.patch.object(self.syncmgr, '_get_best_stored_block_height', return_value=target_height2):
            with asynctest.patch.object(self.nodemgr, 'increase_node_timeout_count') as nodemgr_increase_timeout_count:
                result = await self.syncmgr._check_timeout()

        request_info.mark_failed_node.assert_called_with(node1_id)
        # both nodes had a flight that timed out
        nodemgr_increase_timeout_count.assert_has_calls([asynctest.mock.call(node1_id),
                                                         asynctest.mock.call(node2_id)],
                                                        any_order=True)
        # the first time we call it we no longer have any connected nodes, so we can't request from anyone anymore
        self.assertEqual(-3, result)

        # now we "connect" a new node
        mock_node = node.NeoNode(protocol=object())
        mock_node.best_height = 10
        mock_node_id = 789
        mock_node.nodeid = mock_node_id
        mock_node.request_block_data = asynctest.CoroutineMock()
        self.nodemgr.nodes = [mock_node]
        # and try again
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            with asynctest.patch.object(self.syncmgr, '_get_best_stored_block_height', return_value=target_height2):
                with asynctest.patch.object(self.nodemgr, 'increase_node_timeout_count'):
                    await self.syncmgr._check_timeout()

        # and validate that a new data request is sent
        self.assertIn("Block timeout for blocks 2 - 2", log_context.output[0])
        mock_node.request_block_data.assert_awaited_once_with(count=1, index_start=2)
        # and also a new flight was added for the new node
        flight = request_info.most_recent_flight()
        self.assertEqual(mock_node_id, flight.node_id)

        # just for coverage
        flight.reset_start_time()
        self.assertTrue(datetime.utcnow().timestamp() - flight.start_time < 0.1)


class SyncManagerVarious(asynctest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.syncmgr = convenience.SyncManager()
        cls.nodemgr = convenience.NodeManager()

    def setUp(self) -> None:
        self.syncmgr._reset_for_test()
        self.nodemgr._reset_for_test()

    async def test_start_timedout(self):
        with self.assertRaises(Exception) as context:
            with self.assertLogs(network_logger, 'DEBUG') as log_context:
                await self.syncmgr.start(timeout=0.2)
        self.assertIn("Waiting for nodemanager to start", log_context.output[0])
        self.assertIn("Nodemanager failed to start within specified timeout 0.2", str(context.exception))

    async def test_start_shutdown(self):
        self.nodemgr.is_running = True
        # adding an item in the block cache to test that it also runs the `persist_blocks` coroutine
        self.syncmgr.block_cache = [object()]
        with asynctest.patch.object(self.syncmgr, 'persist_blocks', return_value=asynctest.CoroutineMock()):
            with self.assertLogs(network_logger, 'DEBUG') as log_context:
                await self.syncmgr.start(timeout=2)

                self.assertIn("Starting services", log_context.output[1])
                self.assertIsNotNone(self.syncmgr._service_task)

                await asyncio.sleep(0.1)

                self.syncmgr.persist_blocks.assert_awaited_once()

                await self.syncmgr.shutdown()

                for t in self.syncmgr._tasks:
                    self.assertTrue(t.done())

    def test_on_block_received(self):
        # first test receiving a block we have no outstanding request for
        fake_block = asynctest.MagicMock()
        fake_block.index = 1
        fake_block.__len__.return_value = 50
        self.assertEqual(-1, self.syncmgr.on_block_received(from_nodeid=123, block=fake_block))

        # next test receiving a block that we DO have an outstanding request for, but not from the node that is now
        # delivering the block
        request_info = convenience.RequestInfo(height=1)
        request_info.add_new_flight(convenience.FlightInfo(node_id=456, height=1))
        self.syncmgr.block_requests[1] = request_info
        self.assertEqual(-2, self.syncmgr.on_block_received(from_nodeid=123, block=fake_block))
        self.assertEqual(request_info, self.syncmgr.block_requests.get(1, None))

        # next test a valid scenario (outstanding request and receiving a block from the right node)
        mocked_node = node.NeoNode(object())
        mocked_node.nodeweight.append_new_speed = asynctest.MagicMock()
        mocked_node.nodeid = 456
        self.nodemgr.nodes = [mocked_node]
        self.syncmgr.on_block_received(from_nodeid=456, block=fake_block)
        mocked_node.nodeweight.append_new_speed.assert_called_once()
        self.assertIn(fake_block, self.syncmgr.block_cache)
        self.assertEqual(1, len(self.syncmgr.block_cache))

        # and finally try again for the same block and ensure it was not added again to the cache
        self.syncmgr.on_block_received(from_nodeid=456, block=fake_block)
        self.assertEqual(1, len(self.syncmgr.block_cache))

    async def test_persist_blocks(self):

        fake_block1 = asynctest.MagicMock()
        fake_block1.index = 1
        fake_block2 = asynctest.MagicMock()
        fake_block2.index = 2

        # inserting out of order on purpose to also validate sorting
        self.syncmgr.block_cache = [fake_block2, fake_block1]

        mocked_result = asynctest.Mock()
        with asynctest.patch.object(self.syncmgr.ledger, 'persist', side_effect=mocked_result):
            await self.syncmgr.persist_blocks()

        # test that we persisted the blocks in order
        mocked_result.assert_has_calls([asynctest.mock.call(fake_block1),
                                        asynctest.mock.call(fake_block2)],
                                       any_order=False)

        # now test with an exception happening during persist
        self.syncmgr.block_cache = [fake_block2, fake_block1]
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            with asynctest.patch.object(self.syncmgr.ledger, 'persist', side_effect=Exception):
                await self.syncmgr.persist_blocks()
        self.assertIn("Unexpected exception happened while processing the block cache", log_context.output[0])
        self.assertFalse(self.syncmgr._is_persisting_blocks)

        # test that we don't persist if we're starting to shutdown
        self.syncmgr.shutting_down = True
        mocked_result = asynctest.Mock()
        with asynctest.patch.object(self.syncmgr.ledger, 'persist', side_effect=mocked_result):
            await self.syncmgr.persist_blocks()
        mocked_result.assert_not_called()


class SyncManagerTimedTestCase(asynctest.ClockedTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.syncmgr = convenience.SyncManager()

    def setUp(self) -> None:
        self.syncmgr._reset_for_test()

    async def test_utility_run_in_loop(self):
        counter = 0

        async def coro():
            nonlocal counter
            counter += 1

        self.syncmgr._run_in_loop(coro, 1)
        # trigger the task by ticking the loop once
        await self.advance(0)
        self.assertEqual(1, counter)
        await self.advance(0.9)
        self.assertEqual(1, counter)
        await self.advance(0.1)
        self.assertEqual(2, counter)
        self.syncmgr._tasks[0].cancel()
