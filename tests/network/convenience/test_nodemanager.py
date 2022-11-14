import aiodns
import logging
import socket
import asyncio
from unittest import mock, IsolatedAsyncioTestCase, TestCase, skip
from neo3.network import node, message, capabilities
from neo3.network.convenience import nodemanager, requestinfo
from neo3.network.payloads import address, version, ping
from neo3 import network_logger
from neo3.settings import settings
from datetime import datetime
from copy import deepcopy
from neo3.core import msgrouter


class NodeManagerTestCase(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.nodemgr = nodemanager.NodeManager()

    def setUp(self) -> None:
        self.nodemgr._reset_for_test()
        node.NeoNode._reset_for_test()
        settings.reset_settings_to_default()

        self.node1 = node.NeoNode(object(), object())
        self.node2 = node.NeoNode(object(), object())

        self.addr1 = address.NetworkAddress(address="127.0.0.1:10333")
        self.addr2 = address.NetworkAddress(address="127.0.0.2:20333")
        self.node1.address = self.addr1
        self.node2.address = self.addr2

    def test_get_node_addresses(self):
        self.nodemgr.nodes = [self.node1, self.node2]
        addr_list = self.nodemgr.get_node_addresses()
        self.assertEqual([self.addr1, self.addr2], addr_list)

    def test_get_node_by_id(self):
        self.nodemgr.nodes = [self.node1, self.node2]
        n = self.nodemgr.get_node_by_nodeid(self.node1.nodeid)
        self.assertEqual(self.node1, n)

        random_id = 999
        n = self.nodemgr.get_node_by_nodeid(random_id)
        self.assertEqual(None, n)

    def test_get_node_with_height1(self):
        # no connected nodes = early exit
        self.assertEqual(None, self.nodemgr.get_node_with_height(height=1))

    def test_get_node_with_height2(self):
        # can select from 2 , should get the one with the highest weight
        self.node1.best_height = 10
        # increasing error count lowers weight
        self.node1.nodeweight.error_response_count = 5

        self.node2.best_height = 10

        # setup node manager
        self.nodemgr.nodes = [self.node1, self.node2]
        self.assertEqual(self.node2, self.nodemgr.get_node_with_height(height=1))

    def test_get_node_with_height3(self):
        # should return None if none of the nodes have the requested height
        self.node1.best_height = 0
        self.node2.best_height = 0
        # setup node manager
        self.nodemgr.nodes = [self.node1, self.node2]
        self.assertEqual(None, self.nodemgr.get_node_with_height(height=10))

    def test_get_least_failed_node1(self):
        # should return None if none of the nodes have the requested height
        self.node1.best_height = 0
        self.node2.best_height = 0
        # setup node manager
        self.nodemgr.nodes = [self.node1, self.node2]
        ri = requestinfo.RequestInfo(height=10)
        self.assertEqual(None, self.nodemgr.get_least_failed_node(ri))

    def test_get_least_failed_node2(self):
        # should return the node with the lowest fail count for the request
        # for this test we setup that node1 has failed before, whereas node2 hasn't
        self.node1.best_height = 10
        self.node2.best_height = 10

        ri = requestinfo.RequestInfo(height=1)
        # pretend node 1 has already failed once for this request
        ri.failed_nodes[self.node1.nodeid] = 1

        # setup node manager
        self.nodemgr.nodes = [self.node1, self.node2]
        self.assertEqual(self.node2, self.nodemgr.get_least_failed_node(ri))

    def test_get_least_failed_node3(self):
        # should not return a node that is in the process of disconnecting but does have the correct height
        self.node1.best_height = 10
        self.node1.disconnecting = True
        self.nodemgr.nodes = [self.node1, self.node2]
        ri = requestinfo.RequestInfo(height=10)
        self.assertEqual(None, self.nodemgr.get_least_failed_node(ri))

    def test_increase_node_error_count(self):
        self.nodemgr.nodes = [self.node1, self.node2]

        # we expect self.assertLogs to raise an AssertionError because there will be no DEBUG output logs
        # we call self.assertLogs because we want to test for no DBEUG logs being produced
        with self.assertRaises(AssertionError) as assert_log_context:
            with self.assertLogs(network_logger, "DEBUG") as context:
                self.nodemgr.increase_node_error_count(self.node1.nodeid)
        self.assertEqual(1, self.node1.nodeweight.error_response_count)
        self.assertEqual(0, len(context.output))

    def test_increase_node_error_count2(self):
        self.nodemgr.nodes = [self.node1, self.node2]
        # set a current value that certainly will exceed whatever the user configuration will say
        self.node1.nodeweight.error_response_count += 999

        with self.assertLogs(network_logger, "DEBUG") as context:
            with mock.patch.object(
                self.node1,
                "disconnect",
                new_callable=mock.MagicMock,  # forcing this to non-async version to prevent runtime warning
            ):
                with mock.patch("asyncio.create_task") as mocked_create_task:
                    self.nodemgr.increase_node_error_count(self.node1.nodeid)
        self.assertEqual(1000, self.node1.nodeweight.error_response_count)
        self.assertIn("max error count threshold exceeded", context.output[0])

    def test_increase_node_timeout_count(self):
        self.nodemgr.nodes = [self.node1, self.node2]

        self.nodemgr.increase_node_timeout_count(self.node1.nodeid)
        self.assertEqual(1, self.node1.nodeweight.timeout_count)

    def test_increase_node_timeout_count2(self):
        # test we detect max count threshold exceeding and schedule a disconnect task
        self.nodemgr.nodes = [self.node1, self.node2]
        # set a current value that certainly will exceed whatever the user configuration will say
        self.node1.nodeweight.timeout_count += 999

        with self.assertLogs(network_logger, "DEBUG") as context:
            with mock.patch.object(
                self.node1,
                "disconnect",
                new_callable=mock.MagicMock,  # forcing this to non-async version to prevent runtime warning):
            ):
                with mock.patch("asyncio.create_task"):
                    self.nodemgr.increase_node_timeout_count(self.node1.nodeid)
        self.assertEqual(1000, self.node1.nodeweight.timeout_count)
        self.assertIn("max timeout count threshold exceeded", context.output[0])


caps = [capabilities.FullNodeCapability(0)]
m_version = message.Message(
    msg_type=message.MessageType.VERSION,
    payload=version.VersionPayload(
        nonce=123, user_agent="NEO3-MOCK-CLIENT", capabilities=caps
    ),
)
m_verack = message.Message(msg_type=message.MessageType.VERACK)

m_ping = message.Message(
    msg_type=message.MessageType.PING, payload=ping.PingPayload(height=0)
).to_array()


async def fake_create_task(coro):
    await coro


class NodeManagerTestCase2(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # stdio_handler = logging.StreamHandler()
        # stdio_handler.setLevel(logging.DEBUG)
        # stdio_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s - %(module)s:%(lineno)s %(message)s"))
        async_logger = logging.getLogger("asyncio")
        # async_logger.addHandler(stdio_handler)
        async_logger.setLevel(logging.DEBUG)

        network_logger = logging.getLogger("neo3.network")
        # network_logger.addHandler(stdio_handler)
        network_logger.setLevel(logging.DEBUG)

        cls.nodemgr = nodemanager.NodeManager()

    def setUp(self) -> None:
        self.nodemgr._reset_for_test()
        node.NeoNode._reset_for_test()
        settings.reset_settings_to_default()

    async def test_start_shutdown(self):
        settings.register({"network": {"seedlist": ["127.0.0.1:1111"], "magic": 769}})

        self.nodemgr.start()
        # need to keep this outside or it will go out of scope and close the socket
        r, w = socket.socketpair()

        def client_provider():
            loop = asyncio.get_running_loop()
            v = deepcopy(m_version)
            v.payload.magic = 769
            loop.call_soon(w.send, v.to_array())
            loop.call_soon(w.send, m_verack.to_array())
            yield r, w

        # configure nodemanager to use a mock client
        self.nodemgr._test_client_provider = client_provider
        self.nodemgr._test_data = {"peername": ("127.0.0.1", 1111)}

        call_back_result = None

        def client_connect_done(node_instance, failure):
            nonlocal call_back_result
            call_back_result = node_instance

        # listen to a connection done event
        msgrouter.on_client_connect_done += client_connect_done

        # initial state
        self.assertFalse(self.nodemgr.is_running)
        # advance loop
        await asyncio.sleep(0.1)
        self.assertTrue(self.nodemgr.is_running)
        # 4 looping service tasks
        self.assertEqual(4, len(self.nodemgr.tasks))
        self.assertIsInstance(call_back_result, node.NeoNode)
        await self.nodemgr.shutdown()
        for t in self.nodemgr.tasks:
            self.assertTrue(t.done())
        r.close()
        w.close()

    async def test_fill_open_connection_spots_no_clients(self):
        # create 1 open spot
        self.nodemgr.max_clients = 1
        # ensure we have an address that can be connected to
        node.NeoNode.addresses = [address.NetworkAddress(address="127.0.0.1:1111")]

        with self.assertLogs(network_logger, "DEBUG") as context:
            await self.nodemgr._fill_open_connection_spots()
        self.assertIn("Found 1 open pool spots", context.output[0])
        self.assertIn("Adding 127.0.0.1:1111 to connection queue", context.output[1])

    async def test_fill_open_connection_spots_dont_queue_addr_that_is_already_queued(
        self,
    ):
        self.node1 = node.NeoNode(object(), object())

        # ensure we have an address that can be connected to
        addr = address.NetworkAddress(address="127.0.0.1:1111")
        # create 1 open spot
        self.nodemgr.max_clients = 2
        node.NeoNode.addresses = [addr]
        # and ensure we pretend we have already queued this address
        self.nodemgr.queued_addresses = [addr]

        with self.assertLogs(network_logger, "DEBUG") as context:
            with mock.patch("asyncio.create_task"):
                await self.nodemgr._fill_open_connection_spots()
        self.assertIn("Found 1 open pool spots", context.output[0])
        # context.output length should only contain the above debug message, nothing more
        self.assertEqual(1, len(context.output))

    async def test_fill_open_connection_spots_no_addresses_to_fill_spots(self):
        # we first test that no errors occur if we have open spots, but we still meet our minimum required clients
        # this should not cause any error count increases
        self.nodemgr.min_clients = 1
        self.nodemgr.max_clients = 2
        # just a placeholder to have a count matching min_clients
        self.nodemgr.nodes = [object()]
        node.NeoNode.addresses = []

        with self.assertLogs(network_logger, "DEBUG") as context:
            await self.nodemgr._fill_open_connection_spots()
        self.assertIn(
            "Found 1 open pool spots, trying to add nodes...", context.output[0]
        )
        self.assertIn(
            "No addresses available to fill spots. However, minimum clients still satisfied",
            context.output[1],
        )

        # next we clear the nodes and start inducing errors for not being able to fill the open spots
        self.nodemgr.nodes = []
        with self.assertLogs(network_logger, "DEBUG") as context:
            await self.nodemgr._fill_open_connection_spots()
        self.assertIn(
            "Found 2 open pool spots, trying to add nodes...", context.output[0]
        )
        self.assertIn("Increasing pool spot error count to 1", context.output[1])

        with self.assertLogs(network_logger, "DEBUG") as context:
            await self.nodemgr._fill_open_connection_spots()
        self.assertIn(
            "Found 2 open pool spots, trying to add nodes...", context.output[0]
        )
        self.assertIn("Increasing pool spot error count to 2", context.output[1])

        # 3rd time we reached our threshold
        # let's also set up an address in POOR state that should be reset to NEW
        addr = address.NetworkAddress(address="127.0.0.1:1111")
        addr.set_state_poor()
        node.NeoNode.addresses = [addr]
        with self.assertLogs(network_logger, "DEBUG") as context:
            await self.nodemgr._fill_open_connection_spots()
        self.assertIn(
            "Found 2 open pool spots, trying to add nodes...", context.output[0]
        )
        self.assertIn("Recycling old addresses", context.output[1])
        self.assertEqual(0, self.nodemgr.MAX_NODE_POOL_ERROR_COUNT)
        self.assertTrue(node.NeoNode.addresses[0].is_state_new)

    async def test_fill_open_connection_spots_node_timeout_error(self):
        self.nodemgr.min_clients = 1
        self.nodemgr.max_clients = 2

        addr = address.NetworkAddress(address="127.0.0.1:1111")
        node.NeoNode.addresses = [addr]

        call_back_result = None

        def client_connect_done(node_instance, failure):
            nonlocal call_back_result
            call_back_result = failure

        # listen to a connection done event
        msgrouter.on_client_connect_done += client_connect_done

        with self.assertLogs(network_logger, "DEBUG") as context:
            # for some reason patching asyncio.open_connection just doesn't work in this test
            # working around it like this
            with mock.patch.object(
                node.NeoNode, "connect_to", return_value=(None, (f"...", "Timed out"))
            ):
                await self.nodemgr._fill_open_connection_spots()

        # advance loop
        await asyncio.sleep(0.1)
        self.assertEqual("Timed out", call_back_result[1])
        self.assertIn(
            "Found 2 open pool spots, trying to add nodes...", context.output[0]
        )


class NodeManagerTimedTestCase(IsolatedAsyncioTestCase):  # asynctest.ClockedTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.nodemgr = nodemanager.NodeManager()

    def setUp(self) -> None:
        self.nodemgr._reset_for_test()
        node.NeoNode._reset_for_test()
        settings.reset_settings_to_default()

        fake_reader, fake_writer = object(), object()
        self.node1 = node.NeoNode(fake_reader, fake_writer)
        self.node2 = node.NeoNode(fake_reader, fake_writer)

        self.addr1 = address.NetworkAddress(address="127.0.0.1:10333")
        self.addr2 = address.NetworkAddress(address="127.0.0.2:20333")
        self.node1.address = self.addr1
        self.node2.address = self.addr2

    @skip("Only worked with asynctest.ClockedTestCase, no replacement yet")
    async def test_utility_run_in_loop(self):
        counter = 0

        async def coro():
            nonlocal counter
            counter += 1

        self.nodemgr._run_in_loop(coro, 1)
        # trigger the task by ticking the loop once
        await self.advance(0)
        self.assertEqual(1, counter)
        await self.advance(0.9)
        self.assertEqual(1, counter)
        await self.advance(0.1)
        self.assertEqual(2, counter)
        self.nodemgr.tasks[0].cancel()

    async def test_monitor_node_height_disconnect_when_treshold_exceeded(self):
        # ensure we exceed the threshold
        self.node1.best_height_last_update = (
            datetime.utcnow().timestamp() - self.nodemgr.MAX_HEIGHT_UPDATE_DURATION - 1
        )
        self.nodemgr.nodes = [self.node1]
        with self.assertLogs(network_logger, "DEBUG") as context:
            with mock.patch.object(self.node1, "disconnect") as patched_node_disconnect:
                await self.nodemgr._monitor_node_height()
        self.assertIn("max height update threshold exceeded", context.output[0])
        patched_node_disconnect.assert_called_with(
            reason=address.DisconnectReason.POOR_PERFORMANCE
        )

    @skip("too slow, need pytest + looptime to enable")
    async def test_monitor_node_height_within_limits(self):
        # Note https://github.com/nolar/looptime/tree/main/looptime could solve this
        # if we were using pytest instead of unittest

        # test that if the last height update timestamp of a node is within the treshold
        # that we only ask for another update
        self.nodemgr.nodes = [self.node1]
        with self.assertLogs(network_logger, "DEBUG") as context:
            with mock.patch.object(
                self.node1, "send_message", side_effect=mock.AsyncMock()
            ) as patched_node_send_msg:
                await self.nodemgr._monitor_node_height()
        self.assertIn(" to send us a height update (PING)", context.output[0])
        self.assertGreater(len(patched_node_send_msg.call_args), 0)
        msg = patched_node_send_msg.call_args[0][0]
        self.assertEqual(message.MessageType.PING, msg.type)
        # finally test that our tasks is created
        self.assertEqual(1, len(self.nodemgr.tasks))
        await asyncio.sleep(1)
        # and the call back called once done.
        self.assertEqual(0, len(self.nodemgr.tasks))

    @skip("too slow, need pytest + looptime to enable")
    async def test_query_addresses(self):
        self.nodemgr.nodes = [self.node1]
        with self.assertLogs(network_logger, "DEBUG") as context:
            with mock.patch.object(
                self.node1, "request_address_list", side_effect=mock.AsyncMock()
            ) as patched_node_req_addr:
                await self.nodemgr._query_addresses()
        self.assertIn("Asking node ", context.output[1])
        self.assertIn("for its address list", context.output[1])
        patched_node_req_addr.assert_called_once()
        # finally test that our tasks is created
        self.assertEqual(1, len(self.nodemgr.tasks))
        await asyncio.sleep(1)
        # and the call back called once done.
        self.assertEqual(0, len(self.nodemgr.tasks))

    async def test_seed_list_processing(self):
        # specific testing of named addresses
        settings.network.seedlist = ["google.com:1111"]

        # for whatever reason I can't find the right way to mock the property, tried PropertyMock and what not.
        # this works *shrug*
        class wtf:
            host = "127.0.0.123"

        result = [wtf()]
        with mock.patch(
            "aiodns.DNSResolver.query",
            side_effect=mock.AsyncMock(return_value=result),
        ) as query_result:
            await self.nodemgr._process_seed_list_addresses()
        self.assertEqual(1, len(node.NeoNode.addresses))

        with self.assertLogs(network_logger, "DEBUG") as context:
            with mock.patch(
                "aiodns.DNSResolver.query", side_effect=aiodns.error.DNSError
            ) as query_result:
                await self.nodemgr._process_seed_list_addresses()
        self.assertIn(
            "Skipping google.com, address could not be resolved", context.output[0]
        )
