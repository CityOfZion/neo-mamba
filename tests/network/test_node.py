import socket
import logging
import asyncio
from neo3.network import node, message, capabilities, ipfilter
from neo3.network.payloads import (
    version,
    address,
    block,
    empty,
    inventory,
    ping,
    transaction,
)
from copy import deepcopy
from neo3 import network_logger
from neo3.settings import settings
from neo3.core import types
from unittest import mock, IsolatedAsyncioTestCase
from tests import helpers as test_helpers


class NeoNodeTestCase(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # network_logger = logging.getLogger("neo3.network")
        # network_logger.setLevel(logging.DEBUG)
        # stdio_handler = logging.StreamHandler()
        # network_logger.addHandler(stdio_handler)

        caps = [
            capabilities.FullNodeCapability(0),
            capabilities.ServerCapability(
                n_type=capabilities.NodeCapabilityType.TCPSERVER, port=10333
            ),
        ]

        cls.m_version = message.Message(
            msg_type=message.MessageType.VERSION,
            payload=version.VersionPayload(1, "NEO3-MOCK-CLIENT", caps),
        )
        cls.m_verack = message.Message(msg_type=message.MessageType.VERACK)

        host = "127.0.0.1"
        port = 1111
        cls.peername_data = {"peername": (host, port)}

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()
        network_logger = logging.getLogger("neo3.network")
        network_logger.handlers.clear()

    def setUp(self) -> None:
        settings.reset_settings_to_default()
        node.NeoNode._reset_for_test()
        ipfilter.ipfilter.reset()

    async def test_connect_to(self):
        with self.assertRaises(ValueError) as context:
            await node.NeoNode.connect_to()
        self.assertIn(
            "host and port was not specified and no sock specified",
            str(context.exception),
        )

        with self.assertRaises(ValueError) as context:
            await node.NeoNode.connect_to(host="123", socket=object())
        self.assertIn(
            "host/port and socket can not be specified at the same time",
            str(context.exception),
        )

    async def test_connect_to_with_socket(self):
        r, w = socket.socketpair()
        loop = asyncio.get_running_loop()

        host = "127.0.0.1"
        port = 1111
        test_data = {"peername": (host, port)}

        with self.assertLogs(network_logger, "DEBUG") as log_context:
            # hand-shake data
            loop.call_soon(w.send, self.m_version.to_array())
            loop.call_soon(w.send, self.m_verack.to_array())
            n, _ = await node.NeoNode.connect_to(socket=r, _test_data=test_data)
        r.close()
        w.close()
        self.assertIn("Trying to connect to socket", log_context.output[0])
        self.assertIn(
            f"Connected to NEO3-MOCK-CLIENT @ {host}:{port}: 0", log_context.output[2]
        )
        self.assertIsInstance(n, node.NeoNode)
        await n.disconnect(address.DisconnectReason.SHUTTING_DOWN)

    async def test_connect_to_with_host_ip(self):
        # just for basic coverage, we use the above socket mock for more indepth testing
        host = "127.0.0.1"
        port = 1111

        with self.assertLogs(network_logger, "DEBUG") as log_context:
            with mock.patch.object(asyncio, "open_connection"):
                _, _ = await node.NeoNode.connect_to(host, port)
        self.assertIn(f"Trying to connect to: {host}:{port}", log_context.output[0])

    async def test_connect_to_exceptions(self):
        with mock.patch.object(asyncio, "open_connection") as mocked_open_conn:
            mocked_open_conn.side_effect = asyncio.TimeoutError
            node_instance, failure = await node.NeoNode.connect_to(socket=object())
            self.assertIsNone(node_instance)
            self.assertEqual("Timed out", failure[1])

        with mock.patch.object(asyncio, "open_connection") as mocked_open_conn:
            mocked_open_conn.side_effect = OSError("unreachable")
            node_instance, failure = await node.NeoNode.connect_to(socket=object())
            self.assertIsNone(node_instance)
            self.assertEqual("Failed to connect for reason unreachable", failure[1])

        with mock.patch.object(asyncio, "open_connection") as mocked_open_conn:
            mocked_open_conn.side_effect = asyncio.CancelledError
            node_instance, failure = await node.NeoNode.connect_to(socket=object())
            self.assertIsNone(node_instance)
            self.assertEqual("Cancelled", failure[1])

    def test_helpers(self):
        addr1 = address.NetworkAddress(address="127.0.0.1:1111")
        addr1.set_state_dead()
        addr2 = address.NetworkAddress(address="127.0.0.1:2222")
        node.NeoNode.addresses = [addr1, addr2]
        result = node.NeoNode.get_address_new()
        self.assertEqual(addr2, result)

        n = node.NeoNode(object(), object())
        addr = n._find_address_by_host_port("127.0.0.1:1111")
        self.assertEqual(addr1, addr)
        addr = n._find_address_by_host_port("127.0.0.1:3333")
        self.assertEqual(None, addr)

    async def test_handshake_first_message_not_VERSION(self):
        r, w = socket.socketpair()
        loop = asyncio.get_running_loop()

        with self.assertLogs(network_logger, "DEBUG") as log_context:
            loop.call_soon(w.send, self.m_verack.to_array())
            await node.NeoNode.connect_to(socket=r, _test_data=self.peername_data)
        r.close()
        w.close()
        self.assertIn(
            "Disconnect called with reason=HANDSHAKE_VERSION_ERROR",
            log_context.output[1],
        )

    async def test_handshake_version_validation_failed(self):
        # mock the version validation call result. The version_validation function is tested down below
        settings.network.magic = 769
        r, w = socket.socketpair()
        loop = asyncio.get_running_loop()
        version = deepcopy(self.m_version)
        # ensure the network magic read from the stream is different
        version.payload.magic = 123
        with self.assertLogs(network_logger, "DEBUG") as log_context:
            loop.call_soon(w.send, version.to_array())
            await node.NeoNode.connect_to(socket=r, _test_data=self.peername_data)
        r.close()
        w.close()
        self.assertIn(
            "Disconnect called with reason=HANDSHAKE_VERSION_ERROR",
            log_context.output[2],
        )

    async def test_handshake_second_message_not_VERACK(self):
        # ensure we have the same magic
        settings.network.magic = self.m_version.payload.magic

        r, w = socket.socketpair()
        loop = asyncio.get_running_loop()

        with self.assertLogs(network_logger, "DEBUG") as log_context:
            loop.call_soon(w.send, self.m_version.to_array())
            loop.call_soon(w.send, self.m_version.to_array())
            await node.NeoNode.connect_to(socket=r, _test_data=self.peername_data)
        r.close()
        w.close()
        self.assertIn(
            "Disconnect called with reason=HANDSHAKE_VERACK_ERROR",
            log_context.output[2],
        )

    def _new_version(self):
        self.start_height = 888
        caps = [
            capabilities.FullNodeCapability(start_height=self.start_height),
            capabilities.ServerCapability(
                capabilities.NodeCapabilityType.TCPSERVER, 10333
            ),
        ]
        return version.VersionPayload(
            nonce=123, user_agent="NEO3-MOCK-CLIENT", capabilities=caps
        )

    def test_version_validation_client_is_self(self):
        n = node.NeoNode(object(), object())

        # test for client is self
        version = self._new_version()
        version.nonce = n.nodeid
        with self.assertLogs(network_logger, "DEBUG") as log_context:
            result = n._validate_version(version)
        self.assertFalse(result)
        self.assertIn("Client is self", log_context.output[0])

    def test_version_validation_wrong_network(self):
        n = node.NeoNode(object(), object())

        # test for wrong network
        settings.network.magic = 769
        version = self._new_version()
        version.magic = 111
        with self.assertLogs(network_logger, "DEBUG") as log_context:
            result = n._validate_version(version)
        self.assertFalse(result)
        self.assertIn("Wrong network id", log_context.output[0])

    def test_version_validation_should_updating_address_to_connected_state(self):
        n = node.NeoNode(object(), object())

        # test updating address state to CONNECTED
        # this is relevant for addresses that have been added through the nodemanager based on the seedlist
        # set the addresses ourselves to mimick the nodemanager startup behaviour
        node.NeoNode.addresses = [n.address]
        version = self._new_version()

        result = n._validate_version(version)
        # validate our address is now set to CONNECTED
        self.assertTrue(result)
        self.assertTrue(n.address.is_state_connected)
        self.assertEqual(self.start_height, n.best_height)

    def test_version_validation_should_add_new_address(self):
        # when using the `connect_to` method or when a server is hosted accepting incoming clients
        # we should add the address to our know addresses list
        n = node.NeoNode(object(), object())
        # normally this is updated by `connection_made()`, since we skip that in this test we set it manually
        n.address.address = "127.0.0.1:1111"
        self.assertEqual(0, len(node.NeoNode.addresses))

        version = self._new_version()
        with self.assertLogs(network_logger, "DEBUG") as log_context:
            n._validate_version(version)
        self.assertEqual(1, len(node.NeoNode.addresses))
        self.assertIn(
            "Adding address from outside 127.0.0.1:1111", log_context.output[0]
        )

    def test_version_validation_fail_if_no_full_node_capabilities(self):
        n = node.NeoNode(object(), object())

        version = self._new_version()
        # remove the full node capability
        version.capabilities.pop(0)
        result = n._validate_version(version)
        self.assertFalse(result)

    async def test_connect_blocked_by_ipfilter(self):
        ipfilter.ipfilter.blacklist_add("127.0.0.1")
        r, w = socket.socketpair()
        loop = asyncio.get_running_loop()
        with self.assertLogs(network_logger, "DEBUG") as log_context:
            loop.call_soon(w.send, self.m_version.to_array())
            loop.call_soon(w.send, self.m_verack.to_array())
            await node.NeoNode.connect_to(socket=r, _test_data=self.peername_data)
        r.close()
        w.close()
        self.assertIn("Blocked by ipfilter: 127.0.0.1:1111", log_context.output[1])

    async def test_req_addr_list(self):
        n = node.NeoNode(object(), object())
        n.send_message = mock.AsyncMock()
        await n.request_address_list()

        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETADDR, m.type)
        self.assertIsInstance(m.payload, empty.EmptyPayload)

    async def test_send_addr_list(self):
        n = node.NeoNode(object(), object())
        n.send_message = mock.AsyncMock()
        n.addresses = [address.NetworkAddress(address="127.0.0.1:1111")]
        await n.send_address_list(n.addresses)

        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.ADDR, m.type)
        self.assertIsInstance(m.payload, address.AddrPayload)
        self.assertEqual(n.addresses, m.payload.addresses)

    async def test_req_headers(self):
        n = node.NeoNode(object(), object())
        n.send_message = mock.AsyncMock()
        index_start = 0
        count = 10

        await n.request_headers(index_start, count)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETHEADERS, m.type)
        self.assertIsInstance(m.payload, block.GetBlockByIndexPayload)
        self.assertEqual(index_start, m.payload.index_start)
        self.assertEqual(count, m.payload.count)

    async def test_send_headers(self):
        n = node.NeoNode(object(), object())
        n.send_message = mock.AsyncMock()
        headers = 2001 * [test_helpers.SerializableObject()]

        await n.send_headers(headers)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.HEADERS, m.type)
        self.assertIsInstance(m.payload, block.HeadersPayload)
        # max sure it clips the size to max 2K headers
        self.assertEqual(2000, len(m.payload.headers))

    async def test_req_blocks(self):
        n = node.NeoNode(object(), object())
        n.send_message = mock.AsyncMock()
        hash_start = types.UInt256.from_string(
            "65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9"
        )
        count = 10

        await n.request_blocks(hash_start, count)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETBLOCKS, m.type)
        self.assertIsInstance(m.payload, block.GetBlocksPayload)
        self.assertEqual(hash_start, m.payload.hash_start)
        self.assertEqual(count, m.payload.count)

    async def test_req_block_data(self):
        n = node.NeoNode(object(), object())
        n.send_message = mock.AsyncMock()
        index_start = 1
        count = 2

        await n.request_block_data(index_start, count)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETBLOCKBYINDEX, m.type)
        self.assertIsInstance(m.payload, block.GetBlockByIndexPayload)
        self.assertEqual(index_start, m.payload.index_start)
        self.assertEqual(count, m.payload.count)

    async def test_request_data(self):
        n = node.NeoNode(object(), object())
        n.send_message = mock.AsyncMock()
        hash1 = types.UInt256.from_string(
            "65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9"
        )
        hash2 = types.UInt256.from_string(
            "65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aaaaa"
        )
        hashes = [hash1, hash2]

        await n.request_data(inventory.InventoryType.BLOCK, hashes)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETDATA, m.type)
        self.assertIsInstance(m.payload, inventory.InventoryPayload)
        self.assertEqual(hashes, m.payload.hashes)

    async def test_send_inventory_and_relay(self):
        # test 2 in 1
        # taken from the Transaction testcase in `test_payloads.py`
        raw_tx = bytes.fromhex(
            "007B000000C8010000000000001503000000000000010000000154A64CAC1B1073E662933EF3E30B007CD98D67D7000002010201000155"
        )
        tx = transaction.Transaction.deserialize_from_bytes(raw_tx)

        n = node.NeoNode(object(), object())
        n.send_message = mock.AsyncMock()

        await n.relay(tx)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.INV, m.type)
        self.assertIsInstance(m.payload, inventory.InventoryPayload)
        self.assertEqual(tx.hash(), m.payload.hashes[0])

    async def test_processing_messages(self):
        m_addr = message.Message(
            msg_type=message.MessageType.ADDR, payload=address.AddrPayload([])
        )
        m_block = message.Message(
            msg_type=message.MessageType.BLOCK, payload=block.Block._serializable_init()
        )
        m_inv1 = message.Message(
            msg_type=message.MessageType.INV,
            payload=inventory.InventoryPayload(
                inventory.InventoryType.BLOCK,
                hashes=[
                    types.UInt256.from_string(
                        "65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9"
                    )
                ],
            ),
        )
        m_inv2 = message.Message(
            msg_type=message.MessageType.INV,
            payload=inventory.InventoryPayload(inventory.InventoryType.TX, []),
        )
        m_getaddr = message.Message(
            msg_type=message.MessageType.GETADDR, payload=empty.EmptyPayload()
        )
        m_mempool = message.Message(
            msg_type=message.MessageType.MEMPOOL, payload=empty.EmptyPayload()
        )

        # taken from the Headers testcase in `test_payloads`
        raw_headers_payload = bytes.fromhex(
            "0000000001FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A402FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A400000000000000007B00000000F7B4D00143932F3B6243CFC06CB4A68F22C739E201020102020304"
        )
        m_headers = message.Message(
            msg_type=message.MessageType.HEADERS,
            payload=block.HeadersPayload.deserialize_from_bytes(raw_headers_payload),
        )
        m_ping = message.Message(
            msg_type=message.MessageType.PING, payload=ping.PingPayload(0)
        )
        m_pong = message.Message(
            msg_type=message.MessageType.PONG, payload=ping.PingPayload(0)
        )
        m_reject = message.Message(
            msg_type=message.MessageType.REJECT, payload=empty.EmptyPayload()
        )

        def _mock_data(self):
            # first do handshake
            yield self.m_version.to_array()
            yield self.m_verack.to_array()
            # next send all types of messages we handle
            yield m_addr.to_array()
            yield m_block.to_array()
            yield m_inv1.to_array()
            yield m_inv2.to_array()
            yield m_getaddr.to_array()
            yield m_mempool.to_array()
            yield m_headers.to_array()
            yield m_ping.to_array()
            yield m_pong.to_array()
            yield m_reject.to_array()

        loop = asyncio.get_running_loop()
        r, w = socket.socketpair()

        data = b"".join(list(_mock_data(self)))
        with self.assertLogs(network_logger, "DEBUG") as log_context:
            try:

                loop.call_soon(w.send, data)
                n, _ = await node.NeoNode.connect_to(
                    socket=r, _test_data=self.peername_data
                )
                n.start_message_handler()
            except Exception as e:
                print(f"Unexpected: {e}")

            await asyncio.sleep(0.5)
            await n.disconnect(address.DisconnectReason.SHUTTING_DOWN)
        r.close()
        w.close()

    def test_utility_function(self):
        with self.assertRaises(ValueError) as context:
            node.encode_base62(-100)
        self.assertIn("cannot encode negative numbers", str(context.exception))

        self.assertEqual("0", node.encode_base62(0))

        self.assertEqual("w1R", node.encode_base62(123123))
