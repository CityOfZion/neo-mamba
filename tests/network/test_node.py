import asynctest
import socket
import logging
import asyncio
import binascii
from functools import partial
from neo3.network import node, message, payloads, capabilities, ipfilter, protocol, encode_base62

from neo3 import settings, network_logger
from neo3.core import types
from unittest import mock
from tests import helpers as test_helpers


class NeoNodeSocketMock(asynctest.SocketMock):
    def __init__(self, loop, hostaddr: str, port: int):
        super(NeoNodeSocketMock, self).__init__()
        self.type = socket.SOCK_STREAM
        self.recv_buffer = bytearray()
        self.loop = loop
        self.hostaddr = hostaddr
        self.port = port
        self.recv_data = self._recv_data()
        caps = [capabilities.FullNodeCapability(0),
                capabilities.ServerCapability(n_type=capabilities.NodeCapabilityType.TCPSERVER, port=10333)]
        self.m_send_version = message.Message(msg_type=message.MessageType.VERSION,
                                              payload=payloads.VersionPayload(nonce=123,
                                                                          user_agent="NEO3-MOCK-CLIENT",
                                                                                 capabilities=caps))
        self.m_verack = message.Message(msg_type=message.MessageType.VERACK)

    def _recv_data(self):
        yield self.m_send_version.to_array()
        yield self.m_verack.to_array()
        raise BlockingIOError
        # while True:
        #     yield message.Message(msg_type=message.MessageType.PING,
        #                           payload=payloads.PingPayload(height=0)).to_array()

    def recv(self, max_bytes):
        if not self.recv_buffer:
            try:
                self.recv_buffer.extend(next(self.recv_data))
                asynctest.set_read_ready(self, self.loop)
            except StopIteration:
                # nothing left
                pass

        data = self.recv_buffer[:max_bytes]
        self.recv_buffer = self.recv_buffer[max_bytes:]

        if self.recv_buffer:
            # Some more data to read
            asynctest.set_read_ready(self, self.loop)

        return data

    def send(self, data):
        asynctest.set_read_ready(self, self.loop)
        return len(data)

    def getpeername(self):
        return (self.hostaddr, self.port)


class NeoNodeTestCase(asynctest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        network_logger = logging.getLogger('neo3.network')
        network_logger.setLevel(logging.DEBUG)
        stdio_handler = logging.StreamHandler()
        network_logger.addHandler(stdio_handler)

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def setUp(self) -> None:
        settings.reset_settings_to_default()
        node.NeoNode._reset_for_test()
        ipfilter.ipfilter.reset()

    async def test_connect_to(self):
        with self.assertRaises(ValueError) as context:
            await node.NeoNode.connect_to()
        self.assertIn("host and port was not specified and no sock specified", str(context.exception))

        with self.assertRaises(ValueError) as context:
            await node.NeoNode.connect_to(host='123', socket=object())
        self.assertIn("host/port and socket can not be specified at the same time", str(context.exception))

    async def test_connect_to_with_socket(self):
        settings.network.magic = 769

        socket_mock = NeoNodeSocketMock(self.loop, '127.0.0.1', 1111)

        with self.assertLogs(network_logger, 'DEBUG') as log_context:
           n, _ = await node.NeoNode.connect_to(socket=socket_mock)
        self.assertIn("Trying to connect to socket", log_context.output[0])
        self.assertIn("Connected to NEO3-MOCK-CLIENT @ 127.0.0.1:1111", log_context.output[2])
        self.assertIsInstance(n, node.NeoNode)
        await n.disconnect(payloads.DisconnectReason.SHUTTING_DOWN)

    async def test_connect_to_with_host_ip(self):
        # just for basic coverage, we use the above socket mock for more indepth testing
        host = '127.0.0.1'
        port = 1111

        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            with asynctest.patch.object(self.loop, 'create_connection'):
                _, _ = await node.NeoNode.connect_to(host, port)
        self.assertIn(f"Trying to connect to: {host}:{port}", log_context.output[0])

    async def test_connect_to_exceptions(self):
        loop = asynctest.MagicMock()

        loop.create_connection.side_effect = asyncio.TimeoutError
        node_instance, failure = await node.NeoNode.connect_to(socket=object(), loop=loop)
        self.assertIsNone(node_instance)
        self.assertEqual("Timed out", failure[1])

        loop.create_connection.side_effect = OSError("unreachable")
        node_instance, failure = await node.NeoNode.connect_to(socket=object(), loop=loop)
        self.assertIsNone(node_instance)
        self.assertEqual("Failed to connect for reason unreachable", failure[1])

        loop.create_connection.side_effect = asyncio.CancelledError
        node_instance, failure = await node.NeoNode.connect_to(socket=object(), loop=loop)
        self.assertIsNone(node_instance)
        self.assertEqual("Cancelled", failure[1])

    def test_helpers(self):
        addr1 = payloads.NetworkAddress(address='127.0.0.1:1111')
        addr1.set_state_dead()
        addr2 = payloads.NetworkAddress(address='127.0.0.1:2222')
        node.NeoNode.addresses = [addr1, addr2]
        result = node.NeoNode.get_address_new()
        self.assertEqual(addr2, result)

        n = node.NeoNode(object())
        addr = n._find_address_by_host_port('127.0.0.1:1111')
        self.assertEqual(addr1, addr)
        addr = n._find_address_by_host_port('127.0.0.1:3333')
        self.assertEqual(None, addr)

    async def test_handshake_first_message_not_VERSION(self):
        settings.network.magic = 769
        socket_mock = NeoNodeSocketMock(self.loop, '127.0.0.1', 1111)

        def _recv_data2(self):
            yield self.m_verack.to_array()

        socket_mock.recv_data = _recv_data2(socket_mock)
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            await node.NeoNode.connect_to(socket=socket_mock)
        self.assertIn("Disconnect called with reason=HANDSHAKE_VERSION_ERROR", log_context.output[1])

    async def test_handshake_version_validation_failed(self):
        # mock the version validation call result. The version_validation function is tested down below
        settings.network.magic = 769
        socket_mock = NeoNodeSocketMock(self.loop, '127.0.0.1', 1111)
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            with asynctest.patch('neo3.network.node.NeoNode._validate_version', return_value=False):
                await node.NeoNode.connect_to(socket=socket_mock)

        self.assertIn("Disconnect called with reason=HANDSHAKE_VERSION_ERROR", log_context.output[1])

    async def test_handshake_second_message_not_VERACK(self):
        settings.network.magic = 769
        socket_mock = NeoNodeSocketMock(self.loop, '127.0.0.1', 1111)

        def _recv_data2(self):
            yield self.m_send_version.to_array()
            yield self.m_send_version.to_array()

        socket_mock.recv_data = _recv_data2(socket_mock)

        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            await node.NeoNode.connect_to(socket=socket_mock)
        self.assertIn("Disconnect called with reason=HANDSHAKE_VERACK_ERROR", log_context.output[2])

    def _new_version(self):
        self.start_height = 888
        caps = [capabilities.FullNodeCapability(start_height=self.start_height),
                capabilities.ServerCapability(capabilities.NodeCapabilityType.TCPSERVER, 10333)]
        return payloads.VersionPayload(nonce=123, user_agent="NEO3-MOCK-CLIENT", capabilities=caps)

    def test_version_validation_client_is_self(self):
        n = node.NeoNode(object())

        # test for client is self
        version = self._new_version()
        version.nonce = n.nodeid
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            result = n._validate_version(version)
        self.assertFalse(result)
        self.assertIn("Client is self", log_context.output[0])

    def test_version_validation_wrong_network(self):
        n = node.NeoNode(object())

        # test for wrong network
        settings.network.magic = 769
        version = self._new_version()
        version.magic = 111
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            result = n._validate_version(version)
        self.assertFalse(result)
        self.assertIn("Wrong network id", log_context.output[0])

    def test_version_validation_should_updating_address_to_connected_state(self):
        n = node.NeoNode(object())

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
        n = node.NeoNode(object())
        # normally this is updated by `connection_made()`, since we skip that in this test we set it manually
        n.address.address = '127.0.0.1:1111'
        self.assertEqual(0, len(node.NeoNode.addresses))

        version = self._new_version()
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            n._validate_version(version)
        self.assertEqual(1, len(node.NeoNode.addresses))
        self.assertIn("Adding address from outside 127.0.0.1:1111", log_context.output[0])

    def test_version_validation_fail_if_no_full_node_capabilities(self):
        n = node.NeoNode(object())

        version = self._new_version()
        # remove the full node capability
        version.capabilities.pop(0)
        result = n._validate_version(version)
        self.assertFalse(result)

    async def test_connect_blocked_by_ipfilter(self):
        settings.network.magic = 769
        socket_mock = NeoNodeSocketMock(self.loop, '127.0.0.1', 1111)
        ipfilter.ipfilter.blacklist_add('127.0.0.1')

        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            await node.NeoNode.connect_to(socket=socket_mock)
        self.assertIn("Blocked by ipfilter: 127.0.0.1:1111", log_context.output[1])

    async def test_req_addr_list(self):
        n = node.NeoNode(object())
        n.send_message = asynctest.CoroutineMock()
        await n.request_address_list()

        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETADDR, m.type)
        self.assertIsInstance(m.payload, payloads.EmptyPayload)

    async def test_send_addr_list(self):
        n = node.NeoNode(object())
        n.send_message = asynctest.CoroutineMock()
        n.addresses = [payloads.NetworkAddress(address='127.0.0.1:1111')]
        await n.send_address_list(n.addresses)

        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.ADDR, m.type)
        self.assertIsInstance(m.payload, payloads.AddrPayload)
        self.assertEqual(n.addresses, m.payload.addresses)

    async def test_req_headers(self):
        n = node.NeoNode(object())
        n.send_message = asynctest.CoroutineMock()
        hash_start = types.UInt256.from_string("65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9")
        count = 10

        await n.request_headers(hash_start, count)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETHEADERS, m.type)
        self.assertIsInstance(m.payload, payloads.GetBlocksPayload)
        self.assertEqual(hash_start, m.payload.hash_start)
        self.assertEqual(count, m.payload.count)

    async def test_send_headers(self):
        n = node.NeoNode(object())
        n.send_message = asynctest.CoroutineMock()
        headers = 2001 * [test_helpers.SerializableObject()]

        await n.send_headers(headers)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.HEADERS, m.type)
        self.assertIsInstance(m.payload, payloads.HeadersPayload)
        # max sure it clips the size to max 2K headers
        self.assertEqual(2000, len(m.payload.headers))

    async def test_req_blocks(self):
        n = node.NeoNode(object())
        n.send_message = asynctest.CoroutineMock()
        hash_start = types.UInt256.from_string("65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9")
        count = 10

        await n.request_blocks(hash_start, count)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETBLOCKS, m.type)
        self.assertIsInstance(m.payload, payloads.GetBlocksPayload)
        self.assertEqual(hash_start, m.payload.hash_start)
        self.assertEqual(count, m.payload.count)

    async def test_req_block_data(self):
        n = node.NeoNode(object())
        n.send_message = asynctest.CoroutineMock()
        index_start = 1
        count = 2

        await n.request_block_data(index_start, count)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETBLOCKBYINDEX, m.type)
        self.assertIsInstance(m.payload, payloads.GetBlockByIndexPayload)
        self.assertEqual(index_start, m.payload.index_start)
        self.assertEqual(count, m.payload.count)

    async def test_request_data(self):
        n = node.NeoNode(object())
        n.send_message = asynctest.CoroutineMock()
        hash1 = types.UInt256.from_string("65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9")
        hash2 = types.UInt256.from_string("65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aaaaa")
        hashes = [hash1, hash2]

        await n.request_data(payloads.InventoryType.BLOCK, hashes)
        self.assertIsNotNone(n.send_message.call_args)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.GETDATA, m.type)
        self.assertIsInstance(m.payload, payloads.InventoryPayload)
        self.assertEqual(hashes, m.payload.hashes)

    async def test_send_inventory_and_relay(self):
        # test 2 in 1
        # taken from the Transaction testcase in `test_payloads.py`
        raw_tx = binascii.unhexlify(b'007B000000C8010000000000001503000000000000010000000154A64CAC1B1073E662933EF3E30B007CD98D67D7000002010201000155')
        tx = payloads.Transaction.deserialize_from_bytes(raw_tx)

        n = node.NeoNode(object())
        n.send_message = asynctest.CoroutineMock()

        await n.relay(tx)
        m = n.send_message.call_args[0][0]  # type: message.Message
        self.assertEqual(message.MessageType.INV, m.type)
        self.assertIsInstance(m.payload, payloads.InventoryPayload)
        self.assertEqual(tx.hash(), m.payload.hashes[0])

    async def test_processing_messages(self):
        settings.network.magic = 769
        socket_mock = NeoNodeSocketMock(self.loop, '127.0.0.1', 1111)

        m_addr = message.Message(msg_type=message.MessageType.ADDR, payload=payloads.AddrPayload([]))
        m_block = message.Message(msg_type=message.MessageType.BLOCK, payload=payloads.EmptyPayload())
        m_inv1 = message.Message(msg_type=message.MessageType.INV, payload=payloads.InventoryPayload(
            payloads.InventoryType.BLOCK,
            hashes=[types.UInt256.from_string("65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9")]
        ))
        m_inv2 = message.Message(msg_type=message.MessageType.INV,
                                 payload=payloads.InventoryPayload(payloads.InventoryType.TX, []))
        m_getaddr = message.Message(msg_type=message.MessageType.GETADDR, payload=payloads.EmptyPayload())
        m_mempool = message.Message(msg_type=message.MessageType.MEMPOOL, payload=payloads.EmptyPayload())

        # taken from the Headers testcase in `test_payloads`
        raw_headers_payload = binascii.unhexlify(b'020000000001FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A402FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A400000000000000007B0000008A2B438EACA8B4B2AB6B4524B5A69A45D920C35101020102020304000000000001FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A402FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A400000000000000007B0000008A2B438EACA8B4B2AB6B4524B5A69A45D920C3510102010202030400')
        m_headers = message.Message(msg_type=message.MessageType.HEADERS,
                                    payload=payloads.HeadersPayload.deserialize_from_bytes(raw_headers_payload))
        m_ping = message.Message(msg_type=message.MessageType.PING, payload=payloads.PingPayload(0))
        m_pong = message.Message(msg_type=message.MessageType.PONG, payload=payloads.PingPayload(0))
        m_reject = message.Message(msg_type=message.MessageType.REJECT, payload=payloads.EmptyPayload())

        def _recv_data2(self):
            # first do handshake
            yield self.m_send_version.to_array()
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

        socket_mock.recv_data = _recv_data2(socket_mock)
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            try:
                n, _ = await node.NeoNode.connect_to(socket=socket_mock)
            except Exception as e:
                print(f"GVD {e}")

            await asyncio.sleep(0.5)
            await n.disconnect(payloads.DisconnectReason.SHUTTING_DOWN)

    @asynctest.SkipTest
    async def test_processing_messages3(self):
        # we got 2 cases for which we need to test without using a backend
        settings.network.magic = 769
        settings.storage.use_default = False
        socket_mock = NeoNodeSocketMock(self.loop, '127.0.0.1', 1111)

        m_inv1 = message.Message(msg_type=message.MessageType.INV, payload=payloads.InventoryPayload(
            payloads.InventoryType.BLOCK,
            hashes=[types.UInt256.from_string("65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9")]
        ))
        m_ping = message.Message(msg_type=message.MessageType.PING, payload=payloads.PingPayload(0))

        def _recv_data2(self):
            print("my recv data 2 called ")
            # first do handshake
            yield self.m_send_version.to_array()
            yield self.m_verack.to_array()
            yield m_inv1.to_array()
            yield m_ping.to_array()

        socket_mock.recv_data = _recv_data2(socket_mock)
        with self.assertLogs(network_logger, 'DEBUG') as log_context:
            with mock.patch('neo3.network.node.NeoNode.send_message', new_callable=asynctest.CoroutineMock):
            # with asynctest.patch('neo3.network.node.NeoNode.send_message', return_value=asynctest.CoroutineMock()):
                n, _ = await node.NeoNode.connect_to(socket=socket_mock)
                await asyncio.sleep(0.1)
                await n.disconnect(payloads.DisconnectReason.SHUTTING_DOWN)
        # print(n.send_message.call_args)

    # async def test_wtf(self):
    #     protocol = asynctest.MagicMock()
    #     protocol.send_message = asynctest.CoroutineMock()
    #     nn = node.NeoNode(protocol)
    #     mock_read_message = asynctest.CoroutineMock()
    #     nn.read_message = mock_read_message
    #
    #     m_inv1 = message.Message(msg_type=message.MessageType.INV, payload=payloads.InventoryPayload(
    #         payloads.InventoryType.BLOCK,
    #         hashes=[types.UInt256.from_string("65793a030c0dcd4fff4da8a6a6d5daa8b570750da4fdeea1bbc43bdf124aedc9")]
    #     ))
    #     m_ping = message.Message(msg_type=message.MessageType.PING, payload=payloads.PingPayload(0))
    #
    #     mock_read_message.side_effect = [m_inv1, m_ping]
    #     await nn._process_incoming_data()

    def test_utility_function(self):
        with self.assertRaises(ValueError) as context:
            encode_base62(-100)
        self.assertIn("cannot encode negative numbers", str(context.exception))

        self.assertEqual('0', encode_base62(0))

        self.assertEqual('w1R', encode_base62(123123))

