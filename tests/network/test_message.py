import unittest
import binascii
import lz4
from unittest.mock import patch, call
from neo3.network import payloads, message
from neo3.core.types.uint import UInt256
from neo3.core import serialization

class NetworkMessageTestCase(unittest.TestCase):
    def test_create_no_payload(self):
        m = message.Message(message.MessageType.PING, payload=None)
        self.assertEqual(message.MessageType.PING, m.type)
        self.assertEqual(message.MessageConfig.NONE, m.config)

    def test_create_inv_message(self):
        hashes = [UInt256.zero()]
        inv_payload = payloads.InventoryPayload(payloads.InventoryType.BLOCK, hashes)
        m = message.Message(message.MessageType.INV, inv_payload)
        data = m.to_array()

        self.assertEqual(message.MessageType.INV, m.type)
        self.assertEqual(message.MessageConfig.NONE, m.config)
        self.assertIsInstance(m.payload, payloads.InventoryPayload)

        """
            Taken from constructing the same object in C#
            
            UInt256[] hashes = { UInt256.Zero };
            var inv_payload = InvPayload.Create(InventoryType.Block, hashes);
            ISerializable message = Message.Create(MessageCommand.Inv, inv_payload);

            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(ms))
            {
                message.Serialize(writer);
                writer.Flush();
                byte[] data = ms.ToArray();
                Console.WriteLine($"b\'{BitConverter.ToString(data).Replace("-","")}\'");
            }          

        """
        expected_data = binascii.unhexlify(b'0027222C010000000000000000000000000000000000000000000000000000000000000000')
        self.assertEqual(expected_data, data)

    def test_create_compressed_inv_message(self):
        hashes = [UInt256.zero(), UInt256.zero(), UInt256.zero(), UInt256.zero()]
        inv_payload = payloads.InventoryPayload(payloads.InventoryType.BLOCK, hashes)
        m = message.Message(message.MessageType.INV, inv_payload)
        data = m.to_array() # triggers payload compression

        self.assertEqual(message.MessageType.INV, m.type)
        self.assertEqual(message.MessageConfig.COMPRESSED, m.config)
        self.assertIsInstance(m.payload, payloads.InventoryPayload)

        """
        Data created in the same fashion as how it's done in test_create_inv_message()
        The deviation is `hashes` now contains 4 x UInt256.zero()
        """

        expected_data = binascii.unhexlify(b'012711820000003F2C0400010067500000000000')
        self.assertEqual(expected_data, data)

    def test_inv_message_deserialization(self):
        # see test_create_compressed_inv_message() how it was obtained
        raw_data = binascii.unhexlify(b'012711820000003F2C0400010067500000000000')
        m = message.Message.deserialize_from_bytes(raw_data)
        self.assertIsInstance(m.payload, payloads.InventoryPayload)
        self.assertEqual(132, len(m))

    def test_deserialization_with_not_enough_data(self):
        with self.assertRaises(ValueError) as context:
            m = message.Message.deserialize_from_bytes(bytearray(2))
        self.assertEqual(str(context.exception), "Could not read byte from empty stream")

    def test_deserialization_without_payload(self):
        # some message types like PING/PONG have no payload
        m = message.Message(message.MessageType.PING)
        data = m.to_array()
        m2 = message.Message.deserialize_from_bytes(data)
        self.assertEqual(message.MessageType.PING, m2.type)
        self.assertEqual(0, len(m2.payload))

    def test_deserialization_from_stream(self):
        # see test_create_compressed_inv_message() how it was obtained
        raw_data = binascii.unhexlify(b'012711820000003F2C0400010067500000000000')
        with serialization.BinaryReader(raw_data) as br:
            m = message.Message(message.MessageType.DEFAULT)
            m.deserialize(br)
            self.assertEqual(m.type, message.MessageType.INV)
            self.assertEqual(m.payload.type, payloads.inventory.InventoryType.BLOCK)

    def test_deserialization_with_unsupported_payload_type(self):
        hashes = [UInt256.zero()]
        inv_payload = payloads.InventoryPayload(payloads.InventoryType.BLOCK, hashes)
        m = message.Message(message.MessageType.ALERT, inv_payload)

        m2 = message.Message.deserialize_from_bytes(m.to_array())
        self.assertIsInstance(m2.payload, payloads.EmptyPayload)

    def test_deserialization_erroneous_compressed_data(self):
        # see test_create_compressed_inv_message() how it was obtained
        raw_data = binascii.unhexlify(b'01270D3F020400010067500000000000')

        with patch('lz4.block.decompress') as lz4_mock:
            with self.assertRaises(ValueError) as context:
                lz4_mock.side_effect = lz4.block.LZ4BlockError()
                m = message.Message.deserialize_from_bytes(raw_data)
            self.assertEqual("Invalid payload data - decompress failed", str(context.exception))

    def test_payload_from_data(self):
        with patch('neo3.core.serialization.BinaryReader') as br:
            reader = br.return_value.__enter__.return_value
            message.Message._payload_from_data(message.MessageType.INV, b'')
            message.Message._payload_from_data(message.MessageType.GETBLOCKBYINDEX, b'')
            message.Message._payload_from_data(message.MessageType.VERSION, b'')
            message.Message._payload_from_data(message.MessageType.VERACK, b'')
            message.Message._payload_from_data(message.MessageType.BLOCK, b'')
            message.Message._payload_from_data(message.MessageType.HEADERS, b'')
            message.Message._payload_from_data(message.MessageType.PING, b'')
            message.Message._payload_from_data(message.MessageType.PONG, b'')
            message.Message._payload_from_data(message.MessageType.ADDR, b'')
            message.Message._payload_from_data(message.MessageType.TRANSACTION, b'')

            calls = [
                call(payloads.InventoryPayload),
                call(payloads.GetBlockByIndexPayload),
                call(payloads.VersionPayload),
                call(payloads.EmptyPayload),
                call(payloads.Block),
                call(payloads.HeadersPayload),
                call(payloads.PingPayload),
                call(payloads.PingPayload),
                call(payloads.AddrPayload),
                call(payloads.Transaction)
            ]
            reader.read_serializable.assert_has_calls(calls, any_order=False)
