import unittest
import binascii
from neo3.network import capabilities
from neo3.core import serialization


class FullNodeCapabilitiesTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        FullNodeCapability capability = new FullNodeCapability(123);

        Console.WriteLine($"{capability.Size}");
        Console.WriteLine($"{BitConverter.ToString(capability.ToArray()).Replace("-", "")}");
        """
        cls.capability = capabilities.FullNodeCapability(start_height=123)

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 5
        self.assertEqual(expected_len, len(self.capability))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b"107B000000")
        self.assertEqual(expected_data, self.capability.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_capability = (
            capabilities.FullNodeCapability.deserialize_from_bytes(
                self.capability.to_array()
            )
        )
        self.assertEqual(
            self.capability.start_height, deserialized_capability.start_height
        )


class ServerNodeCapabilitiesTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        ServerCapability capability = new ServerCapability(NodeCapabilityType.TcpServer, 10333);

        Console.WriteLine($"{capability.Size}");
        Console.WriteLine($"{BitConverter.ToString(capability.ToArray()).Replace("-", "")}");
        """
        cls.capability = capabilities.ServerCapability(
            n_type=capabilities.NodeCapabilityType.TCPSERVER, port=10333
        )

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 3
        self.assertEqual(expected_len, len(self.capability))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b"015D28")
        self.assertEqual(expected_data, self.capability.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_capability = capabilities.ServerCapability.deserialize_from_bytes(
            self.capability.to_array()
        )
        self.assertEqual(
            capabilities.NodeCapabilityType.TCPSERVER, deserialized_capability.type
        )
        self.assertEqual(self.capability.type, deserialized_capability.type)
        self.assertEqual(self.capability.port, deserialized_capability.port)

    def test_creation_with_invalid_type(self):
        with self.assertRaises(TypeError) as context:
            capabilities.ServerCapability(n_type=999, port=123)
        self.assertIn("999 not one of: TCPSERVER WSSERVER", str(context.exception))


class BaseCapabilitiesTestCase(unittest.TestCase):
    def test_deserialize_from(self):
        server = capabilities.ServerCapability(
            n_type=capabilities.NodeCapabilityType.TCPSERVER, port=10333
        )
        fullnode = capabilities.FullNodeCapability(start_height=123)

        with serialization.BinaryReader(server.to_array()) as br:
            capability = capabilities.NodeCapability.deserialize_from(br)
        self.assertIsInstance(capability, capabilities.ServerCapability)

        with serialization.BinaryReader(fullnode.to_array()) as br:
            capability = capabilities.NodeCapability.deserialize_from(br)
        self.assertIsInstance(capability, capabilities.FullNodeCapability)

        # test equality
        # ServerCapability capability = new ServerCapability(NodeCapabilityType.TcpServer, 10333);
        # ServerCapability capability2 = new ServerCapability(NodeCapabilityType.TcpServer, 10333);
        # Console.WriteLine($"{capability == capability2} {capability.Equals(capability2)}"); // false false
        fullnode2 = capabilities.FullNodeCapability(start_height=123)
        self.assertNotEqual(fullnode, fullnode2)
        self.assertFalse(fullnode == fullnode2)
        self.assertFalse(id(fullnode) == id(fullnode2))
