import unittest
import binascii
from neo3 import contracts
from copy import deepcopy


class VersionTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_creation_with_negative_values(self):
        with self.assertRaises(ValueError) as context:
            contracts.Version(-1, 0, 0, 0)
        self.assertEqual("Negative version numbers are not allowed", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version(0, -1, 0, 0)
        self.assertEqual("Negative version numbers are not allowed", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version(0, 0, -1, 0)
        self.assertEqual("Negative version numbers are not allowed", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version(0, 0, 0, -1)
        self.assertEqual("Negative version numbers are not allowed", str(context.exception))

    def test_creation_with_too_large_values(self):
        with self.assertRaises(ValueError) as context:
            contracts.Version(256, 0, 0, 0)
        self.assertEqual("Version numbers cannot exceed 255", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version(0, 256, 0, 0)
        self.assertEqual("Version numbers cannot exceed 255", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version(0, 0, 256, 0)
        self.assertEqual("Version numbers cannot exceed 255", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version(0, 0, 0, 256)
        self.assertEqual("Version numbers cannot exceed 255", str(context.exception))

    def test_len(self):
        v = contracts.Version(1, 0, 0, 0)
        self.assertEqual(16, len(v))

    def test_serialization(self):
        """
        Version v = new Version(100,120,130,140);
        using (MemoryStream ms = new MemoryStream(1024))
        using (BinaryWriter writer = new BinaryWriter(ms))
        {
            writer.Write(v.Major);
            writer.Write(v.Minor);
            writer.Write(v.Build);
            writer.Write(v.Revision);
            ms.Seek(0, SeekOrigin.Begin);
            Console.WriteLine(ms.ToArray().ToHexString());
        }
        """
        v = contracts.Version(100, 120, 130, 140)
        expected = binascii.unhexlify(b'6400000078000000820000008c000000')
        self.assertEqual(expected, v.to_array())

    def test_deserialization(self):
        v = contracts.Version(100, 120, 130, 140)
        v_deserialized = contracts.Version.deserialize_from_bytes(v.to_array())
        self.assertEqual(v, v_deserialized)

    def test_from_string(self):
        # too few parts
        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1")
        self.assertEqual("Cannot parse version from: 1", str(context.exception))        # too little information

        # too many parts
        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1.1.1.1.1")
        self.assertEqual("Cannot parse version from: 1.1.1.1.1", str(context.exception))

        # negative version numbers
        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("-1.1.1.1")
        self.assertIn("Cannot parse major field from", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1.-1.1.1")
        self.assertIn("Cannot parse minor field from", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1.1.-1.1")
        self.assertIn("Cannot parse build field from", str(context.exception))
        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1.1.1.-1")
        self.assertIn("Cannot parse revision field from", str(context.exception))

        # too large positive version numbers
        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("256.1.1.1")
        self.assertIn("Cannot parse major field from", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1.256.1.1")
        self.assertIn("Cannot parse minor field from", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1.1.256.1")
        self.assertIn("Cannot parse build field from", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1.1.1.256")
        self.assertIn("Cannot parse revision field from", str(context.exception))

        # parse with invalid number
        with self.assertRaises(ValueError) as context:
            contracts.Version.from_string("1.notanumber")
        self.assertIn("Cannot parse minor field from", str(context.exception))

        # parse without build/revision
        v = contracts.Version.from_string("1.2")
        self.assertEqual(contracts.Version(1,2,0,0), v)

        # parse without revision
        v = contracts.Version.from_string("1.2.3")
        self.assertEqual(contracts.Version(1,2,3,0), v)

        # parse complete ok
        v = contracts.Version.from_string("1.2.3.4")
        self.assertEqual(contracts.Version(1,2,3,4), v)

    def test_eq(self):
        v = contracts.Version.from_string("1.2.3.4")
        v2 = contracts.Version.from_string("1.2.3.4")
        self.assertFalse(v == object())
        self.assertTrue(v == v2)


class NEFTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        Version v = new Version(1,2,3,4);
        var nef = new NefFile
        {
            Version = v,
            Compiler = "neo3-boa by COZ.io",
            Script = new byte[] {1, 2, 3}
        };

        nef.ScriptHash = nef.Script.ToScriptHash();
        nef.CheckSum = NefFile.ComputeChecksum(nef);
        Console.WriteLine(nef.ToArray().ToHexString());
        Console.WriteLine(nef.Size);
        """
        cls.expected = binascii.unhexlify(b'4e4546336e656f332d626f6120627920434f5a2e696f0000000000000000000000000000010000000200000003000000040000009bc4860bb936abf262d7a51f74b4304833fee3b204f92d6a03010203')
        cls.expected_length = 80
        version = contracts.Version(1,2,3,4)
        compiler = "neo3-boa by COZ.io"
        cls.nef = contracts.NEF(compiler_name=compiler, version=version, script=b'\x01\x02\x03')

    def test_serialization(self):
        self.assertEqual(self.expected, self.nef.to_array())

    def test_deserialization(self):
        nef = contracts.NEF.deserialize_from_bytes(self.expected)
        self.assertEqual(self.nef.magic, nef.magic)
        self.assertEqual(self.nef.compiler, nef.compiler)
        self.assertEqual(self.nef.version, nef.version)
        self.assertEqual(self.nef.script, nef.script)
        self.assertEqual(self.nef.script_hash, nef.script_hash)
        self.assertIn(self.nef.checksum, nef.checksum)

    def test_deserialization_error(self):
        # test with wrong checksum
        nef = deepcopy(self.nef)
        nef.checksum = b'DEADBEEF'
        with self.assertRaises(ValueError) as context:
            contracts.NEF.deserialize_from_bytes(nef.to_array())
        self.assertEqual("Deserialization error - invalid checksum", str(context.exception))

        nef = deepcopy(self.nef)
        nef.script = b'DEADBEEF'
        with self.assertRaises(ValueError) as context:
            contracts.NEF.deserialize_from_bytes(nef.to_array())
        self.assertEqual("Deserialization error - invalid script_hash", str(context.exception))

    def test_len(self):
        self.assertEqual(self.expected_length, len(self.nef))

    def test_eq(self):
        version = contracts.Version(1,2,3,4)
        compiler = "neo3-boa by COZ.io"
        nef = contracts.NEF(compiler_name=compiler, version=version, script=b'\x01\x02\x03')
        nef2 = contracts.NEF(compiler_name=compiler, version=version, script=b'\x01\x02\x03')
        self.assertFalse(nef == object())
        self.assertTrue(nef == nef2)

