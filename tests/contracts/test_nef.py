import unittest
import binascii
from neo3 import contracts
from copy import deepcopy


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
        cls.expected = binascii.unhexlify(b'4e4546336e656f332d626f6120627920434f5a2e696f0000000000000000000000000000736f6d652076657273696f6e0000000000000000000000000000000000000000030102035752f2b1')
        cls.expected_length = 76
        version = "some version"
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
        self.assertEqual(self.nef.checksum, nef.checksum)

    def test_deserialization_error(self):
        nef = deepcopy(self.nef)
        nef.magic = 0xDEADBEEF
        with self.assertRaises(ValueError) as context:
            contracts.NEF.deserialize_from_bytes(nef.to_array())
        self.assertEqual("Deserialization error - Incorrect magic", str(context.exception))

        nef = deepcopy(self.nef)
        nef.script = b''
        with self.assertRaises(ValueError) as context:
            contracts.NEF.deserialize_from_bytes(nef.to_array())
        self.assertEqual("Deserialization error - Script can't be empty", str(context.exception))

        # test with wrong checksum
        nef = deepcopy(self.nef)
        nef._checksum = 0xDEADBEEF
        with self.assertRaises(ValueError) as context:
            contracts.NEF.deserialize_from_bytes(nef.to_array())
        self.assertEqual("Deserialization error - Invalid checksum", str(context.exception))

    def test_len(self):
        self.assertEqual(self.expected_length, len(self.nef))

    def test_eq(self):
        version = "some version"
        compiler = "neo3-boa by COZ.io"
        nef = contracts.NEF(compiler_name=compiler, version=version, script=b'\x01\x02\x03')
        nef2 = contracts.NEF(compiler_name=compiler, version=version, script=b'\x01\x02\x03')
        self.assertFalse(nef == object())
        self.assertTrue(nef == nef2)
