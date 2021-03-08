import unittest
import binascii
from neo3 import contracts
from neo3.core import types
from copy import deepcopy


class NEFTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var nef = new NefFile
        {
            Compiler = "test-compiler 0.1",
            Script = new byte[] {(byte) OpCode.RET},
            Tokens = new MethodToken[]
            {
                new MethodToken()
                {
                    Hash = UInt160.Zero,
                    Method = "test_method",
                    ParametersCount = 0,
                    HasReturnValue = true,
                    CallFlags = CallFlags.None
                }
            }
        };
        nef.CheckSum = NefFile.ComputeChecksum(nef);
        Console.WriteLine(nef.ToArray().ToHexString());
        Console.WriteLine(nef.Size);
        """
        cls.expected = binascii.unhexlify(b'4e454633746573742d636f6d70696c657220302e31000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000b746573745f6d6574686f64000001000000014010993d46')
        cls.expected_length = 115
        compiler = "test-compiler 0.1"
        ret = b'\x40'  # vm.OpCode.RET
        tokens = [contracts.MethodToken(types.UInt160.zero(), "test_method", 0, True, contracts.CallFlags.NONE)]
        cls.nef = contracts.NEF(compiler_name=compiler, script=ret, tokens=tokens)

    def test_serialization(self):
        self.assertEqual(self.expected, self.nef.to_array())

    def test_deserialization(self):
        nef = contracts.NEF.deserialize_from_bytes(self.expected)
        self.assertEqual(self.nef.magic, nef.magic)
        self.assertEqual(self.nef.compiler, nef.compiler)
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
        compiler = "test-compiler 0.1"
        ret = b'\x40'  # vm.OpCode.RET
        nef = contracts.NEF(compiler_name=compiler, script=ret)
        nef2 = contracts.NEF(compiler_name=compiler, script=ret)
        self.assertFalse(nef == object())
        self.assertTrue(nef == nef2)
