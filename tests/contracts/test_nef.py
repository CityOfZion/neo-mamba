import unittest
import binascii
from neo3.contracts import callflags, nef
from neo3.core import types
from copy import deepcopy


class NEFTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var nef = new NefFile
        {
            Compiler = "test-compiler 0.1",
            Source = "source_link",
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
        cls.expected = binascii.unhexlify(
            b"4e454633746573742d636f6d70696c657220302e3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b736f757263655f6c696e6b000100000000000000000000000000000000000000000b746573745f6d6574686f64000001000000014072adaf87"
        )
        cls.expected_length = 126
        compiler = "test-compiler 0.1"
        source = "source_link"
        ret = b"\x40"  # vm.OpCode.RET
        tokens = [
            nef.MethodToken(
                types.UInt160.zero(), "test_method", 0, True, callflags.CallFlags.NONE
            )
        ]
        cls.nef = nef.NEF(
            compiler_name=compiler, script=ret, tokens=tokens, source=source
        )

    def test_serialization(self):
        self.assertEqual(self.expected, self.nef.to_array())

    def test_deserialization(self):
        nef_ = nef.NEF.deserialize_from_bytes(self.expected)
        self.assertEqual(self.nef.magic, nef_.magic)
        self.assertEqual(self.nef.source, nef_.source)
        self.assertEqual(self.nef.compiler, nef_.compiler)
        self.assertEqual(self.nef.script, nef_.script)
        self.assertEqual(self.nef.checksum, nef_.checksum)

    def test_deserialization_error(self):
        nef1 = deepcopy(self.nef)
        nef1.magic = 0xDEADBEEF
        with self.assertRaises(ValueError) as context:
            nef.NEF.deserialize_from_bytes(nef1.to_array())
        self.assertEqual(
            "Deserialization error - Incorrect magic", str(context.exception)
        )

        nef_ = deepcopy(self.nef)
        nef_.script = b""
        with self.assertRaises(ValueError) as context:
            nef.NEF.deserialize_from_bytes(nef_.to_array())
        self.assertEqual(
            "Deserialization error - Script can't be empty", str(context.exception)
        )

        # test with wrong checksum
        nef_ = deepcopy(self.nef)
        nef_._checksum = 0xDEADBEEF
        with self.assertRaises(ValueError) as context:
            nef.NEF.deserialize_from_bytes(nef_.to_array())
        self.assertEqual(
            "Deserialization error - Invalid checksum", str(context.exception)
        )

    def test_len(self):
        self.assertEqual(self.expected_length, len(self.nef))

    def test_eq(self):
        compiler = "test-compiler 0.1"
        ret = b"\x40"  # vm.OpCode.RET
        nef1 = nef.NEF(compiler_name=compiler, script=ret)
        nef2 = nef.NEF(compiler_name=compiler, script=ret)
        self.assertFalse(nef1 == object())
        self.assertTrue(nef1 == nef2)
