import unittest
from neo3 import vm
from neo3.core import types, cryptography
from neo3.contracts import callflags


class ScriptBuilderTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_emit(self):
        # test emit opcode without operand
        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.DUP)
        self.assertEqual(vm.OpCode.DUP, sb.to_array())

        # test emit opcode withop operand
        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.PUSHDATA1, b"\x01")
        self.assertEqual(vm.OpCode.PUSHDATA1 + b"\x01", sb.to_array())

    def test_emit_push_simple(self):
        sb = vm.ScriptBuilder()
        sb.emit_push(None)
        sb.emit_push(True)
        sb.emit_push(False)
        expected = vm.OpCode.PUSHNULL + vm.OpCode.PUSHT + vm.OpCode.PUSHF
        self.assertEqual(expected, sb.to_array())

    def test_emit_push_strings(self):
        sb = vm.ScriptBuilder()
        sb.emit_push("hello")
        # captured from C#
        expected = "0c0568656c6c6f"
        self.assertEqual(expected, sb.to_array().hex())

        sb = vm.ScriptBuilder()
        sb.emit_push("привет")
        expected = "0c0cd0bfd180d0b8d0b2d0b5d182"
        self.assertEqual(expected, sb.to_array().hex())

    def test_emit_push_uint(self):
        sb = vm.ScriptBuilder()
        sb.emit_push(
            types.UInt160.from_string("0x6f1837723768f27a6f6a14452977e3e0e264f2cc")
        )
        # captured from C#
        expected = "0c14ccf264e2e0e3772945146a6f7af268377237186f"
        self.assertEqual(expected, sb.to_array().hex())

    def test_emit_push_public_key(self):
        key_raw = bytes.fromhex(
            "03b209fd4f53a7170ea4444e0cb0a6bb6a53c2bd016926989cf85f9b0fba17a70c"
        )
        pub_key = cryptography.ECPoint.deserialize_from_bytes(key_raw)
        sb = vm.ScriptBuilder()
        sb.emit_push(pub_key)
        # captured from C#
        expected = (
            "0c2103b209fd4f53a7170ea4444e0cb0a6bb6a53c2bd016926989cf85f9b0fba17a70c"
        )
        self.assertEqual(expected, sb.to_array().hex())

    def test_emit_push_enum(self):
        sb = vm.ScriptBuilder()
        sb.emit_push(vm.OpCode.DUP)
        # captured from C#
        expected = "004a"
        self.assertEqual(expected, sb.to_array().hex())

    def test_emit_push_small_numbers(self):
        sb = vm.ScriptBuilder()
        for i in range(16 + 1):
            sb.emit_push(i)
        # captured from C#
        expected = "101112131415161718191a1b1c1d1e1f20"
        self.assertEqual(expected, sb.to_array().hex())

        # check with BigInteger type
        sb = vm.ScriptBuilder()
        sb.emit_push(types.BigInteger.one())
        self.assertEqual(b"\x11", sb.to_array())

    def test_emit_push_bigger_numbers(self):
        sb = vm.ScriptBuilder()
        sb.emit_push(0x1F)  # PUSHINT8
        sb.emit_push(0xFF)  # PUSHINT16
        sb.emit_push(0xFFFF)  # PUSHINT32
        sb.emit_push(0xFFFFFFFF)  # PUSHINT64
        sb.emit_push(0xFFFFFFFF_FFFFFFFF)  # PUSHINT128
        sb.emit_push(types.BigInteger(b"\x01" * 17))  # PUSHINT256

        # captured from C#
        expected = "001f01ff0002ffff000003ffffffff0000000004ffffffffffffffff0000000000000000050101010101010101010101010101010101000000000000000000000000000000"
        self.assertEqual(expected, sb.to_array().hex())

        with self.assertRaises(ValueError) as context:
            sb.emit_push(types.BigInteger(b"\x01" * 33))
        self.assertEqual(
            "Input number exceeds maximum data size of 32 bytes", str(context.exception)
        )

    def test_emit_push_bytes(self):
        sb = vm.ScriptBuilder()
        sb.emit_push(b"\x01")
        expected = "0c0101"
        self.assertEqual(expected, sb.to_array().hex())
        self.assertEqual(vm.OpCode.PUSHDATA1 + b"\x01\x01", sb.to_array())

        data = b"\x01" * 0x100
        sb = vm.ScriptBuilder()
        sb.emit_push(data)
        expected = "0d000101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"
        self.assertEqual(expected, sb.to_array().hex())

        data = b"\x01" * 0x10000
        sb = vm.ScriptBuilder()
        sb.emit_push(data)
        expected_header = bytes.fromhex("0e00000100")
        self.assertEqual(expected_header + data, sb.to_array())

        data = b"\x01" * 0x10001
        sb = vm.ScriptBuilder()
        sb.emit_push(data)
        expected_header = bytes.fromhex("0e01000100")
        self.assertEqual(expected_header + data, sb.to_array())

        sb = vm.ScriptBuilder()
        with self.assertRaises(ValueError) as context:
            sb.emit_push(b"")
        self.assertEqual("Cannot push zero sized data", str(context.exception))

        # too slow
        # data = b'\x01' * (0xFFFFFFFF + 1)
        # sb = vm.ScriptBuilder()
        # with self.assertRaises(ValueError) as context:
        #     sb.emit_push(data)
        # self.assertIn("Value is too long", str(context.exception))

    def test_emit_push_dict(self):
        data = {"a": 123, "b": 456}

        sb = vm.ScriptBuilder()
        sb.emit_push(data)
        expected = "007b0c016101c8010c016212be"
        self.assertEqual(expected, sb.to_array().hex())

        # test invalid key type
        sb = vm.ScriptBuilder()
        with self.assertRaises(ValueError) as context:
            sb.emit_push({1.0: "abc"})
        self.assertEqual(
            "Unsupported key type <class 'float'>. Supported types by the VM are bool, int and str",
            str(context.exception),
        )

    def test_emit_push_list(self):
        data = ["a", 123, "b", 456]

        sb = vm.ScriptBuilder()
        sb.emit_push(data)
        expected = "01c8010c0162007b0c016114c0"
        self.assertEqual(expected, sb.to_array().hex())

    def test_emit_push_unsupported(self):
        class Unsupported:
            pass

        sb = vm.ScriptBuilder()
        with self.assertRaises(ValueError) as context:
            sb.emit_push(Unsupported())
        self.assertIn("Unsupported value type", str(context.exception))

    def test_emit_jump(self):
        sb = vm.ScriptBuilder()
        sb.emit_jump(vm.OpCode.JMP, 127)
        sb.emit_jump(vm.OpCode.JMP, 128)

        # captured from C#
        expected = "227f2380000000"
        self.assertEqual(expected, sb.to_array().hex())

        sb = vm.ScriptBuilder()
        with self.assertRaises(ValueError) as context:
            sb.emit_jump(vm.OpCode.DUP, 1)
        self.assertEqual(
            "OpCode DUP is not a valid jump OpCode", str(context.exception)
        )

    def test_emit_call(self):
        sb = vm.ScriptBuilder()
        sb.emit_call(127)
        sb.emit_call(128)

        # captured from C#
        expected = "347f3580000000"
        self.assertEqual(expected, sb.to_array().hex())

    def test_emit_syscall(self):
        sb = vm.ScriptBuilder()
        sb.emit_syscall(0xE393C875)

        # captured from C#
        expected = "4175c893e3"
        self.assertEqual(expected, sb.to_array().hex())

        sb = vm.ScriptBuilder()
        sb.emit_syscall(vm.Syscalls.SYSTEM_CONTRACT_CALL)

        # captured from C#
        expected = "41627d5b52"
        self.assertEqual(expected, sb.to_array().hex())

    def test_emit_contract_call(self):
        """
        UInt160 sh;
        UInt160.TryParse("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5", out sh);

        using ScriptBuilder sb = new();
        sb.EmitDynamicCall(sh, "symbol", CallFlags.ReadOnly);
        Console.WriteLine(sb.ToArray().ToHexString());
        """
        sh = types.UInt160.from_string("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")
        sb = vm.ScriptBuilder()
        sb.emit_contract_call(sh, "symbol", callflags.CallFlags.READ_ONLY)

        expected = (
            "c2150c0673796d626f6c0c14f563ea40bc283d4d0e05c48ea305b3f2a07340ef41627d5b52"
        )
        self.assertEqual(expected, sb.to_array().hex())

    def test_emit_contract_call_with_args(self):
        """
        UInt160 sh;
        UInt160 account;
        UInt160.TryParse("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5", out sh);
        UInt160.TryParse("0xd2a4cff31913016155e38e474a2c06d08be276cf", out account);

        using ScriptBuilder sb = new();
        sb.EmitDynamicCall(sh, "balanceOf", CallFlags.ReadOnly, account);
        Console.WriteLine(sb.ToArray().ToHexString());
        """
        sh = types.UInt160.from_string("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")
        account = types.UInt160.from_string(
            "0xd2a4cff31913016155e38e474a2c06d08be276cf"
        )
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(
            sh, "balanceOf", [account], callflags.CallFlags.READ_ONLY
        )

        expected = "0c14cf76e28bd0062c4a478ee35561011319f3cfa4d211c0150c0962616c616e63654f660c14f563ea40bc283d4d0e05c48ea305b3f2a07340ef41627d5b52"
        self.assertEqual(expected, sb.to_array().hex())


class SyscallsTestCase(unittest.TestCase):
    def test_find_by_name(self):
        name = "System.Runtime.BurnGas"
        s = vm.Syscalls.get_by_name(name)
        self.assertEqual(name, s.name)
        self.assertIsNone(vm.Syscalls.get_by_name("fake"))

    def test_find_by_number(self):
        number = 3163314883
        s = vm.Syscalls.get_by_number(number)
        self.assertEqual(number, s.number)
        self.assertIsNone(vm.Syscalls.get_by_number(123))

    def test_all(self):
        self.assertEqual(35, len(list(vm.Syscalls.all())))

    def test_equality(self):
        # allow to compare against ints (should match the syscall number)
        burn_gas_number = 3163314883
        fake_number = 123
        self.assertEqual(burn_gas_number, vm.Syscalls.SYSTEM_RUNTIME_BURN_GAS)
        self.assertNotEqual(fake_number, vm.Syscalls.SYSTEM_RUNTIME_BURN_GAS)

        # allow to compare against strings (should match the syscall name)
        name = "System.Runtime.BurnGas"
        name_wrong = "nope"
        self.assertEqual(name, vm.Syscalls.SYSTEM_RUNTIME_BURN_GAS)
        self.assertNotEqual(name_wrong, vm.Syscalls.SYSTEM_RUNTIME_BURN_GAS)

        # compare against instances
        self.assertEqual(
            vm.Syscalls.SYSTEM_RUNTIME_BURN_GAS, vm.Syscalls.SYSTEM_RUNTIME_BURN_GAS
        )
        self.assertNotEqual(
            vm.Syscalls.SYSTEM_RUNTIME_BURN_GAS, vm.Syscalls.SYSTEM_CONTRACT_CALL
        )

        # compare against byte sequences
        self.assertEqual(
            b"\x56\xe7\xb3\x27", vm.Syscalls.SYSTEM_CRYPTO_CHECK_STANDARD_ACCOUNT
        )
        self.assertNotEqual(
            b"\x01\x01\x01\x01", vm.Syscalls.SYSTEM_CRYPTO_CHECK_STANDARD_ACCOUNT
        )

        self.assertNotEqual(vm.Syscalls.SYSTEM_RUNTIME_BURN_GAS, None)
