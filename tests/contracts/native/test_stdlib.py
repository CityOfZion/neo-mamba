import unittest
import binascii
from neo3 import vm, contracts
from neo3.core import syscall_name_to_int
from tests.contracts.interop.utils import test_engine


class StdLibTestCase(unittest.TestCase):
    def test_binary_serialization(self):
        engine = test_engine(has_snapshot=True)
        original_item = 100
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "serialize", [original_item])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.pop()
        self.assertIsInstance(item, vm.ByteStringStackItem)
        self.assertEqual(b'\x21\x01\x64', item.to_array())

    def test_binary_deserialization(self):
        engine = test_engine(has_snapshot=True)
        original_item = 100
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "serialize", [original_item])
        # now take the results of the "serialize" call and call "deserialize" on the StdLib contract
        sb.emit_push(1)
        sb.emit(vm.OpCode.PACK)  # pack the results of "serialize" as the arguments for the next call
        sb.emit_push(0xF)  # CallFlags.ALL
        sb.emit_push("deserialize")
        sb.emit_push(contracts.StdLibContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.pop()
        self.assertEqual(original_item, int(item))

    def test_json_serialization(self):
        sb = vm.ScriptBuilder()
        sb.emit_push(5)
        sb.emit_push(1)  # arg len
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(0xF)  # CallFlags.ALL
        sb.emit_push("jsonSerialize")
        sb.emit_push(contracts.StdLibContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        sb.emit(vm.OpCode.PUSH0)
        sb.emit(vm.OpCode.NOT)
        sb.emit_push(1)  # arg len
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(0xF)  # CallFlags.ALL
        sb.emit_push("jsonSerialize")
        sb.emit_push(contracts.StdLibContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        sb.emit_push("test")
        sb.emit_push(1)  # arg len
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(0xF)  # CallFlags.ALL
        sb.emit_push("jsonSerialize")
        sb.emit_push(contracts.StdLibContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        sb.emit(vm.OpCode.PUSHNULL)
        sb.emit_push(1)  # arg len
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(0xF)  # CallFlags.ALL
        sb.emit_push("jsonSerialize")
        sb.emit_push(contracts.StdLibContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        sb.emit(vm.OpCode.NEWMAP)
        sb.emit(vm.OpCode.DUP)
        sb.emit_push("key")
        sb.emit_push("value")
        sb.emit(vm.OpCode.SETITEM)
        sb.emit_push(1)  # arg len
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(0xF)  # CallFlags.ALL
        sb.emit_push("jsonSerialize")
        sb.emit_push(contracts.StdLibContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        data = sb.to_array()

        engine = test_engine(has_snapshot=True)
        engine.load_script(vm.Script(data))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)

        def pop_to_human_readable():
            return binascii.unhexlify(str(engine.result_stack.pop()).encode()).decode()

        self.assertEqual('{"key":"value"}', pop_to_human_readable())
        self.assertEqual('null', pop_to_human_readable())
        self.assertEqual('"test"', pop_to_human_readable())
        self.assertEqual('true', pop_to_human_readable())
        self.assertEqual('5', pop_to_human_readable())

    def test_json_deserialization(self):
        script = vm.ScriptBuilder()
        script.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "jsonDeserialize", ["{\"key\":\"value\"}"])
        script.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "jsonDeserialize", ["null"])

        engine = test_engine(has_snapshot=True)
        data = script.to_array()
        engine.load_script(vm.Script(data))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(2, len(engine.result_stack._items))
        self.assertIsInstance(engine.result_stack.pop(), vm.NullStackItem)
        r = engine.result_stack.pop()
        self.assertIsInstance(r, vm.MapStackItem)
        self.assertEqual(1, len(r))
        self.assertEqual(vm.ByteStringStackItem("key"), r.keys()[0])
        self.assertEqual(vm.ByteStringStackItem("value"), r.values()[0])

    def test_atoi(self):
        engine = test_engine(has_snapshot=True)
        original_item = b'100'
        base = 10
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "atoi", [original_item, base])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(100), item)

        engine = test_engine(has_snapshot=True)
        original_item = b'64'
        base = 16
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "atoi", [original_item, base])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(100), item)

        engine = test_engine(has_snapshot=True)
        invalid_base = 2
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "atoi", [original_item, invalid_base])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()

        self.assertEqual(vm.VMState.FAULT, engine.state)
        self.assertIn("Invalid base specified", engine.exception_message)

    def test_itoa(self):
        engine = test_engine(has_snapshot=True)
        original_item = 100
        base = 10
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "itoa", [original_item, base])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.pop()
        self.assertEqual('100', item.to_array().decode('utf-8'))

        engine = test_engine(has_snapshot=True)
        base = 16
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "itoa", [original_item, base])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.pop()
        self.assertEqual('64', item.to_array().decode('utf-8'))

        engine = test_engine(has_snapshot=True)
        invalid_base = 2
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "itoa", [original_item, invalid_base])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()

        self.assertEqual(vm.VMState.FAULT, engine.state)
        self.assertIn("Invalid base specified", engine.exception_message)

    def test_base64_encode(self):
        engine = test_engine(has_snapshot=True)
        original_item = 100
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "base64Encode", [original_item])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.peek()
        self.assertEqual('ZA==', item.to_array().decode())

    def test_base64_decode(self):
        engine = test_engine(has_snapshot=True)
        original_item = 100
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "base64Encode", [original_item])
        # now take the results of the "base64Encode" call and call "base64Decode" on the StdLib contract
        sb.emit_push(1)  # arg len
        sb.emit(vm.OpCode.PACK)  # pack the results of "base64Encode" as the arguments for the next call
        sb.emit_push(0xF)  # CallFlags.ALL
        sb.emit_push("base64Decode")
        sb.emit_push(contracts.StdLibContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.pop()
        self.assertEqual(original_item, int(item.to_biginteger()))

    def test_base58_encode(self):
        engine = test_engine(has_snapshot=True)
        original_item = 100
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "base58Encode", [original_item])
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.peek()
        self.assertEqual('2j', item.to_array().decode())

    def test_base58_decode(self):
        engine = test_engine(has_snapshot=True)
        original_item = 100
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call_with_args(contracts.StdLibContract().hash, "base58Encode", [original_item])
        # now take the results of the "base58Encode" call and call "base64Decode" on the StdLib contract
        sb.emit_push(1)
        sb.emit(vm.OpCode.PACK)  # pack the results of "base58Encode" as the arguments for the next call
        sb.emit_push(0xF)  # CallFlags.ALL
        sb.emit_push("base58Decode")
        sb.emit_push(contracts.StdLibContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        item = engine.result_stack.pop()
        self.assertEqual(original_item, int(item.to_biginteger()))
