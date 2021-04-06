import unittest
import binascii
from neo3 import vm
from neo3 import contracts
from tests.contracts.interop.utils import syscall_name_to_int


class JSONInteropTestCase(unittest.TestCase):
    def test_serialization(self):
        script = vm.ScriptBuilder()
        script.emit_push(5)
        script.emit_syscall(syscall_name_to_int("System.Json.Serialize"))
        script.emit(vm.OpCode.PUSH0)
        script.emit(vm.OpCode.NOT)
        script.emit_syscall(syscall_name_to_int("System.Json.Serialize"))
        script.emit_push("test")
        script.emit_syscall(syscall_name_to_int("System.Json.Serialize"))
        script.emit(vm.OpCode.PUSHNULL)
        script.emit_syscall(syscall_name_to_int("System.Json.Serialize"))
        script.emit(vm.OpCode.NEWMAP)
        script.emit(vm.OpCode.DUP)
        script.emit_push("key")
        script.emit_push("value")
        script.emit(vm.OpCode.SETITEM)
        script.emit_syscall(syscall_name_to_int("System.Json.Serialize"))

        data = script.to_array()

        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, None, None, 0, True)
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

    def test_deserialization(self):
        script = vm.ScriptBuilder()
        script.emit_push(123)
        script.emit_syscall(syscall_name_to_int("System.Json.Deserialize"))
        script.emit_push("null")
        script.emit_syscall(syscall_name_to_int("System.Json.Deserialize"))

        data = script.to_array()

        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, None, None, 0, True)
        engine.load_script(vm.Script(data))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(2, len(engine.result_stack._items))
        self.assertIsInstance(engine.result_stack.pop(), vm.NullStackItem)
        self.assertEqual(vm.BigInteger(123), engine.result_stack.pop().to_biginteger())
