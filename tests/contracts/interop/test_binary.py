import unittest
from neo3 import vm
from neo3 import contracts
from neo3.contracts import interop


class BinaryInteropTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = vm.ApplicationEngine(contracts.TriggerType.APPLICATION, object(), object(), 1000)
        cls.engine.load_script(vm.Script(b''))

    def test_serialization(self):
        self.engine.push(vm.IntegerStackItem(vm.BigInteger(100)))
        self.assertTrue(interop.InteropService.invoke_with_name(self.engine, "System.Binary.Serialize"))
        item = self.engine.current_context.evaluation_stack.pop()
        self.assertEqual(b'\x21\x01\x64', item.get_bytes())

        # Create an item with data larger than engine.MAX_ITEM_SIZE
        # this should fail in the BinarySerializer class
        self.engine.push(vm.ByteStringStackItem(b'\x01' * (1024 * 1024 * 2)))
        with self.assertRaises(ValueError) as context:
            interop.InteropService.invoke_with_name(self.engine, "System.Binary.Serialize")
        self.assertEqual("Output length exceeds max size", str(context.exception))

    def test_deserialization(self):
        bi = vm.BigInteger(100)
        self.engine.push(vm.IntegerStackItem(bi))
        self.assertTrue(interop.InteropService.invoke_with_name(self.engine, "System.Binary.Serialize"))
        self.assertTrue(interop.InteropService.invoke_with_name(self.engine, "System.Binary.Deserialize"))
        item = self.engine.current_context.evaluation_stack.pop().to_biginteger()
        self.assertEqual(bi, item)

        self.engine.push(vm.ByteStringStackItem(b'\xfa\x01'))
        with self.assertRaises(ValueError) as context:
            interop.InteropService.invoke_with_name(self.engine, "System.Binary.Deserialize")
        self.assertEqual("Invalid format", str(context.exception))
