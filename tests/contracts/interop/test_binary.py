import unittest
from neo3 import vm
from neo3 import contracts
from neo3.contracts import interop
from .utils import test_engine


class BinaryInteropTestCase(unittest.TestCase):
    def test_serialization(self):
        engine = test_engine()
        engine.push(vm.IntegerStackItem(100))
        engine.invoke_syscall_by_name("System.Binary.Serialize")
        item = engine.pop()
        self.assertIsInstance(item, vm.ByteStringStackItem)
        self.assertEqual(b'\x21\x01\x64', item.to_array())

        # Create an item with data larger than engine.MAX_ITEM_SIZE
        # this should fail in the BinarySerializer class
        engine.push(vm.ByteStringStackItem(b'\x01' * (1024 * 1024 * 2)))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Binary.Serialize")
        self.assertEqual("Output length exceeds max size", str(context.exception))

    def test_deserialization(self):
        engine = test_engine()
        original_item = vm.IntegerStackItem(100)
        engine.push(original_item)
        engine.invoke_syscall_by_name("System.Binary.Serialize")
        engine.invoke_syscall_by_name("System.Binary.Deserialize")
        item = engine.pop()
        self.assertEqual(original_item, item)

        engine.push(vm.ByteStringStackItem(b'\xfa\x01'))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Binary.Deserialize")
        self.assertEqual("Invalid format", str(context.exception))

    def test_base64(self):
        engine = test_engine()
        original_item = vm.IntegerStackItem(100)
        engine.push(original_item)
        engine.invoke_syscall_by_name("System.Binary.Base64Encode")
        item = engine.pop()
        self.assertEqual('ZA==', item.to_array().decode())

        engine.push(item)
        engine.invoke_syscall_by_name("System.Binary.Base64Decode")
        item = engine.pop()
        self.assertEqual(original_item, vm.IntegerStackItem(item.to_array()))
