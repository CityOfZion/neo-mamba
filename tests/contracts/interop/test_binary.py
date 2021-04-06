import unittest
from neo3 import vm
from tests.contracts.interop.utils import test_engine


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

    def test_base58(self):
        engine = test_engine()
        original_item = vm.IntegerStackItem(100)
        engine.push(original_item)
        engine.invoke_syscall_by_name("System.Binary.Base58Encode")
        item = engine.pop()
        self.assertEqual('2j', item.to_array().decode())

        engine.push(item)
        engine.invoke_syscall_by_name("System.Binary.Base58Decode")
        item = engine.pop()
        self.assertEqual(original_item, vm.IntegerStackItem(item.to_array()))

    def test_itoa(self):
        engine = test_engine()
        original_item = vm.IntegerStackItem(100)
        base = vm.IntegerStackItem(10)
        engine.push(base)
        engine.push(original_item)
        engine.invoke_syscall_by_name("System.Binary.Itoa")
        item = engine.pop()
        self.assertEqual('100', item.to_array().decode('utf-8'))

        engine = test_engine()
        base = vm.IntegerStackItem(16)
        engine.push(base)
        engine.push(original_item)
        engine.invoke_syscall_by_name("System.Binary.Itoa")
        item = engine.pop()
        self.assertEqual('64', item.to_array().decode('utf-8'))

        engine = test_engine()
        invalid_base = vm.IntegerStackItem(2)
        engine.push(invalid_base)
        engine.push(original_item)
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Binary.Itoa")
        self.assertIn("Invalid base specified", str(context.exception))

    def test_atoi(self):
        engine = test_engine()
        original_item = vm.ByteStringStackItem(b'100')
        base = vm.IntegerStackItem(10)
        engine.push(base)
        engine.push(original_item)
        engine.invoke_syscall_by_name("System.Binary.Atoi")
        item = engine.pop()
        self.assertEqual(vm.IntegerStackItem(100), item)

        engine = test_engine()
        original_item = vm.ByteStringStackItem(b'64')
        base = vm.IntegerStackItem(16)
        engine.push(base)
        engine.push(original_item)
        engine.invoke_syscall_by_name("System.Binary.Atoi")
        item = engine.pop()
        self.assertEqual(vm.IntegerStackItem(100), item)

        engine = test_engine()
        invalid_base = vm.IntegerStackItem(2)
        engine.push(invalid_base)
        engine.push(original_item)
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Binary.Atoi")
        self.assertIn("Invalid base specified", str(context.exception))
