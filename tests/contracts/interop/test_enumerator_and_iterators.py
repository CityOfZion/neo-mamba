import unittest
from neo3 import vm
from neo3.contracts.interop.enumerator import ArrayWrapper, MapWrapper, ByteArrayWrapper
from tests.contracts.interop.utils import syscall_name_to_int, test_engine


class EnumeratorIteratorTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_iterator_create_from_array(self):
        engine = test_engine()
        array = vm.ArrayStackItem(engine.reference_counter)
        item1 = vm.ByteStringStackItem(b'\x01')
        item2 = vm.ByteStringStackItem(b'\x02')
        array.append(item1)
        array.append(item2)
        engine.push(array)
        r = engine.invoke_syscall_by_name("System.Iterator.Create")
        self.assertIsInstance(r, ArrayWrapper)
        self.assertTrue(r.next())
        self.assertEqual(item1, r.value())
        self.assertTrue(r.next())
        self.assertEqual(item2, r.value())
        self.assertFalse(r.next())

    def test_iterator_create_from_map(self):
        engine = test_engine()
        map_item = vm.MapStackItem(engine.reference_counter)
        key1 = vm.IntegerStackItem(1)
        key2 = vm.IntegerStackItem(3)
        item1 = vm.IntegerStackItem(2)
        item2 = vm.IntegerStackItem(4)
        map_item[key1] = item1
        map_item[key2] = item2
        engine.push(map_item)
        r = engine.invoke_syscall_by_name("System.Iterator.Create")
        self.assertIsInstance(r, MapWrapper)
        self.assertTrue(r.next())
        value = r.value()
        self.assertIsInstance(value, vm.StructStackItem)
        self.assertEqual(2, len(value))
        self.assertEqual(key1, value[0])
        self.assertEqual(item1, value[1])
        self.assertTrue(r.next())
        value = r.value()
        self.assertIsInstance(value, vm.StructStackItem)
        self.assertEqual(2, len(value))
        self.assertEqual(key2, value[0])
        self.assertEqual(item2, value[1])
        # exhausted the iterator
        self.assertFalse(r.next())
        with self.assertRaises(ValueError) as context:
            r.value()
        self.assertEqual("Cannot call 'value' without having advanced the iterator at least once", str(context.exception))

    def test_iterator_create_from_buffer(self):
        engine = test_engine()
        buffer = vm.BufferStackItem(b'\x03\x04')
        engine.push(buffer)
        r = engine.invoke_syscall_by_name("System.Iterator.Create")
        self.assertIsInstance(r, ByteArrayWrapper)
        with self.assertRaises(ValueError) as context:
            r.value()
        self.assertEqual("Cannot call 'value' without having advanced the iterator at least once", str(context.exception))

        self.assertTrue(r.next())
        self.assertEqual(vm.IntegerStackItem(3), r.value())

        self.assertTrue(r.next())
        self.assertEqual(vm.IntegerStackItem(4), r.value())

        self.assertFalse(r.next())
        self.assertEqual(vm.IntegerStackItem(4), r.value())

    def test_iterator_create_from_primitive_type(self):
        engine = test_engine()
        buffer = vm.ByteStringStackItem(b'\x03\x04')
        engine.push(buffer)
        r = engine.invoke_syscall_by_name("System.Iterator.Create")
        self.assertIsInstance(r, ByteArrayWrapper)
        self.assertTrue(r.next())
        self.assertEqual(vm.IntegerStackItem(3), r.value())

        self.assertTrue(r.next())
        self.assertEqual(vm.IntegerStackItem(4), r.value())

        self.assertFalse(r.next())
        self.assertEqual(vm.IntegerStackItem(4), r.value())

    def test_iterator_create_invalid_type(self):
        engine = test_engine()
        item = vm.NullStackItem()
        engine.push(item)
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Iterator.Create")
        self.assertEqual(f"Cannot create iterator from unsupported type: {type(item)}", str(context.exception))

    def test_iterator_next_and_value(self):
        engine = test_engine()
        # same map setup code as test_iterator_create_from_map()
        map_item = vm.MapStackItem(engine.reference_counter)
        key1 = vm.IntegerStackItem(1)
        key2 = vm.IntegerStackItem(3)
        item1 = vm.IntegerStackItem(2)
        item2 = vm.IntegerStackItem(4)
        map_item[key1] = item1
        map_item[key2] = item2

        # we build a script such that we can create an interator, move it forward and retrieves the key and values
        script = vm.ScriptBuilder()
        # initialize 1 slot to store the iterator in
        script.emit(vm.OpCode.INITSLOT)
        script.emit_raw(b'\x01\x00')

        script.emit_syscall(syscall_name_to_int("System.Iterator.Create"))
        # save the iterator and retrieve it again
        script.emit(vm.OpCode.STLOC0)
        script.emit(vm.OpCode.LDLOC0)
        script.emit_syscall(syscall_name_to_int("System.Iterator.Next"))
        # clear the result of `iterator.Next()`, we assume it will say True
        script.emit(vm.OpCode.DROP)

        script.emit(vm.OpCode.LDLOC0)
        script.emit_syscall(syscall_name_to_int("System.Iterator.Value"))

        engine.load_script(vm.Script(script.to_array()))
        engine.push(map_item)
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        # we expect a key and a value wrapped in a struct
        self.assertEqual(len(engine.result_stack), 1)
        struct = engine.result_stack.pop()
        self.assertIsInstance(struct, vm.StructStackItem)
        self.assertEqual(2, len(struct))

        self.assertEqual(key1, struct[0])
        self.assertEqual(item1, struct[1])

    @unittest.SkipTest
    def test_iterator_keys(self):
        # we iterate over just the 2 keys in our map
        engine = test_engine()
        map_item = vm.MapStackItem(engine.reference_counter)
        key1 = vm.IntegerStackItem(1)
        key2 = vm.IntegerStackItem(3)
        item1 = vm.IntegerStackItem(2)
        item2 = vm.IntegerStackItem(4)
        map_item[key1] = item1
        map_item[key2] = item2

        script = vm.ScriptBuilder()
        # initialize 1 slot to store the iterator in
        script.emit(vm.OpCode.INITSLOT)
        script.emit_raw(b'\x01\x00')

        script.emit_syscall(syscall_name_to_int("System.Iterator.Create"))
        script.emit_syscall(syscall_name_to_int("System.Iterator.Keys"))
        script.emit(vm.OpCode.STLOC0)

        # we have 2 keys in our map, so we can repeat this sequence twice
        for _ in range(2):
            script.emit(vm.OpCode.LDLOC0)
            script.emit_syscall(syscall_name_to_int("System.Enumerator.Next"))
            script.emit(vm.OpCode.DROP)
            script.emit(vm.OpCode.LDLOC0)
            script.emit_syscall(syscall_name_to_int("System.Enumerator.Value"))

        engine.load_script(vm.Script(script.to_array()))
        engine.push(map_item)
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        # we expect a 2 keys on there
        self.assertEqual(len(engine.result_stack), 2)
        # key2 was put on last, comes of first
        key2_from_engine = engine.result_stack.pop()
        self.assertEqual(key2, key2_from_engine)

        key1_from_engine = engine.result_stack.pop()
        self.assertEqual(key1, key1_from_engine)

    def test_array_value_exception(self):
        """
        calling `value` on an array iterator without having called `next` should fail
        """
        engine = test_engine()
        array = vm.ArrayStackItem(engine.reference_counter)
        item = vm.IntegerStackItem(123)
        array.append(item)
        engine.push(array)
        engine.invoke_syscall_by_name("System.Iterator.Create")

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Iterator.Value")
        self.assertEqual("Cannot call 'value' without having advanced the iterator at least once", str(context.exception))

    def test_bytearray_value_exception(self):
        """
        calling `value` on an ByteArray iterator without having called `next` should fail
        """
        engine = test_engine()
        item = vm.IntegerStackItem(123)
        engine.push(item)
        engine.invoke_syscall_by_name("System.Iterator.Create")

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Iterator.Value")
        self.assertEqual("Cannot call 'value' without having advanced the iterator at least once", str(context.exception))
