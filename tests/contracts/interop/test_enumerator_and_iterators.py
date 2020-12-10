import unittest
from neo3 import vm
from neo3.contracts.interop.enumerator import ArrayWrapper, MapWrapper, ByteArrayWrapper
from .utils import syscall_name_to_int
from .utils import test_engine


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
        self.assertEqual(key1, r.key())
        self.assertEqual(item1, r.value())
        self.assertTrue(r.next())
        self.assertEqual(key2, r.key())
        self.assertEqual(item2, r.value())
        # exhausted the iterator
        self.assertFalse(r.next())
        with self.assertRaises(ValueError) as context:
            r.key()
        self.assertEqual("Cannot call 'key' without having advanced the iterator at least once", str(context.exception))
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
            r.key()
        self.assertEqual("Cannot call 'key' without having advanced the iterator at least once", str(context.exception))
        with self.assertRaises(ValueError) as context:
            r.value()
        self.assertEqual("Cannot call 'value' without having advanced the iterator at least once", str(context.exception))

        self.assertTrue(r.next())
        self.assertEqual(vm.IntegerStackItem(0), r.key())
        self.assertEqual(vm.IntegerStackItem(3), r.value())

        self.assertTrue(r.next())
        self.assertEqual(vm.IntegerStackItem(1), r.key())
        self.assertEqual(vm.IntegerStackItem(4), r.value())

        self.assertFalse(r.next())
        self.assertEqual(vm.IntegerStackItem(1), r.key())
        self.assertEqual(vm.IntegerStackItem(4), r.value())


    def test_iterator_create_from_primitive_type(self):
        engine = test_engine()
        buffer = vm.ByteStringStackItem(b'\x03\x04')
        engine.push(buffer)
        r = engine.invoke_syscall_by_name("System.Iterator.Create")
        self.assertIsInstance(r, ByteArrayWrapper)
        self.assertTrue(r.next())
        self.assertEqual(vm.IntegerStackItem(0), r.key())
        self.assertEqual(vm.IntegerStackItem(3), r.value())

        self.assertTrue(r.next())
        self.assertEqual(vm.IntegerStackItem(1), r.key())
        self.assertEqual(vm.IntegerStackItem(4), r.value())

        self.assertFalse(r.next())
        self.assertEqual(vm.IntegerStackItem(1), r.key())
        self.assertEqual(vm.IntegerStackItem(4), r.value())

    def test_iterator_create_invalid_type(self):
        engine = test_engine()
        item = vm.NullStackItem()
        engine.push(item)
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Iterator.Create")
        self.assertEqual(f"Cannot create iterator from unsupported type: {type(item)}", str(context.exception))

    def test_iterator_key_and_value(self):
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
        script.emit_syscall(syscall_name_to_int("System.Enumerator.Next"))
        # clear the result of `Enumerator.Next()`, we assume it will say True
        script.emit(vm.OpCode.DROP)

        script.emit(vm.OpCode.LDLOC0)
        script.emit_syscall(syscall_name_to_int("System.Iterator.Key"))

        script.emit(vm.OpCode.LDLOC0)
        script.emit_syscall(syscall_name_to_int("System.Enumerator.Value"))

        engine.load_script(vm.Script(script.to_array()))
        engine.push(map_item)
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        # we expect a key and a value on their
        self.assertEqual(len(engine.result_stack), 2)
        # value was put on last, comes of first
        value = engine.result_stack.pop()
        self.assertEqual(item1, value)

        key = engine.result_stack.pop()
        self.assertEqual(key1, key)

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

    def test_iterator_values(self):
        # we iterate over just the 2 values in our map
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
        script.emit_syscall(syscall_name_to_int("System.Iterator.Values"))
        script.emit(vm.OpCode.STLOC0)

        # we have 2 values in our map, so we can repeat this sequence twice
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
        # we expect a 2 values on there
        self.assertEqual(len(engine.result_stack), 2)
        # item2 was put on last, comes of first
        item2_from_engine = engine.result_stack.pop()
        self.assertEqual(item2, item2_from_engine)

        item1_from_engine = engine.result_stack.pop()
        self.assertEqual(item1, item1_from_engine)

    def test_iterator_concat(self):
        engine = test_engine()
        array1 = vm.ArrayStackItem(engine.reference_counter)
        item1 = vm.IntegerStackItem(123)
        array1.append(item1)

        array2 = vm.ArrayStackItem(engine.reference_counter)
        item2 = vm.IntegerStackItem(456)
        array2.append(item2)

        script = vm.ScriptBuilder()
        # initialize 1 slot to store the iterator in
        script.emit(vm.OpCode.INITSLOT)
        script.emit_raw(b'\x01\x00')

        # stack state at this point is
        # * array2
        # * array1
        script.emit_syscall(syscall_name_to_int("System.Iterator.Create"))
        # Iterator.create removed array2 and places an iterator on the stack, we store this in a variables slot
        script.emit(vm.OpCode.STLOC0)
        # so we can call iterator.create again, with array1 as argument
        script.emit_syscall(syscall_name_to_int("System.Iterator.Create"))
        # we restore the iterator of array2
        script.emit(vm.OpCode.LDLOC0)
        # we concat and get [array2, array1]
        script.emit_syscall(syscall_name_to_int("System.Iterator.Concat"))
        script.emit(vm.OpCode.STLOC0)

        # have just 1 value per iterator, so we call next and value just 2 times
        for _ in range(2):
            script.emit(vm.OpCode.LDLOC0)
            script.emit_syscall(syscall_name_to_int("System.Enumerator.Next"))
            script.emit(vm.OpCode.DROP)
            script.emit(vm.OpCode.LDLOC0)
            script.emit_syscall(syscall_name_to_int("System.Enumerator.Value"))

        # we add a call to key for coverage
        script.emit(vm.OpCode.LDLOC0)
        script.emit_syscall(syscall_name_to_int("System.Iterator.Key"))

        engine.load_script(vm.Script(script.to_array()))
        engine.push(array1)
        engine.push(array2)
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        # we expect 3 values on there, 1 key/array index and 2 array values
        self.assertEqual(len(engine.result_stack), 3)

        key_from_engine = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(0), key_from_engine)

        item1_from_engine = engine.result_stack.pop()
        self.assertEqual(item1, item1_from_engine)

        # item2 was put on last, comes of first
        item2_from_engine = engine.result_stack.pop()
        self.assertEqual(item2, item2_from_engine)

    def test_array_key_exception(self):
        """
        calling `key` on an array iterator without having called `next` should fail
        """
        engine = test_engine()
        array = vm.ArrayStackItem(engine.reference_counter)
        item = vm.IntegerStackItem(123)
        array.append(item)
        engine.push(array)
        engine.invoke_syscall_by_name("System.Iterator.Create")
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Iterator.Key")
        self.assertEqual("Cannot call 'key' without having advanced the iterator at least once", str(context.exception))

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
            engine.invoke_syscall_by_name("System.Enumerator.Value")
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
            engine.invoke_syscall_by_name("System.Enumerator.Value")
        self.assertEqual("Cannot call 'value' without having advanced the iterator at least once", str(context.exception))

    def test_enumerator_create_from_array(self):
        engine = test_engine()
        array = vm.ArrayStackItem(engine.reference_counter)
        item1 = vm.ByteStringStackItem(b'\x01')
        array.append(item1)
        engine.push(array)
        r = engine.invoke_syscall_by_name("System.Enumerator.Create")
        self.assertIsInstance(r, ArrayWrapper)
        self.assertTrue(r.next())
        self.assertEqual(item1, r.value())

    def test_enumerator_create_from_primitive(self):
        engine = test_engine()
        item1 = vm.IntegerStackItem(123)
        engine.push(item1)
        r = engine.invoke_syscall_by_name("System.Enumerator.Create")
        self.assertIsInstance(r, ByteArrayWrapper)
        self.assertTrue(r.next())
        self.assertEqual(item1, r.value())

    def test_enumerator_create_invalid_type(self):
        engine = test_engine()
        item = vm.NullStackItem()
        engine.push(item)
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Enumerator.Create")
        self.assertEqual(f"Cannot create iterator from unsupported type: {type(item)}", str(context.exception))

    def test_enumerator_concat(self):
        engine = test_engine()
        array1 = vm.ArrayStackItem(engine.reference_counter)
        item1 = vm.IntegerStackItem(123)
        array1.append(item1)

        array2 = vm.ArrayStackItem(engine.reference_counter)
        item2 = vm.IntegerStackItem(456)
        array2.append(item2)

        script = vm.ScriptBuilder()
        # initialize 1 slot to store the iterator in
        script.emit(vm.OpCode.INITSLOT)
        script.emit_raw(b'\x01\x00')

        script.emit_syscall(syscall_name_to_int("System.Enumerator.Create"))
        # Iterator.create removed array2 and places an iterator on the stack, we store this in a variables slot
        script.emit(vm.OpCode.STLOC0)
        # so we can call iterator.create again, with array1 as argument
        script.emit_syscall(syscall_name_to_int("System.Enumerator.Create"))
        # we restore the iterator of array2
        script.emit(vm.OpCode.LDLOC0)
        # we concat and get [array2, array1]
        script.emit_syscall(syscall_name_to_int("System.Enumerator.Concat"))
        script.emit(vm.OpCode.STLOC0)

        # have just 1 value per iterator, so we call next and value just 2 times
        for _ in range(2):
            script.emit(vm.OpCode.LDLOC0)
            script.emit_syscall(syscall_name_to_int("System.Enumerator.Next"))
            script.emit(vm.OpCode.DROP)
            script.emit(vm.OpCode.LDLOC0)
            script.emit_syscall(syscall_name_to_int("System.Enumerator.Value"))

        engine.load_script(vm.Script(script.to_array()))
        engine.push(array1)
        engine.push(array2)
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        # we expect 2 array values on the stack
        self.assertEqual(len(engine.result_stack), 2)

        item1_from_engine = engine.result_stack.pop()
        self.assertEqual(item1, item1_from_engine)

        # item2 was put on last, comes of first
        item2_from_engine = engine.result_stack.pop()
        self.assertEqual(item2, item2_from_engine)
