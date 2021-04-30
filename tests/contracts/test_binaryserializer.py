import unittest
from neo3 import vm, contracts


class BinarySerializerTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    @classmethod
    def setUpClass(cls) -> None:
        cls.reference_counter = vm.ReferenceCounter()

    def test_with_map(self):
        """
        var m = new Map(new ReferenceCounter());
        var i = new Integer(new BigInteger(1));
        var i2 = new Integer(new BigInteger(2));
        var b = new Neo.VM.Types.Boolean(true);
        m[i] = b;
        m[i2] = b;

        """
        # moved outside of multiline comment because pycharm is broken: https://youtrack.jetbrains.com/issue/PY-43117
        #Console.WriteLine($"b'\\x{BitConverter.ToString(BinarySerializer.Serialize(m, 999)).Replace("-", @"\x")}'");
        m = vm.MapStackItem(self.reference_counter)
        i = vm.IntegerStackItem(vm.BigInteger(1))
        i2 = vm.IntegerStackItem(vm.BigInteger(2))
        b = vm.BooleanStackItem(True)
        m[i] = b
        m[i2] = b
        expected = b'\x48\x02\x21\x01\x01\x20\x01\x21\x01\x02\x20\x01'
        out = contracts.BinarySerializer.serialize(m, 999)
        self.assertEqual(expected, out)

        # now we add a reference to ourselves.
        with self.assertRaises(ValueError) as context:
            m[i] = m
            contracts.BinarySerializer.serialize(m, 999)
        self.assertEqual("Item already exists", str(context.exception))

        # now test deserialization
        m[i] = b # restore m[i] to original content
        new_m = contracts.BinarySerializer.deserialize(out, 2048, self.reference_counter)
        self.assertEqual(len(m), len(new_m))
        self.assertEqual(m.keys(), new_m.keys())
        self.assertEqual(m.values(), new_m.values())

    def test_with_array(self):
        """
        var a = new Neo.VM.Types.Array();
        var i = new Integer(new BigInteger(1));
        var i2 = new Integer(new BigInteger(2));
        a.Add(i);
        a.Add(i2);
        """
        # Console.WriteLine($"b'\\x{BitConverter.ToString(BinarySerializer.Serialize(a, 999)).Replace("-", @"\x")}'");
        # moved outside of multiline comment because pycharm is broken: https://youtrack.jetbrains.com/issue/PY-43117
        i = vm.IntegerStackItem(vm.BigInteger(1))
        i2 = vm.IntegerStackItem(vm.BigInteger(2))
        a = vm.ArrayStackItem(self.reference_counter)
        a.append(i)
        a.append(i2)
        expected = b'\x40\x02\x21\x01\x01\x21\x01\x02'
        out = contracts.BinarySerializer.serialize(a, 999)
        self.assertEqual(expected, out)

        # now we add a reference to ourselves.
        with self.assertRaises(ValueError) as context:
            a.append(a)
            contracts.BinarySerializer.serialize(a, 999)
        self.assertEqual("Item already exists", str(context.exception))

        # now test deserialization
        # first remove the reference to self
        a.remove(len(a) - 1)
        new_a = contracts.BinarySerializer.deserialize(out, 2048, self.reference_counter)
        self.assertIsInstance(a, vm.ArrayStackItem)
        self.assertEqual(a._items, new_a._items)

    def test_with_null(self):
        n = vm.NullStackItem()
        x = contracts.BinarySerializer.serialize(n, 999)
        self.assertEqual(b'\x00', x)

        new_n = contracts.BinarySerializer.deserialize(x, 1, self.reference_counter)
        self.assertIsInstance(new_n, vm.NullStackItem)

    def test_serialize_with_invalid_stackitem(self):
        s = vm.Script(b'')
        p = vm.PointerStackItem(s, 0)

        with self.assertRaises(ValueError) as context:
            contracts.BinarySerializer.serialize(p, 999)
        self.assertIn("Cannot serialize", str(context.exception))

    def test_serialize_with_exceeding_max_length(self):
        with self.assertRaises(ValueError) as context:
            n = vm.NullStackItem()
            contracts.BinarySerializer.serialize(n, 0)
        self.assertEqual("Output length exceeds max size", str(context.exception))

    def test_deserialize_invalid_data(self):
        with self.assertRaises(ValueError) as context:
            contracts.BinarySerializer.deserialize(b'', 1, self.reference_counter)
        self.assertEqual("Nothing to deserialize", str(context.exception))

    def test_deserialize_bytestring(self):
        data = b'\x01\x02'
        b = vm.ByteStringStackItem(data)
        b_serialized = contracts.BinarySerializer.serialize(b, 999)
        new_b = contracts.BinarySerializer.deserialize(b_serialized, 999, self.reference_counter)
        self.assertIsInstance(new_b, vm.ByteStringStackItem)
        self.assertEqual(new_b, b)

    def test_deserialize_buffer(self):
        data = b'\x01\x02'
        b = vm.BufferStackItem(data)
        b_serialized = contracts.BinarySerializer.serialize(b, 999)
        new_b = contracts.BinarySerializer.deserialize(b_serialized, 999, self.reference_counter)
        self.assertIsInstance(new_b, vm.BufferStackItem)
        self.assertEqual(new_b.to_array(), b.to_array())

    def test_deserialize_struct(self):
        s = vm.StructStackItem(self.reference_counter)
        bool1 = vm.BooleanStackItem(True)
        bool2 = vm.BooleanStackItem(False)
        s.append([bool1, bool2])
        s_serialized = contracts.BinarySerializer.serialize(s, 999)
        new_s = contracts.BinarySerializer.deserialize(s_serialized, 999, self.reference_counter)
        self.assertIsInstance(new_s, vm.StructStackItem)
        for l, r in zip(new_s._items, s._items):
            self.assertEqual(l, r)

    def test_deserialize_with_invalid_format(self):
        data = b'\x01\x02'
        b = vm.BufferStackItem(data)
        b_serialized = bytearray(contracts.BinarySerializer.serialize(b, 999))
        b_serialized[0] = 0xFF # non existing stackitem type
        with self.assertRaises(ValueError) as context:
            contracts.BinarySerializer.deserialize(b_serialized, 999, self.reference_counter)
        self.assertEqual("Invalid format", str(context.exception))