import unittest
from neo3.api.helpers import stdlib
from neo3.core import types


class TestStdLibHelpers(unittest.TestCase):
    def test_with_map(self):
        """
        C# reference code
            var m = new Map(new ReferenceCounter());
            var i = new Integer(new BigInteger(1));
            var i2 = new Integer(new BigInteger(2));
            var b = new Neo.VM.Types.Boolean(true);
            m[i] = b;
            m[i2] = b;
        """
        # moved outside of multiline comment because pycharm is broken: https://youtrack.jetbrains.com/issue/PY-43117
        # Console.WriteLine($"b'\\x{BitConverter.ToString(BinarySerializer.Serialize(m, 999)).Replace("-", @"\x")}'");

        data = b"\x48\x02\x21\x01\x01\x20\x01\x21\x01\x02\x20\x01"

        expected = {1: True, 2: True}
        results: dict = stdlib.binary_deserialize(data)

        self.assertEqual(expected, results)

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
        data = b"\x40\x02\x21\x01\x01\x21\x01\x02"
        expected = [1, 2]
        results: dict = stdlib.binary_deserialize(data)
        self.assertEqual(expected, results)

    def test_with_null(self):
        data = b"\x00"
        expected = None
        results: dict = stdlib.binary_deserialize(data)
        self.assertEqual(expected, results)

    def test_deserialize_bytestring(self):
        data = b"\x28\x02\x01\x02"
        expected = b"\x01\x02"
        results: dict = stdlib.binary_deserialize(data)
        self.assertEqual(expected, results)

    def test_deserialize_buffer(self):
        data = b"\x30\x02\x01\x02"
        expected = b"\x01\x02"
        results: dict = stdlib.binary_deserialize(data)
        self.assertEqual(expected, results)

    def test_deserialize_struct(self):
        # struct with 2 integers (1,2)
        data = b"\x41\x02\x21\x01\x01\x21\x01\x02"
        expected = [1, 2]
        results: dict = stdlib.binary_deserialize(data)
        self.assertEqual(expected, results)

    def test_invalid(self):
        data = b"\xFF"  # invalid stack item type
        with self.assertRaises(ValueError) as context:
            stdlib.binary_deserialize(data)
        self.assertIn("not a valid StackItemType", str(context.exception))

        with self.assertRaises(ValueError) as context:
            stdlib.binary_deserialize(b"")
        self.assertEqual("Nothing to deserialize", str(context.exception))


if __name__ == "__main__":
    unittest.main()
