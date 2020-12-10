import unittest
from neo3.core import utils, serialization
from neo3.core.serialization import BinaryReader, BinaryWriter
from enum import IntEnum


class DummyEnum(IntEnum):
    DEFAULT = 0


class DummySerializable(serialization.ISerializable):

    def serialize(self, writer: BinaryWriter) -> None:
        pass

    def deserialize(self, reader: BinaryReader) -> None:
        pass

    def __len__(self):
        return 2


class VarSizeTestCase(unittest.TestCase):
    def test_varsize_int(self):
        self.assertEqual(1, utils.get_var_size(0xFC))
        self.assertEqual(3, utils.get_var_size(0xFD))
        self.assertEqual(3, utils.get_var_size(0xFFFF))
        self.assertEqual(5, utils.get_var_size(0xFFFF + 1))

    def test_varsize_string(self):
        input = "abc"
        self.assertEqual(1+len(input), utils.get_var_size(input))

        input = "a" * 0xFC
        self.assertEqual(1 + len(input), utils.get_var_size(input))

        # boundary check
        input = "a" * 0xFD
        self.assertEqual(3 + len(input), utils.get_var_size(input))

        input = "a" * 0xFFFF
        self.assertEqual(3 + len(input), utils.get_var_size(input))

        input = "a" * (0xFFFF + 1)
        self.assertEqual(5 + len(input), utils.get_var_size(input))

    def test_iterables(self):
        iterable = []
        self.assertEqual(1, utils.get_var_size(iterable))

        iterable = b'\x01\x02'
        self.assertEqual(1 + len(iterable), utils.get_var_size(iterable))

        iterable = [DummySerializable(), DummySerializable()]
        fixed_dummy_size = 2
        self.assertEqual(1 + (2 * fixed_dummy_size), utils.get_var_size(iterable))

        # so far NEO only has byte enums, so the length is fixed to 1
        iterable = [DummyEnum.DEFAULT, DummyEnum.DEFAULT]
        self.assertEqual(1 + 2, utils.get_var_size(iterable))

        # test unsupported type in iterable
        iterable = [object()]
        with self.assertRaises(TypeError) as context:
            utils.get_var_size(iterable)
        self.assertIn("Cannot accurately determine size of objects that do not", str(context.exception))

    def test_not_supported_objects(self):
        with self.assertRaises(ValueError) as context:
            utils.get_var_size(object())
        self.assertIn("NOT SUPPORTED", str(context.exception))
