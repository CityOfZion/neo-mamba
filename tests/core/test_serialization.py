import unittest
from neo3.core import serialization

class SerializableObj(serialization.ISerializable):
    """Helper class for tests"""
    def __init__(self, a: int = None):
        self.a = a

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint8(self.a)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.a = reader.read_uint8()

    def __len__(self):
        return 1


class ISerializableTestCase(unittest.TestCase):
    def test_deserialize_from_bytes(self):
        # test class method
        s1 = SerializableObj()
        obj = s1.deserialize_from_bytes(b'\x01')
        self.assertEqual(1, obj.a)

class BinaryReaderTestCase(unittest.TestCase):
    def test_read_bytes(self):
        with serialization.BinaryReader(b'\x01') as br:
            b = br.read_byte()
            self.assertEqual(b'\x01', b)

        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(b'') as br:
                b = br.read_byte()
        self.assertIn("Could not read byte from empty stream", str(context.exception))


        input_data = b'\x01\x02\x03'
        with serialization.BinaryReader(input_data) as br:
            b = br.read_bytes(2)
            self.assertEqual(input_data[:2], b)

        # try reading more than available
        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(input_data) as br:
                b = br.read_bytes(5)
        self.assertIn("Could not read 5 bytes from stream. Only found 3 bytes of data", str(context.exception))

    def test_read_bool(self):
        with serialization.BinaryReader(b'\x00') as br:
            b = br.read_bool()
            self.assertIsInstance(b, bool)
            self.assertFalse(b)

        with serialization.BinaryReader(b'\x01') as br:
            b = br.read_bool()
            self.assertIsInstance(b, bool)
            self.assertTrue(b)

        with serialization.BinaryReader(b'\x55') as br:
            b = br.read_bool()
            self.assertIsInstance(b, bool)
            self.assertTrue(b)

    def test_reading_uint8(self):
        input_data = b'\x01\x02'
        # make sure we read only 1 byte
        with serialization.BinaryReader(input_data) as br:
            b = br.read_uint8()
            self.assertEqual(input_data[0], b)

        # validate we read an unsigned byte
        with serialization.BinaryReader(b'\xFF') as br:
            b = br.read_uint8()
            self.assertEqual(255, b)

    def test_read_uint16(self):
        input_data = b'\x01\x02\x03'
        # make sure we read only 2 bytes
        with serialization.BinaryReader(input_data) as br:
            b = br.read_uint16()
            self.assertEqual(int.from_bytes(input_data[:2],'little'), b)

        # validate we read as unsigned
        with serialization.BinaryReader(b'\x01\xFF') as br:
            b = br.read_uint16()
            self.assertEqual(65281, b)

    def test_read_int16(self):
        input_data = b'\x01\xFF'
        with serialization.BinaryReader(input_data) as br:
            b = br.read_int16()
            self.assertEqual(-255, b)

    def test_read_uint32(self):
        input_data = b'\x01\x02\x03\x04\x05'
        # make sure we read only 4 bytes
        with serialization.BinaryReader(input_data) as br:
            b = br.read_uint32()
            self.assertEqual(int.from_bytes(input_data[:4],'little'), b)

        # validate we read as unsigned
        with serialization.BinaryReader(b'\x01\x02\x03\xFF') as br:
            b = br.read_uint32()
            self.assertEqual(4278387201, b)

    def test_read_int32(self):
        with serialization.BinaryReader(b'\x01\x02\x03\xFF') as br:
            b = br.read_int32()
            self.assertEqual(-16580095, b)

    def test_read_uint64(self):
        input_data = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09'
        # make sure we read only 4 bytes
        with serialization.BinaryReader(input_data) as br:
            b = br.read_uint64()
            self.assertEqual(int.from_bytes(input_data[:8],'little'), b)

        # validate we read as unsigned
        with serialization.BinaryReader(b'\x01\x02\x03\x04\x05\x06\x07\xFF') as br:
            b = br.read_uint64()
            self.assertEqual(18376663423120507393, b)

    def test_read_int64(self):
        with serialization.BinaryReader(b'\x01\x02\x03\x04\x05\x06\x07\xFF') as br:
            b = br.read_int64()
            self.assertEqual(-70080650589044223, b)

    def test_read_var_int(self):
        # no value
        with serialization.BinaryReader(b'\x00') as br:
            b = br.read_var_int()
            self.assertEqual(0, b)

        # a value smaller than 0xFD is encoded in 1 byte
        with serialization.BinaryReader(b'\xFC') as br:
            b = br.read_var_int()
            self.assertEqual(252, b)

        # a value smaller than 0xFFFF is encoded in 3 bytes
        input_data = b'\xfd\x01\xFF'
        with serialization.BinaryReader(input_data) as br:
            b = br.read_var_int()
            self.assertEqual(65281, b)

        # a value smaller than 0xFFFFFFFF is encoded in 5 bytes
        input_data = b'\xfe\x01\x02\x03\xFF'
        with serialization.BinaryReader(input_data) as br:
            b = br.read_var_int()
            self.assertEqual(4278387201, b)

        # a value bigger than 0xFFFFFFFF is encoded in 9 bytes
        input_data = b'\xff\x01\x02\x03\x04\x05\x06\x07\x08\xFF'
        with serialization.BinaryReader(input_data) as br:
            b = br.read_var_int()
            self.assertEqual(578437695752307201, b)

        # test reader with max size
        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(b'\xFC') as br:
                b = br.read_var_int(max=10)
        self.assertIn("Invalid format", str(context.exception))

    def test_read_var_bytes(self):
        input_data = b'\x02\x01\x02\x03'
        with serialization.BinaryReader(input_data) as br:
            b = br.read_var_bytes()
            self.assertEqual(input_data[1:3], b)

        """
            test reading with insufficient data
            the C# equivalent will try to read up to what's encoded amount of bytes from the stream or less!
            
            byte[] value = { 0x2 };
            using (MemoryStream ms = new MemoryStream(value, false))
            using (BinaryReader reader = new BinaryReader(ms, System.Text.Encoding.UTF8))
            {
                byte[] b = reader.ReadVarBytes();
            }

        # encode 2 bytes of remaining data, but supply none
        """
        input_data = b'\x02'
        with serialization.BinaryReader(input_data) as br:
            b = br.read_var_bytes()
            self.assertEqual(b'', b)

    def test_read_bytes_with_grouping(self):
        # test with invalid group_size's
        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(b'') as br:
                br.read_bytes_with_grouping(group_size=-1)
        self.assertIn("group_size must be > 0 and <= 254", str(context.exception))

        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(b'') as br:
                br.read_bytes_with_grouping(group_size=-0)
        self.assertIn("group_size must be > 0 and <= 254", str(context.exception))

        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(b'') as br:
                br.read_bytes_with_grouping(group_size=255)
        self.assertIn("group_size must be > 0 and <= 254", str(context.exception))

        # read empty value
        group_size = 16
        with serialization.BinaryWriter() as bw:
            bw.write_bytes_with_grouping(b'', group_size)
            data = bw._stream.getvalue()
            with serialization.BinaryReader(data) as br:
                result = br.read_bytes_with_grouping(group_size)
                self.assertEqual(b'', result)

        # test with value smaller than group_size
        with serialization.BinaryWriter() as bw:
            input = b'\x11' * 10
            bw.write_bytes_with_grouping(input, group_size)
            data = bw._stream.getvalue()
            with serialization.BinaryReader(data) as br:
                result = br.read_bytes_with_grouping(group_size)
                self.assertEqual(input, result)

        # test with value exact same length as group_size
        with serialization.BinaryWriter() as bw:
            input = b'\x11' * 16
            bw.write_bytes_with_grouping(input, group_size)
            data = bw._stream.getvalue()
            with serialization.BinaryReader(data) as br:
                result = br.read_bytes_with_grouping(group_size)
                self.assertEqual(input, result)

        # test with value exceeding length of group_size (thus having 2 groups)
        with serialization.BinaryWriter() as bw:
            input = b'\x11' *20
            bw.write_bytes_with_grouping(input, group_size)
            data = bw._stream.getvalue()
            with serialization.BinaryReader(data) as br:
                result = br.read_bytes_with_grouping(group_size)
                self.assertEqual(input, result)

        # test with invalid group size encoding
        group_data = b'\x11' * 16
        # this should not be bigger than `group_size`, in this case b'\x10'
        remaining_group_length = b'\x11'
        data = group_data + remaining_group_length
        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(data) as br:
                br.read_bytes_with_grouping(group_size)
        self.assertIn("corrupt remainder length", str(context.exception))

    def test_read_string(self):
        input_data = b'\x02\x41\x42'
        with serialization.BinaryReader(input_data) as br:
            s = br.read_var_string()
            self.assertIsInstance(s, str)
            self.assertEqual('AB', s)

        # test with insufficient data
        input_data = b'\x02\x41'
        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(input_data) as br:
                s = br.read_var_string()
        self.assertIn("unpack requires a buffer of 2 bytes", str(context.exception))

    def test_reading_serializable(self):
        s1 = SerializableObj(1)

        with serialization.BinaryReader(s1.to_array()) as br:
            obj = br.read_serializable(obj_type=SerializableObj)
            self.assertIsInstance(obj, serialization.ISerializable)
            self.assertIsInstance(obj, SerializableObj)
            self.assertEqual(1, obj.a)

    def test_reading_list_of_serializables(self):
        s1 = SerializableObj(1)
        s2 = SerializableObj(2)

        array_length = b'\x02'
        with serialization.BinaryReader(array_length + s1.to_array() + s2.to_array()) as br:
            objs = br.read_serializable_list(obj_type=SerializableObj)
            self.assertIsInstance(objs, list)
            self.assertTrue(2, len(objs))
            for o in objs:
                self.assertIsInstance(o, SerializableObj)

        # test but limit max array
        array_length = b'\x02'
        with serialization.BinaryReader(array_length + s1.to_array() + s2.to_array()) as br:
            objs = br.read_serializable_list(obj_type=SerializableObj, max=1)
            self.assertIsInstance(objs, list)
            self.assertTrue(1, len(objs))
            for o in objs:
                self.assertIsInstance(o, SerializableObj)

    def test_length(self):
        input_data = b'\x02\x41\x42'
        with serialization.BinaryReader(input_data) as br:
            self.assertEqual(3, len(br))

class BinaryWriterTestCase(unittest.TestCase):
    def test_write_bytes(self):
        with serialization.BinaryWriter() as bw:
            bw.write_uint8(5)
            bw.write_uint16(257)
            self.assertEqual(b'\x05\x01\x01', bw._stream.getvalue())

    def test_write_bool(self):
        with serialization.BinaryWriter() as bw:
            bw.write_bool(0)
            bw.write_bool(1)
            bw.write_bool(15)
            self.assertEqual(b'\x00\x01\x01', bw._stream.getvalue())

    def test_write_uint8(self):
        with serialization.BinaryWriter() as bw:
            bw.write_uint8(255)
            # this also validates signed vs unsigned. If it was signed it would need an extra \x00 to express the value
            # and would not fit in 1 byte
            self.assertEqual(b'\xFF', bw._stream.getvalue())

    def test_write_uint16(self):
        with serialization.BinaryWriter() as bw:
            bw.write_uint16(0xFFFF)
            # this also validates signed vs unsigned. If it was signed it would need an extra \x00 to express the value
            # and would not fit in 2 bytes
            self.assertEqual(b'\xFF\xFF', bw._stream.getvalue())

    def test_write_uint32(self):
        with serialization.BinaryWriter() as bw:
            bw.write_uint32(0xFFFFFFFF)
            # this also validates signed vs unsigned. If it was signed it would need an extra \x00 to express the value
            # and would not fit in 4 bytes
            self.assertEqual(b'\xFF\xFF\xFF\xFF', bw._stream.getvalue())

    def test_write_uint64(self):
        with serialization.BinaryWriter() as bw:
            bw.write_uint64(0xFFFFFFFFFFFFFFFF)
            # this also validates signed vs unsigned. If it was signed it would need an extra \x00 to express the value
            # and would not fit in 8 bytes
            self.assertEqual(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', bw._stream.getvalue())

    def test_write_int16(self):
        with serialization.BinaryWriter() as bw:
            bw.write_int16(-1)
            # this also validates signed vs unsigned. If it was unsigned it would be without \x00
            self.assertEqual(b'\xFF\xFF', bw._stream.getvalue())

    def test_write_int32(self):
        with serialization.BinaryWriter() as bw:
            bw.write_int32(-1)
            # this also validates signed vs unsigned. If it was unsigned it would be without \x00
            self.assertEqual(b'\xFF\xFF\xFF\xFF', bw._stream.getvalue())

    def test_write_int64(self):
        with serialization.BinaryWriter() as bw:
            bw.write_int64(-1)
            # this also validates signed vs unsigned. If it was unsigned it would be without \x00
            self.assertEqual(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', bw._stream.getvalue())

    def test_write_var_string(self):
        with serialization.BinaryWriter() as bw:
            bw.write_var_string('ABC')
            self.assertEqual(b'\x03\x41\x42\x43', bw._stream.getvalue())

    def test_write_var_int(self):
        with self.assertRaises(TypeError) as context:
            with serialization.BinaryWriter() as bw:
                bw.write_var_int(b'\x01')
        self.assertIn("not int type.", str(context.exception))

        with self.assertRaises(ValueError) as context:
            with serialization.BinaryWriter() as bw:
                bw.write_var_int(-1)
        self.assertIn("too small.", str(context.exception))

        with serialization.BinaryWriter() as bw:
            bw.write_var_int(1)
            self.assertEqual(b'\x01', bw._stream.getvalue())

        with serialization.BinaryWriter() as bw:
            bw.write_var_int(65535)  # 0xFFFF edge
            self.assertEqual(b'\xfd\xff\xFF', bw._stream.getvalue())

        with serialization.BinaryWriter() as bw:
            bw.write_var_int(4294967295)  # 0xFFFFFFFF edge
            self.assertEqual(b'\xfe\xff\xff\xff\xff', bw._stream.getvalue())

        with serialization.BinaryWriter() as bw:
            bw.write_var_int(4294967296)
            self.assertEqual(b'\xff\x00\x00\x00\x00\x01\x00\x00\x00', bw._stream.getvalue())

    def test_write_var_bytes(self):
        with serialization.BinaryWriter() as bw:
            bw.write_var_bytes(b'\x01\x02\x03\x04')
            self.assertEqual(b'\x04\x01\x02\x03\x04', bw._stream.getvalue())

    def test_write_var_bytes_with_grouping(self):
        # test with invalid group_size's
        with self.assertRaises(ValueError) as context:
            with serialization.BinaryWriter() as bw:
                bw.write_bytes_with_grouping(b'', group_size=-1)
        self.assertIn("group_size must be > 0 and <= 254", str(context.exception))

        with self.assertRaises(ValueError) as context:
            with serialization.BinaryWriter() as bw:
                bw.write_bytes_with_grouping(b'', group_size=0)
        self.assertIn("group_size must be > 0 and <= 254", str(context.exception))

        with self.assertRaises(ValueError) as context:
            with serialization.BinaryWriter() as bw:
                bw.write_bytes_with_grouping(b'', group_size=255)
        self.assertIn("group_size must be > 0 and <= 254", str(context.exception))

        # test empty value
        with serialization.BinaryWriter() as bw:
            bw.write_bytes_with_grouping(b'', group_size=16)
            self.assertEqual(b'\x00' * 17, bw._stream.getvalue())

        # test with value smaller than group_size
        with serialization.BinaryWriter() as bw:
            group_size = 16
            value = b'\x11' * 10
            bw.write_bytes_with_grouping(value, group_size=group_size)
            padding = (group_size - len(value)) * b'\x00'
            self.assertEqual(value + padding + bytes([len(value)]), bw._stream.getvalue())

        # test with value exact same length as group_size
        with serialization.BinaryWriter() as bw:
            group_size = 16
            value = b'\x11' * 16
            bw.write_bytes_with_grouping(value, group_size=group_size)
            self.assertEqual(value + b'\xff', bw._stream.getvalue())

        # test with value exceeding length of group_size
        with serialization.BinaryWriter() as bw:
            group_size = 16
            value = b'\x11' * 20
            bw.write_bytes_with_grouping(value, group_size=group_size)

            padding = b'\x00' * 12
            len_remainder = len(value) % group_size
            # 16 bytes value + group byte + 4 remaining bytes + padding + length remainder
            expected = b'\x11' * 16 + b'\x10' + b'\x11' * 4 + padding + bytes([len_remainder])
            self.assertEqual(expected, bw._stream.getvalue())

    def test_write_serializable(self):
        s1 = SerializableObj(1)
        with serialization.BinaryWriter() as bw:
            bw.write_serializable(s1)
            self.assertEqual(b'\x01', bw._stream.getvalue())

    def test_write_list_of_serializable_objects(self):
        s1 = SerializableObj(1)
        s2 = SerializableObj(3)
        with serialization.BinaryWriter() as bw:
            bw.write_serializable_list([s1, s2])
            self.assertEqual(b'\x02\x01\x03', bw._stream.getvalue())

    def test_length(self):
        with serialization.BinaryWriter() as br:
            br.write_uint16(1000)
            self.assertEqual(2, len(br))

        with serialization.BinaryWriter() as br:
            br.write_uint64(1000)
            self.assertEqual(8, len(br))

