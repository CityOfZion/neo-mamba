from unittest import TestCase
from neo3.core.types.uint import _UIntBase
from neo3.core.types import UInt160, UInt256
from neo3.core import serialization


class UIntBase(_UIntBase):
    def serialize(self) -> bytearray:
        pass

    @classmethod
    def deserialize(cls, data: bytes):
        pass


class UIntBaseTest(TestCase):
    def test_create_with_empty_data(self):
        x = UIntBase(num_bytes=2)
        self.assertEqual(len(x._data), 2)
        self.assertEqual(x._data, b'\x00\x00')

    def test_valid_rawbytes_data(self):
        x = UIntBase(num_bytes=2, data=b'\xaa\xbb')
        self.assertEqual(len(x._data), 2)
        self.assertNotEqual(len(x._data), 4)

    def test_raw_data_that_can_be_decoded(self):
        """
        some raw data can be decoded e.g. bytearray.fromhex('1122') but shouldn't be
        """
        tricky_raw_data = bytes.fromhex('1122')
        x = UIntBase(num_bytes=2, data=tricky_raw_data)
        self.assertEqual(x._data, tricky_raw_data)

    def test_data_length_mistmatch(self):
        with self.assertRaises(ValueError) as context:
            x = UIntBase(num_bytes=2, data=b'a')  # 2 != 1
        self.assertTrue("Invalid UInt: data length" in str(context.exception))

    def test_size(self):
        x = UIntBase(num_bytes=2, data=b'\xaa\xbb')
        self.assertEqual(len(x), 2)

    def test_hash_code(self):
        x = UIntBase(num_bytes=4, data=bytearray.fromhex('DEADBEEF'))
        self.assertEqual(hash(x), 4022250974)
        x = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))
        self.assertEqual(hash(x), 8721)

    def test_to_string(self):
        x = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))
        self.assertEqual('2211', str(x))
        self.assertNotEqual('1122', str(x))

    def test_equal(self):
        x = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))
        y = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))
        z = UIntBase(num_bytes=2, data=bytearray.fromhex('2211'))

        self.assertFalse(x == None)
        self.assertFalse(x == int(1122))
        self.assertTrue(x == x)
        self.assertTrue(x == y)
        self.assertTrue(x != z)

    def test_hash(self):
        x = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))
        y = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))
        z = UIntBase(num_bytes=2, data=bytearray.fromhex('2211'))
        self.assertEqual(hash(x), hash(y))
        self.assertNotEqual(hash(x), hash(z))

    def test_compare_to(self):
        x = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))
        y = UIntBase(num_bytes=3, data=bytearray.fromhex('112233'))
        z = UIntBase(num_bytes=2, data=bytearray.fromhex('1133'))
        xx = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))

        # test invalid type
        with self.assertRaises(TypeError) as context:
            x._compare_to(None)

        expected = "Cannot compare UIntBase to type NoneType"
        self.assertEqual(expected, str(context.exception))

        # test invalid length
        with self.assertRaises(ValueError) as context:
            x._compare_to(y)

        expected = "Cannot compare UIntBase with length 2 to UIntBase with length 3"
        self.assertEqual(expected, str(context.exception))

        # test data difference ('22' < '33')
        self.assertEqual(-1, x._compare_to(z))
        # test data difference ('33' > '22')
        self.assertEqual(1, z._compare_to(x))
        # test data equal
        self.assertEqual(0, x._compare_to(xx))

    def test_rich_comparison_methods(self):
        x = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))
        z = UIntBase(num_bytes=2, data=bytearray.fromhex('1133'))
        xx = UIntBase(num_bytes=2, data=bytearray.fromhex('1122'))

        self.assertTrue(x < z)
        self.assertTrue(z > x)
        self.assertTrue(x <= xx)
        self.assertTrue(x >= xx)


class UInt160_and_256Test(TestCase):
    def test_zero(self):
        uint160 = UInt160.zero()
        self.assertEqual(20, len(uint160.to_array()))

        uint256 = UInt256.zero()
        self.assertEqual(32, len(uint256.to_array()))

    def test_from_string_wrong_length(self):
        with self.assertRaises(ValueError) as ctx:
            UInt160.from_string("1122")
        self.assertEqual("Invalid UInt160 Format: 4 chars != 40 chars", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            UInt256.from_string("1122")
        self.assertEqual("Invalid UInt256 Format: 4 chars != 64 chars", str(ctx.exception))

    def test_from_string_various(self):
        uint160 = UInt160.from_string("11" * 20)
        expected_data_uint160 = bytearray([0x11] * 20)
        self.assertEqual(expected_data_uint160, uint160.to_array())

        uint256 = UInt256.from_string("11" * 32)
        expected_data_uint256 = bytearray([0x11] * 32)
        self.assertEqual(expected_data_uint256, uint256.to_array())


        uint160_from_bytes = UInt160.deserialize_from_bytes(expected_data_uint160)
        self.assertEqual(expected_data_uint160, uint160_from_bytes.to_array())

        uint256_from_bytes = UInt256.deserialize_from_bytes(expected_data_uint256)
        self.assertEqual(expected_data_uint256, uint256_from_bytes.to_array())

        # test deserialize with too much data
        data_uint160 = bytearray(21 * [0x11])
        uint160_from_bytes = UInt160.deserialize_from_bytes(data_uint160)
        self.assertEqual(data_uint160[:20], uint160_from_bytes.to_array())

        data_uint256 = bytearray(33 * [0x11])
        uint256_from_bytes = UInt256.deserialize_from_bytes(data_uint256)
        self.assertEqual(expected_data_uint256[:32], uint256_from_bytes.to_array())

        # test deserialize with too little data
        data_uint160 = bytearray(19 * [0x11])
        data_uint256 = bytearray(31 * [0x11])
        with self.assertRaises(ValueError) as ctx:
            UInt160.deserialize_from_bytes(data_uint160)
        self.assertEqual("Insufficient data 19 bytes is less than the required 20", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            UInt256.deserialize_from_bytes(data_uint256)
        self.assertEqual("Insufficient data 31 bytes is less than the required 32", str(ctx.exception))

    def test_deserialize_from_stream(self):
        data_uint160 = bytearray(20 * [0x11])
        data_uint256 = bytearray(32 * [0x11])

        with serialization.BinaryReader(data_uint160) as br:
            # we explicitly call deserialize, instead of br.read_uint160() for coverage
            uint160 = UInt160.zero()
            uint160.deserialize(br)
            self.assertEqual(data_uint160, uint160._data)

        with serialization.BinaryReader(data_uint256) as br:
            uint256 = UInt256.zero()
            uint256.deserialize(br)
            self.assertEqual(data_uint256, uint256._data)

    def test_serialize_to_stream(self):
        data_uint160 = bytearray(20 * [0x11])
        data_uint256 = bytearray(32 * [0x11])
        uint160 = UInt160(data_uint160)
        uint256 = UInt256(data_uint256)

        with serialization.BinaryWriter() as bw:
            bw.write_serializable(uint160)
            self.assertEqual(data_uint160, bw._stream.getvalue())

        with serialization.BinaryWriter() as bw:
            bw.write_serializable(uint256)
            self.assertEqual(data_uint256, bw._stream.getvalue())
