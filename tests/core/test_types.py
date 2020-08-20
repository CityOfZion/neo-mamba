from unittest import TestCase
from neo3.core.types.uint import _UIntBase
from neo3.core.types import BigInteger, UInt160, UInt256
from neo3.core import serialization

class BigIntegerTestCase(TestCase):
    def test_big_integer_add(self):
        b1 = BigInteger(10)
        b2 = BigInteger(20)

        b3 = b1 + b2

        self.assertIsInstance(b3, BigInteger)
        self.assertEqual(30, b3)

    def test_big_integer_sub(self):
        b1 = BigInteger(5505505505505505050505)
        b2 = BigInteger(5505505505505505000000)

        b3 = b1 - b2

        self.assertIsInstance(b3, BigInteger)
        self.assertEqual(50505, b3)

    def test_big_integer_mul(self):
        b1 = BigInteger(55055055055055)
        b2 = BigInteger(55055055055)

        b3 = b1 * b2

        self.assertIsInstance(b3, BigInteger)
        self.assertEqual(3031059087112109081053025, b3)

    def test_big_integer_div(self):
        b1 = BigInteger(55055055055055)
        b2 = BigInteger(55055055)

        b3 = b1 / b2
        self.assertIsInstance(b3, BigInteger)
        self.assertEqual(1000000, b3)

    def test_big_integer_div2(self):
        b1 = BigInteger(41483775933600000000)
        b2 = BigInteger(414937759336)

        b3 = b1 / b2
        b4 = b1 // b2
        self.assertIsInstance(b3, BigInteger)
        self.assertEqual(99975899, b3)
        self.assertEqual(b4, b3)

    def test_big_integer_div_rounding(self):
        b1 = BigInteger(1)
        b2 = BigInteger(2)
        self.assertEqual(0, b1 / b2)  # 0.5 -> 0

        b1 = BigInteger(2)
        b2 = BigInteger(3)
        self.assertEqual(0, b1 / b2)  # 0.66 -> 0

        b1 = BigInteger(5)
        b2 = BigInteger(4)
        self.assertEqual(1, b1 / b2)  # 1.25 -> 1

        b1 = BigInteger(5)
        b2 = BigInteger(3)
        self.assertEqual(1, b1 / b2)  # 1.66 -> 1

        b1 = BigInteger(-1)
        b2 = BigInteger(3)
        self.assertEqual(0, b1 / b2)  # -0.33 -> 0

        b1 = BigInteger(-5)
        b2 = BigInteger(3)
        self.assertEqual(-1, b1 / b2)  # -1.66 -> -1

        b1 = BigInteger(1)
        b2 = BigInteger(-2)
        self.assertEqual(0, b1/b2)

    def test_big_integer_div_old_block1473972(self):
        b1 = BigInteger(-11001000000)
        b2 = BigInteger(86400)
        result = b1 / b2
        self.assertEqual(-127326, result)

    def test_big_integer_float(self):
        b1 = BigInteger(5505.001)
        b2 = BigInteger(55055.999)

        b3 = b1 + b2

        self.assertIsInstance(b3, BigInteger)
        self.assertEqual(60560, b3)

    def test_big_integer_to_bytearray(self):
        b1 = BigInteger(8972340892734890723)
        ba = b1.to_bytearray()

        integer = BigInteger.frombytes(ba)
        self.assertEqual(8972340892734890723, integer)

        b2 = BigInteger(-100)
        b2ba = b2.to_bytearray()
        integer2 = BigInteger.frombytes(b2ba)
        self.assertEqual(-100, integer2)

        b3 = BigInteger(128)
        b3ba = b3.to_bytearray()
        self.assertEqual(b'\x80\x00', b3ba)

        b4 = BigInteger(0)
        b4ba = b4.to_bytearray()
        self.assertEqual(b'\x00', b4ba)

        b5 = BigInteger(-146)
        b5ba = b5.to_bytearray()
        self.assertEqual(b'\x6e\xff', b5ba)

        b6 = BigInteger(-48335248028225339427907476932896373492484053930)
        b6ba = b6.to_bytearray()
        self.assertEqual(20, len(b6ba))

        b7 = BigInteger(-399990000)
        b7ba = b7.to_bytearray()
        self.assertEqual(b'\x10\xa3\x28\xe8', b7ba)

        b8 = BigInteger(-65023)
        b8ba = b8.to_bytearray()
        self.assertEqual(b'\x01\x02\xff', b8ba)

    def test_big_integer_frombytes(self):
        b1 = BigInteger(8972340892734890723)
        ba = b1.to_bytearray()

        b2 = BigInteger.frombytes(ba)
        self.assertEqual(b1, b2)
        self.assertTrue(b1 == b2)

    def test_big_integer_sign(self):
        b1 = BigInteger(3)
        b2 = BigInteger(0)
        b3 = BigInteger(-4)
        self.assertEqual(1, b1.sign)
        self.assertEqual(0, b2.sign)
        self.assertEqual(-1, b3.sign)

    def test_big_integer_modulo(self):
        b1 = BigInteger(860593)
        b2 = BigInteger(-201)
        self.assertEqual(112, b1 % b2)

        b1 = BigInteger(20195283520469175757)
        b2 = BigInteger(1048576)
        self.assertEqual(888269, b1 % b2)

        b1 = BigInteger(-18224909727634776050312394179610579601844989529623334093909233530432892596607)
        b2 = BigInteger(14954691977398614017)
        self.assertEqual(-3100049211437790421, b1 % b2)

        b3 = BigInteger.frombytes(b'+K\x05\xbe\xaai\xfa\xd4')
        self.assertEqual(b3, b1 % b2)

    def test_dunder_methods(self):
        b1 = BigInteger(1)
        b2 = BigInteger(2)
        b3 = BigInteger(3)

        self.assertEqual(1, abs(b1))
        self.assertEqual(0, b1 % 1)
        self.assertEqual(-1, -b1)
        self.assertEqual("1", str(b1))
        self.assertEqual(1, b3 // b2)

        right_shift = b3 >> b1
        self.assertEqual(1, right_shift)
        self.assertIsInstance(right_shift, BigInteger)

        left_shift = b1 << b3
        self.assertEqual(8, left_shift)
        self.assertIsInstance(left_shift, BigInteger)

    def test_negative_shifting(self):
        # C#'s BigInteger changes a left shift with a negative shift index,
        # to a right shift with a positive index.

        b1 = BigInteger(8)
        b2 = BigInteger(-3)
        # shift against BigInteger
        self.assertEqual(1, b1 << b2)
        # shift against integer
        self.assertEqual(1, b1 << -3)

        # the same as above but for right shift
        self.assertEqual(64, b1 >> b2)
        self.assertEqual(64, b1 >> -3)

    def test_specials(self):
        self.assertEqual(0, BigInteger.ZERO())
        self.assertEqual(1, BigInteger.ONE())
        b = BigInteger.ZERO()

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

    def test_valid_data(self):
        x = UIntBase(num_bytes=2, data=b'aabb')
        # test for proper conversion to raw bytes
        self.assertEqual(len(x._data), 2)
        self.assertNotEqual(len(x._data), 4)

        x = UIntBase(num_bytes=3, data=bytearray.fromhex('aabbcc'))
        self.assertEqual(len(x._data), 3)
        self.assertNotEqual(len(x._data), 6)

    def test_valid_rawbytes_data(self):
        x = UIntBase(num_bytes=2, data=b'\xaa\xbb')
        self.assertEqual(len(x._data), 2)
        self.assertNotEqual(len(x._data), 4)

    def test_invalid_data_type(self):
        with self.assertRaises(TypeError) as context:
            x = UIntBase(num_bytes=2, data='abc')
        self.assertTrue("Invalid data type" in str(context.exception))

    def test_raw_data_that_can_be_decoded(self):
        """
        some raw data can be decoded e.g. bytearray.fromhex('1122') but shouldn't be
        """
        tricky_raw_data = bytes.fromhex('1122')
        x = UIntBase(num_bytes=2, data=tricky_raw_data)
        self.assertEqual(x._data, tricky_raw_data)

    def test_data_length_mistmatch(self):
        with self.assertRaises(ValueError) as context:
            x = UIntBase(num_bytes=2, data=b'aa')  # 2 != 1
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
