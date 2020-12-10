from unittest import TestCase
from neo3.vm import BigInteger


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

    def test_big_integer_to_bytearray(self):
        b1 = BigInteger(8972340892734890723)
        ba = b1.to_array()

        integer = BigInteger(ba)
        self.assertEqual(8972340892734890723, integer)

        b2 = BigInteger(-100)
        b2ba = b2.to_array()
        integer2 = BigInteger(b2ba)
        self.assertEqual(-100, integer2)

        b3 = BigInteger(128)
        b3ba = b3.to_array()
        self.assertEqual(b'\x80\x00', b3ba)

        b4 = BigInteger(0)
        b4ba = b4.to_array()
        self.assertEqual(b'\x00', b4ba)

        b5 = BigInteger(-146)
        b5ba = b5.to_array()
        self.assertEqual(b'\x6e\xff', b5ba)

        b6 = BigInteger(-48335248028225339427907476932896373492484053930)
        b6ba = b6.to_array()
        self.assertEqual(20, len(b6ba))

        b7 = BigInteger(-399990000)
        b7ba = b7.to_array()
        self.assertEqual(b'\x10\xa3\x28\xe8', b7ba)

        b8 = BigInteger(-65023)
        b8ba = b8.to_array()
        self.assertEqual(b'\x01\x02\xff', b8ba)

    def test_big_integer_frombytes(self):
        b1 = BigInteger(8972340892734890723)
        ba = b1.to_array()

        b2 = BigInteger(ba)
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

        b3 = BigInteger(b'+K\x05\xbe\xaai\xfa\xd4')
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
        self.assertEqual(0, BigInteger.zero())
        self.assertEqual(1, BigInteger.one())
        b = BigInteger.zero()
