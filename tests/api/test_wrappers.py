import unittest
from neo3.core import types
from neo3.api.wrappers import _check_address_and_convert


class WrapperUtilsTest(unittest.TestCase):
    def test_check_address_and_convert(self):
        hash_in = types.UInt160.from_string(
            "0x7e9237a93f64407141a5b86c760200c66c81e2ec"
        )
        self.assertIsInstance(_check_address_and_convert(hash_in), types.UInt160)

        with self.assertRaises(ValueError) as context:
            _check_address_and_convert(object())
        self.assertEqual(
            "Input is of type <class 'object'> expected UInt160 or NeoAddress(str)",
            str(context.exception),
        )

        invalid_address = "NgNJsBfhcoJSm6MVMpMeGLqEK5mSQXuJTt"
        with self.assertRaises(ValueError) as context:
            _check_address_and_convert(invalid_address)
        self.assertEqual("Invalid checksum", str(context.exception))

        valid_address = "NgNJsBfhcoJSm6MVMpMeGLqEK5mSQXuJTq"
        self.assertIsInstance(_check_address_and_convert(valid_address), types.UInt160)
