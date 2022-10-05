import unittest
from neo3.contracts.callflags import CallFlags


class CallFlagsTestCase(unittest.TestCase):
    def test_parsing_from_string(self):
        tests = [
            ("None", CallFlags.NONE),
            ("ReadStates", CallFlags.READ_STATES),
            ("WriteStates", CallFlags.WRITE_STATES),
            ("AllowCall", CallFlags.ALLOW_CALL),
            ("AllowNotify", CallFlags.ALLOW_NOTIFY),
            ("States", CallFlags.STATES),
            ("ReadOnly", CallFlags.READ_ONLY),
            ("All", CallFlags.ALL),
        ]
        for input, expected in tests:
            self.assertEqual(expected, CallFlags.from_csharp_name(input))

    def test_parsing_invalid_input(self):
        with self.assertRaises(ValueError) as context:
            CallFlags.from_csharp_name("bla")
        self.assertEqual(
            "bla is not a valid member of CallFlags", str(context.exception)
        )

    def test_parsing_from_string_with_multiple_flags(self):
        input = "ReadStates, AllowCall"
        cf = CallFlags.from_csharp_name(input)
        expected = CallFlags.READ_STATES | CallFlags.ALLOW_CALL
        self.assertNotEqual(CallFlags.READ_STATES, cf)
        self.assertNotEqual(CallFlags.ALLOW_CALL, cf)
        self.assertEqual(expected, cf)
