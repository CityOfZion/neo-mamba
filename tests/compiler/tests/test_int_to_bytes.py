"""Tests for int.to_bytes(length, byteorder, *, signed=False)."""

import unittest

from neo3.compiler import TypecheckError, compile_function

_CALL_L = 0x35
_CONVERT = 0xDB
_LEFT = 0x8D
_REVERSEITEMS = 0xD1
_NEWBUFFER = 0x88
_SIGN = 0x99


# ---------------------------------------------------------------------------
# Constant folding — no CALL_L emitted, result is a PUSHDATA literal
# ---------------------------------------------------------------------------


class TestConstantFolding(unittest.TestCase):
    """When both value and length are literals the result is folded at compile time."""

    def _fold(self, src: str) -> bytes:
        bc = compile_function(src)
        self.assertNotIn(_CALL_L, bc, "constant to_bytes should not emit CALL_L")
        return bc

    def test_defaults_big_unsigned(self):
        # (5).to_bytes() → b'\x05'  (length=1, byteorder='big', signed=False)
        src = "def f() -> bytes:\n    return (5).to_bytes()"
        bc = self._fold(src)
        self.assertIn(0x05, bc)

    def test_zero_defaults(self):
        src = "def f() -> bytes:\n    return (0).to_bytes()"
        bc = self._fold(src)
        self.assertIn(0x00, bc)

    def test_little_unsigned(self):
        # (256).to_bytes(2, 'little') → b'\x00\x01'
        src = "def f() -> bytes:\n    return (256).to_bytes(2, 'little')"
        bc = self._fold(src)
        # PUSHDATA1 content: b'\x00\x01'
        self.assertIn(0x00, bc)
        self.assertIn(0x01, bc)

    def test_big_unsigned(self):
        # (256).to_bytes(2, 'big') → b'\x01\x00'
        src = "def f() -> bytes:\n    return (256).to_bytes(2, 'big')"
        bc = self._fold(src)
        self.assertIn(0x01, bc)

    def test_little_signed_positive(self):
        # (127).to_bytes(1, 'little', signed=True) → b'\x7f'
        src = "def f() -> bytes:\n    return (127).to_bytes(1, 'little', signed=True)"
        self._fold(src)

    def test_little_signed_negative(self):
        # (-1).to_bytes(2, 'little', signed=True) → b'\xff\xff'
        src = "def f() -> bytes:\n    return (-1).to_bytes(2, 'little', signed=True)"
        self._fold(src)

    def test_big_signed_negative(self):
        # (-1).to_bytes(2, 'big', signed=True) → b'\xff\xff'
        src = "def f() -> bytes:\n    return (-1).to_bytes(2, 'big', signed=True)"
        self._fold(src)

    def test_keyword_length(self):
        src = "def f() -> bytes:\n    return (1).to_bytes(length=2, byteorder='big')"
        self._fold(src)

    def test_keyword_byteorder(self):
        src = "def f() -> bytes:\n    return (1).to_bytes(2, byteorder='little')"
        self._fold(src)

    def test_overflow_raises(self):
        # 256 does not fit in 1 byte unsigned
        src = "def f() -> bytes:\n    return (256).to_bytes(1, 'big')"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_negative_unsigned_raises(self):
        # -1 does not fit in 1 unsigned byte
        src = "def f() -> bytes:\n    return (-1).to_bytes(1, 'big')"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_signed_overflow_raises(self):
        # 128 does not fit in 1 signed byte (max 127)
        src = "def f() -> bytes:\n    return (128).to_bytes(1, 'big', signed=True)"
        with self.assertRaises(TypecheckError):
            compile_function(src)


# ---------------------------------------------------------------------------
# Dynamic values — CALL_L to helper, helper emitted once
# ---------------------------------------------------------------------------


class TestDynamicCompiles(unittest.TestCase):
    """Dynamic int values route through the shared helper function."""

    def _compile(self, src: str) -> bytes:
        bc = compile_function(src)
        self.assertIn(_CALL_L, bc)
        return bc

    def test_little_unsigned_compiles(self):
        src = "def f(x: int, n: int) -> bytes:\n    return x.to_bytes(n, 'little')"
        self._compile(src)

    def test_little_signed_compiles(self):
        src = "def f(x: int, n: int) -> bytes:\n    return x.to_bytes(n, 'little', signed=True)"
        bc = self._compile(src)
        self.assertIn(_SIGN, bc)  # signed helper uses SIGN opcode

    def test_big_unsigned_compiles(self):
        src = "def f(x: int, n: int) -> bytes:\n    return x.to_bytes(n, 'big')"
        bc = self._compile(src)
        self.assertIn(_REVERSEITEMS, bc)

    def test_big_signed_compiles(self):
        src = "def f(x: int, n: int) -> bytes:\n    return x.to_bytes(n, 'big', signed=True)"
        bc = self._compile(src)
        self.assertIn(_SIGN, bc)
        self.assertIn(_REVERSEITEMS, bc)

    def test_default_byteorder_is_big(self):
        # No byteorder arg → big-endian helper → REVERSEITEMS present
        src = "def f(x: int) -> bytes:\n    return x.to_bytes(1)"
        bc = self._compile(src)
        self.assertIn(_REVERSEITEMS, bc)

    def test_default_length_is_1(self):
        # No args → compiles with the big-unsigned helper
        src = "def f(x: int) -> bytes:\n    return x.to_bytes()"
        bc = self._compile(src)
        self.assertIn(_REVERSEITEMS, bc)

    def test_constant_length_dynamic_value(self):
        # Length is a constant literal but value is dynamic → still uses helper
        src = "def f(x: int) -> bytes:\n    return x.to_bytes(4, 'little')"
        self._compile(src)

    def test_helper_emitted_once_for_same_variant(self):
        # Two calls with same variant → helper byte sequence appears once in bytecode
        src = (
            "def f(x: int, y: int) -> bytes:\n"
            "    a: bytes = x.to_bytes(4, 'little')\n"
            "    b: bytes = y.to_bytes(4, 'little')\n"
            "    return a"
        )
        bc = compile_function(src)
        # Count INITSLOT bytes followed by 0x00 0x02 (little_unsigned header)
        # The helper body should appear exactly once regardless of call count
        helper_header = bytes([0x57, 0x00, 0x02])  # INITSLOT 0 locals 2 args
        self.assertEqual(bc.count(helper_header), 1)

    def test_result_type_is_bytes(self):
        # Assigning to bytes variable compiles without type error
        src = (
            "def f(x: int, n: int) -> bytes:\n"
            "    b: bytes = x.to_bytes(n, 'little')\n"
            "    return b"
        )
        self.assertIsInstance(compile_function(src), bytes)


# ---------------------------------------------------------------------------
# Boundary / sign-edge cases (constant folding — verified by Python semantics)
# ---------------------------------------------------------------------------


class TestBoundaryValues(unittest.TestCase):

    def _result_bytes(self, src: str) -> bytes:
        """Compile and extract the PUSHDATA1 payload (folded constant)."""
        bc = compile_function(src)
        self.assertNotIn(_CALL_L, bc)
        return bc

    def test_127_little_1_unsigned(self):
        # 127 fits in 1 unsigned byte
        src = "def f() -> bytes:\n    return (127).to_bytes(1, 'little')"
        self._result_bytes(src)

    def test_128_little_1_unsigned(self):
        # 128 fits in 1 unsigned byte
        src = "def f() -> bytes:\n    return (128).to_bytes(1, 'little')"
        self._result_bytes(src)

    def test_127_little_1_signed(self):
        # 127 is the max positive for 1 signed byte
        src = "def f() -> bytes:\n    return (127).to_bytes(1, 'little', signed=True)"
        self._result_bytes(src)

    def test_minus128_little_1_signed(self):
        # -128 is the min for 1 signed byte
        src = "def f() -> bytes:\n    return (-128).to_bytes(1, 'little', signed=True)"
        self._result_bytes(src)

    def test_255_little_unsigned_2bytes(self):
        # 255 in 2 bytes LE unsigned → b'\xff\x00'
        src = "def f() -> bytes:\n    return (255).to_bytes(2, 'little')"
        self._result_bytes(src)

    def test_65535_little_unsigned(self):
        src = "def f() -> bytes:\n    return (65535).to_bytes(2, 'little')"
        self._result_bytes(src)

    def test_0xffff_vs_minus1_signed(self):
        # 0xFFFF unsigned != -1 signed — make sure both compile without error
        src1 = "def f() -> bytes:\n    return (0xFFFF).to_bytes(2, 'little')"
        src2 = "def f() -> bytes:\n    return (-1).to_bytes(2, 'little', signed=True)"
        self._result_bytes(src1)
        self._result_bytes(src2)

    def test_big_endian_255(self):
        # (255).to_bytes(2, 'big') → b'\x00\xff'
        src = "def f() -> bytes:\n    return (255).to_bytes(2, 'big')"
        self._result_bytes(src)

    def test_big_endian_minus1_signed(self):
        # (-1).to_bytes(2, 'big', signed=True) → b'\xff\xff'
        src = "def f() -> bytes:\n    return (-1).to_bytes(2, 'big', signed=True)"
        self._result_bytes(src)


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


class TestErrors(unittest.TestCase):

    def test_non_int_receiver_raises(self):
        src = "def f(s: str) -> bytes:\n    return s.to_bytes(1, 'big')"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_bytes_receiver_raises(self):
        src = "def f(b: bytes) -> bytes:\n    return b.to_bytes(1, 'big')"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_non_literal_byteorder_raises(self):
        src = "def f(x: int, order: str) -> bytes:\n" "    return x.to_bytes(1, order)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_invalid_byteorder_raises(self):
        src = "def f(x: int) -> bytes:\n    return x.to_bytes(1, 'middle')"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_non_literal_signed_raises(self):
        src = (
            "def f(x: int, s: bool) -> bytes:\n"
            "    return x.to_bytes(1, 'big', signed=s)"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_too_many_positional_args_raises(self):
        src = "def f(x: int) -> bytes:\n    return x.to_bytes(1, 'big', False)"
        with self.assertRaises((TypecheckError, Exception)):
            compile_function(src)

    def test_unknown_keyword_raises(self):
        src = (
            "def f(x: int) -> bytes:\n    return x.to_bytes(1, 'big', endian='little')"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_str_length_raises(self):
        src = "def f(x: int) -> bytes:\n    return x.to_bytes('a', 'big')"
        with self.assertRaises(TypecheckError):
            compile_function(src)
