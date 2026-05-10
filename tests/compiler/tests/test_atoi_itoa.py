import unittest

from neo3.compiler import TypecheckError, compile_function

_PACK = 0xC0
_SYSCALL = 0x41
_CONVERT = 0xDB


class TestAtoi(unittest.TestCase):
    """int(s) and int(s, base) → StdLib.atoi"""

    def test_int_str_default_base_compiles(self):
        src = "def f(s: str) -> int:\n    return int(s)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_str_default_base_emits_syscall(self):
        src = "def f(s: str) -> int:\n    return int(s)"
        bc = compile_function(src)
        self.assertIn(_PACK, bc)
        self.assertIn(_SYSCALL, bc)

    def test_int_str_default_base_no_convert(self):
        src = "def f(s: str) -> int:\n    return int(s)"
        bc = compile_function(src)
        self.assertNotIn(_CONVERT, bc)

    def test_int_str_explicit_base10_compiles(self):
        src = "def f(s: str) -> int:\n    return int(s, 10)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_str_base16_compiles(self):
        src = "def f(s: str) -> int:\n    return int(s, 16)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_str_literal_compiles(self):
        src = 'def f() -> int:\n    return int("123")'
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_bool_still_uses_convert(self):
        src = "def f(b: bool) -> int:\n    return int(b)"
        bc = compile_function(src)
        self.assertIn(_CONVERT, bc)

    def test_int_bytes_still_uses_convert(self):
        src = "def f(b: bytes) -> int:\n    return int(b)"
        bc = compile_function(src)
        self.assertIn(_CONVERT, bc)

    def test_int_str_base8_raises(self):
        src = "def f(s: str) -> int:\n    return int(s, 8)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_int_str_base2_raises(self):
        src = "def f(s: str) -> int:\n    return int(s, 2)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_int_int_with_base_raises(self):
        src = "def f(x: int) -> int:\n    return int(x, 10)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_int_bytes_with_base_raises(self):
        src = "def f(b: bytes) -> int:\n    return int(b, 16)"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestItoa(unittest.TestCase):
    """str(x) and str(x, base) → StdLib.itoa for int x"""

    def test_str_int_default_compiles(self):
        src = "def f(x: int) -> str:\n    return str(x)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_int_default_emits_syscall(self):
        src = "def f(x: int) -> str:\n    return str(x)"
        bc = compile_function(src)
        self.assertIn(_PACK, bc)
        self.assertIn(_SYSCALL, bc)

    def test_str_int_default_no_convert(self):
        src = "def f(x: int) -> str:\n    return str(x)"
        bc = compile_function(src)
        self.assertNotIn(_CONVERT, bc)

    def test_str_int_base10_compiles(self):
        src = "def f(x: int) -> str:\n    return str(x, 10)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_int_base16_compiles(self):
        src = "def f(x: int) -> str:\n    return str(x, 16)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_bytes_still_uses_convert(self):
        src = "def f(b: bytes) -> str:\n    return str(b)"
        bc = compile_function(src)
        self.assertIn(_CONVERT, bc)

    def test_str_bool_does_not_use_convert(self):
        src = "def f(b: bool) -> str:\n    return str(b)"
        bc = compile_function(src)
        self.assertNotIn(_CONVERT, bc)

    def test_str_bool_compiles(self):
        src = "def f(b: bool) -> str:\n    return str(b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_int_base8_raises(self):
        src = "def f(x: int) -> str:\n    return str(x, 8)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_str_bytes_with_base_raises(self):
        src = "def f(b: bytes) -> str:\n    return str(b, 10)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_str_int_base_non_int_raises(self):
        src = 'def f(x: int) -> str:\n    return str(x, "10")'
        with self.assertRaises((TypecheckError, Exception)):
            compile_function(src)
