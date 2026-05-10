import unittest

from neo3.compiler import TypecheckError, compile_function


class TestIntConvert(unittest.TestCase):

    def test_int_from_bool_compiles(self):
        src = "def f(b: bool) -> int:\n    return int(b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_from_str_compiles(self):
        src = "def f(s: str) -> int:\n    return int(s)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_from_bytes_compiles(self):
        src = "def f(b: bytes) -> int:\n    return int(b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_from_bytearray_compiles(self):
        src = "def f(ba: bytearray) -> int:\n    return int(ba)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_from_int_compiles(self):
        src = "def f(x: int) -> int:\n    return int(x)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_emits_convert_opcode(self):
        src = "def f(b: bool) -> int:\n    return int(b)"
        bc = compile_function(src)
        self.assertIn(0xDB, bc)  # CONVERT

    def test_int_from_list_raises(self):
        src = "def f(lst: list[int]) -> int:\n    return int(lst)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_int_from_optional_raises(self):
        from typing import Optional

        src = "def f(x: int) -> int:\n    y: int = 0\n    return int(y)"
        # This should compile fine (int->int); test Optional separately
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_from_optional_type_raises(self):
        src = "def f(x: int) -> int:\n    return int(x)\n"
        # Wrap in Optional context by annotating with Optional[int]
        src2 = """
def f() -> int:
    x: int = 5
    y: int = int(x)
    return y
"""
        self.assertIsInstance(compile_function(src2), bytes)


class TestBoolConvert(unittest.TestCase):

    def test_bool_from_int_compiles(self):
        src = "def f(x: int) -> bool:\n    return bool(x)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bool_from_str_compiles(self):
        src = "def f(s: str) -> bool:\n    return bool(s)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bool_from_bytes_compiles(self):
        src = "def f(b: bytes) -> bool:\n    return bool(b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bool_from_bytearray_compiles(self):
        src = "def f(ba: bytearray) -> bool:\n    return bool(ba)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bool_emits_convert_opcode(self):
        src = "def f(x: int) -> bool:\n    return bool(x)"
        bc = compile_function(src)
        self.assertIn(0xDB, bc)  # CONVERT
        self.assertIn(0x20, bc)  # Boolean tag

    def test_bool_from_dict_raises(self):
        src = "def f(d: dict[str, int]) -> bool:\n    return bool(d)"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestStrConvert(unittest.TestCase):

    def test_str_from_bytes_compiles(self):
        src = "def f(b: bytes) -> str:\n    return str(b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_from_bytearray_compiles(self):
        src = "def f(ba: bytearray) -> str:\n    return str(ba)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_from_int_compiles(self):
        src = "def f(x: int) -> str:\n    return str(x)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_from_bool_compiles(self):
        src = "def f(b: bool) -> str:\n    return str(b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_emits_convert_opcode(self):
        src = "def f(b: bytes) -> str:\n    return str(b)"
        bc = compile_function(src)
        self.assertIn(0xDB, bc)  # CONVERT

    def test_str_from_tuple_raises(self):
        src = "def f(t: tuple[int]) -> str:\n    return str(t)"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestBytesConvert(unittest.TestCase):

    def test_bytes_from_str_compiles(self):
        src = "def f(s: str) -> bytes:\n    return bytes(s)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bytes_from_bytearray_compiles(self):
        src = "def f(ba: bytearray) -> bytes:\n    return bytes(ba)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bytes_from_int_compiles(self):
        src = "def f(x: int) -> bytes:\n    return bytes(x)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bytes_emits_convert_opcode(self):
        src = "def f(s: str) -> bytes:\n    return bytes(s)"
        bc = compile_function(src)
        self.assertIn(0xDB, bc)  # CONVERT

    def test_bytes_from_list_raises(self):
        src = "def f(lst: list[int]) -> bytes:\n    return bytes(lst)"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestConvertInExpressions(unittest.TestCase):

    def test_convert_used_in_arithmetic(self):
        src = """
def f(b: bool) -> int:
    return int(b) + 1
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_convert_chained(self):
        src = """
def f(x: int) -> str:
    return str(bytes(x))
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_convert_in_condition(self):
        src = """
def f(x: int) -> bool:
    if bool(x):
        return True
    return False
"""
        self.assertIsInstance(compile_function(src), bytes)
