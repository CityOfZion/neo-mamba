import unittest

from neo3.compiler import TypecheckError, compile_function

_PACK = 0xC0
_SYSCALL = 0x41


class TestBytesHex(unittest.TestCase):

    def test_bytes_var_compiles(self):
        src = "def f(b: bytes) -> str:\n    return b.hex()"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bytearray_var_compiles(self):
        src = "def f(b: bytearray) -> str:\n    return b.hex()"
        self.assertIsInstance(compile_function(src), bytes)

    def test_literal_compiles(self):
        src = 'def f() -> str:\n    return b"\\x01\\x02".hex()'
        self.assertIsInstance(compile_function(src), bytes)

    def test_emits_pack_opcode(self):
        src = "def f(b: bytes) -> str:\n    return b.hex()"
        bc = compile_function(src)
        self.assertIn(_PACK, bc)

    def test_emits_syscall_opcode(self):
        src = "def f(b: bytes) -> str:\n    return b.hex()"
        bc = compile_function(src)
        self.assertIn(_SYSCALL, bc)

    def test_result_used_in_expression(self):
        src = "def f(b: bytes) -> int:\n    s: str = b.hex()\n    return len(s)"
        self.assertIsInstance(compile_function(src), bytes)


class TestBytesHexErrors(unittest.TestCase):

    def test_str_raises(self):
        src = "def f(s: str) -> str:\n    return s.hex()"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_int_raises(self):
        src = "def f(x: int) -> str:\n    return x.hex()"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_hex_with_arg_raises(self):
        src = "def f(b: bytes) -> str:\n    return b.hex(1)"
        with self.assertRaises((TypecheckError, Exception)):
            compile_function(src)
