import unittest

from neo3.compiler import TypecheckError, compile_function

_PACK = 0xC0
_SYSCALL = 0x41


class TestBytesFromHex(unittest.TestCase):

    def test_literal_arg_compiles(self):
        src = 'def f() -> bytes:\n    return bytes.fromhex("aabbcc")'
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_var_arg_compiles(self):
        src = "def f(s: str) -> bytes:\n    return bytes.fromhex(s)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_emits_pack_opcode(self):
        src = "def f(s: str) -> bytes:\n    return bytes.fromhex(s)"
        bc = compile_function(src)
        self.assertIn(_PACK, bc)

    def test_emits_syscall_opcode(self):
        src = "def f(s: str) -> bytes:\n    return bytes.fromhex(s)"
        bc = compile_function(src)
        self.assertIn(_SYSCALL, bc)

    def test_used_in_expression(self):
        src = (
            "def f(s: str) -> int:\n    b: bytes = bytes.fromhex(s)\n    return len(b)"
        )
        self.assertIsInstance(compile_function(src), bytes)


class TestBytesFromHexErrors(unittest.TestCase):

    def test_int_arg_raises(self):
        src = "def f(x: int) -> bytes:\n    return bytes.fromhex(x)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_bytes_arg_raises(self):
        src = 'def f() -> bytes:\n    return bytes.fromhex(b"aabb")'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_no_args_raises(self):
        src = "def f() -> bytes:\n    return bytes.fromhex()"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_two_args_raises(self):
        src = 'def f() -> bytes:\n    return bytes.fromhex("aa", "bb")'
        with self.assertRaises(TypecheckError):
            compile_function(src)
