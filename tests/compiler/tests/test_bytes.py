import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestBytesLiteral(unittest.TestCase):

    def test_bytes_literal_compiles(self):
        src = """
def f() -> bytes:
    return b"hello"
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        # PUSHDATA1 = 0x0C must appear in the bytecode
        self.assertIn(0x0C, bc)

    def test_bytes_literal_pushdata1_format(self):
        src = """
def f() -> bytes:
    return b"hi"
"""
        bc = compile_function(src)
        # Find PUSHDATA1 (0x0C), followed by length byte (2), followed by b"hi"
        idx = bc.index(0x0C)
        self.assertEqual(bc[idx + 1], 2)
        self.assertEqual(bc[idx + 2 : idx + 4], b"hi")

    def test_bytes_local_variable(self):
        src = """
def f() -> bytes:
    x: bytes = b"neo"
    return x
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_bytes_as_argument(self):
        src = """
def f(data: bytes) -> bytes:
    return data
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_empty_bytes_literal(self):
        src = """
def f() -> bytes:
    return b""
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        idx = bc.index(0x0C)
        self.assertEqual(bc[idx + 1], 0)  # length = 0

    def test_bytes_cfg_has_push_bytes(self):
        src = """
def f() -> bytes:
    return b"abc"
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("PUSH_BYTES", ops)


class TestBytearrayLiteral(unittest.TestCase):

    def test_bytearray_compiles(self):
        src = """
def f() -> bytearray:
    return bytearray(5)
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        # NEWBUFFER = 0x88
        self.assertIn(0x88, bc)

    def test_bytearray_local_variable(self):
        src = """
def f() -> bytearray:
    buf: bytearray = bytearray(10)
    return buf
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_bytearray_as_argument(self):
        src = """
def f(buf: bytearray) -> bytearray:
    return buf
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_bytearray_cfg_has_newbuffer(self):
        src = """
def f() -> bytearray:
    return bytearray(3)
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("PUSH_INT", ops)  # size arg
        self.assertIn("NEWBUFFER", ops)


class TestLen(unittest.TestCase):

    def test_len_bytes_compiles(self):
        src = """
def f() -> int:
    return len(b"hello")
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        # SIZE = 0xCA
        self.assertIn(0xCA, bc)

    def test_len_bytearray_compiles(self):
        src = """
def f(buf: bytearray) -> int:
    return len(buf)
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCA, bc)

    def test_len_bytes_cfg_ops(self):
        src = """
def f() -> int:
    return len(b"ab")
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("PUSH_BYTES", ops)
        self.assertIn("SIZE", ops)

    def test_len_bytearray_cfg_ops(self):
        src = """
def f(n: int) -> int:
    return len(bytearray(n))
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("NEWBUFFER", ops)
        self.assertIn("SIZE", ops)

    def test_len_local_bytes(self):
        src = """
def f() -> int:
    data: bytes = b"neo3"
    return len(data)
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestTypeErrors(unittest.TestCase):

    def test_len_of_int_raises(self):
        src = """
def f(x: int) -> int:
    return len(x)
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_len_of_bool_raises(self):
        src = """
def f(x: bool) -> int:
    return len(x)
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_bytearray_from_bytes_compiles(self):
        src = """
def f() -> bytearray:
    return bytearray(b"hello")
"""
        compile_function(src)

    def test_bytearray_reverse_compiles(self):
        src = """
def f() -> bytearray:
    ba: bytearray = bytearray(b"hello")
    ba.reverse()
    return ba
"""
        compile_function(src)

    def test_bytearray_reverse_on_invalid_type_raises(self):
        src = """
def f(s: str) -> str:
    s.reverse()
    return s
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_assign_bytes_to_int_raises(self):
        src = """
def f() -> int:
    x: int = b"hi"
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_assign_int_to_bytes_raises(self):
        src = """
def f() -> bytes:
    x: bytes = 42
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_arithmetic_on_bytes_raises(self):
        src = """
def f(a: bytes, b: bytes) -> int:
    return a + b
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestCat(unittest.TestCase):

    def test_bytes_plus_bytes_compiles(self):
        src = """
def f(a: bytes, b: bytes) -> bytes:
    return a + b
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8B, bc)  # CAT

    def test_bytearray_plus_bytearray_compiles(self):
        src = """
def f(a: bytearray, b: bytearray) -> bytearray:
    return a + b
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8B, bc)  # CAT
        self.assertIn(0xDB, bc)  # CONVERT

    def test_bytes_plus_bytearray_returns_bytes(self):
        src = """
def f(a: bytes, b: bytearray) -> bytes:
    return a + b
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8B, bc)
        self.assertNotIn(0xDB, bc)  # no CONVERT needed

    def test_bytearray_plus_bytes_returns_bytes(self):
        src = """
def f(a: bytearray, b: bytes) -> bytes:
    return a + b
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8B, bc)
        self.assertNotIn(0xDB, bc)

    def test_bytearray_cat_cfg_has_convert(self):
        src = """
def f(a: bytearray, b: bytearray) -> bytearray:
    return a + b
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("cat", ops)
        self.assertIn("CONVERT", ops)

    def test_bytes_cat_cfg_no_convert(self):
        src = """
def f(a: bytes, b: bytes) -> bytes:
    return a + b
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("cat", ops)
        self.assertNotIn("CONVERT", ops)

    def test_cat_local_variable(self):
        src = """
def f(a: bytes, b: bytes) -> bytes:
    result: bytes = a + b
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_bytes_plus_int_raises(self):
        src = """
def f(a: bytes, n: int) -> bytes:
    return a + n
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_int_plus_bytes_raises(self):
        src = """
def f(n: int, b: bytes) -> bytes:
    return n + b
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_int_addition_still_works(self):
        src = """
def f(a: int, b: int) -> int:
    return a + b
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertNotIn(0x8B, bc)  # no CAT


class TestIndex(unittest.TestCase):

    def test_bytes_index_compiles(self):
        src = """
def f(data: bytes) -> int:
    return data[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCE, bc)  # PICKITEM

    def test_bytearray_index_compiles(self):
        src = """
def f(buf: bytearray, i: int) -> int:
    return buf[i]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCE, bc)

    def test_index_result_is_int(self):
        src = """
def f(data: bytes) -> int:
    x: int = data[2]
    return x
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_index_literal_bytes(self):
        src = """
def f() -> int:
    return b"neo"[1]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_index_cfg_has_pickitem(self):
        src = """
def f(data: bytes, i: int) -> int:
    return data[i]
"""
        cfg = _build_cfg(src)
        ops = [instr.op for b in cfg.blocks.values() for instr in b.instructions]
        self.assertIn("PICKITEM", ops)

    def test_index_int_raises(self):
        src = """
def f(n: int) -> int:
    return n[0]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_index_bool_index_raises(self):
        src = """
def f(data: bytes, flag: bool) -> int:
    return data[flag]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


if __name__ == "__main__":
    unittest.main()
