import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestStrLiteral(unittest.TestCase):

    def test_str_literal_compiles(self):
        src = """
def f() -> str:
    return "hello"
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x0C, bc)  # PUSHDATA1

    def test_str_literal_utf8_encoded(self):
        src = """
def f() -> str:
    return "hi"
"""
        bc = compile_function(src)
        idx = bc.index(0x0C)
        self.assertEqual(bc[idx + 1], 2)  # length = 2
        self.assertEqual(bc[idx + 2 : idx + 4], b"hi")

    def test_str_local_variable(self):
        src = """
def f() -> str:
    name: str = "neo"
    return name
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_str_as_argument(self):
        src = """
def f(s: str) -> str:
    return s
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_empty_str_literal(self):
        src = """
def f() -> str:
    return ""
"""
        bc = compile_function(src)
        idx = bc.index(0x0C)
        self.assertEqual(bc[idx + 1], 0)

    def test_str_cfg_has_push_str(self):
        src = """
def f() -> str:
    return "abc"
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("PUSH_STR", ops)


class TestStrLen(unittest.TestCase):

    def test_len_str_compiles(self):
        src = """
def f() -> int:
    return len("hello")
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCA, bc)  # SIZE

    def test_len_str_arg_compiles(self):
        src = """
def f(s: str) -> int:
    return len(s)
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_len_str_cfg_has_size(self):
        src = """
def f(s: str) -> int:
    return len(s)
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("SIZE", ops)


class TestStrConcat(unittest.TestCase):

    def test_str_plus_str_compiles(self):
        src = """
def f(a: str, b: str) -> str:
    return a + b
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8B, bc)  # CAT

    def test_str_plus_str_no_convert(self):
        # str + str → str (ByteString), no CONVERT needed
        src = """
def f(a: str, b: str) -> str:
    return a + b
"""
        bc = compile_function(src)
        self.assertNotIn(0xDB, bc)  # no CONVERT

    def test_str_concat_local(self):
        src = """
def f(a: str, b: str) -> str:
    result: str = a + b
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_str_plus_bytes_raises(self):
        src = """
def f(a: str, b: bytes) -> str:
    return a + b
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_str_plus_bytearray_raises(self):
        src = """
def f(a: str, b: bytearray) -> str:
    return a + b
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_bytes_plus_str_raises(self):
        src = """
def f(a: bytes, b: str) -> bytes:
    return a + b
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestStrEquality(unittest.TestCase):

    def test_str_eq_str_compiles(self):
        src = """
def f(a: str, b: str) -> bool:
    return a == b
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x97, bc)  # EQUAL

    def test_str_neq_str_compiles(self):
        src = """
def f(a: str, b: str) -> bool:
    return a != b
"""
        bc = compile_function(src)
        self.assertIn(0x98, bc)  # NOTEQUAL

    def test_str_eq_bytes_folds_to_false(self):
        # Python: "abc" == b"abc" → False, not an error
        src = """
def f(a: str, b: bytes) -> bool:
    return a == b
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertNotIn(0x97, bc)  # no EQUAL emitted
        self.assertIn(0x09, bc)  # PUSHF (false)

    def test_str_neq_bytes_folds_to_true(self):
        src = """
def f(a: str, b: bytes) -> bool:
    return a != b
"""
        bc = compile_function(src)
        self.assertNotIn(0x98, bc)  # no NOTEQUAL emitted
        self.assertIn(0x08, bc)  # PUSHT (true)

    def test_bytes_eq_str_folds_to_false(self):
        src = """
def f(a: bytes, b: str) -> bool:
    return a == b
"""
        bc = compile_function(src)
        self.assertNotIn(0x97, bc)
        self.assertIn(0x09, bc)

    def test_str_eq_str_cfg_has_equal(self):
        src = """
def f(a: str, b: str) -> bool:
    return a == b
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("==", ops)


class TestStrTypeErrors(unittest.TestCase):

    def test_assign_str_to_int_raises(self):
        src = """
def f() -> int:
    x: int = "hello"
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_assign_int_to_str_raises(self):
        src = """
def f() -> str:
    x: str = 42
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_len_of_int_unchanged(self):
        src = """
def f(x: int) -> int:
    return len(x)
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


if __name__ == "__main__":
    unittest.main()
