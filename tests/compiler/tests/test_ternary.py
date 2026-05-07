import unittest

from neo3.compiler import TypecheckError, compile_function


class TestTernary(unittest.TestCase):

    def test_basic_ternary_compiles(self):
        src = "def f(a: int, b: int, c: bool) -> int:\n    return a if c else b"
        self.assertIsInstance(compile_function(src), bytes)

    def test_ternary_with_comparison_condition(self):
        src = "def f(a: int, b: int) -> int:\n    return a if a > b else b"
        self.assertIsInstance(compile_function(src), bytes)

    def test_ternary_emits_conditional_jump(self):
        src = "def f(a: int, b: int, c: bool) -> int:\n    return a if c else b"
        bc = compile_function(src)
        self.assertIn(0x25, bc)  # JMPIF_L

    def test_ternary_in_assignment(self):
        src = """
def f(x: int) -> int:
    y: int = x if x > 0 else 0
    return y
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_ternary_as_subexpression(self):
        src = "def f(a: int, b: int, c: bool) -> int:\n    return (a if c else b) + 1"
        self.assertIsInstance(compile_function(src), bytes)

    def test_nested_ternary(self):
        src = """
def f(a: int, b: int, c: int, p: bool, q: bool) -> int:
    return a if p else (b if q else c)
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_ternary_branch_type_mismatch_raises(self):
        src = "def f(a: int, b: bool, c: bool) -> int:\n    return a if c else b"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_ternary_non_bool_condition_raises(self):
        src = "def f(a: int, b: int) -> int:\n    return a if a else b"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_ternary_bool_branches(self):
        src = "def f(c: bool, p: bool, q: bool) -> bool:\n    return p if c else q"
        self.assertIsInstance(compile_function(src), bytes)
