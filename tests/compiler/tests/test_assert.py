import unittest

from neo3.compiler import TypecheckError, compile_function


class TestAssertNoMessage(unittest.TestCase):

    def test_assert_true_compiles(self):
        src = "def f() -> int:\n    assert True\n    return 1"
        self.assertIsInstance(compile_function(src), bytes)

    def test_assert_emits_assert_opcode(self):
        src = "def f() -> int:\n    assert True\n    return 1"
        bc = compile_function(src)
        self.assertIn(0x39, bc)  # ASSERT

    def test_assert_bool_var_compiles(self):
        src = "def f(cond: bool) -> int:\n    assert cond\n    return 1"
        self.assertIsInstance(compile_function(src), bytes)

    def test_assert_comparison_compiles(self):
        src = "def f(x: int) -> int:\n    assert x > 0\n    return x"
        self.assertIsInstance(compile_function(src), bytes)

    def test_assert_non_bool_condition_raises(self):
        src = "def f(x: int) -> int:\n    assert x\n    return x"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestAssertWithMessage(unittest.TestCase):

    def test_assert_msg_literal_compiles(self):
        src = 'def f(cond: bool) -> int:\n    assert cond, "bad input"\n    return 1'
        self.assertIsInstance(compile_function(src), bytes)

    def test_assert_msg_emits_assertmsg_opcode(self):
        src = 'def f(cond: bool) -> int:\n    assert cond, "bad input"\n    return 1'
        bc = compile_function(src)
        self.assertIn(0xE1, bc)  # ASSERTMSG

    def test_assert_msg_str_var_compiles(self):
        src = "def f(cond: bool, msg: str) -> int:\n    assert cond, msg\n    return 1"
        self.assertIsInstance(compile_function(src), bytes)

    def test_assert_msg_non_str_raises(self):
        src = "def f(cond: bool, x: int) -> int:\n    assert cond, x\n    return 1"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_assert_msg_non_bool_condition_raises(self):
        src = 'def f(x: int) -> int:\n    assert x, "err"\n    return x'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_assert_in_function_body_with_other_stmts(self):
        src = """
def f(x: int) -> int:
    y: int = x + 1
    assert y > 0
    assert y > 0, "y must be positive"
    return y
"""
        self.assertIsInstance(compile_function(src), bytes)
