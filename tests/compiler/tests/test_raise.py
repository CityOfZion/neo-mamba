import unittest

from neo3.compiler import TypecheckError, compile_function


class TestRaiseWithMessage(unittest.TestCase):

    def test_raise_with_str_literal_compiles(self):
        src = 'def f(x: int) -> int:\n    raise ValueError("bad input")\n    return x'
        self.assertIsInstance(compile_function(src), bytes)

    def test_raise_emits_throw_opcode(self):
        src = 'def f(x: int) -> int:\n    raise ValueError("bad input")\n    return x'
        bc = compile_function(src)
        self.assertIn(0x3A, bc)  # THROW

    def test_raise_with_str_var_compiles(self):
        src = "def f(msg: str) -> int:\n    raise ValueError(msg)\n    return 0"
        self.assertIsInstance(compile_function(src), bytes)

    def test_raise_non_str_message_raises(self):
        src = "def f(x: int) -> int:\n    raise ValueError(x)\n    return 0"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_raise_in_if_branch_compiles(self):
        src = """
def f(x: int) -> int:
    if x < 0:
        raise ValueError("negative")
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)


class TestRaiseNoArgs(unittest.TestCase):

    def test_raise_no_args_compiles(self):
        src = "def f(x: int) -> int:\n    raise ValueError()\n    return x"
        self.assertIsInstance(compile_function(src), bytes)

    def test_raise_no_args_emits_throw(self):
        src = "def f(x: int) -> int:\n    raise ValueError()\n    return x"
        bc = compile_function(src)
        self.assertIn(0x3A, bc)  # THROW

    def test_raise_bare_type_compiles(self):
        src = "def f(x: int) -> int:\n    raise ValueError\n    return x"
        self.assertIsInstance(compile_function(src), bytes)


class TestRaiseErrors(unittest.TestCase):

    def test_bare_raise_not_supported(self):
        src = "def f(x: int) -> int:\n    raise\n    return x"
        with self.assertRaises(TypecheckError):
            compile_function(src)
