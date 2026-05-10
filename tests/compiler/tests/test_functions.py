import unittest

from neo3.compiler import TypecheckError, compile_module


# ---------------------------------------------------------------------------
# Multiple functions + CALL_L
# ---------------------------------------------------------------------------


class TestMultiFunctionCalls(unittest.TestCase):

    _ADD_SRC = """
def add(a: int, b: int) -> int:
    return a + b

def main(x: int, y: int) -> int:
    result: int = add(x, y)
    return result
"""

    # --- compilation ---

    def test_two_functions_compile(self):
        self.assertIsInstance(compile_module(self._ADD_SRC), bytes)

    def test_call_l_opcode_in_bytecode(self):
        bc = compile_module(self._ADD_SRC)
        self.assertIn(0x35, bc)  # CALL_L opcode

    def test_return_value_in_expression(self):
        src = """
def add(a: int, b: int) -> int:
    return a + b

def main(x: int, y: int) -> int:
    result: int = add(x, y) + 1
    return result
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_call_in_while_condition(self):
        src = """
def gt_zero(n: int) -> bool:
    return n > 0

def countdown(n: int) -> int:
    while gt_zero(n):
        n -= 1
    return n
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_recursive_function_compiles(self):
        src = """
def fact(n: int) -> int:
    result: int = 1
    if n > 1:
        result = n * fact(n - 1)
    return result
"""
        self.assertIsInstance(compile_module(src), bytes)

    # --- type / arity errors ---

    def test_call_wrong_arg_type_raises(self):
        src = """
def needs_bool(b: bool) -> bool:
    return b

def caller(x: int) -> bool:
    return needs_bool(x)
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_call_wrong_arity_raises(self):
        src = """
def add(a: int, b: int) -> int:
    return a + b

def caller(x: int) -> int:
    return add(x)
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_call_unknown_function_raises(self):
        src = """
def caller(x: int) -> int:
    return unknown(x)
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
