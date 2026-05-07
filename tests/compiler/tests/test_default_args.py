"""Tests for default argument values in function definitions."""

import unittest
from neo3.compiler import TypecheckError, compile_module


class TestDefaultArgCompiles(unittest.TestCase):
    """Default args compile without error and produce valid bytecode."""

    def test_single_int_default(self) -> None:
        src = """
def f(x: int, y: int = 5) -> int:
    return x + y
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_multiple_defaults(self) -> None:
        src = """
def f(a: int, b: int = 2, c: int = 3) -> int:
    return a + b + c
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_all_args_have_defaults(self) -> None:
        src = """
def f(x: int = 1, y: int = 2) -> int:
    return x + y
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_bool_default(self) -> None:
        src = """
def f(x: int, flag: bool = True) -> bool:
    if flag:
        return x > 0
    return False
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_str_default(self) -> None:
        src = """
def f(prefix: str = "hello") -> str:
    return prefix
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_bytes_default(self) -> None:
        src = """
def f(data: bytes = b"\\x01\\x02") -> bytes:
    return data
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_none_default(self) -> None:
        src = """
from typing import Optional
def f(x: Optional[int] = None) -> bool:
    return x is None
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_zero_default(self) -> None:
        src = """
def f(x: int = 0) -> int:
    return x
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_negative_int_default(self) -> None:
        """Negative integer literals are ast.UnaryOp(op=USub, operand=Constant), not Constant.
        So they must be rejected with TypecheckError."""
        with self.assertRaises(TypecheckError):
            compile_module(
                """
def f(x: int = -7) -> int:
    return x
"""
            )

    def test_default_in_helper_callable_from_public(self) -> None:
        src = """
def add(a: int, b: int = 100) -> int:
    return a + b

def entry(x: int) -> int:
    return add(x)
"""
        self.assertIsInstance(compile_module(src), bytes)


class TestDefaultArgCallSite(unittest.TestCase):
    """Arity checking with defaults at call sites."""

    def test_call_with_all_args(self) -> None:
        src = """
def f(x: int, y: int = 5) -> int:
    return x + y

def g(a: int) -> int:
    return f(a, 10)
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_call_with_default_omitted(self) -> None:
        src = """
def f(x: int, y: int = 5) -> int:
    return x + y

def g(a: int) -> int:
    return f(a)
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_call_omit_two_defaults(self) -> None:
        src = """
def f(a: int, b: int = 2, c: int = 3) -> int:
    return a + b + c

def g(x: int) -> int:
    return f(x)
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_call_omit_one_of_two_defaults(self) -> None:
        src = """
def f(a: int, b: int = 2, c: int = 3) -> int:
    return a + b + c

def g(x: int) -> int:
    return f(x, 20)
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_stmt_call_with_default_omitted(self) -> None:
        """Statement-call (void function) also supports defaults."""
        src = """
x: int = 0

def log(msg: str, level: int = 0) -> None:
    global x
    x = level

def entry() -> None:
    log("hello")
"""
        self.assertIsInstance(compile_module(src), bytes)


class TestDefaultArgErrors(unittest.TestCase):
    """Type errors related to defaults."""

    def test_too_few_required_args_raises(self) -> None:
        src = """
def f(x: int, y: int) -> int:
    return x + y

def g() -> int:
    return f(1)
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_too_many_args_raises(self) -> None:
        src = """
def f(x: int) -> int:
    return x

def g() -> int:
    return f(1, 2)
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_too_many_args_when_defaults_present_raises(self) -> None:
        src = """
def f(x: int, y: int = 5) -> int:
    return x + y

def g() -> int:
    return f(1, 2, 3)
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_non_literal_default_raises(self) -> None:
        """Default must be a plain constant — a name reference raises."""
        with self.assertRaises(TypecheckError):
            compile_module(
                """
def f(x: int = some_var) -> int:
    return x
"""
            )

    def test_list_default_raises(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                """
def f(x: list[int] = [1, 2]) -> int:
    return x[0]
"""
            )

    def test_wrong_type_for_defaulted_arg_raises(self) -> None:
        """Passing wrong type for a param that has a default → TypecheckError."""
        with self.assertRaises(TypecheckError):
            compile_module(
                """
def f(x: int, y: int = 5) -> int:
    return x + y

def caller() -> int:
    return f(1, True)
"""
            )

    def test_nested_function_def_raises(self) -> None:
        """Nested function definitions are explicitly rejected."""
        with self.assertRaises(TypecheckError):
            compile_module(
                """
def outer(x: int) -> int:
    def inner(y: int) -> int:
        return y + 1
    return inner(x)
"""
            )
