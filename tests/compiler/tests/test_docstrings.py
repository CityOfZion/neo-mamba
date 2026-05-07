"""Tests that docstrings and bare string expressions are silently ignored."""

import unittest
from neo3.compiler import compile_module


class TestDocstringsCompile(unittest.TestCase):
    """Docstrings must not cause errors and must not affect the emitted bytecode."""

    def _src_without(self) -> str:
        return """
def f(x: int) -> int:
    return x + 1
"""

    def test_function_docstring_single_line(self) -> None:
        src = """
def f(x: int) -> int:
    "Compute x plus one."
    return x + 1
"""
        self.assertEqual(compile_module(src), compile_module(self._src_without()))

    def test_function_docstring_multiline(self) -> None:
        src = '''
def f(x: int) -> int:
    """
    Compute x plus one.

    Args:
        x: the input value.
    """
    return x + 1
'''
        self.assertEqual(compile_module(src), compile_module(self._src_without()))

    def test_module_docstring(self) -> None:
        """Module-level docstring (before any function) must not raise."""
        src = '''
"""This contract does maths."""

def f(x: int) -> int:
    return x + 1
'''
        self.assertEqual(compile_module(src), compile_module(self._src_without()))

    def test_inline_string_expression(self) -> None:
        """A bare string anywhere in a function body is also a no-op."""
        src = """
def f(x: int) -> int:
    "step one"
    y: int = x + 1
    "step two"
    return y
"""
        expected = """
def f(x: int) -> int:
    y: int = x + 1
    return y
"""
        self.assertEqual(compile_module(src), compile_module(expected))

    def test_comment_above_statement(self) -> None:
        """A # comment on its own line is stripped by ast.parse before the compiler sees it."""
        src = """
def f(x: int) -> int:
    # compute x plus one
    return x + 1
"""
        self.assertEqual(compile_module(src), compile_module(self._src_without()))

    def test_inline_comment(self) -> None:
        """A trailing # comment on the same line as a statement is stripped by ast.parse."""
        src = """
def f(x: int) -> int:
    return x + 1  # this returns x plus one
"""
        self.assertEqual(compile_module(src), compile_module(self._src_without()))

    def test_docstring_in_multi_function_module(self) -> None:
        """Docstrings in every function of a multi-function module all compile."""
        src = '''
"""Module docstring."""

def helper(n: int) -> int:
    """Return n doubled."""
    return n * 2

def entry(x: int) -> int:
    """Entry point."""
    return helper(x)
'''
        self.assertIsInstance(compile_module(src), bytes)
