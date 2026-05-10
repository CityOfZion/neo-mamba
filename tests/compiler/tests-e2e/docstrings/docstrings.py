from neo3.sc.compiletime import public

"""
Module-level docstring.

This contract demonstrates that docstrings at all levels are
silently ignored by the compiler and do not affect bytecode.
"""


@public
def add(a: int, b: int) -> int:
    """Add two integers and return the result."""
    return a + b


@public
def multiply(a: int, b: int) -> int:
    """
    Multiply two integers.

    Args:
        a: first factor
        b: second factor

    Returns:
        the product a * b
    """
    "inline string before body"
    result: int = a * b
    "inline string mid-body"
    return result


@public
def subtract(a: int, b: int) -> int:
    # subtract b from a
    result: int = a - b  # compute the difference
    return result  # this returns the difference
