import unittest

from neo3.compiler import TypecheckError, compile_function, disassemble


class TestDictCompBasic(unittest.TestCase):

    def test_identity_compiles(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    result: dict[int, int] = {x: x for x in lst}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_transform_value_compiles(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    result: dict[int, int] = {x: x * 2 for x in lst}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_filter_compiles(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    result: dict[int, int] = {x: x for x in lst if x > 0}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_filter_and_transform_compiles(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    result: dict[int, int] = {x: x * 2 for x in lst if x > 0}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_multiple_filters_compiles(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    result: dict[int, int] = {x: x for x in lst if x > 0 if x < 100}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_return_directly(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    return {x: x * 2 for x in lst}
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_str_keys(self):
        src = """
def f(lst: list[str]) -> dict[str, int]:
    result: dict[str, int] = {s: 1 for s in lst}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_bytes_keys(self):
        src = """
def f(lst: list[bytes]) -> dict[bytes, int]:
    result: dict[bytes, int] = {b: 1 for b in lst}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_bool_keys(self):
        src = """
def f(lst: list[bool]) -> dict[bool, int]:
    result: dict[bool, int] = {b: 1 for b in lst}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestDictCompRange(unittest.TestCase):

    def test_range_one_arg(self):
        src = """
def f() -> dict[int, int]:
    result: dict[int, int] = {x: x * x for x in range(5)}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_range_two_args(self):
        src = """
def f() -> dict[int, int]:
    result: dict[int, int] = {x: x for x in range(1, 10)}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_range_with_step(self):
        src = """
def f() -> dict[int, int]:
    result: dict[int, int] = {x: x for x in range(0, 10, 2)}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_range_with_filter(self):
        src = """
def f() -> dict[int, int]:
    result: dict[int, int] = {x: x for x in range(10) if x > 4}
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestDictCompBytecode(unittest.TestCase):

    def test_uses_newmap_and_setitem(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    result: dict[int, int] = {x: x for x in lst}
    return result
"""
        bc = compile_function(src)
        dis = disassemble(bc)
        self.assertIn("NEWMAP", dis)
        self.assertIn("SETITEM", dis)


class TestDictCompErrors(unittest.TestCase):

    def test_multiple_generators_rejected(self):
        src = """
def f(a: list[int], b: list[int]) -> dict[int, int]:
    return {x: y for x in a for y in b}
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_non_list_non_range_iterable_rejected(self):
        src = """
def f(d: dict[str, int]) -> dict[str, int]:
    return {k: 1 for k in d}
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_invalid_key_type_rejected(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    inner: list[int] = [1]
    return {inner: x for x in lst}
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_non_bool_filter_rejected(self):
        src = """
def f(lst: list[int]) -> dict[int, int]:
    return {x: x for x in lst if x + 1}
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)
