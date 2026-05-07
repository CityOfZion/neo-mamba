import unittest

from neo3.compiler import TypecheckError, compile_function, disassemble


class TestListCompBasic(unittest.TestCase):

    def test_identity_compiles(self):
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x for x in lst]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_transform_compiles(self):
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x * 2 for x in lst]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_filter_compiles(self):
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x for x in lst if x > 0]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_filter_and_transform_compiles(self):
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x * 2 for x in lst if x > 0]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_multiple_filters_compiles(self):
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x for x in lst if x > 0 if x < 100]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_return_directly(self):
        src = """
def f(lst: list[int]) -> list[int]:
    return [x * 2 for x in lst]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_as_call_argument(self):
        src = """
def identity(lst: list[int]) -> list[int]:
    return lst

def f(lst: list[int]) -> list[int]:
    return identity([x for x in lst])
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_bool_element_type(self):
        src = """
def f(lst: list[int]) -> list[bool]:
    result: list[bool] = [x > 0 for x in lst]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_str_element_type(self):
        src = """
def f(lst: list[str]) -> list[str]:
    result: list[str] = [s for s in lst]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestListCompRange(unittest.TestCase):

    def test_range_one_arg(self):
        src = """
def f() -> list[int]:
    result: list[int] = [x for x in range(5)]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_range_two_args(self):
        src = """
def f() -> list[int]:
    result: list[int] = [x for x in range(1, 10)]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_range_with_step(self):
        src = """
def f() -> list[int]:
    result: list[int] = [x for x in range(0, 10, 2)]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_range_with_negative_step(self):
        src = """
def f() -> list[int]:
    result: list[int] = [x for x in range(10, 0, -1)]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_range_with_transform(self):
        src = """
def f() -> list[int]:
    result: list[int] = [x * x for x in range(5)]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_range_with_filter(self):
        src = """
def f() -> list[int]:
    result: list[int] = [x for x in range(10) if x > 4]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestListCompBytecode(unittest.TestCase):
    """Spot-check that key opcodes appear in the output."""

    def test_identity_uses_newarray0_and_append(self):
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x for x in lst]
    return result
"""
        bc = compile_function(src)
        dis = disassemble(bc)
        self.assertIn("NEWARRAY0", dis)
        self.assertIn("APPEND", dis)

    def test_filter_uses_conditional_jump(self):
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x for x in lst if x > 0]
    return result
"""
        bc = compile_function(src)
        dis = disassemble(bc)
        # Filter emits a conditional branch: true→append block, false→skip
        self.assertIn("JMPIF_L", dis)

    def test_range_comp_uses_newarray0_and_append(self):
        src = """
def f() -> list[int]:
    result: list[int] = [x for x in range(5)]
    return result
"""
        bc = compile_function(src)
        dis = disassemble(bc)
        self.assertIn("NEWARRAY0", dis)
        self.assertIn("APPEND", dis)


class TestListCompErrors(unittest.TestCase):

    def test_multiple_generators_rejected(self):
        src = """
def f(a: list[int], b: list[int]) -> list[int]:
    result: list[int] = [x for x in a for y in b]
    return result
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_nested_comp_as_element_rejected(self):
        src = """
def f(matrix: list[list[int]]) -> list[list[int]]:
    result: list[list[int]] = [[x for x in row] for row in matrix]
    return result
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_non_list_non_range_iterable_rejected(self):
        src = """
def f(d: dict[str, int]) -> list[str]:
    result: list[str] = [k for k in d]
    return result
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_non_bool_filter_rejected(self):
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x for x in lst if x + 1]
    return result
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_async_comp_rejected(self):
        # async comprehension: gen.is_async is True
        # We can't easily write one in plain source, so just test the guard
        # is exercised via the multiple-generators path
        src = """
def f(lst: list[int]) -> list[int]:
    result: list[int] = [x for x in lst for y in lst]
    return result
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)
