import unittest

from neo3.compiler import TypecheckError, compile_function


class TestTupleType(unittest.TestCase):

    def test_tuple_annotation_parses(self):
        src = "def f(x: int) -> tuple[int, str]:\n    return (x, 'hello')"
        self.assertIsInstance(compile_function(src), bytes)

    def test_single_element_tuple_type(self):
        src = "def f(x: int) -> tuple[int]:\n    return (x,)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_triple_element_tuple_type(self):
        src = "def f(a: int, b: bool, c: str) -> tuple[int, bool, str]:\n    return (a, b, c)"
        self.assertIsInstance(compile_function(src), bytes)


class TestTupleLiteral(unittest.TestCase):

    def test_tuple_literal_compiles(self):
        src = "def f() -> tuple[int, str]:\n    return (1, 'x')"
        self.assertIsInstance(compile_function(src), bytes)

    def test_tuple_literal_emits_newarray(self):
        src = "def f() -> tuple[int, str]:\n    return (1, 'x')"
        bc = compile_function(src)
        self.assertIn(0xC2, bc)  # NEWARRAY0

    def test_tuple_literal_type_mismatch_return(self):
        src = "def f() -> tuple[int, str]:\n    return (1, 2)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_empty_tuple_raises(self):
        src = "def f() -> tuple[int]:\n    return ()"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestTupleUnpack(unittest.TestCase):

    def test_unpack_from_literal_compiles(self):
        src = """
def f() -> int:
    a, b = (1, 2)
    return a
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_unpack_infers_types(self):
        src = """
def f() -> int:
    a, b = (42, 'hello')
    return a
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_unpack_from_function_call(self):
        src = """
def make() -> tuple[int, str]:
    return (7, 'ok')

def f() -> int:
    x, y = make()
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_unpack_into_existing_locals(self):
        src = """
def f() -> int:
    a: int = 0
    b: str = 'x'
    a, b = (1, 'y')
    return a
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_unpack_wrong_count_raises(self):
        src = """
def f() -> int:
    a, b, c = (1, 2)
    return a
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_unpack_type_mismatch_raises(self):
        src = """
def f() -> int:
    a: str = 'x'
    b: int = 0
    a, b = (1, 2)
    return b
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_unpack_non_tuple_raises(self):
        src = """
def f(lst: list[int]) -> int:
    a, b = lst
    return a
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestTupleIndexing(unittest.TestCase):

    def test_constant_index_compiles(self):
        src = """
def f() -> int:
    t: tuple[int, str] = (5, 'hi')
    return t[0]
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_constant_index_second_element(self):
        src = """
def f() -> str:
    t: tuple[int, str] = (5, 'hi')
    return t[1]
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_variable_index_raises(self):
        src = """
def f(i: int) -> int:
    t: tuple[int, str] = (5, 'hi')
    return t[i]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_out_of_range_index_raises(self):
        src = """
def f() -> int:
    t: tuple[int, str] = (5, 'hi')
    return t[5]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestTupleImmutability(unittest.TestCase):

    def test_element_assignment_raises(self):
        src = """
def f() -> int:
    t: tuple[int, str] = (1, 'x')
    t[0] = 99
    return t[0]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestMultipleReturnValues(unittest.TestCase):

    def test_multiple_return_compiles(self):
        src = """
def divmod_int(a: int, b: int) -> tuple[int, int]:
    return (a // b, a % b)
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_caller_unpacks_multiple_return(self):
        src = """
def divmod_int(a: int, b: int) -> tuple[int, int]:
    return (a // b, a % b)

def f(a: int, b: int) -> int:
    q, r = divmod_int(a, b)
    return q
"""
        self.assertIsInstance(compile_function(src), bytes)
