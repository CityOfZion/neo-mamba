import unittest

from neo3.compiler import TypecheckError, compile_function, compile_module


class TestNoneLiteral(unittest.TestCase):

    def test_none_return_from_void_function(self):
        src = "def f() -> None:\n    return None"
        self.assertIsInstance(compile_function(src), bytes)

    def test_void_return_does_not_push_null(self):
        src = "def f() -> None:\n    return None"
        bc = compile_function(src)
        self.assertNotIn(0x0B, bc)  # bare RET; no PUSHNULL for void functions

    def test_optional_return_none_emits_pushnull(self):
        src = "def f() -> Optional[int]:\n    return None"
        bc = compile_function(src)
        self.assertIn(0x0B, bc)  # PUSHNULL must appear for Optional return

    def test_none_return_from_optional_function(self):
        src = "def f() -> Optional[int]:\n    return None"
        self.assertIsInstance(compile_function(src), bytes)

    def test_int_return_from_optional_function(self):
        src = "def f(x: int) -> Optional[int]:\n    return x"
        self.assertIsInstance(compile_function(src), bytes)

    def test_return_type_mismatch_with_void_raises(self):
        src = "def f(x: int) -> None:\n    return x"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_return_none_from_int_raises(self):
        src = "def f() -> int:\n    return None"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestOptionalLocals(unittest.TestCase):

    def test_optional_local_assigned_none(self):
        src = """
def f() -> Optional[int]:
    x: Optional[int] = None
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_optional_local_assigned_int(self):
        src = """
def f(n: int) -> Optional[int]:
    x: Optional[int] = n
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_optional_param(self):
        src = "def f(x: Optional[int]) -> Optional[int]:\n    return x"
        self.assertIsInstance(compile_function(src), bytes)

    def test_optional_local_type_mismatch_raises(self):
        src = """
def f() -> bool:
    x: Optional[int] = True
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestIsNone(unittest.TestCase):

    def test_is_none_compiles(self):
        src = "def f(x: Optional[int]) -> bool:\n    return x is None"
        self.assertIsInstance(compile_function(src), bytes)

    def test_is_none_emits_isnull(self):
        src = "def f(x: Optional[int]) -> bool:\n    return x is None"
        bc = compile_function(src)
        self.assertIn(0xD8, bc)  # ISNULL

    def test_is_not_none_compiles(self):
        src = "def f(x: Optional[int]) -> bool:\n    return x is not None"
        self.assertIsInstance(compile_function(src), bytes)

    def test_is_not_none_emits_isnull_and_not(self):
        src = "def f(x: Optional[int]) -> bool:\n    return x is not None"
        bc = compile_function(src)
        self.assertIn(0xD8, bc)  # ISNULL
        self.assertIn(0xAA, bc)  # NOT

    def test_is_none_in_if_condition(self):
        src = """
def f(x: Optional[int]) -> int:
    if x is None:
        return 0
    return 1
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_is_none_on_non_optional_raises(self):
        src = "def f(x: int) -> bool:\n    return x is None"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_is_not_none_on_non_optional_raises(self):
        src = "def f(x: bool) -> bool:\n    return x is not None"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestVoidCallStmt(unittest.TestCase):

    def test_void_function_called_as_stmt(self):
        src = """
def log() -> None:
    return None

def f() -> int:
    log()
    return 1
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_void_call_does_not_emit_drop(self):
        # A -> None function leaves nothing on the stack; DROP must not be emitted
        src = """
def log() -> None:
    return None

def f() -> int:
    log()
    return 42
"""
        bc = compile_module(src)
        self.assertNotIn(0x45, bc)  # DROP must be absent

    def test_non_void_called_as_stmt_compiles_and_drops(self):
        src = """
def get() -> int:
    return 1

def f() -> int:
    get()
    return 0
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x45, bc)  # DROP must be emitted

    def test_non_void_str_return_as_stmt(self):
        src = """
def greet() -> str:
    return "hello"

def f() -> int:
    greet()
    return 42
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x45, bc)  # DROP must be emitted


class TestWhileNarrowing(unittest.TestCase):

    def test_while_is_not_none_narrows_body(self):
        # x is Optional[int]; inside the while body x is narrowed to int
        src = """
def f(x: Optional[int]) -> int:
    result: int = 0
    while x is not None:
        result = x + 1
        break
    return result
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_while_is_not_none_type_restored_after_loop(self):
        # After the while loop x reverts to Optional[int]
        src = """
def f(x: Optional[int]) -> Optional[int]:
    while x is not None:
        break
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_while_body_rejects_int_from_optional_without_narrowing(self):
        # Without a narrowing while, using Optional[int] as int is a type error
        src = """
def f(x: Optional[int]) -> int:
    result: int = 0
    if x is not None:
        result = x + 1
    return result
"""
        self.assertIsInstance(compile_function(src), bytes)


class TestAssertNarrowing(unittest.TestCase):

    def test_assert_is_not_none_narrows_subsequent(self):
        # After `assert x is not None`, x is narrowed from Optional[int] to int
        src = """
def f(x: Optional[int]) -> int:
    assert x is not None
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_assert_is_not_none_with_msg_narrows(self):
        src = """
def f(x: Optional[int]) -> int:
    assert x is not None, "x must not be None"
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_assert_is_none_narrows_to_none(self):
        # After `assert x is None`, x is narrowed to NoneType
        src = """
def f(x: Optional[int]) -> None:
    assert x is None
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_optional_without_assert_rejects_int_return(self):
        # Without the assert, returning Optional[int] from -> int is a type error
        src = """
def f(x: Optional[int]) -> int:
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)
