import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestEnumerate(unittest.TestCase):

    # ------------------------------------------------------------------
    # Basic compilation
    # ------------------------------------------------------------------

    def test_enumerate_basic_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    s: int = 0
    for i, x in enumerate(lst):
        s += i + x
    return s
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_enumerate_with_start_literal_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    s: int = 0
    for i, x in enumerate(lst, 10):
        s += i
    return s
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_enumerate_with_start_variable_compiles(self):
        src = """
def f(lst: list[int], start: int) -> int:
    s: int = 0
    for i, x in enumerate(lst, start):
        s += i
    return s
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_enumerate_str_list_compiles(self):
        src = """
def f(lst: list[str]) -> int:
    count: int = 0
    for i, x in enumerate(lst):
        count += i
    return count
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    # ------------------------------------------------------------------
    # HIR structure
    # ------------------------------------------------------------------

    def test_enumerate_produces_while_loop(self):
        from neo3.compiler.hir import While

        src = """
def f(lst: list[int]) -> int:
    s: int = 0
    for i, x in enumerate(lst):
        s += i + x
    return s
"""
        cfg = _build_cfg(src)
        # Should produce a while-loop (CondJump terminator exists)
        terminators = [b.terminator.__class__.__name__ for b in cfg.blocks.values()]
        self.assertIn("CondJump", terminators)

    def test_enumerate_emits_pickitem(self):
        src = """
def f(lst: list[int]) -> int:
    s: int = 0
    for i, x in enumerate(lst):
        s += x
    return s
"""
        bc = compile_function(src)
        self.assertIn(0xCE, bc)  # PICKITEM for element access

    # ------------------------------------------------------------------
    # Zero-start optimisation: no extra temp
    # ------------------------------------------------------------------

    def test_enumerate_zero_start_no_start_temp(self):
        """enumerate(lst) and enumerate(lst, 0) should not allocate a __for_start__ temp."""
        import ast as _ast

        from neo3.compiler import CFGBuilder, HIRBuilder

        src_default = """
def f(lst: list[int]) -> int:
    s: int = 0
    for i, x in enumerate(lst):
        s += i
    return s
"""
        src_zero = """
def f(lst: list[int]) -> int:
    s: int = 0
    for i, x in enumerate(lst, 0):
        s += i
    return s
"""
        for src in (src_default, src_zero):
            tree = _ast.parse(src)
            hir_fn = HIRBuilder().build(tree.body[0])
            # No __for_start__ temp should be allocated when start == 0
            self.assertFalse(
                any("__for_start_" in name for name in hir_fn.locals),
                msg=f"Unexpected __for_start__ temp in: {list(hir_fn.locals)}",
            )

    def test_enumerate_nonzero_start_emits_add(self):
        """enumerate(lst, 5) must add 5 to the index each iteration."""
        src = """
def f(lst: list[int]) -> int:
    s: int = 0
    for i, x in enumerate(lst, 5):
        s += i
    return s
"""
        bc = compile_function(src)
        self.assertIn(0x9E, bc)  # ADD

    # ------------------------------------------------------------------
    # for/else
    # ------------------------------------------------------------------

    def test_enumerate_for_else_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    for i, x in enumerate(lst):
        if x < 0:
            return i
    else:
        return -1
    return -1
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    # ------------------------------------------------------------------
    # break / continue
    # ------------------------------------------------------------------

    def test_enumerate_break_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    for i, x in enumerate(lst):
        if x == 0:
            break
    return i
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_enumerate_continue_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    s: int = 0
    for i, x in enumerate(lst):
        if x < 0:
            continue
        s += x
    return s
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    # ------------------------------------------------------------------
    # Pre-declared loop variables
    # ------------------------------------------------------------------

    def test_enumerate_predeclared_vars_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    i: int = 0
    x: int = 0
    for i, x in enumerate(lst):
        pass
    return i + x
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    # ------------------------------------------------------------------
    # Error cases
    # ------------------------------------------------------------------

    def test_enumerate_wrong_arg_count_zero(self):
        src = """
def f(lst: list[int]) -> int:
    for i, x in enumerate():
        pass
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_enumerate_wrong_arg_count_three(self):
        src = """
def f(lst: list[int]) -> int:
    for i, x in enumerate(lst, 0, 1):
        pass
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_enumerate_non_list_iterable(self):
        src = """
def f(d: dict[int, int]) -> int:
    for i, x in enumerate(d):
        pass
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_enumerate_non_int_start(self):
        src = """
def f(lst: list[int]) -> int:
    for i, x in enumerate(lst, "oops"):
        pass
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_enumerate_index_type_mismatch(self):
        src = """
def f(lst: list[int]) -> int:
    i: str = "hi"
    for i, x in enumerate(lst):
        pass
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_enumerate_element_type_mismatch(self):
        src = """
def f(lst: list[int]) -> int:
    x: str = "hi"
    for i, x in enumerate(lst):
        pass
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)
