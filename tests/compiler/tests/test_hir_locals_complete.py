import ast
import unittest

from neo3.compiler import CFGBuilder, HIRBuilder, compile_function
from neo3.compiler.hir import ClassInfo, FieldInfo
from neo3.compiler.types import IntType


class TestHIRLocalsComplete(unittest.TestCase):
    """Item 6: fn.locals must be fully populated by HIRBuilder; CFGBuilder must not grow it."""

    def _locals_delta(self, src: str) -> int:
        """Return len(fn.locals_after_cfg) - len(fn.locals_after_hir). Must be 0 after fix."""
        tree = ast.parse(src)
        fn_node = tree.body[0]
        hir = HIRBuilder().build(fn_node)
        before = len(hir.locals)
        CFGBuilder(hir).build()
        return len(hir.locals) - before

    def test_step_slice_no_new_locals_in_cfg(self):
        """Step-slice temp slots must be in fn.locals after HIR, not added by CFGBuilder."""
        src = """
def f(b: bytes) -> bytes:
    return b[::2]
"""
        self.assertEqual(self._locals_delta(src), 0)

    def test_step_slice_with_start_no_new_locals_in_cfg(self):
        src = """
def f(b: bytes) -> bytes:
    return b[1::2]
"""
        self.assertEqual(self._locals_delta(src), 0)

    def test_list_insert_no_new_locals_in_cfg(self):
        """ListInsert temp slots must be in fn.locals after HIR, not added by CFGBuilder."""
        src = """
def f(lst: list[int]) -> None:
    lst.insert(0, 42)
"""
        self.assertEqual(self._locals_delta(src), 0)

    def test_print_list_no_new_locals_in_cfg(self):
        """PrintListStmt temp slot must be in fn.locals after HIR, not added by CFGBuilder."""
        src = """
def f(lst: list[int]) -> None:
    print(lst)
"""
        self.assertEqual(self._locals_delta(src), 0)

    def test_new_instance_no_new_locals_in_cfg(self):
        """NewInstance temp slot must be in fn.locals after HIR, not added by CFGBuilder."""
        src = """
class Foo:
    x: int = 0
def f() -> Foo:
    return Foo()
"""
        tree = ast.parse(src)
        class_node = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
        fn_node = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "f"
        )
        registry = {
            "Foo": ClassInfo(
                name="Foo",
                bases=[],
                class_mro=[],
                fields={"x": FieldInfo(name="x", index=0, type=IntType())},
                methods={},
                class_vars={},
                total_fields=1,
                ast_node=class_node,
            )
        }
        hir = HIRBuilder(class_registry=registry).build(fn_node)
        before = len(hir.locals)
        CFGBuilder(hir, class_registry=registry).build()
        self.assertEqual(len(hir.locals), before)

    # -- correctness: compilation must still succeed after the refactor --

    def test_step_slice_still_compiles(self):
        src = """
def f(b: bytes) -> bytes:
    return b[::2]
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_list_insert_still_compiles(self):
        src = """
def f(lst: list[int]) -> None:
    lst.insert(0, 42)
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_print_list_still_compiles(self):
        src = """
def f(lst: list[int]) -> None:
    print(lst)
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_new_instance_still_compiles(self):
        src = """
class Foo:
    x: int = 0
def f() -> Foo:
    return Foo()
"""
        self.assertIsInstance(compile_function(src), bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
