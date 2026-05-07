import ast
import unittest

from neo3.compiler import (
    CFGBuilder,
    Compare,
    Continue,
    HIRBuilder,
    If,
    LocalStore,
    TryExcept,
    TypecheckError,
    While,
    compile_function,
    _for_rewrite_continues,
)

from tests.compiler.tests.helpers import _build_cfg

# ---------------------------------------------------------------------------
# for i in range(...)
# ---------------------------------------------------------------------------


class TestForRange(unittest.TestCase):

    # ------------------------------------------------------------------
    # Basic compilation / HIR structure
    # ------------------------------------------------------------------

    def test_for_range_stop_compiles(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n):
        s += i
    return s
"""
        compile_function(src)  # must not raise

    def test_for_range_start_stop_compiles(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(0, n):
        s += i
    return s
"""
        compile_function(src)

    def test_for_range_positive_step_compiles(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(0, n, 2):
        s += i
    return s
"""
        compile_function(src)

    def test_for_range_negative_step_compiles(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n, 0, -1):
        s += i
    return s
"""
        compile_function(src)

    def test_for_loop_variable_auto_declared(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n):
        s += i
    return s
"""
        from neo3.compiler import INT

        tree = ast.parse(src)
        hir = HIRBuilder().build(tree.body[0])
        self.assertIn("i", hir.locals)
        self.assertEqual(hir.locals["i"][1], INT)

    def test_for_loop_desugars_to_while_in_hir(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n):
        s += i
    return s
"""
        tree = ast.parse(src)
        hir = HIRBuilder().build(tree.body[0])
        # body[0]=s decl, body[1]=i init (LocalStore), body[2]=While, body[3]=return
        self.assertIsInstance(hir.body[1], LocalStore)
        self.assertIsInstance(hir.body[2], While)

    # ------------------------------------------------------------------
    # CFG structure
    # ------------------------------------------------------------------

    def test_for_loop_creates_while_header_block(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n):
        s += i
    return s
"""
        tree = ast.parse(src)
        hir = HIRBuilder().build(tree.body[0])
        cfg = CFGBuilder(hir).build()
        self.assertTrue(any("while_header" in lbl for lbl in cfg.blocks))

    def test_for_loop_last_body_stmt_is_increment(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n):
        s += i
    return s
"""
        tree = ast.parse(src)
        hir = HIRBuilder().build(tree.body[0])
        while_node = hir.body[2]
        self.assertIsInstance(while_node, While)
        last = while_node.body[-1]
        self.assertIsInstance(last, LocalStore)
        self.assertEqual(last.name, "i")

    def test_for_range_negative_step_uses_gt_condition(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n, 0, -1):
        s += i
    return s
"""
        tree = ast.parse(src)
        hir = HIRBuilder().build(tree.body[0])
        while_node = hir.body[2]
        self.assertIsInstance(while_node, While)
        self.assertIsInstance(while_node.condition, Compare)
        self.assertEqual(while_node.condition.op, ">")

    # ------------------------------------------------------------------
    # Continue semantics
    # ------------------------------------------------------------------

    def test_for_continue_gets_increment_prepended(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n):
        if i == i:
            continue
        s += i
    return s
"""
        tree = ast.parse(src)
        hir = HIRBuilder().build(tree.body[0])
        while_node = hir.body[2]
        self.assertIsInstance(while_node, While)
        # First stmt in body is the If containing continue
        if_stmt = while_node.body[0]
        self.assertIsInstance(if_stmt, If)
        # Inside then_body: [LocalStore(increment), Continue()]
        self.assertEqual(len(if_stmt.then_body), 2)
        self.assertIsInstance(if_stmt.then_body[0], LocalStore)
        self.assertEqual(if_stmt.then_body[0].name, "i")
        self.assertIsInstance(if_stmt.then_body[1], Continue)

    # ------------------------------------------------------------------
    # Error cases
    # ------------------------------------------------------------------

    def test_for_non_range_iter_raises(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in n:
        s += i
    return s
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_for_zero_step_raises(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(0, n, 0):
        s += i
    return s
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_for_non_int_stop_raises(self):
        src = """
def f(flag: bool) -> int:
    s: int = 0
    for i in range(flag):
        s += i
    return s
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_for_step_not_literal_raises(self):
        src = """
def f(n: int, step: int) -> int:
    s: int = 0
    for i in range(0, n, step):
        s += i
    return s
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_for_wrong_target_raises(self):
        src = """
def f(n: int) -> int:
    s: int = 0
    for a, b in range(n):
        s += a
    return s
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


# ---------------------------------------------------------------------------
# item-9: _for_rewrite_continues must recurse into TryExcept bodies
# ---------------------------------------------------------------------------


class TestForRewriteContinuesInTry(unittest.TestCase):
    """Regression: continue inside try/except inside for skips index increment."""

    def _make_increment(self):
        from neo3.compiler import IntLiteral, BinOp, LocalLoad, IntType

        return LocalStore(
            name="i",
            slot=0,
            value=BinOp(
                op="+",
                left=LocalLoad(name="i", type=IntType()),
                right=IntLiteral(1),
                type=IntType(),
            ),
            type=IntType(),
        )

    def test_continue_in_try_body_gets_increment(self):
        """continue in try body must have increment prepended after rewrite."""
        inc = self._make_increment()
        try_node = TryExcept(
            try_body=[Continue()],
            catch_body=None,
            finally_body=None,
            handler_var=None,
            handler_var_slot=None,
        )
        result = _for_rewrite_continues([try_node], inc)
        self.assertEqual(len(result), 1)
        rewritten = result[0]
        self.assertIsInstance(rewritten, TryExcept)
        self.assertEqual(len(rewritten.try_body), 2)
        self.assertIsInstance(rewritten.try_body[0], LocalStore)
        self.assertEqual(rewritten.try_body[0].name, "i")
        self.assertIsInstance(rewritten.try_body[1], Continue)

    def test_continue_in_catch_body_gets_increment(self):
        """continue in except body must have increment prepended after rewrite."""
        inc = self._make_increment()
        try_node = TryExcept(
            try_body=[],
            catch_body=[Continue()],
            finally_body=None,
            handler_var=None,
            handler_var_slot=None,
        )
        result = _for_rewrite_continues([try_node], inc)
        rewritten = result[0]
        self.assertIsInstance(rewritten, TryExcept)
        self.assertEqual(len(rewritten.catch_body), 2)
        self.assertIsInstance(rewritten.catch_body[0], LocalStore)
        self.assertIsInstance(rewritten.catch_body[1], Continue)

    def test_continue_in_finally_body_gets_increment(self):
        """continue in finally body must have increment prepended after rewrite."""
        inc = self._make_increment()
        try_node = TryExcept(
            try_body=[],
            catch_body=None,
            finally_body=[Continue()],
            handler_var=None,
            handler_var_slot=None,
        )
        result = _for_rewrite_continues([try_node], inc)
        rewritten = result[0]
        self.assertIsInstance(rewritten, TryExcept)
        self.assertEqual(len(rewritten.finally_body), 2)
        self.assertIsInstance(rewritten.finally_body[0], LocalStore)
        self.assertIsInstance(rewritten.finally_body[1], Continue)

    def test_continue_in_try_inside_for_range_compiles(self):
        """End-to-end: for loop with continue inside try must compile without error."""
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n):
        try:
            if i == 2:
                continue
            s = s + i
        except:
            pass
    return s
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_continue_in_try_hir_has_increment_before_continue(self):
        """HIR for for-loop with continue-in-try must have increment before Continue."""
        src = """
def f(n: int) -> int:
    s: int = 0
    for i in range(n):
        try:
            continue
        except:
            pass
    return s
"""
        tree = ast.parse(src)
        hir = HIRBuilder().build(tree.body[0])
        while_node = hir.body[2]
        self.assertIsInstance(while_node, While)
        try_node = while_node.body[0]
        self.assertIsInstance(try_node, TryExcept)
        # try_body should be [LocalStore(i = i + 1), Continue()]
        self.assertEqual(len(try_node.try_body), 2)
        self.assertIsInstance(try_node.try_body[0], LocalStore)
        self.assertEqual(try_node.try_body[0].name, "i")
        self.assertIsInstance(try_node.try_body[1], Continue)


if __name__ == "__main__":
    unittest.main(verbosity=2)
