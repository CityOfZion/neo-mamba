import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _blocks_with, _build_cfg

# ---------------------------------------------------------------------------
# Chained comparisons (e.g. b < 10 < arg)
# ---------------------------------------------------------------------------


class TestChainedComparison(unittest.TestCase):

    _SRC = """
def Main(arg: int) -> int:
    a: int = 0
    b: int = 0
    while b < 10 < arg:
        a = a + 2
        b = b + 1
    return a
"""

    def test_chained_compare_compiles(self):
        self.assertIsInstance(compile_function(self._SRC), bytes)

    def test_chained_compare_cfg_has_and_short_circuit(self):
        cfg = _build_cfg(self._SRC)
        # BoolAnd now emits short-circuit blocks instead of a booland instruction
        and_false_blocks = _blocks_with(cfg, "and_false")
        self.assertEqual(len(and_false_blocks), 1)

    def test_triple_chained_compare_compiles(self):
        src = """
def f(a: int, b: int, c: int, d: int) -> int:
    x: int = 0
    while a < b < c < d:
        x = x + 1
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_triple_chained_compare_cfg_has_two_and_short_circuits(self):
        src = """
def f(a: int, b: int, c: int, d: int) -> int:
    x: int = 0
    while a < b < c < d:
        x = x + 1
    return x
"""
        cfg = _build_cfg(src)
        # Two BoolAnd nodes → two and_false short-circuit blocks
        and_false_blocks = _blocks_with(cfg, "and_false")
        self.assertEqual(len(and_false_blocks), 2)


class TestChainedComparisonErrors(unittest.TestCase):

    def test_unsupported_compare_op_raises(self):
        src_is = """
def g(a: int, b: int) -> int:
    x: int = 0
    if a is b:
        x = 1
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src_is)


# ---------------------------------------------------------------------------
# Logical operators: not, and, or
# ---------------------------------------------------------------------------


class TestLogicalOperators(unittest.TestCase):

    # --- compilation (happy path) ---

    def test_not_compiles(self):
        src = """
def f(a: int) -> int:
    x: int = 0
    while not (a == 0):
        x = x + 1
        a = a - 1
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_and_compiles(self):
        src = """
def f(a: int, b: int) -> int:
    x: int = 0
    while a > 0 and b > 0:
        x = x + 1
        a = a - 1
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_or_compiles(self):
        src = """
def f(a: int, b: int) -> int:
    x: int = 0
    while a > 0 or b > 0:
        x = x + 1
        a = a - 1
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    # --- CFG instruction presence ---

    def _all_instrs(self, src):
        cfg = _build_cfg(src)
        return [i for b in cfg.blocks.values() for i in b.instructions]

    def test_not_cfg_emits_not_instr(self):
        src = """
def f(a: int) -> int:
    x: int = 0
    while not (a == 0):
        x = x + 1
        a = a - 1
    return x
"""
        ops = [i.op for i in self._all_instrs(src)]
        self.assertIn("not", ops)

    def test_and_cfg_has_short_circuit_blocks(self):
        src = """
def f(a: int, b: int) -> int:
    x: int = 0
    while a > 0 and b > 0:
        x = x + 1
        a = a - 1
    return x
"""
        cfg = _build_cfg(src)
        self.assertEqual(len(_blocks_with(cfg, "and_false")), 1)
        self.assertEqual(len(_blocks_with(cfg, "and_rhs")), 1)

    def test_or_cfg_has_short_circuit_blocks(self):
        src = """
def f(a: int, b: int) -> int:
    x: int = 0
    while a > 0 or b > 0:
        x = x + 1
        a = a - 1
    return x
"""
        cfg = _build_cfg(src)
        self.assertEqual(len(_blocks_with(cfg, "or_true")), 1)
        self.assertEqual(len(_blocks_with(cfg, "or_rhs")), 1)

    # --- multi-value folding ---

    def test_triple_and_has_two_short_circuit_blocks(self):
        src = """
def f(a: int, b: int, c: int) -> int:
    x: int = 0
    while a > 0 and b > 0 and c > 0:
        x = x + 1
        a = a - 1
    return x
"""
        cfg = _build_cfg(src)
        self.assertEqual(len(_blocks_with(cfg, "and_false")), 2)

    def test_triple_or_has_two_short_circuit_blocks(self):
        src = """
def f(a: int, b: int, c: int) -> int:
    x: int = 0
    while a > 0 or b > 0 or c > 0:
        x = x + 1
        a = a - 1
    return x
"""
        cfg = _build_cfg(src)
        self.assertEqual(len(_blocks_with(cfg, "or_true")), 2)

    # --- type errors ---

    def test_not_rejects_int_operand(self):
        src = """
def f(x: int) -> int:
    y: int = 0
    while not x:
        y = y + 1
    return y
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_and_rejects_int_operands(self):
        src = """
def f(x: int, y: int) -> int:
    z: int = 0
    while x and y:
        z = z + 1
    return z
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_or_rejects_int_operands(self):
        src = """
def f(x: int, y: int) -> int:
    z: int = 0
    while x or y:
        z = z + 1
    return z
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


# ---------------------------------------------------------------------------
# Unary minus
# ---------------------------------------------------------------------------


class TestUnaryMinus(unittest.TestCase):

    def test_negate_compiles(self):
        src = """
def f(a: int) -> int:
    x: int = -a
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_negate_cfg_emits_negate_instr(self):
        src = """
def f(a: int) -> int:
    x: int = -a
    return x
"""
        cfg = _build_cfg(src)
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("negate", all_ops)

    def test_negate_of_literal_compiles(self):
        src = """
def f() -> int:
    x: int = -5
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_negate_rejects_bool_operand(self):
        src = """
def f(b: bool) -> int:
    x: int = 0
    if not b:
        x = -b
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


# ---------------------------------------------------------------------------
# Augmented assignment
# ---------------------------------------------------------------------------


class TestAugmentedAssignment(unittest.TestCase):

    def _src(self, body: str) -> str:
        return f"def f(a: int, b: int) -> int:\n    x: int = 0\n{body}\n    return x\n"

    # --- compilation ---

    def test_add_assign_compiles(self):
        self.assertIsInstance(compile_function(self._src("    x += 1")), bytes)

    def test_sub_assign_compiles(self):
        self.assertIsInstance(compile_function(self._src("    x -= 1")), bytes)

    def test_mul_assign_compiles(self):
        self.assertIsInstance(compile_function(self._src("    x *= 2")), bytes)

    def test_floordiv_assign_compiles(self):
        self.assertIsInstance(compile_function(self._src("    x //= 2")), bytes)

    def test_mod_assign_compiles(self):
        self.assertIsInstance(compile_function(self._src("    x %= 3")), bytes)

    def test_augassign_on_arg_compiles(self):
        src = """
def f(n: int) -> int:
    n += 1
    return n
"""
        self.assertIsInstance(compile_function(src), bytes)

    # --- CFG structure ---

    def test_add_assign_emits_add_instr(self):
        cfg = _build_cfg(self._src("    x += 1"))
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("+", all_ops)

    # --- type errors ---

    def test_augassign_on_bool_raises(self):
        src = """
def f() -> int:
    b: bool = True
    b += 1
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_augassign_undeclared_raises(self):
        src = """
def f() -> int:
    x += 1
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
