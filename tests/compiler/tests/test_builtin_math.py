import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestAbs(unittest.TestCase):

    def test_abs_compiles(self):
        src = "def f(a: int) -> int:\n    return abs(a)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_abs_literal_compiles(self):
        src = "def f() -> int:\n    return abs(-5)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_abs_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int) -> int:\n    return abs(a)")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("abs", all_ops)

    def test_abs_on_str_raises(self):
        src = "def f(a: str) -> int:\n    return abs(a)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_abs_on_bool_raises(self):
        src = "def f(a: bool) -> int:\n    return abs(a)"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestMinMax(unittest.TestCase):

    def test_min_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    return min(a, b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_max_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    return max(a, b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_min_literal_compiles(self):
        src = "def f() -> int:\n    return min(3, 7)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_max_literal_compiles(self):
        src = "def f() -> int:\n    return max(3, 7)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_min_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int, b: int) -> int:\n    return min(a, b)")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("min", all_ops)

    def test_max_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int, b: int) -> int:\n    return max(a, b)")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("max", all_ops)

    def test_min_on_str_raises(self):
        src = "def f(a: str, b: int) -> int:\n    return min(a, b)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_max_on_str_raises(self):
        src = "def f(a: int, b: str) -> int:\n    return max(a, b)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_min_one_arg_falls_through_to_error(self):
        # min(x) with one arg should not match our 2-arg case and fall through to
        # the general call handler, which will raise because min is not a declared function
        src = "def f(a: int) -> int:\n    return min(a)"
        with self.assertRaises((TypecheckError, Exception)):
            compile_function(src)
