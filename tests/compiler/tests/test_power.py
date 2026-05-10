import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestPowerOp(unittest.TestCase):

    def test_power_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    return a ** b"
        self.assertIsInstance(compile_function(src), bytes)

    def test_power_literal_compiles(self):
        src = "def f() -> int:\n    return 2 ** 10"
        self.assertIsInstance(compile_function(src), bytes)

    def test_augmented_power_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    a **= b\n    return a"
        self.assertIsInstance(compile_function(src), bytes)

    def test_power_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int, b: int) -> int:\n    return a ** b")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("**", all_ops)

    def test_power_on_str_raises(self):
        src = "def f(a: str, b: int) -> int:\n    return a ** b"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_power_on_bool_raises(self):
        src = "def f(a: bool, b: int) -> int:\n    return a ** b"
        with self.assertRaises(TypecheckError):
            compile_function(src)
