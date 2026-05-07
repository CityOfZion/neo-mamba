import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestBitwiseOps(unittest.TestCase):

    def _compile(self, body: str) -> bytes:
        src = f"def f(a: int, b: int) -> int:\n{body}"
        return compile_function(src)

    def test_bitwise_and_compiles(self):
        self.assertIsInstance(self._compile("    return a & b"), bytes)

    def test_bitwise_or_compiles(self):
        self.assertIsInstance(self._compile("    return a | b"), bytes)

    def test_bitwise_xor_compiles(self):
        self.assertIsInstance(self._compile("    return a ^ b"), bytes)

    def test_bitwise_not_compiles(self):
        self.assertIsInstance(self._compile("    return ~a"), bytes)

    def test_chained_and_or_compiles(self):
        self.assertIsInstance(self._compile("    return a & b | a"), bytes)

    def test_augmented_and_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    a &= b\n    return a"
        self.assertIsInstance(compile_function(src), bytes)

    def test_augmented_or_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    a |= b\n    return a"
        self.assertIsInstance(compile_function(src), bytes)

    def test_augmented_xor_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    a ^= b\n    return a"
        self.assertIsInstance(compile_function(src), bytes)

    def test_bitwise_and_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int, b: int) -> int:\n    return a & b")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("&", all_ops)

    def test_bitwise_or_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int, b: int) -> int:\n    return a | b")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("|", all_ops)

    def test_bitwise_xor_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int, b: int) -> int:\n    return a ^ b")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("^", all_ops)

    def test_bitwise_not_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int) -> int:\n    return ~a")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("invert", all_ops)

    def test_bitwise_not_on_bool_raises(self):
        src = "def f(a: bool) -> int:\n    return ~a"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_bitwise_and_on_str_raises(self):
        src = "def f(a: str, b: str) -> int:\n    return a & b"
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestShiftOps(unittest.TestCase):

    def _compile(self, body: str) -> bytes:
        src = f"def f(a: int, b: int) -> int:\n{body}"
        return compile_function(src)

    def test_left_shift_compiles(self):
        self.assertIsInstance(self._compile("    return a << b"), bytes)

    def test_right_shift_compiles(self):
        self.assertIsInstance(self._compile("    return a >> b"), bytes)

    def test_augmented_left_shift_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    a <<= b\n    return a"
        self.assertIsInstance(compile_function(src), bytes)

    def test_augmented_right_shift_compiles(self):
        src = "def f(a: int, b: int) -> int:\n    a >>= b\n    return a"
        self.assertIsInstance(compile_function(src), bytes)

    def test_left_shift_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int, b: int) -> int:\n    return a << b")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("<<", all_ops)

    def test_right_shift_emits_correct_opcode(self):
        cfg = _build_cfg("def f(a: int, b: int) -> int:\n    return a >> b")
        all_ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn(">>", all_ops)

    def test_left_shift_on_str_raises(self):
        src = "def f(a: str, b: int) -> int:\n    return a << b"
        with self.assertRaises(TypecheckError):
            compile_function(src)
