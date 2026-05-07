import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg

# ---------------------------------------------------------------------------
# General error cases
# ---------------------------------------------------------------------------


class TestErrors(unittest.TestCase):

    def test_break_outside_loop(self):
        src = """
def f(n: int) -> int:
    break
    return n
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_continue_outside_loop(self):
        src = """
def f(n: int) -> int:
    continue
    return n
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_break_after_loop_is_error(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    while i > 0:
        i = i - 1
    break
    return i
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_continue_after_loop_is_error(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    while i > 0:
        i = i - 1
    continue
    return i
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_while_condition_must_be_bool(self):
        src = """
def f(n: int) -> int:
    i: int = n
    while i:
        i = i - 1
    return i
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


# ---------------------------------------------------------------------------
# Mutable arguments (STARG)
# ---------------------------------------------------------------------------


class TestArgMutability(unittest.TestCase):

    def test_arg_reassignment_compiles(self):
        src = """
def f(n: int) -> int:
    n = n + 1
    return n
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_arg_reassignment_emits_starg(self):
        src = """
def f(n: int) -> int:
    n = n + 1
    return n
"""
        cfg = _build_cfg(src)
        starg_instrs = [
            instr
            for block in cfg.blocks.values()
            for instr in block.instructions
            if instr.op == "STARG"
        ]
        self.assertEqual(len(starg_instrs), 1)
        self.assertEqual(starg_instrs[0].operand, 0)  # first arg → index 0

    def test_arg_reassignment_type_mismatch(self):
        src = """
def f(n: int) -> int:
    n = True
    return n
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_while_loop_with_mutable_arg(self):
        """Canonical countdown using only the argument — no local copy needed."""
        src = """
def countdown(n: int) -> int:
    while n > 0:
        n = n - 1
    return n
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_annotated_arg_reassignment_compiles(self):
        src = """
def f(n: int) -> int:
    n: int = n + 1
    return n
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_annotated_arg_reassignment_emits_starg(self):
        src = """
def f(n: int) -> int:
    n: int = n + 1
    return n
"""
        cfg = _build_cfg(src)
        starg_instrs = [
            instr
            for block in cfg.blocks.values()
            for instr in block.instructions
            if instr.op == "STARG"
        ]
        self.assertEqual(len(starg_instrs), 1)
        self.assertEqual(starg_instrs[0].operand, 0)

    def test_annotated_arg_reassignment_type_mismatch(self):
        src = """
def f(n: int) -> int:
    n: bool = True
    return n
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_multiple_args_starg_index(self):
        """STARG for the second argument uses index 1."""
        src = """
def f(a: int, b: int) -> int:
    b = b + 1
    return b
"""
        cfg = _build_cfg(src)
        starg_instrs = [
            instr
            for block in cfg.blocks.values()
            for instr in block.instructions
            if instr.op == "STARG"
        ]
        self.assertEqual(len(starg_instrs), 1)
        self.assertEqual(starg_instrs[0].operand, 1)  # second arg → index 1


if __name__ == "__main__":
    unittest.main(verbosity=2)
