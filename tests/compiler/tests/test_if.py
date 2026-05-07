import unittest

from neo3.compiler import CondJump, Jump, TypecheckError, compile_function

from tests.compiler.tests.helpers import _blocks_with, _build_cfg, _labels

# ---------------------------------------------------------------------------
# if / elif / else
# ---------------------------------------------------------------------------


class TestIfElif(unittest.TestCase):

    def test_all_branches_return(self):
        """elif chain where every branch returns must compile without error."""
        src = """
def f(n: int) -> int:
    if n == 0:
        return 10
    elif n == 1:
        return 100
    else:
        return 1000
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_join_block_unreachable_when_all_branches_return(self):
        """Join block should have no incoming jumps when all branches terminate."""
        src = """
def f(n: int) -> int:
    if n == 0:
        return 10
    elif n == 1:
        return 100
    else:
        return 1000
"""
        cfg = _build_cfg(src)
        join_blocks = _blocks_with(cfg, "join")
        all_targets = {
            b.terminator.target
            for b in cfg.blocks.values()
            if isinstance(b.terminator, Jump)
        } | {
            t
            for b in cfg.blocks.values()
            if isinstance(b.terminator, CondJump)
            for t in (b.terminator.true_target, b.terminator.false_target)
        }
        for jb in join_blocks:
            self.assertNotIn(jb.label, all_targets)


if __name__ == "__main__":
    unittest.main(verbosity=2)
