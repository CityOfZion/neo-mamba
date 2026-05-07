import unittest

from neo3.compiler import CondJump, Jump, TypecheckError, compile_function

from tests.compiler.tests.helpers import _blocks_with, _build_cfg, _labels

# ---------------------------------------------------------------------------
# Regression: plain while still works
# ---------------------------------------------------------------------------


class TestRegression(unittest.TestCase):

    def test_sum_to_compiles(self):
        src = """
def sum_to(n: int) -> int:
    result: int = 0
    i: int = 0
    while i < n:
        result = result + i
        i = i + 1
    return result
"""
        bytecode = compile_function(src)
        self.assertIsInstance(bytecode, bytes)
        self.assertGreater(len(bytecode), 0)

    def test_plain_while_has_no_else_block(self):
        src = """
def f(n: int) -> int:
    while n > 0:
        n = n - 1
    return n
"""
        cfg = _build_cfg(src)
        self.assertFalse(any("while_else" in l for l in _labels(cfg)))

    def test_plain_while_has_exit_block(self):
        src = """
def f(n: int) -> int:
    while n > 0:
        n = n - 1
    return n
"""
        cfg = _build_cfg(src)
        self.assertTrue(any("while_exit" in l for l in _labels(cfg)))

    def test_plain_while_header_false_branch_targets_exit(self):
        src = """
def f(n: int) -> int:
    while n > 0:
        n = n - 1
    return n
"""
        cfg = _build_cfg(src)
        header = _blocks_with(cfg, "while_header")[0]
        exit_ = _blocks_with(cfg, "while_exit")[0]
        self.assertIsInstance(header.terminator, CondJump)
        self.assertEqual(header.terminator.false_target, exit_.label)


# ---------------------------------------------------------------------------
# continue
# ---------------------------------------------------------------------------


class TestContinue(unittest.TestCase):

    def test_continue_compiles(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    result: int = 0
    while i < n:
        i = i + 1
        if i == 1:
            continue
        result = result + i
    return result
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_continue_block_jumps_to_header(self):
        # When continue is the only statement in a branch, the "then" block
        # should terminate with Jump(header_lbl).
        src = """
def f(n: int) -> int:
    i: int = 0
    while i < n:
        if i == 0:
            continue
        i = i + 1
    return i
"""
        cfg = _build_cfg(src)
        header_lbl = _blocks_with(cfg, "while_header")[0].label
        # Find a "then" block (not the body back-edge) that jumps to header
        then_blocks_to_header = [
            b
            for l, b in cfg.blocks.items()
            if "then" in l
            and isinstance(b.terminator, Jump)
            and b.terminator.target == header_lbl
        ]
        self.assertEqual(len(then_blocks_to_header), 1)


# ---------------------------------------------------------------------------
# break
# ---------------------------------------------------------------------------


class TestBreak(unittest.TestCase):

    def test_break_compiles(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    while i < n:
        if i == 3:
            break
        i = i + 1
    return i
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_body_with_only_break_jumps_to_exit(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    while i < n:
        break
    return i
"""
        cfg = _build_cfg(src)
        exit_lbl = _blocks_with(cfg, "while_exit")[0].label
        body = _blocks_with(cfg, "while_body")[0]
        # The body's only statement is a break, so it terminates with Jump(exit)
        self.assertIsInstance(body.terminator, Jump)
        self.assertEqual(body.terminator.target, exit_lbl)

    def test_break_does_not_jump_to_header(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    while i < n:
        break
    return i
"""
        cfg = _build_cfg(src)
        header_lbl = _blocks_with(cfg, "while_header")[0].label
        body = _blocks_with(cfg, "while_body")[0]
        self.assertNotEqual(body.terminator.target, header_lbl)


# ---------------------------------------------------------------------------
# while / else
# ---------------------------------------------------------------------------


class TestWhileElse(unittest.TestCase):

    def test_while_else_compiles(self):
        src = """
def f(n: int) -> bool:
    i: int = 0
    found: bool = False
    while i < n:
        i = i + 1
    else:
        found = True
    return found
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_while_else_block_present(self):
        src = """
def f(n: int) -> bool:
    i: int = 0
    found: bool = False
    while i < n:
        i = i + 1
    else:
        found = True
    return found
"""
        cfg = _build_cfg(src)
        self.assertTrue(any("while_else" in l for l in _labels(cfg)))
        self.assertTrue(any("while_exit" in l for l in _labels(cfg)))

    def test_header_false_branch_targets_else(self):
        src = """
def f(n: int) -> bool:
    i: int = 0
    found: bool = False
    while i < n:
        i = i + 1
    else:
        found = True
    return found
"""
        cfg = _build_cfg(src)
        header = _blocks_with(cfg, "while_header")[0]
        else_lbl = _blocks_with(cfg, "while_else")[0].label
        self.assertIsInstance(header.terminator, CondJump)
        self.assertEqual(header.terminator.false_target, else_lbl)

    def test_else_block_jumps_to_exit(self):
        src = """
def f(n: int) -> bool:
    i: int = 0
    found: bool = False
    while i < n:
        i = i + 1
    else:
        found = True
    return found
"""
        cfg = _build_cfg(src)
        else_blk = _blocks_with(cfg, "while_else")[0]
        exit_lbl = _blocks_with(cfg, "while_exit")[0].label
        self.assertIsInstance(else_blk.terminator, Jump)
        self.assertEqual(else_blk.terminator.target, exit_lbl)

    def test_break_jumps_past_else_to_exit(self):
        src = """
def f(n: int) -> int:
    result: int = 0
    while result < n:
        break
    else:
        result = 99
    return result
"""
        cfg = _build_cfg(src)
        exit_lbl = _blocks_with(cfg, "while_exit")[0].label
        else_lbl = _blocks_with(cfg, "while_else")[0].label
        body = _blocks_with(cfg, "while_body")[0]
        # break → Jump(exit), NOT Jump(else)
        self.assertIsInstance(body.terminator, Jump)
        self.assertEqual(body.terminator.target, exit_lbl)
        self.assertNotEqual(body.terminator.target, else_lbl)

    def test_while_else_with_return_in_else(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    while i < n:
        i = i + 1
    else:
        return i
    return i
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_while_else_all_paths_return(self):
        """while/else where body may return early and else returns — no exit block needed."""
        src = """
def f(n: int) -> int:
    i: int = 0
    while i < n:
        if i == 3:
            return i
        i = i + 1
    else:
        return 10
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_while_else_all_paths_return_no_exit_block(self):
        """Exit block must not appear in the CFG when it is unreachable."""
        src = """
def f(n: int) -> int:
    i: int = 0
    while i < n:
        if i == 3:
            return i
        i = i + 1
    else:
        return 10
"""
        cfg = _build_cfg(src)
        self.assertFalse(any("while_exit" in l for l in _labels(cfg)))

    def test_while_else_break_makes_exit_reachable(self):
        """break skips the else block; the exit block must still be created."""
        src = """
def f(n: int) -> int:
    i: int = 0
    while i < n:
        if i == 3:
            break
        i = i + 1
    else:
        return 10
    return i
"""
        cfg = _build_cfg(src)
        self.assertTrue(any("while_exit" in l for l in _labels(cfg)))


# ---------------------------------------------------------------------------
# Nested loops
# ---------------------------------------------------------------------------


class TestNestedLoops(unittest.TestCase):

    def test_nested_loops_compile(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    j: int = 0
    while i < n:
        while j < n:
            if j == 2:
                break
            j = j + 1
        if i == 1:
            continue
        i = i + 1
    return i
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_nested_loops_have_independent_exit_and_header_blocks(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    j: int = 0
    while i < n:
        while j < n:
            if j == 2:
                break
            j = j + 1
        if i == 1:
            continue
        i = i + 1
    return i
"""
        cfg = _build_cfg(src)
        self.assertEqual(len(_blocks_with(cfg, "while_exit")), 2)
        self.assertEqual(len(_blocks_with(cfg, "while_header")), 2)

    def test_inner_break_targets_inner_exit(self):
        src = """
def f(n: int) -> int:
    i: int = 0
    j: int = 0
    while i < n:
        while j < n:
            break
        i = i + 1
    return i
"""
        cfg = _build_cfg(src)
        headers = _blocks_with(cfg, "while_header")
        body_blocks = _blocks_with(cfg, "while_body")

        # The outer body block closes with Jump(inner_header) to enter the inner
        # loop.  That makes the inner header the one a while_body block jumps to.
        inner_header = next(
            h
            for h in headers
            if any(
                isinstance(b.terminator, Jump) and b.terminator.target == h.label
                for b in body_blocks
            )
        )
        # The inner exit is the false branch of the inner header's CondJump.
        self.assertIsInstance(inner_header.terminator, CondJump)
        inner_exit_lbl = inner_header.terminator.false_target

        # The break block is the body block that jumps to the inner exit.
        break_body = next(
            b
            for b in body_blocks
            if isinstance(b.terminator, Jump) and b.terminator.target == inner_exit_lbl
        )
        self.assertEqual(break_body.terminator.target, inner_exit_lbl)


if __name__ == "__main__":
    unittest.main(verbosity=2)
