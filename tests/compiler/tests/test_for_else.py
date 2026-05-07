import unittest

from neo3.compiler import CondJump, Jump, compile_function, compile_module

from tests.compiler.tests.helpers import _blocks_with, _build_cfg, _labels


class TestForRangeElse(unittest.TestCase):

    def test_for_range_else_compiles(self):
        src = """
def f(n: int) -> int:
    result: int = 0
    for i in range(n):
        result = result + i
    else:
        result = -1
    return result
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_for_range_no_else_no_else_block(self):
        src = """
def f(n: int) -> int:
    result: int = 0
    for i in range(n):
        result = result + i
    return result
"""
        cfg = _build_cfg(src)
        self.assertFalse(any("while_else" in l for l in _labels(cfg)))

    def test_for_range_else_block_present(self):
        src = """
def f(n: int) -> int:
    result: int = 0
    for i in range(n):
        result = result + i
    else:
        result = -1
    return result
"""
        cfg = _build_cfg(src)
        self.assertTrue(any("while_else" in l for l in _labels(cfg)))

    def test_for_range_header_false_branch_targets_else(self):
        src = """
def f(n: int) -> int:
    result: int = 0
    for i in range(n):
        result = result + i
    else:
        result = -1
    return result
"""
        cfg = _build_cfg(src)
        headers = _blocks_with(cfg, "while_header")
        self.assertEqual(len(headers), 1)
        header = headers[0]
        self.assertIsInstance(header.terminator, CondJump)
        else_lbl = _blocks_with(cfg, "while_else")[0].label
        self.assertEqual(header.terminator.false_target, else_lbl)

    def test_for_range_else_jumps_to_exit(self):
        src = """
def f(n: int) -> int:
    result: int = 0
    for i in range(n):
        result = result + i
    else:
        result = -1
    return result
"""
        cfg = _build_cfg(src)
        else_blk = _blocks_with(cfg, "while_else")[0]
        exit_lbl = _blocks_with(cfg, "while_exit")[0].label
        self.assertIsInstance(else_blk.terminator, Jump)
        self.assertEqual(else_blk.terminator.target, exit_lbl)

    def test_for_range_break_skips_else(self):
        src = """
def f(n: int) -> int:
    result: int = 0
    for i in range(n):
        if i > 5:
            break
        result = result + i
    else:
        result = -1
    return result
"""
        cfg = _build_cfg(src)
        else_lbl = _blocks_with(cfg, "while_else")[0].label
        exit_lbl = _blocks_with(cfg, "while_exit")[0].label
        # Find the block whose terminator is a Jump caused by break
        break_blocks = [
            b
            for b in cfg.blocks.values()
            if isinstance(b.terminator, Jump)
            and b.terminator.target == exit_lbl
            and "while_else" not in b.label
        ]
        self.assertTrue(len(break_blocks) >= 1)
        for b in break_blocks:
            self.assertNotEqual(b.terminator.target, else_lbl)


class TestForListElse(unittest.TestCase):

    def test_for_list_else_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    result: int = 0
    for x in lst:
        result = result + x
    else:
        result = -1
    return result
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_for_list_else_block_present(self):
        src = """
def f(lst: list[int]) -> int:
    result: int = 0
    for x in lst:
        result = result + x
    else:
        result = -1
    return result
"""
        cfg = _build_cfg(src)
        self.assertTrue(any("while_else" in l for l in _labels(cfg)))


class TestForDictItemsElse(unittest.TestCase):

    def test_for_dict_items_else_compiles(self):
        src = """
def f(d: dict[str, int]) -> int:
    result: int = 0
    for k, v in d.items():
        result = result + v
    else:
        result = -1
    return result
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_for_dict_items_else_block_present(self):
        src = """
def f(d: dict[str, int]) -> int:
    result: int = 0
    for k, v in d.items():
        result = result + v
    else:
        result = -1
    return result
"""
        cfg = _build_cfg(src)
        self.assertTrue(any("while_else" in l for l in _labels(cfg)))
