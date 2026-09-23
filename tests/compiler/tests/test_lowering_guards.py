import ast
import dataclasses
import unittest

from neo3.compiler import CFGBuilder, HIRBuilder, Linearizer
from neo3.compiler.cfg import CFG, Jump, Ret, StackInstr
from neo3.compiler.hir import HIRFunction, Return
from neo3.compiler.types import INT, NONE


@dataclasses.dataclass(frozen=True)
class _UnknownNode:
    """Stand-in for an HIR node / terminator with no lowering."""

    type: object = INT


def _build_hir(source: str) -> HIRFunction:
    tree = ast.parse(source)
    fn_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    return HIRBuilder().build(fn_node)


def _void_fn() -> HIRFunction:
    return HIRFunction(name="f", args=[], return_type=NONE, locals={}, body=[])


class TestCFGBuilderRejectsUnknownNodes(unittest.TestCase):

    def test_unknown_expression_raises(self):
        hir = _build_hir(
            """
def f() -> int:
    return 1
"""
        )
        ret = hir.body[0]
        self.assertIsInstance(ret, Return)
        hir.body[0] = dataclasses.replace(ret, value=_UnknownNode())
        with self.assertRaises(NotImplementedError) as ctx:
            CFGBuilder(hir).build()
        self.assertIn("_UnknownNode", str(ctx.exception))

    def test_unknown_statement_raises(self):
        hir = _build_hir(
            """
def f() -> None:
    pass
"""
        )
        hir.body.insert(0, _UnknownNode())
        with self.assertRaises(NotImplementedError) as ctx:
            CFGBuilder(hir).build()
        self.assertIn("_UnknownNode", str(ctx.exception))


class TestLinearizerRejectsMalformedBlocks(unittest.TestCase):

    def test_unknown_terminator_raises(self):
        cfg = CFG(entry="entry", blocks={})
        cfg.new_block("entry").terminator = _UnknownNode()
        with self.assertRaises(NotImplementedError) as ctx:
            Linearizer(cfg, _void_fn()).generate()
        self.assertIn("_UnknownNode", str(ctx.exception))

    def test_open_block_with_instructions_raises(self):
        cfg = CFG(entry="entry", blocks={})
        entry = cfg.new_block("entry")
        entry.instructions.append(StackInstr(op="PUSH_INT", type=INT, operand=1))
        with self.assertRaises(NotImplementedError) as ctx:
            Linearizer(cfg, _void_fn()).generate()
        self.assertIn("entry", str(ctx.exception))

    def test_jump_to_open_block_raises(self):
        cfg = CFG(entry="entry", blocks={})
        cfg.new_block("entry").terminator = Jump(target="dangling")
        cfg.new_block("other").terminator = Ret()
        cfg.new_block("dangling")
        with self.assertRaises(NotImplementedError) as ctx:
            Linearizer(cfg, _void_fn()).generate()
        self.assertIn("dangling", str(ctx.exception))

    def test_empty_open_block_emits_nothing(self):
        # Unreachable join block left behind when all if/else branches return.
        cfg = CFG(entry="entry", blocks={})
        cfg.new_block("entry").terminator = Ret()
        cfg.new_block("join")
        self.assertEqual(Linearizer(cfg, _void_fn()).generate(), b"\x40")  # RET


if __name__ == "__main__":
    unittest.main()
