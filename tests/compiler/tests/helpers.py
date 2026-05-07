import ast as _ast
from typing import Optional

from neo3.compiler import CFGBuilder, ClassInfo, HIRBuilder


def _build_cfg(source: str, class_registry: Optional[dict[str, ClassInfo]] = None):
    tree = _ast.parse(source)
    fn_node = next(n for n in _ast.walk(tree) if isinstance(n, _ast.FunctionDef))
    hir = HIRBuilder(class_registry=class_registry).build(fn_node)
    return CFGBuilder(hir).build()


def _labels(cfg) -> set[str]:
    return set(cfg.blocks.keys())


def _blocks_with(cfg, substring: str):
    return [b for l, b in cfg.blocks.items() if substring in l]
