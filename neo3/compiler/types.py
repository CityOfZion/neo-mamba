from __future__ import annotations
import ast
import dataclasses
from typing import Optional, Union

# ---------------------------------------------------------------------------
# 1. TYPE SYSTEM
# ---------------------------------------------------------------------------


class _TypeBase:
    """Default predicate implementations for all compiler type objects."""

    def is_numeric(self) -> bool:
        return False

    def is_byteslike(self) -> bool:
        return False


@dataclasses.dataclass(frozen=True)
class IntType(_TypeBase):
    def __str__(self):
        return "int"

    def is_numeric(self) -> bool:
        return True


@dataclasses.dataclass(frozen=True)
class BoolType(_TypeBase):
    def __str__(self):
        return "bool"

    def is_numeric(self) -> bool:
        return True


@dataclasses.dataclass(frozen=True)
class BytesType(_TypeBase):
    def __str__(self):
        return "bytes"

    def is_byteslike(self) -> bool:
        return True


@dataclasses.dataclass(frozen=True)
class BytearrayType(_TypeBase):
    def __str__(self):
        return "bytearray"

    def is_byteslike(self) -> bool:
        return True


@dataclasses.dataclass(frozen=True)
class StrType(_TypeBase):
    def __str__(self):
        return "str"

    def is_byteslike(self) -> bool:
        return True


@dataclasses.dataclass(frozen=True)
class ListType(_TypeBase):
    elem: "Type"

    def __str__(self):
        return f"list[{self.elem}]"


@dataclasses.dataclass(frozen=True)
class DictType(_TypeBase):
    key: "Type"
    val: "Type"

    def __str__(self):
        return f"dict[{self.key}, {self.val}]"


@dataclasses.dataclass(frozen=True)
class TupleType(_TypeBase):
    elements: tuple["Type", ...]  # fixed-length, heterogeneous

    def __str__(self):
        return f"tuple[{', '.join(str(e) for e in self.elements)}]"


@dataclasses.dataclass(frozen=True)
class NoneType(_TypeBase):
    def __str__(self):
        return "None"


@dataclasses.dataclass(frozen=True)
class OptionalType(_TypeBase):
    inner: "Type"

    def __str__(self):
        return f"Optional[{self.inner}]"


@dataclasses.dataclass(frozen=True)
class ClassType(_TypeBase):
    name: str

    def __str__(self):
        return self.name


@dataclasses.dataclass(frozen=True)
class AnyType(_TypeBase):
    def __str__(self):
        return "Any"


@dataclasses.dataclass(frozen=True)
class IteratorType(_TypeBase):
    def __str__(self):
        return "Iterator"


@dataclasses.dataclass(frozen=True)
class UInt160Type(_TypeBase):
    def __str__(self):
        return "UInt160"


@dataclasses.dataclass(frozen=True)
class UInt256Type(_TypeBase):
    def __str__(self):
        return "UInt256"


@dataclasses.dataclass(frozen=True)
class ECPointType(_TypeBase):
    def __str__(self):
        return "ECPoint"


@dataclasses.dataclass(frozen=True)
class UnionType(_TypeBase):
    types: tuple["Type", ...]

    def __str__(self):
        return " | ".join(str(t) for t in self.types)


Type = Union[
    IntType,
    BoolType,
    BytesType,
    BytearrayType,
    StrType,
    ListType,
    DictType,
    TupleType,
    NoneType,
    OptionalType,
    "ClassType",
    "AnyType",
    "IteratorType",
    "UInt160Type",
    "UInt256Type",
    "ECPointType",
    "UnionType",
]
INT = IntType()
BOOL = BoolType()
BYTES = BytesType()
BYTEARRAY = BytearrayType()
STR = StrType()
NONE = NoneType()
ANY = AnyType()
ITERATOR = IteratorType()
UINT160 = UInt160Type()
UINT256 = UInt256Type()
ECPOINT = ECPointType()
LIST_STR = ListType(STR)
_BYTESLIKE = (BytesType, BytearrayType, StrType, UInt160Type, UInt256Type, ECPointType)


class TypecheckError(Exception):
    def __init__(
        self,
        msg: str,
        *,
        lineno: Optional[int] = None,
        col_offset: Optional[int] = None,
        filename: Optional[str] = None,
    ) -> None:
        super().__init__(msg)
        self.lineno = lineno
        self.col_offset = col_offset
        self.filename = filename

    def __str__(self) -> str:
        parts: list[str] = []
        if self.filename:
            parts.append(self.filename)
        if self.lineno is not None:
            loc = f"line {self.lineno}"
            if self.col_offset is not None:
                loc += f", col {self.col_offset + 1}"
            parts.append(loc)
        prefix = ", ".join(parts)
        msg = super().__str__()
        return f"{prefix}: {msg}" if prefix else msg


def _resolve_simple_type(annotation: ast.expr) -> "Type":
    """Simplified type resolver used for ``@syscall`` return/arg annotations.

    Does not require a class registry — unknown names become ``ClassType(name)``.
    """
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return NONE
    if isinstance(annotation, ast.Name):
        match annotation.id:
            case "int":
                return INT
            case "bool":
                return BOOL
            case "str":
                return STR
            case "bytes":
                return BYTES
            case "None":
                return NONE
            case "UInt160":
                return UINT160
            case "UInt256":
                return UINT256
            case "ECPoint":
                return ECPOINT
            case "Iterator":
                return ITERATOR
            case "FindOptions":
                return INT
            case "CallFlags":
                return INT
            case "NamedCurveHash":
                return INT
            case _:
                return ClassType(annotation.id)
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        left = _resolve_simple_type(annotation.left)
        right = _resolve_simple_type(annotation.right)
        return UnionType(types=(left, right))
    if (
        isinstance(annotation, ast.Subscript)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id == "Optional"
    ):
        return OptionalType(_resolve_simple_type(annotation.slice))
    raise TypecheckError(
        f"@syscall: unsupported type annotation: {ast.dump(annotation)}",
        lineno=getattr(annotation, "lineno", None),
        col_offset=getattr(annotation, "col_offset", None),
    )


def _type_of_folded(v: object) -> Optional[Type]:
    """Map a Python constant value to its compiler Type, or None if not representable."""
    if isinstance(v, bool):
        return BOOL
    if isinstance(v, int):
        return INT
    if isinstance(v, str):
        return STR
    if isinstance(v, bytes):
        return BYTES
    return None
