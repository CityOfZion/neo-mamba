from __future__ import annotations
import ast
import dataclasses
from typing import Any, Optional, Union

from ._constants import _WRITE_SYSCALL_NAMES
from .types import (
    Type,
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
    ClassType,
    AnyType,
    IteratorType,
    UInt160Type,
    UInt256Type,
    ECPointType,
    UnionType,
    TypecheckError,
    _resolve_simple_type,
    INT,
    BOOL,
    BYTES,
    BYTEARRAY,
    STR,
    NONE,
    ANY,
    ITERATOR,
    UINT160,
    UINT256,
    ECPOINT,
    LIST_STR,
    _BYTESLIKE,
)

# ---------------------------------------------------------------------------
# 2. TYPED HIR
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class IntLiteral:
    value: int
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class BoolLiteral:
    value: bool
    type: Type = dataclasses.field(default_factory=lambda: BOOL, init=False)


@dataclasses.dataclass
class LocalLoad:
    name: str
    type: Type


@dataclasses.dataclass
class BinOp:
    left: "Expr"
    op: str  # '+' '-' '*' '//' '%' '**' '&' '|' '^' '<<' '>>'
    right: "Expr"
    type: Type


@dataclasses.dataclass
class Compare:
    left: "Expr"
    op: str  # '==' '!=' '<' '<=' '>' '>='
    right: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: BOOL, init=False)


@dataclasses.dataclass
class BoolAnd:
    left: "Expr"
    right: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: BOOL, init=False)


@dataclasses.dataclass
class BoolOr:
    left: "Expr"
    right: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: BOOL, init=False)


@dataclasses.dataclass
class IfExp:
    condition: "Expr"
    then_expr: "Expr"
    else_expr: "Expr"
    type: Type


@dataclasses.dataclass
class Not:
    operand: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: BOOL, init=False)


@dataclasses.dataclass
class Negate:
    operand: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class Invert:
    """~x — bitwise NOT of an int."""

    operand: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class Abs:
    """abs(x) — absolute value of an int."""

    arg: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class Min:
    """min(a, b) — smaller of two ints."""

    left: "Expr"
    right: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class Max:
    """max(a, b) — larger of two ints."""

    left: "Expr"
    right: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class Call:
    name: str
    args: list["Expr"]
    type: Type


@dataclasses.dataclass
class BytesLiteral:
    value: bytes
    type: Type = dataclasses.field(default_factory=lambda: BYTES, init=False)


@dataclasses.dataclass
class NewBuffer:
    """bytearray(n) — zero-filled mutable Buffer of size n."""

    size: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: BYTEARRAY, init=False)


@dataclasses.dataclass
class Len:
    """len(x) for bytes/bytearray — produces int."""

    arg: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class BytesFromHex:
    """bytes.fromhex(s) — calls StdLib.HexDecode via System.Contract.Call; s must be str."""

    arg: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: BYTES, init=False)


@dataclasses.dataclass(frozen=True)
class SyscallCall:
    """A direct NeoVM SYSCALL call mapped from a registered Python import.

    is_stmt=False → expression (result left on stack).
    is_stmt=True  → statement (void; no DROP needed since type is always NONE).
    args are in Python call order; push_order gives the VM push sequence.
    """

    hash: bytes  # 4-byte LE interop hash
    args: list  # visited Expr nodes in Python call order
    push_order: list  # indices into args for VM push order
    type: Type  # NONE = void
    is_stmt: bool = False


@dataclasses.dataclass
class NotifyCall:
    """on_event(args) — emits SYSCALL System.Runtime.Notify; args packed into Array state."""

    event_name: str
    args: list  # visited Expr nodes in Python call order
    type: Type = dataclasses.field(default_factory=lambda: NONE, init=False)


@dataclasses.dataclass
class BytesHex:
    """b.hex() — calls StdLib.hexEncode via System.Contract.Call; b must be bytes/bytearray."""

    arg: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: STR, init=False)


@dataclasses.dataclass
class IntToBytes:
    """x.to_bytes(length=1, byteorder='big', *, signed=False) — pure NeoVM bytecode, no StdLib call.
    byteorder and signed are resolved at compile time; length may be any int expression.
    """

    value: (
        "Expr"  # the integer (dynamic — constant is folded to BytesLiteral at HIR time)
    )
    length: "Expr"  # target byte count
    byteorder: str  # 'little' or 'big'
    signed: bool  # True / False
    type: Type = dataclasses.field(default_factory=lambda: BYTES, init=False)


@dataclasses.dataclass
class IntFromBytes:
    """int.from_bytes(b, byteorder='big', *, signed=False) — converts bytes/bytearray to int.
    byteorder and signed are resolved at compile time; pure NeoVM bytecode, no StdLib call.
    """

    arg: "Expr"  # the bytes/bytearray value
    byteorder: str  # 'little' or 'big'
    signed: bool  # True / False
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class Atoi:
    """int(s[, base]) — calls StdLib.atoi via System.Contract.Call; s: str, base: int (10 or 16)."""

    arg: "Expr"  # the string to parse
    base: "Expr"  # numeric base (10 or 16)
    type: Type = dataclasses.field(default_factory=lambda: INT, init=False)


@dataclasses.dataclass
class Itoa:
    """str(x[, base]) — calls StdLib.itoa via System.Contract.Call; x: int, base: int (10 or 16)."""

    arg: "Expr"  # the integer to format
    base: "Expr"  # numeric base (10 or 16)
    type: Type = dataclasses.field(default_factory=lambda: STR, init=False)


@dataclasses.dataclass
class StrSplit:
    """s.split([sep]) — calls StdLib.stringSplit via System.Contract.Call; s must be str."""

    arg: "Expr"  # the string to split
    sep: "Expr"  # StringLiteral(" ") when not provided
    remove_empty: bool  # True when no sep (Python no-arg semantics)
    type: Type = dataclasses.field(default_factory=lambda: LIST_STR, init=False)


@dataclasses.dataclass(frozen=True)
class ContractCall:
    """ClassName.method(args) on a @contract-decorated class — emits System.Contract.Call.

    is_stmt=False → expression (result left on stack).
    is_stmt=True  → statement (CFGBuilder emits DROP after the call).
    """

    contract_hash: (
        bytes  # 20-byte LE UInt160 (from @contract decorator via UInt160.to_array())
    )
    method: str  # smart contract entry point name (Python method name, or display_name if set)
    args: list  # visited Expr nodes in Python call order
    type: Type  # return type trusted from Python annotation
    call_flags: int = 15  # CallFlags value; default CallFlags.ALL
    is_stmt: bool = False


@dataclasses.dataclass(frozen=True)
class DynamicContractCall:
    """call_contract(script_hash, method, args, call_flags) intrinsic.

    All four values are runtime expressions; emits System.Contract.Call SYSCALL.
    is_stmt=False → expression (result left on stack).
    is_stmt=True  → statement (CFGBuilder emits DROP after the call).
    """

    script_hash: "Expr"  # UInt160 (ByteString)
    method: "Expr"  # str (ByteString)
    args: "Expr"  # list[Any] (Array)
    call_flags: "Expr"  # int (Integer)
    type: Type = dataclasses.field(default_factory=lambda: ANY)
    is_stmt: bool = False


@dataclasses.dataclass
class TypeConvert:
    """int(x)/bool(x)/str(x)/bytes(x) — emit CONVERT opcode with a StackItemType tag."""

    arg: "Expr"
    type: Type  # target type: INT, BOOL, STR, or BYTES


@dataclasses.dataclass
class Cast:
    """typing.cast(T, val) — compile-time type assertion; emits no opcodes, just declares type."""

    arg: "Expr"
    type: Type  # target type declared in cast(T, val)


@dataclasses.dataclass
class Index:
    """container[i] — index into bytes, bytearray, or list[T]."""

    value: "Expr"
    index: "Expr"
    type: Type  # INT for bytes/bytearray; elem type for list[T]


@dataclasses.dataclass
class StrIndex:
    """s[i] — get a single character from str; emits SUBSTR(s, i, 1) → str."""

    value: "Expr"
    index: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: STR, init=False)


@dataclasses.dataclass
class StringLiteral:
    value: str  # Python str; UTF-8 encoded at emit time
    type: Type = dataclasses.field(default_factory=lambda: STR, init=False)


@dataclasses.dataclass
class Slice:
    """data[start:stop:step] for bytes / bytearray / str."""

    value: "Expr"
    start: Optional["Expr"]  # None = from beginning
    stop: Optional["Expr"]  # None = to end
    step: Optional["Expr"]  # None means step=1 (use native LEFT/SUBSTR/RIGHT)
    type: Type  # same as value.type, set by HIRBuilder
    # Pre-allocated temp slots (data,start,stop,step,count,result,write_idx,read_idx); None when step=None
    step_slots: Optional[tuple[int, int, int, int, int, int, int, int]] = None


@dataclasses.dataclass
class ListLiteral:
    """[e1, e2, ...] — homogeneous list literal."""

    elements: list["Expr"]
    type: Type  # ListType(elem)


@dataclasses.dataclass
class TupleLiteral:
    """(e1, e2, ...) — heterogeneous tuple literal; NeoVM Array at runtime."""

    elements: list["Expr"]
    type: Type  # TupleType


@dataclasses.dataclass
class DictLiteral:
    """{ k1: v1, ... } — typed dict literal."""

    pairs: list  # list of (Expr, Expr)
    type: "DictType"


@dataclasses.dataclass
class HasKey:
    """key in d — checks if key exists in a dict[K,V]."""

    container: "Expr"
    key: "Expr"
    type: Type = dataclasses.field(default_factory=lambda: BOOL, init=False)


@dataclasses.dataclass
class DictKeys:
    """d.keys() — returns Array of keys as list[K]."""

    container: "Expr"
    type: Type  # ListType(key_t)


@dataclasses.dataclass
class DictValues:
    """d.values() — returns Array of values as list[V]."""

    container: "Expr"
    type: Type  # ListType(val_t)


@dataclasses.dataclass
class StaticLoad:
    """Load a module-level static field onto the stack."""

    name: str
    slot: int
    type: Type


@dataclasses.dataclass
class NoneLiteral:
    type: Type = dataclasses.field(default_factory=lambda: NONE, init=False)


@dataclasses.dataclass
class IsNone:
    """x is None / x is not None — emits ISNULL (+ NOT if negated)."""

    operand: "Expr"
    negated: bool = False
    type: Type = dataclasses.field(default_factory=lambda: BOOL, init=False)


@dataclasses.dataclass
class IsType:
    """isinstance(x, T) — emits ISTYPE with StackItemType tag. T must be a concrete primitive."""

    operand: "Expr"
    tag: int  # StackItemType tag: 0x21=int, 0x20=bool, 0x28=str/bytes, 0x30=bytearray
    type: Type = dataclasses.field(default_factory=lambda: BOOL, init=False)


@dataclasses.dataclass
class GetField:
    """self.x — read an instance field; emits PICKITEM at a constant index."""

    obj: "Expr"
    field_name: str
    field_index: int
    type: Type


@dataclasses.dataclass
class NewInstance:
    """ClassName(args) — allocate a new NeoVM Array and call __init__."""

    class_name: str
    args: list["Expr"]
    type: Type  # ClassType(class_name)
    temp_slot: int = -1  # pre-allocated local slot for the instance; set by HIRBuilder


@dataclasses.dataclass
class MethodCall:
    """obj.method(args) — push user args r-to-l, push obj (self), CALL_L."""

    obj: "Expr"
    compiled_name: str  # mangled name e.g. "Animal_greet"
    args: list["Expr"]
    type: Type


Expr = Union[
    IntLiteral,
    BoolLiteral,
    LocalLoad,
    BinOp,
    Compare,
    BoolAnd,
    BoolOr,
    IfExp,
    Not,
    Negate,
    Invert,
    Abs,
    Min,
    Max,
    Call,
    BytesLiteral,
    NewBuffer,
    Len,
    BytesFromHex,
    BytesHex,
    IntToBytes,
    IntFromBytes,
    Atoi,
    Itoa,
    StrSplit,
    TypeConvert,
    Cast,
    Index,
    StrIndex,
    StringLiteral,
    Slice,
    ListLiteral,
    TupleLiteral,
    DictLiteral,
    HasKey,
    DictKeys,
    DictValues,
    StaticLoad,
    NoneLiteral,
    IsNone,
    IsType,
    GetField,
    NewInstance,
    MethodCall,
    SyscallCall,
    ContractCall,
    DynamicContractCall,
]


@dataclasses.dataclass(frozen=True)
class LocalStore:
    name: str
    slot: int  # local slot index (is_arg=False) or arg index (is_arg=True)
    value: Expr
    type: Type
    is_arg: bool = False


@dataclasses.dataclass(frozen=True)
class Return:
    value: Expr
    type: Type


@dataclasses.dataclass(frozen=True)
class If:
    condition: Expr
    then_body: list["Stmt"]
    else_body: list["Stmt"]


@dataclasses.dataclass(frozen=True)
class While:
    condition: Expr
    body: list["Stmt"]
    else_body: list["Stmt"]


@dataclasses.dataclass(frozen=True)
class Break:
    pass


@dataclasses.dataclass(frozen=True)
class Continue:
    pass


@dataclasses.dataclass(frozen=True)
class ListAppend:
    """lst.append(v) — mutates list in place; no stack result."""

    container: Expr
    value: Expr


@dataclasses.dataclass(frozen=True)
class ReverseItems:
    """ba.reverse() / lst.reverse() — reverses container in place; no stack result."""

    container: Expr


@dataclasses.dataclass(frozen=True)
class ItemStore:
    """container[index] = value — mutates list or dict in place; no stack result."""

    container: Expr  # ListType or DictType
    index: Expr  # IntType for list; key type for dict
    value: Expr  # must match container element/value type


@dataclasses.dataclass(frozen=True)
class TupleUnpack:
    """a, b = expr — destructure a tuple into separate locals/args."""

    source: "Expr"  # must be TupleType
    targets: list  # list of (slot: int, is_arg: bool, type: Type) per position


@dataclasses.dataclass(frozen=True)
class StaticStore:
    """Store a value into a module-level static field; no stack result."""

    name: str
    slot: int
    value: Expr
    type: Type


@dataclasses.dataclass(frozen=True)
class CallStmt:
    """Call a function as a statement; result dropped via DROP if return_type != NONE."""

    name: str
    args: list[Expr]
    return_type: Type = NONE


@dataclasses.dataclass(frozen=True)
class Assert:
    """assert cond [, msg] — faults if condition is false."""

    condition: "Expr"
    message: "Optional[Expr]"  # None → ASSERT opcode; str expr → ASSERTMSG opcode


@dataclasses.dataclass(frozen=True)
class Raise:
    """raise ExceptionType[(msg)] — aborts with optional str message (THROW=0x3A)."""

    message: "Optional[Expr]"  # None → PUSHNULL + THROW; str expr → push msg + THROW


@dataclasses.dataclass(frozen=True)
class PrintStmt:
    """print(msg) — emits SYSCALL System.Runtime.Log; msg must be str or bytes."""

    msg: "Expr"


@dataclasses.dataclass(frozen=True)
class PrintListStmt:
    """print(list_expr) — runtime check: if len>0, jsonSerialize then System.Runtime.Log."""

    list_expr: "Expr"
    temp_slot: int = -1  # pre-allocated local slot for the list; set by HIRBuilder


@dataclasses.dataclass(frozen=True)
class AbortStmt:
    """abort() / abort(msg) — emits ABORT or ABORTMSG; terminates execution unconditionally."""

    msg: "Optional[Expr]" = None  # None → ABORT (0x38); str expr → ABORTMSG (0xE0)


@dataclasses.dataclass(frozen=True)
class TryExcept:
    """try/except/finally statement."""

    try_body: "list[Stmt]"
    catch_body: "Optional[list[Stmt]]"  # None if no except clause
    finally_body: "Optional[list[Stmt]]"  # None if no finally clause
    handler_var: Optional[str]  # exception variable name (from 'as e')
    handler_var_slot: Optional[int]  # local slot for exception variable


@dataclasses.dataclass(frozen=True)
class SetField:
    """self.x = v — write an instance field; emits SETITEM at a constant index."""

    obj: "Expr"
    field_name: str
    field_index: int
    value: "Expr"
    field_type: Type


@dataclasses.dataclass(frozen=True)
class MethodCallStmt:
    """obj.method(args) called as a statement; result dropped via DROP if return_type != NONE."""

    obj: "Expr"
    compiled_name: str
    args: list["Expr"]
    return_type: Type = NONE


Stmt = Union[
    LocalStore,
    Return,
    If,
    While,
    Break,
    Continue,
    ListAppend,
    ReverseItems,
    ItemStore,
    TupleUnpack,
    StaticStore,
    CallStmt,
    Assert,
    Raise,
    PrintStmt,
    PrintListStmt,
    AbortStmt,
    SyscallCall,
    NotifyCall,
    TryExcept,
    SetField,
    MethodCallStmt,
    ContractCall,
    DynamicContractCall,
]


@dataclasses.dataclass
class HIRFunction:
    name: str
    args: list[tuple[str, Type]]
    return_type: Type
    locals: dict[str, tuple[int, Type]]
    body: list[Stmt]


@dataclasses.dataclass
class FieldInfo:
    name: str
    index: int  # slot in the NeoVM Array
    type: Type


@dataclasses.dataclass
class MethodInfo:
    name: str  # Python name ("greet")
    compiled_name: str  # mangled ("Animal_greet")
    kind: str  # "instance" | "static" | "class"
    ast_node: ast.FunctionDef
    display_name: Optional[str] = (
        None  # overrides the entry point string in System.Contract.Call
    )
    call_flags: int = 15  # CallFlags value for this method; default CallFlags.ALL


@dataclasses.dataclass
class ClassInfo:
    name: str
    bases: list[str]  # direct base names in declared order
    class_mro: list[str]  # C3 MRO (excludes self)
    fields: dict[str, FieldInfo]  # all instance fields (merged from parents+self)
    methods: dict[
        str, MethodInfo
    ]  # all methods (merged from parents+self; child overrides)
    class_vars: dict[str, tuple[int, Type]]  # name → (static slot index, type)
    total_fields: int
    ast_node: ast.ClassDef
    contract_hash: Optional[bytes] = (
        None  # set when class has @contract decorator; 20-byte LE
    )


# ---------------------------------------------------------------------------
# Pre-built class info for built-in NeoVM-mapped types
# ---------------------------------------------------------------------------

_TRIMMED_TX_FIELDS: dict[str, "FieldInfo"] = {
    "hash": FieldInfo(name="hash", index=0, type=UINT256),
    "version": FieldInfo(name="version", index=1, type=INT),
    "nonce": FieldInfo(name="nonce", index=2, type=INT),
    "sender": FieldInfo(name="sender", index=3, type=UINT160),
    "system_fee": FieldInfo(name="system_fee", index=4, type=INT),
    "network_fee": FieldInfo(name="network_fee", index=5, type=INT),
    "valid_until_block": FieldInfo(name="valid_until_block", index=6, type=INT),
    "script": FieldInfo(name="script", index=7, type=BYTES),
}
_TRIMMED_TX_CLASS_INFO = ClassInfo(
    name="TrimmedTransaction",
    bases=[],
    class_mro=[],
    fields=_TRIMMED_TX_FIELDS,
    methods={},
    class_vars={},
    total_fields=8,
    ast_node=ast.ClassDef(
        name="TrimmedTransaction",
        bases=[],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    ),
)

_TRIMMED_BLOCK_FIELDS: dict[str, "FieldInfo"] = {
    "hash": FieldInfo(name="hash", index=0, type=UINT256),
    "version": FieldInfo(name="version", index=1, type=INT),
    "previous_hash": FieldInfo(name="previous_hash", index=2, type=UINT256),
    "merkle_root": FieldInfo(name="merkle_root", index=3, type=UINT256),
    "timestamp": FieldInfo(name="timestamp", index=4, type=INT),
    "nonce": FieldInfo(name="nonce", index=5, type=INT),
    "index": FieldInfo(name="index", index=6, type=INT),
    "primary_index": FieldInfo(name="primary_index", index=7, type=INT),
    "next_consensus": FieldInfo(name="next_consensus", index=8, type=UINT160),
    "transaction_count": FieldInfo(name="transaction_count", index=9, type=INT),
}
_TRIMMED_BLOCK_CLASS_INFO = ClassInfo(
    name="TrimmedBlock",
    bases=[],
    class_mro=[],
    fields=_TRIMMED_BLOCK_FIELDS,
    methods={},
    class_vars={},
    total_fields=10,
    ast_node=ast.ClassDef(
        name="TrimmedBlock",
        bases=[],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    ),
)

_NEO_ACCOUNT_STATE_FIELDS: dict[str, "FieldInfo"] = {
    "balance": FieldInfo(name="balance", index=0, type=INT),
    "height": FieldInfo(name="height", index=1, type=INT),
    "vote_to": FieldInfo(name="vote_to", index=2, type=ECPOINT),
    "last_gas_per_vote": FieldInfo(name="last_gas_per_vote", index=3, type=INT),
}
_NEO_ACCOUNT_STATE_CLASS_INFO = ClassInfo(
    name="NeoAccountState",
    bases=[],
    class_mro=[],
    fields=_NEO_ACCOUNT_STATE_FIELDS,
    methods={},
    class_vars={},
    total_fields=4,
    ast_node=ast.ClassDef(
        name="NeoAccountState",
        bases=[],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    ),
)

_CONTRACT_STATE_FIELDS: dict[str, "FieldInfo"] = {
    "id": FieldInfo(name="id", index=0, type=INT),
    "update_counter": FieldInfo(name="update_counter", index=1, type=INT),
    "hash": FieldInfo(name="hash", index=2, type=UINT160),
    "nef": FieldInfo(name="nef", index=3, type=BYTES),
    "manifest": FieldInfo(name="manifest", index=4, type=BYTES),
}
_CONTRACT_STATE_CLASS_INFO = ClassInfo(
    name="ContractState",
    bases=[],
    class_mro=[],
    fields=_CONTRACT_STATE_FIELDS,
    methods={},
    class_vars={},
    total_fields=5,
    ast_node=ast.ClassDef(
        name="ContractState",
        bases=[],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    ),
)


def _is_subclass_of(child: str, parent: str, registry: dict) -> bool:
    """Return True if child is parent or transitively inherits from parent."""
    if child == parent:
        return True
    info = registry.get(child)
    return info is not None and any(
        _is_subclass_of(b, parent, registry) for b in info.bases
    )


def resolve_annotation(
    node: ast.expr,
    class_registry: Optional[dict[str, "ClassInfo"]] = None,
    extra_names: Optional[dict[str, Type]] = None,
    filename: Optional[str] = None,
    module_fn_maps: Optional[dict[str, dict[str, str]]] = None,
    module_names: Optional[set] = None,
) -> Type:
    def _recurse(n: ast.expr) -> Type:
        return resolve_annotation(
            n, class_registry, extra_names, filename, module_fn_maps, module_names
        )

    def _err(msg: str) -> TypecheckError:
        lineno = getattr(node, "lineno", None)
        col = getattr(node, "col_offset", None)
        return TypecheckError(msg, lineno=lineno, col_offset=col, filename=filename)

    if isinstance(node, ast.Constant) and node.value is None:
        return NONE
    if isinstance(node, ast.Name):
        match node.id:
            case "int":
                return INT
            case "bool":
                return BOOL
            case "bytes":
                return BYTES
            case "bytearray":
                return BYTEARRAY
            case "str":
                return STR
            case "None":
                return NONE
            case "Any":
                return ANY
            case "UInt160":
                return UINT160
            case "UInt256":
                return UINT256
            case "ECPoint":
                return ECPOINT
            case "Iterator":
                return ITERATOR
            case "FindOptions" | "CallFlags" | "NamedCurveHash":
                return INT
            case "list" | "List":
                return ListType(ANY)
        if extra_names is not None and node.id in extra_names:
            return extra_names[node.id]
        if class_registry is not None and node.id in class_registry:
            return ClassType(node.id)
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name) and node.value.id in ("list", "List"):
            elem = _recurse(node.slice)
            return ListType(elem)
        if isinstance(node.value, ast.Name) and node.value.id in ("dict", "Dict"):
            if not isinstance(node.slice, ast.Tuple) or len(node.slice.elts) != 2:
                raise _err("dict annotation must be dict[K, V]")
            key_t = _recurse(node.slice.elts[0])
            val_t = _recurse(node.slice.elts[1])
            _VALID_KEY_TYPES = (IntType, BoolType, BytesType, StrType)
            if not isinstance(key_t, _VALID_KEY_TYPES):
                raise TypecheckError(
                    f"dict key type must be int, bool, bytes, or str; got {key_t}",
                    lineno=getattr(node, "lineno", None),
                    col_offset=getattr(node, "col_offset", None),
                    filename=filename,
                )
            return DictType(key_t, val_t)
        if isinstance(node.value, ast.Name) and node.value.id == "tuple":
            slice_ = node.slice
            if isinstance(slice_, ast.Tuple):
                elems = tuple(_recurse(e) for e in slice_.elts)
            else:
                elems = (_recurse(slice_),)
            return TupleType(elems)
        if isinstance(node.value, ast.Name) and node.value.id == "Optional":
            inner = _recurse(node.slice)
            return OptionalType(inner)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        ns = node.value.id
        if module_fn_maps is not None and ns in module_fn_maps:
            mangled = module_fn_maps[ns].get(node.attr, node.attr)
            if class_registry is not None and mangled in class_registry:
                return ClassType(mangled)
        # Fallback for namespaces in module_names but not module_fn_maps (e.g. sc library
        # modules imported as `from neo3.sc import utils`): resolve the attr as a
        # bare name so that utils.Iterator, utils.UInt160, etc. work correctly.
        if module_names is not None and ns in module_names:
            return _recurse(ast.Name(id=node.attr, ctx=ast.Load()))
    raise _err(f"Unsupported type annotation: {ast.dump(node)}")


def _container_param_compatible(
    value_type: Type,
    declared_type: Type,
    class_registry: Optional[dict[str, "ClassInfo"]] = None,
) -> bool:
    """Like _type_compatible but Any in value position does not satisfy a concrete declared type.
    Used for covariant container element/key/value checks so that dict[str, Any] (inferred from
    heterogeneous literals) cannot be assigned to dict[str, int]."""
    if isinstance(declared_type, AnyType):
        return True
    if isinstance(value_type, AnyType):
        return False
    return _type_compatible(value_type, declared_type, class_registry)


def _type_compatible(
    value_type: Type,
    declared_type: Type,
    class_registry: Optional[dict[str, "ClassInfo"]] = None,
) -> bool:
    """Return True if value_type can be assigned to declared_type.
    Allows T or None to be assigned to Optional[T].
    Allows a subclass instance to be assigned where a base class is expected."""
    if isinstance(value_type, AnyType) or isinstance(declared_type, AnyType):
        return True
    if value_type == declared_type:
        return True
    if isinstance(declared_type, OptionalType):
        return _type_compatible(
            value_type, declared_type.inner, class_registry
        ) or isinstance(value_type, NoneType)
    if isinstance(declared_type, UnionType):
        return any(
            _type_compatible(value_type, t, class_registry) for t in declared_type.types
        )
    # If the value itself is a union, all its members must be compatible with declared_type
    if isinstance(value_type, UnionType):
        return all(
            _type_compatible(t, declared_type, class_registry) for t in value_type.types
        )
    if (
        isinstance(value_type, ClassType)
        and isinstance(declared_type, ClassType)
        and class_registry is not None
    ):
        return _is_subclass_of(value_type.name, declared_type.name, class_registry)
    if isinstance(declared_type, DictType) and isinstance(value_type, DictType):
        return _container_param_compatible(
            value_type.key, declared_type.key, class_registry
        ) and _container_param_compatible(
            value_type.val, declared_type.val, class_registry
        )
    if isinstance(declared_type, ListType) and isinstance(value_type, ListType):
        return _container_param_compatible(
            value_type.elem, declared_type.elem, class_registry
        )
    return False


def _type_mismatch_msg(context: str, expected: Type, got: Type) -> str:
    return f"Type mismatch {context}: expected {expected}, got {got}"


def _for_rewrite_continues(stmts: list[Stmt], increment: LocalStore) -> list[Stmt]:
    """Replace each Continue() with [increment, Continue()], recursing into If and TryExcept.
    Does NOT recurse into While (those have their own continue targets)."""
    result: list[Stmt] = []
    for stmt in stmts:
        match stmt:
            case Continue():
                result.append(increment)
                result.append(Continue())
            case If(condition=cond, then_body=then_b, else_body=else_b):
                result.append(
                    If(
                        condition=cond,
                        then_body=_for_rewrite_continues(then_b, increment),
                        else_body=_for_rewrite_continues(else_b, increment),
                    )
                )
            case TryExcept(
                try_body=try_b,
                catch_body=catch_b,
                finally_body=finally_b,
                handler_var=hvar,
                handler_var_slot=hslot,
            ):
                result.append(
                    TryExcept(
                        try_body=_for_rewrite_continues(try_b, increment),
                        catch_body=(
                            _for_rewrite_continues(catch_b, increment)
                            if catch_b is not None
                            else None
                        ),
                        finally_body=(
                            _for_rewrite_continues(finally_b, increment)
                            if finally_b is not None
                            else None
                        ),
                        handler_var=hvar,
                        handler_var_slot=hslot,
                    )
                )
            case _:
                result.append(stmt)
    return result


def _always_terminates(stmts: list) -> bool:
    """True when all control paths through stmts unconditionally leave (return/raise)."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If) and last.orelse:
        return _always_terminates(last.body) and _always_terminates(last.orelse)
    return False


# ---------------------------------------------------------------------------
# Moved from __init__.py
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _PublicMethodInfo:
    name: str  # resolved: alias if given, else the function name
    offset: int
    params: list[tuple[str, Type]]
    return_type: Type
    safe: bool = False


@dataclasses.dataclass
class _EventInfo:
    fn_name: str  # Python function name
    event_name: str  # ABI event name (from name=...)
    params: list[
        tuple[str, Type]
    ]  # (abi_name, type) — rename applied; Optional kept for type checking


def _c3_mro(
    name: str,
    bases: list[str],
    registry: dict,
    *,
    lineno: Optional[int] = None,
    col_offset: Optional[int] = None,
    filename: Optional[str] = None,
) -> list[str]:
    """Compute the C3 linearization of *name*'s MRO (excluding *name* itself)."""
    if not bases:
        return []
    # Validate all bases exist and detect circular inheritance
    for b in bases:
        if b not in registry:
            raise TypecheckError(
                f"Class '{name}' inherits from unknown class '{b}'",
                lineno=lineno,
                col_offset=col_offset,
                filename=filename,
            )
        if name in registry[b].class_mro:
            raise TypecheckError(
                f"Circular inheritance detected: '{name}' appears in MRO of base '{b}'",
                lineno=lineno,
                col_offset=col_offset,
                filename=filename,
            )
    # For a single base this degenerates to [base, *base_mro]
    # Full C3 merge for multiple bases
    sequences = [[b] + registry[b].class_mro for b in bases] + [list(bases)]

    result: list[str] = []
    while True:
        # Remove empty sequences
        sequences = [s for s in sequences if s]
        if not sequences:
            return result
        # Find a good head: first element of some seq that doesn't appear in any tail
        for seq in sequences:
            candidate = seq[0]
            if not any(candidate in s[1:] for s in sequences):
                result.append(candidate)
                for s in sequences:
                    if s and s[0] == candidate:
                        s.pop(0)
                break
        else:
            raise TypecheckError(
                f"Inconsistent MRO for class '{name}': cannot linearize bases {bases}",
                lineno=lineno,
                col_offset=col_offset,
                filename=filename,
            )


def _merge_fields(
    class_name: str,
    class_mro: list[str],
    own_fields: dict[str, Type],
    registry: dict,
    *,
    lineno: Optional[int] = None,
    col_offset: Optional[int] = None,
    filename: Optional[str] = None,
) -> dict[str, FieldInfo]:
    """Merge parent field layouts (MRO order, most-base-last) then append own fields.
    Raises TypecheckError on index conflicts."""
    merged: dict[str, FieldInfo] = {}
    used_indices: dict[int, str] = {}  # index → field name owning that slot
    # Walk MRO from most-base to most-derived (reverse) so indices accumulate correctly
    for ancestor in reversed(class_mro):
        ancestor_info = registry[ancestor]
        for fname, fi in ancestor_info.fields.items():
            if fname in merged:
                existing = merged[fname]
                if existing.index != fi.index:
                    raise TypecheckError(
                        f"Multiple inheritance field index conflict in '{class_name}': "
                        f"field '{fname}' has index {existing.index} from one base but "
                        f"{fi.index} from '{ancestor}'",
                        lineno=lineno,
                        col_offset=col_offset,
                        filename=filename,
                    )
                if existing.type != fi.type:
                    raise TypecheckError(
                        f"Multiple inheritance field type conflict in '{class_name}': "
                        f"field '{fname}' has type {existing.type} from one base but "
                        f"{fi.type} from '{ancestor}'",
                        lineno=lineno,
                        col_offset=col_offset,
                        filename=filename,
                    )
            else:
                if fi.index in used_indices:
                    existing_name = used_indices[fi.index]
                    raise TypecheckError(
                        f"Multiple inheritance field index conflict in '{class_name}': "
                        f"field '{fname}' from '{ancestor}' and field '{existing_name}' "
                        f"both have index {fi.index}",
                        lineno=lineno,
                        col_offset=col_offset,
                        filename=filename,
                    )
                merged[fname] = fi
                used_indices[fi.index] = fname

    # Append own fields after all inherited fields
    next_idx = len(merged)
    for fname, ftype in own_fields.items():
        if fname not in merged:
            merged[fname] = FieldInfo(name=fname, index=next_idx, type=ftype)
            next_idx += 1
    return merged


def _get_method_kind(fn_node: ast.FunctionDef) -> str:
    for d in fn_node.decorator_list:
        if isinstance(d, ast.Name) and d.id in ("staticmethod", "classmethod"):
            return "static" if d.id == "staticmethod" else "class"
    return "instance"


def _walk_hir_node(
    node: object, hir_fn_map: dict, visited: set[str], found: list[str]
) -> None:
    """Recursively walk HIR nodes, collecting write-syscall op names into *found*."""
    if node is None:
        return
    if isinstance(node, list):
        for item in node:
            _walk_hir_node(item, hir_fn_map, visited, found)
        return
    if isinstance(node, SyscallCall):
        op = _WRITE_SYSCALL_NAMES.get(node.hash)
        if op:
            found.append(op)
        for arg in node.args:
            _walk_hir_node(arg, hir_fn_map, visited, found)
        return
    if isinstance(node, (Call, CallStmt)):
        fn_name = node.name
        if fn_name not in visited and fn_name in hir_fn_map:
            visited.add(fn_name)
            _walk_hir_node(hir_fn_map[fn_name].body, hir_fn_map, visited, found)
        for arg in node.args:
            _walk_hir_node(arg, hir_fn_map, visited, found)
        return
    if isinstance(node, (MethodCall, MethodCallStmt)):
        fn_name = node.compiled_name
        if fn_name not in visited and fn_name in hir_fn_map:
            visited.add(fn_name)
            _walk_hir_node(hir_fn_map[fn_name].body, hir_fn_map, visited, found)
        _walk_hir_node(node.obj, hir_fn_map, visited, found)
        for arg in node.args:
            _walk_hir_node(arg, hir_fn_map, visited, found)
        return
    if isinstance(node, NewInstance):
        init_name = f"{node.class_name}___init__"
        if init_name not in visited and init_name in hir_fn_map:
            visited.add(init_name)
            _walk_hir_node(hir_fn_map[init_name].body, hir_fn_map, visited, found)
        for arg in node.args:
            _walk_hir_node(arg, hir_fn_map, visited, found)
        return
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        for f in dataclasses.fields(node):
            val = getattr(node, f.name)
            if val is None or isinstance(val, (int, float, str, bool, bytes)):
                continue
            _walk_hir_node(val, hir_fn_map, visited, found)


def _collect_write_ops(
    stmts: list, hir_fn_map: dict[str, "HIRFunction"], visited: set[str]
) -> list[str]:
    """Walk HIR stmts/exprs and return names of state-modifying syscalls reachable from *stmts*."""
    found: list[str] = []
    _walk_hir_node(stmts, hir_fn_map, visited, found)
    return found
