from __future__ import annotations
import ast
import dataclasses
import hashlib
import os
from typing import Optional, Union
from neo3.core.types import UInt160, UInt256
from neo3.vm import Syscalls
from neo3.sc.types import (
    FindOptions as _FindOptions_enum,
    CallFlags as _CallFlags_enum,
    NamedCurveHash as _NamedCurveHash_enum,
)

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
    _BYTESLIKE,
    _type_of_folded,
)
from .hir import (
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
    SyscallCall,
    NotifyCall,
    BytesHex,
    IntToBytes,
    IntFromBytes,
    Atoi,
    Itoa,
    StrSplit,
    ContractCall,
    DynamicContractCall,
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
    TryExcept,
    SetField,
    MethodCallStmt,
    Expr,
    Stmt,
    HIRFunction,
    MethodInfo,
    ClassInfo,
    resolve_annotation,
    _type_compatible,
    _type_mismatch_msg,
    _for_rewrite_continues,
    _always_terminates,
    _EventInfo,
    _c3_mro,
    _merge_fields,
    _get_method_kind,
)

_ITERATOR_MODULE = "neo3.sc.utils.iterator"
_UTILS_MODULE = "neo3.sc.utils"
_TYPES_MODULE = "neo3.sc.types"

_SYSCALL_ITERATOR_NEXT: bytes = Syscalls.get_by_name(
    "System.Iterator.Next"
).number.to_bytes(4, "little")
_SYSCALL_ITERATOR_VALUE: bytes = Syscalls.get_by_name(
    "System.Iterator.Value"
).number.to_bytes(4, "little")

# The module that must be imported for the @public decorator to be recognised.
_COMPILETIME_MODULE = "neo3.sc.compiletime"
_COMPILETIME_PARENT = "neo3.sc"  # for `from neo3.sc import compiletime`
_COMPILER_PACKAGE_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

# Modules whose functions are @syscall-decorated; resolved dynamically from their
# source files rather than via a hardcoded registry.
_SYSCALL_DECORATOR_MODULES: frozenset[str] = frozenset(
    {
        "neo3.sc.runtime",
        "neo3.sc.storage",
    }
)

# FindOptions / CallFlags attribute → integer value.
# Derived from the canonical enum definitions in neo3.sc.types rather
# than being hardcoded, so they can never drift out of sync.
_FIND_OPTIONS_VALUES: dict[str, int] = {
    name: m.value for name, m in _FindOptions_enum.__members__.items()
}
_CALL_FLAGS_VALUES: dict[str, int] = {
    name: m.value for name, m in _CallFlags_enum.__members__.items()
}
_NAMED_CURVE_HASH_VALUES: dict[str, int] = {
    name: m.value for name, m in _NamedCurveHash_enum.__members__.items()
}


@dataclasses.dataclass
class _SyscallSpec:
    """Descriptor for a direct-SYSCALL function exposed via a Python import."""

    hash: bytes  # 4-byte LE interop hash (first 4 bytes of SHA256 of method name)
    params: list  # expected arg Types in Python call order
    ret: Type  # NONE = void (statement only); anything else = expression
    push_order: list  # indices into params in VM push order (last = top of stack)
    defaults: Optional[dict[int, int]] = None  # param_index → default int value
    param_names: list = dataclasses.field(default_factory=list)  # Python param names


class HIRBuilder:
    """Converts a Python AST function into High-level Intermediate Representation (HIR).

    One ``HIRBuilder`` instance is created per function.  Module-level state
    (function signatures, static variables, class definitions, imported
    syscall/event decorators, …) is injected via constructor arguments so that
    multiple functions in the same module can share a consistent view of the
    program.

    Type checking is performed during the AST walk: every HIR expression node
    carries an inferred ``Type``, and mismatches raise ``TypecheckError``.
    Optional narrowing is applied for ``assert isinstance(x, T)`` guards and
    ``is None`` / ``is not None`` checks at the top of ``if`` branches.

    Attributes:
        _signatures: Map from mangled function name to ``(arg_types, return_type)``.
        _statics: Map from static variable name to ``(slot_index, type)``.
        _func_defaults: Default HIR expressions keyed by mangled function name
            and parameter index.
        _class_registry: Optional map from class name to ``ClassInfo`` for
            field lookups and method dispatch.
        _current_class: Name of the class currently being compiled, or ``None``
            for module-level functions.
        _locals: Map from local variable name to ``(slot_index, type)`` for
            the function being compiled.
        _args: Map from argument name to ``(slot_index, type)`` for the
            function being compiled.
        _return_type: Declared return type of the current function.
        _in_loop: ``True`` while the builder is processing a loop body.
        _pre_stmts: Synthetic HIR statements prepended to the function body
            before user-written statements (e.g. ``self``-extraction for
            instance methods).
    """

    def __init__(
        self,
        signatures: Optional[dict[str, tuple[list[Type], Type]]] = None,
        statics: Optional[dict[str, tuple[int, Type]]] = None,
        func_defaults: Optional[dict[str, dict[int, "Expr"]]] = None,
        class_registry: Optional[dict[str, "ClassInfo"]] = None,
        current_class: Optional[str] = None,
        module_names: Optional[set[str]] = None,
        aliases: Optional[dict[str, str]] = None,
        syscall_fn_specs: Optional[dict[str, "_SyscallSpec"]] = None,
        syscall_module_fn_specs: Optional[dict[str, "dict[str, _SyscallSpec]"]] = None,
        event_fn_specs: Optional[dict[str, "_EventInfo"]] = None,
        iterator_names: Optional[set[str]] = None,
        findoptions_names: Optional[set[str]] = None,
        callflags_names: Optional[set[str]] = None,
        namedcurvehash_names: Optional[set[str]] = None,
        module_fn_maps: Optional[dict[str, dict[str, str]]] = None,
        filename: Optional[str] = None,
    ):
        """Initialise the builder with module-level context for a single function.

        Args:
            signatures: Map from mangled function name to
                ``(arg_types, return_type)`` for all functions visible in the
                module.
            statics: Map from static variable name to ``(slot_index, type)``.
            func_defaults: Default HIR expressions keyed by mangled function
                name and parameter index.
            class_registry: Mapping of class name to ``ClassInfo`` for
                field and method resolution.
            current_class: Name of the class whose method is being compiled,
                or ``None`` for module-level functions.
            module_names: Set of module-alias names imported into the file,
                used to recognise ``module.func(…)`` call patterns.
            aliases: Map from local alias name to canonical type name for
                type-annotation resolution (e.g. ``{"Container": "Box"}``).
            syscall_fn_specs: Map from local function name to ``_SyscallSpec``
                for functions decorated with ``@syscall``.
            syscall_module_fn_specs: Map from module alias to a nested map of
                function name to ``_SyscallSpec``, for namespace imports of
                syscall functions.
            event_fn_specs: Map from local function name to ``_EventInfo`` for
                functions decorated with ``@event``.
            iterator_names: Set of locally imported names that resolve to
                ``IteratorType``, used during annotation resolution.
            findoptions_names: Set of locally imported names that refer to
                ``FindOptions`` constants (enables constant folding).
            callflags_names: Set of locally imported names that refer to
                ``CallFlags`` constants (enables constant folding).
            namedcurvehash_names: Set of locally imported names that refer to
                ``NamedCurveHash`` constants (enables constant folding).
            module_fn_maps: Map from module alias to a map of Python function
                name to mangled compiled name, used for cross-module calls.
            filename: Source file path included in ``TypecheckError`` messages.
        """
        self._signatures: dict[str, tuple[list[Type], Type]] = signatures or {}
        self._statics: dict[str, tuple[int, Type]] = statics or {}
        self._statics_current_types: dict[str, Type] = {
            k: t for k, (_, t) in (statics or {}).items()
        }
        self._func_defaults: dict[str, dict[int, "Expr"]] = func_defaults or {}
        self._class_registry: Optional[dict[str, "ClassInfo"]] = class_registry
        self._current_class: Optional[str] = current_class
        self._module_names: set[str] = module_names or set()
        self._aliases: dict[str, str] = aliases or {}
        self._module_fn_maps: dict[str, dict[str, str]] = module_fn_maps or {}
        # Maps local function name → _SyscallSpec for @syscall-decorated functions
        self._syscall_fn_specs: dict[str, "_SyscallSpec"] = syscall_fn_specs or {}
        # Maps module_alias → {fn_name → _SyscallSpec} for namespace imports
        self._syscall_module_fn_specs: dict[str, "dict[str, _SyscallSpec]"] = (
            syscall_module_fn_specs or {}
        )
        # Maps local function name → _EventInfo for @event-decorated functions
        self._event_fn_specs: dict[str, "_EventInfo"] = event_fn_specs or {}
        # Maps imported local name → IteratorType for type annotation resolution
        self._iterator_extra: dict[str, Type] = {
            n: ITERATOR for n in (iterator_names or set())
        }
        # Set of local names that refer to FindOptions (for constant folding)
        self._findoptions_names: set[str] = findoptions_names or set()
        # Set of local names that refer to CallFlags (for constant folding)
        self._callflags_names: set[str] = callflags_names or set()
        # Set of local names that refer to NamedCurveHash (for constant folding)
        self._namedcurvehash_names: set[str] = namedcurvehash_names or set()
        self._filename: Optional[str] = filename
        self._current_node: Optional[ast.AST] = None
        self._current_method_kind: str = "instance"
        self._cls_alias: Optional[str] = None  # name of 'cls' param in classmethods
        self._locals: dict[str, tuple[int, Type]] = {}
        self._args: dict[str, tuple[int, Type]] = {}
        # Tracks the type a local was *first declared* with (before any assert narrowing).
        # Used to undo narrowing leaking between if/elif branches.
        self._local_orig_types: dict[str, Type] = {}
        self._return_type: Optional[Type] = None
        self._in_loop: bool = False
        self._declared_globals: set[str] = set()
        self._pre_stmts: list[Stmt] = []
        # Maps mangled name → user-visible "mod.fn" label for error messages.
        self._name_display: dict[str, str] = {}

    def _err(self, msg: str) -> "Never":
        node = self._current_node
        lineno = getattr(node, "lineno", None)
        col = getattr(node, "col_offset", None)
        raise TypecheckError(
            msg, lineno=lineno, col_offset=col, filename=self._filename
        )

    def _alloc_temp(self, hint: str, t: Type) -> int:
        """Append a synthetic temp slot to the function's local table and return its index."""
        name = f"__tmp_{hint}_{len(self._locals)}__"
        slot = len(self._locals)
        self._locals[name] = (slot, t)
        return slot

    def _alloc_named_temp(self, hint: str, t: Type) -> tuple[str, int]:
        """Like _alloc_temp but also returns the generated name (for LocalLoad/LocalStore)."""
        name = f"__tmp_{hint}_{len(self._locals)}__"
        slot = len(self._locals)
        self._locals[name] = (slot, t)
        return name, slot

    def _desugar_list_insert(
        self, obj: "Expr", idx: "Expr", val: "Expr"
    ) -> "list[Stmt]":
        """Desugar lst.insert(idx, val) to a While-based shift-right loop.

        Algorithm:
          store lst/idx/val in temps; n = len(lst); lst.append(val); j = n
          while j > idx: lst[j] = lst[j-1]; j -= 1
          lst[idx] = val
        """
        assert isinstance(obj.type, ListType)
        elem_t = obj.type.elem

        name_lst, slot_lst = self._alloc_named_temp("ins_lst", obj.type)
        name_idx, slot_idx = self._alloc_named_temp("ins_idx", INT)
        name_val, slot_val = self._alloc_named_temp("ins_val", elem_t)
        name_n, slot_n = self._alloc_named_temp("ins_n", INT)
        name_j, slot_j = self._alloc_named_temp("ins_j", INT)

        lst_load = LocalLoad(name=name_lst, type=obj.type)
        idx_load = LocalLoad(name=name_idx, type=INT)
        val_load = LocalLoad(name=name_val, type=elem_t)
        n_load = LocalLoad(name=name_n, type=INT)
        j_load = LocalLoad(name=name_j, type=INT)

        return [
            LocalStore(name=name_lst, slot=slot_lst, value=obj, type=obj.type),
            LocalStore(name=name_idx, slot=slot_idx, value=idx, type=INT),
            LocalStore(name=name_val, slot=slot_val, value=val, type=elem_t),
            LocalStore(name=name_n, slot=slot_n, value=Len(lst_load), type=INT),
            ListAppend(container=lst_load, value=val_load),
            LocalStore(name=name_j, slot=slot_j, value=n_load, type=INT),
            While(
                condition=Compare(left=j_load, op=">", right=idx_load),
                body=[
                    ItemStore(
                        container=lst_load,
                        index=j_load,
                        value=Index(
                            value=lst_load,
                            index=BinOp(
                                left=j_load, op="-", right=IntLiteral(1), type=INT
                            ),
                            type=elem_t,
                        ),
                    ),
                    LocalStore(
                        name=name_j,
                        slot=slot_j,
                        value=BinOp(left=j_load, op="-", right=IntLiteral(1), type=INT),
                        type=INT,
                    ),
                ],
                else_body=[],
            ),
            ItemStore(container=lst_load, index=idx_load, value=val_load),
        ]

    def _display(self, name: str) -> str:
        return self._name_display.get(name, name)

    def _check_atoi_base(self, base_node: ast.expr) -> None:
        """Raise TypecheckError if base_node is a literal integer not equal to 10 or 16."""
        if isinstance(base_node, ast.Constant) and isinstance(base_node.value, int):
            if base_node.value not in (10, 16):
                self._err(f"base must be 10 or 16, got {base_node.value}")

    def _resolve_annotation(self, node: ast.expr) -> Type:
        # Substitute import aliases in type annotations (e.g. Container → Box)
        if self._aliases and isinstance(node, ast.Name) and node.id in self._aliases:
            node = ast.Name(id=self._aliases[node.id], ctx=ast.Load())
        return resolve_annotation(
            node,
            self._class_registry,
            extra_names=self._iterator_extra,
            filename=self._filename,
            module_fn_maps=self._module_fn_maps if self._module_fn_maps else None,
            module_names=self._module_names if self._module_names else None,
        )

    def _fn_self_name(self) -> str:
        """Return the name of the 'self' arg in the current instance method."""
        for name, (_, t) in self._args.items():
            if isinstance(t, ClassType):
                return name
        self._err("'super()' used outside an instance method")

    def build_method(self, node: ast.FunctionDef, kind: str) -> HIRFunction:
        """Compile a class method. kind: 'instance' | 'static' | 'class'."""
        self._current_method_kind = kind
        if node.returns is None:
            if not node.name.endswith("__init__"):
                self._err(
                    f"Method '{self._current_class}.{node.name}' missing return annotation"
                )
            self._return_type = NoneType()
        else:
            self._return_type = self._resolve_annotation(node.returns)

        raw_params = list(node.args.args)
        args: list[tuple[str, Type]] = []

        if kind == "instance":
            if not raw_params:
                self._err(
                    f"Instance method '{node.name}' must have 'self' as first parameter"
                )
            self_param = raw_params[0]
            self_type = ClassType(self._current_class)
            self._args[self_param.arg] = (0, self_type)
            args.append((self_param.arg, self_type))
            raw_params = raw_params[1:]
        elif kind == "class":
            if not raw_params:
                self._err(
                    f"Class method '{node.name}' must have 'cls' as first parameter"
                )
            self._cls_alias = raw_params[0].arg
            raw_params = raw_params[1:]
        # static: no implicit first parameter

        for arg in raw_params:
            if arg.annotation is None:
                self._err(f"Argument '{arg.arg}' missing annotation")
            t = self._resolve_annotation(arg.annotation)
            self._args[arg.arg] = (len(args), t)
            args.append((arg.arg, t))

        body = self._visit_stmts(node.body)

        compiled_name = f"{self._current_class}_{node.name}"
        return HIRFunction(
            name=compiled_name,
            args=args,
            return_type=self._return_type,
            locals=dict(self._locals),
            body=body,
        )

    def build(self, node: ast.FunctionDef) -> HIRFunction:
        if node.returns is None:
            self._err(f"Function '{node.name}' missing return annotation")
        self._return_type = self._resolve_annotation(node.returns)

        args = []
        for arg in node.args.args:
            if arg.annotation is None:
                self._err(f"Argument '{arg.arg}' missing annotation")
            t = self._resolve_annotation(arg.annotation)
            self._args[arg.arg] = (len(args), t)
            args.append((arg.arg, t))

        for stmt in node.body:
            if isinstance(stmt, ast.Global):
                for name in stmt.names:
                    if name not in self._statics:
                        self._err(
                            f"'global {name}': '{name}' is not declared as a module-level static field"
                        )
                    self._declared_globals.add(name)

        body = self._visit_stmts(node.body)

        return HIRFunction(
            name=node.name,
            args=args,
            return_type=self._return_type,
            locals=dict(self._locals),
            body=body,
        )

    def _resolve_aliases_in_stmt(self, node: "ast.stmt") -> "ast.stmt":
        """Rewrite import-alias names in a statement node before dispatch."""
        if (
            self._aliases
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in self._aliases
        ):
            orig = self._aliases[node.value.func.id]
            node = ast.Expr(
                value=ast.Call(
                    func=ast.Name(id=orig, ctx=ast.Load()),
                    args=node.value.args,
                    keywords=node.value.keywords,
                )
            )
        if (
            self._aliases
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id in self._aliases
        ):
            _resolved_cls = self._aliases[node.value.func.value.id]
            node = ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id=_resolved_cls, ctx=ast.Load()),
                        attr=node.value.func.attr,
                        ctx=node.value.func.ctx,
                    ),
                    args=node.value.args,
                    keywords=node.value.keywords,
                )
            )
        return node

    def _visit_if_stmt(self, node: "ast.If") -> "If":
        """Compile an ast.If node — includes Optional narrowing and join-point type merging."""
        cond = self._visit_expr(node.test)
        if cond.type != BOOL:
            self._err("if condition must be bool")

        snap_locals = dict(self._locals)
        snap_args = dict(self._args)
        snap_statics = dict(self._statics_current_types)
        then_terminates = _always_terminates(node.body)
        orelse_terminates = _always_terminates(node.orelse)

        none_check = self._extract_none_check(node.test)
        nc_var: Optional[str] = None
        is_none: bool = False
        if none_check is not None:
            nc_var, is_none = none_check
            _, nc_opt = (
                self._locals[nc_var] if nc_var in self._locals else self._args[nc_var]
            )
            assert isinstance(nc_opt, OptionalType)
            nc_inner = nc_opt.inner
            if not is_none:
                self._set_local_type(nc_var, nc_inner)

        then_body = self._visit_stmts(node.body)
        post_then_locals = dict(self._locals)
        post_then_args = dict(self._args)
        post_then_statics = dict(self._statics_current_types)

        self._restore_types(snap_locals, snap_args, snap_statics)

        if nc_var is not None and is_none:
            self._set_local_type(nc_var, nc_inner)

        else_body = self._visit_stmts(node.orelse)
        post_orelse_locals = dict(self._locals)
        post_orelse_args = dict(self._args)
        post_orelse_statics = dict(self._statics_current_types)

        self._join_types(
            post_then_locals,
            post_then_args,
            post_orelse_locals,
            post_orelse_args,
            snap_locals,
            snap_args,
            then_terminates,
            orelse_terminates,
            snap_statics,
            post_then_statics,
            post_orelse_statics,
        )

        return If(condition=cond, then_body=then_body, else_body=else_body)

    def _visit_while_stmt(self, node: "ast.While") -> "While":
        """Compile an ast.While node — includes Optional narrowing and loop context save/restore."""
        cond = self._visit_expr(node.test)
        if cond.type != BOOL:
            self._err("while condition must be bool")
        prev_in_loop = self._in_loop
        self._in_loop = True
        snap_locals_w = dict(self._locals)
        snap_args_w = dict(self._args)
        snap_statics_w = dict(self._statics_current_types)
        nc = self._extract_none_check(node.test)
        if nc is not None and not nc[1]:
            varname, _ = nc
            _, opt_t = (
                self._locals[varname]
                if varname in self._locals
                else self._args[varname]
            )
            self._set_local_type(varname, opt_t.inner)
        body_stmts = self._visit_stmts(node.body)
        self._restore_types(snap_locals_w, snap_args_w, snap_statics_w)
        else_stmts = self._visit_stmts(node.orelse)
        self._in_loop = prev_in_loop
        return While(condition=cond, body=body_stmts, else_body=else_stmts)

    def _visit_try_stmt(self, node: "ast.Try") -> "TryExcept":
        """Compile an ast.Try node — validates constraints and visits all sub-bodies."""
        if node.orelse:
            self._err("try/else is not supported")
        if len(node.handlers) > 1:
            self._err("only one except clause is supported")

        snap_locals_t = dict(self._locals)
        snap_args_t = dict(self._args)
        snap_statics_t = dict(self._statics_current_types)

        try_body_hir = self._visit_stmts(node.body)

        catch_body: Optional[list[Stmt]] = None
        handler_var: Optional[str] = None
        handler_var_slot: Optional[int] = None

        if node.handlers:
            h = node.handlers[0]
            if h.type is not None:
                self._err(
                    "typed 'except SomeType:' is not supported: NeoVM has no exception "
                    "type system, so exception type filtering is impossible at runtime. "
                    "Use bare 'except:' instead."
                )
            self._restore_types(snap_locals_t, snap_args_t, snap_statics_t)
            if h.name is not None:
                handler_var = h.name
                handler_var_slot = len(self._locals)
                self._locals[h.name] = (handler_var_slot, STR)
            catch_body = self._visit_stmts(h.body)

        finally_body: Optional[list[Stmt]] = None
        if node.finalbody:
            self._restore_types(snap_locals_t, snap_args_t, snap_statics_t)
            finally_body = self._visit_stmts(node.finalbody)

        if catch_body is None and finally_body is None:
            self._err("try requires at least one except or finally clause")

        return TryExcept(
            try_body=try_body_hir,
            catch_body=catch_body,
            finally_body=finally_body,
            handler_var=handler_var,
            handler_var_slot=handler_var_slot,
        )

    def _visit_stmt(self, node: ast.stmt) -> Stmt:
        self._current_node = node
        node = self._resolve_aliases_in_stmt(node)

        match node:
            case ast.AnnAssign(target=ast.Name(id=name), annotation=ann, value=val):
                return self._handle_annassign(name, ann, val)

            case ast.Assign(targets=[ast.Name(id=name)], value=val):
                return self._handle_assign_name(name, val)

            case ast.AugAssign(target=ast.Name(id=name), op=op, value=val):
                return self._handle_augassign(name, op, val)

            case ast.Return(value=val):
                if val is None:
                    if self._return_type != NONE:
                        self._err("bare 'return' not supported in non-void functions")
                    return Return(value=NoneLiteral(), type=NONE)
                expr = self._visit_expr(val)
                if not _type_compatible(
                    expr.type, self._return_type, self._class_registry
                ):
                    self._err(
                        f"Return type mismatch: expected {self._return_type}, got {expr.type}"
                    )
                return Return(value=expr, type=expr.type)

            case ast.If():
                return self._visit_if_stmt(node)

            case ast.While():
                return self._visit_while_stmt(node)

            case ast.Break():
                if not self._in_loop:
                    self._err("'break' outside loop")
                return Break()

            case ast.Continue():
                if not self._in_loop:
                    self._err("'continue' outside loop")
                return Continue()

            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=obj_node, attr="append"),
                    args=[arg_node],
                    keywords=[],
                )
            ):
                obj = self._visit_expr(obj_node)
                if not isinstance(obj.type, ListType):
                    self._err(".append() only supported on list[T]")
                arg = self._visit_expr(arg_node)
                if not _type_compatible(arg.type, obj.type.elem, self._class_registry):
                    self._err(
                        f".append() type mismatch: expected {obj.type.elem}, got {arg.type}"
                    )
                return ListAppend(container=obj, value=arg)

            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=obj_node, attr="insert"),
                    args=[idx_node, val_node],
                    keywords=[],
                )
            ):
                obj = self._visit_expr(obj_node)
                if not isinstance(obj.type, ListType):
                    self._err(".insert() only supported on list[T]")
                idx = self._visit_expr(idx_node)
                if not isinstance(idx.type, IntType):
                    self._err(".insert() index must be int")
                val = self._visit_expr(val_node)
                if not _type_compatible(val.type, obj.type.elem, self._class_registry):
                    self._err(
                        f".insert() type mismatch: expected {obj.type.elem}, got {val.type}"
                    )
                self._pre_stmts.extend(self._desugar_list_insert(obj, idx, val))
                return None

            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=obj_node, attr="reverse"),
                    args=[],
                    keywords=[],
                )
            ):
                obj = self._visit_expr(obj_node)
                if not isinstance(obj.type, (BytearrayType, ListType)):
                    self._err(".reverse() only supported on bytearray and list[T]")
                return ReverseItems(container=obj)

            case ast.Assign(targets=[ast.Tuple(elts=tgt_nodes)], value=val_node):
                rhs = self._visit_expr(val_node)
                if not isinstance(rhs.type, TupleType):
                    self._err("can only unpack a tuple expression")
                if len(tgt_nodes) != len(rhs.type.elements):
                    self._err(
                        f"unpack mismatch: {len(tgt_nodes)} targets vs "
                        f"{len(rhs.type.elements)} elements in {rhs.type}"
                    )
                tgts = []
                for tgt_node, elem_t in zip(tgt_nodes, rhs.type.elements):
                    if not isinstance(tgt_node, ast.Name):
                        self._err("tuple unpack targets must be simple names")
                    name = tgt_node.id
                    if name in self._args:
                        slot, declared_t = self._args[name]
                        if not _type_compatible(
                            elem_t, declared_t, self._class_registry
                        ):
                            self._err(
                                f"unpack type mismatch: '{name}' declared as {declared_t}, got {elem_t}"
                            )
                        tgts.append((slot, True, declared_t))
                    elif name in self._locals:
                        slot, declared_t = self._locals[name]
                        if not _type_compatible(
                            elem_t, declared_t, self._class_registry
                        ):
                            self._err(
                                f"unpack type mismatch: '{name}' declared as {declared_t}, got {elem_t}"
                            )
                        tgts.append((slot, False, declared_t))
                    else:
                        # First assignment — infer type from tuple element
                        slot = len(self._locals)
                        self._locals[name] = (slot, elem_t)
                        tgts.append((slot, False, elem_t))
                return TupleUnpack(source=rhs, targets=tgts)

            case ast.Assign(
                targets=[ast.Subscript(value=ctr_node, slice=idx_node)], value=val_node
            ):
                container = self._visit_expr(ctr_node)
                if isinstance(container.type, DictType):
                    key = self._visit_expr(idx_node)
                    if not _type_compatible(
                        key.type, container.type.key, self._class_registry
                    ):
                        self._err(
                            f"dict key type mismatch: expected {container.type.key}, got {key.type}"
                        )
                    value = self._visit_expr(val_node)
                    if not _type_compatible(
                        value.type, container.type.val, self._class_registry
                    ):
                        self._err(
                            f"dict value type mismatch: expected {container.type.val}, got {value.type}"
                        )
                    return ItemStore(container=container, index=key, value=value)
                elif isinstance(container.type, ListType):
                    index = self._visit_expr(idx_node)
                    if not isinstance(index.type, IntType):
                        self._err("list index must be int")
                    value = self._visit_expr(val_node)
                    if not _type_compatible(
                        value.type, container.type.elem, self._class_registry
                    ):
                        self._err(
                            f"cannot assign {value.type} to list[{container.type.elem}]"
                        )
                    return ItemStore(container=container, index=index, value=value)
                elif isinstance(container.type, BytearrayType):
                    index = self._visit_expr(idx_node)
                    if not isinstance(index.type, IntType):
                        self._err("bytearray index must be int")
                    value = self._visit_expr(val_node)
                    if not isinstance(value.type, IntType):
                        self._err("bytearray element must be int")
                    return ItemStore(container=container, index=index, value=value)
                elif isinstance(container.type, TupleType):
                    self._err("tuples are immutable; element assignment not allowed")
                else:
                    self._err(
                        "subscript assignment only supported for list[T], dict[K,V], or bytearray"
                    )

            case ast.Expr(
                value=ast.Call(func=ast.Name(id="print"), args=print_args, keywords=[])
            ):
                if len(print_args) != 1:
                    self._err(
                        f"print() takes exactly 1 argument ({len(print_args)} given)"
                    )
                msg = self._visit_expr(print_args[0])
                if isinstance(msg.type, ListType):
                    return PrintListStmt(
                        list_expr=msg,
                        temp_slot=self._alloc_temp("print_list", msg.type),
                    )
                elif msg.type in (STR, BYTES):
                    return PrintStmt(msg=msg)
                else:
                    self._err(
                        f"print() argument must be str, bytes, or list, got {msg.type}"
                    )

            case ast.Expr(
                value=ast.Call(func=ast.Name(id="abort"), args=abort_args, keywords=[])
            ):
                if len(abort_args) == 0:
                    return AbortStmt(msg=None)
                elif len(abort_args) == 1:
                    msg = self._visit_expr(abort_args[0])
                    if msg.type != STR:
                        self._err(f"abort() message must be str, got {msg.type}")
                    return AbortStmt(msg=msg)
                else:
                    self._err(
                        f"abort() takes 0 or 1 arguments ({len(abort_args)} given)"
                    )

            case ast.Expr(
                value=ast.Call(
                    func=ast.Name(id="call_contract"), args=cc_args, keywords=[]
                )
            ):
                # call_contract() used as a statement — result is discarded (DROP in CFGBuilder).
                return self._build_call_contract(cc_args, is_stmt=True)

            case ast.Expr(
                value=ast.Call(func=ast.Name(id=name), args=call_args, keywords=[])
            ) if (name in self._event_fn_specs):
                info = self._event_fn_specs[name]
                if len(call_args) != len(info.params):
                    self._err(
                        f"'{name}' event takes {len(info.params)} args, got {len(call_args)}"
                    )
                visited_ev: list[Expr] = []
                for i, (call_arg, (_, expected_type)) in enumerate(
                    zip(call_args, info.params)
                ):
                    a = self._visit_expr(call_arg)
                    if not _type_compatible(
                        a.type, expected_type, self._class_registry
                    ):
                        self._err(
                            f"Arg {i} of event '{name}': expected {expected_type}, got {a.type}"
                        )
                    visited_ev.append(a)
                return NotifyCall(event_name=info.event_name, args=visited_ev)

            case ast.Expr(
                value=ast.Call(
                    func=ast.Name(id=name), args=call_args, keywords=call_kwargs
                )
            ) if (name in self._syscall_fn_specs):
                spec = self._syscall_fn_specs[name]
                if spec.ret != NONE:
                    self._err(
                        f"'{name}()' returns {spec.ret} and cannot be used as a statement; "
                        "assign the result"
                    )
                return self._build_syscall_from_spec(
                    name, spec, call_args, call_kwargs, is_stmt=True
                )

            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=mod_name), attr=fn_name),
                    args=call_args,
                    keywords=call_kwargs,
                )
            ) if (
                mod_name in self._syscall_module_fn_specs
                and fn_name in self._syscall_module_fn_specs[mod_name]
            ):
                spec = self._syscall_module_fn_specs[mod_name][fn_name]
                if spec.ret != NONE:
                    self._err(
                        f"'{mod_name}.{fn_name}()' returns {spec.ret} and cannot be used "
                        "as a statement; assign the result"
                    )
                return self._build_syscall_from_spec(
                    fn_name, spec, call_args, call_kwargs, is_stmt=True
                )

            case ast.Expr(
                value=ast.Call(func=ast.Name(id=name), args=call_args, keywords=[])
            ):
                if name not in self._signatures:
                    self._err(f"Unknown function '{self._display(name)}'")
                param_types, return_type = self._signatures[name]
                defaults = self._func_defaults.get(name, {})
                num_required = len(param_types) - len(defaults)
                if len(call_args) < num_required:
                    self._err(
                        f"'{self._display(name)}' requires at least {num_required} args, got {len(call_args)}"
                    )
                if len(call_args) > len(param_types):
                    self._err(
                        f"'{self._display(name)}' takes at most {len(param_types)} args, got {len(call_args)}"
                    )
                visited: list[Expr] = []
                for i, expected in enumerate(param_types):
                    if i < len(call_args):
                        arg = self._visit_expr(call_args[i])
                    else:
                        arg = defaults[i]
                    if not _type_compatible(arg.type, expected, self._class_registry):
                        self._err(
                            f"Arg {i} of '{self._display(name)}': expected {expected}, got {arg.type}"
                        )
                    visited.append(arg)
                return CallStmt(name=name, args=visited, return_type=return_type)

            case ast.Assert(test=test, msg=msg):
                cond = self._visit_expr(test)
                if cond.type != BOOL:
                    self._err("assert condition must be bool")
                message: Optional[Expr] = None
                if msg is not None:
                    message = self._visit_expr(msg)
                    if message.type != STR:
                        self._err("assert message must be str")
                return Assert(condition=cond, message=message)

            case ast.Raise(exc=exc):
                if exc is None:
                    self._err("bare 'raise' (re-raise) is not supported")
                message: Optional[Expr] = None
                if isinstance(exc, ast.Call) and exc.args:
                    msg_expr = self._visit_expr(exc.args[0])
                    if msg_expr.type != STR:
                        self._err("raise message must be str")
                    message = msg_expr
                return Raise(message=message)

            case ast.Try():
                return self._visit_try_stmt(node)

            # --- Class field assignment: self.field: Type = value ---
            case ast.AnnAssign(
                target=ast.Attribute(value=obj_node, attr=fname),
                annotation=ann,
                value=val,
            ):
                return self._handle_field_annassign(obj_node, fname, ann, val)

            # --- Class field assignment: self.field = value ---
            case ast.Assign(
                targets=[ast.Attribute(value=obj_node, attr=fname)], value=val
            ):
                return self._handle_field_assign(obj_node, fname, val)

            # --- Class variable assignment: ClassName.var = value ---
            case ast.Assign(
                targets=[ast.Attribute(value=ast.Name(id=cname), attr=cvar)], value=val
            ) if (self._class_registry and cname in self._class_registry):
                return self._handle_classvar_assign(cname, cvar, val)

            # --- super().method(args) as statement ---
            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(func=ast.Name(id="super"), args=[]),
                        attr=meth_name,
                    ),
                    args=call_args,
                    keywords=[],
                )
            ) if (
                self._current_class and self._class_registry
            ):
                info = self._class_registry[self._current_class]
                if not info.class_mro:
                    self._err(
                        f"super() called in '{self._current_class}' which has no base class"
                    )
                parent_name = info.class_mro[0]
                parent_info = self._class_registry[parent_name]
                if meth_name not in parent_info.methods:
                    self._err(
                        f"super() has no method '{meth_name}' in parent '{parent_name}'"
                    )
                mi = parent_info.methods[meth_name]
                compiled_name = mi.compiled_name
                param_types, return_type = self._signatures[compiled_name]
                user_param_types = (
                    param_types[1:] if mi.kind == "instance" else param_types
                )
                if len(call_args) != len(user_param_types):
                    self._err(
                        f"super().{meth_name} takes {len(user_param_types)} args, got {len(call_args)}"
                    )
                visited_s: list[Expr] = []
                for i, (a_node, expected) in enumerate(
                    zip(call_args, user_param_types)
                ):
                    a = self._visit_expr(a_node)
                    if not _type_compatible(a.type, expected, self._class_registry):
                        self._err(
                            f"Arg {i} of 'super().{meth_name}': expected {expected}, got {a.type}"
                        )
                    visited_s.append(a)
                self_arg_name = self._fn_self_name()
                self_expr = LocalLoad(
                    name=self_arg_name, type=ClassType(self._current_class)
                )
                return MethodCallStmt(
                    obj=self_expr, compiled_name=compiled_name, args=visited_s
                )

            # --- Module void call as statement: abc.foo(args) ---
            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=mod_name), attr=fn_name),
                    args=call_args,
                    keywords=[],
                )
            ) if (
                self._module_names
                and mod_name in self._module_names
                and mod_name not in self._locals
                and mod_name not in self._args
                and mod_name not in self._statics
            ):
                _actual_fn = self._module_fn_maps.get(mod_name, {}).get(
                    fn_name, fn_name
                )
                self._name_display[_actual_fn] = f"{mod_name}.{fn_name}"
                new_expr = ast.Expr(
                    value=ast.Call(
                        func=ast.Name(id=_actual_fn, ctx=ast.Load()),
                        args=call_args,
                        keywords=[],
                    )
                )
                ast.copy_location(new_expr, node)
                return self._visit_stmt(new_expr)

            # --- Iterator method calls as statements — always errors (non-void return) ---
            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=obj_node, attr=meth_name),
                    args=[],
                    keywords=[],
                )
            ) if meth_name in ("next", "value"):
                obj = self._visit_expr(obj_node)
                if isinstance(obj.type, IteratorType):
                    self._err(
                        f"Iterator.{meth_name}() returns a value and cannot be used as a "
                        "statement; use it in a while condition or assign the result"
                    )

            # --- @contract class method call as statement (ClassName.method(args)) ---
            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=cname), attr=meth_name),
                    args=call_args,
                    keywords=[],
                )
            ) if (
                self._class_registry
                and cname in self._class_registry
                and self._class_registry[cname].contract_hash is not None
            ):
                # Reuse the expression dispatch (handles default injection, type-checking).
                cc = self._visit_expr(node.value)
                return dataclasses.replace(cc, is_stmt=True)

            # --- Non-@contract class static/classmethod call as statement ---
            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=cname), attr=meth_name),
                    args=call_args,
                    keywords=[],
                )
            ) if (
                self._class_registry
                and cname in self._class_registry
                and self._class_registry[cname].contract_hash is None
            ):
                info = self._class_registry[cname]
                if meth_name not in info.methods:
                    self._err(f"Unknown method '{meth_name}' on class '{cname}'")
                if info.methods[meth_name].kind == "instance":
                    self._err(
                        f"Cannot call instance method '{cname}.{meth_name}' without an instance"
                    )
                # Reuse expression dispatch — handles default injection and type-checking.
                call_expr = self._visit_expr(node.value)
                if not isinstance(call_expr, Call):
                    self._err(
                        f"Internal error: expected Call for '{cname}.{meth_name}'"
                    )
                return CallStmt(
                    name=call_expr.name, args=call_expr.args, return_type=call_expr.type
                )

            # --- Method call as statement ---
            case ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(value=obj_node, attr=meth_name),
                    args=call_args,
                    keywords=[],
                )
            ) if not (
                # don't intercept list mutator methods — handled above
                meth_name
                in ("append", "insert")
            ):
                obj = self._visit_expr(obj_node)
                if not isinstance(obj.type, ClassType) or self._class_registry is None:
                    self._err(
                        f"Method calls only supported on class instances; got {obj.type}"
                    )
                info = self._class_registry[obj.type.name]
                if meth_name not in info.methods:
                    self._err(
                        f"Unknown method '{meth_name}' on class '{obj.type.name}'"
                    )
                mi = info.methods[meth_name]
                compiled_name = mi.compiled_name
                param_types, return_type = self._signatures[compiled_name]
                # param_types includes 'self' at index 0 for instance methods
                user_param_types = (
                    param_types[1:] if mi.kind == "instance" else param_types
                )
                if len(call_args) != len(user_param_types):
                    self._err(
                        f"'{meth_name}' takes {len(user_param_types)} args, got {len(call_args)}"
                    )
                visited: list[Expr] = []
                for i, (a_node, expected) in enumerate(
                    zip(call_args, user_param_types)
                ):
                    a = self._visit_expr(a_node)
                    if not _type_compatible(a.type, expected, self._class_registry):
                        self._err(
                            f"Arg {i} of '{meth_name}': expected {expected}, got {a.type}"
                        )
                    visited.append(a)
                return MethodCallStmt(
                    obj=obj,
                    compiled_name=compiled_name,
                    args=visited,
                    return_type=return_type,
                )

            case ast.Expr(value=ast.Constant(value=str())):
                return None  # docstring or bare string expression — silently ignored

            case ast.Global():
                return None  # already processed in pre-scan; no HIR statement emitted
            case ast.Pass():
                return None  # no-op
            case ast.FunctionDef():
                self._err("nested function definitions are not supported")
            case ast.ClassDef():
                self._err("nested class definitions are not supported")
            case _:
                self._err(f"Unsupported statement: {ast.dump(node)}")

    def _build_syscall(
        self,
        module: str,
        func: str,
        spec: "_SyscallSpec",
        call_args: list[ast.expr],
        is_stmt: bool = False,
    ) -> "SyscallCall":
        """Typecheck args against spec and return a SyscallCall HIR node."""
        n_expected = len(spec.params)
        n_got = len(call_args)
        if n_got < n_expected:
            if spec.defaults is None:
                self._err(
                    f"{module}.{func}() takes {n_expected} argument(s) ({n_got} given)"
                )
            filled = list(call_args)
            for i in range(n_got, n_expected):
                if i not in spec.defaults:
                    self._err(f"{module}.{func}() missing required argument {i + 1}")
                filled.append(ast.Constant(value=spec.defaults[i]))
            call_args = filled
        elif n_got > n_expected:
            self._err(
                f"{module}.{func}() takes {n_expected} argument(s) ({n_got} given)"
            )
        visited: list = []
        for i, (arg_node, expected_type) in enumerate(zip(call_args, spec.params)):
            arg = self._visit_expr(arg_node)
            if not _type_compatible(arg.type, expected_type, self._class_registry):
                self._err(
                    f"{module}.{func}() argument {i + 1} must be "
                    f"{expected_type}, got {arg.type}"
                )
            visited.append(arg)
        return SyscallCall(
            hash=spec.hash,
            args=visited,
            push_order=list(spec.push_order),
            type=spec.ret,
            is_stmt=is_stmt,
        )

    def _build_syscall_from_spec(
        self,
        name: str,
        spec: "_SyscallSpec",
        call_args: list[ast.expr],
        kwargs: Optional[list[ast.keyword]] = None,
        is_stmt: bool = False,
    ) -> "SyscallCall":
        """Build a SyscallCall from a _SyscallSpec, injecting any registered defaults.

        Keyword arguments are resolved to positional indices via spec.param_names.
        """
        n_expected = len(spec.params)

        # Merge keyword args into a mutable positional slots list (None = unfilled).
        slots: list[Optional[ast.expr]] = list(call_args) + [None] * (
            n_expected - len(call_args)
        )
        if len(call_args) > n_expected:
            self._err(
                f"'{name}()' takes {n_expected} argument(s) ({len(call_args)} given)"
            )
        for kw in kwargs or []:
            if kw.arg is None:
                self._err(f"'{name}()' does not accept **kwargs")
            if kw.arg not in spec.param_names:
                self._err(f"'{name}()' has no parameter '{kw.arg}'")
            idx = spec.param_names.index(kw.arg)
            if slots[idx] is not None:
                self._err(f"'{name}()' got multiple values for argument '{kw.arg}'")
            slots[idx] = kw.value

        # Fill remaining None slots from registered defaults.
        for i, slot in enumerate(slots):
            if slot is None:
                if spec.defaults is None or i not in spec.defaults:
                    pname = (
                        spec.param_names[i] if i < len(spec.param_names) else str(i + 1)
                    )
                    self._err(f"'{name}()' missing required argument '{pname}'")
                slots[i] = ast.Constant(value=spec.defaults[i])

        visited: list = []
        for i, (arg_node, expected_type) in enumerate(zip(slots, spec.params)):
            arg = self._visit_expr(arg_node)
            if not _type_compatible(arg.type, expected_type, self._class_registry):
                self._err(
                    f"'{name}()' argument {i + 1}: expected {expected_type}, got {arg.type}"
                )
            visited.append(arg)
        return SyscallCall(
            hash=spec.hash,
            args=visited,
            push_order=list(spec.push_order),
            type=spec.ret,
            is_stmt=is_stmt,
        )

    def _build_call_contract(
        self, pos_args: list[ast.expr], is_stmt: bool = False
    ) -> "DynamicContractCall":
        """Validate and build a DynamicContractCall node for the call_contract() intrinsic."""
        n = len(pos_args)
        if n < 2 or n > 4:
            self._err(f"call_contract() takes 2 to 4 arguments ({n} given)")
        sh = self._visit_expr(pos_args[0])
        if not isinstance(sh.type, (UInt160Type, AnyType)):
            self._err(
                f"call_contract() arg 1 (script_hash) must be UInt160, got {sh.type}"
            )
        m = self._visit_expr(pos_args[1])
        if m.type not in (STR, ANY):
            self._err(f"call_contract() arg 2 (method) must be str, got {m.type}")
        if n >= 3:
            a: Expr = self._visit_expr(pos_args[2])
            if not isinstance(a.type, (ListType, AnyType)):
                self._err(f"call_contract() arg 3 (args) must be list, got {a.type}")
        else:
            a = ListLiteral([], type=ListType(ANY))
        if n >= 4:
            cf: Expr = self._visit_expr(pos_args[3])
            if cf.type not in (INT, ANY):
                self._err(
                    f"call_contract() arg 4 (call_flags) must be int, got {cf.type}"
                )
        else:
            cf = IntLiteral(15)  # CallFlags.ALL
        return DynamicContractCall(
            script_hash=sh, method=m, args=a, call_flags=cf, type=ANY, is_stmt=is_stmt
        )

    def _extract_none_check(self, test: ast.expr) -> Optional[tuple[str, bool]]:
        """If test is `x is None` / `x is not None` on a local Optional variable,
        return (varname, is_none) where is_none=True for 'is None', False for 'is not None'.
        Returns None if the pattern doesn't match."""
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value is None
            and isinstance(test.left, ast.Name)
        ):
            return None
        name = test.left.id
        if name not in self._locals and name not in self._args:
            return None
        _, t = self._locals[name] if name in self._locals else self._args[name]
        if not isinstance(t, OptionalType):
            return None
        if isinstance(test.ops[0], ast.Is):
            return (name, True)  # is None
        if isinstance(test.ops[0], ast.IsNot):
            return (name, False)  # is not None
        return None

    def _set_local_type(self, name: str, new_type: Type) -> Type:
        """Temporarily update the type of a local/arg; return the old type for restoration."""
        if name in self._locals:
            slot, old = self._locals[name]
            self._locals[name] = (slot, new_type)
            return old
        slot, old = self._args[name]
        self._args[name] = (slot, new_type)
        return old

    def _restore_types(
        self,
        snap_locals: dict[str, tuple[int, "Type"]],
        snap_args: dict[str, tuple[int, "Type"]],
        snap_statics: dict[str, "Type"],
    ) -> None:
        """Restore type state to a snapshot, keeping slots but undoing narrowing.

        Variables that existed before the snapshot have their types reset.
        Variables declared after the snapshot (new slots) are kept but their
        types are reset to _local_orig_types (the type at first declaration,
        before any assert-narrowing).
        """
        for k, (s, cur_t) in list(self._locals.items()):
            if k in snap_locals:
                self._locals[k] = (s, snap_locals[k][1])
            else:
                self._locals[k] = (s, self._local_orig_types.get(k, cur_t))
        self._args = dict(snap_args)
        self._statics_current_types = dict(snap_statics)

    def _join_types(
        self,
        post_then_locals: dict[str, tuple[int, "Type"]],
        post_then_args: dict[str, tuple[int, "Type"]],
        post_orelse_locals: dict[str, tuple[int, "Type"]],
        post_orelse_args: dict[str, tuple[int, "Type"]],
        snap_locals: dict[str, tuple[int, "Type"]],
        snap_args: dict[str, tuple[int, "Type"]],
        then_terminates: bool,
        orelse_terminates: bool,
        snap_statics: dict[str, "Type"],
        post_then_statics: dict[str, "Type"],
        post_orelse_statics: dict[str, "Type"],
    ) -> None:
        """Apply join-point narrowing after an if/elif/else.

        Rules for each variable present in both branches:
        - Both branches agree on type T → use T.
        - Then-branch always terminates → use orelse type.
        - Orelse always terminates → use then type.
        - Neither terminates, types differ → revert to the pre-if type from
          snap_locals (conservative: we can't know which branch ran).
        """
        for k in set(post_then_locals) & set(post_orelse_locals):
            s = self._locals.get(k, post_orelse_locals[k])[0]
            then_t = post_then_locals[k][1]
            orelse_t = post_orelse_locals[k][1]
            if then_t == orelse_t:
                self._locals[k] = (s, then_t)
            elif then_terminates and not orelse_terminates:
                self._locals[k] = (s, orelse_t)
            elif orelse_terminates and not then_terminates:
                self._locals[k] = (s, then_t)
            elif k in snap_locals:
                self._locals[k] = (s, snap_locals[k][1])
        for k in set(post_then_args) & set(post_orelse_args):
            s = self._args[k][0]
            then_t = post_then_args[k][1]
            orelse_t = post_orelse_args[k][1]
            if then_t == orelse_t:
                self._args[k] = (s, then_t)
            elif then_terminates and not orelse_terminates:
                self._args[k] = (s, orelse_t)
            elif orelse_terminates and not then_terminates:
                self._args[k] = (s, then_t)
            elif k in snap_args:
                self._args[k] = (s, snap_args[k][1])
        for k in set(post_then_statics) & set(post_orelse_statics):
            then_t = post_then_statics[k]
            orelse_t = post_orelse_statics[k]
            if then_t == orelse_t:
                self._statics_current_types[k] = then_t
            elif then_terminates and not orelse_terminates:
                self._statics_current_types[k] = orelse_t
            elif orelse_terminates and not then_terminates:
                self._statics_current_types[k] = then_t
            elif k in snap_statics:
                self._statics_current_types[k] = snap_statics[k]

    def _check_narrowing_guard(self, node: ast.If) -> Optional[tuple[str, Type]]:
        """Detect guard patterns 'if x is None: <always terminates>' (no else).
        Returns (varname, narrowed_type) so subsequent code can treat x as the unwrapped type.
        """
        if node.orelse:
            return None
        if not _always_terminates(node.body):
            return None
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value is None
            and isinstance(test.left, ast.Name)
        ):
            return None
        name = test.left.id
        if name not in self._locals and name not in self._args:
            return None
        _, t = self._locals[name] if name in self._locals else self._args[name]
        if not isinstance(t, OptionalType):
            return None
        if isinstance(test.ops[0], ast.Is):
            # if x is None: <terminates> → after this x is definitely not None
            return (name, t.inner)
        if isinstance(test.ops[0], ast.IsNot):
            # if x is not None: <terminates> → after this x is definitely None
            return (name, NONE)
        return None

    def _visit_stmts(self, stmts: list) -> list[Stmt]:
        result: list[Stmt] = []
        for s in stmts:
            assert not self._pre_stmts, (
                f"_pre_stmts not drained before processing {ast.dump(s)!r:.120}; "
                "a prior _visit_expr call leaked setup statements"
            )
            if isinstance(s, ast.For):
                for_stmts = self._visit_for(s)
                if self._pre_stmts:
                    result.extend(self._pre_stmts)
                    self._pre_stmts = []
                result.extend(for_stmts)
            else:
                stmt = self._visit_stmt(s)
                if self._pre_stmts:
                    result.extend(self._pre_stmts)
                    self._pre_stmts = []
                if stmt is not None:
                    result.append(stmt)
            # Apply Optional type narrowing after guard clauses
            if isinstance(s, ast.If):
                narrowing = self._check_narrowing_guard(s)
                if narrowing is not None:
                    name, new_type = narrowing
                    if name in self._locals:
                        slot, _ = self._locals[name]
                        self._locals[name] = (slot, new_type)
                    elif name in self._args:
                        slot, _ = self._args[name]
                        self._args[name] = (slot, new_type)
            # `assert x is not None` / `assert x is None` narrows for subsequent stmts
            elif isinstance(s, ast.Assert):
                nc = self._extract_none_check(s.test)
                if nc is not None:
                    varname, is_none = nc
                    if varname in self._locals:
                        slot, opt_t = self._locals[varname]
                        self._locals[varname] = (
                            slot,
                            opt_t.inner if not is_none else NONE,
                        )
                    elif varname in self._args:
                        slot, opt_t = self._args[varname]
                        self._args[varname] = (
                            slot,
                            opt_t.inner if not is_none else NONE,
                        )
        return result

    def _visit_for(self, node: ast.For) -> list[Stmt]:
        # Tuple target: supported with enumerate() or dict.items()
        if isinstance(node.target, ast.Tuple):
            elts = node.target.elts
            if len(elts) != 2 or not all(isinstance(e, ast.Name) for e in elts):
                self._err(
                    "for loop tuple target must be exactly two simple variable names"
                )
            k_var, v_var = elts[0].id, elts[1].id
            if (
                isinstance(node.iter, ast.Call)
                and isinstance(node.iter.func, ast.Name)
                and node.iter.func.id == "enumerate"
            ):
                return self._desugar_for_enumerate(node, k_var, v_var)
            if not (
                isinstance(node.iter, ast.Call)
                and isinstance(node.iter.func, ast.Attribute)
                and node.iter.func.attr == "items"
                and not node.iter.args
            ):
                self._err(
                    "for loop with tuple target only supported with dict.items() or enumerate()"
                )
            dict_expr = self._visit_expr(node.iter.func.value)
            if not isinstance(dict_expr.type, DictType):
                self._err(".items() only supported on dict[K,V]")
            return self._desugar_for_dict_items(node, k_var, v_var, dict_expr)

        if not isinstance(node.target, ast.Name):
            self._err("for loop target must be a simple variable")
        var = node.target.id

        # Check for list[T] or Iterator iteration (including d.keys() / d.values())
        if not (
            isinstance(node.iter, ast.Call)
            and isinstance(node.iter.func, ast.Name)
            and node.iter.func.id == "range"
        ):
            iter_expr = self._visit_expr(node.iter)
            if isinstance(iter_expr.type, IteratorType):
                return self._desugar_for_iterator(node, var, iter_expr)
            if not isinstance(iter_expr.type, ListType):
                self._err(
                    "for loop only supports range(), list[T], d.keys(), d.values(), or Iterator"
                )
            return self._desugar_for_list(node, var, iter_expr)

        range_args = node.iter.args
        if len(range_args) == 1:
            start_node: Optional[ast.expr] = None
            stop_node = range_args[0]
            step_val = 1
        elif len(range_args) == 2:
            start_node = range_args[0]
            stop_node = range_args[1]
            step_val = 1
        elif len(range_args) == 3:
            start_node = range_args[0]
            stop_node = range_args[1]
            step_node = range_args[2]
            if isinstance(step_node, ast.Constant) and isinstance(step_node.value, int):
                step_val = step_node.value
            elif (
                isinstance(step_node, ast.UnaryOp)
                and isinstance(step_node.op, ast.USub)
                and isinstance(step_node.operand, ast.Constant)
                and isinstance(step_node.operand.value, int)
            ):
                step_val = -step_node.operand.value
            else:
                self._err("range() step must be an integer literal")
            if step_val == 0:
                self._err("range() step cannot be zero")
        else:
            self._err("range() requires 1 to 3 arguments")

        start_expr: Expr = (
            IntLiteral(value=0) if start_node is None else self._visit_expr(start_node)
        )
        stop_expr = self._visit_expr(stop_node)

        if start_expr.type != INT:
            self._err("range() start must be int")
        if stop_expr.type != INT:
            self._err("range() stop must be int")

        if var in self._args:
            idx, t = self._args[var]
            if t != INT:
                self._err(f"loop variable '{var}' already declared as {t}")
            is_arg = True
        elif var in self._locals:
            idx, t = self._locals[var]
            if t != INT:
                self._err(f"loop variable '{var}' already declared as {t}")
            is_arg = False
        else:
            idx = len(self._locals)
            self._locals[var] = (idx, INT)
            is_arg = False

        prev_in_loop = self._in_loop
        self._in_loop = True
        snap_lf = dict(self._locals)
        snap_af = dict(self._args)
        snap_sf = dict(self._statics_current_types)
        raw_body = self._visit_stmts(node.body)
        self._restore_types(snap_lf, snap_af, snap_sf)
        else_stmts = self._visit_stmts(node.orelse)
        self._in_loop = prev_in_loop

        return self._build_range_loop(
            var, idx, start_expr, stop_expr, step_val, raw_body, else_stmts, is_arg
        )

    def _build_range_loop(
        self,
        var: str,
        idx: int,
        start_expr: "Expr",
        stop_expr: "Expr",
        step_val: int,
        body_stmts: list[Stmt],
        else_stmts: list[Stmt],
        is_arg: bool,
    ) -> list[Stmt]:
        """Build [init, While(...)] for a range-based loop from pre-built HIR body."""
        inc_op = "+" if step_val > 0 else "-"
        increment = LocalStore(
            name=var,
            slot=idx,
            value=BinOp(
                left=LocalLoad(name=var, type=INT),
                op=inc_op,
                right=IntLiteral(value=abs(step_val)),
                type=INT,
            ),
            type=INT,
            is_arg=is_arg,
        )
        cond_op = "<" if step_val > 0 else ">"
        cond = Compare(
            left=LocalLoad(name=var, type=INT),
            op=cond_op,
            right=stop_expr,
        )
        rewritten_body = _for_rewrite_continues(body_stmts, increment) + [increment]
        init = LocalStore(name=var, slot=idx, value=start_expr, type=INT, is_arg=is_arg)
        return [init, While(condition=cond, body=rewritten_body, else_body=else_stmts)]

    def _desugar_for_list(self, node: ast.For, var: str, lst: Expr) -> list[Stmt]:
        """Desugar `for x in lst` to an index-based while loop."""
        elem_t = lst.type.elem  # type: ignore[union-attr]

        # Resolve or declare the loop variable
        if var in self._args:
            var_slot, var_t = self._args[var]
            var_is_arg = True
        elif var in self._locals:
            var_slot, var_t = self._locals[var]
            var_is_arg = False
        else:
            var_slot = len(self._locals)
            self._locals[var] = (var_slot, elem_t)
            var_t = elem_t
            var_is_arg = False
        if var_t != elem_t:
            self._err(f"loop variable '{var}' has type {var_t}, expected {elem_t}")

        prev_in_loop = self._in_loop
        self._in_loop = True
        snap_lfl = dict(self._locals)
        snap_afl = dict(self._args)
        snap_sfl = dict(self._statics_current_types)
        raw_body = self._visit_stmts(node.body)
        self._restore_types(snap_lfl, snap_afl, snap_sfl)
        else_stmts = self._visit_stmts(node.orelse)
        self._in_loop = prev_in_loop

        return self._build_list_iter_loop(
            var, var_slot, var_is_arg, lst, raw_body, else_stmts
        )

    def _build_list_iter_loop(
        self,
        var: str,
        var_slot: int,
        var_is_arg: bool,
        lst: "Expr",
        body_stmts: list[Stmt],
        else_stmts: list[Stmt],
    ) -> list[Stmt]:
        """Build an index-based while loop over a list from pre-built HIR body."""
        elem_t: Type = lst.type.elem  # type: ignore[union-attr]

        # Synthetic temporaries (mangled names avoid user-visible collisions)
        n = len(self._locals)
        lst_name = f"__for_lst_{n}__"
        len_name = f"__for_len_{n}__"
        idx_name = f"__for_idx_{n}__"
        lst_slot = len(self._locals)
        self._locals[lst_name] = (lst_slot, lst.type)
        len_slot = len(self._locals)
        self._locals[len_name] = (len_slot, INT)
        idx_slot = len(self._locals)
        self._locals[idx_name] = (idx_slot, INT)

        lst_load = LocalLoad(name=lst_name, type=lst.type)
        len_load = LocalLoad(name=len_name, type=INT)
        idx_load = LocalLoad(name=idx_name, type=INT)

        init_stmts: list[Stmt] = [
            LocalStore(name=lst_name, slot=lst_slot, value=lst, type=lst.type),
            LocalStore(name=len_name, slot=len_slot, value=Len(lst_load), type=INT),
            LocalStore(name=idx_name, slot=idx_slot, value=IntLiteral(0), type=INT),
        ]
        elem_assign = LocalStore(
            name=var,
            slot=var_slot,
            value=Index(value=lst_load, index=idx_load, type=elem_t),
            type=elem_t,
            is_arg=var_is_arg,
        )
        increment = LocalStore(
            name=idx_name,
            slot=idx_slot,
            value=BinOp(left=idx_load, op="+", right=IntLiteral(1), type=INT),
            type=INT,
        )
        rewritten_body = (
            [elem_assign] + _for_rewrite_continues(body_stmts, increment) + [increment]
        )
        cond = Compare(left=idx_load, op="<", right=len_load)
        return init_stmts + [
            While(condition=cond, body=rewritten_body, else_body=else_stmts)
        ]

    def _desugar_for_iterator(
        self, node: ast.For, var: str, iter_expr: "Expr"
    ) -> list[Stmt]:
        """Desugar `for x in iterator` to a while loop driven by iterator.next() / iterator.value()."""
        n = len(self._locals)
        iter_name = f"__for_iter_{n}__"
        iter_slot = len(self._locals)
        self._locals[iter_name] = (iter_slot, ITERATOR)
        iter_load = LocalLoad(name=iter_name, type=ITERATOR)

        if var in self._args:
            var_slot, var_t = self._args[var]
            var_is_arg = True
        elif var in self._locals:
            var_slot, var_t = self._locals[var]
            var_is_arg = False
        else:
            var_slot = len(self._locals)
            self._locals[var] = (var_slot, ANY)
            var_t = ANY
            var_is_arg = False

        prev_in_loop = self._in_loop
        self._in_loop = True
        snap_lfi = dict(self._locals)
        snap_afi = dict(self._args)
        snap_sfi = dict(self._statics_current_types)
        raw_body = self._visit_stmts(node.body)
        self._restore_types(snap_lfi, snap_afi, snap_sfi)
        else_stmts = self._visit_stmts(node.orelse)
        self._in_loop = prev_in_loop

        next_call = SyscallCall(
            hash=_SYSCALL_ITERATOR_NEXT, args=[iter_load], push_order=[0], type=BOOL
        )
        value_call = SyscallCall(
            hash=_SYSCALL_ITERATOR_VALUE, args=[iter_load], push_order=[0], type=ANY
        )
        value_assign = LocalStore(
            name=var, slot=var_slot, value=value_call, type=var_t, is_arg=var_is_arg
        )
        # No _for_rewrite_continues needed: no increment step; continue jumps back to while header
        return [
            LocalStore(name=iter_name, slot=iter_slot, value=iter_expr, type=ITERATOR),
            While(
                condition=next_call,
                body=[value_assign] + raw_body,
                else_body=else_stmts,
            ),
        ]

    def _desugar_list_comp(
        self,
        node: ast.expr,
        elt_node: ast.expr,
        generators: list,
    ) -> "Expr":
        """Desugar [expr for var in iterable if cond] to a temp list + loop, injected via _pre_stmts."""
        if len(generators) != 1:
            self._err("only single-generator list comprehensions are supported")
        gen = generators[0]
        if gen.is_async:
            self._err("async comprehensions are not supported")
        if not isinstance(gen.target, ast.Name):
            self._err("list comprehension target must be a simple variable name")
        var = gen.target.id

        # --- Iterable: range() or list[T] ---
        is_range_iter = (
            isinstance(gen.iter, ast.Call)
            and isinstance(gen.iter.func, ast.Name)
            and gen.iter.func.id == "range"
        )
        if is_range_iter:
            range_args = gen.iter.args
            if len(range_args) == 1:
                start_node_c: Optional[ast.expr] = None
                stop_node_c = range_args[0]
                step_val_c = 1
            elif len(range_args) == 2:
                start_node_c = range_args[0]
                stop_node_c = range_args[1]
                step_val_c = 1
            elif len(range_args) == 3:
                start_node_c = range_args[0]
                stop_node_c = range_args[1]
                step_node_c = range_args[2]
                if isinstance(step_node_c, ast.Constant) and isinstance(
                    step_node_c.value, int
                ):
                    step_val_c = step_node_c.value
                elif (
                    isinstance(step_node_c, ast.UnaryOp)
                    and isinstance(step_node_c.op, ast.USub)
                    and isinstance(step_node_c.operand, ast.Constant)
                    and isinstance(step_node_c.operand.value, int)
                ):
                    step_val_c = -step_node_c.operand.value
                else:
                    self._err("range() step must be an integer literal")
                if step_val_c == 0:
                    self._err("range() step cannot be zero")
            else:
                self._err("range() requires 1 to 3 arguments")

            start_expr_c: Expr = (
                IntLiteral(value=0)
                if start_node_c is None
                else self._visit_expr(start_node_c)
            )
            stop_expr_c = self._visit_expr(stop_node_c)
            if start_expr_c.type != INT:
                self._err("range() start must be int")
            if stop_expr_c.type != INT:
                self._err("range() stop must be int")

            elem_type_c: Type = INT
            if var in self._args:
                var_idx_c, var_t_c = self._args[var]
                if var_t_c != INT:
                    self._err(f"loop variable '{var}' already declared as {var_t_c}")
                var_is_arg_c = True
            elif var in self._locals:
                var_idx_c, var_t_c = self._locals[var]
                if var_t_c != INT:
                    self._err(f"loop variable '{var}' already declared as {var_t_c}")
                var_is_arg_c = False
            else:
                var_idx_c = len(self._locals)
                self._locals[var] = (var_idx_c, INT)
                var_is_arg_c = False
            iter_expr_c: Optional[Expr] = None
        else:
            iter_expr_c = self._visit_expr(gen.iter)
            if not isinstance(iter_expr_c.type, ListType):
                self._err(
                    "list comprehension iterable must be list[T], range(), d.keys(), or d.values()"
                )
            elem_type_c = iter_expr_c.type.elem

            if var in self._args:
                var_idx_c, var_t_c = self._args[var]
                if var_t_c != elem_type_c:
                    self._err(
                        f"loop variable '{var}' has type {var_t_c}, expected {elem_type_c}"
                    )
                var_is_arg_c = True
            elif var in self._locals:
                var_idx_c, var_t_c = self._locals[var]
                if var_t_c != elem_type_c:
                    self._err(
                        f"loop variable '{var}' has type {var_t_c}, expected {elem_type_c}"
                    )
                var_is_arg_c = False
            else:
                var_idx_c = len(self._locals)
                self._locals[var] = (var_idx_c, elem_type_c)
                var_is_arg_c = False
            start_expr_c = stop_expr_c = IntLiteral(0)  # unused placeholders
            step_val_c = 1  # unused

        # --- Filter conditions ---
        filter_cond: Optional[Expr] = None
        for cond_node in gen.ifs:
            cond_expr = self._visit_expr(cond_node)
            if cond_expr.type != BOOL:
                self._err("list comprehension filter condition must be bool")
            filter_cond = (
                cond_expr
                if filter_cond is None
                else BoolAnd(left=filter_cond, right=cond_expr)
            )

        # --- Element expression (detect nested comprehensions) ---
        saved_pre = self._pre_stmts
        self._pre_stmts = []
        elt_expr = self._visit_expr(elt_node)
        if self._pre_stmts:
            self._pre_stmts = saved_pre
            self._err("nested list comprehensions are not supported")
        self._pre_stmts = saved_pre

        out_type: Type = ListType(elt_expr.type)

        # --- Allocate result temp ---
        result_name = f"__comp_result_{len(self._locals)}__"
        result_slot = len(self._locals)
        self._locals[result_name] = (result_slot, out_type)

        # --- Build comprehension body ---
        append_stmt: Stmt = ListAppend(
            container=LocalLoad(name=result_name, type=out_type),
            value=elt_expr,
        )
        comp_body: list[Stmt] = (
            [If(condition=filter_cond, then_body=[append_stmt], else_body=[])]
            if filter_cond is not None
            else [append_stmt]
        )

        # --- Build loop ---
        if is_range_iter:
            loop_stmts = self._build_range_loop(
                var,
                var_idx_c,
                start_expr_c,
                stop_expr_c,
                step_val_c,
                comp_body,
                [],
                var_is_arg_c,
            )
        else:
            assert iter_expr_c is not None
            loop_stmts = self._build_list_iter_loop(
                var, var_idx_c, var_is_arg_c, iter_expr_c, comp_body, []
            )

        # --- Inject pre-stmts: init result list + loop ---
        init_result: Stmt = LocalStore(
            name=result_name,
            slot=result_slot,
            value=ListLiteral(elements=[], type=out_type),
            type=out_type,
            is_arg=False,
        )
        self._pre_stmts.extend([init_result] + loop_stmts)

        return LocalLoad(name=result_name, type=out_type)

    def _desugar_dict_comp(
        self,
        key_node: ast.expr,
        val_node: ast.expr,
        generators: list,
    ) -> "Expr":
        """Desugar {k: v for var in iterable if cond} to a temp dict + loop, injected via _pre_stmts."""
        if len(generators) != 1:
            self._err("only single-generator dict comprehensions are supported")
        gen = generators[0]
        if gen.is_async:
            self._err("async comprehensions are not supported")
        if not isinstance(gen.target, ast.Name):
            self._err("dict comprehension target must be a simple variable name")
        var = gen.target.id

        # --- Iterable: range() or list[T] ---
        is_range_iter = (
            isinstance(gen.iter, ast.Call)
            and isinstance(gen.iter.func, ast.Name)
            and gen.iter.func.id == "range"
        )
        if is_range_iter:
            range_args = gen.iter.args
            if len(range_args) == 1:
                start_node_c: Optional[ast.expr] = None
                stop_node_c = range_args[0]
                step_val_c = 1
            elif len(range_args) == 2:
                start_node_c = range_args[0]
                stop_node_c = range_args[1]
                step_val_c = 1
            elif len(range_args) == 3:
                start_node_c = range_args[0]
                stop_node_c = range_args[1]
                step_node_c = range_args[2]
                if isinstance(step_node_c, ast.Constant) and isinstance(
                    step_node_c.value, int
                ):
                    step_val_c = step_node_c.value
                elif (
                    isinstance(step_node_c, ast.UnaryOp)
                    and isinstance(step_node_c.op, ast.USub)
                    and isinstance(step_node_c.operand, ast.Constant)
                    and isinstance(step_node_c.operand.value, int)
                ):
                    step_val_c = -step_node_c.operand.value
                else:
                    self._err("range() step must be an integer literal")
                if step_val_c == 0:
                    self._err("range() step cannot be zero")
            else:
                self._err("range() requires 1 to 3 arguments")

            start_expr_c: Expr = (
                IntLiteral(value=0)
                if start_node_c is None
                else self._visit_expr(start_node_c)
            )
            stop_expr_c = self._visit_expr(stop_node_c)
            if start_expr_c.type != INT:
                self._err("range() start must be int")
            if stop_expr_c.type != INT:
                self._err("range() stop must be int")

            if var in self._args:
                var_idx_c, var_t_c = self._args[var]
                if var_t_c != INT:
                    self._err(f"loop variable '{var}' already declared as {var_t_c}")
                var_is_arg_c = True
            elif var in self._locals:
                var_idx_c, var_t_c = self._locals[var]
                if var_t_c != INT:
                    self._err(f"loop variable '{var}' already declared as {var_t_c}")
                var_is_arg_c = False
            else:
                var_idx_c = len(self._locals)
                self._locals[var] = (var_idx_c, INT)
                var_is_arg_c = False
            iter_expr_c: Optional[Expr] = None
        else:
            iter_expr_c = self._visit_expr(gen.iter)
            if not isinstance(iter_expr_c.type, ListType):
                self._err(
                    "dict comprehension iterable must be list[T], range(), d.keys(), or d.values()"
                )
            elem_type_c: Type = iter_expr_c.type.elem

            if var in self._args:
                var_idx_c, var_t_c = self._args[var]
                if var_t_c != elem_type_c:
                    self._err(
                        f"loop variable '{var}' has type {var_t_c}, expected {elem_type_c}"
                    )
                var_is_arg_c = True
            elif var in self._locals:
                var_idx_c, var_t_c = self._locals[var]
                if var_t_c != elem_type_c:
                    self._err(
                        f"loop variable '{var}' has type {var_t_c}, expected {elem_type_c}"
                    )
                var_is_arg_c = False
            else:
                var_idx_c = len(self._locals)
                self._locals[var] = (var_idx_c, elem_type_c)
                var_is_arg_c = False
            start_expr_c = stop_expr_c = IntLiteral(0)  # unused placeholders
            step_val_c = 1  # unused

        # --- Filter conditions ---
        filter_cond: Optional[Expr] = None
        for cond_node in gen.ifs:
            cond_expr = self._visit_expr(cond_node)
            if cond_expr.type != BOOL:
                self._err("dict comprehension filter condition must be bool")
            filter_cond = (
                cond_expr
                if filter_cond is None
                else BoolAnd(left=filter_cond, right=cond_expr)
            )

        # --- Key + value expressions (detect nested comprehensions) ---
        saved_pre = self._pre_stmts
        self._pre_stmts = []
        key_expr = self._visit_expr(key_node)
        val_expr = self._visit_expr(val_node)
        if self._pre_stmts:
            self._pre_stmts = saved_pre
            self._err("nested comprehensions in dict comprehension are not supported")
        self._pre_stmts = saved_pre

        # --- Validate key type ---
        _VALID_KEY_TYPES = (IntType, BoolType, BytesType, StrType)
        if not isinstance(key_expr.type, _VALID_KEY_TYPES):
            self._err(
                f"dict comprehension key must be int, bool, str, or bytes; got {key_expr.type}"
            )

        out_type: Type = DictType(key=key_expr.type, val=val_expr.type)

        # --- Allocate result temp ---
        result_name = f"__comp_result_{len(self._locals)}__"
        result_slot = len(self._locals)
        self._locals[result_name] = (result_slot, out_type)

        # --- Build comprehension body ---
        set_stmt: Stmt = ItemStore(
            container=LocalLoad(name=result_name, type=out_type),
            index=key_expr,
            value=val_expr,
        )
        comp_body: list[Stmt] = (
            [If(condition=filter_cond, then_body=[set_stmt], else_body=[])]
            if filter_cond is not None
            else [set_stmt]
        )

        # --- Build loop ---
        if is_range_iter:
            loop_stmts = self._build_range_loop(
                var,
                var_idx_c,
                start_expr_c,
                stop_expr_c,
                step_val_c,
                comp_body,
                [],
                var_is_arg_c,
            )
        else:
            assert iter_expr_c is not None
            loop_stmts = self._build_list_iter_loop(
                var, var_idx_c, var_is_arg_c, iter_expr_c, comp_body, []
            )

        # --- Inject pre-stmts: init result dict + loop ---
        init_result: Stmt = LocalStore(
            name=result_name,
            slot=result_slot,
            value=DictLiteral(pairs=[], type=out_type),
            type=out_type,
            is_arg=False,
        )
        self._pre_stmts.extend([init_result] + loop_stmts)

        return LocalLoad(name=result_name, type=out_type)

    def _desugar_for_dict_items(
        self, node: ast.For, k_var: str, v_var: str, dict_expr: Expr
    ) -> list[Stmt]:
        """Desugar `for k, v in d.items()` to index-based while over d.keys()."""
        dict_t = dict_expr.type  # type: ignore[union-attr]
        key_t = dict_t.key
        val_t = dict_t.val
        keys_t = ListType(key_t)

        # Resolve or declare k_var
        if k_var in self._args:
            k_slot, k_existing_t = self._args[k_var]
            k_is_arg = True
        elif k_var in self._locals:
            k_slot, k_existing_t = self._locals[k_var]
            k_is_arg = False
        else:
            k_slot = len(self._locals)
            self._locals[k_var] = (k_slot, key_t)
            k_existing_t = key_t
            k_is_arg = False
        if k_existing_t != key_t:
            self._err(
                f"loop variable '{k_var}' has type {k_existing_t}, expected {key_t}"
            )

        # Resolve or declare v_var
        if v_var in self._args:
            v_slot, v_existing_t = self._args[v_var]
            v_is_arg = True
        elif v_var in self._locals:
            v_slot, v_existing_t = self._locals[v_var]
            v_is_arg = False
        else:
            v_slot = len(self._locals)
            self._locals[v_var] = (v_slot, val_t)
            v_existing_t = val_t
            v_is_arg = False
        if v_existing_t != val_t:
            self._err(
                f"loop variable '{v_var}' has type {v_existing_t}, expected {val_t}"
            )

        # Synthetic temporaries
        n = len(self._locals)
        dict_name = f"__for_dict_{n}__"
        keys_name = f"__for_keys_{n}__"
        len_name = f"__for_len_{n}__"
        idx_name = f"__for_idx_{n}__"
        dict_slot = len(self._locals)
        self._locals[dict_name] = (dict_slot, dict_t)
        keys_slot = len(self._locals)
        self._locals[keys_name] = (keys_slot, keys_t)
        len_slot = len(self._locals)
        self._locals[len_name] = (len_slot, INT)
        idx_slot = len(self._locals)
        self._locals[idx_name] = (idx_slot, INT)

        dict_load = LocalLoad(name=dict_name, type=dict_t)
        keys_load = LocalLoad(name=keys_name, type=keys_t)
        len_load = LocalLoad(name=len_name, type=INT)
        idx_load = LocalLoad(name=idx_name, type=INT)

        init_stmts: list[Stmt] = [
            LocalStore(name=dict_name, slot=dict_slot, value=dict_expr, type=dict_t),
            LocalStore(
                name=keys_name,
                slot=keys_slot,
                value=DictKeys(container=dict_load, type=keys_t),
                type=keys_t,
            ),
            LocalStore(name=len_name, slot=len_slot, value=Len(keys_load), type=INT),
            LocalStore(name=idx_name, slot=idx_slot, value=IntLiteral(0), type=INT),
        ]

        k_assign = LocalStore(
            name=k_var,
            slot=k_slot,
            value=Index(value=keys_load, index=idx_load, type=key_t),
            type=key_t,
            is_arg=k_is_arg,
        )
        # After k_assign, k_var holds the current key — use it to look up the value
        v_assign = LocalStore(
            name=v_var,
            slot=v_slot,
            value=Index(
                value=dict_load, index=LocalLoad(name=k_var, type=key_t), type=val_t
            ),
            type=val_t,
            is_arg=v_is_arg,
        )
        increment = LocalStore(
            name=idx_name,
            slot=idx_slot,
            value=BinOp(left=idx_load, op="+", right=IntLiteral(1), type=INT),
            type=INT,
        )

        prev_in_loop = self._in_loop
        self._in_loop = True
        snap_lfd = dict(self._locals)
        snap_afd = dict(self._args)
        snap_sfd = dict(self._statics_current_types)
        raw_body = self._visit_stmts(node.body)
        self._restore_types(snap_lfd, snap_afd, snap_sfd)
        else_stmts = self._visit_stmts(node.orelse)
        self._in_loop = prev_in_loop

        rewritten_body = (
            [k_assign, v_assign]
            + _for_rewrite_continues(raw_body, increment)
            + [increment]
        )
        cond = Compare(left=idx_load, op="<", right=len_load)
        return init_stmts + [
            While(condition=cond, body=rewritten_body, else_body=else_stmts)
        ]

    def _desugar_for_enumerate(
        self, node: ast.For, i_var: str, x_var: str
    ) -> list[Stmt]:
        """Desugar `for i, x in enumerate(lst[, start])` to an index-based while loop."""
        enum_call = node.iter  # type: ignore[assignment]
        args = enum_call.args
        if len(args) < 1 or len(args) > 2:
            self._err("enumerate() requires 1 or 2 arguments")
        iter_expr = self._visit_expr(args[0])
        if not isinstance(iter_expr.type, ListType):
            self._err("enumerate() iterable must be list[T]")
        elem_t: Type = iter_expr.type.elem

        # Parse optional start argument
        raw_start: Expr = (
            IntLiteral(value=0) if len(args) == 1 else self._visit_expr(args[1])
        )
        if raw_start.type != INT:
            self._err("enumerate() start must be int")
        has_start = not (isinstance(raw_start, IntLiteral) and raw_start.value == 0)

        # Resolve or declare i_var (type int)
        if i_var in self._args:
            i_slot, i_existing_t = self._args[i_var]
            i_is_arg = True
        elif i_var in self._locals:
            i_slot, i_existing_t = self._locals[i_var]
            i_is_arg = False
        else:
            i_slot = len(self._locals)
            self._locals[i_var] = (i_slot, INT)
            i_existing_t = INT
            i_is_arg = False
        if i_existing_t != INT:
            self._err(f"loop variable '{i_var}' has type {i_existing_t}, expected int")

        # Resolve or declare x_var (type elem_t)
        if x_var in self._args:
            x_slot, x_existing_t = self._args[x_var]
            x_is_arg = True
        elif x_var in self._locals:
            x_slot, x_existing_t = self._locals[x_var]
            x_is_arg = False
        else:
            x_slot = len(self._locals)
            self._locals[x_var] = (x_slot, elem_t)
            x_existing_t = elem_t
            x_is_arg = False
        if x_existing_t != elem_t:
            self._err(
                f"loop variable '{x_var}' has type {x_existing_t}, expected {elem_t}"
            )

        # Synthetic temporaries
        n = len(self._locals)
        lst_name = f"__for_lst_{n}__"
        len_name = f"__for_len_{n}__"
        idx_name = f"__for_idx_{n}__"
        lst_slot = len(self._locals)
        self._locals[lst_name] = (lst_slot, iter_expr.type)
        len_slot = len(self._locals)
        self._locals[len_name] = (len_slot, INT)
        idx_slot = len(self._locals)
        self._locals[idx_name] = (idx_slot, INT)

        lst_load = LocalLoad(name=lst_name, type=iter_expr.type)
        len_load = LocalLoad(name=len_name, type=INT)
        idx_load = LocalLoad(name=idx_name, type=INT)

        init_stmts: list[Stmt] = [
            LocalStore(
                name=lst_name, slot=lst_slot, value=iter_expr, type=iter_expr.type
            ),
            LocalStore(name=len_name, slot=len_slot, value=Len(lst_load), type=INT),
            LocalStore(name=idx_name, slot=idx_slot, value=IntLiteral(0), type=INT),
        ]

        # Optional start temp (skip when start == 0)
        if has_start:
            start_name = f"__for_start_{n}__"
            start_slot = len(self._locals)
            self._locals[start_name] = (start_slot, INT)
            init_stmts.append(
                LocalStore(name=start_name, slot=start_slot, value=raw_start, type=INT)
            )
            start_load = LocalLoad(name=start_name, type=INT)
            i_expr: Expr = BinOp(left=idx_load, op="+", right=start_load, type=INT)
        else:
            i_expr = idx_load

        i_assign = LocalStore(
            name=i_var, slot=i_slot, value=i_expr, type=INT, is_arg=i_is_arg
        )
        x_assign = LocalStore(
            name=x_var,
            slot=x_slot,
            value=Index(value=lst_load, index=idx_load, type=elem_t),
            type=elem_t,
            is_arg=x_is_arg,
        )
        increment = LocalStore(
            name=idx_name,
            slot=idx_slot,
            value=BinOp(left=idx_load, op="+", right=IntLiteral(1), type=INT),
            type=INT,
        )

        prev_in_loop = self._in_loop
        self._in_loop = True
        snap_lfe = dict(self._locals)
        snap_afe = dict(self._args)
        snap_sfe = dict(self._statics_current_types)
        raw_body = self._visit_stmts(node.body)
        self._restore_types(snap_lfe, snap_afe, snap_sfe)
        else_stmts = self._visit_stmts(node.orelse)
        self._in_loop = prev_in_loop

        rewritten_body = (
            [i_assign, x_assign]
            + _for_rewrite_continues(raw_body, increment)
            + [increment]
        )
        cond = Compare(left=idx_load, op="<", right=len_load)
        return init_stmts + [
            While(condition=cond, body=rewritten_body, else_body=else_stmts)
        ]

    # ------------------------------------------------------------------
    # Assignment helpers (extracted from _visit_stmt for readability)
    # ------------------------------------------------------------------

    def _handle_annassign(self, name: str, ann: ast.expr, val: ast.expr) -> Stmt:
        if name in self._statics:
            self._err(
                f"'{name}' is a static field; cannot redeclare as a local variable"
            )
        if val is None:
            self._err(f"'{name}' must have a value")
        declared = self._resolve_annotation(ann)
        expr = self._visit_expr(val)
        if isinstance(expr, ListLiteral) and not expr.elements:
            expr = dataclasses.replace(expr, type=declared)
        if isinstance(expr, DictLiteral) and not expr.pairs:
            expr = dataclasses.replace(expr, type=declared)
        if not _type_compatible(expr.type, declared, self._class_registry):
            self._err(_type_mismatch_msg(f"assigning '{name}'", declared, expr.type))
        if name in self._args:
            idx, arg_declared = self._args[name]
            if declared != arg_declared:
                self._err(
                    _type_mismatch_msg(
                        f"re-annotating argument '{name}'", arg_declared, declared
                    )
                )
            return LocalStore(
                name=name, slot=idx, value=expr, type=declared, is_arg=True
            )
        if name not in self._locals:
            self._locals[name] = (len(self._locals), declared)
            self._local_orig_types[name] = declared
        slot, _ = self._locals[name]
        return LocalStore(name=name, slot=slot, value=expr, type=declared)

    def _handle_assign_name(self, name: str, val: ast.expr) -> Stmt:
        if (
            name not in self._locals
            and name not in self._args
            and name not in self._statics
        ):
            expr = self._visit_expr(val)
            if isinstance(expr.type, NoneType):
                self._err(
                    f"Cannot infer type of '{name}' from None. "
                    f"Use an explicit annotation, e.g. "
                    f"'{name}: Optional[<type>] = None' or '{name}: NoneType = None'."
                )
            if isinstance(expr, ListLiteral) and not expr.elements:
                expr = dataclasses.replace(expr, type=ListType(ANY))
            if isinstance(expr, DictLiteral) and not expr.pairs:
                expr = dataclasses.replace(expr, type=DictType(ANY, ANY))
            inferred = expr.type
            slot = len(self._locals)
            self._locals[name] = (slot, inferred)
            self._local_orig_types[name] = inferred
            return LocalStore(name=name, slot=slot, value=expr, type=inferred)
        if name in self._statics:
            slot, declared = self._statics[name]
            expr = self._visit_expr(val)
            if not _type_compatible(expr.type, declared, self._class_registry):
                self._err(
                    _type_mismatch_msg(
                        f"assigning static '{name}'", declared, expr.type
                    )
                )
            self._statics_current_types[name] = expr.type
            return StaticStore(name=name, slot=slot, value=expr, type=declared)
        if name in self._args:
            idx, declared = self._args[name]
            expr = self._visit_expr(val)
            if not _type_compatible(expr.type, declared, self._class_registry):
                self._err(
                    _type_mismatch_msg(
                        f"reassigning argument '{name}'", declared, expr.type
                    )
                )
            return LocalStore(
                name=name, slot=idx, value=expr, type=declared, is_arg=True
            )
        slot, declared = self._locals[name]
        expr = self._visit_expr(val)
        if not _type_compatible(expr.type, declared, self._class_registry):
            self._err(_type_mismatch_msg(f"reassigning '{name}'", declared, expr.type))
        return LocalStore(name=name, slot=slot, value=expr, type=declared)

    def _handle_augassign(self, name: str, op: ast.operator, val: ast.expr) -> Stmt:
        if name in self._statics:
            slot, declared = self._statics[name]
            if declared != INT:
                self._err(
                    f"Augmented assignment requires int operand, '{name}' is {declared}"
                )
            rhs = self._visit_expr(val)
            if rhs.type != INT:
                self._err(
                    "Augmented assignment requires int operand on right-hand side"
                )
            load = StaticLoad(name=name, slot=slot, type=declared)
            value = BinOp(left=load, op=self._map_binop(op), right=rhs, type=INT)
            self._statics_current_types[name] = INT
            return StaticStore(name=name, slot=slot, value=value, type=declared)
        if name not in self._locals and name not in self._args:
            self._err(f"'{name}' used in augmented assignment before declaration.")
        if name in self._args:
            idx, declared = self._args[name]
            is_arg = True
        else:
            idx, declared = self._locals[name]
            is_arg = False
        if declared != INT:
            self._err(
                f"Augmented assignment requires int operand, '{name}' is {declared}"
            )
        rhs = self._visit_expr(val)
        if rhs.type != INT:
            self._err("Augmented assignment requires int operand on right-hand side")
        load = LocalLoad(name=name, type=declared)
        value = BinOp(left=load, op=self._map_binop(op), right=rhs, type=INT)
        return LocalStore(
            name=name, slot=idx, value=value, type=declared, is_arg=is_arg
        )

    def _handle_field_annassign(
        self,
        obj_node: ast.expr,
        fname: str,
        ann: ast.expr,
        val: Optional[ast.expr],
    ) -> Stmt:
        obj = self._visit_expr(obj_node)
        if not isinstance(obj.type, ClassType) or self._class_registry is None:
            self._err(
                f"Annotated attribute assignment only supported on class instances"
            )
        info = self._class_registry[obj.type.name]
        if fname not in info.fields:
            self._err(f"Unknown field '{fname}' on class '{obj.type.name}'")
        fi = info.fields[fname]
        declared = self._resolve_annotation(ann)
        if declared != fi.type:
            self._err(
                f"Field '{fname}' declared as {fi.type}, annotation says {declared}"
            )
        if val is None:
            self._err(f"Field '{fname}' must have a value")
        expr = self._visit_expr(val)
        if isinstance(expr, ListLiteral) and not expr.elements:
            expr = dataclasses.replace(expr, type=fi.type)
        if isinstance(expr, DictLiteral) and not expr.pairs:
            expr = dataclasses.replace(expr, type=fi.type)
        if not _type_compatible(expr.type, fi.type, self._class_registry):
            self._err(
                _type_mismatch_msg(f"assigning field '{fname}'", fi.type, expr.type)
            )
        return SetField(
            obj=obj,
            field_name=fname,
            field_index=fi.index,
            value=expr,
            field_type=fi.type,
        )

    def _handle_field_assign(
        self, obj_node: ast.expr, fname: str, val: ast.expr
    ) -> Stmt:
        obj = self._visit_expr(obj_node)
        if not isinstance(obj.type, ClassType) or self._class_registry is None:
            self._err(f"Attribute assignment only supported on class instances")
        info = self._class_registry[obj.type.name]
        if fname not in info.fields:
            self._err(f"Unknown field '{fname}' on class '{obj.type.name}'")
        fi = info.fields[fname]
        expr = self._visit_expr(val)
        if not _type_compatible(expr.type, fi.type, self._class_registry):
            self._err(
                _type_mismatch_msg(f"assigning field '{fname}'", fi.type, expr.type)
            )
        return SetField(
            obj=obj,
            field_name=fname,
            field_index=fi.index,
            value=expr,
            field_type=fi.type,
        )

    def _handle_classvar_assign(self, cname: str, cvar: str, val: ast.expr) -> Stmt:
        info = self._class_registry[cname]
        if cvar not in info.class_vars:
            self._err(f"Unknown class variable '{cvar}' on '{cname}'")
        slot, declared = info.class_vars[cvar]
        expr = self._visit_expr(val)
        if not _type_compatible(expr.type, declared, self._class_registry):
            self._err(
                _type_mismatch_msg(
                    f"assigning class var '{cname}.{cvar}'", declared, expr.type
                )
            )
        return StaticStore(name=f"{cname}.{cvar}", slot=slot, value=expr, type=declared)

    # ------------------------------------------------------------------
    # Complex call helpers (extracted from _visit_expr for readability)
    # ------------------------------------------------------------------

    def _visit_to_bytes_call(
        self,
        obj_node: ast.expr,
        args_nodes: list,
        kws: list,
    ) -> Expr:
        obj = self._visit_expr(obj_node)
        if not isinstance(obj.type, IntType):
            self._err(f".to_bytes() requires int receiver, got {obj.type}")
        if len(args_nodes) > 2:
            self._err(
                "int.to_bytes() takes at most 2 positional args: length, byteorder"
            )
        len_node: Optional[ast.expr] = None
        len_expr: Expr = IntLiteral(value=1)
        byteorder_val: str = "big"
        signed_val: bool = False
        if len(args_nodes) >= 1:
            len_node = args_nodes[0]
            len_expr = self._visit_expr(args_nodes[0])
            if not isinstance(len_expr.type, IntType):
                self._err(f"int.to_bytes() length must be int, got {len_expr.type}")
        if len(args_nodes) >= 2:
            bo_node = args_nodes[1]
            if not isinstance(bo_node, ast.Constant) or bo_node.value not in (
                "little",
                "big",
            ):
                self._err(
                    "int.to_bytes() byteorder must be string literal 'little' or 'big'"
                )
            byteorder_val = bo_node.value
        for kw in kws:
            if kw.arg == "length":
                if len(args_nodes) >= 1:
                    self._err(
                        "int.to_bytes() got multiple values for argument 'length'"
                    )
                len_node = kw.value
                len_expr = self._visit_expr(kw.value)
                if not isinstance(len_expr.type, IntType):
                    self._err(f"int.to_bytes() length must be int, got {len_expr.type}")
            elif kw.arg == "byteorder":
                if len(args_nodes) >= 2:
                    self._err(
                        "int.to_bytes() got multiple values for argument 'byteorder'"
                    )
                if not isinstance(kw.value, ast.Constant) or kw.value.value not in (
                    "little",
                    "big",
                ):
                    self._err(
                        "int.to_bytes() byteorder must be string literal 'little' or 'big'"
                    )
                byteorder_val = kw.value.value
            elif kw.arg == "signed":
                if not isinstance(kw.value, ast.Constant) or not isinstance(
                    kw.value.value, bool
                ):
                    self._err(
                        "int.to_bytes() 'signed' must be a bool literal (True or False)"
                    )
                signed_val = kw.value.value
            else:
                self._err(f"int.to_bytes() unexpected keyword argument '{kw.arg}'")
        obj_const: Optional[int] = None
        if isinstance(obj, IntLiteral):
            obj_const = obj.value
        elif isinstance(obj, Negate) and isinstance(obj.operand, IntLiteral):
            obj_const = -obj.operand.value
        else:
            ast_val = _try_fold_const_expr(obj_node, {})
            if isinstance(ast_val, int) and not isinstance(ast_val, bool):
                obj_const = ast_val
        len_const: Optional[int] = (
            len_expr.value if isinstance(len_expr, IntLiteral) else None
        )
        if len_const is None and len_node is not None:
            ast_len = _try_fold_const_expr(len_node, {})
            if isinstance(ast_len, int) and not isinstance(ast_len, bool):
                len_const = ast_len
        if obj_const is not None and len_const is not None:
            try:
                folded = obj_const.to_bytes(len_const, byteorder_val, signed=signed_val)
            except (OverflowError, ValueError) as exc:
                self._err(f"int.to_bytes() constant evaluation failed: {exc}")
            return BytesLiteral(value=folded)
        return IntToBytes(
            value=obj, length=len_expr, byteorder=byteorder_val, signed=signed_val
        )

    def _visit_from_bytes_call(self, args_nodes: list, kws: list) -> Expr:
        if len(args_nodes) < 1:
            self._err("int.from_bytes() missing required argument: 'bytes'")
        if len(args_nodes) > 2:
            self._err(
                "int.from_bytes() takes at most 2 positional args: bytes, byteorder"
            )
        byteorder_val = "big"
        signed_val = False
        arg_expr = self._visit_expr(args_nodes[0])
        if not isinstance(arg_expr.type, (BytesType, BytearrayType)):
            self._err(
                f"int.from_bytes() argument must be bytes or bytearray, got {arg_expr.type}"
            )
        if len(args_nodes) >= 2:
            bo_node = args_nodes[1]
            if not isinstance(bo_node, ast.Constant) or bo_node.value not in (
                "little",
                "big",
            ):
                self._err(
                    "int.from_bytes() byteorder must be string literal 'little' or 'big'"
                )
            byteorder_val = bo_node.value
        for kw in kws:
            if kw.arg == "byteorder":
                if len(args_nodes) >= 2:
                    self._err(
                        "int.from_bytes() got multiple values for argument 'byteorder'"
                    )
                if not isinstance(kw.value, ast.Constant) or kw.value.value not in (
                    "little",
                    "big",
                ):
                    self._err(
                        "int.from_bytes() byteorder must be string literal 'little' or 'big'"
                    )
                byteorder_val = kw.value.value
            elif kw.arg == "signed":
                if not isinstance(kw.value, ast.Constant) or not isinstance(
                    kw.value.value, bool
                ):
                    self._err(
                        "int.from_bytes() 'signed' must be a bool literal (True or False)"
                    )
                signed_val = kw.value.value
            else:
                self._err(f"int.from_bytes() unexpected keyword argument '{kw.arg}'")
        if isinstance(arg_expr, BytesLiteral):
            return IntLiteral(
                value=int.from_bytes(arg_expr.value, byteorder_val, signed=signed_val)
            )
        return IntFromBytes(arg=arg_expr, byteorder=byteorder_val, signed=signed_val)

    def _resolve_aliases_in_expr(self, node: "ast.expr") -> "ast.expr":
        """Rewrite import-alias names in an expression node before dispatch."""
        # Pre-resolve import aliases: alias(args) → original(args)
        if (
            self._aliases
            and isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in self._aliases
        ):
            orig = self._aliases[node.func.id]
            node = ast.Call(
                func=ast.Name(id=orig, ctx=ast.Load()),
                args=node.args,
                keywords=node.keywords,
            )
        # Pre-resolve import aliases for attribute access: Alias.attr → Mangled.attr
        if self._aliases:
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                _fa = node.func
                if isinstance(_fa.value, ast.Name) and _fa.value.id in self._aliases:
                    _resolved_cls = self._aliases[_fa.value.id]
                    node = ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id=_resolved_cls, ctx=ast.Load()),
                            attr=_fa.attr,
                            ctx=_fa.ctx,
                        ),
                        args=node.args,
                        keywords=node.keywords,
                    )
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name) and node.value.id in self._aliases:
                    _resolved_cls = self._aliases[node.value.id]
                    node = ast.Attribute(
                        value=ast.Name(id=_resolved_cls, ctx=ast.Load()),
                        attr=node.attr,
                        ctx=node.ctx,
                    )
        return node

    def _visit_atom(self, node: "ast.expr") -> "Expr":
        """Handle literal constants and name lookups."""
        match node:
            case ast.Constant(value=None):
                return NoneLiteral()
            case ast.Constant(value=v) if isinstance(v, bool):
                return BoolLiteral(v)
            case ast.Constant(value=v) if isinstance(v, int):
                return IntLiteral(v)
            case ast.Constant(value=v) if isinstance(v, str):
                return StringLiteral(v)
            case ast.Constant(value=v) if isinstance(v, bytes):
                return BytesLiteral(v)
            case ast.Name(id=name):
                if name in self._args:
                    _, t = self._args[name]
                    return LocalLoad(name=name, type=t)
                if name in self._locals:
                    return LocalLoad(name=name, type=self._locals[name][1])
                # Apply import alias for static reads (e.g. MAX_LIMIT → LIMIT)
                actual = self._aliases.get(name, name) if self._aliases else name
                if actual in self._statics:
                    slot, _ = self._statics[actual]
                    t = self._statics_current_types.get(
                        actual, self._statics[actual][1]
                    )
                    return StaticLoad(name=actual, slot=slot, type=t)
                self._err(f"Undefined variable '{name}'")
            case _:
                self._err(f"Unsupported expression: {ast.dump(node)}")

    def _visit_operator_expr(self, node: "ast.expr") -> "Expr":
        """Handle binary ops, comparisons, boolean ops, unary ops, and ternary."""
        match node:
            case ast.BinOp(left=l, op=ast.Add(), right=r):
                left, right = self._visit_expr(l), self._visit_expr(r)
                if isinstance(left.type, _BYTESLIKE) and isinstance(
                    right.type, _BYTESLIKE
                ):
                    # str cannot mix with bytes/bytearray (Python TypeError)
                    str_mixed = isinstance(left.type, StrType) != isinstance(
                        right.type, StrType
                    )
                    if str_mixed:
                        self._err(f"cannot concatenate {left.type} and {right.type}")
                    result_type = (
                        BYTEARRAY
                        if isinstance(left.type, BytearrayType)
                        and isinstance(right.type, BytearrayType)
                        else STR if isinstance(left.type, StrType) else BYTES
                    )
                    return BinOp(left=left, op="cat", right=right, type=result_type)
                if left.type != INT or right.type != INT:
                    self._err("arithmetic requires int operands")
                return BinOp(left=left, op="+", right=right, type=INT)
            case ast.BinOp(
                op=ast.Pow(),
                right=ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=v)),
            ) if isinstance(v, int):
                self._err("negative exponent not supported — result would be float")
            case ast.BinOp(left=l, op=op, right=r):
                left, right = self._visit_expr(l), self._visit_expr(r)
                if left.type != INT or right.type != INT:
                    self._err("arithmetic requires int operands")
                return BinOp(left=left, op=self._map_binop(op), right=right, type=INT)
            case ast.Compare(
                left=l, ops=[ast.Is()], comparators=[ast.Constant(value=None)]
            ):
                operand = self._visit_expr(l)
                if not isinstance(operand.type, (OptionalType, NoneType)):
                    self._err(
                        f"'is None' requires Optional or None type, got {operand.type}"
                    )
                return IsNone(operand=operand, negated=False)
            case ast.Compare(
                left=l, ops=[ast.IsNot()], comparators=[ast.Constant(value=None)]
            ):
                operand = self._visit_expr(l)
                if not isinstance(operand.type, (OptionalType, NoneType)):
                    self._err(
                        f"'is not None' requires Optional or None type, got {operand.type}"
                    )
                return IsNone(operand=operand, negated=True)
            case ast.Compare(left=l, ops=[ast.In()], comparators=[r]):
                key = self._visit_expr(l)
                container = self._visit_expr(r)
                if not isinstance(container.type, DictType):
                    self._err("'in' operator only supported for dict[K,V]")
                if key.type != container.type.key:
                    self._err(
                        f"'in' key type mismatch: expected {container.type.key}, got {key.type}"
                    )
                return HasKey(container=container, key=key)
            case ast.Compare(left=l, ops=[op], comparators=[r]):
                left, right = self._visit_expr(l), self._visit_expr(r)
                # str vs bytes: distinct types — fold to constant per Python semantics
                str_bytes_mix = (
                    isinstance(left.type, StrType) and isinstance(right.type, BytesType)
                ) or (
                    isinstance(left.type, BytesType) and isinstance(right.type, StrType)
                )
                if str_bytes_mix:
                    mapped = self._map_cmp(op)
                    if mapped == "==":
                        return BoolLiteral(False)
                    if mapped == "!=":
                        return BoolLiteral(True)
                    self._err("cannot order-compare str and bytes")
                # NeoVM LT/LE/GT/GE on ByteString interprets bytes as a little-endian integer —
                # not lexicographic. Reject ordering on str/bytes/bytearray at compile time.
                if self._map_cmp(op) in ("<", "<=", ">", ">=") and isinstance(
                    left.type, (StrType, BytesType, BytearrayType)
                ):
                    self._err(
                        "ordering not supported for str/bytes — NeoVM interprets bytes as integers, not lexicographically"
                    )
                return Compare(left=left, op=self._map_cmp(op), right=right)
            case ast.Compare(left=l, ops=ops, comparators=comparators):
                # Desugar `a op1 b op2 c` → BoolAnd(Compare(a,op1,b), Compare(b,op2,c))
                # Intermediate values are re-evaluated (safe: no side effects in HIR).
                all_exprs = [self._visit_expr(l)] + [
                    self._visit_expr(c) for c in comparators
                ]
                result: Expr = Compare(
                    left=all_exprs[0], op=self._map_cmp(ops[0]), right=all_exprs[1]
                )
                for i, op in enumerate(ops[1:], 1):
                    cmp = Compare(
                        left=all_exprs[i],
                        op=self._map_cmp(ops[i]),
                        right=all_exprs[i + 1],
                    )
                    result = BoolAnd(left=result, right=cmp)
                return result
            case ast.IfExp(test=test, body=body, orelse=orelse):
                cond = self._visit_expr(test)
                if cond.type != BOOL:
                    self._err("ternary condition must be bool")
                then_expr = self._visit_expr(body)
                else_expr = self._visit_expr(orelse)
                if then_expr.type != else_expr.type:
                    self._err(
                        f"ternary branches must have the same type: {then_expr.type} vs {else_expr.type}"
                    )
                return IfExp(
                    condition=cond,
                    then_expr=then_expr,
                    else_expr=else_expr,
                    type=then_expr.type,
                )
            case ast.BoolOp(op=op, values=values):
                exprs = [self._visit_expr(v) for v in values]
                for e in exprs:
                    if e.type != BOOL:
                        self._err("'and'/'or' requires bool operands")
                result = exprs[0]
                if isinstance(op, ast.And):
                    for e in exprs[1:]:
                        result = BoolAnd(left=result, right=e)
                else:
                    for e in exprs[1:]:
                        result = BoolOr(left=result, right=e)
                return result
            case ast.UnaryOp(op=ast.Not(), operand=operand):
                expr = self._visit_expr(operand)
                if expr.type != BOOL:
                    self._err("'not' requires a bool operand")
                return Not(operand=expr)
            case ast.UnaryOp(op=ast.USub(), operand=operand):
                expr = self._visit_expr(operand)
                if expr.type != INT:
                    self._err("unary '-' requires an int operand")
                return Negate(operand=expr)
            case ast.UnaryOp(op=ast.Invert(), operand=operand):
                expr = self._visit_expr(operand)
                if expr.type != INT:
                    self._err("'~' requires an int operand")
                return Invert(operand=expr)
            case _:
                self._err(f"Unsupported expression: {ast.dump(node)}")

    def _visit_attribute_expr(self, node: "ast.Attribute") -> "Expr":
        """Handle attribute access: enum-constant folding, module statics, class vars, instance fields."""
        match node:
            case ast.Attribute(value=ast.Name(id=fo_name), attr=attr_name) if (
                fo_name in self._findoptions_names
            ):
                if attr_name not in _FIND_OPTIONS_VALUES:
                    self._err(f"FindOptions has no member '{attr_name}'")
                return IntLiteral(_FIND_OPTIONS_VALUES[attr_name])
            case ast.Attribute(value=ast.Name(id=cf_name), attr=attr_name) if (
                cf_name in self._callflags_names
            ):
                if attr_name not in _CALL_FLAGS_VALUES:
                    self._err(f"CallFlags has no member '{attr_name}'")
                return IntLiteral(_CALL_FLAGS_VALUES[attr_name])
            case ast.Attribute(value=ast.Name(id=nch_name), attr=attr_name) if (
                nch_name in self._namedcurvehash_names
            ):
                if attr_name not in _NAMED_CURVE_HASH_VALUES:
                    self._err(f"NamedCurveHash has no member '{attr_name}'")
                return IntLiteral(_NAMED_CURVE_HASH_VALUES[attr_name])
            # --- Module static read: abc.CONST ---
            case ast.Attribute(value=ast.Name(id=mod_name), attr=attr) if (
                self._module_names
                and mod_name in self._module_names
                and mod_name not in self._locals
                and mod_name not in self._args
                and mod_name not in self._statics
            ):
                _mangled_attr = self._module_fn_maps.get(mod_name, {}).get(attr, attr)
                if _mangled_attr in self._statics:
                    slot, _ = self._statics[_mangled_attr]
                    t = self._statics_current_types.get(
                        _mangled_attr, self._statics[_mangled_attr][1]
                    )
                    return StaticLoad(name=_mangled_attr, slot=slot, type=t)
                self._err(f"Unknown attribute '{attr}' in module '{mod_name}'")
            # --- Class variable read: ClassName.var ---
            case ast.Attribute(value=ast.Name(id=cname), attr=attr) if (
                self._class_registry and cname in self._class_registry
            ):
                info = self._class_registry[cname]
                if attr in info.class_vars:
                    slot, t = info.class_vars[attr]
                    return StaticLoad(name=f"{cname}.{attr}", slot=slot, type=t)
                self._err(f"Unknown class attribute '{attr}' on '{cname}'")
            # --- Instance field access: obj.field ---
            case ast.Attribute(value=obj_node, attr=attr):
                obj = self._visit_expr(obj_node)
                if isinstance(obj.type, ClassType) and self._class_registry:
                    info = self._class_registry.get(obj.type.name)
                    if info is not None:
                        if attr in info.fields:
                            fi = info.fields[attr]
                            return GetField(
                                obj=obj,
                                field_name=attr,
                                field_index=fi.index,
                                type=fi.type,
                            )
                        if attr in info.class_vars:
                            slot, t = info.class_vars[attr]
                            return StaticLoad(
                                name=f"{obj.type.name}.{attr}", slot=slot, type=t
                            )
                        self._err(f"Unknown field '{attr}' on class '{obj.type.name}'")
                self._err(f"Attribute access not supported on {obj.type}")
            case _:
                self._err(f"Unsupported expression: {ast.dump(node)}")

    def _visit_call(self, node: "ast.Call") -> "Expr":
        """Handle all call expressions: builtins, stdlib, syscalls, methods, constructors."""
        match node:
            case ast.Call(func=ast.Name(id="len"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if not isinstance(
                    arg.type,
                    (
                        BytesType,
                        BytearrayType,
                        StrType,
                        ListType,
                        DictType,
                        UInt160Type,
                        UInt256Type,
                        ECPointType,
                    ),
                ):
                    self._err(
                        "len() requires bytes, bytearray, str, list, or dict operand"
                    )
                return Len(arg)
            case ast.Call(func=ast.Name(id="bytearray"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if isinstance(arg.type, IntType):
                    return NewBuffer(arg)
                if not isinstance(
                    arg.type, (BoolType, StrType, BytesType, BytearrayType)
                ):
                    self._err(f"bytearray() cannot convert {arg.type}")
                return TypeConvert(arg=arg, type=BYTEARRAY)
            case ast.Call(func=ast.Name(id="abs"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if arg.type != INT:
                    self._err("abs() requires an int argument")
                return Abs(arg)
            case ast.Call(func=ast.Name(id="min"), args=[a_node, b_node]):
                a = self._visit_expr(a_node)
                b = self._visit_expr(b_node)
                if a.type != INT or b.type != INT:
                    self._err("min() requires int arguments")
                return Min(a, b)
            case ast.Call(func=ast.Name(id="max"), args=[a_node, b_node]):
                a = self._visit_expr(a_node)
                b = self._visit_expr(b_node)
                if a.type != INT or b.type != INT:
                    self._err("max() requires int arguments")
                return Max(a, b)
            case ast.Call(func=ast.Name(id="int"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if isinstance(arg.type, StrType):
                    # int("123") → atoi("123", 10)
                    return Atoi(arg=arg, base=IntLiteral(10))
                if not isinstance(
                    arg.type, (IntType, BoolType, BytesType, BytearrayType)
                ):
                    self._err(f"int() cannot convert {arg.type}")
                return TypeConvert(arg=arg, type=INT)
            case ast.Call(func=ast.Name(id="int"), args=[arg_node, base_node]):
                arg = self._visit_expr(arg_node)
                if not isinstance(arg.type, StrType):
                    self._err("int(x, base) is only supported when x is str")
                base = self._visit_expr(base_node)
                if not isinstance(base.type, IntType):
                    self._err("int(x, base) requires base to be int")
                self._check_atoi_base(base_node)
                return Atoi(arg=arg, base=base)
            case ast.Call(func=ast.Name(id="bool"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if not (arg.type.is_numeric() or arg.type.is_byteslike()):
                    self._err(f"bool() cannot convert {arg.type}")
                return TypeConvert(arg=arg, type=BOOL)
            case ast.Call(func=ast.Name(id="str"), args=[arg_node, base_node]):
                arg = self._visit_expr(arg_node)
                if not isinstance(arg.type, IntType):
                    self._err("str(x, base) requires x to be int")
                base = self._visit_expr(base_node)
                if not isinstance(base.type, IntType):
                    self._err("str(x, base) requires base to be int")
                self._check_atoi_base(base_node)
                return Itoa(arg=arg, base=base)
            case ast.Call(func=ast.Name(id="str"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if isinstance(arg.type, IntType):
                    # str(123) → itoa(123, 10) — decimal string, matching Python semantics
                    return Itoa(arg=arg, base=IntLiteral(10))
                if isinstance(arg.type, BoolType):
                    # str(True) → "True", str(False) → "False" — Python semantics via ternary
                    return IfExp(
                        condition=arg,
                        then_expr=StringLiteral("True"),
                        else_expr=StringLiteral("False"),
                        type=STR,
                    )
                if not arg.type.is_byteslike():
                    self._err(f"str() cannot convert {arg.type}")
                return TypeConvert(arg=arg, type=STR)
            case ast.Call(func=ast.Name(id="bytes"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if not (arg.type.is_numeric() or arg.type.is_byteslike()):
                    self._err(f"bytes() cannot convert {arg.type}")
                return TypeConvert(arg=arg, type=BYTES)
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id="UInt160"), attr="zero"), args=[]
            ):
                return TypeConvert(arg=BytesLiteral(b"\x00" * 20), type=UINT160)
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id="UInt256"), attr="zero"), args=[]
            ):
                return TypeConvert(arg=BytesLiteral(b"\x00" * 32), type=UINT256)
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id="UInt160"), attr="from_string"),
                args=[arg_node],
            ):
                arg = self._visit_expr(arg_node)
                if not isinstance(arg, StringLiteral):
                    self._err(
                        "UInt160.from_string() requires a string literal argument"
                    )
                return TypeConvert(
                    arg=BytesLiteral(UInt160.from_string(arg.value).to_array()),
                    type=UINT160,
                )
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id="UInt256"), attr="from_string"),
                args=[arg_node],
            ):
                arg = self._visit_expr(arg_node)
                if not isinstance(arg, StringLiteral):
                    self._err(
                        "UInt256.from_string() requires a string literal argument"
                    )
                return TypeConvert(
                    arg=BytesLiteral(UInt256.from_string(arg.value).to_array()),
                    type=UINT256,
                )
            case ast.Call(func=ast.Name(id="UInt160"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if not isinstance(arg.type, BytesType):
                    self._err(f"UInt160() requires bytes (got {arg.type})")
                if isinstance(arg, BytesLiteral) and len(arg.value) != 20:
                    self._err(
                        f"UInt160() requires exactly 20 bytes (got {len(arg.value)})"
                    )
                return TypeConvert(arg=arg, type=UINT160)
            case ast.Call(func=ast.Name(id="UInt256"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if not isinstance(arg.type, BytesType):
                    self._err(f"UInt256() requires bytes (got {arg.type})")
                if isinstance(arg, BytesLiteral) and len(arg.value) != 32:
                    self._err(
                        f"UInt256() requires exactly 32 bytes (got {len(arg.value)})"
                    )
                return TypeConvert(arg=arg, type=UINT256)
            case ast.Call(func=ast.Name(id="ECPoint"), args=[arg_node]):
                arg = self._visit_expr(arg_node)
                if not isinstance(arg.type, BytesType):
                    self._err(f"ECPoint() requires bytes (got {arg.type})")
                if isinstance(arg, BytesLiteral) and len(arg.value) != 33:
                    self._err(
                        f"ECPoint() requires exactly 33 bytes (got {len(arg.value)})"
                    )
                return TypeConvert(arg=arg, type=ECPOINT)
            case ast.Call(func=ast.Name(id="call_contract"), args=cc_args, keywords=[]):
                return self._build_call_contract(cc_args)
            case ast.Call(
                func=ast.Attribute(value=recv_node, attr="next"),
                args=[],
                keywords=[],
            ):
                recv = self._visit_expr(recv_node)
                if isinstance(recv.type, IteratorType):
                    return SyscallCall(
                        hash=_SYSCALL_ITERATOR_NEXT,
                        args=[recv],
                        push_order=[0],
                        type=BOOL,
                    )
            case ast.Call(
                func=ast.Attribute(value=recv_node, attr="value"),
                args=[],
                keywords=[],
            ):
                recv = self._visit_expr(recv_node)
                if isinstance(recv.type, IteratorType):
                    return SyscallCall(
                        hash=_SYSCALL_ITERATOR_VALUE,
                        args=[recv],
                        push_order=[0],
                        type=ANY,
                    )
            case ast.Call(func=ast.Name(id=name)) if name in self._event_fn_specs:
                self._err(
                    f"'{name}' is an event emitter and cannot be used as an expression"
                )

            case ast.Call(
                func=ast.Name(id=name), args=call_args, keywords=call_kwargs
            ) if (name in self._syscall_fn_specs):
                spec = self._syscall_fn_specs[name]
                if spec.ret == NONE:
                    self._err(f"'{name}()' is void and cannot be used as an expression")
                return self._build_syscall_from_spec(name, spec, call_args, call_kwargs)

            case ast.Call(
                func=ast.Attribute(value=ast.Name(id=mod_name), attr=fn_name),
                args=call_args,
                keywords=call_kwargs,
            ) if (
                mod_name in self._syscall_module_fn_specs
                and fn_name in self._syscall_module_fn_specs[mod_name]
            ):
                spec = self._syscall_module_fn_specs[mod_name][fn_name]
                if spec.ret == NONE:
                    self._err(
                        f"'{mod_name}.{fn_name}()' is void and cannot be used as an expression"
                    )
                return self._build_syscall_from_spec(
                    fn_name, spec, call_args, call_kwargs
                )
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id="bytes"), attr="fromhex"),
                args=[arg_node],
                keywords=[],
            ):
                arg = self._visit_expr(arg_node)
                if not isinstance(arg.type, StrType):
                    self._err(f"bytes.fromhex() argument must be str, got {arg.type}")
                return BytesFromHex(arg=arg)
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id="bytes"), attr="fromhex"),
                keywords=[],
            ):
                self._err(
                    f"bytes.fromhex() takes exactly 1 argument ({len(node.args)} given)"
                )
            case ast.Call(
                func=ast.Attribute(value=obj_node, attr="hex"),
                args=[],
                keywords=[],
            ):
                obj = self._visit_expr(obj_node)
                if not isinstance(obj.type, (BytesType, BytearrayType)):
                    self._err(f".hex() requires bytes or bytearray, got {obj.type}")
                return BytesHex(arg=obj)
            case ast.Call(
                func=ast.Attribute(value=obj_node, attr="to_array"),
                args=[],
                keywords=[],
            ):
                obj = self._visit_expr(obj_node)
                if not isinstance(obj.type, (UInt160Type, UInt256Type, ECPointType)):
                    self._err(
                        f".to_array() is only supported on UInt160, UInt256, and ECPoint"
                        f" (got {obj.type})"
                    )
                return TypeConvert(arg=obj, type=BYTES)
            case ast.Call(
                func=ast.Attribute(value=obj_node, attr="split"),
                args=args_nodes,
                keywords=kws,
            ):
                if kws:
                    self._err("str.split() does not accept keyword arguments")
                obj = self._visit_expr(obj_node)
                if not isinstance(obj.type, StrType):
                    self._err(f".split() requires str receiver, got {obj.type}")
                if len(args_nodes) == 0:
                    sep: Expr = StringLiteral(value="")
                    remove_empty = True
                elif len(args_nodes) == 1:
                    sep = self._visit_expr(args_nodes[0])
                    if not isinstance(sep.type, StrType):
                        self._err(f".split() separator must be str, got {sep.type}")
                    remove_empty = False
                else:
                    self._err(
                        "str.split() maxsplit parameter is not supported; "
                        "use s.split() or s.split(sep) only"
                    )
                return StrSplit(arg=obj, sep=sep, remove_empty=remove_empty)
            case ast.Call(
                func=ast.Attribute(value=obj_node, attr="to_bytes"),
                args=args_nodes,
                keywords=kws,
            ):
                return self._visit_to_bytes_call(obj_node, args_nodes, kws)
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id="int"), attr="from_bytes"),
                args=args_nodes,
                keywords=kws,
            ):
                return self._visit_from_bytes_call(args_nodes, kws)
            case ast.Call(func=ast.Name(id="isinstance"), args=[obj_node, type_node]):
                operand = self._visit_expr(obj_node)
                _ISTYPE_TAGS: dict[type, int] = {
                    IntType: 0x21,
                    BoolType: 0x20,
                    StrType: 0x28,
                    BytesType: 0x28,
                    BytearrayType: 0x30,
                }
                try:
                    target_type = self._resolve_annotation(type_node)
                except TypeError:
                    self._err(
                        "isinstance() type argument must be a concrete primitive type"
                    )
                tag = _ISTYPE_TAGS.get(type(target_type))
                if tag is None:
                    self._err(
                        f"isinstance() only supports int, bool, str, bytes, bytearray; got {target_type}"
                    )
                return IsType(operand=operand, tag=tag)
            case ast.Call(func=ast.Name(id="cast"), args=[type_node, val_node]):
                try:
                    target_type = self._resolve_annotation(type_node)
                except TypeError:
                    self._err("cast() type argument must be a valid type annotation")
                val = self._visit_expr(val_node)
                return Cast(arg=val, type=target_type)
            # --- super().method(args) ---
            case ast.Call(
                func=ast.Attribute(
                    value=ast.Call(func=ast.Name(id="super"), args=[]),
                    attr=meth_name,
                ),
                args=call_args,
                keywords=[],
            ) if (
                self._current_class and self._class_registry
            ):
                info = self._class_registry[self._current_class]
                if not info.class_mro:
                    self._err(
                        f"super() called in '{self._current_class}' which has no base class"
                    )
                parent_name = info.class_mro[0]
                parent_info = self._class_registry[parent_name]
                if meth_name not in parent_info.methods:
                    self._err(
                        f"super() has no method '{meth_name}' in parent '{parent_name}'"
                    )
                mi = parent_info.methods[meth_name]
                compiled_name = mi.compiled_name
                param_types, return_type = self._signatures[compiled_name]
                user_param_types = (
                    param_types[1:] if mi.kind == "instance" else param_types
                )
                if len(call_args) != len(user_param_types):
                    self._err(
                        f"super().{meth_name} takes {len(user_param_types)} args, got {len(call_args)}"
                    )
                visited_s: list[Expr] = []
                for i, (a_node, expected) in enumerate(
                    zip(call_args, user_param_types)
                ):
                    a = self._visit_expr(a_node)
                    if not _type_compatible(a.type, expected, self._class_registry):
                        self._err(
                            f"Arg {i} of 'super().{meth_name}': expected {expected}, got {a.type}"
                        )
                    visited_s.append(a)
                # Emit as MethodCall with 'self' loaded from args
                self_arg_name = self._fn_self_name()
                self_expr = LocalLoad(
                    name=self_arg_name, type=ClassType(self._current_class)
                )
                return MethodCall(
                    obj=self_expr,
                    compiled_name=compiled_name,
                    args=visited_s,
                    type=return_type,
                )

            # --- Module namespace call: abc.foo(args) or abc.MyClass(args) ---
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id=mod_name), attr=fn_name),
                args=call_args,
                keywords=[],
            ) if (
                self._module_names
                and mod_name in self._module_names
                and mod_name not in self._locals
                and mod_name not in self._args
                and mod_name not in self._statics
            ):
                # Delegate to existing plain-name dispatch (NewInstance or Call),
                # mapping fn_name through the module's mangle map first.
                _actual_fn = self._module_fn_maps.get(mod_name, {}).get(
                    fn_name, fn_name
                )
                self._name_display[_actual_fn] = f"{mod_name}.{fn_name}"
                new_call = ast.Call(
                    func=ast.Name(id=_actual_fn, ctx=ast.Load()),
                    args=call_args,
                    keywords=[],
                )
                ast.copy_location(new_call, node)
                return self._visit_expr(new_call)

            # --- Static/class method via class name: ClassName.method(args) ---
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id=cname), attr=meth_name),
                args=call_args,
                keywords=[],
            ) if (
                self._class_registry and cname in self._class_registry
            ):
                info = self._class_registry[cname]
                if meth_name not in info.methods:
                    self._err(f"Unknown method '{meth_name}' on class '{cname}'")
                mi = info.methods[meth_name]
                if mi.kind == "instance":
                    self._err(
                        f"Cannot call instance method '{meth_name}' on class '{cname}' without an instance"
                    )
                compiled_name = mi.compiled_name
                param_types, return_type = self._signatures[compiled_name]
                n_params = len(param_types)
                n_given = len(call_args)
                if n_given < n_params:
                    ast_defs = mi.ast_node.args.defaults  # right-aligned in Python AST
                    n_defs = len(ast_defs)
                    filled: list = list(call_args)
                    for i in range(n_given, n_params):
                        di = i - (n_params - n_defs)
                        if di < 0:
                            self._err(
                                f"'{cname}.{meth_name}' takes {n_params} args, got {n_given}"
                            )
                        filled.append(ast_defs[di])
                    call_args = filled
                elif n_given > n_params:
                    self._err(
                        f"'{cname}.{meth_name}' takes {n_params} args, got {n_given}"
                    )
                visited_c: list[Expr] = []
                for i, (a_node, expected) in enumerate(zip(call_args, param_types)):
                    a = self._visit_expr(a_node)
                    if not _type_compatible(a.type, expected, self._class_registry):
                        self._err(
                            f"Arg {i} of '{cname}.{meth_name}': expected {expected}, got {a.type}"
                        )
                    visited_c.append(a)
                # @contract class → emit System.Contract.Call instead of CALL_L
                if info.contract_hash is not None:
                    entry_point = (
                        mi.display_name if mi.display_name is not None else meth_name
                    )
                    return ContractCall(
                        contract_hash=info.contract_hash,
                        method=entry_point,
                        args=visited_c,
                        type=return_type,
                        call_flags=mi.call_flags,
                    )
                return Call(name=compiled_name, args=visited_c, type=return_type)

            # --- Instance method call: obj.method(args) ---
            case ast.Call(
                func=ast.Attribute(value=obj_node, attr=meth_name),
                args=call_args,
                keywords=[],
            ) if self._class_registry:
                obj = self._visit_expr(obj_node)
                if isinstance(obj.type, ClassType):
                    info = self._class_registry.get(obj.type.name)
                    if info is not None and meth_name in info.methods:
                        mi = info.methods[meth_name]
                        compiled_name = mi.compiled_name
                        param_types, return_type = self._signatures[compiled_name]
                        user_param_types = (
                            param_types[1:] if mi.kind == "instance" else param_types
                        )
                        if len(call_args) != len(user_param_types):
                            self._err(
                                f"'{meth_name}' takes {len(user_param_types)} args, got {len(call_args)}"
                            )
                        visited_m: list[Expr] = []
                        for i, (a_node, expected) in enumerate(
                            zip(call_args, user_param_types)
                        ):
                            a = self._visit_expr(a_node)
                            if not _type_compatible(
                                a.type, expected, self._class_registry
                            ):
                                self._err(
                                    f"Arg {i} of '{meth_name}': expected {expected}, got {a.type}"
                                )
                            visited_m.append(a)
                        return MethodCall(
                            obj=obj,
                            compiled_name=compiled_name,
                            args=visited_m,
                            type=return_type,
                        )
                # Fall through to dict .keys()/.values() or error
                if not isinstance(obj.type, DictType) or meth_name not in (
                    "keys",
                    "values",
                ):
                    self._err(f"Unknown method '{meth_name}' on {obj.type}")
                if call_args:
                    self._err(f"'{meth_name}' takes no arguments")
                if meth_name == "keys":
                    return DictKeys(container=obj, type=ListType(obj.type.key))
                return DictValues(container=obj, type=ListType(obj.type.val))

            case ast.Call(
                func=ast.Attribute(value=obj_node, attr=attr), args=[], keywords=[]
            ):
                obj = self._visit_expr(obj_node)
                if not isinstance(obj.type, DictType):
                    self._err(f"Unknown method '{attr}' on {obj.type}")
                match attr:
                    case "keys":
                        return DictKeys(container=obj, type=ListType(obj.type.key))
                    case "values":
                        return DictValues(container=obj, type=ListType(obj.type.val))
                    case _:
                        self._err(f"Unknown method '{attr}' on {obj.type}")

            # --- NewInstance: ClassName(args) ---
            case ast.Call(func=ast.Name(id=name), args=call_args) if (
                self._class_registry and name in self._class_registry
            ):
                info = self._class_registry[name]
                inst_type = ClassType(name)
                init_name = f"{name}___init__"
                if init_name in self._signatures:
                    param_types, _ = self._signatures[init_name]
                    # param_types[0] is self; user args start at 1
                    user_param_types = param_types[1:]
                    if len(call_args) != len(user_param_types):
                        self._err(
                            f"'{name}.__init__' takes {len(user_param_types)} args, got {len(call_args)}"
                        )
                    visited_n: list[Expr] = []
                    for i, (a_node, expected) in enumerate(
                        zip(call_args, user_param_types)
                    ):
                        a = self._visit_expr(a_node)
                        if not _type_compatible(a.type, expected, self._class_registry):
                            self._err(
                                f"Arg {i} of '{name}': expected {expected}, got {a.type}"
                            )
                        visited_n.append(a)
                else:
                    if call_args:
                        self._err(f"'{name}' takes no arguments (no __init__ defined)")
                    visited_n = []
                return NewInstance(
                    class_name=name,
                    args=visited_n,
                    type=inst_type,
                    temp_slot=self._alloc_temp(f"inst_{name}", inst_type),
                )

            # --- IntEnum constructor: FindOptions(x), CallFlags(x), NamedCurveHash(x) → int identity ---
            case ast.Call(func=ast.Name(id=name), args=[single_arg]) if name in (
                "FindOptions",
                "CallFlags",
                "NamedCurveHash",
            ):
                val = self._visit_expr(single_arg)
                if not _type_compatible(val.type, INT, self._class_registry):
                    self._err(f"'{name}(...)' expects an int argument, got {val.type}")
                return val if isinstance(val.type, IntType) else TypeConvert(val, INT)

            # --- cls(...) inside a classmethod → NewInstance ---
            case ast.Call(func=ast.Name(id=name), args=call_args) if (
                self._cls_alias and name == self._cls_alias and self._current_class
            ):
                return self._visit_expr(
                    ast.Call(
                        func=ast.Name(id=self._current_class),
                        args=call_args,
                        keywords=[],
                    )
                )

            case ast.Call(func=ast.Name(id=name), args=call_args):
                if name not in self._signatures:
                    self._err(f"Unknown function '{self._display(name)}'")
                param_types, return_type = self._signatures[name]
                defaults = self._func_defaults.get(name, {})
                num_required = len(param_types) - len(defaults)
                if len(call_args) < num_required:
                    self._err(
                        f"'{self._display(name)}' requires at least {num_required} args, got {len(call_args)}"
                    )
                if len(call_args) > len(param_types):
                    self._err(
                        f"'{self._display(name)}' takes at most {len(param_types)} args, got {len(call_args)}"
                    )
                visited: list[Expr] = []
                for i, expected in enumerate(param_types):
                    if i < len(call_args):
                        arg = self._visit_expr(call_args[i])
                    else:
                        arg = defaults[i]
                    if not _type_compatible(arg.type, expected, self._class_registry):
                        self._err(
                            f"Arg {i} of '{self._display(name)}': expected {expected}, got {arg.type}"
                        )
                    visited.append(arg)
                return Call(name=name, args=visited, type=return_type)
            case _:
                self._err(f"Unsupported expression: {ast.dump(node)}")

    def _visit_collection_or_subscript(self, node: "ast.expr") -> "Expr":
        """Handle subscript/indexing, collection literals, comprehensions, and f-strings."""
        match node:
            case ast.Subscript(value=v, slice=s):
                value = self._visit_expr(v)
                match s:
                    case ast.Slice(lower=lo, upper=hi, step=st):
                        if not value.type.is_byteslike():
                            self._err("slicing requires bytes, bytearray, or str")
                        step = None
                        if st is not None:
                            step = self._visit_expr(st)
                            if not isinstance(step.type, IntType):
                                self._err("slice step must be int")
                            if isinstance(step, Negate):
                                self._err("slice step must be positive")
                            if isinstance(step, IntLiteral) and step.value <= 0:
                                self._err("slice step must be positive")
                            if isinstance(step, IntLiteral) and step.value == 1:
                                step = None  # treat as no-step; use native opcodes
                        start = self._visit_expr(lo) if lo is not None else None
                        stop = self._visit_expr(hi) if hi is not None else None
                        for idx in [start, stop]:
                            if idx is not None and not isinstance(idx.type, IntType):
                                self._err("slice indices must be int")
                        step_slots = None
                        if step is not None:
                            step_slots = (
                                self._alloc_temp("data", value.type),
                                self._alloc_temp("start", INT),
                                self._alloc_temp("stop", INT),
                                self._alloc_temp("step", INT),
                                self._alloc_temp("count", INT),
                                self._alloc_temp("result", BYTEARRAY),
                                self._alloc_temp("write_idx", INT),
                                self._alloc_temp("read_idx", INT),
                            )
                        return Slice(
                            value=value,
                            start=start,
                            stop=stop,
                            step=step,
                            type=value.type,
                            step_slots=step_slots,
                        )
                    case _:
                        if isinstance(value.type, DictType):
                            key = self._visit_expr(s)
                            if key.type != value.type.key:
                                self._err(
                                    f"dict key type mismatch: expected {value.type.key}, got {key.type}"
                                )
                            return Index(value=value, index=key, type=value.type.val)
                        elif isinstance(value.type, ListType):
                            index = self._visit_expr(s)
                            if not isinstance(index.type, IntType):
                                self._err("list index must be int")
                            return Index(value=value, index=index, type=value.type.elem)
                        elif isinstance(value.type, StrType):
                            index = self._visit_expr(s)
                            if not isinstance(index.type, IntType):
                                self._err("str index must be int")
                            return StrIndex(value=value, index=index)
                        elif isinstance(value.type, (BytesType, BytearrayType)):
                            index = self._visit_expr(s)
                            if not isinstance(index.type, IntType):
                                self._err("index must be int")
                            return Index(value=value, index=index, type=INT)
                        elif isinstance(value.type, TupleType):
                            if not isinstance(s, ast.Constant) or not isinstance(
                                s.value, int
                            ):
                                self._err(
                                    "tuple indexing requires a compile-time integer constant"
                                )
                            i = s.value
                            if i < 0 or i >= len(value.type.elements):
                                self._err(
                                    f"tuple index {i} out of range for {value.type}"
                                )
                            return Index(
                                value=value,
                                index=IntLiteral(i),
                                type=value.type.elements[i],
                            )
                        else:
                            self._err(
                                "indexing requires str, bytes, bytearray, list[T], dict[K,V], or tuple[...]"
                            )
            case ast.List(elts=elts):
                if not elts:
                    # Placeholder type; fixed up in AnnAssign context
                    return ListLiteral(elements=[], type=ListType(INT))
                elements = [self._visit_expr(e) for e in elts]
                elem_t = elements[0].type
                for e in elements[1:]:
                    if e.type != elem_t:
                        elem_t = ANY
                        break
                return ListLiteral(elements=elements, type=ListType(elem_t))
            case ast.Tuple(elts=elts, ctx=ast.Load()):
                if not elts:
                    self._err("empty tuple literals are not supported")
                elements = [self._visit_expr(e) for e in elts]
                return TupleLiteral(
                    elements=elements,
                    type=TupleType(tuple(e.type for e in elements)),
                )
            case ast.Dict(keys=keys, values=values):
                if not keys:
                    # Placeholder type; fixed up in AnnAssign context
                    return DictLiteral(pairs=[], type=DictType(INT, INT))
                pairs_exprs = [
                    (self._visit_expr(k), self._visit_expr(v))
                    for k, v in zip(keys, values)
                ]
                key_t = pairs_exprs[0][0].type
                val_t = pairs_exprs[0][1].type
                _VALID_KEY_TYPES = (IntType, BoolType, BytesType, StrType)
                if not isinstance(key_t, _VALID_KEY_TYPES):
                    self._err(
                        f"dict key type must be int, bool, bytes, or str; got {key_t}"
                    )
                for k_expr, v_expr in pairs_exprs[1:]:
                    if k_expr.type != key_t:
                        self._err("dict literal keys must all be the same type")
                    if v_expr.type != val_t:
                        val_t = AnyType()
                return DictLiteral(pairs=pairs_exprs, type=DictType(key_t, val_t))
            case ast.ListComp(elt=elt_node, generators=generators):
                return self._desugar_list_comp(node, elt_node, generators)
            case ast.DictComp(key=key_node, value=val_node, generators=generators):
                return self._desugar_dict_comp(key_node, val_node, generators)
            case ast.JoinedStr(values=parts):
                return self._visit_fstring(node, parts)
            case _:
                self._err(f"Unsupported expression: {ast.dump(node)}")

    def _visit_expr(self, node: ast.expr) -> Expr:
        self._current_node = node
        node = self._resolve_aliases_in_expr(node)
        match node:
            case ast.Constant() | ast.Name():
                return self._visit_atom(node)
            case (
                ast.BinOp() | ast.UnaryOp() | ast.Compare() | ast.BoolOp() | ast.IfExp()
            ):
                return self._visit_operator_expr(node)
            case ast.Call():
                return self._visit_call(node)
            case ast.Attribute():
                return self._visit_attribute_expr(node)
            case (
                ast.Subscript()
                | ast.List()
                | ast.Tuple()
                | ast.Dict()
                | ast.ListComp()
                | ast.DictComp()
                | ast.JoinedStr()
            ):
                return self._visit_collection_or_subscript(node)
            case _:
                self._err(f"Unsupported expression: {ast.dump(node)}")

    def _visit_fstring(self, node: ast.JoinedStr, parts: list) -> "Expr":
        exprs: list = []
        for part in parts:
            match part:
                case ast.Constant(value=str() as s):
                    if s:
                        exprs.append(StringLiteral(s))
                case ast.FormattedValue(
                    value=val_node, conversion=conv, format_spec=spec
                ):
                    if spec is not None:
                        self._err("f-string format specs are not supported")
                    if conv not in (-1, 115):
                        self._err("f-string !r and !a conversions are not supported")
                    val = self._visit_expr(val_node)
                    if isinstance(val.type, StrType):
                        exprs.append(val)
                    elif isinstance(val.type, IntType):
                        exprs.append(Itoa(arg=val, base=IntLiteral(10)))
                    elif isinstance(val.type, BoolType):
                        exprs.append(
                            IfExp(
                                condition=val,
                                then_expr=StringLiteral("True"),
                                else_expr=StringLiteral("False"),
                                type=STR,
                            )
                        )
                    else:
                        self._err(
                            f"f-string: cannot interpolate type {val.type}; "
                            f"use .hex() or an explicit str() conversion"
                        )
        if not exprs:
            return StringLiteral("")
        result = exprs[0]
        for e in exprs[1:]:
            result = BinOp(left=result, op="cat", right=e, type=STR)
        return result

    def _map_binop(self, op: ast.operator) -> str:
        match op:
            case ast.Add():
                return "+"
            case ast.Sub():
                return "-"
            case ast.Mult():
                return "*"
            case ast.FloorDiv():
                return "//"
            case ast.Mod():
                return "%"
            case ast.Pow():
                return "**"
            case ast.BitAnd():
                return "&"
            case ast.BitOr():
                return "|"
            case ast.BitXor():
                return "^"
            case ast.LShift():
                return "<<"
            case ast.RShift():
                return ">>"
            case _:
                self._err(f"Unsupported operator: {op}")

    def _map_cmp(self, op: ast.cmpop) -> str:
        match op:
            case ast.Eq():
                return "=="
            case ast.NotEq():
                return "!="
            case ast.Lt():
                return "<"
            case ast.LtE():
                return "<="
            case ast.Gt():
                return ">"
            case ast.GtE():
                return ">="
            case _:
                self._err(f"Unsupported comparison: {op}")


def _is_public_decorator(
    d: ast.expr,
    ct_names: set[str],
    ct_modules: set[str],
) -> bool:
    """Return True if decorator *d* resolves to the @public from compiler.sc.compiletime."""
    if isinstance(d, ast.Name):
        return d.id in ct_names
    if isinstance(d, ast.Attribute) and d.attr == "public":
        return isinstance(d.value, ast.Name) and d.value.id in ct_modules
    if isinstance(d, ast.Call):
        f = d.func
        if isinstance(f, ast.Name):
            return f.id in ct_names
        if isinstance(f, ast.Attribute) and f.attr == "public":
            return isinstance(f.value, ast.Name) and f.value.id in ct_modules
    return False


def _extract_public_params(d: ast.expr) -> tuple[Optional[str], bool]:
    """Return (alias_name, safe) from @public or @public(name=..., safe=...)."""
    if not isinstance(d, ast.Call):
        return None, False
    alias: Optional[str] = None
    safe = False
    for kw in d.keywords:
        if (
            kw.arg == "name"
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, str)
        ):
            alias = kw.value.value
        elif kw.arg == "safe" and isinstance(kw.value, ast.Constant):
            safe = bool(kw.value.value)
    return alias, safe


def _is_event_decorator(
    d: ast.expr, event_names: set[str], ct_modules: set[str]
) -> bool:
    """True if decorator *d* resolves to @event from compiler.sc.compiletime."""
    if isinstance(d, ast.Call):
        f = d.func
        if isinstance(f, ast.Name):
            return f.id in event_names
        if isinstance(f, ast.Attribute) and f.attr == "event":
            return isinstance(f.value, ast.Name) and f.value.id in ct_modules
    return False


def _extract_event_info(
    d: ast.expr,
    fn: ast.FunctionDef,
    class_registry: dict,
    filename: Optional[str],
    extra_names: dict,
    module_fn_maps: Optional[dict[str, dict[str, str]]] = None,
    module_names: Optional[set] = None,
) -> "_EventInfo":
    """Parse @event(name=..., rename=[...]) and the decorated function's signature."""
    assert isinstance(d, ast.Call)
    event_name: Optional[str] = None
    rename_map: dict[str, str] = {}
    if (
        d.args
        and isinstance(d.args[0], ast.Constant)
        and isinstance(d.args[0].value, str)
    ):
        event_name = d.args[0].value
    for kw in d.keywords:
        if (
            kw.arg == "name"
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, str)
        ):
            event_name = kw.value.value
        elif kw.arg == "rename" and isinstance(kw.value, ast.List):
            for elt in kw.value.elts:
                if (
                    isinstance(elt, (ast.Tuple, ast.List))
                    and len(elt.elts) == 2
                    and isinstance(elt.elts[0], ast.Constant)
                    and isinstance(elt.elts[1], ast.Constant)
                ):
                    rename_map[elt.elts[0].value] = elt.elts[1].value
                else:
                    raise TypecheckError(
                        "@event rename entries must be (str, str) tuple literals",
                        lineno=elt.lineno,
                        col_offset=elt.col_offset,
                        filename=filename,
                    )
    if event_name is None:
        raise TypecheckError(
            f"@event on '{fn.name}' requires a name= keyword argument",
            lineno=fn.lineno,
            col_offset=fn.col_offset,
            filename=filename,
        )

    params: list[tuple[str, Type]] = []
    for arg in fn.args.args:
        if arg.annotation is None:
            raise TypecheckError(
                f"@event '{fn.name}': argument '{arg.arg}' missing type annotation",
                lineno=arg.lineno,
                col_offset=arg.col_offset,
                filename=filename,
            )
        t = resolve_annotation(
            arg.annotation,
            class_registry,
            extra_names=extra_names,
            filename=filename,
            module_fn_maps=module_fn_maps,
            module_names=module_names,
        )
        # Keep the original type (including Optional) for call-site type checking.
        # _type_to_contract_param strips Optional when generating the manifest.
        abi_name = rename_map.get(arg.arg, arg.arg)
        params.append((abi_name, t))
    return _EventInfo(fn_name=fn.name, event_name=event_name, params=params)


def _literal_to_hir_expr(node: ast.expr, filename: Optional[str] = None) -> "Expr":
    """Convert a constant AST node to a typed HIR expression.
    Only accepts plain literals and known IntFlag attribute accesses (FindOptions,
    CallFlags, NamedCurveHash); raises TypecheckError otherwise."""
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "CallFlags"
        and node.attr in _CALL_FLAGS_VALUES
    ):
        return IntLiteral(_CALL_FLAGS_VALUES[node.attr])
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "NamedCurveHash"
        and node.attr in _NAMED_CURVE_HASH_VALUES
    ):
        return IntLiteral(_NAMED_CURVE_HASH_VALUES[node.attr])
    if isinstance(node, (ast.Tuple, ast.List)) and not node.elts:
        return ListLiteral([], type=ListType(ANY))
    if not isinstance(node, ast.Constant):
        raise TypecheckError(
            "default argument must be a constant literal (int, bool, str, bytes, or None)",
            lineno=getattr(node, "lineno", None),
            col_offset=getattr(node, "col_offset", None),
            filename=filename,
        )
    v = node.value
    if v is None:
        return NoneLiteral()
    if isinstance(v, bool):
        return BoolLiteral(v)
    if isinstance(v, int):
        return IntLiteral(v)
    if isinstance(v, str):
        return StringLiteral(v)
    if isinstance(v, bytes):
        return BytesLiteral(v)
    raise TypecheckError(
        f"unsupported default literal type: {type(v).__name__}",
        lineno=getattr(node, "lineno", None),
        col_offset=getattr(node, "col_offset", None),
        filename=filename,
    )


def _extract_display_name(
    fn_node: ast.FunctionDef, dn_names: set[str], filename: Optional[str] = None
) -> Optional[str]:
    """Return the string argument of @display_name("name") if present, else None.
    Raises TypecheckError if @display_name is present but malformed."""
    for d in fn_node.decorator_list:
        is_call = (
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Name)
            and d.func.id in dn_names
        )
        is_bare = isinstance(d, ast.Name) and d.id in dn_names
        if is_bare:
            raise TypecheckError(
                "@display_name requires a string argument, e.g. @display_name('methodName')",
                lineno=d.lineno,
                col_offset=d.col_offset,
                filename=filename,
            )
        if is_call:
            call = d
            if (
                len(call.args) == 1
                and not call.keywords
                and isinstance(call.args[0], ast.Constant)
                and isinstance(call.args[0].value, str)
            ):
                return call.args[0].value
            raise TypecheckError(
                "@display_name requires exactly one string literal argument, "
                "e.g. @display_name('methodName')",
                lineno=call.lineno,
                col_offset=call.col_offset,
                filename=filename,
            )
    return None


def _has_display_name_decorator(fn_node: ast.FunctionDef, dn_names: set[str]) -> bool:
    """Return True if any decorator resolves to @display_name."""
    for d in fn_node.decorator_list:
        if isinstance(d, ast.Name) and d.id in dn_names:
            return True
        if (
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Name)
            and d.func.id in dn_names
        ):
            return True
    return False


def _extract_call_flags_dec(
    fn_node: ast.FunctionDef, cf_dec_names: set[str], filename: Optional[str] = None
) -> Optional[int]:
    """Return the integer CallFlags value from @call_flags(X) if present, else None.
    Accepts an integer literal or a CallFlags.<ATTR> attribute access.
    Raises TypecheckError if the decorator is present but malformed."""
    for d in fn_node.decorator_list:
        is_call = (
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Name)
            and d.func.id in cf_dec_names
        )
        if not is_call:
            continue
        call = d
        if len(call.args) != 1 or call.keywords:
            raise TypecheckError(
                "@call_flags requires exactly one argument, e.g. @call_flags(CallFlags.READ_STATES)",
                lineno=call.lineno,
                col_offset=call.col_offset,
                filename=filename,
            )
        arg = call.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
            return arg.value
        if (
            isinstance(arg, ast.Attribute)
            and isinstance(arg.value, ast.Name)
            and arg.attr in _CALL_FLAGS_VALUES
        ):
            return _CALL_FLAGS_VALUES[arg.attr]
        raise TypecheckError(
            "@call_flags argument must be an integer literal or CallFlags.<ATTR>",
            lineno=call.lineno,
            col_offset=call.col_offset,
            filename=filename,
        )
    return None


def _is_contract_decorator(
    d: ast.expr,
    ct_names: set[str],
    ct_modules: set[str],
) -> bool:
    """Return True if decorator *d* resolves to @contract from compiler.sc.compiletime."""
    if isinstance(d, ast.Call):
        f = d.func
        if isinstance(f, ast.Name):
            return f.id in ct_names
        if isinstance(f, ast.Attribute) and f.attr == "contract":
            return isinstance(f.value, ast.Name) and f.value.id in ct_modules
    return False


def _extract_contract_hash(d: ast.expr, filename: Optional[str] = None) -> bytes:
    """Extract the 20-byte LE contract hash from @contract("0x...") decorator."""
    assert isinstance(d, ast.Call) and d.args
    arg = d.args[0]
    if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
        raise TypecheckError(
            "@contract requires a string literal script hash argument",
            lineno=getattr(d, "lineno", None),
            col_offset=getattr(d, "col_offset", None),
            filename=filename,
        )
    return UInt160.from_string(arg.value).to_array()


def _build_class_registry(
    tree: ast.Module,
    statics: dict[str, tuple[int, Type]],
    ct_names: Optional[set[str]] = None,
    ct_modules: Optional[set[str]] = None,
    dn_names: Optional[set[str]] = None,
    cf_dec_names: Optional[set[str]] = None,
    filename: Optional[str] = None,
    module_fn_maps: Optional[dict[str, dict[str, str]]] = None,
    module_names: Optional[set] = None,
) -> tuple[
    dict[str, ClassInfo], dict[str, tuple[int, Type]], list[tuple[int, Type, ast.expr]]
]:
    """Scan all ClassDef nodes in tree.body, build the registry, and extend statics
    with any class variables discovered.
    Returns (registry, updated_statics, class_var_inits) where class_var_inits has the
    same shape as static_inits: (slot, type, raw_ast_value)."""
    _ct_names = ct_names or set()
    _ct_modules = ct_modules or set()
    _dn_names = dn_names or set()
    _cf_dec_names = cf_dec_names or set()
    registry: dict[str, ClassInfo] = {}
    statics = dict(statics)  # work on a copy
    class_var_inits: list[tuple[int, Type, ast.expr]] = []

    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue

        cname = node.name
        display_name = getattr(node, "_original_name", cname)

        # Reject nested ClassDef anywhere inside class body
        for item in ast.walk(node):
            if item is node:
                continue
            if isinstance(item, ast.ClassDef):
                raise TypecheckError(
                    "nested class definitions are not supported",
                    lineno=item.lineno,
                    col_offset=item.col_offset,
                    filename=filename,
                )

        # Resolve base names
        bases: list[str] = []
        for base_node in node.bases:
            if not isinstance(base_node, ast.Name):
                raise TypecheckError(
                    f"Class '{display_name}': base class must be a simple name, got {ast.dump(base_node)}",
                    lineno=base_node.lineno,
                    col_offset=base_node.col_offset,
                    filename=filename,
                )
            bname = base_node.id
            if bname not in registry:
                raise TypecheckError(
                    f"Class '{display_name}': base class '{bname}' not yet defined "
                    f"(forward references not supported)",
                    lineno=base_node.lineno,
                    col_offset=base_node.col_offset,
                    filename=filename,
                )
            bases.append(bname)

        class_mro = _c3_mro(
            cname,
            bases,
            registry,
            lineno=node.lineno,
            col_offset=node.col_offset,
            filename=filename,
        )

        # Detect @contract decorator
        contract_hash: Optional[bytes] = None
        for dec in node.decorator_list:
            if _is_contract_decorator(dec, _ct_names, _ct_modules):
                contract_hash = _extract_contract_hash(dec, filename=filename)
                break

        if contract_hash is not None:
            # --- @contract interface class ---
            # Collect only @staticmethod methods; reject anything else.
            # Field annotations (e.g. `hash: UInt160`) are silently ignored.
            methods_own: dict[str, MethodInfo] = {}
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    kind = _get_method_kind(item)
                    if kind != "static":
                        raise TypecheckError(
                            f"@contract class '{display_name}': only @staticmethod methods are allowed, "
                            f"got '{item.name}' with kind '{kind}'",
                            lineno=item.lineno,
                            col_offset=item.col_offset,
                            filename=filename,
                        )
                    # Validate body: only pass statements and docstrings allowed
                    for stmt in item.body:
                        if isinstance(stmt, (ast.Pass, ast.Expr)):
                            continue
                        raise TypecheckError(
                            f"@contract class '{display_name}': method '{item.name}' body must be "
                            f"'pass' only (no implementation)",
                            lineno=stmt.lineno,
                            col_offset=stmt.col_offset,
                            filename=filename,
                        )
                    mname = item.name
                    compiled_name = f"{cname}_{mname}"
                    dn = _extract_display_name(item, _dn_names, filename=filename)
                    cf_val = _extract_call_flags_dec(
                        item, _cf_dec_names, filename=filename
                    )
                    methods_own[mname] = MethodInfo(
                        name=mname,
                        compiled_name=compiled_name,
                        kind=kind,
                        ast_node=item,
                        display_name=dn,
                        call_flags=cf_val if cf_val is not None else 15,
                    )
                elif isinstance(item, (ast.AnnAssign, ast.Pass, ast.Expr)):
                    pass  # field annotations (hash: UInt160), docstrings, pass — all ignored
                else:
                    raise TypecheckError(
                        f"@contract class '{display_name}': only @staticmethod methods are allowed",
                        lineno=item.lineno,
                        col_offset=item.col_offset,
                        filename=filename,
                    )
            registry[cname] = ClassInfo(
                name=cname,
                bases=bases,
                class_mro=class_mro,
                fields={},
                methods=methods_own,
                class_vars={},
                total_fields=0,
                ast_node=node,
                contract_hash=contract_hash,
            )
            continue

        # --- Regular class ---
        # Scan class body for methods and class variables
        methods_own: dict[str, MethodInfo] = {}
        class_vars: dict[str, tuple[int, Type]] = {}

        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                if _dn_names and _has_display_name_decorator(item, _dn_names):
                    raise TypecheckError(
                        f"@display_name can only be used in @contract classes, "
                        f"found on '{item.name}' in class '{display_name}'",
                        lineno=item.lineno,
                        col_offset=item.col_offset,
                        filename=filename,
                    )
                kind = _get_method_kind(item)
                mname = item.name
                compiled_name = f"{cname}_{mname}"
                methods_own[mname] = MethodInfo(
                    name=mname,
                    compiled_name=compiled_name,
                    kind=kind,
                    ast_node=item,
                )
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                varname = item.target.id
                vartype = resolve_annotation(
                    item.annotation,
                    registry,
                    filename=getattr(node, "_src_file", filename),
                    module_fn_maps=module_fn_maps,
                    module_names=module_names,
                )
                slot = len(statics)
                statics[f"{cname}.{varname}"] = (slot, vartype)
                class_vars[varname] = (slot, vartype)
                if item.value is not None:
                    class_var_inits.append((slot, vartype, item.value))
            elif (
                isinstance(item, ast.Assign)
                and len(item.targets) == 1
                and isinstance(item.targets[0], ast.Name)
                and item.value is not None
            ):
                # Unannotated class variable: infer type from the value.
                varname = item.targets[0].id
                vartype: Optional[Type] = _infer_type_from_ast_expr(
                    item.value, statics, registry
                )
                if vartype is None:
                    raise TypecheckError(
                        f"Class '{display_name}': cannot infer type of class variable '{varname}' "
                        f"from assignment; add a type annotation: '{varname}: <type> = ...'",
                        lineno=item.lineno,
                        col_offset=item.col_offset,
                        filename=filename,
                    )
                slot = len(statics)
                statics[f"{cname}.{varname}"] = (slot, vartype)
                class_vars[varname] = (slot, vartype)
                class_var_inits.append((slot, vartype, item.value))
            elif isinstance(item, (ast.Pass, ast.Expr)):
                pass  # docstrings, pass statements

        # Discover own instance fields from __init__ body
        own_fields: dict[str, Type] = {}
        init_fn = methods_own.get("__init__")
        if init_fn is not None:
            src_file = getattr(node, "_src_file", filename)
            for stmt in ast.walk(init_fn.ast_node):
                if isinstance(stmt, ast.AnnAssign):
                    tgt = stmt.target
                    if (
                        isinstance(tgt, ast.Attribute)
                        and isinstance(tgt.value, ast.Name)
                        and tgt.value.id == "self"
                        and tgt.attr not in own_fields
                    ):
                        ftype = resolve_annotation(
                            stmt.annotation,
                            registry,
                            filename=src_file,
                            module_fn_maps=module_fn_maps,
                            module_names=module_names,
                        )
                        own_fields[tgt.attr] = ftype
                elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    tgt = stmt.targets[0]
                    if (
                        isinstance(tgt, ast.Attribute)
                        and isinstance(tgt.value, ast.Name)
                        and tgt.value.id == "self"
                        and tgt.attr not in own_fields
                    ):
                        inferred = _infer_type_from_ast_expr(
                            stmt.value, statics, registry
                        )
                        if inferred is None:
                            raise TypecheckError(
                                f"Class '{display_name}': cannot infer type of field '{tgt.attr}' "
                                f"from assignment; add a type annotation: "
                                f"'self.{tgt.attr}: <type> = ...'",
                                lineno=stmt.lineno,
                                col_offset=stmt.col_offset,
                                filename=src_file,
                            )
                        own_fields[tgt.attr] = inferred

        # Merge field layouts
        fields = _merge_fields(
            cname,
            class_mro,
            own_fields,
            registry,
            lineno=node.lineno,
            col_offset=node.col_offset,
            filename=filename,
        )

        # Merge methods: start from inherited (MRO order), overlay own
        merged_methods: dict[str, MethodInfo] = {}
        for ancestor in reversed(class_mro):
            for mname, mi in registry[ancestor].methods.items():
                merged_methods[mname] = mi
        for mname, mi in methods_own.items():
            merged_methods[mname] = mi

        # Inherit class_vars from ancestors
        merged_class_vars: dict[str, tuple[int, Type]] = {}
        for ancestor in reversed(class_mro):
            merged_class_vars.update(registry[ancestor].class_vars)
        merged_class_vars.update(class_vars)

        registry[cname] = ClassInfo(
            name=cname,
            bases=bases,
            class_mro=class_mro,
            fields=fields,
            methods=merged_methods,
            class_vars=merged_class_vars,
            total_fields=len(fields),
            ast_node=node,
        )

    return registry, statics, class_var_inits


def _stmt_name(stmt: ast.stmt) -> Optional[str]:
    """Return the top-level name defined by a statement, or None."""
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return stmt.name
    if isinstance(stmt, ast.ClassDef):
        return stmt.name
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    return None


def _mangle_prefix(abs_path: str, search_path: str) -> str:
    """Compute a unique mangle prefix for an imported module based on its path.

    Example: search_path=/project, abs_path=/project/usecase/user.py → "usecase_user_"
    """
    rel = os.path.relpath(abs_path, search_path)
    stem = os.path.splitext(rel)[0]
    prefix = (
        stem.replace(os.sep, "_").replace("/", "_").replace("-", "_").replace(".", "_")
    )
    return prefix + "_"


def _collect_local_names(fn: ast.FunctionDef) -> set[str]:
    """Return all names locally defined in a function: args + Store-context assignments."""
    names: set[str] = set()
    all_args = (
        list(fn.args.args)
        + list(getattr(fn.args, "posonlyargs", []))
        + list(fn.args.kwonlyargs)
    )
    if fn.args.vararg:
        all_args.append(fn.args.vararg)
    if fn.args.kwarg:
        all_args.append(fn.args.kwarg)
    for arg in all_args:
        names.add(arg.arg)
    for stmt in fn.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
    return names


class _MangleTransformer(ast.NodeTransformer):
    """Rewrite Name-node references (Load context) according to a mangle_map.

    Used to update all call sites, type annotations, isinstance checks, and
    inheritance bases within a module body after its top-level names are mangled.
    Assignment *targets* are intentionally left to the caller so that local
    variables inside functions are not confused with module-level definitions.
    """

    def __init__(self, mangle_map: dict[str, str]) -> None:
        self._map = mangle_map

    def visit_Name(self, node: ast.Name) -> ast.Name:
        if isinstance(node.ctx, ast.Load) and node.id in self._map:
            new_node = ast.Name(id=self._map[node.id], ctx=node.ctx)
            ast.copy_location(new_node, node)
            return new_node
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # Local variables and args shadow module-level names — don't mangle them.
        local_names = _collect_local_names(node)
        excluded = local_names & set(self._map)
        if not excluded:
            return self.generic_visit(node)
        child_map = {k: v for k, v in self._map.items() if k not in excluded}
        child = _MangleTransformer(child_map)
        new_node = ast.FunctionDef(
            name=node.name,
            args=self.visit(node.args),  # annotations reference module-level types
            body=[child.visit(s) for s in node.body],
            decorator_list=[self.visit(d) for d in node.decorator_list],
            returns=self.visit(node.returns) if node.returns else node.returns,
        )
        ast.copy_location(new_node, node)
        return new_node


def _mangle_module_body(
    body: list[ast.stmt], mangle_map: dict[str, str]
) -> list[ast.stmt]:
    """Apply mangle_map to the definition names and all Load-context references.

    Returns a new list of statements with:
    - FunctionDef/ClassDef/AnnAssign definition names renamed via mangle_map
    - Every Name(ctx=Load) whose id is in mangle_map rewritten (call sites,
      annotations, isinstance args, base classes, etc.)
    """
    transformer = _MangleTransformer(mangle_map)
    result = []
    for stmt in body:
        stmt = transformer.visit(stmt)
        # Rename top-level definition names (the *definition* node itself carries
        # the name as a str attribute, not an ast.Name, so the transformer above
        # won't touch it — we rename explicitly here).
        if isinstance(stmt, ast.FunctionDef) and stmt.name in mangle_map:
            stmt = _rename_function(stmt, mangle_map[stmt.name])
        elif isinstance(stmt, ast.ClassDef) and stmt.name in mangle_map:
            orig_cls = stmt
            stmt = ast.ClassDef(
                name=mangle_map[orig_cls.name],
                bases=orig_cls.bases,
                keywords=orig_cls.keywords,
                body=orig_cls.body,
                decorator_list=orig_cls.decorator_list,
            )
            ast.copy_location(stmt, orig_cls)
            stmt._original_name = orig_cls.name  # type: ignore[attr-defined]
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id in mangle_map
        ):
            orig_ann = stmt
            new_tgt = ast.Name(id=mangle_map[orig_ann.target.id], ctx=ast.Store())
            ast.copy_location(new_tgt, orig_ann.target)
            stmt = ast.AnnAssign(
                target=new_tgt,
                annotation=orig_ann.annotation,
                value=orig_ann.value,
                simple=orig_ann.simple,
            )
            ast.copy_location(stmt, orig_ann)
        result.append(stmt)
    return result


def _rename_function(node: ast.FunctionDef, new_name: str) -> ast.FunctionDef:
    """Return a shallow copy of a FunctionDef with a different name."""
    renamed = ast.FunctionDef(
        name=new_name,
        args=node.args,
        body=node.body,
        decorator_list=node.decorator_list,
        returns=node.returns,
        type_comment=getattr(node, "type_comment", None),
    )
    ast.copy_location(renamed, node)
    return renamed


def _load_module_stmts(
    module_path: str,
    module_key: str,
    search_path: str,
    seen: set[str],
    included: set[str],
    ct_names: Optional[set[str]] = None,
    ct_modules: Optional[set[str]] = None,
    event_names: Optional[set[str]] = None,
    dn_names: Optional[set[str]] = None,
    cf_dec_names: Optional[set[str]] = None,
    imported_builtin_classes: Optional[set[str]] = None,
    iterator_names: Optional[set[str]] = None,
    findoptions_names: Optional[set[str]] = None,
    callflags_names: Optional[set[str]] = None,
    namedcurvehash_names: Optional[set[str]] = None,
    syscall_fn_specs: Optional[dict[str, "_SyscallSpec"]] = None,
    syscall_module_fn_specs: Optional[dict[str, "dict[str, _SyscallSpec]"]] = None,
    caller_lineno: Optional[int] = None,
    caller_col_offset: Optional[int] = None,
    caller_filename: Optional[str] = None,
    stmts_registry: Optional[dict[str, list[ast.stmt]]] = None,
    mangle_registry: Optional[dict[str, dict[str, str]]] = None,
) -> tuple[list[ast.stmt], dict[str, dict[str, str]], set[str]]:
    """
    Load and parse the Python file at *module_path*, recursively resolve any
    imports it contains, and return the merged list of non-import top-level
    statements (with top-level names mangled to avoid cross-module collisions).

    *module_key* is the logical name used for circular-import detection.
    *seen*     tracks modules currently on the call stack (for cycle detection).
    *included* tracks modules whose stmts have already been added (for dedup).
    *stmts_registry* maps abs_path → UNMANGLED merged stmts for lookup/validation.
    *mangle_registry* maps abs_path → {original_name: mangled_name}; shared and
    mutated so callers can recover the mapping for alias registration.
    """
    if stmts_registry is None:
        stmts_registry = {}
    if mangle_registry is None:
        mangle_registry = {}
    if module_key in seen:
        raise TypecheckError(
            f"Circular import detected: '{module_key}'",
            lineno=caller_lineno,
            col_offset=caller_col_offset,
            filename=caller_filename,
        )
    if not os.path.isfile(module_path):
        raise TypecheckError(
            f"Module not found: '{module_key}' (looked for '{module_path}')",
            lineno=caller_lineno,
            col_offset=caller_col_offset,
            filename=caller_filename,
        )
    abs_path = os.path.abspath(module_path)
    if abs_path in included:
        return [], {}, set()  # already bundled by a prior import — skip
    included.add(abs_path)

    seen = seen | {module_key}  # immutable so siblings don't share the guard
    with open(module_path) as f:
        source = f.read()
    tree = ast.parse(source)

    import_nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    body = [n for n in tree.body if not isinstance(n, (ast.Import, ast.ImportFrom))]

    mod_dir = os.path.dirname(abs_path)
    extra, _mod_names, _aliases, _mm_inner, _mfm_inner = _resolve_imports(
        import_nodes,
        mod_dir,
        seen,
        included,
        ct_names=ct_names,
        ct_modules=ct_modules,
        event_names=event_names,
        dn_names=dn_names,
        cf_dec_names=cf_dec_names,
        imported_builtin_classes=imported_builtin_classes,
        iterator_names=iterator_names,
        findoptions_names=findoptions_names,
        callflags_names=callflags_names,
        namedcurvehash_names=namedcurvehash_names,
        syscall_fn_specs=syscall_fn_specs,
        syscall_module_fn_specs=syscall_module_fn_specs,
        filename=abs_path,
        root_path=search_path,
        stmts_registry=stmts_registry,
        mangle_registry=mangle_registry,
    )
    # Merge any mangle entries discovered by sub-imports into the shared registry.
    mangle_registry.update(_mm_inner)

    # Store UNMANGLED stmts in the registry so that alias-validation lookups for
    # already-bundled modules still find names by their original (pre-mangle) names.
    stmts_registry[abs_path] = extra + body

    # Build mangle_map for this module's own top-level definitions.
    prefix = _mangle_prefix(abs_path, search_path)
    local_names = {_stmt_name(s) for s in body if _stmt_name(s) is not None}
    mangle_map: dict[str, str] = {n: prefix + n for n in local_names}
    # Also include names imported by this module (_aliases) so that re-exports
    # from __init__.py files are visible to callers.  Own definitions take
    # precedence (mangle_map is the right operand and wins on key collision).
    mangle_registry[abs_path] = {**_aliases, **mangle_map}

    # Body rewrite map: own names + imported names (so calls inside function bodies
    # that reference imported names get rewritten to their mangled names too).
    body_mangle_map = {**_aliases, **mangle_map}

    # Apply mangling: rewrite definition names and all Load-context references.
    mangled_body = _mangle_module_body(body, body_mangle_map)

    all_stmts = extra + mangled_body
    # Tag each top-level stmt with the source file it came from so _compile_full
    # can pass the right filename to HIRBuilder when compiling each function.
    for stmt in all_stmts:
        if not hasattr(stmt, "_src_file"):
            stmt._src_file = abs_path
        # Propagate into class bodies so inner FunctionDef nodes also carry the right file.
        if isinstance(stmt, ast.ClassDef):
            for item in stmt.body:
                if isinstance(item, ast.FunctionDef) and not hasattr(item, "_src_file"):
                    item._src_file = abs_path
    return all_stmts, _mfm_inner, _mod_names


def _resolve_imports(
    import_nodes: list[ast.stmt],
    search_path: Optional[str],
    seen: set[str],
    included: Optional[set[str]] = None,
    ct_names: Optional[set[str]] = None,
    ct_modules: Optional[set[str]] = None,
    event_names: Optional[set[str]] = None,
    syscall_fn_specs: Optional[dict[str, "_SyscallSpec"]] = None,
    syscall_module_fn_specs: Optional[dict[str, "dict[str, _SyscallSpec]"]] = None,
    imported_builtin_classes: Optional[set[str]] = None,
    iterator_names: Optional[set[str]] = None,
    findoptions_names: Optional[set[str]] = None,
    callflags_names: Optional[set[str]] = None,
    namedcurvehash_names: Optional[set[str]] = None,
    dn_names: Optional[set[str]] = None,
    cf_dec_names: Optional[set[str]] = None,
    filename: Optional[str] = None,
    root_path: Optional[str] = None,
    stmts_registry: Optional[dict[str, list[ast.stmt]]] = None,
    mangle_registry: Optional[dict[str, dict[str, str]]] = None,
) -> tuple[
    list[ast.stmt],
    set[str],
    dict[str, str],
    dict[str, dict[str, str]],
    dict[str, dict[str, str]],
]:
    """
    Process a list of ast.Import / ast.ImportFrom nodes.

    Returns:
      extra_stmts    – all AST statements from resolved modules to prepend
      module_names   – namespace names from `import abc` / `import abc as a`
      aliases        – {alias_name: mangled_name} for imported names
      mangle_registry – {abs_path: {orig: mangled}} accumulated across all loads
      module_fn_maps  – {ns_name: {orig: mangled}} for `import mod` namespace calls

    Design notes:
    - For `from mod import x`:  ALL stmts from mod (including its transitive
      imports) are bundled so that deps of x are always present.
    - Top-level names in every imported module are mangled with a module-path
      prefix so same-named functions/classes in different modules don't conflict.
    - For `from mod import X as Z` (class / static): original name kept; Z→X
      recorded in aliases so HIRBuilder can substitute at annotation / load sites.
    - Deduplication: each file is included at most once via the shared `included`
      set (keyed by absolute path), so transitive imports of the same module don't
      produce duplicate definitions.
    """
    if included is None:
        included = set()
    if stmts_registry is None:
        stmts_registry = {}
    if mangle_registry is None:
        mangle_registry = {}

    extra_stmts: list[ast.stmt] = []
    # Tracks function names already bundled from neo3.sc.* modules so that
    # `from neo3.sc import storage` followed by
    # `from neo3.sc.storage import get_int` doesn't emit get_int twice.
    _bundled_sc_fns: set[str] = set()
    module_names: set[str] = set()
    module_fn_maps: dict[str, dict[str, str]] = {}  # ns_name → {orig: mangled}
    aliases: dict[str, str] = {}
    _ct_names = ct_names if ct_names is not None else set()
    _ct_modules = ct_modules if ct_modules is not None else set()
    _event_names = event_names if event_names is not None else set()
    _syscall_fn_specs = syscall_fn_specs if syscall_fn_specs is not None else {}
    _syscall_module_fn_specs = (
        syscall_module_fn_specs if syscall_module_fn_specs is not None else {}
    )
    _imported_builtin_classes = (
        imported_builtin_classes if imported_builtin_classes is not None else set()
    )
    _iterator_names = iterator_names if iterator_names is not None else set()
    _findoptions_names = findoptions_names if findoptions_names is not None else set()
    _callflags_names = callflags_names if callflags_names is not None else set()
    _namedcurvehash_names = (
        namedcurvehash_names if namedcurvehash_names is not None else set()
    )
    _dn_names = dn_names if dn_names is not None else set()
    _cf_dec_names = cf_dec_names if cf_dec_names is not None else set()
    # Project root for absolute import resolution. At the top-level call
    # root_path is None so _root == search_path (unchanged behaviour). In
    # recursive calls from _load_module_stmts, root_path is the project root
    # and search_path is mod_dir, so absolute imports resolve from the root
    # while relative imports still use search_path via _base_for_level.
    _root = root_path if root_path is not None else search_path

    # Cache: abs_path → stmts returned by _load_module_stmts.
    # Used so a second import of the same module (e.g. `from utils import add as plus`
    # after `from utils import add`) can still look up and alias names without
    # re-adding stmts to extra_stmts.
    stmts_cache: dict[str, list[ast.stmt]] = {}

    def _file_path(dotted: str, base: str) -> str:
        flat = os.path.join(base, os.path.join(*dotted.split("."))) + ".py"
        if not os.path.isfile(flat):
            pkg = os.path.join(base, *dotted.split("."), "__init__.py")
            if os.path.isfile(pkg):
                return pkg
        return flat

    # Modules silently skipped — used only for type annotations; the compiler
    # understands Optional[T], List[T] etc. by name without needing the import.
    _ANNOTATION_ONLY_MODULES = {"typing", "typing_extensions"}

    def _load(
        dotted: str,
        base: str,
        lineno: Optional[int] = None,
        col_offset: Optional[int] = None,
        filename: Optional[str] = None,
    ) -> Optional[list[ast.stmt]]:
        """Load stmts. Returns None = skip entirely (annotation-only module).
        Returns [] = already bundled. Raises TypecheckError if file not found."""
        root = dotted.split(".")[0]
        if root in _ANNOTATION_ONLY_MODULES:
            return None  # silently skip — only used for type annotations
        path = _file_path(dotted, base)
        if not os.path.isfile(path):
            msg = (
                f"Cannot import '{dotted}': module not found. "
                "Only local .py files can be imported; stdlib and third-party packages are not supported."
            )
            if dotted.startswith("neo3.sc."):
                fallback = _file_path(dotted, _COMPILER_PACKAGE_ROOT)
                if os.path.isfile(fallback):
                    path = fallback
                else:
                    raise TypecheckError(
                        msg, lineno=lineno, col_offset=col_offset, filename=filename
                    )
            else:
                raise TypecheckError(
                    msg, lineno=lineno, col_offset=col_offset, filename=filename
                )
        abs_path = os.path.abspath(path)
        # "Expected" abs-path: what _apply_aliases_to_stmts will compute from
        # _file_path(dotted, base) — may differ from abs_path when a fallback
        # (_COMPILER_PACKAGE_ROOT) was used.
        _expected_abs = os.path.abspath(_file_path(dotted, base))
        if abs_path in stmts_cache:
            # Ensure the expected path is also aliased in mangle_registry so
            # _apply_aliases_to_stmts can find the mangle map by the key it
            # independently computes.
            if _expected_abs != abs_path:
                mangle_registry.setdefault(
                    _expected_abs, mangle_registry.get(abs_path, {})
                )
            return []  # already bundled; cache available for alias lookups
        stmts, _sub_mfm, _sub_mod_names = _load_module_stmts(
            path,
            dotted,
            base,
            seen,
            included,
            _ct_names,
            _ct_modules,
            _event_names,
            _dn_names,
            cf_dec_names=_cf_dec_names,
            imported_builtin_classes=_imported_builtin_classes,
            iterator_names=_iterator_names,
            findoptions_names=_findoptions_names,
            callflags_names=_callflags_names,
            namedcurvehash_names=_namedcurvehash_names,
            syscall_fn_specs=_syscall_fn_specs,
            syscall_module_fn_specs=_syscall_module_fn_specs,
            caller_lineno=lineno,
            caller_col_offset=col_offset,
            caller_filename=filename,
            stmts_registry=stmts_registry,
            mangle_registry=mangle_registry,
        )
        module_fn_maps.update(_sub_mfm)
        module_names.update(_sub_mod_names)
        stmts_cache[abs_path] = stmts_registry.get(abs_path, stmts)
        # Register expected-path alias so _apply_aliases_to_stmts finds the map.
        if _expected_abs != abs_path and abs_path in mangle_registry:
            mangle_registry[_expected_abs] = mangle_registry[abs_path]
        return stmts

    def _load_relative(dotted: str, base: str) -> list[ast.stmt]:
        path = _file_path(dotted, base)
        abs_path = os.path.abspath(path)
        if abs_path in stmts_cache:
            return []
        stmts, _sub_mfm, _sub_mod_names = _load_module_stmts(
            path,
            dotted,
            _root if _root is not None else base,
            seen,
            included,
            _ct_names,
            _ct_modules,
            _event_names,
            _dn_names,
            cf_dec_names=_cf_dec_names,
            imported_builtin_classes=_imported_builtin_classes,
            iterator_names=_iterator_names,
            findoptions_names=_findoptions_names,
            callflags_names=_callflags_names,
            namedcurvehash_names=_namedcurvehash_names,
            syscall_fn_specs=_syscall_fn_specs,
            syscall_module_fn_specs=_syscall_module_fn_specs,
            stmts_registry=stmts_registry,
            mangle_registry=mangle_registry,
        )
        module_fn_maps.update(_sub_mfm)
        module_names.update(_sub_mod_names)
        stmts_cache[abs_path] = stmts_registry.get(abs_path, stmts)
        return stmts

    def _stmts_for_lookup(dotted: str, base: str) -> Optional[list[ast.stmt]]:
        """Return UNMANGLED stmts for alias/name validation even if already bundled."""
        path = _file_path(dotted, base)
        if not os.path.isfile(path):
            if dotted.startswith("neo3.sc."):
                fallback = _file_path(dotted, _COMPILER_PACKAGE_ROOT)
                if os.path.isfile(fallback):
                    path = fallback
                else:
                    return None
            else:
                return None
        abs_path = os.path.abspath(path)
        if abs_path in stmts_cache:
            return stmts_cache[abs_path]
        stmts, _sub_mfm, _sub_mod_names = _load_module_stmts(
            path,
            dotted,
            _root if _root is not None else base,
            seen,
            included,
            _ct_names,
            _ct_modules,
            _event_names,
            _dn_names,
            cf_dec_names=_cf_dec_names,
            imported_builtin_classes=_imported_builtin_classes,
            iterator_names=_iterator_names,
            findoptions_names=_findoptions_names,
            callflags_names=_callflags_names,
            namedcurvehash_names=_namedcurvehash_names,
            syscall_fn_specs=_syscall_fn_specs,
            syscall_module_fn_specs=_syscall_module_fn_specs,
            stmts_registry=stmts_registry,
            mangle_registry=mangle_registry,
        )
        module_fn_maps.update(_sub_mfm)
        module_names.update(_sub_mod_names)
        stmts_cache[abs_path] = stmts_registry.get(abs_path, stmts)
        return stmts_cache[abs_path]

    def _base_for_level(
        level: int,
        lineno: Optional[int] = None,
        col_offset: Optional[int] = None,
    ) -> str:
        if search_path is None:
            raise TypecheckError(
                "Relative imports require a file-system search path; "
                "pass search_path to compile_module() or use compile_to_nef()",
                lineno=lineno,
                col_offset=col_offset,
                filename=filename,
            )
        base = search_path
        for _ in range(level - 1):
            base = os.path.dirname(base)
        return base

    def _apply_aliases_to_stmts(
        stmts: list[ast.stmt],
        requested: dict[str, str],
        mod_key: str,
        filename: Optional[str] = None,
        mod_abs_path: Optional[str] = None,
    ) -> list[ast.stmt]:
        """
        Bundle all stmts from the module (for transitive dep coverage) while
        registering any import aliases in the shared aliases dict.
        Names in stmts are already mangled; mangle_map is used to convert the
        original requested name to its mangled form before lookup and registration.
        Also validates that every explicitly requested name exists.
        """
        mod_mm = mangle_registry.get(mod_abs_path, {}) if mod_abs_path else {}
        # Build mangled-name → stmt index map for the loaded (mangled) stmts
        by_name: dict[str, int] = {}
        for i, s in enumerate(stmts):
            n = _stmt_name(s)
            if n is not None:
                by_name[n] = i

        for orig, as_name in requested.items():
            mangled = mod_mm.get(orig, orig)
            if mangled not in by_name:
                # Check if orig names a submodule of mod_key (e.g. delivery/admin.py)
                if _root is not None:
                    sub_dotted = f"{mod_key}.{orig}"
                    sub_path = _file_path(sub_dotted, _root)
                    if os.path.isfile(sub_path):
                        sub_stmts = _load(
                            sub_dotted,
                            _root,
                            lineno=getattr(node, "lineno", None),
                            col_offset=getattr(node, "col_offset", None),
                            filename=filename,
                        )
                        extra_stmts.extend(sub_stmts)
                        module_names.add(as_name)
                        _sub_abs = os.path.abspath(sub_path)
                        if _sub_abs in mangle_registry:
                            module_fn_maps[as_name] = mangle_registry[_sub_abs]
                        continue
                # Name may be a special compiler type that was stripped from stmts
                # because it was handled by the inner _resolve_imports call (e.g.
                # Iterator re-exported via __init__.py).  Check the live name sets.
                if orig in _iterator_names:
                    if as_name != orig:
                        _iterator_names.discard(orig)
                        _iterator_names.add(as_name)
                    continue
                if orig in _findoptions_names:
                    if as_name != orig:
                        _findoptions_names.discard(orig)
                        _findoptions_names.add(as_name)
                    continue
                if orig in _callflags_names:
                    if as_name != orig:
                        _callflags_names.discard(orig)
                        _callflags_names.add(as_name)
                    continue
                if orig in _namedcurvehash_names:
                    if as_name != orig:
                        _namedcurvehash_names.discard(orig)
                        _namedcurvehash_names.add(as_name)
                    continue
                raise TypecheckError(
                    f"Cannot import '{orig}' from '{mod_key}': name not found",
                    lineno=getattr(node, "lineno", None),
                    col_offset=getattr(node, "col_offset", None),
                    filename=filename,
                )
            if as_name == mangled:
                continue  # no alias needed — imported name matches mangled name
            aliases[as_name] = mangled
        return list(stmts)

    for node in import_nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import compiler.sc.compiletime as ct` — track the module alias,
                # never bundle. Works even without search_path.
                if alias.name == _COMPILETIME_MODULE:
                    if alias.asname:
                        _ct_modules.add(alias.asname)
                    continue
                # `import neo3.sc.storage as storage` (or any @syscall module) —
                # load all @syscall specs for the module, track alias, never bundle.
                if alias.name in _SYSCALL_DECORATOR_MODULES:
                    if alias.asname:
                        _syscall_module_fn_specs[alias.asname] = _load_syscall_specs(
                            alias.name, search_path
                        )
                    continue
                # Iterator / types modules — never bundle; names tracked via from-import.
                if alias.name in (_ITERATOR_MODULE, _TYPES_MODULE):
                    continue
                if search_path is None:
                    continue
                stmts = _load(
                    alias.name,
                    _root,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    filename=filename,
                )
                if stmts is None:
                    continue  # annotation-only module — silently skip
                extra_stmts.extend(stmts)
                ns_name = alias.asname if alias.asname else alias.name
                module_names.add(ns_name)
                if _root is not None:
                    _imp_path = _file_path(alias.name, _root)
                    _imp_abs = (
                        os.path.abspath(_imp_path)
                        if os.path.isfile(_imp_path)
                        else None
                    )
                    if _imp_abs and _imp_abs in mangle_registry:
                        module_fn_maps[ns_name] = mangle_registry[_imp_abs]

        elif isinstance(node, ast.ImportFrom):
            # Compiletime-only modules: track what was imported, never bundle.
            # These are handled before the search_path guard so they work in tests
            # that compile from a source string without a file-system path.
            if (
                not (node.level and node.level > 0)
                and node.module == _COMPILETIME_MODULE
            ):
                # `from compiler.sc.compiletime import public [as pub]` or contract
                for alias in node.names:
                    local = alias.asname if alias.asname else alias.name
                    if alias.name == "*":
                        _ct_names.add("public")
                        _ct_names.add("contract")
                        _event_names.add("event")
                        _dn_names.add("display_name")
                        _cf_dec_names.add("call_flags")
                    elif alias.name == "display_name":
                        _dn_names.add(local)
                    elif alias.name == "call_flags":
                        _cf_dec_names.add(local)
                    elif alias.name == "event":
                        _event_names.add(local)
                    else:
                        _ct_names.add(local)
                continue
            if (
                not (node.level and node.level > 0)
                and node.module in _SYSCALL_DECORATOR_MODULES
            ):
                # `from neo3.sc.storage import get [as g]` — @syscall spec only.
                # `from neo3.sc.storage import get_int` — non-@syscall: bundle body.
                mod_specs = _load_syscall_specs(node.module, search_path)
                # Eagerly load full module stmts if any requested name is not a
                # @syscall function, so we can bundle those function bodies.
                has_non_syscall = any(a.name not in mod_specs for a in node.names)
                full_stmts_by_name: dict[str, ast.FunctionDef] = {}
                if has_non_syscall:
                    _bases = ([search_path] if search_path else []) + [
                        _COMPILER_PACKAGE_ROOT
                    ]
                    for _base in _bases:
                        _mod_path = _find_module_file(node.module, _base)
                        if _mod_path:
                            with open(_mod_path) as _f:
                                _raw = ast.parse(_f.read()).body
                            full_stmts_by_name = {
                                s.name: s
                                for s in _raw
                                if isinstance(s, ast.FunctionDef)
                            }
                            break
                    # Auto-register every @syscall spec from this module so that
                    # internal calls inside bundled functions (e.g. get_int calling
                    # get) resolve correctly without requiring an explicit import.
                    for _spec_name, _spec in mod_specs.items():
                        _syscall_fn_specs.setdefault(_spec_name, _spec)
                for alias in node.names:
                    local = alias.asname if alias.asname else alias.name
                    if alias.name in mod_specs:
                        # @syscall function — register spec; no bytecode emitted.
                        spec = mod_specs[alias.name]
                        _syscall_fn_specs[local] = spec
                        if isinstance(spec.ret, ClassType):
                            _imported_builtin_classes.add(spec.ret.name)
                    elif alias.name in full_stmts_by_name:
                        # Regular function with a real body — bundle it.
                        fn_stmt: ast.FunctionDef = full_stmts_by_name[alias.name]
                        if local != alias.name:
                            fn_stmt = _rename_function(fn_stmt, local)
                        if fn_stmt.name not in _bundled_sc_fns:
                            extra_stmts.append(fn_stmt)
                            _bundled_sc_fns.add(fn_stmt.name)
                    else:
                        valid = sorted(mod_specs) + sorted(
                            k for k in full_stmts_by_name if k not in mod_specs
                        )
                        raise TypecheckError(
                            f"Cannot import '{alias.name}' from '{node.module}': "
                            f"available names are {valid}",
                            lineno=node.lineno,
                            col_offset=node.col_offset,
                            filename=filename,
                        )
                continue
            if not (node.level and node.level > 0) and node.module == _ITERATOR_MODULE:
                # `from neo3.sc.utils.iterator import Iterator [as It]`
                for alias in node.names:
                    if alias.name != "Iterator":
                        raise TypecheckError(
                            f"Cannot import '{alias.name}' from '{_ITERATOR_MODULE}'",
                            lineno=node.lineno,
                            col_offset=node.col_offset,
                            filename=filename,
                        )
                    _iterator_names.add(alias.asname if alias.asname else alias.name)
                continue
            if not (node.level and node.level > 0) and node.module == _UTILS_MODULE:
                # `from neo3.sc.utils import Iterator [as It]`,
                # `call_contract`, or `abort`.
                # Handled without bundling the utils module body so that call_contract
                # and abort keep their original names at call sites (HIRBuilder matches
                # them by the literal strings "call_contract"/"abort").
                for alias in node.names:
                    if alias.name == "Iterator":
                        _iterator_names.add(
                            alias.asname if alias.asname else alias.name
                        )
                    elif alias.name in ("call_contract", "abort"):
                        pass  # intrinsic builtins; handled by name in HIRBuilder
                    else:
                        raise TypecheckError(
                            f"Cannot import '{alias.name}' from '{_UTILS_MODULE}'",
                            lineno=node.lineno,
                            col_offset=node.col_offset,
                            filename=filename,
                        )
                continue
            if not (node.level and node.level > 0) and node.module == _TYPES_MODULE:
                # `from neo3.sc.types import FindOptions [as FO]`, UInt160,
                # UInt256, or TrimmedTransaction — all annotation/type-registry only.
                for alias in node.names:
                    if alias.name == "FindOptions":
                        _findoptions_names.add(
                            alias.asname if alias.asname else alias.name
                        )
                    elif alias.name == "CallFlags":
                        _callflags_names.add(
                            alias.asname if alias.asname else alias.name
                        )
                    elif alias.name == "NamedCurveHash":
                        _namedcurvehash_names.add(
                            alias.asname if alias.asname else alias.name
                        )
                    elif alias.name in ("UInt160", "UInt256", "ECPoint"):
                        pass  # type annotation only; resolves via resolve_annotation
                    elif alias.name == "TrimmedTransaction":
                        _imported_builtin_classes.add("TrimmedTransaction")
                    elif alias.name == "TrimmedBlock":
                        _imported_builtin_classes.add("TrimmedBlock")
                    elif alias.name == "NeoAccountState":
                        _imported_builtin_classes.add("NeoAccountState")
                    elif alias.name == "ContractState":
                        _imported_builtin_classes.add("ContractState")
                    else:
                        raise TypecheckError(
                            f"Cannot import '{alias.name}' from '{_TYPES_MODULE}'",
                            lineno=node.lineno,
                            col_offset=node.col_offset,
                            filename=filename,
                        )
                continue
            if (
                not (node.level and node.level > 0)
                and node.module == _COMPILETIME_PARENT
            ):
                # `from neo3.sc import compiletime [as ct]`
                ct_aliases = [a for a in node.names if a.name == "compiletime"]
                for alias in ct_aliases:
                    _ct_modules.add(alias.asname if alias.asname else alias.name)
                # `from neo3.sc import X [as alias]` — discover and bundle
                # any submodule X under neo3.sc.* automatically, regardless
                # of whether it has @syscall functions.  This avoids maintaining a
                # hard-coded allowlist and ensures new subpackages work without
                # any changes to the compiler.
                _sc_bases = ([search_path] if search_path else []) + [
                    _COMPILER_PACKAGE_ROOT
                ]
                for alias in node.names:
                    if alias.name == "compiletime":
                        continue  # already handled above
                    local = alias.asname if alias.asname else alias.name
                    full_mod_name = f"{_COMPILETIME_PARENT}.{alias.name}"
                    # Locate the submodule file
                    _mod_path = None
                    for _base in _sc_bases:
                        _mod_path = _find_module_file(full_mod_name, _base)
                        if _mod_path:
                            break
                    if _mod_path is None:
                        raise TypecheckError(
                            f"Cannot import '{alias.name}' from '{_COMPILETIME_PARENT}': "
                            f"submodule not found",
                            lineno=node.lineno,
                            col_offset=node.col_offset,
                            filename=filename,
                        )
                    # Load @syscall specs (returns {} when none present)
                    mod_specs = _load_syscall_specs(full_mod_name, search_path)
                    if mod_specs:
                        _syscall_module_fn_specs[local] = mod_specs
                    # Bundle non-@syscall function bodies
                    with open(_mod_path) as _f:
                        _raw_stmts = ast.parse(_f.read()).body
                    for _s in _raw_stmts:
                        if isinstance(_s, ast.FunctionDef) and _s.name not in mod_specs:
                            if _s.name not in _bundled_sc_fns:
                                extra_stmts.append(_s)
                                _bundled_sc_fns.add(_s.name)
                    # Auto-register @syscall specs as bare names so that internal
                    # calls inside bundled bodies (e.g. get_int calling get) resolve
                    # correctly without requiring an explicit import at the call site.
                    for _spec_name, _spec in mod_specs.items():
                        _syscall_fn_specs.setdefault(_spec_name, _spec)
                        if isinstance(_spec.ret, ClassType):
                            _imported_builtin_classes.add(_spec.ret.name)
                    module_names.add(local)
                continue  # entire `from neo3.sc import ...` handled
            if node.level and node.level > 0:
                base = _base_for_level(
                    node.level, lineno=node.lineno, col_offset=node.col_offset
                )
                if node.module:
                    stmts = _load_relative(node.module, base)
                    mod_key = node.module
                    lookup_base: Optional[str] = base
                else:
                    # `from . import x, y` — each name is a module file
                    for alias in node.names:
                        if alias.name == "*":
                            raise TypecheckError(
                                "'from . import *' is not supported; "
                                "use 'from .module import *' instead",
                                lineno=node.lineno,
                                col_offset=node.col_offset,
                                filename=filename,
                            )
                        rel_stmts = _load_relative(alias.name, base)
                        extra_stmts.extend(rel_stmts)
                        ns_name = alias.asname if alias.asname else alias.name
                        module_names.add(ns_name)
                        _rel_abs = os.path.abspath(_file_path(alias.name, base))
                        if _rel_abs in mangle_registry:
                            module_fn_maps[ns_name] = mangle_registry[_rel_abs]
                    continue
            else:
                if search_path is None or node.module is None:
                    continue
                stmts = _load(
                    node.module,
                    _root,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    filename=filename,
                )
                if stmts is None:
                    continue  # annotation-only module — silently skip
                mod_key = node.module
                lookup_base = _root

            wildcard = any(a.name == "*" for a in node.names)
            if wildcard:
                # Include all public (non-underscore) top-level names.
                # Register aliases so the entry file can call them by their
                # original (unmangled) names.
                _wc_abs = (
                    os.path.abspath(_file_path(mod_key, lookup_base))
                    if lookup_base
                    else None
                )
                _wc_mm = mangle_registry.get(_wc_abs, {}) if _wc_abs else {}
                _wc_reverse = {v: k for k, v in _wc_mm.items()}
                for stmt in stmts:
                    name = _stmt_name(stmt)
                    if name is not None and not name.startswith("_"):
                        extra_stmts.append(stmt)
                        orig = _wc_reverse.get(name, name)
                        if orig != name:
                            aliases[orig] = name
            else:
                # Build requested map: original_name → as_name
                requested: dict[str, str] = {
                    a.name: (a.asname if a.asname else a.name) for a in node.names
                }
                if stmts:
                    # Module newly bundled — apply aliases and add stmts
                    _mod_abs = (
                        os.path.abspath(_file_path(mod_key, lookup_base))
                        if lookup_base
                        else None
                    )
                    bundled = _apply_aliases_to_stmts(
                        stmts,
                        requested,
                        mod_key,
                        filename=filename,
                        mod_abs_path=_mod_abs,
                    )
                    extra_stmts.extend(bundled)
                else:
                    # Module already bundled — validate names and register aliases
                    # without adding duplicate stmts.
                    # Use mangle_registry directly: after Fix 1 it contains both
                    # own definitions and re-exported names, so orig in _mod_mm2 is
                    # the canonical existence check (no fragile by_name lookup needed).
                    _mod_abs2 = (
                        os.path.abspath(_file_path(mod_key, lookup_base))
                        if lookup_base
                        else None
                    )
                    _mod_mm2 = mangle_registry.get(_mod_abs2, {}) if _mod_abs2 else {}
                    for orig, as_name in requested.items():
                        if orig in _mod_mm2:
                            mangled2 = _mod_mm2[orig]
                            if as_name != mangled2:
                                aliases[as_name] = mangled2
                            continue
                        # Not in mangle_registry — try submodule file, special names, error.
                        if _root is not None:
                            sub_dotted = f"{mod_key}.{orig}"
                            sub_path = _file_path(sub_dotted, _root)
                            if os.path.isfile(sub_path):
                                sub_stmts = _load(
                                    sub_dotted,
                                    _root,
                                    lineno=node.lineno,
                                    col_offset=node.col_offset,
                                    filename=filename,
                                )
                                extra_stmts.extend(sub_stmts)
                                module_names.add(as_name)
                                _sub_abs = os.path.abspath(sub_path)
                                if _sub_abs in mangle_registry:
                                    module_fn_maps[as_name] = mangle_registry[_sub_abs]
                                continue
                        if orig in _iterator_names:
                            if as_name != orig:
                                _iterator_names.discard(orig)
                                _iterator_names.add(as_name)
                            continue
                        if orig in _findoptions_names:
                            if as_name != orig:
                                _findoptions_names.discard(orig)
                                _findoptions_names.add(as_name)
                            continue
                        if orig in _callflags_names:
                            if as_name != orig:
                                _callflags_names.discard(orig)
                                _callflags_names.add(as_name)
                            continue
                        if orig in _namedcurvehash_names:
                            if as_name != orig:
                                _namedcurvehash_names.discard(orig)
                                _namedcurvehash_names.add(as_name)
                            continue
                        raise TypecheckError(
                            f"Cannot import '{orig}' from '{mod_key}': name not found",
                            lineno=node.lineno,
                            col_offset=node.col_offset,
                            filename=filename,
                        )

    return extra_stmts, module_names, aliases, mangle_registry, module_fn_maps


def _collect_module_statics(
    body: list,
    iterator_extra: dict,
    filename: Optional[str],
    module_fn_maps: Optional[dict[str, dict[str, str]]] = None,
    module_names: Optional[set] = None,
) -> tuple[dict, list, dict]:
    """Pass 1: collect module-level static field declarations from *body*.

    Returns (statics, static_inits, const_values).
    """
    statics: dict[str, tuple[int, Type]] = {}
    static_inits: list[tuple[int, Type, ast.expr]] = []
    const_values: dict[str, object] = {}

    # Pass 1a: Annotated statics (ast.AnnAssign)
    for node in body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            if name in statics:
                raise TypecheckError(
                    f"Import conflict: '{name}' is already defined; "
                    f"use 'import ... as <alias>' or 'from ... import {name} as <alias>' to rename one",
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    filename=filename,
                )
            t = resolve_annotation(
                node.annotation,
                extra_names=iterator_extra,
                filename=filename,
                module_fn_maps=module_fn_maps,
                module_names=module_names,
            )
            slot = len(statics)
            statics[name] = (slot, t)
            if node.value is not None:
                static_inits.append((slot, t, node.value))
                folded = _try_fold_const_expr(node.value, const_values)
                if folded is not None:
                    const_values[name] = folded

    # Pass 1b: Unannotated module-level assignments — collect those whose values can
    # be resolved as compile-time constants or UInt160/UInt256.from_string() calls.
    # Multi-pass loop handles forward references.
    pending: list[ast.Assign] = [
        node
        for node in body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    ]
    changed = True
    while changed and pending:
        changed = False
        still_pending: list[ast.Assign] = []
        for node in pending:
            name = node.targets[0].id  # type: ignore[union-attr]
            if name in statics:
                raise TypecheckError(
                    f"Import conflict: '{name}' is already defined; "
                    f"use 'import ... as <alias>' or 'from ... import {name} as <alias>' to rename one",
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    filename=filename,
                )
            val_node = node.value
            # UInt160 / UInt256 from_string(literal) pattern
            if (
                isinstance(val_node, ast.Call)
                and isinstance(val_node.func, ast.Attribute)
                and isinstance(val_node.func.value, ast.Name)
                and val_node.func.attr == "from_string"
                and val_node.func.value.id in ("UInt160", "UInt256")
                and len(val_node.args) == 1
                and isinstance(val_node.args[0], ast.Constant)
                and isinstance(val_node.args[0].value, str)
            ):
                t = UINT160 if val_node.func.value.id == "UInt160" else UINT256
                slot = len(statics)
                statics[name] = (slot, t)
                static_inits.append((slot, t, val_node))
                changed = True
                continue
            # Generic constant folding
            folded = _try_fold_const_expr(val_node, const_values)
            if folded is not None:
                t = _type_of_folded(folded)
                if t is not None:
                    slot = len(statics)
                    statics[name] = (slot, t)
                    folded_node = ast.Constant(value=folded)
                    ast.copy_location(folded_node, val_node)
                    static_inits.append((slot, t, folded_node))
                    const_values[name] = folded
                    changed = True
                    continue
            still_pending.append(node)
        pending = still_pending

    return statics, static_inits, const_values


def _extract_syscall_decorator_name(fn: ast.FunctionDef) -> Optional[str]:
    """Return the syscall interop-method name from a ``@syscall("name")`` decorator, or None.

    Accepts any call-style decorator whose sole argument is a string constant,
    regardless of what the function is named locally (``syscall``, ``ct.syscall``, etc.).
    The body is trusted to be ``pass``; callers must validate separately.
    """
    for dec in fn.decorator_list:
        if (
            isinstance(dec, ast.Call)
            and len(dec.args) == 1
            and not dec.keywords
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            func = dec.func
            if isinstance(func, ast.Name):
                return dec.args[0].value
            if isinstance(func, ast.Attribute) and func.attr == "syscall":
                return dec.args[0].value
    return None


def _eval_default_expr(node: ast.expr) -> Optional[int]:
    """Fold a function-default AST node to an integer, or return None.

    Handles plain integer constants, ``FindOptions.<ATTR>``,
    ``CallFlags.<ATTR>``, and ``NamedCurveHash.<ATTR>`` attribute accesses.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "FindOptions"
        and node.attr in _FIND_OPTIONS_VALUES
    ):
        return _FIND_OPTIONS_VALUES[node.attr]
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "CallFlags"
        and node.attr in _CALL_FLAGS_VALUES
    ):
        return _CALL_FLAGS_VALUES[node.attr]
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "NamedCurveHash"
        and node.attr in _NAMED_CURVE_HASH_VALUES
    ):
        return _NAMED_CURVE_HASH_VALUES[node.attr]


def _try_fold_const_expr(
    node: ast.expr, const_values: dict
) -> Optional[Union[int, bool, str, bytes]]:
    """Try to evaluate a module-level expression as a compile-time constant.

    Returns the Python value (int/bool/str/bytes) on success, None if the
    expression cannot be fully resolved with the currently known *const_values*.
    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (bool, int, str, bytes)):
            return node.value
        return None
    if isinstance(node, ast.Name):
        return const_values.get(node.id)
    if isinstance(node, ast.UnaryOp):
        operand = _try_fold_const_expr(node.operand, const_values)
        if operand is None:
            return None
        if (
            isinstance(node.op, ast.USub)
            and isinstance(operand, int)
            and not isinstance(operand, bool)
        ):
            return -operand
        if (
            isinstance(node.op, ast.Invert)
            and isinstance(operand, int)
            and not isinstance(operand, bool)
        ):
            return ~operand
        if isinstance(node.op, ast.UAdd) and isinstance(operand, int):
            return operand
        return None
    if isinstance(node, ast.BinOp):
        left = _try_fold_const_expr(node.left, const_values)
        right = _try_fold_const_expr(node.right, const_values)
        if left is None or right is None:
            return None
        op = node.op
        try:
            if isinstance(op, ast.Add):
                return left + right  # works for int, str, bytes
            if (
                isinstance(op, ast.Sub)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left - right
            if (
                isinstance(op, ast.Mult)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left * right
            if (
                isinstance(op, ast.Pow)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                if right < 0:
                    return None  # float result not supported
                return left**right
            if (
                isinstance(op, ast.FloorDiv)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left // right
            if (
                isinstance(op, ast.Mod)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left % right
            if (
                isinstance(op, ast.BitAnd)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left & right
            if (
                isinstance(op, ast.BitOr)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left | right
            if (
                isinstance(op, ast.BitXor)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left ^ right
            if (
                isinstance(op, ast.LShift)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left << right
            if (
                isinstance(op, ast.RShift)
                and isinstance(left, int)
                and isinstance(right, int)
            ):
                return left >> right
        except (ZeroDivisionError, OverflowError):
            return None
    return None


def _infer_type_from_ast_expr(
    node: ast.expr,
    statics: "dict[str, tuple[int, Type]]",
    registry: "dict[str, ClassInfo]",
) -> "Optional[Type]":
    """Best-effort type inference for an AST expression in the class pre-pass.

    Resolves constants, simple name lookups (module statics), and attribute
    accesses like ``ClassName.ATTR`` by consulting the already-built *statics*
    and *registry* tables.  Returns ``None`` when the expression is too complex
    to resolve without the full HIR machinery.
    """
    if isinstance(node, ast.Constant):
        v = node.value
        if v is None:
            return NONE
        if isinstance(v, bool):
            return BOOL
        if isinstance(v, int):
            return INT
        if isinstance(v, str):
            return STR
        if isinstance(v, bytes):
            return BYTES
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _infer_type_from_ast_expr(node.operand, statics, registry)
        return INT if isinstance(inner, IntType) else None
    if isinstance(node, ast.Name):
        entry = statics.get(node.id)
        return entry[1] if entry is not None else None
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        # ClassName.attr or module.name — resolve via statics first, then class_vars
        mangled = f"{node.value.id}.{node.attr}"
        entry = statics.get(mangled)
        if entry is not None:
            return entry[1]
        cls_info = registry.get(node.value.id)
        if cls_info is not None:
            cv = cls_info.class_vars.get(node.attr)
            if cv is not None:
                return cv[1]
        return None
    if isinstance(node, ast.List) and not node.elts:
        return ListType(ANY)
    if isinstance(node, ast.Dict) and not node.keys:
        return DictType(ANY, ANY)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "to_bytes"
    ):
        return BYTES
    return None


def _find_module_file(module_name: str, base: str) -> Optional[str]:
    """Return the ``__init__.py`` or ``.py`` path for *module_name* under *base*, or None."""
    pkg = os.path.join(base, *module_name.split("."), "__init__.py")
    if os.path.isfile(pkg):
        return pkg
    parts = module_name.split(".")
    py = os.path.join(base, *parts[:-1], parts[-1] + ".py")
    return py if os.path.isfile(py) else None


def _load_syscall_specs(
    module_name: str, search_path: Optional[str]
) -> "dict[str, _SyscallSpec]":
    """Read a ``@syscall``-decorated module and return ``fn_name → _SyscallSpec``.

    Searches *search_path* first (if provided), then the compiler package root.
    Only functions with a ``@syscall(...)`` decorator are included.
    Integer defaults (including ``FindOptions.<ATTR>``) are extracted from the
    function's default argument list.
    """
    stmts: list[ast.stmt] = []
    bases = ([search_path] if search_path else []) + [_COMPILER_PACKAGE_ROOT]
    for base in bases:
        path = _find_module_file(module_name, base)
        if path:
            with open(path) as _f:
                stmts = ast.parse(_f.read()).body
            break
    specs: dict[str, _SyscallSpec] = {}
    for stmt in stmts:
        if not isinstance(stmt, ast.FunctionDef):
            continue
        syscall_name = _extract_syscall_decorator_name(stmt)
        if syscall_name is None:
            continue
        h = hashlib.sha256(syscall_name.encode()).digest()[:4]
        params = [_resolve_simple_type(a.annotation) for a in stmt.args.args]
        pnames = [a.arg for a in stmt.args.args]
        ret = _resolve_simple_type(stmt.returns) if stmt.returns is not None else NONE
        n = len(params)
        d = len(stmt.args.defaults)
        defaults: dict[int, int] = {}
        for i, dnode in enumerate(stmt.args.defaults):
            v = _eval_default_expr(dnode)
            if v is not None:
                defaults[n - d + i] = v
        specs[stmt.name] = _SyscallSpec(
            hash=h,
            params=params,
            ret=ret,
            push_order=list(reversed(range(n))),
            defaults=defaults if defaults else None,
            param_names=pnames,
        )
    return specs
