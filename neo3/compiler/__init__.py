"""
Neo3 Python Compiler

Pipeline:
    Python source -> AST -> TypedHIR -> CFG -> linearized bytecode
"""

import ast
import hashlib
import json
import os
import warnings
from typing import Optional

from neo3.contracts.abi import (
    ContractABI,
    ContractEventDescriptor,
    ContractMethodDescriptor,
    ContractParameterDefinition,
    ContractParameterType,
)
from neo3.contracts.manifest import ContractManifest
from neo3.contracts.nef import NEF
from neo3.core.types import UInt160

from .types import (
    Type,
    ListType,
    DictType,
    TupleType,
    NoneType,
    OptionalType,
    ClassType,
    UInt160Type,
    UInt256Type,
    ECPointType,
    CompilerWarning,
    TypecheckError,
    INT,
    BOOL,
    BYTES,
    BYTEARRAY,
    STR,
    NONE,
    ITERATOR,
    UINT160,
    UINT256,
    ECPOINT,
    ANY,
)
from .hir import (
    Call,
    ClassInfo,
    Expr,
    FieldInfo,
    HIRFunction,
    MethodInfo,
    resolve_annotation,
    _PublicMethodInfo,
    _EventInfo,
    _collect_write_ops,
    _collect_contract_calls,
)
from .hir_builder import (
    HIRBuilder,
    _SyscallSpec,
    _build_class_registry,
    _collect_module_statics,
    _extract_event_info,
    _extract_manifest_override,
    _extract_public_params,
    _extract_syscall_decorator_name,
    _is_event_decorator,
    _is_public_decorator,
    _literal_to_hir_expr,
    _resolve_imports,
)
from .cfg import CFG, OpCode
from .cfg_builder import CFGBuilder
from .linearizer import (
    Emitter,
    Linearizer,
    _emit_static_literal,
    _emit_to_bytes_helper,
)

# Strip internal compiler file/line info from CompilerWarning messages so the
# output is useful to contract authors rather than compiler developers.
_orig_formatwarning = warnings.formatwarning


def _formatwarning(message, category, filename, lineno, line=None):
    if issubclass(category, CompilerWarning):
        return f"{category.__name__}: {message}\n"
    return _orig_formatwarning(message, category, filename, lineno, line)


warnings.formatwarning = _formatwarning


def _loc(
    filename: Optional[str], lineno: Optional[int], col_offset: Optional[int]
) -> str:
    """Return a 'file, line N, col M: ' prefix for warning messages, or '' if no info."""
    parts: list[str] = []
    if filename:
        parts.append(filename)
    if lineno is not None:
        loc = f"line {lineno}"
        if col_offset is not None:
            loc += f", col {col_offset + 1}"
        parts.append(loc)
    return (", ".join(parts) + ": ") if parts else ""


# ---------------------------------------------------------------------------
# Pre-built class info for built-in NeoVM-mapped types
# ---------------------------------------------------------------------------

_TRIMMED_TX_FIELDS: dict[str, FieldInfo] = {
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

_TRIMMED_BLOCK_FIELDS: dict[str, FieldInfo] = {
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

_NEO_ACCOUNT_STATE_FIELDS: dict[str, FieldInfo] = {
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

_CONTRACT_STATE_FIELDS: dict[str, FieldInfo] = {
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

_NOTIFICATION_FIELDS: dict[str, FieldInfo] = {
    "script_hash": FieldInfo(name="script_hash", index=0, type=UINT160),
    "event_name": FieldInfo(name="event_name", index=1, type=STR),
    "state": FieldInfo(name="state", index=2, type=ListType(ANY)),
}
_NOTIFICATION_CLASS_INFO = ClassInfo(
    name="Notification",
    bases=[],
    class_mro=[],
    fields=_NOTIFICATION_FIELDS,
    methods={},
    class_vars={},
    total_fields=3,
    ast_node=ast.ClassDef(
        name="Notification",
        bases=[],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    ),
)

_WITNESS_CONDITION_FIELDS: dict[str, FieldInfo] = {
    "type": FieldInfo(name="type", index=0, type=INT),
}
_WITNESS_CONDITION_CLASS_INFO = ClassInfo(
    name="WitnessCondition",
    bases=[],
    class_mro=[],
    fields=_WITNESS_CONDITION_FIELDS,
    methods={},
    class_vars={},
    total_fields=1,
    ast_node=ast.ClassDef(
        name="WitnessCondition",
        bases=[],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    ),
)

_WITNESS_RULE_FIELDS: dict[str, FieldInfo] = {
    "action": FieldInfo(name="action", index=0, type=INT),
    "condition": FieldInfo(
        name="condition", index=1, type=ClassType("WitnessCondition")
    ),
}
_WITNESS_RULE_CLASS_INFO = ClassInfo(
    name="WitnessRule",
    bases=[],
    class_mro=[],
    fields=_WITNESS_RULE_FIELDS,
    methods={},
    class_vars={},
    total_fields=2,
    ast_node=ast.ClassDef(
        name="WitnessRule",
        bases=[],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    ),
)

_SIGNER_FIELDS: dict[str, FieldInfo] = {
    "account": FieldInfo(name="account", index=0, type=UINT160),
    "scopes": FieldInfo(name="scopes", index=1, type=INT),
    "allowed_contracts": FieldInfo(
        name="allowed_contracts", index=2, type=ListType(UINT160)
    ),
    "allowed_groups": FieldInfo(name="allowed_groups", index=3, type=ListType(ECPOINT)),
    "rules": FieldInfo(name="rules", index=4, type=ListType(ClassType("WitnessRule"))),
}
_SIGNER_CLASS_INFO = ClassInfo(
    name="Signer",
    bases=[],
    class_mro=[],
    fields=_SIGNER_FIELDS,
    methods={},
    class_vars={},
    total_fields=5,
    ast_node=ast.ClassDef(
        name="Signer",
        bases=[],
        keywords=[],
        body=[ast.Pass()],
        decorator_list=[],
    ),
)


def _type_to_contract_param(t: Type) -> ContractParameterType:
    if t is INT:
        return ContractParameterType.INTEGER
    if t is BOOL:
        return ContractParameterType.BOOLEAN
    if t is STR:
        return ContractParameterType.STRING
    if t is BYTES or t is BYTEARRAY:
        return ContractParameterType.BYTEARRAY
    if isinstance(t, ListType):
        return ContractParameterType.ARRAY
    if isinstance(t, TupleType):
        return ContractParameterType.ARRAY
    if isinstance(t, DictType):
        return ContractParameterType.MAP
    if t is NONE:
        return ContractParameterType.VOID
    if isinstance(t, OptionalType):
        # Strip Optional — Neo VM treats all values as nullable; use the inner type
        return _type_to_contract_param(t.inner)
    if isinstance(t, UInt160Type):
        return ContractParameterType.HASH160
    if isinstance(t, UInt256Type):
        return ContractParameterType.HASH256
    if isinstance(t, ECPointType):
        return ContractParameterType.PUBLICKEY
    if isinstance(t, ClassType):
        return ContractParameterType.ARRAY
    return ContractParameterType.ANY


def _compile_full(
    source: str,
    search_path: Optional[str] = None,
    filename: Optional[str] = None,
) -> tuple[bytes, list[_PublicMethodInfo], list[_EventInfo], Optional[dict]]:
    tree = ast.parse(source)

    # Resolve imports: split import statements from the main body, load imported
    # modules, and prepend their AST nodes so all passes see a flat merged tree.
    import_nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    main_body = [
        n for n in tree.body if not isinstance(n, (ast.Import, ast.ImportFrom))
    ]
    ct_names: set[str] = set()
    ct_modules: set[str] = set()
    event_names: set[str] = set()
    syscall_fn_specs: dict[str, _SyscallSpec] = {}
    syscall_module_fn_specs: dict[str, dict[str, _SyscallSpec]] = {}
    imported_builtin_classes: set[str] = set()
    iterator_names: set[str] = set()
    findoptions_names: set[str] = set()
    callflags_names: set[str] = set()
    namedcurvehash_names: set[str] = set()
    witnessscope_names: set[str] = set()
    witnessruleaction_names: set[str] = set()
    witnessconditiontype_names: set[str] = set()
    dn_names: set[str] = set()
    cf_dec_names: set[str] = set()
    manifest_cls_names: set[str] = set()
    extra_stmts, module_names, aliases, mangle_registry, module_fn_maps = (
        _resolve_imports(
            import_nodes,
            search_path,
            seen=set(),
            included=set(),
            ct_names=ct_names,
            ct_modules=ct_modules,
            event_names=event_names,
            syscall_fn_specs=syscall_fn_specs,
            syscall_module_fn_specs=syscall_module_fn_specs,
            imported_builtin_classes=imported_builtin_classes,
            iterator_names=iterator_names,
            findoptions_names=findoptions_names,
            callflags_names=callflags_names,
            namedcurvehash_names=namedcurvehash_names,
            witnessscope_names=witnessscope_names,
            witnessruleaction_names=witnessruleaction_names,
            witnessconditiontype_names=witnessconditiontype_names,
            dn_names=dn_names,
            cf_dec_names=cf_dec_names,
            manifest_cls_names=manifest_cls_names,
            filename=filename,
        )
    )
    # Build reverse map (mangled_name → original_name) for ABI name restoration
    reverse_mangle: dict[str, str] = {
        v: k for mm in mangle_registry.values() for k, v in mm.items()
    }
    # Extract ContractManifest(...) override call and remove it from the body
    # before any compilation pass sees it.
    manifest_override, main_body = _extract_manifest_override(
        main_body, manifest_cls_names, filename=filename
    )
    tree.body = extra_stmts + main_body
    iterator_extra: dict[str, Type] = {n: ITERATOR for n in iterator_names}

    # Pass 1: Collect module-level static field declarations (anywhere in tree.body)
    statics, static_inits, const_values = _collect_module_statics(
        tree.body,
        iterator_extra,
        filename,
        module_fn_maps=module_fn_maps,
        module_names=module_names,
    )

    # Pass 2: Build class registry (may extend statics with class variables)
    class_registry, statics, class_var_inits = _build_class_registry(
        tree,
        statics,
        ct_names=ct_names,
        ct_modules=ct_modules,
        dn_names=dn_names,
        cf_dec_names=cf_dec_names,
        filename=filename,
        module_fn_maps=module_fn_maps,
        module_names=module_names,
    )
    static_inits.extend(class_var_inits)

    # Inject pre-built class infos for types imported from neo3.sc.types / runtime
    if "TrimmedTransaction" in imported_builtin_classes:
        class_registry["TrimmedTransaction"] = _TRIMMED_TX_CLASS_INFO
    if "NeoAccountState" in imported_builtin_classes:
        class_registry["NeoAccountState"] = _NEO_ACCOUNT_STATE_CLASS_INFO
    if "ContractState" in imported_builtin_classes:
        class_registry["ContractState"] = _CONTRACT_STATE_CLASS_INFO
    if "TrimmedBlock" in imported_builtin_classes:
        class_registry["TrimmedBlock"] = _TRIMMED_BLOCK_CLASS_INFO
    if "Notification" in imported_builtin_classes:
        class_registry["Notification"] = _NOTIFICATION_CLASS_INFO
    if "WitnessCondition" in imported_builtin_classes:
        class_registry["WitnessCondition"] = _WITNESS_CONDITION_CLASS_INFO
    if "WitnessRule" in imported_builtin_classes:
        class_registry["WitnessRule"] = _WITNESS_RULE_CLASS_INFO
    if "Signer" in imported_builtin_classes:
        class_registry["Signer"] = _SIGNER_CLASS_INFO

    fn_nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef)]

    # Scan for @event-decorated functions; collect EventInfo, skip their compilation.
    event_fn_specs: dict[str, _EventInfo] = {}
    for fn in fn_nodes:
        for d in fn.decorator_list:
            if _is_event_decorator(d, event_names, ct_modules):
                info = _extract_event_info(
                    d,
                    fn,
                    class_registry,
                    filename,
                    iterator_extra,
                    module_fn_maps=module_fn_maps,
                    module_names=module_names,
                )
                event_fn_specs[fn.name] = info
                break

    # Scan user-defined functions for @syscall decorator.  These are compiled to
    # direct SYSCALL opcodes; their bodies are skipped.
    for fn in fn_nodes:
        syscall_name = _extract_syscall_decorator_name(fn)
        if syscall_name is not None and fn.name not in syscall_fn_specs:
            h = hashlib.sha256(syscall_name.encode()).digest()[:4]
            fn_filename = getattr(fn, "_src_file", filename)
            params = [
                resolve_annotation(
                    a.annotation,
                    class_registry,
                    filename=fn_filename,
                    module_fn_maps=module_fn_maps,
                    module_names=module_names,
                )
                for a in fn.args.args
            ]
            ret = (
                resolve_annotation(
                    fn.returns,
                    class_registry,
                    filename=fn_filename,
                    module_fn_maps=module_fn_maps,
                    module_names=module_names,
                )
                if fn.returns is not None
                else NONE
            )
            n = len(params)
            syscall_fn_specs[fn.name] = _SyscallSpec(
                hash=h,
                params=params,
                ret=ret,
                push_order=list(reversed(range(n))),
            )

    # Identify @public functions/methods — decorator must originate from
    # compiler.sc.compiletime (tracked via ct_names / ct_modules).
    # Maps compiled_name → (abi_alias, safe).
    public_decorators: dict[str, tuple[Optional[str], bool]] = {}
    for fn in fn_nodes:
        for d in fn.decorator_list:
            if _is_public_decorator(d, ct_names, ct_modules):
                public_decorators[fn.name] = _extract_public_params(d)
                break

    public_method_compiled: dict[str, tuple[Optional[str], bool]] = {}
    for ci in class_registry.values():
        for mi in ci.methods.values():
            for d in mi.ast_node.decorator_list:
                if _is_public_decorator(d, ct_names, ct_modules):
                    public_method_compiled[mi.compiled_name] = _extract_public_params(d)
                    break

    # Catch any @public usage that was NOT recognised (import missing).
    # A decorator whose name resolves to "public" but isn't from the compiletime
    # module would just be silently ignored — raise a clear error instead.
    def _looks_like_public(d: ast.expr) -> bool:
        """True if the decorator *looks* like @public by name but was not recognised."""
        if isinstance(d, ast.Name):
            return d.id == "public"
        if isinstance(d, ast.Attribute):
            return d.attr == "public"
        if isinstance(d, ast.Call):
            f = d.func
            return (isinstance(f, ast.Name) and f.id == "public") or (
                isinstance(f, ast.Attribute) and f.attr == "public"
            )
        return False

    for fn in fn_nodes:
        for d in fn.decorator_list:
            if _looks_like_public(d) and not _is_public_decorator(
                d, ct_names, ct_modules
            ):
                raise TypecheckError(
                    "'@public' requires 'from neo3.sc.compiletime import public'",
                    lineno=getattr(d, "lineno", fn.lineno),
                    col_offset=getattr(d, "col_offset", fn.col_offset),
                    filename=getattr(fn, "_src_file", filename),
                )
    for ci in class_registry.values():
        for mi in ci.methods.values():
            for d in mi.ast_node.decorator_list:
                if _looks_like_public(d) and not _is_public_decorator(
                    d, ct_names, ct_modules
                ):
                    raise TypecheckError(
                        "'@public' requires 'from neo3.sc.compiletime import public'",
                        lineno=getattr(d, "lineno", mi.ast_node.lineno),
                        col_offset=getattr(d, "col_offset", mi.ast_node.col_offset),
                        filename=getattr(mi.ast_node, "_src_file", filename),
                    )

    if not fn_nodes and not class_registry:
        raise TypecheckError("No function found", filename=filename)

    # Pass 3: Collect all function + method signatures
    signatures: dict[str, tuple[list[Type], Type]] = {}
    func_defaults: dict[str, dict[int, Expr]] = {}
    fn_origins: dict[str, tuple[Optional[str], Optional[int]]] = (
        {}
    )  # name → (file, lineno)

    for fn_node in fn_nodes:
        if fn_node.name in syscall_fn_specs:
            continue  # @syscall wrapper — no body to compile; spec is already recorded
        if fn_node.name in event_fn_specs:
            continue  # @event emitter — no body to compile; spec is already recorded
        if fn_node.name in ("abort", "call_contract"):
            continue  # intrinsic stub — handled directly by HIRBuilder
        fn_filename = getattr(fn_node, "_src_file", filename)
        if fn_node.name in signatures:
            orig_file, orig_line = fn_origins[fn_node.name]
            orig_hint = (
                f" (first defined in {orig_file} at line {orig_line})"
                if orig_file
                else ""
            )
            _display_name = reverse_mangle.get(fn_node.name, fn_node.name)
            raise TypecheckError(
                f"Import conflict: '{_display_name}' is already defined{orig_hint}; "
                f"use 'from ... import {_display_name} as <alias>' to rename one",
                lineno=fn_node.lineno,
                col_offset=fn_node.col_offset,
                filename=fn_filename,
            )
        if fn_node.returns is None:
            _display_name = reverse_mangle.get(fn_node.name, fn_node.name)
            raise TypecheckError(
                f"Function '{_display_name}' missing return annotation",
                lineno=fn_node.lineno,
                col_offset=fn_node.col_offset,
                filename=fn_filename,
            )
        return_type = resolve_annotation(
            fn_node.returns,
            class_registry,
            extra_names=iterator_extra,
            filename=fn_filename,
            module_fn_maps=module_fn_maps,
            module_names=module_names,
        )
        param_types: list[Type] = []
        for arg in fn_node.args.args:
            if arg.annotation is None:
                raise TypecheckError(
                    f"Argument '{arg.arg}' missing annotation",
                    lineno=arg.lineno,
                    col_offset=arg.col_offset,
                    filename=fn_filename,
                )
            param_types.append(
                resolve_annotation(
                    arg.annotation,
                    class_registry,
                    extra_names=iterator_extra,
                    filename=fn_filename,
                    module_fn_maps=module_fn_maps,
                    module_names=module_names,
                )
            )
        signatures[fn_node.name] = (param_types, return_type)
        fn_origins[fn_node.name] = (fn_filename, fn_node.lineno)
        fn_defaults: dict[int, Expr] = {}
        offset = len(fn_node.args.args) - len(fn_node.args.defaults)
        for i, default_ast in enumerate(fn_node.args.defaults):
            fn_defaults[offset + i] = _literal_to_hir_expr(
                default_ast, filename=fn_filename
            )
        func_defaults[fn_node.name] = fn_defaults

    # Collect method signatures (include 'self' as first param for instance methods)
    own_method_nodes: set[int] = (
        set()
    )  # id() of ast nodes compiled under their defining class
    for ci in class_registry.values():
        if ci.contract_hash is not None:
            # @contract interface: collect signatures for call-site type checking,
            # but mark methods so they are not compiled as local functions.
            for mi in ci.methods.values():
                compiled = mi.compiled_name
                if compiled in signatures:
                    continue
                fn_node = mi.ast_node
                fn_filename = getattr(fn_node, "_src_file", filename)
                if fn_node.returns is None:
                    _cls_display = reverse_mangle.get(ci.name, ci.name)
                    raise TypecheckError(
                        f"@contract method '{_cls_display}.{mi.name}' missing return annotation",
                        lineno=fn_node.lineno,
                        col_offset=fn_node.col_offset,
                        filename=fn_filename,
                    )
                return_type = resolve_annotation(
                    fn_node.returns,
                    class_registry,
                    extra_names=iterator_extra,
                    filename=fn_filename,
                    module_fn_maps=module_fn_maps,
                    module_names=module_names,
                )
                raw_params = list(fn_node.args.args)
                param_types: list[Type] = []
                for arg in raw_params:
                    if arg.annotation is None:
                        _cls_display = reverse_mangle.get(ci.name, ci.name)
                        raise TypecheckError(
                            f"@contract method '{_cls_display}.{mi.name}': "
                            f"argument '{arg.arg}' missing annotation",
                            lineno=arg.lineno,
                            col_offset=arg.col_offset,
                            filename=fn_filename,
                        )
                    param_types.append(
                        resolve_annotation(
                            arg.annotation,
                            class_registry,
                            extra_names=iterator_extra,
                            filename=fn_filename,
                            module_fn_maps=module_fn_maps,
                            module_names=module_names,
                        )
                    )
                signatures[compiled] = (param_types, return_type)
            continue  # do not compile these methods

        for mi in ci.methods.values():
            # Only collect signature for methods defined in this class (not inherited)
            compiled = mi.compiled_name
            if compiled in signatures:
                continue  # already collected (e.g. inherited and already processed)
            fn_node = mi.ast_node
            fn_filename = getattr(fn_node, "_src_file", filename)
            own_method_nodes.add(id(fn_node))
            if fn_node.returns is None and mi.name != "__init__":
                raise TypecheckError(
                    f"Method '{reverse_mangle.get(ci.name, ci.name)}.{mi.name}' missing return annotation",
                    lineno=fn_node.lineno,
                    col_offset=fn_node.col_offset,
                    filename=fn_filename,
                )
            return_type = (
                NoneType()
                if fn_node.returns is None
                else resolve_annotation(
                    fn_node.returns,
                    class_registry,
                    extra_names=iterator_extra,
                    filename=fn_filename,
                    module_fn_maps=module_fn_maps,
                    module_names=module_names,
                )
            )
            raw_params = list(fn_node.args.args)
            param_types = []
            if mi.kind == "instance":
                param_types.append(ClassType(ci.name))  # self
                raw_params = raw_params[1:]
            elif mi.kind == "class":
                raw_params = raw_params[1:]  # skip cls
            for arg in raw_params:
                if arg.annotation is None:
                    raise TypecheckError(
                        f"Argument '{arg.arg}' missing annotation",
                        lineno=arg.lineno,
                        col_offset=arg.col_offset,
                        filename=fn_filename,
                    )
                param_types.append(
                    resolve_annotation(
                        arg.annotation,
                        class_registry,
                        extra_names=iterator_extra,
                        filename=fn_filename,
                        module_fn_maps=module_fn_maps,
                        module_names=module_names,
                    )
                )
            signatures[compiled] = (param_types, return_type)
            fn_defaults = {}
            offset = len(fn_node.args.args) - len(fn_node.args.defaults)
            for i, default_ast in enumerate(fn_node.args.defaults):
                fn_defaults[offset + i] = _literal_to_hir_expr(
                    default_ast, filename=fn_filename
                )
            func_defaults[compiled] = fn_defaults

    # Pass 4: Build HIR + CFG
    pairs = []

    for fn_node in fn_nodes:
        if fn_node.name in syscall_fn_specs:
            continue  # @syscall wrapper — no body to compile
        if fn_node.name in event_fn_specs:
            continue  # @event emitter — no body to compile
        if fn_node.name in ("abort", "call_contract"):
            continue  # intrinsic stub — handled directly by HIRBuilder
        fn_filename = getattr(fn_node, "_src_file", filename)
        hir = HIRBuilder(
            signatures,
            statics=statics,
            func_defaults=func_defaults,
            class_registry=class_registry,
            module_names=module_names,
            aliases=aliases,
            syscall_fn_specs=syscall_fn_specs,
            syscall_module_fn_specs=syscall_module_fn_specs,
            event_fn_specs=event_fn_specs,
            iterator_names=iterator_names,
            findoptions_names=findoptions_names,
            callflags_names=callflags_names,
            namedcurvehash_names=namedcurvehash_names,
            witnessscope_names=witnessscope_names,
            witnessruleaction_names=witnessruleaction_names,
            witnessconditiontype_names=witnessconditiontype_names,
            module_fn_maps=module_fn_maps,
            filename=fn_filename,
        ).build(fn_node)
        cfg = CFGBuilder(hir, class_registry=class_registry).build()
        pairs.append((hir, cfg))

    # Compile methods (once per defining class; skip inherited; skip @contract interfaces)
    compiled_method_names: set[str] = set()
    for ci in class_registry.values():
        if ci.contract_hash is not None:
            continue  # @contract interface — methods are not compiled as local functions
        for mi in ci.methods.values():
            if mi.compiled_name in compiled_method_names:
                continue  # already compiled (inherited from parent)
            compiled_method_names.add(mi.compiled_name)
            fn_filename = getattr(mi.ast_node, "_src_file", filename)
            hir = HIRBuilder(
                signatures,
                statics=statics,
                func_defaults=func_defaults,
                class_registry=class_registry,
                current_class=ci.name,
                module_names=module_names,
                aliases=aliases,
                syscall_fn_specs=syscall_fn_specs,
                syscall_module_fn_specs=syscall_module_fn_specs,
                event_fn_specs=event_fn_specs,
                iterator_names=iterator_names,
                findoptions_names=findoptions_names,
                callflags_names=callflags_names,
                namedcurvehash_names=namedcurvehash_names,
                witnessscope_names=witnessscope_names,
                witnessruleaction_names=witnessruleaction_names,
                witnessconditiontype_names=witnessconditiontype_names,
                module_fn_maps=module_fn_maps,
                filename=fn_filename,
            ).build_method(mi.ast_node, mi.kind)
            cfg = CFGBuilder(hir, class_registry=class_registry).build()
            pairs.append((hir, cfg))

    # @public(safe=True) callgraph check — walk HIR of each safe entry point and
    # reject any that can reach a state-modifying storage syscall.
    all_public = {**public_decorators, **public_method_compiled}
    safe_fn_names = {fn_name for fn_name, (_, safe) in all_public.items() if safe}
    if safe_fn_names:
        hir_fn_map: dict[str, HIRFunction] = {hir.name: hir for hir, _ in pairs}
        fn_node_by_name = {fn.name: fn for fn in fn_nodes}
        for fn_name in safe_fn_names:
            if fn_name not in hir_fn_map:
                continue
            write_ops = _collect_write_ops(
                hir_fn_map[fn_name].body, hir_fn_map, visited={fn_name}
            )
            if write_ops:
                op_name, op_lineno, op_col, op_file = write_ops[0]
                op_loc_parts: list[str] = []
                if op_file:
                    op_loc_parts.append(op_file)
                if op_lineno is not None:
                    loc = f"line {op_lineno}"
                    if op_col is not None:
                        loc += f", col {op_col + 1}"
                    op_loc_parts.append(loc)
                op_loc = (" at " + ", ".join(op_loc_parts)) if op_loc_parts else ""
                _fn_node = fn_node_by_name.get(fn_name)
                raise TypecheckError(
                    f"Function '{fn_name}' is marked @public(safe=True) but calls the "
                    f"state-modifying operation '{op_name}'{op_loc}. Either remove the "
                    f"write operation or change to @public(safe=False).",
                    lineno=_fn_node.lineno if _fn_node else None,
                    col_offset=_fn_node.col_offset if _fn_node else None,
                    filename=(
                        getattr(_fn_node, "_src_file", filename)
                        if _fn_node
                        else filename
                    ),
                )

    # Permission validation: if the manifest overrides permissions with a non-trivial
    # list, verify that every static external contract call is covered.
    if manifest_override and "permissions" in manifest_override:
        perms: list[dict] = manifest_override["permissions"]
        has_full_wildcard = any(
            p.get("contract") == "*" and p.get("methods") == "*" for p in perms
        )
        if not has_full_wildcard:
            has_group = any(
                p.get("contract", "").startswith(("02", "03")) for p in perms
            )
            if has_group:
                for p in perms:
                    if p.get("contract", "").startswith(("02", "03")):
                        prefix = _loc(
                            p.get("_filename"), p.get("_lineno"), p.get("_col_offset")
                        )
                        warnings.warn(
                            f"{prefix}ContractManifest contains a group-based permission; "
                            "external call permissions cannot be statically validated.",
                            CompilerWarning,
                            stacklevel=2,
                        )
            _perm_fn_map: dict[str, HIRFunction] = {h.name: h for h, _ in pairs}
            all_ext_calls: list[tuple[bytes, str]] = []
            all_dyn_locs: list[tuple[Optional[int], Optional[int], Optional[str]]] = []
            for hir_fn, _ in pairs:
                ext_calls, dyn_locs = _collect_contract_calls(hir_fn.body, _perm_fn_map)
                all_ext_calls.extend(ext_calls)
                all_dyn_locs.extend(dyn_locs)
            seen_dyn: set[tuple] = set()
            for dyn_lineno, dyn_col, dyn_file in all_dyn_locs:
                key = (dyn_lineno, dyn_col, dyn_file)
                if key in seen_dyn:
                    continue
                seen_dyn.add(key)
                prefix = _loc(dyn_file, dyn_lineno, dyn_col)
                warnings.warn(
                    f"{prefix}call_contract() (dynamic dispatch) cannot be "
                    "permission-validated at compile time.",
                    CompilerWarning,
                    stacklevel=2,
                )
            if not has_group:
                permitted: list[tuple[Optional[bytes], Optional[list[str]]]] = []
                for p in perms:
                    c = p.get("contract", "*")
                    m = p.get("methods", "*")
                    p_hash = None if c == "*" else UInt160.from_string(c).to_array()
                    p_methods = (
                        None if m == "*" else (m if isinstance(m, list) else [m])
                    )
                    permitted.append((p_hash, p_methods))
                missing: list[tuple[str, str]] = []
                seen_calls: set[tuple[bytes, str]] = set()
                for call_hash, call_method in all_ext_calls:
                    key = (call_hash, call_method)
                    if key in seen_calls:
                        continue
                    seen_calls.add(key)
                    covered = any(
                        (p_hash is None or p_hash == call_hash)
                        and (p_methods is None or call_method in p_methods)
                        for p_hash, p_methods in permitted
                    )
                    if not covered:
                        hash_str = "0x" + call_hash[::-1].hex()
                        missing.append((hash_str, call_method))
                if missing:
                    lines = [f"  Contract: {h} Method: {m}" for h, m in missing]
                    raise TypecheckError(
                        "ContractManifest permissions do not cover the following "
                        "external contract calls:\n"
                        + "\n".join(lines)
                        + "\nAdd the missing permissions or use "
                        "Permission(contract='*', methods='*').",
                        filename=filename,
                    )

    # Linearize all functions into a shared emitter
    shared_em = Emitter()
    call_fixups: list[tuple[int, int, str]] = []
    func_offsets: dict[str, int] = {}

    # Emit _initialize preamble if any static fields are declared
    if statics:
        func_offsets["_initialize"] = 0
        shared_em.emit_opcode(OpCode.INITSSLOT)
        shared_em.emit_byte(len(statics))
        for slot, t, raw_val in static_inits:
            _emit_static_literal(shared_em, raw_val, t, filename=filename)
            shared_em.emit_opcode(OpCode.STSFLD)
            shared_em.emit_byte(slot)
        shared_em.emit_opcode(OpCode.RET)

    for hir, cfg in pairs:
        lin = Linearizer(cfg, hir, emitter=shared_em, call_fixups=call_fixups)
        func_offsets[hir.name] = lin.generate_into()

    # Emit int.to_bytes helper functions once for each variant referenced by the compiled code.
    # We discover which variants are needed by scanning call_fixups for __to_bytes_* names.
    needed_to_bytes = {
        func_name
        for _, _, func_name in call_fixups
        if func_name.startswith("__to_bytes_")
    }
    for variant in sorted(needed_to_bytes):  # deterministic order
        func_offsets[variant] = shared_em.pos()
        if variant == "__to_bytes_little_unsigned":
            _emit_to_bytes_helper(shared_em, "little", False)
        elif variant == "__to_bytes_little_signed":
            _emit_to_bytes_helper(shared_em, "little", True)
        elif variant == "__to_bytes_big_unsigned":
            _emit_to_bytes_helper(shared_em, "big", False)
        elif variant == "__to_bytes_big_signed":
            _emit_to_bytes_helper(shared_em, "big", True)

    # Patch CALL_L fixups now that all function offsets are known
    for placeholder_pos, call_opcode_pos, func_name in call_fixups:
        if func_name not in func_offsets:
            raise TypecheckError(f"Undefined function '{func_name}'", filename=filename)
        shared_em.patch_i32(placeholder_pos, call_opcode_pos, func_offsets[func_name])

    public_methods_info: list[_PublicMethodInfo] = []
    if statics:
        public_methods_info.append(
            _PublicMethodInfo(name="_initialize", offset=0, params=[], return_type=NONE)
        )
    for hir, _ in pairs:
        dec = public_decorators.get(hir.name) or public_method_compiled.get(hir.name)
        if dec is None:
            continue
        alias, safe = dec
        public_methods_info.append(
            _PublicMethodInfo(
                name=(
                    alias
                    if alias is not None
                    else reverse_mangle.get(hir.name, hir.name)
                ),
                offset=func_offsets[hir.name],
                params=list(hir.args),
                return_type=hir.return_type,
                safe=safe,
            )
        )

    return (
        shared_em.bytecode(),
        public_methods_info,
        list(event_fn_specs.values()),
        manifest_override,
    )


def compile_module(
    source: str,
    search_path: Optional[str] = None,
    filename: Optional[str] = None,
) -> bytes:
    bytecode, _, _, _ = _compile_full(
        source, search_path=search_path, filename=filename
    )
    return bytecode


def compile_function(source: str) -> bytes:
    return compile_module(source)


def compile_to_nef(source: str, output_path: str) -> None:
    """Compile *source*, write <output_path> (.nef) and <stem>.manifest.json."""
    abs_output = os.path.abspath(output_path)
    search_path = os.path.dirname(abs_output)
    src_file = os.path.splitext(abs_output)[0] + ".py"
    script, public_methods, event_infos, manifest_override = _compile_full(
        source, search_path=search_path, filename=src_file
    )

    # NEF
    nef = NEF(compiler_name="hyper", script=script)
    nef_path = os.path.splitext(output_path)[0] + ".nef"
    try:
        with open(nef_path, "wb") as f:
            f.write(nef.to_array())
    except OSError as e:
        raise OSError(f"Failed to write NEF file '{nef_path}': {e}") from e

    # Manifest
    contract_name = os.path.splitext(os.path.basename(output_path))[0]
    manifest_path = os.path.splitext(output_path)[0] + ".manifest.json"

    methods = [
        ContractMethodDescriptor(
            name=m.name,
            offset=m.offset,
            parameters=[
                ContractParameterDefinition(
                    param_name, _type_to_contract_param(param_type)
                )
                for param_name, param_type in m.params
            ],
            return_type=_type_to_contract_param(m.return_type),
            safe=m.safe,
        )
        for m in public_methods
    ]
    events = [
        ContractEventDescriptor(
            name=e.event_name,
            parameters=[
                ContractParameterDefinition(
                    param_name, _type_to_contract_param(param_type)
                )
                for param_name, param_type in e.params
            ],
        )
        for e in event_infos
    ]
    manifest = ContractManifest(contract_name)
    manifest.abi = ContractABI(methods=methods, events=events)

    manifest_json = manifest.to_json()
    if manifest_override:
        if "permissions" in manifest_override:
            manifest_override["permissions"] = [
                {k: v for k, v in p.items() if not k.startswith("_")}
                for p in manifest_override["permissions"]
            ]
        manifest_json.update(manifest_override)

    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_json, f, indent=4)
    except OSError as e:
        raise OSError(f"Failed to write manifest file '{manifest_path}': {e}") from e
