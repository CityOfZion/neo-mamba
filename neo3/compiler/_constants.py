from __future__ import annotations
import hashlib
import os

from neo3.contracts.contract import CONTRACT_HASHES as _CONTRACT_HASHES
from neo3 import vm as _neo3_vm
from neo3.core.types import UInt160 as _UInt160, UInt256 as _UInt256
from neo3.sc.types import (
    FindOptions as _FindOptions_enum,
    CallFlags as _CallFlags_enum,
    NamedCurveHash as _NamedCurveHash_enum,
)

# Interop constants for StdLib contract calls
_STDLIB_HASH: bytes = _CONTRACT_HASHES.STD_LIB.to_array()  # 20-byte UInt160 LE
_SYSCALL_CONTRACT_CALL: bytes = _neo3_vm.Syscalls.get_by_name(
    "System.Contract.Call"
).number.to_bytes(4, "little")
_SYSCALL_NOTIFY: bytes = _neo3_vm.Syscalls.get_by_name(
    "System.Runtime.Notify"
).number.to_bytes(4, "little")
# Syscall hashes derived from their interop method names — single source of truth.
_SYSCALL_RUNTIME_LOG: bytes = hashlib.sha256("System.Runtime.Log".encode()).digest()[:4]
_SYSCALL_ITERATOR_NEXT: bytes = hashlib.sha256(
    "System.Iterator.Next".encode()
).digest()[:4]
_SYSCALL_ITERATOR_VALUE: bytes = hashlib.sha256(
    "System.Iterator.Value".encode()
).digest()[:4]
_SYSCALL_STORAGE_PUT: bytes = hashlib.sha256(
    "System.Storage.Local.Put".encode()
).digest()[:4]
_SYSCALL_STORAGE_DELETE: bytes = hashlib.sha256(
    "System.Storage.Local.Delete".encode()
).digest()[:4]
# Map write-syscall hash → human-readable name used in error messages.
_WRITE_SYSCALL_NAMES: dict[bytes, str] = {
    _SYSCALL_STORAGE_PUT: "storage.put",
    _SYSCALL_STORAGE_DELETE: "storage.delete",
}


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

_ITERATOR_MODULE = "neo3.sc.utils.iterator"
_UTILS_MODULE = "neo3.sc.utils"
_TYPES_MODULE = "neo3.sc.types"
_RUNTIME_MODULE = "neo3.sc.runtime"
