# SC Interop Layer — Authoring Guide

This directory defines the smart contract interoperability layer. It exposes NeoVM syscalls and native contract interfaces as ordinary Python functions and classes that contract authors can import.

---

## Directory Layout

```
neo3/sc/
  compiletime/__init__.py   # @syscall, @public, @contract, @display_name, @call_flags, @event decorators
  runtime/__init__.py        # Direct-SYSCALL wrappers: check_witness, get_random, etc.
  storage/__init__.py        # Direct-SYSCALL wrappers: get, put, delete, find
  types/__init__.py          # Interop types: UInt160, UInt256, ECPoint, CallFlags, FindOptions, ...
  utils/
    __init__.py              # call_contract() dynamic intrinsic + abort()
    iterator.py              # Iterator type stub
  contracts/
    neotoken.py              # @contract wrapper for NeoToken
    gastoken.py              # @contract wrapper for GasToken
    management.py            # @contract wrapper for ContractManagement
    stdlib.py                # @contract wrapper for StdLib
    cryptolib.py             # @contract wrapper for CryptoLib
    ledger.py                # @contract wrapper for LedgerContract
    policy.py                # @contract wrapper for PolicyContract
    rolemanagement.py        # @contract wrapper for RoleManagement
```

---

## Two Dispatch Paths

The compiler has two distinct paths for interop calls:

| Path | How it works | When to use |
|------|-------------|-------------|
| **@syscall** | Function decorated `@syscall("System.X.Y")` → loaded at compile-init → emits a `SYSCALL` opcode with the 4-byte interop hash | Low-level syscalls with no state management (runtime, storage primitives) |
| **@contract** | Class decorated `@contract("0x...")` → static methods compile to `System.Contract.Call` with the contract hash | Native contract wrappers (NeoToken, GasToken, StdLib, etc.) |

---

## Adding a @syscall Function

Use this for any function that maps directly to a single NeoVM interop syscall.

### Pattern

```python
# neo3/compiler/sc/runtime/__init__.py  (or storage/__init__.py)

from neo3.sc.compiletime import syscall
from neo3.sc.types import UInt160  # import any needed types

@syscall("System.Runtime.CheckWitness")
def check_witness(hash: UInt160) -> bool:
    pass
```

### Rules

1. **Decorator**: `@syscall("System.X.Y")` — the exact interop method name. The 4-byte hash is `sha256(name)[:4]` (little-endian). You never write the hash manually.
2. **Module**: The function must live in a module listed in `_SYSCALL_DECORATOR_MODULES` in `compiler.py` (currently `neo3.sc.runtime` and `neo3.sc.storage`). Functions in other modules are not auto-loaded as syscalls.
3. **Body**: Must be `pass` — the body is never compiled.
4. **Annotations**: All parameters and the return type must use types from `neo3.sc.types` or Python builtins (`int`, `bool`, `str`, `bytes`, `None`). `Optional[T]` is supported. The return type `None` means the call is void (statement-only).
5. **Push order**: Args are pushed in reverse order (last arg on top of the stack). This is handled automatically — no manual ordering needed.
6. **Defaults**: Integer defaults (including `FindOptions.<ATTR>` and `CallFlags.<ATTR>` attribute accesses) are supported and injected at the call site when an arg is omitted.

### How the compiler loads syscall specs

At compile-time, `_load_syscall_specs(module_name, search_path)` reads the source file and extracts every `@syscall`-decorated function into a `_SyscallSpec`. The spec captures: hash, param types, return type, push order, and any integer defaults. When the compiled contract imports the function (`from neo3.sc.runtime import check_witness`), the import is intercepted and the spec is registered; the source is **not** bundled.

---

## Adding a @contract Wrapper

Use this for on-chain contracts that expose multiple methods (native contracts, protocol-level contracts, your own deployed contracts).

### Pattern

```python
# x/compiler/sc/contracts/mywrapper.py

from typing import Any, Optional
from neo3.sc.compiletime import call_flags, contract, display_name
from neo3.sc.types import CallFlags, UInt160

@contract("0xaabbccdd...")   # 20-byte script hash, little-endian hex with 0x prefix
class MyContract:
    """Brief description."""

    hash: UInt160  # field annotation — silently ignored by the compiler, useful for type hints

    @staticmethod
    @call_flags(CallFlags.READ_STATES)   # optional; default is CallFlags.ALL
    @display_name("onChainMethodName")   # optional; defaults to the Python method name
    def my_method(arg1: bytes, arg2: int) -> int:
        pass
```

### Rules

1. **Decorator**: `@contract("0x...")` — the hex string is converted to a 20-byte little-endian `UInt160` at compile time. The `0x` prefix is required.
2. **Methods**: Only `@staticmethod` methods with `pass` bodies are supported.
3. **`@display_name`**: Use this when the on-chain method name differs from the Python name (e.g. `totalSupply` vs `total_supply`). Without it, the Python method name is used as the on-chain method name.
4. **`@call_flags`**: Override the `CallFlags` for a specific method. Defaults to `CallFlags.ALL` (= 0x0F). Use `CallFlags.READ_STATES` for read-only methods to reduce gas cost.
5. **Annotations**: All parameters and return types must use supported compiler types (see `types/__init__.py`). Use `Any` from `typing` for stack-item arguments of unknown type. `object` is not supported — use `Any` instead.
6. **Body**: Must be `pass` — the body is never compiled.
7. **Defaults**: Constant default values (e.g. `data: Any = None`, `base: int = 10`) on `@contract` method parameters are injected at call sites when trailing args are omitted — same semantics as regular function defaults.
8. **`hash` field**: The `hash: UInt160` annotation is informational only; it does not compile to any bytecode.

### How the compiler resolves @contract calls

When the contract source imports a `@contract` class (e.g. `from neo3.sc.contracts.neotoken import NeoToken`), the compiler bundles the wrapper source into the compilation unit. The class is registered in the `ClassInfo` registry with `contract_hash` set. When a static method is called (`NeoToken.balance_of(account)`), the compiler emits a `ContractCall` HIR node which the CFGBuilder translates to a `contract_call` StackInstr and the Linearizer emits as:

```
PUSH n_args   ; number of args
PACK          ; pack args into Array
PUSH call_flags
PUSH method_name (as PUSHDATA1)
PUSH contract_hash (as PUSHDATA1, 20-byte LE)
SYSCALL System.Contract.Call
```

---

## Adding a New Native Contract Wrapper (Step-by-Step)

1. Find the script hash at [Neo Docs Native Contracts](https://developers.neo.org/docs/n3/reference/scapi/framework/native) or `neo3/contracts/contract.py` in the neo-mamba package.
2. Create `x/compiler/sc/contracts/mycontract.py` following the `@contract` pattern above.
3. Add `from neo3.sc.contracts.mycontract import MyContract` to `x/compiler/sc/contracts/__init__.py`.
4. Verify with `_compile_full(src, search_path=<project_root>)` that a minimal contract using the new wrapper compiles.

---

## @display_name Convention

`@display_name("onChainName")` maps a Python snake_case method name to its camelCase on-chain counterpart:

```python
@staticmethod
@display_name("totalSupply")
def total_supply() -> int:
    pass
```

Without `@display_name`, the Python method name is used verbatim as the on-chain entry point name.

---

## Supported Types in Annotations

| Python annotation | NeoVM type |
|-------------------|-----------|
| `int` | Integer |
| `bool` | Boolean |
| `str` | ByteString (UTF-8) |
| `bytes` | ByteString |
| `bytearray` | Buffer |
| `list` / `list[T]` | Array |
| `None` | Null (void return) |
| `Optional[T]` | T or Null |
| `Any` | any stack item |
| `UInt160` | 20-byte ByteString |
| `UInt256` | 32-byte ByteString |
| `ECPoint` | 33-byte ByteString |
| `Iterator` | NeoVM iterator handle |
| `CallFlags` | Integer (IntFlag) |
| `FindOptions` | Integer (IntFlag) |
| `TrimmedTransaction` | Struct (deserialized on Python side) |
| `ContractState` | Array (deserialized on Python side) |
| `NeoAccountState` | Struct (deserialized on Python side) |

**Note**: `object` is not a valid annotation — use `Any` instead.
