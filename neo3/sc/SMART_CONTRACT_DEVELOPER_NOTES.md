# Smart Contract Developer Notes

This compiler translates a typed subset of Python to NeoVM3 bytecode. Most Python you write will work as expected, but there are deviations. This document covers everything that differs from standard Python.

---

## Type Annotations

Function arguments and return types always need annotations. Local variables are inferred from the RHS on first assignment — annotations are optional unless the type cannot be inferred:

```python
def add(a: int, b: int) -> int:
    result = a + b      # inferred as int, no annotation needed
    result = result + 1
    return result

x = None                # compile error — cannot infer type from None
x: Optional[int] = None  # correct

items = []              # compile error — element type unknown
items: list[int] = []   # correct
```

---

## Supported Types

| Type | Notes |
|------|-------|
| `int` | Arbitrary-precision integer |
| `bool` | |
| `str` | Immutable UTF-8 byte string |
| `bytes` | Immutable byte string |
| `bytearray` | Mutable byte buffer |
| `list[T]` | Homogeneous dynamic array |
| `dict[K, V]` | Key must be `int`, `bool`, `str`, or `bytes` |
| `tuple[T1, T2, ...]` | Fixed-length, heterogeneous, immutable at compile time |
| `Optional[T]` | T or None |
| `None` | Null |
| `Any` | Escape hatch; compatible with all types in both directions |

`float`, `complex`, `set`, `frozenset`, and other Python types are **not supported**.

---

## Integer Division and Modulo

`//` and `%` truncate toward zero (C# `BigInteger` semantics), **not** toward negative infinity like Python.

```python
-7 // 2   # gives -3 in this compiler, -4 in Python
-7 % 2    # gives -1 in this compiler,  1 in Python
```

This only matters for negative operands. Positive operands behave identically.

---

## No Float Support

`x ** -2` is rejected at compile time — the result would be a float, which NeoVM cannot represent. Variable negative exponents compile but fault the VM at runtime.

---

## Type Conversions

These differ from Python in important ways:

| Call | Behaviour |
|------|-----------|
| `int(b)` where `b: bytes` | Interprets bytes as little-endian **signed** integer — NOT a decimal parse |
| `int(s)` where `s: str` | Calls StdLib `atoi`; only base 10 or 16 supported |
| `int("ff", 16)` | Returns **-1** — NeoVM BigInteger: if the high bit is set the value is negative. Prefix with `"0"` for positive: `int("0ff", 16)` → 255 |
| `str(x, 16)` where `x: int` | Returns hex string — Python raises `TypeError` for this call |
| `str(b)` where `b: bytes` | Returns raw bytes as a string — Python gives `"b'hello'"` |
| `bytes(x)` where `x: int` | Returns LE byte encoding — Python's `bytes(5)` creates 5 zero bytes |

---

## String and Bytes

**Ordering comparisons rejected:** `<`, `<=`, `>`, `>=` on `str`, `bytes`, or `bytearray` raise a compile error. NeoVM compares ByteStrings as little-endian integers, which gives opposite results to Python's lexicographic order.

**Augmented assignment is int-only:** `s += other` on a `str` is a compile error. Write `s = s + other` instead. This restriction applies to all augmented operators (`+=`, `-=`, `*=`, etc.) on non-int types.

**`x in seq` membership test only works for `dict`**, not `list` or `tuple`. Use an explicit loop to search a list.

**`s.split(sep, maxsplit=...)` — `maxsplit` not supported**, raises a compile error.

**f-strings:** `bytes`/`bytearray` values cannot be interpolated directly — call `.hex()` first. Format specs (`{x:08d}`) and `!r`/`!a` conversion flags are not supported.

---

## Boolean Operators Require `bool` Operands

`and`, `or`, and `not` all require operands that are statically typed `bool`. Python's general truthiness (non-zero integers, non-empty lists, etc.) is not supported.

```python
x: int = 5
if x:           # compile error — x is int, not bool
    pass
if not x:       # compile error — same reason
    pass
if x != 0:      # correct
    pass
```

---

## `isinstance`

Only single primitive types: `int`, `bool`, `str`, `bytes`, `bytearray`. Tuple-of-types (`isinstance(x, (int, str))`) is not supported. `list`, `dict`, and `tuple` are not supported because they are indistinguishable at runtime in NeoVM. Use `x is None` / `x is not None` for None checks.

**`bool` and `int` are distinct at the VM level** — `isinstance(x, int)` returns `False` for a `bool` value.

---

## Module-Level Variables Are Per-Invocation

Module-level variables are static fields that are **re-initialised on every contract invocation**. They are not persistent storage. Use the storage API for data that must survive between calls.

Initialiser values must be constant literals (`int`, `bool`, `str`, `bytes`, `None`).

```python
counter: int = 0   # reset to 0 on every invocation
```

---

## Exceptions

- Only bare `except:` is supported. Typed `except SomeError:` and `except SomeError as e:` are compile errors — NeoVM has no exception type system.
- `raise ExceptionType("msg")` works, but the exception type is ignored; only the message matters.
- Bare `raise` (re-raise) is not supported.
- `try/else` is not supported.
- At most one `except` clause per `try`.

---

## Default Argument Values

Defaults must be **constant literals** (`int`, `bool`, `str`, `bytes`, `None`). Expressions and negative integer literals are not allowed.

```python
def f(x: int, y: int = 5) -> int: ...   # ok
def f(x: int, y: int = -1) -> int: ...  # compile error
def f(x: int, y: int = other_var) -> int: ...  # compile error
```

---

## Tuples

- Elements must be accessed by a **compile-time integer constant** index (`t[0]`). Variable indexing (`t[i]`) is a compile error.

---

## `to_bytes` / `from_bytes`

- Overflow **faults the VM** instead of raising `OverflowError`.
- `length > 32` is undefined — NeoVM integers are at most 32 bytes.

---

## Imports

Only **local `.py` files** can be imported. The standard library and third-party packages are not available. Circular imports are rejected.

```python
from math import sqrt   # compile error
import os               # compile error
from .utils import helper  # ok — relative import of a local file
```

---

## Classes

- **No nested class definitions.**
- **No forward base-class references** (base class must be defined before the subclass in the source).
- Only zero-argument `super()` is supported (`super().method(args)`).

---

## `enumerate`

Only supported in the two-target `for i, x in enumerate(lst)` form. The iterable must be a `list[T]`; `enumerate(range(...))` is not supported.

---

## Comprehensions

Single generator only. Multiple generators (`[x for a in b for x in a]`) are rejected. The iterable must be a `list[T]` or `range(...)`.

---

## `print`

Maps to a Neo node log event (`System.Runtime.Log`). Accepts a single argument of type `str`, `bytes`, or `list[T]`. Lists are serialized to JSON before logging.

---

## `assert`

The condition must be `bool`. The message (if provided) must be `str`. A failing assert **faults the VM** (terminates the contract call), it does not raise a catchable exception.

---

## `global`

`global name` is supported, but `name` must already exist as a module-level variable. It cannot introduce new top-level names.

---

## Slicing

Step values of 0 or negative literal values are rejected at compile time. A variable step that evaluates to 0 at runtime will fault the VM.
