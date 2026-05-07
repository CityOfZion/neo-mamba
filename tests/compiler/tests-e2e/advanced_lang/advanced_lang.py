from neo3.sc.compiletime import public
from typing import Optional

# ── static fields ──────────────────────────────────────────────────────────────
# Static fields are initialised once per invocation (before the called method runs).
# They are shared across CALL_L helper calls within the same invocation.

counter: int = 0
label: str = "hello"


def _bump() -> None:
    global counter
    counter += 1


@public
def static_read_label() -> str:
    # Verifies _initialize set the string field correctly.
    return label


@public
def static_bump_twice() -> int:
    # Verifies static is shared across internal CALL_L calls.
    _bump()
    _bump()
    return counter


# ── ternary ────────────────────────────────────────────────────────────────────


@public
def abs_val(x: int) -> int:
    return x if x >= 0 else -x


@public
def clamp(x: int, lo: int, hi: int) -> int:
    y: int = x if x >= lo else lo
    return y if y <= hi else hi


# ── None / Optional ────────────────────────────────────────────────────────────


@public
def optional_or_default(flag: bool) -> int:
    x: Optional[int] = None
    if flag:
        x = 42
    if x is None:
        return -1
    return x


@public
def is_not_none(flag: bool) -> bool:
    x: Optional[int] = None
    if flag:
        x = 99
    return x is not None


# ── assert ─────────────────────────────────────────────────────────────────────


@public
def guarded_add(a: int, b: int) -> int:
    assert a >= 0
    assert b >= 0
    return a + b


@public
def checked_div(a: int, b: int) -> int:
    assert b != 0, "division by zero"
    return a // b


# ── raise ──────────────────────────────────────────────────────────────────────


@public
def safe_input(n: int) -> int:
    if n < 0:
        raise ValueError("negative input")
    return n


# ── for...else ────────────────────────────────────────────────────────────────


@public
def range_sum_else(n: int) -> int:
    # else fires when loop completes without break
    result: int = 0
    for i in range(n):
        result += i
    else:
        result += 1000
    return result


@public
def range_sum_break(n: int, stop: int) -> int:
    # break skips else
    result: int = 0
    for i in range(n):
        if i == stop:
            break
        result += i
    else:
        result += 1000
    return result


# ── tuples ────────────────────────────────────────────────────────────────────


@public
def swap(a: int, b: int) -> tuple[int, int]:
    return (b, a)


@public
def divmod_pair(a: int, b: int) -> tuple[int, int]:
    q: int = a // b
    r: int = a % b
    return (q, r)


@public
def tuple_constant_index() -> int:
    t: tuple[int, int, int] = (10, 20, 30)
    return t[1]


@public
def unpack_swap() -> int:
    a, b = swap(3, 7)
    return a - b
