from typing import Optional

from neo3.sc.compiletime import public
from neo3.sc.contracts.ledger import LedgerContract

# ── static field assignment narrowing ───────────────────────────────────────

_static_val: Optional[int] = None


@public
def static_field_narrowing(path: int) -> int:
    """Both if and else branches assign int to an Optional[int] static.
    The join-point type must be int so the final return compiles."""
    global _static_val
    if path == 1:
        _static_val = 10
    else:
        _static_val = 20
    return _static_val


# ── if/elif pattern (original bug) ──────────────────────────────────────────


@public
def block_index_by_path(path: int) -> int:
    """Each branch assigns Optional[TrimmedBlock], asserts non-None, then a
    shared return accesses .index.  Compiler must not leak then-branch narrowing
    into elif-branch, and must narrow the join-point type to TrimmedBlock."""
    if path == 1:
        b = LedgerContract.get_block(0)
        assert b is not None, "block not found"
    elif path == 2:
        b = LedgerContract.get_block(0)
        assert b is not None, "block not found"
    else:
        return -1
    return b.index


# ── none-check if: secondary assert in then must not leak to else ────────────


@public
def none_check_secondary_assert(a: Optional[int], b: Optional[int]) -> int:
    """if a is not None: assert b is not None (narrows b in then-body only).
    else-body must still treat b as Optional so it can guard with if b is None."""
    if a is not None:
        assert b is not None
        return a + b
    else:
        if b is None:
            return -1
        return b


# ── while/else: assert in body must not leak to else ────────────────────────


@public
def while_else_optional(x: Optional[int]) -> int:
    """while body asserts x is not None.  The else clause must still see
    Optional[int] and be able to do a is-None guard."""
    n: int = 0
    while n < 2:
        assert x is not None
        n = n + 1
    else:
        if x is None:
            return -1
        return x
    return 0


# ── try/except: catch assert must not leak into try body ─────────────────────


@public
def try_catch_optional(x: Optional[int]) -> int:
    """Assert x is not None in the try body; catch falls back to 0.
    Verifies correct visit order (try first) so the try body properly sees
    Optional[int] before the assert."""
    try:
        assert x is not None
        return x + 1
    except:
        return 0


# ── for/else: body assert must not leak to else ──────────────────────────────


@public
def for_else_optional(x: Optional[int]) -> int:
    """for-loop body asserts x is not None on each iteration.  The else clause
    must still see Optional[int] and be able to guard."""
    for i in range(2):
        assert x is not None
    else:
        if x is None:
            return -1
        return x
    return 0
