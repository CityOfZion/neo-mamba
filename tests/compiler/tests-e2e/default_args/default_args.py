from neo3.sc.compiletime import public
from typing import Optional

# ── single default ────────────────────────────────────────────────────────────


def _add(x: int, y: int = 5) -> int:
    return x + y


@public
def add_with_default(x: int) -> int:
    return _add(x)


@public
def add_explicit(x: int, y: int) -> int:
    return _add(x, y)


# ── multiple defaults ─────────────────────────────────────────────────────────


def _combine(a: int, b: int = 2, c: int = 3) -> int:
    return a + b + c


@public
def combine_all_defaults(a: int) -> int:
    return _combine(a)


@public
def combine_one_default(a: int, b: int) -> int:
    return _combine(a, b)


@public
def combine_no_defaults(a: int, b: int, c: int) -> int:
    return _combine(a, b, c)


# ── bool default ──────────────────────────────────────────────────────────────


def _guarded(x: int, flag: bool = True) -> int:
    if flag:
        return x * 2
    return x


@public
def guarded_default(x: int) -> int:
    return _guarded(x)


@public
def guarded_explicit_false(x: int) -> int:
    return _guarded(x, False)


# ── str default ───────────────────────────────────────────────────────────────


def _greet(name: str, prefix: str = "Hello") -> str:
    return prefix + name


@public
def greet_default(name: str) -> str:
    return _greet(name)


@public
def greet_explicit(name: str, prefix: str) -> str:
    return _greet(name, prefix)


# ── None default ─────────────────────────────────────────────────────────────


def _is_absent(x: Optional[int] = None) -> bool:
    return x is None


@public
def absent_default() -> bool:
    return _is_absent()


@public
def absent_explicit(x: int) -> bool:
    return _is_absent(x)


# ── all-defaults function ─────────────────────────────────────────────────────


def _point(x: int = 0, y: int = 0) -> int:
    return x + y


@public
def point_no_args() -> int:
    return _point()


@public
def point_one_arg(x: int) -> int:
    return _point(x)


@public
def point_two_args(x: int, y: int) -> int:
    return _point(x, y)
