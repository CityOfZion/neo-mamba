from neo3.sc.compiletime import public


@public
def int_eq(a: int, b: int) -> bool:
    return a == b


@public
def int_ne(a: int, b: int) -> bool:
    return a != b


@public
def int_lt(a: int, b: int) -> bool:
    return a < b


@public
def int_le(a: int, b: int) -> bool:
    return a <= b


@public
def int_gt(a: int, b: int) -> bool:
    return a > b


@public
def int_ge(a: int, b: int) -> bool:
    return a >= b


@public
def str_eq(a: str, b: str) -> bool:
    return a == b


@public
def str_ne(a: str, b: str) -> bool:
    return a != b


@public
def bytes_eq(a: bytes, b: bytes) -> bool:
    return a == b


@public
def bytes_ne(a: bytes, b: bytes) -> bool:
    return a != b


@public
def in_range(x: int, lo: int, hi: int) -> bool:
    return lo <= x <= hi
