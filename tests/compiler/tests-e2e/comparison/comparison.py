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
def bytes_concat_eq(a: bytes, x: bytes, y: bytes) -> bool:
    return a == (x + y)


@public
def bytes_slice_eq(a: bytes, x: bytes) -> bool:
    return a == x[1:]


@public
def str_index_eq(a: str, s: str, i: int) -> bool:
    return a == s[i]


@public
def bytearray_eq(a: bytearray, b: bytearray) -> bool:
    return a == b


@public
def bytearray_ne(a: bytearray, b: bytearray) -> bool:
    return a != b


@public
def bytearray_bytes_eq(a: bytearray, b: bytes) -> bool:
    return a == b


@public
def in_range(x: int, lo: int, hi: int) -> bool:
    return lo <= x <= hi
