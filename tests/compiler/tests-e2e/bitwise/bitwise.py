from neo3.sc.compiletime import public


@public
def bitwise_and(a: int, b: int) -> int:
    return a & b


@public
def bitwise_or(a: int, b: int) -> int:
    return a | b


@public
def bitwise_xor(a: int, b: int) -> int:
    return a ^ b


@public
def bitwise_not(a: int) -> int:
    return ~a


@public
def left_shift(a: int, n: int) -> int:
    return a << n


@public
def right_shift(a: int, n: int) -> int:
    return a >> n


@public
def aug_and(a: int, b: int) -> int:
    a &= b
    return a


@public
def aug_or(a: int, b: int) -> int:
    a |= b
    return a


@public
def aug_xor(a: int, b: int) -> int:
    a ^= b
    return a


@public
def aug_shl(a: int, n: int) -> int:
    a <<= n
    return a


@public
def aug_shr(a: int, n: int) -> int:
    a >>= n
    return a
