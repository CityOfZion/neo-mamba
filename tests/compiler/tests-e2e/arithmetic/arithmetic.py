from neo3.sc.compiletime import public


@public
def add(a: int, b: int) -> int:
    return a + b


@public
def subtract(a: int, b: int) -> int:
    return a - b


@public
def multiply(a: int, b: int) -> int:
    return a * b


@public
def divide(a: int, b: int) -> int:
    return a // b


@public
def modulo(a: int, b: int) -> int:
    return a % b


@public
def power(base: int, exp: int) -> int:
    return base**exp


@public
def absolute(a: int) -> int:
    return abs(a)


@public
def minimum(a: int, b: int) -> int:
    return min(a, b)


@public
def maximum(a: int, b: int) -> int:
    return max(a, b)


@public
def negate(a: int) -> int:
    return -a


@public
def aug_add(a: int, b: int) -> int:
    a += b
    return a


@public
def aug_sub(a: int, b: int) -> int:
    a -= b
    return a


@public
def aug_mul(a: int, b: int) -> int:
    a *= b
    return a


@public
def aug_div(a: int, b: int) -> int:
    a //= b
    return a


@public
def aug_mod(a: int, b: int) -> int:
    a %= b
    return a
