from neo3.sc.compiletime import public

# Private helpers — not exposed in the ABI, called via CALL_L internally.


def _add(a: int, b: int) -> int:
    return a + b


def _mul(a: int, b: int) -> int:
    return a * b


@public
def compound(a: int, b: int, c: int) -> int:
    # Chained helper calls: a*b + c
    return _add(_mul(a, b), c)


@public
def factorial(n: int) -> int:
    # Direct recursion. factorial(0) = 1 by convention.
    if n <= 1:
        return 1
    return n * factorial(n - 1)


@public
def fibonacci(n: int) -> int:
    # Double recursion. fib(0)=0, fib(1)=1.
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)


# Mutual recursion: _is_even calls _is_odd and vice-versa.
# _is_odd is defined after _is_even — tests forward-reference resolution.


def _is_even(n: int) -> bool:
    if n == 0:
        return True
    return _is_odd(n - 1)


def _is_odd(n: int) -> bool:
    if n == 0:
        return False
    return _is_even(n - 1)


@public
def check_even(n: int) -> bool:
    return _is_even(n)


@public
def check_odd(n: int) -> bool:
    return _is_odd(n)


@public
def mutable_arg(x: int) -> int:
    # Reassigns the argument slot (STARG) and reads it back (LDARG).
    x = x + 10
    return x


@public
def gcd(a: int, b: int) -> int:
    # Iterative Euclidean algorithm — both argument slots reassigned each iteration.
    # NeoVM truncation-toward-zero % matches Python for non-negative inputs.
    while b != 0:
        temp: int = b
        b = a % b
        a = temp
    return a


@public
def void_noop(x: int) -> None:
    # Void function: emits bare RET (no PUSHNULL).
    y: int = x + 1
    return None


def _double(x: int) -> int:
    return x * 2


@public
def discard_return(x: int) -> int:
    _double(x)  # result intentionally discarded via DROP
    return x + 1
