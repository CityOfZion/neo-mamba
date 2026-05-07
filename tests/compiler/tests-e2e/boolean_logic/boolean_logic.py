from neo3.sc.compiletime import public


@public
def bool_and(a: bool, b: bool) -> bool:
    return a and b


@public
def bool_or(a: bool, b: bool) -> bool:
    return a or b


@public
def bool_not(a: bool) -> bool:
    return not a


@public
def and3(a: bool, b: bool, c: bool) -> bool:
    return a and b and c


@public
def or3(a: bool, b: bool, c: bool) -> bool:
    return a or b or c


@public
def and_or(a: bool, b: bool, c: bool) -> bool:
    return a and b or c


@public
def not_and(a: bool, b: bool) -> bool:
    return not a and b


@public
def not_or(a: bool, b: bool) -> bool:
    return not a or b


@public
def not_not(a: bool) -> bool:
    return not not a


@public
def and_sc(a: bool, b: int, c: int) -> bool:
    # If a is False, short-circuit prevents evaluating b // c
    return a and (b // c == 0)


@public
def or_sc(a: bool, b: int, c: int) -> bool:
    # If a is True, short-circuit prevents evaluating b // c
    return a or (b // c == 0)
