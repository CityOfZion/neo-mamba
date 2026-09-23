from neo3.sc.compiletime import public


@public
def pop_default_value() -> int:
    x: list[int] = [1, 2, 3, 4, 5]
    return x.pop()


@public
def pop_default_remaining() -> list[int]:
    x: list[int] = [1, 2, 3, 4, 5]
    x.pop()
    return x


@public
def pop_value(idx: int) -> int:
    x: list[int] = [1, 2, 3, 4, 5]
    return x.pop(idx)


@public
def pop_remaining(idx: int) -> list[int]:
    x: list[int] = [1, 2, 3, 4, 5]
    x.pop(idx)
    return x


@public
def pop_until_empty() -> list[int]:
    x: list[int] = [1, 2, 3]
    x.pop()
    x.pop()
    x.pop()
    return x


@public
def pop_out_of_range() -> int:
    x: list[int] = [1, 2, 3]
    return x.pop(-100)
