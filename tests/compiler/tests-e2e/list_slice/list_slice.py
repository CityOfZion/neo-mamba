from neo3.sc.compiletime import public


@public
def slice_from(start: int) -> list[int]:
    x: list[int] = [1, 2, 3, 4, 5]
    return x[start:]


@public
def slice_to(stop: int) -> list[int]:
    x: list[int] = [1, 2, 3, 4, 5]
    return x[:stop]


@public
def slice_range(start: int, stop: int) -> list[int]:
    x: list[int] = [1, 2, 3, 4, 5]
    return x[start:stop]


@public
def slice_step(start: int, stop: int, step: int) -> list[int]:
    x: list[int] = [1, 2, 3, 4, 5]
    return x[start:stop:step]


@public
def slice_full() -> list[int]:
    x: list[int] = [1, 2, 3, 4, 5]
    return x[:]


@public
def slice_str(start: int) -> list[str]:
    x: list[str] = ["a", "b", "c", "d", "e"]
    return x[start:]
