from neo3.sc.compiletime import public


@public
def enum_sum_indices(lst: list[int]) -> int:
    """Sum of all enumerate indices."""
    s: int = 0
    for i, x in enumerate(lst):
        s += i
    return s


@public
def enum_sum_values(lst: list[int]) -> int:
    """Sum of all enumerate values."""
    s: int = 0
    for i, x in enumerate(lst):
        s += x
    return s


@public
def enum_sum_both(lst: list[int]) -> int:
    """Sum of index * value for each element."""
    s: int = 0
    for i, x in enumerate(lst):
        s += i * x
    return s


@public
def enum_with_start(lst: list[int], start: int) -> int:
    """Sum of enumerate indices with a custom start."""
    s: int = 0
    for i, x in enumerate(lst, start):
        s += i
    return s


@public
def enum_break(lst: list[int]) -> int:
    """Return the enumerate index of the first zero value, or -1."""
    for i, x in enumerate(lst):
        if x == 0:
            return i
    return -1


@public
def enum_continue(lst: list[int]) -> list[int]:
    """Collect indices where value > 0, skipping non-positives."""
    result: list[int] = []
    for i, x in enumerate(lst):
        if x <= 0:
            continue
        result.append(i)
    return result


@public
def enum_for_else(lst: list[int]) -> int:
    """Return index of first negative, or -1 via else."""
    for i, x in enumerate(lst):
        if x < 0:
            return i
    else:
        return -1
    return -1


@public
def enum_empty(lst: list[int]) -> int:
    """enumerate over empty list returns 0."""
    s: int = 0
    for i, x in enumerate(lst):
        s += i + x
    return s
