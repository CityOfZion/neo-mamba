from neo3.sc.compiletime import public


@public
def insert_middle() -> list[int]:
    lst: list[int] = [1, 2, 4, 5]
    lst.insert(2, 3)
    return lst


@public
def insert_at_zero() -> list[int]:
    lst: list[int] = [2, 3, 4]
    lst.insert(0, 1)
    return lst


@public
def insert_at_end() -> list[int]:
    lst: list[int] = [1, 2, 3]
    lst.insert(3, 4)
    return lst


@public
def insert_into_empty() -> list[int]:
    lst: list[int] = []
    lst.insert(0, 99)
    return lst


@public
def insert_dynamic_index(idx: int) -> list[int]:
    lst: list[int] = [10, 20, 30]
    lst.insert(idx, 99)
    return lst


@public
def insert_str() -> list[str]:
    lst: list[str] = ["a", "c"]
    lst.insert(1, "b")
    return lst
