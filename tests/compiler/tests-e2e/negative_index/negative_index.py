from neo3.sc.compiletime import public


@public
def list_get(idx: int) -> int:
    x: list[int] = [10, 20, 30, 40, 50]
    return x[idx]


@public
def list_get_literal_last() -> int:
    x: list[int] = [10, 20, 30, 40, 50]
    return x[-1]


@public
def list_get_literal_first() -> int:
    x: list[int] = [10, 20, 30, 40, 50]
    return x[-5]


@public
def list_get_param(xs: list[int]) -> int:
    return xs[-1]


@public
def list_set(idx: int, val: int) -> list[int]:
    x: list[int] = [10, 20, 30, 40, 50]
    x[idx] = val
    return x


@public
def list_set_literal_last(val: int) -> list[int]:
    x: list[int] = [10, 20, 30, 40, 50]
    x[-1] = val
    return x


@public
def bytes_get(data: bytes, idx: int) -> int:
    return data[idx]


@public
def bytes_get_literal_last(data: bytes) -> int:
    return data[-1]


@public
def bytearray_set(data: bytes, idx: int, val: int) -> bytes:
    ba: bytearray = bytearray(data)
    ba[idx] = val
    return bytes(ba)


@public
def str_get(s: str, idx: int) -> str:
    return s[idx]


@public
def tuple_get_last() -> int:
    t: tuple[int, int, int] = (1, 2, 3)
    return t[-1]


@public
def dict_negative_key(k: int) -> int:
    d: dict[int, int] = {-1: 7, 1: 9}
    return d[k]


@public
def while_last_countdown() -> int:
    x: list[int] = [9, 9, 4]
    count: int = 0
    while x[-1] > 0:
        x[-1] = x[-1] - 1
        count += 1
    return count


@public
def bytes_slice_from(data: bytes, start: int) -> bytes:
    return data[start:]


@public
def bytes_slice_to(data: bytes, stop: int) -> bytes:
    return data[:stop]


@public
def bytes_slice_range(data: bytes, start: int, stop: int) -> bytes:
    return data[start:stop]


@public
def bytes_slice_step(data: bytes, start: int, stop: int) -> bytes:
    return data[start:stop:2]


@public
def bytes_slice_literal_last_two(data: bytes) -> bytes:
    return data[-2:]


@public
def str_slice_range(s: str, start: int, stop: int) -> str:
    return s[start:stop]
