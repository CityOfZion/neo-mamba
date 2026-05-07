from typing import Any, Dict

from neo3.sc.compiletime import public

# ── str ──────────────────────────────────────────────────────────


@public
def str_len(s: str) -> int:
    return len(s)


@public
def str_concat(a: str, b: str) -> str:
    return a + b


@public
def str_index(s: str, i: int) -> str:
    return s[i]


@public
def str_slice_left(s: str, n: int) -> str:
    return s[:n]


@public
def str_slice_mid(s: str, start: int, stop: int) -> str:
    return s[start:stop]


@public
def str_slice_rest(s: str, start: int) -> str:
    return s[start:]


@public
def str_slice_step2(s: str) -> str:
    return s[0:6:2]


# ── bytes ─────────────────────────────────────────────────────────


@public
def bytes_len() -> int:
    b: bytes = b"\x01\x02\x03\x04\x05"
    return len(b)


@public
def bytes_index(b: bytes, i: int) -> int:
    return b[i]


@public
def bytes_concat(a: bytes, b: bytes) -> bytes:
    return a + b


@public
def bytes_slice(b: bytes, start: int, stop: int) -> bytes:
    return b[start:stop]


@public
def bytes_step_slice() -> bytes:
    b: bytes = b"\x01\x02\x03\x04\x05\x06"
    return b[0:6:2]


# ── bytearray ─────────────────────────────────────────────────────


@public
def bytearray_len() -> int:
    ba: bytearray = bytearray(5)
    return len(ba)


@public
def bytearray_index_zero_fill() -> int:
    ba: bytearray = bytearray(3)
    return ba[0]


@public
def bytearray_mutate() -> int:
    ba: bytearray = bytearray(3)
    ba[1] = 99
    return ba[1]


# ── list[T] ──────────────────────────────────────────────────────


@public
def list_empty_len() -> int:
    lst: list[int] = []
    return len(lst)


@public
def list_literal_len() -> int:
    lst: list[int] = [1, 2, 3]
    return len(lst)


@public
def list_append_len() -> int:
    lst: list[int] = []
    lst.append(10)
    lst.append(20)
    return len(lst)


@public
def list_literal_index() -> int:
    lst: list[int] = [10, 20, 30]
    return lst[1]


@public
def list_mutate() -> int:
    lst: list[int] = [1, 2, 3]
    lst[0] = 99
    return lst[0]


@public
def list_for_sum() -> int:
    lst: list[int] = [1, 2, 3, 4, 5]
    total: int = 0
    for x in lst:
        total += x
    return total


@public
def list_build_and_sum() -> int:
    lst: list[int] = []
    lst.append(10)
    lst.append(20)
    lst.append(30)
    total: int = 0
    for x in lst:
        total += x
    return total


@public
def list_bool_count() -> int:
    flags: list[bool] = [True, False, True, True, False]
    count: int = 0
    for f in flags:
        if f:
            count += 1
    return count


# ── dict[K, V] ───────────────────────────────────────────────────


@public
def dict_set_get() -> int:
    d: dict[str, int] = {}
    d["key"] = 42
    return d["key"]


@public
def dict_literal_len() -> int:
    d: dict[int, int] = {1: 10, 2: 20, 3: 30}
    return len(d)


@public
def dict_membership_present() -> bool:
    d: dict[str, int] = {"a": 1, "b": 2}
    return "a" in d


@public
def dict_membership_absent() -> bool:
    d: dict[str, int] = {"a": 1, "b": 2}
    return "c" in d


@public
def dict_update_value() -> int:
    d: dict[str, int] = {"x": 10}
    d["x"] = 99
    return d["x"]


@public
def dict_values_list() -> list[int]:
    d: dict[str, int] = {"b": 20, "a": 10, "c": 30}
    result: list[int] = []
    for v in d.values():
        result.append(v)
    return result


@public
def dict_keys_list() -> list[int]:
    d: dict[int, bool] = {3: True, 1: False, 2: True}
    result: list[int] = []
    for k in d.keys():
        result.append(k)
    return result


@public
def dict_items_keys_in_order() -> list[int]:
    d: dict[int, int] = {4: 5, 2: 3}
    result: list[int] = []
    for k, v in d.items():
        result.append(k)
    return result


# ── Dict[str, Any] — heterogeneous values ────────────────────────


@public
def dict_any_get_int() -> int:
    d: Dict[str, Any] = {"count": 42, "label": "hello"}
    return d["count"]


@public
def dict_any_get_str() -> str:
    d: Dict[str, Any] = {"count": 42, "label": "hello"}
    return d["label"]
