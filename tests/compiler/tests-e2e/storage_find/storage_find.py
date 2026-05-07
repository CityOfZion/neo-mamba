from typing import Any

from neo3.sc.compiletime import public
from neo3.sc.storage import find, put
from neo3.sc.types import FindOptions


@public
def _deploy(data: Any, update: bool) -> None:
    put(b"data1", b"fizz")
    put(b"data2", b"buzz")
    put(b"data3", b"unit")
    put(b"data4", b"test")


@public
def find_keys(prefix: bytes) -> list[bytes]:
    list_: list[bytes] = []
    for key in find(prefix, FindOptions.KEYS_ONLY):
        list_.append(key)
    return list_
