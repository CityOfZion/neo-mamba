from typing import Any

from neo3.sc.compiletime import public
from neo3.sc.contracts.stdlib import StdLib
from neo3.sc.storage import find, put
from neo3.sc.types import FindOptions


@public
def _deploy(data: Any, update: bool) -> None:
    put(b"data1", b"fizz")
    put(b"data2", b"buzz")
    put(b"data3", b"unit")
    put(b"data4", b"test")
    # Serialized integers for DESERIALIZE_VALUES tests
    put(b"num1", StdLib.serialize(42))
    put(b"num2", StdLib.serialize(100))
    # Serialized [a, b] arrays for PICK_FIELD0 / PICK_FIELD1 tests
    put(b"pair1", StdLib.serialize([10, 20]))
    put(b"pair2", StdLib.serialize([30, 40]))


@public
def find_pairs(prefix: bytes) -> list[Any]:
    list_: list[Any] = []
    for item in find(prefix):
        list_.append(item)
    return list_


@public
def find_values_only(prefix: bytes) -> list[bytes]:
    list_: list[bytes] = []
    for value in find(prefix, FindOptions.VALUES_ONLY):
        list_.append(value)
    return list_


@public
def find_keys_remove_prefix(prefix: bytes) -> list[bytes]:
    list_: list[bytes] = []
    for key in find(prefix, FindOptions.KEYS_ONLY | FindOptions.REMOVE_PREFIX):
        list_.append(key)
    return list_


@public
def find_keys_backwards(prefix: bytes) -> list[bytes]:
    list_: list[bytes] = []
    for key in find(prefix, FindOptions.KEYS_ONLY | FindOptions.BACKWARDS):
        list_.append(key)
    return list_


@public
def find_keys_only(prefix: bytes) -> list[bytes]:
    list_: list[bytes] = []
    for key in find(prefix, FindOptions.KEYS_ONLY):
        list_.append(key)
    return list_


@public
def find_deserialize_values(prefix: bytes) -> list[Any]:
    list_: list[Any] = []
    for value in find(prefix, FindOptions.VALUES_ONLY | FindOptions.DESERIALIZE_VALUES):
        list_.append(value)
    return list_


@public
def find_pick_field0(prefix: bytes) -> list[Any]:
    list_: list[Any] = []
    for value in find(
        prefix,
        FindOptions.VALUES_ONLY
        | FindOptions.DESERIALIZE_VALUES
        | FindOptions.PICK_FIELD0,
    ):
        list_.append(value)
    return list_


@public
def find_pick_field1(prefix: bytes) -> list[Any]:
    list_: list[Any] = []
    for value in find(
        prefix,
        FindOptions.VALUES_ONLY
        | FindOptions.DESERIALIZE_VALUES
        | FindOptions.PICK_FIELD1,
    ):
        list_.append(value)
    return list_
