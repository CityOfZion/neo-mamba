from typing import Optional

from neo3.sc.compiletime import public
from neo3.sc.storage import get, put, delete, get_int as storage_get_int


@public
def store(key: bytes, value: bytes) -> None:
    put(key, value)


@public
def load(key: bytes) -> Optional[bytes]:
    return get(key)


@public
def remove(key: bytes) -> None:
    delete(key)


@public
def overwrite(key: bytes, first: bytes, second: bytes) -> bytes:
    put(key, first)
    put(key, second)
    result = get(key)
    if result is None:
        raise Exception("key not found")
    return result


@public
def round_trip(key: bytes, value: bytes) -> bytes:
    put(key, value)
    result = get(key)
    if result is None:
        raise Exception("key not found")
    return result


@public
def store_and_delete(key: bytes, value: bytes) -> None:
    put(key, value)
    delete(key)


@public
def get_int() -> int:
    key = b"mykey"
    put(key, (5).to_bytes())
    return storage_get_int(key)


@public
def put_int(x: int) -> int:
    key = b"mykey"
    put(key, x.to_bytes())
    return storage_get_int(key)
