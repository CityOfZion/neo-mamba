from typing import Optional

from neo3.sc.compiletime import syscall
from neo3.sc.types import FindOptions
from neo3.sc.utils.iterator import Iterator


@syscall("System.Storage.Local.Get")
def get(key: bytes) -> Optional[bytes]:
    """
    Read a value from local contract storage.

    Compiles to: SYSCALL System.Storage.Local.Get (hash 0xd58d5ee8)
    Requires CallFlags.READ_STATES.

    Returns the stored bytes, or None if the key does not exist.
    """
    pass


@syscall("System.Storage.Local.Put")
def put(key: bytes, value: bytes) -> None:
    """
    Write a value to local contract storage.

    Compiles to: SYSCALL System.Storage.Local.Put (hash 0x390ce30a)
    Requires CallFlags.WRITE_STATES.
    """
    pass


@syscall("System.Storage.Local.Delete")
def delete(key: bytes) -> None:
    """
    Delete a value from local contract storage.

    Compiles to: SYSCALL System.Storage.Local.Delete (hash 0x7554f594)
    Requires CallFlags.WRITE_STATES.
    """
    pass


@syscall("System.Storage.Local.Find")
def find(prefix: bytes, options: FindOptions = FindOptions.NONE) -> Iterator:
    pass


def get_int(key: bytes) -> int:
    """
    Get a value as integer from the persistent store based on the given key.

    Args:
        key: storage key to lookup

    Returns: storage value as integer, or 0 if the key does not exist

    Examples:
        >>> put_int(b'unit', 5)
        ... get_int(b'unit')
        5

        >>> get_int(b'fake_key')
        0
    """
    result = get(key)
    if result is None:
        return 0
    return int.from_bytes(result)


def put_int(key: bytes, value: int) -> None:
    """
    Store an integer value in the persistent store under the given key.

    Note: this will store the value in 1 byte, big-endian, unsigned. Raises overflow if
    it does not fit

    Args:
        key: storage key
        value: what to store
    """
    put(key, value.to_bytes())
