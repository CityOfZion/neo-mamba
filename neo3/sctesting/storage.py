"""
Common post processor functions for the get_storage() method.
"""

from neo3.core import types, cryptography
from neo3.wallet import utils as walletutils
from neo3.wallet.types import NeoAddress
from neo3.api.helpers import stdlib
from typing_extensions import Protocol
from typing import Any


class PostProcessor(Protocol):
    def __call__(self, data: bytes, *args: Any) -> Any: ...


def as_uint160(data: bytes, *_: Any) -> types.UInt160:
    """
    Convert the data to a UInt160

    Args:
        data: a serialized UInt160
    """
    return types.UInt160(data)


def as_uint256(data: bytes, *_: Any) -> types.UInt256:
    """
    Convert the data to a UInt256

    Args:
        data: a serialized UInt256
    """
    return types.UInt256(data)


def as_int(data: bytes, *_: Any) -> int:
    """
    Convert the data to an integer
    """
    return int(types.BigInteger(data))


def as_str(data: bytes, *_: Any) -> str:
    """
    Convert the data to a UTF-8 encoded string
    """
    return data.decode()


def as_address(data: bytes, *_: Any) -> NeoAddress:
    """
    Convert the data to a Neo address string

    Args:
        data: a serialized UInt160
    """
    return walletutils.script_hash_to_address(types.UInt160(data))


def as_public_key(data: bytes, *_: Any) -> cryptography.ECPoint:
    """
    Convert the data to a public key

    Args:
        data: a serialized compressed public key
    """
    return cryptography.ECPoint.deserialize_from_bytes(data)


def stdlib_deserialize(data: bytes, *_: Any) -> Any:
    """
    Deserialize the data using the Binary Deserialize logic of the StdLib native contract

    Args:
        data: data that has been serialized using the StdLib native contract binary serialize method
    """
    return stdlib.binary_deserialize(data)
