"""
NEO address utilities.
"""
import base58
from neo3.core import types, cryptography, utils as coreutils
from neo3.wallet.types import NeoAddress
from neo3.contracts import utils as contractutils


def script_hash_to_address(
    script_hash: types.UInt160, address_version: int = 0x35
) -> NeoAddress:
    """
    Convert the specified script hash to an address.

    Args:
        script_hash: script hash to convert.
        address_version: network protocol address version. Historically has been fixed to `0x35` for MainNet and TestNet.
         Use the `getversion()` RPC method to query for its value.
    """
    data = address_version.to_bytes(1, "little") + script_hash.to_array()
    return base58.b58encode_check(data).decode("utf-8")


def address_to_script_hash(address: NeoAddress) -> types.UInt160:
    """
    Convert the specified address to a script hash.

    Args:
        address: address to convert.

    Raises:
        ValueError: if the length of data (address value in bytes) is not valid.
        ValueError: if the account version is not valid.
    """
    validate_address(address)
    data = base58.b58decode_check(address)
    return types.UInt160(data[1:])


def public_key_to_script_hash(public_key: cryptography.ECPoint) -> types.UInt160:
    """
    Convert the specified public key to a script hash.
    """
    contract_script = contractutils.create_signature_redeemscript(public_key)
    return coreutils.to_script_hash(contract_script)


def is_valid_address(address: NeoAddress) -> bool:
    """
    Test if the provided address is a valid address.

    Args:
        address: an address.
    """
    try:
        validate_address(address)
    except ValueError:
        return False
    return True


def validate_address(address: NeoAddress, address_version: int = 0x35) -> None:
    """
    Validate a given address. If address is not valid an exception will be raised.

    Args:
        address: an address.
        address_version: network protocol address version. Historically has been fixed to `0x35` for MainNet and TestNet.
         Use the `getversion()` RPC method to query for its value.

    Raises:
        ValueError: if the length of data(address value in bytes) is not valid.
        ValueError: if the account version is not valid.
    """
    data: bytes = base58.b58decode_check(address)
    if len(data) != len(types.UInt160.zero()) + 1:
        raise ValueError(
            f"The address is wrong, because data (address value in bytes) length should be "
            f"{len(types.UInt160.zero()) + 1}"
        )
    elif data[0] != address_version:
        raise ValueError(f"The account version is not {address_version}")
