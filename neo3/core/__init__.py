from __future__ import annotations
import abc
import hashlib
import unicodedata
from typing import TypeVar, Type

import base58

from Crypto.Cipher import AES
from neo3.core.cryptography import KeyPair


from neo3 import vm, settings, contracts
from enum import IntEnum
from events import Events  # type: ignore
from neo3.core import types
from neo3.core.cryptography import KeyPair

msgrouter = Events()
# :noindex:

NEP_HEADER = bytes([0x01, 0x42])
NEP_FLAG = bytes([0xe0])

class Size(IntEnum):
    """
    Explicit bytes of memory consumed
    """
    uint8 = 1
    uint16 = 2
    uint32 = 4
    uint64 = 8
    uint160 = 20
    uint256 = 32


class IClonable(abc.ABC):
    @abc.abstractmethod
    def clone(self):
        """
        Create a deep copy of self
        """

    def from_replica(self, replica):
        """ shallow copy from a replica object """


class IJson(abc.ABC):
    @abc.abstractmethod
    def to_json(self) -> dict:
        """ convert object into json """

    @classmethod
    @abc.abstractmethod
    def from_json(cls, json: dict):
        """ create object from JSON """


T = TypeVar('T', bound='IInteroperable')


class IInteroperable(abc.ABC):
    @abc.abstractmethod
    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        """ Convert object to a virtual machine stack item"""

    @classmethod
    def from_stack_item(cls: Type[T], stack_item: vm.StackItem) -> T:
        """ Convert a stack item into an object"""
        raise ValueError(f"{cls.__class__.__name__} cannot be converted to a stack item")


def to_script_hash(data: bytes) -> types.UInt160:
    """
    Create a script hash based on the input data.

    Args:
        data: data to hash
    """
    intermediate_data = hashlib.sha256(data).digest()
    data_ = hashlib.new('ripemd160', intermediate_data).digest()
    return types.UInt160(data_)


def syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)


def address_to_script_hash(address: str, version: int = settings.network.account_version) -> types.UInt160:
    """
    Converts the specified address to a script hash.

    Args:
        address: address to convert
        version: address version
    """
    data_ = base58.b58decode_check(address)
    if len(data_) != len(types.UInt160.zero()) + 1:
        raise ValueError("Invalid address.")

    if data_[0] != version:
        raise ValueError("Incompatible version.")

    return types.UInt160(data_[1:])


def to_address(script_hash: types.UInt160, version: int = settings.network.account_version) -> str:
    """
    Converts the specified script hash to an address.

    Args:
        script_hash: script hash to convert
        version: address version
    """
    data_ = version.to_bytes(1, 'little') + script_hash.to_array()

    return base58.b58encode_check(data_).decode('utf-8')


def private_key_to_nep2(private_key: bytes, passphrase: str) -> bytes:
    key_pair = KeyPair(private_key=private_key)
    script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(key_pair.public_key))
    address = to_address(script_hash)
    # NEP2 checksum: hash the address twice and get the first 4 bytes
    first_hash = hashlib.sha256(address.encode("utf-8")).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    checksum = second_hash[:4]

    pwd_normalized = bytes(unicodedata.normalize('NFC', passphrase), 'utf-8')
    derived = hashlib.scrypt(password=pwd_normalized, salt=checksum,
                             n=16384,
                             r=8,
                             p=8,
                             dklen=64)

    derived1 = derived[:32]
    derived2 = derived[32:]

    xor_ed = xor_bytes(bytes(private_key), derived1)
    cipher = AES.new(derived2, AES.MODE_ECB)
    encrypted = cipher.encrypt(xor_ed)

    nep2 = bytearray()
    nep2.extend(NEP_HEADER)
    nep2.extend(NEP_FLAG)
    nep2.extend(checksum)
    nep2.extend(encrypted)

    # Finally, encode with Base58Check
    encoded_nep2 = base58.b58encode_check(bytes(nep2))

    return encoded_nep2


def private_key_from_nep2(nep2_key: bytes, passphrase: str) -> bytes:
    if not nep2_key or len(nep2_key) != 58:
        raise ValueError('Please provide a nep2_key with a length of 58 bytes (LEN: {0:d})'.format(len(nep2_key)))

    address_hash_size = 4
    address_hash_offset = len(NEP_FLAG) + len(NEP_HEADER)

    try:
        decoded_key = base58.b58decode_check(nep2_key)
    except Exception:
        raise ValueError("Invalid nep2_key")

    address_checksum = decoded_key[address_hash_offset:address_hash_offset + address_hash_size]
    encrypted = decoded_key[-32:]

    pwd_normalized = bytes(unicodedata.normalize('NFC', passphrase), 'utf-8')
    derived = hashlib.scrypt(password=pwd_normalized, salt=address_checksum,
                             n=16384,
                             r=8,
                             p=8,
                             dklen=64)

    derived1 = derived[:32]
    derived2 = derived[32:]

    cipher = AES.new(derived2, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)
    private_key = xor_bytes(decrypted, derived1)

    # Now check that the address hashes match. If they don't, the password was wrong.
    key_pair = KeyPair(private_key=private_key)
    script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(key_pair.public_key))
    address = to_address(script_hash)
    first_hash = hashlib.sha256(address.encode("utf-8")).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    checksum = second_hash[:4]
    if checksum != address_checksum:
        raise ValueError("Wrong passphrase")

    return private_key


def xor_bytes(a: bytes, b: bytes):
    """
    XOR on two bytes objects
    Args:
        a (bytes): object 1
        b (bytes): object 2
    Returns:
        bytes: The XOR result
    """
    assert len(a) == len(b)
    res = bytearray()
    for i in range(len(a)):
        res.append(a[i] ^ b[i])
    return bytes(res)
