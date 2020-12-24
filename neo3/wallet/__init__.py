import base58
import hashlib
import unicodedata

from .account import Account
from Crypto.Cipher import AES
from neo3.core.cryptography import KeyPair
from neo3.core import to_script_hash
from .. import contracts

NEP_HEADER = bytearray([0x01, 0x42])
NEP_FLAG = bytearray([0xe0])


def private_key_to_nep2(private_key: bytes, passphrase: str):
    key_pair = KeyPair(private_key=private_key)
    script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(key_pair.public_key))
    address = Account.script_hash_to_address(script_hash)
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


def private_key_from_nep2(nep2_key: str, passphrase: str):
    if len(nep2_key) != 58:
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
    address = Account.script_hash_to_address(script_hash)
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
