from __future__ import annotations

import base58
import hashlib
import unicodedata
from typing import Optional

from Crypto.Cipher import AES
from neo3 import settings, contracts
from neo3.core import types, to_script_hash
from neo3.core.cryptography import ECPoint
from neo3.core.cryptography import KeyPair

# both constants below are used to encrypt/decrypt a private key to/from a nep2 key
NEP_HEADER = bytes([0x01, 0x42])
NEP_FLAG = bytes([0xe0])


class Account:

    def __init__(self, password: str,
                 private_key: Optional[bytes] = None,
                 watch_only: bool = False,
                 address: Optional[str] = None
                 ):
        """
        Instantiate an account. This constructor should only be directly called when it's desired to create a new
        account using just a password and a randomly generated private key, otherwise, they should call another
        function.
        """

        public_key: Optional[ECPoint] = None
        encrypted_key: Optional[bytes] = None

        if not watch_only:
            key_pair: KeyPair

            if private_key is None:
                key_pair = KeyPair.generate()
                private_key = key_pair.private_key
            else:
                key_pair = KeyPair(private_key)
            encrypted_key = self.private_key_to_nep2(private_key, password)
            script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(key_pair.public_key))
            address = self.script_hash_to_address(script_hash)
            public_key = key_pair.public_key

        self.address = address
        self.public_key = public_key
        self.encrypted_key = encrypted_key

    @property
    def script_hash(self) -> types.UInt160:
        return self.address_to_script_hash(self.address)

    @classmethod
    def from_encrypted_key(cls, nep2_key: str, password: str) -> Account:
        """
        Instantiate and returns an account from a given nep2 key and password.

        Args:
            nep2_key: the encrypted private key.
            password: the password to decrypt the nep2 key.

        Returns:
            The newly created account.
        """
        return cls(password=password, private_key=cls.private_key_from_nep2(nep2_key, password))

    @classmethod
    def from_private_key(cls, private_key: bytes, password: str) -> Account:
        """
        Instantiate and returns an account from a given private key and password.

        Args:
            private_key: the private key that will be used to create an encrypted key.
            password: the password to encrypt a randomly generated private key.

        Returns:
            The newly created account.
        """
        return cls(password=password, private_key=private_key)

    @classmethod
    def watch_only(cls, script_hash: types.UInt160) -> Account:
        """
        Instantiate and returns a watch-only account from a given script hash.

        Args:
            script_hash: the script hash that will identify an account to be watched.

        Returns:
            The account that will be monitored.
        """
        return cls(password='', watch_only=True, address=cls.script_hash_to_address(script_hash))

    @classmethod
    def watch_only_from_address(cls, address: str) -> Account:
        """
        Instantiate and returns a watch-only account from a given address.

        Args:
            address: the address that will identify an account to be watched.

        Returns:
            The account that will be monitored.
        """
        return cls(password='', watch_only=True, address=address)

    @staticmethod
    def script_hash_to_address(script_hash: types.UInt160) -> str:
        """
        Converts the specified script hash to an address.

        Args:
            script_hash: script hash to convert
        """
        version = settings.network.account_version  # this is the current Neo's protocol version
        data_ = version.to_bytes(1, 'little') + script_hash.to_array()

        return base58.b58encode_check(data_).decode('utf-8')

    @staticmethod
    def address_to_script_hash(address: str) -> types.UInt160:
        """
        Converts the specified address to a script hash.

        Args:
            address: address to convert

        Raises:
            ValueError: if the length of data_ isn't 21.
            ValueError: if the script hash version isn't 3.0.
        """
        data_ = base58.b58decode_check(address)
        if len(data_) != len(types.UInt160.zero()) + 1:
            raise ValueError('The address is wrong, because data_ length should be 21')

        if data_[0] != settings.network.account_version:   # Only accepted version is 3.0
            raise ValueError('The version is not 3.0')

        return types.UInt160(data=data_[1:])

    @staticmethod
    def private_key_from_nep2(nep2_key: str, passphrase: str) -> bytes:
        """
        Decrypt a nep2 key into a private key.

        Args:
            nep2_key: the key that will be decrypt.
            passphrase: the password to decrypt the nep2 key.

        Raises:
            ValueError: if the passphrase is incorrect or the version of the account is not 3.0.

        Returns:
            the private key.
        """
        if len(nep2_key) != 58:
            raise ValueError(f"Please provide a nep2_key with a length of 58 bytes (LEN: {len(nep2_key)})")

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
        private_key = Account.xor_bytes(decrypted, derived1)

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

    @staticmethod
    def private_key_to_nep2(private_key: bytes, passphrase: str) -> bytes:
        """
        Encrypt a private key into a nep2 key.

        Args:
            private_key: the key that will be encrypt.
            passphrase: the password to encrypt the nep2 key.

        Returns:
            the encrypted nep2 key.
        """
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

        xor_ed = Account.xor_bytes(bytes(private_key), derived1)
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

    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
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
