from __future__ import annotations

import base58
from typing import Optional

from neo3 import settings
from neo3.core import types


class Account:

    def __init__(self, password: Optional[str] = None,
                 private_key: Optional[bytes] = None,
                 nep2_key: Optional[str] = None,
                 watch_only: bool = False,
                 script_hash: Optional[types.UInt160] = None,
                 address: Optional[str] = None
                 ):
        """
        Instantiate an account, this constructor should not be called by the user.
        """

        self._key = None
        from neo3.core.cryptography import ECPoint
        public_key: Optional[ECPoint] = None
        encrypted_key: Optional[bytes] = None

        if watch_only:
            if script_hash is not None and address is None:
                address = self.script_hash_to_address(script_hash)
            elif address is not None and script_hash is None:
                address = address

        elif password is not None:
            from neo3.wallet import private_key_to_nep2
            from neo3.core.cryptography import KeyPair
            key_pair: KeyPair
            if private_key is not None and nep2_key is None:
                pass
            elif nep2_key is not None and private_key is None:
                from neo3.wallet import private_key_from_nep2
                private_key = private_key_from_nep2(nep2_key, password)

            if private_key is None:
                key_pair = KeyPair.generate()
                private_key = key_pair.private_key
            else:
                key_pair = KeyPair(private_key)
            encrypted_key = private_key_to_nep2(private_key, password)
            from neo3.core import to_script_hash
            from neo3 import contracts
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
    def from_password(cls, password: str) -> Account:
        """
        Instantiate and returns an account from a given password.

        Args:
            password: the password to encrypt a randomly generated private key.

        Returns:
            The newly created account.
        """
        return cls(password=password)

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
        return cls(password=password, nep2_key=nep2_key)

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
    def from_script_hash(cls, script_hash: types.UInt160) -> Account:
        """
        Instantiate and returns a watch-only account from a given script hash.

        Args:
            script_hash: the script hash that will identify an account to be watched.

        Returns:
            The account that will be monitored.
        """
        return cls(watch_only=True, script_hash=script_hash)

    @classmethod
    def from_address(cls, address: str) -> Account:
        """
        Instantiate and returns a watch-only account from a given address.

        Args:
            address: the address that will identify an account to be watched.

        Returns:
            The account that will be monitored.
        """
        return cls(watch_only=True, address=address)

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
            ValueErros: if the script hash version isn't 3.0.
        """
        data_ = base58.b58decode_check(address)
        if len(data_) != len(types.UInt160.zero()) + 1:
            raise ValueError('The address is wrong, because data_ length should be 21')

        if data_[0] != settings.network.account_version:   # Only accepted version is 3.0
            raise ValueError('The version is not 3.0')

        return types.UInt160(data=data_[1:])
