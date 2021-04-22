from __future__ import annotations

from neo3 import contracts, settings
from neo3.wallet import private_key_from_nep2, address_to_script_hash, to_address, NEP6Contract
from neo3.core import cryptography, types, to_script_hash


class Account:

    def __init__(self, script_hash: types.UInt160, nep2key: str = None):
        self._script_hash: types.UInt160 = script_hash
        self._nep2key: str = nep2key
        self.label = ''
        self.is_default = False
        self.lock = False
        self._key: cryptography.KeyPair = None
        self.contract: contracts.Contract = None
        self.extra = None

    @property
    def address(self) -> str:
        return to_address(self._script_hash, settings.network.account_version)

    @property
    def decrypted(self) -> bool:
        return self._nep2key is not None or self._key is not None

    @property
    def has_key(self) -> bool:
        return self._nep2key is not None

    @classmethod
    def from_nep2(cls, key: str, password: str) -> Account:
        private_key = private_key_from_nep2(key, password)
        key_pair = cryptography.KeyPair(private_key)
        script_hash = to_script_hash(key_pair.public_key)
        account = cls(script_hash, key)
        return account

    @classmethod
    def from_json(cls, json: dict) -> Account:
        account = cls(address_to_script_hash(json['address'], settings.network.account_version), json['key'])

        account.label = json['label']
        account.is_default = json['isdefault']
        account.lock = json['lock']
        account.contract = NEP6Contract.from_json(json['contract'])
        account.extra = json['extra']

        return account

    def to_json(self) -> dict:
        return {
            'address': self.address,
            'label': self.label,
            'isdefault': self.is_default,
            'lock': self.lock,
            'key': self._nep2key,
            'contract': self.contract.to_json() if hasattr(self.contract, 'to_json') else None,
            'extra': self.extra
        }

    def get_key(self, password: str = None) -> cryptography.KeyPair:
        if self._nep2key is None:
            return None

        # TODO: validate password
        return self._key
