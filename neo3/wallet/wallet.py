from __future__ import annotations
from typing import Any, Dict, List, Optional
from jsonschema import validate  # type: ignore
from neo3.core import IJson
from neo3.wallet.account import Account
from neo3.wallet.scrypt_parameters import ScryptParameters

# Wallet JSON validation schema
schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "scrypt": {"$ref": "#/$defs/scrypt_parameters"},
        "accounts": {
            "type": "array",
            "items": {"$ref": "#/$defs/account"},
            "minItems": 0,
        },
        "extra": {"type": ["object", "null"],
                  "properties": {},
                  "additionalProperties": True
                  },
    },
    "required": ["path", "name", "scrypt", "accounts", "extra"],
    "$defs": {
        "account": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "label": {"type": "string"},
                "is_default": {"type": "boolean"},
                "lock": {"type": "boolean"},
                "key": {"type": "string"},
                "contract": {"type": ""},
                "extra": {"type": ["object", "null"],
                          "properties": {},
                          "additionalProperties": True}
            },
            "required": ["address", "label", "is_default", "lock", "key", "contract", "extra"]

        },
        "scrypt_parameters": {
            "type": "object",
            "properties": {
                "n": {"type": "integer"},
                "r": {"type": "integer"},
                "p": {"type": "integer"}
            },
            "required": ["n", "r", "p"]
        }
    }
}


class Wallet(IJson):

    _wallet_version = '3.0'

    def __init__(self,
                 name: Optional[str] = None,
                 version: str = _wallet_version,
                 scrypt: Optional[ScryptParameters] = None,
                 accounts: List[Account] = None,
                 extra: Optional[Dict[Any, Any]] = None):
        """
        Args:
            name: a user defined label for the wallet
            version: the wallet's version, must be equal to or greater than 3.0
            scrypt:  the parameters of the Scrypt algorithm used for encrypting and decrypting the private keys in the
            wallet.
            accounts: an array of Account objects to add to the wallet.
            extra: a user defined object for storing extra data. This field can be None.
        """

        self.name = name
        self.version = version
        self.scrypt = scrypt if scrypt else ScryptParameters()
        self.accounts = accounts if accounts is not None else []
        self.extra = extra

    def save(self) -> None:
        """
        Saves the wallet.

        This is called automatically when using the context manager.

        See Also:
            :class:`~neo3.wallet.nep6.nep6diskwallet.NEP6DiskWallet`
        """
        pass

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        # it's a placeholder, it'll be refined on #70
        json = {
            'name': self.name,
            'version': self.version,
            'scrypt': {
                'n': self.scrypt.n,
                'r': self.scrypt.r,
                'p': self.scrypt.p
            },
            'accounts': self.accounts,
            'extra': self.extra
        }

        return json

    @classmethod
    def from_json(cls, json: dict) -> Wallet:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if the 'version' property is under 3.0 or is not a valid string.
        """
        validate(json, schema=schema)
        try:
            if float(json['version']) < 3.0:
                raise ValueError("Format error - invalid 'version'")
        except ValueError:
            raise ValueError("Format error - invalid 'version'")

        return cls(name=json['name'],
                   version=json['version'],
                   scrypt=ScryptParameters(json['scrypt']['n'],
                                           json['scrypt']['r'],
                                           json['scrypt']['p']),
                   accounts=json['accounts'],
                   extra=json['extra'])

    def __enter__(self) -> Wallet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.save()
