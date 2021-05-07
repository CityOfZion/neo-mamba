from __future__ import annotations

from typing import Any, Dict, List, Optional

from jsonschema import validate  # type: ignore

from neo3.core import IJson
from neo3.wallet.account import Account
from neo3.wallet.scrypt_parameters import ScryptParameters


# A sample schema, like what we'd get from json.load()
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
    _default_path = './wallet.json'

    def __init__(self,
                 path: Optional[str] = None,
                 name: Optional[str] = None,
                 version: str = _wallet_version,
                 scrypt: ScryptParameters = ScryptParameters(),
                 accounts: List[Account] = None,
                 extra: Optional[Dict[Any, Any]] = None):
        """
        Args:
            path: if the wallet must be persisted, the file path where it is persisted
            name: a label that the user has given to the wallet
            version: the wallet's version, must be equal to or greater than 3.0
            scrypt: a ScryptParameters object which describes the parameters of the Scrypt algorithm used for encrypting
                    and decrypting the private keys in the wallet.
            accounts: an array of Account objects which describe the details of each account in the wallet.
            extra: an object that is defined by the implementor of the client for storing extra data. This field can be
                   None.
        """

        self.path = path
        self.name = name
        self.version = version
        self.scrypt = scrypt
        self.accounts = accounts if accounts is not None else []
        self.extra = extra

    @classmethod
    def default(cls, path: str = _default_path, name: Optional[str] = 'wallet.json') -> Wallet:
        """
        Create a new Wallet with the default settings.

        Args:
            path: the JSON's path.
            name: the Wallet name.
        """
        return cls(path=path,
                   name=name,
                   version=cls._wallet_version,
                   scrypt=ScryptParameters(),
                   accounts=[],
                   extra=None)

    def save(self):
        """
        Saves the wallet.
        If it's required a specific way of saving it, this should be overwritten in a specialized wallet.
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
            KeyError: if the data supplied does not contain the necessary key.
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

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.save()
