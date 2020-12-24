import os.path
import json
from jsonschema import validate  # type: ignore
from typing import List, Dict, Any, TypeVar, Type, Optional

from neo3.core import IJson
from neo3.wallet.scrypt_parameters import ScryptParameters
from neo3.wallet.account import Account


def encode_scrypt_parameters(scrypt_parameters):
    if isinstance(scrypt_parameters, ScryptParameters):
        return {'n': scrypt_parameters.n, 'r': scrypt_parameters.r, 'p': scrypt_parameters.p,
                'length': scrypt_parameters.length}
    else:
        type_name = scrypt_parameters.__class__.__name__
        raise TypeError(f"Object of type '{type_name}' is not JSON serializable")


T = TypeVar('T', bound='Wallet')

# A sample schema, like what we'd get from json.load()
schema = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
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
                "p": {"type": "integer"},
                "length": {"type": "integer"}
            },
            "required": ["n", "r", "p"]
        }
    }
}


class Wallet(IJson):

    def __init__(self,
                 path: str,
                 name: Optional[str],
                 version: str,
                 scrypt: ScryptParameters,
                 accounts: List[Account],
                 extra: Optional[Dict[Any, Any]]):
        """
        Args:
            path: the JSON's path
            name: a label that the user has given to the wallet
            version: the wallet's version, must be equal or greater then 3.0
            scrypt: a ScryptParameters object which describes the parameters of the SCrypt algorithm used for encrypting
                    and decrypting the private keys in the wallet.
            accounts: an array of Account objects which describe the details of each account in the wallet.
            extra: an object that is defined by the implementor of the client for storing extra data. This field can be
                   None.
        """

        self.path = path
        self.name = name
        self.version = version
        self.scrypt = scrypt
        self.accounts = accounts
        self.extra = extra

    @classmethod
    def default(cls: Type[T], path: str, name: Optional[str] = None) -> T:
        """
        Create a new Wallet with the default settings.

        Args:
            path: the JSON's path.
            name: the Wallet name.
        """
        return cls(path, name, "3.0", ScryptParameters.default(), [], None)

    @classmethod
    def from_file(cls: Type[T], path: str) -> T:
        """
        Create a Wallet from a JSON file.

        Args:
            path: the JSON's path.
        """
        if os.path.isfile(path):
            with open(path) as json_file:
                data = json.load(json_file)

        return cls.from_json(data)

    def save(self):
        """
        Save a wallet as a JSON.
        """
        with open(self.path, 'w') as json_file:
            json.dump(self.to_json(), json_file, default=encode_scrypt_parameters)

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """

        json = {
            'path': self.path,
            'name': self.name,
            'version': self.version,
            'scrypt': self.scrypt,
            'accounts': self.accounts,
            'extra': self.extra
        }

        return json

    @classmethod
    def from_json(cls: Type[T], json: dict) -> T:
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

        return cls(json['path'],
                   json['name'],
                   json['version'],
                   ScryptParameters(json['scrypt']['n'],
                                    json['scrypt']['r'],
                                    json['scrypt']['p'],
                                    json['scrypt']['length']),
                   json['accounts'],
                   json['extra'])
