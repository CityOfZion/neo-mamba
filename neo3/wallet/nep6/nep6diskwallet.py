from __future__ import annotations
import json
import os.path
from typing import List, Optional
from neo3.wallet.account import Account
from neo3.wallet.scrypt_parameters import ScryptParameters
from neo3.wallet.wallet import Wallet


class NEP6DiskWallet(Wallet):
    """
    A specialised wallet for persisting wallets to media.
    """
    _default_path = './wallet.json'

    def __init__(self,
                 path: str,
                 name: Optional[str] = None,
                 version: str = Wallet._wallet_version,
                 scrypt: Optional[ScryptParameters] = None,
                 accounts: List[Account] = None,
                 default_account: Optional[Account] = None,
                 extra: Optional[dict] = None):
        """

        Args:
            path: the location where the wallet will be stored.
            name: a user defined label for the wallet
            version: the wallet's version, must be equal to or greater than 3.0
            scrypt:  the parameters of the Scrypt algorithm used for encrypting and decrypting the private keys in the
            wallet.
            accounts: an array of Account objects to add to the wallet.
            extra: a user defined object for storing extra data. This field can be None.
        """

        filepath, extension = os.path.splitext(path)
        if len(extension) == 0:
            # if the path doesn't have a file extension, sets it as a .json file
            path += '.json'

        if name is None:
            # sets the wallet name the same as the file name
            dir_path, name = os.path.split(path)
            name, extension = os.path.splitext(name)

        self.path: str = path
        super().__init__(name=name,
                         version=version,
                         scrypt=scrypt,
                         accounts=accounts,
                         default_account=default_account,
                         extra=extra)

    def save(self) -> None:
        """
        Persists the wallet
        """
        with open(self.path, 'w') as json_file:
            json.dump(self.to_json(), json_file)

    @classmethod
    def default(cls, path: str = _default_path, name: Optional[str] = 'wallet.json') -> NEP6DiskWallet:
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
