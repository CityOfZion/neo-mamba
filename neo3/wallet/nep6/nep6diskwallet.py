from __future__ import annotations

import json
import os.path
from typing import List, Optional

from neo3.wallet.account import Account
from neo3.wallet.scrypt_parameters import ScryptParameters
from neo3.wallet.wallet import Wallet


class NEP6DiskWallet(Wallet):

    _default_path = './wallet.json'

    def __init__(self,
                 path: str,
                 name: Optional[str] = None,
                 version: str = Wallet._wallet_version,
                 scrypt: ScryptParameters = ScryptParameters(),
                 accounts: List[Account] = None,
                 extra: Optional[dict] = None):

        filepath, extension = os.path.splitext(path)
        if len(extension) == 0:
            # if the path doesn't have a file extension, sets it as a .json file
            path += '.json'

        if name is None:
            # sets the wallet name as the same as the file name
            dir_path, name = os.path.split(path)
            name, extension = os.path.splitext(name)

        self.path: str = path
        super().__init__(name=name,
                         version=version,
                         scrypt=scrypt,
                         accounts=accounts,
                         extra=extra)

    def save(self):
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
