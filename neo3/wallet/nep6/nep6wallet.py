from __future__ import annotations

import json
import os.path
from typing import List, Optional

from neo3.wallet.account import Account
from neo3.wallet.scrypt_parameters import ScryptParameters
from neo3.wallet.wallet import Wallet


class NEP6Wallet(Wallet):

    def __init__(self,
                 path: str,
                 name: Optional[str] = None,
                 version: str = Wallet._wallet_version,
                 scrypt: ScryptParameters = ScryptParameters(),
                 accounts: List[Account] = None,
                 extra: Optional[dict] = None):

        super().__init__(path=path,
                         name=name,
                         version=version,
                         scrypt=scrypt,
                         accounts=accounts,
                         extra=extra)

    def save(self):
        """
        Persists the wallet
        """
        if self.path is not None:
            with open(self.path, 'w') as json_file:
                json.dump(self.to_json(), json_file)

    @classmethod
    def new_wallet(cls, location: str) -> NEP6Wallet:
        """
        Create a new Wallet that should be persisted to the given file

        Args:
            location: target file where the wallet's going to be persisted
        """
        filepath, extension = os.path.splitext(location)
        if len(extension) == 0:
            # if the path doesn't have a file extension, sets it as a .json file
            location += '.json'

        # sets the wallet name as the same as the file name
        dir_path, filename = os.path.split(location)
        filename, extension = os.path.splitext(filename)

        return cls(
            name=filename,
            path=location,
            version=cls._wallet_version,
            scrypt=ScryptParameters(),
            accounts=[]
        )
