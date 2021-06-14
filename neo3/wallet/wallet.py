from __future__ import annotations
from typing import Any, Dict, List, Optional
from jsonschema import validate  # type: ignore
from neo3.core import IJson, cryptography
from neo3.wallet.account import Account, AccountContract
from neo3 import contracts
from neo3.wallet.scrypt_parameters import ScryptParameters


class MultiSigContext:
    def __init__(self):
        self.initialised = False
        self.signing_threshold = 999
        #: List of valid public keys for signing
        self.expected_public_keys: List[cryptography.ECPoint] = []
        #: Completed pairs
        self.signature_pairs: Dict[cryptography.ECPoint, bytes] = {}

    @property
    def is_complete(self):
        return len(self.signature_pairs) >= self.signing_threshold

    def signing_status(self) -> Dict[cryptography.ECPoint, bool]:
        # shows which keys have been completed
        pass

    def process_contract(self, script: bytes) -> None:
        valid, threshold, public_keys = contracts.Contract.parse_as_multisig_contract(script)
        if not valid:
            raise ValueError("Invalid script")
        self.expected_public_keys = public_keys
        self.signing_threshold = threshold
        self.initialised = True


class Wallet(IJson):
    _wallet_version = '1.0'

    # Wallet JSON validation schema
    json_schema = {
        "type": "object",
        "properties": {
            "name": {"type": ["string", "null"]},
            "version": {"type": "string"},
            "scrypt": ScryptParameters.json_schema,
            "accounts": {
                "type": "array",
                "items": Account._json_schema,
                "minItems": 0,
            },
            "extra": {"type": ["object", "null"],
                      "properties": {},
                      "additionalProperties": True
                      },
        },
        "required": ["name", "version", "scrypt", "accounts", "extra"]
    }

    def __init__(self,
                 name: Optional[str] = None,
                 version: str = _wallet_version,
                 scrypt: Optional[ScryptParameters] = None,
                 accounts: List[Account] = None,
                 default_account: Optional[Account] = None,
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

        if accounts is None:
            accounts = []

        if default_account is not None and default_account not in accounts:
            # default account must be in the account list
            accounts.append(default_account)
        elif default_account is None and len(accounts) > 0:
            # if no account is defined as default, the first will be considered the default account
            default_account = accounts[0]

        self.accounts = accounts if accounts is not None else []
        self._default_account: Optional[Account] = default_account
        self.extra = extra if extra else {}

    def account_new(self, password: str, label: str = None, is_default=False) -> Account:
        """
        Creates a new account and adds it in the wallet

        Args:
            password: the password to encrypt the account
            label: optional label to identify the account
            is_default: whether it should set the created account as the default
        """
        account = Account(password=password,
                          watch_only=False,
                          label=label
                          )

        self.account_add(account, is_default)
        return account

    @property
    def account_default(self) -> Optional[Account]:
        """
        Returns the default account if at least one account is present
        """
        return self._default_account

    def import_multisig_address(self,
                                signing_threshold: int,
                                public_keys: List[cryptography.ECPoint]
                                ) -> Account:
        if signing_threshold < 1 or signing_threshold > 1024:
            raise ValueError("Invalid signing threshold")

        if signing_threshold > len(public_keys):
            raise ValueError(f"Minimum signing threshold is {signing_threshold}, "
                             f"received only {len(public_keys)} public keys")

        multisig_contract = contracts.Contract.create_multisig_contract(signing_threshold, public_keys)
        # we start with a watchonly as base
        account = Account.watch_only(multisig_contract.script_hash)
        account.contract = AccountContract.from_contract(multisig_contract)

        # if the wallet contains an account matching one required in the multisig, then copy key material
        self._augment_multisig_with_key_material(account)
        self.account_add(account)
        return account

    def _augment_multisig_with_key_material(self, account: Account):
        """
        Tries to augment multisig accounts with key material such that they can be used for signing

        There are 2 scenario's
        1. A multisig account is added while there already exists a regular account with key material for one of the
        keys required by the multisig
        2. A regular account is added while there already exists a multisig account missing key material that the
        regular now adds.
        """
        if account.contract is None:
            return

        is_multisig, _, public_keys = contracts.Contract.parse_as_multisig_contract(account.contract.script)
        if is_multisig:
            # scenario 1
            for acc in self.accounts:
                if not acc.is_watchonly and acc.public_key in public_keys:
                    # copy key information of the first matching account
                    account.encrypted_key = acc.encrypted_key
                    account.public_key = acc.public_key
                    break
        else:
            # scenario 2
            for acc in self.accounts:
                if acc.is_watchonly and acc.is_multisig and acc.contract:  # testing acc.contract to silence mypy
                    _, _, public_keys = contracts.Contract.parse_as_multisig_contract(acc.contract.script)
                    if account.public_key in public_keys:
                        acc.encrypted_key = account.encrypted_key
                        acc.public_key = account.public_key
                        break

    def account_add(self, account: Account, is_default=False) -> bool:
        """
        Includes an account in the wallet

        Args:
            account: the account to be included
            is_default: whether it should set the created account as the default

        Raises:
            ValueError: if the account's label is already used by another one
        """
        # true if ok, false if duplicate (any other possible reasons? otherwise we need to throw exceptions)
        if account in self.accounts:
            return False

        if account.label is not None and self.account_get_by_label(account.label) is not None:
            raise ValueError(f"Label is already used by an account '{account.label}'")

        # if first account, also set to default
        if is_default or len(self.accounts) == 0:
            self._default_account = account

        self._augment_multisig_with_key_material(account)
        self.accounts.append(account)
        return True

    def account_delete(self, account: Account) -> bool:
        """
        Removes an account from the wallet

        Args:
            account: the account to be removed
        """
        # return success or not
        if account not in self.accounts:
            return False

        self.accounts.remove(account)
        if account == self._default_account:
            # if it was the default account, select a new one
            # first by default
            self._default_account = self.accounts[0] if len(self.accounts) > 0 else None

        return True

    def account_delete_by_label(self, label: str) -> bool:
        """
        Removes an account from the wallet given its label

        Args:
            label: unique identifier of the account
        """
        # return success or not
        account = self.account_get_by_label(label)

        if account is None:
            # account with that label was not found
            return False

        return self.account_delete(account)

    def account_get_by_label(self, label: str) -> Optional[Account]:
        """
        Gets an account given its label. Returns None if not found.

        Args:
            label: unique identifier of the account
        """
        # returns the account with given label. None if the account is not found
        return next((acc for acc in self.accounts if acc.label == label), None)

    def save(self):
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
        return {
            'name': self.name,
            'version': self.version,
            'scrypt': self.scrypt.to_json(),
            'accounts': [self._account_to_json(account) for account in self.accounts],
            'extra': self.extra if len(self.extra) > 0 else None
        }

    def _account_to_json(self, account: Account) -> dict:
        is_default = self._default_account is not None and self._default_account.address == account.address
        json_account = account.to_json()
        json_account['isDefault'] = is_default
        return json_account

    @classmethod
    def from_json(cls, json: dict, password: str = None) -> Wallet:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.
            password: the password to decrypt the json data.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if the 'version' property is under 1.0 or is not a valid string.
        """
        validate(json, schema=cls.json_schema)
        try:
            if float(json['version']) < 1.0:
                raise ValueError("Format error - invalid 'version'")
        except ValueError:
            raise ValueError("Format error - invalid 'version'")

        accounts = []
        default_account = None
        if len(json['accounts']) > 0:
            if password is None:
                raise ValueError('Missing wallet password to decrypt account data')
            else:
                for json_account in json['accounts']:
                    account_from_json = Account.from_json(json_account, password)
                    accounts.append(account_from_json)
                    if default_account is None and hasattr(json, 'isDefault') and json['isDefault']:
                        default_account = account_from_json

        return cls(name=json['name'],
                   version=json['version'],
                   scrypt=ScryptParameters.from_json(json['scrypt']),
                   accounts=accounts,
                   default_account=default_account,
                   extra=json['extra'])

    def __enter__(self) -> Wallet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.save()
