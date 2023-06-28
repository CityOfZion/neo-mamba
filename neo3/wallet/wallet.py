"""
Containers following the NEP-6 wallet standard.
"""
from __future__ import annotations
import os.path
import json
from typing import Any, Optional
from collections.abc import Sequence
from jsonschema import validate  # type: ignore
from neo3.core import interfaces, cryptography
from neo3.contracts import contract, utils as contractutils
from neo3.wallet import account
from neo3.wallet import scrypt_parameters as scrypt


class Wallet(interfaces.IJson):
    """
    Base container.
    """

    _wallet_version = "1.0"

    # Wallet JSON validation schema
    json_schema = {
        "type": "object",
        "properties": {
            "name": {"type": ["string", "null"]},
            "version": {"type": "string"},
            "scrypt": scrypt.ScryptParameters.json_schema,
            "accounts": {
                "type": "array",
                "items": account.Account._json_schema,
                "minItems": 0,
            },
            "extra": {
                "type": ["object", "null"],
                "properties": {},
                "additionalProperties": True,
            },
        },
        "required": ["name", "version", "scrypt", "accounts", "extra"],
    }

    def __init__(
        self,
        name: Optional[str] = None,
        version: str = _wallet_version,
        scrypt_params: Optional[scrypt.ScryptParameters] = None,
        accounts: Optional[Sequence[account.Account]] = None,
        default_account: Optional[account.Account] = None,
        extra: Optional[dict[Any, Any]] = None,
    ):
        """
        Args:
            name: a user defined label for the wallet.
            version: the wallet's version, must be equal to or greater than 3.0.
            scrypt_params:  the parameters of the Scrypt algorithm used for encrypting and decrypting the private keys
            in the wallet.
            accounts: an array of Account objects to add to the wallet.
            extra: a user defined object for storing extra data. This field can be None.
        """

        self.name = name
        self.version = version
        try:
            self.scrypt = scrypt_params if scrypt_params else scrypt.ScryptParameters()
        except AttributeError:
            pass

        if accounts is None:
            accounts = []
        else:
            accounts = list(accounts)

        if default_account is not None and default_account not in accounts:
            # default account must be in the account list
            accounts.append(default_account)
        elif default_account is None and len(accounts) > 0:
            # if no account is defined as default, the first will be considered the default account
            default_account = accounts[0]

        self.accounts = accounts if accounts is not None else []
        self._default_account: Optional[account.Account] = default_account
        self.extra = extra if extra else {}

    def account_new(
        self, password: str, label: Optional[str] = None, is_default=False
    ) -> account.Account:
        """
        Create a new account and adds it in the wallet.

        Args:
            password: the password to encrypt the account.
            label: optional label to identify the account.
            is_default: set the created account as the default.
        """
        account_ = account.Account(
            password=password,
            watch_only=False,
            label=label,
            scrypt_parameters=self.scrypt,
        )

        self.account_add(account_, is_default)
        return account_

    @property
    def account_default(self) -> Optional[account.Account]:
        """
        Return the default account if at least one account is present.
        """
        return self._default_account

    def import_multisig_address(
        self, signing_threshold: int, public_keys: Sequence[cryptography.ECPoint]
    ) -> account.Account:
        """
        Import a multi-signature account into the container.

        Args:
            signing_threshold: minimum number of keys required for signing.
            public_keys: the public keys the multisignature address consists off.

        Raises:
            ValueError: if the signing treshold exceeds 1024.
                        if the signing treshold exceeds the number of public_keys.
        """
        if signing_threshold < 1 or signing_threshold > 1024:
            raise ValueError("Invalid signing threshold")

        if signing_threshold > len(public_keys):
            raise ValueError(
                f"Minimum signing threshold is {signing_threshold}, "
                f"received only {len(public_keys)} public keys"
            )

        multisig_contract = contract.Contract.create_multisig_contract(
            signing_threshold, public_keys
        )
        # we start with a watchonly as base
        account_ = account.Account.watch_only(multisig_contract.script_hash)
        account_.contract = account.AccountContract.from_contract(multisig_contract)

        # if the wallet contains an account matching one required in the multisig, then copy key material
        self._augment_multisig_with_key_material(account_)
        self.account_add(account_)
        return account_

    def _augment_multisig_with_key_material(self, acc: account.Account):
        """
        Tries to augment multi-sig accounts with key material such that they can be used for signing.

        There are 2 scenarios
        1. A multi-sig account is added while there already exists a regular account with key material for one of the
        keys required by the multi-signature.
        2. A regular account is added while there already exists a multi-sig account missing key material that the
        regular now adds.
        """
        if acc.contract is None:
            return

        is_multisig, _, public_keys = contractutils.parse_as_multisig_contract(
            acc.contract.script
        )
        if is_multisig:
            # scenario 1
            for account_ in self.accounts:
                if not account_.is_watchonly and account_.public_key in public_keys:
                    # copy key information of the first matching account
                    acc.encrypted_key = account_.encrypted_key
                    acc.public_key = account_.public_key
                    break
        else:
            # scenario 2
            for account_ in self.accounts:
                # testing acc.contract to silence mypy
                if account_.is_watchonly and account_.is_multisig and account_.contract:
                    _, _, public_keys = contractutils.parse_as_multisig_contract(
                        account_.contract.script
                    )
                    if acc.public_key in public_keys:
                        account_.encrypted_key = acc.encrypted_key
                        account_.public_key = acc.public_key
                        break

    def account_add(self, acc: account.Account, is_default=False) -> bool:
        """
        Add account in the wallet.

        Args:
            acc: the account to be added.
            is_default: set the created account as the default.

        Raises:
            ValueError: if the account's label is already used by another one.
        """
        # true if ok, false if duplicate (any other possible reasons? otherwise we need to throw exceptions)
        if acc in self.accounts:
            return False

        if acc.label is not None and self.account_get_by_label(acc.label) is not None:
            raise ValueError(f"Label is already used by an account '{acc.label}'")

        # if first account, also set to default
        if is_default or len(self.accounts) == 0:
            self._default_account = acc

        self._augment_multisig_with_key_material(acc)
        self.accounts.append(acc)
        return True

    def account_delete(self, acc: account.Account) -> bool:
        """
        Remove an account from the wallet.

        Args:
            acc: the account to be removed.
        """
        # return success or not
        if acc not in self.accounts:
            return False

        self.accounts.remove(acc)
        if acc == self._default_account:
            # if it was the default account, select a new one
            # first by default
            self._default_account = self.accounts[0] if len(self.accounts) > 0 else None

        return True

    def account_delete_by_label(self, label: str) -> bool:
        """
        Remove an account from the wallet given its label.

        Args:
            label: unique identifier of the account.
        """
        # return success or not
        acc = self.account_get_by_label(label)

        if acc is None:
            # account with that label was not found
            return False

        return self.account_delete(acc)

    def account_get_by_label(self, label: str) -> Optional[account.Account]:
        """
        Get an account given its label. Returns None if not found.

        Args:
            label: unique identifier of the account.
        """
        # returns the account with given label. None if the account is not found
        return next((acc for acc in self.accounts if acc.label == label), None)

    def save(self):
        """
        Save the wallet.

        This is called automatically when using the context manager.

        See Also:
            [DiskWallet](#neo3.wallet.wallet.DiskWallet)
        """
        pass

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        return {
            "name": self.name,
            "version": self.version,
            "scrypt": self.scrypt.to_json(),
            "accounts": [self._account_to_json(acc) for acc in self.accounts],
            "extra": self.extra if len(self.extra) > 0 else None,
        }

    def _account_to_json(self, acc: account.Account) -> dict:
        is_default = (
            self._default_account is not None
            and self._default_account.address == acc.address
        )
        json_account = acc.to_json()
        json_account["isDefault"] = is_default
        return json_account

    @classmethod
    def from_json(cls, json: dict, passwords: Optional[list[str]] = None):
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.
            passwords: the password to decrypt the account data.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if the `version` property is under 1.0 or is not a valid string.
        """
        validate(json, schema=cls.json_schema)
        try:
            if float(json["version"]) < 1.0:
                raise ValueError("Format error - invalid 'version'")
        except ValueError:
            raise ValueError("Format error - invalid 'version'")

        accounts = []
        default_account = None
        scryptp = scrypt.ScryptParameters.from_json(json["scrypt"])
        if (len_accounts := len(json["accounts"])) > 0:
            if passwords is None:
                # mypy is being annoying about re-assigning to the same variable with a different type
                # we just need a list with None's for zip() to work and to create a watch only account.
                passwords = [None] * len(json["accounts"])  # type: ignore
            else:
                len_pws = len(passwords)
                if len_accounts != len_pws:
                    raise ValueError(
                        f"Incorrect number of passwords provided ({len_pws}) for number of accounts in wallet ({len_accounts})"
                    )
            for json_account, pw in zip(json["accounts"], passwords):
                account_from_json = account.Account.from_json(
                    json_account, pw, scrypt_parameters=scryptp
                )
                accounts.append(account_from_json)
                if (
                    default_account is None
                    and hasattr(json, "isDefault")
                    and json["isDefault"]
                ):
                    default_account = account_from_json

        return cls(
            name=json["name"],
            version=json["version"],
            scrypt_params=scryptp,
            accounts=accounts,
            default_account=default_account,
            extra=json["extra"],
        )

    @classmethod
    def from_file(cls, path: str, passwords: Optional[list[str]] = None):
        """
        Load wallet from file.

        Args:
            path: path as passed to `open()`.
            passwords: the password to decrypt the account data.
        """
        with open(path, "r") as f:
            return cls.from_json(json.load(f), passwords)

    def __enter__(self) -> Wallet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.save()


class DiskWallet(Wallet):
    """
    Specialised wallet for persisting to media.
    """

    _default_path = "./wallet.json"

    def __init__(
        self,
        path: str,
        name: Optional[str] = None,
        version: str = Wallet._wallet_version,
        scrypt_params: Optional[scrypt.ScryptParameters] = None,
        accounts: Optional[Sequence[account.Account]] = None,
        default_account: Optional[account.Account] = None,
        extra: Optional[dict] = None,
    ):
        """
        Args:
            path: the location where the wallet will be stored.
            name: a user defined label for the wallet.
            version: the wallet's version, must be equal to or greater than 3.0.
            scrypt_params:  the parameters of the Scrypt algorithm used for encrypting and decrypting the private keys
            in the wallet.
            accounts: an array of Account objects to add to the wallet.
            extra: a user defined object for storing extra data. This field can be None.
        """

        filepath, extension = os.path.splitext(path)
        if len(extension) == 0:
            # if the path doesn't have a file extension, sets it as a .json file
            path += ".json"

        if name is None:
            # sets the wallet name the same as the file name
            dir_path, name = os.path.split(path)
            name, extension = os.path.splitext(name)

        self.path: str = path
        super(DiskWallet, self).__init__(
            name=name,
            version=version,
            scrypt_params=scrypt_params,
            accounts=accounts,
            default_account=default_account,
            extra=extra,
        )

    def save(self) -> None:
        """
        Persist the wallet to disk.
        """
        with open(self.path, "w") as json_file:
            json.dump(self.to_json(), json_file)

    @classmethod
    def default(
        cls, path: str = _default_path, name: Optional[str] = "wallet.json"
    ) -> DiskWallet:
        """
        Create a new wallet with the default settings.

        Args:
            path: the JSON's path.
            name: the wallet name.
        """
        return cls(
            path=path,
            name=name,
            version=cls._wallet_version,
            scrypt_params=scrypt.ScryptParameters(),
            accounts=[],
            extra=None,
        )

    @classmethod
    def from_json(cls, json: dict, passwords: Optional[list[str]] = None):
        w = Wallet.from_json(json, passwords)
        path = ""
        return cls(
            path, w.name, w.version, w.scrypt, w.accounts, w.account_default, w.extra
        )

    @classmethod
    def from_file(cls, path: str, passwords: Optional[list[str]] = None):
        with open(path, "r") as f:
            w = cls.from_json(json.load(f), passwords)
            w.path = path
            return w
