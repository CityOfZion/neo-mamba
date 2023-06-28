"""
Classes to work with account key material.
"""
from __future__ import annotations
import base58  # type: ignore
import base64
import hashlib
import unicodedata
from typing import Optional, Any
from Crypto.Cipher import AES  # type: ignore
from jsonschema import validate  # type: ignore
from neo3 import settings, vm
from neo3.contracts import abi, utils as contractutils, contract
from neo3.network.payloads import transaction, verification
from neo3.core import types, utils as coreutils, cryptography
from neo3.wallet import utils, scrypt_parameters as scrypt
from neo3.wallet.types import NeoAddress

# both constants below are used to encrypt/decrypt a private key to/from a nep2 key
NEP_HEADER = bytes([0x01, 0x42])
NEP_FLAG = bytes([0xE0])
# both constants are used when trying to decrypt a private key from a wif
WIF_PREFIX = bytes([0x80])
WIF_SUFFIX = bytes([0x01])
PRIVATE_KEY_LENGTH = 32


class MultiSigContext:
    """
    Signing context for use with multi signature accounts.
    """

    def __init__(self):
        #: indicates if the context has been initialised for usage.
        self.initialised = False
        #: minimum of signatures required for signing.
        self.signing_threshold = 999
        #: list of valid public keys for signing.
        self.expected_public_keys: list[cryptography.ECPoint] = []
        #: completed pairs.
        self.signature_pairs: dict[cryptography.ECPoint, bytes] = {}

    @property
    def is_complete(self):
        return len(self.signature_pairs) >= self.signing_threshold

    def signing_status(self) -> dict[cryptography.ECPoint, bool]:
        # shows which keys have been completed
        raise NotImplementedError

    def process_contract(self, script: bytes) -> None:
        valid, threshold, public_keys = contractutils.parse_as_multisig_contract(script)
        if not valid:
            raise ValueError("Invalid script")
        self.expected_public_keys = public_keys
        self.signing_threshold = threshold
        self.initialised = True


class AccountContract(contract.Contract):
    _contract_params_schema = {
        "type": ["object", "null"],
        "properties": {"name": {"type": "string"}, "type": {"type": "string"}},
        "required": ["name", "type"],
    }
    _json_schema = {
        "type": ["object", "null"],
        "properties": {
            "script": {"type": "string"},
            "parameters": {
                "type": "array",
                "items": _contract_params_schema,
                "minItems": 0,
            },
            "deployed": {"type": "boolean"},
        },
        "required": ["script", "parameters", "deployed"],
    }

    def __init__(
        self, script: bytes, parameter_list: list[abi.ContractParameterDefinition]
    ):
        super().__init__(script, [param.type for param in parameter_list])

        self.parameter_names: list[str] = [param.name for param in parameter_list]
        self.deployed: bool = False

    @classmethod
    def from_contract(cls, c: contract.Contract) -> AccountContract:
        if isinstance(c, AccountContract):
            return c

        parameters = [
            abi.ContractParameterDefinition(f"arg{index}", c.parameter_list[index])
            for index in range(len(c.parameter_list))
        ]
        return cls(script=c.script, parameter_list=parameters)

    @classmethod
    def from_json(cls, json: dict) -> AccountContract:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.
        """
        validate(json, schema=cls._json_schema)

        c = cls(
            script=base64.b64decode(json["script"]),
            parameter_list=list(
                map(
                    lambda p: abi.ContractParameterDefinition.from_json(p),
                    json["parameters"],
                )
            ),
        )
        c.deployed = json["deployed"]

        return c

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        return {
            "script": base64.b64encode(self.script).decode("utf-8"),
            "parameters": list(
                map(
                    lambda index: {
                        "name": self.parameter_names[index],
                        "type": self.parameter_list[index].PascalCase(),
                    },
                    range(len(self.parameter_list)),
                )
            ),
            "deployed": self.deployed,
        }


class Account:
    """
    Container class for handling key material. Can be used to sign transactions.
    """

    _json_schema = {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "label": {"type": ["string", "null"]},
            "isDefault": {"type": "boolean"},
            "lock": {"type": "boolean"},
            "key": {"type": ["string", "null"]},
            "contract": AccountContract._json_schema,
            "extra": {
                "type": ["object", "null"],
                "properties": {},
                "additionalProperties": True,
            },
        },
        "required": ["address", "label", "isDefault", "lock", "key", "extra"],
    }

    def __init__(
        self,
        password: Optional[str] = None,
        private_key: Optional[bytes] = None,
        watch_only: bool = False,
        address: Optional[NeoAddress] = None,
        label: Optional[str] = None,
        lock: bool = False,
        contract_: Optional[contract.Contract] = None,
        extra: Optional[dict[str, Any]] = None,
        scrypt_parameters: Optional[scrypt.ScryptParameters] = None,
    ):
        """
        Instantiate an account. This constructor should only be directly called when it's desired to create a new
        account using just a password and a randomly generated private key, otherwise use the alternative constructors.
        """
        public_key: Optional[cryptography.ECPoint] = None
        encrypted_key: Optional[bytes] = None
        contract_script: Optional[bytes] = None

        if watch_only:
            if address is None:
                raise ValueError("Creating a watch only account requires an address")
            else:
                utils.validate_address(address)

        else:
            if not watch_only and password is None:
                raise ValueError(
                    "Can't create an account without a password unless it is a watch only account. "
                    "To create a watch only accont set `watch_only` to `True` and provide an address"
                )
            key_pair: cryptography.KeyPair

            if private_key is None:
                key_pair = cryptography.KeyPair.generate()
                private_key = key_pair.private_key
            else:
                key_pair = cryptography.KeyPair(private_key)
            encrypted_key = self.private_key_to_nep2(
                private_key, password, scrypt_parameters
            )
            contract_script = contractutils.create_signature_redeemscript(
                key_pair.public_key
            )
            script_hash = coreutils.to_script_hash(contract_script)
            address = address if address else utils.script_hash_to_address(script_hash)
            public_key = key_pair.public_key

        self.label: Optional[str] = label
        self.address: NeoAddress = address
        self.public_key = public_key
        self.encrypted_key = encrypted_key
        self.lock = lock
        self.scrypt_parameters = scrypt_parameters

        if isinstance(contract_, contract.Contract):
            contract_ = AccountContract.from_contract(contract_)
        elif contract_script is not None:
            default_parameters_list = [
                abi.ContractParameterDefinition(
                    name="signature", type=abi.ContractParameterType.SIGNATURE
                )
            ]
            contract_ = AccountContract(contract_script, default_parameters_list)
        self.contract: Optional[AccountContract] = contract_
        self.extra = extra if extra else {}

    def __eq__(self, other) -> bool:
        return isinstance(other, Account) and self.address == other.address

    @property
    def script_hash(self) -> types.UInt160:
        """
        Return account script hash.
        """
        return utils.address_to_script_hash(self.address)

    @property
    def is_watchonly(self) -> bool:
        """
        Return if the account can only be used for observing or in test transactions.
        """
        if self.encrypted_key is None:
            return True
        else:
            return False

    @property
    def is_multisig(self) -> bool:
        """
        Return if the account requires multiple signers.
        """
        if self.contract is None:
            return False
        return contractutils.is_multisig_contract(self.contract.script)

    @property
    def is_single_sig(self) -> bool:
        """
        Return if the account requires a single signer.
        """
        if self.contract is None:
            return False
        return contractutils.is_signature_contract(self.contract.script)

    def add_as_sender(
        self,
        tx: transaction.Transaction,
        scope: Optional[verification.WitnessScope] = None,
    ):
        """
        Add the account as sender of the transaction.

        Args:
            tx: the transaction to modify.
            scope: the type of scope the signature of the sender has. Defaults to CALLED_BY_ENTRY.
             See Also: WitnessScope.
        """
        scope = scope if scope else verification.WitnessScope.CALLED_BY_ENTRY
        tx.signers.insert(0, verification.Signer(self.script_hash, scope))

    def sign_tx(
        self, tx: transaction.Transaction, password: str, magic: Optional[int] = None
    ) -> None:
        """
        Helper function that signs the TX, adds the Witness and Sender.

        Args:
            tx: transaction to sign.
            password: the password to decrypt the private key for signing.
            magic: the network magic.

        Raises:
            ValueError: if transaction validation fails.
        """
        if magic is None:
            magic = settings.settings.network.magic

        self._validate_tx(tx)

        message = (
            magic.to_bytes(4, byteorder="little", signed=False) + tx.hash().to_array()
        )
        signature = self.sign(message, password)

        invocation_script = vm.ScriptBuilder().emit_push(signature).to_array()
        # mypy can't infer that the is_watchonly check ensures public_key has a value
        verification_script = contractutils.create_signature_redeemscript(self.public_key)  # type: ignore
        tx.witnesses.append(
            verification.Witness(invocation_script, verification_script)
        )

    def sign_multisig_tx(
        self,
        tx: transaction.Transaction,
        password: str,
        context: MultiSigContext,
        magic: Optional[int] = None,
    ) -> None:
        """
        Sign a transaction with a multi-signature account.

        Args:
            tx: the transaction to sign.
            password: account password.
            context: the signing context.
            magic: override network magic.
        """
        if magic is None:
            magic = settings.settings.network.magic

        if not self.contract:
            raise ValueError("Account is not a valid multi-signature account")

        # When importing a multi-sig account it searches for an associated regular account to copy key material from.
        # However, it is possible to add a multi-sig account before having a regular account with one of the required
        # public keys for the multi-sig account. Therefore, we should check if we actually have key material to continue
        if self.is_watchonly:
            _, _, public_keys = contractutils.parse_as_multisig_contract(
                self.contract.script
            )
            raise ValueError(
                f"Cannot sign with watch only account. Try adding a regular account to your wallet "
                f"matching one of the following public keys, or update the key material for this account "
                f"directly."
                f" {list(map(lambda pk: str(pk), public_keys))}"
            )

        self._validate_tx(tx)

        if not self.is_multisig:
            raise ValueError("Account is not a valid multi-signature account")

        if not context.initialised:
            context.process_contract(self.contract.script)

        if self.public_key not in context.expected_public_keys:
            raise ValueError(
                "Account is not in the required key list for this signing context"
            )

        message = (
            magic.to_bytes(4, byteorder="little", signed=False) + tx.hash().to_array()
        )
        signature = self.sign(message, password)

        context.signature_pairs.update({self.public_key: signature})

        if context.is_complete:
            # build and insert multisig witness
            sb = vm.ScriptBuilder()

            pairs = list(context.signature_pairs.items())
            # sort by public key
            pairs.sort(key=lambda p: p[0])

            for i, (key, sig) in enumerate(pairs):
                if i == context.signing_threshold:
                    break
                sb.emit_push(sig)

            invocation_script = sb.to_array()
            verification_script = contractutils.create_multisig_redeemscript(
                context.signing_threshold, context.expected_public_keys
            )

            tx.witnesses.append(
                verification.Witness(invocation_script, verification_script)
            )

    def sign(self, data: bytes, password: str) -> bytes:
        """
        Sign arbitrary data using the SECP256R1 curve.

        Args:
            data: data to be signed.
            password: the password to decrypt the private key.

        Returns:
            signature of the signed data.
        """
        if self.is_watchonly:
            raise ValueError("Cannot sign transaction using a watch only account")
        # mypy can't infer that the is_watchonly check ensures encrypted_key has a value
        private_key = self.private_key_from_nep2(self.encrypted_key.decode("utf-8"), password)  # type: ignore
        return cryptography.sign(data, private_key)

    @classmethod
    def create_new(
        cls, password: str, scrypt_parameters: Optional[scrypt.ScryptParameters] = None
    ) -> Account:
        """
        Instantiate and returns a new account encrypted using password.

        Args:
            password: the password to decrypt the nep2 key.
            scrypt_parameters: supply custom Scrypt parameters.

        Returns:
            The newly created account.
        """
        return cls(
            password=password, watch_only=False, scrypt_parameters=scrypt_parameters
        )

    @classmethod
    def from_encrypted_key(
        cls,
        encrypted_key: str,
        password: str,
        scrypt_parameters: Optional[scrypt.ScryptParameters] = None,
    ) -> Account:
        """
        Instantiate and returns an account from a given key and password.
        Default settings assume a NEP-2 encrypted key.

        Args:
            encrypted_key: the encrypted private key.
            password: the password to decrypt the nep2 key.
            scrypt_parameters: supply custom Scrypt parameters.

        Returns:
            The newly created account.
        """
        return cls(
            password=password,
            private_key=cls.private_key_from_nep2(
                encrypted_key, password, scrypt_parameters
            ),
            scrypt_parameters=scrypt_parameters,
        )

    @classmethod
    def from_private_key(
        cls,
        private_key: bytes,
        password: str,
        scrypt_parameters: Optional[scrypt.ScryptParameters] = None,
    ) -> Account:
        """
        Instantiate and returns an account from a given private key and password.

        Args:
            private_key: the private key that will be used to create an encrypted key.
            password: the password to encrypt a randomly generated private key.
            scrypt_parameters: optional custom parameters to be used in the Scrypt algorithm. Default settings conform
            to the NEP-2 standard.

        Returns:
            the newly created account.
        """
        return cls(
            password=password,
            private_key=private_key,
            scrypt_parameters=scrypt_parameters,
        )

    @classmethod
    def from_wif(
        cls,
        wif: str,
        password: str,
        _scrypt_parameters: Optional[scrypt.ScryptParameters] = None,
    ) -> Account:
        """
        Instantiate and returns an account from a given wif and password.

        Args:
            wif: the wif that will be decrypted to get a private key and generate an encrypted key.
            password: the password to encrypt the private key with.
            _scrypt_parameters: the Scrypt parameters to use to encode the private key. Default conforms to NEP-2.

        Returns:
            the newly created account.
        """
        return cls(
            password=password,
            private_key=cls.private_key_from_wif(wif),
            scrypt_parameters=_scrypt_parameters,
        )

    @classmethod
    def watch_only(cls, script_hash: types.UInt160) -> Account:
        """
        Instantiate and returns a watch-only account from a given script hash.

        Args:
            script_hash: the script hash that will identify an account to be watched.

        Returns:
            the account that will be monitored.
        """
        return cls(
            password="",
            watch_only=True,
            address=utils.script_hash_to_address(script_hash),
        )

    @classmethod
    def watch_only_from_address(cls, address: NeoAddress) -> Account:
        """
        Instantiate and returns a watch-only account from a given address.

        Args:
            address: the address that will identify an account to be watched.

        Returns:
            the account that will be monitored.
        """
        return cls(password="", watch_only=True, address=address)

    def to_json(self) -> dict:
        return {
            "address": self.address,
            "label": self.label,
            "lock": self.lock,
            "key": self.encrypted_key.decode("utf-8")
            if self.encrypted_key is not None
            else None,
            "contract": self.contract.to_json() if self.contract is not None else None,
            "extra": self.extra if len(self.extra) > 0 else None,
        }

    @classmethod
    def from_json(
        cls,
        json: dict,
        password: Optional[str],
        scrypt_parameters: Optional[scrypt.ScryptParameters] = None,
    ) -> Account:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.
            password: the password to decrypt the json data.
            scrypt_parameters: the Scrypt parameters to use to encode the private key. Default conforms to NEP-2.

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
        """
        validate(json, schema=cls._json_schema)

        private_key = None
        if json["key"] is not None and password is not None:
            private_key = cls.private_key_from_nep2(
                json["key"], password, scrypt_parameters
            )

        return cls(
            password=password,
            private_key=private_key,
            address=json["address"],
            label=json["label"],
            lock=json["lock"],
            contract_=AccountContract.from_json(json["contract"]),
            extra=json["extra"],
            scrypt_parameters=scrypt_parameters,
            watch_only=True if private_key is None else False,
        )

    @staticmethod
    def private_key_from_nep2(
        nep2_key: str,
        passphrase: str,
        _scrypt_parameters: Optional[scrypt.ScryptParameters] = None,
    ) -> bytes:
        """
        Decrypt a nep2 key into a private key.

        Args:
            nep2_key: the key that will be decrypted.
            passphrase: the password to decrypt the nep2 key.
            _scrypt_parameters: a ScryptParameters object that will be passed to the key derivation function.

        Raises:
            ValueError: if the length of the nep2_key is not valid.
            ValueError: if it's not possible to decode the nep2_key.
            ValueError: if the passphrase is incorrect or the version of the account is not valid.

        Returns:
            the private key.
        """
        if _scrypt_parameters is None:
            _scrypt_parameters = scrypt.ScryptParameters()

        if len(nep2_key) != 58:
            raise ValueError(
                f"Please provide a nep2_key with a length of 58 bytes (LEN: {len(nep2_key)})"
            )

        address_hash_size = 4
        address_hash_offset = len(NEP_FLAG) + len(NEP_HEADER)

        try:
            decoded_key = base58.b58decode_check(nep2_key)
        except Exception:
            raise ValueError("Base58decode failure of nep2 key")

        address_checksum = decoded_key[
            address_hash_offset : address_hash_offset + address_hash_size
        ]
        encrypted = decoded_key[-32:]

        pwd_normalized = bytes(unicodedata.normalize("NFC", passphrase), "utf-8")
        derived = hashlib.scrypt(
            password=pwd_normalized,
            salt=address_checksum,
            n=_scrypt_parameters.n,
            r=_scrypt_parameters.r,
            p=_scrypt_parameters.p,
            dklen=64,
        )

        derived1 = derived[:32]
        derived2 = derived[32:]

        cipher = AES.new(derived2, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        private_key = Account._xor_bytes(decrypted, derived1)

        # Now check that the address hashes match. If they don't, the password was wrong.
        key_pair = cryptography.KeyPair(private_key=private_key)
        script_hash = coreutils.to_script_hash(
            contractutils.create_signature_redeemscript(key_pair.public_key)
        )
        address = utils.script_hash_to_address(script_hash)
        first_hash = hashlib.sha256(address.encode("utf-8")).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        checksum = second_hash[:4]
        if checksum != address_checksum:
            raise ValueError(
                f"Wrong passphrase or key was encrypted with an address version that is not "
                f"{settings.settings.network.account_version}"
            )

        return private_key

    @staticmethod
    def private_key_to_nep2(
        private_key: bytes,
        passphrase: str,
        _scrypt_parameters: Optional[scrypt.ScryptParameters] = None,
    ) -> bytes:
        """
        Encrypt a private key into a nep2 key.

        Args:
            private_key: the key that will be encrypted.
            passphrase: the password to encrypt the nep2 key.
            _scrypt_parameters: a ScryptParameters object that will be passed to the key derivation function.

        Returns:
            the encrypted nep2 key.
        """
        if _scrypt_parameters is None:
            _scrypt_parameters = scrypt.ScryptParameters()

        key_pair = cryptography.KeyPair(private_key=private_key)
        script_hash = coreutils.to_script_hash(
            contractutils.create_signature_redeemscript(key_pair.public_key)
        )
        address = utils.script_hash_to_address(script_hash)
        # NEP2 checksum: hash the address twice and get the first 4 bytes
        first_hash = hashlib.sha256(address.encode("utf-8")).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        checksum = second_hash[:4]

        pwd_normalized = bytes(unicodedata.normalize("NFC", passphrase), "utf-8")
        derived = hashlib.scrypt(
            password=pwd_normalized,
            salt=checksum,
            n=_scrypt_parameters.n,
            r=_scrypt_parameters.r,
            p=_scrypt_parameters.p,
            dklen=64,
        )

        derived1 = derived[:32]
        derived2 = derived[32:]

        xor_ed = Account._xor_bytes(bytes(private_key), derived1)
        cipher = AES.new(derived2, AES.MODE_ECB)
        encrypted = cipher.encrypt(xor_ed)

        nep2 = bytearray()
        nep2.extend(NEP_HEADER)
        nep2.extend(NEP_FLAG)
        nep2.extend(checksum)
        nep2.extend(encrypted)

        # Finally, encode with Base58Check
        encoded_nep2 = base58.b58encode_check(bytes(nep2))

        return encoded_nep2

    @staticmethod
    def private_key_from_wif(wif: str) -> bytes:
        """
        Decrypt a private key from a wif.

        Args:
            wif: the wif that will be decrypted.

        Raises:
            ValueError: if the wif is not valid.
        """
        try:
            decoded_key: bytes = base58.b58decode_check(wif)
        except Exception:
            raise ValueError("Base58decode failure of wif")

        if len(decoded_key) != 34:
            raise ValueError(
                f"The decoded wif length should be "
                f"{len(WIF_PREFIX) + PRIVATE_KEY_LENGTH + len(WIF_SUFFIX)}, while the given wif "
                f"length is {len(decoded_key)}"
            )
        elif decoded_key[:1] != WIF_PREFIX:
            raise ValueError(f"The decoded wif first byte should be {str(WIF_PREFIX)}")
        elif decoded_key[-1:] != WIF_SUFFIX:
            raise ValueError(f"The decoded wif last byte should be {str(WIF_SUFFIX)}")

        private_key = decoded_key[1:33]

        return private_key

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        """
        XOR on two bytes objects

        Args:
            a (bytes): object 1
            b (bytes): object 2
        Returns:
            the XOR result
        """
        assert len(a) == len(b)
        res = bytearray()
        for i in range(len(a)):
            res.append(a[i] ^ b[i])
        return bytes(res)

    def _validate_tx(self, tx: transaction.Transaction) -> None:
        """
        Helper to validate properties before signing
        """
        if tx.network_fee == 0 or tx.system_fee == 0:
            raise ValueError(
                "Transaction validation failure - "
                "a transaction without network and system fees will always fail to validate on chain"
            )

        if len(tx.signers) == 0:
            raise ValueError("Transaction validation failure - Missing sender")

        if len(tx.script) == 0:
            raise ValueError(
                "Transaction validation failure - script field can't be empty"
            )

        if self.is_watchonly:
            raise ValueError("Cannot sign transaction using a watch only account")
