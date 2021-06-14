from __future__ import annotations
import base58  # type: ignore
import base64
import hashlib
import unicodedata
from typing import Optional, Dict, Any, List
from Crypto.Cipher import AES
from jsonschema import validate  # type: ignore
from neo3 import settings, contracts, vm, wallet, storage
from neo3.network import payloads
from neo3.core import types, to_script_hash, cryptography, syscall_name_to_int


# both constants below are used to encrypt/decrypt a private key to/from a nep2 key
NEP_HEADER = bytes([0x01, 0x42])
NEP_FLAG = bytes([0xe0])
# both constants are used when trying to decrypt a private key from a wif
WIF_PREFIX = bytes([0x80])
WIF_SUFFIX = bytes([0x01])
PRIVATE_KEY_LENGTH = 32


class AccountContract(contracts.Contract):
    _contract_params_schema = {
        "type": ["object", "null"],
        "properties": {
            "name": {"type": "string"},
            "type": {"type": "string"}
        },
        "required": ["name", "type"]
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
            "deployed": {"type": "boolean"}
        },
        "required": ["script", "parameters", "deployed"]
    }

    def __init__(self, script: bytes, parameter_list: List[contracts.ContractParameterDefinition]):
        super().__init__(script, [param.type for param in parameter_list])

        self.parameter_names: List[str] = [param.name for param in parameter_list]
        self.deployed: bool = False

    @classmethod
    def from_contract(cls, contract: contracts.Contract) -> AccountContract:
        if isinstance(contract, AccountContract):
            return contract

        parameters = [contracts.ContractParameterDefinition(f"arg{index}", contract.parameter_list[index])
                      for index in range(len(contract.parameter_list))]
        return cls(script=contract.script,
                   parameter_list=parameters)

    @classmethod
    def from_json(cls, json: dict) -> AccountContract:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.
        """
        validate(json, schema=cls._json_schema)

        contract = cls(
            script=base64.b64decode(json['script']),
            parameter_list=list(map(lambda p: contracts.ContractParameterDefinition.from_json(p), json['parameters']))
        )
        contract.deployed = json['deployed']

        return contract

    def to_json(self) -> dict:
        """ Convert object into JSON representation. """
        return {
            'script': base64.b64encode(self.script).decode('utf-8'),
            'parameters': list(map(lambda index: {'name': self.parameter_names[index],
                                                  'type': self.parameter_list[index].PascalCase()
                                                  },
                                   range(len(self.parameter_list)))),
            'deployed': self.deployed
        }


class Account:
    _json_schema = {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "label": {"type": ["string", "null"]},
            "isDefault": {"type": "boolean"},
            "lock": {"type": "boolean"},
            "key": {"type": ["string", "null"]},
            "contract": AccountContract._json_schema,
            "extra": {"type": ["object", "null"],
                      "properties": {},
                      "additionalProperties": True
                      }
        },
        "required": ["address", "label", "isDefault", "lock", "key", "extra"]
    }

    def __init__(self, password: str,
                 private_key: Optional[bytes] = None,
                 watch_only: bool = False,
                 address: Optional[str] = None,
                 label: Optional[str] = None,
                 lock: bool = False,
                 contract: Optional[contracts.Contract] = None,
                 extra: Optional[Dict[str, Any]] = None
                 ):
        """
        Instantiate an account. This constructor should only be directly called when it's desired to create a new
        account using just a password and a randomly generated private key, otherwise use the alternative constructors
        """
        public_key: Optional[cryptography.ECPoint] = None
        encrypted_key: Optional[bytes] = None
        contract_script: Optional[bytes] = None

        if watch_only:
            if address is None:
                raise ValueError("Creating a watch only account requires an address")
            else:
                self.validate_address(address)

        else:
            key_pair: cryptography.KeyPair

            if private_key is None:
                key_pair = cryptography.KeyPair.generate()
                private_key = key_pair.private_key
            else:
                key_pair = cryptography.KeyPair(private_key)
            encrypted_key = self.private_key_to_nep2(private_key, password)
            contract_script = contracts.Contract.create_signature_redeemscript(key_pair.public_key)
            script_hash = to_script_hash(contract_script)
            address = address if address else self.script_hash_to_address(script_hash)
            public_key = key_pair.public_key

        self.label: Optional[str] = label
        self.address: str = address
        self.public_key = public_key
        self.encrypted_key = encrypted_key
        self.lock = lock

        if not isinstance(contract, AccountContract):
            if contract is not None:
                contract = AccountContract.from_contract(contract)
            elif contract_script is not None:
                default_parameters_list = [
                    contracts.ContractParameterDefinition(name='signature',
                                                          type=contracts.ContractParameterType.SIGNATURE)
                ]
                contract = AccountContract(contract_script, default_parameters_list)

        self.contract: Optional[AccountContract] = contract
        self.extra = extra if extra else {}

    def __eq__(self, other) -> bool:
        return isinstance(other, Account) and self.address == other.address

    @property
    def script_hash(self) -> types.UInt160:
        return self.address_to_script_hash(self.address)

    @property
    def is_watchonly(self) -> bool:
        if self.encrypted_key is None:
            return True
        else:
            return False

    @property
    def is_multisig(self) -> bool:
        if self.contract is None:
            return False
        return contracts.Contract.is_multisig_contract(self.contract.script)

    @property
    def is_single_sig(self) -> bool:
        if self.contract is None:
            return False
        return contracts.Contract.is_signature_contract(self.contract.script)

    def add_as_sender(self, tx: payloads.Transaction):
        """
        Add the account as sender of the transaction.

        Args:
            tx: the transaction to modify
        """
        tx.signers.insert(0, payloads.Signer(self.script_hash, payloads.WitnessScope.GLOBAL))

    def sign_tx(self, tx: payloads.Transaction, password: str, magic: Optional[int] = None) -> None:
        """
        Helper function that signs the TX, adds the Witness and Sender

        Args:
            tx: transaction to sign
            password: the password to decrypt the private key for signing
            magic: the network magic

        Raises:
            ValueError: if transaction validation fails
        """
        if magic is None:
            magic = settings.network.magic

        self._validate_tx(tx)

        message = magic.to_bytes(4, byteorder="little", signed=False) + tx.hash().to_array()
        signature = self.sign(message, password)

        invocation_script = vm.ScriptBuilder().emit_push(signature).to_array()
        # mypy can't infer that the is_watchonly check ensures public_key has a value
        verification_script = contracts.Contract.create_signature_redeemscript(self.public_key)  # type: ignore
        tx.witnesses.insert(0, payloads.Witness(invocation_script, verification_script))

    def sign_multisig_tx(self,
                         tx: payloads.Transaction,
                         password: str,
                         context: wallet.MultiSigContext,
                         magic: Optional[int] = None) -> None:
        if magic is None:
            magic = settings.network.magic

        if not self.contract:
            raise ValueError("Account is not a valid multi-signature account")

        # When importing a multi-sig account it searches for an associated regular account to copy key material from.
        # However, it is possible to add a multi-sig account before having a regular account with one of the required
        # public keys for the multi-sig account. Therefore, we should check if we actually have key material to continue
        if self.is_watchonly:
            _, _, public_keys = contracts.Contract.parse_as_multisig_contract(self.contract.script)
            raise ValueError(f"Cannot sign with watch only account. Try adding a regular account to your wallet "
                             f"matching one of the following public keys, or update the key material for this account "
                             f"directly."
                             f" {list(map(lambda pk: str(pk), public_keys))}")

        self._validate_tx(tx)

        if not self.is_multisig:
            raise ValueError("Account is not a valid multi-signature account")

        if not context.initialised:
            context.process_contract(self.contract.script)

        if self.public_key not in context.expected_public_keys:
            raise ValueError("Account is not in the required key list for this signing context")

        message = magic.to_bytes(4, byteorder="little", signed=False) + tx.hash().to_array()
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
            verification_script = contracts.Contract.create_multisig_redeemscript(context.signing_threshold,
                                                                                  context.expected_public_keys)

            tx.witnesses.insert(0, payloads.Witness(invocation_script, verification_script))

    def sign(self, data: bytes, password: str) -> bytes:
        """
        Sign arbitrary data using the SECP256R1 curve.

        Args:
            data: data to be signed
            password: the password to decrypt the private key

        Returns:
            signature of the signed data
        """
        if self.is_watchonly:
            raise ValueError("Cannot sign transaction using a watch only account")
        # mypy can't infer that the is_watchonly check ensures encrypted_key has a value
        private_key = self.private_key_from_nep2(self.encrypted_key.decode("utf-8"), password)  # type: ignore
        return cryptography.sign(data, private_key)

    @classmethod
    def create_new(cls, password: str) -> Account:
        return cls(password=password, watch_only=False)

    @classmethod
    def from_encrypted_key(cls, nep2_key: str, password: str) -> Account:
        """
        Instantiate and returns an account from a given nep2 key and password.

        Args:
            nep2_key: the encrypted private key.
            password: the password to decrypt the nep2 key.

        Returns:
            The newly created account.
        """
        return cls(password=password, private_key=cls.private_key_from_nep2(nep2_key, password))

    @classmethod
    def from_private_key(cls, private_key: bytes, password: str) -> Account:
        """
        Instantiate and returns an account from a given private key and password.

        Args:
            private_key: the private key that will be used to create an encrypted key.
            password: the password to encrypt a randomly generated private key.

        Returns:
            The newly created account.
        """
        return cls(password=password, private_key=private_key)

    @classmethod
    def from_wif(cls, wif: str, password: str) -> Account:
        """
        Instantiate and returns an account from a given wif and password.

        Args:
            wif: the wif that will be decrypted to get a private key and generate an encrypted key.
            password: the password to encrypt the private key with.

        Returns:
            The newly created account.
        """
        return cls(password=password, private_key=cls.private_key_from_wif(wif))

    @classmethod
    def watch_only(cls, script_hash: types.UInt160) -> Account:
        """
        Instantiate and returns a watch-only account from a given script hash.

        Args:
            script_hash: the script hash that will identify an account to be watched.

        Returns:
            The account that will be monitored.
        """
        return cls(password='', watch_only=True, address=cls.script_hash_to_address(script_hash))

    @classmethod
    def watch_only_from_address(cls, address: str) -> Account:
        """
        Instantiate and returns a watch-only account from a given address.

        Args:
            address: the address that will identify an account to be watched.

        Returns:
            The account that will be monitored.
        """
        return cls(password='', watch_only=True, address=address)

    def to_json(self) -> dict:
        return {
            'address': self.address,
            'label': self.label,
            'lock': self.lock,
            'key': self.encrypted_key.decode('utf-8') if self.encrypted_key is not None else None,
            'contract': self.contract.to_json() if self.contract is not None else None,
            'extra': self.extra if len(self.extra) > 0 else None
        }

    @classmethod
    def from_json(cls, json: dict, password: str) -> Account:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.
            password: the password to decrypt the json data.

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
        """
        validate(json, schema=cls._json_schema)

        return cls(password=password,
                   private_key=(cls.private_key_from_nep2(json['key'], password)
                                if json['key'] is not None else json['key']),
                   address=json['address'],
                   label=json['label'],
                   lock=json['lock'],
                   contract=AccountContract.from_json(json['contract']),
                   extra=json['extra']
                   )

    @staticmethod
    def script_hash_to_address(script_hash: types.UInt160) -> str:
        """
        Converts the specified script hash to an address.

        Args:
            script_hash: script hash to convert.
        """
        version = settings.network.account_version  # this is the current Neo's protocol version
        data = version.to_bytes(1, 'little') + script_hash.to_array()

        return base58.b58encode_check(data).decode('utf-8')

    @staticmethod
    def address_to_script_hash(address: str) -> types.UInt160:
        """
        Converts the specified address to a script hash.

        Args:
            address: address to convert

        Raises:
            ValueError: if the length of data (address value in bytes) is not valid.
            ValueError: if the account version is not valid.
        """
        Account.validate_address(address)

        data = base58.b58decode_check(address)

        return types.UInt160(data[1:])

    @staticmethod
    def private_key_from_nep2(nep2_key: str, passphrase: str,
                              scrypt_parameters: Optional[wallet.ScryptParameters] = None) -> bytes:
        """
        Decrypt a nep2 key into a private key.

        Args:
            nep2_key: the key that will be decrypt.
            passphrase: the password to decrypt the nep2 key.
            scrypt_parameters: a ScryptParameters object that will be passed to the key derivation function.

        Raises:
            ValueError: if the length of the nep2_key is not valid.
            ValueError: if it's not possible to decode the nep2_key.
            ValueError: if the passphrase is incorrect or the version of the account is not valid.

        Returns:
            the private key.
        """
        if scrypt_parameters is None:
            scrypt_parameters = wallet.ScryptParameters()

        if len(nep2_key) != 58:
            raise ValueError(f"Please provide a nep2_key with a length of 58 bytes (LEN: {len(nep2_key)})")

        address_hash_size = 4
        address_hash_offset = len(NEP_FLAG) + len(NEP_HEADER)

        try:
            decoded_key = base58.b58decode_check(nep2_key)
        except Exception:
            raise ValueError("Base58decode failure of nep2 key")

        address_checksum = decoded_key[address_hash_offset:address_hash_offset + address_hash_size]
        encrypted = decoded_key[-32:]

        pwd_normalized = bytes(unicodedata.normalize("NFC", passphrase), "utf-8")
        derived = hashlib.scrypt(password=pwd_normalized, salt=address_checksum,
                                 n=scrypt_parameters.n,
                                 r=scrypt_parameters.r,
                                 p=scrypt_parameters.p,
                                 dklen=64)

        derived1 = derived[:32]
        derived2 = derived[32:]

        cipher = AES.new(derived2, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        private_key = Account._xor_bytes(decrypted, derived1)

        # Now check that the address hashes match. If they don't, the password was wrong.
        key_pair = cryptography.KeyPair(private_key=private_key)
        script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(key_pair.public_key))
        address = Account.script_hash_to_address(script_hash)
        first_hash = hashlib.sha256(address.encode("utf-8")).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        checksum = second_hash[:4]
        if checksum != address_checksum:
            raise ValueError(f"Wrong passphrase or key was encrypted with an address version that is not "
                             f"{settings.network.account_version}")

        return private_key

    @staticmethod
    def private_key_to_nep2(private_key: bytes, passphrase: str,
                            scrypt_parameters: Optional[wallet.ScryptParameters] = None) -> bytes:
        """
        Encrypt a private key into a nep2 key.

        Args:
            private_key: the key that will be encrypt.
            passphrase: the password to encrypt the nep2 key.
            scrypt_parameters: a ScryptParameters object that will be passed to the key derivation function.

        Returns:
            the encrypted nep2 key.
        """
        if scrypt_parameters is None:
            scrypt_parameters = wallet.ScryptParameters()

        key_pair = cryptography.KeyPair(private_key=private_key)
        script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(key_pair.public_key))
        address = Account.script_hash_to_address(script_hash)
        # NEP2 checksum: hash the address twice and get the first 4 bytes
        first_hash = hashlib.sha256(address.encode("utf-8")).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        checksum = second_hash[:4]

        pwd_normalized = bytes(unicodedata.normalize("NFC", passphrase), "utf-8")
        derived = hashlib.scrypt(password=pwd_normalized, salt=checksum,
                                 n=scrypt_parameters.n,
                                 r=scrypt_parameters.r,
                                 p=scrypt_parameters.p,
                                 dklen=64)

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
            raise ValueError(f"The decoded wif length should be "
                             f"{len(WIF_PREFIX) + PRIVATE_KEY_LENGTH + len(WIF_SUFFIX)}, while the given wif "
                             f"length is {len(decoded_key)}")
        elif decoded_key[:1] != WIF_PREFIX:
            raise ValueError(f"The decoded wif first byte should be {str(WIF_PREFIX)}")
        elif decoded_key[-1:] != WIF_SUFFIX:
            raise ValueError(f"The decoded wif last byte should be {str(WIF_SUFFIX)}")

        private_key = decoded_key[1: 33]

        return private_key

    @staticmethod
    def is_valid_address(address: str) -> bool:
        """
        Test if the provided address is a valid address.

        Args:
            address: an address.
        """
        try:
            Account.validate_address(address)
        except ValueError:
            return False
        return True

    @staticmethod
    def validate_address(address: str) -> None:
        """
        Validate a given address. If address is not valid an exception will be raised.

        Args:
            address: an address.

        Raises:
            ValueError: if the length of data(address value in bytes) is not valid.
            ValueError: if the account version is not valid.
        """
        data: bytes = base58.b58decode_check(address)
        if len(data) != len(types.UInt160.zero()) + 1:
            raise ValueError(f"The address is wrong, because data (address value in bytes) length should be "
                             f"{len(types.UInt160.zero()) + 1}")
        elif data[0] != settings.network.account_version:
            raise ValueError(f"The account version is not {settings.network.account_version}")

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        """
        XOR on two bytes objects
        Args:
            a (bytes): object 1
            b (bytes): object 2
        Returns:
            bytes: The XOR result
        """
        assert len(a) == len(b)
        res = bytearray()
        for i in range(len(a)):
            res.append(a[i] ^ b[i])
        return bytes(res)

    def _validate_tx(self, tx: payloads.Transaction) -> None:
        """
        Helper to validate properties before signing
        """
        if tx.network_fee == 0 or tx.system_fee == 0:
            raise ValueError("Transaction validation failure - "
                             "a transaction without network and system fees will always fail to validate on chain")

        if len(tx.signers) == 0:
            raise ValueError("Transaction validation failure - Missing sender")

        if len(tx.script) == 0:
            raise ValueError("Transaction validation failure - script field can't be empty")

        if self.is_watchonly:
            raise ValueError("Cannot sign transaction using a watch only account")
