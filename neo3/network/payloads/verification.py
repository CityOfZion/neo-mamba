from __future__ import annotations
import hashlib
import abc
import base64
from enum import IntFlag
from neo3.core import serialization, utils, types, cryptography, Size as s, IJson
from neo3.network import payloads
from neo3 import storage
from typing import List, Dict, Any, no_type_check


class Signer(serialization.ISerializable, IJson):
    """
    A class that specifies who can pass CheckWitness() verifications in a smart contract.
    """

    #: Maximum number of allowed_contracts or allowed_groups
    MAX_SUB_ITEMS = 16

    def __init__(self, account: types.UInt160,
                 scope: payloads.WitnessScope = None,
                 allowed_contracts: List[types.UInt160] = None,
                 allowed_groups: List[cryptography.ECPoint] = None):
        #: The TX sender.
        self.account = account
        #: payloads.WitnessScope: The configured validation scope.
        self.scope = scope if scope else payloads.WitnessScope.NONE
        #: List[types.UInt160]: Whitelist of contract script hashes if used with
        #: :const:`~neo3.network.payloads.verification.WitnessScope.CUSTOM_CONTRACTS`.
        self.allowed_contracts = allowed_contracts if allowed_contracts else []
        #: List[cryptography.ECPoint]: Whitelist of public keys if used with
        #: :const:`~neo3.network.payloads.verification.WitnessScope.CUSTOM_GROUPS`.
        self.allowed_groups = allowed_groups if allowed_groups else []

    def __len__(self):
        contracts_size = 0
        if payloads.WitnessScope.CUSTOM_CONTRACTS in self.scope:
            contracts_size = utils.get_var_size(self.allowed_contracts)

        groups_size = 0
        if payloads.WitnessScope.CUSTOM_GROUPS in self.scope:
            groups_size = utils.get_var_size(self.allowed_groups)

        return s.uint160 + s.uint8 + contracts_size + groups_size

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.account != other.account:
            return False
        return True

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_serializable(self.account)
        writer.write_uint8(self.scope)

        if payloads.WitnessScope.CUSTOM_CONTRACTS in self.scope:
            writer.write_serializable_list(self.allowed_contracts)

        if payloads.WitnessScope.CUSTOM_GROUPS in self.scope:
            writer.write_serializable_list(self.allowed_groups)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.account = reader.read_serializable(types.UInt160)
        self.scope = payloads.WitnessScope(reader.read_uint8())

        if payloads.WitnessScope.GLOBAL in self.scope and self.scope != payloads.WitnessScope.GLOBAL:
            raise ValueError("Deserialization error - invalid scope. GLOBAL scope not allowed with other scope types")

        if payloads.WitnessScope.CUSTOM_CONTRACTS in self.scope:
            self.allowed_contracts = reader.read_serializable_list(types.UInt160)

        if payloads.WitnessScope.CUSTOM_GROUPS in self.scope:
            self.allowed_groups = reader.read_serializable_list(cryptography.ECPoint,  # type: ignore
                                                                max=self.MAX_SUB_ITEMS)

    def to_json(self) -> dict:
        """ Convert object into json """
        json: Dict[str, Any] = {
            "account": "0x" + str(self.account),
            "scopes": self.scope.to_csharp_name(),
        }

        if payloads.WitnessScope.CUSTOM_CONTRACTS in self.scope:
            json.update({"allowedcontracts": list(map(lambda a: "0x" + str(a), self.allowed_contracts))})
        if payloads.WitnessScope.CUSTOM_GROUPS in self.scope:
            json.update({"allowedgroups": list(map(lambda g: str(g), self.allowed_groups))})

        return json

    @classmethod
    def from_json(cls, json: dict):
        """ Create object from JSON """
        account = types.UInt160.from_string(json['account'][2:])
        scopes = payloads.WitnessScope.from_chsarp_name(json['scopes'])

        allowed_contracts = []
        if "allowedcontracts" in json:
            for contract in json['allowedcontracts']:
                allowed_contracts.append(types.UInt160.from_string(contract[2:]))

        allowed_groups = []
        if "allowedgroups" in json:
            for group in json['allowedgroups']:
                allowed_groups.append(cryptography.ECPoint.deserialize_from_bytes(bytes.fromhex(group)))

        return cls(account, scopes, allowed_contracts, allowed_groups)

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt160.zero())


class Witness(serialization.ISerializable, IJson):
    """
    An executable verification script that validates a verifiable object like a transaction.
    """
    _MAX_INVOCATION_SCRIPT = 1024
    _MAX_VERIFICATION_SCRIPT = 1024

    def __init__(self, invocation_script: bytes, verification_script: bytes):
        #: A set of VM instructions to setup the stack for verification.
        self.invocation_script = invocation_script
        #: A set of VM instructions that does the actual verification.
        #: It is expected to set the result stack to a boolean True if validation passed.
        self.verification_script = verification_script
        self._script_hash = None

    def __len__(self):
        return utils.get_var_size(self.invocation_script) + utils.get_var_size(self.verification_script)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_var_bytes(self.invocation_script)
        writer.write_var_bytes(self.verification_script)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.invocation_script = reader.read_var_bytes(max=self._MAX_INVOCATION_SCRIPT)
        self.verification_script = reader.read_var_bytes(max=self._MAX_VERIFICATION_SCRIPT)

    def script_hash(self) -> types.UInt160:
        """ Get the script hash based on the verification script."""
        intermediate_data = hashlib.sha256(self.verification_script).digest()
        data = hashlib.new('ripemd160', intermediate_data).digest()
        return types.UInt160(data=data)

    def to_json(self) -> dict:
        """ Convert object into json """
        return {
            "invocation": base64.b64encode(self.invocation_script).decode(),
            "verification": base64.b64encode(self.verification_script).decode()
        }

    @classmethod
    def from_json(cls, json: dict):
        """ Create object from JSON """
        return cls(base64.b64decode(json['invocation']), base64.b64decode(json['verification']))

    @classmethod
    def _serializable_init(cls):
        return cls(b'', b'')


class WitnessScope(IntFlag):
    """
    Determine the rules for a smart contract :func:`CheckWitness()` sys call.
    """
    #: No Contract was witnessed. Only sign the transaction.
    NONE = 0x0
    #: Allow the witness if the current calling script hash equals the entry script hash into the virtual machine.
    #: Using this prevents passing :func:`CheckWitness()` in a smart contract called via another smart contract.
    CALLED_BY_ENTRY = 0x01
    #: Allow the witness if called from a smart contract that is whitelisted in the signer
    #: :attr:`~neo3.network.payloads.verification.Signer.allowed_contracts` attribute.
    CUSTOM_CONTRACTS = 0x10
    #: Allow the witness if any public key is in the signer
    #: :attr:`~neo3.network.payloads.verification.Signer.allowed_groups` attribute is whitelisted in the contracts
    #: manifest.groups array.
    CUSTOM_GROUPS = 0x20
    #: Allow the witness in all context. Equal to NEO 2.x's default behaviour.
    GLOBAL = 0x80

    @no_type_check
    def to_csharp_name(self) -> str:
        """
        Internal helper to match C# convention
        """
        if self == 0:
            return "None"
        flags = []
        if self.CALLED_BY_ENTRY in self:
            flags.append("CalledByEntry")
        if self.CUSTOM_CONTRACTS in self:
            flags.append("CustomContracts")
        if self.CUSTOM_GROUPS in self:
            flags.append("CustomGroups")
        if self.GLOBAL in self:
            flags.append("Global")
        return ", ".join(flags)

    @classmethod
    def from_chsarp_name(cls, csharp_name):
        """
        Internal helper to parse from C# convention
        """
        c = cls(cls.NONE)
        if "CalledByEntry" in csharp_name:
            c |= c.CALLED_BY_ENTRY
        if "CustomContracts" in csharp_name:
            c |= c.CUSTOM_CONTRACTS
        if "CustomGroups" in csharp_name:
            c |= c.CUSTOM_GROUPS
        if "Global" in csharp_name:
            c |= c.GLOBAL
        return c


class IVerifiable(serialization.ISerializable):
    def __init__(self, *args, **kwargs):
        super(IVerifiable, self).__init__(*args, **kwargs)
        self.witnesses: List[Witness] = []

    @abc.abstractmethod
    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        """ """

    @abc.abstractmethod
    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        """ """

    @abc.abstractmethod
    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        """
        Helper method to get the data used in verifying the object.
        """

    def get_hash_data(self, protocol_magic: int) -> bytes:
        """ Get the unsigned data

        Args:
            protocol_magic: network protocol number (NEO MainNet = 5195086, Testnet = 1951352142, private net = ??)
        """
        with serialization.BinaryWriter() as writer:
            writer.write_uint32(protocol_magic)
            self.serialize_unsigned(writer)
            return writer.to_array()
