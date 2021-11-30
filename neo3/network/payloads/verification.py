from __future__ import annotations
import hashlib
import abc
import base64
from enum import IntFlag, IntEnum
from neo3.core import serialization, utils, types, cryptography, Size as s, IJson
from neo3.network import payloads
from neo3 import storage, contracts
from typing import List, Dict, Any, no_type_check, Iterator


class Signer(serialization.ISerializable, IJson):
    """
    A class that specifies who can pass CheckWitness() verifications in a smart contract.
    """

    #: Maximum number of allowed_contracts or allowed_groups
    MAX_SUB_ITEMS = 16

    def __init__(self, account: types.UInt160,
                 scope: payloads.WitnessScope = None,
                 allowed_contracts: List[types.UInt160] = None,
                 allowed_groups: List[cryptography.ECPoint] = None,
                 rules: List[WitnessRule] = None):
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
        #: List of rules that must pass for the current execution context when used with
        #: :const:`~neo3.network.payloads.verification.WitnessScope.WITNESS_RULES`.
        self.rules = rules if rules else []

    def __len__(self):
        contracts_size = 0
        if payloads.WitnessScope.CUSTOM_CONTRACTS in self.scope:
            contracts_size = utils.get_var_size(self.allowed_contracts)

        groups_size = 0
        if payloads.WitnessScope.CUSTOM_GROUPS in self.scope:
            groups_size = utils.get_var_size(self.allowed_groups)

        rules_size = 0
        if payloads.WitnessScope.WITNESS_RULES in self.scope:
            rules_size = utils.get_var_size(self.rules)

        return s.uint160 + s.uint8 + contracts_size + groups_size + rules_size

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

        if payloads.WitnessScope.WITNESS_RULES in self.scope:
            writer.write_serializable_list(self.rules)

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
            self.allowed_contracts = reader.read_serializable_list(types.UInt160, max=self.MAX_SUB_ITEMS)

        if payloads.WitnessScope.CUSTOM_GROUPS in self.scope:
            self.allowed_groups = reader.read_serializable_list(cryptography.ECPoint,  # type: ignore
                                                                max=self.MAX_SUB_ITEMS)

        if payloads.WitnessScope.WITNESS_RULES in self.scope:
            self.rules = reader.read_serializable_list(WitnessRule, max=self.MAX_SUB_ITEMS)

    def get_all_rules(self) -> Iterator[WitnessRule]:
        if payloads.WitnessScope.GLOBAL in self.scope:
            yield WitnessRule(WitnessRuleAction.ALLOW, ConditionBool(True))
        else:
            if payloads.WitnessScope.CALLED_BY_ENTRY in self.scope:
                yield WitnessRule(WitnessRuleAction.ALLOW, ConditionCalledByEntry())

            if payloads.WitnessScope.CUSTOM_CONTRACTS in self.scope:
                for hash_ in self.allowed_contracts:
                    yield WitnessRule(WitnessRuleAction.ALLOW, ConditionScriptHash(hash_))

            if payloads.WitnessScope.CUSTOM_GROUPS in self.scope:
                for group in self.allowed_groups:
                    yield WitnessRule(WitnessRuleAction.ALLOW, ConditionGroup(group))

            if payloads.WitnessScope.WITNESS_RULES in self.scope:
                for rule in self.rules:
                    yield rule

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
        if payloads.WitnessScope.WITNESS_RULES in self.scope:
            json.update({"rules": list(map(lambda r: r.to_json(), self.rules))})

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
    #: Allow the witness if the specified #: :attr:`~neo3.network.payloads.verification.Signer.rules are satisfied
    WITNESS_RULES = 0x40
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


class WitnessRuleAction(IntEnum):
    DENY = 0
    ALLOW = 1


class WitnessConditionType(IntEnum):
    BOOLEAN = 0x0
    NOT = 0x01
    AND = 0x2
    OR = 0x03
    SCRIPT_HASH = 0x18
    GROUP = 0x19
    CALLED_BY_ENTRY = 0x20
    CALLED_BY_CONTRACT = 0x28
    CALLED_BY_GROUP = 0x29

    def to_csharp_string(self) -> str:
        if self == WitnessConditionType.SCRIPT_HASH:
            return "ScriptHash"
        elif self == WitnessConditionType.CALLED_BY_ENTRY:
            return "CalledByEntry"
        elif self == WitnessConditionType.CALLED_BY_CONTRACT:
            return "CalledByContract"
        elif self == WitnessConditionType.CALLED_BY_GROUP:
            return "CalledByGroup"
        else:
            return self.name.title()


class WitnessCondition(serialization.ISerializable, IJson):
    MAX_SUB_ITEMS = 16
    MAX_NESTING_DEPTH = 2

    _type = WitnessConditionType.BOOLEAN

    def __len__(self):
        return s.uint8  # 1 byte witness condition

    @property
    def type(self) -> WitnessConditionType:
        return self._type

    @abc.abstractmethod
    def match(self, engine: contracts.ApplicationEngine) -> bool:
        """ Check if the current execution context matches the condition"""

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint8(self.type.value)
        self._serialize_without_type(writer)

    @abc.abstractmethod
    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        """ """

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self._type = WitnessConditionType(reader.read_uint8())
        self._deserialize_without_type(reader, self.MAX_NESTING_DEPTH)

    @abc.abstractmethod
    def _deserialize_without_type(self, reader: serialization.BinaryReader, max_nesting_depth: int) -> None:
        """ Deserialize from a buffer without reading the `type` member. """

    @staticmethod
    def _deserialize_conditions(reader: serialization.BinaryReader, max_nesting_depth: int) -> List[WitnessCondition]:
        conditions = []
        for _ in range(reader.read_var_int(WitnessCondition.MAX_SUB_ITEMS)):
            conditions.append(WitnessCondition._deserialize_from(reader, max_nesting_depth))
        return conditions

    @staticmethod
    def _deserialize_from(reader: serialization.BinaryReader, max_nesting_depth: int) -> WitnessCondition:
        condition_type = reader.read_uint8()
        for sub in WitnessCondition.__subclasses__():
            child = sub._serializable_init()  # type: ignore
            if child.type.value == condition_type:
                child._deserialize_without_type(reader, max_nesting_depth)
                return child
        else:
            raise ValueError(f"Deserialization error - unknown witness condition. Type: {condition_type}")

    def to_json(self) -> dict:
        return {'type': self.type.to_csharp_string()}

    @classmethod
    def from_json(cls, json: dict):
        raise NotImplementedError()


class ConditionAnd(WitnessCondition):
    _type = WitnessConditionType.AND

    def __init__(self, expressions: List[WitnessCondition]):
        self.expressions = expressions

    def __len__(self):
        return super(ConditionAnd, self).__len__() + utils.get_var_size(self.expressions)

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return self.expressions == other.expressions

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable_list(self.expressions)

    def _deserialize_without_type(self, reader: serialization.BinaryReader, max_nesting_depth: int) -> None:
        if max_nesting_depth <= 0:
            raise ValueError("Max nesting depth cannot be negative")
        self.expressions = WitnessCondition._deserialize_conditions(reader, max_nesting_depth)
        if len(self.expressions) == 0:
            raise ValueError("Cannot have 0 expressions")

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        return all([condition.match(engine) for condition in self.expressions])

    def to_json(self) -> dict:
        json = super(ConditionAnd, self).to_json()
        json['expressions'] = list(map(lambda exp: exp.to_json(), self.expressions))
        return json

    @classmethod
    def _serializable_init(cls):
        return cls([])


class ConditionBool(WitnessCondition):
    _type = WitnessConditionType.BOOLEAN

    def __init__(self, value: bool):
        self.value = value

    def __len__(self):
        return super(ConditionBool, self).__len__() + s.uint8

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return self.value == other.value

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_bool(self.value)

    def _deserialize_without_type(self, reader: serialization.BinaryReader, max_nesting_depth: int) -> None:
        self.value = reader.read_bool()

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        return self.value

    def to_json(self) -> dict:
        json = super(ConditionBool, self).to_json()
        json['expression'] = self.value
        return json

    @classmethod
    def _serializable_init(cls):
        return cls(False)


class ConditionNot(WitnessCondition):
    _type = WitnessConditionType.NOT

    def __init__(self, expression: WitnessCondition):
        self.expression = expression

    def __len__(self):
        return super(ConditionNot, self).__len__() + len(self.expression)

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return self.expression == other.expression

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable(self.expression)

    def _deserialize_without_type(self, reader: serialization.BinaryReader, max_nesting_depth: int) -> None:
        if max_nesting_depth <= 0:
            raise ValueError("Max nesting depth cannot be negative")
        self.expression = WitnessCondition._deserialize_from(reader, max_nesting_depth - 1)

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        return not self.expression.match(engine)

    def to_json(self) -> dict:
        json = super(ConditionNot, self).to_json()
        json["expression"] = self.expression.to_json()
        return json

    @classmethod
    def _serializable_init(cls):
        return cls(ConditionBool(False))


class ConditionOr(WitnessCondition):
    _type = WitnessConditionType.OR

    def __init__(self, expressions: List[WitnessCondition]):
        self.expressions = expressions

    def __len__(self):
        return super(ConditionOr, self).__len__() + utils.get_var_size(self.expressions)

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return self.expressions == other.expressions

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable_list(self.expressions)

    def _deserialize_without_type(self, reader: serialization.BinaryReader, max_nesting_depth: int) -> None:
        if max_nesting_depth <= 0:
            raise ValueError("Max nesting depth cannot be negative")
        self.expressions = WitnessCondition._deserialize_conditions(reader, max_nesting_depth)
        if len(self.expressions) == 0:
            raise ValueError("Cannot have 0 expressions")

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        return any([condition.match(engine) for condition in self.expressions])

    def to_json(self) -> dict:
        json = super(ConditionOr, self).to_json()
        json['expressions'] = list(map(lambda exp: exp.to_json(), self.expressions))
        return json

    @classmethod
    def _serializable_init(cls):
        return cls([])


class ConditionCalledByContract(WitnessCondition):
    _type = WitnessConditionType.CALLED_BY_CONTRACT

    def __init__(self, hash_: types.UInt160):
        self.hash_ = hash_

    def __len__(self):
        return super(ConditionCalledByContract, self).__len__() + s.uint160

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable(self.hash_)

    def _deserialize_without_type(self, reader: serialization.BinaryReader, max_nesting_depth: int) -> None:
        self.hash_ = reader.read_serializable(types.UInt160)

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        return engine.calling_scripthash == self.hash_

    def to_json(self) -> dict:
        json = super(ConditionCalledByContract, self).to_json()
        json["hash"] = f"0x{self.hash_}"
        return json

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt160.zero())


class ConditionCalledByEntry(WitnessCondition):
    _type = WitnessConditionType.CALLED_BY_ENTRY

    def __eq__(self, other):
        if type(self) == type(other):
            return True
        return False

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        pass

    def _deserialize_without_type(self, reader: serialization.BinaryReader, max_nesting_depth: int) -> None:
        pass

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        return (len(engine.current_context.calling_scripthash_bytes) == 0
                or engine.calling_scripthash == engine.entry_scripthash)


class ConditionCalledByGroup(WitnessCondition):
    _type = WitnessConditionType.CALLED_BY_GROUP

    def __init__(self, group: cryptography.ECPoint):
        self.group = group

    def __len__(self):
        return super(ConditionCalledByGroup, self).__len__() + len(self.group)

    def __eq__(self, other):
        if type(self) != type(other):
            return False

        return self.group == other.group

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable(self.group)

    def _deserialize_without_type(self, reader: serialization.BinaryReader, max_nesting_depth: int) -> None:
        self.group = reader.read_serializable(cryptography.ECPoint)  # type: ignore

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        engine._validate_callflags(contracts.CallFlags.READ_STATES)
        contract = contracts.ManagementContract().get_contract(engine.snapshot, engine.calling_scripthash)
        return contract is not None and contract.manifest.contains_group(self.group)

    def to_json(self) -> dict:
        json = super(ConditionCalledByGroup, self).to_json()
        json["group"] = str(self.group)
        return json

    @classmethod
    def _serializable_init(cls):
        return cls(cryptography.ECPoint.deserialize_from_bytes(b'\x00'))


class ConditionGroup(ConditionCalledByGroup):
    _type = WitnessConditionType.GROUP

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        engine._validate_callflags(contracts.CallFlags.READ_STATES)
        contract = contracts.ManagementContract().get_contract(engine.snapshot, engine.current_scripthash)
        return contract is not None and contract.manifest.contains_group(self.group)


class ConditionScriptHash(ConditionCalledByContract):
    _type = WitnessConditionType.SCRIPT_HASH

    def match(self, engine: contracts.ApplicationEngine) -> bool:
        return engine.current_scripthash == self.hash_


class WitnessRule(serialization.ISerializable, IJson):
    def __init__(self, action: WitnessRuleAction, condition: WitnessCondition):
        self.action = action
        self.condition = condition

    def __len__(self):
        return s.uint8 + len(self.condition)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint8(self.action.value)
        writer.write_serializable(self.condition)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.action = WitnessRuleAction(reader.read_uint8())
        self.condition = WitnessCondition._deserialize_from(reader, WitnessCondition.MAX_NESTING_DEPTH)

    def to_json(self) -> dict:
        return {
            'action': self.action.name.title(),
            'condition': self.condition.to_json()
        }

    @classmethod
    def from_json(cls, json: dict):
        raise NotImplementedError()

    @classmethod
    def _serializable_init(cls):
        return cls(WitnessRuleAction.DENY, ConditionBool(False))


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
