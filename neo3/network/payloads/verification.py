"""
Classes for managing transaction signers and signature scopes.
"""
from __future__ import annotations
import hashlib
import abc
import base64
from enum import IntFlag, IntEnum
from neo3.core import serialization, utils, types, cryptography, Size as s, interfaces
from typing import Optional, Any, no_type_check, Iterator
from collections.abc import Sequence


class WitnessScope(IntFlag):
    """
    Flags that determine where in the system the signature is valid. Used by `CheckWitness()` sys call.
    """

    #: No Contract was witnessed. Only sign the transaction.
    NONE = 0x0
    #: Allow the witness if the current calling script hash equals the entry script hash into the virtual machine.
    #: Using this prevents passing `CheckWitness()` in a smart contract called via another smart contract.
    CALLED_BY_ENTRY = 0x01
    #: Allow the witness if called from a smart contract that is whitelisted in the signer `allowed_contracts`
    #: attribute.
    CUSTOM_CONTRACTS = 0x10
    #: Allow the witness if any public key is in the signer `allowed_groups` attribute is whitelisted in the contracts
    #: manifest.groups array.
    CUSTOM_GROUPS = 0x20
    #: Allow the witness if the specified `Signer.rules` are satisfied
    WITNESS_RULES = 0x40
    #: Allow the witness in all context. Equal to NEO 2.x's default behaviour.
    GLOBAL = 0x80

    @no_type_check
    def to_csharp_name(self) -> str:
        #: Internal helper to match C# convention.
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
        if self.WITNESS_RULES in self:
            flags.append("WitnessRules")
        return ", ".join(flags)

    @classmethod
    def from_chsarp_name(cls, csharp_name):
        #: Internal helper to parse from C# convention
        c = cls(cls.NONE)
        if "CalledByEntry" in csharp_name:
            c |= c.CALLED_BY_ENTRY
        if "CustomContracts" in csharp_name:
            c |= c.CUSTOM_CONTRACTS
        if "CustomGroups" in csharp_name:
            c |= c.CUSTOM_GROUPS
        if "Global" in csharp_name:
            c |= c.GLOBAL
        if "WitnessRules" in csharp_name:
            c |= c.WITNESS_RULES
        return c


class Signer(serialization.ISerializable, interfaces.IJson):
    """
    A class that specifies the rules of who can pass `CheckWitness()` verifications in a smart contract.
    """

    #: Maximum number of allowed_contracts or allowed_groups
    MAX_SUB_ITEMS = 16

    def __init__(
        self,
        account: types.UInt160,
        scope: WitnessScope = WitnessScope.CALLED_BY_ENTRY,
        allowed_contracts: Optional[Sequence[types.UInt160]] = None,
        allowed_groups: Optional[Sequence[cryptography.ECPoint]] = None,
        rules: Optional[Sequence[WitnessRule]] = None,
    ):
        #: The TX sender.
        self.account = account
        #: WitnessScope: The configured validation scope.
        self.scope = scope
        #: list[types.UInt160]: Whitelist of contract script hashes if used with `WitnessScope.CUSTOM_CONTRACTS`.
        self.allowed_contracts = allowed_contracts if allowed_contracts else []
        #: list[cryptography.ECPoint]: Whitelist of public keys if used with `WitnessScope.CUSTOM_GROUPS`.
        self.allowed_groups = allowed_groups if allowed_groups else []
        #: List of rules that must pass for the current execution context when used with `WitnessScope.WITNESS_RULES`.
        self.rules = rules if rules else []

    def __len__(self):
        contracts_size = 0
        if WitnessScope.CUSTOM_CONTRACTS in self.scope:
            contracts_size = utils.get_var_size(self.allowed_contracts)

        groups_size = 0
        if WitnessScope.CUSTOM_GROUPS in self.scope:
            groups_size = utils.get_var_size(self.allowed_groups)

        rules_size = 0
        if WitnessScope.WITNESS_RULES in self.scope:
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

        if WitnessScope.CUSTOM_CONTRACTS in self.scope:
            writer.write_serializable_list(self.allowed_contracts)

        if WitnessScope.CUSTOM_GROUPS in self.scope:
            writer.write_serializable_list(self.allowed_groups)

        if WitnessScope.WITNESS_RULES in self.scope:
            writer.write_serializable_list(self.rules)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.account = reader.read_serializable(types.UInt160)
        self.scope = WitnessScope(reader.read_uint8())

        if WitnessScope.GLOBAL in self.scope and self.scope != WitnessScope.GLOBAL:
            raise ValueError(
                "Deserialization error - invalid scope. GLOBAL scope not allowed with other scope types"
            )

        if WitnessScope.CUSTOM_CONTRACTS in self.scope:
            self.allowed_contracts = reader.read_serializable_list(
                types.UInt160, max=self.MAX_SUB_ITEMS
            )

        if WitnessScope.CUSTOM_GROUPS in self.scope:
            self.allowed_groups = reader.read_serializable_list(
                cryptography.ECPoint, max=self.MAX_SUB_ITEMS  # type: ignore
            )

        if WitnessScope.WITNESS_RULES in self.scope:
            self.rules = reader.read_serializable_list(
                WitnessRule, max=self.MAX_SUB_ITEMS
            )

    def get_all_rules(self) -> Iterator[WitnessRule]:
        """
        Return all witness rules.
        """
        if WitnessScope.GLOBAL in self.scope:
            yield WitnessRule(WitnessRuleAction.ALLOW, ConditionBool(True))
        else:
            if WitnessScope.CALLED_BY_ENTRY in self.scope:
                yield WitnessRule(WitnessRuleAction.ALLOW, ConditionCalledByEntry())

            if WitnessScope.CUSTOM_CONTRACTS in self.scope:
                for hash_ in self.allowed_contracts:
                    yield WitnessRule(
                        WitnessRuleAction.ALLOW, ConditionScriptHash(hash_)
                    )

            if WitnessScope.CUSTOM_GROUPS in self.scope:
                for group in self.allowed_groups:
                    yield WitnessRule(WitnessRuleAction.ALLOW, ConditionGroup(group))

            if WitnessScope.WITNESS_RULES in self.scope:
                for rule in self.rules:
                    yield rule

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        json: dict[str, Any] = {
            "account": "0x" + str(self.account),
            "scopes": self.scope.to_csharp_name(),
        }

        if WitnessScope.CUSTOM_CONTRACTS in self.scope:
            json.update(
                {
                    "allowedcontracts": list(
                        map(lambda a: "0x" + str(a), self.allowed_contracts)
                    )
                }
            )
        if WitnessScope.CUSTOM_GROUPS in self.scope:
            json.update(
                {"allowedgroups": list(map(lambda g: str(g), self.allowed_groups))}
            )
        if WitnessScope.WITNESS_RULES in self.scope:
            json.update({"rules": list(map(lambda r: r.to_json(), self.rules))})

        return json

    @classmethod
    def from_json(cls, json: dict):
        """Create object from JSON."""
        account = types.UInt160.from_string(json["account"][2:])
        scopes = WitnessScope.from_chsarp_name(json["scopes"])

        allowed_contracts = []
        if "allowedcontracts" in json:
            for contract in json["allowedcontracts"]:
                allowed_contracts.append(types.UInt160.from_string(contract[2:]))

        allowed_groups = []
        if "allowedgroups" in json:
            for group in json["allowedgroups"]:
                allowed_groups.append(
                    cryptography.ECPoint.deserialize_from_bytes(bytes.fromhex(group))
                )

        rules = []
        if "rules" in json:
            for rule in json["rules"]:
                rules.append(WitnessRule.from_json(rule))

        return cls(account, scopes, allowed_contracts, allowed_groups, rules)

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt160.zero())


class Witness(serialization.ISerializable, interfaces.IJson):
    """
    An executable verification script that validates a verifiable object like a transaction.
    """

    _MAX_INVOCATION_SCRIPT = 1024
    _MAX_VERIFICATION_SCRIPT = 1024

    def __init__(self, invocation_script: bytes, verification_script: bytes):
        #: A set of VM instructions to set up the stack for verification.
        self.invocation_script = invocation_script
        #: A set of VM instructions that does the actual verification.
        #: It is expected to set the result stack to a boolean True if validation passed.
        self.verification_script = verification_script
        self._script_hash = None

    def __len__(self):
        return utils.get_var_size(self.invocation_script) + utils.get_var_size(
            self.verification_script
        )

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
        self.verification_script = reader.read_var_bytes(
            max=self._MAX_VERIFICATION_SCRIPT
        )

    def script_hash(self) -> types.UInt160:
        """Get the script hash based on the verification script."""
        intermediate_data = hashlib.sha256(self.verification_script).digest()
        data = hashlib.new("ripemd160", intermediate_data).digest()
        return types.UInt160(data=data)

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        return {
            "invocation": base64.b64encode(self.invocation_script).decode(),
            "verification": base64.b64encode(self.verification_script).decode(),
        }

    @classmethod
    def from_json(cls, json: dict):
        """Create object from JSON"""
        return cls(
            base64.b64decode(json["invocation"]), base64.b64decode(json["verification"])
        )

    @classmethod
    def _serializable_init(cls):
        return cls(b"", b"")


class WitnessRuleAction(IntEnum):
    """
    Witness rule execution.
    """

    DENY = 0
    ALLOW = 1


class WitnessConditionType(IntEnum):
    """
    Type of valid witness conditions.
    """

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

    @classmethod
    def from_csharp_string(cls, name: str):
        match name:
            case "ScriptHash":
                return WitnessConditionType.SCRIPT_HASH
            case "CalledByEntry":
                return WitnessConditionType.CALLED_BY_ENTRY
            case "CalledByContract":
                return WitnessConditionType.CALLED_BY_CONTRACT
            case "CalledByGroup":
                return WitnessConditionType.CALLED_BY_GROUP
            case _:
                _name = name.upper()
                for k, v in cls.__members__.items():
                    if k == _name:
                        return v
                else:
                    raise ValueError(f"{name} cannot be converted to {cls.__name__}")


class WitnessCondition(serialization.ISerializable, interfaces.IJson):
    """
    Base class for conditions.
    """

    MAX_SUB_ITEMS = 16
    MAX_NESTING_DEPTH = 2

    _type = WitnessConditionType.BOOLEAN

    def __len__(self):
        return s.uint8  # 1 byte witness condition

    @property
    def type(self) -> WitnessConditionType:
        return self._type

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
    def _deserialize_without_type(
        self, reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> None:
        """Deserialize from a buffer without reading the `type` member."""

    @staticmethod
    def _deserialize_conditions(
        reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> list[WitnessCondition]:
        conditions = []
        for _ in range(reader.read_var_int(WitnessCondition.MAX_SUB_ITEMS)):
            conditions.append(
                WitnessCondition._deserialize_from(reader, max_nesting_depth)
            )
        return conditions

    @staticmethod
    def _deserialize_from(
        reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> WitnessCondition:
        condition_type = reader.read_uint8()

        def find_condition(condition) -> Optional[WitnessCondition]:
            for sub in condition.__subclasses__():
                child = sub._serializable_init()
                if child.type.value == condition_type:
                    child._deserialize_without_type(reader, max_nesting_depth)
                    return child
                if len(sub.__subclasses__()) > 0:
                    condition = find_condition(sub)
                    if condition is not None:
                        return condition
            return None

        condition = find_condition(WitnessCondition)
        if condition is None:
            raise ValueError(
                f"Deserialization error - unknown witness condition. Type: {hex(condition_type)}"
            )
        else:
            return condition

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        return {"type": self.type.to_csharp_string()}

    @classmethod
    def from_json(cls, json: dict):
        """Create object from JSON"""
        condition_type = WitnessConditionType.from_csharp_string(json["type"])
        for sub in WitnessCondition.__subclasses__():
            child = sub._serializable_init()  # type: ignore
            if child.type == condition_type:
                return child.from_json(json)


class ConditionAnd(WitnessCondition):
    """
    Match all conditions.
    """

    _type = WitnessConditionType.AND

    def __init__(self, expressions: list[WitnessCondition]):
        self.expressions = expressions

    def __len__(self):
        return super(ConditionAnd, self).__len__() + utils.get_var_size(
            self.expressions
        )

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return self.expressions == other.expressions

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable_list(self.expressions)

    def _deserialize_without_type(
        self, reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> None:
        if max_nesting_depth <= 0:
            raise ValueError("Max nesting depth cannot be negative")
        self.expressions = WitnessCondition._deserialize_conditions(
            reader, max_nesting_depth
        )
        if len(self.expressions) == 0:
            raise ValueError("Cannot have 0 expressions")

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        json = super(ConditionAnd, self).to_json()
        json["expressions"] = list(map(lambda exp: exp.to_json(), self.expressions))
        return json

    @classmethod
    def from_json(cls, json: dict):
        return cls(
            list(
                map(lambda expr: WitnessCondition.from_json(expr), json["expressions"])
            )
        )

    @classmethod
    def _serializable_init(cls):
        return cls([])


class ConditionBool(WitnessCondition):
    """
    Fixed value. Can be used to emulate GLOBAL scope.
    """

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

    def _deserialize_without_type(
        self, reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> None:
        self.value = reader.read_bool()

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        json = super(ConditionBool, self).to_json()
        json["expression"] = self.value
        return json

    @classmethod
    def from_json(cls, json: dict):
        return cls(json["expression"])

    @classmethod
    def _serializable_init(cls):
        return cls(False)


class ConditionNot(WitnessCondition):
    """
    Invert condition.
    """

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

    def _deserialize_without_type(
        self, reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> None:
        if max_nesting_depth <= 0:
            raise ValueError("Max nesting depth cannot be negative")
        self.expression = WitnessCondition._deserialize_from(
            reader, max_nesting_depth - 1
        )

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        json = super(ConditionNot, self).to_json()
        json["expression"] = self.expression.to_json()
        return json

    @classmethod
    def from_json(cls, json: dict):
        return cls(WitnessCondition.from_json(json["expression"]))

    @classmethod
    def _serializable_init(cls):
        return cls(ConditionBool(False))


class ConditionOr(WitnessCondition):
    """
    Match any from a list of conditions.
    """

    _type = WitnessConditionType.OR

    def __init__(self, expressions: list[WitnessCondition]):
        self.expressions = expressions

    def __len__(self):
        return super(ConditionOr, self).__len__() + utils.get_var_size(self.expressions)

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return self.expressions == other.expressions

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable_list(self.expressions)

    def _deserialize_without_type(
        self, reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> None:
        if max_nesting_depth <= 0:
            raise ValueError("Max nesting depth cannot be negative")
        self.expressions = WitnessCondition._deserialize_conditions(
            reader, max_nesting_depth
        )
        if len(self.expressions) == 0:
            raise ValueError("Cannot have 0 expressions")

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        json = super(ConditionOr, self).to_json()
        json["expressions"] = list(map(lambda exp: exp.to_json(), self.expressions))
        return json

    @classmethod
    def from_json(cls, json: dict):
        return cls(
            list(
                map(lambda expr: WitnessCondition.from_json(expr), json["expressions"])
            )
        )

    @classmethod
    def _serializable_init(cls):
        return cls([])


class ConditionCalledByContract(WitnessCondition):
    """
    Match hash against caller script hash.
    """

    _type = WitnessConditionType.CALLED_BY_CONTRACT

    def __init__(self, hash_: types.UInt160):
        self.hash_ = hash_

    def __len__(self):
        return super(ConditionCalledByContract, self).__len__() + s.uint160

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return self.hash_ == other.hash_

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable(self.hash_)

    def _deserialize_without_type(
        self, reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> None:
        self.hash_ = reader.read_serializable(types.UInt160)

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        json = super(ConditionCalledByContract, self).to_json()
        json["hash"] = f"0x{self.hash_}"
        return json

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt160.zero())

    @classmethod
    def from_json(cls, json: dict):
        return cls(types.UInt160.from_string(json["hash"]))


class ConditionCalledByEntry(WitnessCondition):
    """
    Match hash against entry script hash.
    """

    _type = WitnessConditionType.CALLED_BY_ENTRY

    def __eq__(self, other):
        if type(self) == type(other):
            return True
        return False

    @classmethod
    def from_json(cls, json: dict):
        return cls()

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        pass

    def _deserialize_without_type(
        self, reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> None:
        pass


class ConditionCalledByGroup(WitnessCondition):
    """
    Match key against the caller group.
    """

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

    def _deserialize_without_type(
        self, reader: serialization.BinaryReader, max_nesting_depth: int
    ) -> None:
        self.group = reader.read_serializable(cryptography.ECPoint)  # type: ignore

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        json = super(ConditionCalledByGroup, self).to_json()
        json["group"] = str(self.group)
        return json

    @classmethod
    def from_json(cls, json: dict):
        return cls(
            cryptography.ECPoint.deserialize_from_bytes(bytes.fromhex(json["group"]))
        )

    @classmethod
    def _serializable_init(cls):
        return cls(cryptography.ECPoint.deserialize_from_bytes(b"\x00"))


class ConditionGroup(ConditionCalledByGroup):
    """
    Match group against current script hash.
    """

    _type = WitnessConditionType.GROUP


class ConditionScriptHash(ConditionCalledByContract):
    """
    Match hash against another script hash.
    """

    _type = WitnessConditionType.SCRIPT_HASH


class WitnessRule(serialization.ISerializable, interfaces.IJson):
    """
    A firewall like rule with an action to deny or allow if the condition matches. Gives fine-grained control over
    where the signature of the witness is valid inside the system.
    """

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
        self.condition = WitnessCondition._deserialize_from(
            reader, WitnessCondition.MAX_NESTING_DEPTH
        )

    def to_json(self) -> dict:
        """Convert object into JSON representation."""
        return {
            "action": self.action.name.title(),
            "condition": self.condition.to_json(),
        }

    @classmethod
    def from_json(cls, json: dict):
        """Create object from JSON."""
        action = WitnessRuleAction.DENY
        if json["action"] == "Allow":
            action = WitnessRuleAction.ALLOW
        condition = WitnessCondition.from_json(json["condition"])
        return cls(action, condition)

    @classmethod
    def _serializable_init(cls):
        return cls(WitnessRuleAction.DENY, ConditionBool(False))


class IVerifiable(serialization.ISerializable):
    """
    Verifiable interface.
    """

    def __init__(self, *args, **kwargs):
        super(IVerifiable, self).__init__(*args, **kwargs)
        self.witnesses: list[Witness] = []

    @abc.abstractmethod
    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        """ """

    @abc.abstractmethod
    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        """ """

    @abc.abstractmethod
    def get_script_hashes_for_verifying(self, snapshot) -> list[types.UInt160]:
        """
        Helper method to get the data used in verifying the object.
        """

    def get_hash_data(self, protocol_magic: int) -> bytes:
        """Get the unsigned data.

        Args:
            protocol_magic: network protocol number (NEO MainNet = 860833102, Testnet (T5) = 894710606, private net = ?)
        """
        with serialization.BinaryWriter() as writer:
            writer.write_uint32(protocol_magic)
            self.serialize_unsigned(writer)
            return writer.to_array()
