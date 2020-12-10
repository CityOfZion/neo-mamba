from __future__ import annotations
import enum
from typing import List, Optional, Type
from enum import IntEnum
from neo3.core import types, IJson, IInteroperable, serialization
from neo3 import contracts, vm


class ContractParameterType(IntEnum):
    ANY = 0x00,
    BOOLEAN = 0x10,
    INTEGER = 0x11,
    BYTEARRAY = 0x12,
    STRING = 0x13,
    HASH160 = 0x14,
    HASH256 = 0x15,
    PUBLICKEY = 0x16,
    SIGNATURE = 0x17,
    ARRAY = 0x20,
    MAP = 0x22,
    INTEROP_INTERFACE = 0x30,
    VOID = 0xff

    def PascalCase(self) -> str:
        if self == ContractParameterType.BYTEARRAY:
            return "ByteArray"
        elif self == ContractParameterType.INTEROP_INTERFACE:
            return "InteropInterface"
        elif self == ContractParameterType.PUBLICKEY:
            return "PublicKey"
        else:
            return self.name.title()

    @classmethod
    def from_type(cls, class_type: Type[object]) -> ContractParameterType:
        if class_type is None:
            return ContractParameterType.VOID
        elif class_type in [bool, vm.BooleanStackItem]:
            return ContractParameterType.BOOLEAN
        elif class_type in [int, vm.BigInteger]:
            return ContractParameterType.INTEGER
        elif class_type in [bytes, bytearray, vm.BufferStackItem, vm.ByteStringStackItem]:
            return ContractParameterType.BYTEARRAY
        elif issubclass(class_type, serialization.ISerializable):
            return ContractParameterType.BYTEARRAY
        elif class_type == str:
            return ContractParameterType.STRING
        elif class_type == vm.MapStackItem:
            return ContractParameterType.MAP
        elif class_type in [vm.ArrayStackItem, vm.StructStackItem, list]:
            return ContractParameterType.ARRAY
        elif issubclass(class_type, IInteroperable):
            return ContractParameterType.ARRAY
        elif issubclass(class_type, enum.Enum):
            return ContractParameterType.INTEGER
        else:
            return ContractParameterType.ANY


class ContractParameterDefinition(IJson):
    """
    A parameter description for a contract Method or Event.
    """
    def __init__(self, name: str, type: contracts.ContractParameterType):
        """
        Args:
            name: the human readable identifier.
            type: the type of parameter.
        """
        self.name = name
        self.type = type

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.name == other.name and self.type == other.type

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = {
            "name": self.name,
            "type": self.type.PascalCase()
        }
        return json

    @classmethod
    def from_json(cls, json: dict) -> ContractParameterDefinition:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
        """
        return cls(
            name=json['name'],
            type=contracts.ContractParameterType[json['type'].upper()]
        )


class ContractEventDescriptor(IJson):
    """
    A description for an event that a contract can broadcast.
    """
    def __init__(self, name: str, parameters: List[ContractParameterDefinition]):
        """

        Args:
            name: the human readable identifier of the event.
            parameters: the list of parameters the event takes.
        """
        self.name = name
        self.parameters = parameters

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.name == other.name and self.parameters == other.parameters

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = {
            "name": self.name,
            "parameters": list(map(lambda p: p.to_json(), self.parameters))
        }
        return json

    @classmethod
    def from_json(cls, json: dict) -> ContractEventDescriptor:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
        """
        return cls(
            name=json['name'],
            parameters=list(map(lambda p: ContractParameterDefinition.from_json(p), json['parameters']))
        )


class ContractMethodDescriptor(ContractEventDescriptor, IJson):
    """
    A description of a callable method on a contract.
    """
    def __init__(self, name: str,
                 offset: int,
                 parameters: List[ContractParameterDefinition],
                 return_type: contracts.ContractParameterType):
        """
        Args:
            name: the human readable identifier of the method.
            offset: script offset
            parameters: the list of parameters the method takes.
            return_type: the type of the returned value.
        """
        super(ContractMethodDescriptor, self).__init__(name, parameters)
        self.offset = offset
        self.return_type = return_type

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (self.name == other.name
                and self.parameters == other.parameters
                and self.offset == other.offset
                and self.return_type == other.return_type)

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = super(ContractMethodDescriptor, self).to_json()
        json.update({
            "offset": self.offset,
            "returntype": self.return_type.PascalCase()
        })
        return json

    @classmethod
    def from_json(cls, json: dict) -> ContractMethodDescriptor:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
        """
        return cls(
            name=json['name'],
            offset=json['offset'],
            parameters=list(map(lambda p: contracts.ContractParameterDefinition.from_json(p), json['parameters'])),
            return_type=contracts.ContractParameterType[json['returntype'].upper()]
        )

    def __repr__(self):
        return f"<{self.__class__.__name__} at {hex(id(self))}> {self.name}"


class ContractABI(IJson):
    """
    The smart contract application binary interface describes the callable events and contracts for a given
    smart contract.
    """
    def __init__(self,
                 contract_hash: types.UInt160,
                 methods: List[contracts.ContractMethodDescriptor],
                 events: List[contracts.ContractEventDescriptor]):
        """

        Args:
            contract_hash: the result of performing RIPEMD160(SHA256(vm_script)), where vm_script is the smart contract
            byte code.
            methods: the available methods in the contract.
            events: the various events that can be broad casted by the contract.
        """
        self.contract_hash = contract_hash
        self.methods = methods
        self.events = events

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (self.contract_hash == other.contract_hash
                and self.methods == other.methods
                and self.events == other.events)

    def get_method(self, name) -> Optional[contracts.ContractMethodDescriptor]:
        """
        Return the ContractMethodDescriptor matching the name or None otherwise.

        Args:
            name: the name of the method to return.
        """
        for m in self.methods:
            if m.name == name:
                return m
        else:
            return None

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = {
            "hash": '0x' + str(self.contract_hash),
            "methods": list(map(lambda m: m.to_json(), self.methods)),
            "events": list(map(lambda e: e.to_json(), self.events))
        }
        return json

    @classmethod
    def from_json(cls, json: dict) -> ContractABI:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
        """
        return cls(
            contract_hash=types.UInt160.from_string(json['hash'][2:]),
            methods=list(map(lambda m: contracts.ContractMethodDescriptor.from_json(m), json['methods'])),
            events=list(map(lambda e: contracts.ContractEventDescriptor.from_json(e), json['events'])),
        )
