"""
NEP-14 Application Binary Interface classes.
"""
from __future__ import annotations
from typing import Optional
from collections.abc import Sequence
from enum import IntEnum
from neo3.core import interfaces
from neo3.contracts import utils as contractutils


class ContractParameterType(IntEnum):
    """
    Type information for a contract method parameter.
    """

    ANY = 0x00
    BOOLEAN = 0x10
    INTEGER = 0x11
    BYTEARRAY = 0x12
    STRING = 0x13
    HASH160 = 0x14
    HASH256 = 0x15
    PUBLICKEY = 0x16
    SIGNATURE = 0x17
    ARRAY = 0x20
    MAP = 0x22
    INTEROPINTERFACE = 0x30
    VOID = 0xFF

    def PascalCase(self) -> str:
        if self == ContractParameterType.BYTEARRAY:
            return "ByteArray"
        elif self == ContractParameterType.INTEROPINTERFACE:
            return "InteropInterface"
        elif self == ContractParameterType.PUBLICKEY:
            return "PublicKey"
        else:
            return self.name.title()


class ContractParameterDefinition(interfaces.IJson):
    """
    A parameter description for a contract Method or Event.
    """

    def __init__(self, name: str, type: ContractParameterType):
        """
        Args:
            name: the human-readable identifier.
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
        json = {"name": self.name, "type": self.type.PascalCase()}
        return json

    @classmethod
    def from_json(cls, json: dict) -> ContractParameterDefinition:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if the manifest name property has an incorrect format.
            ValueError: if the type is VOID.
        """
        c = cls(
            name=contractutils.validate_type(json["name"], str),
            type=ContractParameterType[
                contractutils.validate_type(json["type"], str).upper()
            ],
        )
        if c.name is None or len(c.name) == 0:
            raise ValueError("Format error - invalid 'name'")
        if c.type == ContractParameterType.VOID:
            raise ValueError("Format error - parameter type VOID is not allowed")
        return c


class ContractEventDescriptor(interfaces.IJson):
    """
    A description for an event that a contract can broadcast.
    """

    def __init__(self, name: str, parameters: Sequence[ContractParameterDefinition]):
        """

        Args:
            name: the human-readable identifier of the event.
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
            "parameters": list(map(lambda p: p.to_json(), self.parameters)),
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
            ValueError: if the `name` property has an incorrect format.
        """
        c = cls(
            name=contractutils.validate_type(json["name"], str),
            parameters=list(
                map(
                    lambda p: ContractParameterDefinition.from_json(p),
                    json["parameters"],
                )
            ),
        )
        if c.name is None or len(c.name) == 0:
            raise ValueError("Format error - invalid 'name'")
        return c


class ContractMethodDescriptor(ContractEventDescriptor, interfaces.IJson):
    """
    A description of a callable method on a contract.
    """

    def __init__(
        self,
        name: str,
        offset: int,
        parameters: Sequence[ContractParameterDefinition],
        return_type: ContractParameterType,
        safe: bool,
    ):
        """
        Args:
            name: the human-readable identifier of the method.
            offset: script offset.
            parameters: the list of parameters the method takes.
            return_type: the type of the returned value.
        """
        super(ContractMethodDescriptor, self).__init__(name, parameters)
        self.offset = offset
        self.return_type = return_type
        self.safe = safe

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (
            self.name == other.name
            and self.parameters == other.parameters
            and self.offset == other.offset
            and self.return_type == other.return_type
            and self.safe == other.safe
        )

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = super(ContractMethodDescriptor, self).to_json()
        json.update(
            {
                "returntype": self.return_type.PascalCase(),
                "offset": self.offset,
                "safe": self.safe,
            }
        )
        return json

    @classmethod
    def from_json(cls, json: dict) -> ContractMethodDescriptor:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if the manifest name property has an incorrect format.
            ValueError: if the offset is negative.
        """
        c = cls(
            name=contractutils.validate_type(json["name"], str),
            offset=contractutils.validate_type(json["offset"], int),
            parameters=list(
                map(
                    lambda p: ContractParameterDefinition.from_json(p),
                    json["parameters"],
                )
            ),
            return_type=ContractParameterType[
                contractutils.validate_type(json["returntype"], str).upper()
            ],
            safe=contractutils.validate_type(json["safe"], bool),
        )
        if c.name is None or len(c.name) == 0:
            raise ValueError("Format error - invalid 'name'")
        if c.offset < 0:
            raise ValueError("Format error - negative offset not allowed")
        return c

    def __repr__(self):
        return f"<{self.__class__.__name__} at {hex(id(self))}> {self.name}"


class ContractABI(interfaces.IJson):
    """
    The smart contract application binary interface describes the callable events and contracts for a given
     smart contract.
    """

    def __init__(
        self,
        methods: Sequence[ContractMethodDescriptor],
        events: Sequence[ContractEventDescriptor],
    ):
        """
        Args:
            methods: the available methods in the contract.
            events: the various events that can be broadcast by the contract.
        """
        self.methods = methods
        self.events = events

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.methods == other.methods and self.events == other.events

    def get_method(
        self, name, parameter_count: int
    ) -> Optional[ContractMethodDescriptor]:
        """
        Return the ContractMethodDescriptor matching the name (and optional parameter count) or `None` otherwise.

        Args:
            name: the name of the method to return.
            parameter_count: the expected number of parameters teh method has.
        """
        if parameter_count < -1 or parameter_count > 0xFFFF:
            raise ValueError("Parameter count is out of range")

        if parameter_count >= 0:
            for m in self.methods:
                if m.name == name and len(m.parameters) == parameter_count:
                    return m
            else:
                return None
        else:
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
            "methods": list(map(lambda m: m.to_json(), self.methods)),
            "events": list(map(lambda e: e.to_json(), self.events)),
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
            ValueError: if the contract has no methods.
        """
        c = cls(
            methods=list(
                map(lambda m: ContractMethodDescriptor.from_json(m), json["methods"])
            ),
            events=list(
                map(lambda e: ContractEventDescriptor.from_json(e), json["events"])
            ),
        )
        if len(c.methods) == 0:
            raise ValueError("Invalid contract - contract has no methods")
        return c
