from __future__ import annotations
import abc
import hashlib
from typing import TypeVar, Type
from neo3 import vm
from enum import IntEnum
from events import Events  # type: ignore
from neo3.core import types, jsonpath


msgrouter = Events()

# :noindex:


class Size(IntEnum):
    """
    Explicit bytes of memory consumed
    """
    uint8 = 1
    uint16 = 2
    uint32 = 4
    uint64 = 8
    uint160 = 20
    uint256 = 32


class IClonable(abc.ABC):
    @abc.abstractmethod
    def clone(self):
        """
        Create a deep copy of self
        """

    def from_replica(self, replica):
        """ shallow copy from a replica object """


class IJson(abc.ABC):
    @abc.abstractmethod
    def to_json(self) -> dict:
        """ convert object into json """

    @classmethod
    @abc.abstractmethod
    def from_json(cls, json: dict):
        """ create object from JSON """


T = TypeVar('T', bound='IInteroperable')


class IInteroperable(abc.ABC):
    @abc.abstractmethod
    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        """ Convert object to a virtual machine stack item"""

    @classmethod
    def from_stack_item(cls: Type[T], stack_item: vm.StackItem) -> T:
        """ Convert a stack item into an object"""
        raise ValueError(f"{cls.__class__.__name__} cannot be converted to a stack item")


def to_script_hash(data: bytes) -> types.UInt160:
    """
    Create a script hash based on the input data.

    Args:
        data: data to hash
    """
    intermediate_data = hashlib.sha256(data).digest()
    data_ = hashlib.new('ripemd160', intermediate_data).digest()
    return types.UInt160(data_)


def syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)
