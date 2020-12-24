from __future__ import annotations
from typing import cast
from enum import IntFlag
from neo3 import vm
from neo3.core import serialization, utils, IClonable, IInteroperable, Size as s
from neo3.core.serialization import BinaryReader, BinaryWriter


class StorageFlags(IntFlag):
    NONE = 0
    CONSTANT = 0x1


class StorageItem(serialization.ISerializable, IClonable):
    def __init__(self, value: bytes, is_constant=False):
        self.value = value
        self.is_constant = is_constant

    def __len__(self):
        return utils.get_var_size(self.value) + s.uint8

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.value == other.value

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_var_bytes(self.value)
        writer.write_bool(self.is_constant)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.value = reader.read_var_bytes()
        self.is_constant = reader.read_bool()

    def clone(self) -> StorageItem:
        return StorageItem(self.value, self.is_constant)

    def from_replica(self, replica: StorageItem) -> None:
        self.value = replica.value
        self.is_constant = replica.is_constant

    @classmethod
    def _serializable_init(cls):
        return cls(b'')


class Nep5StorageState(IInteroperable, serialization.ISerializable):
    """
    Helper class for NEP5 balance state

    Use the from_storage() method if you're working with a DB snapshot and intend to modify the state values.
    It will ensure that the cache is updated automatically.
    """

    def __init__(self):
        super(Nep5StorageState, self).__init__()
        self._balance: vm.BigInteger = vm.BigInteger.zero()
        self._storage_item = StorageItem(b'')

    def __len__(self):
        return len(self._balance.to_array())

    @classmethod
    def from_storage(cls, storage_item: StorageItem):
        state = cls()
        state._storage_item = storage_item
        with serialization.BinaryReader(storage_item.value) as reader:
            state.deserialize(reader)
        return state

    @property
    def balance(self) -> vm.BigInteger:
        return self._balance

    @balance.setter
    def balance(self, value: vm.BigInteger) -> None:
        self._balance = value
        self._storage_item.value = self.to_array()

    def serialize(self, writer: BinaryWriter) -> None:
        writer.write_var_bytes(self._balance.to_array())

    def deserialize(self, reader: BinaryReader) -> None:
        self._balance = vm.BigInteger(reader.read_var_bytes())

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        s = vm.StructStackItem(reference_counter)
        s.append(vm.IntegerStackItem(self._balance))
        return s

    def from_stack_item(self, stack_item: vm.StackItem) -> None:
        si = cast(vm.StructStackItem, stack_item)
        self._balance = si[0].to_biginteger()
