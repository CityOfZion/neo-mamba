from __future__ import annotations
from typing import Type, Optional
from enum import IntFlag
from neo3.core import serialization, utils, IClonable, Size as s


class StorageFlags(IntFlag):
    NONE = 0
    CONSTANT = 0x1


class StorageItem(serialization.ISerializable, IClonable):
    def __init__(self, value: bytes, is_constant=False):
        self._value = value
        self.is_constant = is_constant
        self._cache: Optional[serialization.ISerializable] = None

    def __len__(self):
        return utils.get_var_size(self.value) + s.uint8

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.value == other.value

    @property
    def value(self) -> bytes:
        if self._cache:
            return self._cache.to_array()
        return self._value

    @value.setter
    def value(self, new_value: bytes) -> None:
        self._value = new_value
        self._cache = None

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

    def get(self, type_: Type[serialization.ISerializable]):
        if self._cache and type(self._cache) == type_:
            return self._cache

        t = type_._serializable_init()
        self._cache = t.deserialize_from_bytes(self.value)
        return self._cache

    @classmethod
    def _serializable_init(cls):
        return cls(b'')
