from __future__ import annotations
from typing import Type, Optional
from neo3.core import serialization, utils, IClonable, Size as s


class StorageItem(serialization.ISerializable, IClonable):
    def __init__(self, value: bytes):
        self._value = value
        self._cache: Optional[serialization.ISerializable] = None

    def __len__(self):
        return utils.get_var_size(self.value)

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
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_bytes(self.value)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        remaining_stream_size = len(reader) - reader._stream.tell()
        self.value = reader.read_bytes(remaining_stream_size)

    def clone(self) -> StorageItem:
        """ Deep clone """
        return StorageItem(self.value)

    def from_replica(self, replica: StorageItem) -> None:
        """ Copy instance variables from other instance """
        self.value = replica.value

    def get(self, type_: Type[serialization.ISerializable]):
        """ Transform the data into `type` and cache the value """
        if self._cache and type(self._cache) == type_:
            return self._cache

        t = type_._serializable_init()
        self._cache = t.deserialize_from_bytes(self.value)
        return self._cache

    @classmethod
    def _serializable_init(cls):
        return cls(b'')
