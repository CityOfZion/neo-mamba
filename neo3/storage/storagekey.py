import mmh3  # type: ignore
from neo3.core import serialization, types, Size as s, utils
from neo3 import vm


class StorageKey(serialization.ISerializable):
    def __init__(self, id_: int, key: bytes):
        self.id = id_
        self.key = key

    def __len__(self):
        return s.uint32 + len(self.key)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.id == other.id and self.key == other.key

    def __hash__(self):
        return hash(self.id) + mmh3.hash(self.key, seed=0, signed=False)

    def __repr__(self):
        return f"<{self.__class__.__name__} at {hex(id(self))}> [{self.id}] {self.key}"

    def __add__(self, other):
        if type(other) in [bytes, bytearray]:
            return StorageKey(self.id, self.key + other)
        if isinstance(other, (serialization.ISerializable, vm.BigInteger)):
            return StorageKey(self.id, self.key + other.to_array())
        else:
            return NotImplemented

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_int32(self.id)
        writer.write_bytes(self.key)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.id = reader.read_int32()
        remaining_stream_size = len(reader) - reader._stream.tell()
        self.key = reader.read_bytes(remaining_stream_size)

    @classmethod
    def _serializable_init(cls):
        return cls(0, b'')
