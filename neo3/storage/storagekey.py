import mmh3  # type: ignore
from neo3.core import serialization, types, Size as s, utils


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

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_int32(self.id)
        writer.write_var_bytes(self.key)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.id = reader.read_int32()
        self.key = reader.read_var_bytes()

    @classmethod
    def _serializable_init(cls):
        return cls(0, b'')
