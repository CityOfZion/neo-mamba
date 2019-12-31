from neo3.core import serialization
from neo3.core.serialization import BinaryReader, BinaryWriter


class SerializableObject(serialization.ISerializable):
    def serialize(self, writer: BinaryWriter) -> None:
        pass

    def deserialize(self, reader: BinaryReader) -> None:
        pass

    def __len__(self):
        return 0