from __future__ import annotations
from neo3.core import serialization, utils, Size as s, cryptography as crypto


class FilterAddPayload(serialization.ISerializable):
    def __init__(self, data: bytes):
        """
        Create payload.

        Args:
            data: the data to add to the configured bloomfilter.

        """
        self.data = data

    def __len__(self):
        return utils.get_var_size(self.data)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_var_bytes(self.data)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.data = reader.read_var_bytes(520)

    @classmethod
    def _serializable_init(cls):
        return cls(b'')


class FilterLoadPayload(serialization.ISerializable):
    def __init__(self, filter: crypto.BloomFilter):
        """
        Create payload.

        Args:
            filter: bloom filter to load
        """
        self.filter = filter.get_bits()
        self.K = filter.K
        self.tweak = filter.tweak

    def __len__(self):
        return utils.get_var_size(self.filter) + s.uint8 + s.uint32

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_var_bytes(self.filter)
        writer.write_uint8(self.K)
        writer.write_uint32(self.tweak)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.filter = reader.read_var_bytes(max=36000)
        self.K = reader.read_uint8()
        if self.K > 50:
            raise ValueError("Deserialization error - K exceeds limit of 50")
        self.tweak = reader.read_uint32()

    @classmethod
    def _serializable_init(cls):
        bf = crypto.BloomFilter(8, 2, 345)
        return cls(bf)
