"""
Heartbeat payload with chain height information.
"""
from __future__ import annotations
from datetime import datetime
from random import randint
from neo3.core import Size as s, serialization


class PingPayload(serialization.ISerializable):
    def __init__(self, height: int = 0) -> None:
        #: The current local chain height
        self.current_height = height
        #: The local time in UTC as a timestamp
        self.timestamp = int(datetime.utcnow().timestamp())
        #: Random number
        self.nonce = randint(100, 10000)

    def __len__(self) -> int:
        """Get the total size in bytes of the object."""
        return s.uint32 + s.uint32 + s.uint32

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_uint32(self.current_height)
        writer.write_uint32(self.timestamp)
        writer.write_uint32(self.nonce)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.current_height = reader.read_uint32()
        self.timestamp = reader.read_uint32()
        self.nonce = reader.read_uint32()
