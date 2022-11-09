from __future__ import annotations
from enum import IntEnum
from neo3.core import Size as s, serialization
from typing import TypeVar

ConsensusMessage_t = TypeVar("ConsensusMessage_t", bound="ConsensusMessage")


class ConsensusMessageType(IntEnum):
    CHANGE_VIEW = 0x00
    PREPARE_REQUEST = 0x20
    PREPARE_RESPONSE = 0x21
    COMMIT = 0x30
    RECOVERY_REQUEST = 0x40
    RECOVERY_MESSAGE = 0x41


class ConsensusMessage(serialization.ISerializable):
    """
    Base class for the various consensus messages
    """

    def __init__(self, type: ConsensusMessageType):
        self.type = type
        self.view_number: int = 0

    def __len__(self):
        return s.uint8 + s.uint8

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_uint8(self.type)
        writer.write_uint8(self.view_number)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.type = ConsensusMessageType(reader.read_uint8())
        self.view_number = reader.read_uint8()

    @classmethod
    def _serializable_init(cls):
        return cls(ConsensusMessageType.CHANGE_VIEW)
