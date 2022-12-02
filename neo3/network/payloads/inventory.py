from __future__ import annotations
import abc
from enum import IntEnum
from neo3.core import types, Size as s, utils, serialization
from neo3.network.payloads import verification
from collections.abc import Sequence


class InventoryType(IntEnum):
    TX = 0x2B
    BLOCK = 0x2C
    CONSENSUS = 0x2D
    EXTENSIBLE = 0x2E


class InventoryPayload(serialization.ISerializable):
    """
    A payload used to share inventory hashes.

    Use by `getdata`, `getblocks` and `mempool` message types.
    """

    def __init__(self, type: InventoryType, hashes: Sequence[types.UInt256]):
        """
        Create payload.

        Args:
            type: indicator to what type of object the hashes of this payload relate to.
            hashes: hashes of "type" objects.
        """
        self.type = type
        self.hashes = hashes

    def __len__(self):
        """Get the total size in bytes of the object."""
        return s.uint8 + utils.get_var_size(self.hashes)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_uint8(self.type)
        writer.write_var_int(len(self.hashes))
        for h in self.hashes:  # type: types.UInt256
            writer.write_bytes(h.to_array())

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.type = InventoryType(reader.read_uint8())
        self.hashes = reader.read_serializable_list(types.UInt256)

    @classmethod
    def _serializable_init(cls):
        return cls(InventoryType.BLOCK, [])


class IInventory(verification.IVerifiable):
    """
    Inventory interface.
    """

    @abc.abstractmethod
    def hash(self) -> types.UInt256:
        """"""

    @property
    @abc.abstractmethod
    def inventory_type(self) -> InventoryType:
        """"""
