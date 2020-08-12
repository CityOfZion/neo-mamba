from __future__ import annotations
from enum import IntEnum
from typing import List
from neo3.core import types
from neo3.core import Size as s, utils
from neo3.core import serialization
import abc


class InventoryType(IntEnum):
    TX = 0x2b
    BLOCK = 0x2c
    CONSENSUS = 0x2d


class InventoryPayload(serialization.ISerializable):
    """
    A payload used to share inventory hashes.

    See also:
        - :ref:`getblocks <message-usage-getblocks>`
        - :ref:`getdata <message-usage-getdata>`
        - :ref:`mempool <message-usage-mempool>`
    """

    def __init__(self, type: InventoryType, hashes: List[types.UInt256]):
        """
        Create payload.

        Args:
            type: indicator to what type of object the the hashes of this payload relate to.
            hashes: hashes of "type" objects.
        """
        self.type = type
        self.hashes = hashes

    def __len__(self):
        """ Get the total size in bytes of the object. """
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


class IInventory(abc.ABC):
    @abc.abstractmethod
    def hash(self) -> types.UInt256:
        """"""

    @property
    @abc.abstractmethod
    def inventory_type(self) -> InventoryType:
        """"""
