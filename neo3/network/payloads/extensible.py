from __future__ import annotations
import hashlib
from typing import List
from neo3 import storage, settings
from neo3.core import types, serialization, Size as s, utils
from neo3.network import payloads, message
from neo3.network.payloads import InventoryType


class ExtensiblePayload(payloads.IInventory):
    def __init__(self,
                 category: str,
                 valid_block_start: int,
                 valid_block_end: int,
                 sender: types.UInt160,
                 data: bytes,
                 witness: payloads.Witness):
        #: An identifier to which category the data belongs
        self.category = category
        #: Starting height in which the payload is valid
        self.valid_block_start = valid_block_start
        #: Last height height in which the payload is valid
        self.valid_block_end = valid_block_end
        #: The hash of the account who has send the payload to the network
        self.sender = sender
        #: Arbitrary data as required by the payload category
        self.data = data
        #: The witness of the payload
        self.witness = witness

    def __len__(self):
        return (utils.get_var_size(self.category)
                + s.uint32
                + s.uint32
                + s.uint160
                + utils.get_var_size(self.data)
                + 1
                + len(self.witness))

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        self.serialize_unsigned(writer)
        writer.write_uint8(1)
        writer.write_serializable(self.witness)

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the unsigned part of the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_var_string(self.category)
        writer.write_uint32(self.valid_block_start)
        writer.write_uint32(self.valid_block_end)
        writer.write_serializable(self.sender)
        writer.write_var_bytes(self.data)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if the check byte is not 1.
        """
        self.deserialize_unsigned(reader)
        if reader.read_uint8() != 1:
            raise ValueError("Deserialization error - check byte incorrect")
        self.witness = reader.read_serializable(payloads.Witness)

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the unsigned data part of the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if the valid_block_start exceeds the valid_block_end field.
        """
        self.category = reader.read_var_string(32)
        self.valid_block_start = reader.read_uint32()
        self.valid_block_end = reader.read_uint32()
        if self.valid_block_start >= self.valid_block_end:
            raise ValueError("Deserialization error - valid_block_start is bigger than valid_block_end")
        self.sender = reader.read_serializable(types.UInt160)
        self.data = reader.read_var_bytes(message.Message.PAYLOAD_MAX_SIZE)

    def hash(self) -> types.UInt256:
        """
        Get a unique identifier based on the unsigned data portion of the object.
        """
        with serialization.BinaryWriter() as bw:
            self.serialize_unsigned(bw)
            data_to_hash = bytearray(bw._stream.getvalue())
            data = hashlib.sha256(data_to_hash).digest()
            return types.UInt256(data=data)

    @property
    def inventory_type(self) -> InventoryType:
        """
        Inventory type identifier.
        """
        return InventoryType.EXTENSIBLE

    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        """
        Helper method to get the data used in verifying the object.
        """
        return [self.sender]

    @classmethod
    def _serializable_init(cls):
        return cls('', 0, 0, types.UInt160.zero(), b'', payloads.Witness(b'', b''))
