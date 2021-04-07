from __future__ import annotations
import hashlib
from typing import List
from neo3 import storage, settings
from neo3.core import types, serialization, Size as s, utils
from neo3.network import payloads
from neo3.network.payloads import InventoryType


class ExtensiblePayload(payloads.IInventory):
    def __init__(self,
                 category: str,
                 valid_block_start: int,
                 valid_block_end: int,
                 sender: types.UInt160,
                 data: bytes,
                 witness: payloads.Witness):
        self.category = category
        self.valid_block_start = valid_block_start
        self.valid_block_end = valid_block_end
        self.sender = sender
        self.data = data
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
        self.serialize_unsigned(writer)
        writer.write_uint8(1)
        writer.write_serializable(self.witness)

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        writer.write_var_string(self.category)
        writer.write_uint32(self.valid_block_start)
        writer.write_uint32(self.valid_block_end)
        writer.write_serializable(self.sender)
        writer.write_var_bytes(self.data)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.deserialize_unsigned(reader)
        if reader.read_uint8() != 1:
            raise ValueError("Deserialization error - check byte incorrect")
        self.witness = reader.read_serializable(payloads.Witness)

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        self.category = reader.read_var_string(32)
        self.valid_block_start = reader.read_uint32()
        self.valid_block_end = reader.read_uint32()
        if self.valid_block_start >= self.valid_block_end:
            raise ValueError("Deserialization error - valid_block_starts is bigger than valid_block_end")
        self.sender = reader.read_serializable(types.UInt160)
        self.data = reader.read_var_bytes(0xFFFF)

    def hash(self) -> types.UInt256:
        intermediate_data = hashlib.sha256(self.get_hash_data(settings.network.magic)).digest()
        data = hashlib.sha256(intermediate_data).digest()
        return types.UInt256(data)

    @property
    def inventory_type(self) -> InventoryType:
        return InventoryType.EXTENSIBLE

    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        return [self.sender]
