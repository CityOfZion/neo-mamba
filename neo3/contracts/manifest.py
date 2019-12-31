"""
    Place holder until the contracts package gets fully implemented.
"""
from neo3.core import serialization
from neo3.core.serialization import BinaryReader, BinaryWriter


class ContractManifest(serialization.ISerializable):
    def __init__(self):
        # temp attr until implemented
        self._attr_for_test = 0

    def __len__(self):
        return 1

    def serialize(self, writer: BinaryWriter) -> None:
        """"""
        writer.write_uint8(self._attr_for_test)

    def deserialize(self, reader: BinaryReader) -> None:
        """"""
        self._attr_for_test = reader.read_uint8()
