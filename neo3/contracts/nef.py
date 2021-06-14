from __future__ import annotations
import hashlib
from typing import List
from neo3.core import serialization, types, Size as s, utils
from neo3 import contracts


class NEF(serialization.ISerializable):
    def __init__(self,
                 compiler_name: str = None,
                 script: bytes = None,
                 tokens: List[MethodToken] = None):
        """
        Create a Neo Executable Format file.

        Args:
            compiler_name: human readable name of the compiler and version used to create the script data.
            Automatically limited to 64 bytes
            script: a byte array of raw VM opcodes.
        """
        self.magic = 0x3346454E
        if compiler_name is None:
            self.compiler = 'unknown'
        else:
            self.compiler = compiler_name[:64] + bytearray(64 - len(compiler_name)).decode('utf-8')
        self.script = script if script else b''
        self._checksum = 0
        self.tokens = [] if tokens is None else tokens
        # this is intentional, because NEO computes the initial checksum by serializing itself while checksum is 0
        self._checksum = self.compute_checksum()

    def __len__(self):
        return (
            s.uint32  # magic
            + 64  # compiler
            + 2  # reserved
            + utils.get_var_size(self.tokens)
            + 2  # reserved
            + s.uint32  # checksum
            + utils.get_var_size(self.script))

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (self.magic == other.magic
                and self.compiler == other.compiler
                and self.script == other.script
                and self.tokens == other.tokens
                and self.checksum == other.checksum)

    @property
    def checksum(self) -> int:
        if self._checksum == 0:
            self._checksum = self.compute_checksum()
        return self._checksum

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_uint32(self.magic)
        writer.write_bytes(self.compiler.encode('utf-8').ljust(64, b'\x00'))
        writer.write_bytes(b'\x00\x00')
        writer.write_serializable_list(self.tokens)
        writer.write_bytes(b'\x00\x00')
        writer.write_var_bytes(self.script)
        writer.write_uint32(self._checksum)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        if reader.read_uint32() != self.magic:
            raise ValueError("Deserialization error - Incorrect magic")
        self.compiler = reader.read_bytes(64).decode('utf-8')
        if reader.read_uint16() != 0:
            raise ValueError("Reserved bytes must be 0")
        self.tokens = reader.read_serializable_list(MethodToken)
        if reader.read_uint16() != 0:
            raise ValueError("Reserved bytes must be 0")

        self.script = reader.read_var_bytes(max=512 * 1024)
        if len(self.script) == 0:
            raise ValueError("Deserialization error - Script can't be empty")

        checksum = int.from_bytes(reader.read_bytes(4), 'little')
        if checksum != self.compute_checksum():
            raise ValueError("Deserialization error - Invalid checksum")
        else:
            self._checksum = checksum

    def compute_checksum(self) -> int:
        """
        Compute the checksum of the NEF file.
        """
        return int.from_bytes(hashlib.sha256(hashlib.sha256(self.to_array()[:-4]).digest()).digest()[:4], 'little')

    @classmethod
    def _serializable_init(cls):
        c = cls()
        c._checksum = 0
        return c


class MethodToken(serialization.ISerializable):
    def __init__(self,
                 hash: types.UInt160,
                 method: str,
                 parameters_count: int,
                 has_return_value: bool,
                 call_flags: contracts.CallFlags):
        self.hash = hash
        self.method = method
        self.parameters_count = parameters_count
        self.has_return_value = has_return_value
        self.call_flags = call_flags

    def __len__(self):
        return s.uint160 + utils.get_var_size(self.method) + s.uint16 + s.uint8 + s.uint8

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_serializable(self.hash)
        writer.write_var_string(self.method)
        writer.write_uint16(self.parameters_count)
        writer.write_uint8(self.has_return_value)
        writer.write_uint8(self.call_flags.value)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.hash = reader.read_serializable(types.UInt160)
        self.method = reader.read_var_string(32)
        self.parameters_count = reader.read_uint16()
        self.has_return_value = bool(reader.read_uint8())
        self.call_flags = contracts.CallFlags(reader.read_uint8())

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt160.zero(), "", 0, False, contracts.CallFlags.NONE)
