from __future__ import annotations
import hashlib
from neo3.core import serialization, types, Size as s, utils


class NEF(serialization.ISerializable):
    def __init__(self, compiler_name: str = None, version: str = None, script: bytes = None):
        """
        Create a Neo Executable Format file.

        Args:
            compiler_name: human readable name of the compiler used to create the script data. Automatically limited to
            32 bytes
            version: compiler version information
            script: a byte array of raw VM opcodes.
        """
        self.magic = 0x3346454E
        if compiler_name is None:
            self.compiler = 'unknown'
        else:
            self.compiler = compiler_name[:32] + bytearray(32 - len(compiler_name)).decode('utf-8')
        if version is None:
            self.version = "unknown"
        else:
            self.version = version[:32] + bytearray(32 - len(version)).decode('utf-8')
        self.script = script if script else b''
        self._checksum = 0
        # this is intentional, because NEO computes the initial checksum by serializing itself while checksum is 0
        self._checksum = self.compute_checksum()

    def __len__(self):
        return (
            s.uint32  # magic
            + 32  # compiler
            + 32  # version
            + s.uint32  # checksum
            + utils.get_var_size(self.script))

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (self.magic == other.magic
                and self.compiler == other.compiler
                and self.version == other.version
                and self.script == other.script
                and self.checksum == other.checksum)

    @property
    def checksum(self):
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
        writer.write_bytes(self.compiler.encode('utf-8'))
        writer.write_bytes(self.version.encode('utf-8'))
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
        self.compiler = reader.read_bytes(32).decode('utf-8')
        self.version = reader.read_bytes(32).decode('utf-8')
        self.script = reader.read_var_bytes()
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
