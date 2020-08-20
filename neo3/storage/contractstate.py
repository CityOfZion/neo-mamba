import hashlib
from neo3.core import serialization, IClonable, utils, types
from neo3.core.serialization import BinaryReader, BinaryWriter
from neo3.contracts import manifest


class ContractState(serialization.ISerializable, IClonable):
    def __init__(self, script: bytes, _manifest: manifest.ContractManifest):
        self.script = script
        self.manifest = _manifest

    def __len__(self):
        return utils.get_var_size(self.script) + len(self.manifest)

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.script_hash() != other.script_hash():
            return False
        return True

    def serialize(self, writer: BinaryWriter) -> None:
        writer.write_var_bytes(self.script)
        writer.write_serializable(self.manifest)

    def deserialize(self, reader: BinaryReader) -> None:
        self.script = reader.read_var_bytes()
        self.manifest = reader.read_serializable(manifest.ContractManifest)

    def from_replica(self, replica):
        super().from_replica(replica)
        self.script = replica.script
        self.manifest = replica.manifest

    def clone(self):
        return ContractState(self.script, self.manifest)

    def script_hash(self) -> types.UInt160:
        """ Get the script hash."""
        intermediate_data = hashlib.sha256(self.script).digest()
        data = hashlib.new('ripemd160', intermediate_data).digest()
        return types.UInt160(data=data)

    @classmethod
    def _serializable_init(cls):
        return cls(b'', manifest.ContractManifest())
