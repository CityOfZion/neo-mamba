from __future__ import annotations
import hashlib
import json
from neo3.core import serialization, IClonable, utils, types, IInteroperable
from neo3.core.serialization import BinaryReader, BinaryWriter
from neo3.contracts import manifest
from neo3 import vm, contracts
from copy import deepcopy


class ContractState(serialization.ISerializable, IClonable, IInteroperable):
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

    def __deepcopy__(self, memodict={}):
        return ContractState.deserialize_from_bytes(self.to_array())

    @property
    def has_storage(self) -> bool:
        return contracts.ContractFeatures.HAS_STORAGE in self.manifest.features

    @property
    def is_payable(self) -> bool:
        return contracts.ContractFeatures.PAYABLE in self.manifest.features

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
        return ContractState(self.script, deepcopy(self.manifest))

    def script_hash(self) -> types.UInt160:
        """ Get the script hash."""
        intermediate_data = hashlib.sha256(self.script).digest()
        data = hashlib.new('ripemd160', intermediate_data).digest()
        return types.UInt160(data=data)

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        array = vm.ArrayStackItem(reference_counter)
        script = vm.ByteStringStackItem(self.script)
        manifest = vm.ByteStringStackItem(str(self.manifest))
        has_storage = vm.BooleanStackItem(self.has_storage)
        is_payable = vm.BooleanStackItem(self.is_payable)
        array.append([script, manifest, has_storage, is_payable])
        return array

    @classmethod
    def _serializable_init(cls):
        return cls(b'', manifest.ContractManifest())
