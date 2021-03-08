from __future__ import annotations
from typing import cast
from neo3.core import serialization, IClonable, types, IInteroperable, Size as s
from neo3.core.serialization import BinaryReader, BinaryWriter
from neo3.contracts import manifest
from neo3 import vm, contracts
from copy import deepcopy


class ContractState(serialization.ISerializable, IClonable, IInteroperable):
    def __init__(self,
                 id_: int,
                 nef: contracts.NEF,
                 manifest_: manifest.ContractManifest,
                 update_counter: int,
                 hash_: types.UInt160):
        self.id = id_
        self.nef = nef
        self.manifest = manifest_
        self.update_counter = update_counter
        self.hash = hash_

    def __len__(self):
        return (s.uint32  # id
                + len(self.nef.to_array())
                + len(self.manifest)
                + s.uint16  # update counter
                + len(self.hash))

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.hash != other.hash:
            return False
        return True

    def __deepcopy__(self, memodict={}):
        return ContractState.deserialize_from_bytes(self.to_array())

    @property
    def script(self) -> bytes:
        return self.nef.script

    @script.setter
    def script(self, value: bytes) -> None:
        self.nef.script = value

    def serialize(self, writer: BinaryWriter) -> None:
        writer.write_int32(self.id)
        writer.write_serializable(self.nef)
        writer.write_serializable(self.manifest)
        writer.write_uint32(self.update_counter)
        writer.write_serializable(self.hash)

    def deserialize(self, reader: BinaryReader) -> None:
        self.id = reader.read_int32()
        self.nef = reader.read_serializable(contracts.NEF)
        self.manifest = reader.read_serializable(manifest.ContractManifest)
        self.update_counter = reader.read_uint32()
        self.hash = reader.read_serializable(types.UInt160)

    def from_replica(self, replica):
        super().from_replica(replica)
        self.id = replica.id
        self.nef = replica.nef
        self.manifest = replica.manifest
        self.update_counter = replica.update_counter
        self.hash = replica.hash

    def clone(self):
        return ContractState(self.id, deepcopy(self.nef), deepcopy(self.manifest), self.update_counter, self.hash)

    @classmethod
    def from_stack_item(cls, stack_item: vm.StackItem):
        array = cast(vm.ArrayStackItem, stack_item)
        id = int(array[0].to_biginteger())
        update_counter = int(array[1].to_biginteger())
        hash_ = types.UInt160(array[2].to_array())
        nef = contracts.NEF.deserialize_from_bytes(array[3].to_array())
        manifest = contracts.ContractManifest.deserialize_from_bytes(array[4].to_array())
        return cls(id, nef, manifest, update_counter, hash_)

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        array = vm.ArrayStackItem(reference_counter)
        id_ = vm.IntegerStackItem(self.id)
        nef = vm.ByteStringStackItem(self.nef.to_array())
        manifest = vm.ByteStringStackItem(self.manifest.to_array())
        update_counter = vm.IntegerStackItem(self.update_counter)
        hash_ = vm.ByteStringStackItem(self.hash.to_array())
        array.append([id_, update_counter, hash_, nef, manifest])
        return array

    def can_call(self, target_contract: ContractState, target_method: str) -> bool:
        results = list(map(lambda p: p.is_allowed(target_contract, target_method), self.manifest.permissions))
        return any(results)

    @classmethod
    def _serializable_init(cls):
        return cls(0, contracts.NEF._serializable_init(), manifest.ContractManifest(), 0, types.UInt160.zero())
