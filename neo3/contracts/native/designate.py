from __future__ import annotations
from enum import IntEnum
from typing import List
from . import NativeContract
from neo3 import storage, contracts, cryptography
from neo3.core import serialization


class DesignateRole(IntEnum):
    STATE_VALIDATOR = 4
    ORACLE = 8


class DesignateContract(NativeContract):
    _service_name = "Designation"
    _id = -5

    def init(self):
        self.manifest.features = contracts.ContractFeatures.HAS_STORAGE

        self._register_contract_method(self.get_designated_by_role,
                                       "getDesignatedByRole",
                                       1000000,
                                       return_type=List[cryptography.ECPoint],
                                       add_engine=False,
                                       add_snapshot=True,
                                       safe_method=True)

        self._register_contract_method(self.designate_as_role,
                                       "designateAsRole",
                                       0,
                                       return_type=None,
                                       add_engine=True,
                                       add_snapshot=False,
                                       safe_method=False)

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        for role in DesignateRole.__members__.values():  # type: DesignateRole
            storage_key_role = storage.StorageKey(self.script_hash, role.to_bytes(1, 'little'))
            engine.snapshot.storages.put(storage_key_role, storage.StorageItem(b'\x00'))

    def get_designated_by_role(self, snapshot: storage.Snapshot, role: DesignateRole) -> List[cryptography.ECPoint]:
        storage_key = storage.StorageKey(self.script_hash, role.to_bytes(1, 'little'))
        storage_item = snapshot.storages.get(storage_key)
        with serialization.BinaryReader(storage_item.value) as reader:
            return reader.read_serializable_list(cryptography.ECPoint)

    def designate_as_role(self,
                          engine: contracts.ApplicationEngine,
                          role: DesignateRole,
                          nodes: List[cryptography.ECPoint]) -> None:
        if len(nodes) == 0:
            raise ValueError("[DesignateContract] Cannot designate empty nodes list")

        if len(nodes) > 32:
            raise ValueError("[DesignateContract] Cannot designate a nodes list larger than 32")

        if not self._check_committee(engine):
            raise ValueError("[DesignateContract] check committee failed")

        nodes.sort()
        storage_key = storage.StorageKey(self.script_hash, role.to_bytes(1, 'little'))
        with serialization.BinaryWriter() as writer:
            writer.write_serializable_list(nodes)
            storage_item = storage.StorageItem(writer.to_array())
        engine.snapshot.storages.update(storage_key, storage_item)
