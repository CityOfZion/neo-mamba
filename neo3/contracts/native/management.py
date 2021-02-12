from __future__ import annotations
import json
from . import NativeContract
from typing import Optional, List
from neo3 import storage, contracts, vm
from neo3.core import to_script_hash, types, msgrouter
from neo3.network import payloads
from neo3.contracts.interop import register


class ManagementContract(NativeContract):
    _id = 0
    _service_name = "ContractManagement"

    _PREFIX_NEXT_AVAILABLE_ID = b'\x0F'
    _PREFIX_CONTRACT = b'\x08'
    _PREFIX_MINIMUM_DEPLOYMENT_FEE = b'\x14'

    key_contract = storage.StorageKey(_id, _PREFIX_CONTRACT)
    key_next_id = storage.StorageKey(_id, _PREFIX_NEXT_AVAILABLE_ID)
    key_min_deploy_fee = storage.StorageKey(_id, _PREFIX_MINIMUM_DEPLOYMENT_FEE)

    def init(self):
        super(ManagementContract, self).init()

        self._register_contract_method(self.get_contract,
                                       1000000,
                                       "getContract",
                                       add_engine=False,
                                       add_snapshot=True,
                                       return_type=storage.ContractState,
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.contract_create,
                                       0,
                                       "deploy",
                                       add_engine=True,
                                       add_snapshot=False,
                                       return_type=None,
                                       parameter_names=["nef_file", "manifest"],
                                       parameter_types=[bytes, bytes],
                                       call_flags=(contracts.CallFlags.WRITE_STATES
                                                   | contracts.CallFlags.ALLOW_NOTIFY)
                                       )
        self._register_contract_method(self.contract_update,
                                       0,
                                       "update",
                                       add_engine=True,
                                       add_snapshot=False,
                                       return_type=None,
                                       parameter_names=["nef_file", "manifest"],
                                       parameter_types=[bytes, bytes],
                                       call_flags=(contracts.CallFlags.WRITE_STATES
                                                   | contracts.CallFlags.ALLOW_NOTIFY)
                                       )
        self._register_contract_method(self.contract_destroy,
                                       1000000,
                                       "destroy",
                                       add_engine=True,
                                       add_snapshot=False,
                                       return_type=None,
                                       call_flags=(contracts.CallFlags.WRITE_STATES
                                                   | contracts.CallFlags.ALLOW_NOTIFY)
                                       )
        self._register_contract_method(self.get_minimum_deployment_fee,
                                       1000000,
                                       "getMinimumDeploymentFee",
                                       add_engine=False,
                                       add_snapshot=True,
                                       return_type=int,
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self._set_minimum_deployment_fee,
                                       3000000,
                                       "setMinimumDeploymentFee",
                                       add_engine=True,
                                       add_snapshot=False,
                                       return_type=None,
                                       call_flags=contracts.CallFlags.WRITE_STATES)

        self.manifest.abi.events = [
            contracts.ContractEventDescriptor(
                "Deploy",
                parameters=[
                    contracts.ContractParameterDefinition("Hash", contracts.ContractParameterType.HASH160)
                ]
            ),
            contracts.ContractEventDescriptor(
                "Update",
                parameters=[
                    contracts.ContractParameterDefinition("Hash", contracts.ContractParameterType.HASH160)
                ]
            ),
            contracts.ContractEventDescriptor(
                "Destroy",
                parameters=[
                    contracts.ContractParameterDefinition("Hash", contracts.ContractParameterType.HASH160)
                ]
            ),
        ]

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        engine.snapshot.storages.put(
            self.key_min_deploy_fee,
            storage.StorageItem(vm.BigInteger(10_00000000).to_array())
        )

    def get_next_available_id(self, snapshot: storage.Snapshot) -> int:
        key = self.create_key(self._PREFIX_NEXT_AVAILABLE_ID)
        item = snapshot.storages.try_get(key, read_only=False)
        if item is None:
            value = vm.BigInteger(1)
            item = storage.StorageItem(value.to_array())
        else:
            value = vm.BigInteger(item.value) + 1
            item.value = value.to_array()
        snapshot.storages.update(key, item)
        return int(value)

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        for contract in self._contracts.values():
            if contract.active_block_index != engine.snapshot.persisting_block.index:
                continue
            storage_key = self.create_key(self._PREFIX_CONTRACT + contract.hash.to_array())
            storage_item = storage.StorageItem(
                storage.ContractState(contract.id, contract.nef, contract.manifest, 0, contract.hash).to_array()
            )
            engine.snapshot.storages.put(storage_key, storage_item)
            contract._initialize(engine)

    def get_contract(self, snapshot: storage.Snapshot, hash_: types.UInt160) -> Optional[storage.ContractState]:
        storage_item = snapshot.storages.try_get(self.key_contract + hash_.to_array(), read_only=True)
        if storage_item is None:
            return None
        return storage.ContractState.deserialize_from_bytes(storage_item.value)

    def contract_create(self, engine: contracts.ApplicationEngine, nef_file: bytes, manifest: bytes) -> None:
        if not isinstance(engine.script_container, payloads.Transaction):
            raise ValueError("Cannot create contract without a Transaction script container")

        nef_len = len(nef_file)
        manifest_len = len(manifest)
        if (nef_len == 0
                or nef_len > engine.MAX_CONTRACT_LENGTH
                or manifest_len == 0
                or manifest_len > contracts.ContractManifest.MAX_LENGTH):
            raise ValueError("Invalid NEF or manifest length")

        engine.add_gas(
            max(engine.STORAGE_PRICE * (nef_len + manifest_len), self.get_minimum_deployment_fee(engine.snapshot))
        )

        nef = contracts.NEF.deserialize_from_bytes(nef_file)
        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.ABORT)
        sb.emit_push(engine.script_container.sender.to_array())
        sb.emit_push(nef.script)
        hash_ = to_script_hash(sb.to_array())

        key = self.create_key(self._PREFIX_CONTRACT + hash_.to_array())
        contract = engine.snapshot.storages.try_get(key)
        if contract is not None:
            raise ValueError("Contract already exists")

        contract = storage.ContractState(
            self.get_next_available_id(engine.snapshot),
            nef,
            contracts.ContractManifest.from_json(json.loads(manifest.decode())),
            0,
            hash_
        )

        if not contract.manifest.is_valid(hash_):
            raise ValueError("Error: invalid manifest")

        engine.snapshot.storages.put(key, storage.StorageItem(contract.to_array()))

        engine.push(engine._native_to_stackitem(contract, storage.ContractState))
        method_descriptor = contract.manifest.abi.get_method("_deploy")
        if method_descriptor is not None:
            engine.call_from_native(hash_, hash_, method_descriptor.name, [vm.BooleanStackItem(False)])

        msgrouter.interop_notify(self.hash,
                                 "Deploy",
                                 vm.ArrayStackItem(engine.reference_counter,
                                                   vm.ByteStringStackItem(contract.hash.to_array())
                                                   )
                                 )

    def contract_update(self, engine: contracts.ApplicationEngine, nef_file: bytes, manifest: bytes) -> None:
        nef_len = len(nef_file)
        manifest_len = len(manifest)

        engine.add_gas(engine.STORAGE_PRICE * (nef_len + manifest_len))

        key = self.create_key(self._PREFIX_CONTRACT + engine.current_scripthash.to_array())
        contract_storage_item = engine.snapshot.storages.try_get(key, read_only=False)
        if contract_storage_item is None:
            raise ValueError("Can't find contract to update")

        contract = storage.ContractState.deserialize_from_bytes(contract_storage_item.value)
        if nef_len == 0:
            raise ValueError(f"Invalid NEF length: {nef_len}")

        # update contract
        contract.nef = contracts.NEF.deserialize_from_bytes(nef_file)

        if manifest_len == 0 or manifest_len > contracts.ContractManifest.MAX_LENGTH:
            raise ValueError(f"Invalid manifest length: {manifest_len}")

        contract.manifest = contracts.ContractManifest.from_json(json.loads(manifest.decode()))
        if not contract.manifest.is_valid(contract.hash):
            raise ValueError("Error: manifest does not match with script")

        contract.update_counter += 1

        if len(nef_file) != 0:
            method_descriptor = contract.manifest.abi.get_method("_deploy")
            if method_descriptor is not None:
                engine.call_from_native(self.hash, contract.hash, method_descriptor.name, [vm.BooleanStackItem(True)])

        msgrouter.interop_notify(self.hash,
                                 "Update",
                                 vm.ArrayStackItem(engine.reference_counter,
                                                   vm.ByteStringStackItem(contract.hash.to_array())
                                                   )
                                 )

    def contract_destroy(self, engine: contracts.ApplicationEngine) -> None:
        hash_ = engine.current_scripthash
        key = self.create_key(self._PREFIX_CONTRACT + hash_.to_array())
        contract = engine.snapshot.storages.try_get(key)

        if contract is None:
            return

        engine.snapshot.storages.delete(hash_)

        for key, _ in engine.snapshot.storages.find(contract.id.to_bytes(4, 'little', signed=True), b''):
            engine.snapshot.storages.delete(key)

        msgrouter.interop_notify(self.hash,
                                 "Destroy",
                                 vm.ArrayStackItem(engine.reference_counter,
                                                   vm.ByteStringStackItem(contract.hash.to_array())
                                                   )
                                 )

    def get_minimum_deployment_fee(self, snapshot: storage.Snapshot) -> int:
        key = self.create_key(self._PREFIX_MINIMUM_DEPLOYMENT_FEE)
        return int.from_bytes(snapshot.storages[key].value, 'little')

    def _set_minimum_deployment_fee(self, engine: contracts.ApplicationEngine, value: int) -> None:
        if value < 0:
            raise ValueError("Can't set deployment fee to a negative value")
        if not self._check_committee(engine):
            raise ValueError
        key = self.create_key(self._PREFIX_MINIMUM_DEPLOYMENT_FEE)
        engine.snapshot.storages.update(key, storage.StorageItem(vm.BigInteger(value).to_array()))
