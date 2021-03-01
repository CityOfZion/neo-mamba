from __future__ import annotations
import json
from . import NativeContract
from typing import Optional
from neo3 import storage, contracts, vm
from neo3.core import to_script_hash, types, msgrouter
from neo3.network import payloads


class ManagementContract(NativeContract):
    _id = -1
    _service_name = "ContractManagement"

    key_min_deploy_fee = storage.StorageKey(_id, b'\x14')

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
        self._register_contract_method(self.contract_create_with_data,
                                       0,
                                       "deploy",
                                       add_engine=True,
                                       add_snapshot=False,
                                       return_type=None,
                                       parameter_names=["nef_file", "manifest", "data"],
                                       parameter_types=[bytes, bytes, vm.StackItem],
                                       call_flags=(contracts.CallFlags.WRITE_STATES
                                                   | contracts.CallFlags.ALLOW_NOTIFY)
                                       )
        self._register_contract_method(self.contract_update,
                                       0,
                                       "update",
                                       add_engine=True,
                                       add_snapshot=False,
                                       return_type=None,
                                       parameter_names=["nef_file", "manifest", "data"],
                                       parameter_types=[bytes, bytes, vm.StackItem],
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
        engine.snapshot.contract_id = 1

    def get_next_available_id(self, snapshot: storage.Snapshot) -> int:
        snapshot.contract_id += 1
        return snapshot.contract_id

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        # NEO implicitely expects a certain order of contract initialization
        # Native contracts have negative values for `id`, so we reverse the results
        sorted_contracts = sorted(self.registered_contracts, key=lambda contract: contract.id, reverse=True)
        for contract in sorted_contracts:
            if contract.active_block_index != engine.snapshot.persisting_block.index:
                continue
            engine.snapshot.contracts.put(
                storage.ContractState(contract.id, contract.nef, contract.manifest, 0, contract.hash)
            )
            contract._initialize(engine)

    def get_contract(self, snapshot: storage.Snapshot, hash_: types.UInt160) -> Optional[storage.ContractState]:
        return snapshot.contracts.try_get(hash_)

    def contract_create(self,
                        engine: contracts.ApplicationEngine,
                        nef_file: bytes,
                        manifest: bytes) -> None:
        self.contract_create_with_data(engine, nef_file, manifest, vm.NullStackItem())

    def contract_create_with_data(self,
                                  engine: contracts.ApplicationEngine,
                                  nef_file: bytes,
                                  manifest: bytes,
                                  data: vm.StackItem) -> None:
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
        parsed_manifest = contracts.ContractManifest.from_json(json.loads(manifest.decode()))

        self.validate(nef.script, parsed_manifest.abi)

        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.ABORT)
        sb.emit_push(engine.script_container.sender.to_array())
        sb.emit_push(nef.checksum)
        sb.emit_push(parsed_manifest.name)
        hash_ = to_script_hash(sb.to_array())

        existing_contract = engine.snapshot.contracts.try_get(hash_)
        if existing_contract is not None:
            raise ValueError("Contract already exists")

        contract = storage.ContractState(self.get_next_available_id(engine.snapshot), nef, parsed_manifest, 0, hash_)
        if not contract.manifest.is_valid(hash_):
            raise ValueError("Error: invalid manifest")
        engine.snapshot.contracts.put(contract)

        engine.push(engine._native_to_stackitem(contract, storage.ContractState))
        method_descriptor = contract.manifest.abi.get_method("_deploy", 2)
        if method_descriptor is not None:
            engine.call_from_native(hash_, hash_, method_descriptor.name, [data, vm.BooleanStackItem(False)])

        msgrouter.interop_notify(self.hash,
                                 "Deploy",
                                 vm.ArrayStackItem(engine.reference_counter,
                                                   vm.ByteStringStackItem(contract.hash.to_array())
                                                   )
                                 )

    def contract_update(self,
                        engine: contracts.ApplicationEngine,
                        nef_file: bytes,
                        manifest: bytes,
                        data: vm.StackItem) -> None:
        nef_len = len(nef_file)
        manifest_len = len(manifest)

        engine.add_gas(engine.STORAGE_PRICE * (nef_len + manifest_len))

        contract = engine.snapshot.contracts.try_get(engine.current_scripthash, read_only=False)
        if contract is None:
            raise ValueError("Can't find contract to update")

        if nef_len == 0:
            raise ValueError(f"Invalid NEF length: {nef_len}")

        # update contract
        contract.nef = contracts.NEF.deserialize_from_bytes(nef_file)

        if manifest_len == 0 or manifest_len > contracts.ContractManifest.MAX_LENGTH:
            raise ValueError(f"Invalid manifest length: {manifest_len}")

        manifest_new = contracts.ContractManifest.from_json(json.loads(manifest.decode()))
        if manifest_new.name != contract.manifest.name:
            raise ValueError("Error: cannot change contract name")
        if not contract.manifest.is_valid(contract.hash):
            raise ValueError("Error: manifest does not match with script")
        contract.manifest = manifest_new

        self.validate(contract.nef.script, contract.manifest.abi)

        contract.update_counter += 1

        if len(nef_file) != 0:
            method_descriptor = contract.manifest.abi.get_method("_deploy", 2)
            if method_descriptor is not None:
                engine.call_from_native(self.hash,
                                        contract.hash,
                                        method_descriptor.name,
                                        [data, vm.BooleanStackItem(True)])

        msgrouter.interop_notify(self.hash,
                                 "Update",
                                 vm.ArrayStackItem(engine.reference_counter,
                                                   vm.ByteStringStackItem(contract.hash.to_array())
                                                   )
                                 )

    def contract_destroy(self, engine: contracts.ApplicationEngine) -> None:
        hash_ = engine.current_scripthash
        contract = engine.snapshot.contracts.try_get(hash_)

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
        return int.from_bytes(snapshot.storages[self.key_min_deploy_fee].value, 'little')

    def _set_minimum_deployment_fee(self, engine: contracts.ApplicationEngine, value: int) -> None:
        if value < 0:
            raise ValueError("Can't set deployment fee to a negative value")
        if not self._check_committee(engine):
            raise ValueError
        engine.snapshot.storages.update(self.key_min_deploy_fee, storage.StorageItem(vm.BigInteger(value).to_array()))

    def validate(self, script: bytes, abi: contracts.ContractABI):
        s = vm.Script(script, True)
        for method in abi.methods:
            s.get_instruction(method.offset)
        events = []
        for event in abi.events:
            if event.name in events:
                raise ValueError("Duplicate event in ABI")
            else:
                events.append(event)
