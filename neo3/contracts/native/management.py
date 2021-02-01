from __future__ import annotations
import json
from . import NativeContract
from typing import Optional
from neo3 import storage, contracts, vm
from neo3.core import to_script_hash, types
from neo3.network import payloads
from neo3.contracts.interop import register


@register("contract_call_internal", 0, contracts.native.CallFlags.ALL, False, [])
def contract_call_internal(engine: contracts.ApplicationEngine,
                           contract_hash: types.UInt160,
                           method: str,
                           args: vm.ArrayStackItem,
                           flags: contracts.native.CallFlags,
                           convention: contracts.ReturnTypeConvention) -> None:
    if method.startswith('_'):
        raise ValueError("[System.Contract.Call] Method not allowed to start with _")

    target_contract = ManagementContract().get_contract(engine.snapshot, contract_hash)
    if target_contract is None:
        raise ValueError("[System.Contract.Call] Can't find target contract")

    method_descriptor = target_contract.manifest.abi.get_method(method)
    if method_descriptor is None:
        raise ValueError(f"[System.Contract.Call] Method '{method}' does not exist on target contract")

    current_contract = ManagementContract().get_contract(engine.snapshot, engine.current_scripthash)
    if current_contract and not current_contract.can_call(target_contract, method):
        raise ValueError(
            f"[System.Contract.Call] Not allowed to call target method '{method}' according to manifest")

    contract_call_internal_ex(engine, target_contract, method_descriptor, args, flags, convention)


def contract_call_internal_ex(engine: contracts.ApplicationEngine,
                              contract: storage.ContractState,
                              contract_method_descriptor: contracts.ContractMethodDescriptor,
                              args: vm.ArrayStackItem,
                              flags: contracts.native.CallFlags,
                              convention: contracts.ReturnTypeConvention) -> None:
    counter = engine._invocation_counter.get(contract.hash, 0)
    engine._invocation_counter.update({contract.hash: counter + 1})

    engine._get_invocation_state(engine.current_context).convention = convention

    state = engine.current_context
    calling_flags = state.call_flags

    arg_len = len(args)
    expected_len = len(contract_method_descriptor.parameters)
    if arg_len != expected_len:
        raise ValueError(
            f"[System.Contract.Call] Invalid number of contract arguments. Expected {expected_len} actual {arg_len}")  # noqa

    context_new = engine.load_contract(contract, contract_method_descriptor.name, flags & calling_flags)
    if context_new is None:
        raise ValueError
    context_new.calling_script = state.script

    if contracts.NativeContract.is_native(contract.hash):
        context_new.evaluation_stack.push(args)
        context_new.evaluation_stack.push(vm.ByteStringStackItem(contract_method_descriptor.name.encode('utf-8')))
    else:
        for item in reversed(args):
            context_new.evaluation_stack.push(item)
        context_new.ip = contract_method_descriptor.offset


class ManagementContract(NativeContract):
    _service_name = "Neo Contract Management"
    _id = 0

    _PREFIX_NEXT_AVAILABLE_ID = b'\x0F'
    _PREFIX_CONTRACT = b'\x08'

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
                                       call_flags=contracts.native.CallFlags.WRITE_STATES)
        self._register_contract_method(self.contract_update,
                                       0,
                                       "update",
                                       add_engine=True,
                                       add_snapshot=False,
                                       return_type=None,
                                       parameter_names=["nef_file", "manifest"],
                                       parameter_types=[bytes, bytes],
                                       call_flags=contracts.native.CallFlags.WRITE_STATES)
        self._register_contract_method(self.contract_destroy,
                                       1000000,
                                       "destroy",
                                       add_engine=True,
                                       add_snapshot=False,
                                       return_type=None,
                                       call_flags=contracts.native.CallFlags.WRITE_STATES)

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
                storage.ContractState(contract.id, contract.script, contract.manifest, 0, contract.hash).to_array()
            )
            engine.snapshot.storages.put(storage_key, storage_item)
            contract._initialize(engine)

    def get_contract(self, snapshot: storage.Snapshot, hash_: types.UInt160) -> Optional[storage.ContractState]:
        storage_key = self.create_key(self._PREFIX_CONTRACT + hash_.to_array())
        storage_item = snapshot.storages.try_get(storage_key, read_only=True)
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

        engine.add_gas(engine.STORAGE_PRICE * (nef_len + manifest_len))

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
            nef.script,
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
            contract_call_internal_ex(engine,
                                      contract,
                                      method_descriptor,
                                      vm.ArrayStackItem(engine.reference_counter, vm.BooleanStackItem(False)),
                                      contracts.native.CallFlags.ALL,
                                      contracts.ReturnTypeConvention.ENSURE_IS_EMPTY
                                      )

    def contract_update(self, engine: contracts.ApplicationEngine, nef_file: bytes, manifest: bytes) -> None:
        nef_len = len(nef_file)
        manifest_len = len(manifest)

        engine.add_gas(engine.STORAGE_PRICE * (nef_len + manifest_len))

        key = self.create_key(self._PREFIX_CONTRACT + engine.current_scripthash.to_array())
        contract = engine.snapshot.storages.try_get(key, read_only=False)
        if contract is None:
            raise ValueError("Can't find contract to update")

        if nef_len == 0:
            raise ValueError(f"Invalid NEF length: {nef_len}")

        nef = contracts.NEF.deserialize_from_bytes(nef_file)
        # update contract
        contract.script = nef.script

        if manifest_len == 0 or manifest_len > contracts.ContractManifest.MAX_LENGTH:
            raise ValueError(f"Invalid manifest length: {manifest_len}")

        contract.manifest = contracts.ContractManifest.from_json(json.loads(manifest.decode()))
        if not contract.manifest.is_valid(contract.hash_):
            raise ValueError("Error: manifest does not match with script")

        contract.update_counter += 1

        if len(nef_file) != 0:
            method_descriptor = contract.manifest.abi.get_method("_deploy")
            if method_descriptor is not None:
                contract_call_internal_ex(engine,
                                          contract,
                                          method_descriptor,
                                          vm.ArrayStackItem(engine.reference_counter, vm.BooleanStackItem(True)),
                                          contracts.native.CallFlags.ALL,
                                          contracts.ReturnTypeConvention.ENSURE_IS_EMPTY
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
