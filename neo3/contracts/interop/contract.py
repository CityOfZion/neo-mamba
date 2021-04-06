from __future__ import annotations
import json
from typing import List, Any
from neo3 import vm, contracts, storage, settings, blockchain
from neo3.network import payloads
from neo3.core import cryptography, types, to_script_hash
from neo3.contracts.interop import register


@register("System.Contract.Call", 1 << 15, contracts.CallFlags.ALLOW_CALL)
def contract_call(engine: contracts.ApplicationEngine,
                  contract_hash: types.UInt160,
                  method: str,
                  call_flags: contracts.CallFlags,
                  args: vm.ArrayStackItem) -> None:
    if method.startswith("_"):
        raise ValueError("Invalid method name")

    target_contract = contracts.ManagementContract().get_contract(engine.snapshot, contract_hash)
    if target_contract is None:
        raise ValueError("[System.Contract.Call] Can't find target contract")

    method_descriptor = target_contract.manifest.abi.get_method(method, len(args))
    if method_descriptor is None:
        raise ValueError(f"[System.Contract.Call] Method '{method}' does not exist on target contract")

    has_return_value = method_descriptor.return_type != contracts.ContractParameterType.VOID
    if not has_return_value:
        engine.current_context.evaluation_stack.push(vm.NullStackItem())

    engine._contract_call_internal2(target_contract, method_descriptor, call_flags, has_return_value, list(args))


@register("System.Contract.IsStandard", 1 << 10, contracts.CallFlags.READ_STATES)
def contract_is_standard(engine: contracts.ApplicationEngine, hash_: types.UInt160) -> bool:
    contract = contracts.ManagementContract().get_contract(engine.snapshot, hash_)
    if contract:
        return (contracts.Contract.is_signature_contract(contract.script)
                or contracts.Contract.is_multisig_contract(contract.script))

    if isinstance(engine.script_container, payloads.Transaction):
        for witness in engine.script_container.witnesses:
            if witness.script_hash() == hash_:
                return contracts.Contract.is_signature_contract(witness.verification_script)

    return False


@register("System.Contract.GetCallFlags", 1 << 10, contracts.CallFlags.NONE)
def get_callflags(engine: contracts.ApplicationEngine) -> contracts.CallFlags:
    return contracts.CallFlags(engine.current_context.call_flags)


@register("System.Contract.CreateStandardAccount", 1 << 8, contracts.CallFlags.NONE)
def contract_create_standard_account(engine: contracts.ApplicationEngine,
                                     public_key: cryptography.ECPoint) -> types.UInt160:
    return to_script_hash(contracts.Contract.create_signature_redeemscript(public_key))


@register("System.Contract.NativeOnPersist", 0, contracts.CallFlags.WRITE_STATES)
def native_on_persist(engine: contracts.ApplicationEngine) -> None:
    if engine.trigger != contracts.TriggerType.ON_PERSIST:
        raise SystemError()
    # NEO implicitely expects the ManagementContract to be called first *ugh*
    # because ManagementContract.on_persist will call _initialize() on all other native contracts
    # which is needed for the other contracts to work properly when their on_persist() is called
    sorted_contracts = sorted(contracts.NativeContract().registered_contracts, key=lambda c: c.id, reverse=True)
    for contract in sorted_contracts:
        if contract.active_block_index <= engine.snapshot.persisting_block.index:
            contract.on_persist(engine)


@register("System.Contract.NativePostPersist", 0, contracts.CallFlags.WRITE_STATES)
def native_post_persist(engine: contracts.ApplicationEngine) -> None:
    if engine.trigger != contracts.TriggerType.POST_PERSIST:
        raise SystemError()
    for contract in contracts.NativeContract._contracts.values():
        if contract.active_block_index <= engine.snapshot.persisting_block.index:
            contract.post_persist(engine)


@register("System.Contract.CallNative", 0, contracts.CallFlags.NONE)
def call_native(engine: contracts.ApplicationEngine, contract_id: int) -> None:
    contract = contracts.NativeContract.get_contract_by_id(contract_id)
    if contract is None:
        raise ValueError(f"Can't find native contract with id {contract_id}")

    if contract.active_block_index > engine.snapshot.best_block_height:
        raise ValueError(f"Native contract is not active until blockheight {contract.active_block_index}")
    contract.invoke(engine)
