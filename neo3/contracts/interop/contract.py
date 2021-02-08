from __future__ import annotations
import json
from typing import List
from neo3 import vm, contracts, storage, settings, blockchain
from neo3.network import payloads
from neo3.core import cryptography, types, to_script_hash
from neo3.contracts.interop import register


@register("System.Contract.Call", 1 << 15, contracts.CallFlags.ALLOW_CALL,
          [types.UInt160, str, vm.ArrayStackItem, contracts.CallFlags])
def contract_call(engine: contracts.ApplicationEngine,
                  contract_hash: types.UInt160,
                  method: str,
                  call_flags: contracts.CallFlags,
                  has_return_value: bool,
                  pcount: int) -> None:
    if method.startswith("_"):
        raise ValueError("Invalid method name")
    # unlike C# we don't need this check as Python doesn't allow creating invalid enums
    # and will thrown an exception while converting the arguments for the function
    # if ((callFlags & ~CallFlags.All) != 0)
    #     throw new ArgumentOutOfRangeException(nameof(callFlags));
    if pcount > len(engine.current_context.evaluation_stack):
        raise ValueError
    args: List[vm.StackItem] = []
    for _ in range(pcount):
        args.append(engine.pop())

    engine._contract_call_internal(contract_hash, method, call_flags, has_return_value, args)


@register("System.Contract.IsStandard", 1 << 10, contracts.CallFlags.READ_STATES, [types.UInt160])
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


@register("System.Contract.CreateStandardAccount", 1 << 8, contracts.CallFlags.NONE, [cryptography.ECPoint])
def contract_create_standard_account(engine: contracts.ApplicationEngine,
                                     public_key: cryptography.ECPoint) -> types.UInt160:
    return to_script_hash(contracts.Contract.create_signature_redeemscript(public_key))


@register("System.Contract.NativeOnPersist", 0, contracts.CallFlags.WRITE_STATES)
def native_on_persist(engine: contracts.ApplicationEngine) -> None:
    if engine.trigger != contracts.TriggerType.ON_PERSIST:
        raise SystemError()
    for contract in contracts.NativeContract._contracts.values():
        if contract.active_block_index <= engine.snapshot.persisting_block.index:
            contract.on_persist(engine)


@register("System.Contract.NativePostPersist", 0, contracts.CallFlags.WRITE_STATES)
def native_post_persist(engine: contracts.ApplicationEngine) -> None:
    if engine.trigger != contracts.TriggerType.POST_PERSIST:
        raise SystemError()
    for contract in contracts.NativeContract._contracts.values():
        if contract.active_block_index <= engine.snapshot.persisting_block.index:
            contract.post_persist(engine)


@register("System.Contract.CallNative", 0, contracts.CallFlags.NONE, [str])
def call_native(engine: contracts.ApplicationEngine, name: str) -> None:
    contract = contracts.NativeContract.get_contract_by_name(name)
    if contract is None or contract.active_block_index > engine.snapshot.block_height:
        raise ValueError
    contract.invoke(engine)
