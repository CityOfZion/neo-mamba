from __future__ import annotations
import json
from neo3 import vm, contracts, storage, settings, blockchain
from neo3.network import payloads
from neo3.core import cryptography, types, to_script_hash
from neo3.contracts.interop import register


@register("System.Contract.Create", 0, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False, [bytes, bytes])
def contract_create(engine: contracts.ApplicationEngine, nef_file: bytes, manifest: bytes) -> None:
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

    contract = engine.snapshot.contracts.try_get(hash_)
    if contract is not None:
        raise ValueError("Contract already exists")

    new_id = engine.snapshot.contract_id + 1
    engine.snapshot.contract_id = new_id

    contract = storage.ContractState(
        new_id,
        nef.script,
        contracts.ContractManifest.from_json(json.loads(manifest.decode())),
        0,
        hash_
    )

    if not contract.manifest.is_valid(hash_):
        raise ValueError("Error: invalid manifest")

    engine.snapshot.contracts.put(contract)

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


@register("System.Contract.Update", 0, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False, [bytes, bytes])
def contract_update(engine: contracts.ApplicationEngine, nef_file: bytes, manifest: bytes) -> None:
    nef_len = len(nef_file)
    manifest_len = len(manifest)

    engine.add_gas(engine.STORAGE_PRICE * (nef_len + manifest_len))

    contract = engine.snapshot.contracts.try_get(engine.current_scripthash, read_only=False)
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


@register("System.Contract.Destroy", 1000000, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False)
def contract_destroy(engine: contracts.ApplicationEngine) -> None:
    hash_ = engine.current_scripthash
    contract = engine.snapshot.contracts.try_get(hash_)

    if contract is None:
        return

    engine.snapshot.contracts.delete(hash_)

    for key, _ in engine.snapshot.storages.find(contract.script_hash(), b''):
        engine.snapshot.storages.delete(key)


@register("contract_call_internal", 0, contracts.native.CallFlags.ALL, False, [])
def contract_call_internal(engine: contracts.ApplicationEngine,
                           contract_hash: types.UInt160,
                           method: str,
                           args: vm.ArrayStackItem,
                           flags: contracts.native.CallFlags,
                           convention: contracts.ReturnTypeConvention) -> None:
    if method.startswith('_'):
        raise ValueError("[System.Contract.Call] Method not allowed to start with _")

    target_contract = engine.snapshot.contracts.try_get(contract_hash, read_only=True)
    if target_contract is None:
        raise ValueError("[System.Contract.Call] Can't find target contract")

    method_descriptor = target_contract.manifest.abi.get_method(method)
    if method_descriptor is None:
        raise ValueError(f"[System.Contract.Call] Method '{method}' does not exist on target contract")

    current_contract = engine.snapshot.contracts.try_get(engine.current_scripthash, read_only=True)
    if current_contract and not current_contract.can_call(target_contract, method):
        raise ValueError(f"[System.Contract.Call] Not allowed to call target method '{method}' according to manifest")

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


@register("System.Contract.Call", 1000000, contracts.native.CallFlags.ALLOW_CALL, False,
          [types.UInt160, str, vm.ArrayStackItem])
def contract_call(engine: contracts.ApplicationEngine,
                  contract_hash: types.UInt160,
                  method: str,
                  args: vm.ArrayStackItem) -> None:
    contract_callex(engine, contract_hash, method, args, contracts.native.CallFlags.ALL)


@register("System.Contract.CallEx", 1000000, contracts.native.CallFlags.ALLOW_CALL, False,
          [types.UInt160, str, vm.ArrayStackItem, contracts.native.CallFlags])
def contract_callex(engine: contracts.ApplicationEngine,
                    contract_hash: types.UInt160,
                    method: str,
                    args: vm.ArrayStackItem,
                    flags: contracts.native.CallFlags) -> None:
    # unlike C# we don't need this check as Python doesn't allow creating invalid enums
    # and will thrown an exception while converting the arguments for the function
    # if ((callFlags & ~CallFlags.All) != 0)
    #     throw new ArgumentOutOfRangeException(nameof(callFlags));
    contract_call_internal(engine, contract_hash, method, args, flags, contracts.ReturnTypeConvention.ENSURE_NOT_EMPTY)


@register("System.Contract.IsStandard", 30000, contracts.native.CallFlags.ALLOW_STATES, True, [types.UInt160])
def contract_is_standard(engine: contracts.ApplicationEngine, hash_: types.UInt160) -> bool:
    contract = engine.snapshot.contracts.try_get(hash_)
    if contract:
        return (contracts.Contract.is_signature_contract(contract.script)
                or contracts.Contract.is_multisig_contract(contract.script))

    if isinstance(engine.script_container, payloads.Transaction):
        for witness in engine.script_container.witnesses:
            if witness.script_hash() == hash_:
                return contracts.Contract.is_signature_contract(witness.verification_script)

    return False


@register("System.Contract.GetCallFlags", 30000, contracts.native.CallFlags.NONE, False)
def get_callflags(engine: contracts.ApplicationEngine) -> contracts.native.CallFlags:
    return contracts.native.CallFlags(engine.current_context.call_flags)


@register("System.Contract.CreateStandardAccount", 10000, contracts.native.CallFlags.NONE, True,
          [cryptography.ECPoint])
def contract_create_standard_account(engine: contracts.ApplicationEngine,
                                     public_key: cryptography.ECPoint) -> types.UInt160:
    return to_script_hash(contracts.Contract.create_signature_redeemscript(public_key))
