from __future__ import annotations
import json
from neo3 import vm, contracts, storage, settings, blockchain
from neo3.network import payloads
from neo3.core import cryptography, types, to_script_hash
from neo3.contracts.interop import register


@register("System.Contract.Create", 0, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False, [bytes, bytes])
def contract_create(engine: contracts.ApplicationEngine, script: bytes, manifest: bytes) -> storage.ContractState:
    script_len = len(script)
    manifest_len = len(manifest)
    if (script_len == 0
            or script_len > engine.MAX_CONTRACT_LENGTH
            or manifest_len == 0
            or manifest_len > contracts.ContractManifest.MAX_LENGTH):
        raise ValueError("Invalid script or manifest length")

    engine.add_gas(engine.STORAGE_PRICE * (script_len + manifest_len))

    hash_ = to_script_hash(script)
    contract = engine.snapshot.contracts.try_get(hash_)
    if contract is not None:
        raise ValueError("Contract already exists")

    contract = storage.ContractState(script, contracts.ContractManifest.from_json(json.loads(manifest.decode())))
    if not contract.manifest.is_valid(hash_):
        raise ValueError("Error: manifest does not match with script")

    engine.snapshot.contracts.put(contract)
    return contract


@register("System.Contract.Update", 0, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False, [bytes, bytes])
def contract_update(engine: contracts.ApplicationEngine, script: bytes, manifest: bytes) -> None:
    script_len = len(script)
    manifest_len = len(manifest)

    # TODO: In preview 4 revert back to
    # engine.add_gas(engine.STORAGE_PRICE * (script_len + manifest_len))
    # They made a mistake in their storage price calculation logic where manifest size is never taken into account
    engine.add_gas(engine.STORAGE_PRICE * script_len)

    contract = engine.snapshot.contracts.try_get(engine.current_scripthash, read_only=True)
    if contract is None:
        raise ValueError("Can't find contract to update")

    if script_len == 0 or script_len > engine.MAX_CONTRACT_LENGTH:
        raise ValueError(f"Invalid script length: {script_len}")

    hash_ = to_script_hash(script)
    if hash_ == engine.current_scripthash or engine.snapshot.contracts.try_get(hash_) is not None:
        raise ValueError("Nothing to update")

    old_contract_has_storage = contract.has_storage
    contract = storage.ContractState(script, contract.manifest)
    contract.manifest.abi.contract_hash = hash_

    engine.snapshot.contracts.put(contract)

    # migrate storage to new contract hash
    with blockchain.Blockchain().backend.get_snapshotview() as snapshot:
        if old_contract_has_storage:
            for key, value in snapshot.storages.find(engine.current_scripthash, b''):
                # delete the old storage
                snapshot.storages.delete(key)
                # update key to new contract hash
                key.contract = contract.script_hash()
                # now persist all data under new contract key
                snapshot.storages.put(key, value)
        snapshot.commit()
    engine.snapshot.contracts.delete(engine.current_scripthash)

    if manifest_len == 0 or manifest_len > contracts.ContractManifest.MAX_LENGTH:
        raise ValueError(f"Invalid manifest length: {manifest_len}")

    contract.manifest = contracts.ContractManifest.from_json(json.loads(manifest.decode()))
    if not contract.manifest.is_valid(contract.script_hash()):
        raise ValueError("Error: manifest does not match with script")
    if (not contract.has_storage
            and len(list(engine.snapshot.storages.find(contract.script_hash(), key_prefix=b''))) != 0):
        raise ValueError("Error: New contract does not support storage while old contract has existing storage")


@register("System.Contract.Destroy", 1000000, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False)
def contract_destroy(engine: contracts.ApplicationEngine) -> None:
    hash_ = engine.current_scripthash
    contract = engine.snapshot.contracts.try_get(hash_)

    if contract is None:
        return

    engine.snapshot.contracts.delete(hash_)

    if contract.has_storage:
        for key, _ in engine.snapshot.storages.find(contract.script_hash(), b''):
            engine.snapshot.storages.delete(key)


def contract_call_internal(engine: contracts.ApplicationEngine,
                           contract_hash: types.UInt160,
                           method: str,
                           args: vm.ArrayStackItem,
                           flags: contracts.native.CallFlags) -> None:
    if method.startswith('_'):
        raise ValueError("[System.Contract.Call] Method not allowed to start with _")

    target_contract = engine.snapshot.contracts.try_get(contract_hash, read_only=True)
    if target_contract is None:
        raise ValueError("[System.Contract.Call] Can't find target contract")

    current_contract = engine.snapshot.contracts.try_get(engine.current_scripthash, read_only=True)
    if current_contract and not current_contract.manifest.can_call(target_contract.manifest, method):
        raise ValueError(f"[System.Contract.Call] Not allowed to call target method '{method}' according to manifest")

    counter = engine._invocation_counter.get(target_contract.script_hash(), 0)
    engine._invocation_counter.update({target_contract.script_hash(): counter + 1})

    engine._get_invocation_state(engine.current_context).check_return_value = True

    state = engine.current_context
    calling_flags = state.call_flags

    contract_method_descriptor = target_contract.manifest.abi.get_method(method)
    if contract_method_descriptor is None:
        raise ValueError(f"[System.Contract.Call] requested target method '{method}' does not exist on target contract")

    arg_len = len(args)
    expected_len = len(contract_method_descriptor.parameters)
    if arg_len != expected_len:
        raise ValueError(
            f"[System.Contract.Call] Invalid number of contract arguments. Expected {expected_len} actual {arg_len}")  # noqa

    context_new = engine.load_script(vm.Script(target_contract.script))
    context_new.calling_script = state.script
    context_new.call_flags = flags & calling_flags

    if contracts.NativeContract.is_native(contract_hash):
        context_new.evaluation_stack.push(args)
        context_new.evaluation_stack.push(vm.ByteStringStackItem(method.encode('utf-8')))
    else:
        for item in reversed(args):
            context_new.evaluation_stack.push(item)
        context_new.ip = contract_method_descriptor.offset

    contract_method_descriptor = target_contract.manifest.abi.get_method("_initialize")
    if contract_method_descriptor is not None:
        engine.load_cloned_context(contract_method_descriptor.offset)


@register("System.Contract.Call", 1000000, contracts.native.CallFlags.ALLOW_CALL, False,
          [types.UInt160, str, vm.ArrayStackItem])
def contract_call(engine: contracts.ApplicationEngine,
                  contract_hash: types.UInt160,
                  method: str,
                  args: vm.ArrayStackItem) -> None:
    contract_call_internal(engine, contract_hash, method, args, contracts.native.CallFlags.ALL)


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
    contract_call_internal(engine, contract_hash, method, args, flags)


@register("System.Contract.IsStandard", 30000, contracts.native.CallFlags.NONE, True, [types.UInt160])
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
