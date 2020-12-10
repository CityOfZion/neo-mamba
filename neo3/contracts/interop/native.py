from __future__ import annotations
from neo3 import contracts, storage
from neo3.contracts.interop import register


@register("Neo.Native.Deploy", 0, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False, [])
def deploy_native(engine: contracts.ApplicationEngine) -> None:
    if engine.snapshot.persisting_block.index != 0:
        raise ValueError("Can only deploy native contracts in the genenis block")

    for nc in contracts.NativeContract()._contracts.values():
        engine.snapshot.contracts.put(storage.ContractState(nc.script, nc.manifest))
        nc._initialize(engine)


@register("Neo.Native.Call", 0, contracts.native.CallFlags.NONE, False, [str])
def call_native(engine: contracts.ApplicationEngine, contract_name: str) -> None:
    contracts.NativeContract.get_contract(contract_name).invoke(engine)
