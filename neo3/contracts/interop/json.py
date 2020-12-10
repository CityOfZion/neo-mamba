from __future__ import annotations
from neo3 import vm, contracts
from neo3.contracts.interop import register


@register("System.Json.Serialize", 100000, contracts.native.CallFlags.NONE, True, [vm.StackItem])
def json_serialize(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> bytes:
    return bytes(contracts.JSONSerializer.serialize(stack_item, engine.MAX_ITEM_SIZE), 'utf-8')


@register("System.Json.Deserialize", 100000, contracts.native.CallFlags.NONE, True, [bytes])
def json_deserialize(engine: contracts.ApplicationEngine, data: bytes) -> vm.StackItem:
    return contracts.JSONSerializer.deserialize(data.decode(), engine.reference_counter)
