from __future__ import annotations
from neo3 import vm, contracts
from neo3.contracts.interop import register


@register("System.Binary.Serialize", 100000, contracts.native.CallFlags.NONE, True, [vm.StackItem])
def binary_serialize(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> bytes:
    return contracts.BinarySerializer.serialize(stack_item, engine.MAX_ITEM_SIZE)


@register("System.Binary.Deserialize", 500000, contracts.native.CallFlags.NONE, True, [bytes])
def binary_serialize(engine: contracts.ApplicationEngine, data: bytes) -> vm.StackItem:
    return contracts.BinarySerializer.deserialize(data,
                                                  engine.MAX_STACK_SIZE,
                                                  engine.MAX_ITEM_SIZE,
                                                  engine.reference_counter)
