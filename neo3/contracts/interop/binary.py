from neo3 import vm, contracts
from neo3.contracts.interop import register


@register("System.Binary.Serialize", 100000, contracts.TriggerType.ALL, contracts.native.CallFlags.NONE)
def binary_serialize(engine: vm.ApplicationEngine) -> bool:
    stack_item = engine.try_pop_item()
    if stack_item is None:
        return False
    serialized = contracts.BinarySerializer.serialize(stack_item, engine.MAX_ITEM_SIZE)
    engine.push(vm.ByteStringStackItem(serialized))
    return True


@register("System.Binary.Deserialize", 500000, contracts.TriggerType.ALL, contracts.native.CallFlags.NONE)
def binary_serialize(engine: vm.ApplicationEngine) -> bool:
    data = engine.try_pop_bytes()
    if not data:
        return False
    item = contracts.BinarySerializer.deserialize(data,
                                                  engine.MAX_STACK_SIZE,
                                                  engine.MAX_ITEM_SIZE,
                                                  engine.reference_counter)
    engine.push(item)
    return True
