from __future__ import annotations
import base64
import base58  # type: ignore
from neo3 import vm, contracts
from neo3.contracts.interop import register


@register("System.Binary.Serialize", 1 << 12, contracts.CallFlags.NONE)
def binary_serialize(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> bytes:
    return contracts.BinarySerializer.serialize(stack_item, engine.MAX_ITEM_SIZE)


@register("System.Binary.Deserialize", 1 << 14, contracts.CallFlags.NONE)
def binary_derialize(engine: contracts.ApplicationEngine, data: bytes) -> vm.StackItem:
    return contracts.BinarySerializer.deserialize(data,
                                                  engine.MAX_STACK_SIZE,
                                                  engine.MAX_ITEM_SIZE,
                                                  engine.reference_counter)


@register("System.Binary.Base64Encode", 1 << 12, contracts.CallFlags.NONE)
def base64_encode(engine: contracts.ApplicationEngine, data: bytes) -> str:
    return base64.b64encode(data).decode()


@register("System.Binary.Base64Decode", 1 << 12, contracts.CallFlags.NONE)
def base64_decode(engine: contracts.ApplicationEngine, data: bytes) -> bytes:
    return base64.b64decode(data)


@register("System.Binary.Base58Encode", 1 << 12, contracts.CallFlags.NONE)
def base58_encode(engine: contracts.ApplicationEngine, data: bytes) -> str:
    return base58.b58encode(data).decode()


@register("System.Binary.Base58Decode", 1 << 12, contracts.CallFlags.NONE)
def base58_decode(engine: contracts.ApplicationEngine, data: bytes) -> bytes:
    return base58.b58decode(data)


@register("System.Binary.Itoa", 1 << 12, contracts.CallFlags.NONE)
def do_itoa(engine: contracts.ApplicationEngine, value: vm.BigInteger, base: int) -> str:
    if base == 10:
        return str(value)
    elif base == 16:
        return hex(int(value))[2:]
    else:
        raise ValueError("Invalid base specified")


@register("System.Binary.Atoi", 1 << 12, contracts.CallFlags.NONE)
def do_atoi(engine: contracts.ApplicationEngine, value: str, base: int) -> int:
    if base != 10 and base != 16:
        raise ValueError("Invalid base specified")
    else:
        return int(value, base)
