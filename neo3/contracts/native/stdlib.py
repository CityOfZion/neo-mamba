from __future__ import annotations
import base64
import base58  # type: ignore
from . import NativeContract, register
from neo3 import contracts, vm


class StdLibContract(NativeContract):

    _service_name = "StdLib"
    _id = -2

    def init(self):
        super(StdLibContract, self).init()

    @register("serialize", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def binary_serialize(self, engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> bytes:
        return contracts.BinarySerializer.serialize(stack_item, engine.MAX_ITEM_SIZE)

    @register("deserialize", contracts.CallFlags.NONE, cpu_price=1 << 14)
    def binary_deserialize(self, engine: contracts.ApplicationEngine, data: bytes) -> vm.StackItem:
        return contracts.BinarySerializer.deserialize(data, engine.MAX_ITEM_SIZE, engine.reference_counter)

    @register("jsonSerialize", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def json_serialize(self, engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> bytes:
        return bytes(contracts.JSONSerializer.serialize(stack_item, engine.MAX_ITEM_SIZE), 'utf-8')

    @register("jsonDeserialize", contracts.CallFlags.NONE, cpu_price=1 << 14)
    def json_deserialize(self, engine: contracts.ApplicationEngine, data: bytes) -> vm.StackItem:
        return contracts.JSONSerializer.deserialize(data.decode(), engine.reference_counter)

    @register("itoa", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def do_itoa(self, value: vm.BigInteger, base: int) -> str:
        if base == 10:
            return str(value)
        elif base == 16:
            return hex(int(value))[2:]
        else:
            raise ValueError("Invalid base specified")

    @register("atoi", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def do_atoi(self, value: str, base: int) -> int:
        if base != 10 and base != 16:
            raise ValueError("Invalid base specified")
        else:
            return int(value, base)

    @register("base64Encode", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def base64_encode(self, data: bytes) -> str:
        return base64.b64encode(data).decode()

    @register("base64Decode", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def base64_decode(self, data: bytes) -> bytes:
        return base64.b64decode(data)

    @register("base58Encode", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def base58_encode(self, data: bytes) -> str:
        return base58.b58encode(data).decode()

    @register("base58Decode", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def base58_decode(self, data: bytes) -> bytes:
        return base58.b58decode(data)
