from __future__ import annotations
import base64
import base58  # type: ignore
from . import NativeContract, register
from neo3 import contracts, vm
from typing import List
import orjson as json  # type: ignore


class StdLibContract(NativeContract):
    _MAX_INPUT_LENGTH = 1024

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
        return contracts.JSONSerializer.deserialize(json.loads(data.decode()), engine.reference_counter)

    @register("itoa", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def do_itoa_base10(self, value: vm.BigInteger) -> str:
        return self.do_itoa(value, 10)

    @register("itoa", contracts.CallFlags.NONE, cpu_price=1 << 12)
    def do_itoa(self, value: vm.BigInteger, base: int) -> str:
        if base == 10:
            return str(value)
        elif base == 16:
            return hex(int(value))[2:]
        else:
            raise ValueError("Invalid base specified")

    @register("atoi", contracts.CallFlags.NONE, cpu_price=1 << 6)
    def do_atoi_base10(self, value: str) -> int:
        return self.do_atoi(value, 10)

    @register("atoi", contracts.CallFlags.NONE, cpu_price=1 << 6)
    def do_atoi(self, value: str, base: int) -> int:
        if len(value) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Value exceeds maximum length of {self._MAX_INPUT_LENGTH}")
        if base != 10 and base != 16:
            raise ValueError("Invalid base specified")
        else:
            return int(value, base)

    @register("base64Encode", contracts.CallFlags.NONE, cpu_price=1 << 5)
    def base64_encode(self, data: bytes) -> str:
        if len(data) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Value exceeds maximum length of {self._MAX_INPUT_LENGTH}")
        return base64.b64encode(data).decode()

    @register("base64Decode", contracts.CallFlags.NONE, cpu_price=1 << 5)
    def base64_decode(self, data: bytes) -> bytes:
        if len(data) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Value exceeds maximum length of {self._MAX_INPUT_LENGTH}")
        return base64.b64decode(data)

    @register("base58Encode", contracts.CallFlags.NONE, cpu_price=1 << 13)
    def base58_encode(self, data: bytes) -> str:
        if len(data) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Value exceeds maximum length of {self._MAX_INPUT_LENGTH}")
        return base58.b58encode(data).decode()

    @register("base58Decode", contracts.CallFlags.NONE, cpu_price=1 << 10)
    def base58_decode(self, data: bytes) -> bytes:
        if len(data) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Value exceeds maximum length of {self._MAX_INPUT_LENGTH}")
        return base58.b58decode(data)

    @register("base58CheckEncode", contracts.CallFlags.NONE, cpu_price=1 << 16)
    def base58_check_encode(self, data: bytes) -> str:
        if len(data) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Value exceeds maximum length of {self._MAX_INPUT_LENGTH}")
        return base58.b58encode_check(data).decode()

    @register("base58CheckDecode", contracts.CallFlags.NONE, cpu_price=1 << 16)
    def base58_check_decode(self, data: bytes) -> bytes:
        if len(data) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Value exceeds maximum length of {self._MAX_INPUT_LENGTH}")
        return base58.b58decode_check(data)

    @register("memoryCompare", contracts.CallFlags.NONE, cpu_price=1 << 5)
    def memory_compare(self, str1: bytes, str2: bytes) -> int:
        if len(str1) > self._MAX_INPUT_LENGTH or len(str2) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"One or both arguments exceed maximum length of {self._MAX_INPUT_LENGTH}")
        if str1 < str2:
            return -1
        elif str1 == str2:
            return 0
        else:
            return 1

    @register("memorySearch", contracts.CallFlags.NONE, cpu_price=1 << 6)
    def memory_search1(self, memory: bytes, needle: bytes) -> int:
        return self.memory_search(memory, needle, 0, False)

    @register("memorySearch", contracts.CallFlags.NONE, cpu_price=1 << 6)
    def memory_search2(self, memory: bytes, needle: bytes, start: int) -> int:
        return self.memory_search(memory, needle, start, False)

    @register("memorySearch", contracts.CallFlags.NONE, cpu_price=1 << 6)
    def memory_search(self, memory: bytes, needle: bytes, start: int, backwards: bool) -> int:
        if len(memory) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Value exceeds maximum length of {self._MAX_INPUT_LENGTH}")

        if len(memory) == 0:
            return -1

        if backwards:
            return memory[:start].rfind(needle)
        else:
            idx = memory[start:].find(needle)
            return idx + start

    @register("stringSplit", contracts.CallFlags.NONE, cpu_price=1 << 8)
    def string_split1(self, data: str, separator: str) -> List[str]:
        if len(data) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Input value exceeds maximum length of {self._MAX_INPUT_LENGTH}")

        return data.split(separator)

    @register("stringSplit", contracts.CallFlags.NONE, cpu_price=1 << 8)
    def string_split2(self, data: str, separator: str, remove_empty_entries: bool) -> List[str]:
        if len(data) > self._MAX_INPUT_LENGTH:
            raise ValueError(f"Input value exceeds maximum length of {self._MAX_INPUT_LENGTH}")

        result = data.split(separator)
        if remove_empty_entries:
            result = [x for x in result if x != '']
        return result
