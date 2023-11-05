"""
This module holds helper functions for data that has been serialized using the StdLib native contract
"""

from neo3 import vm
from typing import NamedTuple, cast, Any
from neo3.core import serialization, types


class PlaceHolder(NamedTuple):
    type: vm.StackItemType
    count: int  # type: ignore


def binary_deserialize(data: bytes):
    """
    Deserialize data that has been serialized using StdLib.serialize()

    This is the equivalent of the StdLib.deserialize()
    https://github.com/neo-project/neo/blob/29fab8d3f8f21046a95232b29053c08f9d81f0e3/src/Neo/SmartContract/Native/StdLib.cs#L39
    and can be used to deserialize data from smart contract storage that was serialized when stored.
    """
    # https://github.com/neo-project/neo-vm/blob/859417ad8ff25c2e4a432b6b5b628149875b3eb9/src/Neo.VM/ExecutionEngineLimits.cs#L39
    max_size = 0xFFFF * 2
    if len(data) == 0:
        raise ValueError("Nothing to deserialize")

    deserialized: list[Any | PlaceHolder] = []
    to_deserialize = 1
    with serialization.BinaryReader(data) as reader:
        while not to_deserialize == 0:
            to_deserialize -= 1
            item_type = vm.StackItemType(reader.read_byte()[0])
            if item_type == vm.StackItemType.ANY:
                deserialized.append(None)
            elif item_type == vm.StackItemType.BOOLEAN:
                deserialized.append(reader.read_bool())
            elif item_type == vm.StackItemType.INTEGER:
                # https://github.com/neo-project/neo-vm/blob/859417ad8ff25c2e4a432b6b5b628149875b3eb9/src/Neo.VM/Types/Integer.cs#L27
                deserialized.append(int(types.BigInteger(reader.read_var_bytes(32))))
            elif item_type in [vm.StackItemType.BYTESTRING, vm.StackItemType.BUFFER]:
                deserialized.append(reader.read_var_bytes(len(data)))
            elif item_type in [vm.StackItemType.ARRAY, vm.StackItemType.STRUCT]:
                count = reader.read_var_int(max_size)
                deserialized.append(PlaceHolder(item_type, count))
                to_deserialize += count
            elif item_type == vm.StackItemType.MAP:
                count = reader.read_var_int(max_size)
                deserialized.append(PlaceHolder(item_type, count))
                to_deserialize += count * 2
            else:
                raise ValueError("unreachable")

    temp: list = []
    while len(deserialized) > 0:
        item = deserialized.pop()
        if type(item) == PlaceHolder:
            item = cast(PlaceHolder, item)
            if item.type == vm.StackItemType.ARRAY:
                array = []
                for _ in range(0, item.count):
                    array.append(temp.pop())
                temp.append(array)
            elif item.type == vm.StackItemType.STRUCT:
                struct = []
                for _ in range(0, item.count):
                    struct.append(temp.pop())
                temp.append(struct)
            elif item.type == vm.StackItemType.MAP:
                m = dict()
                for _ in range(0, item.count):
                    k = temp.pop()
                    v = temp.pop()
                    m[k] = v
                temp.append(m)
        else:
            temp.append(item)
    return temp.pop()
