from __future__ import annotations
from collections import namedtuple
from neo3 import vm
from neo3.core import serialization
from typing import NamedTuple, Union, List, TypeVar, TYPE_CHECKING

StackItem_T = TypeVar('StackItem_T', bound=vm.StackItem)


class PlaceHolder(NamedTuple):
    type: vm.StackItemType
    count: int  # type: ignore


class BinarySerializer:

    @staticmethod
    def serialize(stack_item: StackItem_T, max_size: int) -> bytes:
        """
        Serialize a stack item.

        Note: Interop and Pointer stack items are not supported.

        Args:
            stack_item: the stack item to serialize.
            max_size: maximum byte array output size.

        Raises:
            ValueError: when a circular reference exists in a Map, Struct or Array.
            ValueError: if the output exceeds `max_size`.
        """
        unserialized = [stack_item]
        serialized: List[Union[StackItem_T, PlaceHolder]] = []
        with serialization.BinaryWriter() as writer:
            while len(unserialized) > 0:
                item = unserialized.pop()
                item_type = type(item)
                writer.write_uint8(int(item.get_type()))

                if item_type == vm.NullStackItem:
                    continue
                elif item_type == vm.BooleanStackItem:
                    writer.write_bool(item.to_boolean())
                elif item_type in [vm.IntegerStackItem, vm.ByteStringStackItem, vm.BufferStackItem]:
                    writer.write_var_bytes(item.to_array())
                elif item_type in [vm.ArrayStackItem, vm.StructStackItem]:
                    if item in serialized:
                        raise ValueError("Item already exists")
                    serialized.append(item)
                    writer.write_var_int(len(item))
                    for element in reversed(item):
                        unserialized.append(element)
                elif item_type == vm.MapStackItem:
                    if item in serialized:
                        raise ValueError("Item already exists")
                    serialized.append(item)
                    writer.write_var_int(len(item))
                    for k, v in reversed(item):
                        unserialized.append(v)
                        unserialized.append(k)
                else:
                    raise ValueError(f"Cannot serialize {item_type}")

            if len(writer) > max_size:
                raise ValueError("Output length exceeds max size")
            return writer.to_array()

    @staticmethod
    def deserialize(data: bytes,
                    max_size: int,
                    max_item_size: int,
                    reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        """
        Deserialize data into a stack item.

        Args:
            data: byte array of a serialized stack item.
            max_size: data reading limit for Array, Struct and Map types.
            max_item_size: data reading limit for ByteString or Buffer types.
            reference_counter: a valid reference counter instance. Get's passed into reference stack items.
        """
        if len(data) == 0:
            raise ValueError("Nothing to deserialize")

        deserialized = []
        to_deserialize = 1
        with serialization.BinaryReader(data) as reader:
            while not to_deserialize == 0:
                to_deserialize -= 1
                item_type = vm.StackItemType(reader.read_byte()[0])
                if item_type == vm.StackItemType.ANY:
                    deserialized.append(vm.NullStackItem())
                elif item_type == vm.StackItemType.BOOLEAN:
                    deserialized.append(vm.BooleanStackItem(reader.read_bool()))
                elif item_type == vm.StackItemType.INTEGER:
                    deserialized.append(
                        vm.IntegerStackItem(vm.BigInteger(
                            reader.read_var_bytes(vm.IntegerStackItem.MAX_SIZE)
                        ))
                    )
                elif item_type == vm.StackItemType.BYTESTRING:
                    deserialized.append(vm.ByteStringStackItem(reader.read_var_bytes(max_item_size)))
                elif item_type == vm.StackItemType.BUFFER:
                    deserialized.append(vm.BufferStackItem(reader.read_var_bytes(max_item_size)))
                elif item_type in [vm.StackItemType.ARRAY, vm.StackItemType.STRUCT]:
                    count = reader.read_var_int(max_size)
                    deserialized.append(PlaceHolder(item_type, count))
                    to_deserialize += count
                elif item_type == vm.StackItemType.MAP:
                    count = reader.read_var_int(max_size)
                    deserialized.append(PlaceHolder(item_type, count))
                    to_deserialize += count * 2
                else:
                    raise ValueError("Invalid format")

        temp = []
        while len(deserialized) > 0:
            item = deserialized.pop()
            if type(item) == PlaceHolder:
                if item.type == vm.StackItemType.ARRAY:
                    array = vm.ArrayStackItem(reference_counter)
                    for _ in range(0, item.count):
                        array.append(temp.pop())
                    item = array
                elif item.type == vm.StackItemType.STRUCT:
                    struct = vm.StructStackItem(reference_counter)
                    for _ in range(0, item.count):
                        struct.append(temp.pop())
                    item = struct
                elif item.type == vm.StackItemType.MAP:
                    m = vm.MapStackItem(reference_counter)
                    for _ in range(0, item.count):
                        k = temp.pop()
                        v = temp.pop()
                        m[k] = v
                    item = m
            temp.append(item)
        return temp.pop()
