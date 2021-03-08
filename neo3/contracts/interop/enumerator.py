from __future__ import annotations
import abc
from typing import Union, Iterator, cast
from neo3 import vm, contracts
from neo3.contracts.interop import register


class IIterator(abc.ABC):
    @abc.abstractmethod
    def next(self) -> bool:
        """ Advance the iterator """

    @abc.abstractmethod
    def value(self) -> vm.StackItem:
        """ Get the current value """


class ArrayWrapper(IIterator):
    def __init__(self, array: vm.ArrayStackItem):
        super(ArrayWrapper, self).__init__()
        self.array = array
        self.index = -1

    def next(self) -> bool:
        next_index = self.index + 1
        if next_index >= len(self.array):
            return False
        self.index = next_index
        return True

    def value(self) -> vm.StackItem:
        if self.index < 0:
            raise ValueError("Cannot call 'value' without having advanced the iterator at least once")
        return self.array[self.index]


class ByteArrayWrapper(IIterator):
    def __init__(self, value: Union[vm.BufferStackItem, vm.PrimitiveType]):
        self.array = value.to_array()
        self.index = -1

    def next(self) -> bool:
        next_index = self.index + 1
        if next_index >= len(self.array):
            return False
        self.index = next_index
        return True

    def value(self) -> vm.StackItem:
        if self.index < 0:
            raise ValueError("Cannot call 'value' without having advanced the iterator at least once")
        return vm.IntegerStackItem(self.array[self.index])


class MapWrapper(IIterator):
    def __init__(self, map_item: vm.MapStackItem, reference_counter: vm.ReferenceCounter):
        super(MapWrapper, self).__init__()
        self.it = iter(map_item)
        self.reference_counter = reference_counter
        self._key = None
        self._value = None

    def value(self) -> vm.StackItem:
        if self._value is None:
            raise ValueError("Cannot call 'value' without having advanced the iterator at least once")
        return vm.StructStackItem(self.reference_counter, [self._key, self._value])

    def next(self) -> bool:
        try:
            self._key, self._value = next(self.it)
        except StopIteration:
            self._key = None
            self._value = None
            return False
        return True


class StorageIterator(IIterator):
    def __init__(self, generator, options: contracts.FindOptions, reference_counter: vm.ReferenceCounter):
        self.it = generator
        self.options = options
        self.reference_counter = reference_counter
        self._pair = None

    def next(self) -> bool:
        try:
            self._pair = next(self.it)
            return True
        except StopIteration:
            self._pair = None
            return False

    def value(self) -> vm.StackItem:
        if self._pair is None:
            raise ValueError("Cannot call 'value' without having advanced the iterator at least once")
        key = self._pair[0].key
        value = self._pair[1].value
        if contracts.FindOptions.REMOVE_PREFIX in self.options:
            key = key[1:]

        if contracts.FindOptions.DESERIALIZE_VALUES in self.options:
            item: vm.StackItem = contracts.BinarySerializer.deserialize(value, 1024, len(value), self.reference_counter)
        else:
            item = vm.ByteStringStackItem(value)

        if contracts.FindOptions.PICK_FIELD0 in self.options:
            item = cast(vm.ArrayStackItem, item)
            item = item[0]
        elif contracts.FindOptions.PICK_FIELD1 in self.options:
            item = cast(vm.ArrayStackItem, item)
            item = item[1]

        if contracts.FindOptions.KEYS_ONLY in self.options:
            return vm.ByteStringStackItem(key)

        if contracts.FindOptions.VALUES_ONLY in self.options:
            return vm.ByteStringStackItem(value)

        return vm.StructStackItem(self.reference_counter,
                                  [
                                      vm.ByteStringStackItem(self._pair[0].key),
                                      vm.ByteStringStackItem(self._pair[1].value)
                                  ])


@register("System.Iterator.Create", 1 << 4, contracts.CallFlags.NONE)
def iterator_create(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> IIterator:
    if isinstance(stack_item, vm.ArrayStackItem):
        return ArrayWrapper(stack_item)
    elif isinstance(stack_item, vm.MapStackItem):
        return MapWrapper(stack_item, engine.reference_counter)
    elif isinstance(stack_item, (vm.BufferStackItem, vm.PrimitiveType)):
        return ByteArrayWrapper(stack_item)
    else:
        raise ValueError(f"Cannot create iterator from unsupported type: {type(stack_item)}")


@register("System.Iterator.Next", 1 << 15, contracts.CallFlags.NONE)
def iterator_next(engine: contracts.ApplicationEngine, iterator: IIterator) -> bool:
    return iterator.next()


@register("System.Iterator.Value", 1 << 4, contracts.CallFlags.NONE)
def iterator_value(engine: contracts.ApplicationEngine, iterator: IIterator) -> vm.StackItem:
    return iterator.value()
