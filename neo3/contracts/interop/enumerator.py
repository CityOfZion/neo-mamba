from __future__ import annotations
import abc
from typing import cast
from neo3 import vm, contracts
from neo3.contracts.interop import register


class IIterator(abc.ABC):
    @abc.abstractmethod
    def next(self) -> bool:
        """ Advance the iterator """

    @abc.abstractmethod
    def value(self) -> vm.StackItem:
        """ Get the current value """


class StorageIterator(IIterator):
    def __init__(self,
                 generator,
                 prefix_length: int,
                 options: contracts.FindOptions,
                 reference_counter: vm.ReferenceCounter):
        self.it = generator
        self.prefix_len = prefix_length
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
            key = key[self.prefix_len:]

        if contracts.FindOptions.DESERIALIZE_VALUES in self.options:
            item: vm.StackItem = contracts.BinarySerializer.deserialize(value, 1024, self.reference_counter)
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

        return vm.StructStackItem(self.reference_counter, [vm.ByteStringStackItem(key), item])


@register("System.Iterator.Next", 1 << 15, contracts.CallFlags.NONE)
def iterator_next(engine: contracts.ApplicationEngine, iterator: IIterator) -> bool:
    return iterator.next()


@register("System.Iterator.Value", 1 << 4, contracts.CallFlags.NONE)
def iterator_value(engine: contracts.ApplicationEngine, iterator: IIterator) -> vm.StackItem:
    return iterator.value()
