from __future__ import annotations
import abc
from typing import Union, Iterator
from neo3 import vm, contracts
from neo3.contracts.interop import register


class IEnumerator(abc.ABC):
    @abc.abstractmethod
    def next(self) -> bool:
        """ Advance the iterator """

    @abc.abstractmethod
    def value(self) -> vm.StackItem:
        """ Get the current value """


class StorageKeyIterator(IEnumerator):
    def __init__(self, iterator: Iterator, remove_prefix: bytes):
        self.it = iterator
        self.remove_prefix = remove_prefix
        self._key = None
        self._value = None

    def next(self) -> bool:
        try:
            self._key, self._value = next(self.it)
        except StopIteration:
            self._key = None
            self._value = None
            return False
        return True

    def value(self) -> vm.StackItem:
        if self._key is None:
            raise ValueError("Cannot call 'value' without having advanced the iterator at least once")
        if len(self.remove_prefix) > 0:
            return vm.ByteStringStackItem(self._key.to_array().lstrip(self.remove_prefix))
        return vm.ByteStringStackItem(self._key.to_array())


class IIterator(IEnumerator, abc.ABC):
    @abc.abstractmethod
    def key(self) -> vm.PrimitiveType:
        """ Get the key value (e.g. for a map) or index for arrays """


class ArrayWrapper(IIterator):
    def __init__(self, array: vm.ArrayStackItem):
        super(ArrayWrapper, self).__init__()
        self.array = array
        self.index = -1

    def key(self) -> vm.PrimitiveType:
        if self.index < 0:
            raise ValueError("Cannot call 'key' without having advanced the iterator at least once")

        return vm.IntegerStackItem(self.index)

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


class MapWrapper(IIterator):
    def __init__(self, map_item: vm.MapStackItem):
        super(MapWrapper, self).__init__()
        self.it = iter(map_item)
        self._key = None
        self._value = None

    def key(self) -> vm.PrimitiveType:
        if self._key is None:
            raise ValueError("Cannot call 'key' without having advanced the iterator at least once")

        return self._key

    def value(self) -> vm.StackItem:
        if self._value is None:
            raise ValueError("Cannot call 'value' without having advanced the iterator at least once")
        return self._value

    def next(self) -> bool:
        try:
            self._key, self._value = next(self.it)
        except StopIteration:
            self._key = None
            self._value = None
            return False
        return True


class ByteArrayWrapper(IIterator):
    def __init__(self, value: Union[vm.BufferStackItem, vm.PrimitiveType]):
        self.array = value.to_array()
        self.index = -1

    def key(self) -> vm.PrimitiveType:
        if self.index < 0:
            raise ValueError("Cannot call 'key' without having advanced the iterator at least once")

        return vm.IntegerStackItem(self.index)

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


class IteratorKeysWrapper(IEnumerator):
    def __init__(self, iterator: IIterator):
        self.it = iterator

    def next(self) -> bool:
        return self.it.next()

    def value(self) -> vm.StackItem:
        return self.it.key()


class IteratorValuesWrapper(IEnumerator):
    def __init__(self, iterator: IIterator):
        self.it = iterator

    def next(self) -> bool:
        return self.it.next()

    def value(self) -> vm.StackItem:
        return self.it.value()


class StorageIterator(IIterator):
    def __init__(self, generator):
        self.it = generator
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
        return vm.ByteStringStackItem(self._pair[1].value)

    def key(self) -> vm.PrimitiveType:
        if self._pair is None:
            raise ValueError("Cannot call 'key' without having advanced the iterator at least once")
        return vm.ByteStringStackItem(self._pair[0].key)


@register("System.Enumerator.Create", 1 << 4, contracts.native.CallFlags.NONE, [vm.StackItem])
def enumerator_create(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> IEnumerator:
    if isinstance(stack_item, vm.ArrayStackItem):
        return ArrayWrapper(stack_item)
    elif isinstance(stack_item, (vm.BufferStackItem, vm.PrimitiveType)):
        return ByteArrayWrapper(stack_item)
    else:
        raise ValueError(f"Cannot create iterator from unsupported type: {type(stack_item)}")


@register("System.Enumerator.Next", 1 << 15, contracts.native.CallFlags.NONE, [IEnumerator])
def enumerator_next(engine: contracts.ApplicationEngine, it: IEnumerator) -> bool:
    return it.next()


@register("System.Enumerator.Value", 1 << 4, contracts.native.CallFlags.NONE, [IEnumerator])
def enumerator_value(engine: contracts.ApplicationEngine, it: IEnumerator) -> vm.StackItem:
    return it.value()


@register("System.Iterator.Create", 400, contracts.native.CallFlags.NONE, [vm.StackItem])
def iterator_create(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> IIterator:
    if isinstance(stack_item, vm.ArrayStackItem):
        return ArrayWrapper(stack_item)
    elif isinstance(stack_item, vm.MapStackItem):
        return MapWrapper(stack_item)
    elif isinstance(stack_item, (vm.BufferStackItem, vm.PrimitiveType)):
        return ByteArrayWrapper(stack_item)
    else:
        raise ValueError(f"Cannot create iterator from unsupported type: {type(stack_item)}")


@register("System.Iterator.Key", 1 << 4, contracts.native.CallFlags.NONE, [IIterator])
def iterator_key(engine: contracts.ApplicationEngine, iterator: IIterator) -> vm.PrimitiveType:
    return iterator.key()


@register("System.Iterator.Keys", 1 << 4, contracts.native.CallFlags.NONE, [IIterator])
def iterator_keys(engine: contracts.ApplicationEngine, iterator: IIterator) -> IEnumerator:
    return IteratorKeysWrapper(iterator)


@register("System.Iterator.Values", 1 << 4, contracts.native.CallFlags.NONE, [IIterator])
def iterator_values(engine: contracts.ApplicationEngine, iterator: IIterator) -> IEnumerator:
    return IteratorValuesWrapper(iterator)
