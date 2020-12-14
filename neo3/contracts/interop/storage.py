from __future__ import annotations
from typing import Optional
from neo3 import contracts, storage
from neo3.core import types
from neo3.contracts.interop import register, IIterator, StorageIterator

MAX_STORAGE_KEY_SIZE = 64
STORAGE_PRICE = 100000
MAX_STORAGE_VALUE_SIZE = 65535


@register("System.Storage.GetContext", 400, contracts.native.CallFlags.ALLOW_STATES, False, [])
def get_context(engine: contracts.ApplicationEngine) -> storage.StorageContext:
    contract = engine.snapshot.contracts.try_get(engine.current_scripthash, read_only=True)
    if not contract.has_storage:
        raise ValueError("Cannot get context for smart contract without storage")
    return storage.StorageContext(engine.current_scripthash, False)


@register("System.Storage.GetReadOnlyContext", 400, contracts.native.CallFlags.ALLOW_STATES, False, [])
def get_read_only_context(engine: contracts.ApplicationEngine) -> storage.StorageContext:
    contract = engine.snapshot.contracts.try_get(engine.current_scripthash, read_only=True)
    if not contract.has_storage:
        raise ValueError("Cannot get context for smart contract without storage")
    return storage.StorageContext(contract.script_hash(), True)


@register("System.Storage.AsReadOnly", 400, contracts.native.CallFlags.ALLOW_STATES, False, [storage.StorageContext])
def context_as_read_only(engine: contracts.ApplicationEngine,
                         context: storage.StorageContext) -> storage.StorageContext:
    if not context.is_read_only:
        context = storage.StorageContext(context.script_hash, True)
    return context


@register("System.Storage.Get", 1000000, contracts.native.CallFlags.ALLOW_STATES, False,
          [storage.StorageContext, bytes])
def storage_get(engine: contracts.ApplicationEngine, context: storage.StorageContext, key: bytes) -> Optional[bytes]:
    storage_key = storage.StorageKey(context.script_hash, key)
    item = engine.snapshot.storages.try_get(storage_key, read_only=True)
    if item is not None:
        return item.value
    return None


@register("System.Storage.Find", 1000000, contracts.native.CallFlags.ALLOW_STATES, False,
          [storage.StorageContext, bytes])
def storage_find(engine: contracts.ApplicationEngine, context: storage.StorageContext, key: bytes) -> IIterator:
    it = StorageIterator(engine.snapshot.storages.find(context.script_hash, key))
    return it


def _storage_put_internal(engine: contracts.ApplicationEngine,
                          context: storage.StorageContext,
                          key: bytes,
                          value: bytes,
                          flags: storage.StorageFlags) -> None:
    if len(key) > MAX_STORAGE_KEY_SIZE:
        raise ValueError(f"Storage key length exceeds maximum of {MAX_STORAGE_KEY_SIZE}")
    if len(value) > MAX_STORAGE_VALUE_SIZE:
        raise ValueError(f"Storage value length exceeds maximum of {MAX_STORAGE_VALUE_SIZE}")
    if context.is_read_only:
        raise ValueError("Cannot persist to read-only storage context")

    storage_key = storage.StorageKey(context.script_hash, key)
    item = engine.snapshot.storages.try_get(storage_key, read_only=False)

    is_constant = storage.StorageFlags.CONSTANT in flags
    if item is None:
        new_data_len = len(key) + len(value)
        item = storage.StorageItem(b'', is_constant)
        engine.snapshot.storages.put(storage_key, item)
    else:
        if item.is_constant:
            raise ValueError("StorageItem is marked as constant")
        if len(value) <= len(item.value):
            new_data_len = 1
        else:
            new_data_len = len(value) - len(item.value)

    engine.add_gas(new_data_len * STORAGE_PRICE)
    item.value = value
    item.is_constant = is_constant


@register("System.Storage.Put", 0, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False,
          [storage.StorageContext, bytes, bytes])
def storage_put(engine: contracts.ApplicationEngine,
                context: storage.StorageContext,
                key: bytes,
                value: bytes) -> None:
    _storage_put_internal(engine, context, key, value, storage.StorageFlags.NONE)


@register("System.Storage.PutEx", 0, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False,
          [storage.StorageContext, bytes, bytes, storage.StorageFlags])
def storage_put_ex(engine: contracts.ApplicationEngine,
                   context: storage.StorageContext,
                   key: bytes,
                   value: bytes,
                   flags: storage.StorageFlags) -> None:
    _storage_put_internal(engine, context, key, value, flags)


@register("System.Storage.Delete", 1 * STORAGE_PRICE, contracts.native.CallFlags.ALLOW_MODIFIED_STATES, False,
          [storage.StorageContext, bytes])
def storage_delete(engine: contracts.ApplicationEngine, context: storage.StorageContext, key: bytes) -> None:
    if context.is_read_only:
        raise ValueError("Cannot delete from read-only storage context")
    storage_key = storage.StorageKey(context.script_hash, key)
    item = engine.snapshot.storages.try_get(storage_key)
    if item and item.is_constant:
        raise ValueError("Cannot delete a storage item that is marked constant")
    engine.snapshot.storages.delete(storage_key)
