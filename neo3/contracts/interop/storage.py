from __future__ import annotations
from typing import Optional
from neo3 import contracts, storage
from neo3.contracts.interop import register, IIterator, StorageIterator

MAX_STORAGE_KEY_SIZE = 64
MAX_STORAGE_VALUE_SIZE = 65535


@register("System.Storage.GetContext", 1 << 4, contracts.CallFlags.READ_STATES)
def get_context(engine: contracts.ApplicationEngine) -> storage.StorageContext:
    contract = contracts.ManagementContract().get_contract(engine.snapshot, engine.current_scripthash)
    if contract is None:
        raise ValueError("Contract not deployed")
    return storage.StorageContext(contract.id, False)


@register("System.Storage.GetReadOnlyContext", 1 << 4, contracts.CallFlags.READ_STATES)
def get_read_only_context(engine: contracts.ApplicationEngine) -> storage.StorageContext:
    contract = contracts.ManagementContract().get_contract(engine.snapshot, engine.current_scripthash)
    if contract is None:
        raise ValueError("Contract not deployed")
    return storage.StorageContext(contract.id, True)


@register("System.Storage.AsReadOnly", 1 << 4, contracts.CallFlags.READ_STATES)
def context_as_read_only(engine: contracts.ApplicationEngine,
                         context: storage.StorageContext) -> storage.StorageContext:
    if not context.is_read_only:
        context = storage.StorageContext(context.id, True)
    return context


@register("System.Storage.Get", 1 << 15, contracts.CallFlags.READ_STATES)
def storage_get(engine: contracts.ApplicationEngine, context: storage.StorageContext, key: bytes) -> Optional[bytes]:
    storage_key = storage.StorageKey(context.id, key)
    item = engine.snapshot.storages.try_get(storage_key, read_only=True)
    if item is not None:
        return item.value
    return None


@register("System.Storage.Find", 1 << 15, contracts.CallFlags.READ_STATES)
def storage_find(engine: contracts.ApplicationEngine,
                 context: storage.StorageContext,
                 key: bytes,
                 options: contracts.FindOptions) -> IIterator:
    opt = contracts.FindOptions
    if opt.KEYS_ONLY in options and (
            opt.VALUES_ONLY in options
            or opt.DESERIALIZE_VALUES in options
            or opt.PICK_FIELD0 in options
            or opt.PICK_FIELD1 in options):
        raise ValueError("KEYS_ONLY and (VALUES_ONLY || DESERIALIZE_VALUES || PICK_FIELD0 || PICK_FIELD1) are mutually "
                         "exclusive")
    if opt.VALUES_ONLY in options and (opt.KEYS_ONLY in options or opt.REMOVE_PREFIX in options):
        raise ValueError("VALUES_ONLY and (KEYS_ONLY || REMOVE_PREFIX) are mutually exclusive")
    if opt.PICK_FIELD0 in options and opt.PICK_FIELD1 in options:
        raise ValueError("PICK_FIELD0 and PICK_FIELD1 are mutually exclusive")
    if (opt.PICK_FIELD0 in options or opt.PICK_FIELD1 in options) and opt.DESERIALIZE_VALUES not in options:
        raise ValueError("Can't use PICK_FIELD option without DESERIALIZE_VALUES")

    prefix_key = context.id.to_bytes(4, 'little', signed=True) + key
    it = StorageIterator(engine.snapshot.storages.find(prefix_key), len(key), options, engine.reference_counter)
    return it


@register("System.Storage.Put", 1 << 15, contracts.CallFlags.WRITE_STATES)
def storage_put(engine: contracts.ApplicationEngine, context: storage.StorageContext, key: bytes, value: bytes) -> None:
    if len(key) > MAX_STORAGE_KEY_SIZE:
        raise ValueError(f"Storage key length exceeds maximum of {MAX_STORAGE_KEY_SIZE}")
    if len(value) > MAX_STORAGE_VALUE_SIZE:
        raise ValueError(f"Storage value length exceeds maximum of {MAX_STORAGE_VALUE_SIZE}")
    if context.is_read_only:
        raise ValueError("Cannot persist to read-only storage context")

    storage_key = storage.StorageKey(context.id, key)
    item = engine.snapshot.storages.try_get(storage_key, read_only=False)

    if item is None:
        new_data_len = len(key) + len(value)
        item = storage.StorageItem(b'')
        engine.snapshot.storages.put(storage_key, item)
    else:
        if len(value) == 0:
            new_data_len = 0
        elif len(value) <= len(item.value):
            new_data_len = (len(value) - 1) // 4 + 1
        elif len(item.value) == 0:
            new_data_len = len(value)
        else:
            new_data_len = (len(item.value) - 1) // 4 + 1 + len(value) - len(item.value)

    engine.add_gas(new_data_len * engine.STORAGE_PRICE)
    item.value = value


@register("System.Storage.Delete", 1 << 15, contracts.CallFlags.WRITE_STATES)
def storage_delete(engine: contracts.ApplicationEngine, context: storage.StorageContext, key: bytes) -> None:
    if context.is_read_only:
        raise ValueError("Cannot delete from read-only storage context")
    storage_key = storage.StorageKey(context.id, key)
    engine.snapshot.storages.delete(storage_key)
