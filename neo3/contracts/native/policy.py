from __future__ import annotations
from . import NativeContract, register
from neo3.core import types
from neo3 import storage, contracts, vm


class PolicyContract(NativeContract):
    _id: int = -7

    DEFAULT_EXEC_FEE_FACTOR = 30
    MAX_EXEC_FEE_FACTOR = 1000
    DEFAULT_FEE_PER_BYTE = 1000
    DEFAULT_STORAGE_PRICE = 100000
    MAX_STORAGE_PRICE = 10000000

    key_fee_per_byte = storage.StorageKey(_id, b'\x0A')
    key_blocked_account = storage.StorageKey(_id, b'\x0F')
    key_exec_fee_factor = storage.StorageKey(_id, b'\x12')
    key_storage_price = storage.StorageKey(_id, b'\x13')

    _storage_price = 0

    def init(self):
        super(PolicyContract, self).init()

    @register("getFeePerByte", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_fee_per_byte(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum fee per byte of storage.

        Returns:
            int: maximum fee.
        """
        data = snapshot.storages.get(self.key_fee_per_byte, read_only=True)
        return int.from_bytes(data.value, 'little', signed=True)

    @register("isBlocked", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def is_blocked(self, snapshot: storage.Snapshot, account: types.UInt160) -> bool:
        """
        Check if the account is blocked

        Transaction from blocked accounts will be rejected by the consensus nodes.
        """

        si = snapshot.storages.try_get(self.key_blocked_account + account.to_array(), read_only=True)
        if si is None:
            return False
        else:
            return True

    @register("setFeePerByte", contracts.CallFlags.STATES, cpu_price=1 << 15)
    def _set_fee_per_byte(self, engine: contracts.ApplicationEngine, value: int) -> None:
        """
        Should only be called through syscalls
        """
        if value < 0 or value > 100000000:
            raise ValueError("New value exceeds FEE_PER_BYTE limits")

        if not self._check_committee(engine):
            raise ValueError("Check committee failed")

        storage_item = engine.snapshot.storages.get(self.key_fee_per_byte, read_only=False)
        storage_item.value = self._int_to_bytes(value)

    @register("blockAccount", contracts.CallFlags.STATES, cpu_price=1 << 15)
    def _block_account(self, engine: contracts.ApplicationEngine, account: types.UInt160) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committee(engine):
            return False
        storage_key = self.key_blocked_account + account.to_array()
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            storage_item = storage.StorageItem(b'\x00')
            engine.snapshot.storages.update(storage_key, storage_item)
        else:
            return False

        return True

    @register("unblockAccount", contracts.CallFlags.STATES, cpu_price=1 << 15)
    def _unblock_account(self, engine: contracts.ApplicationEngine, account: types.UInt160) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committee(engine):
            return False
        storage_key = self.key_blocked_account + account.to_array()
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            return False
        else:
            engine.snapshot.storages.delete(storage_key)
        return True

    @register("getExecFeeFactor", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_exec_fee_factor(self, snapshot: storage.Snapshot) -> int:
        storage_item = snapshot.storages.get(self.key_exec_fee_factor, read_only=True)
        return int(vm.BigInteger(storage_item.value))

    @register("getStoragePrice", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_storage_price(self, snapshot: storage.Snapshot) -> int:
        if self._storage_price:
            return self._storage_price

        storage_item = snapshot.storages.get(self.key_storage_price, read_only=True)
        return int(vm.BigInteger(storage_item.value))

    @register("setExecFeeFactor", contracts.CallFlags.STATES, cpu_price=1 << 15)
    def _set_exec_fee_factor(self, engine: contracts.ApplicationEngine, value: int) -> None:
        if value == 0 or value > self.MAX_EXEC_FEE_FACTOR:
            raise ValueError("New exec fee value out of range")
        if not self._check_committee(engine):
            raise ValueError("Check committee failed")
        storage_item = engine.snapshot.storages.get(self.key_exec_fee_factor, read_only=False)
        storage_item.value = vm.BigInteger(value).to_array()

    @register("setStoragePrice", contracts.CallFlags.STATES, cpu_price=1 << 15)
    def _set_storage_price(self, engine: contracts.ApplicationEngine, value: int) -> None:
        if value == 0 or value > self.MAX_STORAGE_PRICE:
            raise ValueError("New storage price value out of range")
        if not self._check_committee(engine):
            raise ValueError("Check committee failed")
        storage_item = engine.snapshot.storages.get(self.key_storage_price, read_only=False)
        storage_item.value = vm.BigInteger(value).to_array()

        self._storage_price = value

    def _int_to_bytes(self, value: int) -> bytes:
        return value.to_bytes((value.bit_length() + 7 + 1) // 8, 'little', signed=True)  # +1 for signed

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        def _to_si(value: int) -> storage.StorageItem:
            return storage.StorageItem(self._int_to_bytes(value))

        engine.snapshot.storages.put(self.key_fee_per_byte, _to_si(self.DEFAULT_FEE_PER_BYTE))
        engine.snapshot.storages.put(self.key_exec_fee_factor, _to_si(self.DEFAULT_EXEC_FEE_FACTOR))
        engine.snapshot.storages.put(self.key_storage_price, _to_si(self.DEFAULT_STORAGE_PRICE))
