from __future__ import annotations
from . import NativeContract
from neo3.core import types
from neo3 import storage, contracts, vm
from neo3.network import message


class PolicyContract(NativeContract):
    _id: int = -5

    DEFAULT_EXEC_FEE_FACTOR = 30
    MAX_EXEC_FEE_FACTOR = 1000
    DEFAULT_STORAGE_PRICE = 100000
    MAX_STORAGE_PRICE = 10000000

    key_max_transactions_per_block = storage.StorageKey(_id, b'\x17')
    key_fee_per_byte = storage.StorageKey(_id, b'\x0A')
    key_blocked_account = storage.StorageKey(_id, b'\x0F')
    key_max_block_size = storage.StorageKey(_id, b'\x0C')
    key_max_block_system_fee = storage.StorageKey(_id, b'\x11')
    key_exec_fee_factor = storage.StorageKey(_id, b'\x12')
    key_storage_price = storage.StorageKey(_id, b'\x13')

    _storage_price = 0

    def init(self):
        super(PolicyContract, self).init()

        self._register_contract_method(self.get_max_block_size,
                                       "getMaxBlockSize",
                                       1000000,
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       )
        self._register_contract_method(self.get_max_transactions_per_block,
                                       "getMaxTransactionsPerBlock",
                                       1000000,
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       )
        self._register_contract_method(self.get_max_block_system_fee,
                                       "getMaxBlockSystemFee",
                                       1000000,
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       )
        self._register_contract_method(self.get_fee_per_byte,
                                       "getFeePerByte",
                                       1000000,
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       )
        self._register_contract_method(self.is_blocked,
                                       "isBlocked",
                                       1000000,
                                       parameter_names=["account"],
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       )
        self._register_contract_method(self._block_account,
                                       "blockAccount",
                                       3000000,
                                       parameter_names=["account"],
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._unblock_account,
                                       "unblockAccount",
                                       3000000,
                                       parameter_names=["account"],
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_max_block_size,
                                       "setMaxBlockSize",
                                       3000000,
                                       parameter_names=["value"],
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_max_transactions_per_block,
                                       "setMaxTransactionsPerBlock",
                                       3000000,
                                       parameter_names=["value"],
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_max_block_system_fee,
                                       "setMaxBlockSystemFee",
                                       3000000,
                                       parameter_names=["value"],
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_fee_per_byte,
                                       "setFeePerByte",
                                       3000000,
                                       parameter_names=["value"],
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self.get_exec_fee_factor,
                                       "getExecFeeFactor",
                                       1000000,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )
        self._register_contract_method(self.get_storage_price,
                                       "getStoragePrice",
                                       1000000,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )
        self._register_contract_method(self._set_exec_fee_factor,
                                       "setExecFeeFactor",
                                       3000000,
                                       parameter_names=["value"],
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )
        self._register_contract_method(self._set_storage_price,
                                       "setStoragePrice",
                                       3000000,
                                       parameter_names=["value"],
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )

    def _int_to_bytes(self, value: int) -> bytes:
        return value.to_bytes((value.bit_length() + 7 + 1) // 8, 'little', signed=True)  # +1 for signed

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        def _to_si(value: int) -> storage.StorageItem:
            return storage.StorageItem(self._int_to_bytes(value))

        engine.snapshot.storages.put(self.key_max_transactions_per_block, _to_si(512))
        engine.snapshot.storages.put(self.key_fee_per_byte, _to_si(1000))
        engine.snapshot.storages.put(self.key_max_block_size, _to_si(1024 * 256))
        engine.snapshot.storages.put(self.key_max_block_system_fee, _to_si(int(contracts.GasToken().factor * 9000)))
        engine.snapshot.storages.put(self.key_exec_fee_factor, _to_si(self.DEFAULT_EXEC_FEE_FACTOR))
        engine.snapshot.storages.put(self.key_storage_price, _to_si(self.DEFAULT_STORAGE_PRICE))

    def get_max_block_size(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum size of a Block.

        Returns:
            int: maximum number of bytes.
        """
        data = snapshot.storages.get(
            self.key_max_block_size,
            read_only=True
        )
        return int.from_bytes(data.value, 'little', signed=True)

    def get_max_transactions_per_block(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum number of transaction in a Block.

        Returns:
            int: maximum number of transaction.
        """
        data = snapshot.storages.get(self.key_max_transactions_per_block, read_only=True)
        return int.from_bytes(data.value, 'little', signed=True)

    def get_max_block_system_fee(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum system fee of a Block.

        Returns:
            int: maximum system fee.
        """
        data = snapshot.storages.get(self.key_max_block_system_fee, read_only=True)
        return int.from_bytes(data.value, 'little', signed=True)

    def get_fee_per_byte(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum fee per byte of storage.

        Returns:
            int: maximum fee.
        """
        data = snapshot.storages.get(self.key_fee_per_byte, read_only=True)
        return int.from_bytes(data.value, 'little', signed=True)

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

    def _set_max_block_size(self, engine: contracts.ApplicationEngine, value: int) -> None:
        """
        Should only be called through syscalls
        """
        if value >= message.Message.PAYLOAD_MAX_SIZE:
            raise ValueError("New blocksize exceeds PAYLOAD_MAX_SIZE")

        if not self._check_committee(engine):
            raise ValueError("Check committee failed")

        storage_item = engine.snapshot.storages.get(self.key_max_block_size, read_only=False)
        storage_item.value = self._int_to_bytes(value)

    def _set_max_transactions_per_block(self, engine: contracts.ApplicationEngine, value: int) -> None:
        """
        Should only be called through syscalls
        """
        if value > 0xFFFE:  # MaxTransactionsPerBlock
            raise ValueError("New value exceeds MAX_TRANSACTIONS_PER_BLOCK")

        if not self._check_committee(engine):
            raise ValueError("Check committee failed")

        storage_item = engine.snapshot.storages.get(self.key_max_transactions_per_block, read_only=False)
        storage_item.value = self._int_to_bytes(value)

    def _set_max_block_system_fee(self, engine: contracts.ApplicationEngine, value: int) -> None:
        """
        Should only be called through syscalls
        """
        # unknown magic value
        if value <= 4007600:
            raise ValueError("Invalid new system fee")

        if not self._check_committee(engine):
            raise ValueError("Check committee failed")

        storage_item = engine.snapshot.storages.get(self.key_max_block_system_fee, read_only=False)
        storage_item.value = self._int_to_bytes(value)

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

    def get_exec_fee_factor(self, snapshot: storage.Snapshot) -> int:
        storage_item = snapshot.storages.get(self.key_exec_fee_factor, read_only=True)
        return int(vm.BigInteger(storage_item.value))

    def get_storage_price(self, snapshot: storage.Snapshot) -> int:
        if self._storage_price:
            return self._storage_price

        storage_item = snapshot.storages.get(self.key_storage_price, read_only=True)
        return int(vm.BigInteger(storage_item.value))

    def _set_exec_fee_factor(self, engine: contracts.ApplicationEngine, value: int) -> None:
        if value == 0 or value > self.MAX_EXEC_FEE_FACTOR:
            raise ValueError("New exec fee value out of range")
        if not self._check_committee(engine):
            raise ValueError("Check committee failed")
        storage_item = engine.snapshot.storages.get(self.key_exec_fee_factor, read_only=False)
        storage_item.value = vm.BigInteger(value).to_array()

    def _set_storage_price(self, engine: contracts.ApplicationEngine, value: int) -> None:
        if value == 0 or value > self.MAX_STORAGE_PRICE:
            raise ValueError("New storage price value out of range")
        if not self._check_committee(engine):
            raise ValueError("Check committee failed")
        storage_item = engine.snapshot.storages.get(self.key_storage_price, read_only=False)
        storage_item.value = vm.BigInteger(value).to_array()

        self._storage_price = value
