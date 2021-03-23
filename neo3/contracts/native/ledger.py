from __future__ import annotations
from typing import Optional
from .nativecontract import NativeContract
from neo3 import storage, contracts, vm
from neo3.core import types
from neo3.network import payloads


class LedgerContract(NativeContract):
    _id = -2

    def init(self):
        super(LedgerContract, self).init()
        self._register_contract_method(self.current_hash,
                                       "currentHash",
                                       1000000,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )
        self._register_contract_method(self.current_index,
                                       "currentIndex",
                                       1000000,
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.get_block,
                                       "getBlock",
                                       1000000,
                                       parameter_names=["block_index_or_hash"],
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.get_tx_for_contract,
                                       "getTransaction",
                                       1000000,
                                       parameter_names=["tx_hash"],
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.get_tx_height,
                                       "getTransactionheight",
                                       1000000,
                                       parameter_names=["tx_hash"],
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.get_tx_from_block,
                                       "getTransactionFromBlock",
                                       2000000,
                                       parameter_names=["block_index_or_hash", "tx_index"],
                                       call_flags=contracts.CallFlags.READ_STATES)

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        # Unlike C# the current block or its transactions are not persisted here,
        # it is still done in the Blockchain class in the persist() function
        pass

    def current_hash(self, snapshot: storage.Snapshot) -> types.UInt256:
        return snapshot.persisting_block.hash()

    def current_index(self, snapshot) -> int:
        return snapshot.best_block_height

    def get_block(self, snapshot: storage.Snapshot, index_or_hash: bytes) -> Optional[payloads.TrimmedBlock]:
        if len(index_or_hash) < types.UInt256._BYTE_LEN:
            height = vm.BigInteger(index_or_hash)
            if height < 0 or height > 4294967295:  # uint.MaxValue
                raise ValueError("Invalid height")
            block = snapshot.blocks.try_get_by_height(height, read_only=True)
        elif len(index_or_hash) == types.UInt256._BYTE_LEN:
            block_hash = types.UInt256(index_or_hash)
            block = snapshot.blocks.try_get(block_hash, read_only=True)
        else:
            raise ValueError("Invalid data")

        if block and not self._is_traceable_block(snapshot, block.index):
            block = None
        return block.trim()

    def get_tx_for_contract(self, snapshot: storage.Snapshot, hash_: types.UInt256) -> Optional[payloads.Transaction]:
        tx = snapshot.transactions.try_get(hash_, read_only=True)
        if tx is None or not self._is_traceable_block(snapshot, tx.block_height):
            return None
        return tx

    def get_tx_height(self, snapshot: storage.Snapshot, hash_: types.UInt256) -> int:
        tx = snapshot.transactions.try_get(hash_, read_only=True)
        if tx is None or not self._is_traceable_block(snapshot, tx.block_height):
            return -1
        return tx.block_height

    def get_tx_from_block(self,
                          snapshot: storage.Snapshot,
                          block_index_or_hash: bytes,
                          tx_index: int) -> Optional[payloads.Transaction]:
        if len(block_index_or_hash) < types.UInt256._BYTE_LEN:
            height = vm.BigInteger(block_index_or_hash)
            if height < 0 or height > 4294967295:  # uint.MaxValue
                raise ValueError("Invalid height")
            block = snapshot.blocks.try_get_by_height(height, read_only=True)
        elif len(block_index_or_hash) == types.UInt256._BYTE_LEN:
            block_hash = types.UInt256(block_index_or_hash)
            block = snapshot.blocks.try_get(block_hash, read_only=True)
        else:
            raise ValueError("Invalid data")

        if block and not self._is_traceable_block(snapshot, block.index):
            block = None
        if tx_index < 0 or tx_index > len(block.transactions) - 1:
            raise ValueError("Transaction index out of range")
        return block.transactions[tx_index]

    def _is_traceable_block(self, snapshot: storage.Snapshot, index: int) -> bool:
        current_idx = self.current_index(snapshot)
        if index > current_idx:
            return False
        # otherwise limit search back distance
        MAX_TRACABLE_BLOCKS = 2_102_400
        return index + MAX_TRACABLE_BLOCKS > current_idx
