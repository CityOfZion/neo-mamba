from __future__ import annotations
from typing import Optional
from . import register, NativeContract
from neo3 import storage, contracts, vm
from neo3.core import types
from neo3.network import payloads


class LedgerContract(NativeContract):
    _id = -4

    def init(self):
        super(LedgerContract, self).init()

    @register("currentHash", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def current_hash(self, snapshot: storage.Snapshot) -> types.UInt256:
        return snapshot.persisting_block.hash()

    @register("currentIndex", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def current_index(self, snapshot: storage.Snapshot) -> int:
        return snapshot.best_block_height

    @register("getBlock", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
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

    @register("getTransaction", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_tx_for_contract(self, snapshot: storage.Snapshot, hash_: types.UInt256) -> Optional[payloads.Transaction]:
        tx = snapshot.transactions.try_get(hash_, read_only=True)
        if tx is None or not self._is_traceable_block(snapshot, tx.block_height):
            return None
        return tx

    @register("getTransactionheight", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_tx_height(self, snapshot: storage.Snapshot, hash_: types.UInt256) -> int:
        tx = snapshot.transactions.try_get(hash_, read_only=True)
        if tx is None or not self._is_traceable_block(snapshot, tx.block_height):
            return -1
        return tx.block_height

    @register("getTransactionFromBlock", contracts.CallFlags.READ_STATES, cpu_price=1 << 16)
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
        if tx_index < 0 or tx_index >= len(block.transactions):
            raise ValueError("Transaction index out of range")
        return block.transactions[tx_index]

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        # Unlike C# the current block or its transactions are not persisted here,
        # it is still done in the Blockchain class in the persist() function
        pass

    def _is_traceable_block(self, snapshot: storage.Snapshot, index: int) -> bool:
        current_idx = self.current_index(snapshot)
        if index > current_idx:
            return False
        # otherwise limit search back distance
        MAX_TRACABLE_BLOCKS = 2_102_400
        return index + MAX_TRACABLE_BLOCKS > current_idx
