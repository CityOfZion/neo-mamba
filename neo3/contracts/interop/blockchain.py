from __future__ import annotations
from neo3 import vm, contracts, storage
from neo3.network import payloads
from neo3.core import types
from neo3.contracts.interop import register
from typing import Optional


def _is_traceable_block(snapshot: storage.Snapshot, index: int):
    if index > snapshot.block_height:
        # Why does C# have this? It seems not reachable because if we always try to get
        # the block or tx from the snapshot and if it is in the snapshot it can never be
        # higher than the snapshot.block_height
        # Leaving it here expecting some bug fix on the C# project sooner or later
        return False  # pragma: no cover
    # otherwise limit search back distance
    return index + payloads.Transaction.MAX_VALID_UNTIL_BLOCK_INCREMENT > snapshot.block_height


@register("System.Blockchain.GetHeight", 400, contracts.native.CallFlags.ALLOW_STATES, True)
def blockchain_get_height(engine: contracts.ApplicationEngine) -> int:
    return engine.snapshot.block_height


def _try_get_block(engine: contracts.ApplicationEngine, data: bytes) -> Optional[payloads.Block]:
    if len(data) < types.UInt256._BYTE_LEN:
        height = vm.BigInteger(data)
        if height < 0 or height > 4294967295:  # uint.MaxValue
            raise ValueError("Invalid height")
        block = engine.snapshot.blocks.try_get_by_height(height)
    elif len(data) == types.UInt256._BYTE_LEN:
        block_hash = types.UInt256(data)
        block = engine.snapshot.blocks.try_get(block_hash)
    else:
        raise ValueError("Invalid data")

    if block and not _is_traceable_block(engine.snapshot, block.index):
        block = None  # pragma: no cover (unreachable)
    return block


@register("System.Blockchain.GetBlock", 2500000, contracts.native.CallFlags.ALLOW_STATES, True, [bytes])
def blockchain_get_block(engine: contracts.ApplicationEngine, data: bytes) -> Optional[payloads.Block]:
    return _try_get_block(engine, data)


@register("System.Blockchain.GetTransactionFromBlock", 1000000, contracts.native.CallFlags.ALLOW_STATES, True,
          [bytes, int])
def blockchain_get_transaction_from_block(engine: contracts.ApplicationEngine,
                                          data: bytes,
                                          tx_index: int) -> Optional[payloads.Transaction]:
    block = _try_get_block(engine, data)

    if block is None:
        return None
    else:
        if tx_index < 0 or tx_index > (len(block.transactions) - 1):
            raise ValueError(f"Transaction index out of range: {tx_index}")

        return block.transactions[tx_index]


@register("System.Blockchain.GetTransaction", 1000000, contracts.native.CallFlags.ALLOW_STATES, True, [types.UInt256])
def blockchain_get_transaction(engine: contracts.ApplicationEngine,
                               tx_hash: types.UInt256) -> Optional[payloads.Transaction]:
    tx = engine.snapshot.transactions.try_get(tx_hash)
    if tx and not _is_traceable_block(engine.snapshot, tx.block_height):
        tx = None  # pragma: no cover
    return tx


@register("System.Blockchain.GetTransactionHeight", 1000000, contracts.native.CallFlags.ALLOW_STATES, True,
          [types.UInt256])
def blockchain_get_transaction_height(engine: contracts.ApplicationEngine, tx_hash: types.UInt256) -> int:
    tx = engine.snapshot.transactions.try_get(tx_hash)
    if tx and not _is_traceable_block(engine.snapshot, tx.block_height):
        tx = None  # pragma: no cover

    if tx is None:
        return -1
    else:
        return tx.block_height


@register("System.Blockchain.GetContract", 1000000, contracts.native.CallFlags.ALLOW_STATES, True, [types.UInt160])
def blockchain_get_contract(engine: contracts.ApplicationEngine, contract_hash: types.UInt160) -> storage.ContractState:
    return engine.snapshot.contracts.try_get(contract_hash)
