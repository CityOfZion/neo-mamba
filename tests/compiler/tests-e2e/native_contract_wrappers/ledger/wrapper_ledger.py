from typing import Any, Optional

from neo3.sc.compiletime import public
from neo3.sc.contracts.ledger import LedgerContract
from neo3.sc.types import TrimmedBlock, UInt160, UInt256


@public
def get_current_index() -> int:
    return LedgerContract.current_index()


@public
def get_current_hash() -> UInt256:
    return LedgerContract.current_hash()


@public
def get_tx_height(hash: UInt256) -> int:
    return LedgerContract.get_transaction_height(hash)


@public
def get_block_exists(index_or_hash: Any) -> bool:
    block = LedgerContract.get_block(index_or_hash)
    return block is not None


@public
def get_block_index_field(block_idx: int) -> int:
    block = LedgerContract.get_block(block_idx)
    if block is None:
        raise Exception("block not found")
    return block.index


@public
def get_block_version_field(block_idx: int) -> int:
    block = LedgerContract.get_block(block_idx)
    if block is None:
        raise Exception("block not found")
    return block.version


@public
def get_block_hash_field(block_idx: int) -> UInt256:
    block = LedgerContract.get_block(block_idx)
    if block is None:
        raise Exception("block not found")
    return block.hash


@public
def get_block_next_consensus_field(block_idx: int) -> UInt160:
    block = LedgerContract.get_block(block_idx)
    if block is None:
        raise Exception("block not found")
    return block.next_consensus


@public
def get_block_tx_count_field(block_idx: int) -> int:
    block = LedgerContract.get_block(block_idx)
    if block is None:
        raise Exception("block not found")
    return block.transaction_count
