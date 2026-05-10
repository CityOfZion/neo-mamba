from typing import Any, Optional

from neo3.sc.compiletime import call_flags, contract, display_name
from neo3.sc.types import CallFlags, TrimmedTransaction, UInt160, UInt256, TrimmedBlock


@contract("0xda65b600f7124ce6c79950c1772a36403104f2be")
class LedgerContract:
    """
    Represents the Ledger native contract, providing read-only access to blocks
    and transactions.

    See:
        https://developers.neo.org/docs/n3/reference/scapi/framework/native/Ledger
    """

    hash: UInt160

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("currentIndex")
    def current_index() -> int:
        """Return the index (height) of the most recently persisted block."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("currentHash")
    def current_hash() -> UInt256:
        """Return the hash of the most recently persisted block."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getBlock")
    def get_block(index_or_hash: Any) -> Optional[TrimmedBlock]:
        """Return the block at the given index (int) or hash (UInt256).

        Returns None if no block with that index / hash exists yet.
        """
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getTransaction")
    def get_transaction(hash: UInt256) -> Optional[TrimmedTransaction]:
        """Return the transaction with the given hash, or None."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getTransactionHeight")
    def get_transaction_height(hash: UInt256) -> int:
        """Return the block index containing the transaction, or -1 if not found."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getTransactionFromBlock")
    def get_transaction_from_block(
        block_index_or_hash: Any, tx_index: int
    ) -> Optional[TrimmedTransaction]:
        """Return the *tx_index*-th transaction in the specified block."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("currentIndex")
    def get_current_index() -> int:
        pass
