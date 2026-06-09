from typing import Any, Optional

from neo3.sc.compiletime import call_flags, contract, display_name
from neo3.sc.types import CallFlags, ECPoint, UInt160


@contract("0xd2a4cff31913016155e38e474a2c06d08be276cf")
class GasToken:
    """
    Represents the GAS native contract.

    See:
        https://developers.neo.org/docs/n3/reference/scapi/framework/native/Gas
    """

    hash: UInt160

    @staticmethod
    def symbol() -> str:
        """Get the token symbol"""
        pass

    @staticmethod
    def decimals() -> int:
        """Get the number of supported decimals."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("totalSupply")
    def total_supply() -> int:
        """
        Get the total token supply deployed in the system.
        """
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("balanceOf")
    def balance_of(account: UInt160) -> int:
        """
        Get the token balance for the given `account`.
        """
        pass

    @staticmethod
    @display_name("transfer")
    def transfer(
        from_account: UInt160, to_account: UInt160, amount: int, data: Any = None
    ) -> bool:
        """
        Move `amount` of tokens from `from_account` to `to_account`. If successful a `Transfer` event is emitted
        even if the amount is 0 or the sender and receiver are the same.

        Returns:
            `True` if successful.

        Note:
            If `to_account` is a smart contract with a `onNEP17Payment` handler then `data` will be passed to that handler.
        """
        pass
