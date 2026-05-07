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
        pass

    @staticmethod
    def decimals() -> int:
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("totalSupply")
    def total_supply() -> int:
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("balanceOf")
    def balance_of(account: UInt160) -> int:
        pass

    @staticmethod
    @display_name("transfer")
    def transfer(
        from_account: UInt160, to_account: UInt160, amount: int, data: Any
    ) -> bool:
        pass
