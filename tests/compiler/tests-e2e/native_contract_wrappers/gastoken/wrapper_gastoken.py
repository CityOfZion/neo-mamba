from neo3.sc.compiletime import public
from neo3.sc.contracts.gastoken import GasToken
from neo3.sc.types import UInt160


@public
def get_symbol() -> str:
    return GasToken.symbol()


@public
def get_decimals() -> int:
    return GasToken.decimals()


@public
def get_total_supply() -> int:
    return GasToken.total_supply()


@public
def get_balance_of(account: UInt160) -> int:
    return GasToken.balance_of(account)
