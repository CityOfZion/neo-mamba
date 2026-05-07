from neo3.sc.compiletime import public
from neo3.sc.contracts.policy import PolicyContract
from neo3.sc.types import UInt160


@public
def get_fee_per_byte() -> int:
    return PolicyContract.get_fee_per_byte()


@public
def get_exec_fee_factor() -> int:
    return PolicyContract.get_exec_fee_factor()


@public
def get_storage_price() -> int:
    return PolicyContract.get_storage_price()


@public
def check_is_blocked(account: UInt160) -> bool:
    return PolicyContract.is_blocked(account)
