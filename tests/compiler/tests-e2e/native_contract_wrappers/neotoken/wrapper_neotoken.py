from typing import Any

from neo3.sc.compiletime import public
from neo3.sc.contracts.neotoken import NeoToken
from neo3.sc.types import ECPoint, UInt160, NeoAccountState


@public
def get_symbol() -> str:
    return NeoToken.symbol()


@public
def get_decimals() -> int:
    return NeoToken.decimals()


@public
def get_total_supply() -> int:
    return NeoToken.total_supply()


@public
def get_balance_of(account: UInt160) -> int:
    return NeoToken.balance_of(account)


@public
def get_gas_per_block() -> int:
    return NeoToken.get_gas_per_block()


@public
def get_unclaimed_gas(account: UInt160, end: int) -> int:
    return NeoToken.unclaimed_gas(account, end)


@public
def get_committee() -> list[ECPoint]:
    return NeoToken.get_committee()


@public
def get_committee_address() -> UInt160:
    return NeoToken.get_committee_address()


@public
def get_register_price() -> int:
    return NeoToken.get_register_price()


@public
def get_next_block_validators() -> list[ECPoint]:
    return NeoToken.get_next_block_validators()


@public
def get_candidate_vote(pubkey: ECPoint) -> int:
    return NeoToken.get_candidate_vote(pubkey)


@public
def do_transfer(from_addr: UInt160, to_addr: UInt160, amount: int, data: Any) -> bool:
    return NeoToken.transfer(from_addr, to_addr, amount, data)


@public
def get_account_state(account: UInt160) -> NeoAccountState:
    return NeoToken.get_account_state(account)
