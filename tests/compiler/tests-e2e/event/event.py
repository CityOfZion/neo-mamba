from typing import Optional

from neo3.sc.compiletime import event, public
from neo3.sc.types import ECPoint, UInt160, UInt256


@event(name="Transfer", rename=[("from_", "from")])
def on_transfer(from_: Optional[UInt160], to: Optional[UInt160], amount: int) -> None:
    pass


@event(name="Ping")
def on_ping(value: int) -> None:
    pass


@public
def do_transfer(from_: UInt160, to: UInt160, amount: int) -> None:
    on_transfer(from_, to, amount)


@public
def do_mint(to: UInt160, amount: int) -> None:
    on_transfer(None, to, amount)


@public
def do_ping(value: int) -> None:
    on_ping(value)


@event(name="Extra")
def on_extra(flag: bool, data: dict[str, int], txid: UInt256, pubkey: ECPoint) -> None:
    pass


@public
def do_extra(flag: bool, data: dict[str, int], txid: UInt256, pubkey: ECPoint) -> None:
    on_extra(flag, data, txid, pubkey)
