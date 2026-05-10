from typing import Optional
from neo3.sc.compiletime import public
from neo3.sc.contracts.ledger import LedgerContract

module_attr: Optional[int] = None


def returns_something() -> str:
    return "something"


@public
def main(x: int) -> int:
    returns_something()
    return x
