from neo3.sc.compiletime import public
from neo3.sc.runtime import get_current_signers
from neo3.sc.types import Signer


@public
def signers() -> list[Signer]:
    return get_current_signers()
