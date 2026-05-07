from neo3.sc.types import UInt160
from neo3.sc.compiletime import public
from neo3.sc.runtime import get_calling_script_hash, check_witness


@public
def zero_account() -> bool:
    return check_witness(UInt160.zero())


@public
def calling_account() -> bool:
    return check_witness(get_calling_script_hash())
