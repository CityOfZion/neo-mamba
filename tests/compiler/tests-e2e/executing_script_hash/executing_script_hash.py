from neo3.sc.compiletime import public
from neo3.sc.runtime import get_executing_script_hash
from neo3.sc.types import UInt160


@public
def get_my_hash() -> UInt160:
    return get_executing_script_hash()
