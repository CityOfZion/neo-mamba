from neo3.sc.compiletime import public
from neo3.sc.runtime import get_random


@public
def getrandom() -> int:
    return get_random()
