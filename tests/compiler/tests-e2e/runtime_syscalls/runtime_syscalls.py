from neo3.sc.compiletime import public
from neo3.sc.runtime import (
    get_random,
    gas_left,
    burn_gas,
    get_time,
    get_invocation_counter,
    load_script,
)


@public
def getrandom() -> int:
    return get_random()


@public
def gas_left_and_burn(amount: int) -> None:
    before = gas_left()
    print(str(before))
    burn_gas(amount)
    after = gas_left()
    print(str(after))


@public
def gettime() -> int:
    return get_time()


@public
def getinvocationcounter() -> int:
    return get_invocation_counter()


@public
def run_add_script() -> int:
    args: list = [1, 2]
    return load_script(b"\x9e", args=args)  # opcode.ADD
