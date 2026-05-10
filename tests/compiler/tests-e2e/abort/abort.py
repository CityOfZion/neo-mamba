from neo3.sc.compiletime import public
from neo3.sc.utils import abort


@public
def do_abort() -> None:
    abort()


@public
def do_abort_msg() -> None:
    abort("something went wrong")


@public
def conditional_abort(x: int) -> int:
    if x == 0:
        abort()
    return x


@public
def conditional_abort_msg(x: int) -> int:
    if x == 0:
        abort("x must not be zero")
    return x
