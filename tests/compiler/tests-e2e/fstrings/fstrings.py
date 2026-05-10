from neo3.sc.compiletime import public


@public
def greet(name: str) -> str:
    return f"Hello, {name}!"


@public
def format_int(n: int) -> str:
    return f"value={n}"


@public
def format_bool(flag: bool) -> str:
    return f"{flag}"


@public
def str_bool_true() -> str:
    return str(True)


@public
def str_bool_false() -> str:
    return str(False)


@public
def multi(a: str, b: str, n: int) -> str:
    return f"{a} and {b} = {n}"
