from x.compiler.sc.compiletime import public


@public
def print_str(msg: str) -> None:
    print(msg)


@public
def print_bytes(msg: bytes) -> None:
    print(msg)


@public
def print_list(msg: list) -> None:
    print(msg)
