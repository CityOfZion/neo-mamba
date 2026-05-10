from neo3.sc.compiletime import public


@public
def log_str(msg: str) -> None:
    print(msg)


@public
def log_bytes(msg: bytes) -> None:
    print(msg)


@public
def log_literal() -> None:
    print("hello from contract")


@public
def log_list_ints(items: list[int]) -> None:
    print(items)


@public
def log_empty_list() -> None:
    items: list[int] = []
    print(items)
