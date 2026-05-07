from neo3.sc.compiletime import public


@public
def parse_decimal(s: str) -> int:
    return int(s)


@public
def parse_decimal_explicit(s: str) -> int:
    return int(s, 10)


@public
def parse_hex(s: str) -> int:
    return int(s, 16)


@public
def to_decimal(x: int) -> str:
    return str(x)


@public
def to_decimal_explicit(x: int) -> str:
    return str(x, 10)


@public
def to_hex(x: int) -> str:
    return str(x, 16)
