from neo3.sc.compiletime import public


@public
def encode(b: bytes) -> str:
    return b.hex()


@public
def encode_bytearray(b: bytearray) -> str:
    return b.hex()
