from neo3.sc.compiletime import public


@public
def decode(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)
