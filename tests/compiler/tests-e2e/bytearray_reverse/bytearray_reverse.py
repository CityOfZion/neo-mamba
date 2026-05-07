from neo3.sc.compiletime import public


@public
def reverse_bytes(data: bytes) -> bytes:
    ba: bytearray = bytearray(data)
    ba.reverse()
    return bytes(ba)


@public
def reverse_bytearray(data: bytearray) -> bytes:
    data.reverse()
    return bytes(data)
