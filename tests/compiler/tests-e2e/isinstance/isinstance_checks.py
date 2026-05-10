from neo3.sc.compiletime import public

# ── int checks ────────────────────────────────────────────────────────────────


@public
def int_is_int(x: int) -> bool:
    return isinstance(x, int)


@public
def int_is_bool(x: int) -> bool:
    return isinstance(x, bool)


@public
def int_is_str(x: int) -> bool:
    return isinstance(x, str)


@public
def int_is_bytes(x: int) -> bool:
    return isinstance(x, bytes)


@public
def int_is_bytearray(x: int) -> bool:
    return isinstance(x, bytearray)


# ── bool checks ───────────────────────────────────────────────────────────────


@public
def bool_is_bool(x: bool) -> bool:
    return isinstance(x, bool)


@public
def bool_is_int(x: bool) -> bool:
    # NeoVM divergence: returns False (Boolean tag 0x20 ≠ Integer tag 0x21).
    # Python: isinstance(True, int) = True (bool is a subclass of int).
    return isinstance(x, int)


# ── str checks ────────────────────────────────────────────────────────────────


@public
def str_is_str(x: str) -> bool:
    return isinstance(x, str)


@public
def str_is_bytes(x: str) -> bool:
    # NeoVM divergence: returns True (both str and bytes are ByteString tag 0x28).
    # Python: isinstance("hello", bytes) = False.
    return isinstance(x, bytes)


@public
def str_is_int(x: str) -> bool:
    return isinstance(x, int)


# ── bytes checks ──────────────────────────────────────────────────────────────


@public
def bytes_is_bytes(x: bytes) -> bool:
    return isinstance(x, bytes)


@public
def bytes_is_str(x: bytes) -> bool:
    # NeoVM divergence: returns True (both bytes and str are ByteString tag 0x28).
    # Python: isinstance(b"\x01", str) = False.
    return isinstance(x, str)


@public
def bytes_is_int(x: bytes) -> bool:
    return isinstance(x, int)


# ── bytearray checks ──────────────────────────────────────────────────────────


@public
def bytearray_is_bytearray() -> bool:
    ba: bytearray = bytearray(3)
    return isinstance(ba, bytearray)


@public
def bytearray_is_bytes() -> bool:
    ba: bytearray = bytearray(3)
    # Buffer (0x30) ≠ ByteString (0x28) — returns False, same as Python.
    return isinstance(ba, bytes)


@public
def bytearray_is_str() -> bool:
    ba: bytearray = bytearray(3)
    # Buffer (0x30) ≠ ByteString (0x28) — returns False.
    return isinstance(ba, str)


# ── isinstance in branch / expression context ─────────────────────────────────


@public
def isinstance_branch(x: int) -> int:
    if isinstance(x, int):
        return 1
    return 0


@public
def isinstance_and(x: int, y: int) -> bool:
    return isinstance(x, int) and isinstance(y, int)
