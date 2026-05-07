from neo3.sc.compiletime import public

# ── int / bool conversions ─────────────────────────────────────────────────────


@public
def int_to_bool(x: int) -> bool:
    return bool(x)


@public
def bool_to_int(b: bool) -> int:
    return int(b)


# ── bytes → int  via CONVERT (NeoVM: LE signed integer, NOT decimal parse) ────


@public
def str_to_int(b: bytes) -> int:
    return int(b)


# ── bytes → int  (same LE signed semantics as str → int) ─────────────────────


@public
def bytes_to_int(b: bytes) -> int:
    return int(b)


# ── bytearray → int  (Buffer treated as LE signed integer) ───────────────────


@public
def bytearray_to_int_single_byte(n: int) -> int:
    ba: bytearray = bytearray(1)
    ba[0] = n
    return int(ba)


@public
def bytearray_to_int_two_bytes(lo: int, hi: int) -> int:
    ba: bytearray = bytearray(2)
    ba[0] = lo
    ba[1] = hi
    return int(ba)


# ── int → str / bytes  (NeoVM: LE byte representation, NOT decimal string) ────


@public
def int_to_str(x: int) -> str:
    return str(x)


@public
def int_to_bytes(x: int) -> bytes:
    return bytes(x)


# ── bool → str / bytes ────────────────────────────────────────────────────────


@public
def bool_to_str(b: bool) -> str:
    return str(b)


@public
def bool_to_bytes(b: bool) -> bytes:
    return bytes(b)


# ── str / bytes → bool ────────────────────────────────────────────────────────


@public
def str_to_bool(s: str) -> bool:
    return bool(s)


@public
def bytes_to_bool(b: bytes) -> bool:
    return bool(b)


# ── str ↔ bytes  (both are ByteString at the VM level; type annotation changes) ─


@public
def str_to_bytes(s: str) -> bytes:
    return bytes(s)


@public
def bytes_to_str(b: bytes) -> str:
    return str(b)


# ── bytearray → bytes / str ───────────────────────────────────────────────────


@public
def bytearray_to_bytes_single(n: int) -> bytes:
    ba: bytearray = bytearray(1)
    ba[0] = n
    return bytes(ba)


@public
def bytearray_to_str_single(n: int) -> str:
    ba: bytearray = bytearray(1)
    ba[0] = n
    return str(ba)


# ── identity conversions ──────────────────────────────────────────────────────


@public
def int_to_int(x: int) -> int:
    return int(x)


@public
def bool_to_bool(b: bool) -> bool:
    return bool(b)


@public
def str_to_str(s: str) -> str:
    return str(s)


@public
def bytes_to_bytes(b: bytes) -> bytes:
    return bytes(b)
