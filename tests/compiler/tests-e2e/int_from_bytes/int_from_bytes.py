from neo3.sc.compiletime import public

# ── little-endian unsigned ────────────────────────────────────────────────────


@public
def from_le_unsigned(b: bytes) -> int:
    return int.from_bytes(b, "little")


# ── little-endian signed ──────────────────────────────────────────────────────


@public
def from_le_signed(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=True)


# ── big-endian unsigned ───────────────────────────────────────────────────────


@public
def from_be_unsigned(b: bytes) -> int:
    return int.from_bytes(b, "big")


# ── big-endian signed ─────────────────────────────────────────────────────────


@public
def from_be_signed(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=True)


# ── constant-folded (compiled to a literal, no opcodes emitted at runtime) ────


@public
def const_le() -> int:
    return int.from_bytes(b"\x00\x01", "little")


@public
def const_be() -> int:
    return int.from_bytes(b"\x01\x00", "big")


# ── default byteorder ('big') ─────────────────────────────────────────────────


@public
def default_byteorder(b: bytes) -> int:
    return int.from_bytes(b)
