from neo3.sc.compiletime import public

# ── little-endian unsigned ────────────────────────────────────────────────────


@public
def to_le_unsigned(x: int, n: int) -> bytes:
    return x.to_bytes(n, "little")


# ── little-endian signed ──────────────────────────────────────────────────────


@public
def to_le_signed(x: int, n: int) -> bytes:
    return x.to_bytes(n, "little", signed=True)


# ── big-endian unsigned ───────────────────────────────────────────────────────


@public
def to_be_unsigned(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")


# ── big-endian signed ─────────────────────────────────────────────────────────


@public
def to_be_signed(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big", signed=True)


# ── constant-folded (compiled to a literal, no helper called) ─────────────────


@public
def const_le() -> bytes:
    return (256).to_bytes(2, "little")


@public
def const_be() -> bytes:
    return (256).to_bytes(2, "big")


# ── default args (length=1, byteorder='big') ──────────────────────────────────


@public
def default_args(x: int) -> bytes:
    return x.to_bytes()
