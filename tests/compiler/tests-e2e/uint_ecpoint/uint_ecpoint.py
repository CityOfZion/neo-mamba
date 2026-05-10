from neo3.sc.compiletime import public
from neo3.sc.types import ECPoint, UInt160, UInt256

# ── construct from bytes, return via to_array() ──────────────────────────────


@public
def uint160_roundtrip(data: bytes) -> bytes:
    h: UInt160 = UInt160(data)
    return h.to_array()


@public
def uint256_roundtrip(data: bytes) -> bytes:
    h: UInt256 = UInt256(data)
    return h.to_array()


@public
def ecpoint_roundtrip(data: bytes) -> bytes:
    pk: ECPoint = ECPoint(data)
    return pk.to_array()


# ── accept typed arg, return via to_array() ───────────────────────────────────


@public
def uint160_to_bytes(h: UInt160) -> bytes:
    return h.to_array()


@public
def uint256_to_bytes(h: UInt256) -> bytes:
    return h.to_array()


@public
def ecpoint_to_bytes(pk: ECPoint) -> bytes:
    return pk.to_array()
