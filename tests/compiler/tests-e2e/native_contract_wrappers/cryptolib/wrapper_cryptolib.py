from neo3.sc.compiletime import public
from neo3.sc.contracts.cryptolib import CryptoLib
from neo3.sc.types import ECPoint


@public
def do_sha256(data: bytes) -> bytes:
    return CryptoLib.sha256(data)


@public
def do_ripemd160(data: bytes) -> bytes:
    return CryptoLib.ripemd160(data)


@public
def do_murmur32(data: bytes, seed: int) -> bytes:
    return CryptoLib.murmur32(data, seed)


@public
def do_verify_with_ecdsa(
    message: bytes, pubkey: ECPoint, signature: bytes, curve: int
) -> bool:
    return CryptoLib.verify_with_ecdsa(message, pubkey, signature, curve)


@public
def do_bls12381_roundtrip(data: bytes) -> bytes:
    point = CryptoLib.bls12381_deserialize(data)
    return CryptoLib.bls12381_serialize(point)
