from neo3.sc.compiletime import public
from neo3.sc.contracts.cryptolib import CryptoLib


@public
def do_sha256(data: bytes) -> bytes:
    return CryptoLib.sha256(data)


@public
def do_ripemd160(data: bytes) -> bytes:
    return CryptoLib.ripemd160(data)


@public
def do_murmur32(data: bytes, seed: int) -> bytes:
    return CryptoLib.murmur32(data, seed)
