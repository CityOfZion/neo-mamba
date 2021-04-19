from __future__ import annotations
import hashlib
import enum
from . import NativeContract, register
from neo3 import contracts
from neo3.core import cryptography


class NamedCurve(enum.IntEnum):
    SECP256K1 = 22
    SECP256R1 = 23


class CryptoContract(NativeContract):

    _service_name = "CryptoLib"
    _id = -3

    curves = {
        NamedCurve.SECP256K1: cryptography.ECCCurve.SECP256K1,
        NamedCurve.SECP256R1: cryptography.ECCCurve.SECP256R1
    }

    def init(self):
        super(CryptoContract, self).init()

    @register("ripemd160", 1 << 15, contracts.CallFlags.NONE)
    def ripemd160(self, data: bytes) -> bytes:
        return hashlib.new('ripemd160', data).digest()

    @register("sha256", 1 << 15, contracts.CallFlags.NONE)
    def sha256(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @register("verifyWithECDsa", 1 << 15, contracts.CallFlags.NONE)
    def verify_with_ecdsa(self, message: bytes, public_key: bytes, signature: bytes, curve: NamedCurve) -> bool:
        return cryptography.verify_signature(message, signature, public_key, self.curves.get(curve))
