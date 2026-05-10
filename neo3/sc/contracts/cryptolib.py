from typing import Any

from neo3.sc.compiletime import call_flags, contract, display_name
from neo3.sc.types import CallFlags, ECPoint, UInt160


@contract("0x726cb6e0cd8628a1350a611384688911ab75f51b")
class CryptoLib:
    """
    Represents the CryptoLib native contract.

    See:
        https://developers.neo.org/docs/n3/reference/scapi/framework/native/CryptoLib
    """

    hash: UInt160

    @staticmethod
    @call_flags(CallFlags.NONE)
    @display_name("sha256")
    def sha256(data: bytes) -> bytes:
        """Compute SHA-256 hash of *data*."""
        pass

    @staticmethod
    @call_flags(CallFlags.NONE)
    @display_name("ripemd160")
    def ripemd160(data: bytes) -> bytes:
        """Compute RIPEMD-160 hash of *data*."""
        pass

    @staticmethod
    @call_flags(CallFlags.NONE)
    @display_name("murmur32")
    def murmur32(data: bytes, seed: int) -> bytes:
        """Compute Murmur32 hash of *data* with *seed*."""
        pass

    @staticmethod
    @call_flags(CallFlags.NONE)
    @display_name("verifyWithECDsa")
    def verify_with_ecdsa(
        message: bytes, pubkey: ECPoint, signature: bytes, curve: int
    ) -> bool:
        """Verify an ECDSA signature.

        Args:
            message: the message that was signed.
            pubkey: the signer's public key.
            signature: the DER-encoded signature bytes.
            curve: the named curve ID (e.g. NamedCurveHash.secp256r1Sha256 = 22).
        """
        pass

    @staticmethod
    @call_flags(CallFlags.NONE)
    @display_name("bls12381Serialize")
    def bls12381_serialize(g: Any) -> bytes:
        """Serialize a BLS12-381 point."""
        pass

    @staticmethod
    @call_flags(CallFlags.NONE)
    @display_name("bls12381Deserialize")
    def bls12381_deserialize(data: bytes) -> Any:
        """Deserialize a BLS12-381 point."""
        pass
