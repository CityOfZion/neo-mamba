from __future__ import annotations
from .merkletree import MerkleTree
from .bloomfilter import BloomFilter
from .ecc import ECCCurve, ECPoint, KeyPair, ECCException, ecdsa_verify, ecdsa_sign
import hashlib

__all__ = ['MerkleTree', 'BloomFilter', 'ECCCurve', 'ECPoint', 'KeyPair', 'sign', 'verify_signature',
           'ECCException']


def sign(message: bytes, private_key: bytes, curve=ECCCurve.SECP256R1, hash_func=hashlib.sha256) -> bytes:
    return ecdsa_sign(private_key, message, curve, hash_func)


def verify_signature(message: bytes,
                     signature: bytes,
                     public_key: bytes,
                     curve: ECCCurve = ECCCurve.SECP256R1,
                     hash_func=hashlib.sha256) -> bool:
    """
    Test is the `signature` is signed by `public_key` valid for `message`.

    Args:
        message: the data the signature was created over
        signature: the signature to validate for `message`
        public_key: the public key the message was signed with
        curve: the ECC curve to use for verifying

    Raises:
        ValueError: for the Secp256r1 curve if the public key has an invalid format

    """
    pub_key = ECPoint(public_key, curve, True)
    return ecdsa_verify(signature, message, pub_key, hash_func)
