from __future__ import annotations
import ecdsa as _ecdsa  # type: ignore
import hashlib
from enum import Enum, auto
from .ecc import (EllipticCurve, ECDSA)  # type: ignore
from .merkletree import MerkleTree
from .bloomfilter import BloomFilter
from bitcoin import (  # type: ignore
    decompress as bitcoin_decompress,
    change_curve as bitcoin_change_curve,
    ecdsa_raw_sign as bitcoin_ecdsa_raw_sign)
from .keypair import KeyPair


__all__ = ['EllipticCurve', 'ECDSA', 'MerkleTree', 'BloomFilter', 'KeyPair', 'ECCCurve']


class ECCCurve(Enum):
    NISTP256 = auto()
    SECPK256k1 = auto()


def verify_signature(message: bytes, signature: bytes, public_key: bytes, curve: ECCCurve) -> bool:
    """
    Test is the `signature` is signed by `public_key` valid for `message`.

    Args:
        message: the data the signature was created over
        signature: the signature to validate for `message`
        public_key: the public key the message was signed with
        curve: the ECC curve to use for verifying

    Raises:
        ValueError: for the NISTP256/Secp256r1 curve if the public key has an invalid format

    """
    if curve == ECCCurve.NISTP256:
        length = len(public_key)
        if length != 33 and (public_key[0] == 0x2 or public_key[0] == 0x3):
            public_key = bitcoin_decompress(public_key)
        elif length == 65 and public_key[0] == 0x4:
            public_key = public_key[1:]
        elif length != 64:
            raise ValueError("Invalid public key bytes")
        ecdsa_curve = _ecdsa.NIST256p
    else:
        ecdsa_curve = _ecdsa.SECP256k1

    try:
        vk = _ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa_curve, hashfunc=hashlib.sha256)
        return vk.verify(signature, message, hashfunc=hashlib.sha256)
    except Exception:
        return False


def sign(message: bytes, private_key: bytes, curve: ECCCurve = ECCCurve.NISTP256) -> bytes:
    """
    Create a signature for a message using the supplied private key.

    Args:
        message: the data to sign
        private_key: the key to use
        curve: the ECC curve to use. Defaults to Secp256r1 as mostly used by NEO (such as in wallets)

    Returns:
        bytes: the signature belonging to the message.
    """
    if curve == ECCCurve.NISTP256:
        P = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        N = 115792089210356248762697446949407573529996955224135760342422259061068512044369
        A = 115792089210356248762697446949407573530086143415290314195533631308867097853948
        B = 41058363725152142129326129780047268409114441015993725554835256314039467401291
        Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
        Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109
    elif curve == ECCCurve.SECPK256k1:
        P = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        N = 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        A = 0
        B = 7
        Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    else:
        raise ValueError("Unknown curve - can't initialize")

    bitcoin_change_curve(P, N, A, B, Gx, Gy)
    hash_ = hashlib.sha256(message).hexdigest()
    v, r, s = bitcoin_ecdsa_raw_sign(hash_, private_key)
    rb = r.to_bytes(32, 'big')
    sb = s.to_bytes(32, 'big')
    sig = rb + sb
    return sig
