from __future__ import annotations
from neo3 import contracts, settings
from neo3.core import cryptography
from neo3.contracts.interop import register
from typing import List


CHECKSIG_PRICE = 1 << 15


@register("System.Crypto.CheckSig", CHECKSIG_PRICE, contracts.CallFlags.NONE)
def verify_with_ECDSA_Secp256r1(engine: contracts.ApplicationEngine,
                                public_key: bytes,
                                signature: bytes) -> bool:
    return cryptography.verify_signature(engine.script_container.get_hash_data(settings.network.magic),
                                         signature,
                                         public_key,
                                         cryptography.ECCCurve.SECP256R1)


@register("System.Crypto.CheckMultisig", 0, contracts.CallFlags.NONE)
def check_multisig_with_ECDSA_Secp256r1(engine: contracts.ApplicationEngine,
                                        public_keys: List[bytes],
                                        signatures: List[bytes]) -> bool:
    len_pub_keys = len(public_keys)
    len_sigs = len(signatures)
    if len_sigs == 0:
        raise ValueError("No signatures supplied")
    if len_pub_keys == 0:
        raise ValueError("No public keys supplied")
    if len_sigs > len_pub_keys:
        raise ValueError(f"Verification requires {len_sigs} public keys, got only {len_pub_keys}")

    message = engine.script_container.get_hash_data(settings.network.magic)

    engine.add_gas(len_pub_keys * CHECKSIG_PRICE * engine.exec_fee_factor)

    i = 0
    j = 0
    try:
        while i < len_sigs and j < len_pub_keys:
            if cryptography.verify_signature(message, signatures[i], public_keys[j], cryptography.ECCCurve.SECP256R1):
                i += 1
            j += 1

            if len_sigs - i > len_pub_keys - j:
                return False
    except cryptography.ECCException as e:
        return False
    return True
