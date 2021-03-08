from __future__ import annotations
import hashlib
from neo3 import vm, contracts, settings
from neo3.network import payloads
from neo3.core import cryptography
from neo3.contracts.interop import register
from typing import cast, List


def stackitem_to_hash_data(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> bytes:
    if isinstance(stack_item, vm.InteropStackItem):
        item = stack_item.get_object()
        if not issubclass(type(item), payloads.IVerifiable):
            raise ValueError("Invalid type")
        item = cast(payloads.IVerifiable, item)
        value = item.get_hash_data(settings.network.magic)
    elif isinstance(stack_item, vm.NullStackItem):
        value = engine.script_container.get_hash_data(settings.network.magic)
    else:
        value = stack_item.to_array()
    return value


@register("Neo.Crypto.RIPEMD160", 1 << 15, contracts.CallFlags.NONE)
def do_ripemd160(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> bytes:
    value = stackitem_to_hash_data(engine, stack_item)
    return hashlib.new('ripemd160', value).digest()


@register("Neo.Crypto.SHA256", 1 << 15, contracts.CallFlags.NONE)
def do_sha256(engine: contracts.ApplicationEngine, stack_item: vm.StackItem) -> bytes:
    value = stackitem_to_hash_data(engine, stack_item)
    return hashlib.sha256(value).digest()


@register("Neo.Crypto.VerifyWithECDsaSecp256r1", 1 << 15, contracts.CallFlags.NONE)
def verify_with_ECDSA_Secp256r1(engine: contracts.ApplicationEngine,
                                stack_item: vm.StackItem,
                                public_key: bytes,
                                signature: bytes) -> bool:
    value = stackitem_to_hash_data(engine, stack_item)
    return cryptography.verify_signature(value, signature, public_key, cryptography.ECCCurve.SECP256R1)


@register("Neo.Crypto.VerifyWithECDsaSecp256k1", 1 << 15, contracts.CallFlags.NONE)
def verify_with_ECDSA_Secp256k1(engine: contracts.ApplicationEngine,
                                stack_item: vm.StackItem,
                                public_key: bytes,
                                signature: bytes) -> bool:
    value = stackitem_to_hash_data(engine, stack_item)
    return cryptography.verify_signature(value, signature, public_key, cryptography.ECCCurve.SECP256K1)


def _check_multisig(engine: contracts.ApplicationEngine,
                    stack_item: vm.StackItem,
                    public_keys: List[bytes],
                    signatures: List[bytes],
                    curve: cryptography.ECCCurve) -> bool:
    len_pub_keys = len(public_keys)
    len_sigs = len(signatures)
    if len_sigs == 0:
        raise ValueError("No signatures supplied")
    if len_pub_keys == 0:
        raise ValueError("No public keys supplied")
    if len_sigs > len_pub_keys:
        raise ValueError(f"Verification requires {len_sigs} public keys, got only {len_pub_keys}")

    message = stackitem_to_hash_data(engine, stack_item)

    engine.add_gas(len_pub_keys * (1 << 15) * engine.exec_fee_factor)

    i = 0
    j = 0
    try:
        while i < len_sigs and j < len_pub_keys:
            if cryptography.verify_signature(message, signatures[i], public_keys[j], curve):
                i += 1
            j += 1

            if len_sigs - i > len_pub_keys - j:
                return False
    except cryptography.ECCException as e:
        return False
    return True


@register("Neo.Crypto.CheckMultisigWithECDsaSecp256r1", 0, contracts.CallFlags.NONE)
def check_multisig_with_ECDSA_Secp256r1(engine: contracts.ApplicationEngine,
                                        stack_item: vm.StackItem,
                                        public_keys: List[bytes],
                                        signatures: List[bytes]) -> bool:
    return _check_multisig(engine, stack_item, public_keys, signatures, cryptography.ECCCurve.SECP256R1)


@register("Neo.Crypto.CheckMultisigWithECDsaSecp256k1", 0, contracts.CallFlags.NONE)
def check_multisig_with_ECDSA_Secp256k1(engine: contracts.ApplicationEngine,
                                        stack_item: vm.StackItem,
                                        public_keys: List[bytes],
                                        signatures: List[bytes]) -> bool:
    return _check_multisig(engine, stack_item, public_keys, signatures, cryptography.ECCCurve.SECP256K1)
