"""
Contract utilities for determing the contract hash, contract types, extracting public keys and signing treshold and more.
"""
from typing import Type
from collections.abc import Sequence
from neo3.core import types, utils as coreutils, cryptography
from neo3 import vm


def get_contract_hash(
    sender: types.UInt160, nef_checksum: int, contract_name: str
) -> types.UInt160:
    """
    Return the calculated contract hash.

    Args:
        sender: script hash of account that deployed the contract.
        nef_checksum: checksum of the contract's NEF file.
        contract_name: the name from the contract's manifest.
    Returns:
        a unique contract identifier.
    """
    sb = vm.ScriptBuilder()
    sb.emit(vm.OpCode.ABORT)
    sb.emit_push(sender)
    sb.emit_push(nef_checksum)
    sb.emit_push(contract_name)
    return coreutils.to_script_hash(sb.to_array())


def validate_type(obj: object, type_: Type):
    """
    Helper function to validate ABI type information.

    Args:
        obj: target object.
        type_: expected type

    Raises:
        ValueError: if types do not match.
    """
    if type(obj) != type_:
        raise ValueError(f"Expected type '{type_}' , got '{type(obj)}' instead")
    return obj


def create_multisig_redeemscript(
    m: int, public_keys: Sequence[cryptography.ECPoint]
) -> bytes:
    """
    Create a multi-signature redeem script requiring `m` signatures from the list `public_keys`.

    This generated script is intended to be executed by the VM to indicate that the requested action is allowed.

    Args:
        m: minimum number of signature required for signing. Can't be lower than 2.
        public_keys: public keys to use during verification.

    Raises:
        ValueError: if the minimum required signatures is not met.
        ValueError: if the maximum allowed signatures is exceeded.
        ValueError: if the maximum allowed public keys is exceeded.
    """
    if m < 1:
        raise ValueError(f"Minimum required signature count is 1, specified {m}.")

    if m > len(public_keys):
        raise ValueError(
            "Invalid public key count. "
            "Minimum required signatures is bigger than supplied public keys count."
        )

    if len(public_keys) > 1024:
        raise ValueError(
            f"Supplied public key count ({len(public_keys)}) exceeds maximum of 1024."
        )

    sb = vm.ScriptBuilder()
    sb.emit_push(m)
    public_keys = list(public_keys)
    public_keys.sort()

    for key in public_keys:
        sb.emit_push(key.encode_point(True))

    sb.emit_push(len(public_keys))
    sb.emit_syscall(vm.Syscalls.SYSTEM_CRYPTO_CHECK_MULTI_SIGNATURE_ACCOUNT)
    return sb.to_array()


def create_signature_redeemscript(public_key: cryptography.ECPoint) -> bytes:
    """
    Create a single signature redeem script.

    This generated script is intended to be executed by the VM to indicate that the requested action is allowed.

    Args:
        public_key: the public key to use during verification.
    """
    sb = vm.ScriptBuilder()
    sb.emit_push(public_key.encode_point(True))
    sb.emit_syscall(vm.Syscalls.SYSTEM_CRYPTO_CHECK_STANDARD_ACCOUNT)
    return sb.to_array()


def is_signature_contract(script: bytes) -> bool:
    """
    Test if the provided script is a (single) signature contract.

    Args:
        script: contract script.
    """
    if len(script) != 40:
        return False

    if (
        script[0] != vm.OpCode.PUSHDATA1
        or script[1] != 33
        or script[35] != vm.OpCode.SYSCALL
        or script[36:40] != vm.Syscalls.SYSTEM_CRYPTO_CHECK_STANDARD_ACCOUNT
    ):
        return False
    return True


def is_multisig_contract(script: bytes) -> bool:
    """
    Test if the provided script is a multi-signature contract.

    Args:
        script: contract script.
    """
    valid, _, _ = parse_as_multisig_contract(script)
    return valid


def parse_as_multisig_contract(
    script: bytes,
) -> tuple[bool, int, list[cryptography.ECPoint]]:
    """
    Try to parse script as multisig contract and extract related data.

    Args:
        script: array of vm byte code.

    Returns:
        bool: `True` if the script passes as a valid multisignature contract script. `False` otherwise.
        int: the signing threshold if validation passed. 0 otherwise.
        list[ECPoint]: the public keys in the script if valiation passed. An empty array otherwise.
    """
    script = bytes(script)
    VALIDATION_FAILURE: tuple[bool, int, list[cryptography.ECPoint]] = (False, 0, [])

    len_script = len(script)
    if len_script < 42:
        return VALIDATION_FAILURE

    # read signature length, which is encoded as variable_length
    first_byte = script[0]
    if first_byte == int(vm.OpCode.PUSHINT8):
        signature_threshold = script[1]
        i = 2
    elif first_byte == int(vm.OpCode.PUSHINT16):
        signature_threshold = int.from_bytes(script[1:3], "little", signed=False)
        i = 3
    elif int(vm.OpCode.PUSH1) <= first_byte <= int(vm.OpCode.PUSH16):
        signature_threshold = first_byte - int(vm.OpCode.PUSH0)
        i = 1
    else:
        return VALIDATION_FAILURE

    if signature_threshold < 1 or signature_threshold > 1024:
        return VALIDATION_FAILURE

    # try reading public keys and do a basic format validation
    pushdata1 = int(vm.OpCode.PUSHDATA1)
    public_keys = []
    while script[i] == pushdata1:
        if len_script <= i + 35:
            return VALIDATION_FAILURE
        if script[i + 1] != 33:
            return VALIDATION_FAILURE
        public_keys.append(
            cryptography.ECPoint.deserialize_from_bytes(script[i + 2 : i + 2 + 33])
        )
        i += 35

    public_key_count = len(public_keys)
    if public_key_count < signature_threshold or public_key_count > 1024:
        return VALIDATION_FAILURE

    # validate that the number of collected public keys match the expected count
    value = script[i]
    if value == int(vm.OpCode.PUSHINT8):
        if len_script <= i + 1 or public_key_count != script[i + 1]:
            return VALIDATION_FAILURE
        i += 2
    elif value == int(vm.OpCode.PUSHINT16):
        if len_script < i + 3 or public_key_count != int.from_bytes(
            script[i + 1 : i + 3], "little", signed=False
        ):
            return VALIDATION_FAILURE
        i += 3
    elif int(vm.OpCode.PUSH1) <= value <= int(vm.OpCode.PUSH16):
        if public_key_count != value - int(vm.OpCode.PUSH0):
            return VALIDATION_FAILURE
        i += 1
    else:
        return VALIDATION_FAILURE

    if len_script != i + 5:
        return VALIDATION_FAILURE

    if script[i] != int(vm.OpCode.SYSCALL):
        return VALIDATION_FAILURE
    i += 1

    syscall_num = int.from_bytes(script[i : i + 4], "little")
    if syscall_num != vm.Syscalls.SYSTEM_CRYPTO_CHECK_MULTI_SIGNATURE_ACCOUNT:
        return VALIDATION_FAILURE
    return True, signature_threshold, public_keys
