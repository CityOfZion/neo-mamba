from __future__ import annotations
from typing import List
from neo3 import contracts
from neo3.core import cryptography, to_script_hash, types
from neo3 import vm


class Contract:
    def __init__(self, script: bytes, parameter_list: List[contracts.ContractParameterType]):
        self.script = script
        self.parameter_list = parameter_list
        self._script_hash = to_script_hash(self.script)
        self._address = None

    @property
    def script_hash(self) -> types.UInt160:
        """
        The contract script hash
        """
        return self._script_hash

    @classmethod
    def create_multisig_contract(cls, m: int, public_keys: List[cryptography.ECPoint]) -> Contract:
        """
        Create a multi-signature contract requiring `m` signatures from the list `public_keys`.

        Args:
            m: minimum number of signature required for signing. Can't be lower than 2.
            public_keys: public keys to use during verification.
        """
        return cls(script=cls.create_multisig_redeemscript(m, public_keys),
                   parameter_list=[contracts.ContractParameterType.SIGNATURE] * m)

    @staticmethod
    def create_multisig_redeemscript(m: int, public_keys: List[cryptography.ECPoint]) -> bytes:
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
            raise ValueError("Invalid public key count. "
                             "Minimum required signatures is bigger than supplied public keys count.")

        if len(public_keys) > 1024:
            raise ValueError(f"Supplied public key count ({len(public_keys)}) exceeds maximum of 1024.")

        sb = vm.ScriptBuilder()
        sb.emit_push(m)
        public_keys.sort()

        for key in public_keys:
            sb.emit_push(key.encode_point(True))

        sb.emit_push(len(public_keys))
        sb.emit(vm.OpCode.PUSHNULL)
        sb.emit_syscall(contracts.syscall_name_to_int("Neo.Crypto.CheckMultisigWithECDsaSecp256r1"))
        return sb.to_array()

    @classmethod
    def create_signature_contract(cls, public_key: cryptography.ECPoint) -> Contract:
        """
        Create a signature contract.

        Args:
            public_key: the public key to use during verification.

        Returns:

        """
        return cls(cls.create_signature_redeemscript(public_key), [contracts.ContractParameterType.SIGNATURE])

    @staticmethod
    def create_signature_redeemscript(public_key: cryptography.ECPoint) -> bytes:
        """
        Create a single signature redeem script.

        This generated script is intended to be executed by the VM to indicate that the requested action is allowed.

        Args:
            public_key: the public key to use during verification.
        """
        sb = vm.ScriptBuilder()
        sb.emit_push(public_key.encode_point(True))
        sb.emit(vm.OpCode.PUSHNULL)
        sb.emit_syscall(contracts.syscall_name_to_int("Neo.Crypto.VerifyWithECDsaSecp256r1"))
        return sb.to_array()

    @staticmethod
    def is_signature_contract(script: bytes) -> bool:
        """
        Test if the provided script is signature contract.

        Args:
            script: contract script.
        """
        if len(script) != 41:
            return False

        if (script[0] != vm.OpCode.PUSHDATA1
                or script[1] != 33
                or script[35] != vm.OpCode.PUSHNULL
                or script[36] != vm.OpCode.SYSCALL
                or int.from_bytes(script[37:41], 'little') != contracts.syscall_name_to_int(
                    "Neo.Crypto.VerifyWithECDsaSecp256r1")):
            return False
        return True

    @staticmethod
    def is_multisig_contract(script: bytes) -> bool:
        """
        Test if the provided script is multi-signature contract.

        Args:
            script: contract script.
        """

        len_script = len(script)
        if len_script < 43:
            return False

        # read signature length, which is encoded as variable_length
        first_byte = script[0]
        if first_byte == int(vm.OpCode.PUSHINT8):
            signature_count = script[1]
            i = 2
        elif first_byte == int(vm.OpCode.PUSHINT16):
            signature_count = int.from_bytes(script[1:3], 'little', signed=False)
            i = 3
        elif int(vm.OpCode.PUSH1) <= first_byte <= int(vm.OpCode.PUSH16):
            signature_count = first_byte - int(vm.OpCode.PUSH0)
            i = 1
        else:
            return False

        if signature_count < 1 or signature_count > 1024:
            return False

        # try reading public keys and do a basic format validation
        pushdata1 = int(vm.OpCode.PUSHDATA1)
        public_key_count = 0
        while script[i] == pushdata1:
            if len_script <= i + 35:
                return False
            if script[i + 1] != 33:
                return False
            i += 35
            public_key_count += 1

        if public_key_count < signature_count or public_key_count > 1024:
            return False

        # validate that the number of collected public keys match the expected count
        value = script[i]
        if value == int(vm.OpCode.PUSHINT8):
            if len_script <= i + 1 or public_key_count != script[i + 1]:
                return False
            i += 2
        elif value == int(vm.OpCode.PUSHINT16):
            if len_script < i + 3 or public_key_count != int.from_bytes(script[i + 1:i + 3], 'little', signed=False):
                return False
            i += 3
        elif int(vm.OpCode.PUSH1) <= value <= int(vm.OpCode.PUSH16):
            if public_key_count != value - int(vm.OpCode.PUSH0):
                return False
            i += 1
        else:
            return False

        if len_script != i + 6:
            return False

        if script[i] != int(vm.OpCode.PUSHNULL):
            return False
        if script[i + 1] != int(vm.OpCode.SYSCALL):
            return False
        i += 2

        syscall_num = int.from_bytes(script[i:i + 4], 'little')
        if syscall_num != contracts.syscall_name_to_int("Neo.Crypto.CheckMultisigWithECDsaSecp256r1"):
            return False
        return True
