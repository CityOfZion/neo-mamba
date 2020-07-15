from __future__ import annotations
from enum import Enum
from typing import List
from neo3 import contracts
from neo3.core import cryptography
from neo3 import vm


class Contract:
    def __init__(self, script: bytes, parameter_list: List[contracts.ContractParameterType]):
        self.script = script
        self.parameter_list = parameter_list
        self._script_hash = None
        self._address = None

    @property
    def script_hash(self):
        return

    @classmethod
    def create_multisig_contract(cls, m: int, public_keys: List[cryptography.EllipticCurve.ECPoint]) -> Contract:
        return cls(script=cls.create_multisig_redeemscript(m, public_keys),
                   parameter_list=[contracts.ContractParameterType.SIGNATURE] * m)

    @staticmethod
    def create_multisig_redeemscript(m: int, public_keys: List[cryptography.EllipticCurve.ECPoint]) -> bytes:
        """

        Args:
            m: minimum number of signature required for signing. Can't be lower than 2.
            public_keys: public keys to verify against in the syscall.
        """
        if m < 1:
            raise Exception(f"Minimum required signature count is 1, specified {m}.")

        if m > len(public_keys):
            raise Exception("Invalid public key count. "
                            "Minimum required signatures is bigger than supplied public keys count.")

        if len(public_keys) > 1024:
            raise Exception(f"Supplied public key count ({len(public_keys)}) exceeds maximum of 1024.")

        sb = vm.ScriptBuilder()
        sb.emit_push(m)
        public_keys.sort()

        for key in public_keys:
            sb.emit_push(key.encode_point(True))

        sb.emit_push(len(public_keys))
        sb.emit(vm.OpCode.PUSHNULL)
        sb.emit_syscall(123)  # TODO: Fix this with correct syscall!
        return sb.to_array()

    @classmethod
    def create_signature_contract(cls, public_key: cryptography.EllipticCurve.ECPoint):
        return cls(cls.create_signature_redeemscript(public_key), [contracts.ContractParameterType.SIGNATURE])

    @staticmethod
    def create_signature_redeemscript(public_key: cryptography.EllipticCurve.ECPoint) -> bytes:
        sb = vm.ScriptBuilder()
        sb.emit_push(public_key.encode_point(True))
        sb.emit(vm.OpCode.PUSHNULL)
        sb.emit_syscall(123)  # TODO: fix this with correct syscalL!
        return sb.to_array()
