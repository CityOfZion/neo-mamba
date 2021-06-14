from __future__ import annotations

import binascii
from typing import List, cast, Tuple
from copy import deepcopy
from neo3 import contracts, vm
from neo3.core import cryptography, to_script_hash, types, serialization, IClonable, IInteroperable, Size as s


class Contract:
    def __init__(self, script: bytes, parameter_list: List[contracts.ContractParameterType]):
        #: The contract instructions (OpCodes)
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
        sb.emit_syscall(contracts.syscall_name_to_int("System.Crypto.CheckMultisig"))
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
        sb.emit_syscall(contracts.syscall_name_to_int("System.Crypto.CheckSig"))
        return sb.to_array()

    @staticmethod
    def is_signature_contract(script: bytes) -> bool:
        """
        Test if the provided script is signature contract.

        Args:
            script: contract script.
        """
        if len(script) != 40:
            return False

        if (script[0] != vm.OpCode.PUSHDATA1
                or script[1] != 33
                or script[35] != vm.OpCode.SYSCALL
                or int.from_bytes(script[36:40], 'little') != contracts.syscall_name_to_int(
                    "System.Crypto.CheckSig")):
            return False
        return True

    @staticmethod
    def is_multisig_contract(script: bytes) -> bool:
        """
        Test if the provided script is multi-signature contract.

        Args:
            script: contract script.
        """
        valid, _, _ = Contract.parse_as_multisig_contract(script)
        return valid

    @staticmethod
    def parse_as_multisig_contract(script: bytes) -> Tuple[bool, int, List[cryptography.ECPoint]]:
        """
        Try to parse script as multisig contract and extract related data.

        Args:
            script: array of vm byte code

        Returns:
            bool: True if the script passes as a valid multisignature contract script. False otherwise
            int: the signing threshold if validation passed. 0 otherwise
            list[ECPoint]: the public keys in the script if valiation passed. An empty array otherwise.
        """
        script = bytes(script)
        VALIDATION_FAILURE: Tuple[bool, int, List[cryptography.ECPoint]] = (False, 0, [])

        len_script = len(script)
        if len_script < 42:
            return VALIDATION_FAILURE

        # read signature length, which is encoded as variable_length
        first_byte = script[0]
        if first_byte == int(vm.OpCode.PUSHINT8):
            signature_threshold = script[1]
            i = 2
        elif first_byte == int(vm.OpCode.PUSHINT16):
            signature_threshold = int.from_bytes(script[1:3], 'little', signed=False)
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
            public_keys.append(cryptography.ECPoint.deserialize_from_bytes(script[i + 2:i + 2 + 33]))
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
            if len_script < i + 3 or public_key_count != int.from_bytes(script[i + 1:i + 3], 'little', signed=False):
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

        syscall_num = int.from_bytes(script[i:i + 4], 'little')
        if syscall_num != contracts.syscall_name_to_int("System.Crypto.CheckMultisig"):
            return VALIDATION_FAILURE
        return True, signature_threshold, public_keys

    @staticmethod
    def get_consensus_address(validators: List[cryptography.ECPoint]) -> types.UInt160:
        script = contracts.Contract.create_multisig_redeemscript(
            len(validators) - (len(validators) - 1) // 3,
            validators
        )
        return to_script_hash(script)


class ContractState(serialization.ISerializable, IClonable, IInteroperable):
    def __init__(self,
                 id_: int,
                 nef: contracts.NEF,
                 manifest_: contracts.ContractManifest,
                 update_counter: int,
                 hash_: types.UInt160):
        self.id = id_
        self.nef = nef
        self.manifest = manifest_
        self.update_counter = update_counter
        self.hash = hash_

    def __len__(self):
        return (s.uint32  # id
                + len(self.nef.to_array())
                + len(self.manifest)
                + s.uint16  # update counter
                + len(self.hash))

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.hash != other.hash:
            return False
        return True

    def __deepcopy__(self, memodict={}):
        return ContractState.deserialize_from_bytes(self.to_array())

    @property
    def script(self) -> bytes:
        return self.nef.script

    @script.setter
    def script(self, value: bytes) -> None:
        self.nef.script = value

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_int32(self.id)
        writer.write_serializable(self.nef)
        writer.write_serializable(self.manifest)
        writer.write_uint16(self.update_counter)
        writer.write_serializable(self.hash)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.id = reader.read_int32()
        self.nef = reader.read_serializable(contracts.NEF)
        self.manifest = reader.read_serializable(contracts.ContractManifest)
        self.update_counter = reader.read_uint16()
        self.hash = reader.read_serializable(types.UInt160)

    def from_replica(self, replica):
        super().from_replica(replica)
        self.id = replica.id
        self.nef = replica.nef
        self.manifest = replica.manifest
        self.update_counter = replica.update_counter
        self.hash = replica.hash

    def clone(self):
        return ContractState(self.id, deepcopy(self.nef), deepcopy(self.manifest), self.update_counter, self.hash)

    @classmethod
    def from_stack_item(cls, stack_item: vm.StackItem):
        array = cast(vm.ArrayStackItem, stack_item)
        id = int(array[0].to_biginteger())
        update_counter = int(array[1].to_biginteger())
        hash_ = types.UInt160(array[2].to_array())
        nef = contracts.NEF.deserialize_from_bytes(array[3].to_array())
        manifest = contracts.ContractManifest.deserialize_from_bytes(array[4].to_array())
        return cls(id, nef, manifest, update_counter, hash_)

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        array = vm.ArrayStackItem(reference_counter)
        id_ = vm.IntegerStackItem(self.id)
        nef = vm.ByteStringStackItem(self.nef.to_array())
        update_counter = vm.IntegerStackItem(self.update_counter)
        hash_ = vm.ByteStringStackItem(self.hash.to_array())
        array.append([id_, update_counter, hash_, nef, self.manifest.to_stack_item(reference_counter)])
        return array

    def can_call(self, target_contract: ContractState, target_method: str) -> bool:
        results = list(map(lambda p: p.is_allowed(target_contract, target_method), self.manifest.permissions))
        return any(results)

    @classmethod
    def _serializable_init(cls):
        return cls(0, contracts.NEF._serializable_init(), contracts.ContractManifest(), 0, types.UInt160.zero())
