"""
Smart contract and account contract classes. Contains a list of all native contracts.
"""
from __future__ import annotations
from collections.abc import Sequence
from dataclasses import dataclass
from neo3.contracts import abi, utils, nef, manifest
from neo3.core import cryptography, utils as coreutils, types, serialization, Size as s


@dataclass
class _ContractHashes:
    CRYPTO_LIB = types.UInt160.from_string("0x726cb6e0cd8628a1350a611384688911ab75f51b")
    GAS_TOKEN = types.UInt160.from_string("0xd2a4cff31913016155e38e474a2c06d08be276cf")
    LEDGER = types.UInt160.from_string("0xda65b600f7124ce6c79950c1772a36403104f2be")
    MANAGEMENT = types.UInt160.from_string("0xfffdc93764dbaddd97c48f252a53ea4643faa3fd")
    NEO_TOKEN = types.UInt160.from_string("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")
    ORACLE = types.UInt160.from_string("0xfe924b7cfe89ddd271abaf7210a80a7e11178758")
    POLICY = types.UInt160.from_string("0xcc5e4edd9f5f8dba8bb65734541df7a1c081c67b")
    ROLE_MANAGEMENT = types.UInt160.from_string(
        "0x49cf4e5378ffcd4dec034fd98a174c5491e395e2"
    )
    STD_LIB = types.UInt160.from_string("0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0")


#: List of Neo's native contract hashes.
CONTRACT_HASHES = _ContractHashes()


class Contract:
    """
    Generic contract.
    """

    def __init__(
        self, script: bytes, parameter_list: Sequence[abi.ContractParameterType]
    ):
        #: The contract instructions (OpCodes)
        self.script = script
        self.parameter_list = parameter_list
        self._script_hash = coreutils.to_script_hash(self.script)
        self._address = None

    @property
    def script_hash(self) -> types.UInt160:
        """
        The contract script hash.
        """
        return self._script_hash

    @classmethod
    def create_multisig_contract(
        cls, m: int, public_keys: Sequence[cryptography.ECPoint]
    ) -> Contract:
        """
        Create a multi-signature contract requiring `m` signatures from the list `public_keys`.

        Args:
            m: minimum number of signature required for signing. Can't be lower than 2.
            public_keys: public keys to use during verification.
        """
        return cls(
            script=utils.create_multisig_redeemscript(m, public_keys),
            parameter_list=[abi.ContractParameterType.SIGNATURE] * m,
        )

    @classmethod
    def create_signature_contract(cls, public_key: cryptography.ECPoint) -> Contract:
        """
        Create a signature contract.

        Args:
            public_key: the public key to use during verification.
        """
        return cls(
            utils.create_signature_redeemscript(public_key),
            [abi.ContractParameterType.SIGNATURE],
        )


class ContractState(serialization.ISerializable):
    """
    Smart contract chain state container.
    """

    def __init__(
        self,
        id_: int,
        nef: nef.NEF,
        manifest_: manifest.ContractManifest,
        update_counter: int,
        hash_: types.UInt160,
    ):
        self.id = id_
        self.nef = nef
        self.manifest = manifest_
        self.update_counter = update_counter
        self.hash = hash_

    def __len__(self):
        return (
            s.uint32  # id
            + len(self.nef.to_array())
            + len(self.manifest)
            + s.uint16  # update counter
            + len(self.hash)
        )

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
        """
        NEF script
        """
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
        self.nef = reader.read_serializable(nef.NEF)
        self.manifest = reader.read_serializable(manifest.ContractManifest)
        self.update_counter = reader.read_uint16()
        self.hash = reader.read_serializable(types.UInt160)

    def can_call(self, target_contract: ContractState, target_method: str) -> bool:
        """
        Utility function to check if the contract has permission to call `target_method` on `target_contract`.

        Args:
            target_contract:
            target_method:

        Returns:
            `True` if allowed. `False` if not possible.
        """
        results = list(
            map(
                lambda p: p.is_allowed(
                    target_contract.hash, target_contract.manifest, target_method
                ),
                self.manifest.permissions,
            )
        )
        return any(results)

    @classmethod
    def _serializable_init(cls):
        return cls(
            0,
            nef.NEF._serializable_init(),
            manifest.ContractManifest(),
            0,
            types.UInt160.zero(),
        )
