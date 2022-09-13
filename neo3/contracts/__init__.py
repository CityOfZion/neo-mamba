from __future__ import annotations
import typing
from .callflags import CallFlags
from .descriptor import ContractPermissionDescriptor
from .manifest import (ContractGroup,
                       ContractManifest,
                       ContractPermission,
                       WildcardContainer)

from .abi import (ContractParameterType,
                  ContractMethodDescriptor,
                  ContractEventDescriptor,
                  ContractParameterDefinition,
                  ContractABI)
from .nef import (NEF, MethodToken)
from .contract import (Contract, ContractState)
from .findoptions import FindOptions
from dataclasses import dataclass
from neo3.core import types, to_script_hash
from . import vm


@dataclass
class ContractHashes:

    CRYPTO_LIB = types.UInt160.from_string("0x726cb6e0cd8628a1350a611384688911ab75f51b")
    GAS_TOKEN = types.UInt160.from_string("0xd2a4cff31913016155e38e474a2c06d08be276cf")
    LEDGER = types.UInt160.from_string("0xda65b600f7124ce6c79950c1772a36403104f2be")
    MANAGEMENT = types.UInt160.from_string("0xfffdc93764dbaddd97c48f252a53ea4643faa3fd")
    NEO_TOKEN = types.UInt160.from_string("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")
    ORACLE = types.UInt160.from_string("0xfe924b7cfe89ddd271abaf7210a80a7e11178758")
    POLICY = types.UInt160.from_string("0xcc5e4edd9f5f8dba8bb65734541df7a1c081c67b")
    ROLE_MANAGEMENT = types.UInt160.from_string("0x49cf4e5378ffcd4dec034fd98a174c5491e395e2")
    STD_LIB = types.UInt160.from_string("0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0")


# Neo's native contract hashes
CONTRACT_HASHES = ContractHashes()


def validate_type(obj: object, type_: typing.Type):
    if type(obj) != type_:
        raise ValueError(f"Expected type '{type_}' , got '{type(obj)}' instead")
    return obj


def get_contract_hash(sender: types.UInt160, nef_checksum: int, contract_name: str) -> types.UInt160:
    sb = vm.ScriptBuilder()
    sb.emit(vm.OpCode.ABORT)
    sb.emit_push(sender)
    sb.emit_push(nef_checksum)
    sb.emit_push(contract_name)
    return to_script_hash(sb.to_array())


__all__ = ['ContractParameterType',
           'ContractMethodDescriptor',
           'ContractEventDescriptor',
           'ContractParameterDefinition',
           'Contract',
           'ContractState',
           'CallFlags',
           'NEF',
           'MethodToken',
           'FindOptions',
           'get_contract_hash']
