from __future__ import annotations
import hashlib
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
from neo3.core import types


@dataclass
class ContractHashes:
    MANAGEMENT: types.UInt160 = types.UInt160.from_string("0xfffdc93764dbaddd97c48f252a53ea4643faa3fd")


CONTRACT_HASHES = ContractHashes()


def syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)


def validate_type(obj: object, type_: typing.Type):
    if type(obj) != type_:
        raise ValueError(f"Expected type '{type_}' , got '{type(obj)}' instead")
    return obj


__all__ = ['ContractParameterType',
           'ContractMethodDescriptor',
           'ContractEventDescriptor',
           'ContractParameterDefinition',
           'Contract',
           'ContractState',
           'CallFlags',
           'syscall_name_to_int',
           'NEF',
           'MethodToken',
           'FindOptions']
