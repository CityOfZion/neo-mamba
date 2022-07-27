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
