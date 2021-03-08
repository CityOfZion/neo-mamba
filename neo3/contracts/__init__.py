from __future__ import annotations
import hashlib
from .callflags import CallFlags
from .contracttypes import (TriggerType)
from .descriptor import (ContractPermissionDescriptor)
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
from .binaryserializer import BinarySerializer
from .jsonserializer import (NEOJson, JSONSerializer)
from .findoptions import FindOptions
from .applicationengine import ApplicationEngine
from .native import (NativeContract,
                     PolicyContract,
                     NeoToken,
                     GasToken,
                     OracleContract,
                     DesignationContract,
                     DesignateRole,
                     ManagementContract,
                     NonFungibleToken,
                     NFTState,
                     NameService,
                     LedgerContract)


def syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)


__all__ = ['ContractParameterType',
           'TriggerType',
           'ContractMethodDescriptor',
           'ContractEventDescriptor',
           'ContractParameterDefinition',
           'Contract',
           'ContractState',
           'BinarySerializer',
           'NEOJson',
           'JSONSerializer',
           'NativeContract',
           'CallFlags',
           'PolicyContract',
           'ApplicationEngine',
           'syscall_name_to_int',
           'DesignationContract',
           'DesignateRole',
           'NameService',
           'LedgerContract',
           'NEF',
           'MethodToken',
           'FindOptions']
