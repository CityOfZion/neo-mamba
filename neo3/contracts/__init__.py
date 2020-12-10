from __future__ import annotations
import hashlib
from .contracttypes import (TriggerType)
from .descriptor import (ContractPermissionDescriptor)
from .manifest import (ContractGroup,
                       ContractFeatures,
                       ContractManifest,
                       ContractPermission,
                       WildcardContainer)

from .abi import (ContractParameterType,
                  ContractMethodDescriptor,
                  ContractEventDescriptor,
                  ContractParameterDefinition,
                  ContractABI)
from .nef import (NEF, Version)
from .contract import Contract
from .binaryserializer import BinarySerializer
from .jsonserializer import (NEOJson, JSONSerializer)
from .native import (CallFlags, NativeContract, PolicyContract, NeoToken, GasToken)
from .applicationengine import ApplicationEngine


def syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)


__all__ = ['ContractParameterType',
           'TriggerType',
           'ContractMethodDescriptor',
           'ContractEventDescriptor',
           'ContractParameterDefinition',
           'Contract',
           'BinarySerializer',
           'NEOJson',
           'JSONSerializer',
           'NativeContract',
           'CallFlags',
           'PolicyContract',
           'ApplicationEngine',
           'syscall_name_to_int']
