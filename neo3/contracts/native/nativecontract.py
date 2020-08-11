from __future__ import annotations
import abc
import hashlib
from typing import List, Callable, Dict, Set
from neo3 import contracts, vm
from neo3.core import types, utils
from enum import IntFlag


class CallFlags(IntFlag):
    NONE = 0,
    ALLOW_STATES = 0x1
    ALLOW_MODIFIED_STATES = 0x02
    ALLOW_CALL = 0x04
    ALLOW_NOTIFY = 0x08
    READ_ONLY = ALLOW_STATES | ALLOW_CALL | ALLOW_NOTIFY
    ALL = ALLOW_STATES | ALLOW_MODIFIED_STATES | ALLOW_CALL | ALLOW_NOTIFY


class ContractMethodMetadata:
    def __init__(self, delegate: Callable[[contracts.ApplicationEngine, vm.ArrayStackItem, vm.StackItem], None],
                 price: int,
                 required_flags: CallFlags):
        self.delegate = delegate
        self.price = price
        self.required_flag = required_flags


def RequiredAttributes(*required_attrs):

    class RequiredAttributesMeta(type):
        def __init__(cls, name, bases, attrs):
            missing_attrs = ["'%s'" % attr for attr in required_attrs
                             if not hasattr(cls, attr)]
            if missing_attrs:
                raise AttributeError("class '%s' requires attribute%s %s" %
                                     (name, "s" * (len(missing_attrs) > 1),
                                      ", ".join(missing_attrs)))
    return RequiredAttributesMeta


class NativeContract:
    __metaclass__ = RequiredAttributes("_id", "_service_name")

    _id: int = -1
    _service_name: str = "override me"

    def __init__(self):
        self._contracts: List[NativeContract] = []
        self._methods: Dict[str, ContractMethodMetadata] = {}
        self._neo = None  # TODO: NeoToken()
        self._gas = None  # TODO: GasToken()
        self._policy = None  # TODO: PolicyContract()
        self._service_hash: int = int.from_bytes(hashlib.sha256(self._service_name.encode()).digest()[:4],
                                                 'little', signed=False)
        self._script: bytes = vm.ScriptBuilder().emit_syscall(self._service_hash).to_array()
        self._hash: types.UInt160 = utils.script_hash_from_bytes(self._script)
        self._manifest: contracts.ContractManifest = contracts.ContractManifest(contract_hash=self._hash)
        self._manifest.abi.methods = []
        self._manifest.safe_methods = contracts.WildcardContainer()
        self._register_contract_method(self.supported_standards,
                                       "supportedStandards",
                                       0,
                                       contracts.ContractParameterType.ARRAY,
                                       safe_method=True)

    def _register_contract_method(self,
                                  func: Callable,
                                  func_name: str,
                                  price: int,
                                  return_type: contracts.ContractParameterType,
                                  parameter_types: List[contracts.ContractParameterType] = None,
                                  parameter_names: List[str] = None,
                                  safe_method: bool = False
                                  ):
        """
        Registers a contract method into the manifest

        Args:
            func: func pointer.
            func_name: the name of the callable function.
            price: the cost of calling the function.
            return_type: the function return value type.
            parameter_types: the function argument types.
            parameter_names: the function argument names.
            safe_method: dumb logic NEO added that we must support. See https://github.com/neo-project/neo/issues/1664
        """
        params = []
        if parameter_types is not None and parameter_names is not None:
            if len(parameter_types) != len(parameter_names):
                raise ValueError(f"Parameter types count must match parameter names count! "
                                 f"{len(parameter_types)}!={len(parameter_names)}")

            for t, n in zip(parameter_types, parameter_names):
                params.append(contracts.ContractParameterDefinition(
                    name=n,
                    type=t
                ))

        self._manifest.abi.methods.append(
            contracts.ContractMethodDescriptor(
                name=func_name,
                offset=-1,
                return_type=return_type,
                parameters=params
            )
        )
        self._manifest.safe_methods._data.append(func_name)
        call_flags = CallFlags.NONE if safe_method else CallFlags.ALLOW_MODIFIED_STATES
        self._methods.update({func_name: ContractMethodMetadata(func, price, call_flags)})

    @property
    def neo(self):
        return self._neo

    @property
    def gas(self):
        return self._gas

    @property
    def policy(self):
        return self._policy

    @property
    def service_name(self) -> str:
        return self._service_name

    @property
    def service_hash(self) -> int:
        return self._service_hash

    @property
    def script(self) -> bytes:
        return self._script

    @property
    def hash(self) -> types.UInt160:
        return self._hash

    @property
    def id(self) -> int:
        return self._id

    @property
    def manifest(self) -> contracts.ContractManifest:
        return self._manifest

    @abc.abstractmethod
    def supported_standards(self) -> Set[str]:
        return set("NEP-10")

    @staticmethod
    def initialize(engine: contracts.ApplicationEngine) -> bool:
        """
        Args:
            engine: ApplicationEngine
        Raises:
            ValueError: if the engine is not configured with APPLICATION trigger type
        """
        if engine.trigger != contracts.TriggerType.APPLICATION:
            raise ValueError(f"Invalid trigger {engine.trigger}, must be APPLICATION")
        return True

    def invoke(self, engine: contracts.ApplicationEngine):
        # TODO: implement
        pass
