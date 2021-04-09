from __future__ import annotations
import inspect
from typing import List, Callable, Dict, Tuple, Any, Optional, get_type_hints
from neo3 import contracts, vm, storage, settings
from neo3.core import types, to_script_hash
from neo3.network import convenience


class _ContractMethodMetadata:
    """
    Internal helper class containing meta data that helps in translating VM Stack Items to the arguments types of the
     handling function. Applies to native contracts only.
    """

    def __init__(self, handler: Callable[..., None],
                 price: int,
                 required_flags: contracts.CallFlags,
                 add_engine: bool,
                 add_snapshot: bool,
                 return_type,
                 parameter_types=None):
        self.handler = handler
        self.price = price
        self.return_type = return_type
        self.parameters = parameter_types if parameter_types else []
        self.required_flags = required_flags
        self.add_engine = add_engine
        self.add_snapshot = add_snapshot


class _NativeMethodMeta:
    def __init__(self, func: Callable):
        self.handler = func
        self.name: str = func.name  # type:ignore
        self.price: int = func.price  # type: ignore
        self.required_flags: contracts.CallFlags = func.flags  # type: ignore
        self.add_engine = False
        self.add_snapshot = False
        self.return_type = None

        parameter_types = []
        parameter_names = []
        for k, v in get_type_hints(func).items():
            if k == 'return':
                if v != type(None):
                    self.return_type = v
                continue
            parameter_types.append(v)
            parameter_names.append(k)

        # check if engine or snapshot should be included
        # and filter this from the parameter list for the ABI
        if len(parameter_types) > 0:
            if parameter_types[0] == contracts.ApplicationEngine:
                self.add_engine = True
                parameter_types = parameter_types[1:]
            elif parameter_types[0] == storage.Snapshot:
                self.add_snapshot = True
                parameter_types = parameter_types[1:]

        params = []
        for t, n in zip(parameter_types, parameter_names):
            params.append(contracts.ContractParameterDefinition(
                name=n,
                type=contracts.ContractParameterType.from_type(t)
            ))
        self.parameter_types = parameter_types
        self.descriptor = contracts.ContractMethodDescriptor(
            name=func.name,  # type: ignore
            offset=0,
            return_type=contracts.ContractParameterType.from_type(self.return_type),
            parameters=params,
            safe=(func.flags & ~contracts.CallFlags.READ_ONLY) == 0  # type: ignore
        )


class NativeContract(convenience._Singleton):
    #: unique contract identifier
    _id: int = -99999

    #: A dictionary of all native contracts in the system
    _contracts: Dict[str, NativeContract] = {}
    #: A dictionary for accessing a native contract by its hash
    _contract_hashes: Dict[types.UInt160, NativeContract] = {}

    _service_name: Optional[str] = None

    active_block_index = 0

    def init(self):
        self._methods: Dict[int, _NativeMethodMeta] = {}  # offset, meta

        self._management = contracts.ManagementContract()
        self._neo = contracts.NeoToken()
        self._gas = contracts.GasToken()
        self._policy = contracts.PolicyContract()
        self._nameservice = contracts.NameService()
        self._oracle = contracts.OracleContract()
        self._ledger = contracts.LedgerContract()
        self._role = contracts.DesignationContract()

        methods_meta = []
        for pair in inspect.getmembers(self, lambda m: hasattr(m, "native_call")):
            methods_meta.append(_NativeMethodMeta(pair[1]))

        methods_meta.sort(key=lambda x: (x.descriptor.name, len(x.descriptor.parameters)))

        sb = vm.ScriptBuilder()
        for meta in methods_meta:
            meta.descriptor.offset = len(sb)
            sb.emit_push(0)
            self._methods.update({len(sb): meta})
            sb.emit_syscall(1736177434)  # "System.Contract.CallNative"
            sb.emit(vm.OpCode.RET)

        self._script: bytes = sb.to_array()
        self.nef = contracts.NEF("neo-core-v3.0", self._script)

        sender = types.UInt160.zero()  # OpCode.PUSH1
        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.ABORT)
        sb.emit_push(sender.to_array())
        sb.emit_push(0)
        sb.emit_push(self.service_name())
        self._hash: types.UInt160 = to_script_hash(sb.to_array())
        self._manifest: contracts.ContractManifest = contracts.ContractManifest()
        self._manifest.name = self.service_name()
        self._manifest.abi.methods = list(map(lambda m: m.descriptor, methods_meta))

        if self._id != NativeContract._id:
            self._contracts.update({self.service_name(): self})
            self._contract_hashes.update({self._hash: self})

        self.active_block_index = settings.native_contract_activation.get(self.service_name, 0)

    @classmethod
    def get_contract_by_name(cls, name: str) -> Optional[NativeContract]:
        """
        Get the contract instance by its service name
        Args:
            name: service name of the contract

        """
        contract = cls._contracts.get(name, None)
        return contract

    @classmethod
    def get_contract_by_id(cls, contract_id: int) -> Optional[NativeContract]:
        for contract in cls._contracts.values():
            if contract_id == contract.id:
                return contract
        else:
            return None

    @classmethod
    def get_contract_by_hash(cls, contract_hash: types.UInt160) -> Optional[NativeContract]:
        return cls._contract_hashes.get(contract_hash, None)

    @property
    def registered_contract_names(self) -> List[str]:
        """ The names of all deployed contracts. """
        return list(self._contracts.keys())

    @property
    def registered_contracts(self) -> List[NativeContract]:
        """ All deployed contracts. """
        return list(self._contracts.values())

    def service_name(self) -> str:
        """ The human readable name. """
        if self._service_name is None:
            return self.__class__.__name__
        else:
            return self._service_name

    @property
    def script(self) -> bytes:
        """ The contract byte code. """
        return self._script

    @property
    def hash(self) -> types.UInt160:
        """ Contract hash based of the contracts byte code + sender. """
        return self._hash

    @property
    def id(self) -> int:
        """ Unique identifier. """
        return self._id

    @property
    def manifest(self) -> contracts.ContractManifest:
        """ The associated contract manifest. """
        return self._manifest

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        """
        Called once when a native contract is deployed

        Args:
            engine: ApplicationEngine
        """

    def invoke(self, engine: contracts.ApplicationEngine, version: int) -> None:
        """
        Calls a contract function

        Reads the required arguments from the engine's stack and converts them to the appropiate contract function types

        Args:
            engine: the engine executing the smart contract
            version: which version of the smart contract to load

        Raises:
             SystemError: if not the contract is not yet active
             ValueError: if the request contract version is not
             ValueError: if the function to be called does not exist on the contract
             ValueError: if trying to call a function without having the correct CallFlags
        """
        if self.active_block_index > engine.snapshot.best_block_height:
            raise SystemError(f"The request native contract {self.service_name()} is not active until height"
                              f" {self.active_block_index}")
        if version != 0:
            raise ValueError(f"Native contract version {version} is not active")  # type: ignore

        context = engine.current_context
        flags = contracts.CallFlags(context.call_flags)
        method = self._methods.get(context.ip, None)
        if method is None:
            raise ValueError(f"Method at IP \"{context.ip}\" does not exist on contract {self.service_name()}")
        if method.required_flags not in flags:
            raise ValueError(f"Method requires call flag: {method.required_flags} received: {flags}")

        engine.add_gas(method.price)

        params: List[Any] = []
        if method.add_engine:
            params.append(engine)

        if method.add_snapshot:
            params.append(engine.snapshot)

        for t in method.parameter_types:
            params.append(engine._stackitem_to_native(context.evaluation_stack.pop(), t))

        if len(params) > 0:
            return_value = method.handler(*params)
        else:
            return_value = method.handler()
        if method.return_type is not None:
            context.evaluation_stack.push(engine._native_to_stackitem(return_value, type(return_value)))

    @staticmethod
    def is_native(hash_: types.UInt160) -> bool:
        """
        Determine if the hash belong to a native contract.

        Args:
            hash_: a script hash

        Returns:
            True: if a contract is found matching the hash. False otherwise.
        """
        return hash_ in NativeContract._contract_hashes

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        """
        Called by the Blockchain class when persisting a block.
        It will trigger the minting of GAS and updating of the NextValidators in storage

        Should not be called manually.
        """
        pass

    def post_persist(self, engine: contracts.ApplicationEngine):
        pass

    def _check_committee(self, engine: contracts.ApplicationEngine) -> bool:
        addr = contracts.NeoToken().get_committee_address(engine.snapshot)
        return engine.checkwitness(addr)

    def create_key(self, prefix: bytes) -> storage.StorageKey:
        return storage.StorageKey(self._id, prefix)
