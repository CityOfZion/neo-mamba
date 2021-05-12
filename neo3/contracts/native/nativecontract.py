from __future__ import annotations
import inspect
from typing import List, Callable, Dict, Any, Optional, get_type_hints
from neo3 import contracts, vm, storage, settings
from neo3.core import types, to_script_hash
from neo3.network import convenience


class _NativeMethodMeta:
    def __init__(self, func: Callable):
        self.handler = func
        self.name: str = func.name  # type:ignore
        self.cpu_price: int = func.cpu_price  # type: ignore
        self.storage_price: int = func.storage_price  # type: ignore
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
            if v == contracts.ApplicationEngine:
                self.add_engine = True
                continue
            elif v == storage.Snapshot:
                self.add_snapshot = True
                continue
            parameter_types.append(v)
            parameter_names.append(k)

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

    #: Allows for overriding the contract name in the ABI. Otherwise the name equals the class name.
    _service_name: Optional[str] = None

    #: The block index at which the native contract becomes active.
    active_block_index = 0

    def init(self):
        self._methods: Dict[int, _NativeMethodMeta] = {}  # offset, meta

        self._management = contracts.ManagementContract()
        self._neo = contracts.NeoToken()
        self._gas = contracts.GasToken()
        self._policy = contracts.PolicyContract()
        self._oracle = contracts.OracleContract()
        self._ledger = contracts.LedgerContract()
        self._role = contracts.DesignationContract()
        self._crypto = contracts.CryptoContract()
        self._stdlib = contracts.StdLibContract()

        # Find all methods that have been augmented by the @register decorator
        # and turn them into methods that can be called by VM scripts
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
        """ Get the native contract by its service id """
        for contract in cls._contracts.values():
            if contract_id == contract.id:
                return contract
        else:
            return None

    @classmethod
    def get_contract_by_hash(cls, contract_hash: types.UInt160) -> Optional[NativeContract]:
        """ Get the native contract by its contract hash """
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

    def invoke(self, engine: contracts.ApplicationEngine, version: int) -> None:
        """
        Calls a contract function

        Reads the required arguments from the engine's stack and converts them to the appropiate contract function types

        Args:
            engine: the engine executing the smart contract
            version: which version of the smart contract to load

        Raises:
             ValueError: if the request contract version is not
             ValueError: if the function to be called does not exist on the contract
             ValueError: if trying to call a function without having the correct CallFlags
        """
        if version != 0:
            raise ValueError(f"Native contract version {version} is not active")  # type: ignore

        context = engine.current_context
        flags = contracts.CallFlags(context.call_flags)
        method = self._methods.get(context.ip, None)
        if method is None:
            raise ValueError(f"Method at IP \"{context.ip}\" does not exist on contract {self.service_name()}")
        if method.required_flags not in flags:
            raise ValueError(f"Method requires call flag: {method.required_flags} received: {flags}")

        engine.add_gas(method.cpu_price
                       * contracts.PolicyContract().get_exec_fee_factor(engine.snapshot)
                       + method.storage_price
                       * contracts.PolicyContract().get_storage_price(engine.snapshot))

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

    def create_key(self, prefix: bytes) -> storage.StorageKey:
        """
        Helper to create a storage key for the contract

        Args:
            prefix: the storage prefix to be used
        """
        return storage.StorageKey(self._id, prefix)

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        """
        Called once when a native contract is deployed

        Args:
            engine: ApplicationEngine
        """

    def _check_committee(self, engine: contracts.ApplicationEngine) -> bool:
        addr = contracts.NeoToken().get_committee_address(engine.snapshot)
        return engine.checkwitness(addr)
