from __future__ import annotations
from typing import List, Callable, Dict, Tuple, Iterator, Any, cast, Optional
from neo3 import contracts, vm, storage, settings
from neo3.core import types, to_script_hash, serialization, cryptography, msgrouter, Size as s
from neo3.network import message, convenience
from enum import IntFlag
from collections import Sequence


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
        self.required_flag = required_flags
        self.add_engine = add_engine
        self.add_snapshot = add_snapshot


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
        self._methods: Dict[str, _ContractMethodMetadata] = {}

        self._management = contracts.ManagementContract()
        self._neo = NeoToken()
        self._gas = GasToken()
        self._policy = PolicyContract()
        self._nameservice = contracts.NameService()
        self._oracle = contracts.OracleContract()

        sb = vm.ScriptBuilder()
        sb.emit_push(self.id)
        sb.emit_syscall(1736177434)  # "System.Contract.CallNative"
        self._script: bytes = sb.to_array()
        self.nef = contracts.NEF("ScriptBuilder", "3.0", self._script)
        sender = types.UInt160.zero()  # OpCode.PUSH1
        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.ABORT)
        sb.emit_push(sender.to_array())
        sb.emit_push(self._script)
        self._hash: types.UInt160 = to_script_hash(sb.to_array())
        self._manifest: contracts.ContractManifest = contracts.ContractManifest()
        self._manifest.name = self.service_name()
        self._manifest.abi.methods = []
        if self._id != NativeContract._id:
            self._contracts.update({self.service_name(): self})
            self._contract_hashes.update({self._hash: self})

        self.active_block_index = settings.native_contract_activation.get(self.service_name, 0)

        self._register_contract_method(self.on_persist,
                                       "onPersist",
                                       0,
                                       return_type=None,
                                       add_engine=True,
                                       add_snapshot=False,
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self.post_persist,
                                       "postPersist",
                                       0,
                                       return_type=None,
                                       add_engine=True,
                                       add_snapshot=False,
                                       call_flags=contracts.CallFlags.WRITE_STATES)

    @classmethod
    def get_contract_by_name(cls, name: str) -> Optional[NativeContract]:
        """
        Get the contract instance by its service name
        Args:
            name: service name of the contract

        Raise:
            ValueError: if the contract is not registered on the chain and cannot be obtained
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

    def _register_contract_method(self,
                                  func: Callable,
                                  func_name: str,
                                  price: int,
                                  return_type,
                                  parameter_types: list = None,
                                  parameter_names: List[str] = None,
                                  add_engine: bool = False,
                                  add_snapshot: bool = False,
                                  call_flags: contracts.CallFlags = contracts.CallFlags.NONE
                                  ) -> None:
        """
        Registers a native contract method into the manifest

        Args:
            func: func pointer.
            func_name: the name of the callable function.
            price: the cost of calling the function.
            return_type: the function return value type.
            parameter_types: the function argument types.
            parameter_names: the function argument names.
            safe_method: dumb logic NEO added that we must support. See https://github.com/neo-project/neo/issues/1664
                         set to True is the function callFlags does not include ALLOW_MODIFY_STATES
        """
        params = []
        if parameter_types is not None and parameter_names is not None:
            if len(parameter_types) != len(parameter_names):
                raise ValueError(f"Parameter types count must match parameter names count! "
                                 f"{len(parameter_types)}!={len(parameter_names)}")

            for t, n in zip(parameter_types, parameter_names):
                params.append(contracts.ContractParameterDefinition(
                    name=n,
                    type=contracts.ContractParameterType.from_type(t)
                ))

        self._manifest.abi.methods.append(
            contracts.ContractMethodDescriptor(
                name=func_name,
                offset=0,
                return_type=contracts.ContractParameterType.from_type(return_type),
                parameters=params,
                safe=(call_flags & ~contracts.CallFlags.READ_ONLY) == 0
            )
        )

        self._methods.update({func_name: _ContractMethodMetadata(
            func, price, call_flags, add_engine, add_snapshot, return_type, parameter_types)
        })

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

    def invoke(self, engine: contracts.ApplicationEngine) -> None:
        """
        Calls a contract function

        Reads the required arguments from the engine's stack and converts them to the appropiate contract function types

        Args:
            engine: the engine executing the smart contract

        Raises:
             SystemError: if called using `Neo.Native.Call`, use `System.Contract.Call` instead
             ValueError: if the function to be called does not exist on the contract
             ValueError: if trying to call a function without having the correct CallFlags
        """
        if engine.current_scripthash != self.hash:
            raise SystemError("It is not allowed to use Neo.Native.Call directly, use System.Contract.Call")

        context = engine.current_context
        operation = context.evaluation_stack.pop().to_array().decode()

        flags = contracts.CallFlags(context.call_flags)
        method = self._methods.get(operation, None)
        if method is None:
            raise ValueError(f"Method \"{operation}\" does not exist on contract {self.service_name()}")
        if method.required_flag not in flags:
            raise ValueError(f"Method requires call flag: {method.required_flag} received: {flags}")

        engine.add_gas(method.price)

        params: List[Any] = []
        if method.add_engine:
            params.append(engine)

        if method.add_snapshot:
            params.append(engine.snapshot)

        for i in range(len(method.parameters)):
            params.append(engine._stackitem_to_native(context.evaluation_stack.pop(), method.parameters[i]))

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
        addr = NeoToken().get_committee_address()
        return engine.checkwitness(addr)

    def create_key(self, prefix: bytes) -> storage.StorageKey:
        return storage.StorageKey(self._id, prefix)


class PolicyContract(NativeContract):
    _id: int = -4

    DEFAULT_EXEC_FEE_FACTOR = 30
    MAX_EXEC_FEE_FACTOR = 1000
    DEFAULT_STORAGE_PRICE = 100000
    MAX_STORAGE_PRICE = 10000000

    _PREFIX_MAX_TRANSACTIONS_PER_BLOCK = b'\x17'
    _PREFIX_FEE_PER_BYTE = b'\x0A'
    _PREFIX_BLOCKED_ACCOUNT = b'\x0F'
    _PREFIX_MAX_BLOCK_SIZE = b'\x0C'
    _PREFIX_MAX_BLOCK_SYSTEM_FEE = b'\x11'
    _PREFIX_EXEC_FEE_FACTOR = b'\x12'
    _PREFIX_STORAGE_PRICE = b'\x13'

    def init(self):
        super(PolicyContract, self).init()

        self._register_contract_method(self.get_max_block_size,
                                       "getMaxBlockSize",
                                       1000000,
                                       return_type=int,
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self.get_max_transactions_per_block,
                                       "getMaxTransactionsPerBlock",
                                       1000000,
                                       return_type=int,
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self.get_max_block_system_fee,
                                       "getMaxBlockSystemFee",
                                       1000000,
                                       return_type=int,
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self.get_fee_per_byte,
                                       "getFeePerByte",
                                       1000000,
                                       return_type=int,
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self.is_blocked,
                                       "isBlocked",
                                       1000000,
                                       return_type=bool,
                                       parameter_types=[types.UInt160],
                                       parameter_names=["account"],
                                       call_flags=contracts.CallFlags.READ_STATES,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self._block_account,
                                       "blockAccount",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[types.UInt160],
                                       parameter_names=["account"],
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._unblock_account,
                                       "unblockAccount",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[types.UInt160],
                                       parameter_names=["account"],
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_max_block_size,
                                       "setMaxBlockSize",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[int],
                                       parameter_names=["value"],
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_max_transactions_per_block,
                                       "setMaxTransactionsPerBlock",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[int],
                                       parameter_names=["value"],
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_max_block_system_fee,
                                       "setMaxBlockSystemFee",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[int],
                                       parameter_names=["value"],
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_fee_per_byte,
                                       "setFeePerByte",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[int],
                                       parameter_names=["value"],
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self.get_exec_fee_factor,
                                       "getExecFeeFactor",
                                       1000000,
                                       return_type=int,
                                       add_engine=False,
                                       add_snapshot=True,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )
        self._register_contract_method(self.get_storage_price,
                                       "getStoragePrice",
                                       1000000,
                                       return_type=int,
                                       add_engine=False,
                                       add_snapshot=True,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )
        self._register_contract_method(self._set_exec_fee_factor,
                                       "setExecFeeFactor",
                                       3000000,
                                       return_type=bool,
                                       add_engine=True,
                                       add_snapshot=False,
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )
        self._register_contract_method(self._set_storage_price,
                                       "setStoragePrice",
                                       3000000,
                                       return_type=bool,
                                       add_engine=True,
                                       add_snapshot=False,
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )

    def get_max_block_size(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum size of a Block.

        Returns:
            int: maximum number of bytes.
        """
        data = snapshot.storages.try_get(
            self.create_key(self._PREFIX_MAX_BLOCK_SIZE),
            read_only=True
        )
        if data is None:
            return 1024 * 256
        return int.from_bytes(data.value, 'little', signed=True)

    def get_max_transactions_per_block(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum number of transaction in a Block.

        Returns:
            int: maximum number of transaction.
        """
        data = snapshot.storages.try_get(
            self.create_key(self._PREFIX_MAX_TRANSACTIONS_PER_BLOCK),
            read_only=True
        )
        if data is None:
            return 512
        return int.from_bytes(data.value, 'little', signed=True)

    def get_max_block_system_fee(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum system fee of a Block.

        Returns:
            int: maximum system fee.
        """
        data = snapshot.storages.try_get(
            self.create_key(self._PREFIX_MAX_BLOCK_SYSTEM_FEE),
            read_only=True
        )
        if data is None:
            x = GasToken().factor * 9000
            return int(x)
        return int.from_bytes(data.value, 'little', signed=True)

    def get_fee_per_byte(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum fee per byte of storage.

        Returns:
            int: maximum fee.
        """
        data = snapshot.storages.try_get(
            self.create_key(self._PREFIX_FEE_PER_BYTE),
            read_only=True
        )
        if data is None:
            return 1000
        return int.from_bytes(data.value, 'little', signed=True)

    def is_blocked(self, snapshot: storage.Snapshot, account: types.UInt160) -> bool:
        """
        Check if the account is blocked

        Transaction from blocked accounts will be rejected by the consensus nodes.
        """

        si = snapshot.storages.try_get(
            self.create_key(self._PREFIX_BLOCKED_ACCOUNT + account.to_array()),
            read_only=True
        )
        if si is None:
            return False
        else:
            return True

    def _set_max_block_size(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        """
        Should only be called through syscalls
        """
        if value >= message.Message.PAYLOAD_MAX_SIZE:
            raise ValueError("New blocksize exceeds PAYLOAD_MAX_SIZE")

        if not self._check_committee(engine):
            return False

        storage_key = self.create_key(self._PREFIX_MAX_BLOCK_SIZE)
        storage_item = engine.snapshot.storages.try_get(
            storage_key,
            read_only=False
        )
        if storage_item is None:
            storage_item = storage.StorageItem(b'')
            engine.snapshot.storages.update(storage_key, storage_item)
        storage_item.value = value.to_bytes((value.bit_length() + 7) // 8, 'little', signed=True)
        return True

    def _set_max_transactions_per_block(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        """
        Should only be called through syscalls
        """
        if value > 0xFFFE:  # MaxTransactionsPerBlock
            raise ValueError("New value exceeds MAX_TRANSACTIONS_PER_BLOCK")

        if not self._check_committee(engine):
            return False

        storage_key = self.create_key(self._PREFIX_MAX_TRANSACTIONS_PER_BLOCK)
        storage_item = engine.snapshot.storages.try_get(
            storage_key,
            read_only=False
        )
        if storage_item is None:
            storage_item = storage.StorageItem(b'')
            engine.snapshot.storages.update(storage_key, storage_item)

        storage_item.value = value.to_bytes((value.bit_length() + 7) // 8, 'little', signed=True)
        return True

    def _set_max_block_system_fee(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        """
        Should only be called through syscalls
        """
        # unknown magic value
        if value <= 4007600:
            return False

        if not self._check_committee(engine):
            return False

        storage_key = self.create_key(self._PREFIX_MAX_BLOCK_SYSTEM_FEE)
        storage_item = engine.snapshot.storages.try_get(
            storage_key,
            read_only=False
        )
        if storage_item is None:
            storage_item = storage.StorageItem(b'')
            engine.snapshot.storages.update(storage_key, storage_item)

        storage_item.value = value.to_bytes((value.bit_length() + 7) // 8, 'little', signed=True)
        return True

    def _set_fee_per_byte(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        """
        Should only be called through syscalls
        """
        if value < 0 or value > 100000000:
            raise ValueError("New value exceeds FEE_PER_BYTE limits")

        if not self._check_committee(engine):
            return False

        storage_key = self.create_key(self._PREFIX_FEE_PER_BYTE)
        storage_item = engine.snapshot.storages.try_get(
            storage_key,
            read_only=False
        )
        if storage_item is None:
            storage_item = storage.StorageItem(b'')
            engine.snapshot.storages.update(storage_key, storage_item)

        storage_item.value = value.to_bytes((value.bit_length() + 7) // 8, 'little', signed=True)
        return True

    def _block_account(self, engine: contracts.ApplicationEngine, account: types.UInt160) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committee(engine):
            return False
        storage_key = self.create_key(self._PREFIX_BLOCKED_ACCOUNT + account.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            storage_item = storage.StorageItem(b'\x01')
            engine.snapshot.storages.update(storage_key, storage_item)
        else:
            return False

        return True

    def _unblock_account(self, engine: contracts.ApplicationEngine, account: types.UInt160) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committee(engine):
            return False
        storage_key = self.create_key(self._PREFIX_BLOCKED_ACCOUNT + account.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            return False
        else:
            engine.snapshot.storages.delete(storage_key)
        return True

    def get_exec_fee_factor(self, snapshot: storage.Snapshot) -> int:
        storage_item = snapshot.storages.try_get(self.create_key(self._PREFIX_EXEC_FEE_FACTOR))
        if storage_item is None:
            return self.DEFAULT_EXEC_FEE_FACTOR
        return int(vm.BigInteger(storage_item.value))

    def get_storage_price(self, snapshot: storage.Snapshot) -> int:
        storage_item = snapshot.storages.try_get(self.create_key(self._PREFIX_STORAGE_PRICE))
        if storage_item is None:
            return self.DEFAULT_STORAGE_PRICE
        return int(vm.BigInteger(storage_item.value))

    def _set_exec_fee_factor(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        if value == 0 or value > self.MAX_EXEC_FEE_FACTOR:
            raise ValueError("New exec fee value out of range")
        if not self._check_committee(engine):
            return False
        storage_key = self.create_key(self._PREFIX_EXEC_FEE_FACTOR)
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            storage_item = storage.StorageItem(vm.BigInteger(value).to_array())
        else:
            storage_item.value = vm.BigInteger(value).to_array()
        engine.snapshot.storages.update(storage_key, storage_item)
        return True

    def _set_storage_price(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        if value == 0 or value > self.MAX_STORAGE_PRICE:
            raise ValueError("New storage price value out of range")
        if not self._check_committee(engine):
            return False
        storage_key = self.create_key(self._PREFIX_STORAGE_PRICE)
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            storage_item = storage.StorageItem(vm.BigInteger(value).to_array())
        else:
            storage_item.value = vm.BigInteger(value).to_array()
        engine.snapshot.storages.update(storage_key, storage_item)
        return True


class FungibleToken(NativeContract):
    _id: int = -99999
    _decimals: int = -1

    _PREFIX_ACCOUNT = b'\x14'
    _PREFIX_TOTAL_SUPPLY = b'\x0B'

    _state = storage.FungibleTokenStorageState
    _symbol: str = ""

    def init(self):
        super(FungibleToken, self).init()
        self.manifest.supported_standards = ["NEP-17"]
        self.manifest.abi.events = [
            contracts.ContractEventDescriptor(
                "Transfer",
                parameters=[
                    contracts.ContractParameterDefinition("from", contracts.ContractParameterType.HASH160),
                    contracts.ContractParameterDefinition("to", contracts.ContractParameterType.HASH160),
                    contracts.ContractParameterDefinition("amount", contracts.ContractParameterType.INTEGER)
                ]
            )
        ]
        self.factor = pow(vm.BigInteger(10), vm.BigInteger(self._decimals))

        self._register_contract_method(self.total_supply,
                                       "totalSupply",
                                       1000000,
                                       return_type=vm.BigInteger,
                                       add_snapshot=True,
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.balance_of,
                                       "balanceOf",
                                       1000000,
                                       parameter_names=["account"],
                                       parameter_types=[types.UInt160],
                                       return_type=vm.BigInteger,
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.transfer,
                                       "transfer",
                                       8000000,
                                       parameter_names=["account_from", "account_to", "amount", "data"],
                                       parameter_types=[types.UInt160, types.UInt160, vm.BigInteger, vm.StackItem],
                                       return_type=bool,
                                       add_engine=True,
                                       call_flags=(contracts.CallFlags.WRITE_STATES
                                                   | contracts.CallFlags.ALLOW_CALL
                                                   | contracts.CallFlags.ALLOW_NOTIFY))
        self._register_contract_method(self.symbol,
                                       "symbol",
                                       0,
                                       return_type=str,
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.on_persist,
                                       "onPersist",
                                       0,
                                       return_type=None,
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)

    def symbol(self) -> str:
        """ Token symbol. """
        return self._symbol

    def mint(self,
             engine: contracts.ApplicationEngine,
             account: types.UInt160,
             amount: vm.BigInteger,
             call_on_payment: bool) -> None:
        """
        Mint an amount of tokens into account.

        Increases the total supply of the token.
        """
        if amount.sign < 0:
            raise ValueError("Can't mint a negative amount")

        if amount == vm.BigInteger.zero():
            return

        storage_key = self.create_key(self._PREFIX_ACCOUNT + account.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)

        if storage_item is None:
            storage_item = storage.StorageItem(self._state().to_array())
            engine.snapshot.storages.put(storage_key, storage_item)

        state = self._state.from_storage(storage_item)
        self.on_balance_changing(engine, account, state, amount)
        state.balance += amount

        storage_key = self.create_key(self._PREFIX_TOTAL_SUPPLY)
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            storage_item = storage.StorageItem(amount.to_array())
            engine.snapshot.storages.put(storage_key, storage_item)
        else:
            old_value = vm.BigInteger(storage_item.value)
            storage_item.value = (amount + old_value).to_array()
        self._post_transfer(engine, types.UInt160.zero(), account, amount, vm.NullStackItem(), call_on_payment)

    def burn(self, engine: contracts.ApplicationEngine, account: types.UInt160, amount: vm.BigInteger) -> None:
        """
        Burn an amount of tokens from account.

        Reduces the total supply of the token.

        Raises:
            ValueError: if amount is negative
            ValueError: if the burn amount is larger than the available balance in the account
        """
        if amount.sign < 0:
            raise ValueError("Can't burn a negative amount")

        if amount == vm.BigInteger.zero():
            return

        storage_key = self.create_key(self._PREFIX_ACCOUNT + account.to_array())
        storage_item = engine.snapshot.storages.get(storage_key, read_only=False)

        state = self._state.from_storage(storage_item)
        if state.balance < amount:
            raise ValueError(f"Insufficient balance. Requesting to burn {amount}, available {state.balance}")

        self.on_balance_changing(engine, account, state, -amount)
        if state.balance == amount:
            engine.snapshot.storages.delete(storage_key)
        else:
            state.balance -= amount
            engine.snapshot.storages.update(storage_key, storage_item)

        storage_key = self.create_key(self._PREFIX_TOTAL_SUPPLY)
        storage_item = engine.snapshot.storages.get(storage_key, read_only=False)
        old_value = vm.BigInteger(storage_item.value)
        new_value = old_value - amount
        if new_value == vm.BigInteger.zero():
            engine.snapshot.storages.delete(storage_key)
        else:
            storage_item.value = new_value.to_array()
        self._post_transfer(engine, account, types.UInt160.zero(), amount, vm.NullStackItem(), False)

    def total_supply(self, snapshot: storage.Snapshot) -> vm.BigInteger:
        """ Get the total deployed tokens. """
        storage_key = self.create_key(self._PREFIX_TOTAL_SUPPLY)
        storage_item = snapshot.storages.try_get(storage_key)
        if storage_item is None:
            return vm.BigInteger.zero()
        else:
            return vm.BigInteger(storage_item.value)

    def balance_of(self, snapshot: storage.Snapshot, account: types.UInt160) -> vm.BigInteger:
        """
        Get the balance of an account.

        Args:
            snapshot: snapshot of the storage
            account: script hash of the account to obtain the balance of

        Returns:
            amount of balance.

        Note: The returned value is still in internal format. Divide the results by the contract's `decimals`
        """
        storage_key = self.create_key(self._PREFIX_ACCOUNT + account.to_array())
        storage_item = snapshot.storages.try_get(storage_key)
        if storage_item is None:
            return vm.BigInteger.zero()
        else:
            state = self._state.deserialize_from_bytes(storage_item.value)
            return state.balance

    def _post_transfer(self,
                       engine: contracts.ApplicationEngine,
                       account_from: types.UInt160,
                       account_to: types.UInt160,
                       amount: vm.BigInteger,
                       data: vm.StackItem,
                       call_on_payment: bool) -> None:
        state = vm.ArrayStackItem(engine.reference_counter)
        if account_from == types.UInt160.zero():
            state.append(vm.NullStackItem())
        else:
            state.append(vm.ByteStringStackItem(account_from.to_array()))
        if account_to == types.UInt160.zero():
            state.append(vm.NullStackItem())
        else:
            state.append(vm.ByteStringStackItem(account_to.to_array()))
        state.append(vm.IntegerStackItem(amount))

        msgrouter.interop_notify(self.hash, "Transfer", state)

        # wallet or smart contract
        if not call_on_payment \
                or account_to == types.UInt160.zero() \
                or contracts.ManagementContract().get_contract(engine.snapshot, account_to) is None:
            return

        if account_from == types.UInt160.zero():
            from_: vm.StackItem = vm.NullStackItem()
        else:
            from_ = vm.ByteStringStackItem(account_from.to_array())
        engine.call_from_native(self.hash, account_to, "onPayment", [from_, vm.IntegerStackItem(amount), data])

    def transfer(self,
                 engine: contracts.ApplicationEngine,
                 account_from: types.UInt160,
                 account_to: types.UInt160,
                 amount: vm.BigInteger,
                 data: vm.StackItem
                 ) -> bool:
        """
        Transfer tokens from one account to another.

        Raises:
            ValueError: if the requested amount is negative.

        Returns:
            True on success. False otherwise.
        """
        if amount.sign < 0:
            raise ValueError("Can't transfer a negative amount")

        # transfer from an account not owned by the smart contract that is requesting the transfer
        # and there is no signature that approves we are allowed todo so
        if account_from != engine.calling_scripthash and not engine.checkwitness(account_from):
            return False

        storage_key_from = self.create_key(self._PREFIX_ACCOUNT + account_from.to_array())
        storage_item_from = engine.snapshot.storages.try_get(storage_key_from, read_only=False)

        if storage_item_from is None:
            return False

        state_from = self._state.from_storage(storage_item_from)
        if amount == vm.BigInteger.zero():
            self.on_balance_changing(engine, account_from, state_from, amount)
        else:
            if state_from.balance < amount:
                return False

            if account_from == account_to:
                self.on_balance_changing(engine, account_from, state_from, vm.BigInteger.zero())
            else:
                self.on_balance_changing(engine, account_from, state_from, -amount)
                if state_from.balance == amount:
                    engine.snapshot.storages.delete(storage_key_from)
                else:
                    state_from.balance -= amount

                storage_key_to = self.create_key(self._PREFIX_ACCOUNT + account_to.to_array())
                storage_item_to = engine.snapshot.storages.try_get(storage_key_to, read_only=False)
                if storage_item_to is None:
                    storage_item_to = storage.StorageItem(b'')
                    state_to = self._state()
                else:
                    state_to = self._state.deserialize_from_bytes(storage_item_to.value)

                self.on_balance_changing(engine, account_to, state_to, amount)
                state_to.balance += amount
                storage_item_to.value = state_to.to_array()
                engine.snapshot.storages.update(storage_key_to, storage_item_to)
        self._post_transfer(engine, account_from, account_to, amount, data, True)
        return True

    def on_balance_changing(self, engine: contracts.ApplicationEngine,
                            account: types.UInt160,
                            state,
                            amount: vm.BigInteger) -> None:
        pass


class _NeoTokenStorageState(storage.FungibleTokenStorageState):
    """
    Helper class for storing voting and bonus GAS state

    Use the from_storage() method if you're working with a DB snapshot and intend to modify the state values.
    It will ensure that the cache is updated automatically.
    """

    def __init__(self):
        super(_NeoTokenStorageState, self).__init__()
        self._vote_to: cryptography.ECPoint = cryptography.ECPoint.deserialize_from_bytes(
            b'\x00')
        self._balance_height: int = 0
        self._storage_item = storage.StorageItem(b'')

    def __len__(self):
        return super(_NeoTokenStorageState, self).__len__() + len(self.vote_to) + s.uint32

    @classmethod
    def from_storage(cls, storage_item: storage.StorageItem):
        state = cls()
        state._storage_item = storage_item
        with serialization.BinaryReader(storage_item.value) as reader:
            state.deserialize(reader)
        return state

    @property
    def balance_height(self) -> int:
        return self._balance_height

    @balance_height.setter
    def balance_height(self, value: int) -> None:
        self._balance_height = value
        self._storage_item.value = self.to_array()

    @property
    def vote_to(self) -> cryptography.ECPoint:
        return self._vote_to

    @vote_to.setter
    def vote_to(self, public_key: cryptography.ECPoint) -> None:
        self._vote_to = public_key
        self._storage_item.value = self.to_array()

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        super(_NeoTokenStorageState, self).serialize(writer)
        writer.write_serializable(self._vote_to)
        writer.write_uint32(self._balance_height)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        super(_NeoTokenStorageState, self).deserialize(reader)
        self._vote_to = reader.read_serializable(cryptography.ECPoint)  # type: ignore
        self._balance_height = reader.read_uint32()


class _CandidateState(serialization.ISerializable):
    """
    Helper class for storing consensus candidates and their votes

    Use the from_storage() method if you're working with a DB snapshot and intend to modify the state values.
    It will ensure that the cache is updated automatically.
    """

    def __init__(self):
        self._registered = True
        self._votes = vm.BigInteger.zero()
        self._storage_item = storage.StorageItem(b'')

    def __len__(self):
        return 1 + len(self._votes.to_array())

    @classmethod
    def from_storage(cls, storage_item: storage.StorageItem):
        state = cls()
        state._storage_item = storage_item
        with serialization.BinaryReader(storage_item.value) as reader:
            state.deserialize(reader)
        return state

    @property
    def registered(self) -> bool:
        return self._registered

    @registered.setter
    def registered(self, value: bool) -> None:
        self._registered = value
        self._storage_item.value = self.to_array()

    @property
    def votes(self) -> vm.BigInteger:
        return self._votes

    @votes.setter
    def votes(self, value) -> None:
        self._votes = value
        self._storage_item.value = self.to_array()

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_bool(self._registered)
        writer.write_var_bytes(self._votes.to_array())

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self._registered = reader.read_bool()
        self._votes = vm.BigInteger(reader.read_var_bytes())


class _CommitteeState(serialization.ISerializable):
    def __init__(self, snapshot: storage.Snapshot, validators: Dict[cryptography.ECPoint, vm.BigInteger]):
        self._snapshot = snapshot
        self._validators = validators
        self._storage_key = storage.StorageKey(NeoToken().id, NeoToken()._PREFIX_COMMITTEE)

        with serialization.BinaryWriter() as writer:
            self.serialize(writer)
            self._storage_item = storage.StorageItem(writer.to_array())
            snapshot.storages.update(self._storage_key, self._storage_item)

    def __len__(self):
        return len(self.to_array())

    def __getitem__(self, item: cryptography.ECPoint) -> vm.BigInteger:
        return self._validators[item]

    @staticmethod
    def compute_members(snapshot: storage.Snapshot) -> Dict[cryptography.ECPoint, vm.BigInteger]:
        pass

    @property
    def validators(self) -> List[cryptography.ECPoint]:
        return list(self._validators.keys())

    def update(self, snapshot: storage.Snapshot, validators: Dict[cryptography.ECPoint, vm.BigInteger]) -> None:
        self._validators = validators
        self._snapshot = snapshot
        with serialization.BinaryWriter() as writer:
            self.serialize(writer)
            self._storage_item.value = writer.to_array()
        self._snapshot.storages.update(self._storage_key, self._storage_item)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_var_int(len(self._validators))
        for key, value in self._validators.items():
            writer.write_serializable(key)
            writer.write_var_bytes(value.to_array())

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        length = reader.read_var_int()
        self._validators.clear()
        for _ in range(length):
            public_key = reader.read_serializable(cryptography.ECPoint)  # type: ignore
            self._validators.update({
                public_key: vm.BigInteger(reader.read_var_bytes())
            })


class _GasRecord(serialization.ISerializable):
    def __init__(self, index: int, gas_per_block: vm.BigInteger):
        self._index = index
        self._gas_per_block = gas_per_block
        self._storage_item = storage.StorageItem(b'')

    def __len__(self):
        return s.uint32 + len(self._gas_per_block.to_array())

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, value: int):
        self._index = value
        self._storage_item.value = self.to_array()

    @property
    def gas_per_block(self):
        return self._gas_per_block

    @gas_per_block.setter
    def gas_per_block(self, value: vm.BigInteger) -> None:
        self._gas_per_block = value
        self._storage_item.value = self.to_array()

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint32(self._index)
        writer.write_var_bytes(self._gas_per_block.to_array())

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self._index = reader.read_uint32()
        self._gas_per_block = vm.BigInteger(reader.read_var_bytes())

    @classmethod
    def _serializable_init(cls):
        return cls(0, vm.BigInteger.zero())


class GasBonusState(serialization.ISerializable, Sequence):
    def __init__(self, initial_record: _GasRecord = None):
        self._storage_key = storage.StorageKey(NeoToken().id, NeoToken()._PREFIX_GAS_PER_BLOCK)
        self._records: List[_GasRecord] = [initial_record] if initial_record else []
        self._storage_item = storage.StorageItem(b'')
        self._iter = iter(self._records)

    def __len__(self):
        return len(self._records)

    def __iter__(self):
        self._iter = iter(self._records)
        return self

    def __next__(self) -> _GasRecord:
        value = next(self._iter)
        value._storage_item = self._storage_item
        return value

    def __getitem__(self, item):
        return self._records.__getitem__(item)

    def __setitem__(self, key, record: _GasRecord) -> None:
        self._records[key] = record
        self._storage_item.value = self.to_array()

    @classmethod
    def from_snapshot(cls, snapshot: storage.Snapshot):
        record = cls()
        record._storage_item = snapshot.storages.get(
            storage.StorageKey(NeoToken().id, NeoToken()._PREFIX_GAS_PER_BLOCK))
        with serialization.BinaryReader(record._storage_item.value) as reader:
            record.deserialize(reader)
        return record

    def append(self, record: _GasRecord) -> None:
        self._records.append(record)
        self._storage_item.value = self.to_array()

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable_list(self._records)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self._records = reader.read_serializable_list(_GasRecord)


class NeoToken(FungibleToken):
    _id: int = -2
    _decimals: int = 0

    _PREFIX_COMMITTEE = b'\x0e'
    _PREFIX_CANDIDATE = b'\x21'
    _PREFIX_VOTERS_COUNT = b'\x01'
    _PREFIX_GAS_PER_BLOCK = b'\x29'
    _PREFIX_VOTER_REWARD_PER_COMMITTEE = b'\x17'

    key_candidate = storage.StorageKey(_id, _PREFIX_CANDIDATE)

    _NEO_HOLDER_REWARD_RATIO = 10
    _COMMITTEE_REWARD_RATIO = 10
    _VOTER_REWARD_RATIO = 80
    _symbol = "NEO"
    _state = _NeoTokenStorageState
    _candidates_dirty = True
    _candidates: List[Tuple[cryptography.ECPoint, vm.BigInteger]] = []

    def _calculate_bonus(self,
                         snapshot: storage.Snapshot,
                         vote: cryptography.ECPoint,
                         value: vm.BigInteger,
                         start: int,
                         end: int) -> vm.BigInteger:
        if value == vm.BigInteger.zero() or start >= end:
            return vm.BigInteger.zero()

        if value.sign < 0:
            raise ValueError("Can't calculate bonus over negative balance")

        neo_holder_reward = self._calculate_neo_holder_reward(snapshot, value, start, end)
        if vote.is_zero():
            return neo_holder_reward

        border = self.create_key(self._PREFIX_VOTER_REWARD_PER_COMMITTEE + vote.to_array()).to_array()
        key_start = self.create_key(
            self._PREFIX_VOTER_REWARD_PER_COMMITTEE + vote.to_array() + vm.BigInteger(start).to_array()
        ).to_array()

        items = list(snapshot.storages.find_range(self.hash, key_start, border, "reverse"))
        if len(items) > 0:
            start_reward_per_neo = vm.BigInteger(items[0][1].value)  # first pair returned, StorageItem
        else:
            start_reward_per_neo = vm.BigInteger.zero()

        key_end = self.create_key(
            self._PREFIX_VOTER_REWARD_PER_COMMITTEE + vote.to_array() + vm.BigInteger(end).to_array()
        ).to_array()

        items = list(snapshot.storages.find_range(self.hash, key_end, border, "reverse"))
        if len(items) > 0:
            end_reward_per_neo = vm.BigInteger(items[0][1].value)  # first pair returned, StorageItem
        else:
            end_reward_per_neo = vm.BigInteger.zero()

        return neo_holder_reward + value * (end_reward_per_neo - start_reward_per_neo) / 100000000

    def _calculate_neo_holder_reward(self,
                                     snapshot: storage.Snapshot,
                                     value: vm.BigInteger,
                                     start: int,
                                     end: int) -> vm.BigInteger:
        gas_bonus_state = GasBonusState.from_snapshot(snapshot)
        gas_sum = 0
        for pair in reversed(gas_bonus_state):  # type: _GasRecord
            cur_idx = pair.index
            if cur_idx >= end:
                continue
            if cur_idx > start:
                gas_sum += pair.gas_per_block * (end - cur_idx)
                end = cur_idx
            else:
                gas_sum += pair.gas_per_block * (end - start)
                break
        return value * gas_sum * self._NEO_HOLDER_REWARD_RATIO / 100 / self.total_amount

    def _should_refresh_committee(self, height: int) -> bool:
        return height % len(settings.standby_committee) == 0

    def _check_candidate(self,
                         snapshot: storage.Snapshot,
                         public_key: cryptography.ECPoint,
                         candidate: _CandidateState) -> None:
        if not candidate.registered and candidate.votes == 0:
            storage_key = self.create_key(self._PREFIX_VOTER_REWARD_PER_COMMITTEE + public_key.to_array())
            for k, v in snapshot.storages.find(storage_key):
                snapshot.storages.delete(k)
            storage_key_candidate = self.create_key(self._PREFIX_CANDIDATE + public_key.to_array())
            snapshot.storages.delete(storage_key_candidate)

    def init(self):
        super(NeoToken, self).init()
        # singleton init, similar to __init__ but called only once
        self.total_amount = self.factor * 100_000_000

        self._register_contract_method(self.register_candidate,
                                       "registerCandidate",
                                       5000000,
                                       parameter_types=[cryptography.ECPoint],
                                       parameter_names=["public_key"],
                                       return_type=bool,
                                       add_snapshot=False,
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)

        self._register_contract_method(self.unregister_candidate,
                                       "unregisterCandidate",
                                       5000000,
                                       parameter_types=[cryptography.ECPoint],
                                       parameter_names=["public_key"],
                                       return_type=bool,
                                       add_snapshot=False,
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)

        self._register_contract_method(self.vote,
                                       "vote",
                                       5000000,
                                       parameter_types=[types.UInt160, cryptography.ECPoint],
                                       parameter_names=["account", "public_key"],
                                       return_type=bool,
                                       add_snapshot=False,
                                       add_engine=True,
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self._set_gas_per_block,
                                       "setGasPerBlock",
                                       5000000,
                                       parameter_types=[vm.BigInteger],
                                       parameter_names=["gas_per_block"],
                                       return_type=bool,
                                       add_engine=True,
                                       add_snapshot=False,
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )
        self._register_contract_method(self.get_gas_per_block,
                                       "getGasPerBlock",
                                       1000000,
                                       return_type=vm.BigInteger,
                                       add_snapshot=True,
                                       add_engine=False,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )
        self._register_contract_method(self.get_committee,
                                       "getCommittee",
                                       100000000,
                                       return_type=List[cryptography.ECPoint],
                                       add_engine=False,
                                       add_snapshot=False,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )

        self._register_contract_method(self.get_candidates,
                                       "getCandidates",
                                       100000000,
                                       return_type=None,  # we manually push onto the engine
                                       add_engine=True,
                                       add_snapshot=False,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )

        self._register_contract_method(self.get_next_block_validators,
                                       "getNextBlockValidators",
                                       100000000,
                                       return_type=List[cryptography.ECPoint],
                                       add_engine=False,
                                       add_snapshot=False,
                                       call_flags=contracts.CallFlags.READ_STATES
                                       )

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        # NEO's native contract initialize. Is called upon contract deploy

        self._committee_state = _CommitteeState(engine.snapshot,
                                                dict.fromkeys(settings.standby_validators, vm.BigInteger(0))
                                                )
        engine.snapshot.storages.put(
            self.create_key(self._PREFIX_VOTERS_COUNT),
            storage.StorageItem(b'\x00')
        )

        gas_bonus_state = GasBonusState(_GasRecord(0, GasToken().factor * 5))
        engine.snapshot.storages.put(
            self.create_key(NeoToken()._PREFIX_GAS_PER_BLOCK),
            storage.StorageItem(gas_bonus_state.to_array())
        )
        self.mint(engine,
                  contracts.Contract.get_consensus_address(settings.standby_validators),
                  self.total_amount,
                  False)

    def total_supply(self, snapshot: storage.Snapshot) -> vm.BigInteger:
        """ Get the total deployed tokens. """
        return self.total_amount

    def on_balance_changing(self, engine: contracts.ApplicationEngine,
                            account: types.UInt160,
                            state,
                            amount: vm.BigInteger) -> None:
        self._distribute_gas(engine, account, state)

        if amount == vm.BigInteger.zero():
            return

        if state.vote_to.is_zero():
            return

        sk_voters_count = self.create_key(self._PREFIX_VOTERS_COUNT)
        si_voters_count = engine.snapshot.storages.get(sk_voters_count, read_only=False)
        new_value = vm.BigInteger(si_voters_count.value) + amount
        si_voters_count.value = new_value.to_array()

        sk_candidate = self.create_key(self._PREFIX_CANDIDATE + state.vote_to.to_array())
        si_candidate = engine.snapshot.storages.get(sk_candidate, read_only=False)
        candidate_state = _CandidateState.from_storage(si_candidate)
        candidate_state.votes += amount
        self._candidates_dirty = True

        self._check_candidate(engine.snapshot, state.vote_to, candidate_state)

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        super(NeoToken, self).on_persist(engine)

        # set next committee
        if self._should_refresh_committee(engine.snapshot.block_height):
            validators = self._compute_committee_members(engine.snapshot)
            self._committee_state.update(engine.snapshot, validators)

    def post_persist(self, engine: contracts.ApplicationEngine):
        super(NeoToken, self).post_persist(engine)
        # distribute GAS for committee
        m = len(settings.standby_committee)
        n = settings.network.validators_count
        index = engine.snapshot.persisting_block.index % m
        gas_per_block = self.get_gas_per_block(engine.snapshot)
        committee = self.get_committee()
        pubkey = committee[index]
        account = to_script_hash(contracts.Contract.create_signature_redeemscript(pubkey))
        GasToken().mint(engine, account, gas_per_block * self._COMMITTEE_REWARD_RATIO / 100, False)

        if self._should_refresh_committee(engine.snapshot.persisting_block.index):
            voter_reward_of_each_committee = gas_per_block * self._VOTER_REWARD_RATIO * 100000000 * m / (m + n) / 100
            for i, member in enumerate(committee):
                factor = 2 if i < n else 1
                member_votes = self._committee_state[member]
                if member_votes > 0:
                    voter_sum_reward_per_neo = factor * voter_reward_of_each_committee / member_votes
                    voter_reward_key = self.create_key(
                        (self._PREFIX_VOTER_REWARD_PER_COMMITTEE + member.to_array()
                         + vm.BigInteger(engine.snapshot.persisting_block.index + 1).to_array())
                    )
                    border = self.create_key(
                        self._PREFIX_VOTER_REWARD_PER_COMMITTEE + member.to_array()
                    ).to_array()
                    result = engine.snapshot.storages.find_range(self.hash, voter_reward_key.to_array(), border)
                    if len(result) > 0:
                        result = result[0]
                    else:
                        result = vm.BigInteger.zero()
                    voter_sum_reward_per_neo += result
                    engine.snapshot.storages.put(voter_reward_key,
                                                 storage.StorageItem(voter_sum_reward_per_neo.to_array()))

    def unclaimed_gas(self, snapshot: storage.Snapshot, account: types.UInt160, end: int) -> vm.BigInteger:
        """
        Return the available bonus GAS for an account.

        Requires sending the accounts balance to release the bonus GAS.

        Args:
            snapshot: snapshot of storage
            account: account to calculate bonus for
            end: ending block height to calculate bonus up to. You should use mostlikly use the current chain height.
        """
        storage_item = snapshot.storages.try_get(
            self.create_key(self._PREFIX_ACCOUNT + account.to_array())
        )
        if storage_item is None:
            return vm.BigInteger.zero()
        state = self._state.deserialize_from_bytes(storage_item.value)
        return self._calculate_bonus(snapshot, state.vote_to, state.balance, state.balance_height, end)

    def register_candidate(self,
                           engine: contracts.ApplicationEngine,
                           public_key: cryptography.ECPoint) -> bool:
        """
        Register a candidate for consensus node election.

        Args:
            engine: Application engine instance
            public_key: the candidate's public key

        Returns:
            True is succesfully registered. False otherwise.
        """
        script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(public_key))
        if not engine.checkwitness(script_hash):
            return False

        storage_key = self.create_key(self._PREFIX_CANDIDATE + public_key.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            state = _CandidateState()
            state.registered = True
            storage_item = storage.StorageItem(state.to_array())
            engine.snapshot.storages.put(storage_key, storage_item)
        else:
            state = _CandidateState.from_storage(storage_item)
            state.registered = True
        self._candidates_dirty = True
        return True

    def unregister_candidate(self,
                             engine: contracts.ApplicationEngine,
                             public_key: cryptography.ECPoint) -> bool:
        """
        Remove a candidate from the consensus node candidate list.
        Args:
            engine: Application engine instance
            public_key: the candidate's public key

        Returns:
            True is succesfully removed. False otherwise.

        """
        script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(public_key))
        if not engine.checkwitness(script_hash):
            return False

        storage_key = self.create_key(self._PREFIX_CANDIDATE + public_key.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            return True
        else:
            state = _CandidateState.from_storage(storage_item)
            state.registered = False
            if state.votes == 0:
                engine.snapshot.storages.delete(storage_key)

        self._candidates_dirty = True
        return True

    def vote(self,
             engine: contracts.ApplicationEngine,
             account: types.UInt160,
             vote_to: cryptography.ECPoint) -> bool:
        """
        Vote on a consensus candidate
        Args:
            engine: Application engine instance.
            account: source account to take voting balance from
            vote_to: candidate public key

        Returns:
            True is vote registered succesfully. False otherwise.
        """
        if not engine.checkwitness(account):
            return False

        storage_key_account = self.create_key(self._PREFIX_ACCOUNT + account.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key_account, read_only=False)
        if storage_item is None:
            return False
        account_state = self._state.from_storage(storage_item)

        storage_key_candidate = self.create_key(self._PREFIX_CANDIDATE + vote_to.to_array())
        storage_item_candidate = engine.snapshot.storages.try_get(storage_key_candidate, read_only=False)
        if storage_key_candidate is None:
            return False

        candidate_state = _CandidateState.from_storage(storage_item_candidate)
        if not candidate_state.registered:
            return False

        if account_state.vote_to.is_zero():
            sk_voters_count = self.create_key(self._PREFIX_VOTERS_COUNT)
            si_voters_count = engine.snapshot.storages.get(sk_voters_count, read_only=False)

            old_value = vm.BigInteger(si_voters_count.value)
            new_value = old_value + account_state.balance
            si_voters_count.value = new_value.to_array()

        if not account_state.vote_to.is_zero():
            sk_validator = self.create_key(self._PREFIX_CANDIDATE + account_state.vote_to.to_array())
            si_validator = engine.snapshot.storages.get(sk_validator, read_only=False)
            validator_state = _CandidateState.from_storage(si_validator)
            validator_state.votes -= account_state.balance

            if not validator_state.registered and validator_state.votes == 0:
                engine.snapshot.storages.delete(sk_validator)

        account_state.vote_to = vote_to
        candidate_state.votes += account_state.balance
        self._candidates_dirty = True

        return True

    def _get_candidates(self,
                        snapshot: storage.Snapshot) -> \
            List[Tuple[cryptography.ECPoint, vm.BigInteger]]:
        if self._candidates_dirty:
            self._candidates = []
            for k, v in snapshot.storages.find(self.key_candidate.to_array()):
                candidate = _CandidateState.deserialize_from_bytes(v.value)
                if candidate.registered:
                    # take of the CANDIDATE prefix
                    point = cryptography.ECPoint.deserialize_from_bytes(k.key[1:])
                    self._candidates.append((point, candidate.votes))
            self._candidates_dirty = False

        return self._candidates

    def get_candidates(self, engine: contracts.ApplicationEngine) -> None:
        array = vm.ArrayStackItem(engine.reference_counter)
        for k, v in self._get_candidates(engine.snapshot):
            struct = vm.StructStackItem(engine.reference_counter)
            struct.append(vm.ByteStringStackItem(k.to_array()))
            struct.append(vm.IntegerStackItem(v))
            array.append(struct)
        engine.push(array)

    def get_next_block_validators(self) -> List[cryptography.ECPoint]:
        keys = self._committee_state.validators[:settings.network.validators_count]
        keys.sort()
        return keys

    def get_committee(self) -> List[cryptography.ECPoint]:
        return sorted(self._committee_state.validators)

    def get_committee_address(self) -> types.UInt160:
        comittees = self.get_committee()
        return to_script_hash(
            contracts.Contract.create_multisig_redeemscript(
                len(comittees) - (len(comittees) - 1) // 2,
                comittees)
        )

    def _compute_committee_members(self, snapshot: storage.Snapshot) -> Dict[cryptography.ECPoint, vm.BigInteger]:
        storage_key = self.create_key(self._PREFIX_VOTERS_COUNT)
        storage_item = snapshot.storages.get(storage_key, read_only=True)
        voters_count = int(vm.BigInteger(storage_item.value))
        voter_turnout = voters_count / float(self.total_amount)

        candidates = self._get_candidates(snapshot)
        if voter_turnout < 0.2 or len(candidates) < len(settings.standby_committee):
            results = {}
            for key in settings.standby_committee:
                results.update({key: self._committee_state[key]})
            return results
        # first sort by votes descending, then by ECPoint ascending
        # we negate the value of the votes (c[1]) such that they get sorted in descending order
        candidates.sort(key=lambda c: (-c[1], c[0]))
        trimmed_candidates = candidates[:len(settings.standby_committee)]
        results = {}
        for candidate in trimmed_candidates:
            results.update({candidate[0]: candidate[1]})
        return results

    def _set_gas_per_block(self, engine: contracts.ApplicationEngine, gas_per_block: vm.BigInteger) -> bool:
        if gas_per_block > 0 or gas_per_block > 10 * self._gas.factor:
            raise ValueError("new gas per block value exceeds limits")

        if not self._check_committee(engine):
            return False

        index = engine.snapshot.persisting_block.index + 1
        gas_bonus_state = GasBonusState.from_snapshot(engine.snapshot)
        if gas_bonus_state[-1].index == index:
            gas_bonus_state[-1] = _GasRecord(index, gas_per_block)
        else:
            gas_bonus_state.append(_GasRecord(index, gas_per_block))
        return True

    def get_gas_per_block(self, snapshot: storage.Snapshot) -> vm.BigInteger:
        index = snapshot.persisting_block.index
        gas_bonus_state = GasBonusState.from_snapshot(snapshot)
        for record in reversed(gas_bonus_state):  # type: _GasRecord
            if record.index <= index:
                return record.gas_per_block
        else:
            raise ValueError

    def _distribute_gas(self,
                        engine: contracts.ApplicationEngine,
                        account: types.UInt160,
                        state: _NeoTokenStorageState) -> None:
        if engine.snapshot.persisting_block is None:
            return

        gas = self._calculate_bonus(engine.snapshot, state.vote_to, state.balance, state.balance_height,
                                    engine.snapshot.persisting_block.index)
        state.balance_height = engine.snapshot.persisting_block.index
        GasToken().mint(engine, account, gas, True)


class GasToken(FungibleToken):
    _id: int = -3
    _decimals: int = 8

    _state = storage.FungibleTokenStorageState
    _symbol = "GAS"

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        account = contracts.Contract.get_consensus_address(settings.standby_validators)
        self.mint(engine, account, vm.BigInteger(30_000_000) * self.factor, False)

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        super(GasToken, self).on_persist(engine)
        total_network_fee = 0
        for tx in engine.snapshot.persisting_block.transactions:
            total_network_fee += tx.network_fee
            self.burn(engine, tx.sender, vm.BigInteger(tx.system_fee + tx.network_fee))
        pub_keys = NeoToken().get_next_block_validators()
        primary = pub_keys[engine.snapshot.persisting_block.consensus_data.primary_index]
        script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(primary))
        self.mint(engine, script_hash, vm.BigInteger(total_network_fee), False)
