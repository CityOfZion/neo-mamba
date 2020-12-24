from __future__ import annotations
from typing import List, Callable, Dict, Tuple, Iterator, Any, cast
from neo3 import contracts, vm, storage, blockchain, settings
from neo3.core import types, to_script_hash, serialization, cryptography, msgrouter, Size as s
from neo3.network import message, convenience
from enum import IntFlag


class CallFlags(IntFlag):
    """
    Describes the required call permissions for contract functions.
    """
    NONE = 0,
    ALLOW_STATES = 0x1
    ALLOW_MODIFIED_STATES = 0x02
    ALLOW_CALL = 0x04
    ALLOW_NOTIFY = 0x08
    READ_ONLY = ALLOW_STATES | ALLOW_CALL | ALLOW_NOTIFY
    ALL = ALLOW_STATES | ALLOW_MODIFIED_STATES | ALLOW_CALL | ALLOW_NOTIFY


class _ContractMethodMetadata:
    """
    Internal helper class containing meta data that helps in translating VM Stack Items to the arguments types of the
     handling function. Applies to native contracts only.
    """
    def __init__(self, handler: Callable[..., None],
                 price: int,
                 required_flags: CallFlags,
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
    #: human-readable name
    _service_name: str = "override me"

    #: A dictionary of all native contracts in the system
    _contracts: Dict[str, NativeContract] = {}
    #: A dictionary for accessing a native contract by its hash
    _contract_hashes: Dict[types.UInt160, NativeContract] = {}

    def init(self):
        self._methods: Dict[str, _ContractMethodMetadata] = {}
        self._neo = NeoToken()
        self._gas = GasToken()
        self._policy = PolicyContract()
        sb = vm.ScriptBuilder()
        sb.emit_push(self._service_name)
        sb.emit_syscall(192440171)  # "Neo.Native.Call"
        self._script: bytes = sb.to_array()
        self._script_hash: types.UInt160 = to_script_hash(self._script)
        self._manifest: contracts.ContractManifest = contracts.ContractManifest(contract_hash=self._script_hash)
        self._manifest.abi.methods = []
        self._manifest.safe_methods = contracts.WildcardContainer()
        self._register_contract_method(self.supported_standards,
                                       "supportedStandards",
                                       0,
                                       list,
                                       safe_method=True)
        self._register_contract_method(self.service_name, "name", 0, return_type=str, safe_method=True)
        if self._id != NativeContract._id:
            self._contracts.update({self._service_name: self})
            self._contract_hashes.update({self._script_hash: self})

    @classmethod
    def get_contract(cls, name: str) -> NativeContract:
        """
        Get the contract instance by its service name
        Args:
            name: service name of the contract

        Raise:
            ValueError: if the contract is not registered on the chain and cannot be obtained
        """
        contract = cls._contracts.get(name, None)
        if contract is None:
            raise ValueError(f"There is no native contract with name: {name}")
        return contract

    def _register_contract_method(self,
                                  func: Callable,
                                  func_name: str,
                                  price: int,
                                  return_type,
                                  parameter_types: list = None,
                                  parameter_names: List[str] = None,
                                  safe_method: bool = False,
                                  add_engine: bool = False,
                                  add_snapshot: bool = False
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
                offset=-1,
                return_type=contracts.ContractParameterType.from_type(return_type),
                parameters=params
            )
        )
        self._manifest.safe_methods._data.append(func_name)
        call_flags = CallFlags.NONE if safe_method else CallFlags.ALLOW_MODIFIED_STATES
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

    @classmethod
    def service_name(cls) -> str:
        """ The human readable name. """
        return cls._service_name

    @property
    def script(self) -> bytes:
        """ The contract byte code. """
        return self._script

    @property
    def script_hash(self) -> types.UInt160:
        """ Contract script hash based of the contrats byte code. """
        return self._script_hash

    @property
    def id(self) -> int:
        """ Unique identifier. """
        return self._id

    @property
    def manifest(self) -> contracts.ContractManifest:
        """ The associated contract manifest. """
        return self._manifest

    def supported_standards(self) -> List[str]:
        """ The list of supported Neo Enhancement Proposals (NEP)."""
        return []

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
        if engine.current_scripthash != self.script_hash:
            raise SystemError("It is not allowed to use Neo.Native.Call directly, use System.Contract.Call")

        operation = engine.pop().to_array().decode()
        stack_item = engine.pop()
        args = stack_item.convert_to(vm.StackItemType.ARRAY)
        args = cast(vm.ArrayStackItem, args)

        flags = contracts.native.CallFlags(engine.current_context.call_flags)
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
            if i < len(args):
                item = args[i]
            else:
                item = vm.NullStackItem()
            params.append(engine._stackitem_to_native(item, method.parameters[i]))

        if len(params) > 0:
            return_value = method.handler(*params)
        else:
            return_value = method.handler()
        if method.return_type is not None:
            engine.push(engine._native_to_stackitem(return_value, type(return_value)))

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
        if engine.trigger != contracts.TriggerType.SYSTEM:
            raise SystemError("Invalid operation")


class PolicyContract(NativeContract):
    _id: int = -3
    _service_name: str = "Policy"

    _PREFIX_MAX_TRANSACTIONS_PER_BLOCK = b'\x17'
    _PREFIX_FEE_PER_BYTE = b'\x0A'
    _PREFIX_BLOCKED_ACCOUNTS = b'\x0F'
    _PREFIX_MAX_BLOCK_SIZE = b'\x0C'
    _PREFIX_MAX_BLOCK_SYSTEM_FEE = b'\x11'

    def init(self):
        super(PolicyContract, self).init()
        self.manifest.features = contracts.ContractFeatures.HAS_STORAGE

        self._register_contract_method(self.get_max_block_size,
                                       "getMaxBlockSize",
                                       1000000,
                                       return_type=int,
                                       safe_method=True,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self.get_max_transactions_per_block,
                                       "getMaxTransactionsPerBlock",
                                       1000000,
                                       return_type=int,
                                       safe_method=True,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self.get_max_block_system_fee,
                                       "getMaxBlockSystemFee",
                                       1000000,
                                       return_type=int,
                                       safe_method=True,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self.get_fee_per_byte,
                                       "getFeePerByte",
                                       1000000,
                                       return_type=int,
                                       safe_method=True,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self.get_blocked_accounts,
                                       "getBlockedAccounts",
                                       1000000,
                                       return_type=int,
                                       safe_method=True,
                                       add_snapshot=True,
                                       )
        self._register_contract_method(self._block_account,
                                       "blockAccount",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[types.UInt160],
                                       parameter_names=["account"],
                                       add_engine=True)
        self._register_contract_method(self._unblock_account,
                                       "unblockAccount",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[types.UInt160],
                                       parameter_names=["account"],
                                       add_engine=True)
        self._register_contract_method(self._set_max_block_size,
                                       "setMaxBlockSize",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[int],
                                       parameter_names=["value"],
                                       add_engine=True)
        self._register_contract_method(self._set_max_transactions_per_block,
                                       "setMaxTransactionsPerBlock",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[int],
                                       parameter_names=["value"],
                                       add_engine=True)
        self._register_contract_method(self._set_max_block_system_fee,
                                       "setMaxBlockSystemFee",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[int],
                                       parameter_names=["value"],
                                       add_engine=True)
        self._register_contract_method(self._set_fee_per_byte,
                                       "setFeePerByte",
                                       3000000,
                                       return_type=bool,
                                       parameter_types=[int],
                                       parameter_names=["value"],
                                       add_engine=True)

    def supported_standards(self) -> List[str]:
        """ The list of supported Neo Enhancement Proposals (NEP)."""
        return []

    def _check_committees(self, engine: contracts.ApplicationEngine) -> bool:
        addr = NeoToken().get_committee_address(engine)
        return engine.checkwitness(addr)

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        # values are stored in signed format, little endian order
        engine.snapshot.storages.put(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_BLOCK_SIZE),
            storage.StorageItem(b'\x00\x00\x04\x00')  # 1024u * 256u
        )
        engine.snapshot.storages.put(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_TRANSACTIONS_PER_BLOCK),
            storage.StorageItem(b'\x00\x02\x00\x00')  # 512u
        )
        engine.snapshot.storages.put(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_BLOCK_SYSTEM_FEE),
            storage.StorageItem(b'\x00\x28\x2e\x8c\xd1\x00\x00\x00')  # 9000 * GAS.Factor
        )
        engine.snapshot.storages.put(
            storage.StorageKey(self.script_hash, self._PREFIX_FEE_PER_BYTE),
            storage.StorageItem(b'\xe8\x03\x00\x00\x00\x00\x00\x00')  # 1000L
        )
        engine.snapshot.storages.put(
            storage.StorageKey(self.script_hash, self._PREFIX_BLOCKED_ACCOUNTS),
            storage.StorageItem(b'\x00')
        )

    def get_max_block_size(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum size of a Block.

        Returns:
            int: maximum number of bytes.
        """
        data = snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_BLOCK_SIZE)
        )
        return int.from_bytes(data.value, 'little', signed=True)

    def get_max_transactions_per_block(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum number of transaction in a Block.

        Returns:
            int: maximum number of transaction.
        """
        data = snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_TRANSACTIONS_PER_BLOCK)
        )
        return int.from_bytes(data.value, 'little', signed=True)

    def get_max_block_system_fee(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum system fee of a Block.

        Returns:
            int: maximum system fee.
        """
        data = snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_BLOCK_SYSTEM_FEE)
        )
        return int.from_bytes(data.value, 'little', signed=True)

    def get_fee_per_byte(self, snapshot: storage.Snapshot) -> int:
        """
        Retrieve the configured maximum fee per byte of storage.

        Returns:
            int: maximum fee.
        """
        data = snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_FEE_PER_BYTE)
        )
        return int.from_bytes(data.value, 'little', signed=True)

    def get_blocked_accounts(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        """
        Retrieve the list of blocked accounts on the Blockchain.

        Transaction from blocked accounts will be rejected by the consensus nodes.

        Returns:
            A list of blocked accounts hashes
        """

        si = snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_BLOCKED_ACCOUNTS)
        )
        with serialization.BinaryReader(si.value) as br:
            return br.read_serializable_list(types.UInt160)

    def _set_max_block_size(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committees(engine):
            return False

        if value >= message.Message.PAYLOAD_MAX_SIZE:
            return False

        storage_item = engine.snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_BLOCK_SIZE),
            read_only=False
        )
        storage_item.value = value.to_bytes((value.bit_length() + 7) // 8, 'little', signed=True)
        return True

    def _set_max_transactions_per_block(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committees(engine):
            return False

        storage_item = engine.snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_TRANSACTIONS_PER_BLOCK),
            read_only=False
        )

        storage_item.value = value.to_bytes((value.bit_length() + 7) // 8, 'little', signed=True)
        return True

    def _set_max_block_system_fee(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committees(engine):
            return False

        # unknown magic value
        if value <= 4007600:
            return False

        storage_item = engine.snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_MAX_BLOCK_SYSTEM_FEE),
            read_only=False
        )

        storage_item.value = value.to_bytes((value.bit_length() + 7) // 8, 'little', signed=True)
        return True

    def _set_fee_per_byte(self, engine: contracts.ApplicationEngine, value: int) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committees(engine):
            return False

        storage_item = engine.snapshot.storages.get(
            storage.StorageKey(self.script_hash, self._PREFIX_FEE_PER_BYTE),
            read_only=False
        )
        storage_item.value = value.to_bytes((value.bit_length() + 7) // 8, 'little', signed=True)
        return True

    def _block_account(self, engine: contracts.ApplicationEngine, account: types.UInt160) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committees(engine):
            return False
        storage_key = storage.StorageKey(self.script_hash,
                                         self._PREFIX_BLOCKED_ACCOUNTS)
        storage_item = engine.snapshot.storages.get(storage_key, read_only=False)

        with serialization.BinaryReader(storage_item.value) as br:
            accounts = br.read_serializable_list(types.UInt160)
        accounts.append(account)

        with serialization.BinaryWriter() as bw:
            bw.write_serializable_list(accounts)
            storage_item.value = bw.to_array()

        return True

    def _unblock_account(self, engine: contracts.ApplicationEngine, account: types.UInt160) -> bool:
        """
        Should only be called through syscalls
        """
        if not self._check_committees(engine):
            return False
        storage_key = storage.StorageKey(self.script_hash,
                                         self._PREFIX_BLOCKED_ACCOUNTS)
        storage_item = engine.snapshot.storages.get(storage_key, read_only=False)

        with serialization.BinaryReader(storage_item.value) as br:
            accounts = br.read_serializable_list(types.UInt160)

        if account not in accounts:
            return False

        accounts.remove(account)
        with serialization.BinaryWriter() as bw:
            bw.write_serializable_list(accounts)
            storage_item.value = bw.to_array()

        return True


class Nep5Token(NativeContract):
    _id: int = -99999
    _service_name: str = "Nep5Token"
    _decimals: int = -1

    _PREFIX_ACCOUNT = b'\x14'
    _PREFIX_TOTAL_SUPPLY = b'\x0B'

    _state = storage.Nep5StorageState
    _symbol: str = ""

    def init(self):
        super(Nep5Token, self).init()
        self.manifest.features = contracts.ContractFeatures.HAS_STORAGE
        self.manifest.supported_standards = ["NEP-5"]
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
                                       safe_method=True)
        self._register_contract_method(self.balance_of,
                                       "balanceOf",
                                       1000000,
                                       parameter_names=["account"],
                                       parameter_types=[types.UInt160],
                                       return_type=vm.BigInteger,
                                       add_engine=True,
                                       safe_method=True)
        self._register_contract_method(self.transfer,
                                       "transfer",
                                       8000000,
                                       parameter_names=["account_from", "account_to", "amount"],
                                       parameter_types=[types.UInt160, types.UInt160, vm.BigInteger],
                                       return_type=bool,
                                       add_engine=True,
                                       safe_method=False)
        self._register_contract_method(self.symbol, "symbol", 0, return_type=str, safe_method=True)
        self._register_contract_method(self.on_persist,
                                       "onPersist",
                                       0,
                                       return_type=None,
                                       add_engine=True,
                                       safe_method=False)

    def symbol(self) -> str:
        """ Token symbol. """
        return self._symbol

    def mint(self, engine: contracts.ApplicationEngine, account: types.UInt160, amount: vm.BigInteger) -> None:
        """
        Mint an amount of tokens into account.

        Increases the total supply of the token.
        """
        if amount.sign < 0:
            raise ValueError("Can't mint a negative amount")

        if amount == vm.BigInteger.zero():
            return

        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_ACCOUNT + account.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)

        if storage_item is None:
            storage_item = storage.StorageItem(self._state().to_array())
            engine.snapshot.storages.put(storage_key, storage_item)

        state = self._state.from_storage(storage_item)
        self.on_balance_changing(engine, account, state, amount)
        state.balance += amount

        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_TOTAL_SUPPLY)
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            storage_item = storage.StorageItem(amount.to_array())
            engine.snapshot.storages.put(storage_key, storage_item)
        else:
            old_value = vm.BigInteger(storage_item.value)
            storage_item.value = (amount + old_value).to_array()
        self._notify_transfer(engine, types.UInt160.zero(), account, amount)

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

        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_ACCOUNT + account.to_array())
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

        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_TOTAL_SUPPLY)
        storage_item = engine.snapshot.storages.get(storage_key, read_only=False)
        old_value = vm.BigInteger(storage_item.value)
        new_value = old_value - amount
        if new_value == vm.BigInteger.zero():
            engine.snapshot.storages.delete(storage_key)
        else:
            storage_item.value = new_value.to_array()
        self._notify_transfer(engine, account, types.UInt160.zero(), amount)

    def total_supply(self, snapshot: storage.Snapshot) -> vm.BigInteger:
        """ Get the total deployed tokens. """
        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_TOTAL_SUPPLY)
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
        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_ACCOUNT + account.to_array())
        storage_item = snapshot.storages.try_get(storage_key)
        if storage_item is None:
            return vm.BigInteger.zero()
        else:
            state = self._state.deserialize_from_bytes(storage_item.value)
            return state.balance

    def _notify_transfer(self,
                         engine: contracts.ApplicationEngine,
                         account_from: types.UInt160,
                         account_to: types.UInt160,
                         amount: vm.BigInteger) -> None:
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

        msgrouter.interop_notify(self.script_hash, "Transfer", state)

    def transfer(self,
                 engine: contracts.ApplicationEngine,
                 account_from: types.UInt160,
                 account_to: types.UInt160,
                 amount: vm.BigInteger
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

        contract_state_to = engine.snapshot.contracts.try_get(account_to, read_only=True)
        if contract_state_to and not contract_state_to.is_payable:
            return False

        storage_key_from = storage.StorageKey(self.script_hash, self._PREFIX_ACCOUNT + account_from.to_array())
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

                storage_key_to = storage.StorageKey(self.script_hash, self._PREFIX_ACCOUNT + account_to.to_array())
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
        self._notify_transfer(engine, account_from, account_to, amount)
        return True

    def on_balance_changing(self, engine: contracts.ApplicationEngine,
                            account: types.UInt160,
                            state,
                            amount: vm.BigInteger) -> None:
        pass

    def supported_standards(self) -> List[str]:
        """ The list of supported Neo Enhancement Proposals (NEP)."""
        return ["NEP-5"]


class _NeoTokenStorageState(storage.Nep5StorageState):
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


class _ValidatorsState(serialization.ISerializable):

    def __init__(self, snapshot: storage.Snapshot, validators: List[cryptography.ECPoint]):
        self._snapshot = snapshot
        self._validators: List[cryptography.ECPoint] = validators
        self._storage_key = storage.StorageKey(NeoToken().script_hash, NeoToken()._PREFIX_NEXT_VALIDATORS)

        with serialization.BinaryWriter() as bw:
            bw.write_serializable_list(validators)
            self._storage_item = storage.StorageItem(bw.to_array())
            snapshot.storages.update(self._storage_key, self._storage_item)

    def __len__(self):
        return sum(map(len, self._validators))

    @property
    def validators(self) -> List[cryptography.ECPoint]:
        return self._validators

    def update(self, snapshot: storage.Snapshot, validators: List[cryptography.ECPoint]) -> None:
        self._validators = validators
        self._snapshot = snapshot
        with serialization.BinaryWriter() as br:
            br.write_serializable_list(validators)
            self._storage_item.value = br.to_array()
        self._snapshot.storages.update(self._storage_key, self._storage_item)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable_list(self._validators)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self._validators = reader.read_serializable_list(cryptography.ECPoint)  # type: ignore


class NeoToken(Nep5Token):
    _id: int = -1
    _service_name = "NEO"
    _decimals: int = 0

    _PREFIX_NEXT_VALIDATORS = b'\x0e'
    _PREFIX_CANDIDATE = b'\x21'
    _PREFIX_VOTERS_COUNT = b'\x01'
    _symbol = "neo"
    _state = _NeoTokenStorageState
    _candidates_dirty = True
    _candidates: List[Tuple[cryptography.ECPoint, vm.BigInteger]] = []

    #: The GAS bonus generation amount per NEO hold per block.
    GAS_BONUS_GENERATION_AMOUNT = [6, 5, 4, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    #: The number of blocks after which the GAS bonus generation amount decreases.
    GAS_BONUS_DECREMENT_INTERVAL = 2000000

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
                                       safe_method=False)

        self._register_contract_method(self.register_candidate,
                                       "unregisterCandidate",
                                       5000000,
                                       parameter_types=[cryptography.ECPoint],
                                       parameter_names=["public_key"],
                                       return_type=bool,
                                       add_snapshot=False,
                                       add_engine=True,
                                       safe_method=False)

        self._register_contract_method(self.vote,
                                       "vote",
                                       500000000,
                                       parameter_types=[types.UInt160, cryptography.ECPoint],
                                       parameter_names=["account", "public_key"],
                                       return_type=bool,
                                       add_snapshot=False,
                                       add_engine=True,
                                       safe_method=False)
        self._validators_state = None

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        # NEO's native contract initialize. Is called upon contract deploy
        engine.snapshot.storages.put(
            storage.StorageKey(self.script_hash, self._PREFIX_VOTERS_COUNT),
            storage.StorageItem(b'\x00')
        )
        self.mint(engine, blockchain.Blockchain().get_consensus_address(settings.standby_validators), self.total_amount)

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

        if not state.vote_to.is_zero():
            sk_candidate = storage.StorageKey(self.script_hash, self._PREFIX_CANDIDATE + state.vote_to.to_array())
            si_candidate = engine.snapshot.storages.get(sk_candidate, read_only=False)
            candidate_state = _CandidateState.from_storage(si_candidate)
            candidate_state.votes += amount
            self._candidates_dirty = True

            sk_voters_count = storage.StorageKey(self.script_hash, self._PREFIX_VOTERS_COUNT)
            si_voters_count = engine.snapshot.storages.get(sk_voters_count, read_only=False)
            new_value = vm.BigInteger(si_voters_count.value) + amount
            si_voters_count.value = new_value.to_array()

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        super(NeoToken, self).on_persist(engine)
        validators = self.get_validators(engine)

        if self._validators_state is None:
            self._validators_state = _ValidatorsState(engine.snapshot, validators)
        self._validators_state.update(engine.snapshot, validators)

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
            storage.StorageKey(self.script_hash, self._PREFIX_ACCOUNT + account.to_array())
        )
        if storage_item is None:
            return vm.BigInteger.zero()
        state = self._state.deserialize_from_bytes(storage_item.value)
        return self._calculate_bonus(state.balance, state.balance_height, end)

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

        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_CANDIDATE + public_key.to_array())
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

        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_CANDIDATE + public_key.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            return True
        else:
            state = _CandidateState.from_storage(storage_item)
            if state.votes == vm.BigInteger.zero():
                engine.snapshot.storages.delete(storage_key)
            else:
                state.registered = False
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

        storage_key_account = storage.StorageKey(self.script_hash, self._PREFIX_ACCOUNT + account.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key_account, read_only=False)
        if storage_item is None:
            return False
        account_state = self._state.from_storage(storage_item)

        storage_key_candidate = storage.StorageKey(self.script_hash, self._PREFIX_CANDIDATE + vote_to.to_array())
        storage_item_candidate = engine.snapshot.storages.try_get(storage_key_candidate, read_only=False)
        if storage_key_candidate is None:
            return False

        candidate_state = _CandidateState.from_storage(storage_item_candidate)
        if not candidate_state.registered:
            return False

        if account_state.vote_to.is_zero():
            sk_voters_count = storage.StorageKey(self.script_hash, self._PREFIX_VOTERS_COUNT)
            si_voters_count = engine.snapshot.storages.get(sk_voters_count, read_only=False)

            old_value = vm.BigInteger(si_voters_count.value)
            new_value = old_value + account_state.balance
            si_voters_count.value = new_value.to_array()

        if not account_state.vote_to.is_zero():
            sk_validator = storage.StorageKey(self.script_hash,
                                              self._PREFIX_CANDIDATE + account_state.vote_to.to_array())
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
                        engine: contracts.ApplicationEngine) -> \
            Iterator[Tuple[cryptography.ECPoint, vm.BigInteger]]:
        if self._candidates_dirty:
            storage_results = list(engine.snapshot.storages.find(self.script_hash, self._PREFIX_CANDIDATE))
            self._candidates = []
            for k, v in storage_results:
                candidate = _CandidateState.deserialize_from_bytes(v.value)
                if candidate.registered:
                    # take of the CANDIDATE prefix
                    point = cryptography.ECPoint.deserialize_from_bytes(k.key[1:])
                    self._candidates.append((point, candidate.votes))
            self._candidates_dirty = False

        return iter(self._candidates)

    def get_candidates(self, engine: contracts.ApplicationEngine) -> None:
        array = vm.ArrayStackItem(engine.reference_counter)
        for k, v in self._get_candidates(engine):
            struct = vm.StructStackItem(engine.reference_counter)
            struct.append(vm.ByteStringStackItem(k.to_array()))
            struct.append(vm.IntegerStackItem(v))
            array.append(struct)
        engine.push(array)

    def get_validators(self, engine: contracts.ApplicationEngine) -> List[cryptography.ECPoint]:
        keys = self._get_committee_members(engine)
        keys = keys[:settings.network.validators_count]
        keys.sort()
        return keys

    def get_comittee(self, engine: contracts.ApplicationEngine) -> List[cryptography.ECPoint]:
        keys = self._get_committee_members(engine)
        keys.sort()
        return keys

    def get_committee_address(self, engine: contracts.ApplicationEngine) -> types.UInt160:
        comittees = self.get_comittee(engine)
        return to_script_hash(
            contracts.Contract.create_multisig_redeemscript(
                len(comittees) - (len(comittees) - 1) // 2,
                comittees)
        )

    def _get_committee_members(self, engine: contracts.ApplicationEngine) -> List[cryptography.ECPoint]:
        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_VOTERS_COUNT)
        storage_item = engine.snapshot.storages.get(storage_key, read_only=True)
        voters_count = int(vm.BigInteger(storage_item.value))
        voter_turnout = voters_count / float(self.total_amount)
        if voter_turnout < 0.2:
            return settings.standby_committee
        candidates = list(self._get_candidates(engine))
        if len(candidates) < len(settings.standby_committee):
            return settings.standby_committee
        # first sort by votes descending, then by ECPoint ascending
        # we negate the value of the votes (c[1]) such that they get sorted in descending order
        candidates.sort(key=lambda c: (-c[1], c[0]))
        public_keys = list(map(lambda c: c[0], candidates))
        return public_keys[:len(settings.standby_committee)]

    def get_next_block_validators(self, snapshot: storage.Snapshot) -> List[cryptography.ECPoint]:
        if self._validators_state:
            return self._validators_state.validators
        else:
            storage_item = snapshot.storages.try_get(
                storage.StorageKey(self.script_hash, self._PREFIX_NEXT_VALIDATORS),
                read_only=True
            )
            if storage_item is None:
                return settings.standby_validators
            with serialization.BinaryReader(storage_item.value) as br:
                return br.read_serializable_list(cryptography.ECPoint)

    def _distribute_gas(self,
                        engine: contracts.ApplicationEngine,
                        account: types.UInt160,
                        state: _NeoTokenStorageState) -> None:
        gas = self._calculate_bonus(state.balance, state.balance_height, engine.snapshot.persisting_block.index)
        state.balance_height = engine.snapshot.persisting_block.index
        GasToken().mint(engine, account, gas)

    def _calculate_bonus(self, value: vm.BigInteger, start: int, end: int) -> vm.BigInteger:
        if value == vm.BigInteger.zero() or start >= end:
            return vm.BigInteger.zero()

        if value.sign < 0:
            raise ValueError("Can't calculate bonus over negative balance")

        amount = vm.BigInteger.zero()
        DECREMENT_INTERVAL = self.GAS_BONUS_DECREMENT_INTERVAL
        GENERATION_AMOUNT = self.GAS_BONUS_GENERATION_AMOUNT
        GENERATION_AMOUNT_LEN = len(GENERATION_AMOUNT)

        ustart = start // DECREMENT_INTERVAL
        if ustart < GENERATION_AMOUNT_LEN:
            istart = start % DECREMENT_INTERVAL
            uend = end // DECREMENT_INTERVAL
            iend = end % DECREMENT_INTERVAL
            if uend >= GENERATION_AMOUNT_LEN:
                uend = GENERATION_AMOUNT_LEN
                iend = 0
            if iend == 0:
                uend -= 1
                iend = DECREMENT_INTERVAL

            while ustart < uend:
                amount += (DECREMENT_INTERVAL - istart) * GENERATION_AMOUNT[ustart]
                ustart += 1
                istart = 0
            amount += (iend - istart) * GENERATION_AMOUNT[ustart]

        return value * amount * GasToken().factor / self.total_amount


class GasToken(Nep5Token):
    _id: int = -2
    _service_name: str = "GAS"
    _decimals: int = 8

    _state = storage.Nep5StorageState
    _symbol = "gas"

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        account = blockchain.Blockchain.get_consensus_address(settings.standby_validators)
        self.mint(engine, account, vm.BigInteger(30_000_000) * self.factor)

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        super(GasToken, self).on_persist(engine)
        for tx in engine.snapshot.persisting_block.transactions:
            self.burn(engine, tx.sender, vm.BigInteger(tx.system_fee + tx.network_fee))
        pub_keys = NeoToken().get_next_block_validators(engine.snapshot)
        primary = pub_keys[engine.snapshot.persisting_block.consensus_data.primary_index]
        script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(primary))
        amount = vm.BigInteger(sum(tx.network_fee for tx in engine.snapshot.persisting_block.transactions))
        self.mint(engine, script_hash, amount)
