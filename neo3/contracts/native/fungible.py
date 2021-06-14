from __future__ import annotations
import struct
from .nativecontract import NativeContract
from .decorator import register
from neo3 import storage, contracts, vm, settings
from neo3.core import types, msgrouter, cryptography, serialization, to_script_hash, Size as s, IInteroperable
from typing import Tuple, List, Dict, Sequence, cast, Optional


class FungibleTokenStorageState(IInteroperable, serialization.ISerializable):
    """
    Helper class for NEP17 balance state
    """

    def __init__(self):
        super(FungibleTokenStorageState, self).__init__()
        self.balance: vm.BigInteger = vm.BigInteger.zero()

    def __len__(self):
        return len(self.balance.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_var_bytes(self.balance.to_array())

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.balance = vm.BigInteger(reader.read_var_bytes())

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        struct_ = vm.StructStackItem(reference_counter)
        struct_.append(vm.IntegerStackItem(self.balance))
        return struct_

    @classmethod
    def from_stack_item(cls, stack_item: vm.StackItem):
        si = cast(vm.StructStackItem, stack_item)
        c = cls()
        c.balance = si[0].to_biginteger()
        return c


class FungibleToken(NativeContract):
    _id: int = -99999
    _decimals: int = -1

    _state = FungibleTokenStorageState
    _symbol: str = ""

    def init(self):
        super(FungibleToken, self).init()

        self.key_account = storage.StorageKey(self._id, b'\x14')
        self.key_total_supply = storage.StorageKey(self._id, b'\x0B')

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

    @register("decimals", contracts.CallFlags.READ_STATES)
    def decimals(self) -> int:
        return self._decimals

    @register("symbol", contracts.CallFlags.READ_STATES)
    def symbol(self) -> str:
        """ Token symbol. """
        return self._symbol

    @register("totalSupply", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def total_supply(self, snapshot: storage.Snapshot) -> vm.BigInteger:
        """ Get the total deployed tokens. """
        storage_item = snapshot.storages.try_get(self.key_total_supply)
        if storage_item is None:
            return vm.BigInteger.zero()
        else:
            return vm.BigInteger(storage_item.value)

    @register("balanceOf", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
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
        storage_item = snapshot.storages.try_get(self.key_account + account)
        if storage_item is None:
            return vm.BigInteger.zero()
        else:
            state = self._state.deserialize_from_bytes(storage_item.value)
            return state.balance

    @register("transfer",
              (contracts.CallFlags.STATES | contracts.CallFlags.ALLOW_CALL | contracts.CallFlags.ALLOW_NOTIFY),
              cpu_price=1 << 17, storage_price=50)
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

        storage_key_from = self.key_account + account_from
        storage_item_from = engine.snapshot.storages.try_get(storage_key_from, read_only=False)

        if storage_item_from is None:
            return False

        state_from = storage_item_from.get(self._state)
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

                storage_key_to = self.key_account + account_to
                storage_item_to = engine.snapshot.storages.try_get(storage_key_to, read_only=False)
                if storage_item_to is None:
                    storage_item_to = storage.StorageItem(self._state().to_array())
                    engine.snapshot.storages.put(storage_key_to, storage_item_to)

                state_to = storage_item_to.get(self._state)

                self.on_balance_changing(engine, account_to, state_to, amount)
                state_to.balance += amount

        self._post_transfer(engine, account_from, account_to, amount, data, True)
        return True

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

        storage_key = self.key_account + account
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)

        if storage_item is None:
            storage_item = storage.StorageItem(self._state().to_array())
            engine.snapshot.storages.put(storage_key, storage_item)

        state = storage_item.get(self._state)
        self.on_balance_changing(engine, account, state, amount)
        state.balance += amount

        storage_item = engine.snapshot.storages.try_get(self.key_total_supply, read_only=False)
        if storage_item is None:
            storage_item = storage.StorageItem(amount.to_array())
            engine.snapshot.storages.put(self.key_total_supply, storage_item)
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

        storage_key = self.key_account + account
        storage_item = engine.snapshot.storages.get(storage_key, read_only=False)

        state = storage_item.get(self._state)
        if state.balance < amount:
            raise ValueError(f"Insufficient balance. Requesting to burn {amount}, available {state.balance}")

        self.on_balance_changing(engine, account, state, -amount)
        if state.balance == amount:
            engine.snapshot.storages.delete(storage_key)
        else:
            state.balance -= amount
            engine.snapshot.storages.update(storage_key, storage_item)

        storage_item = engine.snapshot.storages.get(self.key_total_supply, read_only=False)
        old_value = vm.BigInteger(storage_item.value)
        new_value = old_value - amount
        if new_value == vm.BigInteger.zero():
            engine.snapshot.storages.delete(self.key_total_supply)
        else:
            storage_item.value = new_value.to_array()
        self._post_transfer(engine, account, types.UInt160.zero(), amount, vm.NullStackItem(), False)

    def on_balance_changing(self, engine: contracts.ApplicationEngine,
                            account: types.UInt160,
                            state,
                            amount: vm.BigInteger) -> None:
        pass

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        pass

    def _post_transfer(self,
                       engine: contracts.ApplicationEngine,
                       account_from: types.UInt160,
                       account_to: types.UInt160,
                       amount: vm.BigInteger,
                       data: vm.StackItem,
                       call_on_payment: bool) -> None:
        state = vm.ArrayStackItem(vm.ReferenceCounter())
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
        engine.call_from_native(self.hash, account_to, "onNEP17Payment", [from_, vm.IntegerStackItem(amount), data])


class _NeoTokenStorageState(FungibleTokenStorageState):
    """
    Helper class for storing voting and bonus GAS state
    """

    def __init__(self):
        super(_NeoTokenStorageState, self).__init__()
        self.vote_to: cryptography.ECPoint = cryptography.ECPoint.deserialize_from_bytes(b'\x00')
        self.balance_height: int = 0

    def __len__(self):
        return super(_NeoTokenStorageState, self).__len__() + len(self.vote_to) + s.uint32

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        super(_NeoTokenStorageState, self).serialize(writer)
        writer.write_serializable(self.vote_to)
        writer.write_uint32(self.balance_height)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        super(_NeoTokenStorageState, self).deserialize(reader)
        self.vote_to = reader.read_serializable(cryptography.ECPoint)  # type: ignore
        self.balance_height = reader.read_uint32()

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        struct_ = super(_NeoTokenStorageState, self).to_stack_item(reference_counter)
        struct_ = cast(vm.StructStackItem, struct_)
        struct_.append(vm.IntegerStackItem(self.balance_height))
        if self.vote_to.is_zero():
            struct_.append(vm.NullStackItem())
        else:
            struct_.append(vm.ByteStringStackItem(self.vote_to.to_array()))
        return struct_

    @classmethod
    def from_stack_item(cls, stack_item: vm.StackItem):
        c = super(_NeoTokenStorageState, cls).from_stack_item(stack_item)  # type: _NeoTokenStorageState
        si = cast(vm.StructStackItem, stack_item)
        c.balance_height = int(si[1].to_biginteger())
        c.vote_to = cryptography.ECPoint.deserialize_from_bytes(si[2].to_array())
        return c


class _CandidateState(serialization.ISerializable):
    """
    Helper class for storing consensus candidates and their votes
    """

    def __init__(self):
        self.registered = True
        self.votes = vm.BigInteger.zero()

    def __len__(self):
        return 1 + len(self.votes.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_bool(self.registered)
        writer.write_var_bytes(self.votes.to_array())

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.registered = reader.read_bool()
        self.votes = vm.BigInteger(reader.read_var_bytes())


class _CommitteeState(serialization.ISerializable):
    def __init__(self,
                 snapshot: storage.Snapshot,
                 validators: Dict[cryptography.ECPoint, vm.BigInteger]):
        self.snapshot = snapshot
        self._validators = validators
        self._storage_key = NeoToken().key_committee

    def __len__(self):
        return len(self.to_array())

    def __getitem__(self, item: cryptography.ECPoint) -> vm.BigInteger:
        return self._validators[item]

    @classmethod
    def from_snapshot(cls, snapshot: storage.Snapshot):
        c = cls(snapshot, {})
        with serialization.BinaryReader(snapshot.storages.get(c._storage_key, read_only=True).value) as reader:
            c.deserialize(reader)
        return c

    @property
    def validators(self) -> List[cryptography.ECPoint]:
        return list(self._validators.keys())

    def persist(self, snapshot: storage.Snapshot):
        self.snapshot = snapshot
        self.snapshot.storages.update(self._storage_key, storage.StorageItem(self.to_array()))

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_var_int(len(self._validators))
        for key, value in self._validators.items():
            writer.write_serializable(key)
            writer.write_var_bytes(value.to_array())

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        length = reader.read_var_int()
        if self._validators is None:
            self._validators = {}
        else:
            self._validators.clear()

        for _ in range(length):
            public_key = reader.read_serializable(cryptography.ECPoint)  # type: ignore
            self._validators.update({
                public_key: vm.BigInteger(reader.read_var_bytes())
            })


class _GasRecord(serialization.ISerializable):
    def __init__(self, index: int, gas_per_block: vm.BigInteger):
        self.index = index
        self.gas_per_block = gas_per_block

    def __len__(self):
        return s.uint32 + len(self.gas_per_block.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint32(self.index)
        writer.write_var_bytes(self.gas_per_block.to_array())

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.index = reader.read_uint32()
        self.gas_per_block = vm.BigInteger(reader.read_var_bytes())

    @classmethod
    def _serializable_init(cls):
        return cls(0, vm.BigInteger.zero())


class GasBonusState(serialization.ISerializable, Sequence):
    def __init__(self, initial_record: _GasRecord = None):
        self._storage_key = NeoToken().key_gas_per_block
        self._records: List[_GasRecord] = [initial_record] if initial_record else []
        self._iter = iter(self._records)

    def __len__(self):
        return len(self._records)

    def __iter__(self):
        self._iter = iter(self._records)
        return self

    def __next__(self) -> _GasRecord:
        return next(self._iter)

    def __getitem__(self, item):
        return self._records.__getitem__(item)

    def __setitem__(self, key, record: _GasRecord) -> None:
        self._records[key] = record

    @classmethod
    def from_snapshot(cls, snapshot: storage.Snapshot, read_only=False):
        storage_item = snapshot.storages.get(NeoToken().key_gas_per_block, read_only)
        return storage_item.get(cls)

    def append(self, record: _GasRecord) -> None:
        self._records.append(record)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable_list(self._records)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self._records = reader.read_serializable_list(_GasRecord)


class NeoToken(FungibleToken):
    _id: int = -5
    _decimals: int = 0

    key_committee = storage.StorageKey(_id, b'\x0e')
    key_candidate = storage.StorageKey(_id, b'\x21')
    key_voters_count = storage.StorageKey(_id, b'\x01')
    key_gas_per_block = storage.StorageKey(_id, b'\x29')
    key_voter_reward_per_committee = storage.StorageKey(_id, b'\x17')
    key_register_price = storage.StorageKey(_id, b'\x0D')

    _NEO_HOLDER_REWARD_RATIO = 10
    _COMMITTEE_REWARD_RATIO = 10
    _VOTER_REWARD_RATIO = 80
    _symbol = "NEO"
    _state = _NeoTokenStorageState
    _candidates_dirty = True
    _candidates: List[Tuple[cryptography.ECPoint, vm.BigInteger]] = []

    def init(self):
        super(NeoToken, self).init()
        # singleton init, similar to __init__ but called only once
        self.total_amount = self.factor * 100_000_000
        self._committee_state = None

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        # NEO's native contract initialize. Is called upon contract deploy

        self._committee_state = _CommitteeState(engine.snapshot,
                                                dict.fromkeys(settings.standby_validators, vm.BigInteger(0)))
        engine.snapshot.storages.put(self.key_voters_count, storage.StorageItem(b'\x00'))

        gas_bonus_state = GasBonusState(_GasRecord(0, GasToken().factor * 5))
        engine.snapshot.storages.put(self.key_gas_per_block, storage.StorageItem(gas_bonus_state.to_array()))
        engine.snapshot.storages.put(self.key_register_price,
                                     storage.StorageItem((GasToken().factor * 1000).to_array()))
        self.mint(engine,
                  contracts.Contract.get_consensus_address(settings.standby_validators),
                  self.total_amount,
                  False)

    @register("unclaimedGas", contracts.CallFlags.READ_STATES, cpu_price=1 << 17)
    def unclaimed_gas(self, snapshot: storage.Snapshot, account: types.UInt160, end: int) -> vm.BigInteger:
        """
        Return the available bonus GAS for an account.

        Requires sending the accounts balance to release the bonus GAS.

        Args:
            snapshot: snapshot of storage
            account: account to calculate bonus for
            end: ending block height to calculate bonus up to. You should use mostlikly use the current chain height.
        """
        storage_item = snapshot.storages.try_get(self.key_account + account)
        if storage_item is None:
            return vm.BigInteger.zero()
        state = storage_item.get(self._state)
        return self._calculate_bonus(snapshot, state.vote_to, state.balance, state.balance_height, end)

    @register("registerCandidate", contracts.CallFlags.STATES)
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

        engine.add_gas(self.get_register_price(engine.snapshot))
        storage_key = self.key_candidate + public_key
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            state = _CandidateState()
            state.registered = True
            storage_item = storage.StorageItem(state.to_array())
            engine.snapshot.storages.put(storage_key, storage_item)
        else:
            state = storage_item.get(_CandidateState)
            state.registered = True
        self._candidates_dirty = True
        return True

    @register("unregisterCandidate", contracts.CallFlags.STATES, cpu_price=1 << 16)
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

        storage_key = self.key_candidate + public_key
        storage_item = engine.snapshot.storages.try_get(storage_key, read_only=False)
        if storage_item is None:
            return True
        else:
            state = storage_item.get(_CandidateState)
            state.registered = False
            if state.votes == 0:
                engine.snapshot.storages.delete(storage_key)

        self._candidates_dirty = True
        return True

    @register("vote", contracts.CallFlags.STATES, cpu_price=1 << 16)
    def vote(self,
             engine: contracts.ApplicationEngine,
             account: types.UInt160,
             vote_to: Optional[cryptography.ECPoint]) -> bool:
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

        storage_key_account = self.key_account + account
        storage_item = engine.snapshot.storages.try_get(storage_key_account, read_only=False)
        if storage_item is None:
            return False
        account_state = storage_item.get(self._state)

        candidate_state = None
        if vote_to is not None:
            storage_key_candidate = self.key_candidate + vote_to
            storage_item_candidate = engine.snapshot.storages.try_get(storage_key_candidate, read_only=False)
            if storage_item_candidate is None:
                return False

            candidate_state = storage_item_candidate.get(_CandidateState)
            if not candidate_state.registered:
                return False

        if account_state.vote_to.is_zero() ^ (vote_to is None):
            si_voters_count = engine.snapshot.storages.get(self.key_voters_count, read_only=False)
            old_value = vm.BigInteger(si_voters_count.value)
            if account_state.vote_to.is_zero():
                new_value = old_value + account_state.balance
            else:
                new_value = old_value - account_state.balance
            si_voters_count.value = new_value.to_array()

        self._distribute_gas(engine, account, account_state)

        if not account_state.vote_to.is_zero():
            sk_validator = self.key_candidate + account_state.vote_to
            si_validator = engine.snapshot.storages.get(sk_validator, read_only=False)
            validator_state = si_validator.get(_CandidateState)
            validator_state.votes -= account_state.balance

            if not validator_state.registered and validator_state.votes == 0:
                reward_key = self.key_voter_reward_per_committee + account_state.vote_to.to_array()
                for k, _ in engine.snapshot.storages.find(reward_key):
                    engine.snapshot.storages.delete(k)
                engine.snapshot.storages.delete(sk_validator)

        account_state.vote_to = vote_to if vote_to else cryptography.ECPoint.deserialize_from_bytes(b'\x00')
        if candidate_state is not None:
            candidate_state.votes += account_state.balance
        self._candidates_dirty = True

        return True

    @register("getCandidates", contracts.CallFlags.READ_STATES, cpu_price=1 << 22)
    def get_candidates(self, engine: contracts.ApplicationEngine) -> None:
        """
        Fetch all registered candidates, convert them to a StackItem and push them onto the evaluation stack.
        """
        array = vm.ArrayStackItem(engine.reference_counter)
        for k, v in self._get_candidates(engine.snapshot):
            struct = vm.StructStackItem(engine.reference_counter)
            struct.append(vm.ByteStringStackItem(k.to_array()))
            struct.append(vm.IntegerStackItem(v))
            array.append(struct)
        engine.push(array)

    @register("getNextBlockValidators", contracts.CallFlags.READ_STATES, cpu_price=1 << 16)
    def get_next_block_validators(self, snapshot: storage.Snapshot) -> List[cryptography.ECPoint]:
        """
        Get the public keys of the consensus nodes that will validate the next block.
        """
        keys = self.get_committee_from_cache(snapshot)[:settings.network.validators_count]
        keys.sort()
        return keys

    @register("setGasPerBlock", contracts.CallFlags.STATES, cpu_price=1 << 15)
    def _set_gas_per_block(self, engine: contracts.ApplicationEngine, gas_per_block: vm.BigInteger) -> None:
        if gas_per_block > 0 or gas_per_block > 10 * self._gas.factor:
            raise ValueError("new gas per block value exceeds limits")

        if not self._check_committee(engine):
            raise ValueError("Check committee failed")

        index = engine.snapshot.persisting_block.index + 1
        gas_bonus_state = GasBonusState.from_snapshot(engine.snapshot, read_only=False)
        if gas_bonus_state[-1].index == index:
            gas_bonus_state[-1] = _GasRecord(index, gas_per_block)
        else:
            gas_bonus_state.append(_GasRecord(index, gas_per_block))

    @register("getGasPerBlock", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_gas_per_block(self, snapshot: storage.Snapshot) -> vm.BigInteger:
        """
        Get the amount of gas generated in each block.

        Args:
            snapshot: the snapshot to read the data from

        Returns:
            The amount of gas generated.
        """
        index = snapshot.best_block_height + 1
        gas_bonus_state = GasBonusState.from_snapshot(snapshot, read_only=True)
        for record in reversed(gas_bonus_state):  # type: _GasRecord
            if record.index <= index:
                return record.gas_per_block
        else:
            raise ValueError

    @register("setRegisterPrice", contracts.CallFlags.STATES, cpu_price=1 << 15)
    def set_register_price(self, engine: contracts.ApplicationEngine, register_price: int) -> None:
        if register_price <= 0:
            raise ValueError("Register price cannot be negative or zero")
        if not self._check_committee(engine):
            raise ValueError("CheckCommittee failed for setRegisterPrice")
        item = engine.snapshot.storages.get(self.key_register_price, read_only=False)
        item.value = vm.BigInteger(register_price).to_array()

    @register("getRegisterPrice", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_register_price(self, snapshot: storage.Snapshot) -> int:
        """
        Get the price for registering as a candidate
        """
        return int(vm.BigInteger(snapshot.storages.get(self.key_register_price, read_only=True).value))

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

    @register("getCommittee", contracts.CallFlags.READ_STATES, cpu_price=1 << 16)
    def get_committee(self, snapshot: storage.Snapshot) -> List[cryptography.ECPoint]:
        """
        Get the public keys of the current validators.
        """
        return sorted(self.get_committee_from_cache(snapshot))

    @register("getAccountState", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_account_state(self, snapshot: storage.Snapshot, account: types.UInt160) -> Optional[_NeoTokenStorageState]:
        storage_key_account = self.key_account + account
        storage_item = snapshot.storages.try_get(storage_key_account, read_only=False)
        if storage_item is None:
            return None
        return storage_item.get(self._state)

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

        si_voters_count = engine.snapshot.storages.get(self.key_voters_count, read_only=False)
        new_value = vm.BigInteger(si_voters_count.value) + amount
        si_voters_count.value = new_value.to_array()

        si_candidate = engine.snapshot.storages.get(self.key_candidate + state.vote_to, read_only=False)
        candidate_state = si_candidate.get(_CandidateState)
        candidate_state.votes += amount
        self._candidates_dirty = True
        self._check_candidate(engine.snapshot, state.vote_to, candidate_state)

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        super(NeoToken, self).on_persist(engine)

        # set next committee
        if self._should_refresh_committee(engine.snapshot.persisting_block.index):
            validators = self._compute_committee_members(engine.snapshot)
            if self._committee_state is None:
                self._committee_state = _CommitteeState.from_snapshot(engine.snapshot)
            self._committee_state._validators = validators
            self._committee_state.persist(engine.snapshot)

    def post_persist(self, engine: contracts.ApplicationEngine):
        super(NeoToken, self).post_persist(engine)
        # distribute GAS for committee
        m = len(settings.standby_committee)
        n = settings.network.validators_count
        index = engine.snapshot.persisting_block.index % m
        gas_per_block = self.get_gas_per_block(engine.snapshot)
        committee = self.get_committee_from_cache(engine.snapshot)
        pubkey = committee[index]
        account = to_script_hash(contracts.Contract.create_signature_redeemscript(pubkey))
        GasToken().mint(engine, account, gas_per_block * self._COMMITTEE_REWARD_RATIO / 100, False)

        if self._should_refresh_committee(engine.snapshot.persisting_block.index):
            voter_reward_of_each_committee = gas_per_block * self._VOTER_REWARD_RATIO * 100000000 * m / (m + n) / 100
            for i, member in enumerate(committee):
                factor = 2 if i < n else 1
                member_votes = self._committee_state[member]
                if member_votes > 0:
                    voter_sum_reward_per_neo = voter_reward_of_each_committee * factor / member_votes
                    voter_reward_key = (self.key_voter_reward_per_committee
                                        + member
                                        + self._to_uint32(engine.snapshot.persisting_block.index + 1)
                                        )
                    border = (self.key_voter_reward_per_committee + member).to_array()
                    try:
                        pair = next(engine.snapshot.storages.find_range(voter_reward_key.to_array(), border, "reverse"))
                        result = vm.BigInteger(pair[1].value)
                    except StopIteration:
                        result = vm.BigInteger.zero()
                    voter_sum_reward_per_neo += result
                    engine.snapshot.storages.put(voter_reward_key,
                                                 storage.StorageItem(voter_sum_reward_per_neo.to_array()))

    def get_committee_from_cache(self, snapshot: storage.Snapshot) -> List[cryptography.ECPoint]:
        if self._committee_state is None:
            self._committee_state = _CommitteeState.from_snapshot(snapshot)
        return self._committee_state.validators

    def get_committee_address(self, snapshot: storage.Snapshot) -> types.UInt160:
        """ Get the script hash of the current committee """
        comittees = self.get_committee(snapshot)
        return to_script_hash(
            contracts.Contract.create_multisig_redeemscript(
                len(comittees) - (len(comittees) - 1) // 2,
                comittees)
        )

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
        border = (self.key_voter_reward_per_committee + vote).to_array()
        start_bytes = self._to_uint32(start)
        key_start = (self.key_voter_reward_per_committee + vote + start_bytes).to_array()

        try:
            pair = next(snapshot.storages.find_range(key_start, border, "reverse"))
            start_reward_per_neo = vm.BigInteger(pair[1].value)  # first pair returned, StorageItem
        except StopIteration:
            start_reward_per_neo = vm.BigInteger.zero()

        end_bytes = self._to_uint32(end)
        key_end = (self.key_voter_reward_per_committee + vote + end_bytes).to_array()

        try:
            pair = next(snapshot.storages.find_range(key_end, border, "reverse"))
            end_reward_per_neo = vm.BigInteger(pair[1].value)  # first pair returned, StorageItem
        except StopIteration:
            end_reward_per_neo = vm.BigInteger.zero()

        return neo_holder_reward + value * (end_reward_per_neo - start_reward_per_neo) / 100000000

    def _calculate_neo_holder_reward(self,
                                     snapshot: storage.Snapshot,
                                     value: vm.BigInteger,
                                     start: int,
                                     end: int) -> vm.BigInteger:
        gas_bonus_state = GasBonusState.from_snapshot(snapshot, read_only=True)
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

    def _check_candidate(self,
                         snapshot: storage.Snapshot,
                         public_key: cryptography.ECPoint,
                         candidate: _CandidateState) -> None:
        if not candidate.registered and candidate.votes == 0:
            for k, v in snapshot.storages.find((self.key_voter_reward_per_committee + public_key).to_array()):
                snapshot.storages.delete(k)
            snapshot.storages.delete(self.key_candidate + public_key)

    def _compute_committee_members(self, snapshot: storage.Snapshot) -> Dict[cryptography.ECPoint, vm.BigInteger]:
        storage_item = snapshot.storages.get(self.key_voters_count, read_only=True)
        voters_count = int(vm.BigInteger(storage_item.value))
        voter_turnout = voters_count / float(self.total_amount)

        candidates = self._get_candidates(snapshot)
        if voter_turnout < 0.2 or len(candidates) < len(settings.standby_committee):
            results = {}
            for key in settings.standby_committee:
                for pair in candidates:
                    if pair[0] == key:
                        results.update({key: pair[1]})
                        break
                else:
                    results.update({key: vm.BigInteger.zero()})
            return results
        # first sort by votes descending, then by ECPoint ascending
        # we negate the value of the votes (c[1]) such that they get sorted in descending order
        candidates.sort(key=lambda c: (-c[1], c[0]))
        trimmed_candidates = candidates[:len(settings.standby_committee)]
        results = {}
        for candidate in trimmed_candidates:
            results.update({candidate[0]: candidate[1]})
        return results

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

    def _should_refresh_committee(self, height: int) -> bool:
        return height % len(settings.standby_committee) == 0

    def _to_uint32(self, value: int) -> bytes:
        return struct.pack(">I", value)


class GasToken(FungibleToken):
    _id: int = -6
    _decimals: int = 8

    _state = FungibleTokenStorageState
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
        pub_keys = NeoToken().get_next_block_validators(engine.snapshot)
        primary = pub_keys[engine.snapshot.persisting_block.primary_index]
        script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(primary))
        self.mint(engine, script_hash, vm.BigInteger(total_network_fee), False)

    @register("refuel", contracts.CallFlags.STATES | contracts.CallFlags.ALLOW_NOTIFY, cpu_price=1 << 15)
    def refuel(self, engine: contracts.ApplicationEngine, account: types.UInt160, amount: int):
        if amount < 0:
            raise ValueError("Cannot refuel with negative amount")
        if not engine.checkwitness(account):
            raise ValueError("[refuel] check witness failed")
        self.burn(engine, account, vm.BigInteger(amount))
        engine.refuel(amount)
