from __future__ import annotations
from enum import IntEnum
from contextlib import suppress
from typing import List, cast, Optional
from . import NativeContract
from neo3 import storage, contracts, cryptography, vm
from neo3.core import serialization, IInteroperable, types, msgrouter


class NFTState(IInteroperable, serialization.ISerializable):
    def __init__(self, owner: types.UInt160, name: str, description: str):
        self.owner = owner
        self.name = name
        self.description = description
        # I don't understand where this ID is coming from as its abstract in C# and not overridden
        # we'll probably figure out once we implement the name service in a later PR
        self.id: bytes = b''
        self.storage_item = storage.StorageItem(b'')

    @classmethod
    def from_stack_item(cls, stack_item: vm.StackItem):
        stack_item = cast(vm.StructStackItem, stack_item)
        owner = types.UInt160(stack_item[0].to_array())
        name = stack_item[1].to_array().decode()
        description = stack_item[2].to_array().decode()
        return cls(owner, name, description)

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        return vm.StructStackItem(reference_counter, [
            vm.ByteStringStackItem(self.owner.to_array()),
            vm.ByteStringStackItem(self.name),
            vm.ByteStringStackItem(self.description)
        ])

    @property
    def owner(self):
        return self.owner

    @owner.setter
    def owner(self, new_value: types.UInt160):
        self.owner = new_value
        self.storage_item.value = self.to_array()

    @classmethod
    def from_storage(cls, item: storage.StorageItem):
        c = cls.deserialize_from_bytes(item.value)
        c.storage_item = item
        return c

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable(self.owner)
        writer.write_var_string(self.name)
        writer.write_var_string(self.description)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.owner = reader.read_serializable(types.UInt160)
        self.name = reader.read_var_string()
        self.description = reader.read_var_string()

    def to_json(self) -> dict:
        return {"name": self.name, "description": self.description}

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt160.zero(), "", "")


class NFTAccountState(storage.FungibleTokenStorageState):
    def __init__(self):
        super(NFTAccountState, self).__init__()
        self.tokens: List[bytes] = []

    def add(self, token_id: bytes) -> None:
        self.balance += 1
        if token_id in self.tokens:
            raise ValueError("Token already exists")
        self.tokens.append(token_id)

    def remove(self, token_id: bytes) -> None:
        self.balance -= 1
        with suppress(ValueError):
            self.tokens.remove(token_id)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        super(NFTAccountState, self).deserialize(reader)
        for _ in range(reader.read_var_int()):
            self.tokens.append(reader.read_var_bytes())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        super(NFTAccountState, self).serialize(writer)
        writer.write_var_int(len(self.tokens))
        for i in self.tokens:
            writer.write_var_bytes(i)


class NonFungibleToken(NativeContract):
    _id = -5
    _service_name: Optional[str] = "NonfungibleToken"
    _symbol: str = ""

    _PREFIX_TOTAL_SUPPLY = b'\x0b'
    _PREFIX_TOKEN = b'\x05'
    _PREFIX_ACCOUNT = b'\x07'

    key_total_suppply = storage.StorageKey(_id, _PREFIX_TOTAL_SUPPLY)
    key_token = storage.StorageKey(_id, _PREFIX_TOKEN)
    key_account = storage.StorageKey(_id, _PREFIX_ACCOUNT)

    def init(self):
        super(NonFungibleToken, self).init()
        self.manifest.abi.events = [
            contracts.ContractEventDescriptor(
                "Transfer",
                parameters=[
                    contracts.ContractParameterDefinition("from", contracts.ContractParameterType.HASH160),
                    contracts.ContractParameterDefinition("to", contracts.ContractParameterType.HASH160),
                    contracts.ContractParameterDefinition("amount", contracts.ContractParameterType.INTEGER),
                    contracts.ContractParameterDefinition("tokenId", contracts.ContractParameterType.BYTEARRAY)
                ]
            )
        ]

        self._register_contract_method(self.total_supply,
                                       "totalSupply",
                                       1000000,
                                       return_type=vm.BigInteger,
                                       add_engine=False,
                                       add_snapshot=True,
                                       call_flags=contracts.CallFlags.READ_STATES)

        self._register_contract_method(self.owner_of,
                                       "ownerOf",
                                       1000000,
                                       return_type=types.UInt160,
                                       add_engine=False,
                                       add_snapshot=True,
                                       call_flags=contracts.CallFlags.READ_STATES)

        self._register_contract_method(self.properties,
                                       "properties",
                                       1000000,
                                       return_type=types.UInt160,
                                       add_engine=False,
                                       add_snapshot=True,
                                       call_flags=contracts.CallFlags.READ_STATES)

        self._register_contract_method(self.balance_of,
                                       "balanceOf",
                                       1000000,
                                       return_type=vm.BigInteger,
                                       parameter_types=[types.UInt160],
                                       parameter_names=["owner"],
                                       add_engine=False,
                                       add_snapshot=True,
                                       call_flags=contracts.CallFlags.READ_STATES)
        self._register_contract_method(self.transfer,
                                       "transfer",
                                       9000000,
                                       return_type=bool,
                                       parameter_names=["to", "tokenId"],
                                       parameter_types=[types.UInt160, bytes],
                                       add_engine=True,
                                       add_snapshot=False,
                                       call_flags=(contracts.CallFlags.WRITE_STATES
                                                   | contracts.CallFlags.ALLOW_NOTIFY))

    def mint(self, engine: contracts.ApplicationEngine, token: NFTState) -> None:
        engine.snapshot.storages.put(self.key_token + token.id, storage.StorageItem(token.to_array()))
        sk_account = self.key_account + token.id
        si_account = engine.snapshot.storages.try_get(sk_account, read_only=False)

        if si_account is None:
            si_account = storage.StorageItem(NFTAccountState().to_array())
            engine.snapshot.storages.put(sk_account, si_account)

        account = NFTAccountState.from_storage(si_account)
        account.add(token.id)

        si_total_supply = engine.snapshot.storages.try_get(self.key_total_suppply, read_only=False)
        if si_total_supply is None:
            si_total_supply = storage.StorageItem(vm.BigInteger.one().to_array())
        else:
            new_value = vm.BigInteger(si_total_supply.value) + 1
            si_total_supply.value = new_value.to_array()
        engine.snapshot.storages.update(self.key_total_suppply, si_total_supply)

        self._post_transfer(engine, types.UInt160.zero(), token.owner, token.id)

    def burn(self, engine: contracts.ApplicationEngine, token_id: bytes) -> None:
        key_token = self.key_token + token_id
        si_token = engine.snapshot.storages.try_get(key_token, read_only=True)
        if si_token is None:
            raise ValueError("Token cannot be found")
        token = NFTState.deserialize_from_bytes(si_token.value)
        engine.snapshot.storages.delete(key_token)

        key_account = self.key_account + token.owner.to_array()
        account_state = NFTAccountState.from_storage(engine.snapshot.storages.get(key_account))
        account_state.remove(token_id)

        if account_state.balance == 0:
            engine.snapshot.storages.delete(key_account)

        si_total_supply = engine.snapshot.storages.get(self.key_total_suppply)
        new_value = vm.BigInteger(si_total_supply.value) + 1
        si_total_supply.value = new_value.to_array()

        self._post_transfer(engine, token.owner, types.UInt160.zero(), token_id)

    def total_supply(self, snapshot: storage.Snapshot) -> vm.BigInteger:
        storage_item = snapshot.storages.try_get(self.key_total_suppply)
        if storage_item is None:
            return vm.BigInteger.zero()
        else:
            return vm.BigInteger(storage_item.value)

    def owner_of(self, snapshot: storage.Snapshot, token_id: bytes) -> types.UInt160:
        storage_item = snapshot.storages.get(self.key_token + token_id, read_only=True)
        return NFTState.from_stack_item(storage_item).owner

    def properties(self, snapshot: storage.Snapshot, token_id: bytes) -> dict:
        storage_item = snapshot.storages.get(self.key_token + token_id, read_only=True)
        return NFTState.deserialize_from_bytes(storage_item.value).to_json()

    def balance_of(self, snapshot: storage.Snapshot, owner: types.UInt160) -> vm.BigInteger:
        storage_item = snapshot.storages.try_get(self.key_account + owner.to_array(), read_only=True)
        if storage_item is None:
            return vm.BigInteger.zero()
        return NFTAccountState.deserialize_from_bytes(storage_item.value).balance

    def transfer(self, engine: contracts.ApplicationEngine, account_to: types.UInt160, token_id: bytes) -> bool:
        if account_to == types.UInt160.zero():
            raise ValueError("To account can't be zero")

        key_token = self.key_token + token_id
        storage_item = engine.snapshot.storages.try_get(key_token, read_only=True)
        if storage_item is None:
            raise ValueError("Token state not found")
        token_state = NFTState.deserialize_from_bytes(storage_item.value)
        if token_state.owner != engine.calling_scripthash and engine.checkwitness(token_state.owner):
            return False
        if token_state.owner != account_to:
            token = NFTState.from_stack_item(engine.snapshot.storages.get(key_token, read_only=False))
            key_from = self.key_account + token_state.owner.to_array
            account_state = NFTAccountState.from_storage(engine.snapshot.storages.get(key_from))
            account_state.remove(token_id)
            if account_state.balance == 0:
                engine.snapshot.storages.delete(key_from)
            token.owner = account_to
            key_to = self.key_account + account_to.to_array()
            storage_item = engine.snapshot.storages.try_get(key_to, read_only=False)
            if storage_item is None:
                storage_item = storage.StorageItem(NFTAccountState().to_array())
                engine.snapshot.storages.put(key_to, storage_item)
            NFTAccountState.from_storage(storage_item).add(token_id)
            self.on_transferred(engine, token.owner, token)

        self._post_transfer(engine, token_state.owner, account_to, token_id)
        return True

    def on_transferred(self, engine: contracts.ApplicationEngine, from_account: types.UInt160, token: NFTState) -> None:
        pass

    def _post_transfer(self,
                       engine: contracts.ApplicationEngine,
                       account_from: types.UInt160,
                       account_to: types.UInt160,
                       token_id: bytes) -> None:
        state = vm.ArrayStackItem(engine.reference_counter)
        if account_from == types.UInt160.zero():
            state.append(vm.NullStackItem())
        else:
            state.append(vm.ByteStringStackItem(account_from.to_array()))
        if account_to == types.UInt160.zero():
            state.append(vm.NullStackItem())
        else:
            state.append(vm.ByteStringStackItem(account_to.to_array()))
        state.append(vm.IntegerStackItem(1))
        state.append(vm.ByteStringStackItem(token_id))

        msgrouter.interop_notify(self.hash, "Transfer", state)
