from __future__ import annotations
import re
import struct
import ipaddress
from enum import IntEnum
from .nonfungible import NFTState, NonFungibleToken
from typing import Optional, Iterator, Tuple
from neo3 import contracts, storage, vm
from neo3.core import serialization, types


class RecordType(IntEnum):
    A = 1
    CNAME = 5
    TXT = 16
    AAAA = 28


class NameState(NFTState):
    def __init__(self,
                 owner: types.UInt160,
                 name: str,
                 description: str,
                 expiration: int,
                 admin: Optional[types.UInt160] = None):
        super(NameState, self).__init__(owner, name, description)
        self.expiration = expiration
        self.admin = admin if admin else types.UInt160.zero()
        self.id = name.encode()

    def __len__(self):
        return len(self.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        super(NameState, self).serialize(writer)
        writer.write_uint32(self.expiration)
        writer.write_serializable(self.admin)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        super(NameState, self).deserialize(reader)
        self.expiration = reader.read_uint32()
        self.admin = reader.read_serializable(types.UInt160)

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt160.zero(), "", "", 0, types.UInt160.zero())


class StringList(list, serialization.ISerializable):
    def __len__(self):
        return len(self.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_var_int(len(self[:]))
        for i in self:
            writer.write_var_string(i)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        for _ in range(reader.read_var_int()):
            self.append(reader.read_var_string())


class NameService(NonFungibleToken):
    _id = -8
    _symbol = "NNS"
    _service_name = None

    key_roots = storage.StorageKey(_id, b'\x0a')
    key_domain_price = storage.StorageKey(_id, b'\x16')
    key_expiration = storage.StorageKey(_id, b'\x14')
    key_record = storage.StorageKey(_id, b'\x12')

    ONE_YEAR = 365 * 24 * 3600
    REGEX_ROOT = re.compile("^[a-z][a-z0-9]{0,15}$")
    REGEX_NAME = re.compile("^(?=.{3,255}$)([a-z0-9]{1,62}\\.)+[a-z][a-z0-9]{0,15}$")

    def init(self):
        super(NameService, self).init()
        self._register_contract_method(self.add_root,
                                       "addRoot",
                                       3000000,
                                       parameter_names=["root"],
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )
        self._register_contract_method(self.set_price,
                                       "setPrice",
                                       3000000,
                                       parameter_names=["price"],
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self.register,
                                       "register",
                                       1000000,
                                       parameter_names=["name", "owner"],
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        super(NameService, self)._initialize(engine)
        engine.snapshot.storages.put(self.key_domain_price, storage.StorageItem(vm.BigInteger(1000000000).to_array()))
        engine.snapshot.storages.put(self.key_roots, storage.StorageItem(b'\x00'))

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        now = (engine.snapshot.persisting_block.timestamp // 1000) + 1
        start = (self.key_expiration + self._to_uint32(0)).to_array()
        end = (self.key_expiration + self._to_uint32(now)).to_array()
        for key, _ in engine.snapshot.storages.find_range(start, end):
            engine.snapshot.storages.delete(key)
            for key2, _ in engine.snapshot.storages.find(self.key_record + key.key[5:]).to_array():
                engine.snapshot.storages.delete(key2)
            self.burn(engine, self.key_token + key.key[5:])

    def on_transferred(self, engine: contracts.ApplicationEngine, from_account: types.UInt160, token: NFTState) -> None:
        token.owner = types.UInt160.zero()

    def add_root(self, engine: contracts.ApplicationEngine, root: str) -> None:
        if not self.REGEX_ROOT.match(root):
            raise ValueError("Regex failure - root not found")
        if not self._check_committee(engine):
            raise ValueError("Check committee failed")
        storage_item_roots = engine.snapshot.storages.get(self.key_roots, read_only=False)
        roots = storage_item_roots.get(StringList)
        if root in roots:
            raise ValueError("The name already exists")
        roots.append(root)

    def set_price(self, engine: contracts.ApplicationEngine, price: int) -> None:
        if price <= 0 or price > 10000_00000000:
            raise ValueError(f"New price '{price}' exceeds limits")
        if not self._check_committee(engine):
            raise ValueError("Check committee failed")
        storage_item = engine.snapshot.storages.get(self.key_domain_price, read_only=False)
        storage_item.value = price.to_bytes(8, 'little')

    def get_price(self, snapshot: storage.Snapshot) -> int:
        return int.from_bytes(snapshot.storages.get(self.key_domain_price, read_only=True).value, 'little')

    def is_available(self, snapshot: storage.Snapshot, name: str) -> bool:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        names = name.split(".")
        if len(names) != 2:
            raise ValueError("Invalid format")
        storage_item = snapshot.storages.try_get(self.key_token + name.encode(), read_only=True)
        if storage_item:
            return False
        storage_item_roots = snapshot.storages.get(self.key_roots, read_only=True)
        roots = storage_item_roots.get(StringList)
        if names[1] not in roots:
            raise ValueError(f"'{names[1]}' is not a registered root")
        return True

    def register(self, engine: contracts.ApplicationEngine, name: str, owner: types.UInt160) -> bool:
        if not self.is_available(engine.snapshot, name):
            raise ValueError(f"Registration failure - '{name}' is not available")

        if not engine.checkwitness(owner):
            raise ValueError("CheckWitness failed")
        engine.add_gas(self.get_price(engine.snapshot))

        state = NameState(owner, name, "", (engine.snapshot.persisting_block.timestamp // 1000) + self.ONE_YEAR)
        self.mint(engine, state)
        engine.snapshot.storages.put(
            self.key_expiration + state.expiration.to_bytes(4, 'big') + name.encode(),
            storage.StorageItem(b'\x00')
        )
        return True

    def renew(self, engine: contracts.ApplicationEngine, name: str) -> int:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        names = name.split(".")
        if len(names) != 2:
            raise ValueError("Invalid format")
        storage_item_state = engine.snapshot.storages.get(self.key_token + name.encode(), read_only=False)
        state = storage_item_state.get(NameState)
        state.expiration += self.ONE_YEAR
        return state.expiration

    def set_admin(self, engine: contracts.ApplicationEngine, name: str, admin: types.UInt160) -> None:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        names = name.split(".")

        if len(names) != 2:
            raise ValueError("Invalid format")

        if admin != types.UInt160.zero() and not engine.checkwitness(admin):
            raise ValueError("New admin is not valid - check witness failed")

        storage_item = engine.snapshot.storages.get(self.key_token + name.encode())
        state = storage_item.get(NameState)
        if not engine.checkwitness(state.owner):
            raise ValueError

        state.admin = admin

    def set_record(self, engine: contracts.ApplicationEngine, name: str, record_type: RecordType, data: str) -> None:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")

        if record_type == RecordType.A:
            # we only validate if the data is a valid IPv4 address
            ipaddress.IPv4Address(data)
        elif record_type == RecordType.CNAME:
            if not self.REGEX_NAME.match(data):
                raise ValueError("Invalid CNAME")
        elif record_type == RecordType.TXT:
            if len(data) > 255:
                raise ValueError("TXT data exceeds maximum length of 255")
        elif record_type == RecordType.AAAA:
            # we only validate if the data is a valid IPv6 address
            ipaddress.IPv6Address(data)

        domain = '.'.join(name.split('.')[2:])
        storage_item = engine.snapshot.storages.get(self.key_token + domain.encode())
        state = storage_item.get(NameState)
        if not self._check_admin(engine, state):
            raise ValueError("Admin check failed")

        storage_key_record = self.key_record + domain.encode() + name.encode() + record_type.to_bytes(1, 'little')
        engine.snapshot.storages.update(storage_key_record, storage.StorageItem(data.encode()))

    def get_record(self, snapshot: storage.Snapshot, name: str, record_type: RecordType) -> Optional[str]:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        domain = '.'.join(name.split('.')[2:])
        storage_key_record = self.key_record + domain.encode() + name.encode() + record_type.to_bytes(1, 'little')
        storage_item = snapshot.storages.try_get(storage_key_record)
        if storage_item is None:
            return None
        return storage_item.value.decode()

    def get_records(self, snapshot: storage.Snapshot, name: str) -> Iterator[Tuple[RecordType, str]]:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        domain = '.'.join(name.split('.')[2:])
        storage_key = self.key_record + domain.encode() + name.encode()
        for key, value in snapshot.storages.find(storage_key.to_array()):
            record_type = RecordType(int.from_bytes(key.key[-1], 'little'))
            yield record_type, value.value.decode()

    def delete_record(self, engine: contracts.ApplicationEngine, name: str, record_type: RecordType) -> None:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")

        domain = '.'.join(name.split('.')[2:])
        storage_item = engine.snapshot.storages.get(self.key_token + domain.encode())
        state = storage_item.get(NameState)
        if not self._check_admin(engine, state):
            raise ValueError("Admin check failed")

        storage_key_record = self.key_record + domain.encode() + name.encode() + record_type.to_bytes(1, 'little')
        engine.snapshot.storages.delete(storage_key_record)

    def resolve(self,
                snapshot: storage.Snapshot,
                name: str,
                record_type: RecordType,
                redirect_count: int = 2) -> Optional[str]:
        if redirect_count < 0:
            raise ValueError("Redirect count can't be negative")
        records = {}
        for key, value in self.get_records(snapshot, name):
            records.update({key: value})
        if record_type in records:
            return records[record_type]
        data = records.get(RecordType.CNAME, None)
        if data is None:
            return None
        return self.resolve(snapshot, data, record_type, redirect_count - 1)

    def _check_admin(self, engine: contracts.ApplicationEngine, state: NameState) -> bool:
        if engine.checkwitness(state.owner):
            return True

        if state.admin == types.UInt160.zero:
            return False

        return engine.checkwitness(state.admin)

    def _to_uint32(self, value: int) -> bytes:
        return struct.pack(">I", value)
