from __future__ import annotations
from typing import Optional, cast, List
from . import NativeContract, register
from neo3 import contracts, storage, vm
from neo3.core import types, serialization, to_script_hash, msgrouter
from neo3.network import payloads


class OracleRequest(serialization.ISerializable):
    def __init__(self,
                 original_tx_id: types.UInt256,
                 gas_for_response: int,
                 url: str,
                 filter: str,
                 callback_contract: types.UInt160,
                 callback_method: str,
                 user_data: bytes
                 ):
        self.original_tx_id = original_tx_id
        self.gas_for_response = gas_for_response
        self.url = url
        self.filter = filter
        self.callback_contract = callback_contract
        self.callback_method = callback_method
        self.user_data = user_data

    def __len__(self):
        return len(self.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable(self.original_tx_id)
        writer.write_uint64(self.gas_for_response)
        writer.write_var_string(self.url)
        writer.write_var_string(self.filter)
        writer.write_serializable(self.callback_contract)
        writer.write_var_string(self.callback_method)
        writer.write_var_bytes(self.user_data)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.original_tx_id = reader.read_serializable(types.UInt256)
        self.gas_for_response = reader.read_uint64()
        self.url = reader.read_var_string()
        self.filter = reader.read_var_string()
        self.callback_contract = reader.read_serializable(types.UInt160)
        self.callback_method = reader.read_var_string()
        self.user_data = reader.read_var_bytes()

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt256.zero(), 0, "", "", types.UInt160.zero(), "", b'')


class OracleContract(NativeContract):
    _MAX_URL_LENGTH = 256
    _MAX_FILTER_LEN = 128
    _MAX_CALLBACK_LEN = 32
    _MAX_USER_DATA_LEN = 512
    _id = -9

    key_request_id = storage.StorageKey(_id, b'\x09')
    key_request = storage.StorageKey(_id, b'\x07')
    key_id_list = storage.StorageKey(_id, b'\x06')
    key_price = storage.StorageKey(_id, b'\x05')

    def init(self):
        super(OracleContract, self).init()
        self.manifest.abi.events = [
            contracts.ContractEventDescriptor(
                "OracleRequest",
                parameters=[
                    contracts.ContractParameterDefinition("Id", contracts.ContractParameterType.INTEGER),
                    contracts.ContractParameterDefinition("RequestContract", contracts.ContractParameterType.HASH160),
                    contracts.ContractParameterDefinition("Url", contracts.ContractParameterType.STRING),
                    contracts.ContractParameterDefinition("Filter", contracts.ContractParameterType.STRING)
                ]
            ),
            contracts.ContractEventDescriptor(
                "OracleResponse",
                parameters=[
                    contracts.ContractParameterDefinition("Id", contracts.ContractParameterType.INTEGER),
                    contracts.ContractParameterDefinition("OriginalTx", contracts.ContractParameterType.HASH160)
                ]
            )
        ]

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        engine.snapshot.storages.put(self.key_request_id, storage.StorageItem(vm.BigInteger.zero().to_array()))
        engine.snapshot.storages.put(self.key_price, storage.StorageItem(vm.BigInteger(50000000).to_array()))

    @register("setPrice", contracts.CallFlags.STATES, cpu_price=1 << 15)
    def set_price(self, engine: contracts.ApplicationEngine, price: int) -> None:
        if price <= 0:
            raise ValueError("Oracle->setPrice value cannot be negative or zero")
        if not self._check_committee(engine):
            raise ValueError("Oracle->setPrice check committee failed")
        item = engine.snapshot.storages.get(self.key_price)
        item.value = vm.BigInteger(price).to_array()

    @register("getPrice", contracts.CallFlags.READ_STATES, cpu_price=1 << 15)
    def get_price(self, snapshot: storage.Snapshot) -> int:
        return int(vm.BigInteger(snapshot.storages.get(self.key_price, read_only=True).value))

    @register("finish",
              (contracts.CallFlags.STATES | contracts.CallFlags.ALLOW_CALL | contracts.CallFlags.ALLOW_NOTIFY))
    def finish(self, engine: contracts.ApplicationEngine) -> None:
        tx = engine.script_container
        tx = cast(payloads.Transaction, tx)
        response = tx.try_get_attribute(payloads.OracleResponse)
        if response is None:
            raise ValueError("Oracle response not found")

        request = self.get_request(engine.snapshot, response.id)
        if request is None:
            raise ValueError("Oracle request not found")

        state = vm.ArrayStackItem(
            engine.reference_counter,
            [vm.IntegerStackItem(response.id),
             vm.ByteStringStackItem(request.original_tx_id.to_array())
             ]
        )

        msgrouter.interop_notify(self.hash, "OracleResponse", state)

        user_data = contracts.BinarySerializer.deserialize(request.user_data,
                                                           engine.MAX_STACK_SIZE,
                                                           engine.reference_counter)
        args: List[vm.StackItem] = [vm.ByteStringStackItem(request.url.encode()),
                                    user_data,
                                    vm.IntegerStackItem(int(response.code)),
                                    vm.ByteStringStackItem(response.result)]

        engine.call_from_native(self.hash, request.callback_contract, request.callback_method, args)

    @register("request", contracts.CallFlags.STATES | contracts.CallFlags.ALLOW_NOTIFY)
    def _request(self,
                 engine: contracts.ApplicationEngine,
                 url: str,
                 filter: str,
                 callback: str,
                 user_data: vm.StackItem,
                 gas_for_response: int) -> None:
        if len(url.encode('utf-8')) > self._MAX_URL_LENGTH or \
                len(filter.encode('utf-8')) > self._MAX_FILTER_LEN or \
                len(callback.encode('utf-8')) > self._MAX_CALLBACK_LEN or \
                callback.startswith("_") or \
                gas_for_response < 10000000:
            raise ValueError

        engine.add_gas(self.get_price(engine.snapshot))
        engine.add_gas(gas_for_response)
        self._gas.mint(engine, self.hash, vm.BigInteger(gas_for_response), False)

        si_item_id = engine.snapshot.storages.get(self.key_request_id, read_only=False)
        item_id = vm.BigInteger(si_item_id.value)
        si_item_id.value = (item_id + 1).to_array()

        if contracts.ManagementContract().get_contract(engine.snapshot, engine.calling_scripthash) is None:
            raise ValueError

        oracle_request = OracleRequest(self._get_original_txid(engine),
                                       gas_for_response,
                                       url,
                                       filter,
                                       engine.calling_scripthash,
                                       callback,
                                       contracts.BinarySerializer.serialize(user_data, self._MAX_USER_DATA_LEN))
        engine.snapshot.storages.put(self.key_request + int(item_id).to_bytes(8, 'little', signed=False),
                                     storage.StorageItem(oracle_request.to_array())
                                     )

        sk_id_list = self.key_id_list + self._get_url_hash(url)
        si_id_list = engine.snapshot.storages.try_get(sk_id_list, read_only=False)
        if si_id_list is None:
            si_id_list = storage.StorageItem(b'\x00')

        with serialization.BinaryReader(si_id_list.value) as reader:
            count = reader.read_var_int()
            id_list = []
            for _ in range(count):
                id_list.append(reader.read_uint64())

        id_list.append(item_id)
        if len(id_list) >= 256:
            raise ValueError("Oracle has too many pending responses for this url")

        with serialization.BinaryWriter() as writer:
            writer.write_var_int(len(id_list))
            for id in id_list:
                writer.write_uint64(id)
            si_id_list.value = writer.to_array()
        engine.snapshot.storages.update(sk_id_list, si_id_list)

        state = vm.ArrayStackItem(
            engine.reference_counter,
            [vm.IntegerStackItem(item_id),
             vm.ByteStringStackItem(engine.calling_scripthash.to_array()),
             vm.ByteStringStackItem(url.encode()),
             vm.ByteStringStackItem(filter.encode()),
             ]
        )

        msgrouter.interop_notify(self.hash, "OracleRequest", state)

    @register("verify", contracts.CallFlags.READ_ONLY, cpu_price=1 << 15)
    def _verify(self, engine: contracts.ApplicationEngine) -> bool:
        tx = engine.script_container
        if not isinstance(tx, payloads.Transaction):
            return False
        return bool(tx.try_get_attribute(payloads.OracleResponse))

    def get_request(self, snapshot: storage.Snapshot, id: int) -> Optional[OracleRequest]:
        id_bytes = id.to_bytes(8, 'little', signed=False)
        storage_item = snapshot.storages.try_get(self.key_request + id_bytes)
        if storage_item is None:
            return None

        return OracleRequest.deserialize_from_bytes(storage_item.value)

    def post_persist(self, engine: contracts.ApplicationEngine) -> None:
        super(OracleContract, self).post_persist(engine)
        nodes = []
        for tx in engine.snapshot.persisting_block.transactions:
            response = tx.try_get_attribute(payloads.OracleResponse)
            if response is None:
                continue

            # remove request from storage
            sk_request = self.key_request + response.id.to_bytes(8, 'little')
            si_request = engine.snapshot.storages.try_get(sk_request)
            if si_request is None:
                continue
            request = OracleRequest.deserialize_from_bytes(si_request.value)
            engine.snapshot.storages.delete(sk_request)

            # remove id from id list
            sk_id_list = self.key_id_list + self._get_url_hash(request.url)
            si_id_list = engine.snapshot.storages.try_get(sk_id_list, read_only=False)
            if si_id_list is None:
                si_id_list = storage.StorageItem(b'\x00')

            id_list = si_id_list.get(_IdList)
            id_list.remove(response.id)
            if len(id_list) == 0:
                engine.snapshot.storages.delete(sk_id_list)

            # mint gas for oracle nodes
            nodes_public_keys = contracts.DesignationContract().get_designated_by_role(
                engine.snapshot,
                contracts.DesignateRole.ORACLE,
                engine.snapshot.persisting_block.index)

            for public_key in nodes_public_keys:
                nodes.append([
                    to_script_hash(contracts.Contract.create_signature_redeemscript(public_key)),
                    vm.BigInteger.zero()
                ])
            if len(nodes) > 0:
                idx = response.id % len(nodes)
                # mypy can't figure out that the second item is a BigInteger
                nodes[idx][1] += self.get_price(engine.snapshot)  # type: ignore

        for pair in nodes:
            if pair[1].sign > 0:  # type: ignore
                self._gas.mint(engine, pair[0], pair[1], False)

    def _get_url_hash(self, url: str) -> bytes:
        return to_script_hash(url.encode('utf-8')).to_array()

    def _get_original_txid(self, engine: contracts.ApplicationEngine) -> types.UInt256:
        tx = cast(payloads.Transaction, engine.script_container)
        response = tx.try_get_attribute(payloads.OracleResponse)
        if response is None:
            return tx.hash()
        request = self.get_request(engine.snapshot, response.id)
        if request is None:
            raise ValueError  # C# will throw null pointer access exception
        return request.original_tx_id


class _IdList(list, serialization.ISerializable):
    """
    Helper class to get an IdList from storage and deal with caching.
    """
    def serialize(self, writer: serialization.BinaryWriter) -> None:
        for item in self:
            writer.write_uint64(item)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        count = reader.read_var_int()
        for _ in range(count):
            self.append(reader.read_uint64())
