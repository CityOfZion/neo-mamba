from __future__ import annotations
import aiohttp
import base64
from dataclasses import dataclass
from typing import List, Dict, Union, Optional, TypedDict, Any, Protocol, Iterator, Tuple
import datetime
from neo3 import contracts
from neo3.network import payloads
from neo3.core import types, cryptography, IJson


@dataclass
class BlockValidator:
    public_key: cryptography.ECPoint
    votes: int
    active: bool

    def __repr__(self):
        return f"{self.__class__.__name__}(public_key={self.public_key}, votes={self.votes}, acitive={self.active})"


@dataclass
class NextBlockValidatorsResponse:
    validators: List[BlockValidator]

    @classmethod
    def from_json(cls, json: dict):
        nvr = cls([])
        for validator in json:
            pk = cryptography.ECPoint.deserialize_from_bytes(bytes.fromhex(validator['publickey']))
            votes = int(validator['votes'])
            nvr.validators.append(BlockValidator(pk, votes, validator['active']))
        return nvr


@dataclass
class VersionProtocol:
    addressversion: int
    network: int
    validatorscount: int
    msperblock: int
    maxtraceableblocks: int
    maxtransactionsperblock: int
    maxvaliduntilblockincrement: int
    memorypoolmaxtransactions: int
    initialgasdistribution: int


@dataclass
class GetVersionResponse:
    tcpport: int
    wsport: int
    nonce: int
    useragent: str
    protocol: VersionProtocol

    @classmethod
    def from_json(cls, json: dict):
        json['protocol'] = VersionProtocol(**json['protocol'])
        return cls(**json)


@dataclass
class Peer:
    address: str
    port: int


@dataclass
class GetPeersResponse:
    connected: List[Peer]
    bad: List[Peer]
    unconnected: List[Peer]

    @classmethod
    def from_json(cls, json: dict):
        c = cls([], [], [])
        for p in json['connected']:
            c.connected.append(Peer(**p))
        for p in json['bad']:
            c.bad.append(Peer(**p))
        for p in json['unconnected']:
            c.unconnected.append(Peer(**p))
        return c


@dataclass
class Nep17Balance:
    asset_hash: types.UInt160
    amount: int
    last_updated_block: int

    def __repr__(self):
        return f"{self.__class__.__name__}(asset_hash={self.asset_hash}, amount={self.amount}, " \
               f"last_updated_block={self.last_updated_block})"


@dataclass
class Nep17BalancesResponse:
    balances: List[Nep17Balance]
    address: str

    @classmethod
    def from_json(cls, json: dict):
        c = cls([], json['address'])
        for b in json['balance']:
            h = types.UInt160.from_string(b['assethash'][2:])
            a = int(b['amount'])
            c.balances.append(Nep17Balance(h, a, b['lastupdatedblock']))
        return c


@dataclass
class Nep17Transfer:
    time: datetime.datetime
    asset_hash: types.UInt160
    transfer_address: str
    amount: int
    block_index: int
    transfer_notify_index: int
    tx_hash: types.UInt256

    @classmethod
    def from_json(cls, json: dict):
        time = datetime.datetime.fromtimestamp(json['timestamp'] / 1000, datetime.timezone.utc)
        hash_ = types.UInt160.from_string(json['assethash'][2:])
        transfer_addr = json['transferaddress']
        amount = int(json['amount'])
        tx_hash = types.UInt256.from_string(json['txhash'][2:])
        return cls(time, hash_, transfer_addr, amount, json['blockindex'], json['transfernotifyindex'], tx_hash)

    def __repr__(self):
        return f"{self.__class__.__name__}(time={self.time}, asset_hash={self.asset_hash}, " \
               f"transfer_address={self.transfer_address}, amount={self.amount}, block_index={self.block_index}, " \
               f"transfer_notify_index={self.transfer_notify_index}, tx_hash={self.tx_hash})"


@dataclass
class Nep17TransfersResponse:
    sent: List[Nep17Transfer]
    received: List[Nep17Transfer]
    address: str

    @classmethod
    def from_json(cls, json: dict):
        c = cls([], [], json['address'])
        for t in json['sent']:
            c.sent.append(Nep17Transfer.from_json(t))
        for t in json['received']:
            c.received.append(Nep17Transfer.from_json(t))
        return c


@dataclass
class MempoolResponse:
    """
    A verified transaction in the memory pool is a transaction which has had:
    - basic structural validation (e.g. max tx size)
    - signature validation
    - state validation
        - block validity expiration check
        - available balance vs network and system fees
        - etc
    """
    verified: List[types.UInt256]
    unverified: List[types.UInt256]

    @classmethod
    def from_json(cls, json: dict):
        c = cls([], [])
        for tx in json['verified']:
            c.verified.append(types.UInt256.from_string(tx[2:]))
        for tx in json['unverified']:
            c.unverified.append(types.UInt256.from_string(tx[2:]))
        return c


@dataclass
class StackItem:
    type: str
    value: Any


class MapStackItem(StackItem):
    def items(self) -> Iterator:
        for pair in self.value:  # type: Tuple[StackItem, StackItem]
            yield pair[0].value, pair[1].value

    def keys(self) -> Iterator:
        for pair in self.value:  # type: Tuple[StackItem, StackItem]
            yield pair[0].value

    def values(self) -> Iterator:
        for pair in self.value:  # type: Tuple[StackItem, StackItem]
            yield pair[1].value

    def __getitem__(self, item: str):
        for pair in self.value:  # type: Tuple[StackItem, StackItem]
            if pair[0].value == item:
                return pair[1].value
        else:
            raise KeyError

    def __iter__(self):
        for pair in self.value:  # type: Tuple[StackItem, StackItem]
            yield pair[0].value


_Item = TypedDict("_Item", {"type": str, "value": Any})


@dataclass
class ExecutionResult:
    state: str
    gas_consumed: int
    exception: Optional[str]
    stack: List[StackItem]

    @staticmethod
    def _parse_stack_item(item: _Item) -> StackItem:
        type_ = item['type']
        if type_ in ("Array", "Struct"):
            list_ = list(map(lambda element: ExecutionResult._parse_stack_item(element), item['value']))
            return StackItem(type_, list_)
        elif type_ in ("Boolean", "Pointer"):
            return StackItem(**item)
        if type_ in ("Buffer", "ByteString"):
            return StackItem(type_, base64.b64decode(item['value']))
        elif type_ == "Integer":
            return StackItem(type_, int(item['value']))
        elif type_ == "Map":
            map_ = []
            for stack_item in item['value']:

                key = ExecutionResult._parse_stack_item(stack_item['key'])
                key_type = stack_item['key']['type']
                if key_type == "ByteString":
                    key.value = key.value.decode()
                else:
                    key.value = str(key.value)
                value = ExecutionResult._parse_stack_item(stack_item['value'])
                map_.append((key, value))
            return MapStackItem(type_, map_)
        elif type_ == "Any":
            return StackItem(type_, None)
        else:
            raise ValueError(f"Unknown stack item type: {type_}")
        assert False, "unreachable"  # just to help mypy

    @classmethod
    def from_json(cls, json: dict):
        gc = int(json['gasconsumed'])
        stack = list(map(lambda item: ExecutionResult._parse_stack_item(item), json['stack']))
        return cls(json['state'], gc, json['exception'], stack)


@dataclass
class ExecutionResultResponse(ExecutionResult):
    script: bytes

    @classmethod
    def from_json(cls, json: dict):
        script = base64.b64decode(json['script'])
        gc = int(json['gasconsumed'])
        stack = list(map(lambda item: ExecutionResult._parse_stack_item(item), json['stack']))
        return cls(json['state'], gc, json['exception'], stack, script)


@dataclass
class Notification:
    contract: types.UInt160
    event_name: str
    state: StackItem

    @classmethod
    def from_json(cls, json: dict):
        c = types.UInt160.from_string(json['contract'][2:])
        e = json['eventname']
        s = ExecutionResult._parse_stack_item(json['state'])
        return cls(c, e, s)

    def __repr__(self):
        return f"{self.__class__.__name__}(contract={str(self.contract)}, " \
               f"event_name={self.event_name}, state={self.state})"


@dataclass
class ApplicationExecution(ExecutionResult):
    trigger: str
    notifications: List[Notification]

    @classmethod
    def from_json(cls, json: dict):
        gc = int(json['gasconsumed'])
        stack = list(map(lambda item: ExecutionResult._parse_stack_item(item), json['stack']))
        state = json['vmstate']
        ex = json['exception']
        notifications = []
        for n in json['notifications']:
            notifications.append(Notification.from_json(n))

        return cls(trigger=json['trigger'], notifications=notifications, state=state, gas_consumed=gc, exception=ex,
                   stack=stack)


@dataclass
class AppliationLogResponse:
    tx_id: types.UInt256
    executions: List[ApplicationExecution]

    @classmethod
    def from_json(cls, json: dict):
        tx_id = types.UInt256.from_string(json['txid'][2:])
        executions = []
        for execution in json['executions']:
            executions.append(ApplicationExecution.from_json(execution))
        return cls(tx_id, executions)

    def __repr__(self):
        return f"{self.__class__.__name__}(tx_id={str(self.tx_id)}, executions={self.executions})"


ContractParameter = Union[bool, int, str, bytes, bytearray, types.UInt160, types.UInt256, cryptography.ECPoint,
                          "ContractParameterArray", "ContractParameterDict"]


class ContractParameterArray(Protocol):
    def insert(self, index: int, value: ContractParameter) -> None: ...

    def __getitem__(self, i: int) -> ContractParameter: ...

    def __setitem__(self, i: int, o: ContractParameter) -> None: ...

    def __delitem__(self, i: int) -> None: ...


class ContractParameterDict(Protocol):
    def __setitem__(self, k: ContractParameter, v: ContractParameter) -> None: ...

    def __delitem__(self, v: ContractParameter) -> None: ...

    def __getitem__(self, k: ContractParameter) -> ContractParameter: ...

    def __iter__(self) -> Iterator[ContractParameter]: ...


class _ContractParameter(IJson):
    def __init__(self, obj: ContractParameter):
        self.value: ContractParameter = ''  # just to help mypy
        if isinstance(obj, bool):
            self.type = contracts.ContractParameterType.BOOLEAN
            self.value = obj
        elif isinstance(obj, int):
            self.type = contracts.ContractParameterType.INTEGER
            self.value = str(obj)
        elif isinstance(obj, str):
            self.type = contracts.ContractParameterType.STRING
            self.value = obj
        elif isinstance(obj, (bytes, bytearray)):
            self.type = contracts.ContractParameterType.BYTEARRAY
            self.value = base64.b64encode(obj).decode()
        elif isinstance(obj, types.UInt160):
            self.type = contracts.ContractParameterType.HASH160
            self.value = f"0x{obj}"
        elif isinstance(obj, types.UInt256):
            self.type = contracts.ContractParameterType.HASH256
            self.value = f"0x{obj}"
        elif isinstance(obj, cryptography.ECPoint):
            self.type = contracts.ContractParameterType.PUBLICKEY
            self.value = obj.to_array().hex()
        elif isinstance(obj, list):
            self.type = contracts.ContractParameterType.ARRAY
            self.value = list(map(lambda element: _ContractParameter(element), obj))
        elif isinstance(obj, dict):
            self.type = contracts.ContractParameterType.MAP
            pairs: List[Dict] = []
            for k, v in obj.items():
                pairs.append({"key": _ContractParameter(k), "value": _ContractParameter(v)})
            # It seems like mypy can't follow that ContractParameter is also
            # a List[Dict[ContractParameter, ContractParameter]]
            self.value = pairs  # type: ignore
        else:
            raise ValueError(f"Unsupported type {type(obj)}")

    @classmethod
    def from_json(cls, json: dict):
        """ Not supported """
        raise NotImplementedError

    def to_json(self) -> dict:
        return {"type": self.type.PascalCase(), "value": self.value}


class RPCClient:
    def __init__(self, url: str, timeout: float = 3.0):
        """
        Args:
            url: host + port
            timeout: total time in seconds a request may take
        """
        self.url = url
        self.timeout = timeout
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))

    async def _post(self, json: dict):
        """
        Create a POST request with JSON to `self.url` with `self.timeout`

        Raises:
            asyncio.exceptions.TimeoutError
        """
        async with self.session.post(self.url, json=json) as request:
            return await request.json()

    async def close(self):
        """
        Close the client session
        """
        await self.session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self.session.closed:
            await self.session.close()


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: str = None):
        self.code = code
        self.message = message
        self.data = "" if data is None else data

    def __str__(self):
        if len(self.data) > 0:
            return f"code={self.code}, message={self.message}, data={self.data}"
        else:
            return f"code={self.code}, message={self.message}"


class NeoRpcClient(RPCClient):
    def __init__(self, host: str, **kwargs):
        super(NeoRpcClient, self).__init__(host, **kwargs)

    async def _do_post(self, method: str, params: List = None, id: int = 0, jsonrpc_version: str = "2.0"):
        params = params if params else []
        json = {'jsonrpc': jsonrpc_version, 'id': id, "method": method, "params": params}
        response = await super(NeoRpcClient, self)._post(json)
        if "error" in response:
            raise JsonRpcError(**response['error'])
        return response['result']

    async def calculate_network_fee(self, transaction: Union[bytes, payloads.Transaction]) -> int:
        """
        Obtain the cost of verifying the transaction and including it in a block (a.k.a network fee).
        """
        if isinstance(transaction, payloads.Transaction):
            transaction = transaction.to_array()
        params = [base64.b64encode(transaction).decode()]
        result = await self._do_post("calculatenetworkfee", params)
        return int(result['networkfee'])

    async def get_application_log(self, tx_hash: Union[types.UInt256, str]) -> AppliationLogResponse:
        """
        Fetch the smart contract event logs for a given transaction.

        Commonly used to verify that a transaction sent via `send_transaction()` was executed succesfully on chain.

        Args:
            tx_hash: the hash of the transaction to query for.
        """
        if isinstance(tx_hash, types.UInt256):
            tx_hash = f"0x{str(tx_hash)}"
        result = await self._do_post("getapplicationlog", [tx_hash])
        return AppliationLogResponse.from_json(result)

    async def get_best_block_hash(self) -> types.UInt256:
        """
        Fetch the hash of the highest block in the chain.
        """
        response = await self._do_post("getbestblockhash")
        return types.UInt256.from_string(response[2:])

    async def get_block(self, index_or_hash: Union[int, types.UInt256]) -> payloads.Block:
        """
        Fetch the block by its index or block hash.
        """
        params: List[Union[int, str]] = []
        if isinstance(index_or_hash, types.UInt256):
            params.append(f"0x{index_or_hash}")
        else:
            params.append(index_or_hash)
        response = await self._do_post("getblock", params)
        return payloads.Block.deserialize_from_bytes(base64.b64decode(response))

    async def get_block_count(self) -> int:
        """
        Fetch the current height of the block chain.
        """
        return await self._do_post("getblockcount")

    async def get_block_hash(self, index: int) -> types.UInt256:
        """
        Fetch the block hash by the block's index.
        """
        response = await self._do_post("getblockhash", [index])
        return types.UInt256.from_string(response[2:])

    async def get_block_header(self, index_or_hash: Union[int, types.UInt256]) -> payloads.Header:
        """
        Fetch the block header by its index or block hash.
        """
        if isinstance(index_or_hash, types.UInt256):
            params = [f"0x{index_or_hash}"]
        else:
            params = [str(index_or_hash)]
        response = await self._do_post("getblockheader", params)
        return payloads.Header.deserialize_from_bytes(base64.b64decode(response))

    async def get_committee(self) -> List[cryptography.ECPoint]:
        """
        Fetch the public keys of the current NEO committee.
        """
        response = await self._do_post("getcommittee")
        keys = []
        for pk in response:
            keys.append(cryptography.ECPoint.deserialize_from_bytes(bytes.fromhex(pk)))
        return keys

    async def get_connection_count(self) -> int:
        """
        Fetch the number of peers connected to the node.
        """
        return await self._do_post("getconnectioncount")

    async def get_contract_state(self, contract_hash_or_name: Union[types.UInt160, str]) -> contracts.ContractState:
        """
        Fetch smart contract state information.

        Note:
            Only native contracts can be queried by their name. Name is case-insensitive.
        """
        if isinstance(contract_hash_or_name, types.UInt160):
            params = [f"0x{str(contract_hash_or_name)}"]
        else:
            params = [contract_hash_or_name]
        result = await self._do_post("getcontractstate", params)

        h = types.UInt160.from_string(result['hash'][2:])
        nef = contracts.NEF.from_json(result['nef'])
        manifest = contracts.ContractManifest.from_json(result['manifest'])
        return contracts.ContractState(result['id'], nef, manifest, result['updatecounter'], h)

    async def get_nep17_balances(self, address: str) -> Nep17BalancesResponse:
        """
        Fetch the balance of all NEP17 assets for the specified address.
        """
        result = await self._do_post("getnep17balances", [address])
        return Nep17BalancesResponse.from_json(result)

    async def get_nep17_transfers(self,
                                  address: str,
                                  start_time: Optional[datetime.datetime] = None,
                                  end_time: Optional[datetime.datetime] = None,
                                  ) -> Nep17TransfersResponse:
        """
        Obtain NEP17 transfers for a given address. Defaults to the last 7 days on the server side.

        Args:
            address: account to get transfer for
            start_time: if given the start of the requested range. Must be in UTC and time aware not naïve
            end_time: if given the end of the requested range

        Example:
            # Fetch transfers of the last 14 days
            start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=14)
            await get_nep17_transfers(<your address>, start)
        """
        params = [address]
        if start_time is not None:
            if start_time.tzinfo is None:
                raise ValueError("start_time is a naïve datetime object which can cause incorrect results. Make it "
                                 "time aware by adding tzinfo. For more information see: "
                                 "https://docs.python.org/3/library/datetime.html#datetime.datetime.tzinfo")
            # C# server side expects timestamp in milliseconds instead of seconds
            t = int(start_time.timestamp() * 1000)
            params.append(str(t))

        if end_time is not None:
            if end_time.tzinfo is None:
                raise ValueError("end_time is a naïve object which can cause incorrect results. Make it time aware by "
                                 "adding tzinfo. For more information see: "
                                 "https://docs.python.org/3/library/datetime.html#datetime.datetime.tzinfo")
            t = int(end_time.timestamp() * 1000)
            params.append(str(t))

        result = await self._do_post("getnep17transfers", params)
        return Nep17TransfersResponse.from_json(result)

    async def get_raw_mempool(self) -> MempoolResponse:
        """
        Return the transaction hashes currently in the memory pool waiting to be added to the next produced block.
        """
        result = await self._do_post("getrawmempool", [True])
        return MempoolResponse.from_json(result)

    async def get_next_blockvalidators(self) -> NextBlockValidatorsResponse:
        """
        Fetch the list of next block validators.
        """
        result = await self._do_post("getnextblockvalidators")
        return NextBlockValidatorsResponse.from_json(result)

    async def get_peers(self) -> GetPeersResponse:
        """
        Fetch peer information
        """
        result = await self._do_post("getpeers")
        return GetPeersResponse.from_json(result)

    async def get_storage(self, script_hash: types.UInt160, key: bytes) -> bytes:
        """
        Fetch a value from a smart contracts storage by its key.

        Args:
            script_hash: contract script hash
            key: the storage key to fetch the data for

        Example:
            # fetch the fee per byte from the Policy native contract
            key_fee_per_byte = b'\x0a'
            await client.get_storage(contracts.PolicyContract().hash, key_fee_per_byte)
        """
        hash_ = f"0x{script_hash}"
        key_encoded = base64.b64encode(key).decode()
        result = await self._do_post("getstorage", params=[hash_, key_encoded])
        return base64.b64decode(result)

    async def get_transaction(self, tx_hash: Union[types.UInt256, str]) -> payloads.Transaction:
        """
        Fetch a transaction by its hash.

        Args:
            tx_hash: as string without "0x" prefix!
        """
        if isinstance(tx_hash, str):
            tx_hash = types.UInt256.from_string(tx_hash)
        result = await self._do_post("getrawtransaction", [f"0x{tx_hash}"])
        return payloads.Transaction.deserialize_from_bytes(base64.b64decode(result))

    async def get_transaction_height(self, tx_hash: Union[types.UInt256, str]) -> int:
        """
        Fetch the height of the block the transaction is included in.

        Args:
            tx_hash: as string without "0x" prefix!
        """
        if isinstance(tx_hash, str):
            tx_hash = types.UInt256.from_string(tx_hash)
        return await self._do_post("gettransactionheight", [f"0x{tx_hash}"])

    async def get_unclaimed_gas(self, address: str) -> int:
        """
        Fetch the amount of unclaimed gas for the given address.

        Args:
            address: a NEO address
        """
        result = await self._do_post("getunclaimedgas", [address])
        return int(result['unclaimed'])

    async def get_version(self) -> GetVersionResponse:
        """
        Fetch the node client version, network protocol properties and network ports.
        """
        return GetVersionResponse.from_json(await self._do_post("getversion"))

    async def invoke_contract_verify(self,
                                     contract_hash: Union[types.UInt160, str],
                                     function_params: Optional[List[ContractParameter]] = None,
                                     signers: Optional[List[payloads.Signer]] = None
                                     ) -> ExecutionResultResponse:
        """
        Invoke the `verify` method on the contract.

        Note:
            Calling smart contracts through this function does not alter the blockchain state.
            The smart contract will be called using the Verification trigger (unlike the `invoke_function` method
            which uses the Application trigger).

        Args:
            contract_hash: the hash of the smart contract to call
            function_params: the arguments required by the smart contract function
            signers: additional signers (e.g. for checkwitness passing)
        """
        if isinstance(contract_hash, str):
            contract_hash = types.UInt160.from_string(contract_hash)
        contract_hash = f"0x{contract_hash}"

        function_params = [] if function_params is None else function_params
        function_params = list(map(lambda fp: _ContractParameter(fp).to_json(), function_params))

        signers = [] if signers is None else signers
        signers = list(map(lambda s: s.to_json(), signers))  # type: ignore

        params = [contract_hash, function_params, signers]
        result = await self._do_post("invokecontractverify", params)
        return ExecutionResultResponse.from_json(result)

    async def invoke_function(self,
                              contract_hash: Union[types.UInt160, str],
                              name: str,
                              function_params: Optional[List[ContractParameter]] = None,
                              signers: Optional[List[payloads.Signer]] = None
                              ) -> ExecutionResultResponse:
        """
        Invoke a smart contract function.

        Note:
            Calling smart contracts through this function does not alter the blockchain state.
            To alter the blockchain state use the `send_transaction` method instead.

        Args:
            contract_hash: the hash of the smart contract to call
            name: the name of the function to call on the smart contract
            function_params: the arguments required by the smart contract function
            signers: additional signers (e.g. for checkwitness passing)

        Example:
            # check if an account is blocked using the Policy native contract
            policy_contract = "cc5e4edd9f5f8dba8bb65734541df7a1c081c67b"
            account_to_check = types.UInt160.from_string("86df72a6b4ab5335d506294f9ce993722253b6e2")
            signer_account = types.UInt160.from_string("f621168b1fce3a89c33a5f6bcf7e774b4657031c")
            signer = payloads.Signer(signer_account, payloads.WitnessScope.CALLED_BY_ENTRY)
            await client.invoke_function(contract_hash=policy_contract, name="isBlocked",
                                         function_params=[account_to_check], signers=[signer])
        """
        if isinstance(contract_hash, str):
            contract_hash = types.UInt160.from_string(contract_hash)
        contract_hash = f"0x{contract_hash}"

        function_params = [] if function_params is None else function_params
        function_params = list(map(lambda fp: _ContractParameter(fp).to_json(), function_params))

        signers = [] if signers is None else signers
        signers = list(map(lambda s: s.to_json(), signers))  # type: ignore

        params = [contract_hash, name, function_params, signers]
        result = await self._do_post("invokefunction", params)
        return ExecutionResultResponse.from_json(result)

    async def invoke_script(self,
                            script: bytes,
                            signers: Optional[List[payloads.Signer]] = None
                            ) -> ExecutionResultResponse:
        """
        Executes a script in the virtual machine.

        Note:
            Executing VM scripts through this function does not alter the blockchain state.

        Args:
            script: an array of VM opcodes
            signers: additional signers (e.g. for checkwitness passing)

        Returns:
            The results of executing the script in the VM
        """
        signers = [] if signers is None else signers
        signers = list(map(lambda s: s.to_json(), signers))  # type: ignore

        params = [base64.b64encode(script).decode(), signers]
        result = await self._do_post("invokescript", params)
        return ExecutionResultResponse.from_json(result)

    async def send_transaction(self, tx: Union[payloads.Transaction, bytes]) -> types.UInt256:
        """
        Broadcast a transaction to the network.

        Note:
            uses the `sendrawtransaction` RPC method internally.

        Args:
            tx: either a Transaction object or a serialized Transaction. Must be signed

        Returns:
            a transaction hash if successful.
        """
        if isinstance(tx, payloads.Transaction):
            tx = tx.to_array()
        result = await self._do_post("sendrawtransaction", [base64.b64encode(tx).decode()])
        return types.UInt256.from_string(result['hash'][2:])

    async def send_block(self, block: Union[payloads.Block, bytes]) -> types.UInt256:
        """
        Broadcast a transaction to the network.

        Args:
            block: either a Block object or a serialized Block

        Returns:
            a block hash if successful.
        """
        if isinstance(block, payloads.Block):
            block = block.to_array()
        result = await self._do_post("submitblock", [base64.b64encode(block).decode()])
        return types.UInt256.from_string(result['hash'][2:])

    async def validate_address(self, address: str) -> bool:
        """
        Verify if the given address is valid for the network the node is running on.

        Args:
            address: a NEO address
        """
        result = await self._do_post("validateaddress", [address])
        return result['isvalid']

    async def print_contract_methods(self, contract_hash_or_name: Union[types.UInt160, str]) -> None:
        """
        Helper to fetch all public methods of a smart contract, print their signatures in Python syntax as
        to help determine the right native argument types.

        Note:
            Only native contracts can be queried by their name. Name is case-insensitive.
        """
        state = await self.get_contract_state(contract_hash_or_name)

        print(f"Contract: {state.manifest.name}")
        print((10 + len(state.manifest.name)) * "-")
        for method in state.manifest.abi.methods:
            params = map(lambda p: f", {p.name}: {self._contract_param_to_native(p.type)}", method.parameters)
            params = ''.join(params)  # type: ignore

            # return types are not included because ABI types like ARRAY cannot be properly translated e.g. the
            # following functions both have ARRAY as return type in the ABI but their actual response is very different
            # 1. NeoToken.GetNextBlockValidators returns a list of serialized ECPoints
            # 2. ManagementContract.getContract a serialized ContractState (not even a list)
            print(f"def {method.name}(self{params})")
        print(" ")
        print("ContractParam = Union[bool, int, str, bytes, UInt160, UInt256, ECPoint, list[ContractParam], "
              "Dict[ContractParam, ContractParam]")

    def _contract_param_to_native(self, p):
        if p == contracts.ContractParameterType.BOOLEAN:
            return "bool"
        elif p == contracts.ContractParameterType.INTEGER:
            return "int"
        elif p == contracts.ContractParameterType.STRING:
            return "str"
        elif p == contracts.ContractParameterType.BYTEARRAY:
            return "bytes"
        elif p == contracts.ContractParameterType.HASH160:
            return "UInt160"
        elif p == contracts.ContractParameterType.HASH256:
            return "UInt256"
        elif p == contracts.ContractParameterType.PUBLICKEY:
            return "ECPoint"
        elif p == contracts.ContractParameterType.ARRAY:
            return "list"
        elif p == contracts.ContractParameterType.MAP:
            return "dict"
        elif p == contracts.ContractParameterType.VOID:
            return "None"
        elif p == contracts.ContractParameterType.ANY:
            return "ContractParam"
        else:
            return f"Unknown({str(p)}"
