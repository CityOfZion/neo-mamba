"""
NEO RPC Node client and response classes.
"""
from __future__ import annotations
import aiohttp
import base64
import asyncio
import datetime
import time
from enum import Enum, IntEnum
from contextlib import suppress
from dataclasses import dataclass
from typing import Optional, TypedDict, Any, Protocol, Iterator, Union, cast, Type
from collections.abc import Sequence
from neo3.core import types, cryptography, interfaces, serialization
from neo3.contracts import manifest, nef, contract, abi
from neo3.network.payloads import transaction, block, verification
from neo3.wallet import utils as walletutils


@dataclass
class BlockValidator:
    """
    Activate consensus member.
    """

    public_key: cryptography.ECPoint
    votes: int

    def __repr__(self):
        return f"{self.__class__.__name__}(public_key={self.public_key}, votes={self.votes}"


@dataclass
class Candidate(BlockValidator):
    """
    Candidate consensus member.
    """

    active: bool

    def __repr__(self):
        return f"{self.__class__.__name__}(public_key={self.public_key}, votes={self.votes}, active={self.active}"


@dataclass
class NextBlockValidatorsResponse:
    """
    Response to `getnextblockvalidators` RPC call.
    """

    validators: list[BlockValidator]

    @classmethod
    def from_json(cls, json: dict):
        nvr = cls([])
        for validator in json:
            pk = cryptography.ECPoint.deserialize_from_bytes(
                bytes.fromhex(validator["publickey"])
            )
            votes = int(validator["votes"])
            nvr.validators.append(BlockValidator(pk, votes))
        return nvr


@dataclass
class VersionProtocol:
    """
    Partial response of `getversion` RPC call.
    """

    address_version: int
    network: int
    validators_count: int
    ms_per_block: int
    max_traceable_blocks: int
    max_transactions_per_block: int
    max_valid_until_block_increment: int
    memorypool_max_transactions: int
    initial_gas_distribution: int


@dataclass
class GetVersionResponse:
    """
    Response to `getversion` RPC call.
    """

    tcp_port: int
    ws_port: Optional[int]
    nonce: int
    user_agent: str
    protocol: VersionProtocol

    @classmethod
    def from_json(cls, json: dict):
        p = json["protocol"]
        vp = VersionProtocol(
            p["addressversion"],
            p["network"],
            p["validatorscount"],
            p["msperblock"],
            p["maxtraceableblocks"],
            p["maxtransactionsperblock"],
            p["maxvaliduntilblockincrement"],
            p["memorypoolmaxtransactions"],
            p["initialgasdistribution"],
        )
        wsport = json.get("wsport", None)
        return cls(
            json["tcpport"],
            wsport,
            json["nonce"],
            json["useragent"],
            vp,
        )


@dataclass
class Peer:
    """
    P2P peer information.
    """

    address: str
    port: int


@dataclass
class GetPeersResponse:
    """
    Response to `getpeers` RPC call.
    """

    connected: list[Peer]
    bad: list[Peer]
    unconnected: list[Peer]

    @classmethod
    def from_json(cls, json: dict):
        c = cls([], [], [])
        for p in json["connected"]:
            c.connected.append(Peer(p["address"], p["port"]))
        for p in json["bad"]:
            c.bad.append(Peer(p["address"], p["port"]))
        for p in json["unconnected"]:
            c.unconnected.append(Peer(p["address"], p["port"]))
        return c


@dataclass
class Nep17Balance:
    """
    NEP-17 balance entry.
    """

    asset_hash: types.UInt160
    amount: int
    last_updated_block: int

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(asset_hash={self.asset_hash}, amount={self.amount}, "
            f"last_updated_block={self.last_updated_block})"
        )


@dataclass
class Nep17BalancesResponse:
    """
    Response to `getnep17balances` RPC call.
    """

    balances: list[Nep17Balance]
    address: str

    @classmethod
    def from_json(cls, json: dict):
        c = cls([], json["address"])
        for b in json["balance"]:
            h = types.UInt160.from_string(b["assethash"][2:])
            a = int(b["amount"])
            c.balances.append(Nep17Balance(h, a, b["lastupdatedblock"]))
        return c


@dataclass
class Nep17Transfer:
    """
    NEP-17 transfer record.
    """

    time: datetime.datetime
    asset_hash: types.UInt160
    transfer_address: str
    amount: int
    block_index: int
    transfer_notify_index: int
    tx_hash: types.UInt256

    @classmethod
    def from_json(cls, json: dict):
        time = datetime.datetime.fromtimestamp(
            json["timestamp"] / 1000, datetime.timezone.utc
        )
        hash_ = types.UInt160.from_string(json["assethash"][2:])
        transfer_addr = json["transferaddress"]
        amount = int(json["amount"])
        tx_hash = types.UInt256.from_string(json["txhash"][2:])
        return cls(
            time,
            hash_,
            transfer_addr,
            amount,
            json["blockindex"],
            json["transfernotifyindex"],
            tx_hash,
        )

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(time={self.time}, asset_hash={self.asset_hash}, "
            f"transfer_address={self.transfer_address}, amount={self.amount}, block_index={self.block_index}, "
            f"transfer_notify_index={self.transfer_notify_index}, tx_hash={self.tx_hash})"
        )


@dataclass
class Nep17TransfersResponse:
    """
    Response to `getnep17transfer` RPC call.
    """

    sent: list[Nep17Transfer]
    received: list[Nep17Transfer]
    address: str

    @classmethod
    def from_json(cls, json: dict):
        c = cls([], [], json["address"])
        for t in json["sent"]:
            c.sent.append(Nep17Transfer.from_json(t))
        for t in json["received"]:
            c.received.append(Nep17Transfer.from_json(t))
        return c


@dataclass
class MempoolResponse:
    """
    Response to `getrawmempool` RPC call.

    A verified transaction in the memory pool is a transaction which has had:
    - basic structural validation (e.g. max tx size)
    - signature validation
    - state validation
        - block validity expiration check
        - available balance vs network and system fees
        - etc
    """

    verified: list[types.UInt256]
    unverified: list[types.UInt256]

    @classmethod
    def from_json(cls, json: dict):
        c = cls([], [])
        for tx in json["verified"]:
            c.verified.append(types.UInt256.from_string(tx[2:]))
        for tx in json["unverified"]:
            c.unverified.append(types.UInt256.from_string(tx[2:]))
        return c


class StackItemType(Enum):
    """
    Virtual machine item types that can be found in the `stack` property of responses when executing a script or
     transactions.
    """

    ANY = "Any"
    ARRAY = "Array"
    BOOL = "Boolean"
    BUFFER = "Buffer"
    BYTE_STRING = "ByteString"
    INTEGER = "Integer"
    INTEROP_INTERFACE = "InteropInterface"
    MAP = "Map"
    POINTER = "Pointer"
    STRUCT = "Struct"


@dataclass
class StackItem:
    """
    Virtual machine stack item.
    """

    type: StackItemType
    value: Any

    def __repr__(self):
        return f"{self.__class__.__name__}(type={self.type.name}, value={self.value})"

    def as_bool(self) -> bool:
        """
        Unwrap as `bool`.

        Raises:
            ValueError: if internal item type does not match required.
        """
        if self.type != StackItemType.BOOL:
            raise ValueError(
                f"item is not of type '{StackItemType.BOOL}' but of type '{self.type}'"
            )
        return self.value

    def as_bytes(self) -> bytes:
        """
        Unwrap as `bool`.

        Raises:
            ValueError: if internal item type does not match required.
        """
        if self.type != StackItemType.BYTE_STRING:
            raise ValueError(
                f"item is not of type '{StackItemType.BYTE_STRING}' but of type '{self.type}'"
            )
        return self.value

    def as_str(self) -> str:
        """
        Unwrap as `str`.

        Raises:
            ValueError: if internal item type does not match required.
        """
        if self.type != StackItemType.BYTE_STRING:
            raise ValueError(
                f"item is not of type '{StackItemType.BYTE_STRING}' but of type '{self.type}'"
            )
        v = cast(bytes, self.value)
        return v.decode()

    def as_int(self) -> int:
        """
        Unwrap as `int`.

        Raises:
            ValueError: if internal item type does not match required.

        """
        if self.type != StackItemType.INTEGER:
            raise ValueError(
                f"item is not of type '{StackItemType.INTEGER}' but of type '{self.type}'"
            )
        v = cast(int, self.value)
        return v

    def as_uint160(self) -> types.UInt160:
        """
        Unwrap as `UInt160`.

        Raises:
            ValueError: if internal item type does not match required.
        """
        if self.type not in (StackItemType.BYTE_STRING, StackItemType.BUFFER):
            raise ValueError(
                f"item is not of type '{StackItemType.BYTE_STRING}' or '{StackItemType.BUFFER}' but of type '{self.type}'"
            )
        # we need to ensure the data is hex-escaped
        data = self.value
        with suppress(UnicodeDecodeError, ValueError):
            data = bytes.fromhex(data.decode())
        return types.UInt160(data)

    def as_uint256(self) -> types.UInt256:
        """
        Unwrap as `UInt256`.

        Raises:
            ValueError: if internal item type does not match required.
        """
        if self.type not in (StackItemType.BYTE_STRING, StackItemType.BUFFER):
            raise ValueError(
                f"item is not of type '{StackItemType.BYTE_STRING}' or '{StackItemType.BUFFER}' but of type '{self.type}'"
            )
        # we need to ensure the data is hex-escaped
        data = self.value
        with suppress(UnicodeDecodeError, ValueError):
            data = bytes.fromhex(data.decode())
        return types.UInt256(data)

    def as_address(self) -> str:
        """
        Unwrap as NEO3 address.
        """
        return walletutils.script_hash_to_address(self.as_uint160())

    def as_public_key(self) -> cryptography.ECPoint:
        """
        Unwrap as `ECPoint`.

        Raises:
            ValueError: if internal item type does not match required.
        """
        if self.type not in (StackItemType.BYTE_STRING, StackItemType.BUFFER):
            raise ValueError(
                f"item is not of type '{StackItemType.BYTE_STRING}' or '{StackItemType.BUFFER}' but of type '{self.type}'"
            )
        # we need to ensure the data is hex-escaped
        data = self.value
        with suppress(UnicodeDecodeError, ValueError):
            data = bytes.fromhex(data.decode())
        return cryptography.ECPoint.deserialize_from_bytes(data, validate=True)

    def as_list(self) -> list[StackItem]:
        """
        Unwrap as `list`.

        Raises:
            ValueError: if internal item type does not match required.
        """
        if self.type != StackItemType.ARRAY:
            raise ValueError(
                f"item is not of type '{StackItemType.ARRAY}' but of type '{self.type}'"
            )
        return cast(list, self.value)

    def as_dict(self) -> dict:
        """
        Unwrap as `dict`.

        Raises:
            ValueError: if internal item type does not match required.
        """
        if self.type != StackItemType.MAP:
            raise ValueError(
                f"item is not of type '{StackItemType.MAP}' but of type '{self.type}'"
            )
        m = cast(MapStackItem, self)
        return dict(m.items())

    def as_none(self) -> None:
        """
        Unwrap as `None`.

        Raises:
            ValueError: if internal item type does not match required.

        """
        if self.type != StackItemType.ANY:
            raise ValueError(
                f"item is not of type '{StackItemType.ANY}' but of type '{self.type}'"
            )
        if self.value is not None:
            raise ValueError(f"value is not None but of type '{type(self.value)}")
        return self.value


class MapStackItem(StackItem):
    def items(self) -> Iterator:
        for pair in self.value:  # type: tuple[StackItem, StackItem]
            yield pair[0].value, pair[1].value

    def keys(self) -> Iterator:
        for pair in self.value:  # type: tuple[StackItem, StackItem]
            yield pair[0].value

    def values(self) -> Iterator:
        for pair in self.value:  # type: tuple[StackItem, StackItem]
            yield pair[1].value

    def __getitem__(self, item: str):
        for pair in self.value:  # type: tuple[StackItem, StackItem]
            if pair[0].value == item:
                return pair[1].value
        else:
            raise KeyError

    def __iter__(self):
        for pair in self.value:  # type: tuple[StackItem, StackItem]
            yield pair[0].value


_Item = TypedDict("_Item", {"type": str, "value": Any})


@dataclass
class ExecutionResult:
    """
    Execution result data.
    """

    state: str
    gas_consumed: int
    exception: Optional[str]
    stack: list[StackItem]

    @staticmethod
    def _parse_stack_item(item: _Item) -> StackItem:
        try:
            type_ = StackItemType(item["type"])
        except ValueError:
            raise ValueError(f"Unknown stack item type: {item['type']}")

        if type_ in (StackItemType.ARRAY, StackItemType.STRUCT):
            list_ = list(
                map(
                    lambda element: ExecutionResult._parse_stack_item(element),
                    item["value"],
                )
            )
            return StackItem(type_, list_)
        elif type_ in (StackItemType.BOOL, StackItemType.POINTER):
            return StackItem(type_, item["value"])
        if type_ in (StackItemType.BUFFER, StackItemType.BYTE_STRING):
            return StackItem(type_, base64.b64decode(item["value"]))
        elif type_ == StackItemType.INTEGER:
            return StackItem(type_, int(item["value"]))
        elif type_ == StackItemType.MAP:
            map_ = []
            for stack_item in item["value"]:

                key = ExecutionResult._parse_stack_item(stack_item["key"])
                key_type = StackItemType(stack_item["key"]["type"])
                if key_type == StackItemType.BYTE_STRING:
                    key.value = key.value.decode()
                else:
                    key.value = str(key.value)
                value = ExecutionResult._parse_stack_item(stack_item["value"])
                map_.append((key, value))
            return MapStackItem(type_, map_)
        elif type_ == StackItemType.ANY:
            return StackItem(type_, None)
        elif type_ == StackItemType.INTEROP_INTERFACE:
            if "iterator" not in item.keys():
                raise ValueError(
                    f"Interop stack item only supports iterators, could not find 'iterator' key"
                )
            values = list(
                map(
                    lambda element: ExecutionResult._parse_stack_item(element),
                    item["iterator"],  # type: ignore
                )
            )
            return StackItem(type_, values)
        assert False, "unreachable"

    @classmethod
    def from_json(cls, json: dict):
        gc = int(json["gasconsumed"])
        stack = list(
            map(lambda item: ExecutionResult._parse_stack_item(item), json["stack"])
        )
        return cls(json["state"], gc, json["exception"], stack)


@dataclass
class ExecutionResultResponse(ExecutionResult):
    """
    Response to `invokecontractverify`, `invokefunction` or `invokescript` RPC call.
    """

    script: bytes

    @classmethod
    def from_json(cls, json: dict):
        script = base64.b64decode(json["script"])
        gc = int(json["gasconsumed"])
        stack = list(
            map(lambda item: ExecutionResult._parse_stack_item(item), json["stack"])
        )
        return cls(json["state"], gc, json["exception"], stack, script)


@dataclass
class Notification:
    """
    Smart contract notification entry.
    """

    contract: types.UInt160
    event_name: str
    state: StackItem

    @classmethod
    def from_json(cls, json: dict):
        c = types.UInt160.from_string(json["contract"][2:])
        e = json["eventname"]
        s = ExecutionResult._parse_stack_item(json["state"])
        return cls(c, e, s)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(contract={str(self.contract)}, "
            f"event_name={self.event_name}, state={self.state})"
        )


@dataclass
class ApplicationExecution(ExecutionResult):
    """
    Specialised `ExecutionResult` with additional notification and trigger information.
    """

    trigger: str
    notifications: list[Notification]

    @classmethod
    def from_json(cls, json: dict):
        gc = int(json["gasconsumed"])
        stack = list(
            map(lambda item: ExecutionResult._parse_stack_item(item), json["stack"])
        )
        state = json["vmstate"]
        ex = json.get("exception", None)
        notifications = []
        for n in json["notifications"]:
            notifications.append(Notification.from_json(n))

        return cls(
            trigger=json["trigger"],
            notifications=notifications,
            state=state,
            gas_consumed=gc,
            exception=ex,
            stack=stack,
        )


@dataclass
class TransactionApplicationLogResponse:
    """
    Data log for processing of a transaction on chain.
    """

    tx_hash: types.UInt256
    execution: ApplicationExecution

    @classmethod
    def from_json(cls, json: dict):
        tx_id = types.UInt256.from_string(json["txid"])
        execution = ApplicationExecution.from_json(json["executions"][0])
        return cls(tx_id, execution)

    def __repr__(self):
        return f"{self.__class__.__name__}(tx_hash={str(self.tx_hash)}, execution={self.execution})"


@dataclass
class BlockApplicationLogResponse:
    """
    Data log for processing of a block on chain.

    Does not include the data log for its transactions.
    """

    block_hash: types.UInt256
    executions: list[ApplicationExecution]

    @classmethod
    def from_json(cls, json: dict):
        block_hash = types.UInt256.from_string(json["blockhash"])
        executions = []
        for execution in json["executions"]:
            executions.append(ApplicationExecution.from_json(execution))
        return cls(block_hash, executions)

    def __repr__(self):
        return f"{self.__class__.__name__}(block_hash={str(self.block_hash)}, executions={self.executions})"


ContractParameter = Union[
    bool,
    int,
    str,
    bytes,
    bytearray,
    types.BigInteger,
    types.UInt160,
    types.UInt256,
    cryptography.ECPoint,
    "ContractParameterArray",
    "ContractParameterDict",
    Type[serialization.ISerializable_T],
]


class ContractParameterArray(Protocol):
    """"""

    def insert(self, index: int, value: ContractParameter) -> None:
        ...

    def __getitem__(self, i: int) -> ContractParameter:
        ...

    def __setitem__(self, i: int, o: ContractParameter) -> None:
        ...

    def __delitem__(self, i: int) -> None:
        ...


class ContractParameterDict(Protocol):
    """"""

    def __setitem__(self, k: ContractParameter, v: ContractParameter) -> None:
        ...

    def __delitem__(self, v: ContractParameter) -> None:
        ...

    def __getitem__(self, k: ContractParameter) -> ContractParameter:
        ...

    def __iter__(self) -> Iterator[ContractParameter]:
        ...


class _ContractParameter(interfaces.IJson):
    def __init__(self, obj: ContractParameter):
        self.value: ContractParameter = ""  # just to help mypy
        if isinstance(obj, bool):
            self.type = abi.ContractParameterType.BOOLEAN
            self.value = obj
        elif isinstance(obj, IntEnum):
            self.type = abi.ContractParameterType.INTEGER
            self.value = str(obj.value)
        elif isinstance(obj, (int, types.BigInteger)):
            self.type = abi.ContractParameterType.INTEGER
            self.value = str(obj)
        elif isinstance(obj, str):
            self.type = abi.ContractParameterType.STRING
            self.value = obj
        elif isinstance(obj, (bytes, bytearray)):
            self.type = abi.ContractParameterType.BYTEARRAY
            self.value = base64.b64encode(obj).decode()
        elif isinstance(obj, types.UInt160):
            self.type = abi.ContractParameterType.HASH160
            self.value = f"0x{obj}"
        elif isinstance(obj, types.UInt256):
            self.type = abi.ContractParameterType.HASH256
            self.value = f"0x{obj}"
        elif isinstance(obj, cryptography.ECPoint):
            self.type = abi.ContractParameterType.PUBLICKEY
            self.value = obj.to_array().hex()
        elif isinstance(obj, (list, tuple)):
            self.type = abi.ContractParameterType.ARRAY
            self.value = list(map(lambda element: _ContractParameter(element), obj))
        elif isinstance(obj, dict):
            self.type = abi.ContractParameterType.MAP
            pairs: list[dict] = []
            for k, v in obj.items():
                pairs.append(
                    {"key": _ContractParameter(k), "value": _ContractParameter(v)}
                )
            # It seems like mypy can't follow that ContractParameter is also
            # a list[dict[ContractParameter, ContractParameter]]
            self.value = pairs  # type: ignore
        elif isinstance(obj, serialization.ISerializable):
            self.type = abi.ContractParameterType.BYTEARRAY
            self.value = base64.b64encode(obj.to_array()).decode()
        else:
            raise ValueError(f"Unsupported type {type(obj)}")

    @classmethod
    def from_json(cls, json: dict):
        """Not supported."""
        raise NotImplementedError

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        return {"type": self.type.PascalCase(), "value": self.value}


class RPCClient:
    """
    RPC Client base.
    """

    def __init__(self, url: str, timeout: float = 3.0):
        """
        Args:
            url: host + port.
            timeout: total time in seconds a request may take.
        """
        self.url = url
        self.timeout = timeout
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )

    async def _post(self, json: dict):
        """
        Create a POST request with JSON to `self.url` with `self.timeout`.

        Raises:
            asyncio.exceptions.TimeoutError
        """
        async with self.session.post(self.url, json=json) as request:
            return await request.json()

    async def close(self):
        """
        Close the client session.
        """
        await self.session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self.session.closed:
            await self.session.close()


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Optional[str] = None):
        self.code = code
        self.message = message
        self.data = "" if data is None else data

    def __str__(self):
        if len(self.data) > 0:
            return f"code={self.code}, message={self.message}, data={self.data}"
        else:
            return f"code={self.code}, message={self.message}"


class JsonRpcTimeoutError(JsonRpcError):
    def __init__(self, message: Optional[str] = None):
        self.message = "Operation timed out" if message is None else message

    def __str__(self):
        return self.message


class NeoRpcClient(RPCClient):
    """
    Specialised RPC client for NEO's Node RPC API.
    """

    def __init__(self, host: str, **kwargs):
        super(NeoRpcClient, self).__init__(host, **kwargs)

    async def _do_post(
        self,
        method: str,
        params: Optional[list] = None,
        id: int = 0,
        jsonrpc_version: str = "2.0",
    ):
        params = params if params else []
        json = {
            "jsonrpc": jsonrpc_version,
            "id": id,
            "method": method,
            "params": params,
        }
        response = await super(NeoRpcClient, self)._post(json)
        if "error" in response:
            raise JsonRpcError(**response["error"])
        return response["result"]

    async def calculate_network_fee(self, tx: bytes | transaction.Transaction) -> int:
        """
        Obtain the cost of verifying the transaction and including it in a block (a.k.a network fee).
        """
        if isinstance(tx, transaction.Transaction):
            tx = tx.to_array()
        params = [base64.b64encode(tx).decode()]
        result = await self._do_post("calculatenetworkfee", params)
        return int(result["networkfee"])

    async def get_application_log_transaction(
        self, tx_hash: types.UInt256 | str
    ) -> TransactionApplicationLogResponse:
        """
        Fetch the smart contract event logs for a given transaction.

        Commonly used to verify that a transaction sent via `send_transaction()` was executed succesfully on chain.

        Args:
            tx_hash: the hash of the transaction to query for.
        """
        if isinstance(tx_hash, types.UInt256):
            tx_hash = f"0x{str(tx_hash)}"
        result = await self._do_post("getapplicationlog", [tx_hash])
        return TransactionApplicationLogResponse.from_json(result)

    async def get_application_log_block(
        self, block_hash: types.UInt256 | str
    ) -> BlockApplicationLogResponse:
        """
        Fetch the system event logs for a given block.

        Args:
            block_hash: the hash of the block to query for.
        """
        if isinstance(block_hash, types.UInt256):
            block_hash = f"0x{str(block_hash)}"
        result = await self._do_post("getapplicationlog", [block_hash])
        return BlockApplicationLogResponse.from_json(result)

    async def get_best_block_hash(self) -> types.UInt256:
        """
        Fetch the hash of the highest block in the chain.
        """
        response = await self._do_post("getbestblockhash")
        return types.UInt256.from_string(response[2:])

    async def get_block(self, index_or_hash: int | types.UInt256) -> block.Block:
        """
        Fetch the block by its index or block hash.
        """
        params: list[int | str] = []
        if isinstance(index_or_hash, types.UInt256):
            params.append(f"0x{index_or_hash}")
        else:
            params.append(index_or_hash)
        response = await self._do_post("getblock", params)
        return block.Block.deserialize_from_bytes(base64.b64decode(response))

    async def get_block_count(self) -> int:
        """
        Fetch the current height of the blockchain.
        """
        return await self._do_post("getblockcount")

    async def get_block_hash(self, index: int) -> types.UInt256:
        """
        Fetch the block hash by the block's index.
        """
        response = await self._do_post("getblockhash", [index])
        return types.UInt256.from_string(response[2:])

    async def get_block_header(
        self, index_or_hash: int | types.UInt256
    ) -> block.Header:
        """
        Fetch the block header by its index or block hash.
        """
        if isinstance(index_or_hash, types.UInt256):
            params = [f"0x{index_or_hash}"]
        else:
            params = [str(index_or_hash)]
        response = await self._do_post("getblockheader", params)
        return block.Header.deserialize_from_bytes(base64.b64decode(response))

    async def get_candidates(self) -> Sequence[Candidate]:
        """
        Fetch list of consensus candidates.
        """
        response = await self._do_post("getcandidates")
        candidates = []
        for candidate in response:
            pk = cryptography.ECPoint.deserialize_from_bytes(
                bytes.fromhex(candidate["publickey"])
            )
            votes = int(candidate["votes"])
            candidates.append(Candidate(pk, votes, candidate["active"]))
        return candidates

    async def get_committee(self) -> tuple[cryptography.ECPoint, ...]:
        """
        Fetch the public keys of the current NEO committee.
        """
        response = await self._do_post("getcommittee")
        return tuple(
            map(
                lambda pk: cryptography.ECPoint.deserialize_from_bytes(
                    bytes.fromhex(pk)
                ),
                response,
            )
        )

    async def get_connection_count(self) -> int:
        """
        Fetch the number of peers connected to the node.
        """
        return await self._do_post("getconnectioncount")

    async def get_contract_state(
        self, contract_hash_or_name: types.UInt160 | str
    ) -> contract.ContractState:
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

        h = types.UInt160.from_string(result["hash"][2:])
        nef_ = nef.NEF.from_json(result["nef"])
        manifest_ = manifest.ContractManifest.from_json(result["manifest"])
        return contract.ContractState(
            result["id"], nef_, manifest_, result["updatecounter"], h
        )

    async def get_nep17_balances(self, address: str) -> Nep17BalancesResponse:
        """
        Fetch the balance of all NEP17 assets for the specified address.
        """
        result = await self._do_post("getnep17balances", [address])
        return Nep17BalancesResponse.from_json(result)

    async def get_nep17_transfers(
        self,
        address: str,
        start_time: Optional[datetime.datetime] = None,
        end_time: Optional[datetime.datetime] = None,
    ) -> Nep17TransfersResponse:
        """
        Fetch NEP17 transfers for a given address. Defaults to the last 7 days on the server side.

        Args:
            address: account to get transfer for.
            start_time: if given the start of the requested range. Must be in UTC and time aware not naïve.
            end_time: if given the end of the requested range.

        Example:
            # Fetch transfers of the last 14 days
            start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=14)
            await get_nep17_transfers(<your address>, start)
        """
        params = [address]
        if start_time is not None:
            if start_time.tzinfo is None:
                raise ValueError(
                    "start_time is a naïve datetime object which can cause incorrect results. Make it "
                    "time aware by adding tzinfo. For more information see: "
                    "https://docs.python.org/3/library/datetime.html#datetime.datetime.tzinfo"
                )
            # C# server side expects timestamp in milliseconds instead of seconds
            t = int(start_time.timestamp() * 1000)
            params.append(str(t))

        if end_time is not None:
            if end_time.tzinfo is None:
                raise ValueError(
                    "end_time is a naïve object which can cause incorrect results. Make it time aware by "
                    "adding tzinfo. For more information see: "
                    "https://docs.python.org/3/library/datetime.html#datetime.datetime.tzinfo"
                )
            t = int(end_time.timestamp() * 1000)
            params.append(str(t))

        result = await self._do_post("getnep17transfers", params)
        return Nep17TransfersResponse.from_json(result)

    async def get_raw_mempool(self) -> MempoolResponse:
        """
        Fetch the transaction hashes currently in the memory pool waiting to be added to the next produced block.
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
        Fetch peer information.
        """
        result = await self._do_post("getpeers")
        return GetPeersResponse.from_json(result)

    async def get_storage(self, script_hash: types.UInt160, key: bytes) -> bytes:
        """
        Fetch a value from a smart contracts storage by its key.

        Args:
            script_hash: contract script hash.
            key: the storage key to fetch the data for.

        Example:
            # fetch the fee per byte from the Policy native contract
            key_fee_per_byte = b'\x0a'
            await client.get_storage(contracts.PolicyContract().hash, key_fee_per_byte)
        """
        hash_ = f"0x{script_hash}"
        key_encoded = base64.b64encode(key).decode()
        result = await self._do_post("getstorage", params=[hash_, key_encoded])
        return base64.b64decode(result)

    async def get_transaction(
        self, tx_hash: types.UInt256 | str
    ) -> transaction.Transaction:
        """
        Fetch a transaction by its hash.
        """
        if isinstance(tx_hash, str):
            tx_hash = types.UInt256.from_string(tx_hash)
        result = await self._do_post("getrawtransaction", [f"0x{tx_hash}"])
        return transaction.Transaction.deserialize_from_bytes(base64.b64decode(result))

    async def get_transaction_height(self, tx_hash: types.UInt256 | str) -> int:
        """
        Fetch the height of the block the transaction is included in.
        """
        if isinstance(tx_hash, str):
            tx_hash = types.UInt256.from_string(tx_hash)
        return await self._do_post("gettransactionheight", [f"0x{tx_hash}"])

    async def get_unclaimed_gas(self, address: str) -> int:
        """
        Fetch the amount of unclaimed gas for the given address.

        Args:
            address: a NEO address.
        """
        result = await self._do_post("getunclaimedgas", [address])
        return int(result["unclaimed"])

    async def get_version(self) -> GetVersionResponse:
        """
        Fetch the node client version, network protocol properties and network ports.
        """
        return GetVersionResponse.from_json(await self._do_post("getversion"))

    async def invoke_contract_verify(
        self,
        contract_hash: types.UInt160 | str,
        function_params: Optional[Sequence[ContractParameter]] = None,
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> ExecutionResultResponse:
        """
        Invoke the `verify` method on the contract.

        Note:
            Calling smart contracts through this function does not alter the blockchain state.
            The smart contract will be called using the Verification trigger (unlike the `invoke_function` method
            which uses the Application trigger).

        Args:
            contract_hash: the hash of the smart contract to call.
            function_params: the arguments required by the smart contract function.
            signers: additional signers (e.g. for checkwitness passing).
        """
        if isinstance(contract_hash, str):
            contract_hash = types.UInt160.from_string(contract_hash)
        contract_hash = f"0x{contract_hash}"

        function_params = [] if function_params is None else function_params
        function_params = list(
            map(lambda fp: _ContractParameter(fp).to_json(), function_params)
        )

        signers = [] if signers is None else signers
        signers = list(map(lambda s: s.to_json(), signers))  # type: ignore

        params = [contract_hash, function_params, signers]
        result = await self._do_post("invokecontractverify", params)
        return ExecutionResultResponse.from_json(result)

    async def invoke_function(
        self,
        contract_hash: types.UInt160 | str,
        name: str,
        function_params: Optional[Sequence[ContractParameter]] = None,
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> ExecutionResultResponse:
        """
        Invoke a smart contract function.

        Note:
            Calling smart contracts through this function does not alter the blockchain state.
            To alter the blockchain state use the `send_transaction` method instead.

        Args:
            contract_hash: the hash of the smart contract to call.
            name: the name of the function to call on the smart contract.
            function_params: the arguments required by the smart contract function.
            signers: additional signers (e.g. for checkwitness passing).

        Example:
            # check if an account is blocked using the Policy native contract
            policy_contract = "cc5e4edd9f5f8dba8bb65734541df7a1c081c67b"
            account_to_check = types.UInt160.from_string("86df72a6b4ab5335d506294f9ce993722253b6e2")
            signer_account = types.UInt160.from_string("f621168b1fce3a89c33a5f6bcf7e774b4657031c")
            signer = verification.Signer(signer_account, payloads.WitnessScope.CALLED_BY_ENTRY)
            await client.invoke_function(contract_hash=policy_contract, name="isBlocked",
                                         function_params=[account_to_check], signers=[signer])
        """
        if isinstance(contract_hash, str):
            contract_hash = types.UInt160.from_string(contract_hash)
        contract_hash = f"0x{contract_hash}"

        function_params = [] if function_params is None else function_params
        function_params = list(
            map(lambda fp: _ContractParameter(fp).to_json(), function_params)
        )

        signers = [] if signers is None else signers
        signers = list(map(lambda s: s.to_json(), signers))  # type: ignore

        params = [contract_hash, name, function_params, signers]
        result = await self._do_post("invokefunction", params)
        return ExecutionResultResponse.from_json(result)

    async def invoke_script(
        self, script: bytes, signers: Optional[Sequence[verification.Signer]] = None
    ) -> ExecutionResultResponse:
        """
        Execute a script in the virtual machine.

        Note:
            Executing VM scripts through this function does not alter the blockchain state.

        Args:
            script: an array of VM opcodes.
            signers: additional signers (e.g. for checkwitness passing).

        Returns:
            The results of executing the script in the VM.
        """
        signers = [] if signers is None else signers
        signers = list(map(lambda s: s.to_json(), signers))  # type: ignore

        params = [base64.b64encode(script).decode(), signers]
        result = await self._do_post("invokescript", params)
        return ExecutionResultResponse.from_json(result)

    async def send_transaction(
        self, tx: transaction.Transaction | bytes
    ) -> types.UInt256:
        """
        Broadcast a transaction to the network.

        Note:
            uses the `sendrawtransaction` RPC method internally.

        Args:
            tx: either a Transaction object or a serialized Transaction. Must be signed.

        Returns:
            a transaction hash if successful.
        """
        if isinstance(tx, transaction.Transaction):
            tx = tx.to_array()
        result = await self._do_post(
            "sendrawtransaction", [base64.b64encode(tx).decode()]
        )
        return types.UInt256.from_string(result["hash"][2:])

    async def send_block(self, block_: block.Block | bytes) -> types.UInt256:
        """
        Broadcast a transaction to the network.

        Args:
            block_: either a Block object or a serialized Block.

        Returns:
            a block hash if successful.
        """
        if isinstance(block_, block.Block):
            block_ = block_.to_array()
        result = await self._do_post("submitblock", [base64.b64encode(block_).decode()])
        return types.UInt256.from_string(result["hash"][2:])

    async def validate_address(self, address: str) -> bool:
        """
        Verify if the given address is valid for the network the node is running on.

        Args:
            address: a NEO address.
        """
        result = await self._do_post("validateaddress", [address])
        return result["isvalid"]

    async def print_contract_methods(
        self, contract_hash_or_name: types.UInt160 | str
    ) -> None:
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
            params = map(
                lambda p: f", {p.name}: {self._contract_param_to_native(p.type)}",
                method.parameters,
            )
            params = "".join(params)  # type: ignore

            # return types are not included because ABI types like ARRAY cannot be properly translated e.g. the
            # following functions both have ARRAY as return type in the ABI but their actual response is very different
            # 1. NeoToken.GetNextBlockValidators returns a list of serialized ECPoints
            # 2. ManagementContract.getContract a serialized ContractState (not even a list)
            print(f"def {method.name}(self{params})")
        print(" ")
        print(
            "ContractParam = Union[bool, int, str, bytes, UInt160, UInt256, ECPoint, list[ContractParam], "
            "dict[ContractParam, ContractParam]"
        )

    @staticmethod
    def _contract_param_to_native(p: abi.ContractParameterType) -> str:
        if p == abi.ContractParameterType.BOOLEAN:
            return "bool"
        elif p == abi.ContractParameterType.INTEGER:
            return "int"
        elif p == abi.ContractParameterType.STRING:
            return "str"
        elif p == abi.ContractParameterType.BYTEARRAY:
            return "bytes"
        elif p == abi.ContractParameterType.HASH160:
            return "UInt160"
        elif p == abi.ContractParameterType.HASH256:
            return "UInt256"
        elif p == abi.ContractParameterType.PUBLICKEY:
            return "ECPoint"
        elif p == abi.ContractParameterType.ARRAY:
            return "list"
        elif p == abi.ContractParameterType.MAP:
            return "dict"
        elif p == abi.ContractParameterType.VOID:
            return "None"
        elif p == abi.ContractParameterType.ANY:
            return "ContractParam"
        else:
            return f"Unknown({str(p)}"

    async def get_transaction_receipt(self, tx_hash: types.UInt256) -> Receipt:
        """
        Fetch a transaction receipt.

        Args:
            tx_hash: unique identifier of the transaction to fetch receipt for.
        """
        log = await self.get_application_log_transaction(tx_hash)
        included_in = await self.get_transaction_height(tx_hash)
        confirmations = await self.get_block_count() - included_in

        return Receipt(tx_hash, included_in, confirmations, log.execution)

    async def wait_for_transaction_receipt(
        self, tx_hash: types.UInt256, timeout=20, retry_delay=5
    ) -> Receipt:
        """
        Try to fetch a transaction.

        Args:
            tx_hash: unique identifier of the transaction to fetch the receipt for.
            timeout: maximum time to wait to find the transaction on chain.
            retry_delay: interval between querying the chain for the transaction.

        Raises:
            JsonRpcTimeoutError: if timeout threshold is exceeded
            JsonRpcError: for other errors that might occur.
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                return await self.get_transaction_receipt(tx_hash)
            except JsonRpcError as e:
                if "Unknown transaction" in e.message:
                    await asyncio.sleep(retry_delay)
                else:
                    raise e
        else:
            raise JsonRpcTimeoutError(
                f"Could not find receipt for {tx_hash} within specified timeout of {timeout} seconds"
            )


@dataclass
class Receipt:
    """
    Transaction receipt containing data regarding chain state and events happening as a result of executing the
     transaction.
    """

    tx_hash: types.UInt256
    included_in_block: int
    confirmations: int
    execution: ApplicationExecution
