"""
P2P node. Connects over TCP. Handles network messages.
"""
from __future__ import annotations
import asyncio
import traceback
import struct
import string
from datetime import datetime
from neo3.network import message, capabilities, relaycache
from neo3.network.ipfilter import ipfilter
from neo3.network.convenience import nodeweight
from neo3.network.payloads import address, version, inventory, ping, block
from neo3 import network_logger as logger, settings
from neo3.core import types, msgrouter
from contextlib import suppress
from socket import AF_INET as IP4_FAMILY
from typing import Optional, Callable, cast
from asyncio.streams import StreamWriter, StreamReader
from neo3.network.message import Message
from collections.abc import Sequence


class NeoNode:
    """
    P2P network actor.
    """

    #: list[address.NetworkAddress]: a list of known network addresses (class attribute).
    addresses = []  # type: list[address.NetworkAddress]

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        #: Unique identifier.
        self.nodeid: int = id(self)
        #: Address of the remote endpoint.
        self.address = address.NetworkAddress(
            "0.0.0.0:0", state=address.AddressState.DEAD
        )
        #: Human readable id.
        self.nodeid_human: str = encode_base62(self.nodeid)
        self.version: Optional[version.VersionPayload] = None
        self.tasks: list[asyncio.Task] = []
        self.nodeweight = nodeweight.NodeWeight(self.nodeid)
        #: Best block height of node.
        self.best_height: int = 0
        self.best_height_last_update = datetime.utcnow().timestamp()

        self._read_task: Optional[asyncio.Task] = None

        #: bool: Whether the node is in the process of disconnecting and shutting down its tasks.
        self.disconnecting: bool = False

        #: dict[message.MessageType, Callable[[message.Message], None]]: A table matching message types to handler
        #: functions.
        self.dispatch_table: dict[
            message.MessageType, Callable[[message.Message], None]
        ] = {
            message.MessageType.ADDR: self.handler_addr,
            message.MessageType.BLOCK: self.handler_block,
            message.MessageType.CONSENSUS: self.handler_consensus,
            message.MessageType.INV: self.handler_inv,
            message.MessageType.FILTERADD: self.handler_filteradd,
            message.MessageType.FILTERCLEAR: self.handler_filterclear,
            message.MessageType.FILTERLOAD: self.handler_filterload,
            message.MessageType.GETADDR: self.handler_getaddr,
            message.MessageType.GETBLOCKS: self.handler_getblocks,
            message.MessageType.GETBLOCKBYINDEX: self.handler_getblockdata,
            message.MessageType.GETDATA: self.handler_getdata,
            message.MessageType.GETHEADERS: self.handler_getheaders,
            message.MessageType.HEADERS: self.handler_headers,
            message.MessageType.MEMPOOL: self.handler_mempool,
            message.MessageType.MERKLEBLOCK: self.handler_merkleblock,
            message.MessageType.PING: self.handler_ping,
            message.MessageType.PONG: self.handler_pong,
            message.MessageType.TRANSACTION: self.handler_transaction,
            message.MessageType.EXTENSIBLE: self.handler_extensible,
        }

        self.reader = reader
        self.writer = writer

    def __eq__(self, other):
        if type(other) is type(self):
            return self.address == other.address and self.nodeid == other.nodeid
        else:
            return False

    def __repr__(self):
        return f"<{self.__class__.__name__} at {hex(id(self))}> {self.nodeid_human}"

    def connection_made(self) -> None:
        """
        Event called by the NeoNode.connect_to.
        """
        addr_tuple = self.writer.get_extra_info("peername")
        addr = f"{addr_tuple[0]}:{addr_tuple[1]}"

        network_addr = self._find_address_by_host_port(addr)
        if network_addr:
            # this scenario occurs when the NodeManager queues seed nodes
            self.address = network_addr
        else:
            self.address.address = addr

        if not ipfilter.is_allowed(addr_tuple[0]):
            logger.debug(f"Blocked by ipfilter: {self.address.address}")
            self._create_task_with_cleanup(
                self.disconnect(address.DisconnectReason.IPFILTER_NOT_ALLOWED)
            )
            return

    async def disconnect(self, reason: address.DisconnectReason) -> None:
        """
        Close the connection to remote endpoint.

        Args:
            reason: reason for disconnecting.
        """
        if self.disconnecting:
            return

        self.disconnecting = True

        logger.debug(f"Disconnect called with reason={reason.name}")
        self.address.disconnect_reason = reason
        if reason in [
            address.DisconnectReason.MAX_CONNECTIONS_REACHED,
            address.DisconnectReason.POOR_PERFORMANCE,
            address.DisconnectReason.HANDSHAKE_VERACK_ERROR,
            address.DisconnectReason.HANDSHAKE_VERSION_ERROR,
            address.DisconnectReason.UNKNOWN,
        ]:
            self.address.set_state_poor()
        elif reason == address.DisconnectReason.IPFILTER_NOT_ALLOWED:
            self.address.set_state_dead()

        for t in self.tasks:
            t.cancel()
            with suppress(asyncio.CancelledError):
                logger.debug(f"waiting for task to cancel {t}.")
                await t
                logger.debug("done")
        msgrouter.on_node_disconnected(self, reason)
        self.writer.close()
        await self.writer.wait_closed()

    def handler_addr(self, msg: message.Message) -> None:
        """
        Handler for a message with the `ADDR` type.

        Args:
            msg:
        """
        payload = cast(address.AddrPayload, msg.payload)
        self.addresses = list(set(self.addresses + payload.addresses))
        msgrouter.on_addr(payload.addresses)

    def handler_block(self, msg: message.Message) -> None:
        """
        Handler for a message with the `BLOCK` type.

        Args:
            msg:
        """
        msgrouter.on_block(self.nodeid, msg.payload)

    def handler_consensus(self, msg: message.Message) -> None:
        """
        Handler for a message with the `CONSENSUS` type.

        Args:
            msg:
        """
        pass

    def handler_inv(self, msg: message.Message) -> None:
        """
        Handler for a message with the `INV` type.

        Args:
            msg:
        """
        payload = cast(inventory.InventoryPayload, msg.payload)
        if payload.type == inventory.InventoryType.BLOCK:
            # neo-cli broadcasts INV messages on a regular interval. We can use those as trigger to request
            # their latest block height
            if len(payload.hashes) > 0:
                height = 0
                m = message.Message(
                    msg_type=message.MessageType.PING,
                    payload=ping.PingPayload(height=height),
                )
                self._create_task_with_cleanup(self.send_message(m))
        else:
            logger.debug(
                f"Message with type INV received. No processing for payload type "  # type:ignore
                f"{payload.type.name} implemented"
            )

    def handler_filteradd(self, msg: message.Message) -> None:
        """
        Handler for a message with the `FILTERADD` type.

        Args:
            msg:
        """
        pass

    def handler_filterclear(self, msg: message.Message) -> None:
        """
        Handler for a message with the `FILTERCLEAR` type.

        Args:
            msg:
        """
        pass

    def handler_filterload(self, msg: message.Message) -> None:
        """
        Handler for a message with the `FILTERLOAD` type.

        Args:
            msg:
        """
        pass

    def handler_getaddr(self, msg: message.Message) -> None:
        """
        Handler for a message with the `GETADDR` type.

        Args:
            msg:
        """
        addr_list = []
        for addr in self.addresses:  # type: address.NetworkAddress
            if addr.is_state_new or addr.is_state_connected:
                addr_list.append(addr)
        self._create_task_with_cleanup(self.send_address_list(addr_list))

    def handler_getblocks(self, msg: message.Message) -> None:
        """
        Handler for a message with the `GETBLOCKS` type.

        Args:
            msg:
        """
        pass

    def handler_getblockdata(self, msg: message.Message) -> None:
        """
        Handler for a message with the `GETBLOCKBYINDEX` type.

        Args:
            msg:
        """
        pass

    def handler_getdata(self, msg: message.Message) -> None:
        """
        Handler for a message with the `GETDATA` type.

        Args:
            msg:
        """
        payload = cast(inventory.InventoryPayload, msg.payload)
        for h in payload.hashes:
            item = relaycache.RelayCache().try_get(h)
            if item is None:
                # for the time being we only support data retrieval for our own relays
                continue
            if payload.type == inventory.InventoryType.TX:
                m = message.Message(
                    msg_type=message.MessageType.TRANSACTION, payload=item
                )
                self._create_task_with_cleanup(self.send_message(m))

    def handler_getheaders(self, msg: message.Message) -> None:
        """
        Handler for a message with the `GETHEADERS` type.

        Args:
            msg:
        """
        pass

    def handler_mempool(self, msg: message.Message) -> None:
        """
        Handler for a message with the `MEMPOOL` type.

        Args:
            msg:
        """
        pass

    def handler_merkleblock(self, msg: message.Message) -> None:
        """
        Handler for a message with the `MERKLEBLOCK` type.

        Args:
            msg:
        """
        pass

    def handler_headers(self, msg: message.Message) -> None:
        """
        Handler for a message with the `HEADERS` type.

        Args:
            msg:
        """
        payload = cast(block.HeadersPayload, msg.payload)
        if len(payload.headers) > 0:
            msgrouter.on_headers(self.nodeid, payload.headers)

    def handler_ping(self, msg: message.Message) -> None:
        """
        Handler for a message with the `PING` type.

        Args:
            msg:
        """
        height = 0
        m = message.Message(
            msg_type=message.MessageType.PONG, payload=ping.PingPayload(height=height)
        )
        self._create_task_with_cleanup(self.send_message(m))

    def handler_pong(self, msg: message.Message) -> None:
        """
        Handler for a message with the `PONG` type.

        Args:
            msg:
        """
        payload = cast(ping.PingPayload, msg.payload)
        if self.best_height != payload.current_height:
            logger.debug(
                f"Updating node {self.nodeid_human} height "
                f"from {self.best_height} to {payload.current_height}"
            )
            self.best_height = payload.current_height
            self.best_height_last_update = datetime.utcnow().timestamp()

    def handler_transaction(self, msg: message.Message) -> None:
        """
        Handler for a message with the `TRANSACTION` type.

        Args:
            msg:
        """
        pass

    def handler_extensible(self, msg: message.Message) -> None:
        """
        Handler for a message with the `EXTENSIBLE` type.

        Args:
            msg:
        """
        pass

    def start_message_handler(self) -> None:
        """
        A convenience function to start a message reading loop and forward the messages to their respective handlers as
        configured in :attr:`~neo3.network.node.NeoNode.dispatch_table`.
        """
        # when we break out of the read/write loops, we should make sure we disconnect
        self._read_task = asyncio.create_task(self._process_incoming_data())
        self._read_task.add_done_callback(
            lambda _: asyncio.create_task(
                self.disconnect(address.DisconnectReason.UNKNOWN)
            )
        )

    async def send_message(self, msg: message.Message) -> None:
        """
        Broadcast a message to the network.
        """
        self.writer.write(msg.to_array())
        await self.writer.drain()

    async def read_message(self, timeout: Optional[int] = 30) -> Optional[Message]:
        """
        Read a message from the network.

        Args:
            timeout: maximum time to wait for a message to arrive over the network.
        """
        if timeout == 0:
            # avoid memleak. See: https://bugs.python.org/issue37042
            timeout = None

        async def _read():
            try:
                # readexactly can throw ConnectionResetError
                message_header = await self.reader.readexactly(3)
                payload_length = message_header[2]

                if payload_length == 0xFD:
                    len_bytes = await self.reader.readexactly(2)
                    (payload_length,) = struct.unpack("<H", len_bytes)
                elif payload_length == 0xFE:
                    len_bytes = await self.reader.readexactly(4)
                    (payload_length,) = struct.unpack("<I", len_bytes)
                elif payload_length == 0xFE:
                    len_bytes = await self.reader.readexactly(8)
                    (payload_length,) = struct.unpack("<Q", len_bytes)
                else:
                    len_bytes = b""

                if payload_length > Message.PAYLOAD_MAX_SIZE:
                    raise ValueError("Invalid format")

                payload_data = await self.reader.readexactly(payload_length)
                raw = message_header + len_bytes + payload_data

                try:
                    return Message.deserialize_from_bytes(raw)
                except Exception:
                    logger.debug(
                        f"Failed to deserialize message: {traceback.format_exc()}"
                    )
                    return None

            except (ConnectionResetError, ValueError) as e:
                # ensures we break out of the main run() loop of Node, which triggers a disconnect callback to clean up
                self.disconnecting = True
                logger.debug(
                    f"Failed to read message data for reason: {traceback.format_exc()}"
                )
                return None
            except (asyncio.CancelledError, asyncio.IncompleteReadError):
                return None
            except Exception:
                # ensures we break out of the main run() loop of Node, which triggers a disconnect callback to clean up
                logger.debug(f"error read message 1 {traceback.format_exc()}")
                return None

        try:
            return await asyncio.wait_for(_read(), timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return None
        except Exception:
            logger.debug("error read message 2")
            traceback.print_exc()
            return None

    # raw network commands
    async def request_address_list(self) -> None:
        """
        Send a request for receiving known network addresses.
        """
        m = message.Message(msg_type=message.MessageType.GETADDR)
        await self.send_message(m)

    async def send_address_list(
        self, network_addresses: Sequence[address.NetworkAddress]
    ) -> None:
        """
        Send network addresses.

        Args:
            network_addresses: list of addresses of other network actors.
        """
        m = message.Message(
            msg_type=message.MessageType.ADDR,
            payload=address.AddrPayload(addresses=network_addresses),
        )
        await self.send_message(m)

    async def request_headers(
        self, index_start: int, count: int = block.HeadersPayload.MAX_HEADERS_COUNT
    ) -> None:
        """
        Send a request for headers from `index_start` to `index_start`+`count`.

        Not specifying a `count` results in requesting at most 2000 headers.

        Args:
            index_start: block height to start from.
            count: number of headers to request.
        """
        m = message.Message(
            msg_type=message.MessageType.GETHEADERS,
            payload=block.GetBlockByIndexPayload(index_start, count),
        )
        await self.send_message(m)

    async def send_headers(self, headers: Sequence[block.Header]) -> None:
        """
        Send a list of Header objects.
        """
        if len(headers) > 2000:
            headers = headers[:2000]

        m = message.Message(
            msg_type=message.MessageType.HEADERS, payload=block.HeadersPayload(headers)
        )
        await self.send_message(m)

    async def request_blocks(
        self, hash_start: types.UInt256, count: Optional[int] = None
    ) -> None:
        """
        Send a request for retrieving block hashes from `hash_start` to `hash_start`+`count`.

        Not specifying a `count` results in requesting at most 500 blocks.

        Note:
            The remote node is expected to reply with a Message with the :const:`~neo3.network.message.MessageType.INV`
            type containing the hashes of the requested blocks. Use :meth:`~neo3.network.node.NeoNode.request_data` in
            combination with these hashes to return the actual :class:`~neo3.network.payloads.block.Block` objects.

        See also:
            `NeoNode.request_block_data()` to immediately retrieve
            `neo3.network.payloads.block.Block` objects.

        Args:
            hash_start: block hash to start from.
            count: number of blocks to return.
        """
        m = message.Message(
            msg_type=message.MessageType.GETBLOCKS,
            payload=block.GetBlocksPayload(hash_start, count),
        )
        await self.send_message(m)

    async def request_block_data(self, index_start, count) -> None:
        """
        Send a request for `count` blocks starting from `index_start`.

        Count cannot exceed :attr:`~neo3.network.payloads.block.GetBlockByIndexPayload.MAX_BLOCKS_COUNT`.

        See also:
            :meth:`~neo3.network.node.NeoNode.request_blocks()` to only request block hashes.

        Args:
            index_start: block index to start from.
            count: number of blocks to return.
        """
        m = message.Message(
            msg_type=message.MessageType.GETBLOCKBYINDEX,
            payload=block.GetBlockByIndexPayload(index_start, count),
        )
        await self.send_message(m)

    async def request_data(
        self, type: inventory.InventoryType, hashes: Sequence[types.UInt256]
    ) -> None:
        """
        Send a request for receiving the specified inventory data.

        Args:
            type: the inventory type to request.
            hashes: the hashes of `type` to request.
        """
        if len(hashes) < 1:
            return

        m = message.Message(
            msg_type=message.MessageType.GETDATA,
            payload=inventory.InventoryPayload(type, hashes),
        )
        await self.send_message(m)

    async def send_inventory(
        self, inv_type: inventory.InventoryType, inv_hash: types.UInt256
    ) -> None:
        """
        Send an inventory to the network.

        Args:
            inv_type:
            inv_hash:
        """
        inv = inventory.InventoryPayload(type=inv_type, hashes=[inv_hash])
        m = message.Message(msg_type=message.MessageType.INV, payload=inv)
        await self.send_message(m)

    async def send_ping(self) -> None:
        """
        Send a Ping message and expecting a Pong response.
        """
        height = 0

        p = ping.PingPayload(height)
        m = message.Message(msg_type=message.MessageType.PING, payload=p)
        await self.send_message(m)

    async def relay(self, inv: inventory.IInventory) -> bool:
        """
        Relay the inventory to the network.

        Args:
            inv: should be of type Block, Transaction or Consensus.
        """
        relaycache.RelayCache().add(inv)
        await self.send_inventory(inv.inventory_type, inv.hash())
        return True

    @staticmethod
    async def connect_to(
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout=3,
        socket=None,
        *,
        _test_data: Optional[dict] = None,
    ) -> tuple[Optional[NeoNode], Optional[tuple[str, str]]]:
        """
        Connect to another node.

        Args:
            host: node ip.
            port: node port.
            timeout: max time to wait before aborting.
            socket: use an existing socket.
            _test_data:

        Returns:
            tuple[NeoNode, None]: if connection was established succesfully.
            tuple[None, tuple[host:port, failure_reason]]: if connection is not established successfully.
        """
        if host is not None or port is not None:
            if socket is not None:
                raise ValueError(
                    "host/port and socket can not be specified at the same time"
                )
        if socket is None and (host is None or port is None):
            raise ValueError("host and port was not specified and no sock specified")

        try:
            if socket:
                logger.debug(f"Trying to connect to socket: {socket}.")
                open_conn_coro = asyncio.open_connection(sock=socket)
            else:
                logger.debug(f"Trying to connect to: {host}:{port}.")
                open_conn_coro = asyncio.open_connection(host, port, family=IP4_FAMILY)
            reader, writer = await asyncio.wait_for(open_conn_coro, timeout)

            if _test_data and (peername := _test_data.get("peername")) is not None:
                writer._transport._extra["peername"] = peername  # type: ignore
            node = NeoNode(reader, writer)
            node.connection_made()

            success, fail_reason = await node._do_handshake()
            if success:
                return node, None
            else:
                raise Exception(fail_reason)
        except asyncio.TimeoutError:
            reason = "Timed out"
        except OSError as e:
            reason = f"Failed to connect for reason {e}"
        except asyncio.CancelledError:
            reason = "Cancelled"
        except Exception as e:
            reason = traceback.format_exc()
        return None, (f"{host}:{port}", reason)

    @classmethod
    def get_address_new(cls) -> Optional[address.NetworkAddress]:
        """
        Utility function to return the first address with the state NEW.
        """
        for addr in cls.addresses:
            if addr.is_state_new:
                return addr
        # explicit return to silence mypy
        return None

    async def _do_handshake(self) -> tuple[bool, Optional[address.DisconnectReason]]:
        caps: list[capabilities.NodeCapability] = [capabilities.FullNodeCapability(0)]
        # TODO: fix nonce and port if a service is running
        send_version = message.Message(
            msg_type=message.MessageType.VERSION,
            payload=version.VersionPayload(
                nonce=123, user_agent="NEO-MAMBA", capabilities=caps
            ),
        )
        await self.send_message(send_version)

        m = await self.read_message(timeout=3)
        if not m or m.type != message.MessageType.VERSION:
            await self.disconnect(address.DisconnectReason.HANDSHAKE_VERSION_ERROR)
            return False, address.DisconnectReason.HANDSHAKE_VERSION_ERROR

        if not self._validate_version(m.payload):
            await self.disconnect(address.DisconnectReason.HANDSHAKE_VERSION_ERROR)
            return False, address.DisconnectReason.HANDSHAKE_VERSION_ERROR

        m_verack = message.Message(msg_type=message.MessageType.VERACK)
        await self.send_message(m_verack)

        m = await self.read_message(timeout=3)
        if not m or m.type != message.MessageType.VERACK:
            await self.disconnect(address.DisconnectReason.HANDSHAKE_VERACK_ERROR)
            return False, address.DisconnectReason.HANDSHAKE_VERACK_ERROR

        user_agent = self.version.user_agent if self.version else ""
        logger.debug(
            f"Connected to {user_agent} @ {self.address.address}: {self.best_height}."
        )
        msgrouter.on_node_connected(self)

        return True, None

    def _create_task_with_cleanup(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.append(task)
        task.add_done_callback(lambda fut: self.tasks.remove(fut))

    async def _process_incoming_data(self) -> None:
        """
        Main loop
        """
        logger.debug("Waiting for a message.")
        while not self.disconnecting:
            # we want to always listen for an incoming message
            m = await self.read_message(timeout=1)
            if m is None:
                continue

            handler = self.dispatch_table.get(m.type, None)
            if handler:
                handler(m)
            else:
                logger.debug(f"Unknown message with type: {m.type.name}.")

    def _find_address_by_host_port(self, host_port) -> Optional[address.NetworkAddress]:
        addr = address.NetworkAddress(address=host_port)
        try:
            idx = self.addresses.index(addr)
            return self.addresses[idx]
        except ValueError:
            return None

    def _validate_version(self, version) -> bool:
        if version.nonce == self.nodeid:
            logger.debug("Client is self.")
            return False

        if version.magic != settings.settings.network.magic:
            logger.debug(f"Wrong network id {version.magic}.")
            return False

        for c in version.capabilities:
            if isinstance(c, capabilities.ServerCapability):
                addr = self._find_address_by_host_port(self.address.address)

                if addr:
                    addr.set_state_connected()
                    addr.capabilities = version.capabilities
                else:
                    logger.debug(f"Adding address from outside {self.address.address}.")
                    # new connection initiated from outside
                    addr = address.NetworkAddress(
                        address=self.address.address,
                        capabilities=version.capabilities,
                        state=address.AddressState.CONNECTED,
                    )
                    self.addresses.append(addr)
                break

        for c in version.capabilities:
            if isinstance(c, capabilities.FullNodeCapability):
                # update nodes height indicator
                self.best_height = c.start_height
                self.best_height_last_update = datetime.utcnow().timestamp()
                self.version = version
                return True
        else:
            return False

    @classmethod
    def _reset_for_test(cls) -> None:
        cls.addresses = []


chars = string.digits + string.ascii_letters
base = len(chars)


def encode_base62(num: int):
    """Encode number in base62, returns a string."""
    if num < 0:
        raise ValueError("cannot encode negative numbers")

    if num == 0:
        return chars[0]

    digits = []
    while num:
        rem = num % base
        num = num // base
        digits.append(chars[rem])
    return "".join(reversed(digits))
