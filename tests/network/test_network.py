import asyncio
import logging
from neo3.network import node, message, capabilities
from neo3.network.payloads import address, block
import unittest


class NetworkTestCase(unittest.IsolatedAsyncioTestCase):
    @classmethod
    async def setUpClass(cls) -> None:
        loop = asyncio.get_event_loop()
        loop.set_debug(True)

        def my_exc_handler(loop, context):
            print(f"woahhh error! {context}")
            loop.default_exception_handler(context)

        loop.set_exception_handler(my_exc_handler)

        stdio_handler = logging.StreamHandler()
        stdio_handler.setLevel(logging.DEBUG)
        stdio_handler.setFormatter(
            logging.Formatter("%(levelname)s - %(module)s:%(lineno)s %(message)s")
        )
        async_logger = logging.getLogger("asyncio")
        async_logger.addHandler(stdio_handler)
        async_logger.setLevel(logging.DEBUG)

        network_logger = logging.getLogger("neo3.network")
        network_logger.addHandler(stdio_handler)
        network_logger.setLevel(logging.DEBUG)

    @unittest.skip
    async def test_sending_addresses(self):
        n = await node.NeoNode.connect_to("127.0.0.1", 40333)
        await n.send_address_list(
            [
                address.NetworkAddress(
                    host="127.0.0.1",
                    timestamp=0,
                    capabilities=[capabilities.FullNodeCapability(start_height=123)],
                )
            ]
        )
        await asyncio.sleep(100)

    @unittest.skip
    async def test_basic_setup(self):
        n = await node.NeoNode.connect_to("127.0.0.1", 40333)
        m = message.Message(
            message.MessageType.GETFULLBLOCKS,
            block.GetFullBlocksPayload(index_start=1, count=10),
        )
        if n:
            await n.send_message(m)

            # await n.request_address_list()
            await asyncio.sleep(500)
            self.assertIsInstance(n, node.NeoNode)
            # fake nodemanager
            # - add_connected_node
            # - remove_connected_node
            # - quality_check_result
            # - relay_cache.try_get(header)  (can we create relay cache somewhere else?)
            # - sending address list (requires accessing known nodes)
