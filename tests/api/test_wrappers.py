import unittest
from typing import Optional, Any
from aioresponses import aioresponses
from neo3.core import types
from neo3.api.wrappers import _check_address_and_convert, ChainFacade

JSON = Any


class WrapperUtilsTest(unittest.TestCase):
    def test_check_address_and_convert(self):
        hash_in = types.UInt160.from_string(
            "0x7e9237a93f64407141a5b86c760200c66c81e2ec"
        )
        self.assertIsInstance(_check_address_and_convert(hash_in), types.UInt160)

        with self.assertRaises(ValueError) as context:
            _check_address_and_convert(object())
        self.assertEqual(
            "Input is of type <class 'object'> expected UInt160 or NeoAddress(str)",
            str(context.exception),
        )

        invalid_address = "NgNJsBfhcoJSm6MVMpMeGLqEK5mSQXuJTt"
        with self.assertRaises(ValueError) as context:
            _check_address_and_convert(invalid_address)
        self.assertEqual("Invalid checksum", str(context.exception))

        valid_address = "NgNJsBfhcoJSm6MVMpMeGLqEK5mSQXuJTq"
        self.assertIsInstance(_check_address_and_convert(valid_address), types.UInt160)


class TestChainFacade(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # CAREFULL THIS PATCHES ALL aiohttp CALLS!
        self.helper = aioresponses()
        self.helper.start()

    async def asyncTearDown(self) -> None:
        self.helper.stop()

    def mock_response(
        self, payload: Optional[JSON] = None, exc: Optional[Exception] = None
    ):
        """
        Either payload or exc should be provided
        """
        if payload is not None and exc is not None:
            raise ValueError("Arguments are mutual exclusive")

        if payload is not None:
            json = {"jsonrpc": "2.0", "id": 1, "result": payload}
            self.helper.post("localhost", payload=json)
        else:
            self.helper.post("localhost", exception=exc)

    async def test_receipt_retry_delay_and_timeout(self):
        user_agent = "/Neo:3.0.3/"
        get_version_captured = {
            "tcpport": 10333,
            "wsport": 10334,
            "nonce": 1930156121,
            "useragent": user_agent,
            "rpc": {"maxiteratorresultitems": 100, "sessionenabled": True},
            "protocol": {
                "addressversion": 53,
                "network": 860833102,
                "validatorscount": 7,
                "msperblock": 15000,
                "maxtraceableblocks": 2102400,
                "maxvaliduntilblockincrement": 5760,
                "maxtransactionsperblock": 512,
                "memorypoolmaxtransactions": 50000,
                "initialgasdistribution": 5200000000000000,
                "hardforks": [
                    {"name": "Aspidochelone", "blockheight": 1730000},
                    {"name": "Basilisk", "blockheight": 4120000},
                    {"name": "Cockatrice", "blockheight": 5450000},
                    {"name": "Domovoi", "blockheight": 5570000},
                ],
            },
        }
        self.mock_response(get_version_captured)
        facade = ChainFacade("localhost")
        delay, timeout = await facade._get_receipt_time_values()
        self.assertEqual(3.0, delay)
        self.assertEqual(33.0, timeout)

        self.mock_response(get_version_captured)
        facade = ChainFacade("localhost", receipt_timeout=1)
        delay, timeout = await facade._get_receipt_time_values()
        self.assertEqual(3.0, delay)
        self.assertEqual(1.0, timeout)

        self.mock_response(get_version_captured)
        facade = ChainFacade("localhost", receipt_retry_delay=5)
        delay, timeout = await facade._get_receipt_time_values()
        self.assertEqual(5.0, delay)
        self.assertEqual(35.0, timeout)

        self.mock_response(get_version_captured)
        facade = ChainFacade("localhost", receipt_retry_delay=5, receipt_timeout=1)
        delay, timeout = await facade._get_receipt_time_values()
        self.assertEqual(5.0, delay)
        self.assertEqual(1.0, timeout)
