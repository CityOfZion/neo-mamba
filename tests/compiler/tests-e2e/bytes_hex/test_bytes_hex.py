import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestBytesHex(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "bytes_hex.py").read_text(),
            str(HERE / "bytes_hex"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./bytes_hex.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"bytes_hex{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_encode_basic(self) -> None:
        result, _ = await self.call("encode", [b"\x01\x02\xff"], return_type=str)
        self.assertEqual(result, "0102ff")

    async def test_encode_empty(self) -> None:
        result, _ = await self.call("encode", [b""], return_type=str)
        self.assertEqual(result, "")

    async def test_encode_bytearray(self) -> None:
        result, _ = await self.call(
            "encode_bytearray", [b"\xde\xad\xbe\xef"], return_type=str
        )
        self.assertEqual(result, "deadbeef")
