import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestBytesFromHex(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "bytes_fromhex.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./bytes_fromhex.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"bytes_fromhex{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_decode_basic(self) -> None:
        result, _ = await self.call("decode", ["0102ff"], return_type=bytes)
        self.assertEqual(result, b"\x01\x02\xff")

    async def test_decode_empty(self) -> None:
        result, _ = await self.call("decode", [""], return_type=bytes)
        self.assertEqual(result, b"")

    async def test_decode_all_zeros(self) -> None:
        result, _ = await self.call("decode", ["000000"], return_type=bytes)
        self.assertEqual(result, b"\x00\x00\x00")
