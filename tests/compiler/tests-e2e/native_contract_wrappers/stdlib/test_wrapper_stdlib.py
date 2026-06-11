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
        compile_to_nef(HERE / "wrapper_stdlib.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./wrapper_stdlib.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"wrapper_stdlib{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_decode_basic(self) -> None:
        result, _ = await self.call("main", [b"\x01\x02"], return_type=str)
        self.assertEqual(result, "0102")
