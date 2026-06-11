import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestDocstrings(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "docstrings.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./docstrings.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"docstrings{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_add(self) -> None:
        result, _ = await self.call("add", [3, 4], return_type=int)
        self.assertEqual(result, 7)

    async def test_multiply(self) -> None:
        result, _ = await self.call("multiply", [3, 4], return_type=int)
        self.assertEqual(result, 12)

    async def test_subtract(self) -> None:
        result, _ = await self.call("subtract", [10, 3], return_type=int)
        self.assertEqual(result, 7)
