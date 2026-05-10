import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestScriptContainer(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "runtime_syscalls.py").read_text(),
            str(HERE / "runtime_syscalls"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./runtime_syscalls.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"runtime_syscalls{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_get_random(self) -> None:
        result1, _ = await self.call(
            "getrandom", return_type=int, signing_accounts=[self.genesis]
        )
        result2, _ = await self.call(
            "getrandom", return_type=int, signing_accounts=[self.genesis]
        )
        self.assertNotEqual(result1, result2)
