import asyncio
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
        compile_to_nef(HERE / "checkwitness.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./checkwitness.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"checkwitness{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_zero_account(self) -> None:
        result, _ = await self.call("zero_account", return_type=bool)
        self.assertFalse(result)

    async def test_calling_account(self) -> None:
        result, _ = await self.call("calling_account", return_type=bool)
        self.assertTrue(result)
