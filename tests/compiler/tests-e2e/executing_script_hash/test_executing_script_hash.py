import asyncio
from pathlib import Path

from neo3.sctesting import SmartContractTestCase
from neo3.compiler import compile_to_nef
from neo3.core import types

HERE = Path(__file__).parent


class TestExecutingScriptHash(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "executing_script_hash.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy(
            "./executing_script_hash.nef", cls.genesis
        )

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"executing_script_hash{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_returns_own_contract_hash(self) -> None:
        result, _ = await self.call("get_my_hash", [], return_type=types.UInt160)
        self.assertEqual(self.contract_hash, result)
