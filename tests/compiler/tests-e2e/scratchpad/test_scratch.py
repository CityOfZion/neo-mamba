import asyncio
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestIntToBytes(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "scratch.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./scratch.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"scratch{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ── little-endian unsigned ────────────────────────────────────────────────

    async def test_main(self) -> None:
        result, _ = await self.call("main", [1], return_type=int)
        self.assertEqual(result, 1)
