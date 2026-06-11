import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestPolicyWrapper(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "wrapper_policy.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./wrapper_policy.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"wrapper_policy{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_fee_per_byte_positive(self) -> None:
        result, _ = await self.call("get_fee_per_byte", [], return_type=int)
        self.assertGreater(result, 0)

    async def test_exec_fee_factor_positive(self) -> None:
        result, _ = await self.call("get_exec_fee_factor", [], return_type=int)
        self.assertGreater(result, 0)

    async def test_storage_price_positive(self) -> None:
        result, _ = await self.call("get_storage_price", [], return_type=int)
        self.assertGreater(result, 0)

    async def test_zero_account_not_blocked(self) -> None:
        result, _ = await self.call(
            "check_is_blocked", [b"\x00" * 20], return_type=bool
        )
        self.assertFalse(result)

    async def test_genesis_not_blocked(self) -> None:
        result, _ = await self.call(
            "check_is_blocked", [self.genesis.script_hash], return_type=bool
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
