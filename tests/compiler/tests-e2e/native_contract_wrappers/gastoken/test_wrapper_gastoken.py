import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef
from neo3.contracts.contract import CONTRACT_HASHES

HERE = Path(__file__).parent

GAS = CONTRACT_HASHES.GAS_TOKEN


class TestGasTokenWrapper(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "wrapper_gastoken.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./wrapper_gastoken.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"wrapper_gastoken{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_symbol(self) -> None:
        result, _ = await self.call("get_symbol", [], return_type=str)
        self.assertEqual("GAS", result)

    async def test_decimals(self) -> None:
        result, _ = await self.call("get_decimals", [], return_type=int)
        self.assertEqual(8, result)

    async def test_total_supply_positive(self) -> None:
        result, _ = await self.call("get_total_supply", [], return_type=int)
        self.assertGreater(result, 0)

    async def test_balance_of_genesis_positive(self) -> None:
        result, _ = await self.call(
            "get_balance_of", [self.genesis.script_hash], return_type=int
        )
        self.assertGreater(result, 0)

    async def test_balance_of_zero_account(self) -> None:
        result, _ = await self.call("get_balance_of", [b"\x00" * 20], return_type=int)
        self.assertEqual(0, result)


if __name__ == "__main__":
    unittest.main()
