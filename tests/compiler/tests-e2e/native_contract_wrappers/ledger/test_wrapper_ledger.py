import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import AssertException, SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestLedgerWrapper(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "wrapper_ledger.py").read_text(),
            str(HERE / "wrapper_ledger"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./wrapper_ledger.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"wrapper_ledger{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_current_index_nonnegative(self) -> None:
        result, _ = await self.call("get_current_index", [], return_type=int)
        self.assertGreaterEqual(result, 0)

    async def test_current_hash_is_32_bytes(self) -> None:
        result, _ = await self.call("get_current_hash", [], return_type=bytes)
        self.assertEqual(32, len(result))

    async def test_current_hash_nonzero(self) -> None:
        result, _ = await self.call("get_current_hash", [], return_type=bytes)
        self.assertNotEqual(b"\x00" * 32, result)

    async def test_tx_height_unknown_returns_minus_one(self) -> None:
        result, _ = await self.call("get_tx_height", [b"\x00" * 32], return_type=int)
        self.assertEqual(-1, result)

    async def test_get_block_exists_for_block_zero(self) -> None:
        result, _ = await self.call("get_block_exists", [0], return_type=bool)
        self.assertTrue(result)

    async def test_get_block_for_future_index(self) -> None:
        result, _ = await self.call("get_block_exists", [999_999_999], return_type=bool)
        self.assertFalse(result)

    async def test_get_block_index_field_matches(self) -> None:
        result, _ = await self.call("get_block_index_field", [0], return_type=int)
        self.assertEqual(0, result)

    async def test_get_block_version_is_zero(self) -> None:
        result, _ = await self.call("get_block_version_field", [0], return_type=int)
        self.assertEqual(0, result)

    async def test_get_block_hash_field_is_32_bytes(self) -> None:
        result, _ = await self.call("get_block_hash_field", [0], return_type=bytes)
        self.assertEqual(32, len(result))

    async def test_get_block_hash_field_matches_current_hash(self) -> None:
        block_hash, _ = await self.call("get_block_hash_field", [0], return_type=bytes)
        # get_block(hash) should return the same block
        result, _ = await self.call("get_block_exists", [block_hash], return_type=bool)
        self.assertTrue(result)

    async def test_get_block_next_consensus_is_20_bytes(self) -> None:
        result, _ = await self.call(
            "get_block_next_consensus_field", [0], return_type=bytes
        )
        self.assertEqual(20, len(result))

    async def test_get_block_tx_count_nonnegative(self) -> None:
        result, _ = await self.call("get_block_tx_count_field", [0], return_type=int)
        self.assertGreaterEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
