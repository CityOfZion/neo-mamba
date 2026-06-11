import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestStorageFind(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "storage_find.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./storage_find.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"storage_find{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_find_keys_all_returns_four_keys(self) -> None:
        result, _ = await self.call("find_keys", [b"data"], return_type=list)
        self.assertEqual(4, len(result))

    async def test_find_keys_exact_prefix_returns_one_key(self) -> None:
        result, _ = await self.call("find_keys", [b"data1"], return_type=list)
        self.assertEqual(1, len(result))

    async def test_find_keys_no_match_returns_empty_list(self) -> None:
        result, _ = await self.call("find_keys", [b"xyz"], return_type=list)
        self.assertEqual(0, len(result))

    async def test_find_keys_prefix_narrows_results(self) -> None:
        result_all, _ = await self.call("find_keys", [b"data"], return_type=list)
        result_one, _ = await self.call("find_keys", [b"data2"], return_type=list)
        self.assertEqual(4, len(result_all))
        self.assertEqual(1, len(result_one))


if __name__ == "__main__":
    unittest.main()
