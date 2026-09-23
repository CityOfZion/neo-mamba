import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestListPop(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "list_pop.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./list_pop.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"list_pop{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_pop_default_returns_last_element(self) -> None:
        result, _ = await self.call("pop_default_value", [], return_type=int)
        expected = [1, 2, 3, 4, 5]
        self.assertEqual(expected.pop(), result)

    async def test_pop_default_removes_last_element(self) -> None:
        result, _ = await self.call("pop_default_remaining", [], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        expected = [1, 2, 3, 4, 5]
        expected.pop()
        self.assertEqual(expected, result)

    async def test_pop_value_returns_element_at_index(self) -> None:
        result, _ = await self.call("pop_value", [2], return_type=int)
        expected = [1, 2, 3, 4, 5]
        self.assertEqual(expected.pop(2), result)

    async def test_pop_remaining_removes_element_at_index(self) -> None:
        result, _ = await self.call("pop_remaining", [2], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        expected = [1, 2, 3, 4, 5]
        expected.pop(2)
        self.assertEqual(expected, result)

    async def test_pop_value_negative_index(self) -> None:
        result, _ = await self.call("pop_value", [-1], return_type=int)
        expected = [1, 2, 3, 4, 5]
        self.assertEqual(expected.pop(-1), result)

    async def test_pop_remaining_negative_index(self) -> None:
        result, _ = await self.call("pop_remaining", [-2], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        expected = [1, 2, 3, 4, 5]
        expected.pop(-2)
        self.assertEqual(expected, result)

    async def test_pop_negative_index_equals_first_element(self) -> None:
        result, _ = await self.call("pop_value", [-5], return_type=int)
        expected = [1, 2, 3, 4, 5]
        self.assertEqual(expected.pop(-5), result)

    async def test_pop_until_empty_returns_empty_list(self) -> None:
        result, _ = await self.call("pop_until_empty", [], return_type=list)
        self.assertEqual([], result)

    async def test_pop_out_of_range_negative_index_faults(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("pop_out_of_range", [], return_type=int)


if __name__ == "__main__":
    unittest.main()
