import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestListInsert(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "list_insert.py").read_text(),
            str(HERE / "list_insert"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./list_insert.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"list_insert{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_insert_middle_shifts_elements(self) -> None:
        result, _ = await self.call("insert_middle", [], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [1, 2, 3, 4, 5])

    async def test_insert_at_zero_prepends(self) -> None:
        result, _ = await self.call("insert_at_zero", [], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [1, 2, 3, 4])

    async def test_insert_at_end_appends(self) -> None:
        result, _ = await self.call("insert_at_end", [], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [1, 2, 3, 4])

    async def test_insert_into_empty_list(self) -> None:
        result, _ = await self.call("insert_into_empty", [], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [99])

    async def test_insert_dynamic_index_middle(self) -> None:
        result, _ = await self.call("insert_dynamic_index", [1], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [10, 99, 20, 30])

    async def test_insert_dynamic_index_start(self) -> None:
        result, _ = await self.call("insert_dynamic_index", [0], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [99, 10, 20, 30])

    async def test_insert_dynamic_index_end(self) -> None:
        result, _ = await self.call("insert_dynamic_index", [3], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [10, 20, 30, 99])

    async def test_insert_str_list(self) -> None:
        result, _ = await self.call("insert_str", [], return_type=list)
        result = list(map(lambda si: si.as_str(), result))
        self.assertEqual(result, ["a", "b", "c"])

    def test_insert_on_non_list_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n"
                "@public\ndef f() -> None:\n    s: str = 'hello'\n    s.insert(0, 'x')\n",
                "/tmp/throwaway_insert",
            )

    def test_insert_non_int_index_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n"
                "@public\ndef f() -> None:\n    lst: list[int] = [1, 2]\n    lst.insert('a', 3)\n",
                "/tmp/throwaway_insert",
            )

    def test_insert_type_mismatch_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n"
                "@public\ndef f() -> None:\n    lst: list[int] = [1, 2]\n    lst.insert(0, 'x')\n",
                "/tmp/throwaway_insert",
            )


if __name__ == "__main__":
    unittest.main()
