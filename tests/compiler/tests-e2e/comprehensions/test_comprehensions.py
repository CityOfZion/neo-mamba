import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestComprehensions(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "comprehensions.py").read_text(),
            str(HERE / "comprehensions"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./comprehensions.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"comprehensions{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # list comp / range
    # ------------------------------------------------------------------

    async def test_list_comp_range_basic(self) -> None:
        result, _ = await self.call("list_comp_range_basic", [], return_type=list)
        self.assertEqual([item.as_int() for item in result], [0, 1, 2, 3, 4])

    async def test_list_comp_range_transform(self) -> None:
        result, _ = await self.call("list_comp_range_transform", [], return_type=list)
        self.assertEqual([item.as_int() for item in result], [0, 1, 4, 9, 16])

    async def test_list_comp_range_filter(self) -> None:
        result, _ = await self.call("list_comp_range_filter", [], return_type=list)
        self.assertEqual([item.as_int() for item in result], [0, 2, 4, 6, 8])

    async def test_list_comp_range_step(self) -> None:
        result, _ = await self.call("list_comp_range_step", [], return_type=list)
        self.assertEqual([item.as_int() for item in result], [0, 3, 6, 9])

    async def test_list_comp_range_negative_step(self) -> None:
        result, _ = await self.call(
            "list_comp_range_negative_step", [], return_type=list
        )
        self.assertEqual([item.as_int() for item in result], [9, 6, 3, 0])

    async def test_list_comp_empty(self) -> None:
        result, _ = await self.call("list_comp_empty", [], return_type=list)
        self.assertEqual(result, [])

    # ------------------------------------------------------------------
    # list comp / list iterable
    # ------------------------------------------------------------------

    async def test_list_comp_list_identity(self) -> None:
        result, _ = await self.call(
            "list_comp_list_identity", [[1, 2, 3]], return_type=list
        )
        self.assertEqual([item.as_int() for item in result], [1, 2, 3])

    async def test_list_comp_list_transform(self) -> None:
        result, _ = await self.call(
            "list_comp_list_transform", [[1, 2, 3]], return_type=list
        )
        self.assertEqual([item.as_int() for item in result], [2, 4, 6])

    async def test_list_comp_list_filter(self) -> None:
        result, _ = await self.call(
            "list_comp_list_filter", [[-1, 2, -3, 4]], return_type=list
        )
        self.assertEqual([item.as_int() for item in result], [2, 4])

    # ------------------------------------------------------------------
    # list comp used in expression
    # ------------------------------------------------------------------

    async def test_list_comp_in_len_expr(self) -> None:
        result, _ = await self.call("list_comp_in_len_expr", [], return_type=int)
        self.assertEqual(result, 7)

    # ------------------------------------------------------------------
    # dict comp / range
    # ------------------------------------------------------------------

    async def test_dict_comp_range_lookup(self) -> None:
        result, _ = await self.call("dict_comp_range_lookup", [], return_type=int)
        self.assertEqual(result, 9)

    async def test_dict_comp_range_len(self) -> None:
        result, _ = await self.call("dict_comp_range_len", [], return_type=int)
        self.assertEqual(result, 5)

    async def test_dict_comp_range_filter_len(self) -> None:
        result, _ = await self.call("dict_comp_range_filter_len", [], return_type=int)
        self.assertEqual(result, 5)

    # ------------------------------------------------------------------
    # dict comp / list iterable
    # ------------------------------------------------------------------

    async def test_dict_comp_list_lookup(self) -> None:
        result, _ = await self.call(
            "dict_comp_list_lookup", [[1, 2, 3]], return_type=int
        )
        self.assertEqual(result, 4)

    # ------------------------------------------------------------------
    # Compile-error cases
    # ------------------------------------------------------------------

    def test_list_comp_multiple_generators_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(a: list[int], b: list[int]) -> list[int]:\n    return [x for x in a for y in b]\n",
                "/tmp/throwaway",
            )

    def test_list_comp_nested_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(a: list[int]) -> list[int]:\n    return [[x for x in a] for _ in a]\n",
                "/tmp/throwaway",
            )

    def test_list_comp_non_list_iterable_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(d: dict[str, int]) -> list[str]:\n    return [k for k in d]\n",
                "/tmp/throwaway",
            )

    def test_list_comp_non_bool_filter_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(lst: list[int]) -> list[int]:\n    return [x for x in lst if x + 1]\n",
                "/tmp/throwaway",
            )

    def test_dict_comp_multiple_generators_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(a: list[int], b: list[int]) -> dict[int, int]:\n    return {x: y for x in a for y in b}\n",
                "/tmp/throwaway",
            )

    def test_dict_comp_non_bool_filter_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(lst: list[int]) -> dict[int, int]:\n    return {x: x for x in lst if x + 1}\n",
                "/tmp/throwaway",
            )


if __name__ == "__main__":
    unittest.main()
