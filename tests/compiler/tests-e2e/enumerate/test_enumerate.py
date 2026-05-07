import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestEnumerate(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "enumerate.py").read_text(),
            str(HERE / "enumerate"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./enumerate.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"enumerate{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # Basic enumerate
    # ------------------------------------------------------------------

    async def test_enum_sum_indices(self) -> None:
        # [10, 20, 30] → indices 0+1+2 = 3
        result, _ = await self.call("enum_sum_indices", [[10, 20, 30]], return_type=int)
        self.assertEqual(result, 3)

    async def test_enum_sum_indices_single(self) -> None:
        result, _ = await self.call("enum_sum_indices", [[99]], return_type=int)
        self.assertEqual(result, 0)

    async def test_enum_sum_values(self) -> None:
        result, _ = await self.call("enum_sum_values", [[10, 20, 30]], return_type=int)
        self.assertEqual(result, 60)

    async def test_enum_sum_both(self) -> None:
        # 0*10 + 1*20 + 2*30 = 0 + 20 + 60 = 80
        result, _ = await self.call("enum_sum_both", [[10, 20, 30]], return_type=int)
        self.assertEqual(result, 80)

    # ------------------------------------------------------------------
    # enumerate with start
    # ------------------------------------------------------------------

    async def test_enum_with_start_zero(self) -> None:
        # start=0: same as default → 0+1+2 = 3
        result, _ = await self.call(
            "enum_with_start", [[10, 20, 30], 0], return_type=int
        )
        self.assertEqual(result, 3)

    async def test_enum_with_start_nonzero(self) -> None:
        # start=5: indices 5+6+7 = 18
        result, _ = await self.call(
            "enum_with_start", [[10, 20, 30], 5], return_type=int
        )
        self.assertEqual(result, 18)

    async def test_enum_with_start_one(self) -> None:
        # start=1: indices 1+2+3 = 6
        result, _ = await self.call(
            "enum_with_start", [[10, 20, 30], 1], return_type=int
        )
        self.assertEqual(result, 6)

    # ------------------------------------------------------------------
    # break
    # ------------------------------------------------------------------

    async def test_enum_break_first(self) -> None:
        result, _ = await self.call("enum_break", [[0, 1, 2]], return_type=int)
        self.assertEqual(result, 0)

    async def test_enum_break_middle(self) -> None:
        result, _ = await self.call("enum_break", [[1, 0, 2]], return_type=int)
        self.assertEqual(result, 1)

    async def test_enum_break_not_found(self) -> None:
        result, _ = await self.call("enum_break", [[1, 2, 3]], return_type=int)
        self.assertEqual(result, -1)

    # ------------------------------------------------------------------
    # continue
    # ------------------------------------------------------------------

    async def test_enum_continue_basic(self) -> None:
        # [3, -1, 5, 0, 7] → indices where value > 0: [0, 2, 4]
        result, _ = await self.call(
            "enum_continue", [[3, -1, 5, 0, 7]], return_type=list
        )
        self.assertEqual([item.as_int() for item in result], [0, 2, 4])

    async def test_enum_continue_all_nonpositive(self) -> None:
        result, _ = await self.call("enum_continue", [[-1, 0, -5]], return_type=list)
        self.assertEqual(result, [])

    # ------------------------------------------------------------------
    # for/else
    # ------------------------------------------------------------------

    async def test_enum_for_else_found(self) -> None:
        result, _ = await self.call("enum_for_else", [[1, 2, -3, 4]], return_type=int)
        self.assertEqual(result, 2)

    async def test_enum_for_else_not_found(self) -> None:
        result, _ = await self.call("enum_for_else", [[1, 2, 3]], return_type=int)
        self.assertEqual(result, -1)

    # ------------------------------------------------------------------
    # Empty list
    # ------------------------------------------------------------------

    async def test_enum_empty(self) -> None:
        result, _ = await self.call("enum_empty", [[]], return_type=int)
        self.assertEqual(result, 0)
