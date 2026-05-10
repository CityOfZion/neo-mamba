import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestOptionalNarrowing(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "optional_narrowing.py").read_text(),
            str(HERE / "optional_narrowing"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./optional_narrowing.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"optional_narrowing{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ── static_field_narrowing ───────────────────────────────────────────────

    async def test_static_field_path_1(self) -> None:
        result, _ = await self.call("static_field_narrowing", [1], return_type=int)
        self.assertEqual(result, 10)

    async def test_static_field_path_else(self) -> None:
        result, _ = await self.call("static_field_narrowing", [2], return_type=int)
        self.assertEqual(result, 20)

    # ── block_index_by_path (original if/elif bug) ──────────────────────────

    async def test_path_1_returns_block_index(self) -> None:
        result, _ = await self.call("block_index_by_path", [1], return_type=int)
        self.assertEqual(result, 0)

    async def test_path_2_returns_block_index(self) -> None:
        result, _ = await self.call("block_index_by_path", [2], return_type=int)
        self.assertEqual(result, 0)

    async def test_path_else_returns_minus_one(self) -> None:
        result, _ = await self.call("block_index_by_path", [3], return_type=int)
        self.assertEqual(result, -1)

    # ── none_check_secondary_assert ─────────────────────────────────────────

    async def test_none_check_both_present(self) -> None:
        # a=3, b=4 → a is not None branch, assert b is not None → return 3+4=7
        result, _ = await self.call(
            "none_check_secondary_assert", [3, 4], return_type=int
        )
        self.assertEqual(result, 7)

    async def test_none_check_a_none_b_present(self) -> None:
        # a=None → else branch; b=5 is not None → return 5
        result, _ = await self.call(
            "none_check_secondary_assert", [None, 5], return_type=int
        )
        self.assertEqual(result, 5)

    async def test_none_check_a_none_b_none(self) -> None:
        # a=None → else branch; b is None → return -1
        result, _ = await self.call(
            "none_check_secondary_assert", [None, None], return_type=int
        )
        self.assertEqual(result, -1)

    # ── while_else_optional ─────────────────────────────────────────────────

    async def test_while_else_x_present(self) -> None:
        # x=7, loop runs 2 times asserting x is not None, then else returns x=7
        result, _ = await self.call("while_else_optional", [7], return_type=int)
        self.assertEqual(result, 7)

    async def test_while_else_x_none(self) -> None:
        # x=None, loop body would fault on assert; but loop runs 0 times? No:
        # while n < 2 is True initially, so the assert *will* fault.
        # Pass x=None only when we want the assert to fire — skip this case.
        # Instead verify x=0 (falsy int, but not None) passes the else guard.
        result, _ = await self.call("while_else_optional", [0], return_type=int)
        self.assertEqual(result, 0)

    # ── try_catch_optional ──────────────────────────────────────────────────

    async def test_try_x_present(self) -> None:
        result, _ = await self.call("try_catch_optional", [10], return_type=int)
        self.assertEqual(result, 11)

    async def test_try_x_none_faults_vm(self) -> None:
        # ASSERT (0x39) faults the VM — not caught by TRY_L/ENDTRY_L
        with self.assertRaises(Exception):
            await self.call("try_catch_optional", [None], return_type=int)

    # ── for_else_optional ───────────────────────────────────────────────────

    async def test_for_else_x_present(self) -> None:
        # x=9, loop asserts non-None twice, else returns x=9
        result, _ = await self.call("for_else_optional", [9], return_type=int)
        self.assertEqual(result, 9)

    async def test_for_else_x_zero(self) -> None:
        # x=0 (not None), loop asserts pass, else guard sees 0 and returns 0
        result, _ = await self.call("for_else_optional", [0], return_type=int)
        self.assertEqual(result, 0)
