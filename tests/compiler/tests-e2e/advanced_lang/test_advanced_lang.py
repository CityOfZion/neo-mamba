import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import AbortException, AssertException, SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestAdvancedLang(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "advanced_lang.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./advanced_lang.nef", cls.genesis)
        # _initialize is called automatically by the node before each method invocation.
        # No manual call needed here.

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"advanced_lang{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # Static fields — auto-initialisation by _initialize
    # ------------------------------------------------------------------

    async def test_static_label_auto_initialised(self) -> None:
        # _initialize must have been auto-called; label should equal "hello"
        result, _ = await self.call("static_read_label", [], return_type=str)
        self.assertEqual(result, "hello")

    async def test_static_shared_across_call_l(self) -> None:
        # counter starts at 0 (from _initialize), then _bump() is CALL_L'd twice
        result, _ = await self.call("static_bump_twice", [], return_type=int)
        self.assertEqual(result, 2)

    async def test_static_reset_each_invocation(self) -> None:
        # _initialize is called before EACH method call, so counter resets to 0
        # every time. Calling bump_twice twice should both return 2, not 2 then 4.
        result1, _ = await self.call("static_bump_twice", [], return_type=int)
        result2, _ = await self.call("static_bump_twice", [], return_type=int)
        self.assertEqual(result1, 2)
        self.assertEqual(result2, 2)

    # ------------------------------------------------------------------
    # Ternary expressions
    # ------------------------------------------------------------------

    async def test_ternary_abs_positive(self) -> None:
        result, _ = await self.call("abs_val", [7], return_type=int)
        self.assertEqual(result, 7)

    async def test_ternary_abs_negative(self) -> None:
        result, _ = await self.call("abs_val", [-3], return_type=int)
        self.assertEqual(result, 3)

    async def test_ternary_abs_zero(self) -> None:
        result, _ = await self.call("abs_val", [0], return_type=int)
        self.assertEqual(result, 0)

    async def test_ternary_clamp_in_range(self) -> None:
        result, _ = await self.call("clamp", [5, 1, 10], return_type=int)
        self.assertEqual(result, 5)

    async def test_ternary_clamp_below_min(self) -> None:
        result, _ = await self.call("clamp", [0, 1, 10], return_type=int)
        self.assertEqual(result, 1)

    async def test_ternary_clamp_above_max(self) -> None:
        result, _ = await self.call("clamp", [15, 1, 10], return_type=int)
        self.assertEqual(result, 10)

    # ------------------------------------------------------------------
    # None / Optional — is None / is not None, plus type narrowing
    # ------------------------------------------------------------------

    async def test_optional_none_branch(self) -> None:
        # flag=False → x stays None → is None guard fires → return -1
        result, _ = await self.call("optional_or_default", [False], return_type=int)
        self.assertEqual(result, -1)

    async def test_optional_value_branch(self) -> None:
        # flag=True → x = 42 → is None guard skipped → return x (narrowed to int)
        result, _ = await self.call("optional_or_default", [True], return_type=int)
        self.assertEqual(result, 42)

    async def test_is_not_none_when_set(self) -> None:
        result, _ = await self.call("is_not_none", [True], return_type=bool)
        self.assertTrue(result)

    async def test_is_not_none_when_null(self) -> None:
        result, _ = await self.call("is_not_none", [False], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # assert — passing cases
    # ------------------------------------------------------------------

    async def test_assert_passes(self) -> None:
        result, _ = await self.call("guarded_add", [3, 4], return_type=int)
        self.assertEqual(result, 7)

    async def test_assert_msg_passes(self) -> None:
        result, _ = await self.call("checked_div", [10, 2], return_type=int)
        self.assertEqual(result, 5)

    # ------------------------------------------------------------------
    # assert — failing cases fault the VM
    # ------------------------------------------------------------------

    async def test_assert_faults_on_negative_a(self) -> None:
        with self.assertRaises(AssertException):
            await self.call("guarded_add", [-1, 4], return_type=int)

    async def test_assert_faults_on_negative_b(self) -> None:
        with self.assertRaises(AssertException):
            await self.call("guarded_add", [3, -1], return_type=int)

    async def test_assert_msg_carries_message(self) -> None:
        with self.assertRaises(AssertException) as ctx:
            await self.call("checked_div", [10, 0], return_type=int)
        self.assertIn("division by zero", str(ctx.exception))

    # ------------------------------------------------------------------
    # raise — passing case
    # ------------------------------------------------------------------

    async def test_raise_passes(self) -> None:
        result, _ = await self.call("safe_input", [4], return_type=int)
        self.assertEqual(result, 4)

    # ------------------------------------------------------------------
    # raise — faults the VM with message
    # ------------------------------------------------------------------

    async def test_raise_faults_with_message(self) -> None:
        # THROW produces a FAULT; neo-go reports it without "ASSERT"/"ABORT" keywords,
        # so boaconstructor re-raises it as a plain ValueError containing the message.
        with self.assertRaises(ValueError) as ctx:
            await self.call("safe_input", [-1], return_type=int)
        self.assertIn("negative input", str(ctx.exception))

    # ------------------------------------------------------------------
    # for...else — else fires when no break
    # ------------------------------------------------------------------

    async def test_for_else_fires(self) -> None:
        # range(4): 0+1+2+3=6, no break → else fires (+1000) → 1006
        result, _ = await self.call("range_sum_else", [4], return_type=int)
        self.assertEqual(result, 1006)

    async def test_for_else_fires_on_empty_range(self) -> None:
        # range(0): body never runs; "completed without break" → else still fires
        result, _ = await self.call("range_sum_else", [0], return_type=int)
        self.assertEqual(result, 1000)

    # ------------------------------------------------------------------
    # for...else — else skipped when break fires
    # ------------------------------------------------------------------

    async def test_for_else_skipped_by_break(self) -> None:
        # range(5), break at i==3: accumulates 0+1+2=3, no else → 3
        result, _ = await self.call("range_sum_break", [5, 3], return_type=int)
        self.assertEqual(result, 3)

    async def test_for_else_fires_when_break_never_reached(self) -> None:
        # range(3), stop=10 never hit: 0+1+2=3, else fires (+1000) → 1003
        result, _ = await self.call("range_sum_break", [3, 10], return_type=int)
        self.assertEqual(result, 1003)

    # ------------------------------------------------------------------
    # Tuples — literals, constant indexing, multiple return values, unpack
    # ------------------------------------------------------------------

    async def test_tuple_swap(self) -> None:
        result, _ = await self.call("swap", [3, 7], return_type=list)
        self.assertEqual(result[0].as_int(), 7)
        self.assertEqual(result[1].as_int(), 3)

    async def test_tuple_divmod(self) -> None:
        # 17 // 5 = 3, 17 % 5 = 2
        result, _ = await self.call("divmod_pair", [17, 5], return_type=list)
        self.assertEqual(result[0].as_int(), 3)
        self.assertEqual(result[1].as_int(), 2)

    async def test_tuple_constant_index(self) -> None:
        # t = (10, 20, 30); t[1] → 20
        result, _ = await self.call("tuple_constant_index", [], return_type=int)
        self.assertEqual(result, 20)

    async def test_tuple_unpack(self) -> None:
        # a, b = swap(3, 7) → a=7, b=3; a - b = 4
        result, _ = await self.call("unpack_swap", [], return_type=int)
        self.assertEqual(result, 4)


if __name__ == "__main__":
    unittest.main()
