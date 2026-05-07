import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestControlFlow(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "control_flow.py").read_text(), str(HERE / "control_flow")
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./control_flow.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"control_flow{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # if / else
    # ------------------------------------------------------------------

    async def test_if_positive(self) -> None:
        result, _ = await self.call("if_positive_negative", [5], return_type=int)
        self.assertEqual(result, 1)

    async def test_if_negative(self) -> None:
        result, _ = await self.call("if_positive_negative", [-3], return_type=int)
        self.assertEqual(result, -1)

    async def test_if_zero_takes_else(self) -> None:
        # 0 is not > 0, so else branch executes
        result, _ = await self.call("if_positive_negative", [0], return_type=int)
        self.assertEqual(result, -1)

    # ------------------------------------------------------------------
    # if without else (assignment pattern)
    # ------------------------------------------------------------------

    async def test_if_no_else_true(self) -> None:
        result, _ = await self.call("if_no_else", [5], return_type=int)
        self.assertEqual(result, 1)

    async def test_if_no_else_false(self) -> None:
        result, _ = await self.call("if_no_else", [0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # elif chain
    # ------------------------------------------------------------------

    async def test_elif_negative(self) -> None:
        result, _ = await self.call("elif_chain", [-5], return_type=int)
        self.assertEqual(result, -1)

    async def test_elif_zero(self) -> None:
        result, _ = await self.call("elif_chain", [0], return_type=int)
        self.assertEqual(result, 0)

    async def test_elif_positive(self) -> None:
        result, _ = await self.call("elif_chain", [5], return_type=int)
        self.assertEqual(result, 1)

    # ------------------------------------------------------------------
    # nested if
    # ------------------------------------------------------------------

    async def test_nested_if_both_positive(self) -> None:
        result, _ = await self.call("nested_if", [1, 1], return_type=int)
        self.assertEqual(result, 1)

    async def test_nested_if_x_pos_y_nonpos(self) -> None:
        result, _ = await self.call("nested_if", [1, -1], return_type=int)
        self.assertEqual(result, 2)

    async def test_nested_if_x_nonpos_y_pos(self) -> None:
        # outer else taken; inner if not evaluated
        result, _ = await self.call("nested_if", [-1, 1], return_type=int)
        self.assertEqual(result, 3)

    async def test_nested_if_both_nonpos(self) -> None:
        result, _ = await self.call("nested_if", [-1, -1], return_type=int)
        self.assertEqual(result, 3)

    # ------------------------------------------------------------------
    # while (basic accumulator)
    # ------------------------------------------------------------------

    async def test_while_sum_five(self) -> None:
        # 0+1+2+3+4 = 10
        result, _ = await self.call("while_sum", [5], return_type=int)
        self.assertEqual(result, 10)

    async def test_while_sum_zero_iterations(self) -> None:
        result, _ = await self.call("while_sum", [0], return_type=int)
        self.assertEqual(result, 0)

    async def test_while_sum_one_iteration(self) -> None:
        # range 0..0 adds 0 once
        result, _ = await self.call("while_sum", [1], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # while + break
    # ------------------------------------------------------------------

    async def test_while_break_at_three(self) -> None:
        result, _ = await self.call("while_break", [3], return_type=int)
        self.assertEqual(result, 3)

    async def test_while_break_immediate(self) -> None:
        # limit=0: i=0, 0>=0 → break immediately
        result, _ = await self.call("while_break", [0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # while + continue
    # ------------------------------------------------------------------

    async def test_while_continue_odd_sum_six(self) -> None:
        # i increments first, then skips even: 1+3+5 = 9
        result, _ = await self.call("while_continue_odd_sum", [6], return_type=int)
        self.assertEqual(result, 9)

    async def test_while_continue_odd_sum_zero(self) -> None:
        result, _ = await self.call("while_continue_odd_sum", [0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # while / else
    # ------------------------------------------------------------------

    async def test_while_else_no_break_nonzero(self) -> None:
        # no break ever fired → else always runs
        result, _ = await self.call("while_else_no_break", [3], return_type=int)
        self.assertEqual(result, 99)

    async def test_while_else_no_break_zero_iterations(self) -> None:
        # zero-iteration loop: condition false from start → else still runs
        result, _ = await self.call("while_else_no_break", [0], return_type=int)
        self.assertEqual(result, 99)

    async def test_while_else_with_break_hits_target(self) -> None:
        # breaks at i==3 → skips else → returns 3
        result, _ = await self.call("while_else_with_break", [5, 3], return_type=int)
        self.assertEqual(result, 3)

    async def test_while_else_with_break_misses_target(self) -> None:
        # target beyond range → no break → else returns -1
        result, _ = await self.call("while_else_with_break", [5, 10], return_type=int)
        self.assertEqual(result, -1)

    async def test_while_else_with_break_empty_loop(self) -> None:
        # zero iterations → no break → else returns -1
        result, _ = await self.call("while_else_with_break", [0, 0], return_type=int)
        self.assertEqual(result, -1)

    # ------------------------------------------------------------------
    # for / range (basic)
    # ------------------------------------------------------------------

    async def test_for_sum_five(self) -> None:
        # sum(range(5)) = 0+1+2+3+4 = 10
        result, _ = await self.call("for_sum", [5], return_type=int)
        self.assertEqual(result, 10)

    async def test_for_sum_empty_range(self) -> None:
        result, _ = await self.call("for_sum", [0], return_type=int)
        self.assertEqual(result, 0)

    async def test_for_sum_single_element(self) -> None:
        # range(1) = [0], sum = 0
        result, _ = await self.call("for_sum", [1], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # for / range with start/stop
    # ------------------------------------------------------------------

    async def test_for_range_start_stop_basic(self) -> None:
        # 2+3+4+5 = 14
        result, _ = await self.call("for_range_start_stop", [2, 6], return_type=int)
        self.assertEqual(result, 14)

    async def test_for_range_start_stop_empty(self) -> None:
        result, _ = await self.call("for_range_start_stop", [3, 3], return_type=int)
        self.assertEqual(result, 0)

    async def test_for_range_start_stop_single(self) -> None:
        # range(0, 1) = [0]
        result, _ = await self.call("for_range_start_stop", [0, 1], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # for / range with literal step
    # (range() step must be a compile-time literal — compiler limitation)
    # ------------------------------------------------------------------

    async def test_for_range_step2_basic(self) -> None:
        # 0+2+4+6+8 = 20
        result, _ = await self.call("for_range_step2", [0, 10], return_type=int)
        self.assertEqual(result, 20)

    async def test_for_range_step2_empty(self) -> None:
        result, _ = await self.call("for_range_step2", [0, 0], return_type=int)
        self.assertEqual(result, 0)

    async def test_for_range_step2_single(self) -> None:
        # range(0, 1, 2) = [0]
        result, _ = await self.call("for_range_step2", [0, 1], return_type=int)
        self.assertEqual(result, 0)

    async def test_for_range_step3_basic(self) -> None:
        # 1+4+7 = 12
        result, _ = await self.call("for_range_step3", [1, 10], return_type=int)
        self.assertEqual(result, 12)

    async def test_for_range_step3_empty(self) -> None:
        result, _ = await self.call("for_range_step3", [5, 5], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # for + break
    # ------------------------------------------------------------------

    async def test_for_break_sum_hits_limit(self) -> None:
        # accumulates 0+1+2+3+4=10, breaks when i==5
        result, _ = await self.call("for_break_sum", [10, 5], return_type=int)
        self.assertEqual(result, 10)

    async def test_for_break_sum_limit_beyond_range(self) -> None:
        # limit=10 never reached in range(3): accumulates 0+1+2=3
        result, _ = await self.call("for_break_sum", [3, 10], return_type=int)
        self.assertEqual(result, 3)

    async def test_for_break_sum_immediate_break(self) -> None:
        # breaks at i==0 before accumulating anything
        result, _ = await self.call("for_break_sum", [5, 0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # for + continue
    # ------------------------------------------------------------------

    async def test_for_continue_sum_six(self) -> None:
        # skip even indices (0,2,4); sum odd: 1+3+5 = 9
        result, _ = await self.call("for_continue_sum", [6], return_type=int)
        self.assertEqual(result, 9)

    async def test_for_continue_sum_empty(self) -> None:
        result, _ = await self.call("for_continue_sum", [0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # for / else
    # ------------------------------------------------------------------

    async def test_for_else_no_break_nonzero(self) -> None:
        # loop completes normally → else runs
        result, _ = await self.call("for_else_no_break", [3], return_type=int)
        self.assertEqual(result, 99)

    async def test_for_else_no_break_empty_range(self) -> None:
        # empty range → loop body never executes → else still runs
        result, _ = await self.call("for_else_no_break", [0], return_type=int)
        self.assertEqual(result, 99)

    async def test_for_else_with_break_hits_target(self) -> None:
        # breaks at i==3 → skips else → returns 3
        result, _ = await self.call("for_else_with_break", [5, 3], return_type=int)
        self.assertEqual(result, 3)

    async def test_for_else_with_break_misses_target(self) -> None:
        # target not in range → no break → else returns -1
        result, _ = await self.call("for_else_with_break", [5, 10], return_type=int)
        self.assertEqual(result, -1)

    async def test_for_else_with_break_empty_range(self) -> None:
        # empty range → no break → else returns -1
        result, _ = await self.call("for_else_with_break", [0, 0], return_type=int)
        self.assertEqual(result, -1)


if __name__ == "__main__":
    unittest.main()
