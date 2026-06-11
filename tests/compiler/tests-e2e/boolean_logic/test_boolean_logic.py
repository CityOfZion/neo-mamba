import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_module, compile_to_nef

HERE = Path(__file__).parent


class TestBooleanLogic(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "boolean_logic.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./boolean_logic.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"boolean_logic{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # bool_and truth table
    # ------------------------------------------------------------------

    async def test_and_true_true(self) -> None:
        result, _ = await self.call("bool_and", [True, True], return_type=bool)
        self.assertTrue(result)

    async def test_and_true_false(self) -> None:
        result, _ = await self.call("bool_and", [True, False], return_type=bool)
        self.assertFalse(result)

    async def test_and_false_true(self) -> None:
        result, _ = await self.call("bool_and", [False, True], return_type=bool)
        self.assertFalse(result)

    async def test_and_false_false(self) -> None:
        result, _ = await self.call("bool_and", [False, False], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # bool_or truth table
    # ------------------------------------------------------------------

    async def test_or_true_true(self) -> None:
        result, _ = await self.call("bool_or", [True, True], return_type=bool)
        self.assertTrue(result)

    async def test_or_true_false(self) -> None:
        result, _ = await self.call("bool_or", [True, False], return_type=bool)
        self.assertTrue(result)

    async def test_or_false_true(self) -> None:
        result, _ = await self.call("bool_or", [False, True], return_type=bool)
        self.assertTrue(result)

    async def test_or_false_false(self) -> None:
        result, _ = await self.call("bool_or", [False, False], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # bool_not
    # ------------------------------------------------------------------

    async def test_not_true(self) -> None:
        result, _ = await self.call("bool_not", [True], return_type=bool)
        self.assertFalse(result)

    async def test_not_false(self) -> None:
        result, _ = await self.call("bool_not", [False], return_type=bool)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # and3 (chained)
    # ------------------------------------------------------------------

    async def test_and3_all_true(self) -> None:
        result, _ = await self.call("and3", [True, True, True], return_type=bool)
        self.assertTrue(result)

    async def test_and3_last_false(self) -> None:
        result, _ = await self.call("and3", [True, True, False], return_type=bool)
        self.assertFalse(result)

    async def test_and3_first_false(self) -> None:
        result, _ = await self.call("and3", [False, True, True], return_type=bool)
        self.assertFalse(result)

    async def test_and3_all_false(self) -> None:
        result, _ = await self.call("and3", [False, False, False], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # or3 (chained)
    # ------------------------------------------------------------------

    async def test_or3_all_false(self) -> None:
        result, _ = await self.call("or3", [False, False, False], return_type=bool)
        self.assertFalse(result)

    async def test_or3_last_true(self) -> None:
        result, _ = await self.call("or3", [False, False, True], return_type=bool)
        self.assertTrue(result)

    async def test_or3_first_true(self) -> None:
        result, _ = await self.call("or3", [True, False, False], return_type=bool)
        self.assertTrue(result)

    async def test_or3_all_true(self) -> None:
        result, _ = await self.call("or3", [True, True, True], return_type=bool)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # and_or  (a and b or c)  — precedence: (a and b) or c
    # ------------------------------------------------------------------

    async def test_and_or_tt_f(self) -> None:
        result, _ = await self.call("and_or", [True, True, False], return_type=bool)
        self.assertTrue(result)

    async def test_and_or_tf_f(self) -> None:
        result, _ = await self.call("and_or", [True, False, False], return_type=bool)
        self.assertFalse(result)

    async def test_and_or_ff_t(self) -> None:
        result, _ = await self.call("and_or", [False, False, True], return_type=bool)
        self.assertTrue(result)

    async def test_and_or_ff_f(self) -> None:
        result, _ = await self.call("and_or", [False, False, False], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # not_and  (not a and b)  — precedence: (not a) and b
    # ------------------------------------------------------------------

    async def test_not_and_false_true(self) -> None:
        result, _ = await self.call("not_and", [False, True], return_type=bool)
        self.assertTrue(result)

    async def test_not_and_false_false(self) -> None:
        result, _ = await self.call("not_and", [False, False], return_type=bool)
        self.assertFalse(result)

    async def test_not_and_true_true(self) -> None:
        result, _ = await self.call("not_and", [True, True], return_type=bool)
        self.assertFalse(result)

    async def test_not_and_true_false(self) -> None:
        result, _ = await self.call("not_and", [True, False], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # not_or  (not a or b)  — precedence: (not a) or b
    # ------------------------------------------------------------------

    async def test_not_or_false_false(self) -> None:
        result, _ = await self.call("not_or", [False, False], return_type=bool)
        self.assertTrue(result)

    async def test_not_or_false_true(self) -> None:
        result, _ = await self.call("not_or", [False, True], return_type=bool)
        self.assertTrue(result)

    async def test_not_or_true_false(self) -> None:
        result, _ = await self.call("not_or", [True, False], return_type=bool)
        self.assertFalse(result)

    async def test_not_or_true_true(self) -> None:
        result, _ = await self.call("not_or", [True, True], return_type=bool)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # not_not  (double negation)
    # ------------------------------------------------------------------

    async def test_not_not_true(self) -> None:
        result, _ = await self.call("not_not", [True], return_type=bool)
        self.assertTrue(result)

    async def test_not_not_false(self) -> None:
        result, _ = await self.call("not_not", [False], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # short-circuit and  (right operand divides by c; c=0 faults if evaluated)
    # ------------------------------------------------------------------

    async def test_and_sc_false_skips_rhs(self) -> None:
        """False and (1 // 0 == 0) must return False without faulting."""
        result, _ = await self.call("and_sc", [False, 1, 0], return_type=bool)
        self.assertFalse(result)

    async def test_and_sc_true_zero_dividend(self) -> None:
        """True and (0 // 1 == 0) — right is evaluated: 0 // 1 == 0 is True."""
        result, _ = await self.call("and_sc", [True, 0, 1], return_type=bool)
        self.assertTrue(result)

    async def test_and_sc_true_nonzero_result(self) -> None:
        """True and (4 // 2 == 0) — right is evaluated: 4 // 2 == 2, 2 == 0 is False."""
        result, _ = await self.call("and_sc", [True, 4, 2], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # short-circuit or  (right operand divides by c; c=0 faults if evaluated)
    # ------------------------------------------------------------------

    async def test_or_sc_true_skips_rhs(self) -> None:
        """True or (1 // 0 == 0) must return True without faulting."""
        result, _ = await self.call("or_sc", [True, 1, 0], return_type=bool)
        self.assertTrue(result)

    async def test_or_sc_false_zero_dividend(self) -> None:
        """False or (0 // 1 == 0) — right is evaluated: 0 // 1 == 0 is True."""
        result, _ = await self.call("or_sc", [False, 0, 1], return_type=bool)
        self.assertTrue(result)

    async def test_or_sc_false_nonzero_result(self) -> None:
        """False or (4 // 2 == 0) — right is evaluated: 4 // 2 == 2, 2 == 0 is False."""
        result, _ = await self.call("or_sc", [False, 4, 2], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # compile-time type errors (operands must be bool)
    # ------------------------------------------------------------------

    def test_and_with_int_operands_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(x: int, y: int) -> bool:
    return x and y
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_or_with_int_operands_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(x: int, y: int) -> bool:
    return x or y
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_not_with_int_operand_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(x: int) -> bool:
    return not x
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)


if __name__ == "__main__":
    unittest.main()
