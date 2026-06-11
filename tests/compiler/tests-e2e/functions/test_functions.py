import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestFunctions(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "functions.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./functions.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"functions{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # helper calls (chained CALL_L, non-@public callee)
    # ------------------------------------------------------------------

    async def test_compound_basic(self) -> None:
        # 3*4 + 5 = 17
        result, _ = await self.call("compound", [3, 4, 5], return_type=int)
        self.assertEqual(result, 17)

    async def test_compound_zero_mul(self) -> None:
        # 0*99 + 7 = 7
        result, _ = await self.call("compound", [0, 99, 7], return_type=int)
        self.assertEqual(result, 7)

    async def test_compound_all_same(self) -> None:
        # 2*2 + 2 = 6
        result, _ = await self.call("compound", [2, 2, 2], return_type=int)
        self.assertEqual(result, 6)

    async def test_compound_negative(self) -> None:
        # -3*4 + 1 = -11
        result, _ = await self.call("compound", [-3, 4, 1], return_type=int)
        self.assertEqual(result, -11)

    # ------------------------------------------------------------------
    # direct recursion — factorial
    # ------------------------------------------------------------------

    async def test_factorial_zero(self) -> None:
        result, _ = await self.call("factorial", [0], return_type=int)
        self.assertEqual(result, 1)

    async def test_factorial_one(self) -> None:
        result, _ = await self.call("factorial", [1], return_type=int)
        self.assertEqual(result, 1)

    async def test_factorial_five(self) -> None:
        result, _ = await self.call("factorial", [5], return_type=int)
        self.assertEqual(result, 120)

    async def test_factorial_ten(self) -> None:
        result, _ = await self.call("factorial", [10], return_type=int)
        self.assertEqual(result, 3628800)

    # ------------------------------------------------------------------
    # double recursion — fibonacci
    # ------------------------------------------------------------------

    async def test_fibonacci_zero(self) -> None:
        result, _ = await self.call("fibonacci", [0], return_type=int)
        self.assertEqual(result, 0)

    async def test_fibonacci_one(self) -> None:
        result, _ = await self.call("fibonacci", [1], return_type=int)
        self.assertEqual(result, 1)

    async def test_fibonacci_two(self) -> None:
        result, _ = await self.call("fibonacci", [2], return_type=int)
        self.assertEqual(result, 1)

    async def test_fibonacci_five(self) -> None:
        result, _ = await self.call("fibonacci", [5], return_type=int)
        self.assertEqual(result, 5)

    async def test_fibonacci_ten(self) -> None:
        # fib(10) = 55; max call depth ~10, well within NeoVM limits
        result, _ = await self.call("fibonacci", [10], return_type=int)
        self.assertEqual(result, 55)

    # ------------------------------------------------------------------
    # mutual recursion (_is_even / _is_odd forward reference)
    # ------------------------------------------------------------------

    async def test_check_even_zero(self) -> None:
        result, _ = await self.call("check_even", [0], return_type=bool)
        self.assertTrue(result)

    async def test_check_even_positive(self) -> None:
        result, _ = await self.call("check_even", [4], return_type=bool)
        self.assertTrue(result)

    async def test_check_even_odd_input(self) -> None:
        result, _ = await self.call("check_even", [7], return_type=bool)
        self.assertFalse(result)

    async def test_check_odd_one(self) -> None:
        result, _ = await self.call("check_odd", [1], return_type=bool)
        self.assertTrue(result)

    async def test_check_odd_even_input(self) -> None:
        result, _ = await self.call("check_odd", [8], return_type=bool)
        self.assertFalse(result)

    async def test_check_odd_zero(self) -> None:
        result, _ = await self.call("check_odd", [0], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # mutable argument (STARG / LDARG round-trip)
    # ------------------------------------------------------------------

    async def test_mutable_arg_positive(self) -> None:
        result, _ = await self.call("mutable_arg", [5], return_type=int)
        self.assertEqual(result, 15)

    async def test_mutable_arg_zero(self) -> None:
        result, _ = await self.call("mutable_arg", [0], return_type=int)
        self.assertEqual(result, 10)

    async def test_mutable_arg_negative(self) -> None:
        result, _ = await self.call("mutable_arg", [-3], return_type=int)
        self.assertEqual(result, 7)

    # ------------------------------------------------------------------
    # iterative GCD — both args reassigned each iteration
    # ------------------------------------------------------------------

    async def test_gcd_basic(self) -> None:
        result, _ = await self.call("gcd", [12, 8], return_type=int)
        self.assertEqual(result, 4)

    async def test_gcd_larger(self) -> None:
        result, _ = await self.call("gcd", [100, 75], return_type=int)
        self.assertEqual(result, 25)

    async def test_gcd_coprime(self) -> None:
        result, _ = await self.call("gcd", [17, 5], return_type=int)
        self.assertEqual(result, 1)

    async def test_gcd_second_zero(self) -> None:
        # b=0 → loop never runs → return a
        result, _ = await self.call("gcd", [7, 0], return_type=int)
        self.assertEqual(result, 7)

    async def test_gcd_first_zero(self) -> None:
        # a=0, b=7 → one iteration: temp=7, b=0%7=0, a=7 → return 7
        result, _ = await self.call("gcd", [0, 7], return_type=int)
        self.assertEqual(result, 7)

    # ------------------------------------------------------------------
    # void function (bare RET — no PUSHNULL)
    # ------------------------------------------------------------------

    async def test_void_noop_returns_none(self) -> None:
        # -> None function emits bare RET; NeoVM returns no stack item.
        result, _ = await self.call("void_noop", [42], return_type=None)
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # discarded return value (DROP opcode)
    # ------------------------------------------------------------------

    async def test_discard_return_value(self) -> None:
        # _double(5) is called but its result is discarded; function returns 5+1=6
        result, _ = await self.call("discard_return", [5], return_type=int)
        self.assertEqual(result, 6)

    async def test_discard_return_value_zero(self) -> None:
        result, _ = await self.call("discard_return", [2], return_type=int)
        self.assertEqual(result, 3)


if __name__ == "__main__":
    unittest.main()
