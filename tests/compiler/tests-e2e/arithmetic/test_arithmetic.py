import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestArithmetic(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef((HERE / "arithmetic.py").read_text(), str(HERE / "arithmetic"))
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./arithmetic.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"arithmetic{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # add
    # ------------------------------------------------------------------

    async def test_add_zero_plus_zero(self) -> None:
        result, _ = await self.call("add", [0, 0], return_type=int)
        self.assertEqual(result, 0)

    async def test_add_two_positive_numbers(self) -> None:
        result, _ = await self.call("add", [1, 1], return_type=int)
        self.assertEqual(result, 2)

    async def test_add_larger_positive_numbers(self) -> None:
        result, _ = await self.call("add", [100, 200], return_type=int)
        self.assertEqual(result, 300)

    async def test_add_negative_and_positive_result_zero(self) -> None:
        result, _ = await self.call("add", [-1, 1], return_type=int)
        self.assertEqual(result, 0)

    async def test_add_positive_and_negative_result_positive(self) -> None:
        result, _ = await self.call("add", [5, -3], return_type=int)
        self.assertEqual(result, 2)

    async def test_add_positive_and_negative_result_negative(self) -> None:
        result, _ = await self.call("add", [3, -5], return_type=int)
        self.assertEqual(result, -2)

    async def test_add_two_negative_numbers(self) -> None:
        result, _ = await self.call("add", [-3, -5], return_type=int)
        self.assertEqual(result, -8)

    async def test_add_zero_is_left_identity(self) -> None:
        result, _ = await self.call("add", [0, 7], return_type=int)
        self.assertEqual(result, 7)

    async def test_add_zero_is_right_identity(self) -> None:
        result, _ = await self.call("add", [7, 0], return_type=int)
        self.assertEqual(result, 7)

    async def test_add_large_numbers(self) -> None:
        """2^62 + 2^62 = 2^63 — exercises multi-word integer arithmetic well within the 32-byte VM limit."""
        result, _ = await self.call("add", [2**62, 2**62], return_type=int)
        self.assertEqual(result, 2**63)

    async def test_add_large_negative_numbers(self) -> None:
        result, _ = await self.call("add", [-(2**62), -(2**62)], return_type=int)
        self.assertEqual(result, -(2**63))

    async def test_add_is_commutative(self) -> None:
        """a + b must equal b + a — verifies operand order is not swapped in codegen."""
        ab, _ = await self.call("add", [3, 5], return_type=int)
        ba, _ = await self.call("add", [5, 3], return_type=int)
        self.assertEqual(ab, ba)

    # ------------------------------------------------------------------
    # subtract
    # ------------------------------------------------------------------

    async def test_subtract_positive_numbers(self) -> None:
        result, _ = await self.call("subtract", [5, 3], return_type=int)
        self.assertEqual(result, 2)

    async def test_subtract_zero_from_zero(self) -> None:
        result, _ = await self.call("subtract", [0, 0], return_type=int)
        self.assertEqual(result, 0)

    async def test_subtract_produces_negative(self) -> None:
        result, _ = await self.call("subtract", [3, 5], return_type=int)
        self.assertEqual(result, -2)

    async def test_subtract_two_negatives(self) -> None:
        result, _ = await self.call("subtract", [-3, -5], return_type=int)
        self.assertEqual(result, 2)

    async def test_subtract_large_numbers(self) -> None:
        result, _ = await self.call("subtract", [2**63, 2**62], return_type=int)
        self.assertEqual(result, 2**62)

    # ------------------------------------------------------------------
    # multiply
    # ------------------------------------------------------------------

    async def test_multiply_positive_numbers(self) -> None:
        result, _ = await self.call("multiply", [3, 4], return_type=int)
        self.assertEqual(result, 12)

    async def test_multiply_by_zero(self) -> None:
        result, _ = await self.call("multiply", [999, 0], return_type=int)
        self.assertEqual(result, 0)

    async def test_multiply_by_one(self) -> None:
        result, _ = await self.call("multiply", [42, 1], return_type=int)
        self.assertEqual(result, 42)

    async def test_multiply_negative_by_positive(self) -> None:
        result, _ = await self.call("multiply", [-3, 4], return_type=int)
        self.assertEqual(result, -12)

    async def test_multiply_two_negatives(self) -> None:
        result, _ = await self.call("multiply", [-3, -4], return_type=int)
        self.assertEqual(result, 12)

    async def test_multiply_large_numbers(self) -> None:
        result, _ = await self.call("multiply", [2**31, 2**31], return_type=int)
        self.assertEqual(result, 2**62)

    # ------------------------------------------------------------------
    # divide  (NeoVM truncates toward zero — differs from Python // for negatives)
    # ------------------------------------------------------------------

    async def test_divide_positive_numbers(self) -> None:
        result, _ = await self.call("divide", [10, 3], return_type=int)
        self.assertEqual(result, 3)

    async def test_divide_exact(self) -> None:
        result, _ = await self.call("divide", [12, 4], return_type=int)
        self.assertEqual(result, 3)

    async def test_divide_zero_dividend(self) -> None:
        result, _ = await self.call("divide", [0, 5], return_type=int)
        self.assertEqual(result, 0)

    async def test_divide_negative_dividend_truncates_toward_zero(self) -> None:
        """NeoVM DIV truncates toward zero: -7 // 2 = -3, not -4 as Python floor division would give."""
        result, _ = await self.call("divide", [-7, 2], return_type=int)
        self.assertEqual(result, -3)

    async def test_divide_negative_divisor_truncates_toward_zero(self) -> None:
        result, _ = await self.call("divide", [7, -2], return_type=int)
        self.assertEqual(result, -3)

    async def test_divide_both_negative(self) -> None:
        result, _ = await self.call("divide", [-7, -2], return_type=int)
        self.assertEqual(result, 3)

    # ------------------------------------------------------------------
    # modulo  (NeoVM remainder has the sign of the dividend — differs from Python)
    # ------------------------------------------------------------------

    async def test_modulo_positive_numbers(self) -> None:
        result, _ = await self.call("modulo", [10, 3], return_type=int)
        self.assertEqual(result, 1)

    async def test_modulo_exact_division(self) -> None:
        result, _ = await self.call("modulo", [12, 4], return_type=int)
        self.assertEqual(result, 0)

    async def test_modulo_negative_dividend(self) -> None:
        """NeoVM MOD sign follows the dividend: -7 % 2 = -1 (not 1 as Python gives)."""
        result, _ = await self.call("modulo", [-7, 2], return_type=int)
        self.assertEqual(result, -1)

    async def test_modulo_negative_divisor(self) -> None:
        """NeoVM MOD sign follows the dividend: 7 % -2 = 1 (not -1 as Python gives)."""
        result, _ = await self.call("modulo", [7, -2], return_type=int)
        self.assertEqual(result, 1)

    async def test_modulo_both_negative(self) -> None:
        result, _ = await self.call("modulo", [-7, -2], return_type=int)
        self.assertEqual(result, -1)

    # ------------------------------------------------------------------
    # power
    # ------------------------------------------------------------------

    async def test_power_basic(self) -> None:
        result, _ = await self.call("power", [2, 10], return_type=int)
        self.assertEqual(result, 1024)

    async def test_power_zero_exponent(self) -> None:
        result, _ = await self.call("power", [99, 0], return_type=int)
        self.assertEqual(result, 1)

    async def test_power_one_base(self) -> None:
        result, _ = await self.call("power", [1, 100], return_type=int)
        self.assertEqual(result, 1)

    async def test_power_zero_base(self) -> None:
        result, _ = await self.call("power", [0, 5], return_type=int)
        self.assertEqual(result, 0)

    async def test_power_large_result(self) -> None:
        result, _ = await self.call("power", [2, 62], return_type=int)
        self.assertEqual(result, 2**62)

    async def test_power_negative_base(self) -> None:
        result, _ = await self.call("power", [-2, 3], return_type=int)
        self.assertEqual(result, -8)

    def test_power_negative_literal_exponent_is_compile_error(self) -> None:
        """Negative literal exponents would produce a float in Python — rejected at compile time."""
        src = """
from neo3.sc.compiletime import public
@public
def f(x: int) -> int:
    return x ** -1
"""
        with self.assertRaises(TypecheckError):
            compile_to_nef(src, "/tmp/throwaway")

    # ------------------------------------------------------------------
    # abs
    # ------------------------------------------------------------------

    async def test_abs_positive(self) -> None:
        result, _ = await self.call("absolute", [5], return_type=int)
        self.assertEqual(result, 5)

    async def test_abs_negative(self) -> None:
        result, _ = await self.call("absolute", [-5], return_type=int)
        self.assertEqual(result, 5)

    async def test_abs_zero(self) -> None:
        result, _ = await self.call("absolute", [0], return_type=int)
        self.assertEqual(result, 0)

    async def test_abs_large_negative(self) -> None:
        result, _ = await self.call("absolute", [-(2**62)], return_type=int)
        self.assertEqual(result, 2**62)

    # ------------------------------------------------------------------
    # min / max
    # ------------------------------------------------------------------

    async def test_min_picks_smaller(self) -> None:
        result, _ = await self.call("minimum", [3, 7], return_type=int)
        self.assertEqual(result, 3)

    async def test_min_picks_smaller_reversed(self) -> None:
        result, _ = await self.call("minimum", [7, 3], return_type=int)
        self.assertEqual(result, 3)

    async def test_min_equal_values(self) -> None:
        result, _ = await self.call("minimum", [5, 5], return_type=int)
        self.assertEqual(result, 5)

    async def test_min_with_negative(self) -> None:
        result, _ = await self.call("minimum", [-3, 2], return_type=int)
        self.assertEqual(result, -3)

    async def test_max_picks_larger(self) -> None:
        result, _ = await self.call("maximum", [3, 7], return_type=int)
        self.assertEqual(result, 7)

    async def test_max_picks_larger_reversed(self) -> None:
        result, _ = await self.call("maximum", [7, 3], return_type=int)
        self.assertEqual(result, 7)

    async def test_max_equal_values(self) -> None:
        result, _ = await self.call("maximum", [5, 5], return_type=int)
        self.assertEqual(result, 5)

    async def test_max_with_negative(self) -> None:
        result, _ = await self.call("maximum", [-3, 2], return_type=int)
        self.assertEqual(result, 2)

    # ------------------------------------------------------------------
    # negate
    # ------------------------------------------------------------------

    async def test_negate_positive(self) -> None:
        result, _ = await self.call("negate", [5], return_type=int)
        self.assertEqual(result, -5)

    async def test_negate_negative(self) -> None:
        result, _ = await self.call("negate", [-3], return_type=int)
        self.assertEqual(result, 3)

    async def test_negate_zero(self) -> None:
        result, _ = await self.call("negate", [0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # augmented assignment
    # ------------------------------------------------------------------

    async def test_aug_add(self) -> None:
        result, _ = await self.call("aug_add", [10, 3], return_type=int)
        self.assertEqual(result, 13)

    async def test_aug_sub(self) -> None:
        result, _ = await self.call("aug_sub", [10, 3], return_type=int)
        self.assertEqual(result, 7)

    async def test_aug_mul(self) -> None:
        result, _ = await self.call("aug_mul", [4, 5], return_type=int)
        self.assertEqual(result, 20)

    async def test_aug_div(self) -> None:
        result, _ = await self.call("aug_div", [10, 3], return_type=int)
        self.assertEqual(result, 3)

    async def test_aug_mod(self) -> None:
        result, _ = await self.call("aug_mod", [10, 3], return_type=int)
        self.assertEqual(result, 1)

    async def test_aug_matches_non_aug(self) -> None:
        """Augmented assignment must produce the same result as the explicit binary op."""
        for a, b in [(10, 3), (-7, 2), (0, 5)]:
            add_r, _ = await self.call("add", [a, b], return_type=int)
            aug_r, _ = await self.call("aug_add", [a, b], return_type=int)
            self.assertEqual(add_r, aug_r, f"aug_add mismatch for {a}, {b}")

            sub_r, _ = await self.call("subtract", [a, b], return_type=int)
            aug_r, _ = await self.call("aug_sub", [a, b], return_type=int)
            self.assertEqual(sub_r, aug_r, f"aug_sub mismatch for {a}, {b}")

            mul_r, _ = await self.call("multiply", [a, b], return_type=int)
            aug_r, _ = await self.call("aug_mul", [a, b], return_type=int)
            self.assertEqual(mul_r, aug_r, f"aug_mul mismatch for {a}, {b}")


if __name__ == "__main__":
    unittest.main()
