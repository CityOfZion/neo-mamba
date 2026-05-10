import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestBitwise(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef((HERE / "bitwise.py").read_text(), str(HERE / "bitwise"))
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./bitwise.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"bitwise{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # bitwise_and
    # ------------------------------------------------------------------

    async def test_and_basic(self) -> None:
        result, _ = await self.call("bitwise_and", [0b1100, 0b1010], return_type=int)
        self.assertEqual(result, 0b1000)  # 8

    async def test_and_mask(self) -> None:
        result, _ = await self.call("bitwise_and", [0xFF, 0x0F], return_type=int)
        self.assertEqual(result, 15)

    async def test_and_all_ones_mask(self) -> None:
        # -1 in two's complement is all 1-bits; -1 & x = x
        result, _ = await self.call("bitwise_and", [-1, 5], return_type=int)
        self.assertEqual(result, 5)

    async def test_and_zero(self) -> None:
        result, _ = await self.call("bitwise_and", [0, 0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # bitwise_or
    # ------------------------------------------------------------------

    async def test_or_basic(self) -> None:
        result, _ = await self.call("bitwise_or", [0b1100, 0b1010], return_type=int)
        self.assertEqual(result, 0b1110)  # 14

    async def test_or_zero(self) -> None:
        result, _ = await self.call("bitwise_or", [0, 0], return_type=int)
        self.assertEqual(result, 0)

    async def test_or_negative_identity(self) -> None:
        # -1 | 0 = -1
        result, _ = await self.call("bitwise_or", [-1, 0], return_type=int)
        self.assertEqual(result, -1)

    # ------------------------------------------------------------------
    # bitwise_xor
    # ------------------------------------------------------------------

    async def test_xor_basic(self) -> None:
        result, _ = await self.call("bitwise_xor", [0b1100, 0b1010], return_type=int)
        self.assertEqual(result, 0b0110)  # 6

    async def test_xor_self_is_zero(self) -> None:
        result, _ = await self.call("bitwise_xor", [5, 5], return_type=int)
        self.assertEqual(result, 0)

    async def test_xor_negative_self_is_zero(self) -> None:
        result, _ = await self.call("bitwise_xor", [-1, -1], return_type=int)
        self.assertEqual(result, 0)

    async def test_xor_negative_with_zero(self) -> None:
        result, _ = await self.call("bitwise_xor", [-1, 0], return_type=int)
        self.assertEqual(result, -1)

    # ------------------------------------------------------------------
    # bitwise_not  (~x = -(x+1), matches Python exactly)
    # ------------------------------------------------------------------

    async def test_not_zero(self) -> None:
        result, _ = await self.call("bitwise_not", [0], return_type=int)
        self.assertEqual(result, -1)

    async def test_not_positive(self) -> None:
        result, _ = await self.call("bitwise_not", [5], return_type=int)
        self.assertEqual(result, -6)

    async def test_not_minus_one(self) -> None:
        result, _ = await self.call("bitwise_not", [-1], return_type=int)
        self.assertEqual(result, 0)

    async def test_not_negative(self) -> None:
        result, _ = await self.call("bitwise_not", [-6], return_type=int)
        self.assertEqual(result, 5)

    # ------------------------------------------------------------------
    # left_shift
    # ------------------------------------------------------------------

    async def test_shl_basic(self) -> None:
        result, _ = await self.call("left_shift", [1, 4], return_type=int)
        self.assertEqual(result, 16)

    async def test_shl_multiple_bits(self) -> None:
        result, _ = await self.call("left_shift", [3, 2], return_type=int)
        self.assertEqual(result, 12)

    async def test_shl_negative_value(self) -> None:
        # -1 << 2 = -4 (sign bit propagates in two's complement)
        result, _ = await self.call("left_shift", [-1, 2], return_type=int)
        self.assertEqual(result, -4)

    async def test_shl_by_zero(self) -> None:
        result, _ = await self.call("left_shift", [7, 0], return_type=int)
        self.assertEqual(result, 7)

    # ------------------------------------------------------------------
    # right_shift  (arithmetic / sign-extending, matches Python)
    # ------------------------------------------------------------------

    async def test_shr_basic(self) -> None:
        result, _ = await self.call("right_shift", [256, 2], return_type=int)
        self.assertEqual(result, 64)

    async def test_shr_odd_value(self) -> None:
        # 7 >> 1 = 3 (truncates toward zero, same as Python floor for positives)
        result, _ = await self.call("right_shift", [7, 1], return_type=int)
        self.assertEqual(result, 3)

    async def test_shr_negative_arithmetic(self) -> None:
        # -8 >> 1 = -4 (arithmetic right shift, sign-extending — matches Python)
        result, _ = await self.call("right_shift", [-8, 1], return_type=int)
        self.assertEqual(result, -4)

    async def test_shr_minus_one(self) -> None:
        # -1 >> 1 = -1 (all sign bits, stays -1)
        result, _ = await self.call("right_shift", [-1, 1], return_type=int)
        self.assertEqual(result, -1)

    async def test_shr_by_zero(self) -> None:
        result, _ = await self.call("right_shift", [42, 0], return_type=int)
        self.assertEqual(result, 42)

    # ------------------------------------------------------------------
    # Augmented assignments
    # ------------------------------------------------------------------

    async def test_aug_and(self) -> None:
        result, _ = await self.call("aug_and", [0b1111, 0b1010], return_type=int)
        self.assertEqual(result, 10)  # 0b1010

    async def test_aug_or(self) -> None:
        result, _ = await self.call("aug_or", [0b0101, 0b1010], return_type=int)
        self.assertEqual(result, 15)  # 0b1111

    async def test_aug_xor(self) -> None:
        result, _ = await self.call("aug_xor", [0b1111, 0b0101], return_type=int)
        self.assertEqual(result, 10)  # 0b1010

    async def test_aug_shl(self) -> None:
        result, _ = await self.call("aug_shl", [1, 3], return_type=int)
        self.assertEqual(result, 8)

    async def test_aug_shr(self) -> None:
        result, _ = await self.call("aug_shr", [16, 2], return_type=int)
        self.assertEqual(result, 4)

    # ------------------------------------------------------------------
    # Compile-time type errors
    # ------------------------------------------------------------------

    def test_invert_on_bool_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(b: bool) -> int:
    return ~b
"""
        with self.assertRaises(TypecheckError):
            compile_to_nef(src, "/tmp/throwaway")

    def test_and_on_str_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(a: str, b: str) -> str:
    return a & b
"""
        with self.assertRaises(TypecheckError):
            compile_to_nef(src, "/tmp/throwaway")


if __name__ == "__main__":
    unittest.main()
