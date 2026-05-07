import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestComparison(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef((HERE / "comparison.py").read_text(), str(HERE / "comparison"))
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./comparison.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"comparison{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # int ==
    # ------------------------------------------------------------------

    async def test_int_eq_equal_values(self) -> None:
        result, _ = await self.call("int_eq", [1, 1], return_type=bool)
        self.assertTrue(result)

    async def test_int_eq_unequal_values(self) -> None:
        result, _ = await self.call("int_eq", [1, 2], return_type=bool)
        self.assertFalse(result)

    async def test_int_eq_both_zero(self) -> None:
        result, _ = await self.call("int_eq", [0, 0], return_type=bool)
        self.assertTrue(result)

    async def test_int_eq_both_negative_equal(self) -> None:
        result, _ = await self.call("int_eq", [-1, -1], return_type=bool)
        self.assertTrue(result)

    async def test_int_eq_negative_and_positive(self) -> None:
        result, _ = await self.call("int_eq", [-1, 1], return_type=bool)
        self.assertFalse(result)

    async def test_int_eq_large_equal(self) -> None:
        result, _ = await self.call("int_eq", [2**62, 2**62], return_type=bool)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # int !=
    # ------------------------------------------------------------------

    async def test_int_ne_unequal_values(self) -> None:
        result, _ = await self.call("int_ne", [1, 2], return_type=bool)
        self.assertTrue(result)

    async def test_int_ne_equal_values(self) -> None:
        result, _ = await self.call("int_ne", [1, 1], return_type=bool)
        self.assertFalse(result)

    async def test_int_ne_negative_and_positive(self) -> None:
        result, _ = await self.call("int_ne", [-1, 1], return_type=bool)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # int <
    # ------------------------------------------------------------------

    async def test_int_lt_smaller_is_less(self) -> None:
        result, _ = await self.call("int_lt", [1, 2], return_type=bool)
        self.assertTrue(result)

    async def test_int_lt_larger_is_not_less(self) -> None:
        result, _ = await self.call("int_lt", [2, 1], return_type=bool)
        self.assertFalse(result)

    async def test_int_lt_equal_is_not_less(self) -> None:
        result, _ = await self.call("int_lt", [1, 1], return_type=bool)
        self.assertFalse(result)

    async def test_int_lt_negative_less_than_zero(self) -> None:
        result, _ = await self.call("int_lt", [-1, 0], return_type=bool)
        self.assertTrue(result)

    async def test_int_lt_zero_not_less_than_negative(self) -> None:
        result, _ = await self.call("int_lt", [0, -1], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # int <=
    # ------------------------------------------------------------------

    async def test_int_le_equal_values(self) -> None:
        result, _ = await self.call("int_le", [1, 1], return_type=bool)
        self.assertTrue(result)

    async def test_int_le_smaller_left(self) -> None:
        result, _ = await self.call("int_le", [1, 2], return_type=bool)
        self.assertTrue(result)

    async def test_int_le_larger_left(self) -> None:
        result, _ = await self.call("int_le", [2, 1], return_type=bool)
        self.assertFalse(result)

    async def test_int_le_both_negative_equal(self) -> None:
        result, _ = await self.call("int_le", [-1, -1], return_type=bool)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # int >
    # ------------------------------------------------------------------

    async def test_int_gt_larger_is_greater(self) -> None:
        result, _ = await self.call("int_gt", [2, 1], return_type=bool)
        self.assertTrue(result)

    async def test_int_gt_smaller_is_not_greater(self) -> None:
        result, _ = await self.call("int_gt", [1, 2], return_type=bool)
        self.assertFalse(result)

    async def test_int_gt_equal_is_not_greater(self) -> None:
        result, _ = await self.call("int_gt", [1, 1], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # int >=
    # ------------------------------------------------------------------

    async def test_int_ge_equal_values(self) -> None:
        result, _ = await self.call("int_ge", [1, 1], return_type=bool)
        self.assertTrue(result)

    async def test_int_ge_larger_left(self) -> None:
        result, _ = await self.call("int_ge", [2, 1], return_type=bool)
        self.assertTrue(result)

    async def test_int_ge_smaller_left(self) -> None:
        result, _ = await self.call("int_ge", [1, 2], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # str ==
    # ------------------------------------------------------------------

    async def test_str_eq_identical(self) -> None:
        result, _ = await self.call("str_eq", ["hello", "hello"], return_type=bool)
        self.assertTrue(result)

    async def test_str_eq_different(self) -> None:
        result, _ = await self.call("str_eq", ["hello", "world"], return_type=bool)
        self.assertFalse(result)

    async def test_str_eq_empty_strings(self) -> None:
        result, _ = await self.call("str_eq", ["", ""], return_type=bool)
        self.assertTrue(result)

    async def test_str_eq_case_sensitive(self) -> None:
        """str comparison is byte-level — 'A' (0x41) != 'a' (0x61)."""
        result, _ = await self.call("str_eq", ["A", "a"], return_type=bool)
        self.assertFalse(result)

    async def test_str_eq_empty_vs_nonempty(self) -> None:
        result, _ = await self.call("str_eq", ["", "x"], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # str !=
    # ------------------------------------------------------------------

    async def test_str_ne_different(self) -> None:
        result, _ = await self.call("str_ne", ["hello", "world"], return_type=bool)
        self.assertTrue(result)

    async def test_str_ne_identical(self) -> None:
        result, _ = await self.call("str_ne", ["hello", "hello"], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # bytes ==
    # ------------------------------------------------------------------

    async def test_bytes_eq_identical(self) -> None:
        result, _ = await self.call("bytes_eq", [b"abc", b"abc"], return_type=bool)
        self.assertTrue(result)

    async def test_bytes_eq_different(self) -> None:
        result, _ = await self.call("bytes_eq", [b"abc", b"def"], return_type=bool)
        self.assertFalse(result)

    async def test_bytes_eq_empty(self) -> None:
        result, _ = await self.call("bytes_eq", [b"", b""], return_type=bool)
        self.assertTrue(result)

    async def test_bytes_eq_different_lengths(self) -> None:
        result, _ = await self.call("bytes_eq", [b"ab", b"abc"], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # bytes !=
    # ------------------------------------------------------------------

    async def test_bytes_ne_different(self) -> None:
        result, _ = await self.call("bytes_ne", [b"abc", b"def"], return_type=bool)
        self.assertTrue(result)

    async def test_bytes_ne_identical(self) -> None:
        result, _ = await self.call("bytes_ne", [b"abc", b"abc"], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # chained comparison (lo <= x <= hi)
    # ------------------------------------------------------------------

    async def test_chained_value_inside_range(self) -> None:
        result, _ = await self.call("in_range", [2, 1, 3], return_type=bool)
        self.assertTrue(result)

    async def test_chained_value_at_lower_bound(self) -> None:
        result, _ = await self.call("in_range", [1, 1, 3], return_type=bool)
        self.assertTrue(result)

    async def test_chained_value_at_upper_bound(self) -> None:
        result, _ = await self.call("in_range", [3, 1, 3], return_type=bool)
        self.assertTrue(result)

    async def test_chained_value_below_range(self) -> None:
        result, _ = await self.call("in_range", [0, 1, 3], return_type=bool)
        self.assertFalse(result)

    async def test_chained_value_above_range(self) -> None:
        result, _ = await self.call("in_range", [4, 1, 3], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # compile-time errors — ordering on str/bytes/bytearray rejected
    # ------------------------------------------------------------------

    def test_str_lt_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(a: str, b: str) -> bool:
    return a < b
"""
        with self.assertRaises(TypecheckError):
            compile_to_nef(src, "/tmp/throwaway")

    def test_str_gt_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(a: str, b: str) -> bool:
    return a > b
"""
        with self.assertRaises(TypecheckError):
            compile_to_nef(src, "/tmp/throwaway")

    def test_bytes_lt_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(a: bytes, b: bytes) -> bool:
    return a < b
"""
        with self.assertRaises(TypecheckError):
            compile_to_nef(src, "/tmp/throwaway")

    def test_bytearray_le_is_compile_error(self) -> None:
        src = """
from neo3.sc.compiletime import public
@public
def f(a: bytearray, b: bytearray) -> bool:
    return a <= b
"""
        with self.assertRaises(TypecheckError):
            compile_to_nef(src, "/tmp/throwaway")

    def test_str_bytes_cross_type_lt_is_compile_error(self) -> None:
        """Cross-type ordering was already rejected; this is a regression test."""
        src = """
from neo3.sc.compiletime import public
@public
def f(a: str, b: bytes) -> bool:
    return a < b
"""
        with self.assertRaises(TypecheckError):
            compile_to_nef(src, "/tmp/throwaway")

    def test_str_bytes_cross_type_eq_folds_to_false(self) -> None:
        """str == bytes folds to constant False at compile time."""
        src = """
from neo3.sc.compiletime import public
@public
def f(a: str, b: bytes) -> bool:
    return a == b
"""
        # Should compile without error (constant fold) and always return False
        compile_to_nef(src, "/tmp/throwaway_eq")
        import os

        for ext in (".nef", ".manifest.json"):
            path = f"/tmp/throwaway_eq{ext}"
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
