import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestCollectionTypes(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "collection_types.py").read_text(), str(HERE / "collection_types")
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./collection_types.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"collection_types{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # str — length
    # ------------------------------------------------------------------

    async def test_str_len_empty(self) -> None:
        result, _ = await self.call("str_len", [""], return_type=int)
        self.assertEqual(result, 0)

    async def test_str_len_nonempty(self) -> None:
        result, _ = await self.call("str_len", ["hello"], return_type=int)
        self.assertEqual(result, 5)

    # ------------------------------------------------------------------
    # str — concatenation
    # ------------------------------------------------------------------

    async def test_str_concat_basic(self) -> None:
        result, _ = await self.call("str_concat", ["hello", " world"], return_type=str)
        self.assertEqual(result, "hello world")

    async def test_str_concat_empty_left(self) -> None:
        result, _ = await self.call("str_concat", ["", "abc"], return_type=str)
        self.assertEqual(result, "abc")

    # ------------------------------------------------------------------
    # str — indexing (returns single-char str via SUBSTR count=1)
    # ------------------------------------------------------------------

    async def test_str_index_first(self) -> None:
        result, _ = await self.call("str_index", ["hello", 0], return_type=str)
        self.assertEqual(result, "h")

    async def test_str_index_last(self) -> None:
        result, _ = await self.call("str_index", ["hello", 4], return_type=str)
        self.assertEqual(result, "o")

    async def test_str_index_middle(self) -> None:
        result, _ = await self.call("str_index", ["abcde", 2], return_type=str)
        self.assertEqual(result, "c")

    # ------------------------------------------------------------------
    # str — slicing
    # ------------------------------------------------------------------

    async def test_str_slice_left_basic(self) -> None:
        result, _ = await self.call(
            "str_slice_left", ["hello world", 5], return_type=str
        )
        self.assertEqual(result, "hello")

    async def test_str_slice_left_zero(self) -> None:
        result, _ = await self.call("str_slice_left", ["hello", 0], return_type=str)
        self.assertEqual(result, "")

    async def test_str_slice_mid_basic(self) -> None:
        result, _ = await self.call(
            "str_slice_mid", ["hello world", 6, 11], return_type=str
        )
        self.assertEqual(result, "world")

    async def test_str_slice_mid_inner(self) -> None:
        result, _ = await self.call("str_slice_mid", ["hello", 1, 3], return_type=str)
        self.assertEqual(result, "el")

    async def test_str_slice_rest_basic(self) -> None:
        result, _ = await self.call(
            "str_slice_rest", ["hello world", 6], return_type=str
        )
        self.assertEqual(result, "world")

    async def test_str_slice_rest_from_start(self) -> None:
        result, _ = await self.call("str_slice_rest", ["abc", 0], return_type=str)
        self.assertEqual(result, "abc")

    async def test_str_slice_step2(self) -> None:
        # s[0:6:2] on "abcdef" → picks indices 0,2,4 → "ace"
        result, _ = await self.call("str_slice_step2", ["abcdef"], return_type=str)
        self.assertEqual(result, "ace")

    # ------------------------------------------------------------------
    # bytes — length
    # ------------------------------------------------------------------

    async def test_bytes_len(self) -> None:
        result, _ = await self.call("bytes_len", [], return_type=int)
        self.assertEqual(result, 5)

    # ------------------------------------------------------------------
    # bytes — indexing (returns int, matching Python semantics)
    # ------------------------------------------------------------------

    async def test_bytes_index_first(self) -> None:
        result, _ = await self.call(
            "bytes_index", [b"\x01\x02\x03", 0], return_type=int
        )
        self.assertEqual(result, 1)

    async def test_bytes_index_last(self) -> None:
        result, _ = await self.call(
            "bytes_index", [b"\x01\x02\x03", 2], return_type=int
        )
        self.assertEqual(result, 3)

    # ------------------------------------------------------------------
    # bytes — concatenation and slicing
    # ------------------------------------------------------------------

    async def test_bytes_concat(self) -> None:
        result, _ = await self.call(
            "bytes_concat", [b"\x01\x02", b"\x03\x04"], return_type=bytes
        )
        self.assertEqual(result, b"\x01\x02\x03\x04")

    async def test_bytes_slice(self) -> None:
        result, _ = await self.call(
            "bytes_slice", [b"\x01\x02\x03\x04\x05", 1, 4], return_type=bytes
        )
        self.assertEqual(result, b"\x02\x03\x04")

    async def test_bytes_step_slice(self) -> None:
        # b[0:6:2] on b"\x01\x02\x03\x04\x05\x06" → picks indices 0,2,4 → b"\x01\x03\x05"
        result, _ = await self.call("bytes_step_slice", [], return_type=bytes)
        self.assertEqual(result, b"\x01\x03\x05")

    # ------------------------------------------------------------------
    # bytearray — length, zero-fill, mutation
    # ------------------------------------------------------------------

    async def test_bytearray_len(self) -> None:
        result, _ = await self.call("bytearray_len", [], return_type=int)
        self.assertEqual(result, 5)

    async def test_bytearray_index_zero_fill(self) -> None:
        # bytearray(n) produces a zero-filled Buffer
        result, _ = await self.call("bytearray_index_zero_fill", [], return_type=int)
        self.assertEqual(result, 0)

    async def test_bytearray_mutate(self) -> None:
        result, _ = await self.call("bytearray_mutate", [], return_type=int)
        self.assertEqual(result, 99)

    # ------------------------------------------------------------------
    # list[T] — length
    # ------------------------------------------------------------------

    async def test_list_empty_len(self) -> None:
        result, _ = await self.call("list_empty_len", [], return_type=int)
        self.assertEqual(result, 0)

    async def test_list_literal_len(self) -> None:
        result, _ = await self.call("list_literal_len", [], return_type=int)
        self.assertEqual(result, 3)

    async def test_list_append_len(self) -> None:
        result, _ = await self.call("list_append_len", [], return_type=int)
        self.assertEqual(result, 2)

    # ------------------------------------------------------------------
    # list[T] — indexing and mutation
    # ------------------------------------------------------------------

    async def test_list_literal_index(self) -> None:
        result, _ = await self.call("list_literal_index", [], return_type=int)
        self.assertEqual(result, 20)

    async def test_list_mutate(self) -> None:
        result, _ = await self.call("list_mutate", [], return_type=int)
        self.assertEqual(result, 99)

    # ------------------------------------------------------------------
    # list[T] — iteration
    # ------------------------------------------------------------------

    async def test_list_for_sum(self) -> None:
        result, _ = await self.call("list_for_sum", [], return_type=int)
        self.assertEqual(result, 15)

    async def test_list_build_and_sum(self) -> None:
        result, _ = await self.call("list_build_and_sum", [], return_type=int)
        self.assertEqual(result, 60)

    async def test_list_bool_count(self) -> None:
        # [True, False, True, True, False] → 3 True values
        result, _ = await self.call("list_bool_count", [], return_type=int)
        self.assertEqual(result, 3)

    # ------------------------------------------------------------------
    # dict[K, V] — set/get and length
    # ------------------------------------------------------------------

    async def test_dict_set_get(self) -> None:
        result, _ = await self.call("dict_set_get", [], return_type=int)
        self.assertEqual(result, 42)

    async def test_dict_literal_len(self) -> None:
        result, _ = await self.call("dict_literal_len", [], return_type=int)
        self.assertEqual(result, 3)

    # ------------------------------------------------------------------
    # dict[K, V] — membership test
    # ------------------------------------------------------------------

    async def test_dict_membership_present(self) -> None:
        result, _ = await self.call("dict_membership_present", [], return_type=bool)
        self.assertTrue(result)

    async def test_dict_membership_absent(self) -> None:
        result, _ = await self.call("dict_membership_absent", [], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # dict[K, V] — mutation
    # ------------------------------------------------------------------

    async def test_dict_update_value(self) -> None:
        result, _ = await self.call("dict_update_value", [], return_type=int)
        self.assertEqual(result, 99)

    # ------------------------------------------------------------------
    # dict[K, V] — iteration (insertion order is preserved by NeoVM Map)
    # ------------------------------------------------------------------

    async def test_dict_values_list(self) -> None:
        result, _ = await self.call("dict_values_list", [], return_type=list)
        self.assertEqual([item.as_int() for item in result], [20, 10, 30])

    async def test_dict_keys_list(self) -> None:
        result, _ = await self.call("dict_keys_list", [], return_type=list)
        self.assertEqual([item.as_int() for item in result], [3, 1, 2])

    async def test_dict_items_keys_in_order(self) -> None:
        result, _ = await self.call("dict_items_keys_in_order", [], return_type=list)
        self.assertEqual([item.as_int() for item in result], [4, 2])

    # Dict[str, Any] — heterogeneous values compile and resolve correctly

    async def test_dict_any_get_int(self) -> None:
        result, _ = await self.call("dict_any_get_int", [], return_type=int)
        self.assertEqual(result, 42)

    async def test_dict_any_get_str(self) -> None:
        result, _ = await self.call("dict_any_get_str", [], return_type=str)
        self.assertEqual(result, "hello")


if __name__ == "__main__":
    unittest.main()
