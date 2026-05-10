import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestStorageFindOptions(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "storage_find_options.py").read_text(),
            str(HERE / "storage_find_options"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy(
            "./storage_find_options.nef", cls.genesis
        )

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"storage_find_options{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # --- find_pairs (FindOptions.NONE) ---

    async def test_find_pairs_returns_four_items(self) -> None:
        result, _ = await self.call("find_pairs", [b"data"], return_type=list)
        self.assertEqual(4, len(result))

    async def test_find_pairs_each_item_is_key_value_pair(self) -> None:
        result, _ = await self.call("find_pairs", [b"data"], return_type=list)
        for item in result:
            # FindOptions.NONE returns Struct [key, value] items
            self.assertEqual(2, len(item.value))

    async def test_find_pairs_contains_expected_pairs(self) -> None:
        result, _ = await self.call("find_pairs", [b"data"], return_type=list)
        pairs = {item.value[0].as_bytes(): item.value[1].as_bytes() for item in result}
        self.assertEqual(pairs[b"data1"], b"fizz")
        self.assertEqual(pairs[b"data2"], b"buzz")
        self.assertEqual(pairs[b"data3"], b"unit")
        self.assertEqual(pairs[b"data4"], b"test")

    async def test_find_pairs_no_match_returns_empty(self) -> None:
        result, _ = await self.call("find_pairs", [b"xyz"], return_type=list)
        self.assertEqual(0, len(result))

    async def test_find_pairs_exact_prefix_returns_one(self) -> None:
        result, _ = await self.call("find_pairs", [b"data1"], return_type=list)
        self.assertEqual(1, len(result))
        pair = result[0].value
        self.assertEqual(pair[0].as_bytes(), b"data1")
        self.assertEqual(pair[1].as_bytes(), b"fizz")

    # --- find_values_only (FindOptions.VALUES_ONLY) ---

    async def test_find_values_only_contains_all_values(self) -> None:
        result, _ = await self.call("find_values_only", [b"data"], return_type=list)
        values = {v.as_bytes() for v in result}
        self.assertEqual(4, len(values))
        self.assertEqual(values, {b"fizz", b"buzz", b"unit", b"test"})

    async def test_find_values_only_exact_prefix_returns_one(self) -> None:
        result, _ = await self.call("find_values_only", [b"data1"], return_type=list)
        self.assertEqual(1, len(result))

    async def test_find_values_only_no_match_returns_empty(self) -> None:
        result, _ = await self.call("find_values_only", [b"xyz"], return_type=list)
        self.assertEqual(0, len(result))

    # --- find_keys_remove_prefix (FindOptions.KEYS_ONLY | REMOVE_PREFIX) ---

    async def test_find_keys_remove_prefix_strips_prefix(self) -> None:
        result, _ = await self.call(
            "find_keys_remove_prefix", [b"data"], return_type=list
        )
        suffixes = {k.as_bytes() for k in result}
        self.assertEqual(4, len(suffixes))
        self.assertEqual(suffixes, {b"1", b"2", b"3", b"4"})

    async def test_find_keys_remove_prefix_exact_returns_empty_suffix(self) -> None:
        result, _ = await self.call(
            "find_keys_remove_prefix", [b"data1"], return_type=list
        )
        self.assertEqual(1, len(result))
        self.assertEqual(result[0].as_bytes(), b"")

    async def test_find_keys_remove_prefix_no_match_returns_empty(self) -> None:
        result, _ = await self.call(
            "find_keys_remove_prefix", [b"xyz"], return_type=list
        )
        self.assertEqual(0, len(result))

    # --- find_keys_backwards (FindOptions.KEYS_ONLY | BACKWARDS) ---

    async def test_find_keys_backwards_is_reverse_order(self) -> None:
        result, _ = await self.call("find_keys_backwards", [b"data"], return_type=list)
        keys = [k.as_bytes() for k in result]
        self.assertEqual(4, len(keys))
        self.assertEqual(keys, [b"data4", b"data3", b"data2", b"data1"])

    async def test_find_keys_backwards_no_match_returns_empty(self) -> None:
        result, _ = await self.call("find_keys_backwards", [b"xyz"], return_type=list)
        self.assertEqual(0, len(result))

    # --- find_keys_only (FindOptions.KEYS_ONLY) ---

    async def test_find_keys_only_contains_full_keys(self) -> None:
        result, _ = await self.call("find_keys_only", [b"data"], return_type=list)
        keys = {k.as_bytes() for k in result}
        self.assertEqual(4, len(result))
        self.assertEqual(keys, {b"data1", b"data2", b"data3", b"data4"})

    async def test_find_keys_only_no_match_returns_empty(self) -> None:
        result, _ = await self.call("find_keys_only", [b"xyz"], return_type=list)
        self.assertEqual(0, len(result))

    # --- find_deserialize_values (FindOptions.VALUES_ONLY | DESERIALIZE_VALUES) ---

    async def test_find_deserialize_values_contains_integers(self) -> None:
        result, _ = await self.call(
            "find_deserialize_values", [b"num"], return_type=list
        )
        values = {v.as_int() for v in result}
        self.assertEqual(2, len(result))
        self.assertEqual(values, {42, 100})

    async def test_find_deserialize_values_no_match_returns_empty(self) -> None:
        result, _ = await self.call(
            "find_deserialize_values", [b"xyz"], return_type=list
        )
        self.assertEqual(0, len(result))

    # --- find_pick_field0 (VALUES_ONLY | DESERIALIZE_VALUES | PICK_FIELD0) ---

    async def test_find_pick_field0_values_are_first_elements(self) -> None:
        result, _ = await self.call("find_pick_field0", [b"pair"], return_type=list)
        values = {v.as_int() for v in result}
        self.assertEqual(2, len(result))
        self.assertEqual(values, {10, 30})

    async def test_find_pick_field0_no_match_returns_empty(self) -> None:
        result, _ = await self.call("find_pick_field0", [b"xyz"], return_type=list)
        self.assertEqual(0, len(result))

    # --- find_pick_field1 (VALUES_ONLY | DESERIALIZE_VALUES | PICK_FIELD1) ---

    async def test_find_pick_field1_values_are_second_elements(self) -> None:
        result, _ = await self.call("find_pick_field1", [b"pair"], return_type=list)
        values = {v.as_int() for v in result}
        self.assertEqual(2, len(result))
        self.assertEqual(values, {20, 40})

    async def test_find_pick_field1_no_match_returns_empty(self) -> None:
        result, _ = await self.call("find_pick_field1", [b"xyz"], return_type=list)
        self.assertEqual(0, len(result))


if __name__ == "__main__":
    unittest.main()
