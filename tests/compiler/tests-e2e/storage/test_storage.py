import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestStorage(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "storage.py").read_text(),
            str(HERE / "storage"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./storage.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"storage{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # --- put + get ---

    async def test_put_then_get_returns_value(self) -> None:
        key = b"test_put_get"
        value = b"hello"
        await self.call(
            "store", [key, value], return_type=None, signing_accounts=[self.genesis]
        )
        result, _ = await self.call("load", [key], return_type=bytes)
        self.assertEqual(value, result)

    async def test_round_trip_returns_value(self) -> None:
        key = b"test_round_trip"
        value = b"world"
        result, _ = await self.call(
            "round_trip",
            [key, value],
            return_type=bytes,
            signing_accounts=[self.genesis],
        )
        self.assertEqual(value, result)

    async def test_put_stores_exact_bytes(self) -> None:
        key = b"test_exact"
        value = b"\x00\x01\x02\xff\xfe"
        await self.call(
            "store", [key, value], return_type=None, signing_accounts=[self.genesis]
        )
        result, _ = await self.call("load", [key], return_type=bytes)
        self.assertEqual(value, result)

    async def test_overwrite_returns_second_value(self) -> None:
        key = b"test_overwrite"
        first = b"first"
        second = b"second"
        result, _ = await self.call(
            "overwrite",
            [key, first, second],
            return_type=bytes,
            signing_accounts=[self.genesis],
        )
        self.assertEqual(second, result)

    # --- get_storage verification ---

    async def test_get_storage_contains_put_key(self) -> None:
        key = b"test_getstorage_key"
        value = b"test_getstorage_value"
        await self.call(
            "store", [key, value], return_type=None, signing_accounts=[self.genesis]
        )
        storage = await self.get_storage()
        self.assertIn(key, storage)
        self.assertEqual(value, storage[key])

    async def test_get_storage_with_prefix_filter(self) -> None:
        prefix = b"pfx_"
        key = prefix + b"item"
        value = b"prefixed_value"
        await self.call(
            "store", [key, value], return_type=None, signing_accounts=[self.genesis]
        )
        storage = await self.get_storage(prefix=prefix)
        self.assertIn(key, storage)
        self.assertEqual(value, storage[key])

    async def test_get_storage_prefix_remove_prefix(self) -> None:
        prefix = b"rmv_"
        suffix = b"item"
        key = prefix + suffix
        value = b"prefixed_value2"
        await self.call(
            "store", [key, value], return_type=None, signing_accounts=[self.genesis]
        )
        storage = await self.get_storage(prefix=prefix, remove_prefix=True)
        self.assertIn(suffix, storage)
        self.assertEqual(value, storage[suffix])

    # --- delete ---

    async def test_delete_removes_key_from_storage(self) -> None:
        key = b"test_delete_removes"
        value = b"to_be_deleted"
        await self.call(
            "store", [key, value], return_type=None, signing_accounts=[self.genesis]
        )
        storage_before = await self.get_storage()
        self.assertIn(key, storage_before)

        await self.call(
            "remove", [key], return_type=None, signing_accounts=[self.genesis]
        )
        storage_after = await self.get_storage()
        self.assertNotIn(key, storage_after)

    async def test_store_and_delete_leaves_no_entry(self) -> None:
        key = b"test_store_delete_atomic"
        value = b"gone"
        await self.call(
            "store_and_delete",
            [key, value],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        storage = await self.get_storage()
        self.assertNotIn(key, storage)

    async def test_delete_nonexistent_key_does_not_fault(self) -> None:
        # Deleting a key that was never stored must not fault the VM.
        key = b"test_delete_never_stored_key_xyz"
        await self.call(
            "remove", [key], return_type=None, signing_accounts=[self.genesis]
        )

    # --- overwrite via get_storage ---

    async def test_overwrite_updates_storage(self) -> None:
        key = b"test_overwrite_storage"
        await self.call(
            "store",
            [key, b"original"],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        await self.call(
            "store",
            [key, b"updated"],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        storage = await self.get_storage()
        self.assertIn(key, storage)
        self.assertEqual(b"updated", storage[key])

    # --- multiple keys ---

    async def test_independent_keys_do_not_interfere(self) -> None:
        key_a = b"test_multi_a"
        key_b = b"test_multi_b"
        await self.call(
            "store",
            [key_a, b"alpha"],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        await self.call(
            "store", [key_b, b"beta"], return_type=None, signing_accounts=[self.genesis]
        )
        storage = await self.get_storage()
        self.assertEqual(b"alpha", storage[key_a])
        self.assertEqual(b"beta", storage[key_b])

    async def test_delete_one_key_leaves_other_intact(self) -> None:
        key_a = b"test_del_one_a"
        key_b = b"test_del_one_b"
        await self.call(
            "store", [key_a, b"keep"], return_type=None, signing_accounts=[self.genesis]
        )
        await self.call(
            "store",
            [key_b, b"remove"],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        await self.call(
            "remove", [key_b], return_type=None, signing_accounts=[self.genesis]
        )
        storage = await self.get_storage()
        self.assertIn(key_a, storage)
        self.assertNotIn(key_b, storage)

    async def test_get_int(self):
        result, _ = await self.call("get_int", return_type=int)
        self.assertEqual(5, result)

    async def test_put_int(self):
        result, _ = await self.call("put_int", [4], return_type=int)
        self.assertEqual(4, result)

    async def test_get_none_existant_key(self) -> None:
        result, _ = await self.call("load", [b"something"], return_type=None)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
