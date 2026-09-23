import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestMembership(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "membership.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./membership.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"membership{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def _bool(self, method: str, args: list) -> bool:
        result, _ = await self.call(method, args, return_type=bool)
        return result

    # list[T]

    async def test_int_in_list_found(self) -> None:
        self.assertTrue(await self._bool("int_in_list", [3]))

    async def test_int_in_list_first_and_last(self) -> None:
        self.assertTrue(await self._bool("int_in_list", [1]))
        self.assertTrue(await self._bool("int_in_list", [5]))

    async def test_int_in_list_missing(self) -> None:
        self.assertFalse(await self._bool("int_in_list", [6]))
        self.assertFalse(await self._bool("int_in_list", [-1]))

    async def test_int_not_in_list(self) -> None:
        self.assertFalse(await self._bool("int_not_in_list", [3]))
        self.assertTrue(await self._bool("int_not_in_list", [6]))

    async def test_int_in_empty_list(self) -> None:
        self.assertFalse(await self._bool("int_in_empty_list", [0]))

    async def test_str_in_list(self) -> None:
        self.assertTrue(await self._bool("str_in_list", ["gas"]))
        self.assertFalse(await self._bool("str_in_list", ["ga"]))

    async def test_bytes_in_list(self) -> None:
        self.assertTrue(await self._bool("bytes_in_list", [b"\x02\x03"]))
        self.assertFalse(await self._bool("bytes_in_list", [b"\x02"]))

    async def test_bytearray_in_list_compares_by_value(self) -> None:
        self.assertTrue(await self._bool("bytearray_in_list", [b"\x02\x03"]))
        self.assertFalse(await self._bool("bytearray_in_list", [b"\x03"]))

    # dict[K, V]

    async def test_key_not_in_dict(self) -> None:
        self.assertFalse(await self._bool("key_not_in_dict", ["a"]))
        self.assertTrue(await self._bool("key_not_in_dict", ["c"]))

    # substring

    async def test_substr_in_str(self) -> None:
        self.assertTrue(await self._bool("substr_in_str", ["amb", "mamba"]))
        self.assertTrue(await self._bool("substr_in_str", ["mamba", "mamba"]))
        self.assertFalse(await self._bool("substr_in_str", ["abm", "mamba"]))

    async def test_substr_empty_needle(self) -> None:
        self.assertTrue(await self._bool("substr_in_str", ["", "mamba"]))
        self.assertTrue(await self._bool("substr_in_str", ["", ""]))

    async def test_substr_needle_longer_than_haystack(self) -> None:
        self.assertFalse(await self._bool("substr_in_str", ["mambas", "mamba"]))

    async def test_substr_utf8(self) -> None:
        self.assertTrue(await self._bool("substr_in_str", ["ü", "grün"]))
        self.assertFalse(await self._bool("substr_in_str", ["u", "grün"]))

    async def test_substr_not_in_str(self) -> None:
        self.assertFalse(await self._bool("substr_not_in_str", ["amb", "mamba"]))
        self.assertTrue(await self._bool("substr_not_in_str", ["x", "mamba"]))

    async def test_subbytes_in_bytes(self) -> None:
        self.assertTrue(
            await self._bool("subbytes_in_bytes", [b"\x02\x03", b"\x01\x02\x03"])
        )
        self.assertFalse(
            await self._bool("subbytes_in_bytes", [b"\x03\x02", b"\x01\x02\x03"])
        )

    async def test_subbytes_in_bytearray(self) -> None:
        self.assertTrue(
            await self._bool("subbytes_in_bytearray", [b"\x02", b"\x01\x02"])
        )
        self.assertFalse(
            await self._bool("subbytes_in_bytearray", [b"\x03", b"\x01\x02"])
        )

    async def test_subbytearray_in_bytes(self) -> None:
        self.assertTrue(
            await self._bool("subbytearray_in_bytes", [b"\x02", b"\x01\x02"])
        )
        self.assertFalse(
            await self._bool("subbytearray_in_bytes", [b"\x03", b"\x01\x02"])
        )


if __name__ == "__main__":
    unittest.main()
