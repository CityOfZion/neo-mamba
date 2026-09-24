import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestNegativeIndex(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "negative_index.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./negative_index.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"negative_index{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def _int_list(self, method: str, args: list) -> list[int]:
        result, _ = await self.call(method, args, return_type=list)
        return list(map(lambda si: si.as_int(), result))

    async def test_list_get(self) -> None:
        x = [10, 20, 30, 40, 50]
        for idx in (0, 4, -1, -3, -5):
            with self.subTest(idx=idx):
                result, _ = await self.call("list_get", [idx], return_type=int)
                self.assertEqual(x[idx], result)

    async def test_list_get_out_of_range_faults(self) -> None:
        for idx in (5, -6):
            with self.subTest(idx=idx):
                with self.assertRaises(ValueError):
                    await self.call("list_get", [idx], return_type=int)

    async def test_list_get_literal(self) -> None:
        result, _ = await self.call("list_get_literal_last", [], return_type=int)
        self.assertEqual(50, result)
        result, _ = await self.call("list_get_literal_first", [], return_type=int)
        self.assertEqual(10, result)

    async def test_list_get_param(self) -> None:
        result, _ = await self.call("list_get_param", [[1, 2, 3]], return_type=int)
        self.assertEqual(3, result)

    async def test_list_set(self) -> None:
        for idx in (1, -1, -5):
            with self.subTest(idx=idx):
                expected = [10, 20, 30, 40, 50]
                expected[idx] = 99
                self.assertEqual(expected, await self._int_list("list_set", [idx, 99]))

    async def test_list_set_out_of_range_faults(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("list_set", [-6, 99], return_type=list)

    async def test_list_set_literal_last(self) -> None:
        self.assertEqual(
            [10, 20, 30, 40, 99], await self._int_list("list_set_literal_last", [99])
        )

    async def test_bytes_get(self) -> None:
        data = b"\x01\x02\x03"
        for idx in (0, -1, -3):
            with self.subTest(idx=idx):
                result, _ = await self.call("bytes_get", [data, idx], return_type=int)
                self.assertEqual(data[idx], result)
        result, _ = await self.call("bytes_get_literal_last", [data], return_type=int)
        self.assertEqual(3, result)

    async def test_bytes_get_out_of_range_faults(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("bytes_get", [b"\x01\x02\x03", -4], return_type=int)

    async def test_bytearray_set(self) -> None:
        for idx in (0, -1, -2):
            with self.subTest(idx=idx):
                expected = bytearray(b"\x01\x02\x03")
                expected[idx] = 0xFF
                result, _ = await self.call(
                    "bytearray_set", [b"\x01\x02\x03", idx, 0xFF], return_type=bytes
                )
                self.assertEqual(bytes(expected), result)

    async def test_str_get(self) -> None:
        s = "hello"
        for idx in (0, -1, -5):
            with self.subTest(idx=idx):
                result, _ = await self.call("str_get", [s, idx], return_type=str)
                self.assertEqual(s[idx], result)

    async def test_tuple_get_last(self) -> None:
        result, _ = await self.call("tuple_get_last", [], return_type=int)
        self.assertEqual(3, result)

    async def test_dict_negative_key_is_a_key(self) -> None:
        result, _ = await self.call("dict_negative_key", [-1], return_type=int)
        self.assertEqual(7, result)
        result, _ = await self.call("dict_negative_key", [1], return_type=int)
        self.assertEqual(9, result)

    async def test_negative_index_in_while_condition(self) -> None:
        result, _ = await self.call("while_last_countdown", [], return_type=int)
        self.assertEqual(4, result)

    async def test_bytes_slices(self) -> None:
        data = b"\x01\x02\x03\x04\x05"
        for start in (0, 2, -2, -5, -100, 100):
            with self.subTest(method="bytes_slice_from", start=start):
                result, _ = await self.call(
                    "bytes_slice_from", [data, start], return_type=bytes
                )
                self.assertEqual(data[start:], result)
        for stop in (0, 3, -1, -5, -100, 100):
            with self.subTest(method="bytes_slice_to", stop=stop):
                result, _ = await self.call(
                    "bytes_slice_to", [data, stop], return_type=bytes
                )
                self.assertEqual(data[:stop], result)
        for start, stop in ((1, 3), (-3, -1), (-100, 2), (1, -1), (3, 1), (-2, 100)):
            with self.subTest(method="bytes_slice_range", start=start, stop=stop):
                result, _ = await self.call(
                    "bytes_slice_range", [data, start, stop], return_type=bytes
                )
                self.assertEqual(data[start:stop], result)
        for start, stop in ((0, 5), (-5, -1), (-4, 100), (-100, -2)):
            with self.subTest(method="bytes_slice_step", start=start, stop=stop):
                result, _ = await self.call(
                    "bytes_slice_step", [data, start, stop], return_type=bytes
                )
                self.assertEqual(data[start:stop:2], result)

    async def test_bytes_slice_literal_last_two(self) -> None:
        result, _ = await self.call(
            "bytes_slice_literal_last_two", [b"\x01\x02\x03"], return_type=bytes
        )
        self.assertEqual(b"\x02\x03", result)

    async def test_str_slice_range(self) -> None:
        s = "hello"
        for start, stop in ((1, 3), (-4, -1), (0, 100), (4, 2)):
            with self.subTest(start=start, stop=stop):
                result, _ = await self.call(
                    "str_slice_range", [s, start, stop], return_type=str
                )
                self.assertEqual(s[start:stop], result)


if __name__ == "__main__":
    unittest.main()
