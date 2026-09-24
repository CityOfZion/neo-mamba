import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_module, compile_to_nef

HERE = Path(__file__).parent


class TestListSlice(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "list_slice.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./list_slice.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"list_slice{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_slice_from_start(self) -> None:
        result, _ = await self.call("slice_from", [2], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [3, 4, 5])

    async def test_slice_from_zero_returns_full_list(self) -> None:
        result, _ = await self.call("slice_from", [0], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [1, 2, 3, 4, 5])

    async def test_slice_from_beyond_length_returns_empty(self) -> None:
        result, _ = await self.call("slice_from", [100], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [])

    async def test_slice_to_stop(self) -> None:
        result, _ = await self.call("slice_to", [3], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [1, 2, 3])

    async def test_slice_to_beyond_length_clamps(self) -> None:
        result, _ = await self.call("slice_to", [100], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [1, 2, 3, 4, 5])

    async def test_slice_range(self) -> None:
        result, _ = await self.call("slice_range", [1, 4], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [2, 3, 4])

    async def test_slice_range_start_equals_stop_returns_empty(self) -> None:
        result, _ = await self.call("slice_range", [2, 2], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [])

    async def test_slice_step(self) -> None:
        result, _ = await self.call("slice_step", [0, 5, 2], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [1, 3, 5])

    async def test_slice_full(self) -> None:
        result, _ = await self.call("slice_full", [], return_type=list)
        result = list(map(lambda si: si.as_int(), result))
        self.assertEqual(result, [1, 2, 3, 4, 5])

    async def test_slice_str_elements(self) -> None:
        result, _ = await self.call("slice_str", [2], return_type=list)
        result = list(map(lambda si: si.as_str(), result))
        self.assertEqual(result, ["c", "d", "e"])

    async def _slice(self, method: str, args: list) -> list[int]:
        result, _ = await self.call(method, args, return_type=list)
        return list(map(lambda si: si.as_int(), result))

    async def test_slice_from_negative(self) -> None:
        x = [1, 2, 3, 4, 5]
        for start in (-1, -2, -5, -100):
            with self.subTest(start=start):
                self.assertEqual(x[start:], await self._slice("slice_from", [start]))

    async def test_slice_to_negative(self) -> None:
        x = [1, 2, 3, 4, 5]
        for stop in (-1, -4, -5, -100):
            with self.subTest(stop=stop):
                self.assertEqual(x[:stop], await self._slice("slice_to", [stop]))

    async def test_slice_range_negative(self) -> None:
        x = [1, 2, 3, 4, 5]
        for start, stop in ((-3, -1), (-100, 2), (1, -1), (-1, -3), (3, 1), (-2, 100)):
            with self.subTest(start=start, stop=stop):
                self.assertEqual(
                    x[start:stop], await self._slice("slice_range", [start, stop])
                )

    async def test_slice_step_negative_bounds(self) -> None:
        x = [1, 2, 3, 4, 5]
        for start, stop, step in ((-5, -1, 2), (-4, 100, 2), (-100, -1, 3)):
            with self.subTest(start=start, stop=stop, step=step):
                self.assertEqual(
                    x[start:stop:step],
                    await self._slice("slice_step", [start, stop, step]),
                )

    def test_slice_of_dict_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                "from neo3.sc.compiletime import public\n"
                "@public\ndef f() -> int:\n"
                "    d: dict[int, int] = {1: 2}\n"
                "    x: int = d[0:1]\n"
                "    return x\n"
            )


if __name__ == "__main__":
    unittest.main()
