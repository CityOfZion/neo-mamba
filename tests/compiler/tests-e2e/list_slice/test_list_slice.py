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
