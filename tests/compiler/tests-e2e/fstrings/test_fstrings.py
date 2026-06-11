import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestFStrings(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "fstrings.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./fstrings.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"fstrings{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_greet(self) -> None:
        result, _ = await self.call("greet", ["world"], return_type=str)
        self.assertEqual(result, "Hello, world!")

    async def test_greet_empty_name(self) -> None:
        result, _ = await self.call("greet", [""], return_type=str)
        self.assertEqual(result, "Hello, !")

    async def test_format_int(self) -> None:
        result, _ = await self.call("format_int", [42], return_type=str)
        self.assertEqual(result, "value=42")

    async def test_format_int_zero(self) -> None:
        result, _ = await self.call("format_int", [0], return_type=str)
        self.assertEqual(result, "value=0")

    async def test_format_int_negative(self) -> None:
        result, _ = await self.call("format_int", [-7], return_type=str)
        self.assertEqual(result, "value=-7")

    async def test_format_bool_true(self) -> None:
        result, _ = await self.call("format_bool", [True], return_type=str)
        self.assertEqual(result, "True")

    async def test_format_bool_false(self) -> None:
        result, _ = await self.call("format_bool", [False], return_type=str)
        self.assertEqual(result, "False")

    async def test_str_bool_true(self) -> None:
        result, _ = await self.call("str_bool_true", [], return_type=str)
        self.assertEqual(result, "True")

    async def test_str_bool_false(self) -> None:
        result, _ = await self.call("str_bool_false", [], return_type=str)
        self.assertEqual(result, "False")

    async def test_multi(self) -> None:
        result, _ = await self.call("multi", ["foo", "bar", 3], return_type=str)
        self.assertEqual(result, "foo and bar = 3")
