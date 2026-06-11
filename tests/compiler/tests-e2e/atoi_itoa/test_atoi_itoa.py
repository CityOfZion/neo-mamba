import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestAtoiItoa(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "atoi_itoa.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./atoi_itoa.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"atoi_itoa{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # atoi tests

    async def test_parse_decimal(self) -> None:
        result, _ = await self.call("parse_decimal", ["123"], return_type=int)
        self.assertEqual(result, 123)

    async def test_parse_decimal_zero(self) -> None:
        result, _ = await self.call("parse_decimal", ["0"], return_type=int)
        self.assertEqual(result, 0)

    async def test_parse_decimal_negative(self) -> None:
        result, _ = await self.call("parse_decimal", ["-42"], return_type=int)
        self.assertEqual(result, -42)

    async def test_parse_decimal_explicit(self) -> None:
        result, _ = await self.call(
            "parse_decimal_explicit", ["12345"], return_type=int
        )
        self.assertEqual(result, 12345)

    async def test_parse_hex_with_leading_zero(self) -> None:
        # C# BigInteger.Parse treats hex strings with high bit set as negative.
        # Prefix "0" to force positive interpretation of values >= 0x80.
        result, _ = await self.call("parse_hex", ["00ff"], return_type=int)
        self.assertEqual(result, 255)

    async def test_parse_hex_negative(self) -> None:
        # "ff" has high bit set → treated as -1 (C# BigInteger hex semantics)
        result, _ = await self.call("parse_hex", ["ff"], return_type=int)
        self.assertEqual(result, -1)

    async def test_parse_hex_small(self) -> None:
        # 0x7f has no high bit → always positive
        result, _ = await self.call("parse_hex", ["7f"], return_type=int)
        self.assertEqual(result, 127)

    async def test_parse_hex_mixed(self) -> None:
        result, _ = await self.call("parse_hex", ["1a2b"], return_type=int)
        self.assertEqual(result, 0x1A2B)

    # itoa tests

    async def test_to_decimal(self) -> None:
        result, _ = await self.call("to_decimal", [123], return_type=str)
        self.assertEqual(result, "123")

    async def test_to_decimal_zero(self) -> None:
        result, _ = await self.call("to_decimal", [0], return_type=str)
        self.assertEqual(result, "0")

    async def test_to_decimal_negative(self) -> None:
        result, _ = await self.call("to_decimal", [-42], return_type=str)
        self.assertEqual(result, "-42")

    async def test_to_decimal_explicit(self) -> None:
        result, _ = await self.call("to_decimal_explicit", [12345], return_type=str)
        self.assertEqual(result, "12345")

    async def test_to_hex(self) -> None:
        # itoa adds a leading "0" for values where the high bit would be set,
        # so that round-tripping through atoi gives the correct positive value.
        result, _ = await self.call("to_hex", [255], return_type=str)
        self.assertEqual(result, "0ff")

    async def test_to_hex_small(self) -> None:
        result, _ = await self.call("to_hex", [127], return_type=str)
        self.assertEqual(result, "7f")

    async def test_to_hex_zero(self) -> None:
        result, _ = await self.call("to_hex", [0], return_type=str)
        self.assertEqual(result, "0")
