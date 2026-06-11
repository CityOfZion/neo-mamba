import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestBytearrayReverse(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "bytearray_reverse.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./bytearray_reverse.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"bytearray_reverse{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_reverse_bytes_basic(self) -> None:
        result, _ = await self.call(
            "reverse_bytes", [b"\x01\x02\x03"], return_type=bytes
        )
        self.assertEqual(result, b"\x03\x02\x01")

    async def test_reverse_bytes_single(self) -> None:
        result, _ = await self.call("reverse_bytes", [b"\xab"], return_type=bytes)
        self.assertEqual(result, b"\xab")

    async def test_reverse_bytes_empty(self) -> None:
        result, _ = await self.call("reverse_bytes", [b""], return_type=bytes)
        self.assertEqual(result, b"")

    async def test_reverse_bytes_palindrome(self) -> None:
        result, _ = await self.call(
            "reverse_bytes", [b"\x01\x02\x01"], return_type=bytes
        )
        self.assertEqual(result, b"\x01\x02\x01")

    async def test_reverse_bytearray_basic(self) -> None:
        result, _ = await self.call(
            "reverse_bytearray", [b"\xff\x00\x7f"], return_type=bytes
        )
        self.assertEqual(result, b"\x7f\x00\xff")


if __name__ == "__main__":
    unittest.main()
