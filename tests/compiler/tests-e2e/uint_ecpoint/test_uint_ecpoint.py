import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent

_UINT160 = b"\xab" * 20
_UINT256 = b"\xcd" * 32
_ECPOINT = b"\x02" + b"\x01" * 32


class TestUIntECPoint(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "uint_ecpoint.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./uint_ecpoint.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"uint_ecpoint{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # UInt160 round-trip
    # ------------------------------------------------------------------

    async def test_uint160_roundtrip_returns_same_bytes(self) -> None:
        result, _ = await self.call("uint160_roundtrip", [_UINT160], return_type=bytes)
        self.assertEqual(_UINT160, result)

    async def test_uint160_roundtrip_zero(self) -> None:
        data = b"\x00" * 20
        result, _ = await self.call("uint160_roundtrip", [data], return_type=bytes)
        self.assertEqual(data, result)

    async def test_uint160_to_bytes_from_typed_arg(self) -> None:
        result, _ = await self.call("uint160_to_bytes", [_UINT160], return_type=bytes)
        self.assertEqual(_UINT160, result)

    # ------------------------------------------------------------------
    # UInt256 round-trip
    # ------------------------------------------------------------------

    async def test_uint256_roundtrip_returns_same_bytes(self) -> None:
        result, _ = await self.call("uint256_roundtrip", [_UINT256], return_type=bytes)
        self.assertEqual(_UINT256, result)

    async def test_uint256_roundtrip_zero(self) -> None:
        data = b"\x00" * 32
        result, _ = await self.call("uint256_roundtrip", [data], return_type=bytes)
        self.assertEqual(data, result)

    async def test_uint256_to_bytes_from_typed_arg(self) -> None:
        result, _ = await self.call("uint256_to_bytes", [_UINT256], return_type=bytes)
        self.assertEqual(_UINT256, result)

    # ------------------------------------------------------------------
    # ECPoint round-trip
    # ------------------------------------------------------------------

    async def test_ecpoint_roundtrip_returns_same_bytes(self) -> None:
        result, _ = await self.call("ecpoint_roundtrip", [_ECPOINT], return_type=bytes)
        self.assertEqual(_ECPOINT, result)

    async def test_ecpoint_roundtrip_zero(self) -> None:
        data = b"\x00" * 33
        result, _ = await self.call("ecpoint_roundtrip", [data], return_type=bytes)
        self.assertEqual(data, result)

    async def test_ecpoint_to_bytes_from_typed_arg(self) -> None:
        result, _ = await self.call("ecpoint_to_bytes", [_ECPOINT], return_type=bytes)
        self.assertEqual(_ECPOINT, result)


if __name__ == "__main__":
    unittest.main()
