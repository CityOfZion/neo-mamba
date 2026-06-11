import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestScriptContainer(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "script_container.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./script_container.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"script_container{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_get_hash_returns_32_bytes(self) -> None:
        result, _ = await self.call(
            "get_hash", [], return_type=bytes, signing_accounts=[self.genesis]
        )
        self.assertEqual(32, len(result))

    async def test_get_version_returns_zero(self) -> None:
        result, _ = await self.call(
            "get_version", [], return_type=int, signing_accounts=[self.genesis]
        )
        self.assertEqual(0, result)

    async def test_get_nonce_returns_int(self) -> None:
        result, _ = await self.call(
            "get_nonce", [], return_type=int, signing_accounts=[self.genesis]
        )
        self.assertIsInstance(result, int)

    async def test_get_sender_returns_20_bytes(self) -> None:
        result, _ = await self.call(
            "get_sender", [], return_type=bytes, signing_accounts=[self.genesis]
        )
        self.assertEqual(20, len(result))

    async def test_get_system_fee_returns_non_negative(self) -> None:
        result, _ = await self.call(
            "get_system_fee", [], return_type=int, signing_accounts=[self.genesis]
        )
        self.assertGreaterEqual(result, 0)

    async def test_get_network_fee_returns_non_negative(self) -> None:
        result, _ = await self.call(
            "get_network_fee", [], return_type=int, signing_accounts=[self.genesis]
        )
        self.assertGreaterEqual(result, 0)

    async def test_get_valid_until_block_returns_positive(self) -> None:
        result, _ = await self.call(
            "get_valid_until_block",
            [],
            return_type=int,
            signing_accounts=[self.genesis],
        )
        self.assertGreater(result, 0)

    async def test_get_script_returns_nonempty_bytes(self) -> None:
        result, _ = await self.call(
            "get_script", [], return_type=bytes, signing_accounts=[self.genesis]
        )
        self.assertGreater(len(result), 0)
