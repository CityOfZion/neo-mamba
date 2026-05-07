import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent

_SHA256_HELLO = bytes.fromhex(
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
)
_RIPEMD160_HELLO = bytes.fromhex("108f07b8382412612c048d07d13f814118445acd")


class TestCryptoLibWrapper(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "wrapper_cryptolib.py").read_text(),
            str(HERE / "wrapper_cryptolib"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./wrapper_cryptolib.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"wrapper_cryptolib{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_sha256_hello(self) -> None:
        result, _ = await self.call("do_sha256", [b"hello"], return_type=bytes)
        self.assertEqual(32, len(result))
        self.assertEqual(_SHA256_HELLO, result)

    async def test_ripemd160_hello(self) -> None:
        result, _ = await self.call("do_ripemd160", [b"hello"], return_type=bytes)
        self.assertEqual(20, len(result))
        self.assertEqual(_RIPEMD160_HELLO, result)

    async def test_murmur32_returns_4_bytes(self) -> None:
        result, _ = await self.call("do_murmur32", [b"hello", 0], return_type=bytes)
        self.assertEqual(4, len(result))

    async def test_murmur32_seed_affects_result(self) -> None:
        result_seed0, _ = await self.call(
            "do_murmur32", [b"hello", 0], return_type=bytes
        )
        result_seed1, _ = await self.call(
            "do_murmur32", [b"hello", 1], return_type=bytes
        )
        self.assertNotEqual(result_seed0, result_seed1)


if __name__ == "__main__":
    unittest.main()
