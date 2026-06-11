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

# ECDSA secp256r1+SHA256 test vector (NamedCurveHash.SECP256R1SHA256 = 23)
# private key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
_ECDSA_PUBKEY = bytes.fromhex(
    "02d8cd12ea5c67f2f8a00c1124893edcfa6754c4d6cede6be13bdf2295c810a97f"
)
_ECDSA_MSG = b"hello"
_ECDSA_SIG = bytes.fromhex(
    "ef344ba77e31e21aeb597e8639ba9eb349cfe370ac85d576fe592ef6c7fe169e"
    "c6256ac22beb390006d28dba2098099ec7d3943a78ef7cce2b0ccc67faf12262"
)
_ECDSA_CURVE_SECP256R1SHA256 = 23

# BLS12-381 G1 generator point (compressed, 48 bytes)
_BLS12381_G1 = bytes.fromhex(
    "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac58"
    "6c55e83ff97a1aeffb3af00adb22c6bb"
)


class TestCryptoLibWrapper(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "wrapper_cryptolib.py")
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

    async def test_verify_with_ecdsa_valid(self) -> None:
        result, _ = await self.call(
            "do_verify_with_ecdsa",
            [_ECDSA_MSG, _ECDSA_PUBKEY, _ECDSA_SIG, _ECDSA_CURVE_SECP256R1SHA256],
            return_type=bool,
        )
        self.assertTrue(result)

    async def test_verify_with_ecdsa_invalid_signature(self) -> None:
        result, _ = await self.call(
            "do_verify_with_ecdsa",
            [_ECDSA_MSG, _ECDSA_PUBKEY, bytes(64), _ECDSA_CURVE_SECP256R1SHA256],
            return_type=bool,
        )
        self.assertFalse(result)

    async def test_bls12381_roundtrip_g1(self) -> None:
        result, _ = await self.call(
            "do_bls12381_roundtrip", [_BLS12381_G1], return_type=bytes
        )
        self.assertEqual(_BLS12381_G1, result)


if __name__ == "__main__":
    unittest.main()
