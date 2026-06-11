import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestIntEnumCtor(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "intenum_ctor.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./intenum_ctor.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"intenum_ctor{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_named_curve_hash_ctor_secp256k1sha256(self) -> None:
        result, _ = await self.call("named_curve_hash_ctor", [22], return_type=int)
        self.assertEqual(22, result)

    async def test_named_curve_hash_ctor_secp256r1sha256(self) -> None:
        result, _ = await self.call("named_curve_hash_ctor", [23], return_type=int)
        self.assertEqual(23, result)

    async def test_named_curve_hash_ctor_arbitrary_int(self) -> None:
        result, _ = await self.call("named_curve_hash_ctor", [42], return_type=int)
        self.assertEqual(42, result)

    async def test_named_curve_hash_ctor_zero(self) -> None:
        result, _ = await self.call("named_curve_hash_ctor", [0], return_type=int)
        self.assertEqual(0, result)

    async def test_find_options_ctor_none(self) -> None:
        result, _ = await self.call("find_options_ctor", [0], return_type=int)
        self.assertEqual(0, result)

    async def test_find_options_ctor_keys_only(self) -> None:
        result, _ = await self.call("find_options_ctor", [1], return_type=int)
        self.assertEqual(1, result)

    async def test_find_options_ctor_values_only(self) -> None:
        result, _ = await self.call("find_options_ctor", [4], return_type=int)
        self.assertEqual(4, result)

    async def test_call_flags_ctor_all(self) -> None:
        result, _ = await self.call("call_flags_ctor", [15], return_type=int)
        self.assertEqual(15, result)

    async def test_call_flags_ctor_zero(self) -> None:
        result, _ = await self.call("call_flags_ctor", [0], return_type=int)
        self.assertEqual(0, result)

    async def test_named_curve_hash_literal_roundtrip(self) -> None:
        # NamedCurveHash(NamedCurveHash.SECP256R1SHA256) folds to identity of 23
        result, _ = await self.call("named_curve_hash_literal", [], return_type=int)
        self.assertEqual(23, result)


if __name__ == "__main__":
    unittest.main()
