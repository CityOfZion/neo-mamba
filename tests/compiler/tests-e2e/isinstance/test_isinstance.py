import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef, compile_module

HERE = Path(__file__).parent


class TestIsinstance(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "isinstance_checks.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./isinstance_checks.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"isinstance_checks{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # int type checks
    # ------------------------------------------------------------------

    async def test_int_is_int(self) -> None:
        result, _ = await self.call("int_is_int", [42], return_type=bool)
        self.assertTrue(result)

    async def test_int_is_bool(self) -> None:
        result, _ = await self.call("int_is_bool", [1], return_type=bool)
        self.assertFalse(result)

    async def test_int_is_str(self) -> None:
        result, _ = await self.call("int_is_str", [1], return_type=bool)
        self.assertFalse(result)

    async def test_int_is_bytes(self) -> None:
        result, _ = await self.call("int_is_bytes", [1], return_type=bool)
        self.assertFalse(result)

    async def test_int_is_bytearray(self) -> None:
        result, _ = await self.call("int_is_bytearray", [1], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # bool type checks
    # ------------------------------------------------------------------

    async def test_bool_true_is_bool(self) -> None:
        result, _ = await self.call("bool_is_bool", [True], return_type=bool)
        self.assertTrue(result)

    async def test_bool_false_is_bool(self) -> None:
        result, _ = await self.call("bool_is_bool", [False], return_type=bool)
        self.assertTrue(result)

    async def test_bool_is_int_divergence(self) -> None:
        """NeoVM divergence: isinstance(True, int) = False.
        Python returns True because bool is a subclass of int.
        At the NeoVM level Boolean (tag 0x20) ≠ Integer (tag 0x21), so ISTYPE returns False.
        """
        result, _ = await self.call("bool_is_int", [True], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # str type checks
    # ------------------------------------------------------------------

    async def test_str_is_str(self) -> None:
        result, _ = await self.call("str_is_str", ["hello"], return_type=bool)
        self.assertTrue(result)

    async def test_str_is_bytes_divergence(self) -> None:
        """NeoVM divergence: isinstance("hello", bytes) = True.
        Python returns False. Both str and bytes compile to ByteString (tag 0x28) at
        the VM level, so ISTYPE 0x28 matches both."""
        result, _ = await self.call("str_is_bytes", ["hello"], return_type=bool)
        self.assertTrue(result)

    async def test_str_is_int(self) -> None:
        result, _ = await self.call("str_is_int", ["hello"], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # bytes type checks
    # ------------------------------------------------------------------

    async def test_bytes_is_bytes(self) -> None:
        result, _ = await self.call("bytes_is_bytes", [b"\x01\x02"], return_type=bool)
        self.assertTrue(result)

    async def test_bytes_is_str_divergence(self) -> None:
        """NeoVM divergence: isinstance(b"\x01", str) = True.
        Python returns False. Both bytes and str compile to ByteString (tag 0x28), so
        ISTYPE 0x28 matches both directions."""
        result, _ = await self.call("bytes_is_str", [b"\x01"], return_type=bool)
        self.assertTrue(result)

    async def test_bytes_is_int(self) -> None:
        result, _ = await self.call("bytes_is_int", [b"\x01"], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # bytearray type checks
    # ------------------------------------------------------------------

    async def test_bytearray_is_bytearray(self) -> None:
        result, _ = await self.call("bytearray_is_bytearray", [], return_type=bool)
        self.assertTrue(result)

    async def test_bytearray_is_bytes(self) -> None:
        """Buffer (tag 0x30) ≠ ByteString (tag 0x28) → False.
        Matches Python: isinstance(bytearray(), bytes) = False."""
        result, _ = await self.call("bytearray_is_bytes", [], return_type=bool)
        self.assertFalse(result)

    async def test_bytearray_is_str(self) -> None:
        """Buffer (tag 0x30) ≠ ByteString (tag 0x28) → False."""
        result, _ = await self.call("bytearray_is_str", [], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # isinstance in branch / boolean expression context
    # ------------------------------------------------------------------

    async def test_isinstance_branch_true(self) -> None:
        result, _ = await self.call("isinstance_branch", [99], return_type=int)
        self.assertEqual(result, 1)

    async def test_isinstance_and(self) -> None:
        result, _ = await self.call("isinstance_and", [1, 2], return_type=bool)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # Compile-error cases
    # ------------------------------------------------------------------

    def test_tuple_of_types_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: int) -> bool:\n    return isinstance(x, (int, str))\n",
            )

    def test_list_type_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: list[int]) -> bool:\n    return isinstance(x, list[int])\n",
            )

    def test_dict_type_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: dict[str, int]) -> bool:\n    return isinstance(x, dict[str, int])\n",
            )


if __name__ == "__main__":
    unittest.main()
