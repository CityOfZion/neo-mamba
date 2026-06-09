import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestTypeConversions(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "type_conversions.py").read_text(),
            str(HERE / "type_conversions"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./type_conversions.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"type_conversions{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # int → bool
    # ------------------------------------------------------------------

    async def test_int_to_bool_zero_is_false(self) -> None:
        result, _ = await self.call("int_to_bool", [0], return_type=bool)
        self.assertFalse(result)

    async def test_int_to_bool_one_is_true(self) -> None:
        result, _ = await self.call("int_to_bool", [1], return_type=bool)
        self.assertTrue(result)

    async def test_int_to_bool_negative_is_true(self) -> None:
        result, _ = await self.call("int_to_bool", [-1], return_type=bool)
        self.assertTrue(result)

    async def test_int_to_bool_large_is_true(self) -> None:
        result, _ = await self.call("int_to_bool", [1000], return_type=bool)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # bool → int
    # ------------------------------------------------------------------

    async def test_bool_to_int_true_is_one(self) -> None:
        result, _ = await self.call("bool_to_int", [True], return_type=int)
        self.assertEqual(result, 1)

    async def test_bool_to_int_false_is_zero(self) -> None:
        result, _ = await self.call("bool_to_int", [False], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # str → int  (NeoVM: LE signed integer, NOT a decimal parse)
    # ------------------------------------------------------------------

    async def test_str_to_int_single_byte(self) -> None:
        result, _ = await self.call("str_to_int", [b"\x05"], return_type=int)
        self.assertEqual(result, 5)

    async def test_str_to_int_empty_is_zero(self) -> None:
        result, _ = await self.call("str_to_int", [b""], return_type=int)
        self.assertEqual(result, 0)

    async def test_str_to_int_ff_is_minus_one(self) -> None:
        """b'\\xff' is one byte with all bits set — LE signed = -1, not 255."""
        result, _ = await self.call("str_to_int", [b"\xff"], return_type=int)
        self.assertEqual(result, -1)

    async def test_str_to_int_fe_is_minus_two(self) -> None:
        result, _ = await self.call("str_to_int", [b"\xfe"], return_type=int)
        self.assertEqual(result, -2)

    async def test_str_to_int_two_bytes_le_small(self) -> None:
        """b'\\x01\\x00' = LE 0x0001 = 1 (not 256 as big-endian would give)."""
        result, _ = await self.call("str_to_int", [b"\x01\x00"], return_type=int)
        self.assertEqual(result, 1)

    async def test_str_to_int_two_bytes_le_256(self) -> None:
        """b'\\x00\\x01' = LE 0x0100 = 256."""
        result, _ = await self.call("str_to_int", [b"\x00\x01"], return_type=int)
        self.assertEqual(result, 256)

    # ------------------------------------------------------------------
    # bytes → int  (same LE signed semantics as str → int)
    # ------------------------------------------------------------------

    async def test_bytes_to_int_single_byte(self) -> None:
        result, _ = await self.call("bytes_to_int", [b"\x05"], return_type=int)
        self.assertEqual(result, 5)

    async def test_bytes_to_int_empty_is_zero(self) -> None:
        result, _ = await self.call("bytes_to_int", [b""], return_type=int)
        self.assertEqual(result, 0)

    async def test_bytes_to_int_ff_is_minus_one(self) -> None:
        result, _ = await self.call("bytes_to_int", [b"\xff"], return_type=int)
        self.assertEqual(result, -1)

    async def test_bytes_to_int_two_bytes_le_256(self) -> None:
        result, _ = await self.call("bytes_to_int", [b"\x00\x01"], return_type=int)
        self.assertEqual(result, 256)

    async def test_bytes_to_int_two_bytes_le_small(self) -> None:
        result, _ = await self.call("bytes_to_int", [b"\x01\x00"], return_type=int)
        self.assertEqual(result, 1)

    # ------------------------------------------------------------------
    # bytearray → int
    # ------------------------------------------------------------------

    async def test_bytearray_to_int_small(self) -> None:
        result, _ = await self.call(
            "bytearray_to_int_single_byte", [5], return_type=int
        )
        self.assertEqual(result, 5)

    async def test_bytearray_to_int_127(self) -> None:
        result, _ = await self.call(
            "bytearray_to_int_single_byte", [127], return_type=int
        )
        self.assertEqual(result, 127)

    async def test_bytearray_to_int_255_is_minus_one(self) -> None:
        """ba[0] = 255 stores 0xFF; int(ba) interprets as LE signed = -1."""
        result, _ = await self.call(
            "bytearray_to_int_single_byte", [255], return_type=int
        )
        self.assertEqual(result, -1)

    async def test_bytearray_to_int_two_bytes_le_256(self) -> None:
        """ba = [0x00, 0x01]; int(ba) = LE 0x0100 = 256."""
        result, _ = await self.call(
            "bytearray_to_int_two_bytes", [0, 1], return_type=int
        )
        self.assertEqual(result, 256)

    async def test_bytearray_to_int_two_bytes_le_small(self) -> None:
        result, _ = await self.call(
            "bytearray_to_int_two_bytes", [1, 0], return_type=int
        )
        self.assertEqual(result, 1)

    # ------------------------------------------------------------------
    # int → str  (itoa base 10: decimal string)
    # ------------------------------------------------------------------

    async def test_int_to_str_one(self) -> None:
        """str(1) → '1' (decimal string via itoa)."""
        result, _ = await self.call("int_to_str", [1], return_type=str)
        self.assertEqual(result, "1")

    async def test_int_to_str_zero_is_empty(self) -> None:
        """str(0) → '0'."""
        result, _ = await self.call("int_to_str", [0], return_type=str)
        self.assertEqual(result, "0")

    async def test_int_to_str_minus_one(self) -> None:
        """str(-1) → '-1'."""
        result, _ = await self.call("int_to_str", [-1], return_type=str)
        self.assertEqual(result, "-1")

    async def test_int_to_str_minus_two(self) -> None:
        result, _ = await self.call("int_to_str", [-2], return_type=str)
        self.assertEqual(result, "-2")

    async def test_int_to_str_256(self) -> None:
        """str(256) → '256'."""
        result, _ = await self.call("int_to_str", [256], return_type=str)
        self.assertEqual(result, "256")

    async def test_int_to_bytes_one(self) -> None:
        """bytes(1) uses the same CONVERT 0x28 opcode as str(1)."""
        result, _ = await self.call("int_to_bytes", [1], return_type=bytes)
        self.assertEqual(result, b"\x01")

    async def test_int_to_bytes_zero_is_empty(self) -> None:
        result, _ = await self.call("int_to_bytes", [0], return_type=bytes)
        self.assertEqual(result, b"")

    async def test_int_to_bytes_256(self) -> None:
        result, _ = await self.call("int_to_bytes", [256], return_type=bytes)
        self.assertEqual(result, b"\x00\x01")

    # ------------------------------------------------------------------
    # bool → str  (Python semantics: "True" / "False")
    # ------------------------------------------------------------------

    async def test_bool_to_str_true(self) -> None:
        """str(True) → 'True' — Python semantics via IfExp ternary."""
        result, _ = await self.call("bool_to_str", [True], return_type=str)
        self.assertEqual(result, "True")

    async def test_bool_to_str_false(self) -> None:
        """str(False) → 'False' — Python semantics via IfExp ternary."""
        result, _ = await self.call("bool_to_str", [False], return_type=str)
        self.assertEqual(result, "False")

    async def test_bool_to_bytes_true(self) -> None:
        result, _ = await self.call("bool_to_bytes", [True], return_type=bytes)
        self.assertEqual(result, b"\x01")

    async def test_bool_to_bytes_false(self) -> None:
        """bytes(False) → b'\\x00' — same 1-byte Boolean encoding as str(False)."""
        result, _ = await self.call("bool_to_bytes", [False], return_type=bytes)
        self.assertEqual(result, b"\x00")

    # ------------------------------------------------------------------
    # str / bytes → bool  (empty = False, non-empty = True)
    # ------------------------------------------------------------------

    async def test_str_to_bool_nonempty_is_true(self) -> None:
        result, _ = await self.call("str_to_bool", [b"hello"], return_type=bool)
        self.assertTrue(result)

    async def test_str_to_bool_empty_is_false(self) -> None:
        result, _ = await self.call("str_to_bool", [b""], return_type=bool)
        self.assertFalse(result)

    async def test_str_to_bool_zero_byte_is_false(self) -> None:
        """NeoVM divergence: bool(b'\\x00') = False. NeoVM interprets the bytes as a
        LE integer (\\x00 = 0) and converts that to bool. Python returns True because
        b'\\x00' is a non-empty object."""
        result, _ = await self.call("str_to_bool", [b"\x00"], return_type=bool)
        self.assertFalse(result)

    async def test_bytes_to_bool_nonempty_is_true(self) -> None:
        result, _ = await self.call("bytes_to_bool", [b"\x01"], return_type=bool)
        self.assertTrue(result)

    async def test_bytes_to_bool_empty_is_false(self) -> None:
        result, _ = await self.call("bytes_to_bool", [b""], return_type=bool)
        self.assertFalse(result)

    async def test_bytes_to_bool_zero_byte_is_false(self) -> None:
        """NeoVM divergence: bool(b'\\x00') = False. NeoVM interprets bytes as a LE
        integer (\\x00 = 0) then checks non-zero. Python returns True (non-empty)."""
        result, _ = await self.call("bytes_to_bool", [b"\x00"], return_type=bool)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # str ↔ bytes  (both are ByteString at the VM level; identity at runtime)
    # ------------------------------------------------------------------

    async def test_str_to_bytes_basic(self) -> None:
        result, _ = await self.call("str_to_bytes", ["hello"], return_type=bytes)
        self.assertEqual(result, b"hello")

    async def test_str_to_bytes_empty(self) -> None:
        result, _ = await self.call("str_to_bytes", [""], return_type=bytes)
        self.assertEqual(result, b"")

    async def test_str_to_bytes_binary(self) -> None:
        result, _ = await self.call(
            "str_to_bytes", [b"\x01\x02\x03"], return_type=bytes
        )
        self.assertEqual(result, b"\x01\x02\x03")

    async def test_bytes_to_str_basic(self) -> None:
        result, _ = await self.call("bytes_to_str", [b"hello"], return_type=str)
        self.assertEqual("hello", result)

    async def test_bytes_to_str_empty(self) -> None:
        result, _ = await self.call("bytes_to_str", [b""], return_type=str)
        self.assertEqual("", result)

    # ------------------------------------------------------------------
    # bytearray → bytes / str  (Buffer → ByteString)
    # ------------------------------------------------------------------

    async def test_bytearray_to_bytes_nonzero(self) -> None:
        result, _ = await self.call(
            "bytearray_to_bytes_single", [65], return_type=bytes
        )
        self.assertEqual(result, b"\x41")

    async def test_bytearray_to_bytes_zero_byte(self) -> None:
        result, _ = await self.call("bytearray_to_bytes_single", [0], return_type=bytes)
        self.assertEqual(result, b"\x00")

    async def test_bytearray_to_str_nonzero(self) -> None:
        result, _ = await self.call("bytearray_to_str_single", [65], return_type=bytes)
        self.assertEqual(result, b"\x41")

    # ------------------------------------------------------------------
    # identity conversions
    # ------------------------------------------------------------------

    async def test_int_to_int_positive(self) -> None:
        result, _ = await self.call("int_to_int", [42], return_type=int)
        self.assertEqual(result, 42)

    async def test_int_to_int_negative(self) -> None:
        result, _ = await self.call("int_to_int", [-7], return_type=int)
        self.assertEqual(result, -7)

    async def test_bool_to_bool_true(self) -> None:
        result, _ = await self.call("bool_to_bool", [True], return_type=bool)
        self.assertTrue(result)

    async def test_bool_to_bool_false(self) -> None:
        result, _ = await self.call("bool_to_bool", [False], return_type=bool)
        self.assertFalse(result)

    async def test_str_to_str_identity(self) -> None:
        result, _ = await self.call("str_to_str", [b"hello"], return_type=bytes)
        self.assertEqual(result, b"hello")

    async def test_bytes_to_bytes_identity(self) -> None:
        result, _ = await self.call("bytes_to_bytes", [b"\xab\xcd"], return_type=bytes)
        self.assertEqual(result, b"\xab\xcd")

    # ------------------------------------------------------------------
    # compile-time errors — compound and Optional types are rejected
    # ------------------------------------------------------------------

    def test_int_from_list_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: list[int]) -> int:\n    return int(x)\n",
                "/tmp/throwaway",
            )

    def test_int_from_dict_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: dict[str, int]) -> int:\n    return int(x)\n",
                "/tmp/throwaway",
            )

    def test_int_from_optional_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from typing import Optional\n"
                "from neo3.sc.compiletime import public\n@public\ndef f(x: Optional[int]) -> int:\n    return int(x)\n",
                "/tmp/throwaway",
            )

    def test_bool_from_list_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: list[int]) -> bool:\n    return bool(x)\n",
                "/tmp/throwaway",
            )

    def test_bool_from_optional_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from typing import Optional\n"
                "from neo3.sc.compiletime import public\n@public\ndef f(x: Optional[bool]) -> bool:\n    return bool(x)\n",
                "/tmp/throwaway",
            )

    def test_str_from_list_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: list[int]) -> str:\n    return str(x)\n",
                "/tmp/throwaway",
            )

    def test_str_from_optional_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from typing import Optional\n"
                "from neo3.sc.compiletime import public\n@public\ndef f(x: Optional[str]) -> str:\n    return str(x)\n",
                "/tmp/throwaway",
            )

    def test_bytes_from_list_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: list[int]) -> bytes:\n    return bytes(x)\n",
                "/tmp/throwaway",
            )

    def test_bytes_from_dict_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: dict[str, int]) -> bytes:\n    return bytes(x)\n",
                "/tmp/throwaway",
            )

    def test_bytes_from_optional_is_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from typing import Optional\n"
                "from neo3.sc.compiletime import public\n@public\ndef f(x: Optional[bytes]) -> bytes:\n    return bytes(x)\n",
                "/tmp/throwaway",
            )


if __name__ == "__main__":
    unittest.main()
