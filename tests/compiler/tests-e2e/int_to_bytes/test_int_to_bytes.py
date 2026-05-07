import asyncio
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestIntToBytes(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "int_to_bytes.py").read_text(),
            str(HERE / "int_to_bytes"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./int_to_bytes.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"int_to_bytes{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ── little-endian unsigned ────────────────────────────────────────────────

    async def test_le_unsigned_zero(self) -> None:
        result, _ = await self.call("to_le_unsigned", [0, 2], return_type=bytes)
        self.assertEqual(result, (0).to_bytes(2, "little"))

    async def test_le_unsigned_127(self) -> None:
        result, _ = await self.call("to_le_unsigned", [127, 1], return_type=bytes)
        self.assertEqual(result, (127).to_bytes(1, "little"))

    async def test_le_unsigned_128(self) -> None:
        # 128 needs the sign byte stripped — LEFT(1) on \x80\x00 gives \x80
        result, _ = await self.call("to_le_unsigned", [128, 1], return_type=bytes)
        self.assertEqual(result, (128).to_bytes(1, "little"))

    async def test_le_unsigned_255(self) -> None:
        result, _ = await self.call("to_le_unsigned", [255, 1], return_type=bytes)
        self.assertEqual(result, (255).to_bytes(1, "little"))

    async def test_le_unsigned_255_2bytes(self) -> None:
        result, _ = await self.call("to_le_unsigned", [255, 2], return_type=bytes)
        self.assertEqual(result, (255).to_bytes(2, "little"))

    async def test_le_unsigned_65535(self) -> None:
        result, _ = await self.call("to_le_unsigned", [65535, 2], return_type=bytes)
        self.assertEqual(result, (65535).to_bytes(2, "little"))

    async def test_le_unsigned_256(self) -> None:
        result, _ = await self.call("to_le_unsigned", [256, 2], return_type=bytes)
        self.assertEqual(result, (256).to_bytes(2, "little"))

    # ── little-endian signed ──────────────────────────────────────────────────

    async def test_le_signed_zero(self) -> None:
        result, _ = await self.call("to_le_signed", [0, 2], return_type=bytes)
        self.assertEqual(result, (0).to_bytes(2, "little", signed=True))

    async def test_le_signed_127(self) -> None:
        result, _ = await self.call("to_le_signed", [127, 1], return_type=bytes)
        self.assertEqual(result, (127).to_bytes(1, "little", signed=True))

    async def test_le_signed_minus1(self) -> None:
        result, _ = await self.call("to_le_signed", [-1, 2], return_type=bytes)
        self.assertEqual(result, (-1).to_bytes(2, "little", signed=True))

    async def test_le_signed_minus128(self) -> None:
        result, _ = await self.call("to_le_signed", [-128, 1], return_type=bytes)
        self.assertEqual(result, (-128).to_bytes(1, "little", signed=True))

    async def test_le_signed_minus129(self) -> None:
        result, _ = await self.call("to_le_signed", [-129, 2], return_type=bytes)
        self.assertEqual(result, (-129).to_bytes(2, "little", signed=True))

    async def test_le_signed_0x7fff(self) -> None:
        result, _ = await self.call("to_le_signed", [0x7FFF, 2], return_type=bytes)
        self.assertEqual(result, (0x7FFF).to_bytes(2, "little", signed=True))

    async def test_le_signed_minus1_4bytes(self) -> None:
        # -1 sign-extended to 4 bytes → \xff\xff\xff\xff
        result, _ = await self.call("to_le_signed", [-1, 4], return_type=bytes)
        self.assertEqual(result, (-1).to_bytes(4, "little", signed=True))

    # ── big-endian unsigned ───────────────────────────────────────────────────

    async def test_be_unsigned_zero(self) -> None:
        result, _ = await self.call("to_be_unsigned", [0, 2], return_type=bytes)
        self.assertEqual(result, (0).to_bytes(2, "big"))

    async def test_be_unsigned_127(self) -> None:
        result, _ = await self.call("to_be_unsigned", [127, 1], return_type=bytes)
        self.assertEqual(result, (127).to_bytes(1, "big"))

    async def test_be_unsigned_128(self) -> None:
        result, _ = await self.call("to_be_unsigned", [128, 1], return_type=bytes)
        self.assertEqual(result, (128).to_bytes(1, "big"))

    async def test_be_unsigned_255(self) -> None:
        result, _ = await self.call("to_be_unsigned", [255, 1], return_type=bytes)
        self.assertEqual(result, (255).to_bytes(1, "big"))

    async def test_be_unsigned_256(self) -> None:
        result, _ = await self.call("to_be_unsigned", [256, 2], return_type=bytes)
        self.assertEqual(result, (256).to_bytes(2, "big"))

    async def test_be_unsigned_65535(self) -> None:
        result, _ = await self.call("to_be_unsigned", [65535, 2], return_type=bytes)
        self.assertEqual(result, (65535).to_bytes(2, "big"))

    # ── big-endian signed ─────────────────────────────────────────────────────

    async def test_be_signed_zero(self) -> None:
        result, _ = await self.call("to_be_signed", [0, 2], return_type=bytes)
        self.assertEqual(result, (0).to_bytes(2, "big", signed=True))

    async def test_be_signed_127(self) -> None:
        result, _ = await self.call("to_be_signed", [127, 1], return_type=bytes)
        self.assertEqual(result, (127).to_bytes(1, "big", signed=True))

    async def test_be_signed_minus1(self) -> None:
        result, _ = await self.call("to_be_signed", [-1, 2], return_type=bytes)
        self.assertEqual(result, (-1).to_bytes(2, "big", signed=True))

    async def test_be_signed_minus128(self) -> None:
        result, _ = await self.call("to_be_signed", [-128, 1], return_type=bytes)
        self.assertEqual(result, (-128).to_bytes(1, "big", signed=True))

    async def test_be_signed_minus1_4bytes(self) -> None:
        result, _ = await self.call("to_be_signed", [-1, 4], return_type=bytes)
        self.assertEqual(result, (-1).to_bytes(4, "big", signed=True))

    async def test_be_signed_0x7fff(self) -> None:
        result, _ = await self.call("to_be_signed", [0x7FFF, 2], return_type=bytes)
        self.assertEqual(result, (0x7FFF).to_bytes(2, "big", signed=True))

    # ── constant folding (compile-time) ───────────────────────────────────────

    async def test_const_le(self) -> None:
        # (256).to_bytes(2, 'little') → b'\x00\x01'
        result, _ = await self.call("const_le", [], return_type=bytes)
        self.assertEqual(result, (256).to_bytes(2, "little"))

    async def test_const_be(self) -> None:
        # (256).to_bytes(2, 'big') → b'\x01\x00'
        result, _ = await self.call("const_be", [], return_type=bytes)
        self.assertEqual(result, (256).to_bytes(2, "big"))

    # ── default args ──────────────────────────────────────────────────────────

    async def test_default_args_5(self) -> None:
        # x.to_bytes() → length=1, byteorder='big'
        result, _ = await self.call("default_args", [5], return_type=bytes)
        self.assertEqual(result, (5).to_bytes(1, "big"))

    async def test_default_args_zero(self) -> None:
        result, _ = await self.call("default_args", [0], return_type=bytes)
        self.assertEqual(result, (0).to_bytes(1, "big"))

    # ── overflow: unsigned little-endian faults ───────────────────────────────

    async def test_le_unsigned_overflow_too_large(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("to_le_unsigned", [256, 1], return_type=bytes)

    async def test_le_unsigned_overflow_negative(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("to_le_unsigned", [-1, 1], return_type=bytes)

    # ── overflow: unsigned big-endian faults ──────────────────────────────────

    async def test_be_unsigned_overflow_too_large(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("to_be_unsigned", [256, 1], return_type=bytes)

    async def test_be_unsigned_overflow_negative(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("to_be_unsigned", [-1, 1], return_type=bytes)

    # ── overflow: signed little-endian faults ────────────────────────────────

    async def test_le_signed_overflow_positive(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("to_le_signed", [128, 1], return_type=bytes)

    async def test_le_signed_overflow_negative(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("to_le_signed", [-129, 1], return_type=bytes)

    # ── overflow: signed big-endian faults ───────────────────────────────────

    async def test_be_signed_overflow_positive(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("to_be_signed", [128, 1], return_type=bytes)

    async def test_be_signed_overflow_negative(self) -> None:
        with self.assertRaises(ValueError):
            await self.call("to_be_signed", [-129, 1], return_type=bytes)

    # ── overflow: compile-time constants raise TypecheckError ─────────────────

    def test_constant_overflow_unsigned(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n"
                "@public\ndef f() -> bytes:\n    return (256).to_bytes(1, 'little')\n",
                "/tmp/throwaway",
            )

    def test_constant_overflow_signed(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n"
                "@public\ndef f() -> bytes:\n    return (128).to_bytes(1, 'little', signed=True)\n",
                "/tmp/throwaway",
            )

    def test_constant_negative_unsigned(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n"
                "@public\ndef f() -> bytes:\n    return (-1).to_bytes(1, 'little')\n",
                "/tmp/throwaway",
            )
