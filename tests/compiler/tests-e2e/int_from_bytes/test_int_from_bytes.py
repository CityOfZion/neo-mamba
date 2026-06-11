import asyncio
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestIntFromBytes(SmartContractTestCase):
    """
    ┌───────────────────┬───────┬─────────────────────────────────────────────────────────────────┐
    │       Group       │ Tests │                         What's verified                         │
    ├───────────────────┼───────┼─────────────────────────────────────────────────────────────────┤
    │ LE unsigned       │ 7     │ zero, 127, 128 (high-bit guard), 255, 256, 65535, 32768         │
    ├───────────────────┼───────┼─────────────────────────────────────────────────────────────────┤
    │ LE signed         │ 7     │ zero, 127, −1 (\xff), −128 (\x80), 32767, −32768, multi-byte −1 │
    ├───────────────────┼───────┼─────────────────────────────────────────────────────────────────┤
    │ BE unsigned       │ 7     │ zero, 127, 128 (high-bit guard), 255, 256, 65535, 32768         │
    ├───────────────────┼───────┼─────────────────────────────────────────────────────────────────┤
    │ BE signed         │ 8     │ zero, 127, −1, −128, 258, 32767, −32768, multi-byte −1          │
    ├───────────────────┼───────┼─────────────────────────────────────────────────────────────────┤
    │ Constant folding  │ 2     │ LE and BE literals folded at compile time                       │
    ├───────────────────┼───────┼─────────────────────────────────────────────────────────────────┤
    │ Default byteorder │ 3     │ int.from_bytes(b) defaults to 'big'                             │
    └───────────────────┴───────┴─────────────────────────────────────────────────────────────────┘
    """

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "int_from_bytes.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./int_from_bytes.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"int_from_bytes{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ── little-endian unsigned ────────────────────────────────────────────────

    async def test_le_unsigned_zero(self) -> None:
        result, _ = await self.call("from_le_unsigned", [b"\x00"], return_type=int)
        self.assertEqual(result, int.from_bytes(b"\x00", "little"))

    async def test_le_unsigned_127(self) -> None:
        result, _ = await self.call("from_le_unsigned", [b"\x7f"], return_type=int)
        self.assertEqual(result, 127)

    async def test_le_unsigned_128(self) -> None:
        # \x80 has high bit set; unsigned flag appends \x00 → LE value = 128
        result, _ = await self.call("from_le_unsigned", [b"\x80"], return_type=int)
        self.assertEqual(result, 128)

    async def test_le_unsigned_255(self) -> None:
        result, _ = await self.call("from_le_unsigned", [b"\xff"], return_type=int)
        self.assertEqual(result, 255)

    async def test_le_unsigned_256(self) -> None:
        result, _ = await self.call("from_le_unsigned", [b"\x00\x01"], return_type=int)
        self.assertEqual(result, 256)

    async def test_le_unsigned_65535(self) -> None:
        result, _ = await self.call("from_le_unsigned", [b"\xff\xff"], return_type=int)
        self.assertEqual(result, 65535)

    async def test_le_unsigned_32768(self) -> None:
        # \x00\x80 in LE unsigned = 32768 (high bit of appended \x00 is clear)
        result, _ = await self.call("from_le_unsigned", [b"\x00\x80"], return_type=int)
        self.assertEqual(result, int.from_bytes(b"\x00\x80", "little"))

    # ── little-endian signed ──────────────────────────────────────────────────

    async def test_le_signed_zero(self) -> None:
        result, _ = await self.call("from_le_signed", [b"\x00"], return_type=int)
        self.assertEqual(result, 0)

    async def test_le_signed_127(self) -> None:
        result, _ = await self.call("from_le_signed", [b"\x7f"], return_type=int)
        self.assertEqual(result, 127)

    async def test_le_signed_minus1(self) -> None:
        # \xff in LE signed = -1
        result, _ = await self.call("from_le_signed", [b"\xff"], return_type=int)
        self.assertEqual(result, -1)

    async def test_le_signed_minus128(self) -> None:
        # \x80 in LE signed = -128
        result, _ = await self.call("from_le_signed", [b"\x80"], return_type=int)
        self.assertEqual(result, -128)

    async def test_le_signed_32767(self) -> None:
        result, _ = await self.call("from_le_signed", [b"\xff\x7f"], return_type=int)
        self.assertEqual(result, int.from_bytes(b"\xff\x7f", "little", signed=True))

    async def test_le_signed_minus32768(self) -> None:
        # \x00\x80 in LE signed = -32768 (MSB 0x80 has high bit set)
        result, _ = await self.call("from_le_signed", [b"\x00\x80"], return_type=int)
        self.assertEqual(result, -32768)

    async def test_le_signed_minus1_multibyte(self) -> None:
        result, _ = await self.call(
            "from_le_signed", [b"\xff\xff\xff\xff"], return_type=int
        )
        self.assertEqual(result, -1)

    # ── big-endian unsigned ───────────────────────────────────────────────────

    async def test_be_unsigned_zero(self) -> None:
        result, _ = await self.call("from_be_unsigned", [b"\x00"], return_type=int)
        self.assertEqual(result, 0)

    async def test_be_unsigned_127(self) -> None:
        result, _ = await self.call("from_be_unsigned", [b"\x7f"], return_type=int)
        self.assertEqual(result, 127)

    async def test_be_unsigned_128(self) -> None:
        # \x80 has high bit set; unsigned appends \x00 guard byte after reversing
        result, _ = await self.call("from_be_unsigned", [b"\x80"], return_type=int)
        self.assertEqual(result, 128)

    async def test_be_unsigned_255(self) -> None:
        result, _ = await self.call("from_be_unsigned", [b"\xff"], return_type=int)
        self.assertEqual(result, 255)

    async def test_be_unsigned_256(self) -> None:
        result, _ = await self.call("from_be_unsigned", [b"\x01\x00"], return_type=int)
        self.assertEqual(result, 256)

    async def test_be_unsigned_65535(self) -> None:
        result, _ = await self.call("from_be_unsigned", [b"\xff\xff"], return_type=int)
        self.assertEqual(result, 65535)

    async def test_be_unsigned_32768(self) -> None:
        result, _ = await self.call("from_be_unsigned", [b"\x80\x00"], return_type=int)
        self.assertEqual(result, int.from_bytes(b"\x80\x00", "big"))

    # ── big-endian signed ─────────────────────────────────────────────────────

    async def test_be_signed_zero(self) -> None:
        result, _ = await self.call("from_be_signed", [b"\x00"], return_type=int)
        self.assertEqual(result, 0)

    async def test_be_signed_127(self) -> None:
        result, _ = await self.call("from_be_signed", [b"\x7f"], return_type=int)
        self.assertEqual(result, 127)

    async def test_be_signed_minus1(self) -> None:
        # \xff in BE signed = -1
        result, _ = await self.call("from_be_signed", [b"\xff"], return_type=int)
        self.assertEqual(result, -1)

    async def test_be_signed_minus128(self) -> None:
        result, _ = await self.call("from_be_signed", [b"\x80"], return_type=int)
        self.assertEqual(result, -128)

    async def test_be_signed_258(self) -> None:
        result, _ = await self.call("from_be_signed", [b"\x01\x02"], return_type=int)
        self.assertEqual(result, 258)

    async def test_be_signed_minus32768(self) -> None:
        result, _ = await self.call("from_be_signed", [b"\x80\x00"], return_type=int)
        self.assertEqual(result, -32768)

    async def test_be_signed_32767(self) -> None:
        result, _ = await self.call("from_be_signed", [b"\x7f\xff"], return_type=int)
        self.assertEqual(result, 32767)

    async def test_be_signed_minus1_multibyte(self) -> None:
        result, _ = await self.call(
            "from_be_signed", [b"\xff\xff\xff\xff"], return_type=int
        )
        self.assertEqual(result, -1)

    # ── constant folding (compile-time) ───────────────────────────────────────

    async def test_const_le(self) -> None:
        # int.from_bytes(b"\x00\x01", "little") → 256 folded to IntLiteral at compile time
        result, _ = await self.call("const_le", [], return_type=int)
        self.assertEqual(result, 256)

    async def test_const_be(self) -> None:
        # int.from_bytes(b"\x01\x00", "big") → 256 folded to IntLiteral at compile time
        result, _ = await self.call("const_be", [], return_type=int)
        self.assertEqual(result, 256)

    # ── default byteorder ('big') ─────────────────────────────────────────────

    async def test_default_byteorder_256(self) -> None:
        result, _ = await self.call("default_byteorder", [b"\x01\x00"], return_type=int)
        self.assertEqual(result, 256)

    async def test_default_byteorder_255(self) -> None:
        result, _ = await self.call("default_byteorder", [b"\xff"], return_type=int)
        self.assertEqual(result, 255)

    async def test_default_byteorder_zero(self) -> None:
        result, _ = await self.call("default_byteorder", [b"\x00"], return_type=int)
        self.assertEqual(result, 0)
