import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestImports(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef((HERE / "main.py").read_text(), str(HERE / "main"))
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./main.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"main{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # from utils import add
    # ------------------------------------------------------------------

    async def test_from_import_fn_basic(self) -> None:
        result, _ = await self.call("test_from_import_fn", [3, 4], return_type=int)
        self.assertEqual(result, 7)

    async def test_from_import_fn_zeros(self) -> None:
        result, _ = await self.call("test_from_import_fn", [0, 0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # import utils as u  →  u.add(...)
    # ------------------------------------------------------------------

    async def test_module_fn(self) -> None:
        result, _ = await self.call("test_module_fn", [10, 5], return_type=int)
        self.assertEqual(result, 15)

    # ------------------------------------------------------------------
    # from utils import add as plus
    # ------------------------------------------------------------------

    async def test_alias_fn(self) -> None:
        result, _ = await self.call("test_alias_fn", [7, 3], return_type=int)
        self.assertEqual(result, 10)

    async def test_alias_fn_zeros(self) -> None:
        result, _ = await self.call("test_alias_fn", [0, 0], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # from utils import MULTIPLIER  (static constant)
    # ------------------------------------------------------------------

    async def test_static_direct(self) -> None:
        result, _ = await self.call("test_static_direct", [], return_type=int)
        self.assertEqual(result, 3)

    # ------------------------------------------------------------------
    # import utils as u  →  u.MULTIPLIER
    # ------------------------------------------------------------------

    async def test_static_via_module(self) -> None:
        result, _ = await self.call("test_static_via_module", [], return_type=int)
        self.assertEqual(result, 3)

    # ------------------------------------------------------------------
    # from shapes import Rectangle
    # ------------------------------------------------------------------

    async def test_class_from_import_area(self) -> None:
        result, _ = await self.call("test_class_from_import", [4, 5], return_type=int)
        self.assertEqual(result, 20)

    async def test_class_from_import_unit(self) -> None:
        result, _ = await self.call("test_class_from_import", [1, 1], return_type=int)
        self.assertEqual(result, 1)

    # ------------------------------------------------------------------
    # import shapes  →  shapes.Rectangle(w, h).perimeter()
    # ------------------------------------------------------------------

    async def test_class_via_module_perimeter(self) -> None:
        result, _ = await self.call("test_class_via_module", [3, 4], return_type=int)
        self.assertEqual(result, 14)

    async def test_class_via_module_square(self) -> None:
        result, _ = await self.call("test_class_via_module", [5, 5], return_type=int)
        self.assertEqual(result, 20)

    # ------------------------------------------------------------------
    # multiply (tests transitive dep: multiply is in utils.py)
    # ------------------------------------------------------------------

    async def test_multiply(self) -> None:
        result, _ = await self.call("test_multiply", [3, 4], return_type=int)
        self.assertEqual(result, 12)

    async def test_multiply_zero(self) -> None:
        result, _ = await self.call("test_multiply", [0, 99], return_type=int)
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
