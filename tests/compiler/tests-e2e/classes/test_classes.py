import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestClasses(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef((HERE / "classes.py").read_text(), str(HERE / "classes"))
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./classes.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"classes{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # Counter — __init__, void increment, field read
    # ------------------------------------------------------------------

    async def test_counter_zero_steps(self) -> None:
        result, _ = await self.call("counter_basic", [5, 0], return_type=int)
        self.assertEqual(result, 5)

    async def test_counter_one_step(self) -> None:
        result, _ = await self.call("counter_basic", [3, 1], return_type=int)
        self.assertEqual(result, 4)

    async def test_counter_five_steps(self) -> None:
        result, _ = await self.call("counter_basic", [10, 5], return_type=int)
        self.assertEqual(result, 15)

    async def test_counter_add_positive(self) -> None:
        result, _ = await self.call("counter_add", [7, 3], return_type=int)
        self.assertEqual(result, 10)

    async def test_counter_add_zero(self) -> None:
        result, _ = await self.call("counter_add", [7, 0], return_type=int)
        self.assertEqual(result, 7)

    async def test_two_counters_independent(self) -> None:
        # x starts at 10, incremented once → 11; y starts at 20; sum = 31
        result, _ = await self.call("two_counters", [10, 20], return_type=int)
        self.assertEqual(result, 31)

    # ------------------------------------------------------------------
    # Point — multiple fields, method using both
    # ------------------------------------------------------------------

    async def test_point_manhattan_basic(self) -> None:
        result, _ = await self.call("point_manhattan", [3, 4], return_type=int)
        self.assertEqual(result, 7)

    async def test_point_manhattan_zero(self) -> None:
        result, _ = await self.call("point_manhattan", [0, 0], return_type=int)
        self.assertEqual(result, 0)

    async def test_point_scale_doubles(self) -> None:
        # (3,4) scaled by 2 → (6,8), manhattan = 14
        result, _ = await self.call("point_scale", [3, 4, 2], return_type=int)
        self.assertEqual(result, 14)

    async def test_point_scale_by_one(self) -> None:
        result, _ = await self.call("point_scale", [5, 6, 1], return_type=int)
        self.assertEqual(result, 11)

    # ------------------------------------------------------------------
    # @staticmethod
    # ------------------------------------------------------------------

    async def test_static_square_basic(self) -> None:
        result, _ = await self.call("static_square", [5], return_type=int)
        self.assertEqual(result, 25)

    async def test_static_square_zero(self) -> None:
        result, _ = await self.call("static_square", [0], return_type=int)
        self.assertEqual(result, 0)

    async def test_static_square_negative(self) -> None:
        result, _ = await self.call("static_square", [-4], return_type=int)
        self.assertEqual(result, 16)

    async def test_static_add(self) -> None:
        result, _ = await self.call("static_add", [7, 3], return_type=int)
        self.assertEqual(result, 10)

    # ------------------------------------------------------------------
    # Class variable (module-level static)
    # ------------------------------------------------------------------

    async def test_class_var_get(self) -> None:
        result, _ = await self.call("class_var_get", [], return_type=int)
        self.assertEqual(result, 42)

    # ------------------------------------------------------------------
    # Inheritance + super().__init__
    # ------------------------------------------------------------------

    async def test_dog_weight(self) -> None:
        result, _ = await self.call("dog_weight", [30, 5], return_type=int)
        self.assertEqual(result, 30)

    async def test_dog_age(self) -> None:
        result, _ = await self.call("dog_age", [30, 5], return_type=int)
        self.assertEqual(result, 5)

    async def test_dog_total(self) -> None:
        # weight=30, age=5, total=35
        result, _ = await self.call("dog_total", [30, 5], return_type=int)
        self.assertEqual(result, 35)

    async def test_dog_zero_weight(self) -> None:
        result, _ = await self.call("dog_weight", [0, 3], return_type=int)
        self.assertEqual(result, 0)

    # ------------------------------------------------------------------
    # @classmethod factory
    # ------------------------------------------------------------------

    async def test_classmethod_default(self) -> None:
        result, _ = await self.call("classmethod_default", [], return_type=int)
        self.assertEqual(result, 10)

    async def test_classmethod_explicit(self) -> None:
        result, _ = await self.call("classmethod_explicit", [99], return_type=int)
        self.assertEqual(result, 99)


if __name__ == "__main__":
    unittest.main()
