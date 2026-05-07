import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestDefaultArgs(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "default_args.py").read_text(),
            str(HERE / "default_args"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./default_args.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"default_args{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # single default
    # ------------------------------------------------------------------

    async def test_add_with_default(self) -> None:
        result, _ = await self.call("add_with_default", [3], return_type=int)
        self.assertEqual(result, 8)  # 3 + 5 (default)

    async def test_add_explicit(self) -> None:
        result, _ = await self.call("add_explicit", [3, 10], return_type=int)
        self.assertEqual(result, 13)  # 3 + 10

    # ------------------------------------------------------------------
    # multiple defaults
    # ------------------------------------------------------------------

    async def test_combine_all_defaults(self) -> None:
        result, _ = await self.call("combine_all_defaults", [10], return_type=int)
        self.assertEqual(result, 15)  # 10 + 2 + 3

    async def test_combine_one_default(self) -> None:
        result, _ = await self.call("combine_one_default", [10, 20], return_type=int)
        self.assertEqual(result, 33)  # 10 + 20 + 3

    async def test_combine_no_defaults(self) -> None:
        result, _ = await self.call(
            "combine_no_defaults", [10, 20, 30], return_type=int
        )
        self.assertEqual(result, 60)

    # ------------------------------------------------------------------
    # bool default
    # ------------------------------------------------------------------

    async def test_guarded_default(self) -> None:
        result, _ = await self.call("guarded_default", [7], return_type=int)
        self.assertEqual(result, 14)  # flag=True → x * 2

    async def test_guarded_explicit_false(self) -> None:
        result, _ = await self.call("guarded_explicit_false", [7], return_type=int)
        self.assertEqual(result, 7)  # flag=False → x

    # ------------------------------------------------------------------
    # str default
    # ------------------------------------------------------------------

    async def test_greet_default(self) -> None:
        result, _ = await self.call("greet_default", ["World"], return_type=str)
        self.assertEqual(result, "HelloWorld")

    async def test_greet_explicit(self) -> None:
        result, _ = await self.call("greet_explicit", ["World", "Hi"], return_type=str)
        self.assertEqual(result, "HiWorld")

    # ------------------------------------------------------------------
    # None default
    # ------------------------------------------------------------------

    async def test_absent_default(self) -> None:
        result, _ = await self.call("absent_default", [], return_type=bool)
        self.assertEqual(result, True)

    async def test_absent_explicit(self) -> None:
        result, _ = await self.call("absent_explicit", [42], return_type=bool)
        self.assertEqual(result, False)

    # ------------------------------------------------------------------
    # all-defaults function
    # ------------------------------------------------------------------

    async def test_point_no_args(self) -> None:
        result, _ = await self.call("point_no_args", [], return_type=int)
        self.assertEqual(result, 0)  # 0 + 0

    async def test_point_one_arg(self) -> None:
        result, _ = await self.call("point_one_arg", [5], return_type=int)
        self.assertEqual(result, 5)  # 5 + 0

    async def test_point_two_args(self) -> None:
        result, _ = await self.call("point_two_args", [3, 4], return_type=int)
        self.assertEqual(result, 7)

    # ------------------------------------------------------------------
    # compile-time error: non-literal default
    # ------------------------------------------------------------------

    def test_non_literal_default_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef f(x: int = some_var) -> int:\n    return x\n",
                "/tmp/throwaway",
            )

    def test_nested_function_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n@public\ndef outer(x: int) -> int:\n    def inner(y: int) -> int:\n        return y\n    return inner(x)\n",
                "/tmp/throwaway",
            )
