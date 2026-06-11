import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import AssertException, SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef, compile_module

HERE = Path(__file__).parent


class TestExceptions(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "exceptions.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./exceptions.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"exceptions{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # try/except — no exception
    # ------------------------------------------------------------------

    async def test_try_except_no_exception(self) -> None:
        result, _ = await self.call("try_except_no_exception", [], return_type=int)
        self.assertEqual(result, 42)

    # ------------------------------------------------------------------
    # try/except — exception raised
    # ------------------------------------------------------------------

    async def test_try_except_with_raise(self) -> None:
        result, _ = await self.call("try_except_with_raise", [], return_type=int)
        self.assertEqual(result, -1)

    async def test_try_except_assert_false_not_catchable(self) -> None:
        """NeoVM divergence: ASSERT faults the VM directly — not caught by TRY_L.
        Python: assert False raises AssertionError, catchable by bare except.
        NeoVM: ASSERT (0x39) is a VM-level fault, not a thrown exception, so
        the surrounding try/except cannot intercept it."""
        with self.assertRaises(AssertException):
            await self.call("try_except_assert_false", [], return_type=int)

    async def test_try_except_assertmsg_not_catchable(self) -> None:
        """NeoVM divergence: ASSERTMSG faults the VM directly — not caught by TRY_L.
        Python: assert False, "bad" raises AssertionError("bad"), catchable.
        NeoVM: ASSERTMSG (0xE1) is a VM-level fault with a message, but still
        cannot be intercepted by TRY_L's exception handler."""
        with self.assertRaises(AssertException):
            await self.call("try_except_assertmsg_caught", [], return_type=int)

    # ------------------------------------------------------------------
    # try/finally
    # ------------------------------------------------------------------

    async def test_try_finally_no_exception(self) -> None:
        """finally always runs on normal exit: try sets result=10, finally adds 5."""
        result, _ = await self.call("try_finally_no_exception", [], return_type=int)
        self.assertEqual(result, 15)

    # ------------------------------------------------------------------
    # try/except/finally
    # ------------------------------------------------------------------

    async def test_try_except_finally_no_exception(self) -> None:
        """No exception: try=10, except skipped, finally adds 100 → 110."""
        result, _ = await self.call(
            "try_except_finally_no_exception", [], return_type=int
        )
        self.assertEqual(result, 110)

    async def test_try_except_finally_with_exception(self) -> None:
        """Exception raised: except sets -1, finally adds 100 → 99."""
        result, _ = await self.call(
            "try_except_finally_with_exception", [], return_type=int
        )
        self.assertEqual(result, 99)

    # ------------------------------------------------------------------
    # cross-call propagation
    # ------------------------------------------------------------------

    async def test_cross_call_exception_caught(self) -> None:
        """Exception raised inside a helper function propagates through CALL_L
        and is caught by the surrounding try/except in the caller."""
        result, _ = await self.call("cross_call_exception_caught", [], return_type=int)
        self.assertEqual(result, -1)

    # ------------------------------------------------------------------
    # nested try
    # ------------------------------------------------------------------

    async def test_nested_try_inner_caught(self) -> None:
        """Inner try catches its own exception; outer try is not triggered.
        After inner except sets result=10, outer try body adds 1 → 11."""
        result, _ = await self.call("nested_try_inner_caught", [], return_type=int)
        self.assertEqual(result, 11)

    # ------------------------------------------------------------------
    # return inside try / except
    # ------------------------------------------------------------------

    async def test_return_in_try_body(self) -> None:
        result, _ = await self.call("return_in_try_body", [], return_type=int)
        self.assertEqual(result, 1)

    async def test_return_in_except_body(self) -> None:
        result, _ = await self.call("return_in_except_body", [], return_type=int)
        self.assertEqual(result, 2)

    # ------------------------------------------------------------------
    # code continues after try/except
    # ------------------------------------------------------------------

    async def test_code_after_try_continues(self) -> None:
        result, _ = await self.call("code_after_try_continues", [], return_type=int)
        self.assertEqual(result, 15)

    # ------------------------------------------------------------------
    # Compile-error cases
    # ------------------------------------------------------------------

    def test_typed_except_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                "from neo3.sc.compiletime import public\n@public\ndef f() -> int:\n    try:\n        return 1\n    except ValueError:\n        return 2\n",
            )

    def test_typed_except_with_binding_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                "from neo3.sc.compiletime import public\n@public\ndef f() -> int:\n    try:\n        return 1\n    except Exception as e:\n        return 2\n",
            )

    def test_multiple_handlers_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                "from neo3.sc.compiletime import public\n@public\ndef f() -> int:\n    try:\n        return 1\n    except:\n        return 2\n    except:\n        return 3\n",
            )

    def test_try_else_rejected(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_module(
                "from neo3.sc.compiletime import public\n@public\ndef f() -> int:\n    try:\n        return 1\n    except:\n        return 2\n    else:\n        return 3\n",
            )


if __name__ == "__main__":
    unittest.main()
