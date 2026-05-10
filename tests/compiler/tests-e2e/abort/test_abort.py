import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import AbortException, SmartContractTestCase

from neo3.compiler import TypecheckError, compile_to_nef

HERE = Path(__file__).parent


class TestAbort(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "abort.py").read_text(),
            str(HERE / "abort"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./abort.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"abort{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_abort_no_args_faults_vm(self) -> None:
        with self.assertRaises(AbortException):
            await self.call("do_abort", [], return_type=None)

    async def test_abort_with_message_faults_vm(self) -> None:
        with self.assertRaises(AbortException):
            await self.call("do_abort_msg", [], return_type=None)

    async def test_conditional_abort_no_fault_when_nonzero(self) -> None:
        result, _ = await self.call("conditional_abort", [5], return_type=int)
        self.assertEqual(5, result)

    async def test_conditional_abort_faults_when_zero(self) -> None:
        with self.assertRaises(AbortException):
            await self.call("conditional_abort", [0], return_type=int)

    async def test_conditional_abort_msg_no_fault_when_nonzero(self) -> None:
        result, _ = await self.call("conditional_abort_msg", [42], return_type=int)
        self.assertEqual(42, result)

    async def test_conditional_abort_msg_faults_when_zero(self) -> None:
        with self.assertRaises(AbortException):
            await self.call("conditional_abort_msg", [0], return_type=int)

    def test_abort_wrong_arg_type_raises_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n"
                "from neo3.sc.utils import abort\n"
                "@public\ndef f() -> None:\n    abort(123)\n",
                "/tmp/throwaway_abort",
            )

    def test_abort_too_many_args_raises_compile_error(self) -> None:
        with self.assertRaises(TypecheckError):
            compile_to_nef(
                "from neo3.sc.compiletime import public\n"
                "from neo3.sc.utils import abort\n"
                "@public\ndef f() -> None:\n    abort('a', 'b')\n",
                "/tmp/throwaway_abort",
            )


if __name__ == "__main__":
    unittest.main()
