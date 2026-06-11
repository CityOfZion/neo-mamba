import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestPrint(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "print.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./print.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"print{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_print_str_emits_runtime_log(self) -> None:
        await self.call("log_str", ["hello"], return_type=None)
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual(self.contract_hash, self.runtime_logs[0].contract)
        self.assertEqual("hello", self.runtime_logs[0].msg)

    async def test_print_bytes_emits_runtime_log(self) -> None:
        await self.call("log_bytes", [b"hello"], return_type=None)
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual("hello", self.runtime_logs[0].msg)

    async def test_print_literal_emits_runtime_log(self) -> None:
        await self.call("log_literal", [], return_type=None)
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual("hello from contract", self.runtime_logs[0].msg)


class TestPrintList(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "print.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./print.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"print{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_log_list_ints_emits_runtime_log(self) -> None:
        await self.call("log_list_ints", [[1, 2, 3]], return_type=None)
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual(self.contract_hash, self.runtime_logs[0].contract)
        self.assertEqual("[1,2,3]", self.runtime_logs[0].msg)

    async def test_log_empty_list_emits_no_runtime_log(self) -> None:
        await self.call("log_empty_list", [], return_type=None)
        self.assertEqual(0, len(self.runtime_logs))
