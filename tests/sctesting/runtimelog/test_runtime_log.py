import asyncio
import json
from neo3.sctesting import SmartContractTestCase
from neo3.wallet import account
from neo3.network.payloads.verification import Signer


class RuntimeLogTest(SmartContractTestCase):
    genesis: account.Account

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        if (g := cls.node.wallet.account_get_by_label("committee")) is not None:
            cls.genesis = g
        cls.contract_hash = await cls.deploy(
            "resources/runtimelog_contract.nef", cls.genesis
        )

    async def test_print_str1(self):
        msg = "msg1"
        await self.call("print_str", [msg], return_type=None)
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual(self.contract_hash, self.runtime_logs[0].contract)
        self.assertEqual(msg, self.runtime_logs[0].msg)

    async def test_print_str2(self):
        """validate that notifications are reset between test cases"""
        msg = "msg2"
        await self.call("print_str", [msg], return_type=None)
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual(self.contract_hash, self.runtime_logs[0].contract)
        self.assertEqual(msg, self.runtime_logs[0].msg)

    async def test_with_peristed_tx(self):
        msg = "msg3"
        await self.call(
            "print_str",
            [msg],
            return_type=None,
            signing_accounts=[self.genesis],
            signers=[Signer(self.genesis.script_hash)],
        )
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual(self.contract_hash, self.runtime_logs[0].contract)
        self.assertEqual(msg, self.runtime_logs[0].msg)

    async def test_bytes(self):
        msg = b"msg1"
        await self.call("print_bytes", [msg], return_type=None)
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual(self.contract_hash, self.runtime_logs[0].contract)
        self.assertEqual(msg.decode("utf-8"), self.runtime_logs[0].msg)

    async def test_list(self):
        msg = [1, 2, 3, 4, 5]
        await self.call("print_list", [msg], return_type=None)
        self.assertEqual(1, len(self.runtime_logs))
        self.assertEqual(self.contract_hash, self.runtime_logs[0].contract)
        self.assertEqual(
            json.dumps(msg, separators=(",", ":")), self.runtime_logs[0].msg
        )
