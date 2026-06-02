import asyncio
import unittest
from pathlib import Path

from neo3.api import StackItemType, StackItem
from neo3.compiler import compile_to_nef
from neo3.sctesting import SmartContractTestCase, RawStack
from neo3.network.payloads.verification import Signer
from neo3.core.types import UInt160


HERE = Path(__file__).parent

IDX_ACCOUNT = 0


class TestGetCurrentSigners(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "get_current_signers.py").read_text(),
            str(HERE / "get_current_signers"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy(
            "./get_current_signers.nef", cls.genesis
        )

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"get_current_signers{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_get_current_signers_test_invoke(self) -> None:
        # NeoGo includes a synthetic signer in test invocations (https://github.com/nspcc-dev/neo-go/issues/4290)
        # On a standard Neo node without a transaction context this returns Null.
        # TODO: update once neo-go is fixed
        result, _ = await self.call("signers", return_type=RawStack)
        self.assertEqual(1, len(result))
        signers = result[0].as_list()
        self.assertEqual(1, len(signers))
        self.assertEqual(UInt160.zero(), signers[0].value[IDX_ACCOUNT].as_uint160())

    async def test_get_current_signers_test_invoke_with_custom_signers(self) -> None:
        s1 = Signer(UInt160.from_string("0x6d0656f6dd91469db1c90cc1e574380613f43738"))
        s2 = Signer(UInt160.from_string("0x7f82c030b531e6a1ac53173161735daf67d23112"))
        result, _ = await self.call("signers", return_type=RawStack, signers=[s1, s2])
        self.assertEqual(1, len(result))
        signers = result[0].as_list()
        self.assertEqual(2, len(signers))

        self.assertEqual(s1.account, signers[0].value[IDX_ACCOUNT].as_uint160())
        self.assertEqual(s2.account, signers[1].value[IDX_ACCOUNT].as_uint160())

    async def test_get_current_signers_with_signer(self) -> None:
        result, _ = await self.call(
            "signers", return_type=RawStack, signing_accounts=[self.genesis]
        )
        self.assertEqual(1, len(result))
        signers = result[0].as_list()
        self.assertEqual(1, len(signers))
        self.assertEqual(
            self.genesis.script_hash, signers[0].value[IDX_ACCOUNT].as_uint160()
        )


if __name__ == "__main__":
    unittest.main()
