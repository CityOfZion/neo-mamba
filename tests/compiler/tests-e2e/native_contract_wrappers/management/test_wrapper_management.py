import asyncio
import unittest
from pathlib import Path
from typing import Any

from neo3.sctesting import RawStack, SmartContractTestCase

from neo3.compiler import compile_to_nef
from neo3.contracts.nef import NEF
from neo3.sc.types import ContractState

HERE = Path(__file__).parent


class TestContractManagementWrapper(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "wrapper_management.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy("./wrapper_management.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"wrapper_management{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_get_contract_returns_state_for_known_hash(self) -> None:
        result, _ = await self.call(
            "query_contract", [self.contract_hash], return_type=RawStack
        )
        cs = ContractState.from_stackitem(result[0])
        self.assertEqual(cs.id, 1)
        self.assertEqual(cs.update_counter, 0)
        self.assertEqual(cs.hash.to_array(), self.contract_hash.to_array())

        orig_nef = NEF.from_file(str((HERE / "wrapper_management.nef").resolve()))
        self.assertEqual(cs.nef, orig_nef.to_array())
        self.assertIsNotNone(cs.manifest)

    async def test_get_contract_returns_none_for_unknown_hash(self) -> None:
        result, _ = await self.call("query_contract", [b"\x00" * 20], return_type=None)
        self.assertIsNone(result)

    async def test_get_minimum_deployment_fee_positive(self) -> None:
        result, _ = await self.call("get_min_fee", [], return_type=int)
        self.assertGreater(result, 0)

    async def test_get_contract_by_id_returns_deployed_contract(self) -> None:
        # The wrapper itself is the first user-deployed contract (id=1)
        result, _ = await self.call("query_by_id", [1], return_type=RawStack)
        cs = ContractState.from_stackitem(result[0])
        self.assertEqual(cs.id, 1)
        self.assertEqual(cs.hash.to_array(), self.contract_hash.to_array())

    async def test_get_contract_by_id_returns_none_for_unknown_id(self) -> None:
        result, _ = await self.call("query_by_id", [9999], return_type=None)
        self.assertIsNone(result)

    async def test_count_deployed_includes_user_contract(self) -> None:
        # Native contracts have negative IDs; get_contract_hashes returns user-deployed only.
        # We deployed one contract, so count must be >= 1.
        result, _ = await self.call("count_deployed", [], return_type=int)
        self.assertGreaterEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
