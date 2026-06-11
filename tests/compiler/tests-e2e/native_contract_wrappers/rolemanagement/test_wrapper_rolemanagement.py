import asyncio
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent

# neo3 Role enum values
_ROLE_STATE_VALIDATOR = 4
_ROLE_ORACLE = 8


class TestRoleManagementWrapper(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "wrapper_rolemanagement.py")
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy(
            "./wrapper_rolemanagement.nef", cls.genesis
        )

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"wrapper_rolemanagement{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_state_validator_returns_list(self) -> None:
        result, _ = await self.call(
            "get_role", [_ROLE_STATE_VALIDATOR, 0], return_type=list
        )
        self.assertIsInstance(result, list)

    async def test_oracle_returns_list(self) -> None:
        result, _ = await self.call("get_role", [_ROLE_ORACLE, 0], return_type=list)
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
