import asyncio
import unittest
from pathlib import Path
from unittest import skip
from neo3.network.payloads.verification import Signer, WitnessScope
from neo3.sctesting import RawStack, SmartContractTestCase
from neo3.compiler import compile_to_nef
from typing import Any
from neo3.api.wrappers import NeoToken, GasToken
from neo3.api.helpers.signing import sign_with_account, sign_with_multisig_account
from neo3.contracts.contract import CONTRACT_HASHES
from neo3.sc.types import NeoAccountState

HERE = Path(__file__).parent

GAS = CONTRACT_HASHES.GAS_TOKEN
NEO = CONTRACT_HASHES.NEO_TOKEN
_ECPOINT_NOT_CANDIDATE = b"\x02\xdfH\xf6\x0e\x8f>\x01\xc4\x8f\xf4\x0b\x9b\x7f\x13\x10\xd7\xa8\xb2\xa1\x93\x18\x8b\xef\xe1\xc2\xe3\xdft\x0e\x89P\x93"


class TestNeoTokenWrapper(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.user1 = cls.node.wallet.account_new("alice")
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(HERE / "wrapper_neotoken.py")
        g = cls.node.wallet.account_get_by_label("committee")
        if g is not None:
            cls.genesis = g
        cls.contract_hash, _ = await cls.deploy("./wrapper_neotoken.nef", cls.genesis)
        await cls.transfer(
            GAS, cls.genesis.script_hash, cls.user1.script_hash, 10000, 8
        )
        await cls.transfer(NEO, cls.genesis.script_hash, cls.user1.script_hash, 1000, 0)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"wrapper_neotoken{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_symbol(self) -> None:
        result, _ = await self.call("get_symbol", [], return_type=str)
        self.assertEqual("NEO", result)

    async def test_decimals(self) -> None:
        result, _ = await self.call("get_decimals", [], return_type=int)
        self.assertEqual(0, result)

    async def test_total_supply(self) -> None:
        result, _ = await self.call("get_total_supply", [], return_type=int)
        self.assertEqual(100_000_000, result)

    async def test_balance_of_committee(self) -> None:
        neo = NeoToken()
        receipt = await self.facade.test_invoke(
            neo.balance_of_friendly(self.genesis.script_hash)
        )
        genesis_balance = receipt.result

        result, _ = await self.call(
            "get_balance_of", [self.genesis.script_hash], return_type=int
        )
        self.assertEqual(genesis_balance, result)

    async def test_balance_of_zero_account(self) -> None:
        result, _ = await self.call("get_balance_of", [b"\x00" * 20], return_type=int)
        self.assertEqual(0, result)

    async def test_get_gas_per_block(self) -> None:
        result, _ = await self.call("get_gas_per_block", [], return_type=int)
        self.assertEqual(500_000_000, result)

    @skip(
        "requires `end` parameter to match current max chain height, which depends on when the test is ran compared to starting the node"
    )
    async def test_unclaimed_gas_nonnegative(self) -> None:
        result, _ = await self.call(
            "get_unclaimed_gas",
            [self.genesis.script_hash, 4],
            return_type=int,
            signing_accounts=[self.genesis],
        )
        self.assertGreaterEqual(result, 0)

    async def test_get_committee_nonempty(self) -> None:
        result, _ = await self.call("get_committee", [], return_type=list)
        self.assertGreater(len(result), 0)

    async def test_get_committee_address_is_20_bytes(self) -> None:
        result, _ = await self.call("get_committee_address", [], return_type=bytes)
        self.assertEqual(20, len(result))

    async def test_get_register_price_positive(self) -> None:
        result, _ = await self.call("get_register_price", [], return_type=int)
        self.assertGreater(result, 0)

    async def test_get_next_block_validators_nonempty(self) -> None:
        result, _ = await self.call("get_next_block_validators", [], return_type=list)
        self.assertGreater(len(result), 0)

    async def test_get_candidate_vote_noncandidate(self) -> None:
        result, _ = await self.call(
            "get_candidate_vote", [_ECPOINT_NOT_CANDIDATE], return_type=int
        )
        self.assertEqual(-1, result)

    async def test_transfer_neo(self) -> None:
        result, _ = await self.call(
            "do_transfer",
            [self.genesis.script_hash, self.user1.script_hash, 10, None],
            return_type=bool,
            signing_accounts=[self.genesis],
            signers=[
                Signer(self.genesis.script_hash, WitnessScope.GLOBAL)
            ],  # must change witness scope as default is CALLED_BY_ENTRY but that will fail because it's the contract calling, not the tx sender.
        )
        self.assertTrue(result)

    async def test_get_account_state(self) -> None:
        neo = NeoToken()
        gas = GasToken()
        receipt = await self.facade.test_invoke(
            neo.balance_of_friendly(self.genesis.script_hash)
        )
        genesis_balance = receipt.result

        result, _ = await self.call(
            "get_account_state", [self.genesis.script_hash], return_type=RawStack
        )
        account_state = NeoAccountState.from_stackitem(result[0])
        self.assertEqual(account_state.balance, genesis_balance)
        self.assertGreater(account_state.height, 0)
        self.assertIsNone(account_state.vote_to)
        self.assertEqual(account_state.last_gas_per_vote, 0)
        previous_height = account_state.height

        # now vote such that something changes
        sign_with_user1 = (
            sign_with_account(self.user1),
            Signer(self.user1.script_hash),
        )
        receipt = await self.facade.invoke(
            neo.candidate_register(self.user1.public_key), signers=[sign_with_user1]
        )
        self.assertTrue(receipt)

        sign_with_genesis = (
            sign_with_multisig_account(self.genesis),
            Signer(self.genesis.script_hash),
        )
        receipt = await self.facade.invoke(
            neo.candidate_vote(self.genesis.script_hash, self.user1.public_key),
            signers=[sign_with_genesis],
        )
        self.assertTrue(receipt)

        result, _ = await self.call(
            "get_account_state", [self.genesis.script_hash], return_type=RawStack
        )
        account_state = NeoAccountState.from_stackitem(result[0])
        self.assertEqual(account_state.balance, genesis_balance)
        self.assertGreater(account_state.height, previous_height)
        self.assertEqual(
            account_state.vote_to.to_array(), self.user1.public_key.to_array()
        )
        self.assertEqual(account_state.last_gas_per_vote, 0)


if __name__ == "__main__":
    unittest.main()
