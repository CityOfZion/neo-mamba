"""
This example shows how to vote for your favourite consensus node
"""
import asyncio
from neo3.api.wrappers import ChainFacade, NeoToken
from neo3.api.helpers.signing import sign_insecure_with_account
from neo3.network.payloads.verification import Signer
from examples import shared


async def example_vote(neoxp: shared.NeoExpress):
    wallet = shared.user_wallet
    account = wallet.account_default

    # This is your interface for talking to the blockchain
    facade = ChainFacade(rpc_host=neoxp.rpc_host)
    facade.add_signer(
        sign_insecure_with_account(account, password="123"),
        Signer(account.script_hash),
    )

    # Dedicated Neo native contract wrapper
    neo = NeoToken()
    # get a list of candidates that can be voted on
    candidates = await facade.test_invoke(neo.candidates_registered())
    # the example chain only has 1 candidate, use that
    candidate_pk = candidates[0].public_key

    voter = account.address

    print("Casting vote and waiting for receipt...")
    receipt = await facade.invoke(neo.candidate_vote(voter, candidate_pk))
    print(f"Success? {receipt.result}")


if __name__ == "__main__":
    with shared.NeoExpress() as neoxp:
        asyncio.run(example_vote(neoxp))
