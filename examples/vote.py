import asyncio
from neo3.api.wrappers import Config, ChainFacade, NeoToken
from neo3.api.helpers.signing import sign_insecure_with_account
from neo3.network.payloads.verification import Signer
from examples import shared


async def example_vote(neoxp: shared.NeoExpress):
    # This example shows how to vote for your favourite consensus node
    wallet = shared.user_wallet
    account = wallet.account_default

    config = Config(rpc_host=neoxp.rpc_host)
    config.add_signer(
        sign_insecure_with_account(account, pw="123"),
        Signer(account.script_hash),  # default scope is CALLED_BY_ENTRY
    )
    # This is your interface for talking to the blockchain
    facade = ChainFacade(config)

    # Dedicated Neo native contract wrapper
    neo = NeoToken()
    # get a list of candidates that can be voted on
    candidates = await facade.test_invoke(neo.candidates_registered())
    candidate_pk = candidates[0].public_key

    voter = account.address

    print("Casting vote and waiting for receipt...")
    receipt = await facade.invoke(neo.candidate_vote(voter, candidate_pk), receipt_retry_delay=1)
    print(f"Success? {receipt.result}")


if __name__ == "__main__":
    with shared.NeoExpress(shared.neoxpress_config_path, return_delay=2) as neoxp:
        asyncio.run(example_vote(neoxp))
