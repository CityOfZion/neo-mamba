"""
This example shows how to send tokens to multiple accounts in one go.
It will mint the "COZ Token"
"""
import asyncio
from neo3.api.wrappers import ChainFacade, NeoToken, NEP17Contract
from neo3.api.helpers.signing import sign_insecure_with_account
from neo3.network.payloads.verification import Signer
from examples import shared


async def example_airdrop(neoxp: shared.NeoExpress):
    # This example shows how to airdrop NEP-17 tokens
    wallet = shared.user_wallet
    account = wallet.account_default

    # This is your interface for talking to the blockchain
    facade = ChainFacade(rpc_host=neoxp.rpc_host)
    facade.add_signer(
        sign_insecure_with_account(account, password="123"),
        Signer(account.script_hash),  # default scope is CALLED_BY_ENTRY
    )

    # Use the generic NEP17 class to wrap the token
    token = NEP17Contract(shared.coz_token_hash)
    balance = await facade.test_invoke(token.balance_of(account.address))
    print(f"Current COZ token balance: {balance}")

    # First we have to mint the tokens to our own wallet
    # We do this by sending NEO to the contract
    # We increase the retry delay to match our local chain block production time
    neo = NeoToken()
    print("Minting once...", end="")
    receipt = await facade.invoke(
        neo.transfer(
            source=account.address, destination=shared.coz_token_hash, amount=100
        )
    )
    print(receipt.result)
    print("Minting twice...", end="")
    receipt = await facade.invoke(
        neo.transfer(
            source=account.address, destination=shared.coz_token_hash, amount=100
        )
    )

    print(receipt.result)

    balance = await facade.test_invoke(token.balance_of(account.address))
    print(f"New COZ token balance: {balance}")

    # Now let's airdrop the tokens
    destination_addresses = [
        "NWuHQdxabXPdC6vVwJhxjYELDQPqc1d4TG",
        "NhVnpBxSRjkScZKHGzsEreYAMS1qRrNdaH",
        "NanYZRm6m6sa6Z6F3RBRYSXqdpg5rZqxdZ",
        "NUqLhf1p1vQyP2KJjMcEwmdEBPnbCGouVp",
        "NKuyBkoGdZZSLyPbJEetheRhMjeznFZszf",
    ]
    print("Airdropping 10 tokens and waiting for receipt")
    print(
        await facade.invoke(
            token.transfer_multi(account.address, destination_addresses, 10),
        )
    )


if __name__ == "__main__":
    with shared.NeoExpress() as neoxp:
        asyncio.run(example_airdrop(neoxp))
