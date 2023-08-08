"""
This files has 2 examples that show how to transfer NEP-17 tokens for a contract that
has an existing wrapper (like NEO) and how to transfer for any arbitrary contract that
implements the NEP-17 standard
"""
import asyncio
from neo3.api.wrappers import ChainFacade, NeoToken, NEP17Contract
from neo3.api.helpers.signing import sign_insecure_with_account
from neo3.network.payloads.verification import Signer
from neo3.core import types
from examples import shared


async def example_transfer_neo(neoxp: shared.NeoExpress):
    # This example shows how to transfer NEO tokens, a contract that has a dedicated wrapper
    wallet = shared.user_wallet
    account = wallet.account_default

    # This is your interface for talking to the blockchain
    facade = ChainFacade(rpc_host=neoxp.rpc_host)
    facade.add_signer(
        sign_insecure_with_account(account, password="123"),
        Signer(account.script_hash),  # default scope is CALLED_BY_ENTRY
    )

    source = account.address
    destination = "NUVaphUShQPD82yoXcbvFkedjHX6rUF7QQ"
    # Dedicated Neo native contract wrapper
    neo = NeoToken()
    print("Calling transfer and waiting for receipt...")
    print(await facade.invoke(neo.transfer(source, destination, 10)))


async def example_transfer_other(neoxp: shared.NeoExpress):
    # This example shows how to transfer NEP-17 tokens for a contract that does not
    # have a dedicated wrapper like Neo and Gas have.
    # Most of the setup is the same as the first example
    wallet = shared.user_wallet
    account = wallet.account_default

    # This is your interface for talking to the blockchain
    facade = ChainFacade(rpc_host=neoxp.rpc_host)
    facade.add_signer(
        sign_insecure_with_account(account, password="123"),
        Signer(account.script_hash),  # default scope is CALLED_BY_ENTRY
    )

    source = account.address
    destination = "NUVaphUShQPD82yoXcbvFkedjHX6rUF7QQ"

    # Use the generic NEP17 class to wrap the token and create a similar interface as before
    # The contract hash is that of our sample Nep17 token which is deployed in our neoxpress setup
    contract_hash = types.UInt160.from_string(
        "0x41ee5befd936c90f15893261abbd681f20ed0429"
    )
    token = NEP17Contract(contract_hash)
    # Now call it in the same fashion as before with the NEoToken
    print("Calling transfer and waiting for receipt...")
    print(await facade.invoke(token.transfer(source, destination, 10)))


if __name__ == "__main__":
    with shared.NeoExpress() as neoxp:
        asyncio.run(example_transfer_neo(neoxp))
        asyncio.run(example_transfer_other(neoxp))
