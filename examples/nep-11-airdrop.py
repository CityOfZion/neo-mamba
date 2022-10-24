"""
This example shows how to send NFTs to multiple accounts in one go.
"""
import asyncio
from neo3.api.wrappers import Config, ChainFacade, GasToken, NEP11NonDivisibleContract
from neo3.api.helpers.signing import sign_insecure_with_account
from neo3.network.payloads.verification import Signer
from examples import shared


async def example_airdrop(neoxp: shared.NeoExpress):
    # This example shows how to airdrop NEP-11 tokens
    wallet = shared.user_wallet
    account = wallet.account_default

    config = Config(rpc_host=neoxp.rpc_host)
    config.add_signer(
        sign_insecure_with_account(account, pw="123"),
        Signer(account.script_hash),  # default scope is CALLED_BY_ENTRY
    )
    facade = ChainFacade(config)

    # Use the generic NEP17 class to wrap the token
    token = NEP11NonDivisibleContract(shared.nep11_token_hash)
    balance = len(await facade.test_invoke(token.token_ids_owned_by(account.address)))
    print(f"Current NFT balance: {balance}")

    # First we have to mint the tokens to our own wallet
    # We do this by sending 10 GAS to the contract. We do this in 2 separate transactions because the NFT is
    # in part generated based on the transaction hash
    # We increase the retry delay to match our local chain block production time
    gas = GasToken()
    print("Minting token 1..", end="")
    receipt = await facade.invoke(
        gas.transfer(
            source=account.address,
            destination=shared.nep11_token_hash,
            amount=10 * (8**10),
        ),
        receipt_retry_delay=1,
    )
    print(receipt.result)
    print("Minting token 2..", end="")
    receipt = await facade.invoke(
        gas.transfer(
            source=account.address,
            destination=shared.nep11_token_hash,
            amount=10 * (8**10),
        ),
        receipt_retry_delay=1,
    )
    print(receipt.result)
    token_ids = await facade.test_invoke(token.token_ids_owned_by(account.address))
    print(f"New NFT token balance: {len(token_ids)}, ids: {token_ids}")

    # Now let's airdrop the tokens
    destination_addresses = [
        "NWuHQdxabXPdC6vVwJhxjYELDQPqc1d4TG",
        "NhVnpBxSRjkScZKHGzsEreYAMS1qRrNdaH",
    ]
    print("Airdropping 1 NFT to each address and waiting for receipt...", end="")
    receipt = await facade.invoke(
        token.transfer_multi(destination_addresses, token_ids),
        receipt_retry_delay=1,
    )
    print(receipt.result)

    for d in destination_addresses:
        nft = await facade.test_invoke(token.token_ids_owned_by(d))
        print(f"Address: {d} owns NFT: {nft}")


if __name__ == "__main__":
    with shared.NeoExpress(
        shared.neoxpress_config_path, shared.neoxpress_batch_path
    ) as neoxp:
        asyncio.run(example_airdrop(neoxp))
