"""
This example shows how to send NFTs to multiple accounts in one go (airdrop).
"""
import asyncio
from neo3.api.wrappers import ChainFacade, GasToken, NEP11NonDivisibleContract
from neo3.api.helpers.signing import sign_insecure_with_account
from neo3.network.payloads.verification import Signer
from examples import shared


async def example_airdrop(neoxp: shared.NeoExpress):
    wallet = shared.user_wallet
    account = wallet.account_default

    # This is your interface for talking to the blockchain
    facade = ChainFacade(rpc_host=neoxp.rpc_host)
    facade.add_signer(
        sign_insecure_with_account(account, password="123"),
        Signer(account.script_hash),  # default scope is CALLED_BY_ENTRY
    )

    # Wrap the NFT contract
    ntf = NEP11NonDivisibleContract(shared.nep11_token_hash)
    balance = len(await facade.test_invoke(ntf.token_ids_owned_by(account.address)))
    print(f"Current NFT balance: {balance}")

    # First we have to mint the NFTs to our own wallet
    # We do this by sending 10 GAS to the contract. We do this in 2 separate transactions because the NFT is
    # in part generated based on the transaction hash
    # We increase the retry delay to match our local chain block production time
    gas = GasToken()
    print("Minting NFT 1..", end="")
    receipt = await facade.invoke(
        gas.transfer(
            source=account.address,
            destination=shared.nep11_token_hash,
            amount=10 * (8**10),
        )
    )
    print(receipt.result)
    print("Minting NFT 2..", end="")
    receipt = await facade.invoke(
        gas.transfer(
            source=account.address,
            destination=shared.nep11_token_hash,
            amount=10 * (8**10),
        )
    )
    print(receipt.result)
    token_ids = await facade.test_invoke(ntf.token_ids_owned_by(account.address))
    print(f"New NFT token balance: {len(token_ids)}, ids: {token_ids}")

    # Now let's airdrop the NFTs
    destination_addresses = [
        "NWuHQdxabXPdC6vVwJhxjYELDQPqc1d4TG",
        "NhVnpBxSRjkScZKHGzsEreYAMS1qRrNdaH",
    ]
    print("Airdropping 1 NFT to each address and waiting for receipt...", end="")
    receipt = await facade.invoke(
        ntf.transfer_multi(destination_addresses, token_ids),
    )
    print(receipt.result)

    for d in destination_addresses:
        nft = await facade.test_invoke(ntf.token_ids_owned_by(d))
        print(f"Address: {d} owns NFT: {nft}")


if __name__ == "__main__":
    with shared.NeoExpress() as neoxp:
        asyncio.run(example_airdrop(neoxp))
