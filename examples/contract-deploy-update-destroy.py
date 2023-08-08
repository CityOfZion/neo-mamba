"""
This example shows how to deploy a contract with an `add` function that increases the input with 1.
The contract is then updated on chain with a new version where the `add` function is changed to increase the input by 2.
Finally, the contract is destroyed.
"""

import asyncio
from neo3.api.wrappers import GenericContract, ChainFacade
from neo3.api.helpers.signing import sign_insecure_with_account
from neo3.api.helpers import unwrap
from neo3.contracts import nef, manifest
from neo3.network.payloads.verification import Signer
from examples import shared


async def main(neoxp: shared.NeoExpress):
    wallet = shared.user_wallet
    account = wallet.account_default

    # This is your interface for talking to the blockchain
    facade = ChainFacade(rpc_host=neoxp.rpc_host)
    facade.add_signer(
        sign_insecure_with_account(account, password="123"),
        Signer(account.script_hash),  # default scope is CALLED_BY_ENTRY
    )

    files_path = f"{shared.shared_dir}/deploy-update-destroy/"

    nef_v1 = nef.NEF.from_file(files_path + "contract_v1.nef")
    manifest_v1 = manifest.ContractManifest.from_file(
        files_path + "contract_v1.manifest.json"
    )
    print("Deploying contract v1...", end="")
    receipt = await facade.invoke(GenericContract.deploy(nef_v1, manifest_v1))
    contract_hash = receipt.result
    print(f"contract hash = {contract_hash}")

    contract = GenericContract(contract_hash)
    print("Calling `add` with input 1, result is: ", end="")
    # using test_invoke here because we don't really care about the result being persisted to the chain
    result = await facade.test_invoke(contract.call_function("add", [1]))
    print(unwrap.as_int(result))

    print("Updating contract with version 2...", end="")
    nef_v2 = nef.NEF.from_file(files_path + "contract_v2.nef")
    manifest_v2 = manifest.ContractManifest.from_file(
        files_path + "contract_v2.manifest.json"
    )
    # updating doesn't give any return value. So if it doens't fail then it means success
    await facade.invoke(contract.update(nef=nef_v2, manifest=manifest_v2))
    print("done")

    print("Calling `add` with input 1, result is: ", end="")
    # Using test_invoke here because we don't really care about the result being persisted to the chain
    result = await facade.test_invoke(contract.call_function("add", [1]))
    print(unwrap.as_int(result))

    print("Destroying contract...", end="")
    # destroy also doesn't give any return value. So if it doesn't fail then it means success
    await facade.invoke(contract.destroy())
    print("done")


if __name__ == "__main__":
    with shared.NeoExpress() as neoxp:
        asyncio.run(main(neoxp))
