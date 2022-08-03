"""
A basic CLI script to deploy a smart contract

Example usage:
    python deploy.py -w wallet.json -pw 123 -c mycontract.nef -m mycontract.manifest.json -s https://mainnet1.neo.coz.io:443
"""

import sys
import asyncio
import json
import argparse
from typing import Optional
from neo3 import api, wallet, contracts
from neo3.contracts import vm, get_contract_hash
from neo3.network import payloads


async def main(wallet_path, wallet_pw, nef_path, manifest_path, rpc_host, poll_timeout: Optional[str] = None):
    with open(wallet_path) as f:
        data = json.load(f)
        w = wallet.Wallet.from_json(data, password=wallet_pw)
        account = w.account_default

    with open(nef_path, 'rb') as f:
        nef_bytes = f.read()
        try:
            nef = contracts.NEF.deserialize_from_bytes(nef_bytes)
        except ValueError as e:
            raise ValueError(f"Failed NEF file validation with: {e}")

    with open(manifest_path, 'rb') as f:
        manifest_bytes = f.read()
        manifest_json = json.loads(manifest_bytes.decode('utf-8'))
        try:
            manifest = contracts.ContractManifest.from_json(manifest_json)
        except ValueError as e:
            raise ValueError(f"Failed manifest validation with: {e}")

    # build a contract deploy transaction
    sb = vm.ScriptBuilder()
    sb.emit_contract_call_with_args(contracts.CONTRACT_HASHES.MANAGEMENT, "deploy", [nef_bytes, manifest_bytes])

    tx = payloads.Transaction(version=0,
                              nonce=123,
                              system_fee=0,
                              network_fee=0,
                              valid_until_block=0,
                              attributes=[],
                              signers=[],
                              script=sb.to_array())

    account.add_as_sender(tx)

    async with api.NeoRpcClient(rpc_host) as client:
        try:
            tx.valid_until_block = await client.get_block_count() + 1500

            res = await client.invoke_script(tx.script, tx.signers)
            if res.state != "HALT":
                raise ValueError(f"Failed to get system fee: {res.exception}")
            tx.system_fee = res.gas_consumed

            # adding a witness so we can calculate the network fee
            tx.witnesses.append(payloads.Witness(invocation_script=b'', verification_script=account.contract.script))
            tx.network_fee = await client.calculate_network_fee(tx)
            # removing it here as it will be replaced by a proper one once we're signing
            tx.witnesses = []

            res = await client.get_version()
            account.sign_tx(tx, password=wallet_pw, magic=res.protocol.network)
            tx_id = await client.send_transaction(tx)
            print(f"Contract hash: {get_contract_hash(tx.sender, nef.checksum, manifest.name)}")
            print(f"Transaction id: {tx_id}")
            if poll_timeout is not None:
                print("Polling for transaction status, please wait..")
                status = await api.poll_tx_status(tx_id, client)
                if status == vm.VMState.HALT:
                    print(f"Transaction execution status: Success")
                else:
                    print(f"Transaction execution status: Failed (VMState: {status})")

        except api.JsonRpcError as e:
            print(e)
            sys.exit(-1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Deploy contract')
    parser.add_argument("-w", metavar='WALLET', required=True, help="wallet.json path")
    parser.add_argument("-pw", metavar='PASSWORD', required=True, help="wallet password for signing")
    parser.add_argument("-c", metavar='CONTRACT_NEF', required=True, help="contract .NEF path")
    parser.add_argument("-m", metavar='CONTRACT_MANIFEST', required=True, help="contract .manifest.json path")
    parser.add_argument("-s", metavar='RPC_SERVER', required=True,
                        help="RPC server address e.g. https://mainnet1.neo.coz.io:443")
    parser.add_argument("-p", metavar='TIMEOUT_IN_SECONDS', nargs='?', const=20, type=int,
                        help="Poll for transaction status after deployment. Default timeout is 20 seconds")
    args = parser.parse_args()

    asyncio.run(main(args.w, args.pw, args.c, args.m, args.s, args.p))
