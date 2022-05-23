"""
A basic CLI script to transfer NEP-17 tokens

The following example sends 2.5 GAS from address NSiVJYZej4XsxG5CUpdwn7VRQk8iiiDMPM to address NLzz1iKTc8bJrJB5gGxMgNpkCAWzMywVmo

python transfer.py -w wallet.json -pw 123 -c 0xd2a4cff31913016155e38e474a2c06d08be276cf -f NSiVJYZej4XsxG5CUpdwn7VRQk8iiiDMPM -t NLzz1iKTc8bJrJB5gGxMgNpkCAWzMywVmo -a 2.5 -s https://mainnet1.neo.coz.io:443
"""

import sys
import asyncio
import json
import argparse
from neo3 import api, wallet, vm
from neo3.network import payloads
from neo3.core import types


def create_transfer_script(contract_hash: types.UInt160,
                           from_addr: str,
                           to_addr: str,
                           amount: float,
                           contract_decimals: int) -> bytes:
    # Source account converted to byte array to match the ABI interface
    from_account = wallet.Account.address_to_script_hash(from_addr).to_array()
    # Destination account converted to byte array to match the ABI interface
    to_account = wallet.Account.address_to_script_hash(to_addr).to_array()
    # We multiply the amount with the contract decimals because the NEO internals only support integers
    amount = vm.BigInteger(int(amount * pow(10, contract_decimals)))
    # Arbitrary additional data to supply that will be printed in the "transfer" notify event.
    data = None

    sb = vm.ScriptBuilder()
    sb.emit_dynamic_call_with_args(contract_hash, "transfer", [from_account, to_account, amount, data])
    return sb.to_array()


async def main(wallet_path, wallet_pw, contract_hash, from_addr, to_addr, amount, rpc_host):
    # some basic input validation
    wallet.Account.validate_address(from_addr)
    wallet.Account.validate_address(to_addr)
    contract_hash = types.UInt160.from_string(contract_hash)

    with open(wallet_path) as f:
        data = json.load(f)
        w = wallet.Wallet.from_json(data, password=wallet_pw)
        account = w.account_default

    tx = payloads.Transaction(version=0,
                              nonce=123,
                              system_fee=0,
                              network_fee=0,
                              valid_until_block=0,
                              attributes=[],
                              signers=[],
                              script=b'')

    account.add_as_sender(tx)

    async with api.NeoRpcClient(rpc_host) as client:
        try:
            contract = await client.get_contract_state(contract_hash)
            if "NEP-17" not in contract.manifest.supported_standards:
                raise ValueError("Contract does not support the NEP-17 standard")

            # request the contract decimal count so we can adjust the amount we're sending to the internal format
            # the chain it self only supports integers so we have to convert
            res = await client.invoke_function(contract_hash, "decimals")
            if res.state != "HALT":
                print(f"Failed to get contract decimals: {res.exception}")
            contract_decimals = res.stack[0].value

            tx.script = create_transfer_script(contract_hash, from_addr, to_addr, amount, contract_decimals)

            tx.valid_until_block = await client.get_block_count() + 1500

            res = await client.invoke_script(tx.script, tx.signers)
            if res.state != "HALT":
                print(f"Failed to get system fee: {res.exception}")
            tx.system_fee = res.gas_consumed

            # adding a witness so we can calculate the network fee
            tx.witnesses.append(payloads.Witness(invocation_script=b'', verification_script=account.contract.script))
            tx.network_fee = await client.calculate_network_fee(tx)
            # removing it here as it will be replaced by a proper one once we're signing
            tx.witnesses = []

            res = await client.get_version()
            account.sign_tx(tx, password=wallet_pw, magic=res.protocol.network)
            print(await client.send_transaction(tx))
        except api.JsonRpcError as e:
            print(e)
            sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Deploy contract')
    parser.add_argument("-w", metavar='WALLET', required=True, help="wallet.json path")
    parser.add_argument("-pw", metavar='PASSWORD', required=True, help="wallet password for signing")
    parser.add_argument("-c", metavar='CONTRACT_HASH', required=True, help="contract hash e.g. 0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")
    parser.add_argument("-f", metavar='FROM_ADDR', required=True, help="from address")
    parser.add_argument("-t", metavar='TO_ADDR', required=True, help="to address")
    parser.add_argument("-a", metavar='TOKEN_AMOUNT', required=True, help="amount", type=float)
    parser.add_argument("-s", metavar='RPC_SERVER', required=True, help="RPC server address e.g. https://mainnet1.neo.coz.io:443")
    args = parser.parse_args()

    asyncio.run(main(args.w, args.pw, args.c, args.f, args.t, args.a, args.s))
