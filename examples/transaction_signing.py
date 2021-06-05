"""
Neo-mamba v0.8 transaction signing example
NEO RC3 compatible

This example will show how to withdraw NEO from the genesis block. It will show among others
- Wallet creation
- Key import
- Transaction building to initiate a "transfer" of NEO tokens
- Multi-signature transaction signing
- Relaying the transaction

If you do not have a single-node private net setup, please follow the guide here
https://docs.neo.org/docs/en-us/develop/network/private-chain/solo.html

You can skip the steps in the section "withdrawing-neo-and-gas" and beyond as we will do that here
"""
import logging
import asyncio
import json
from neo3 import settings, wallet, contracts, vm, blockchain
from neo3.network import payloads, convenience

# First configure the network settings. The information is taken from `config.json` in neo-cli
settings.network.magic = 692804366  # `Network` number
settings.network.standby_committee = ["03a60c1deaf147b10691c344c76e5f3dac83b555fdd5a3f8d9e2f623b3d1af8df6"]
settings.network.validators_count = 1  # set to the same number as
settings.network.seedlist = ['127.0.0.1:20333']


# This initialises the local chain with the genesis block and allows us to get a snapshot of the database. This is
# required for calculating network fees automatically. Always call this AFTER setting the network settings otherwise network
# syncing and other parts of the system will fail.
bc = blockchain.Blockchain()
snapshot = bc.currentSnapshot

# We start with adding a wallet with a multi-signature account that we will later need to sign the transaction (as well as
# obtain the address for to specify as source funds).

# There are different means of creating/importing a wallet, choose your flavour. 
# This creates a wallet and add the consensus node account (address) where the key is protected by the password "123"
w = wallet.Wallet()
w.account_add(wallet.Account.from_wif("L2aFaQabd35NspvBzC9xPUzKP1if5WgaC2uw4SkviA58DGvccUEy", "123"))  # See also Account.from_* for alternative constructors

# Alternatively import a wallet by uncommenting the 3 lines below
# with open('wallet.json') as f:
#     data = json.load(f)
#     w = wallet.Wallet.from_json(data)

# Next add the consensus node multisig address to the wallet.
# Note that we only have the consensus node account in our wallet, therefore we can access the account via the
# `account_default` property.
#
# In the single consensus node setup we only need to sign with one key, thus we have a threshold of 1 and just 1 public key.
# In a multi-signature setup (e.g. the 4 nodes setup also described on docs.neo.org) we would enter 3 as threshold and
# supply a list of 4 public keys.
account = w.import_multisig_address(signing_threshold=1, public_keys=[w.account_default.public_key])

# With the wallet ready for use we can start building the script that will transfer NEO from a source account to the
# destination account. For this we need to call the "transfer" function on the NeoToken smart contract.
#
# Its signature on the contract side looks as follows:
#    https://github.com/CityOfZion/neo-mamba/blob/873932c8cb25497b90a39b3e327572746764e699/neo3/contracts/native/fungible.py#L109
#
#    def transfer(self,
#                 engine: contracts.ApplicationEngine,
#                 account_from: types.UInt160,
#                 account_to: types.UInt160,
#                 amount: vm.BigInteger,
#                 data: vm.StackItem
#                 ) -> bool:

# Note that if the first parameter of a native contract is `engine` or `snapshot` then it can be ignored as it will be supplied automatically. This thus
# leaves us with 4 parameters to supply. We can validate this as well by looking at the ABI in the contract's manifest
# via ``print(contracts.NeoToken().manifest)``.
# That looks as follows for the `transfer` function
#{
#        "name": "transfer",
#        "parameters": [
#          {
#            "name": "account_from",
#            "type": "ByteArray"
#          },
#          {
#            "name": "account_to",
#            "type": "ByteArray"
#          },
#          {
#            "name": "amount",
#            "type": "Integer"
#          },
#          {
#            "name": "data",
#            "type": "Any"
#          }
#        ],
#        "returntype": "Boolean",

# Source account converted to byte array to match the ABI interface
from_account = account.script_hash.to_array()
# Destination account converted to byte array to match the ABI interface
to_account = wallet.Account.address_to_script_hash("NU5unwNcWLqPM21cNCRP1LPuhxsTpYvNTf").to_array()
# We multiply this amount with the contract factor (to adjust for tokens with decimals)
amount = 10_000_000 * contracts.NeoToken().factor
# Arbitrary additional data to supply that will be printed in the "transfer" notify event.
data = None

sb = vm.ScriptBuilder()
sb.emit_dynamic_call_with_args(contracts.NeoToken().hash, "transfer", [from_account, to_account, amount, data])

# With our script done we need to create a Transaction and add the script to it.
tx = payloads.Transaction(version=0,
                          nonce=123,
                          system_fee=0,
                          network_fee=0,
                          valid_until_block=1500,  # Make sure this is higher than the current chain height!
                          attributes=[],
                          signers=[],
                          script=sb.to_array())

# Add the multisig address as the sender. Do this before signing because it is part of the signed data.
account.add_as_sender(tx)

# The last step before signing is to add the required fees. This can be done manually, but you'll likely be overpaying
# or adding too little. On a private network this isn't a problem, but on the real chain you'd like to be precise.
wallet.add_system_fee(tx, snapshot)  # the price for executing the transaction script
wallet.add_network_fee(tx, snapshot, account)  # the price for validation and inclusion in a block by the consensus node

# Finally sign with the multisig account. For this we need a signing context.
ctx = wallet.MultiSigContext()
# Once the signing threshold is met the required witness is automatically added to the tx.
account.sign_multisig_tx(tx, "123", ctx)
# If we had a 3 out of 4 multi-signature contract, we'd simply call `sign_multisig_tx` multiple times with each required account.
# The signing context has properties/methods to query which keys still need to sign and whether sufficient accounts have signed
# the tx.


# Add this point we're done with signing and the transaction is ready to be relayed to the network. There are 2 options for this
# 1.  Send the transaction via RPC using the `sendrawtransaction` method
#     https://docs.neo.org/docs/en-us/reference/rpc/latest-version/api/sendrawtransaction.html
#     You can find a public RPC server at https://dora.coz.io/monitor
#     To obtain the RPC input parameter use: print(base64.b64encode(tx.to_array().decode())
#
# 2.  Relay the transaction directly over the P2P layer.
#     This option requires being connected over P2P to the private network and is shown below.

async def sync_network():
    # Will automatically connect to the nodes in the network.seedlist specified above and attempt to maintain connection
    node_mgr = convenience.NodeManager()
    node_mgr.start()

    # The following line will automatically sync the blocks from the network. Assuming that you did not change any
    # settings in the Policy contract, this step can be skipped for a private network. Otherwise you might want to first
    # sync your local chain before building and relaying the transaction. Failing to do so might lead to incorrect
    # calculation of the transaction fees and can lead to rejection of the transaction.

    # sync_mgr = convenience.SyncManager()
    # await sync_mgr.start()

    # Give the node manager time to connect to nodes
    while len(node_mgr.nodes) == 0:
        await asyncio.sleep(1)
    n = node_mgr.nodes[0]
    # Relay the transaction
    await n.relay(tx)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.create_task(sync_network())
    loop.run_forever()
