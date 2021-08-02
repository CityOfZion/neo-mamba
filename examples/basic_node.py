"""
Neo-mamba v0.9 Basic node example
Formal NEO3 Testnet  compatible
"""
from __future__ import annotations
import asyncio
import logging
from neo3.network import convenience
from neo3.storage import implementations as db
from neo3 import blockchain, settings


def enable_network_logging():
    stdio_handler = logging.StreamHandler()
    stdio_handler.setLevel(logging.DEBUG)
    stdio_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s - %(module)s:%(lineno)s %(message)s"))

    network_logger = logging.getLogger('neo3.network')
    network_logger.addHandler(stdio_handler)
    network_logger.setLevel(logging.DEBUG)


async def main():
    # Configure network to Format TestNet
    # Values are taken from config.testnet.json on the neo-node github repo
    # https://github.com/neo-project/neo-node/tree/master/neo-cli
    settings.network.magic = 877933390
    settings.network.seedlist = ['seed1.neo.org:20333']
    settings.network.standby_committee = [
      "023e9b32ea89b94d066e649b124fd50e396ee91369e8e2a6ae1b11c170d022256d",
      "03009b7540e10f2562e5fd8fac9eaec25166a58b26e412348ff5a86927bfac22a2",
      "02ba2c70f5996f357a43198705859fae2cfea13e1172962800772b3d588a9d4abd",
      "03408dcd416396f64783ac587ea1e1593c57d9fea880c8a6a1920e92a259477806",
      "02a7834be9b32e2981d157cb5bbd3acb42cfd11ea5c3b10224d7a44e98c5910f1b",
      "0214baf0ceea3a66f17e7e1e839ea25fd8bed6cd82e6bb6e68250189065f44ff01",
      "030205e9cefaea5a1dfc580af20c8d5aa2468bb0148f1a5e4605fc622c80e604ba",
      "025831cee3708e87d78211bec0d1bfee9f4c85ae784762f042e7f31c0d40c329b8",
      "02cf9dc6e85d581480d91e88e8cbeaa0c153a046e89ded08b4cefd851e1d7325b5",
      "03840415b0a0fcf066bcc3dc92d8349ebd33a6ab1402ef649bae00e5d9f5840828",
      "026328aae34f149853430f526ecaa9cf9c8d78a4ea82d08bdf63dd03c4d0693be6",
      "02c69a8d084ee7319cfecf5161ff257aa2d1f53e79bf6c6f164cff5d94675c38b3",
      "0207da870cedb777fceff948641021714ec815110ca111ccc7a54c168e065bda70",
      "035056669864feea401d8c31e447fb82dd29f342a9476cfd449584ce2a6165e4d7",
      "0370c75c54445565df62cfe2e76fbec4ba00d1298867972213530cae6d418da636",
      "03957af9e77282ae3263544b7b2458903624adc3f5dee303957cb6570524a5f254",
      "03d84d22b8753cf225d263a3a782a4e16ca72ef323cfde04977c74f14873ab1e4c",
      "02147c1b1d5728e1954958daff2f88ee2fa50a06890a8a9db3fa9e972b66ae559f",
      "03c609bea5a4825908027e4ab217e7efc06e311f19ecad9d417089f14927a173d5",
      "0231edee3978d46c335e851c76059166eb8878516f459e085c0dd092f0f1d51c21",
      "03184b018d6b2bc093e535519732b3fd3f7551c8cffaf4621dd5a0b89482ca66c9"
    ]
    settings.network.validators_count = 7

    # Choose the type of storage, uncomment the next line to use leveldb (requires that libleveldb can be found)
    # or use the in-memory DB
    # bc = blockchain.Blockchain(db.LevelDB({'path':'/tmp/neo3/'}))
    bc = blockchain.Blockchain(db.MemoryDB())

    # Uncomment the next line if you're interested in seeing debug information about the network and block syncing process
    # enable_network_logging()

    # Start the helper classes that will connect to the network and sync the chain
    node_mgr = convenience.NodeManager()
    node_mgr.start()

    sync_mgr = convenience.SyncManager()
    await sync_mgr.start()

    async def print_height():
        while True:
            print(f"Local chain height: {bc.height}")
            await asyncio.sleep(2)

    # Start an endless loop informing us about our local chain height
    await print_height()

if __name__ == "__main__":
    asyncio.run(main())
