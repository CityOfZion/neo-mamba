"""
Neo-mamba v0.7 Basic node example
NEO-RC2 compatible
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
    # Configure network to RC2 TestNet
    # Values are taken from config.json on the neo-cli github repo
    settings.network.magic = 844378958
    settings.network.seedlist = ['seed1t.neo.org:20333']
    settings.network.standby_committee = [
      "023e9b32ea89b94d066e649b124fd50e396ee91369e8e2a6ae1b11c170d022256d",
      "03009b7540e10f2562e5fd8fac9eaec25166a58b26e412348ff5a86927bfac22a2",
      "02ba2c70f5996f357a43198705859fae2cfea13e1172962800772b3d588a9d4abd",
      "03408dcd416396f64783ac587ea1e1593c57d9fea880c8a6a1920e92a259477806",
      "02a7834be9b32e2981d157cb5bbd3acb42cfd11ea5c3b10224d7a44e98c5910f1b",
      "0214baf0ceea3a66f17e7e1e839ea25fd8bed6cd82e6bb6e68250189065f44ff01",
      "030205e9cefaea5a1dfc580af20c8d5aa2468bb0148f1a5e4605fc622c80e604ba"
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
