from __future__ import annotations
from typing import Dict, Optional
from neo3.network import convenience, payloads
from neo3.core import types, msgrouter
from neo3 import network_logger as logger
from contextlib import suppress


class RelayCache(convenience._Singleton):
    """
    A cache holding transactions broadcasted to the network to be included in a block.

    Will be accessed in response to a GETDATA network payload.
    """
    def init(self):
        self.cache: Dict[types.UInt256, payloads.inventory.IInventory] = dict()
        msgrouter.on_block_persisted += self.update_cache_for_block_persist

    def add(self, inventory: payloads.inventory.IInventory) -> None:
        self.cache.update({inventory.hash(): inventory})

    def get_and_remove(self, inventory_hash: types.UInt256) -> Optional[payloads.inventory.IInventory]:
        try:
            return self.cache.pop(inventory_hash)
        except KeyError:
            return None

    def try_get(self, inventory_hash: types.UInt256) -> Optional[payloads.inventory.IInventory]:
        return self.cache.get(inventory_hash, None)

    def update_cache_for_block_persist(self, block: payloads.Block) -> None:
        for tx in block.transactions:
            with suppress(KeyError):
                self.cache.pop(tx.hash())
                logger.debug(f"Found {tx.hash()} in last persisted block. Removing from relay cache")

    def reset(self) -> None:
        self.cache = dict()
