"""
Local cache to hold objects for responding to `GETDATA` network payloads.
"""
from __future__ import annotations
from typing import Optional
from neo3.network.payloads import inventory, block
from neo3.core import types, msgrouter
from neo3 import network_logger as logger, singleton
from contextlib import suppress


class RelayCache(singleton._Singleton):
    """
    A cache holding transactions broadcast to the network to be included in a block.

    Will be accessed in response to a GETDATA network payload.
    """

    def init(self):
        self.cache: dict[types.UInt256, inventory.IInventory] = dict()
        msgrouter.on_block_persisted += self.update_cache_for_block_persist

    def add(self, inventory: inventory.IInventory) -> None:
        """
        Add an inventory to the cache.
        """
        self.cache.update({inventory.hash(): inventory})

    def get_and_remove(
        self, inventory_hash: types.UInt256
    ) -> Optional[inventory.IInventory]:
        """
        Pop an inventory from the cache if found.
        """
        try:
            return self.cache.pop(inventory_hash)
        except KeyError:
            return None

    def try_get(self, inventory_hash: types.UInt256) -> Optional[inventory.IInventory]:
        """
        Get an inventory from the cache.
        """
        return self.cache.get(inventory_hash, None)

    def update_cache_for_block_persist(self, block: block.Block) -> None:
        for tx in block.transactions:
            with suppress(KeyError):
                self.cache.pop(tx.hash())
                logger.debug(
                    f"Found {tx.hash()} in last persisted block. Removing from relay cache"
                )

    def reset(self) -> None:
        """
        Empty the cache.
        """
        self.cache = dict()
