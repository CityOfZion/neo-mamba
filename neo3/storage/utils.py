from typing import Tuple
from neo3 import storage

"""
Internal helpers
"""


class NEOByteCompare:
    def __init__(self, direction="forward"):
        if direction == "forward":
            self.direction = 0
        else:
            self.direction = 1

    def compare(self, x: bytes, y: bytes) -> int:
        if self.direction == 0:
            return self._compare_internal(x, y)
        else:
            return -self._compare_internal(x, y)

    def _compare_internal(self, x: bytes, y: bytes) -> int:
        if x == y:
            return 0
        elif x < y:
            return -1
        else:
            return 1


def NEOSeekSort(comperator_func,
                pair_y: Tuple[storage.StorageKey, storage.StorageItem],
                pair_x: Tuple[storage.StorageKey, storage.StorageItem]) -> int:
    return comperator_func(pair_x[0].key, pair_y[0].key)


def create_find_prefix(id: int, prefix: bytes) -> bytes:
    return id.to_bytes(4, 'little', signed=True) + prefix
