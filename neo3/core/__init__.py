from __future__ import annotations
import struct
import abc
from enum import IntEnum
from typing import Tuple
from events import Events  # type: ignore

msgrouter = Events()

# :noindex:


class Size(IntEnum):
    """
    Explicit bytes of memory consumed
    """
    uint8 = 1
    uint16 = 2
    uint32 = 4
    uint64 = 8
    uint160 = 20
    uint256 = 32


class IClonable(abc.ABC):
    @abc.abstractmethod
    def clone(self):
        """
        Create a deep copy of self
        """

    def from_replica(self, replica):
        pass
