from __future__ import annotations
import abc
import hashlib
from enum import IntEnum
from events import Events  # type: ignore
from neo3.core import types


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


