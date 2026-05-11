__all__ = ["msgrouter", "Size"]

from enum import IntEnum
from neo3.core._events import Events  # type: ignore

# :noindex:

msgrouter = Events()


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
