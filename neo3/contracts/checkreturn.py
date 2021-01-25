import enum


class ReturnTypeConvention(enum.IntEnum):
    NONE = 0
    ENSURE_IS_EMPTY = 1
    ENSURE_NOT_EMPTY = 2
