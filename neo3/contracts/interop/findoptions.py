from enum import IntFlag


class FindOptions(IntFlag):
    NONE = 0
    KEYS_ONLY = 1 << 0
    REMOVE_PREFIX = 1 << 1
    VALUES_ONLY = 1 << 2
    DESERIALIZE_VALUES = 1 << 3
    PICK_FIELD0 = 1 << 4
    PICK_FIELD1 = 1 << 5
    ALL = KEYS_ONLY | REMOVE_PREFIX | VALUES_ONLY | DESERIALIZE_VALUES | PICK_FIELD0 | PICK_FIELD1
