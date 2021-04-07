from enum import IntFlag


class CallFlags(IntFlag):
    """
    Describes the required call permissions for contract functions.
    """
    NONE = 0,
    READ_STATES = 0x1
    WRITE_STATES = 0x02
    ALLOW_CALL = 0x04
    ALLOW_NOTIFY = 0x08
    STATES = READ_STATES | WRITE_STATES
    READ_ONLY = READ_STATES | ALLOW_CALL
    ALL = STATES | ALLOW_CALL | ALLOW_NOTIFY
