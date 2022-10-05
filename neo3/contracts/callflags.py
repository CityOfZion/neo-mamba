from enum import IntFlag


class CallFlags(IntFlag):
    """
    Describes the required call permissions for contract functions.
    """

    NONE = 0
    READ_STATES = 0x1
    WRITE_STATES = 0x02
    ALLOW_CALL = 0x04
    ALLOW_NOTIFY = 0x08
    STATES = READ_STATES | WRITE_STATES
    READ_ONLY = READ_STATES | ALLOW_CALL
    ALL = STATES | ALLOW_CALL | ALLOW_NOTIFY

    @classmethod
    def from_csharp_name(cls, input: str):
        def get(input):
            if input == "None":
                return CallFlags.NONE
            elif input == "ReadStates":
                return CallFlags.READ_STATES
            elif input == "WriteStates":
                return CallFlags.WRITE_STATES
            elif input == "AllowCall":
                return CallFlags.ALLOW_CALL
            elif input == "AllowNotify":
                return CallFlags.ALLOW_NOTIFY
            elif input == "States":
                return CallFlags.STATES
            elif input == "ReadOnly":
                return CallFlags.READ_ONLY
            elif input == "All":
                return CallFlags.ALL
            else:
                raise ValueError(f"{input} is not a valid member of {cls.__name__}")

        flags = [get(flag.strip()) for flag in input.split(",")]

        result = flags[0]
        for flag in flags[1:]:
            result |= flag
        return result
