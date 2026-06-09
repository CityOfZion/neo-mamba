from neo3.sc.compiletime import call_flags, contract, display_name
from neo3.sc.types import CallFlags, UInt160


@contract("0xcc5e4edd9f5f8dba8bb65734541df7a1c081c67b")
class PolicyContract:
    """
    Represents the Policy native contract.

    See:
        https://developers.neo.org/docs/n3/reference/scapi/framework/native/Policy
    """

    hash: UInt160

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getFeePerByte")
    def get_fee_per_byte() -> int:
        """Return the fee per transaction byte."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getExecFeeFactor")
    def get_exec_fee_factor() -> int:
        """Return the execution fee factor multiplier."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getStoragePrice")
    def get_storage_price() -> int:
        """Return the storage price per byte."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("isBlocked")
    def is_blocked(account: UInt160) -> bool:
        """Return True if `account` is blocked by policy."""
        pass
