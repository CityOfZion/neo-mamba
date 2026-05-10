from neo3.sc.compiletime import call_flags, contract, display_name
from neo3.sc.types import CallFlags, ECPoint, UInt160


@contract("0x49cf4e5378ffcd4dec034fd98a174c5491e395e2")
class RoleManagement:
    """
    Represents the RoleManagement native contract.

    See:
        https://developers.neo.org/docs/n3/reference/scapi/framework/native/RoleManagement
    """

    hash: UInt160

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getDesignatedByRole")
    def get_designated_by_role(role: int, index: int) -> list:
        """Return the list of ECPoints designated for *role* at block *index*.

        Args:
            role: the role identifier (see neo3.contracts.native.Role).
            index: the block index at which to query.

        Returns:
            list: list of ECPoint values for the designated nodes.
        """
        pass
