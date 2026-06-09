from typing import Optional, Sequence, Any
from neo3.sc.types import UInt160, CallFlags
from neo3.sc.utils.iterator import Iterator


def abort(msg: Optional[str] = None) -> None:
    """
    Abort the execution of a smart contract. Using this will cancel the changes made on the blockchain by the
    transaction.

    >>> abort()     # abort doesn't return anything by itself, but the execution will stop and the VMState will be FAULT
    VMState.FAULT

    >>> abort('abort message')
    VMState.FAULT

    """
    pass


def call_contract(
    script_hash: UInt160,
    method: str,
    args: Optional[list] = None,
    call_flags: CallFlags = CallFlags.ALL,
) -> Any:
    """
    Call a smart contract given the method and the arguments.

    Args:
        script_hash: The script hash of the target smart contract.
        method: The name of the entry point in the target smart contract.
        args: The specified method's arguments. Defaults to ().
        call_flags: The CallFlags to be used to call the contract. Defaults to CallFlags.ALL.

    Example:
        >>> from neo3.sc.contracts import NeoToken
        >>> call_contract(
        ...     NeoToken.hash,
        ...     'balanceOf',
        ...     [UInt160(b'\\xcfv\\xe2\\x8b\\xd0\\x06,JG\\x8e\\xe3Ua\\x01\\x13\\x19\\xf3\\xcf\\xa4\\xd2')]
        ... )
        100


    Returns:
        Any: The result of the specified method.

    Raises:
        Exception: If the CallFlags are invalid, the script hash is not a valid smart contract,
            the method is not found, or the arguments are invalid for the specified method.
    """
    pass
