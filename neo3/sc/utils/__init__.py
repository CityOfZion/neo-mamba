from typing import Optional, Sequence, Any
from neo3.sc.types import UInt160, CallFlags
from neo3.sc.utils.iterator import Iterator


def abort(msg: Optional[str] = None) -> None:
    """
    Aborts the execution of a smart contract. Using this will cancel the changes made on the blockchain by the
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

    Example:
        >>> from neo3.sc.contracts import NeoToken
        >>> call_contract(
        ...     NeoToken.hash,
        ...     'balanceOf',
        ...     [UInt160(b'\\xcfv\\xe2\\x8b\\xd0\\x06,JG\\x8e\\xe3Ua\\x01\\x13\\x19\\xf3\\xcf\\xa4\\xd2')]
        ... )
        100

    Args:
        script_hash (UInt160): The script hash of the target smart contract.
        method (str): The name of the entry point in the target smart contract.
        args (Sequence[Any], optional): The specified method's arguments. Defaults to ().
        call_flags (CallFlags, optional): The CallFlags to be used to call the contract.
            Defaults to CallFlags.ALL.

    Returns:
        Any: The result of the specified method.

    Raises:
        Exception: If the CallFlags are invalid, the script hash is not a valid smart contract,
            the method is not found, or the arguments are invalid for the specified method.
    """
    pass
