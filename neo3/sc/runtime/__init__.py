from typing import Optional, Any
from neo3.sc.types import TrimmedTransaction, UInt160, ECPoint, CallFlags, Notification
from neo3.sc.compiletime import syscall


@syscall("System.Runtime.GetScriptContainer")
def get_script_container() -> TrimmedTransaction:
    """
    Gets the current script container. Which in a smart contract is always the calling transaction.
    """
    pass


@syscall("System.Runtime.GetCallingScriptHash")
def get_calling_script_hash() -> UInt160:  # TODO: these should be optional
    """
    Gets the script hash of the calling contract.
    """
    pass


@syscall("System.Runtime.GetEntryScriptHash")
def get_entry_script_hash() -> (
    UInt160
):  # TODO: these should be optional but can they actually ever be in a smart contract?
    """
    Gets the script hash of the entry context
    """
    pass


@syscall("System.Runtime.GetExecutingScriptHash")
def get_executing_script_hash() -> UInt160:
    """
    Gets the script hash of the current context.
    """
    pass


@syscall("System.Runtime.GetRandom")
def get_random() -> int:
    """
    Gets the random number generated from the VRF
    """
    pass


@syscall("System.Runtime.CheckWitness")
def check_witness(hash: UInt160 | ECPoint) -> bool:
    """
    Determines whether the specified account has witnessed the current transaction

    Args:
        hash: the hash or public key of the account to verify against.
    """
    pass


@syscall("System.Runtime.BurnGas")
def burn_gas(datoshi: int) -> None:
    """
    Burning GAS to benefit the NEO ecosystem.

    Args:
        datoshi: the amount of GAS to burn, in the unit of datoshi, 1 datoshi = 1e-8 GAS
    """
    pass


@syscall("System.Runtime.GasLeft")
def gas_left() -> int:
    """
    Gets the remaining GAS that can be spent in order to complete the execution
    """
    pass


@syscall("System.Runtime.GetTime")
def get_time() -> int:
    """
    Gets the timestamp of the current block
    """
    pass


@syscall("System.Runtime.GetInvocationCounter")
def get_invocation_counter() -> int:
    """
    Gets the number of times the current contract has been called during the execution
    """
    pass


@syscall("System.Runtime.LoadScript")
def load_script(
    script: bytes, call_flags: CallFlags = CallFlags.NONE, args: Optional[list] = None
) -> Any:
    """
    Loads a script at runtime
    """
    pass


@syscall("System.Runtime.GetNotifications")
def get_notifications(script_hash: Optional[UInt160] = None) -> list[Notification]:
    """
    Gets the notifications sent by the specified contract during the execution

    Args:
        script_hash: the contract to return notifications for. Omit to get all notifications.
    """
    pass
