"""
Helper functions to easily fetch native values from the `ResultStack` returned as response by various RPC methods
such as `invoke_function()`, `invoke_script()`, `get_application_log_transaction()` and `get_application_log_block()`.

Includes sanity checking.
"""
from __future__ import annotations
from neo3.api import noderpc
from neo3 import vm
from neo3.core import types, cryptography


def check_state_ok(res: noderpc.ExecutionResult):
    """
    Check if the execution of the transaction finished in a success state.

    Raises:
        ValueError: if the VM state is not HALT.
    """
    if vm.VMState.from_string(res.state) != vm.VMState.HALT:
        raise ValueError(
            f"Transaction execution failed with state {res.state} and err: {res.exception}"
        )


def as_bool(res: noderpc.ExecutionResult, idx: int = 0) -> bool:
    """
    Convert the stack item at `idx` to a `bool`.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to a bool.
    """
    return item(res, idx).as_bool()


def as_str(res: noderpc.ExecutionResult, idx: int = 0) -> str:
    """
    Convert the stack item at `idx` to a `str`.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to a `str`.
    """
    return item(res, idx).as_str()


def as_int(res: noderpc.ExecutionResult, idx: int = 0) -> int:
    """
    Convert the stack item at `idx` to an `int`.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to an int.
    """
    return item(res, idx).as_int()


def as_uint160(res: noderpc.ExecutionResult, idx: int = 0) -> types.UInt160:
    """
    Convert the stack item at `idx` to an `UInt160`.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to an UInt160.
    """
    return item(res, idx).as_uint160()


def as_uint256(res: noderpc.ExecutionResult, idx: int = 0) -> types.UInt256:
    """
    Convert the stack item at `idx` to an `UInt256`.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to an UInt256.
    """
    return item(res, idx).as_uint256()


def as_address(res: noderpc.ExecutionResult, idx: int = 0) -> str:
    """
    Convert the stack item at `idx` to a NEO3 address.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to a NEO3 address.
    """
    return item(res, idx).as_address()


def as_public_key(res: noderpc.ExecutionResult, idx: int = 0) -> cryptography.ECPoint:
    """
    Convert the stack item at `idx` to a public key.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to a bool.
        ECCException: if the resulting key is not valid on the SECP256R1 curve.
    """
    return item(res, idx).as_public_key()


def as_list(res: noderpc.ExecutionResult, idx: int = 0) -> list[noderpc.StackItem]:
    """
    Convert the stack item at `idx` to a `list`.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to a list.
    """
    return item(res, idx).as_list()


def as_dict(res: noderpc.ExecutionResult, idx: int = 0) -> dict:
    """
    Convert the stack item at `idx` to a dictionary.

    Args:
        res: execution result.
        idx: idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to a dict.

    """
    return item(res, idx).as_dict()


def as_none(res: noderpc.ExecutionResult, idx: int = 0) -> None:
    """
    Convert the stack item at `idx` to `None`.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value is not `None`.
    """
    return item(res, idx).as_none()


def as_bytes(res: noderpc.ExecutionResult, idx: int = 0) -> bytes:
    """
    Convert the stack item at `idx` to `bytes`.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.

    Raises:
        ValueError: if the index is out of range, or the value cannot be converted to bytes.

    """
    return item(res, idx).as_bytes()


def item(res: noderpc.ExecutionResult, idx: int = 0) -> noderpc.StackItem:
    """
    Fetch the stack item at `idx` from the result stack. Performs basic validation and bounds checking.

    Args:
        res: execution result.
        idx: the index in the result stack to fetch the stack item from.
    """
    check_state_ok(res)
    if idx > len(res.stack) - 1:
        raise ValueError("Too few result items")
    return res.stack[idx]
