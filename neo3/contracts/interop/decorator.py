from __future__ import annotations
from neo3 import contracts
from neo3.contracts import interop


def register(method: str,
             price: int,
             flags: contracts.native.CallFlags,
             allow_callback: bool,
             param_types=None):
    """
    Register a SYSCALL handler with the Application engine.

    Args:
        method: name of call.
        price: the price of calling the handler.
        flags: ExecutionContext rights needed.
        allow_callback: can be used in callbacks.
        param_types: optional list of function argument types
    """
    def inner_func(func):
        interop.InteropService.register(method, func, price, flags, allow_callback, param_types)
    return inner_func
