from __future__ import annotations
from neo3 import contracts
from neo3.contracts import interop


def register(method: str,
             price: int,
             flags: contracts.native.CallFlags,
             param_types=None):
    """
    Register a SYSCALL handler with the Application engine.

    Args:
        method: name of call.
        price: the price of calling the handler.
        flags: ExecutionContext rights needed.
        param_types: optional list of function argument types
    """
    def inner_func(func):
        interop.InteropService.register(method, func, price, flags, param_types)
        return func
    return inner_func
