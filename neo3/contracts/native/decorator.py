from __future__ import annotations
from neo3 import contracts


def register(method: str,
             price: int,
             flags: contracts.CallFlags):
    """
    Register a publicly callable method on a native contract

    Args:
        method: name of call.
        price: the price of calling the handler.
        flags: ExecutionContext rights needed.
    """
    def inner_func(func):
        func.native_call = True
        func.name = method
        func.price = price
        func.flags = flags
        return func
    return inner_func
