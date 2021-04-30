from __future__ import annotations
from neo3 import contracts


def register(method: str,
             flags: contracts.CallFlags,
             *,
             cpu_price: int = 0,
             storage_price: int = 0):
    """
    Register a publicly callable method on a native contract

    Args:
        method: name of call.
        cpu_price: the computational price of calling the handler.
        storage_price: the storage price of calling the handler.
        flags: ExecutionContext rights needed.
    """
    def inner_func(func):
        func.native_call = True
        func.name = method
        func.cpu_price = cpu_price
        func.storage_price = storage_price
        func.flags = flags
        return func
    return inner_func
