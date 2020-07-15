from neo3 import contracts, vm, storage
from typing import Callable, Union
from neo3.contracts import interop


def register(name: str,
             price_or_calculator: Union[int, Callable[[vm.EvaluationStack, storage.Snapshot], int]],
             triggers: contracts.TriggerType,
             flags: contracts.native.CallFlags):
    """
    Register a SYSCALL with the interoperability service.

    Args:
        name: syscall identifier i.e. "System.Blockchain.GetHeight".
        price_or_calculator: a fixed price for calling the handler, or a callable to dynamically determine the price.
        triggers: the trigger type the contract must have been called with to allow execution of the handler.
        flags: ExecutionContext rights needed.
    """
    def inner_func(func):
        interop.InteropService.register(name, func, price_or_calculator, triggers, flags)
    return inner_func
