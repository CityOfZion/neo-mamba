from __future__ import annotations
import hashlib
from neo3 import vm, contracts, storage
from typing import Dict, Callable, Union


class InteropDescriptor:
    def __init__(self,
                 method: str,
                 handler: Callable,
                 price: int,
                 allowed_triggers: contracts.TriggerType,
                 call_flags: contracts.native.CallFlags):
        """
        Create a interoperability call descriptor.
        This are the functions that can be called using the SYSCALL OpCode in the virtual machine.

        Use the alternative constructor `create_with_price_calculator` if the price needs to be determined dynamically.

        Args:
            method: name of call.
            handler: the function that will be executed when called.
            price: the price of calling the handler.
            allowed_triggers: the trigger type the contract must be called with to allow execution of the handler.
            call_flags: ExecutionContext rights needed.
        """
        self.method = method
        self.hash: int = int.from_bytes(hashlib.sha256(self.method.encode()).digest()[:4], 'little', signed=False)
        self.handler = handler
        self.price = price
        self.allowed_triggers = allowed_triggers
        self.required_call_flags = call_flags
        self.price_calculator = None

    @classmethod
    def create_with_price_calculator(cls,
                                     method: str,
                                     handler: Callable,
                                     price_calculator: Callable[[vm.EvaluationStack, storage.Snapshot], int],
                                     allowed_triggers: contracts.TriggerType,
                                     call_flags: contracts.native.CallFlags):
        """
        Create a interoperability call descriptor with a dynamically constructor price.
        """
        r = cls(method, handler, 0, allowed_triggers, call_flags)
        r.price_calculator = price_calculator
        return r

    def get_price(self, stack: vm.EvaluationStack, snapshot: storage.Snapshot) -> int:
        """
        Return the price of calling this interoperability layer method.

        Args:
            stack:
            snapshot:

        Returns:

        """
        return self.price if self.price_calculator is None else self.price_calculator(stack, snapshot)


class InteropService:
    _methods: Dict[int, InteropDescriptor] = {}

    @classmethod
    def invoke(cls, engine: vm.ApplicationEngine, method: int) -> bool:
        """
        Invoke a interoperability layer method.

        Args:
            engine: the virtual machine to use.
            method: the interoperability identifier to call.

        Returns:
            bool: indicating if the call was executed successfully.
        """
        descriptor = cls._methods.get(method, False)
        if not descriptor:
            return False
        if engine.trigger not in descriptor.allowed_triggers:
            return False
        context = engine.current_context
        if descriptor.required_call_flags not in contracts.native.CallFlags(context.call_flags):
            return False
        return descriptor.handler(engine)

    @classmethod
    def invoke_with_name(cls, engine: vm.ApplicationEngine, method: str):
        method_num = int.from_bytes(hashlib.sha256(method.encode()).digest()[:4], 'little', signed=False)
        return cls.invoke(engine, method_num)

    @classmethod
    def register(cls,
                 method: str,
                 handler: Callable,
                 price_or_calculator: Union[int, Callable[[vm.EvaluationStack, storage.Snapshot], int]],
                 allowed_triggers: contracts.TriggerType,
                 call_flags: contracts.native.CallFlags) -> InteropDescriptor:
        """
        Register an interoperability method to the interoperability service that can be called by the Virtual Machine.

        Args:
            method: name of call.
            handler: the function that will be executed when called.
            price_or_calculator: a fixed price for calling the handler, or a callable to dynamically determine the price.  # noqa
            allowed_triggers: the trigger type the contract must be called with to allow execution of the handler.
            call_flags: ExecutionContext rights needed.
        """
        if type(price_or_calculator) is int:
            descriptor = InteropDescriptor(method, handler, price_or_calculator, allowed_triggers, call_flags)
        else:
            descriptor = InteropDescriptor.create_with_price_calculator(method,
                                                                        handler,
                                                                        price_or_calculator,
                                                                        allowed_triggers,
                                                                        call_flags)
        cls._methods.update({descriptor.hash: descriptor})
        return descriptor
