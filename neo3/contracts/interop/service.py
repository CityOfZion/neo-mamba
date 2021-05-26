from __future__ import annotations
import hashlib
from neo3 import contracts
from typing import Dict, Callable, Optional, get_type_hints


class InteropDescriptor:
    NONE_TYPE = type(None)

    def __init__(self,
                 method: str,
                 handler: Callable,
                 price: int,
                 call_flags: contracts.CallFlags):
        """
        Create a interoperability call descriptor.
        This are the functions that can be called using the SYSCALL OpCode in the virtual machine.

        Use the alternative constructor `create_with_price_calculator` if the price needs to be determined dynamically.

        Args:
            method: name of call.
            handler: the function that will be executed when called.
            price: the price of calling the handler.
            call_flags: ExecutionContext rights needed.
        """
        self.method = method
        self.hash: int = int.from_bytes(hashlib.sha256(self.method.encode()).digest()[:4], 'little', signed=False)
        self.handler = handler
        self.parameters = []
        for k, v in get_type_hints(handler).items():
            if k == 'return':
                self.has_return_value = v != self.NONE_TYPE
                continue
            self.parameters.append(v)

        # while using the @register decorator, the first argument to the function is always the application engine
        # itself, we want to strip that off
        self.parameters = self.parameters[1:]
        self.price = price
        self.required_call_flags = call_flags


class InteropService:
    _methods: Dict[int, InteropDescriptor] = {}

    @classmethod
    def get_descriptor(cls, method_id) -> Optional[InteropDescriptor]:
        return cls._methods.get(method_id, None)

    @classmethod
    def register(cls,
                 method: str,
                 handler: Callable,
                 fixed_price: int,
                 call_flags: contracts.CallFlags) -> InteropDescriptor:
        """
        Register an interoperability method to the interoperability service that can be called by the Virtual Machine.

        Args:
            method: name of call.
            handler: the function that will be executed when called.
            fixed_price: the price for calling the handler.
            call_flags: ExecutionContext rights needed.
        """
        descriptor = InteropDescriptor(method, handler, fixed_price, call_flags)
        cls._methods.update({descriptor.hash: descriptor})
        return descriptor
