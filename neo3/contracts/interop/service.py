from __future__ import annotations
import hashlib
import inspect
from neo3 import contracts
from typing import Dict, Callable, Optional, List, get_type_hints


class InteropDescriptor:
    def __init__(self,
                 method: str,
                 handler: Callable,
                 price: int,
                 call_flags: contracts.CallFlags,
                 param_types: list = None):
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
        # params = []
        # for k, v in get_type_hints(handler):
        #     if k == 'return':
        #         continue
        #     params.append(v)
        # print(f"*** {params == param_types}")
        self.parameters = param_types if param_types else []
        self.has_return_value = inspect.signature(handler).return_annotation != 'None'
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
                 call_flags: contracts.CallFlags,
                 param_types: Optional[List[type]]) -> InteropDescriptor:
        """
        Register an interoperability method to the interoperability service that can be called by the Virtual Machine.

        Args:
            method: name of call.
            handler: the function that will be executed when called.
            fixed_price: the price for calling the handler.
            call_flags: ExecutionContext rights needed.
            param_types: an optional list of types the handler accepts.

                Note: This is a work around until the build-in inspect module can return actual signature parameter
                types instead of strings.
        """
        descriptor = InteropDescriptor(method, handler, fixed_price, call_flags, param_types)
        cls._methods.update({descriptor.hash: descriptor})
        return descriptor
