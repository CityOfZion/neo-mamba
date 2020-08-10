from __future__ import annotations
from neo3 import contracts, storage, vm
from neo3.core import types, cryptography, IInteroperable
from neo3.contracts import interop
from typing import Any, Callable, Dict, cast
import hashlib


class ApplicationEngine(vm.ExecutionEngine):
    GAS_FREE = 0
    _interop_calls: Dict[int, interop.InteropDescriptor] = {}

    def __init__(self,
                 trigger: contracts.TriggerType,
                 container: Any,
                 snapshot: storage.Snapshot,
                 gas: int,
                 test_mode: bool = False
                 ):
        super(ApplicationEngine, self).__init__()
        self.snapshot = snapshot
        self.trigger = trigger
        self.is_test_mode = test_mode
        self.script_container = container
        self.gas_amount = self.GAS_FREE + gas
        self.gas_consumed = 0

    def _convert(self, stack_item, class_type):
        if class_type in [vm.StackItem, vm.PointerStackItem, vm.ArrayStackItem, vm.InteropStackItem]:
            return stack_item
        elif class_type in [int, vm.BigInteger]:
            return stack_item.to_biginteger()
        elif class_type in [bytes, bytearray]:
            return stack_item.to_array()
        elif class_type == bool:
            return stack_item.to_boolean()
        elif class_type == types.UInt160:
            return types.UInt160(data=stack_item.to_array())
        elif class_type == types.UInt256:
            return types.UInt256(data=stack_item.to_array())
        elif class_type == cryptography.EllipticCurve.ECPoint:
            return cryptography.EllipticCurve.ECPoint.deserialize_from_bytes(stack_item.to_array())
        else:
            raise ValueError(f"Unknown class type, don't know how to convert: {class_type}")

    def _native_to_stackitem(self, value, native_type):
        if native_type == vm.StackItem:
            native_type = type(value)
        if native_type in [int, vm.BigInteger]:
            return vm.IntegerStackItem(value)
        elif native_type == type(None):
            return vm.NullStackItem()
        elif issubclass(native_type, IInteroperable):
            value_ = cast(IInteroperable, value)
            return value_.to_stack_item(self.reference_counter)

    def add_gas(self, amount: int):
        self.gas_consumed += amount
        if not self.is_test_mode and self.gas_consumed > self.gas_consumed:
            raise ValueError("Insufficient GAS")

    def on_syscall(self, method_id: int):
        descriptor = interop.InteropService.get_descriptor(method_id)
        if descriptor is None:
            raise KeyError(f"Requested interop {method_id} is not valid")

        if descriptor.required_call_flags not in contracts.native.CallFlags(self.current_context.call_flags):
            raise ValueError(f"Cannot call {descriptor.method} with {self.current_context.call_flags}")

        self.add_gas(descriptor.price)

        parameters = []
        for class_type in descriptor.parameters:
            parameters.append(self._convert(self.pop(), class_type))
        if len(parameters) > 0:
            return_value = descriptor.handler(self, *parameters)
        else:
            return_value = descriptor.handler(self)
        if descriptor.has_return_value:
            self.push(self._native_to_stackitem(return_value, type(return_value)))

    def invoke_syscall_by_name(self, method: str):
        method_num = int.from_bytes(hashlib.sha256(method.encode()).digest()[:4], 'little', signed=False)
        return self.on_syscall(method_num)
