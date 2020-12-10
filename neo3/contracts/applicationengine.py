from __future__ import annotations
from neo3 import contracts, storage, vm
from neo3.network import payloads
from neo3.core import types, cryptography, IInteroperable, serialization, to_script_hash
from neo3.contracts import interop
from typing import Any, Dict, cast, List, Tuple, Type, Optional, Callable
import enum
from dataclasses import dataclass


class ApplicationEngine(vm.ExecutionEngine):
    _interop_calls: Dict[int, interop.InteropDescriptor] = {}
    _invocation_states: Dict[vm.ExecutionContext, InvocationState] = {}
    #: Amount of free GAS added to the engine.
    GAS_FREE = 0
    #: Maximum length of event names for "System.Runtime.Notify" SYSCALLs.
    MAX_EVENT_SIZE = 32
    #: Maximum messasge length for "System.Runtime.Log" SYSCALLs.
    MAX_NOTIFICATION_SIZE = 1024
    #: Maximum size of the smart contract script.
    MAX_CONTRACT_LENGTH = 1024 * 1024
    #: Multiplier for determining the costs of storing the contract including its manifest.
    STORAGE_PRICE = 100000

    @dataclass
    class InvocationState:
        return_type: type = None  # type: ignore
        callback: Optional[Callable] = None
        check_return_value: bool = False

    def __init__(self,
                 trigger: contracts.TriggerType,
                 container: payloads.IVerifiable,
                 snapshot: storage.Snapshot,
                 gas: int,
                 test_mode: bool = False
                 ):
        # Do not use super() version, see
        # https://pybind11.readthedocs.io/en/master/advanced/classes.html#overriding-virtual-functions-in-python
        vm.ExecutionEngine.__init__(self)
        #: A ledger snapshot to use for syscalls such as "System.Blockchain.GetHeight".
        self.snapshot = snapshot
        #: The trigger to run the engine with.
        self.trigger = trigger
        #: A flag to toggle infinite gas
        self.is_test_mode = test_mode

        self.script_container = container
        #: Gas available for consumption by the engine while executing its script.
        self.gas_amount = self.GAS_FREE + gas
        #: The amount of gas used for executing its script.
        self.gas_consumed = 0
        self._invocation_counter: Dict[types.UInt160, int] = {}
        #: Notifications (Notify SYSCALLs) that occured while executing the script.
        self.notifications: List[Tuple[payloads.IVerifiable, types.UInt160, bytes, vm.ArrayStackItem]] = []

    def checkwitness(self, hash_: types.UInt160) -> bool:
        """
        Check if the hash is a valid witness for the engines script_container
        """
        if isinstance(self.script_container, payloads.Transaction):
            tx = self.script_container
            for s in tx.signers:
                if s.account == hash_:
                    signer = s
                    break
            else:
                return False

            if signer.scope == payloads.WitnessScope.GLOBAL:
                return True

            if payloads.WitnessScope.CALLED_BY_ENTRY in signer.scope:
                if self.calling_scripthash == self.entry_scripthash:
                    return True

            if payloads.WitnessScope.CUSTOM_CONTRACTS in signer.scope:
                if self.current_scripthash in signer.allowed_contracts:
                    return True

            if payloads.WitnessScope.CUSTOM_GROUPS in signer.scope:
                contract = self.snapshot.contracts.get(self.calling_scripthash)
                group_keys = set(map(lambda g: g.public_key, contract.manifest.groups))
                if any(group_keys.intersection(signer.allowed_groups)):
                    return True
            return False

        # for other IVerifiable types like Block
        hashes_for_verifying = self.script_container.get_script_hashes_for_verifying(self.snapshot)
        return hash_ in hashes_for_verifying

    def _stackitem_to_native(self, stack_item: vm.StackItem, target_type: Type[object]):
        # checks for type annotations like `List[bytes]` (similar to byte[][] in C#)
        if hasattr(target_type, '__origin__') and target_type.__origin__ == list:  # type: ignore
            element_type = target_type.__args__[0]  # type: ignore
            array = []
            if isinstance(stack_item, vm.ArrayStackItem):
                for e in stack_item:
                    array.append(self._convert(e, element_type))
            else:
                count = stack_item.to_biginteger()
                if count > self.MAX_STACK_SIZE:
                    raise ValueError

                # mypy bug: https://github.com/python/mypy/issues/9755
                for e in range(count):  # type: ignore
                    array.append(self._convert(self.pop(), element_type))
            return array
        else:
            try:
                return self._convert(stack_item, target_type)
            except ValueError:
                if isinstance(stack_item, vm.InteropStackItem):
                    return stack_item.get_object()
                else:
                    raise

    def _convert(self, stack_item: vm.StackItem, class_type: Type[object]) -> object:
        """
        convert VM type to native
        """
        if class_type in [vm.StackItem, vm.PointerStackItem, vm.ArrayStackItem, vm.InteropStackItem]:
            return stack_item
        elif class_type in [int, vm.BigInteger]:
            return stack_item.to_biginteger()
        # mypy bug? https://github.com/python/mypy/issues/9756
        elif class_type in [bytes, bytearray]:  # type: ignore
            return stack_item.to_array()
        elif class_type == bool:
            return stack_item.to_boolean()
        elif class_type == types.UInt160:
            return types.UInt160(data=stack_item.to_array())
        elif class_type == types.UInt256:
            return types.UInt256(data=stack_item.to_array())
        elif class_type == str:
            return stack_item.to_array().decode()
        elif class_type == cryptography.EllipticCurve.ECPoint:
            return cryptography.EllipticCurve.ECPoint.deserialize_from_bytes(stack_item.to_array())
        elif issubclass(class_type, enum.Enum):
            stack_item = cast(vm.IntegerStackItem, stack_item)
            # mypy seems to have trouble understanding types that support __int__
            return class_type(int(stack_item))  # type: ignore
        else:
            raise ValueError(f"Unknown class type, don't know how to convert: {class_type}")

    def _native_to_stackitem(self, value, native_type) -> vm.StackItem:
        """
        Convert native type to VM type

        Note: order of checking matters.
        e.g. a Transaction should be treated as IInteropable, while its also ISerializable
        """
        if isinstance(value, vm.StackItem):
            return value
        elif value is None:
            return vm.NullStackItem()
        elif native_type in [int, vm.BigInteger]:
            return vm.IntegerStackItem(value)
        elif issubclass(native_type, IInteroperable):
            value_ = cast(IInteroperable, value)
            return value_.to_stack_item(self.reference_counter)
        elif issubclass(native_type, serialization.ISerializable):
            serializable_value = cast(serialization.ISerializable, value)
            return vm.ByteStringStackItem(serializable_value.to_array())
        # mypy bug? https://github.com/python/mypy/issues/9756
        elif native_type in [bytes, bytearray]:  # type: ignore
            return vm.ByteStringStackItem(value)
        elif native_type == str:
            return vm.ByteStringStackItem(bytes(value, 'utf-8'))
        elif native_type == bool:
            return vm.BooleanStackItem(value)
        elif issubclass(native_type, (enum.IntFlag, enum.IntEnum)):
            return self._native_to_stackitem(value.value, int)
        else:
            return vm.StackItem.from_interface(value)

    def _get_invocation_state(self, context: vm.ExecutionContext) -> InvocationState:
        state = self._invocation_states.get(context, None)
        if state is None:
            state = self.InvocationState()
            self._invocation_states.update({context: state})
        return state

    def add_gas(self, amount: int) -> None:
        """
        Increase the gas consumed value of the engine.
        Args:
            amount: value to increase with.

        Raise:
            ValueError: if the new gas consumed value exceeds the availe gas amount
        """
        self.gas_consumed += amount
        if not self.is_test_mode and self.gas_consumed > self.gas_amount:
            raise ValueError("Insufficient GAS")

    def on_syscall(self, method_id: int) -> Any:
        """
        Handle interop syscalls.

        Args:
            method_id: unique syscall identifier.

        Raise:
            KeyError: if `method_id` is syscall that is not registered with the engine.
            ValueError: if the requested syscall handler is called with the wrong call flags.
            ValueError: if engine stack parameter to native type conversion fails

        Returns:
            The result of the syscall handler
        """
        descriptor = interop.InteropService.get_descriptor(method_id)
        if descriptor is None:
            raise KeyError(f"Requested interop {method_id} is not valid")

        if descriptor.required_call_flags not in contracts.native.CallFlags(self.current_context.call_flags):
            raise ValueError(f"Cannot call {descriptor.method} with {self.current_context.call_flags}")

        self.add_gas(descriptor.price)

        parameters = []
        for target_type in descriptor.parameters:
            try:
                item = self.pop()
                parameters.append(self._stackitem_to_native(item, target_type))
            except IndexError:
                raise ValueError("Failed to pop parameter from stack")
            except Exception:
                raise ValueError(f"Failed to convert parameter stack item '{item}' to type '{target_type}'")

        if len(parameters) > 0:
            return_value = descriptor.handler(self, *parameters)
        else:
            return_value = descriptor.handler(self)
        if descriptor.has_return_value:
            self.push(self._native_to_stackitem(return_value, type(return_value)))
        return return_value

    def invoke_syscall_by_name(self, method: str) -> Any:
        """
        Helper function to call `on_syscall` using the syscall name.

        Args:
            method: full qualified syscall name. e.g. "System.Runtime.Platform"

        Returns: the result of the syscall handler. e.g. for "System.Runtime.Platform" returns "NEO"
        """
        return self.on_syscall(contracts.syscall_name_to_int(method))

    @property
    def current_scripthash(self) -> types.UInt160:
        """
        Get the script hash of the current executing smart contract

        Note: a smart contract can call other smart contracts.
        """
        return to_script_hash(self.current_context.script._value)

    @property
    def calling_scripthash(self) -> types.UInt160:
        """
        Get the script hash of the smart contract that called the current executing smart contract.

        Note: a smart contract can call other smart contracts.

        Raises:
            ValueError: if the current executing contract has not been called by another contract.
        """
        if len(self.current_context.calling_script) == 0:
            raise ValueError("Cannot retrieve calling script_hash - current context has not yet been called")
        return to_script_hash(self.current_context.calling_script._value)

    @property
    def entry_scripthash(self) -> types.UInt160:
        """
        Get the script hash of the first smart contract loaded into the engine

        Note: a smart contract can call other smart contracts.
        """
        return to_script_hash(self.entry_context.script._value)

    def get_invocation_counter(self) -> int:
        """
        Get the number of times the current contract has been called during this execute() run.

        Note: the counter increases with every "System.Contract.Call" or "System.Contract.CallEx" SYSCALL

        Raises:
            ValueError: if the contract has not been called.
        """
        counter = self._invocation_counter.get(self.current_scripthash, None)
        if counter is None:
            raise ValueError(f"Failed to get invocation counter for the current context: {self.current_scripthash}")
        return counter

    def context_unloaded(self, context: vm.ExecutionContext):
        # Do not use super() version, see
        # https://pybind11.readthedocs.io/en/master/advanced/classes.html#overriding-virtual-functions-in-python
        vm.ExecutionEngine.context_unloaded(self, context)
        if self.uncaught_exception is not None:
            return
        if len(self._invocation_states) == 0:
            return
        try:
            state = self._invocation_states.pop(self.current_context)
        except KeyError:
            return
        if state.check_return_value:
            eval_stack_len = len(context.evaluation_stack)
            if eval_stack_len == 0:
                self.push(vm.NullStackItem())
            elif eval_stack_len > 1:
                raise SystemError("Invalid evaluation stack state")

        if state.callback is None:
            return
        # TODO: implementation Action/DynamicInvoke part of callback logic

    def pre_execute_instruction(self):
        if self.current_context.ip < len(self.current_context.script):
            self.add_gas(opcode_prices.get(self.current_context.current_instruction().opcode))


opcode_prices: Dict[vm.OpCode, int] = {
    vm.OpCode.PUSHINT8: 30,
    vm.OpCode.PUSHINT16: 30,
    vm.OpCode.PUSHINT32: 30,
    vm.OpCode.PUSHINT64: 30,
    vm.OpCode.PUSHINT128: 120,
    vm.OpCode.PUSHINT256: 120,
    vm.OpCode.PUSHA: 120,
    vm.OpCode.PUSHNULL: 30,
    vm.OpCode.PUSHDATA1: 180,
    vm.OpCode.PUSHDATA2: 13000,
    vm.OpCode.PUSHDATA4: 110000,
    vm.OpCode.PUSHM1: 30,
    vm.OpCode.PUSH0: 30,
    vm.OpCode.PUSH1: 30,
    vm.OpCode.PUSH2: 30,
    vm.OpCode.PUSH3: 30,
    vm.OpCode.PUSH4: 30,
    vm.OpCode.PUSH5: 30,
    vm.OpCode.PUSH6: 30,
    vm.OpCode.PUSH7: 30,
    vm.OpCode.PUSH8: 30,
    vm.OpCode.PUSH9: 30,
    vm.OpCode.PUSH10: 30,
    vm.OpCode.PUSH11: 30,
    vm.OpCode.PUSH12: 30,
    vm.OpCode.PUSH13: 30,
    vm.OpCode.PUSH14: 30,
    vm.OpCode.PUSH15: 30,
    vm.OpCode.PUSH16: 30,
    vm.OpCode.NOP: 30,
    vm.OpCode.JMP: 70,
    vm.OpCode.JMP_L: 70,
    vm.OpCode.JMPIF: 70,
    vm.OpCode.JMPIF_L: 70,
    vm.OpCode.JMPIFNOT: 70,
    vm.OpCode.JMPIFNOT_L: 70,
    vm.OpCode.JMPEQ: 70,
    vm.OpCode.JMPEQ_L: 70,
    vm.OpCode.JMPNE: 70,
    vm.OpCode.JMPNE_L: 70,
    vm.OpCode.JMPGT: 70,
    vm.OpCode.JMPGT_L: 70,
    vm.OpCode.JMPGE: 70,
    vm.OpCode.JMPGE_L: 70,
    vm.OpCode.JMPLT: 70,
    vm.OpCode.JMPLT_L: 70,
    vm.OpCode.JMPLE: 70,
    vm.OpCode.JMPLE_L: 70,
    vm.OpCode.CALL: 22000,
    vm.OpCode.CALL_L: 22000,
    vm.OpCode.CALLA: 22000,
    vm.OpCode.ABORT: 30,
    vm.OpCode.ASSERT: 30,
    vm.OpCode.THROW: 22000,
    vm.OpCode.TRY: 100,
    vm.OpCode.TRY_L: 100,
    vm.OpCode.ENDTRY: 100,
    vm.OpCode.ENDTRY_L: 100,
    vm.OpCode.ENDFINALLY: 100,
    vm.OpCode.RET: 0,
    vm.OpCode.SYSCALL: 0,
    vm.OpCode.DEPTH: 60,
    vm.OpCode.DROP: 60,
    vm.OpCode.NIP: 60,
    vm.OpCode.XDROP: 400,
    vm.OpCode.CLEAR: 400,
    vm.OpCode.DUP: 60,
    vm.OpCode.OVER: 60,
    vm.OpCode.PICK: 60,
    vm.OpCode.TUCK: 60,
    vm.OpCode.SWAP: 60,
    vm.OpCode.ROT: 60,
    vm.OpCode.ROLL: 400,
    vm.OpCode.REVERSE3: 60,
    vm.OpCode.REVERSE4: 60,
    vm.OpCode.REVERSEN: 400,
    vm.OpCode.INITSSLOT: 400,
    vm.OpCode.INITSLOT: 800,
    vm.OpCode.LDSFLD0: 60,
    vm.OpCode.LDSFLD1: 60,
    vm.OpCode.LDSFLD2: 60,
    vm.OpCode.LDSFLD3: 60,
    vm.OpCode.LDSFLD4: 60,
    vm.OpCode.LDSFLD5: 60,
    vm.OpCode.LDSFLD6: 60,
    vm.OpCode.LDSFLD: 60,
    vm.OpCode.STSFLD0: 60,
    vm.OpCode.STSFLD1: 60,
    vm.OpCode.STSFLD2: 60,
    vm.OpCode.STSFLD3: 60,
    vm.OpCode.STSFLD4: 60,
    vm.OpCode.STSFLD5: 60,
    vm.OpCode.STSFLD6: 60,
    vm.OpCode.STSFLD: 60,
    vm.OpCode.LDLOC0: 60,
    vm.OpCode.LDLOC1: 60,
    vm.OpCode.LDLOC2: 60,
    vm.OpCode.LDLOC3: 60,
    vm.OpCode.LDLOC4: 60,
    vm.OpCode.LDLOC5: 60,
    vm.OpCode.LDLOC6: 60,
    vm.OpCode.LDLOC: 60,
    vm.OpCode.STLOC0: 60,
    vm.OpCode.STLOC1: 60,
    vm.OpCode.STLOC2: 60,
    vm.OpCode.STLOC3: 60,
    vm.OpCode.STLOC4: 60,
    vm.OpCode.STLOC5: 60,
    vm.OpCode.STLOC6: 60,
    vm.OpCode.STLOC: 60,
    vm.OpCode.LDARG0: 60,
    vm.OpCode.LDARG1: 60,
    vm.OpCode.LDARG2: 60,
    vm.OpCode.LDARG3: 60,
    vm.OpCode.LDARG4: 60,
    vm.OpCode.LDARG5: 60,
    vm.OpCode.LDARG6: 60,
    vm.OpCode.LDARG: 60,
    vm.OpCode.STARG0: 60,
    vm.OpCode.STARG1: 60,
    vm.OpCode.STARG2: 60,
    vm.OpCode.STARG3: 60,
    vm.OpCode.STARG4: 60,
    vm.OpCode.STARG5: 60,
    vm.OpCode.STARG6: 60,
    vm.OpCode.STARG: 60,
    vm.OpCode.NEWBUFFER: 80000,
    vm.OpCode.MEMCPY: 80000,
    vm.OpCode.CAT: 80000,
    vm.OpCode.SUBSTR: 80000,
    vm.OpCode.LEFT: 80000,
    vm.OpCode.RIGHT: 80000,
    vm.OpCode.INVERT: 100,
    vm.OpCode.AND: 200,
    vm.OpCode.OR: 200,
    vm.OpCode.XOR: 200,
    vm.OpCode.EQUAL: 200,
    vm.OpCode.NOTEQUAL: 200,
    vm.OpCode.SIGN: 100,
    vm.OpCode.ABS: 100,
    vm.OpCode.NEGATE: 100,
    vm.OpCode.INC: 100,
    vm.OpCode.DEC: 100,
    vm.OpCode.ADD: 200,
    vm.OpCode.SUB: 200,
    vm.OpCode.MUL: 300,
    vm.OpCode.DIV: 300,
    vm.OpCode.MOD: 300,
    vm.OpCode.SHL: 300,
    vm.OpCode.SHR: 300,
    vm.OpCode.NOT: 100,
    vm.OpCode.BOOLAND: 200,
    vm.OpCode.BOOLOR: 200,
    vm.OpCode.NZ: 100,
    vm.OpCode.NUMEQUAL: 200,
    vm.OpCode.NUMNOTEQUAL: 200,
    vm.OpCode.LT: 200,
    vm.OpCode.LE: 200,
    vm.OpCode.GT: 200,
    vm.OpCode.GE: 200,
    vm.OpCode.MIN: 200,
    vm.OpCode.MAX: 200,
    vm.OpCode.WITHIN: 200,
    vm.OpCode.PACK: 7000,
    vm.OpCode.UNPACK: 7000,
    vm.OpCode.NEWARRAY0: 400,
    vm.OpCode.NEWARRAY: 15000,
    vm.OpCode.NEWARRAY_T: 15000,
    vm.OpCode.NEWSTRUCT0: 400,
    vm.OpCode.NEWSTRUCT: 15000,
    vm.OpCode.NEWMAP: 200,
    vm.OpCode.SIZE: 150,
    vm.OpCode.HASKEY: 270000,
    vm.OpCode.KEYS: 500,
    vm.OpCode.VALUES: 7000,
    vm.OpCode.PICKITEM: 270000,
    vm.OpCode.APPEND: 15000,
    vm.OpCode.SETITEM: 270000,
    vm.OpCode.REVERSEITEMS: 500,
    vm.OpCode.REMOVE: 500,
    vm.OpCode.CLEARITEMS: 400,
    vm.OpCode.ISNULL: 60,
    vm.OpCode.ISTYPE: 60,
    vm.OpCode.CONVERT: 80000,
}
