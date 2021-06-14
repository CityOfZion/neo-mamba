from __future__ import annotations
from neo3 import contracts, storage, vm
from neo3.network import payloads
from neo3.core import types, cryptography, IInteroperable, serialization, to_script_hash
from typing import Any, Dict, cast, List, Tuple, Type, Optional, Union
import enum
from contextlib import suppress


class ApplicationEngine(vm.ApplicationEngineCpp):
    #: Amount of free GAS added to the engine.
    GAS_FREE = 0
    #: Maximum length of event names for "System.Runtime.Notify" SYSCALLs.
    MAX_EVENT_SIZE = 32
    #: Maximum messasge length for "System.Runtime.Log" SYSCALLs.
    MAX_NOTIFICATION_SIZE = 1024
    #: Maximum size of the smart contract script.
    MAX_CONTRACT_LENGTH = 1024 * 1024

    def __init__(self,
                 trigger: contracts.TriggerType,
                 container: payloads.IVerifiable,
                 snapshot: storage.Snapshot,
                 gas: int,
                 test_mode: bool = False
                 ):
        # Do not use super() version, see
        # https://pybind11.readthedocs.io/en/master/advanced/classes.html#overriding-virtual-functions-in-python
        vm.ApplicationEngineCpp.__init__(self, test_mode)
        #: A ledger snapshot to use for syscalls such as "System.Blockchain.GetHeight".
        self.snapshot = snapshot
        #: The trigger to run the engine with.
        self.trigger = trigger
        #: A flag to toggle infinite gas
        self.is_test_mode = test_mode

        self.script_container = container
        #: Gas available for consumption by the engine while executing its script.
        self.gas_amount = self.GAS_FREE + gas
        self._invocation_counter: Dict[types.UInt160, int] = {}
        #: Notifications (Notify SYSCALLs) that occured while executing the script.
        self.notifications: List[Tuple[payloads.IVerifiable, types.UInt160, bytes, vm.ArrayStackItem]] = []
        if self.snapshot is None or self.snapshot.persisting_block is None or self.snapshot.persisting_block.index == 0:
            self.exec_fee_factor = contracts.PolicyContract().DEFAULT_EXEC_FEE_FACTOR
            self.STORAGE_PRICE = contracts.PolicyContract().DEFAULT_STORAGE_PRICE
        else:
            self.exec_fee_factor = contracts.PolicyContract().get_exec_fee_factor(snapshot)
            self.STORAGE_PRICE = contracts.PolicyContract().get_storage_price(snapshot)

        from neo3.contracts import interop
        self.interop = interop

    @property
    def current_scripthash(self) -> types.UInt160:
        """
        Get the script hash of the current executing smart contract

        Note: a smart contract can call other smart contracts.
        """
        if len(self.current_context.scripthash_bytes) == 0:
            return to_script_hash(self.current_context.script._value)
        return types.UInt160(self.current_context.scripthash_bytes)

    @property
    def calling_scripthash(self) -> types.UInt160:
        """
        Get the script hash of the smart contract that called the current executing smart contract.

        Note: a smart contract can call other smart contracts.

        Raises:
            ValueError: if the current executing contract has not been called by another contract.
        """
        if len(self.current_context.calling_scripthash_bytes) == 0:
            raise ValueError("Cannot retrieve calling script_hash - current context has not yet been called")
        return types.UInt160(self.current_context.calling_scripthash_bytes)

    @property
    def entry_scripthash(self) -> types.UInt160:
        """
        Get the script hash of the first smart contract loaded into the engine

        Note: a smart contract can call other smart contracts.
        """
        if len(self.entry_context.scripthash_bytes) == 0:
            return to_script_hash(self.entry_context.script._value)
        return types.UInt160(self.entry_context.scripthash_bytes)

    def checkwitness(self, hash_: types.UInt160) -> bool:
        """
        Check if the hash is a valid witness for the engines script_container
        """
        with suppress(ValueError):
            if hash_ == self.calling_scripthash:
                return True

        if isinstance(self.script_container, payloads.Transaction):
            tx = self.script_container

            response = tx.try_get_attribute(payloads.OracleResponse)
            if response is None:
                signers = tx.signers
            else:
                signers = []
                request = contracts.OracleContract().get_request(self.snapshot, response.id)
                if request:
                    tmp_tx = contracts.LedgerContract().get_tx_for_contract(self.snapshot, request.original_tx_id)
                    if tmp_tx:
                        signers = tmp_tx.signers

            for s in signers:
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
                self._validate_callflags(contracts.CallFlags.READ_STATES)

                contract = contracts.ManagementContract().get_contract(self.snapshot, self.calling_scripthash)
                if contract is None:
                    return False
                group_keys = set(map(lambda g: g.public_key, contract.manifest.groups))
                if any(group_keys.intersection(signer.allowed_groups)):
                    return True
            return False

        self._validate_callflags(contracts.CallFlags.READ_STATES)

        # for other IVerifiable types like Block
        hashes_for_verifying = self.script_container.get_script_hashes_for_verifying(self.snapshot)
        return hash_ in hashes_for_verifying

    def call_from_native(self,
                         calling_scripthash: types.UInt160,
                         hash_: types.UInt160,
                         method: str,
                         args: List[vm.StackItem]) -> None:
        ctx = self.current_context
        self._contract_call_internal(hash_, method, contracts.CallFlags.ALL, False, args)
        self.current_context.calling_scripthash_bytes = calling_scripthash.to_array()
        while self.current_context != ctx:
            self.step_out()

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
        descriptor = self.interop.InteropService.get_descriptor(method_id)
        if descriptor is None:
            raise KeyError(f"Requested interop {method_id} is not valid")

        self._validate_callflags(descriptor.required_call_flags)
        self.add_gas(descriptor.price * self.exec_fee_factor)

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

    def get_invocation_counter(self) -> int:
        """
        Get the number of times the current contract has been called during this execute() run.

        Note: the counter increases with every "System.Contract.Call" SYSCALL

        Raises:
            ValueError: if the contract has not been called.
        """
        counter = self._invocation_counter.get(self.current_scripthash, None)
        if counter is None:
            self._invocation_counter.update({self.current_scripthash: 1})
            counter = 1
        return counter

    def load_context(self, context: vm.ExecutionContext) -> None:
        if len(context.scripthash_bytes) == 0:
            context.scripthash_bytes = to_script_hash(context.script._value).to_array()
        contract_hash = types.UInt160(data=context.scripthash_bytes)
        counter = self._invocation_counter.get(contract_hash, 0)
        self._invocation_counter.update({contract_hash: counter + 1})

        super(ApplicationEngine, self).load_context(context)

    def load_contract(self,
                      contract: contracts.ContractState,
                      method_descriptor: contracts.ContractMethodDescriptor,
                      flags: contracts.CallFlags) -> Optional[vm.ExecutionContext]:

        rvcount = 0 if method_descriptor.return_type == contracts.ContractParameterType.VOID else 1
        context = self.load_script_with_callflags(vm.Script(contract.script),
                                                  flags,
                                                  method_descriptor.offset,
                                                  rvcount)
        # configure state
        context.call_flags = int(flags)
        context.scripthash_bytes = contract.hash.to_array()
        context.nef_bytes = contract.nef.to_array()

        init = contract.manifest.abi.get_method("_initialize", 0)
        if init is not None:
            self.load_context(context.clone(init.offset))
        return context

    def load_token(self, token_id: int) -> vm.ExecutionContext:
        self._validate_callflags(contracts.CallFlags.READ_STATES | contracts.CallFlags.ALLOW_CALL)
        if len(self.current_context.nef_bytes) == 0:
            raise ValueError("Current context has no NEF state")
        nef = contracts.NEF.deserialize_from_bytes(self.current_context.nef_bytes)
        if token_id >= len(nef.tokens):
            raise ValueError("token_id exceeds available tokens")

        token = nef.tokens[token_id]
        if token.parameters_count > len(self.current_context.evaluation_stack):
            raise ValueError("Token count exceeds available paremeters on evaluation stack")
        args: List[vm.StackItem] = []
        for _ in range(token.parameters_count):
            args.append(self.pop())
        return self._contract_call_internal(token.hash, token.method, token.call_flags, token.has_return_value, args)

    def load_script_with_callflags(self,
                                   script: vm.Script,
                                   call_flags: contracts.CallFlags,
                                   initial_position: int = 0,
                                   rvcount: int = -1):
        context = super(ApplicationEngine, self).load_script(script, rvcount, initial_position)
        context.call_flags = int(call_flags)
        return context

    def step_out(self) -> None:
        c = len(self.invocation_stack)
        while self.state != vm.VMState.HALT and self.state != vm.VMState.FAULT and len(self.invocation_stack) >= c:
            self._execute_next()
        if self.state == vm.VMState.FAULT:
            raise ValueError(f"Call from native contract failed: {self.exception_message}")

    def _contract_call_internal(self,
                                contract_hash: types.UInt160,
                                method: str,
                                flags: contracts.CallFlags,
                                has_return_value: bool,
                                args: List[vm.StackItem]) -> vm.ExecutionContext:
        target_contract = contracts.ManagementContract().get_contract(self.snapshot, contract_hash)
        if target_contract is None:
            raise ValueError("[System.Contract.Call] Can't find target contract")

        method_descriptor = target_contract.manifest.abi.get_method(method, len(args))
        if method_descriptor is None:
            raise ValueError(f"[System.Contract.Call] Method '{method}' with {len(args)} arguments does not exist on "
                             f"target contract")
        return self._contract_call_internal2(target_contract, method_descriptor, flags, has_return_value, args)

    def _contract_call_internal2(self,
                                 target_contract: contracts.ContractState,
                                 method_descriptor: contracts.ContractMethodDescriptor,
                                 flags: contracts.CallFlags,
                                 has_return_value: bool,
                                 args: List[vm.StackItem]):
        if method_descriptor.safe:
            flags &= ~(contracts.CallFlags.WRITE_STATES | contracts.CallFlags.ALLOW_NOTIFY)
        else:
            current_contract = contracts.ManagementContract().get_contract(self.snapshot, self.current_scripthash)
            if current_contract and not current_contract.can_call(target_contract, method_descriptor.name):
                raise ValueError(
                    f"[System.Contract.Call] Not allowed to call target method '{method_descriptor.name}' according "
                    f"to manifest")

        counter = self._invocation_counter.get(target_contract.hash, 0)
        self._invocation_counter.update({target_contract.hash: counter + 1})

        state = self.current_context
        calling_script_hash_bytes = state.scripthash_bytes
        calling_flags = state.call_flags

        arg_len = len(args)
        expected_len = len(method_descriptor.parameters)
        if arg_len != expected_len:
            raise ValueError(
                f"[System.Contract.Call] Invalid number of contract arguments. Expected {expected_len} actual {arg_len}")  # noqa

        if has_return_value ^ (method_descriptor.return_type != contracts.ContractParameterType.VOID):
            raise ValueError("Return value type does not match")

        context_new = self.load_contract(target_contract,
                                         method_descriptor,
                                         flags & calling_flags)
        if context_new is None:
            raise ValueError
        context_new.calling_scripthash_bytes = calling_script_hash_bytes

        for item in reversed(args):
            context_new.evaluation_stack.push(item)

        return context_new

    def _stackitem_to_native(self, stack_item: vm.StackItem, target_type: Type[object]):
        # checks for type annotations like `List[bytes]` (similar to byte[][] in C#)
        if hasattr(target_type, '__origin__'):
            if target_type.__origin__ == list:  # type: ignore
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
            if target_type.__origin__ == Union:  # type: ignore
                # handle typing.Optional[type], Optional is an alias for Union[x, None]
                # only support specifying 1 type
                if len(target_type.__args__) != 2:  # type: ignore
                    raise ValueError(f"Don't know how to convert {target_type}")
                if isinstance(stack_item, vm.NullStackItem):
                    return None
                else:
                    for i in target_type.__args__:  # type: ignore
                        if i is None:
                            continue
                        return self._convert(stack_item, i)
        else:
            try:
                return self._convert(stack_item, target_type)
            except ValueError:
                if isinstance(stack_item, vm.InteropStackItem):
                    return stack_item.get_object()
                else:
                    raise

    def _validate_callflags(self, callflags: contracts.CallFlags) -> None:
        if callflags not in contracts.CallFlags(self.current_context.call_flags):
            raise ValueError(f"Context requires callflags {callflags}")

    def _convert(self, stack_item: vm.StackItem, class_type: Type[object]) -> object:
        """
        convert VM type to native
        """
        if class_type in [vm.StackItem, vm.PointerStackItem, vm.ArrayStackItem, vm.InteropStackItem]:
            return stack_item
        elif class_type == int:
            return int(stack_item.to_biginteger())
        elif class_type == vm.BigInteger:
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
            if stack_item == vm.NullStackItem():
                return ""
            return stack_item.to_array().decode()
        elif class_type == cryptography.ECPoint:
            return cryptography.ECPoint.deserialize_from_bytes(stack_item.to_array())
        elif issubclass(class_type, enum.Enum):
            if stack_item.get_type() == vm.StackItemType.INTEGER:
                stack_item = cast(vm.IntegerStackItem, stack_item)
                # mypy seems to have trouble understanding types that support __int__
                return class_type(int(stack_item))  # type: ignore
            elif stack_item.get_type() == vm.StackItemType.BYTESTRING:
                stack_item = cast(vm.ByteStringStackItem, stack_item)
                return class_type(int(stack_item.to_biginteger()))  # type: ignore
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
        elif hasattr(native_type, '__origin__') and native_type.__origin__ == Union:  # type: ignore
            # handle typing.Optional[type], Optional is an alias for Union[x, None]
            # only support specifying 1 type
            if len(native_type.__args__) != 2:
                raise ValueError(f"Don't know how to convert native type {native_type} to stackitem")
            for i in native_type.__args__:
                if i is None:
                    continue
                return self._native_to_stackitem(value, native_type)
            else:
                raise ValueError  # shouldn't be possible, but silences mypy
        else:
            return vm.StackItem.from_interface(value)
