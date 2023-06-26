"""
NEO Virtual Machine classes.
"""
from __future__ import annotations
import hashlib
from enum import IntEnum
from neo3.contracts import callflags
from neo3.core import types, serialization, cryptography
from typing import Optional, Iterator, Union, Type, Protocol
from collections.abc import Sequence


def _syscall_name_to_int(name: str) -> int:
    return int.from_bytes(
        hashlib.sha256(name.encode()).digest()[:4], "little", signed=False
    )


class OpCode(IntEnum):
    """
    NEO Virtual Machine instructions.

    Can be concatenated into a hex-escaped bytes sequence.

    Example:
        In [1]: from neo3.contracts import vm

        In [2]: script = vm.OpCode.PUSHDATA1 + b'\x01' + vm.OpCode.RET

        In [3]: script
        Out[3]: b'\x0c\x01@'
    """

    PUSHINT8 = 0x00
    PUSHINT16 = 0x01
    PUSHINT32 = 0x02
    PUSHINT64 = 0x03
    PUSHINT128 = 0x04
    PUSHINT256 = 0x05
    PUSHT = 0x08
    PUSHF = 0x09
    PUSHA = 0x0A
    PUSHNULL = 0x0B
    PUSHDATA1 = 0x0C
    PUSHDATA2 = 0x0D
    PUSHDATA4 = 0x0E
    PUSHM1 = 0x0F
    PUSH0 = 0x10
    PUSH1 = 0x11
    PUSH2 = 0x12
    PUSH3 = 0x13
    PUSH4 = 0x14
    PUSH5 = 0x15
    PUSH6 = 0x16
    PUSH7 = 0x17
    PUSH8 = 0x18
    PUSH9 = 0x19
    PUSH10 = 0x1A
    PUSH11 = 0x1B
    PUSH12 = 0x1C
    PUSH13 = 0x1D
    PUSH14 = 0x1E
    PUSH15 = 0x1F
    PUSH16 = 0x20
    NOP = 0x21
    JMP = 0x22
    JMP_L = 0x23
    JMPIF = 0x24
    JMPIF_L = 0x25
    JMPIFNOT = 0x26
    JMPIFNOT_L = 0x27
    JMPEQ = 0x28
    JMPEQ_L = 0x29
    JMPNE = 0x2A
    JMPNE_L = 0x2B
    JMPGT = 0x2C
    JMPGT_L = 0x2D
    JMPGE = 0x2E
    JMPGE_L = 0x2F
    JMPLT = 0x30
    JMPLT_L = 0x31
    JMPLE = 0x32
    JMPLE_L = 0x33
    CALL = 0x34
    CALL_L = 0x35
    CALLA = 0x36
    CALLT = 0x37
    ABORT = 0x38
    ASSERT = 0x39
    THROW = 0x3A
    TRY = 0x3B
    TRY_L = 0x3C
    ENDTRY = 0x3D
    ENDTRY_L = 0x3E
    ENDFINALLY = 0x3F
    RET = 0x40
    SYSCALL = 0x41
    DEPTH = 0x43
    DROP = 0x45
    NIP = 0x46
    XDROP = 0x48
    CLEAR = 0x49
    DUP = 0x4A
    OVER = 0x4B
    PICK = 0x4D
    TUCK = 0x4E
    SWAP = 0x50
    ROT = 0x51
    ROLL = 0x52
    REVERSE3 = 0x53
    REVERSE4 = 0x54
    REVERSEN = 0x55
    INITSSLOT = 0x56
    INITSLOT = 0x57
    LDSFLD0 = 0x58
    LDSFLD1 = 0x59
    LDSFLD2 = 0x5A
    LDSFLD3 = 0x5B
    LDSFLD4 = 0x5C
    LDSFLD5 = 0x5D
    LDSFLD6 = 0x5E
    LDSFLD = 0x5F
    STSFLD0 = 0x60
    STSFLD1 = 0x61
    STSFLD2 = 0x62
    STSFLD3 = 0x63
    STSFLD4 = 0x64
    STSFLD5 = 0x65
    STSFLD6 = 0x66
    STSFLD = 0x67
    LDLOC0 = 0x68
    LDLOC1 = 0x69
    LDLOC2 = 0x6A
    LDLOC3 = 0x6B
    LDLOC4 = 0x6C
    LDLOC5 = 0x6D
    LDLOC6 = 0x6E
    LDLOC = 0x6F
    STLOC0 = 0x70
    STLOC1 = 0x71
    STLOC2 = 0x72
    STLOC3 = 0x73
    STLOC4 = 0x74
    STLOC5 = 0x75
    STLOC6 = 0x76
    STLOC = 0x77
    LDARG0 = 0x78
    LDARG1 = 0x79
    LDARG2 = 0x7A
    LDARG3 = 0x7B
    LDARG4 = 0x7C
    LDARG5 = 0x7D
    LDARG6 = 0x7E
    LDARG = 0x7F
    STARG0 = 0x80
    STARG1 = 0x81
    STARG2 = 0x82
    STARG3 = 0x83
    STARG4 = 0x84
    STARG5 = 0x85
    STARG6 = 0x86
    STARG = 0x87
    NEWBUFFER = 0x88
    MEMCPY = 0x89
    CAT = 0x8B
    SUBSTR = 0x8C
    LEFT = 0x8D
    RIGHT = 0x8E
    INVERT = 0x90
    AND = 0x91
    OR = 0x92
    XOR = 0x93
    EQUAL = 0x97
    NOTEQUAL = 0x98
    SIGN = 0x99
    ABS = 0x9A
    NEGATE = 0x9B
    INC = 0x9C
    DEC = 0x9D
    ADD = 0x9E
    SUB = 0x9F
    MUL = 0xA0
    DIV = 0xA1
    MOD = 0xA2
    POW = 0xA3
    SQRT = 0xA4
    MODMUL = 0xA5
    MODPOW = 0xA6
    SHL = 0xA8
    SHR = 0xA9
    NOT = 0xAA
    BOOLAND = 0xAB
    BOOLOR = 0xAC
    NZ = 0xB1
    NUMEQUAL = 0xB3
    NUMNOTEQUAL = 0xB4
    LT = 0xB5
    LE = 0xB6
    GT = 0xB7
    GE = 0xB8
    MIN = 0xB9
    MAX = 0xBA
    WITHIN = 0xBB
    PACKMAP = 0xBE
    PACKSTRUCT = 0xBF
    PACK = 0xC0
    UNPACK = 0xC1
    NEWARRAY0 = 0xC2
    NEWARRAY = 0xC3
    NEWARRAY_T = 0xC4
    NEWSTRUCT0 = 0xC5
    NEWSTRUCT = 0xC6
    NEWMAP = 0xC8
    SIZE = 0xCA
    HASKEY = 0xCB
    KEYS = 0xCC
    VALUES = 0xCD
    PICKITEM = 0xCE
    APPEND = 0xCF
    SETITEM = 0xD0
    REVERSEITEMS = 0xD1
    REMOVE = 0xD2
    CLEARITEMS = 0xD3
    POPITEM = 0xD4
    ISNULL = 0xD8
    ISTYPE = 0xD9
    CONVERT = 0xDB

    def __eq__(self, other):
        if super(OpCode, self).__eq__(other) is True:
            return True
        if isinstance(other, bytes):
            return self.value.to_bytes(1, "little") == other
        return False

    def __add__(self, other):
        if isinstance(other, bytes):
            return self.value.to_bytes(1, "little") + other
        elif isinstance(other, OpCode):
            return self.value.to_bytes(1, "little") + other.to_bytes(1, "little")
        else:
            return super(OpCode, self).__add__(other)

    def __radd__(self, other):
        if isinstance(other, bytes):
            return other + self.value.to_bytes(1, "little")
        elif isinstance(other, OpCode):
            return other.to_bytes(1, "little") + self.value.to_bytes(1, "little")
        else:
            return super(OpCode, self).__radd__(other)


ContractParameter = Union[
    bool,
    int,
    str,
    bytes,
    bytearray,
    types.BigInteger,
    types.UInt160,
    types.UInt256,
    cryptography.ECPoint,
    "ContractParameterArray",
    "ContractParameterDict",
    Type[serialization.ISerializable_T],
]


class ContractParameterArray(Protocol):
    """"""

    def insert(self, index: int, value: ContractParameter) -> None:
        ...

    def __getitem__(self, i: int) -> ContractParameter:
        ...

    def __setitem__(self, i: int, o: ContractParameter) -> None:
        ...

    def __delitem__(self, i: int) -> None:
        ...


class ContractParameterDict(Protocol):
    """"""

    def __setitem__(self, k: ContractParameter, v: ContractParameter) -> None:
        ...

    def __delitem__(self, v: ContractParameter) -> None:
        ...

    def __getitem__(self, k: ContractParameter) -> ContractParameter:
        ...

    def __iter__(self) -> Iterator[ContractParameter]:
        ...


class ScriptBuilder:
    """
    A utility class to create scripts (sequence of opcodes) that can be executed by the
    NEO Virtual Machine.
    """

    def __init__(self):
        self.data = bytearray()

    def emit(self, opcode: OpCode, data: Optional[bytes] = None) -> ScriptBuilder:
        self.emit_raw(opcode.value.to_bytes(1, "little"))
        if data is not None:
            self.emit_raw(data)
        return self

    def emit_push(self, value) -> ScriptBuilder:
        if value is None:
            return self.emit(OpCode.PUSHNULL)
        elif isinstance(value, bool):
            if value is True:
                return self.emit(OpCode.PUSHT)
            else:
                return self.emit(OpCode.PUSHF)
        elif isinstance(value, str):
            self.emit_push(value.encode("utf-8"))
            return self
        elif isinstance(value, serialization.ISerializable):
            return self.emit_push(value.to_array())
        elif isinstance(value, IntEnum):
            return self.emit_push(value.value)
        elif isinstance(value, (types.BigInteger, int)):
            if -1 <= value <= 16:
                self.emit_raw((OpCode.PUSH0 + value).to_bytes(1, "little"))
                return self
            else:
                if isinstance(value, int):
                    bigint = types.BigInteger(value)
                else:
                    bigint = value
                data = bytearray(bigint.to_array())
                if len(data) == 1:
                    return self.emit(OpCode.PUSHINT8, data)
                if len(data) == 2:
                    return self.emit(OpCode.PUSHINT16, data)
                if len(data) <= 4:
                    self._pad_right(data, 4, bigint.sign < 0)
                    return self.emit(OpCode.PUSHINT32, data)
                if len(data) <= 8:
                    self._pad_right(data, 8, bigint.sign < 0)
                    return self.emit(OpCode.PUSHINT64, data)
                if len(data) <= 16:
                    self._pad_right(data, 16, bigint.sign < 0)
                    return self.emit(OpCode.PUSHINT128, data)
                if len(data) <= 32:
                    self._pad_right(data, 32, bigint.sign < 0)
                    return self.emit(OpCode.PUSHINT256, data)
                raise ValueError("Input number exceeds maximum data size of 32 bytes")
        elif isinstance(value, (bytes, bytearray)):
            len_value = len(value)
            if len_value == 0:
                raise ValueError("Cannot push zero sized data")
            if len_value > 0xFFFFFFFF:
                raise ValueError(
                    f"Value is too long {len_value}. Maximum allowed length is 0xFFFF_FFFF"
                )

            if len_value < 0x100:
                self.emit(OpCode.PUSHDATA1)
                self.emit_raw(len_value.to_bytes(1, "little"))
                self.emit_raw(value)
            elif len_value < 0x10000:
                self.emit(OpCode.PUSHDATA2)
                self.emit_raw((len_value & 0xFF).to_bytes(1, "little"))
                self.emit_raw(((len_value >> 8) & 0xFF).to_bytes(1, "little"))
                self.emit_raw(value)
            else:
                self.emit(OpCode.PUSHDATA4)
                self.emit_raw(len_value.to_bytes(4, "little"))
                self.emit_raw(value)
            return self
        elif isinstance(value, Sequence):
            for item in reversed(value):
                if isinstance(item, Sequence):
                    self.emit_push(item)
                    continue
                self.emit_push(item)
            self.emit_push(len(value))
            self.emit(OpCode.PACK)
            return self
        elif isinstance(value, dict):
            for k, v in value.items():
                # This restriction exists on the VM side where keys to a 'Map' may only be of 'PrimitiveType'
                if not isinstance(k, (int, str, bool)):
                    raise ValueError(
                        f"Unsupported key type {type(k)}. Supported types by the VM are bool, int and str"
                    )
                self.emit_push(v)
                self.emit_push(k)
            self.emit_push(len(value))
            return self.emit(OpCode.PACKMAP)
        else:
            raise ValueError(f"Unsupported value type {type(value)}")

    def emit_raw(self, data: bytes) -> ScriptBuilder:
        self.data.extend(data)
        return self

    def emit_jump(self, opcode: OpCode, offset: int) -> ScriptBuilder:
        if opcode < OpCode.JMP or opcode > OpCode.JMPLE_L:
            raise ValueError(f"OpCode {opcode.name} is not a valid jump OpCode")

        # auto correct opcode
        if opcode % 2 == 0 and (offset < -128 or offset > 127):
            opcode = OpCode(opcode + 1)

        if opcode % 2 == 0:
            return self.emit(opcode, offset.to_bytes(1, "little", signed=True))
        else:
            return self.emit(opcode, offset.to_bytes(4, "little", signed=True))

    def emit_call(self, offset: int) -> ScriptBuilder:
        if offset < -128 or offset > 127:
            return self.emit(OpCode.CALL_L, offset.to_bytes(4, "little"))
        else:
            return self.emit(OpCode.CALL, offset.to_bytes(1, "little"))

    def emit_syscall(self, syscall: int | Syscall):
        if isinstance(syscall, Syscall):
            syscall = syscall.number

        return self.emit(OpCode.SYSCALL, syscall.to_bytes(4, "little"))

    def emit_contract_call(
        self,
        script_hash: types.UInt160,
        operation: str,
        call_flags: Optional[callflags.CallFlags] = None,
    ) -> ScriptBuilder:
        """
        Emit opcode sequence to call a smart contrat operation.

        Args:
            script_hash: contract script hash.
            operation: method to call on contract.
            call_flags: call flags for the operation.
        """
        self.emit(OpCode.NEWARRAY0)
        self.emit_push(callflags.CallFlags.ALL if call_flags is None else call_flags)
        self.emit_push(operation)
        self.emit_push(script_hash)
        self.emit_syscall(Syscalls.SYSTEM_CONTRACT_CALL)
        return self

    def emit_contract_call_with_args(
        self,
        script_hash: types.UInt160,
        operation: str,
        args: ContractParameter,
        call_flags: Optional[callflags.CallFlags] = None,
    ) -> ScriptBuilder:
        """
        Emit opcode sequence to call a smart contrat operation with arguments.

        Args:
            script_hash: contract script hash.
            operation: method to call on contract.
            args: parameters to pass to the `operation`.
            call_flags: call flags for the operation.
        """
        if isinstance(args, Sequence):
            for arg in reversed(args):
                self.emit_push(arg)
            self.emit_push(len(args))
            self.emit(OpCode.PACK)
        else:
            self.emit_push(args)
        self.emit_push(callflags.CallFlags.ALL if call_flags is None else call_flags)
        self.emit_push(operation)
        self.emit_push(script_hash)
        self.emit_syscall(Syscalls.SYSTEM_CONTRACT_CALL)
        return self

    def emit_contract_call_and_unwrap_iterator(
        self,
        script_hash,
        operation: str,
        call_flags: Optional[callflags.CallFlags] = None,
        unwrap_limit: int = 2000,
    ) -> ScriptBuilder:
        return self._emit_contract_call_and_unwrap_iterator(
            script_hash, operation, None, call_flags, unwrap_limit
        )

    def emit_contract_call_with_args_and_unwrap_iterator(
        self,
        script_hash,
        operation: str,
        args: ContractParameter,
        call_flags: Optional[callflags.CallFlags] = None,
    ) -> ScriptBuilder:
        return self._emit_contract_call_and_unwrap_iterator(
            script_hash, operation, args, call_flags
        )

    def to_array(self) -> bytes:
        return bytes(self.data)

    def _emit_contract_call_and_unwrap_iterator(
        self,
        script_hash,
        operation: str,
        args: Optional[ContractParameter] = None,
        call_flags: Optional[callflags.CallFlags] = None,
        unwrap_limit: int = 2000,
    ) -> ScriptBuilder:
        """

        Args:
            script_hash: contract hash to call
            operation: method name to call
            args: arguments passed to the method called
            call_flags: call flags of the method called
            unwrap_limit: maximum number of items to return. Can't be larger than the MaxStackSize limit configured for
            the VM or it will throw an exception.
            https://github.com/neo-project/neo-vm/blob/5b0a39811b34abacab1273f3ee5a9a9f7e52ac7b/src/Neo.VM/ExecutionEngineLimits.cs#L34C21-L34C33
            The current default is slightly lower than the max, because that allows for a few other items to be on the
            stack in other function frames.
        """
        # jump to local variables initialization code
        self.emit_jump(OpCode.JMP, 4)
        # the following 2 instructions are for loading the result array and exiting the script
        # it is at the beginning because it make it easy to calculate the offset
        return_results = len(self.data)
        self.emit(OpCode.LDLOC0)
        self.emit(OpCode.RET)
        # reserve 2 local variables for the `iterator` and `results` list
        self.emit(OpCode.INITSLOT)
        self.emit_raw(b"\x03")
        self.emit_raw(b"\x00")
        # store results list in pos 0
        self.emit(OpCode.NEWARRAY0)
        self.emit(OpCode.STLOC0)

        if args is None or (isinstance(args, Sequence) and len(args) == 0):
            self.emit_contract_call(script_hash, operation, call_flags)
        else:
            self.emit_contract_call_with_args(script_hash, operation, args, call_flags)
        # store iterator in pos 1
        self.emit(OpCode.STLOC1)
        # store stack item counter in pos 2
        self.emit_push(0)
        self.emit(OpCode.STLOC2)
        """
        Next set of opcodes does the following

        while iterator.next()
          results.append(iterator.value)
          ctr += 1
          if ctr == stack_limit:
            break
        return results
        """
        loop_start = len(self.data)
        # load iterator as argument for iterator.next
        self.emit(OpCode.LDLOC1)
        # test if the iterator has a value
        self.emit_syscall(Syscalls.SYSTEM_ITERATOR_NEXT)
        # if not jump to exit routine
        self.emit_jump(OpCode.JMPIFNOT, self._offset_to(return_results))
        # load iterator as argument for iterator.value
        self.emit(OpCode.LDLOC1)
        # get result
        self.emit_syscall(Syscalls.SYSTEM_ITERATOR_VALUE)
        # load array
        self.emit(OpCode.LDLOC0)
        # fix argument order for APPEND
        self.emit(OpCode.SWAP)
        self.emit(OpCode.APPEND)
        # load stack item counter
        self.emit(OpCode.LDLOC2)
        self.emit(OpCode.INC)
        self.emit(OpCode.DUP)
        self.emit(OpCode.STLOC2)
        # load stack item limit
        self.emit_push(unwrap_limit)
        self.emit(OpCode.NUMEQUAL)
        self.emit_jump(OpCode.JMPIF, self._offset_to(return_results))
        # jump back to start of `while` loop
        self.emit_jump(OpCode.JMP, self._offset_to(loop_start))
        return self

    def _pad_right(self, data: bytearray, length: int, is_negative: bool):
        if len(data) >= length:
            return
        pad = b"\xFF" if is_negative else b"\x00"
        while len(data) != length:
            data.extend(pad)

    def _offset_to(self, absolute_position: int):
        return absolute_position - len(self.data)


class VMState(IntEnum):
    NONE = 0
    HALT = 1 << 0
    FAULT = 1 << 1
    BREAK = 1 << 2

    @staticmethod
    def from_string(value: str) -> VMState:
        match value:
            case "NONE":
                return VMState.NONE
            case "HALT":
                return VMState.HALT
            case "FAULT":
                return VMState.FAULT
            case "BREAK":
                return VMState.BREAK
            case _:
                raise ValueError(f"{value} cannot be converted to VMState")


class Syscall:
    def __init__(self, syscall_name: str, required_callflags: callflags.CallFlags):
        self.name = syscall_name
        self.number = _syscall_name_to_int(self.name)
        self.required_callflags = required_callflags

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.number}, {self.name}>"

    def __eq__(self, other):
        if type(other) == int:
            return self.number == other
        if type(other) == str:
            return self.name == other
        if type(other) == type(self):
            return self.name == other.name and self.number == other.number
        if type(other) in (bytes, bytearray):
            return self.to_array() == other
        else:
            return False

    def to_array(self) -> bytes:
        return self.number.to_bytes(4, "little")


class Syscalls:
    """
    Container holding all NEO blockchain interop syscalls.
    """

    #: Call another smart contract.
    SYSTEM_CONTRACT_CALL = Syscall(
        "System.Contract.Call",
        callflags.CallFlags.READ_STATES | callflags.CallFlags.ALLOW_CALL,
    )
    #: Internal use only. Added for completeness.
    SYSTEM_CONTRACT_CALL_NATIVE = Syscall(
        "System.Contract.CallNative", callflags.CallFlags.NONE
    )
    #: Get the call flags for the current execution context text.
    SYSTEM_CONTRACT_GET_CALL_FLAGS = Syscall(
        "System.Contract.GetCallFlags", callflags.CallFlags.NONE
    )
    #: Get the (contract) account scripthash for the given public key.
    SYSTEM_CONTRACT_CREATE_STANDARD_ACCOUNT = Syscall(
        "System.Contract.CreateStandardAccount", callflags.CallFlags.NONE
    )
    #: Get the (multisignature contract) account scripthash for the given public key(s).
    SYSTEM_CONTRACT_CREATE_MULTI_SIGNATURE_ACCOUNT = Syscall(
        "System.Contract.CreateMultisigAccount", callflags.CallFlags.NONE
    )
    #: Internal use only. Added for completeness.
    SYSTEM_CONTRACT_NATIVE_ON_PERSIST = Syscall(
        "System.Contract.NativeOnPersist", callflags.CallFlags.STATES
    )
    #: Internal use only. Added for completeness.
    SYSTEM_CONTRACT_NATIVE_POST_PERSIST = Syscall(
        "System.Contract.NativePostPersist", callflags.CallFlags.STATES
    )

    #: Validates the signature of the current script container (usually a transaction).
    SYSTEM_CRYPTO_CHECK_STANDARD_ACCOUNT = Syscall(
        "System.Crypto.CheckSig", callflags.CallFlags.NONE
    )
    #: Validates the signatures of the current script container (usually a transaction).
    SYSTEM_CRYPTO_CHECK_MULTI_SIGNATURE_ACCOUNT = Syscall(
        "System.Crypto.CheckMultisig", callflags.CallFlags.NONE
    )

    #: Advance the iterator to the next element of the collection. See also SYSTEM_STORAGE_FIND.
    SYSTEM_ITERATOR_NEXT = Syscall("System.Iterator.Next", callflags.CallFlags.NONE)
    #: Get the element in the collection at the current position of the iterator. See also SYSTEM_STORAGE_FIND.
    SYSTEM_ITERATOR_VALUE = Syscall("System.Iterator.Value", callflags.CallFlags.NONE)

    #: Get the name of the current platform. For NEO blockchain fixed to "NEO".
    SYSTEM_RUNTIME_PLATFORM = Syscall(
        "System.Runtime.Platform", callflags.CallFlags.NONE
    )
    #: Get the network magic number.
    SYSTEM_RUNTIME_GET_NETWORK = Syscall(
        "System.Runtime.GetNetwork", callflags.CallFlags.NONE
    )
    #: Get the address version.
    SYSTEM_RUNTIME_GET_ADDRESS_VERSION = Syscall(
        "System.Runtime.GetAddressVersion", callflags.CallFlags.NONE
    )
    #: Get the trigger type used in the engine for the current execution.
    SYSTEM_RUNTIME_GET_TRIGGER = Syscall(
        "System.Runtime.GetTrigger", callflags.CallFlags.NONE
    )
    #: Get the timestamp of the block currently being persisted.
    SYSTEM_RUNTIME_GET_TIME = Syscall(
        "System.Runtime.GetTime", callflags.CallFlags.NONE
    )
    #: Get the script container of the current execution (usually the transaction).
    SYSTEM_RUNTIME_GET_SCRIPT_CONTAINER = Syscall(
        "System.Runtime.GetScriptContainer", callflags.CallFlags.NONE
    )
    #: Get the script hash of the current execution context.
    SYSTEM_RUNTIME_GET_EXECUTING_SCRIPT_HASH = Syscall(
        "System.Runtime.GetExecutingScriptHash", callflags.CallFlags.NONE
    )
    #: Get the script hash of the calling contract.
    SYSTEM_RUNTIME_GET_CALLING_SCRIPT_HASH = Syscall(
        "System.Runtime.GetCallingScriptHash", callflags.CallFlags.NONE
    )
    #: Get the script hash of the first execution context script. For a transaction this equals to `Transaction.script`.
    SYSTEM_RUNTIME_GET_ENTRY_SCRIPT_HASH = Syscall(
        "System.Runtime.GetEntryScriptHash", callflags.CallFlags.NONE
    )
    #: Validate whether the specified account has witnessed the current transaction.
    SYSTEM_RUNTIME_CHECK_WITNESS = Syscall(
        "System.Runtime.CheckWitness", callflags.CallFlags.NONE
    )
    #: Get the number of times the current contract has been called during the execution.
    SYSTEM_RUNTIME_GET_INVOCATION_COUNTER = Syscall(
        "System.Runtime.GetInvocationCounter", callflags.CallFlags.NONE
    )
    #: Get a random number.
    SYSTEM_RUNTIME_GET_RANDOM = Syscall(
        "System.Runtime.GetRandom", callflags.CallFlags.NONE
    )
    #: Write a log message.
    SYSTEM_RUNTIME_LOG = Syscall("System.Runtime.Log", callflags.CallFlags.ALLOW_NOTIFY)
    #: Send a notification.
    SYSTEM_RUNTIME_NOTIFY = Syscall(
        "System.Runtime.Notify", callflags.CallFlags.ALLOW_NOTIFY
    )
    #: Get the list of notifications sent by the specified contract during the execution.
    SYSTEM_RUNTIME_GET_NOTIFICATIONS = Syscall(
        "System.Runtime.GetNotifications", callflags.CallFlags.NONE
    )
    #: Get the remaining GAS that can be spent in order to complete the execution.
    SYSTEM_RUNTIME_GAS_LEFT = Syscall(
        "System.Runtime.GasLeft", callflags.CallFlags.NONE
    )
    #: Burns gas.
    SYSTEM_RUNTIME_BURN_GAS = Syscall(
        "System.Runtime.BurnGas", callflags.CallFlags.NONE
    )

    #: Get the storage context for the current contract.
    SYSTEM_STORAGE_GET_CONTEXT = Syscall(
        "System.Storage.GetContext", callflags.CallFlags.READ_STATES
    )
    #: Get the storage context for the current contract as read-only.
    SYSTEM_STORAGE_GET_READ_ONLY_CONTEXT = Syscall(
        "System.Storage.GetReadOnlyContext", callflags.CallFlags.READ_STATES
    )
    #: Convert the existing context to a new read-only context.
    SYSTEM_STORAGE_AS_READ_ONLY = Syscall(
        "System.Storage.AsReadOnly", callflags.CallFlags.READ_STATES
    )
    #: Get an entry from storage by a specified key.
    SYSTEM_STORAGE_GET = Syscall("System.Storage.Get", callflags.CallFlags.READ_STATES)
    #: Find entries from storage by a given a search prefix and search options.
    SYSTEM_STORAGE_FIND = Syscall(
        "System.Storage.Find", callflags.CallFlags.READ_STATES
    )
    #: Persist an entry to storage under a specified key.
    SYSTEM_STORAGE_PUT = Syscall("System.Storage.Put", callflags.CallFlags.WRITE_STATES)
    #: Delete an entry from storage under a specified key.
    SYSTEM_STORAGE_DELETE = Syscall(
        "System.Storage.Delete", callflags.CallFlags.WRITE_STATES
    )

    @classmethod
    def all(cls) -> Iterator[Syscall]:
        for name, value in vars(cls).items():
            if name.isupper():
                yield value

    @classmethod
    def get_by_number(cls, syscall_number: int) -> Optional[Syscall]:
        for name, value in vars(cls).items():
            if name.isupper() and value.number == syscall_number:
                return value
        else:
            return None

    @classmethod
    def get_by_name(cls, syscall_name: str) -> Optional[Syscall]:
        for name, value in vars(cls).items():
            if name.isupper() and value.name == syscall_name:
                return value
        else:
            return None
