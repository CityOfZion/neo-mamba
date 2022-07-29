from __future__ import annotations
import hashlib
from pybiginteger import BigInteger
from enum import IntEnum
from neo3 import contracts
from neo3.core import types


def _syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)


class OpCode(IntEnum):
    PUSHINT8 = 0x00,
    PUSHINT16 = 0x01,
    PUSHINT32 = 0x02,
    PUSHINT64 = 0x03,
    PUSHINT128 = 0x04,
    PUSHINT256 = 0x05,
    PUSHA = 0x0A,
    PUSHNULL = 0x0B,
    PUSHDATA1 = 0x0C,
    PUSHDATA2 = 0x0D,
    PUSHDATA4 = 0x0E,
    PUSHM1 = 0x0F,
    PUSH0 = 0x10,
    PUSH1 = 0x11,
    PUSH2 = 0x12,
    PUSH3 = 0x13,
    PUSH4 = 0x14,
    PUSH5 = 0x15,
    PUSH6 = 0x16,
    PUSH7 = 0x17,
    PUSH8 = 0x18,
    PUSH9 = 0x19,
    PUSH10 = 0x1A,
    PUSH11 = 0x1B,
    PUSH12 = 0x1C,
    PUSH13 = 0x1D,
    PUSH14 = 0x1E,
    PUSH15 = 0x1F,
    PUSH16 = 0x20,
    NOP = 0x21,
    JMP = 0x22,
    JMP_L = 0x23,
    JMPIF = 0x24,
    JMPIF_L = 0x25,
    JMPIFNOT = 0x26,
    JMPIFNOT_L = 0x27,
    JMPEQ = 0x28,
    JMPEQ_L = 0x29,
    JMPNE = 0x2A,
    JMPNE_L = 0x2B,
    JMPGT = 0x2C,
    JMPGT_L = 0x2D,
    JMPGE = 0x2E,
    JMPGE_L = 0x2F,
    JMPLT = 0x30,
    JMPLT_L = 0x31,
    JMPLE = 0x32,
    JMPLE_L = 0x33,
    CALL = 0x34,
    CALL_L = 0x35,
    CALLA = 0x36,
    CALLT = 0x37,
    ABORT = 0x38,
    ASSERT = 0x39,
    THROW = 0x3A,
    TRY = 0x3B,
    TRY_L = 0x3C,
    ENDTRY = 0x3D,
    ENDTRY_L = 0x3E,
    ENDFINALLY = 0x3F,
    RET = 0x40,
    SYSCALL = 0x41,
    DEPTH = 0x43,
    DROP = 0x45,
    NIP = 0x46,
    XDROP = 0x48,
    CLEAR = 0x49,
    DUP = 0x4A,
    OVER = 0x4B,
    PICK = 0x4D,
    TUCK = 0x4E,
    SWAP = 0x50,
    ROT = 0x51,
    ROLL = 0x52,
    REVERSE3 = 0x53,
    REVERSE4 = 0x54,
    REVERSEN = 0x55,
    INITSSLOT = 0x56,
    INITSLOT = 0x57,
    LDSFLD0 = 0x58,
    LDSFLD1 = 0x59,
    LDSFLD2 = 0x5A,
    LDSFLD3 = 0x5B,
    LDSFLD4 = 0x5C,
    LDSFLD5 = 0x5D,
    LDSFLD6 = 0x5E,
    LDSFLD = 0x5F,
    STSFLD0 = 0x60,
    STSFLD1 = 0x61,
    STSFLD2 = 0x62,
    STSFLD3 = 0x63,
    STSFLD4 = 0x64,
    STSFLD5 = 0x65,
    STSFLD6 = 0x66,
    STSFLD = 0x67,
    LDLOC0 = 0x68,
    LDLOC1 = 0x69,
    LDLOC2 = 0x6A,
    LDLOC3 = 0x6B,
    LDLOC4 = 0x6C,
    LDLOC5 = 0x6D,
    LDLOC6 = 0x6E,
    LDLOC = 0x6F,
    STLOC0 = 0x70,
    STLOC1 = 0x71,
    STLOC2 = 0x72,
    STLOC3 = 0x73,
    STLOC4 = 0x74,
    STLOC5 = 0x75,
    STLOC6 = 0x76,
    STLOC = 0x77,
    LDARG0 = 0x78,
    LDARG1 = 0x79,
    LDARG2 = 0x7A,
    LDARG3 = 0x7B,
    LDARG4 = 0x7C,
    LDARG5 = 0x7D,
    LDARG6 = 0x7E,
    LDARG = 0x7F,
    STARG0 = 0x80,
    STARG1 = 0x81,
    STARG2 = 0x82,
    STARG3 = 0x83,
    STARG4 = 0x84,
    STARG5 = 0x85,
    STARG6 = 0x86,
    STARG = 0x87,
    NEWBUFFER = 0x88,
    MEMCPY = 0x89,
    CAT = 0x8B,
    SUBSTR = 0x8C,
    LEFT = 0x8D,
    RIGHT = 0x8E,
    INVERT = 0x90,
    AND = 0x91,
    OR = 0x92,
    XOR = 0x93,
    EQUAL = 0x97,
    NOTEQUAL = 0x98,
    SIGN = 0x99,
    ABS = 0x9A,
    NEGATE = 0x9B,
    INC = 0x9C,
    DEC = 0x9D,
    ADD = 0x9E,
    SUB = 0x9F,
    MUL = 0xA0,
    DIV = 0xA1,
    MOD = 0xA2,
    POW = 0xA3,
    SQRT = 0xA4,
    MODMUL = 0xA5,
    MODPOW = 0xA6,
    SHL = 0xA8,
    SHR = 0xA9,
    NOT = 0xAA,
    BOOLAND = 0xAB,
    BOOLOR = 0xAC,
    NZ = 0xB1,
    NUMEQUAL = 0xB3,
    NUMNOTEQUAL = 0xB4,
    LT = 0xB5,
    LE = 0xB6,
    GT = 0xB7,
    GE = 0xB8,
    MIN = 0xB9,
    MAX = 0xBA,
    WITHIN = 0xBB,
    PACKMAP = 0xBE,
    PACKSTRUCT = 0xBF,
    PACK = 0xC0,
    UNPACK = 0xC1,
    NEWARRAY0 = 0xC2,
    NEWARRAY = 0xC3,
    NEWARRAY_T = 0xC4,
    NEWSTRUCT0 = 0xC5,
    NEWSTRUCT = 0xC6,
    NEWMAP = 0xC8,
    SIZE = 0xCA,
    HASKEY = 0xCB,
    KEYS = 0xCC,
    VALUES = 0xCD,
    PICKITEM = 0xCE,
    APPEND = 0xCF,
    SETITEM = 0xD0,
    REVERSEITEMS = 0xD1,
    REMOVE = 0xD2,
    CLEARITEMS = 0xD3,
    POPITEM = 0xD4,
    ISNULL = 0xD8,
    ISTYPE = 0xD9,
    CONVERT = 0xDB,


class ScriptBuilder:
    # TODO:
    # * implement emit_call, emit_jump
    # * emit_syscall to support SysCalls type (to be added)
    # * test coverage

    def __init__(self):
        self.data = bytearray()

    def emit(self, opcode: OpCode, data: bytes = None) -> ScriptBuilder:
        self.emit_raw(opcode.value.to_bytes(1, "little"))
        if data is not None:
            self.emit_raw(data)
        return self

    def emit_push(self, value) -> ScriptBuilder:
        if value is None:
            return self.emit(OpCode.PUSHNULL)
        elif isinstance(value, bool):
            if value is True:
                return self.emit(OpCode.PUSH1)
            else:
                return self.emit(OpCode.PUSH0)
        elif isinstance(value, str):
            self.emit_push(value.encode('utf-8'))
            return self
        elif isinstance(value, (types.UInt160, types.UInt256)):
            return self.emit_push(value.to_array())
        elif isinstance(value, IntEnum):
            return self.emit_push(value.value)
        elif isinstance(value, (BigInteger, int)):
            if -1 <= value <= 16:
                self.emit_raw((OpCode.PUSH0.value + value).to_bytes(1, "little"))
                return self
            else:
                if isinstance(value, int):
                    bigint = BigInteger(value)
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
                raise ValueError(f"Value is too long {len_value}. Maximum allowed length is 0xFFFF_FFFF")

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

    def emit_raw(self, data: bytes) -> ScriptBuilder:
        self.data.extend(data)
        return self

    def emit_jump(self, opcode: OpCode, offset: int) -> ScriptBuilder:
        raise NotImplementedError

    def emit_call(self, offset: int) -> ScriptBuilder:
        raise NotImplementedError

    def emit_syscall(self, syscall_number: int):
        return self.emit(OpCode.SYSCALL, syscall_number.to_bytes(4, "little"))

    def emit_dynamic_call(self, script_hash: types.UInt160, operation: str) -> ScriptBuilder:
        self.emit(OpCode.NEWARRAY0)
        self.emit_push(contracts.CallFlags.ALL)  # CallFlags.ALL
        self.emit_push(operation)
        self.emit_push(script_hash)
        self.emit_syscall(_syscall_name_to_int("System.Contract.Call"))
        return self

    def emit_dynamic_call_with_args(self, script_hash, operation: str, args) -> ScriptBuilder:
        for arg in reversed(args):
            self.emit_push(arg)
        self.emit_push(len(args))
        self.emit(OpCode.PACK)
        self.emit_push(contracts.CallFlags.ALL)
        self.emit_push(operation)
        self.emit_push(script_hash)
        self.emit_syscall(_syscall_name_to_int("System.Contract.Call"))
        return self

    def _pad_right(self, data: bytearray, length: int, is_negative: bool):
        if len(data) >= length:
            return
        while len(data) != length:
            if is_negative:
                data.extend(b'\xFF')
            else:
                data.extend(b'\x00')

    def to_array(self) -> bytes:
        return bytes(self.data)


class VMState(IntEnum):
    NONE = 0
    HALT = 1 << 0
    FAULT = 1 << 1
    BREAK = 1 << 2