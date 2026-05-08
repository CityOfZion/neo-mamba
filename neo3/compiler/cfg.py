from __future__ import annotations
import dataclasses
import enum
from typing import Any, Literal, Optional

from .types import Type

# All valid StackInstr op values.  Includes direct NeoVM opcode names (CAPS),
# operator symbols mapped to opcodes (+, -, ==, …), lowercase semantic labels
# (cat, call, negate, …), and pseudo-ops expanded by the Linearizer to multiple
# opcodes (PUSH_INT, PUSH_BOOL, syscall, contract_call, notify, …).
StackOp = Literal[
    # Push pseudo-ops (Linearizer selects the right PUSHINT*/PUSHDATA* variant)
    "PUSH_INT",
    "PUSH_BOOL",
    "PUSH_STR",
    "PUSH_BYTES",
    "PUSHNULL",
    # Slot ops
    "LDARG",
    "LDLOC",
    "STLOC",
    "STARG",
    "LDSFLD",
    "STSFLD",
    # Arithmetic operators (symbol form, map to ADD/SUB/MUL/DIV/MOD/POW)
    "+",
    "-",
    "*",
    "//",
    "%",
    "**",
    # Bitwise operators
    "&",
    "|",
    "^",
    "<<",
    ">>",
    # Comparison operators
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    # Boolean ops (semantic labels)
    "booland",
    "boolor",
    # Unary ops (semantic labels)
    "not",
    "negate",
    "invert",
    "abs",
    "min",
    "max",
    # Function call (emits CALL_L with fixup)
    "call",
    # Bytes / string ops
    "cat",
    "NEWBUFFER",
    "SIZE",
    "CONVERT",
    "PICKITEM",
    "SUBSTR",
    "LEFT",
    "RIGHT",
    # Stack manipulation
    "DUP",
    "OVER",
    "SWAP",
    "SIGN",
    "REVERSEITEMS",
    # Collection ops
    "SETITEM",
    "NEWARRAY0",
    "NEWARRAY",
    "APPEND",
    "NEWMAP",
    "HASKEY",
    "KEYS",
    "VALUES",
    # Type checks
    "ISNULL",
    "ISTYPE",
    # Stack discard
    "DROP",
    # Exception / control
    "ASSERT",
    "ASSERTMSG",
    "THROW",
    "TRY_L",
    # Abort
    "ABORT",
    "ABORTMSG",
    # High-level syscall pseudo-ops (each expands to SYSCALL + operands)
    "syscall",
    "syscall_log",
    "contract_call",
    "notify",
]


@dataclasses.dataclass
class StackInstr:
    op: StackOp
    type: Optional[Type] = None
    operand: Optional[Any] = None


@dataclasses.dataclass
class Ret:
    pass


@dataclasses.dataclass
class Jump:
    target: str


@dataclasses.dataclass
class CondJump:
    true_target: str
    false_target: str


@dataclasses.dataclass
class EndTry:
    """Terminates try or catch body; emits ENDTRY_L."""

    end_label: str


@dataclasses.dataclass
class EndFinally:
    """Terminates finally body; emits ENDFINALLY."""

    pass


Terminator = Any  # Union[Ret, Jump, CondJump, EndTry, EndFinally]


@dataclasses.dataclass
class BasicBlock:
    label: str
    instructions: list[StackInstr] = dataclasses.field(default_factory=list)
    terminator: Optional[Terminator] = None


@dataclasses.dataclass
class CFG:
    entry: str
    blocks: dict[str, BasicBlock]

    def new_block(self, label: str) -> BasicBlock:
        bb = BasicBlock(label=label)
        self.blocks[label] = bb
        return bb


class OpCode(enum.IntEnum):
    # push
    PUSHINT8 = 0x00  # operand: 1 byte
    PUSHINT16 = 0x01  # operand: 2 bytes
    PUSHINT32 = 0x02  # operand: 4 bytes
    PUSHINT64 = 0x03  # operand: 8 bytes
    PUSHT = 0x08  # no operand (true)
    PUSHF = 0x09  # no operand (false)
    PUSHNULL = 0x0B  # no operand (null / None)
    # flow control — short (1-byte offset) and long (4-byte offset) variants
    # We always use _L variants so forward jumps never overflow
    JMP_L = 0x23  # operand: 4-byte signed offset from start of instruction
    JMPIF_L = 0x25  # pop bool; jump if true,  4-byte offset
    JMPIFNOT_L = 0x27  # pop bool; jump if false, 4-byte offset
    RET = 0x40  # no operand
    SYSCALL = 0x41  # operand: 4-byte interop method hash (little-endian)
    DROP = 0x45  # pop and discard top of stack
    # slots
    INITSSLOT = 0x56  # operand: 1 byte — initialize n static field slots
    INITSLOT = 0x57  # operand: 2 bytes (locals, args)
    LDSFLD = 0x5F  # operand: 1-byte slot index — load static field
    STSFLD = 0x67  # operand: 1-byte slot index — store static field
    LDLOC = 0x6F  # operand: 1-byte index
    STLOC = 0x77  # operand: 1-byte index
    LDARG = 0x7F  # operand: 1-byte index
    STARG = 0x87  # operand: 1-byte index
    # arithmetic
    INVERT = 0x90
    ABS = 0x9A
    NEGATE = 0x9B
    ADD = 0x9E
    SUB = 0x9F
    MUL = 0xA0
    DIV = 0xA1
    MOD = 0xA2
    POW = 0xA3
    SHL = 0xA8
    SHR = 0xA9
    AND = 0x91
    OR = 0x92
    XOR = 0x93
    MIN = 0xB9
    MAX = 0xBA
    # comparison (produce bool)
    EQUAL = 0x97
    NOTEQUAL = 0x98
    LT = 0xB5
    LE = 0xB6
    GT = 0xB7
    GE = 0xB8
    NOT = 0xAA
    ASSERT = 0x39  # pop bool; fault if false
    THROW = 0x3A  # pop msg; throw exception with message
    TRY_L = 0x3C  # 8-byte operand: two 4-byte signed offsets (catch, finally) from TRY_L start; 0=absent
    ENDTRY_L = 0x3E  # 4-byte operand: signed offset from ENDTRY_L start to end code
    ENDFINALLY = 0x3F  # no operand; jumps to EndPointer or rethrows
    ASSERTMSG = 0xE1  # pop msg (top), pop bool; fault with msg if false
    CALL_L = 0x35
    BOOLAND = 0xAB
    BOOLOR = 0xAC
    CAT = 0x8B  # concatenate two byte sequences → ByteString
    SUBSTR = 0x8C  # pop count, index, ByteString → push ByteString
    LEFT = 0x8D  # pop count, ByteString → push first N bytes as ByteString
    RIGHT = 0x8E  # pop count, ByteString → push last N bytes as ByteString
    # bytes / bytearray
    PUSHDATA1 = 0x0C  # 1-byte size prefix + data
    PUSHDATA2 = 0x0D  # 2-byte size prefix + data
    PUSHDATA4 = 0x0E  # 4-byte size prefix + data
    NEWBUFFER = 0x88  # pop int size, push zero-filled Buffer
    SIZE = 0xCA  # pop bytes/bytearray, push length as int
    PICKITEM = 0xCE  # pop (collection, index), push element
    CONVERT = 0xDB  # pop item, push converted to type (1-byte StackItemType operand)
    ISNULL = 0xD8  # pop item → push bool (true if null)
    ISTYPE = 0xD9  # 1-byte StackItemType operand; pop item → push bool (true if item matches type)
    SETITEM = 0xD0  # pop value, index, compound/buffer → set item[index] = value
    # array / list
    PACK = 0xC0  # pop count n, then pop n items → push Array; Pop: n+1, Push: 1
    NEWARRAY0 = 0xC2  # push empty Array; Pop: 0, Push: 1
    NEWARRAY = 0xC3  # pop count (int) → push Array with N null slots; Pop: 1, Push: 1
    APPEND = 0xCF  # pop item (top) and array → mutate array; Pop: 2, Push: 0
    # map / dict
    NEWMAP = 0xC8  # push empty Map; Pop: 0, Push: 1
    HASKEY = 0xCB  # pop (map, key) → push bool; Pop: 2, Push: 1
    KEYS = 0xCC  # pop map → push Array of keys; Pop: 1, Push: 1
    VALUES = 0xCD  # pop map → push Array of values; Pop: 1, Push: 1
    # stack manipulation
    DUP = 0x4A  # copy top of stack
    OVER = 0x4B  # copy second-from-top to top
    SWAP = 0x50  # (a b → b a)
    SIGN = 0x99  # (a → -1, 0, or 1) — sign of integer
    REVERSEITEMS = 0xD1  # (array/buffer →) reverse in-place
