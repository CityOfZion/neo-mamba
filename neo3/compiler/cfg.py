from __future__ import annotations
import dataclasses
from typing import Any, Literal, Optional

from neo3.vm import OpCode
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
