import ast
from typing import Optional, TYPE_CHECKING
from . import HIRFunction
from neo3.core.types import UInt160, UInt256
from neo3.vm import Syscalls
from .types import (
    Type,
    NoneType,
    OptionalType,
    UInt160Type,
    UInt256Type,
    TypecheckError,
    INT,
    BOOL,
    STR,
    BYTES,
)
from .cfg import (
    StackInstr,
    Ret,
    Jump,
    CondJump,
    EndTry,
    EndFinally,
    BasicBlock,
    CFG,
    OpCode,
    Terminator,
)

_SYSCALL_NOTIFY: bytes = Syscalls.get_by_name("System.Runtime.Notify").number.to_bytes(
    4, "little"
)
_SYSCALL_RUNTIME_LOG: bytes = Syscalls.get_by_name(
    "System.Runtime.Log"
).number.to_bytes(4, "little")
_SYSCALL_CONTRACT_CALL: bytes = Syscalls.get_by_name(
    "System.Contract.Call"
).number.to_bytes(4, "little")


class Emitter:
    """Mutable byte-buffer for assembling NeoVM bytecode.

    Provides low-level helpers for appending opcodes, fixed-width integers,
    and variable-length byte strings.  Jump instructions are emitted with
    32-bit signed relative-offset placeholders that must be back-patched via
    ``patch_i32`` once the target offset is known.

    Attributes:
        _buf: The raw byte accumulator.
    """

    def __init__(self):
        """Initialise an empty byte buffer."""
        self._buf = bytearray()

    def pos(self) -> int:
        """Return the current write position (total bytes emitted so far).

        Returns:
            Current byte offset from the start of the buffer.
        """
        return len(self._buf)

    def emit_opcode(self, op: OpCode) -> None:
        """Append a single NeoVM opcode byte.

        Args:
            op: The opcode to emit.
        """
        self._buf.append(int(op))

    def emit_byte(self, value: int) -> None:
        """Append one byte, masking *value* to the low 8 bits.

        Args:
            value: Integer whose least-significant byte is appended.
        """
        self._buf.append(value & 0xFF)

    def emit_raw(self, data: bytes) -> None:
        """Append raw bytes directly to the buffer.

        Args:
            data: Byte sequence to append verbatim.
        """
        self._buf.extend(data)

    def emit_push_int(self, value: int) -> None:
        """Emit the smallest ``PUSHINT<N>`` instruction that fits *value*.

        Selects among ``PUSHINT8``, ``PUSHINT16``, ``PUSHINT32``, and
        ``PUSHINT64`` based on the signed range of *value*.  The operand is
        written in little-endian byte order.

        Args:
            value: Signed integer to push.  Must fit within a 64-bit signed
                range.

        Raises:
            NotImplementedError: If *value* does not fit in a 64-bit signed
                integer.
        """
        if -(1 << 7) <= value < (1 << 7):
            self.emit_opcode(OpCode.PUSHINT8)
            self.emit_raw(value.to_bytes(1, "little", signed=True))
        elif -(1 << 15) <= value < (1 << 15):
            self.emit_opcode(OpCode.PUSHINT16)
            self.emit_raw(value.to_bytes(2, "little", signed=True))
        elif -(1 << 31) <= value < (1 << 31):
            self.emit_opcode(OpCode.PUSHINT32)
            self.emit_raw(value.to_bytes(4, "little", signed=True))
        elif -(1 << 63) <= value < (1 << 63):
            self.emit_opcode(OpCode.PUSHINT64)
            self.emit_raw(value.to_bytes(8, "little", signed=True))
        else:
            raise NotImplementedError("Large integers not yet supported")

    def emit_jump(self, op: OpCode) -> tuple[int, int]:
        """Emit a jump opcode + 4-byte placeholder.
        Returns (jmp_opcode_pos, placeholder_pos)."""
        jmp_opcode_pos = self.pos()
        self.emit_opcode(op)
        placeholder_pos = self.pos()
        self.emit_raw(b"\x00\x00\x00\x00")
        return jmp_opcode_pos, placeholder_pos

    def patch_i32(self, placeholder_pos: int, jmp_opcode_pos: int, target: int) -> None:
        """Patch jump placeholder. Offset is relative to start of jump opcode."""
        rel = target - jmp_opcode_pos
        self._buf[placeholder_pos : placeholder_pos + 4] = rel.to_bytes(
            4, "little", signed=True
        )

    def emit_push_bytes(self, value: bytes) -> None:
        """Emit a ``PUSHDATA<N>`` instruction for *value*.

        Automatically selects ``PUSHDATA1``, ``PUSHDATA2``, or ``PUSHDATA4``
        based on the length of *value*.

        Args:
            value: Byte string to push onto the NeoVM stack.
        """
        n = len(value)
        if n <= 0xFF:
            self.emit_opcode(OpCode.PUSHDATA1)
            self.emit_byte(n)
        elif n <= 0xFFFF:
            self.emit_opcode(OpCode.PUSHDATA2)
            self._buf.extend(n.to_bytes(2, "little"))
        else:
            self.emit_opcode(OpCode.PUSHDATA4)
            self._buf.extend(n.to_bytes(4, "little"))
        self.emit_raw(value)

    def bytecode(self) -> bytes:
        """Return the assembled bytecode as an immutable ``bytes`` object.

        Returns:
            A snapshot of the internal buffer as ``bytes``.
        """
        return bytes(self._buf)


class Linearizer:
    """Lowers a CFG into linear NeoVM bytecode.

    Takes a completed ``CFG`` (produced by ``CFGBuilder``) together with its
    ``HIRFunction`` and emits the bytecode for a single function.  Blocks are
    emitted in insertion order; unconditional jumps whose target is the
    immediately-following block are elided as a fall-through optimisation.

    Forward-reference jump offsets are filled with 4-byte placeholders and
    back-patched in a second pass once all block offsets are known.

    Two entry points are provided:

    * ``generate()`` — stand-alone mode, returns the function's bytecode as
      ``bytes``.
    * ``generate_into()`` — multi-function mode, emits into a shared
      ``Emitter`` and returns the function's start offset so cross-function
      ``CALL_L`` targets can be resolved by the caller.

    Attributes:
        _cfg: The CFG to linearize.
        _fn: The HIR function, providing local and argument counts for the
            ``INITSLOT`` prologue.
        _em: The byte buffer receiving the emitted bytecode.
        _call_fixups: Module-level list for recording cross-function ``CALL_L``
            placeholders.  ``None`` in stand-alone mode.
        _offsets: Maps block label to its byte offset within the emitter.
        _fixups: List of ``(placeholder_pos, jmp_opcode_pos, label)`` tuples
            collected during emission and resolved in ``_patch_jumps``.
    """

    def __init__(
        self,
        cfg: CFG,
        fn: HIRFunction,
        emitter: Optional[Emitter] = None,
        call_fixups: Optional[list] = None,
    ):
        """Initialise the linearizer for a single function.

        Args:
            cfg: The control flow graph to convert to bytecode.
            fn: The HIR function whose local and argument counts are used for
                the ``INITSLOT`` prologue.
            emitter: Shared ``Emitter`` to write into.  A fresh ``Emitter`` is
                created when ``None`` (stand-alone mode).
            call_fixups: Module-level mutable list for recording ``CALL_L``
                placeholder positions that cannot be resolved immediately
                because the callee may be emitted later.  ``None`` disables
                cross-function fixup collection.
        """
        self._cfg = cfg
        self._fn = fn
        self._em = emitter if emitter is not None else Emitter()
        self._call_fixups = call_fixups  # module-level list; None in single-fn mode
        self._offsets: dict[str, int] = {}
        self._fixups: list[tuple[int, int, str]] = (
            []
        )  # (placeholder_pos, jmp_opcode_pos, label)

    def _emit_function(self) -> None:
        """Emit the function prologue and all basic blocks.

        Emits an ``INITSLOT`` opcode (skipped when both local and argument
        counts are zero, as that is illegal in NeoVM) followed by each basic
        block in insertion order.
        """
        num_locals = len(self._fn.locals)
        num_args = len(self._fn.args)
        if num_locals > 0 or num_args > 0:  # INITSLOT 0 0 is illegal in NeoVM
            self._em.emit_opcode(OpCode.INITSLOT)
            self._em.emit_byte(num_locals)
            self._em.emit_byte(num_args)

        labels = list(self._cfg.blocks.keys())
        for i, label in enumerate(labels):
            block = self._cfg.blocks[label]
            next_label = labels[i + 1] if i + 1 < len(labels) else None
            self._offsets[label] = self._em.pos()
            self._emit_block(block, next_label)

    def generate(self) -> bytes:
        """Single-function mode: generate complete bytecode."""
        self._emit_function()
        self._patch_jumps()
        return self._em.bytecode()

    def generate_into(self) -> int:
        """Multi-function mode: emit into shared emitter, return function start offset."""
        start = self._em.pos()
        self._emit_function()
        self._patch_jumps()  # within-function jumps patched immediately
        return start

    def _emit_block(self, block: BasicBlock, next_label: Optional[str]) -> None:
        """Emit all instructions and the terminator for *block*.

        Args:
            block: The basic block to emit.
            next_label: Label of the block that will be emitted immediately
                after this one, used for fall-through elimination.
        """
        for instr in block.instructions:
            self._emit_instr(instr)
        self._emit_terminator(block.terminator, next_label)

    def _emit_instr(self, instr: StackInstr) -> None:
        """Translate a single ``StackInstr`` into NeoVM bytes.

        Dispatches on the string mnemonic in ``instr.op`` and writes the
        corresponding opcode byte(s) and any operands into the emitter.

        Args:
            instr: The stack instruction to translate.

        Raises:
            NotImplementedError: If ``instr.op`` is not a recognised mnemonic.
        """
        match instr.op:
            case "PUSH_INT":
                self._em.emit_push_int(instr.operand)
            case "PUSH_BOOL":
                self._em.emit_opcode(OpCode.PUSHT if instr.operand else OpCode.PUSHF)
            case "PUSHNULL":
                self._em.emit_opcode(OpCode.PUSHNULL)
            case "LDARG":
                self._em.emit_opcode(OpCode.LDARG)
                self._em.emit_byte(instr.operand)
            case "LDLOC":
                self._em.emit_opcode(OpCode.LDLOC)
                self._em.emit_byte(instr.operand)
            case "STLOC":
                self._em.emit_opcode(OpCode.STLOC)
                self._em.emit_byte(instr.operand)
            case "STARG":
                self._em.emit_opcode(OpCode.STARG)
                self._em.emit_byte(instr.operand)
            case "LDSFLD":
                self._em.emit_opcode(OpCode.LDSFLD)
                self._em.emit_byte(instr.operand)
            case "STSFLD":
                self._em.emit_opcode(OpCode.STSFLD)
                self._em.emit_byte(instr.operand)
            case "+":
                self._em.emit_opcode(OpCode.ADD)
            case "-":
                self._em.emit_opcode(OpCode.SUB)
            case "*":
                self._em.emit_opcode(OpCode.MUL)
            case "//":
                self._em.emit_opcode(OpCode.DIV)
            case "%":
                self._em.emit_opcode(OpCode.MOD)
            case "==":
                self._em.emit_opcode(OpCode.EQUAL)
            case "!=":
                self._em.emit_opcode(OpCode.NOTEQUAL)
            case "<":
                self._em.emit_opcode(OpCode.LT)
            case "<=":
                self._em.emit_opcode(OpCode.LE)
            case ">":
                self._em.emit_opcode(OpCode.GT)
            case ">=":
                self._em.emit_opcode(OpCode.GE)
            case "booland":
                self._em.emit_opcode(OpCode.BOOLAND)
            case "boolor":
                self._em.emit_opcode(OpCode.BOOLOR)
            case "not":
                self._em.emit_opcode(OpCode.NOT)
            case "negate":
                self._em.emit_opcode(OpCode.NEGATE)
            case "invert":
                self._em.emit_opcode(OpCode.INVERT)
            case "abs":
                self._em.emit_opcode(OpCode.ABS)
            case "min":
                self._em.emit_opcode(OpCode.MIN)
            case "max":
                self._em.emit_opcode(OpCode.MAX)
            case "**":
                self._em.emit_opcode(OpCode.POW)
            case "&":
                self._em.emit_opcode(OpCode.AND)
            case "|":
                self._em.emit_opcode(OpCode.OR)
            case "^":
                self._em.emit_opcode(OpCode.XOR)
            case "<<":
                self._em.emit_opcode(OpCode.SHL)
            case ">>":
                self._em.emit_opcode(OpCode.SHR)
            case "call":
                call_opcode_pos, placeholder_pos = self._em.emit_jump(OpCode.CALL_L)
                if self._call_fixups is not None:
                    self._call_fixups.append(
                        (placeholder_pos, call_opcode_pos, instr.operand)
                    )
            case "PUSH_STR":
                self._em.emit_push_bytes(instr.operand.encode("utf-8"))
            case "PUSH_BYTES":
                self._em.emit_push_bytes(instr.operand)
            case "NEWBUFFER":
                self._em.emit_opcode(OpCode.NEWBUFFER)
            case "SIZE":
                self._em.emit_opcode(OpCode.SIZE)
            case "cat":
                self._em.emit_opcode(OpCode.CAT)
            case "CONVERT":
                self._em.emit_opcode(OpCode.CONVERT)
                self._em.emit_byte(instr.operand)
            case "PICKITEM":
                self._em.emit_opcode(OpCode.PICKITEM)
            case "SUBSTR":
                self._em.emit_opcode(OpCode.SUBSTR)
            case "LEFT":
                self._em.emit_opcode(OpCode.LEFT)
            case "RIGHT":
                self._em.emit_opcode(OpCode.RIGHT)
            case "DUP":
                self._em.emit_opcode(OpCode.DUP)
            case "OVER":
                self._em.emit_opcode(OpCode.OVER)
            case "SWAP":
                self._em.emit_opcode(OpCode.SWAP)
            case "SIGN":
                self._em.emit_opcode(OpCode.SIGN)
            case "REVERSEITEMS":
                self._em.emit_opcode(OpCode.REVERSEITEMS)
            case "SETITEM":
                self._em.emit_opcode(OpCode.SETITEM)
            case "NEWARRAY0":
                self._em.emit_opcode(OpCode.NEWARRAY0)
            case "NEWARRAY":
                self._em.emit_opcode(OpCode.NEWARRAY)
            case "APPEND":
                self._em.emit_opcode(OpCode.APPEND)
            case "NEWMAP":
                self._em.emit_opcode(OpCode.NEWMAP)
            case "HASKEY":
                self._em.emit_opcode(OpCode.HASKEY)
            case "KEYS":
                self._em.emit_opcode(OpCode.KEYS)
            case "VALUES":
                self._em.emit_opcode(OpCode.VALUES)
            case "ISNULL":
                self._em.emit_opcode(OpCode.ISNULL)
            case "ISTYPE":
                self._em.emit_opcode(OpCode.ISTYPE)
                self._em.emit_byte(instr.operand)
            case "DROP":
                self._em.emit_opcode(OpCode.DROP)
            case "ASSERT":
                self._em.emit_opcode(OpCode.ASSERT)
            case "ASSERTMSG":
                self._em.emit_opcode(OpCode.ASSERTMSG)
            case "THROW":
                self._em.emit_opcode(OpCode.THROW)
            case "syscall_log":
                self._em.emit_opcode(OpCode.SYSCALL)
                self._em.emit_raw(_SYSCALL_RUNTIME_LOG)
            case "ABORT":
                self._em.emit_raw(bytes([0x38]))
            case "ABORTMSG":
                self._em.emit_raw(bytes([0xE0]))
            case "notify":
                # System.Runtime.Notify: push args (already reversed), PACK into Array,
                # push event name, then SYSCALL.
                event_name, n_args = instr.operand
                self._em.emit_push_int(n_args)
                self._em.emit_opcode(OpCode.PACK)
                name_bytes = event_name.encode("utf-8")
                self._em.emit_opcode(OpCode.PUSHDATA1)
                self._em.emit_raw(bytes([len(name_bytes)]) + name_bytes)
                self._em.emit_opcode(OpCode.SYSCALL)
                self._em.emit_raw(_SYSCALL_NOTIFY)
            case "syscall":
                # Direct SYSCALL: hash stored in instr.operand (4-byte LE)
                self._em.emit_opcode(OpCode.SYSCALL)
                self._em.emit_raw(instr.operand)
            case "contract_call":
                # System.Contract.Call with arbitrary contract hash and method name.
                # Args are already on the stack in reverse order (first arg on top).
                chash, method_name, n_args, call_flags_val = instr.operand
                _method_bytes = method_name.encode("utf-8")
                self._em.emit_opcode(OpCode.PUSHINT8)
                self._em.emit_raw(bytes([n_args]))  # arg count
                self._em.emit_opcode(OpCode.PACK)
                self._em.emit_opcode(OpCode.PUSHINT8)
                self._em.emit_raw(bytes([call_flags_val]))
                self._em.emit_opcode(OpCode.PUSHDATA1)
                self._em.emit_raw(bytes([len(_method_bytes)]) + _method_bytes)
                self._em.emit_opcode(OpCode.PUSHDATA1)
                self._em.emit_raw(bytes([20]) + chash)
                self._em.emit_opcode(OpCode.SYSCALL)
                self._em.emit_raw(_SYSCALL_CONTRACT_CALL)
            case "TRY_L":
                catch_lbl, finally_lbl = instr.operand
                try_opcode_pos = self._em.pos()
                self._em.emit_opcode(OpCode.TRY_L)
                catch_ph = self._em.pos()
                self._em.emit_raw(
                    b"\x00\x00\x00\x00"
                )  # catch offset placeholder (0=absent)
                finally_ph = self._em.pos()
                self._em.emit_raw(
                    b"\x00\x00\x00\x00"
                )  # finally offset placeholder (0=absent)
                if catch_lbl is not None:
                    self._fixups.append((catch_ph, try_opcode_pos, catch_lbl))
                if finally_lbl is not None:
                    self._fixups.append((finally_ph, try_opcode_pos, finally_lbl))
            case _:
                raise NotImplementedError(f"Unknown StackInstr op: {instr.op}")

    def _emit_terminator(self, term: Terminator, next_label: Optional[str]) -> None:
        """Emit the bytecode for a block terminator.

        Unconditional ``Jump`` terminators whose target equals *next_label* are
        omitted entirely (fall-through optimisation).

        Args:
            term: The terminator to emit.
            next_label: Label of the next block in emission order, used to
                detect fall-through opportunities.
        """
        match term:
            case Ret():
                self._em.emit_opcode(OpCode.RET)
            case Jump(target=lbl):
                # Fall-through optimisation: skip the jump if target is the next block.
                if lbl == next_label:
                    return
                jmp_opcode_pos, placeholder_pos = self._em.emit_jump(OpCode.JMP_L)
                self._fixups.append((placeholder_pos, jmp_opcode_pos, lbl))
            case CondJump(true_target=t_lbl, false_target=f_lbl):
                jmpif_pos, true_placeholder = self._em.emit_jump(OpCode.JMPIF_L)
                self._fixups.append((true_placeholder, jmpif_pos, t_lbl))
                # The false branch may also fall through if it's the next block.
                if f_lbl != next_label:
                    jmp_pos, false_placeholder = self._em.emit_jump(OpCode.JMP_L)
                    self._fixups.append((false_placeholder, jmp_pos, f_lbl))
            case EndTry(end_label=lbl):
                end_pos, placeholder = self._em.emit_jump(OpCode.ENDTRY_L)
                self._fixups.append((placeholder, end_pos, lbl))
            case EndFinally():
                self._em.emit_opcode(OpCode.ENDFINALLY)

    def _patch_jumps(self) -> None:
        """Resolve all collected jump placeholders.

        Iterates over ``_fixups`` and overwrites each 4-byte placeholder with
        the correct signed 32-bit relative offset computed from the block
        offsets recorded in ``_offsets``.
        """
        for placeholder_pos, jmp_opcode_pos, label in self._fixups:
            self._em.patch_i32(placeholder_pos, jmp_opcode_pos, self._offsets[label])


# 32-byte fill used by signed to_bytes helpers to sign-extend negative integers
_TO_BYTES_NEG_FILL = b"\xff" * 32


def _emit_static_literal(
    em: Emitter, node: ast.expr, expected_type: Type, filename: Optional[str] = None
) -> None:
    """Emit a single constant literal directly into *em*.
    Raises TypecheckError if the node is not a plain constant."""
    _lineno = getattr(node, "lineno", None)
    _col = getattr(node, "col_offset", None)

    def _loc_err(msg: str) -> TypecheckError:
        return TypecheckError(msg, lineno=_lineno, col_offset=_col, filename=filename)

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.attr == "from_string"
        and node.func.value.id in ("UInt160", "UInt256")
    ):
        cls_name = node.func.value.id
        if (
            len(node.args) != 1
            or not isinstance(node.args[0], ast.Constant)
            or not isinstance(node.args[0].value, str)
        ):
            raise _loc_err(
                f"{cls_name}.from_string() requires a string literal argument"
            )
        s = node.args[0].value
        if cls_name == "UInt160":
            if not isinstance(expected_type, UInt160Type):
                raise _loc_err(
                    f"Static field initialiser type mismatch: expected {expected_type}, got UInt160"
                )
            em.emit_push_bytes(UInt160.from_string(s).to_array())
        else:
            if not isinstance(expected_type, UInt256Type):
                raise _loc_err(
                    f"Static field initialiser type mismatch: expected {expected_type}, got UInt256"
                )
            em.emit_push_bytes(UInt256.from_string(s).to_array())
        return
    if not isinstance(node, ast.Constant):
        raise _loc_err(
            "Static field initialiser must be a constant literal "
            f"(int, bool, str, or bytes); got {type(node).__name__}"
        )
    v = node.value
    if v is None:
        if not isinstance(expected_type, (NoneType, OptionalType)):
            raise _loc_err(
                f"Static field initialiser type mismatch: expected {expected_type}, got None"
            )
        em.emit_opcode(OpCode.PUSHNULL)
    elif isinstance(v, bool):
        if expected_type != BOOL:
            raise _loc_err(
                f"Static field initialiser type mismatch: expected {expected_type}, got bool"
            )
        em.emit_opcode(OpCode.PUSHT if v else OpCode.PUSHF)
    elif isinstance(v, int):
        if expected_type != INT and not (
            isinstance(expected_type, OptionalType) and expected_type.inner == INT
        ):
            raise _loc_err(
                f"Static field initialiser type mismatch: expected {expected_type}, got int"
            )
        em.emit_push_int(v)
    elif isinstance(v, str):
        if expected_type != STR and not (
            isinstance(expected_type, OptionalType) and expected_type.inner == STR
        ):
            raise _loc_err(
                f"Static field initialiser type mismatch: expected {expected_type}, got str"
            )
        em.emit_push_bytes(v.encode("utf-8"))
    elif isinstance(v, bytes):
        if expected_type != BYTES and not (
            isinstance(expected_type, OptionalType) and expected_type.inner == BYTES
        ):
            raise _loc_err(
                f"Static field initialiser type mismatch: expected {expected_type}, got bytes"
            )
        em.emit_push_bytes(v)
    else:
        raise _loc_err(
            f"Static field initialiser must be int, bool, str, or bytes; got {type(v).__name__}"
        )


def _emit_to_bytes_overflow_check_unsigned(em: "Emitter") -> None:
    """Emit runtime overflow guards for unsigned to_bytes helpers (no stack effect).

    Guard 1: value >= 0 — unsigned mode rejects negative values.
    Guard 2: value >> (8*length) == 0 — value fits in length unsigned bytes.
    NeoVM SHR is arithmetic (C# BigInteger), so for non-negative values
    the shift result is 0 iff value < 2^(8*length).
    """
    # Guard 1: value >= 0
    em.emit_opcode(OpCode.LDARG)
    em.emit_byte(0)
    em.emit_push_int(0)
    em.emit_opcode(OpCode.LT)  # value < 0?
    j1_op, j1_ph = em.emit_jump(OpCode.JMPIFNOT_L)
    em.emit_push_bytes(b"int.to_bytes overflow: negative value with signed=False")
    em.emit_opcode(OpCode.THROW)
    em.patch_i32(j1_ph, j1_op, em.pos())
    # Guard 2: value >> (8*length) == 0
    em.emit_opcode(OpCode.LDARG)
    em.emit_byte(0)
    em.emit_opcode(OpCode.LDARG)
    em.emit_byte(1)
    em.emit_push_int(8)
    em.emit_opcode(OpCode.MUL)
    em.emit_opcode(OpCode.SHR)
    em.emit_push_int(0)
    em.emit_opcode(OpCode.NOTEQUAL)  # (value >> 8*length) != 0 → overflow
    j2_op, j2_ph = em.emit_jump(OpCode.JMPIFNOT_L)
    em.emit_push_bytes(b"int.to_bytes overflow: value too large for given length")
    em.emit_opcode(OpCode.THROW)
    em.patch_i32(j2_ph, j2_op, em.pos())


def _emit_to_bytes_overflow_check_signed(em: "Emitter") -> None:
    """Emit runtime overflow guard for signed to_bytes helpers (no stack effect).

    Checks that value >> (8*length - 1) is 0 (positive fits) or -1 (negative fits).
    NeoVM SHR is arithmetic, so this detects both directions of overflow.
    Edge case length=0: shift becomes -1, which C# BigInteger treats as left-shift by 1.
    For value=0 the result is 0 (fits → b''); for non-zero the result != 0 and != -1
    (overflow) — matching Python's OverflowError for non-zero values with length=0.
    """
    em.emit_opcode(OpCode.LDARG)
    em.emit_byte(0)
    em.emit_opcode(OpCode.LDARG)
    em.emit_byte(1)
    em.emit_push_int(8)
    em.emit_opcode(OpCode.MUL)
    em.emit_push_int(1)
    em.emit_opcode(OpCode.SUB)  # 8*length - 1
    em.emit_opcode(OpCode.SHR)  # value >> (8*length - 1); 0 or -1 means fits
    em.emit_opcode(OpCode.DUP)
    em.emit_push_int(0)
    em.emit_opcode(OpCode.EQUAL)  # shifted == 0?
    em.emit_opcode(OpCode.SWAP)
    em.emit_push_int(-1)
    em.emit_opcode(OpCode.EQUAL)  # shifted == -1?
    em.emit_opcode(OpCode.BOOLOR)  # fits?
    j_op, j_ph = em.emit_jump(OpCode.JMPIF_L)
    em.emit_push_bytes(
        b"int.to_bytes overflow: value out of range for signed conversion"
    )
    em.emit_opcode(OpCode.THROW)
    em.patch_i32(j_ph, j_op, em.pos())


def _emit_to_bytes_helper(em: "Emitter", byteorder: str, signed: bool) -> None:
    """Emit one of the four int.to_bytes helper functions directly into *em*.

    Calling convention (right-to-left push, so inside the helper):
      LDARG 0 = value (int)
      LDARG 1 = length (int)
    Returns a bytes value (NeoVM ByteString).

    Divergences from Python:
      - Overflow: faults the VM with an error message (rather than raising OverflowError).
      - length > 32: NeoVM int max is 32 bytes; CONVERT may produce wrong results.
    """
    if byteorder == "little" and not signed:
        # __to_bytes_little_unsigned: 0 locals, 2 args
        # Algorithm: CONVERT to minimal signed LE, zero-pad to >= length, LEFT(length)
        em.emit_opcode(OpCode.INITSLOT)
        em.emit_byte(0)  # locals
        em.emit_byte(2)  # args
        _emit_to_bytes_overflow_check_unsigned(em)
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(0)  # value
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x28)  # → ByteString (minimal signed LE bytes)
        em.emit_push_int(32)
        em.emit_opcode(OpCode.NEWBUFFER)  # 32 zero bytes as fill
        em.emit_opcode(OpCode.CAT)  # le_bytes ++ zeros
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(1)  # length
        em.emit_opcode(OpCode.LEFT)  # first `length` bytes
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x28)  # ensure ByteString (not Buffer)
        em.emit_opcode(OpCode.RET)

    elif byteorder == "little" and signed:
        # __to_bytes_little_signed: 1 local (le_bytes), 2 args
        # Algorithm: CONVERT to LE; choose fill (0xFF*32 if negative, NEWBUFFER(32) if non-negative);
        #            le_bytes ++ fill, LEFT(length).
        em.emit_opcode(OpCode.INITSLOT)
        em.emit_byte(1)  # 1 local: le_bytes (slot 0)
        em.emit_byte(2)  # 2 args
        _emit_to_bytes_overflow_check_signed(em)
        # le_bytes = CONVERT(value)
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(0)
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x28)
        em.emit_opcode(OpCode.STLOC)
        em.emit_byte(0)  # stloc 0 = le_bytes
        # Determine fill: value.SIGN < 0 → 0xFF*32; else → NEWBUFFER(32)
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(0)  # value
        em.emit_opcode(OpCode.SIGN)  # → -1, 0, or 1
        em.emit_push_int(0)
        em.emit_opcode(OpCode.LT)  # sign < 0?
        # JMPIFNOT_L to zero_fill (forward jump — emit placeholder, patch below)
        jmp_op_pos, jmp_placeholder = em.emit_jump(OpCode.JMPIFNOT_L)
        # negative branch: push 32-byte 0xFF fill
        em.emit_push_bytes(_TO_BYTES_NEG_FILL)
        # JMP_L to have_fill
        jmp2_op_pos, jmp2_placeholder = em.emit_jump(OpCode.JMP_L)
        # zero_fill label
        zero_fill_pos = em.pos()
        em.emit_push_int(32)
        em.emit_opcode(OpCode.NEWBUFFER)  # 32 zero bytes
        # have_fill label
        have_fill_pos = em.pos()
        # Patch the JMPIFNOT_L to zero_fill
        em.patch_i32(jmp_placeholder, jmp_op_pos, zero_fill_pos)
        # Patch the JMP_L to have_fill
        em.patch_i32(jmp2_placeholder, jmp2_op_pos, have_fill_pos)
        # Stack: [fill_buffer]; build le_bytes ++ fill and take LEFT(length)
        em.emit_opcode(OpCode.LDLOC)
        em.emit_byte(0)  # le_bytes
        em.emit_opcode(OpCode.SWAP)  # [fill, le_bytes] → [le_bytes, fill]
        em.emit_opcode(OpCode.CAT)  # le_bytes ++ fill
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(1)  # length
        em.emit_opcode(OpCode.LEFT)
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x28)
        em.emit_opcode(OpCode.RET)

    elif byteorder == "big" and not signed:
        # __to_bytes_big_unsigned: 0 locals, 2 args
        # Same LE computation as little_unsigned, then CONVERT→Buffer, REVERSEITEMS, CONVERT→ByteString
        em.emit_opcode(OpCode.INITSLOT)
        em.emit_byte(0)
        em.emit_byte(2)
        _emit_to_bytes_overflow_check_unsigned(em)
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(0)
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x28)
        em.emit_push_int(32)
        em.emit_opcode(OpCode.NEWBUFFER)
        em.emit_opcode(OpCode.CAT)
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(1)
        em.emit_opcode(OpCode.LEFT)
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x30)  # → Buffer (required by REVERSEITEMS)
        # REVERSEITEMS is in-place and pops the item off the stack (like APPEND).
        # DUP first so the reference stays on the stack after the reversal.
        em.emit_opcode(OpCode.DUP)
        em.emit_opcode(
            OpCode.REVERSEITEMS
        )  # reverse in-place → big-endian; pops the dup
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x28)  # → ByteString
        em.emit_opcode(OpCode.RET)

    else:
        assert byteorder == "big" and signed
        # __to_bytes_big_signed: 1 local (le_bytes), 2 args
        # Same signed LE computation as little_signed, then reverse.
        em.emit_opcode(OpCode.INITSLOT)
        em.emit_byte(1)
        em.emit_byte(2)
        _emit_to_bytes_overflow_check_signed(em)
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(0)
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x28)
        em.emit_opcode(OpCode.STLOC)
        em.emit_byte(0)
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(0)
        em.emit_opcode(OpCode.SIGN)
        em.emit_push_int(0)
        em.emit_opcode(OpCode.LT)
        jmp_op_pos, jmp_placeholder = em.emit_jump(OpCode.JMPIFNOT_L)
        em.emit_push_bytes(_TO_BYTES_NEG_FILL)
        jmp2_op_pos, jmp2_placeholder = em.emit_jump(OpCode.JMP_L)
        zero_fill_pos = em.pos()
        em.emit_push_int(32)
        em.emit_opcode(OpCode.NEWBUFFER)
        have_fill_pos = em.pos()
        em.patch_i32(jmp_placeholder, jmp_op_pos, zero_fill_pos)
        em.patch_i32(jmp2_placeholder, jmp2_op_pos, have_fill_pos)
        em.emit_opcode(OpCode.LDLOC)
        em.emit_byte(0)
        em.emit_opcode(OpCode.SWAP)
        em.emit_opcode(OpCode.CAT)
        em.emit_opcode(OpCode.LDARG)
        em.emit_byte(1)
        em.emit_opcode(OpCode.LEFT)
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x30)  # → Buffer
        em.emit_opcode(
            OpCode.DUP
        )  # keep reference; REVERSEITEMS pops without pushing back
        em.emit_opcode(OpCode.REVERSEITEMS)
        em.emit_opcode(OpCode.CONVERT)
        em.emit_byte(0x28)
        em.emit_opcode(OpCode.RET)
