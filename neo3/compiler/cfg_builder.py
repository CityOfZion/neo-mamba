from __future__ import annotations
import itertools
from typing import Optional
from neo3.contracts.contract import CONTRACT_HASHES
from neo3.vm import Syscalls
from .types import (
    Type,
    IntType,
    BoolType,
    BytesType,
    BytearrayType,
    StrType,
    NoneType,
    UInt160Type,
    UInt256Type,
    ECPointType,
    TypecheckError,
    INT,
    BOOL,
    BYTES,
    BYTEARRAY,
    STR,
    NONE,
    ANY,
    LIST_STR,
)
from .hir import (
    IntLiteral,
    BoolLiteral,
    LocalLoad,
    BinOp,
    Compare,
    BoolAnd,
    BoolOr,
    IfExp,
    Not,
    Negate,
    Invert,
    Abs,
    Min,
    Max,
    Call,
    BytesLiteral,
    NewBuffer,
    Len,
    BytesFromHex,
    SyscallCall,
    NotifyCall,
    BytesHex,
    IntToBytes,
    IntFromBytes,
    Atoi,
    Itoa,
    StrSplit,
    ContractCall,
    DynamicContractCall,
    TypeConvert,
    Cast,
    Index,
    StrIndex,
    StringLiteral,
    Slice,
    ListLiteral,
    TupleLiteral,
    DictLiteral,
    HasKey,
    DictKeys,
    DictValues,
    StaticLoad,
    NoneLiteral,
    IsNone,
    IsType,
    GetField,
    NewInstance,
    MethodCall,
    LocalStore,
    Return,
    If,
    While,
    Break,
    Continue,
    ListAppend,
    ReverseItems,
    ItemStore,
    TupleUnpack,
    StaticStore,
    CallStmt,
    Assert,
    Raise,
    PrintStmt,
    PrintListStmt,
    AbortStmt,
    TryExcept,
    SetField,
    MethodCallStmt,
    Expr,
    Stmt,
    HIRFunction,
    ClassInfo,
)
from .cfg import (
    StackOp,
    StackInstr,
    Ret,
    Jump,
    CondJump,
    EndTry,
    EndFinally,
    BasicBlock,
    CFG,
)

_STDLIB_HASH: bytes = CONTRACT_HASHES.STD_LIB.to_array()  # 20-byte UInt160 LE
_SYSCALL_CONTRACT_CALL: bytes = Syscalls.get_by_name("System.Contract.Call").number.to_bytes(4, "little")


class CFGBuilder:
    """Builds a Control Flow Graph (CFG) from a HIR function.

    Walks HIR statement and expression nodes in a single pass, emitting
    ``StackInstr`` instructions into ``BasicBlock`` objects and wiring blocks
    together with ``Terminator`` nodes (``Jump``, ``CondJump``, ``Ret``, …).

    The builder maintains a *current block* cursor that advances as control-flow
    constructs (``If``, ``While``, ``TryExcept``, …) are lowered.
    Short-circuit boolean operators and inline conditionals (``IfExp``) each
    split control flow into extra blocks and reconverge at a join block.

    Attributes:
        _fn: The HIR function being compiled.
        _class_registry: Optional mapping from class name to ``ClassInfo``,
            used to resolve field offsets and constructor calls for user-defined
            classes.
        _cfg: The ``CFG`` being built.  Initially contains only the entry block.
        _current: The basic block currently being populated.
        _loop_break_target: Label of the exit block for the innermost loop,
            or ``None`` when not inside a loop.
        _loop_continue_target: Label of the header block for the innermost loop,
            or ``None`` when not inside a loop.
        _jump_targets: Set of all labels ever used as a jump target, used to
            determine whether an exit block is reachable.
    """

    def __init__(
        self, fn: HIRFunction, class_registry: Optional[dict[str, "ClassInfo"]] = None
    ):
        """Initialise the builder for a single function.

        Args:
            fn: The HIR function whose body will be compiled.
            class_registry: Mapping of class name to ``ClassInfo`` used when
                compiling object-construction and field-access expressions.
                May be ``None`` for functions that contain no class usage.
        """
        self._fn = fn
        self._class_registry: Optional[dict[str, "ClassInfo"]] = class_registry
        self._counter = itertools.count()
        self._cfg = CFG(entry="entry", blocks={})
        self._current = self._cfg.new_block("entry")
        self._loop_break_target: Optional[str] = None
        self._loop_continue_target: Optional[str] = None
        self._jump_targets: set[str] = set()  # all labels ever used as jump targets

    def build(self) -> CFG:
        """Compile the function body and return the completed CFG.

        Iterates over every top-level statement in ``_fn.body``, emitting
        instructions into basic blocks.  If the final current block is still
        open after all statements are processed, an implicit ``Ret`` is added
        for void functions; non-void functions that fall off the end raise a
        ``TypecheckError``.

        Returns:
            The fully-populated ``CFG`` for the function.

        Raises:
            TypecheckError: If a non-void function has no explicit ``return``
                at the end of control flow.
        """
        for stmt in self._fn.body:
            self._emit_stmt(stmt)
        if self._current.terminator is None:
            if isinstance(self._fn.return_type, NoneType):
                self._close(
                    Ret()
                )  # implicit RET for void functions that fall off the end
            else:
                raise TypecheckError(
                    f"Block '{self._current.label}' has no terminator (missing return?)"
                )
        return self._cfg

    def _fresh(self, hint: str) -> str:
        """Return a unique block label with *hint* as a human-readable prefix.

        Args:
            hint: Descriptive prefix for the generated label.

        Returns:
            A string of the form ``"<hint>_<n>"``, where ``<n>`` is a
            monotonically increasing integer counter.
        """
        return f"{hint}_{next(self._counter)}"

    def _emit(self, instr: StackInstr) -> None:
        """Append *instr* to the current block's instruction list.

        Args:
            instr: The stack instruction to append.

        Raises:
            AssertionError: If the current block is already closed (has a
                terminator).
        """
        assert self._current.terminator is None, "Emitting into a closed block"
        self._current.instructions.append(instr)

    def _close(self, term: Terminator) -> None:
        """Set the terminator for the current block and record its jump targets.

        After this call the current block is *closed*; ``_emit`` must not be
        called again without first switching to a new block via ``_switch``.

        Args:
            term: The terminator to attach.  Targets of ``Jump`` and
                ``CondJump`` are added to ``_jump_targets`` so reachability
                can be checked later.

        Raises:
            AssertionError: If the current block already has a terminator.
        """
        assert self._current.terminator is None
        self._current.terminator = term
        match term:
            case Jump(target=t):
                self._jump_targets.add(t)
            case CondJump(true_target=t, false_target=f):
                self._jump_targets.add(t)
                self._jump_targets.add(f)

    def _switch(self, block: BasicBlock) -> None:
        """Change the current insertion target to *block*.

        Args:
            block: The basic block that subsequent ``_emit`` calls will
                populate.
        """
        self._current = block

    def _emit_stmt(self, stmt: Stmt) -> None:
        """Lower a single HIR statement into the current block.

        Dispatches on the concrete ``Stmt`` subtype via a structural ``match``
        statement.  Control-flow statements (``If``, ``While``, ``TryExcept``,
        ``Break``, ``Continue``) create and wire new blocks; expression
        statements and stores append ``StackInstr`` items to the current block.

        Statements reached after the current block is already terminated (dead
        code following an unconditional ``return`` or ``break``) are silently
        dropped.

        Args:
            stmt: The HIR statement to compile.
        """
        if self._current.terminator is not None:
            return

        match stmt:
            case LocalStore(slot=slot, value=expr, type=t, is_arg=is_arg):
                self._emit_expr(expr)
                op: StackOp = "STARG" if is_arg else "STLOC"
                self._emit(StackInstr(op=op, type=t, operand=slot))

            case Return(value=expr, type=t):
                if not isinstance(self._fn.return_type, NoneType):
                    self._emit_expr(expr)
                self._close(Ret())

            case If(condition=cond, then_body=then, else_body=els):
                then_lbl = self._fresh("then")
                join_lbl = self._fresh("join")
                false_target = self._fresh("else") if els else join_lbl

                self._emit_expr(cond)
                self._close(CondJump(true_target=then_lbl, false_target=false_target))

                then_bb = self._cfg.new_block(then_lbl)
                self._switch(then_bb)
                for s in then:
                    self._emit_stmt(s)
                then_needs_join = self._current.terminator is None
                if then_needs_join:
                    self._close(Jump(target=join_lbl))

                if els:
                    else_bb = self._cfg.new_block(false_target)
                    self._switch(else_bb)
                    for s in els:
                        self._emit_stmt(s)
                    else_needs_join = self._current.terminator is None
                    if else_needs_join:
                        self._close(Jump(target=join_lbl))
                else:
                    else_needs_join = (
                        True  # no else → false branch falls through to join
                    )

                join_bb = self._cfg.new_block(join_lbl)
                if then_needs_join or else_needs_join:
                    self._switch(join_bb)

            case While(condition=cond, body=body, else_body=else_body):
                header_lbl = self._fresh("while_header")
                body_lbl = self._fresh("while_body")
                exit_lbl = self._fresh("while_exit")

                # Jump unconditionally into the header from wherever we are.
                # Fall-through suppression in the Linearizer will elide this
                # if the header block is emitted immediately next (it is).
                self._close(Jump(target=header_lbl))

                # header: evaluate condition, branch to body or else/exit
                header_bb = self._cfg.new_block(header_lbl)
                self._switch(header_bb)
                self._emit_expr(cond)
                if else_body:
                    else_lbl = self._fresh("while_else")
                    self._close(CondJump(true_target=body_lbl, false_target=else_lbl))
                else:
                    self._close(CondJump(true_target=body_lbl, false_target=exit_lbl))

                # install this loop's break/continue targets (save enclosing)
                prev_break, prev_continue = (
                    self._loop_break_target,
                    self._loop_continue_target,
                )
                self._loop_break_target = exit_lbl
                self._loop_continue_target = header_lbl

                # body: emit statements, then back-edge to header
                body_bb = self._cfg.new_block(body_lbl)
                self._switch(body_bb)
                for s in body:
                    self._emit_stmt(s)
                if self._current.terminator is None:
                    self._close(Jump(target=header_lbl))

                # else block (only when else_body is non-empty)
                if else_body:
                    else_bb = self._cfg.new_block(else_lbl)
                    self._switch(else_bb)
                    for s in else_body:
                        self._emit_stmt(s)
                    if self._current.terminator is None:
                        self._close(Jump(target=exit_lbl))

                # restore enclosing loop context
                self._loop_break_target, self._loop_continue_target = (
                    prev_break,
                    prev_continue,
                )

                # exit: continuation block (target of break and condition-false).
                # Only reachable if something actually jumps to exit_lbl (the
                # header's false branch in the no-else case, the else fall-through,
                # or a break).  If unreachable, don't create the block so the
                # Linearizer never sees an untermed block.
                exit_is_reachable = exit_lbl in self._jump_targets
                if exit_is_reachable:
                    exit_bb = self._cfg.new_block(exit_lbl)
                    self._switch(exit_bb)

            case Break():
                assert self._loop_break_target is not None
                self._close(Jump(target=self._loop_break_target))

            case Continue():
                assert self._loop_continue_target is not None
                self._close(Jump(target=self._loop_continue_target))

            case ListAppend(container=ctr, value=val):
                self._emit_expr(ctr)
                self._emit_expr(val)
                self._emit(StackInstr(op="APPEND", type=ctr.type))

            case ReverseItems(container=ctr):
                if isinstance(ctr.type, BytearrayType) and isinstance(ctr, LocalLoad):
                    # bytearray args arrive as ByteString from external callers; REVERSEITEMS
                    # requires a Buffer. Convert, store back to the slot so the variable
                    # reflects the mutation, then reverse in-place.
                    arg_names = [n for n, _ in self._fn.args]
                    self._emit_expr(ctr)
                    self._emit(StackInstr(op="CONVERT", type=BYTEARRAY, operand=0x30))
                    self._emit(StackInstr(op="DUP", type=BYTEARRAY))
                    if ctr.name in arg_names:
                        self._emit(
                            StackInstr(
                                op="STARG",
                                type=BYTEARRAY,
                                operand=arg_names.index(ctr.name),
                            )
                        )
                    else:
                        slot, _ = self._fn.locals[ctr.name]
                        self._emit(StackInstr(op="STLOC", type=BYTEARRAY, operand=slot))
                    self._emit(StackInstr(op="REVERSEITEMS", type=BYTEARRAY))
                else:
                    self._emit_expr(ctr)
                    self._emit(StackInstr(op="REVERSEITEMS", type=ctr.type))

            case ItemStore(container=ctr, index=idx, value=val):
                self._emit_expr(ctr)
                self._emit_expr(idx)
                self._emit_expr(val)
                self._emit(StackInstr(op="SETITEM", type=ctr.type))

            case StaticStore(slot=slot, value=expr, type=t):
                self._emit_expr(expr)
                self._emit(StackInstr(op="STSFLD", type=t, operand=slot))

            case CallStmt(name=name, args=args, return_type=rt):
                for arg in reversed(args):
                    self._emit_expr(arg)
                self._emit(StackInstr(op="call", type=rt, operand=name))
                if rt != NONE:
                    self._emit(StackInstr(op="DROP", type=NONE))

            case Assert(condition=cond, message=msg):
                self._emit_expr(cond)
                if msg is None:
                    self._emit(StackInstr(op="ASSERT", type=BOOL))
                else:
                    self._emit_expr(msg)
                    self._emit(StackInstr(op="ASSERTMSG", type=BOOL))

            case Raise(message=msg):
                if msg is not None:
                    self._emit_expr(msg)
                else:
                    self._emit(StackInstr(op="PUSHNULL", type=NONE))
                self._emit(StackInstr(op="THROW", type=NONE))

            case PrintStmt(msg=msg):
                self._emit_expr(msg)
                self._emit(StackInstr(op="syscall_log", type=NONE))

            case PrintListStmt(list_expr=list_expr) as pls:
                assert (
                    pls.temp_slot >= 0
                ), "PrintListStmt.temp_slot must be pre-allocated"
                slot = pls.temp_slot
                self._emit_expr(list_expr)
                self._emit(StackInstr(op="STLOC", type=list_expr.type, operand=slot))
                self._emit(StackInstr(op="LDLOC", type=list_expr.type, operand=slot))
                self._emit(StackInstr(op="SIZE", type=INT))
                self._emit(StackInstr(op="PUSH_INT", type=INT, operand=0))
                self._emit(StackInstr(op=">", type=BOOL))
                log_lbl = self._fresh("print_list_log")
                skip_lbl = self._fresh("print_list_skip")
                self._close(CondJump(true_target=log_lbl, false_target=skip_lbl))
                log_bb = self._cfg.new_block(log_lbl)
                self._switch(log_bb)
                self._emit(StackInstr(op="LDLOC", type=list_expr.type, operand=slot))
                self._emit(
                    StackInstr(
                        op="contract_call",
                        type=STR,
                        operand=(_STDLIB_HASH, "jsonSerialize", 1, 15),
                    )
                )
                self._emit(StackInstr(op="syscall_log", type=NONE))
                self._close(Jump(target=skip_lbl))
                skip_bb = self._cfg.new_block(skip_lbl)
                self._switch(skip_bb)

            case AbortStmt(msg=msg):
                if msg is not None:
                    self._emit_expr(msg)
                self._emit(
                    StackInstr(op="ABORT" if msg is None else "ABORTMSG", type=NONE)
                )

            case NotifyCall() as nc:
                for arg in reversed(nc.args):
                    self._emit_expr(arg)
                self._emit(
                    StackInstr(
                        op="notify", type=NONE, operand=(nc.event_name, len(nc.args))
                    )
                )

            case SyscallCall() as sc_call:
                assert sc_call.is_stmt
                for i in sc_call.push_order:
                    self._emit_expr(sc_call.args[i])
                self._emit(StackInstr(op="syscall", type=NONE, operand=sc_call.hash))

            case ContractCall(
                contract_hash=chash, method=method, args=args, call_flags=cf
            ) as cc:
                assert cc.is_stmt
                # @contract method call as statement — emit call and DROP the return.
                for arg in reversed(args):
                    self._emit_expr(arg)
                self._emit(
                    StackInstr(
                        op="contract_call",
                        type=NONE,
                        operand=(chash, method, len(args), cf),
                    )
                )
                self._emit(StackInstr(op="DROP", type=NONE))

            case DynamicContractCall(
                script_hash=sh, method=m, args=a, call_flags=cf
            ) as dcc:
                assert dcc.is_stmt
                # Same push order as expression case; DROP the return value.
                self._emit_expr(a)
                self._emit_expr(cf)
                self._emit_expr(m)
                self._emit_expr(sh)
                self._emit(
                    StackInstr(op="syscall", type=ANY, operand=_SYSCALL_CONTRACT_CALL)
                )
                self._emit(StackInstr(op="DROP", type=ANY))

            case TryExcept(
                try_body=try_b,
                catch_body=catch_b,
                finally_body=finally_b,
                handler_var=hvar,
                handler_var_slot=hslot,
            ):
                try_lbl = self._fresh("try_body")
                catch_lbl = self._fresh("catch") if catch_b is not None else None
                finally_lbl = self._fresh("finally") if finally_b is not None else None
                end_lbl = self._fresh("try_end")

                # TRY_L registers exception handlers; execution falls through to try body
                self._emit(StackInstr(op="TRY_L", operand=(catch_lbl, finally_lbl)))
                self._close(Jump(target=try_lbl))

                end_reachable = False

                # Try body block
                self._switch(self._cfg.new_block(try_lbl))
                for s in try_b:
                    self._emit_stmt(s)
                if self._current.terminator is None:
                    self._close(EndTry(end_label=end_lbl))
                    end_reachable = True

                # Catch body block — exception value is on stack at entry
                if catch_b is not None:
                    self._switch(self._cfg.new_block(catch_lbl))
                    if hvar is not None:
                        self._emit(StackInstr(op="STLOC", type=STR, operand=hslot))
                    else:
                        self._emit(StackInstr(op="DROP"))
                    for s in catch_b:
                        self._emit_stmt(s)
                    if self._current.terminator is None:
                        self._close(EndTry(end_label=end_lbl))
                        end_reachable = True

                # Finally body block
                if finally_b is not None:
                    self._switch(self._cfg.new_block(finally_lbl))
                    for s in finally_b:
                        self._emit_stmt(s)
                    if self._current.terminator is None:
                        self._close(EndFinally())

                # End block — continuation after try/except/finally
                self._switch(self._cfg.new_block(end_lbl))
                if not end_reachable:
                    # All branches returned early; end block is unreachable dead code.
                    # Add dummy Ret() to satisfy the "every block must have a terminator" invariant.
                    self._close(Ret())

            case TupleUnpack(source=src, targets=tgts):
                self._emit_expr(src)
                for i, (slot, is_arg, typ) in enumerate(tgts):
                    self._emit(StackInstr(op="DUP", type=src.type))
                    self._emit(StackInstr(op="PUSH_INT", type=INT, operand=i))
                    self._emit(StackInstr(op="PICKITEM", type=typ))
                    op2: StackOp = "STARG" if is_arg else "STLOC"
                    self._emit(StackInstr(op=op2, type=typ, operand=slot))
                self._emit(StackInstr(op="DROP", type=src.type))

            case SetField(obj=obj_expr, field_index=idx, value=val_expr, field_type=ft):
                self._emit_expr(obj_expr)
                self._emit(StackInstr(op="PUSH_INT", type=INT, operand=idx))
                self._emit_expr(val_expr)
                self._emit(StackInstr(op="SETITEM", type=ft))

            case MethodCallStmt(
                obj=obj_expr, compiled_name=cname, args=args, return_type=rt
            ):
                for arg in reversed(args):
                    self._emit_expr(arg)
                self._emit_expr(obj_expr)  # self is last pushed = LDARG 0
                self._emit(StackInstr(op="call", type=rt, operand=cname))
                if rt != NONE:
                    self._emit(StackInstr(op="DROP", type=NONE))

    def _emit_slice(
        self,
        v: Expr,
        start: Optional[Expr],
        stop: Optional[Expr],
        step: Optional[Expr],
        t: Type,
        step_slots: Optional[tuple[int, int, int, int, int, int, int, int]] = None,
    ) -> None:
        """Emit stack code for a slice expression ``v[start:stop:step]``.

        The no-step case maps directly to NeoVM's ``LEFT`` / ``RIGHT`` /
        ``SUBSTR`` opcodes.  The step case is lowered to two explicit loops: a
        counting pass to compute the output length, then a fill pass that writes
        bytes into a pre-allocated ``NEWBUFFER``.

        Args:
            v: The sequence being sliced.
            start: Optional lower-bound expression (inclusive).
            stop: Optional upper-bound expression (exclusive).
            step: Optional step expression; when present *step_slots* must also
                be provided.
            t: The element type of *v*, used to decide whether a ``CONVERT``
                is needed to restore the original type after slicing.
            step_slots: Eight pre-allocated local slot indices
                ``(slot_data, slot_start, slot_stop, slot_step, slot_count,
                slot_result, slot_write_idx, slot_read_idx)`` used by the
                stepped-slice loops.  Must not be ``None`` when *step* is not
                ``None``.
        """
        convert_op = 0x28 if isinstance(t, (BytesType, StrType)) else None
        if step is None:
            if start is None and stop is None:
                self._emit_expr(v)
            elif start is None:
                self._emit_expr(v)
                self._emit_expr(stop)
                self._emit(StackInstr(op="LEFT", type=BYTES))
                if convert_op is None:
                    self._emit(StackInstr(op="CONVERT", type=BYTEARRAY, operand=0x30))
            elif stop is None:
                self._emit_expr(v)
                self._emit(StackInstr(op="DUP", type=t))
                self._emit(StackInstr(op="SIZE", type=INT))
                self._emit_expr(start)
                self._emit(StackInstr(op="-", type=INT))
                self._emit(StackInstr(op="RIGHT", type=BYTES))
                if convert_op is None:
                    self._emit(StackInstr(op="CONVERT", type=BYTEARRAY, operand=0x30))
            else:
                self._emit_expr(v)
                self._emit_expr(start)
                self._emit(StackInstr(op="OVER", type=t))
                self._emit(StackInstr(op="SIZE", type=INT))
                self._emit_expr(stop)
                self._emit(StackInstr(op="min", type=INT))
                self._emit(StackInstr(op="OVER", type=INT))
                self._emit(StackInstr(op="-", type=INT))
                self._emit(StackInstr(op="SUBSTR", type=BYTES))
                if convert_op is None:
                    self._emit(StackInstr(op="CONVERT", type=BYTEARRAY, operand=0x30))
        else:
            assert (
                step_slots is not None
            ), "step_slots must be pre-allocated by HIRBuilder"
            (
                slot_data,
                slot_start,
                slot_stop,
                slot_step,
                slot_count,
                slot_result,
                slot_write_idx,
                slot_read_idx,
            ) = step_slots

            def _ld(slot: int, tp: Type) -> StackInstr:
                return StackInstr(op="LDLOC", type=tp, operand=slot)

            def _st(slot: int, tp: Type) -> StackInstr:
                return StackInstr(op="STLOC", type=tp, operand=slot)

            self._emit_expr(v)
            self._emit(_st(slot_data, t))
            if start is not None:
                self._emit_expr(start)
            else:
                self._emit(StackInstr(op="PUSH_INT", type=INT, operand=0))
            self._emit(_st(slot_start, INT))
            if stop is not None:
                self._emit_expr(stop)
            else:
                self._emit(_ld(slot_data, t))
                self._emit(StackInstr(op="SIZE", type=INT))
            self._emit(_ld(slot_data, t))
            self._emit(StackInstr(op="SIZE", type=INT))
            self._emit(StackInstr(op="min", type=INT))
            self._emit(_st(slot_stop, INT))
            self._emit_expr(step)
            self._emit(_st(slot_step, INT))
            self._emit(StackInstr(op="PUSH_INT", type=INT, operand=0))
            self._emit(_st(slot_count, INT))
            self._emit(_ld(slot_start, INT))
            self._emit(_st(slot_read_idx, INT))

            cnt_hdr = self._cfg.new_block(self._fresh("cnt_hdr"))
            cnt_body = self._cfg.new_block(self._fresh("cnt_body"))
            cnt_exit = self._cfg.new_block(self._fresh("cnt_exit"))
            fill_hdr = self._cfg.new_block(self._fresh("fill_hdr"))
            fill_body = self._cfg.new_block(self._fresh("fill_body"))
            fill_exit = self._cfg.new_block(self._fresh("fill_exit"))

            self._close(Jump(target=cnt_hdr.label))

            self._switch(cnt_hdr)
            self._emit(_ld(slot_read_idx, INT))
            self._emit(_ld(slot_stop, INT))
            self._emit(StackInstr(op="<", type=BOOL))
            self._close(
                CondJump(true_target=cnt_body.label, false_target=cnt_exit.label)
            )

            self._switch(cnt_body)
            self._emit(_ld(slot_count, INT))
            self._emit(StackInstr(op="PUSH_INT", type=INT, operand=1))
            self._emit(StackInstr(op="+", type=INT))
            self._emit(_st(slot_count, INT))
            self._emit(_ld(slot_read_idx, INT))
            self._emit(_ld(slot_step, INT))
            self._emit(StackInstr(op="+", type=INT))
            self._emit(_st(slot_read_idx, INT))
            self._close(Jump(target=cnt_hdr.label))

            self._switch(cnt_exit)
            self._emit(_ld(slot_count, INT))
            self._emit(StackInstr(op="NEWBUFFER", type=BYTEARRAY))
            self._emit(_st(slot_result, BYTEARRAY))
            self._emit(StackInstr(op="PUSH_INT", type=INT, operand=0))
            self._emit(_st(slot_write_idx, INT))
            self._emit(_ld(slot_start, INT))
            self._emit(_st(slot_read_idx, INT))
            self._close(Jump(target=fill_hdr.label))

            self._switch(fill_hdr)
            self._emit(_ld(slot_read_idx, INT))
            self._emit(_ld(slot_stop, INT))
            self._emit(StackInstr(op="<", type=BOOL))
            self._close(
                CondJump(true_target=fill_body.label, false_target=fill_exit.label)
            )

            self._switch(fill_body)
            self._emit(_ld(slot_result, BYTEARRAY))
            self._emit(_ld(slot_write_idx, INT))
            self._emit(_ld(slot_data, t))
            self._emit(_ld(slot_read_idx, INT))
            self._emit(StackInstr(op="PICKITEM", type=INT))
            self._emit(StackInstr(op="SETITEM", type=BYTEARRAY))
            self._emit(_ld(slot_write_idx, INT))
            self._emit(StackInstr(op="PUSH_INT", type=INT, operand=1))
            self._emit(StackInstr(op="+", type=INT))
            self._emit(_st(slot_write_idx, INT))
            self._emit(_ld(slot_read_idx, INT))
            self._emit(_ld(slot_step, INT))
            self._emit(StackInstr(op="+", type=INT))
            self._emit(_st(slot_read_idx, INT))
            self._close(Jump(target=fill_hdr.label))

            self._switch(fill_exit)
            self._emit(_ld(slot_result, BYTEARRAY))
            if convert_op is not None:
                self._emit(StackInstr(op="CONVERT", type=t, operand=convert_op))

    def _emit_expr(self, expr: Expr) -> None:
        """Lower a single HIR expression, leaving its result on the NeoVM stack.

        Dispatches on the concrete ``Expr`` subtype via a structural ``match``
        statement.  After this call the evaluation stack has grown by exactly
        one item whose value corresponds to *expr*.

        Args:
            expr: The HIR expression to compile.
        """
        match expr:
            case IntLiteral(value=v):
                self._emit(StackInstr(op="PUSH_INT", type=INT, operand=v))
            case BoolLiteral(value=v):
                self._emit(StackInstr(op="PUSH_BOOL", type=BOOL, operand=v))
            case LocalLoad(name=name, type=t):
                arg_names = [n for n, _ in self._fn.args]
                if name in arg_names:
                    idx = arg_names.index(name)
                    self._emit(StackInstr(op="LDARG", type=t, operand=idx))
                else:
                    slot, _ = self._fn.locals[name]
                    self._emit(StackInstr(op="LDLOC", type=t, operand=slot))
            case BinOp(left=l, op="cat", right=r, type=t) if isinstance(
                t, BytearrayType
            ):
                self._emit_expr(l)
                self._emit_expr(r)
                self._emit(StackInstr(op="cat", type=BYTES))
                self._emit(StackInstr(op="CONVERT", type=BYTEARRAY, operand=0x30))
            case BinOp(left=l, op=op, right=r, type=t):
                self._emit_expr(l)
                self._emit_expr(r)
                self._emit(StackInstr(op=op, type=t))
            case Compare(left=l, op=op, right=r):
                self._emit_expr(l)
                self._emit_expr(r)
                self._emit(StackInstr(op=op, type=BOOL))
            case BoolAnd(left=l, right=r):
                # Short-circuit: if left is False, skip right and push False.
                rhs_lbl = self._fresh("and_rhs")
                sc_false_lbl = self._fresh("and_false")
                join_lbl = self._fresh("and_join")
                self._emit_expr(l)
                self._close(CondJump(true_target=rhs_lbl, false_target=sc_false_lbl))
                rhs_bb = self._cfg.new_block(rhs_lbl)
                self._switch(rhs_bb)
                self._emit_expr(r)
                self._close(Jump(target=join_lbl))
                sc_false_bb = self._cfg.new_block(sc_false_lbl)
                self._switch(sc_false_bb)
                self._emit(StackInstr(op="PUSH_BOOL", type=BOOL, operand=False))
                self._close(Jump(target=join_lbl))
                join_bb = self._cfg.new_block(join_lbl)
                self._switch(join_bb)
            case BoolOr(left=l, right=r):
                # Short-circuit: if left is True, skip right and push True.
                rhs_lbl = self._fresh("or_rhs")
                sc_true_lbl = self._fresh("or_true")
                join_lbl = self._fresh("or_join")
                self._emit_expr(l)
                self._close(CondJump(true_target=sc_true_lbl, false_target=rhs_lbl))
                sc_true_bb = self._cfg.new_block(sc_true_lbl)
                self._switch(sc_true_bb)
                self._emit(StackInstr(op="PUSH_BOOL", type=BOOL, operand=True))
                self._close(Jump(target=join_lbl))
                rhs_bb = self._cfg.new_block(rhs_lbl)
                self._switch(rhs_bb)
                self._emit_expr(r)
                self._close(Jump(target=join_lbl))
                join_bb = self._cfg.new_block(join_lbl)
                self._switch(join_bb)
            case IfExp(condition=cond, then_expr=then_e, else_expr=else_e):
                then_lbl = self._fresh("tern_then")
                else_lbl = self._fresh("tern_else")
                join_lbl = self._fresh("tern_join")

                self._emit_expr(cond)
                self._close(CondJump(true_target=then_lbl, false_target=else_lbl))

                then_bb = self._cfg.new_block(then_lbl)
                self._switch(then_bb)
                self._emit_expr(then_e)
                self._close(Jump(target=join_lbl))

                else_bb = self._cfg.new_block(else_lbl)
                self._switch(else_bb)
                self._emit_expr(else_e)
                self._close(Jump(target=join_lbl))

                join_bb = self._cfg.new_block(join_lbl)
                self._switch(join_bb)
            case Not(operand=operand):
                self._emit_expr(operand)
                self._emit(StackInstr(op="not", type=BOOL))
            case Negate(operand=operand):
                self._emit_expr(operand)
                self._emit(StackInstr(op="negate", type=INT))
            case Invert(operand=operand):
                self._emit_expr(operand)
                self._emit(StackInstr(op="invert", type=INT))
            case Abs(arg=arg):
                self._emit_expr(arg)
                self._emit(StackInstr(op="abs", type=INT))
            case Min(left=l, right=r):
                self._emit_expr(l)
                self._emit_expr(r)
                self._emit(StackInstr(op="min", type=INT))
            case Max(left=l, right=r):
                self._emit_expr(l)
                self._emit_expr(r)
                self._emit(StackInstr(op="max", type=INT))
            case Call(name=name, args=args, type=t):
                # Push args right-to-left so INITSLOT's first pop → LDARG 0
                for arg in reversed(args):
                    self._emit_expr(arg)
                self._emit(StackInstr(op="call", type=t, operand=name))
            case StringLiteral(value=v):
                self._emit(StackInstr(op="PUSH_STR", type=STR, operand=v))
            case BytesLiteral(value=v):
                self._emit(StackInstr(op="PUSH_BYTES", type=BYTES, operand=v))
            case NewBuffer(size=size):
                self._emit_expr(size)
                self._emit(StackInstr(op="NEWBUFFER", type=BYTEARRAY))
            case Len(arg=arg):
                self._emit_expr(arg)
                self._emit(StackInstr(op="SIZE", type=INT))
            case SyscallCall() as sc_call:
                assert not sc_call.is_stmt
                for i in sc_call.push_order:
                    self._emit_expr(sc_call.args[i])
                self._emit(
                    StackInstr(op="syscall", type=sc_call.type, operand=sc_call.hash)
                )
            case BytesFromHex(arg=arg):
                self._emit_expr(arg)
                self._emit(
                    StackInstr(
                        op="contract_call",
                        type=BYTES,
                        operand=(_STDLIB_HASH, "hexDecode", 1, 15),
                    )
                )
            case BytesHex(arg=arg):
                self._emit_expr(arg)
                self._emit(
                    StackInstr(
                        op="contract_call",
                        type=STR,
                        operand=(_STDLIB_HASH, "hexEncode", 1, 15),
                    )
                )
            case IntToBytes(value=val_expr, length=len_expr, byteorder=bo, signed=sg):
                # Push args right-to-left: length (arg[1]) first, value (arg[0]) last
                self._emit_expr(len_expr)
                self._emit_expr(val_expr)
                helper = (
                    f"__to_bytes_{'little' if bo == 'little' else 'big'}"
                    f"_{'signed' if sg else 'unsigned'}"
                )
                self._emit(StackInstr(op="call", type=BYTES, operand=helper))
            case IntFromBytes(arg=arg_expr, byteorder=bo, signed=sg):
                # NeoVM CONVERT 0x21 interprets bytes as little-endian signed BigInteger.
                # Big-endian: convert to Buffer, DUP, REVERSEITEMS (in-place, pops dup) → LE.
                # Unsigned: append \x00 (high byte in LE) so the high bit is always 0.
                self._emit_expr(arg_expr)
                if bo == "big":
                    self._emit(StackInstr(op="CONVERT", type=BYTEARRAY, operand=0x30))
                    self._emit(StackInstr(op="DUP", type=BYTEARRAY))
                    self._emit(StackInstr(op="REVERSEITEMS", type=BYTEARRAY))
                if not sg:
                    self._emit(StackInstr(op="PUSH_BYTES", type=BYTES, operand=b"\x00"))
                    self._emit(StackInstr(op="cat", type=BYTES))
                self._emit(StackInstr(op="CONVERT", type=INT, operand=0x21))
            case Atoi(arg=arg, base=base):
                # push base first → items[1]; push arg last → items[0] after PACK
                self._emit_expr(base)
                self._emit_expr(arg)
                self._emit(
                    StackInstr(
                        op="contract_call",
                        type=INT,
                        operand=(_STDLIB_HASH, "atoi", 2, 15),
                    )
                )
            case Itoa(arg=arg, base=base):
                # push base first → items[1]; push arg last → items[0] after PACK
                self._emit_expr(base)
                self._emit_expr(arg)
                self._emit(
                    StackInstr(
                        op="contract_call",
                        type=STR,
                        operand=(_STDLIB_HASH, "itoa", 2, 15),
                    )
                )
            case StrSplit(arg=arg, sep=sep, remove_empty=remove_empty):
                # push removeEmptyEntries → items[2]; sep → items[1]; input → items[0] after PACK
                self._emit(StackInstr(op="PUSH_BOOL", type=BOOL, operand=remove_empty))
                self._emit_expr(sep)
                self._emit_expr(arg)
                self._emit(
                    StackInstr(
                        op="contract_call",
                        type=LIST_STR,
                        operand=(_STDLIB_HASH, "stringSplit", 3, 15),
                    )
                )
            case ContractCall(
                contract_hash=chash, method=method, args=args, type=t, call_flags=cf
            ) as cc:
                assert not cc.is_stmt
                # Push args in reverse order so items[0]=first arg after PACK
                for arg in reversed(args):
                    self._emit_expr(arg)
                self._emit(
                    StackInstr(
                        op="contract_call",
                        type=t,
                        operand=(chash, method, len(args), cf),
                    )
                )
            case DynamicContractCall(
                script_hash=sh, method=m, args=a, call_flags=cf, type=t
            ) as dcc:
                assert not dcc.is_stmt
                # Stack layout for System.Contract.Call (push bottom→top):
                # args (Array), call_flags (Integer), method (ByteString), script_hash (ByteString)
                self._emit_expr(a)
                self._emit_expr(cf)
                self._emit_expr(m)
                self._emit_expr(sh)
                self._emit(
                    StackInstr(op="syscall", type=t, operand=_SYSCALL_CONTRACT_CALL)
                )
            case TypeConvert(arg=arg, type=t):
                self._emit_expr(arg)
                if isinstance(t, (UInt160Type, UInt256Type, ECPointType)):
                    pass  # input is already a ByteString; no CONVERT needed
                else:
                    if isinstance(t, IntType):
                        tag = 0x21
                    elif isinstance(t, BoolType):
                        tag = 0x20
                    elif isinstance(t, (StrType, BytesType)):
                        tag = 0x28
                    elif isinstance(t, BytearrayType):
                        tag = 0x30
                    else:
                        raise AssertionError(f"TypeConvert: unexpected target type {t}")
                    self._emit(StackInstr(op="CONVERT", type=t, operand=tag))
            case Cast(arg=arg):
                self._emit_expr(arg)  # no-op at runtime; type declared on the HIR node
            case Index(value=v, index=idx):
                self._emit_expr(v)
                self._emit_expr(idx)
                self._emit(StackInstr(op="PICKITEM", type=INT))
            case StrIndex(value=v, index=idx):
                self._emit_expr(v)
                self._emit_expr(idx)
                self._emit(StackInstr(op="PUSH_INT", type=INT, operand=1))
                self._emit(StackInstr(op="SUBSTR", type=STR))
            case Slice(value=v, start=start, stop=stop, step=step, type=t) as s:
                self._emit_slice(v, start, stop, step, t, s.step_slots)

            case ListLiteral(elements=elts, type=t):
                self._emit(StackInstr(op="NEWARRAY0", type=t))
                for el in elts:
                    self._emit(StackInstr(op="DUP", type=t))
                    self._emit_expr(el)
                    self._emit(StackInstr(op="APPEND", type=t))

            case TupleLiteral(elements=elts, type=t):
                self._emit(StackInstr(op="NEWARRAY0", type=t))
                for el in elts:
                    self._emit(StackInstr(op="DUP", type=t))
                    self._emit_expr(el)
                    self._emit(StackInstr(op="APPEND", type=t))

            case DictLiteral(pairs=pairs, type=t):
                self._emit(StackInstr(op="NEWMAP", type=t))
                for k_expr, v_expr in pairs:
                    self._emit(StackInstr(op="DUP", type=t))
                    self._emit_expr(k_expr)
                    self._emit_expr(v_expr)
                    self._emit(StackInstr(op="SETITEM", type=t))

            case HasKey(container=ctr, key=key):
                self._emit_expr(ctr)
                self._emit_expr(key)
                self._emit(StackInstr(op="HASKEY", type=BOOL))

            case DictKeys(container=ctr, type=t):
                self._emit_expr(ctr)
                self._emit(StackInstr(op="KEYS", type=t))

            case DictValues(container=ctr, type=t):
                self._emit_expr(ctr)
                self._emit(StackInstr(op="VALUES", type=t))
            case StaticLoad(slot=slot, type=t):
                self._emit(StackInstr(op="LDSFLD", type=t, operand=slot))
            case NoneLiteral():
                self._emit(StackInstr(op="PUSHNULL", type=NONE))
            case IsNone(operand=operand, negated=negated):
                self._emit_expr(operand)
                self._emit(StackInstr(op="ISNULL", type=BOOL))
                if negated:
                    self._emit(StackInstr(op="not", type=BOOL))
            case IsType(operand=operand, tag=tag):
                self._emit_expr(operand)
                self._emit(StackInstr(op="ISTYPE", type=BOOL, operand=tag))

            case GetField(obj=obj_expr, field_index=idx, type=t):
                self._emit_expr(obj_expr)
                self._emit(StackInstr(op="PUSH_INT", type=INT, operand=idx))
                self._emit(StackInstr(op="PICKITEM", type=t))

            case NewInstance(class_name=cname, args=user_args, type=t) as ni:
                info = self._class_registry[cname]
                assert ni.temp_slot >= 0, "NewInstance.temp_slot must be pre-allocated"
                slot = ni.temp_slot
                self._emit(
                    StackInstr(op="PUSH_INT", type=INT, operand=info.total_fields)
                )
                self._emit(StackInstr(op="NEWARRAY", type=t))
                self._emit(StackInstr(op="STLOC", type=t, operand=slot))
                if "__init__" in info.methods:
                    init_name = f"{cname}___init__"
                    for arg in reversed(user_args):
                        self._emit_expr(arg)
                    self._emit(StackInstr(op="LDLOC", type=t, operand=slot))
                    self._emit(StackInstr(op="call", type=NONE, operand=init_name))
                self._emit(StackInstr(op="LDLOC", type=t, operand=slot))

            case MethodCall(obj=obj_expr, compiled_name=cname, args=user_args, type=t):
                for arg in reversed(user_args):
                    self._emit_expr(arg)
                self._emit_expr(obj_expr)  # self is last pushed = LDARG 0
                self._emit(StackInstr(op="call", type=t, operand=cname))
