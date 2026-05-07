# Compiler Architecture

Compiles a typed Python subset to NeoVM3 bytecode for Neo smart contracts.

## Pipeline

```
Python source str
  → ast.parse()         stdlib AST
  → HIRBuilder          typed HIR tree       compiler/hir_builder.py
  → CFGBuilder          control-flow graph   compiler/cfg_builder.py
  → Linearizer          raw bytecode bytes   compiler/linearizer.py
```

Entry points: `compile_function(src)` → bytes · `compile_to_nef(src, path)` → NEF + manifest.
`_compile_full` drives the loop: resolves imports (AST merge), builds the class registry,
then runs HIR→CFG→Linearizer per function sharing one `Emitter` for inter-function `CALL_L` offsets.

---

## Module map

| File | Contents |
|---|---|
| `types.py` | Type classes (`IntType`…`UnionType`), singletons (`INT`, `BOOL`…), `TypecheckError`, `_type_of_folded` |
| `hir.py` | All HIR node dataclasses, `Expr`/`Stmt` unions, `HIRFunction`, `ClassInfo`/`FieldInfo`/`MethodInfo`, class-registry utilities (`_c3_mro`, `_merge_fields`), HIR-tree walkers |
| `hir_builder.py` | `HIRBuilder`, import/mangling machinery, decorator extractors, `_build_class_registry`, `_collect_module_statics` |
| `cfg.py` | `StackInstr`, CFG terminators, `BasicBlock`, `CFG`, `OpCode` enum |
| `cfg_builder.py` | `CFGBuilder` |
| `linearizer.py` | `Emitter`, `Linearizer`, `_emit_static_literal`, `_emit_to_bytes_*` helpers |
| `_constants.py` | Interop hashes, `_STDLIB_HASH`, `_FIND_OPTIONS_VALUES`, etc. |
| `__init__.py` | `_compile_full`, `compile_module/function/to_nef`, `_type_to_contract_param` |
| `disassembler.py` | `disassemble(bytecode) → str` |

---

## Phase 1 — HIRBuilder

**Receives:** `ast.FunctionDef`, optional `class_registry: dict[str, ClassInfo]`  
**Produces:** `HIRFunction(name, args, return_type, locals, body)`

`args: list[tuple[str, Type]]` — ordered arg pairs; slots are arg indices (LDARG/STARG).  
`locals: dict[str, tuple[int, Type]]` — non-arg locals only; slot is LDLOC/STLOC index.  
Args and locals are disjoint dicts; CFGBuilder checks both when resolving a name load.

**Key invariants:**
- Every `Expr` node carries `.type: Type`. No downstream phase makes type decisions.
- `fn.locals` is complete before `HIRBuilder.build()` returns. CFGBuilder never adds to it.
- `_pre_stmts: list[Stmt]` is empty at the top of each `_visit_stmts` iteration — asserted.
  Used to inject desugared setup statements (list/dict comprehensions, `list.insert`,
  step-slices) before the statement currently being processed.
- Dual-role nodes (`SyscallCall`, `ContractCall`, `DynamicContractCall`) carry
  `is_stmt: bool = False`. HIRBuilder sets it to `True` at all statement call sites.

**Non-obvious decisions:**
- `for i in range(n)` desugars to a `While` node in HIR; continues get the increment
  prepended by `_for_rewrite_continues` before the node is returned.
- Import bundling happens *before* this phase: `_resolve_imports` merges imported module
  ASTs into the compilation unit so HIRBuilder sees a single flat namespace.
- `str(bool)` emits a ternary `IfExp` (→ `"True"`/`"False"`), not `CONVERT` — NeoVM's
  CONVERT on a Boolean gives a ByteString of the raw byte, not the string `"True"`.

**What you'd still need to read from source:**
- `LocalStore.is_arg: bool` — HIRBuilder sets this when the assigned name is in `fn.args`
  (not `fn.locals`); CFGBuilder uses it to choose `STARG` vs `STLOC`.
- Method calling convention: args pushed right-to-left, `self` pushed last (becomes LDARG 0
  inside the method); enforced at every `MethodCall` emit site in HIRBuilder.
- Optional narrowing scope: `_check_narrowing_guard` is called by `_visit_stmts` after
  each `If` node; it only fires when the if-body always terminates and there is no else.

---

## Phase 2 — CFGBuilder

**Receives:** `HIRFunction`  
**Produces:** `CFG(entry, blocks: dict[str, BasicBlock])`

Each `BasicBlock` has `instructions: list[StackInstr]` and exactly one terminator
(`Ret`, `Jump`, `CondJump`, `EndTry`, or `EndFinally`).

`StackInstr.op` is a `StackOp` string literal (e.g. `"LDARG"`, `"PUSH_INT"`, `"+"`,
`"syscall"`) — **not** the `OpCode` enum. This deliberately decouples CFG topology from
the target ISA and lets the Linearizer choose exact encodings. Pseudo-ops like `"call"`,
`"syscall"`, `"contract_call"` each expand to multiple machine instructions.

**Key invariants:**
- Every block has exactly one terminator — asserted at block completion.
- `_emit_expr` asserts `not node.is_stmt`; `_emit_stmt` asserts `node.is_stmt` for the
  dual-role nodes. Catches HIR mis-routing immediately.
- `fn.locals` is read-only. The `_alloc_temp` slots for slice/insert temporaries are
  pre-populated by HIRBuilder.

**Non-obvious decisions:**
- `and`/`or` compile to conditional jump sequences (short-circuit), not BOOLAND/BOOLOR.
- `s[i]` on `str` emits `SUBSTR(s, i, 1)` returning a one-char `str`; `bytes[i]` uses
  PICKITEM returning an `int`. These are different HIR nodes: `StrIndex` vs `Index`.
- `//` and `%` use NeoVM's C# `BigInteger` truncation-toward-zero, diverging from
  Python's floor semantics for negative operands — documented, not fixed.

**What you'd still need to read from source:**
- `LocalLoad` resolution: CFGBuilder builds `arg_names = [n for n, _ in self._fn.args]`;
  if the name is in `arg_names` → `LDARG` with the list index; otherwise `LDLOC` with
  `fn.locals[name][0]`.
- Implicit `RET` for void functions: if the last block of a `-> None` function has no
  terminator, CFGBuilder appends a bare `Ret()`.
- DROP rule: `ContractCall`/`DynamicContractCall` as statements (`is_stmt=True`) emit an
  explicit `DROP` after the call; `SyscallCall` as a statement does not.
- `TRY_L` block ordering: try body → catch body → finally body → continuation must be
  emitted in this exact order; TRY_L offsets point forward into the stream.

---

## Phase 3 — Linearizer

**Receives:** `CFG`, `HIRFunction`, shared `Emitter`, shared `call_fixups` list  
**Produces:** bytes appended into `Emitter._buf`; inter-function call sites recorded in
`call_fixups` for a second patch pass after all function offsets are known.

Blocks are emitted in insertion order (the order CFGBuilder created them).
Fall-through optimisation: a `Jump` whose target is the immediately next block is
suppressed. All jumps use the 4-byte `_L` variants; offsets are relative to the start
of the jump instruction.

**Key invariants:**
- Two-pass resolution: emit a 4-byte zero placeholder, record `(placeholder_pos,
  jump_opcode_pos, label)` in `_fixups`, patch all after the function is emitted.
- `INITSLOT num_locals num_args` is emitted first; `num_locals = len(fn.locals)`,
  `num_args = len(fn.args)`. Omitted entirely if both are zero (illegal in NeoVM).
- `int.to_bytes` helpers (`__to_bytes_little_unsigned` etc.) are emitted once per variant
  after all user functions; `call_fixups` are patched in a final pass.

**What you'd still need to read from source:**
- `call_fixups` tuple layout: `(placeholder_pos, call_opcode_pos, fn_name)` — the offset
  is patched at `placeholder_pos`; `call_opcode_pos` is the start of the `CALL_L` instruction
  (jump offset = `fn_start − call_opcode_pos`).
- Jump offset base: offsets are relative to the **start of the jump instruction** (the opcode
  byte), not the operand byte — consistent across all `_L` variants.
- Pseudo-op expansion: `"call"` → `CALL_L` + 4-byte fixup entry; `"syscall"` → `SYSCALL`
  opcode + 4-byte interop hash; `"contract_call"` → push args count / method name / contract
  hash / call_flags + `SYSCALL _SYSCALL_CONTRACT_CALL`.

---

## End-to-end example

```python
def f(n: int) -> int:
    return n + 1
```

**AST:** `FunctionDef(name='f', args=[arg('n', Name('int'))], body=[Return(BinOp(Name('n'), Add, Constant(1)))])`

**HIR:** `HIRFunction(name='f', args=[('n', IntType())], return_type=IntType(), locals={}, body=[Return(BinOp(left=LocalLoad('n', IntType()), op='+', right=IntLiteral(1), type=IntType()))])`

**CFG (entry block):**
```
StackInstr(op='LDARG',     operand=0,    type=IntType())
StackInstr(op='PUSH_INT',  operand=1,    type=IntType())
StackInstr(op='+',         operand=None, type=IntType())
Ret()
```

**Bytecode:** `57 00 01  7F 00  00 01  9E  40` (9 bytes)
```
0   INITSLOT   0 local, 1 arg
3   LDARG      0
5   PUSHINT8   1
7   ADD
8   RET
```

---

## Intentionally deferred

- **Short slot opcodes** (`LDLOC0`–`LDLOC6` etc.): would shrink output; not emitted. Marked "future optimisation".
- **Closures / nested functions**: design in `memory/reference_closure_plan.md`
  (PUSHA/CALLA); deferred — classes don't need them.
- **Peephole / dead-code elimination**: structural CFG fixes preferred; no pass planned.
