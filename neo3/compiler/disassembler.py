from neo3.vm import Syscalls, OpCode


def disassemble(bytecode: bytes) -> str:
    """Return a human-readable disassembly of NeoVM3 bytecode.

    Format matches the reference tool:
        INDEX    OPCODE       PARAMETER
        0        INITSLOT     0 local, 2 arg    <<
        3        LDARG        0 (00)
    """
    _STACK_ITEM_TYPE = {
        0x00: "Any",
        0x10: "Pointer",
        0x20: "Boolean",
        0x21: "Integer",
        0x28: "ByteString",
        0x30: "Buffer",
        0x40: "Array",
        0x41: "Struct",
        0x48: "Map",
    }

    _SHORT_JUMP = {
        0x22: "JMP",
        0x24: "JMPIF",
        0x26: "JMPIFNOT",
        0x28: "JMPEQ",
        0x2A: "JMPNE",
        0x2C: "JMPGT",
        0x2E: "JMPGE",
        0x30: "JMPLT",
        0x32: "JMPLE",
        0x34: "CALL",
        0x3D: "ENDTRY",
    }

    _LONG_JUMP = {
        0x23: "JMP_L",
        0x25: "JMPIF_L",
        0x27: "JMPIFNOT_L",
        0x29: "JMPEQ_L",
        0x2B: "JMPNE_L",
        0x2D: "JMPGT_L",
        0x2F: "JMPGE_L",
        0x31: "JMPLT_L",
        0x33: "JMPLE_L",
        0x35: "CALL_L",
        0x3E: "ENDTRY_L",
    }

    lines = ["INDEX    OPCODE       PARAMETER"]
    pc = 0
    first = True

    while pc < len(bytecode):
        idx = pc
        op = bytecode[pc]
        pc += 1

        if op == OpCode.PUSHINT8:
            val = int.from_bytes(bytecode[pc : pc + 1], "little", signed=True)
            param = f"{val} ({bytecode[pc]:02x})"
            name = OpCode.PUSHINT8.name
            pc += 1

        elif op == OpCode.PUSHINT16:
            raw = bytecode[pc : pc + 2]
            val = int.from_bytes(raw, "little", signed=True)
            param = f"{val} ({raw.hex()})"
            name = OpCode.PUSHINT16.name
            pc += 2

        elif op == OpCode.PUSHINT32:
            raw = bytecode[pc : pc + 4]
            val = int.from_bytes(raw, "little", signed=True)
            param = f"{val} ({raw.hex()})"
            name = OpCode.PUSHINT32.name
            pc += 4

        elif op == OpCode.PUSHINT64:
            raw = bytecode[pc : pc + 8]
            val = int.from_bytes(raw, "little", signed=True)
            param = f"{val} ({raw.hex()})"
            name = OpCode.PUSHINT64.name
            pc += 8

        elif op == OpCode.PUSHINT128:
            raw = bytecode[pc : pc + 16]
            val = int.from_bytes(raw, "little", signed=True)
            param = f"{val} ({raw.hex()})"
            name = OpCode.PUSHINT128.name
            pc += 16

        elif op == OpCode.PUSHINT256:
            raw = bytecode[pc : pc + 32]
            val = int.from_bytes(raw, "little", signed=True)
            param = f"{val} ({raw.hex()})"
            name = OpCode.PUSHINT256.name
            pc += 32

        elif op == OpCode.PUSHA:
            raw = bytecode[pc : pc + 4]
            pc += 4
            offset = int.from_bytes(raw, "little", signed=True)
            target = idx + offset
            param = f"{target} ({offset}/{raw.hex()})"
            name = OpCode.PUSHA.name

        elif op == OpCode.PUSHDATA1:
            length = bytecode[pc]
            pc += 1
            data = bytecode[pc : pc + length]
            pc += length
            param = f"{data.hex()} (len={length})"
            name = OpCode.PUSHDATA1.name

        elif op == OpCode.PUSHDATA2:
            length = int.from_bytes(bytecode[pc : pc + 2], "little")
            pc += 2
            data = bytecode[pc : pc + length]
            pc += length
            param = f"{data.hex()} (len={length})"
            name = OpCode.PUSHDATA2.name

        elif op == OpCode.PUSHDATA4:
            length = int.from_bytes(bytecode[pc : pc + 4], "little")
            pc += 4
            data = bytecode[pc : pc + length]
            pc += length
            param = f"{data.hex()} (len={length})"
            name = OpCode.PUSHDATA4.name

        elif op in _SHORT_JUMP:
            name = _SHORT_JUMP[op]
            raw = bytecode[pc : pc + 1]
            pc += 1
            offset = int.from_bytes(raw, "little", signed=True)
            target = idx + offset
            param = f"{target} ({offset}/{raw.hex()})"

        elif op in _LONG_JUMP:
            name = _LONG_JUMP[op]
            raw = bytecode[pc : pc + 4]
            pc += 4
            offset = int.from_bytes(raw, "little", signed=True)
            target = idx + offset
            param = f"{target} ({offset}/{raw.hex()})"

        elif op == OpCode.CALLT:
            token = int.from_bytes(bytecode[pc : pc + 2], "little")
            pc += 2
            param = f"{token} ({token:04x})"
            name = OpCode.CALLT.name

        elif op == OpCode.TRY:
            catch_raw = bytecode[pc : pc + 1]
            pc += 1
            finally_raw = bytecode[pc : pc + 1]
            pc += 1
            catch_off = int.from_bytes(catch_raw, "little", signed=True)
            finally_off = int.from_bytes(finally_raw, "little", signed=True)
            catch_target = idx + catch_off if catch_off != 0 else None
            finally_target = idx + finally_off if finally_off != 0 else None
            param = f"catch={catch_target} finally={finally_target}"
            name = OpCode.TRY.name

        elif op == OpCode.TRY_L:
            catch_raw = bytecode[pc : pc + 4]
            pc += 4
            finally_raw = bytecode[pc : pc + 4]
            pc += 4
            catch_off = int.from_bytes(catch_raw, "little", signed=True)
            finally_off = int.from_bytes(finally_raw, "little", signed=True)
            catch_target = idx + catch_off if catch_off != 0 else None
            finally_target = idx + finally_off if finally_off != 0 else None
            param = f"catch={catch_target} finally={finally_target}"
            name = OpCode.TRY_L.name

        elif op == OpCode.SYSCALL:
            raw = bytecode[pc : pc + 4]
            pc += 4
            h = int.from_bytes(raw, "little")
            syscall_name = Syscalls.get_by_number(h)
            param = f"{syscall_name}"
            name = OpCode.SYSCALL.name

        elif op == OpCode.INITSSLOT:
            n = bytecode[pc]
            pc += 1
            param = f"{n} static"
            name = OpCode.INITSSLOT.name

        elif op == OpCode.INITSLOT:
            n_locals = bytecode[pc]
            pc += 1
            n_args = bytecode[pc]
            pc += 1
            param = f"{n_locals} local, {n_args} arg"
            name = OpCode.INITSLOT.name

        elif op in (OpCode.LDSFLD, OpCode.STSFLD):
            name = OpCode.LDSFLD.name if op == OpCode.LDSFLD else OpCode.STSFLD.name
            slot = bytecode[pc]
            pc += 1
            param = f"{slot} ({slot:02x})"

        elif op in (OpCode.LDLOC, OpCode.STLOC, OpCode.LDARG, OpCode.STARG):
            name = OpCode(op).name
            slot = bytecode[pc]
            pc += 1
            param = f"{slot} ({slot:02x})"

        elif op == OpCode.NEWARRAY_T:
            tag = bytecode[pc]
            pc += 1
            type_name = _STACK_ITEM_TYPE.get(tag, f"0x{tag:02x}")
            param = f"{type_name} ({tag:02x})"
            name = OpCode.NEWARRAY_T.name

        elif op == OpCode.ISTYPE:
            tag = bytecode[pc]
            pc += 1
            type_name = _STACK_ITEM_TYPE.get(tag, f"0x{tag:02x}")
            param = f"{type_name} ({tag:02x})"
            name = OpCode.ISTYPE.name

        elif op == OpCode.CONVERT:
            tag = bytecode[pc]
            pc += 1
            type_name = _STACK_ITEM_TYPE.get(tag, f"0x{tag:02x}")
            param = f"{type_name} ({tag:02x})"
            name = OpCode.CONVERT.name

        else:
            param = ""
            try:
                name = OpCode(op).name
            except ValueError:
                name = f"0x{op:02x}"

        suffix = "    <<" if first else ""
        first = False
        lines.append(f"{idx:<9}{name:<13}{param}{suffix}")

    return "\n".join(lines)
