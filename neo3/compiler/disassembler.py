from __future__ import annotations


def disassemble(bytecode: bytes) -> str:
    """Return a human-readable disassembly of NeoVM3 bytecode.

    Format matches the reference tool:
        INDEX    OPCODE       PARAMETER
        0        INITSLOT     0 local, 2 arg    <<
        3        LDARG        0 (00)
    """
    _CONVERT_TYPES = {
        0x20: "Boolean",
        0x21: "Integer",
        0x28: "ByteString",
        0x30: "Buffer",
    }

    # opcodes with no operand
    _NO_OP = {
        0x08: "PUSHT",
        0x09: "PUSHF",
        0x0B: "PUSHNULL",
        0x39: "ASSERT",
        0x3A: "THROW",
        0x40: "RET",
        0x45: "DROP",
        0x4A: "DUP",
        0x4B: "OVER",
        0x8B: "CAT",
        0x8C: "SUBSTR",
        0x8D: "LEFT",
        0x8E: "RIGHT",
        0x88: "NEWBUFFER",
        0x90: "INVERT",
        0x91: "AND",
        0x92: "OR",
        0x93: "XOR",
        0x97: "EQUAL",
        0x98: "NOTEQUAL",
        0x9A: "ABS",
        0x9B: "NEGATE",
        0x9E: "ADD",
        0x9F: "SUB",
        0xA0: "MUL",
        0xA1: "DIV",
        0xA2: "MOD",
        0xA3: "POW",
        0xA8: "SHL",
        0xA9: "SHR",
        0xAA: "NOT",
        0xAB: "BOOLAND",
        0xAC: "BOOLOR",
        0xB5: "LT",
        0xB6: "LE",
        0xB7: "GT",
        0xB8: "GE",
        0xB9: "MIN",
        0xBA: "MAX",
        0xC2: "NEWARRAY0",
        0xC3: "NEWARRAY",
        0xC8: "NEWMAP",
        0xCA: "SIZE",
        0xCB: "HASKEY",
        0xCC: "KEYS",
        0xCD: "VALUES",
        0xCE: "PICKITEM",
        0xCF: "APPEND",
        0xD0: "SETITEM",
        0xD8: "ISNULL",
        0x3F: "ENDFINALLY",
        0xE1: "ASSERTMSG",
        0x50: "SWAP",
        0x99: "SIGN",
        0xD1: "REVERSEITEMS",
    }

    lines = ["INDEX    OPCODE       PARAMETER"]
    pc = 0
    first = True

    while pc < len(bytecode):
        idx = pc
        op = bytecode[pc]
        pc += 1

        if op in _NO_OP:
            param = ""
            name = _NO_OP[op]

        elif op == 0x00:  # PUSHINT8
            val = int.from_bytes(bytecode[pc : pc + 1], "little", signed=True)
            param = f"{val} ({bytecode[pc]:02x})"
            name = "PUSHINT8"
            pc += 1

        elif op == 0x01:  # PUSHINT16
            raw = bytecode[pc : pc + 2]
            val = int.from_bytes(raw, "little", signed=True)
            param = f"{val} ({raw.hex()})"
            name = "PUSHINT16"
            pc += 2

        elif op == 0x02:  # PUSHINT32
            raw = bytecode[pc : pc + 4]
            val = int.from_bytes(raw, "little", signed=True)
            param = f"{val} ({raw.hex()})"
            name = "PUSHINT32"
            pc += 4

        elif op == 0x03:  # PUSHINT64
            raw = bytecode[pc : pc + 8]
            val = int.from_bytes(raw, "little", signed=True)
            param = f"{val} ({raw.hex()})"
            name = "PUSHINT64"
            pc += 8

        elif op == 0x0C:  # PUSHDATA1
            length = bytecode[pc]
            pc += 1
            data = bytecode[pc : pc + length]
            pc += length
            param = f"{data.hex()} (len={length})"
            name = "PUSHDATA1"

        elif op == 0x0D:  # PUSHDATA2
            length = int.from_bytes(bytecode[pc : pc + 2], "little")
            pc += 2
            data = bytecode[pc : pc + length]
            pc += length
            param = f"{data.hex()} (len={length})"
            name = "PUSHDATA2"

        elif op == 0x0E:  # PUSHDATA4
            length = int.from_bytes(bytecode[pc : pc + 4], "little")
            pc += 4
            data = bytecode[pc : pc + length]
            pc += length
            param = f"{data.hex()} (len={length})"
            name = "PUSHDATA4"

        elif op in (
            0x23,
            0x25,
            0x27,
            0x35,
            0x3E,
        ):  # JMP_L, JMPIF_L, JMPIFNOT_L, CALL_L, ENDTRY_L
            name = {
                0x23: "JMP_L",
                0x25: "JMPIF_L",
                0x27: "JMPIFNOT_L",
                0x35: "CALL_L",
                0x3E: "ENDTRY_L",
            }[op]
            raw = bytecode[pc : pc + 4]
            pc += 4
            offset = int.from_bytes(raw, "little", signed=True)
            target = idx + offset
            param = f"{target} ({offset}/{raw.hex()})"

        elif op == 0x3C:  # TRY_L
            catch_raw = bytecode[pc : pc + 4]
            pc += 4
            finally_raw = bytecode[pc : pc + 4]
            pc += 4
            catch_off = int.from_bytes(catch_raw, "little", signed=True)
            finally_off = int.from_bytes(finally_raw, "little", signed=True)
            catch_target = idx + catch_off if catch_off != 0 else None
            finally_target = idx + finally_off if finally_off != 0 else None
            param = f"catch={catch_target} finally={finally_target}"
            name = "TRY_L"

        elif op == 0x56:  # INITSSLOT
            n = bytecode[pc]
            pc += 1
            param = f"{n} static"
            name = "INITSSLOT"

        elif op == 0x57:  # INITSLOT
            n_locals = bytecode[pc]
            pc += 1
            n_args = bytecode[pc]
            pc += 1
            param = f"{n_locals} local, {n_args} arg"
            name = "INITSLOT"

        elif op in (0x5F, 0x67):  # LDSFLD, STSFLD
            name = "LDSFLD" if op == 0x5F else "STSFLD"
            slot = bytecode[pc]
            pc += 1
            param = f"{slot} ({slot:02x})"

        elif op in (0x6F, 0x77, 0x7F, 0x87):  # LDLOC, STLOC, LDARG, STARG
            name = {0x6F: "LDLOC", 0x77: "STLOC", 0x7F: "LDARG", 0x87: "STARG"}[op]
            slot = bytecode[pc]
            pc += 1
            param = f"{slot} ({slot:02x})"

        elif op == 0xDB:  # CONVERT
            tag = bytecode[pc]
            pc += 1
            type_name = _CONVERT_TYPES.get(tag, f"0x{tag:02x}")
            param = f"{type_name} ({tag:02x})"
            name = "CONVERT"

        elif op == 0xD9:  # ISTYPE
            tag = bytecode[pc]
            pc += 1
            type_name = _CONVERT_TYPES.get(tag, f"0x{tag:02x}")
            param = f"{type_name} ({tag:02x})"
            name = "ISTYPE"

        else:
            name = f"0x{op:02x}"
            param = ""

        suffix = "    <<" if first else ""
        first = False
        lines.append(f"{idx:<9}{name:<13}{param}{suffix}")

    return "\n".join(lines)
