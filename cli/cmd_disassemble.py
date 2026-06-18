import sys
import base64
import argparse
from neo3.compiler.disassembler import disassemble


def disassemble_bytecode(args: argparse.Namespace) -> int:
    try:
        if args.nef:
            from neo3.contracts.nef import NEF
            nef = NEF.from_file(args.input)
            bytecode = nef.script
        elif args.base64:
            bytecode = base64.b64decode(args.input, validate=True)
        else:
            bytecode = bytes.fromhex(args.input)
    except Exception as e:
        print(f"neo3: {e}", file=sys.stderr)
        return 1

    print(disassemble(bytecode))
    return 0
