import sys
import argparse
from pathlib import Path
from neo3.compiler import TypecheckError, compile_to_nef


def compile_contract(args: argparse.Namespace) -> int:
    src = Path(args.input_file).resolve()

    if not src.is_file():
        print(f"neo3: file not found: {src}", file=sys.stderr)
        return 1

    try:
        compile_to_nef(src)
    except TypecheckError as e:
        print(f"neo3: {e}", file=sys.stderr)
        return 1

    print(f"Created {src.stem}.nef")
    print(f"Created {src.stem}.manifest.json")
    return 0
