import sys
import os
from neo3.compiler import compile_to_nef, TypecheckError


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: neo3-compile <file.py>", file=sys.stderr)
        sys.exit(1)

    source_path = sys.argv[1]
    if not os.path.isfile(source_path):
        print(f"neo3-compile: file not found: {source_path}", file=sys.stderr)
        sys.exit(1)

    abs_src = os.path.abspath(source_path)
    output_path = os.path.splitext(abs_src)[0] + ".nef"

    with open(abs_src) as f:
        source = f.read()

    try:
        compile_to_nef(source, output_path)
    except TypecheckError as e:
        print(f"neo3-compile: {e}", file=sys.stderr)
        sys.exit(1)

    stem = os.path.splitext(os.path.basename(abs_src))[0]
    print(f"{stem}.nef")
    print(f"{stem}.manifest.json")


if __name__ == "__main__":
    main()
