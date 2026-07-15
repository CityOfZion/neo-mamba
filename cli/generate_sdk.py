import argparse
import sys
import subprocess
import shlex
import platform
import re
from neo_cpm import get_binary_path

def generate_sdk(args: argparse.Namespace) -> int:
    is_posix = platform.system().lower() != "windows"
    sdk_type = "offchain" if args.off_chain else "onchain"

    try:
        cmd = f"{get_binary_path()} generate python -m {args.manifest} -t {sdk_type}"
        if args.c:
            cmd += f" -c {args.c}"
        result = subprocess.run(
            shlex.split(cmd, posix=is_posix),
            capture_output=True,
            text=True,
            check=False
        )
        m = re.search(r'msg="([^"]*)"', result.stdout)
        if m:
            print(m.group(1))

    except Exception as e:
        print(f"mamba: {e}", file=sys.stderr)
        return 1

    return 0