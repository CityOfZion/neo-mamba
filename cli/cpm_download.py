import argparse
import sys
import platform
import subprocess
import shlex
import re
from neo_cpm import get_binary_path

def cpm_download(_: argparse.Namespace) -> int:
    is_posix = platform.system().lower() != "windows"

    try:
        cmd = f"{get_binary_path()} run"
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
