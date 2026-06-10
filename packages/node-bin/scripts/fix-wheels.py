"""
This script is a helper script to correctly rename wheels.

The CI setup will fetch the platform specific neo-go executable and place it in the correct directory where it will be
picked up when packaging. `python -m build` creates a universal wheel and that needs to be fixed to include the correct
platform tag before uploading to PyPi. This cannot be done by simply renaming the file, it also does internal changes in
the wheel hence this script.
"""

import sys
import pathlib
import sysconfig
import platform
import subprocess


def main(wheel_dir):
    platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    # PyPi rejects non-manylinux wheels. Change the tag according to PEP-513
    if platform_tag.startswith("linux"):
        platform_tag = platform_tag.replace("linux", "manylinux1")
    if platform_tag.startswith("macosx"):
        if platform.machine().lower() == "x86_64":
            platform_tag = platform_tag.replace("universal2", "x86_64")
    for f in pathlib.Path(wheel_dir).glob("**/*"):
        if f.name.endswith("any.whl"):
            subprocess.run([
                sys.executable, "-m", "wheel", "tags",
                "--platform-tag", platform_tag,
                "--remove",
                str(f.absolute())
            ], check=True)


if __name__ == "__main__":
    main(sys.argv[1])
