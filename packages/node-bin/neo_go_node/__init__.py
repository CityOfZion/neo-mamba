from pathlib import Path
import stat
import platform


def get_binary_path() -> Path:
    suffix = ".exe" if platform.system() == "Windows" else ""
    path = Path(__file__).parent / "bin" / f"neogo{suffix}"
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path
