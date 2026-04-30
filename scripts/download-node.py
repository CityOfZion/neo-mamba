import logging
import requests
import platform
import os
import stat
import pathlib
from tomlkit import parse
import os

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_umask():
    umask = os.umask(0)
    os.umask(umask)
    return umask


def chmod_plus_x(path):
    os.chmod(
        path,
        os.stat(path).st_mode
        | ((stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) & ~get_umask()),
    )


def main():
    with open("../pyproject.toml") as f:
        doc = parse(f.read())
        target_tag = doc["tool"]["neogo"]["tag"]

        headers = None
        token = os.getenv("GITHUB_TOKEN")
        if token is not None:
            headers = {"authorization": f"Bearer {token}"}

        r = requests.get(
            "https://api.github.com/repos/nspcc-dev/neo-go/releases",
            headers=headers,
        )

        if r.status_code != 200:
            r2 = requests.get("https://api.github.com/rate_limit", headers=headers)
            raise Exception(
                f"we probably exceeded the rate limit. Rate limit info: {r2.json()}"
            )
        for release in r.json():
            if release["tag_name"] != target_tag:
                continue

            if platform.machine().lower() in ["x86_64", "amd64"]:
                arch = "amd64"
            else:
                arch = "arm64"
            system = platform.system().lower()
            asset_needle = f"neo-go-{system}-{arch}"
            if system == "windows":
                asset_needle += ".exe"

            for asset in release["assets"]:
                if asset["name"] == asset_needle:
                    r = requests.get(asset["browser_download_url"], stream=True)
                    print(
                        f"Found release! Downloading {asset['browser_download_url']}...",
                        end="",
                    )
                    data_dir = pathlib.Path(__file__).parent.parent.joinpath(
                        "neo3/sctesting/data"
                    )
                    binary_filename = f"{data_dir}/neogo"
                    if system == "windows":
                        binary_filename += ".exe"

                    with open(binary_filename, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1024):
                            if chunk:  # filter out keep-alive new chunks
                                f.write(chunk)
                    if system in ["darwin", "linux"]:
                        chmod_plus_x(binary_filename)
                    print("done")
                    return


if __name__ == "__main__":
    main()
