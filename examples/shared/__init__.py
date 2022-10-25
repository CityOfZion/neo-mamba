import pathlib
import os
import sys
import shutil
import subprocess
import threading
import time
import json
from typing import Optional
from neo3.wallet.wallet import Wallet
from neo3.core import types

shared_dir = pathlib.Path("shared").resolve(strict=True)

user_wallet = Wallet.from_file(f"{shared_dir}/user-wallet.json", password="123")
coz_wallet = Wallet.from_file(f"{shared_dir}/coz-wallet.json", password="123")
neoxpress_config_path = f"{shared_dir}/default.neo-express"
neoxpress_batch_path = f"{shared_dir}/setup-neoxp-for-tests.batch"
coz_token_hash = types.UInt160.from_string("0x41ee5befd936c90f15893261abbd681f20ed0429")
# corresponds to the nep-11 token in the `/nep11-token/` dir and deployed with the `coz` account
nep11_token_hash = types.UInt160.from_string(
    "0x35de2913c480c19a7667da1cc3b2fe3e4c9de761"
)


class NeoExpress:
    """Neo express wrapper"""

    def __init__(
        self,
        config_path: str,
        batch_path: Optional[str] = None,
        executable_path: Optional[str] = None,
        return_delay: int = 1,
        debug: bool = False,
    ):
        self.prog = "neoxp"
        self.config_path = config_path
        self.batch_path = batch_path
        self.return_delay = return_delay
        self.debug = debug

        with open(self.config_path) as f:
            data = json.load(f)
            port = data["consensus-nodes"][0]["rpc-port"]
            address = data["settings"].get("rpc.BindAddress", "127.0.0.1")
            self.rpc_host = f"http://{address}:{port}"

        if executable_path is not None:
            self._verify_executable(executable_path)
            self.prog = executable_path
        else:
            if sys.platform == "darwin":
                try:
                    subprocess.run(
                        ["bash", "-c", "neoxp -h"],
                        check=True,
                        stdout=subprocess.DEVNULL,
                    )
                except subprocess.SubprocessError:
                    raise ValueError(
                        "Cannot automatically find global neo express executable. Please specify the path"
                    )
            elif shutil.which(self.prog) is None:
                raise ValueError(
                    "Cannot automatically find global neo express executable. Please specify the path"
                )

    def _verify_executable(self, full_path: str):
        if not os.path.isfile(full_path) or not os.access(full_path, os.X_OK):
            raise ValueError(f"Invalid executable: {full_path}")

    def initialize_with(self, batch_path: str):
        print("executing neo-express batch...", end="")
        cmd = f"neoxp batch -r {batch_path}"
        if sys.platform == "darwin":
            subprocess.run(["bash", "-c", cmd], check=True, stdout=subprocess.DEVNULL)
        else:
            subprocess.run(cmd.split(" "), check=True, stdout=subprocess.DEVNULL)
        print("done")

    def run(self, return_delay=None):
        print("starting neo-express...", end="")
        cmd = f"neoxp run -i {self.config_path}"
        kwargs = {"check": True}
        if self.debug is False:
            kwargs["stdout"] = subprocess.DEVNULL
        if sys.platform == "darwin":
            kwargs["args"] = ["bash", "-c", cmd]
        else:
            kwargs["args"] = cmd.split(" ")
        thread = threading.Thread(
            target=subprocess.run, kwargs=kwargs, name="neoxp", daemon=True
        )
        thread.start()
        time.sleep(return_delay if return_delay else self.return_delay)
        print("done")

    def stop(self):
        print("stopping neo-express...", end="")
        cmd = f"neoxp stop -a -i {self.config_path}"
        if sys.platform == "darwin":
            subprocess.run(["bash", "-c", cmd], check=True, stdout=subprocess.DEVNULL)
        else:
            subprocess.run(cmd.split(" "), check=True, stdout=subprocess.DEVNULL)
        print("done")

    def __enter__(self):
        if self.batch_path is not None:
            self.initialize_with(self.batch_path)
        self.run(self.return_delay)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
