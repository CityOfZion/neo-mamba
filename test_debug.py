from neo3.compiler import compile_source_to_nef
import json

src = """
from typing import Any
from neo3.sc.compiletime import public, event
from neo3.sc.types import UInt160

@event
def Transfer(from_addr: UInt160, to_addr: UInt160, amount: int) -> None:
    pass

@public
def symbol() -> str:
    return "TKN"

@public
def decimals() -> int:
    return 8

@public
def totalSupply() -> int:
    return 1000000

@public
def balanceOf(account: UInt160) -> int:
    return 0

@public
def transfer(from_: UInt160, to: UInt160, amount: int, data: Any) -> bool:
    Transfer(from_, to, amount)
    return True
"""

nef, manifest = compile_source_to_nef(src, contract_name="TestToken")
print("Manifest JSON:")
print(json.dumps(manifest.to_json(), indent=2))
print("\nSupported standards:", manifest.supported_standards)
if manifest.extra and "nep_warnings" in manifest.extra:
    print("Warnings:", manifest.extra["nep_warnings"])
