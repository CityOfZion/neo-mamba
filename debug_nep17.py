import json
from tests.compiler.tests.test_nef_manifest import _write_contract

src = """
from typing import Any
from neo3.sc.compiletime import public, event
from neo3.sc.types import UInt160

@event(name="Transfer")
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

_, manifest = _write_contract(src)
print("Methods:")
for m in manifest["abi"]["methods"]:
    print(" ", m["name"], m["parameters"], "->", m["returntype"])
print("Events:")
for e in manifest["abi"]["events"]:
    print(" ", e["name"], e["parameters"])
print("supportedstandards:", manifest.get("supportedstandards"))