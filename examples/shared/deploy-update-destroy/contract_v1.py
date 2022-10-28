"""
    This version of the contract has an `add` method that increases the value by 1.
"""
from typing import Any
from boa3.builtin import NeoMetadata, metadata, public
from boa3.builtin.nativecontract.contractmanagement import ContractManagement


@metadata
def manifest_metadata() -> NeoMetadata:
    """
    Defines this smart contract's metadata information.
    """
    meta = NeoMetadata()
    meta.name = "Example Contract"
    return meta


@public(safe=False)
def update(nef_file: bytes, manifest: bytes, data: Any = None):
    ContractManagement.update(nef_file, manifest, data)


@public
def add(number: int) -> int:
    return number + 1


@public(safe=False)
def destroy():
    ContractManagement.destroy()
