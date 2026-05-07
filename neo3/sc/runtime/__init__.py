from typing import Optional
from neo3.sc.types import TrimmedTransaction, UInt160, ECPoint
from neo3.sc.compiletime import syscall


@syscall("System.Runtime.GetScriptContainer")
def get_script_container() -> TrimmedTransaction:
    pass


@syscall("System.Runtime.GetCallingScriptHash")
def get_calling_script_hash() -> UInt160:  # TODO: these should be optional
    pass


@syscall("System.Runtime.GetEntryScriptHash")
def get_entry_script_hash() -> (
    UInt160
):  # TODO: these should be optional but can they actually ever be in a smart contract?
    pass


@syscall("System.Runtime.GetRandom")
def get_random() -> int:
    pass


@syscall("System.Runtime.CheckWitness")
def check_witness(hash: UInt160 | ECPoint) -> bool:
    pass
