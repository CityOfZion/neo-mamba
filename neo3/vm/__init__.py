"""The actual classes come from C-extension modules"""
from __future__ import annotations
import hashlib
from pybiginteger import BigInteger
from neo3vm import ScriptBuilder as _ScriptBuilder
from neo3vm import *

del globals()['ScriptBuilder']
from neo3vm import ScriptBuilder as _ScriptBuilder


def _syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)


class ScriptBuilder(_ScriptBuilder):  # type: ignore
    def emit_dynamic_call(self, script_hash, operation: str) -> None:
        self.emit(OpCode.NEWARRAY0)
        self.emit_push(0xF)  # CallFlags.ALL
        self.emit_push(operation)
        self.emit_push(script_hash.to_array())
        self.emit_syscall(_syscall_name_to_int("System.Contract.Call"))

    def emit_dynamic_call_with_args(self, script_hash, operation: str, args) -> None:
        for arg in reversed(args):
            self.emit_push(arg)
        self.emit_push(len(args))
        self.emit(OpCode.PACK)
        self.emit_push(0xF)  # CallFlags.ALL
        self.emit_push(operation)
        self.emit_push(script_hash.to_array())
        self.emit_syscall(_syscall_name_to_int("System.Contract.Call"))
