import typing
from neo3.core import types, utils as coreutils
from neo3 import vm


def get_contract_hash(sender: types.UInt160, nef_checksum: int, contract_name: str) -> types.UInt160:
    sb = vm.ScriptBuilder()
    sb.emit(vm.OpCode.ABORT)
    sb.emit_push(sender)
    sb.emit_push(nef_checksum)
    sb.emit_push(contract_name)
    return coreutils.to_script_hash(sb.to_array())


def validate_type(obj: object, type_: typing.Type):
    if type(obj) != type_:
        raise ValueError(f"Expected type '{type_}' , got '{type(obj)}' instead")
    return obj
