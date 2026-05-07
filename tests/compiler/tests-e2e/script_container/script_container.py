from neo3.sc.compiletime import public
from neo3.sc.runtime import get_script_container
from neo3.sc.types import UInt160, UInt256


@public
def get_hash() -> UInt256:
    return get_script_container().hash


@public
def get_version() -> int:
    return get_script_container().version


@public
def get_nonce() -> int:
    return get_script_container().nonce


@public
def get_sender() -> UInt160:
    return get_script_container().sender


@public
def get_system_fee() -> int:
    return get_script_container().system_fee


@public
def get_network_fee() -> int:
    return get_script_container().network_fee


@public
def get_valid_until_block() -> int:
    return get_script_container().valid_until_block


@public
def get_script() -> bytes:
    return get_script_container().script
