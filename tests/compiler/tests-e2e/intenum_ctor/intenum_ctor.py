from neo3.sc.compiletime import public
from neo3.sc.types import CallFlags, FindOptions, NamedCurveHash


@public
def named_curve_hash_ctor(x: int) -> int:
    curve: NamedCurveHash = NamedCurveHash(x)
    return curve


@public
def named_curve_hash_param(x: NamedCurveHash) -> NamedCurveHash:
    curve: NamedCurveHash = x
    return curve


@public
def find_options_ctor(x: int) -> int:
    opts: FindOptions = FindOptions(x)
    return opts


@public
def call_flags_ctor(x: int) -> int:
    flags: CallFlags = CallFlags(x)
    return flags


@public
def named_curve_hash_literal() -> int:
    curve: NamedCurveHash = NamedCurveHash(NamedCurveHash.SECP256R1SHA256)
    return curve
