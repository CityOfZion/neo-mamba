from __future__ import annotations
from neo3.core import serialization
from neo3crypto import (  # type: ignore
    ECPoint as _ECPointCpp,
    ECCCurve,
    ECCException,
    sign as ecdsa_sign,
    verify as ecdsa_verify,
)
from typing import Type, Any
import os
import binascii


# mypy workaround
type_ECPoint = type(_ECPointCpp)  # type: Any
type_Serializable = type(serialization.ISerializable)  # type: Any


class SerializableECPointMeta(type_ECPoint, type_Serializable):
    pass


class ECPoint(
    _ECPointCpp, serialization.ISerializable, metaclass=SerializableECPointMeta
):
    def __init__(self, *args, **kwargs):
        super(ECPoint, self).__init__(*args, **kwargs)

    def __str__(self):
        return binascii.hexlify(self.encode_point(compressed=True)).decode("utf8")

    def __bool__(self):
        return True

    def __hash__(self):
        return hash(self.x + self.y)

    def __deepcopy__(self, memodict={}):
        return ECPoint.deserialize_from_bytes(self.to_array(), self.curve, False)

    def is_zero(self):
        return self.x == 0 and self.y == 0

    def serialize(self, writer: serialization.BinaryWriter, compress=True) -> None:
        if self.is_infinity:
            writer.write_bytes(b"\x00")
        else:
            writer.write_bytes(self.encode_point(compress))

    def deserialize(
        self, reader: serialization.BinaryReader, curve=ECCCurve.SECP256R1
    ) -> None:
        try:
            f0 = reader.read_byte()
        except ValueError:
            # infinity
            self.from_bytes(b"\x00", curve, True)
            return

        f1 = int.from_bytes(f0, "little")
        if f1 == 0:
            # infinity
            self.from_bytes(b"\x00", curve, True)
            return
        elif f1 == 2 or f1 == 3:
            data = reader.read_bytes(32)
            self.from_bytes(f0 + data, curve, True)
            return
        else:
            raise ValueError(f"Unsupported point encoding: {str(f0)}")

    @classmethod
    def deserialize_from_bytes(
        cls: Type[serialization.ISerializable_T],
        data: bytes | bytearray,
        curve: ECCCurve = ECCCurve.SECP256R1,
        validate: bool = True,
    ) -> serialization.ISerializable_T:
        """
        Parse data into an object instance.

        Args:
            data: ECPoint in hex escaped bytes format.
            curve: the curve type to decompress
            validate: validate if the point valid point on the specified curve

        Returns:
            a deserialized instance of the class.
        """
        return cls(data, curve, validate)  # type: ignore

    @classmethod
    def _serializable_init(cls):
        return cls(b"\x00", ECCCurve.SECP256R1, False)


class KeyPair:
    def __init__(self, private_key: bytes, curve: ECCCurve = ECCCurve.SECP256R1):
        self.private_key = private_key
        self.public_key: ECPoint = ECPoint(private_key, curve)

    @classmethod
    def generate(cls):
        return cls(os.urandom(32))
