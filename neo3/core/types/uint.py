from __future__ import annotations
from neo3.core import serialization
from typing import Type, Optional

__all__ = ["UInt160", "UInt256"]


class _UIntBase(serialization.ISerializable):
    _BYTE_LEN = 0

    def __init__(self, data: Optional[bytes | bytearray] = None) -> None:
        """

        Args:
            data:
        """
        super(_UIntBase, self).__init__()
        num_bytes = self._BYTE_LEN

        if data is None:
            self._data = bytes(num_bytes)
        else:
            if len(data) < num_bytes:
                raise ValueError(
                    f"Invalid UInt: data length {len(data)} != specified num_bytes {num_bytes}"
                )
            self._data = data[:num_bytes]

    def __len__(self) -> int:
        """Count of data bytes."""
        return len(self._data)

    def __eq__(self, other) -> bool:
        if other is None:
            return False

        if not isinstance(other, _UIntBase):
            return False

        if other is self:
            return True

        if self._data == other._data:
            return True

        return False

    def __hash__(self):
        slice_length = 4 if len(self._data) >= 4 else len(self._data)
        return int.from_bytes(self._data[:slice_length], "little")

    def __str__(self):
        """Convert the data to a human-readable format (data is in reverse byte order)."""
        db = bytearray(self._data)
        db.reverse()
        return db.hex()

    def _compare_to(self, other) -> int:
        if not isinstance(other, type(self)):
            raise TypeError(
                f"Cannot compare {type(self).__name__} to type {type(other).__name__}"
            )

        x = self._data
        y = other._data

        length = len(x)

        for i in range(length - 1, 0, -1):
            if x[i] > y[i]:
                return 1
            if x[i] < y[i]:
                return -1

        return 0

    def __lt__(self, other):
        return self._compare_to(other) < 0

    def __gt__(self, other):
        return self._compare_to(other) > 0

    def __le__(self, other):
        return self._compare_to(other) <= 0

    def __ge__(self, other):
        return self._compare_to(other) >= 0

    def to_array(self) -> bytes:
        """
        Return an array of bytes representing the UInt

        Returns:
        """
        return bytes(self._data)

    @classmethod
    def _serializable_init(cls):
        return cls(data=b"\x00" * cls._BYTE_LEN)


class UInt160(_UIntBase):
    _BYTE_LEN = 20

    def __init__(self, data: bytes):
        """
        Initialize an instance.

        Args:
            data: hex escaped bytearray.
        """
        super(UInt160, self).__init__(data=data)

    @classmethod
    def deserialize_from_bytes(cls: Type[UInt160], data: bytes) -> UInt160:
        """
        Parse data into an object instance.

        Args:
            data: hex escaped bytes.

        Raises:
            ValueError: if the length of the supplied bytearray is insufficient for the type.
        """
        if len(data) < cls._BYTE_LEN:
            raise ValueError(
                f"Insufficient data {len(data)} bytes is less than the required {cls._BYTE_LEN}"
            )
        return cls(data[: cls._BYTE_LEN])

    @classmethod
    def from_string(cls: Type[UInt160], value: str) -> UInt160:
        """
        Try to parse a string into an instance.

        Note:
            NEO's string representation is in reverse byte order from the internal bytearray.


        Args:
            value: accepts the same input as :py:meth:`bytearray.fromhex`.

        Raises:
            ValueError: if the length of the supplied string does not match.
        """
        if value.startswith("0x"):
            value = value[2:]
        if len(value) != cls._BYTE_LEN * 2:
            raise ValueError(
                f"Invalid {cls.__name__} Format: {len(value)} chars != {cls._BYTE_LEN * 2} chars"
            )
        reversed_data = bytearray.fromhex(value)
        reversed_data.reverse()
        return cls(data=reversed_data)

    @classmethod
    def zero(cls: Type[UInt160]) -> UInt160:
        """
        Returns:
            An instance initialized to zero.
        """
        return cls(data=bytes(20))

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_bytes(self._data)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self._data = bytes(reader.read_bytes(self._BYTE_LEN))


class UInt256(_UIntBase):
    _BYTE_LEN = 32

    def __init__(self, data: bytes):
        """
        Initialize an instance.

        Args:
            data: hex escaped bytearray.
        """
        super(UInt256, self).__init__(data=data)

    @classmethod
    def deserialize_from_bytes(cls: Type[UInt256], data: bytes) -> UInt256:
        """
        Parse data into an object instance.

        Args:
            data: hex escaped bytes.

        Raises:
            ValueError: if the length of the supplied bytearray is insufficient for the type.
        """
        if len(data) < cls._BYTE_LEN:
            raise ValueError(
                f"Insufficient data {len(data)} bytes is less than the required {cls._BYTE_LEN}"
            )
        return cls(data[: cls._BYTE_LEN])

    @classmethod
    def from_string(cls: Type[UInt256], value: str) -> UInt256:
        """
        Try to parse a string into an instance.

        Note:
            NEO's string representation is in reverse byte order from the internal bytearray.


        Args:
            value: accepts the same input as :py:meth:`bytearray.fromhex`.

        Raises:
            ValueError: if the length of the supplied string does not match.
        """
        if value.startswith("0x"):
            value = value[2:]
        if len(value) != cls._BYTE_LEN * 2:
            raise ValueError(
                f"Invalid {cls.__name__} Format: {len(value)} chars != {cls._BYTE_LEN * 2} chars"
            )
        reversed_data = bytearray.fromhex(value)
        reversed_data.reverse()
        return cls(data=reversed_data)

    @classmethod
    def zero(cls: Type[UInt256]) -> UInt256:
        """
        Returns:
            An instance initialized to zero.
        """

        return cls(data=bytes(cls._BYTE_LEN))

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_bytes(self._data)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self._data = bytes(reader.read_bytes(self._BYTE_LEN))
