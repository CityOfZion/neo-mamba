from __future__ import annotations
import sys
import abc
import struct
from io import BytesIO, SEEK_END
from typing import Union, Any, List, Type, TypeVar


ISerializable_T = TypeVar('ISerializable_T', bound='ISerializable')

__all__ = ['ISerializable', 'BinaryReader', 'BinaryWriter']


class ISerializable(abc.ABC):
    """
    An interface like class supporting NEO's network serialization protocol.
    """
    @abc.abstractmethod
    def serialize(self, writer: BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """

    @abc.abstractmethod
    def deserialize(self, reader: BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """

    @classmethod
    def deserialize_from_bytes(cls: Type[ISerializable_T], data: Union[bytes, bytearray]) -> ISerializable_T:
        """
        Parse data into an object instance.

        Args:
            data: hex escaped bytes.

        Returns:
            a deserialized instance of the class.
        """
        with BinaryReader(data) as br:
            payload = cls._serializable_init()
            payload.deserialize(br)
            return payload

    def to_array(self) -> bytes:
        """ Serialize the object into a bytearray."""
        with BinaryWriter() as bw:
            self.serialize(bw)
            return bw._stream.getvalue()

    @abc.abstractmethod
    def __len__(self):
        """ Return the length of the object in number of bytes."""

    @classmethod
    def _serializable_init(cls):
        """
        If the interface inheritor has mandatory arguments, override this functin and provide dummy values. These values
        will be overwritten by the read_serializable, read_serializable_list and deserialize_from_bytes methods that
        rely on this function for class instantiation.
        """
        return cls()


class BinaryReader(object):
    _uint8 = struct.Struct("<B")
    _uint16 = struct.Struct("<H")
    _uint32 = struct.Struct("<I")
    _uint64 = struct.Struct("<Q")
    _int16 = struct.Struct("<h")
    _int32 = struct.Struct("<i")
    _int64 = struct.Struct("<q")
    _uint16BE = struct.Struct(">H")
    _uint32BE = struct.Struct(">I")
    _uint64BE = struct.Struct(">Q")
    _int16BE = struct.Struct(">h")
    _int32BE = struct.Struct(">i")
    _int64BE = struct.Struct(">q")
    """
        A convenience class for reading data from byte streams.

        Context manager support is available to ensure proper cleanup of resources.

        Example:
        ::

            with BinaryReader(b'\\x01\\x02') as br:
                my_value = br.read_uint16()
    """

    def __init__(self, stream: Union[bytes, bytearray]) -> None:
        """
        Create an instance.

        Args:
            stream: a stream to operate on.
        """
        super(BinaryReader, self).__init__()
        self._stream = BytesIO(stream)

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.close()

    def __len__(self):
        io = self._stream
        # Remember our current position
        cur_pos = io.tell()
        # Seek to the end of the File object
        io.seek(0, SEEK_END)
        # Remember position, which is equal to the full length
        full_size = io.tell()
        # Seek back to the current position
        io.seek(cur_pos)
        return full_size

    def read_byte(self) -> bytes:
        """
        Read a single byte.

        Raises:
            ValueError: if 1 byte of data cannot be read from the stream.

        Returns:
            bytes: a hex escaped bytearray with 1 element.
        """
        value = self._stream.read(1)
        if len(value) != 1:
            raise ValueError("Could not read byte from empty stream")
        return value

    def read_bytes(self, length: int, _skip_length_check: bool = False) -> bytes:
        """
        Read the specified number of bytes from the stream.

        Args:
            length: number of bytes to read.

        Raises:
            ValueError: if `length` bytes of data cannot be read from the stream.

        Returns:
            bytes: `length` number of bytes.
        """
        value = self._stream.read(length)
        if not _skip_length_check and len(value) != length:
            raise ValueError(f"Could not read {length} bytes from stream. Only found {len(value)} bytes of data")

        return value

    def read_bool(self) -> bool:
        """
        Read 1 byte as a boolean value from the stream.

        Returns:
            bool: False for b'\x00'. True for all other values.
        """
        return struct.unpack("?", self._stream.read(1))[0]

    def read_uint8(self) -> int:
        """
        Read 1 byte as an unsigned integer value from the stream.
        """
        return self._uint8.unpack(self._stream.read(1))[0]

    def read_uint16(self) -> int:
        """
        Read 2 bytes as an unsigned integer value from the stream.
        """
        return self._uint16.unpack(self._stream.read(2))[0]

    def read_uint16BE(self) -> int:
        """
        Read 2 bytes as an unsigned integer value from the stream.
        """
        return self._uint16BE.unpack(self._stream.read(2))[0]

    def read_int16(self) -> int:
        """
        Read 2 bytes as an unsigned integer value from the stream.
        """
        return self._int16.unpack(self._stream.read(2))[0]

    def read_int16BE(self) -> int:
        """
        Read 2 bytes as an unsigned integer value from the stream.
        """
        return self._int16BE.unpack(self._stream.read(2))[0]

    def read_uint32(self) -> int:
        """
        Read 4 bytes as an unsigned integer value from the stream.
        """
        return self._uint32.unpack(self._stream.read(4))[0]

    def read_uint32BE(self) -> int:
        """
        Read 4 bytes as an unsigned integer value from the stream.
        """
        return self._uint32BE.unpack(self._stream.read(4))[0]

    def read_int32(self) -> int:
        """
        Read 4 bytes as a signed integer value from the stream.
        """
        return self._int32.unpack(self._stream.read(4))[0]

    def read_int32BE(self) -> int:
        """
        Read 4 bytes as a signed integer value from the stream.
        """
        return self._int32BE.unpack(self._stream.read(4))[0]

    def read_uint64(self) -> int:
        """
        Read 8 bytes as an unsigned integer value from the stream.
        """
        return self._uint64.unpack(self._stream.read(8))[0]

    def read_uint64BE(self) -> int:
        """
        Read 8 bytes as an unsigned integer value from the stream.
        """
        return self._uint64BE.unpack(self._stream.read(8))[0]

    def read_int64(self) -> int:
        """
        Read 8 bytes as a signed integer value from the stream.
        """
        return self._int64.unpack(self._stream.read(8))[0]

    def read_int64BE(self) -> int:
        """
        Read 8 bytes as a signed integer value from the stream.
        """
        return self._int64BE.unpack(self._stream.read(8))[0]

    def read_var_int(self, max: int = sys.maxsize) -> int:
        """
        Read a integer that starts with a variable length indicator.

        The NEO network protocol supports encoded length indicating for saving space.
        See: :ref:`library-core-variable-length-encoding`

        See also:
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_int`
            * :func:`~neo3.core.serialization.BinaryReader.read_var_string`
            * :func:`~neo3.core.serialization.BinaryReader.read_var_bytes`


        Args:
            max: (Optional) maximum number of bytes to read.

        Raises:
            ValueError: if the return value exceeds the `max` argument.
        """
        fb = int.from_bytes(self.read_byte(), 'little')
        if fb == 0:
            return fb

        if fb == 0xfd:
            value = self.read_uint16()
        elif fb == 0xfe:
            value = self.read_uint32()
        elif fb == 0xff:
            value = self.read_uint64()
        else:
            value = fb

        if value > max:
            raise ValueError("Invalid format")

        return value

    def read_var_bytes(self, max: int = sys.maxsize) -> bytes:
        """
        Read bytes that starts with a variable length indicator.

        The NEO network protocol supports encoded length indicating for saving space.
        See: :ref:`library-core-variable-length-encoding`

        See also:
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_bytes`
            * :func:`~neo3.core.serialization.BinaryReader.read_var_int`
            * :func:`~neo3.core.serialization.BinaryReader.read_var_string`

        Note:
            This will try to read the amount of bytes as encoded in the stream but will read less if insufficient
            data is available.

        Args:
            max: (Optional) maximum number of bytes to read.
        """
        length = self.read_var_int(max)
        return self.read_bytes(length, _skip_length_check=True)

    def read_var_string(self, max: int = sys.maxsize) -> str:
        """
        Read a UTF-8 string that starts with a variable length indicator.

        The NEO network protocol supports encoded length indicating for saving space.
        See: :ref:`library-core-variable-length-encoding`

        See also:
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_string`
            * :func:`~neo3.core.serialization.BinaryReader.read_var_int`
            * :func:`~neo3.core.serialization.BinaryReader.read_var_bytes`

        Args:
            max: (Optional) maximum number of bytes to read.

        Raises:
            ValueError: if decoding fails or insufficient data is present in the stream.
        """
        length = self.read_var_int(max)
        try:
            data = struct.unpack(f"{length}s", self._stream.read(length))[0]
            return data.decode('utf-8')
        except Exception as e:
            raise ValueError(str(e))

    def read_serializable(self, obj_type: Type[ISerializable_T]) -> ISerializable_T:
        """
        Read and deserialize an object of `obj_type` from the stream.

        Args:
            obj_type: the object class to deserialize into.
        """
        obj = obj_type._serializable_init()
        obj.deserialize(self)
        return obj

    def read_serializable_list(self, obj_type: Type[ISerializable_T], max: int = None) -> List[ISerializable_T]:
        """
        Read and deserialize a list of objects of `obj_type` from the stream.

        Expects to start with a `varint` list length indicator.

        Args:
            obj_type: the object class to deserialize into.
            max: read up to `max` objects from the stream.

        Returns:
            list[ISerializable]: list of deserialized objects.
        """
        obj_array = []
        count = self.read_var_int()
        if max and count > max:
            count = max

        try:
            for _ in range(count):
                obj = obj_type._serializable_init()
                obj.deserialize(self)
                obj_array.append(obj)
        except Exception as e:
            raise ValueError(f"Insufficient data - {str(e)}")
        return obj_array

    def close(self) -> None:
        """
        Close the internal stream to prevent resource leaking.

        Note:
            This is done automatically when using the context manager
        """
        if self._stream:
            self._stream.close()


class BinaryWriter(object):
    """
    A convenience class for writing data to byte streams.

    Context manager support is available to ensure proper cleanup of resources.

    Example:
    ::

        with serialization.BinaryWriter() as bw:
            bw.write_uint8(5)
            self.assertEqual(b'\\x05', bw._stream.getvalue())
    """

    def __init__(self, stream: Union[bytearray, bytes] = None) -> None:
        """
        Create an instance.

        Args:
            stream: a stream to operate on.
        """
        super(BinaryWriter, self).__init__()
        self._stream = BytesIO(stream) if stream else BytesIO()

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.close()

    def __len__(self):
        io = self._stream
        # Remember our current position
        cur_pos = io.tell()
        # Seek to the end of the File object
        io.seek(0, SEEK_END)
        # Remember position, which is equal to the full length
        full_size = io.tell()
        # Seek back to the current position
        io.seek(cur_pos)
        return full_size

    def write_bytes(self, value: bytes) -> int:
        """
        Write a `bytes` type to the stream.

        Args:
            value: array of bytes to write to the stream.

        Returns:
            int: the number of bytes written.
        """
        return self._stream.write(value)

    def _pack(self, fmt, data) -> int:
        """
        Write bytes by packing them according to the provided format `fmt`.

        For more information about the `fmt` format see: https://docs.python.org/3/library/struct.html

        Args:
            fmt (str): format string.
            data (object): the data to write to the raw stream.

        Returns:
            int: the number of bytes written.
        """
        return self.write_bytes(struct.pack(fmt, data))

    def write_bool(self, value: bool) -> int:
        """
        Pack the value as a bool and write 1 byte to the stream.

        Args:
            value: the boolean value to write.

        Returns:
            int: the number of bytes written.
        """
        return self._pack('?', value)

    def write_uint8(self, value) -> int:
        """

        Args:
            value: integer value to write to the stream.

        Returns:
            int: the number of bytes written.
        """
        return self.write_bytes(bytes([value]))

    def write_uint16(self, value: int, endian: str = "<") -> int:
        """
        Pack the value as an unsigned integer and write 2 bytes to the stream.

        Args:
            value: integer value to write to the stream.
            endian: specify the endianness. (Default) Little endian ('<'). Use '>' for big endian.

        Returns:
            int: the number of bytes written.
        """
        return self._pack('%sH' % endian, value)

    def write_uint32(self, value: int, endian: str = "<") -> int:
        """
        Pack the value as a signed integer and write 4 bytes to the stream.

        Args:
            value: integer value to write to the stream.
            endian: specify the endianness. (Default) Little endian ('<'). Use '>' for big endian.

        Returns:
            int: the number of bytes written.
        """
        return self._pack('%sI' % endian, value)

    def write_uint64(self, value: int, endian: str = "<") -> int:
        """
        Pack the value as an unsigned integer and write 8 bytes to the stream.

        Args:
            value: integer value to write to the stream.
            endian (str): specify the endianness. (Default) Little endian ('<'). Use '>' for big endian.

        Returns:
            int: the number of bytes written.
        """
        return self._pack('%sQ' % endian, value)

    def write_int16(self, value: int, endian: str = "<") -> int:
        """
        Pack the value as a signed integer and write 2 bytes to the stream.
        Args:
            value: integer value to write to the stream.
            endian: specify the endianness. (Default) Little endian ('<'). Use '>' for big endian.
        Returns:
            int: the number of bytes written.
        """
        return self._pack('%sh' % endian, value)

    def write_int32(self, value: int, endian: str = "<") -> int:
        """
        Pack the value as a signed integer and write 4 bytes to the stream.
        Args:
            value: integer value to write to the stream.
            endian: specify the endianness. (Default) Little endian ('<'). Use '>' for big endian.
        Returns:
            int: the number of bytes written.
        """
        return self._pack('%si' % endian, value)

    def write_int64(self, value: int, endian: str = "<") -> int:
        """
        Pack the value as an unsigned integer and write 8 bytes to the stream.
        Args:
            value: integer value to write to the stream.
            endian (str): specify the endianness. (Default) Little endian ('<'). Use '>' for big endian.
        Returns:
            int: the number of bytes written.
        """
        return self._pack('%sq' % endian, value)

    def write_var_string(self, value: str, encoding: str = "utf-8") -> int:
        """
        Write a string value to the stream.

        The NEO network protocol supports encoded length indicating for saving space.
        See: :ref:`library-core-variable-length-encoding`

        See also:
            * :func:`~neo3.core.serialization.BinaryReader.read_var_string`
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_bytes`
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_int`

        Args:
            value: string to write to the stream.
            encoding: string encoding format.
        """
        if type(value) is str:
            data = value.encode(encoding)

        length = len(data)
        self.write_var_int(length)
        written = self.write_bytes(data)
        return written

    def write_var_int(self, value: int, endian: str = "<") -> int:
        """
        Write an integer value in a space saving way to the stream.

        The NEO network protocol supports encoded length indicating for saving space.
        See: :ref:`library-core-variable-length-encoding`

        See also:
            * :func:`~neo3.core.serialization.BinaryReader.read_var_int`
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_bytes`
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_string`

        Args:
            value: integer value to write to the stream.
            endian: specify the endianness. (Default) Little endian ('<'). Use '>' for big endian.

        Raises:
            TypeError: if ``value`` is not of type int.
            ValueError: if `value` is < 0.

        Returns:
            int: the number of bytes written.
        """
        if not isinstance(value, int):
            raise TypeError('%s not int type.' % value)

        if value < 0:
            raise ValueError('%d too small.' % value)

        elif value < 0xfd:
            return self.write_bytes(bytes([value]))

        elif value <= 0xffff:
            self.write_bytes(bytes([0xfd]))
            return self.write_uint16(value, endian)

        elif value <= 0xFFFFFFFF:
            self.write_bytes(bytes([0xfe]))
            return self.write_uint32(value, endian)

        else:
            self.write_bytes(bytes([0xff]))
            return self.write_uint64(value, endian)

    def write_var_bytes(self, value: bytes, endian: str = "<") -> int:
        """
        Write bytes into a stream with variable length prefix.

        The NEO network protocol supports encoded length indicating for saving space. See
        :ref:`library-core-variable-length-encoding`

        See also:
            * :func:`~neo3.core.serialization.BinaryReader.read_var_bytes`
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_int`
            * :func:`~neo3.core.serialization.BinaryWriter.write_var_string`

        Args:
            value: bytes to write to the stream.
            endian: specify the endianness. (Default) Little endian ('<'). Use '>' for big endian.

        Returns:
            int: the number of bytes written.
        """
        self.write_var_int(len(value), endian)
        return self.write_bytes(value)

    def write_serializable(self, obj_instance: ISerializable_T) -> None:
        """
        Serialize an object instance and write it to the stream.

        Args:
            obj_instance: the instance to serialize.
        """
        obj_instance.serialize(self)

    def write_serializable_list(self, objects: List[ISerializable_T]) -> None:
        """
        Serialize a list of objects and write them to the stream.

        Args:
            objects: a list of objects.
        """
        self.write_var_int(len(objects))
        for o in objects:
            o.serialize(self)

    def close(self) -> None:
        """
        Close the internal stream to prevent resource leaking.

        Note:
            This is done automatically when using the context manager
        """
        if self._stream:
            self._stream.close()

    def to_array(self) -> bytes:
        """
        Get the raw bytes from the underlying stream.
        """
        return self._stream.getvalue()
