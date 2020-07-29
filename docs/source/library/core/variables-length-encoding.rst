:orphan:

.. _library-core-variable-length-encoding:

Variable Length Encoding
========================

The NEO network protocol supports a variable length encoding for space saving. At its basic form byte array data is to be encoded according to the following table


   +---------------+-------------------+----------------------+
   | Data length   | nr bytes to encode| Format               |
   |               |     length in     |                      |
   +===============+===================+======================+
   | < 0xfd        |         1         | uint8 + data         |
   +---------------+-------------------+----------------------+
   | <= 0xffff     |         3         | 0xfd + uint16 + data |
   +---------------+-------------------+----------------------+
   | <= 0xffffffff |         5         | 0xfe + uint32 + data |
   +---------------+-------------------+----------------------+
   | > 0xffffffff  |         9         | 0xff + uint64 + data |
   +---------------+-------------------+----------------------+

The :class:`~neo3.core.serialization.BinaryReader` and :class:`~neo3.core.serialization.BinaryWriter` classes have functions to easily support these. Specifically:

* :func:`~neo3.core.serialization.BinaryReader.read_var_int`
* :func:`~neo3.core.serialization.BinaryReader.read_var_bytes`
* :func:`~neo3.core.serialization.BinaryReader.read_var_string`
* :func:`~neo3.core.serialization.BinaryWriter.write_var_int`
* :func:`~neo3.core.serialization.BinaryWriter.write_var_bytes`
* :func:`~neo3.core.serialization.BinaryWriter.write_var_string`