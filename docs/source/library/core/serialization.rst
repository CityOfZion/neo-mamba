:mod:`serialization` --- Binary stream helper classes
=====================================================

This module provides classes to help share NEO data structures over the network between nodes.

The BinaryWriter and BinaryReader classes are convenience classes to help serialize and deserialize in a consistent, predictable and easy manner. They provide utility functions for easy writing and reading of :ref:`Variable Length Encoded <library-core-variable-length-encoding>` data.

Objects that want to be serializable through the reader and writer are encouraged to implement the :class:`~neo3.core.serialization.ISerializable` interface. An example using this interface can be seen next

.. code-block:: python

    from neo3.core import serialization, utils, Size

    class SampleObject(serialization.ISerializable):

        data = bytearray([0x00] * 10)
        is_safe = True

        def serialize(self, writer: serialization.BinaryWriter) -> None:
            writer.write_var_bytes(self.data)
            writer.write_bool(self.is_safe)

        def deserialize(self, reader: serialization.BinaryReader) -> None:
            self.data = reader.read_var_bytes()
            self.is_safe = reader.read_bool()

        def __len__(self):
            return utils.get_var_size(self.data) + Size.uint8

    with serialization.BinaryWriter() as bw:
        o = SampleObject()
        o.serialize(bw)
        stream = bw._stream.getvalue()
    print(stream)

    with serialization.BinaryReader(stream) as br:
        o = SampleObject()
        o.deserialize(br)
    print(o.data, o.is_safe)

Working with objects that implement the ISerializable interface benefit from two convenience functions that can simplify the above to

.. code-block:: python

    o = SampleObject()
    # direct serialization to bytes
    print(o.to_array())

    # direct deserialization from bytes
    o = SampleObject.deserialize_from_bytes(stream)
    print(o.data, o.is_safe)


.. autoclass:: neo3.core.serialization.ISerializable
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:
   :special-members: __len__

.. autoclass:: neo3.core.serialization.BinaryReader
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.core.serialization.BinaryWriter
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:
