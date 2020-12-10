.. _library-complextypes:

**********************
Complex data types
**********************
The NEO 3.x system makes heavy use of a small handful of complex data types which are good to be aware off. Because of their heavy usage throughout the whole system, and especially in the virtual machine, it is encouraged to use these types instead of the close looking Python native types like bytes or int. The devil is in the details.

.. data:: UInt160

   A 20-byte data structure commonly used to uniquely identify smart contracts and signing authorities (i.e. Consensus nodes and Transaction owners). See :mod:`~neo3.core.types.uint.UInt160`.

.. data:: UInt256

   A 32-byte data structure commonly used for storing hashes that can uniquely identify Blocks and Transactions among other objects. See :mod:`~neo3.core.types.uint.UInt256`.

.. data:: BigInteger

   A full port of the C# reference implementation implemented as a C-extension. See :ref:`BigInteger <library-vm-biginteger>`.