.. _library-vm-biginteger:

:mod:`biginteger` --- A C# like BigInteger implementation
=========================================================

While Python natively supports infinite numbers through its build in `int <https://docs.python.org/3/library/functions.html#int>`_ type, the BigInteger class of the C# reference implementation exhibits different behaviour in certain areas. By using this class we can prevent any discrepancies in price calculations, virtual machine execution path and more.

In particular the following differences in behaviour can be expected when using this class.

- Negative bitwise shifting is supported. 

  - A negative left shift becomes a positive right shift. 
  - A negative right shift becomes a positive left shift.

- Increased modulo rounding precision.
- Use modulo truncated division instead of floored division.
- Serialization of negative numbers can in certain cases return an extra byte.
- Integer division instead of floating point division.

.. autoclass:: neo3.vm.BigInteger
   :members:
   :undoc-members:
   :show-inheritance:
