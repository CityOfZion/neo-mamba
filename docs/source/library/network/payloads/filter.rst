:mod:`filter` --- Configure bloomfilters
========================================

.. classoverview::
   :class:`neo3.network.payloads.filter.FilterLoadPayload`
   :class:`neo3.network.payloads.filter.FilterAddPayload`


Bloomfilters affect the return results of the :const:`~neo3.network.message.MessageType.GETDATA` and :const:`~neo3.network.message.MessageType.GETBLOCKBYINDEX` message types. See :ref:`getdata <message-usage-getdata>` and :ref:`getblockdata <message-usage-getblockbyindex>` respectively. The mechanism is present in the C# reference implementation but without active use-case.

.. autoclass:: neo3.network.payloads.filter.FilterLoadPayload
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.filter.FilterAddPayload
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:
