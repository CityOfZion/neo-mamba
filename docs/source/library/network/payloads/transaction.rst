:mod:`transaction` --- All things Transaction related
=====================================================

.. classoverview::
   :class:`neo3.network.payloads.transaction.Transaction`
   :class:`neo3.network.payloads.transaction.TransactionAttribute`
   :class:`neo3.network.payloads.transaction.TransactionAttributeType`

This module contains the famous Transaction class.

At its core is a byte array holding the instructions to be executed by the NEO virtual machine. Such instructions can include token balance updates or general smart contract execution.

Auxiliary attributes are included for validation purposes and validity constraints (think; only valid until a certain block) among other reasons.

.. autoclass:: neo3.network.payloads.transaction.Transaction
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.transaction.TransactionAttribute
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.transaction.TransactionAttributeType
   :undoc-members:
   :show-inheritance:
   :inherited-members:
