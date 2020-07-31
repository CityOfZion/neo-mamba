.. _library-network-message:

:mod:`message` --- P2P network packets
======================================

.. classoverview::
   :class:`neo3.network.message.Message`
   :class:`neo3.network.message.MessageType`
   :class:`neo3.network.message.MessageConfig`


This chapter describes the network packet format as well as the protocol for communicating with nodes.

.. _message-type-purpose:

The following section describes the purpose of each message type as well as the expected responses to such messages. See the :ref:`classes <message-classes>` section for the description of the message format.

Usage
~~~~~

.. _message-usage-filteradd:

.. data:: FILTERADD

   Update a configured bloomfilter.

   .. seealso::
      :ref:`filterload <message-usage-filterload>`

   **Payload**: :class:`~neo3.network.payloads.filter.FilterAddPayload`

   **Response type**: None

   **Response payload**: None

.. _message-usage-filterclear:

.. data:: FILTERCLEAR

   Clear a configured bloomfilter.

   **Payload**: None

   **Response type**: None

   **Response payload**: None

.. _message-usage-filterload:

.. data:: FILTERLOAD

   Configure a bloomfilter on the remote node.

   .. seealso::
      :ref:`filteradd <message-usage-filteradd>`

   **Payload**: :class:`~neo3.network.payloads.filter.FilterLoadPayload`

   **Response type**: None

   **Response payload**: None

.. _message-usage-getaddr:

.. data:: GETADDR

   Request a list of known network addresses.

   **Payload**: :class:`~neo3.network.payloads.AddrPayload`

   **Response type**: :const:`~neo3.network.message.MessageType.ADDR`

   **Response payload**: :class:`~neo3.network.payloads.AddrPayload`

.. _message-usage-getdata:

.. data:: GETDATA

   Request inventory types based on a list of hashes.

   **Payload**: :class:`~neo3.network.payloads.block.InventoryPayload`

   **Response type**: Depending on the type indicated in the request payload the response will be one of :const:`~neo3.network.message.MessageType.BLOCK`, :const:`~neo3.network.message.MessageType.CONSENSUS`, :const:`~neo3.network.message.MessageType.TRANSACTION` or :const:`~neo3.network.message.MessageType.MERKLEBLOCK`.

   .. note::

   	A :const:`~neo3.network.message.MessageType.MERKLEBLOCK` response is given when the inventory type is set to :const:`~neo3.network.payloads.inventory.InventoryType.BLOCK` while a bloomfilter is configured on the remote node.

   **Response payload**: Depending on the type indicated in the request payload one of :class:`~neo3.network.payloads.Block`, :class:`~neo3.network.payloads.inventory.InventoryType`, :class:`~neo3.network.payloads.transaction.Transaction` or :class:`~neo3.network.payloads.block.MerkleBlockPayload`.

.. _message-usage-getheaders:

.. data:: GETHEADERS

   Request Header objects (can be used for syncing).
   
   **Payload**: :class:`~neo3.network.payloads.block.GetBlockByIndexPayload`

   **Response type**: :const:`~neo3.network.message.MessageType.HEADERS`

   **Response payload**: :class:`~neo3.network.payloads.block.HeadersPayload`

.. _message-usage-getblocks:
.. data:: GETBLOCKS

   Request block hashes (can be used for syncing).
   
   **Payload**: :class:`~neo3.network.payloads.block.GetBlocksPayload`

   **Response type**: :const:`~neo3.network.message.MessageType.INV`

   **Response payload**: :class:`~neo3.network.payloads.inventory.InventoryPayload` with type set to :const:`~neo3.network.payloads.inventory.InventoryType.BLOCK`

.. _message-usage-getblockbyindex:
.. data:: GETBLOCKBYINDEX

   Request block objects.
   
   **Payload**: :class:`~neo3.network.payloads.block.GetBlockByIndexPayload`

   **Response type**: :const:`~neo3.network.message.MessageType.BLOCK` or :const:`~neo3.network.message.MessageType.MERKLEBLOCK`.

  	.. note::

	   	A :const:`~neo3.network.message.MessageType.MERKLEBLOCK` response is given when a bloomfilter is configured on the remote node.


   **Response payload**: :class:`~neo3.network.payloads.block.Block` or :class:`~neo3.network.payloads.block.MerkleBlockPayload`


.. _message-usage-mempool:

.. data:: MEMPOOL

	Request a list of hashes currently in the mempool.

	**Payload**: None

	**Response type**: :const:`~neo3.network.message.MessageType.INV`

	**Response payload**: :class:`~neo3.network.payloads.inventory.InventoryPayload` with type set to :const:`~neo3.network.payloads.inventory.InventoryType.TX`

.. _message-usage-ping:

.. data:: PING

   Request node chain height update, send own chain height.
   
   **Payload**: :class:`~neo3.network.payloads.ping.PingPayload`

   **Response type**: :const:`~neo3.network.message.MessageType.PONG`

   **Response payload**: :class:`~neo3.network.payloads.ping.PingPayload`

.. _message-usage-reject:

.. data:: REJECT

   Inform a remote node why its connection is rejected.

   .. note::

      Is expected to return a new RejectPayload once `this PR <https://github.com/neo-project/neo/pull/1154>`__ is merged.
   
   **Payload**: None

   **Response type**: None

   **Response payload**: None

.. _message-usage-notfound:

.. data:: NOTFOUND

   Not used.


.. _message-classes:

Classes
~~~~~~~

The Message class encapsulates network payloads for sending and receiving over the TCP/IP network. 

There are various types of messages supported as indicated by the :attr:`~neo3.network.message.Message.type` attribute of the Message class.

.. autoclass:: neo3.network.message.Message
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:
   
.. autoclass:: neo3.network.message.MessageType
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: neo3.network.message.MessageConfig
   :members:
   :undoc-members:
   :show-inheritance:
