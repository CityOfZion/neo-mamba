:mod:`block` --- All things Block related
=========================================

This module contains the famous Block class (and subcomponents) as well as payloads to request block data from the network.

.. classoverview::
   :class:`~neo3.network.payloads.block.Block`
   :class:`~neo3.network.payloads.block.Header`
   :class:`~neo3.network.payloads.block.TrimmedBlock`
   :class:`~neo3.network.payloads.block.GetBlocksPayload`
   :class:`~neo3.network.payloads.block.GetBlockByIndexPayload`
   :class:`~neo3.network.payloads.block.HeadersPayload`
   :class:`~neo3.network.payloads.block.MerkleBlockPayload`

.. _library-network-block-block:

Block and subcomponents
-----------------------

A Block is a data structure pertaining to the NEO network containing transactions that are permanently recorded. Its arguably most important content are the transactions which modify the state of the chain (e.g. token balance updates) or execute a smart contract of which the execution result is recorded. 

.. autoclass:: neo3.network.payloads.block.Block
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.block.TrimmedBlock
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.block.Header
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. _library-network-block-payloads:

Payloads
--------
There are four payloads discussed in this section. Two for requesting data and two for replying to such requests.

Requesting
^^^^^^^^^^
The :class:`~neo3.network.payloads.block.GetBlocksPayload` and :class:`~neo3.network.payloads.block.GetBlockByIndexPayload` are used to request Block data (including block Headers). Use these in conjunction with the :const:`~neo3.network.message.MessageType.GETBLOCKS` and :const:`~neo3.network.message.MessageType.GETBLOCKBYINDEX` or :const:`~neo3.network.message.MessageType.GETHEADERS` message types.

The GetBlocksPayload is used in the classic Bitcoin like data exchange structure in which you request a list of hashes first, then request the actual Block data using the hash list. This gives the flexibility to request a series of Block data which are non-consecutive in a single request.

The GetBlockByIndexPayload is a payload new to NEO3 with which you can directly request the full Block using a block height and a count. This is a simplified interface compared to using the GetBlocksPayload but is limited to consecutive data in a single request.
The GetBlocksByIndexPayload is also used as for requesting headers via the :const:`~neo3.network.message.MessageType.GETHEADERS` message type.

Responding
^^^^^^^^^^
The :class:`~neo3.network.payloads.block.HeadersPayload` is used to reply to a :const:`~neo3.network.message.MessageType.HEADERS` type message and returns :class:`~neo3.network.payloads.block.Header` objects.

The :class:`~neo3.network.payloads.block.MerkleBlockPayload` is used to reply to a :const:`~neo3.network.message.MessageType.GETDATA` or :const:`~neo3.network.message.MessageType.GETBLOCKDATA` type message under the specific condition that a bloomfilter has been loaded (TODO: add ref to filter). Responding to the aforementioned message types under the condition that `no` bloomfilter is present is respectively done via an :const:`~neo3.network.message.MessageType.INV` type message with an InventoryPayload or a :const:`~neo3.network.message.MessageType.BLOCK` type message where the Block object is the message payload.



.. autoclass:: neo3.network.payloads.block.GetBlocksPayload
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.block.GetBlockByIndexPayload
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.block.HeadersPayload
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.block.MerkleBlockPayload
   :undoc-members:
   :show-inheritance:
   :inherited-members:
