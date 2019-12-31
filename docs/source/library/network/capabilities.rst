.. _library-network-capabilities:

:mod:`capabilities` --- Node services
=====================================

.. classoverview::
   :class:`~neo3.network.capabilities.NodeCapability`
   :class:`~neo3.network.capabilities.ServerCapability`
   :class:`~neo3.network.capabilities.FullNodeCapability`
   :class:`~neo3.network.capabilities.NodeCapabilityType`

This module describes the services supported by a node.

A node can provide a variety of services such as a Websocket server or TCP/IPv4 server. These capabilities are shared with a remote node through a :class:`~neo3.network.payloads.version.VersionPayload` during the handshake sequence when setting up a connection. Over time additional services are expected to be added by the NEO Core team. 

The :class:`~neo3.network.capabilities.ServerCapability` tells a node which communication layers (TCP or Websocket) are support for exchanging NEO specific messages. For more information on what information can be requested and how refer to the :ref:`message <message-type-purpose>` module.


.. note::
	This SDK only supports communicating at the TCP transport layer, not on the higher level Websocket application layer.

Where `ServerCapability` shares the details where the general information can be retrieved from, the :class:`~neo3.network.capabilities.FullNodeCapability` indicates that the endpoint maintains full blockchain data and support relaying of data. 

.. autoclass:: neo3.network.capabilities.NodeCapability
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.capabilities.ServerCapability
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.capabilities.FullNodeCapability
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.capabilities.NodeCapabilityType
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

