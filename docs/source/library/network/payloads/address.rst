:mod:`address` --- Network address classes
==========================================

This module contains several classes for working with network addresses. 

.. classoverview::
   :class:`~neo3.network.payloads.AddrPayload`
   :class:`~neo3.network.payloads.NetworkAddress`
   :class:`~neo3.network.payloads.AddressState`
   :class:`~neo3.network.payloads.DisconnectReason`

The :class:`~neo3.network.payloads.AddrPayload` is used to share :class:`~neo3.network.payloads.NetworkAddress`\es with other nodes. A `NetworkAddress` is not just a wrapper around a hostname and port but also holds attributes for labelling its performance using the :class:`~neo3.network.payloads.AddressState` enum and a list of capabilities it has (more next).

Not all nodes in the network have similar performance when it comes to responding to network requests. There are many reasons for this such as geographical location and hardware (disk/cpu/memory) in relationship to the amount of connected nodes. In processes like chain syncing one might want to track a node's performance to ensure the best response times. The network convenience classes do exactly this.

The node listening on a particular address can run a variety of services such as an RPC server, Websocket server or TCP/IPv4 server. This information is shared during the initial handshake with a node (see :ref:`version <library-network-payloads-version>`), included in the network address state and shared with other nodes asking for addresses (see :ref:`requesting address list <message-usage-getaddr>`). This allows one to filter addresses based on the specific services it offers. 


.. autoclass:: neo3.network.payloads.AddrPayload
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.NetworkAddress
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: neo3.network.payloads.DisconnectReason
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: neo3.network.payloads.AddressState
   :members:
   :undoc-members:
   :show-inheritance:
