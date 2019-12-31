.. _library-network-payloads-version:

:mod:`version` --- Node handshake data
======================================

.. classoverview::
   :class:`neo3.network.payloads.version.VersionPayload`

Version information is exchanged with the remote node upon first connection. It is part of the handshake sequence. 

The VersionPayload contains attributes that uniquely identify the node, ensures the node is intended to work on the same network (think Mainnet vs Testnet) and make its :ref:`capabilities <library-network-capabilities>` known to the remote node.
	

.. autoclass:: neo3.network.payloads.version.VersionPayload
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:
