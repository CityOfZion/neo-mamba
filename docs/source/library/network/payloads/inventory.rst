:mod:`inventory` --- Chain inventory
====================================

.. classoverview::
   :class:`neo3.network.payloads.inventory.InventoryType`
   :class:`neo3.network.payloads.inventory.InventoryPayload`
   :class:`neo3.network.payloads.inventory.IInventory`

There are three types of inventory in the NEO chain being Block, Consensus and Transaction, as indicated by :class:`~neo3.network.payloads.inventory.InventoryType`.

Inventory types are shared over the network in a variety of scenarios. `Consensus` inventory types are relayed between NEO's consensus nodes as the data to use to come to an agreement on the next Block to produce. 

Next, the `Block` inventory type is send as a reponse to a :ref:`network request <message-usage-getblocks>`. Additionally, the reference C# neo-cli client regularly broadcasts its latest block hash through this mechanism. 

Finally, the `Transaction` inventory type is commonly used when a new transaction needs to be relayed or is :ref:`requested <message-usage-mempool>` from the mempool.

.. autoclass:: neo3.network.payloads.inventory.InventoryType
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.inventory.InventoryPayload
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.inventory.IInventory
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:
