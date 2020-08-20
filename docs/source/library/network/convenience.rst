.. _library-network-convenience:

******************
Convenient syncing
******************

.. classoverview::
   :class:`neo3.network.convenience.nodemanager.NodeManager`
   :class:`neo3.network.convenience.syncmanager.SyncManager`

Syncing blockchain data at first sight sounds simple but is actually a very complex task. A network client operates in a constantly changing environment where other nodes join and leave the network, are in different geographical locations, have a variety of hardware resources, have varying loads depending on the number of clients and their requests, have varying available bandwidth and possibly even face adversiary actors. In such an environment you want a process that can handle and recover from unexpected behaviour (be it invalid requests, no responses etc). The two classes discussed next do exactly that and allow the user to focus on post processing the Blocks instead of retrieval.

Introducing :class:`~neo3.network.convenience.nodemanager.NodeManager` and :class:`~neo3.network.convenience.syncmanager.SyncManager`. 

.. rubric:: Node manager

The node manager is responsible for establishing and maintaining and pool of active connections to healthy NEO nodes. 

When started it begins by connecting to a seedlist obtained from the global settings object. It runs three services on an interval.

1. a connection pool monitor to ensure it meets the configured mininum and maximum client settings and attempt to fill any open spots . 
2. an address list filler which asks for new addresses from connected nodes to ensure it always has a new node to connect to.
3. a connection pool monitor to ensure that the remote nodes local blockchain height keeps advancing. If they are stuck they'll be replaced by a new node and tagged for poor performance.

In the unlikely event that all nodes fail and there are no more new addresses to connect to, the node manager will recycle all addresses that it historically was able to connect to. This means addresses that it failed to connect to are not retried. Be aware that estbalishing a connection can take time and so recovery is not instantaneous. The recovery times can be tweaked by adjusting the :attr:`~neo3.network.convenience.nodemanager.NodeManager.MAX_NODE_POOL_ERROR` and :attr:`~neo3.network.convenience.nodemanager.NodeManager.POOL_CHECK_INTERVAL` class attributes.


A minimal usage example for individual use is

.. code:: python

   import asyncio
   from neo3 import settings
   from neo3.network import convenience
   from neo3.core import msgrouter


   def connection_done(node_client, failure):
       if failure:
           print(f"Failed to connect to {failure[0]} reason: {failure[1]}.")
       else:
           print(f"Connected to node {node_client.version.user_agent} @ {node_client.address}")

   async def main():
       # set network magic to NEO MainNet
       settings.network.magic = 5195086

       # add a local node to the seedlist for the first connection
       settings.network.seedlist = ['127.0.0.1:40333']

       # listen to the connection event broad casted by the node manager
       msgrouter.on_client_connect_done += connection_done

       node_mgr = convenience.NodeManager()
       node_mgr.start()

       # keep alive
       while True:
           await asyncio.sleep(1)

   if __name__ == "__main__":
       asyncio.run(main())

If you want the full syncing experience take a look at the :ref:`example <library-convenience-full-usage-example>` below.


.. autoclass:: neo3.network.convenience.nodemanager.NodeManager
   :members: start, shutdown, ADDR_QUERY_INTERVAL, MONITOR_HEIGHT_INTERVAL, POOL_CHECK_INTERVAL, MAX_NODE_POOL_ERROR, MAX_NODE_ERROR_COUNT, MAX_NODE_TIMEOUT_COUNT, PING_INTERVAL
   :undoc-members:
   :show-inheritance:

.. rubric:: Sync manager

The sync manager is responsible for bringing the local blockchain in sync with the global blockchain and keeping it in sync.

The sync manager depends on :class:`~neo3.network.convenience.nodemanager.NodeManager` for providing it with healty nodes to request data from. This means it requires the node manager to be started ahead of the sync manager.

A full usage example is

.. _library-convenience-full-usage-example:

.. code:: python

   import asyncio
   from neo3 import settings
   from neo3.network import convenience, payloads
   from neo3.core import msgrouter

   def connection_done(node_client, failure):
       if failure:
           print(f"Failed to connect to {failure[0]} reason: {failure[1]}.")
       else:
           print(f"Connected to node {node_client.version.user_agent} @ {node_client.address}")

   def block_received(from_nodeid: int, block: payloads.Block):
       print(f"Received block with height {block.index}")

   async def main():
       # set network magic to NEO MainNet
       settings.network.magic = 195086

       # add a local node to test against
       settings.network.seedlist = ['127.0.0.1:40333']

       # listen to the connection events broadcasted by the node manager
       msgrouter.on_client_connect_done += connection_done

       # listen to block received events
       msgrouter.on_block += block_received

       node_mgr = convenience.NodeManager()
       node_mgr.start()

       sync_mgr = convenience.SyncManager()
       await sync_mgr.start()

       # keep alive
       while True:
           await asyncio.sleep(1)

   if __name__ == "__main__":
       asyncio.run(main())

Enable logging if you're interested to see the internals in action.

.. code:: python
   
   import logging

   stdio_handler = logging.StreamHandler()
   stdio_handler.setLevel(logging.DEBUG)
   stdio_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s - %(module)s:%(lineno)s %(message)s"))

   network_logger = logging.getLogger('neo3.network')
   network_logger.addHandler(stdio_handler)
   network_logger.setLevel(logging.DEBUG)



.. autoclass:: neo3.network.convenience.syncmanager.SyncManager
   :members: start, shutdown, BLOCK_MAX_CACHE_SIZE, BLOCK_NETWORK_REQ_LIMIT, BLOCK_REQUEST_TIMEOUT
   :undoc-members:
   :show-inheritance: