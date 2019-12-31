:mod:`node` --- NEO network node
================================

.. classoverview::
   :class:`~neo3.network.node.NeoNode`

A :class:`~neo3.network.node.NeoNode` in the networking context is considered an P2P endpoint with which NEO specific network :ref:`message <library-network-message>`\s can be exchanged. It is not to be confused with the generic node term commonly used to refer to a client application that participates in the blockchain network. A node in the generic term would consist of a NeoNode for the network layer, a virtual machine for transaction processing, a persistence layer for storing data and optionally an interface like a GUI or CLI.

.. rubric:: Connecting

Establishing a connection to a node requires just 3 pieces of information. 

1) a network :attr:`~neo3.network.payloads.version.VersionPayload.magic` to select the right network (MainNet, TestNet, private net).
2) an IP address.
3) a port number. 

With this information at hand we can establish a basic connection as follows.

.. code:: python

    import asyncio
    from neo3 import settings
    from neo3.network import node

    async def main():
        # set network magic to NEO MainNet
        settings.network.magic = 5195086

        node_client, error = await node.NeoNode.connect_to('127.0.0.1', 40333)
        if node_client:
            print(f"Connected to {node_client.version.user_agent} @ {node_client.address}")
            # send and receive messages

    if __name__ == "__main__":
        asyncio.run(main())

The :meth:`~neo3.network.node.NeoNode.connect_to` function establishes a network connection and performs the initial handshake. Under the hood it uses :meth:`asyncio.loop.create_connection <python:asyncio.loop.create_connection>` with a :class:`~neo3.network.protocol.NeoProtocol` as the factory.

Once a connection is established it is up to the caller to implement a message loop for handling incoming messages. Such a loop can be started via the convenience :meth:`~neo3.network.node.NeoNode.start_message_handler` method. This loop reads network messages and dispatches them to their associates handlers. 


Connect and disconnect events are broadcasted using `Events <https://pypi.org/project/Events/>`__ via `on_node_connected(client_instance)` and `on_node_disconnected(client_instance, reason)`. You can listen to these events as follows:

.. code:: python

   from neo3.core import msgrouter

   def node_connected(node_client):
       print(f"Connected to node {node_client.version.user_agent} @ {node_client.address}")

   def node_disconnected(node_client, reason):
      print(f"Disconnected from node {node_client.version.user_agent} @ {node_client.address} for reason {reason}")

   msgrouter.on_node_connected += node_connected
   msgrouter.on_node_disconnected += node_disconnected

When connected you likely want to exchange data.

.. rubric:: Exchanging data

At the most basic level you have the :meth:`~neo3.network.node.NeoNode.send_message` and :meth:`~neo3.network.node.NeoNode.read_message` commands. These respectivily take or provide you a network Message and a payload. 

A handfull of convenience functions are present for common requests and responses. Specifically:

- :meth:`~neo3.network.node.NeoNode.request_address_list`
- :meth:`~neo3.network.node.NeoNode.send_address_list`
- :meth:`~neo3.network.node.NeoNode.request_headers`
- :meth:`~neo3.network.node.NeoNode.send_headers`
- :meth:`~neo3.network.node.NeoNode.request_blocks`
- :meth:`~neo3.network.node.NeoNode.request_block_data`
- :meth:`~neo3.network.node.NeoNode.request_data`

Finally, in conjunction with the convenience message loop (started via :meth:`~neo3.network.node.NeoNode.start_message_handler`) a list of message handlers are available that can be overwritten by updating the :attr:`~neo3.network.node.NeoNode.dispatch_table` dictionary to set your own handler. All handlers start with `handler_<name>` and take a :class:`~neo3.network.message.Message` as parameter.

.. autoclass:: neo3.network.node.NeoNode
    :members:
    :undoc-members:

   