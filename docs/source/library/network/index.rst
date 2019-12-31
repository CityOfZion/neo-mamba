.. _library-network-index:

*******
Network
*******

The modules described in this chapter provide mechanisms for NEO network connectivity.

The Message module in combination with the various payload modules provide means to build and decompose the NEO's TCP/IP network traffic. The Node module provides a way to establish connections to other nodes, hook into the various message handlers and/or listening to events like Blocks being received. The convenience package provides a SyncManager and NodeManager which take away the burden of syncing the chain and staying in sync allowing the user to focus on data post processing.

The list of modules described in this chapter is:

.. toctree::
   :maxdepth: 2

   capabilities.rst
   ipfilter.rst
   message.rst
   node.rst
   payloads/index.rst
   convenience.rst