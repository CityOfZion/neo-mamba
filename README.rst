.. image:: https://raw.githubusercontent.com/CityOfZion/visual-identity/develop/_CoZ%20Branding/_Logo/_Logo%20icon/_PNG%20200x178px/CoZ_Icon_DARKBLUE_200x178px.png
    :alt: CoZ logo

neo-mamba
-----------

.. image:: https://circleci.com/gh/CityOfZion/neo-mamba.svg?style=shield
  :target: https://circleci.com/gh/CityOfZion/neo-mamba

.. image:: https://codecov.io/gh/CityOfZion/neo-mamba/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/CityOfZion/neo-mamba

.. image:: http://www.mypy-lang.org/static/mypy_badge.svg
  :target: http://mypy-lang.org/

This SDK intends to provide building blocks for Python developers to interact with the NEO blockchain as a means to lower the entry barrier.

It is a work in progress and thus you can expect that not all parts of the blockchain are supported. What is present should be functioning correctly unless explicitely mentioned (e.g. because they depend on structures not yet available).

Please report any issues on `Github <https://github.com/CityOfZion/neo-mamba/issues>`_ or submit ideas how to improve the SDK.

Also check out our Python smart contract compiler `Boa <https://github.com/CityOfZion/neo3-boa>`_ !

Quick install
-------------
::

   pip install wheel
   pip install neo-mamba

or

::

  git clone https://github.com/CityOfZion/neo-mamba.git
  cd neo-mamba
  pip install wheel
  pip install wheel -e .

This installs mamba with only the ``MemoryDB`` as possible backend. In order to install the requirements to use the
LevelDB backend install the leveldb via extras

::

   pip install -e .[leveldb]

Ensure you have PIP >= 19.3

::

   pip install --upgrade "pip>=19.3"


For full documentation including more elaborate install instructions go to `<https://docs.coz.io/neo3/mamba/index.html>`_.

Roadmap
-------
Over time the following components are expected to be implemented starting with the items in "SDK Core". As we
release versions and receive feedback components may be added or restructured. Some components may end up living in
separate repositories but be included here by default (e.g. virtual machine implementations).

.. image:: https://raw.githubusercontent.com/CityOfZion/neo-mamba/master/docs/source/library/images/SDK_overview.png
    :alt: SDK overview

- Core (v0.1)
- Network (v0.1)
- Storage (v0.1)
- Virtual Machine
- Smart contracts (v0.4)
- Wallet support (v0.8)

Performance
-----------
At the time of releasing v0.7 there was no RC2 test net available for performance measuring. Very few changes in RC2
should affect performance, therefore the RC1 measurements below should still be pretty accurate. RC3 (v0.8) has even
less changes. Performance measurements are on hold until other priorities have been processed.

RC1 measurements
~~~~~~~~~~~~~~~~
RC1 is the first release, out of 5, where `neo-mamba` syncs the blockchain slower than the official client `neo-cli <https://github.com/neo-project/neo-node>`_.
Specifically, 30% slower. New bottlenecks as a result of the RC1 updates have been identified and will be improved on after
the required RC2 updates.

Performance was measured by letting each client sync the RC1 TestNet from an offline file up to block height 146253
as available at that time. Syncing was done without verifying the block witnesses (``--noverify`` flag in ``neo-cli``).
Each client used LevelDB as storage backend, with no other additional plugins running. Each client was synced separately
with no additional resource usage on the system. The test was performed on OSX 10.15.7 on a i7-9750H with 16 GB ram.

FAQ
---
1. ``make docs`` fails with ``no theme named 'neo3' found (missing theme.conf?)``. -> ``python setup.py install``.
Try again.
