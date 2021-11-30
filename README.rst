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

Documentation
-------------
Install the requirements and build them
::

   pip install -e .[docs]
   make docs

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

OSX Big Sur issues
------------------
Parts of Mamba currently do not work as intended on OSX Big Sur. More specific: Mamba makes use of ``PYBIND11`` to wrap
performance critical code written in C++ (i.e. the Virtual Machine). Big Sur requires Python 3.9.1 at `minimum <https://www.python.org/downloads/release/python-391/>`_, which in
turn requires a newer version of ``PYBIND11``. That newer ``PYBIND11`` version ultimately leads to segmentation faults
in the VM. We opted to return to our known working version of ``PYBIND11`` until resolved such that at least Catalina
users can continue to use all features.


FAQ
---
1. ``make docs`` fails with ``no theme named 'neo3' found (missing theme.conf?)``. -> ``python setup.py install``.
Try again.
