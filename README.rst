.. image:: https://raw.githubusercontent.com/CityOfZion/visual-identity/develop/_CoZ%20Branding/_Logo/_Logo%20icon/_PNG%20200x178px/CoZ_Icon_DARKBLUE_200x178px.png
    :alt: CoZ logo

neo3-python
-----------

.. image:: https://circleci.com/gh/CityOfZion/neo3-python.svg?style=shield
  :target: https://circleci.com/gh/CityOfZion/neo3-python

.. image:: https://codecov.io/gh/CityOfZion/neo3-python/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/CityOfZion/neo3-python

.. image:: http://www.mypy-lang.org/static/mypy_badge.svg
  :target: http://mypy-lang.org/

This SDK intends to provide building blocks for Python developers to interact with the NEO blockchain as a means to lower the entry barrier.

It is a work in progress and thus you can expect that not all parts of the blockchain are supported. What is present should be functioning correctly unless explicitely mentioned (e.g. because they depend on structures not yet available).

Please report any issues on `Github <https://github.com/CityOfZion/neo3-python/issues>`_ or submit ideas how to improve the SDK.

Quick install
-------------
::

   pip install wheel neo3-python

or

::

  git clone https://github.com/CityOfZion/neo3-python.git
  cd neo3-python
  pip install wheel -e .


For full documentation including more elaborate install instructions go to `<https://neo3-python.coz
.io/docs/>`_.

Roadmap
-------
Over time the following components are expected to be implemented starting with the items in "SDK Core". As we
release versions and receive feedback components may be added or restructured. Some components may end up living in
separate repositories but be included here by default (e.g. virtual machine implementations).

.. image:: https://raw.githubusercontent.com/CityOfZion/neo3-python/master/docs/source/library/images/SDK_overview.png
    :alt: SDK overview

- Core (v0.1)
- Network (v0.1)
- Storage (v0.1)
- Virtual Machine
- Smart contracts

FAQ
---
1. ``make docs`` fails with ``no theme named 'neo3' found (missing theme.conf?)``. -> ``python setup.py install``.
Try again.
