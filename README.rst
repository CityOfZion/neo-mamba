.. image:: https://raw.githubusercontent.com/CityOfZion/visual-identity/develop/_CoZ%20Branding/_Logo/_Logo%20icon/_PNG%20200x178px/CoZ_Icon_DARKBLUE_200x178px.png
    :alt: CoZ logo

neo-mamba
-----------

.. image:: https://img.shields.io/github/workflow/status/CityOfZion/neo-mamba/CI
  :target: https://shields.io/

.. image:: https://coveralls.io/repos/github/CityOfZion/neo-mamba/badge.svg?branch=master
  :target: https://coveralls.io/github/CityOfZion/neo-mamba?branch=master

.. image:: http://www.mypy-lang.org/static/mypy_badge.svg
  :target: http://mypy-lang.org/

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/psf/black

This SDK intends to provide building blocks for Python developers to interact with the NEO blockchain without requiring to run a full node.
In order to interact with the chain and obtain information it relies heavily on RPC nodes. You can find a list of public RPC nodes `here <https://dora.coz.io/monitor>`_.
::

  Note that up to v0.11.0 this project had a full node focus. Maintaining full node consistency was a
  major resource consumer and ended up not leaving enough resources to develop the areas users are
  more interested in. As such the project direction pivoted since version 0.12.0 to focus on being
  an SDK again.

Please report any issues on `Github <https://github.com/CityOfZion/neo-mamba/issues>`_ or submit ideas how to improve the SDK.

Also check out our Python smart contract compiler `Boa <https://github.com/CityOfZion/neo3-boa>`_ !

Install
-------
Requires Python 3.10.
The SDK only version is currently only available from source. ``pip install mamba`` will get you the full node version
with different requirements (e.g. limited to Linux/OSX)

::

  git clone https://github.com/CityOfZion/neo-mamba.git
  cd neo-mamba
  pip install -e .

Developing or contributing
--------------------------
Install the requirements, modify the code and PR :-)
::

   pip install -e .[dev]

The project uses `Black <https://github.com/psf/black>`_ for code formatting. You might want to
`integrate <https://black.readthedocs.io/en/stable/integrations/editors.html>`_ this into your editor.

Documentation
-------------
Install the requirements and build them
::

   pip install -e .[docs]
   make docs

FAQ
---
1. ``make docs`` fails with ``no theme named 'neo3' found (missing theme.conf?)``. -> ``pip install .``.
Try again.
