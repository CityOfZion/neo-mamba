.. image:: https://www.freepnglogos.com/uploads/under-construction-png/under-construction-sutton-group-heritage-realty-brokerage-durham-region-real-estate-16.png
    :height: 200px
    :width: 400 px
    :alt: under construction
    :align: center



The project has pivoted direction to focus on being a light SDK (=not requiring a full chain locally).
It is nearing the late stages of development before its first release in the new form. Given the large changes there are
still some important areas that are to be redone completely such as documentation.

Follow the project and check back soon if you're looking to use Python to

* Deploy smart contracts
* Transfer NEP-11 and NEP-17 tokens
* Vote for your favourite consensus node
* Interact with on-chain smart contracts
* Manage wallets
* Build and sign specialized transactions
* and more..

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

This SDK provides building blocks for Python developers to interact with the NEO blockchain without requiring to run a full node.
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
External documentation is outdated. Docstrings in source are up to date.
