.. image:: .github/resources/images/logo.png
    :width: 400 px

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

.. image:: https://img.shields.io/pypi/pyversions/neo-mamba
   :alt: PyPI - Python Version

.. image:: .github/resources/images/platformbadge.svg
   :alt: works on

This project is for you if you're looking to use Python to

* Deploy smart contracts
* Transfer NEP-11 and NEP-17 tokens
* Vote for your favourite consensus node
* Interact with on-chain smart contracts
* Manage wallets
* Build and sign specialized transactions
* and more..

This SDK provides building blocks for Python developers to interact with the NEO blockchain without requiring to run a full node.
In order to interact with the chain and obtain information it relies heavily on RPC nodes. You can find a list of public RPC nodes `here <https://dora.coz.io/monitor>`_.

Please report any issues on `Github <https://github.com/CityOfZion/neo-mamba/issues>`_ or submit ideas how to improve the SDK.

Also check out our Python smart contract compiler `Boa <https://github.com/CityOfZion/neo3-boa>`_ !

Install & Documentation
-----------------------
Installation instructions, how to interact with smart contrats as well as API reference documentation can be found at
https://dojo.coz.io/neo3/mamba/

Developing or contributing
--------------------------
Install the requirements, modify the code and PR :-)
::

   pip install -e .[dev]

The project uses `Black <https://github.com/psf/black>`_ for code formatting. You might want to
`integrate <https://black.readthedocs.io/en/stable/integrations/editors.html>`_ this into your editor.
