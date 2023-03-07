# Getting started

Mamba is a Python SDK for interacting with the NEO blockchain. It abstracts away the complexities
of creating the data structures required to interact with smart contracts and change blockchain state. At the same time
it is flexible enough that you can handcraft transactions or even the instructions to be executed by the virtual machine. 
Communication with the network is done through JSON-RPC servers. A list of public RPC servers can be found 
[here](https://dora.coz.io/monitor).

Let's get setup and get a little taste of what using it looks like before diving into how it is structured and how to
work with it to achieve your goals.

## Requirements
* Python 3.10
* Linux, OSX or Windows

## Installation

=== "UNIX"
    ```linenums="0"
    pip install neo-mamba
    ```
=== "Windows"
    ```linenums="0"
    python -m pip install neo-mamba
    ```

### From source

=== "UNIX"
    ```linenums="0"
    git clone https://github.com/CityOfZion/neo-mamba.git
    cd neo-mamba
    python -m venv venv
    source venv/bin/activate
    pip install -e .
    ```
=== "Windows"
    ```linenums="0"
    git clone https://github.com/CityOfZion/neo-mamba.git
    cd neo-mamba
    python -m venv venv
    venv\Scripts\activate
    python -m pip install -e .
    ```

## Quick example
Get the NEO balance for an account

```py3
import asyncio
from neo3.api.wrappers import ChainFacade, NeoToken


async def main():
    facade = ChainFacade.node_provider_mainnet()
    neo = NeoToken()
    print(
        await facade.test_invoke(neo.balance_of("Nbsphyrdyz8ufeWKkNR1MUH2fuLABmqtqU"))
    )


if __name__ == "__main__":
    asyncio.run(main())
```
