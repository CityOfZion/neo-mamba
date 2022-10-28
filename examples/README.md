The modules in the root of this directory contain examples how to perform common actions on the NEO blockchain. 
The `shared` package contains all the test data and wallets to setup the private network and can be ignored.

**Requirements**

Each example creates an isolated private chain allowing you to play with the code. This requires 
[neo-express](https://github.com/neo-project/neo-express) to be installed (ideally globally).

If neo-express is not installed globally then you'll have to adjust the startup code of the example. Each sample starts
with 

```python
if __name__ == "__main__":
   with shared.NeoExpress() as neoxp:
        asyncio.run(example_airdrop(neoxp))
```

update this to include the neoxp executable path
```python
if __name__ == "__main__":
    with shared.NeoExpress.at("path_to_neoxp_executable") as neoxp:
        asyncio.run(example_airdrop(neoxp))
```