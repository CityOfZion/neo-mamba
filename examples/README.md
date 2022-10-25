This directory contains examples how to perform common actions on the NEO blockchain. 

**Requirements**

Each example creates an isolated private chain allowing you to play with the code. This requires 
[neo-express](https://github.com/neo-project/neo-express) to be installed (ideally globally).

If neo-express is not installed globally then you'll have to adjust the startup code of the example. Each sample starts
with 

```python
if __name__ == "__main__":
   with shared.NeoExpress(
        shared.neoxpress_config_path, shared.neoxpress_batch_path
    ) as neoxp:

```

update this to include the neoxp executable path
```python
if __name__ == "__main__":
    with shared.NeoExpress(
        shared.neoxpress_config_path,
        shared.neoxpress_batch_path,
        "path_to_neoxp_executable",
    ) as neoxp:
        asyncio.run(main(neoxp))
```