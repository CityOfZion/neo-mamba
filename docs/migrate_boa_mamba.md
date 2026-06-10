# Table of Contents

1. [Root package update](#root-package-update)
2. [Events](#events)
3. [Manifest meta data](#manifest-meta-data)
4. [Conversion utility functions](#conversion-utility-functions)
5. [sc.runtime](#scruntime)
   - [Script values](#script-values)
   - [various](#various)
6. [Storage](#storage)

## Root package update
**old**

```boa3.sc.*```

**new**

```neo3.sc.*```


## Events
Events creation changed to a decorator style as used in other places.

**old**
```python
from boa3.sc.utils import CreateNewEvent

bind_asset = CreateNewEvent([("nfid", int), ("asid", int)], "Bind")
```

**new**
```python
from neo3.sc.compiletime import event

@event("Bind")
def bind_asset(nfid: int, asid: int):
    pass
```

## Manifest meta data
**old**
```python
from boa3.sc.compiletime import NeoMetadata

def manifest_metadata() -> NeoMetadata:
    meta = NeoMetadata()
    meta.author = "ITEM Systems"
    meta.description = "A digital twin contract for the NFI ecosystem."
    meta.email = "contact@item.systems"
    meta.supported_standards = []

    meta.add_permission(methods='ownerOf')

    return meta
```

**new**
```python
from neo3.sc.compiletime import ContractManifest, Permission

ContractManifest(
    permissions=[
        Permission("*", ["ownerOf"]),
    ],
    extra={
        "author": "ITEM Systems",
        "description": "A digital twin contract for the NFI ecosystem.",
        "email": "contact@item.systems",
    },
)
```

## conversion utility functions
The `to_bool`, `to_bytes`, `to_int`, `to_str` have been removed. 
Use the standard Python methods `bool()`, `bytes` `int()`, `str()`.  

**old**
```python
from boa3.sc.utils import to_bytes, to_int, to_str, to_bool

x = 1
ba = to_bytes(x) 
b = to_bool(x)
s = to_str(x)
i = to_int(b'\x01')
```

**new**
```python
x = 1
ba = x.to_bytes()
b = bool(x)
s = str(x)
i = int.from_bytes(b'\x01', 'little')
```

## sc.runtime
The following describes changes specific to the `neo3.sc.runtime` package.

### script values
Renamed and turned into functions instead of builtins

**old**
```python
calling_script_hash
entry_script_hash
executing_script_hash
script_container
```

**new**
```python
get_calling_script_hash()
get_entry_script_hash()
get_executing_script_hash()
get_script_container()
```

### various
Renamed and turned into functions instead of builtins
- `time` -> `get_time()`
- `invocation_counter` -> `get_invocation_counter()`

# storage
Storage `get()` now returns `Optional[bytes]`. 
This allows you to differentiate between an empty value `b''` stored under the key and the key not existing.
