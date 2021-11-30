Changelog
=========

All notable changes to this project are documented in this file.

[0.9.4] 2021-11-30
------------------
- Fixes as a result of Auditing the latest blocks on the network.

[0.9.3] 2021-11-01
------------------
- Update 3rd party packages
- Fix ``BloomFilter.check()``
- Add RPC client for Neo Node base methods

[0.9.2] 2021-10-11
------------------
- NEO C# v3.03 code updates

[0.8] 2021-06-04
----------------
- RC3 code parity updates
- Add basic wallet support
- Restrict to Python 3.8
- Update docstrings
- Add ``ExtensiblePayload` handler to network
- Add ``to_json/from_json`` support to ``Transaction`` class
- Fix removing vote
- Fix payload for requesting headers
- Automatically add inventory to relay cache when relaying

[0.7] 2021-05-12
----------------
- RC2 updates

[0.6] 2021-04-30
----------------
- RC1 updates

[0.5] 2021-04-07
----------------
- Preview 5 updates

[0.4.1] 2020-12-23
------------------
- Cache candidates
- Cache NEO/GAS contract state
- Drop pure ECC library for own native
- Drop build-in JSON for faster JSON library
- Cache validators
- Moved ``pre_execute_instruction()`` inside partial native ``ApplicationEngine``
- Reduced ``UInt`` types initialization overhead

[0.4] 2020-12-10
----------------
- Add interoperability layer (too many changes to mention)

[0.3] 2020-08-20
----------------
- Add Manifest and NEO Executable Format (NEF) support
- Update Message format to include compressed data length
- Change network payload for requesting headers
- Change Cosigners to Signer and merge with Transaction
- Refactor ISerializable such that subclasses have a self explanatory initialization methods
- Update NodeManager to include a ping service to stay up to date faster


[0.2] 2020-05-11
------------------
- Fix setup.py for PIP versions >= 20
- Fix some storage all() implementations not returning readonly objects, add additional tests to cover these.
- Fix StreamReader protocol for Python >= 3.8
- Fix mypy errors for Python >= 3.8
- Update Transaction hash() function to be inline with NEO v3.0.0-preview2 + update test cases
- Update Inventory types to be inline with NEO v3.0.0-preview2
- Add checks to test if leveldb exists without preventing the InMemoryDB to be used.