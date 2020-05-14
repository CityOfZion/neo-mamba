Changelog
=========

All notable changes to this project are documented in this file.

[0.2] 2020-05-11
------------------
- Fix setup.py for PIP versions >= 20
- Fix some storage all() implementations not returning readonly objects, add additional tests to cover these.
- Fix StreamReader protocol for Python >= 3.8
- Fix mypy errors for Python >= 3.8
- Update Transaction hash() function to be inline with NEO v3.0.0-preview2 + update test cases
- Update Inventory types to be inline with NEO v3.0.0-preview2
- Add checks to test if leveldb exists without preventing the InMemoryDB to be used.