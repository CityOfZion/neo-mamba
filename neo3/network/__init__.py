"""
P2P network classes. Holds `Block` and `Transaction` payloads (among others), a network node and helper classes for
 syncing the chain.
"""
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
