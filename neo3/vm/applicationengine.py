from __future__ import annotations
from neo3 import contracts, storage, vm
from typing import Any


class ApplicationEngine(vm.ExecutionEngine):
    GAS_FREE = 0

    def __init__(self,
                 trigger: contracts.TriggerType,
                 container: Any,
                 snapshot: storage.Snapshot,
                 gas: int,
                 test_mode: bool = False
                 ):
        super(ApplicationEngine, self).__init__()
        self.snapshot = snapshot
        self.trigger = trigger
        self.test_mode = test_mode
        self.script_container = container
        self.gas_amount = self.GAS_FREE + gas
