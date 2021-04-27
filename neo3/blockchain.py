from __future__ import annotations
from typing import List
from datetime import datetime, timezone
from neo3 import contracts, storage, settings, vm
from neo3.core import cryptography, types, to_script_hash, msgrouter, syscall_name_to_int
from neo3.network import payloads, convenience


class Blockchain(convenience._Singleton):
    genesis_block = None

    def init(self, backend: storage.IDBImplementation = None, store_genesis_block=True):  # type: ignore
        self.backend = backend if backend else settings.database
        self._current_snapshot = None
        self.genesis_block = self._create_genesis_block()
        self.genesis_block.rebuild_merkle_root()

        sb = vm.ScriptBuilder().emit_syscall(syscall_name_to_int("System.Contract.NativeOnPersist"))
        self.native_onpersist_script = sb.to_array()
        sb = vm.ScriptBuilder().emit_syscall(syscall_name_to_int("System.Contract.NativePostPersist"))
        self.native_postpersist_script = sb.to_array()

        if self.currentSnapshot.best_block_height < 0 and store_genesis_block:
            self.persist(self.genesis_block)

    @property
    def currentSnapshot(self) -> storage.Snapshot:
        if self._current_snapshot is None:
            self._current_snapshot = self.backend.get_snapshotview()
        return self._current_snapshot  # type: ignore
        # mypy thinks it returns None

    @property
    def height(self):
        return self.currentSnapshot.best_block_height

    @staticmethod
    def _create_genesis_block() -> payloads.Block:
        h = payloads.Header(
            version=0,
            prev_hash=types.UInt256.zero(),
            timestamp=int(datetime(2016, 7, 15, 15, 8, 21, 0, timezone.utc).timestamp() * 1000),
            index=0,
            primary_index=0,
            next_consensus=contracts.Contract.get_consensus_address(settings.standby_validators),
            witness=payloads.Witness(
                invocation_script=b'',
                verification_script=b'\x11'  # (OpCode.PUSH1)
            ),
        )
        return payloads.Block(header=h, transactions=[])

    def persist(self, block: payloads.Block):
        with self.backend.get_snapshotview() as snapshot:
            snapshot.persisting_block = block

            engine = contracts.ApplicationEngine(contracts.TriggerType.ON_PERSIST,
                                                 None, snapshot, 0, True)  # type: ignore
            engine.load_script(vm.Script(self.native_onpersist_script))
            if engine.execute() != vm.VMState.HALT:
                raise ValueError(f"Failed onPersist in native contracts: {engine.exception_message}")

            cloned_snapshot = snapshot.clone()
            for tx in block.transactions:
                tx.block_height = block.index
                cloned_snapshot.transactions.put(tx)
                cloned_snapshot.transactions.commit()

                engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION,
                                                     tx,
                                                     cloned_snapshot,
                                                     tx.system_fee)
                engine.load_script(vm.Script(tx.script))
                state = engine.execute()
                if state == vm.VMState.HALT:
                    cloned_snapshot.commit()
                else:
                    cloned_snapshot = snapshot.clone()

            engine = contracts.ApplicationEngine(contracts.TriggerType.POST_PERSIST,
                                                 None, snapshot, 0, True)  # type: ignore
            engine.load_script(vm.Script(self.native_postpersist_script))
            if engine.execute() != vm.VMState.HALT:
                raise ValueError(f"Failed postPersist in native contracts: {engine.exception_message}")
            """
            LedgerContract updates the current block in the post_persist event
            this means transactions in the persisting block that call LedgerContract.current_hash/current_index()
            will get refer the (previous) block hash/index, not the block they're included in.

            Therefore we wait with persisting the block until here
            """
            snapshot.blocks.put(block)
            snapshot.best_block_height = block.index

            snapshot.commit()
            self._current_snapshot = snapshot
        msgrouter.on_block_persisted(block)
