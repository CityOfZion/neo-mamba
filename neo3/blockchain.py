from __future__ import annotations
from typing import List
from datetime import datetime, timezone
from neo3 import contracts, storage, settings, vm
from neo3.core import cryptography, types, to_script_hash, msgrouter
from neo3.network import payloads, convenience


class Blockchain(convenience._Singleton):
    genesis_block = None

    def init(self, backend: storage.IDBImplementation = None, store_genesis_block=True):  # type: ignore
        self.backend = backend if backend else settings.database
        self._current_snapshot = None
        self.genesis_block = self._create_genesis_block()
        self.genesis_block.rebuild_merkle_root()

        sb = vm.ScriptBuilder()
        for c in [contracts.GasToken(), contracts.NeoToken()]:
            sb.emit_contract_call(c.script_hash, "onPersist")  # type: ignore
            sb.emit(vm.OpCode.DROP)
        self.native_onpersist_script = sb.to_array()

        if self.currentSnapshot.block_height < 0 and store_genesis_block:
            self.persist(self.genesis_block)

    @property
    def currentSnapshot(self) -> storage.Snapshot:
        if self._current_snapshot is None:
            self._current_snapshot = self.backend.get_snapshotview()
        return self._current_snapshot  # type: ignore
        # mypy thinks it returns None

    @property
    def height(self):
        return self.currentSnapshot.block_height

    @staticmethod
    def get_consensus_address(validators: List[cryptography.ECPoint]) -> types.UInt160:
        script = contracts.Contract.create_multisig_redeemscript(
            len(validators) - (len(validators) - 1) // 3,
            validators
        )
        return to_script_hash(script)

    @staticmethod
    def _create_genesis_block() -> payloads.Block:
        script = vm.ScriptBuilder().emit_syscall(contracts.syscall_name_to_int("Neo.Native.Deploy")).to_array()
        b = payloads.Block(
            version=0,
            prev_hash=types.UInt256.zero(),
            timestamp=int(datetime(2016, 7, 15, 15, 8, 21, 0, timezone.utc).timestamp() * 1000),
            index=0,
            next_consensus=Blockchain.get_consensus_address(settings.standby_validators),
            witness=payloads.Witness(
                invocation_script=b'',
                verification_script=b'\x11'  # (OpCode.PUSH1)
            ),
            consensus_data=payloads.ConsensusData(primary_index=0, nonce=2083236893),
            transactions=[payloads.Transaction(
                version=0,
                script=script,
                system_fee=0,
                network_fee=0,
                nonce=0,
                valid_until_block=0,
                signers=[payloads.Signer(
                    account=to_script_hash(b'\x11'),
                    scope=payloads.WitnessScope.FEE_ONLY
                )],
                witnesses=[payloads.Witness(
                    invocation_script=b'',
                    verification_script=b'\x11'
                )]
            )]
        )
        return b

    def persist(self, block: payloads.Block):
        with self.backend.get_snapshotview() as snapshot:
            snapshot.block_height = block.index
            snapshot.blocks.put(block)
            snapshot.persisting_block = block

            if block.index > 0:
                engine = contracts.ApplicationEngine(contracts.TriggerType.SYSTEM,
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

            snapshot.commit()
            self._current_snapshot = snapshot
        msgrouter.on_block_persisted(block)
