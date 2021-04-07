import hashlib
from typing import List
from neo3.network import payloads
from neo3.core import types, serialization, to_script_hash
from neo3 import vm, contracts, blockchain, storage


def contract_hash(sender: types.UInt160, checksum: int, name: str) -> types.UInt160:
    sb = vm.ScriptBuilder()
    sb.emit(vm.OpCode.ABORT)
    sb.emit_push(sender.to_array())
    sb.emit_push(checksum)
    sb.emit_push(name)
    return to_script_hash(sb.to_array())


def syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)


def test_engine(has_container=False, has_snapshot=False, default_script=True, call_flags=contracts.CallFlags.ALL):
    tx = payloads.Transaction._serializable_init()

    # this little hack basically nullifies the singleton behaviour and ensures we create
    # a new instance every time we call it. This in turn gives us a clean backend/snapshot
    blockchain.Blockchain.__it__ = None

    snapshot = blockchain.Blockchain(store_genesis_block=True).currentSnapshot
    if has_container and has_snapshot:
        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, tx, snapshot, 0, test_mode=True)
    elif has_container:
        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, tx, None, 0, test_mode=True)
    elif has_snapshot:
        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, None, snapshot, 0, test_mode=True)
    else:
        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, None, None, 0, test_mode=True)

    if default_script:
        engine.load_script_with_callflags(vm.Script(b'\x40'), call_flags)  # OpCode::RET
    return engine


def test_tx(with_block_height=1, signers: List[types.UInt160]=None) -> payloads.Transaction:
    if signers is None:
        new_signers = [payloads.Signer(types.UInt160.from_string("f782c7fbb2eef6afe629b96c0d53fb525eda64ce"), payloads.WitnessScope.GLOBAL)]
    else:
        new_signers = list(map(lambda v: payloads.Signer(v, payloads.WitnessScope.GLOBAL), signers))

    tx = payloads.Transaction(version=0,
                              nonce=123,
                              system_fee=456,
                              network_fee=789,
                              valid_until_block=with_block_height + 1,
                              attributes=[],
                              signers=new_signers,
                              script=b'\x01',
                              witnesses=[])
    tx.block_height = with_block_height
    return tx


def test_block(with_index=1) -> payloads.Block:
    tx = test_tx(with_index)
    header1 = payloads.Header(
        version=0,
        prev_hash=types.UInt256.from_string("f782c7fbb2eef6afe629b96c0d53fb525eda64ce5345057caf975ac3c2b9ae0a"),
        timestamp=123,
        index=with_index,
        primary_index=0,
        next_consensus=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
        witness=payloads.Witness(invocation_script=b'', verification_script=b'\x55')
    )
    block1 = payloads.Block(header1, transactions=[tx])
    block1.rebuild_merkle_root()
    return block1


class TestIVerifiable(payloads.IVerifiable):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.script_hashes = [types.UInt160.zero()]

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        pass

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        pass

    def __len__(self):
        pass

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        pass

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        pass

    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        return self.script_hashes
