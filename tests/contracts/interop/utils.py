from neo3.network import payloads
from neo3.core import types
from neo3 import vm, contracts, blockchain


def test_engine(has_container=False, has_snapshot=False):
    tx = payloads.Transaction()

    # this little hack basically nullifies the singleton behaviour and ensures we create
    # a new instance every time we call it. This in turn gives us a clean backend/snapshot
    blockchain.Blockchain.__it__ = None

    snapshot = blockchain.Blockchain().currentSnapshot
    if has_container and has_snapshot:
        engine = vm.ApplicationEngine(contracts.TriggerType.APPLICATION, tx, snapshot, 0, test_mode=True)
    elif has_container:
        engine = vm.ApplicationEngine(contracts.TriggerType.APPLICATION, tx, None, 0, test_mode=True)
    elif has_snapshot:
        engine = vm.ApplicationEngine(contracts.TriggerType.APPLICATION, None, snapshot, 0, test_mode=True)
    else:
        engine = vm.ApplicationEngine(contracts.TriggerType.APPLICATION, None, None, 0, test_mode=True)

    engine.load_script(vm.Script(b'\x01'))
    return engine


def test_block(with_index=1):
    tx = payloads.Transaction(version=0,
                              nonce=123,
                              sender=types.UInt160.from_string("4b5acd30ba7ec77199561afa0bbd49b5e94517da"),
                              system_fee=456,
                              network_fee=789,
                              valid_until_block=1,
                              attributes=[],
                              cosigners=[],
                              script=b'\x01',
                              witnesses=[])

    block1 = payloads.Block(version=0,
                            prev_hash=types.UInt256.from_string(
                                "f782c7fbb2eef6afe629b96c0d53fb525eda64ce5345057caf975ac3c2b9ae0a"),
                            timestamp=123,
                            index=with_index,
                            next_consensus=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
                            witness=payloads.Witness(invocation_script=b'', verification_script=b'\x55'),
                            consensus_data=payloads.ConsensusData(primary_index=1, nonce=123),
                            transactions=[tx])
    block1.rebuild_merkle_root()
    return block1
