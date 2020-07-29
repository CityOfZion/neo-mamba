from neo3 import vm, contracts, storage
from neo3.network import payloads
from neo3.core import types
from neo3.contracts.interop import register
from neo3 import blockchain
from typing import Optional

max_traceable_blocks = payloads.Transaction.MAX_VALID_UNTIL_BLOCK_INCREMENT


def _is_traceable_block(snapshot: storage.Snapshot, index: int):
    if index > snapshot.block_height:
        # Why does C# have this? It seems not reachable because it we always try to get
        # the block or tx from the snapshot and if it is in the snapshot it can never be
        # higher than the snapshot.block_height
        return False  # pragma: no cover
    # otherwise limit search back distance
    return index + max_traceable_blocks > snapshot.block_height


@register("System.Blockchain.GetHeight", 400, contracts.TriggerType.APPLICATION, contracts.native.CallFlags.NONE)
def blockchain_get_height(engine: vm.ApplicationEngine) -> bool:
    engine.push(vm.IntegerStackItem(engine.snapshot.block_height))
    return True


def _try_get_block(engine: vm.ApplicationEngine) -> Optional[payloads.Block]:
    height = engine.try_pop_uint()
    if height:
        block = engine.snapshot.blocks.try_get_by_height(height)
    else:
        data = engine.try_pop_bytes()
        if data is None or len(data) != 32:
            raise ValueError("Invalid data")
        block_hash = types.UInt256(data)
        block = engine.snapshot.blocks.try_get(block_hash)

    if block and not _is_traceable_block(engine.snapshot, block.index):
        block = None
    return block


@register("System.Blockchain.GetBlock", 2500000, contracts.TriggerType.APPLICATION, contracts.native.CallFlags.NONE)
def blockchain_get_block(engine: vm.ApplicationEngine) -> bool:
    try:
        block = _try_get_block(engine)
    except ValueError:
        return False

    if block is None:
        engine.push(vm.NullStackItem())
    else:
        engine.push(block.to_stack_item(engine.reference_counter))
    return True


@register("System.Blockchain.GetTransactionFromBlock", 1000000, contracts.TriggerType.APPLICATION,
          contracts.native.CallFlags.NONE)
def blockchain_get_transaction_from_block(engine: vm.ApplicationEngine) -> bool:
    try:
        block = _try_get_block(engine)
    except ValueError:
        return False

    if block is None:
        engine.push(vm.NullStackItem())
    else:
        index = engine.try_pop_int()
        if index is None:
            return False

        if index < 0 or index > (len(block.transactions) - 1):
            return False

        engine.push(block.transactions[index].to_stack_item(engine.reference_counter))
    return True


@register("System.Blockchain.GetTransaction", 1000000, contracts.TriggerType.APPLICATION,
          contracts.native.CallFlags.NONE)
def blockchain_get_transaction(engine: vm.ApplicationEngine) -> bool:
    tx_hash_bytes = engine.try_pop_bytes()
    if tx_hash_bytes is None:
        return False

    tx = engine.snapshot.transactions.try_get(types.UInt256(tx_hash_bytes))
    if tx and not _is_traceable_block(engine.snapshot, tx.block_height):
        tx = None

    if tx is None:
        engine.push(vm.NullStackItem())
    else:
        engine.push(payloads.Transaction.to_stack_item(engine.reference_counter))
    return True


@register("System.Blockchain.GetTransactionHeight", 1000000, contracts.TriggerType.APPLICATION,
          contracts.native.CallFlags.NONE)
def blockchain_get_transaction_height(engine: vm.ApplicationEngine) -> bool:
    tx_hash_bytes = engine.try_pop_bytes()
    if tx_hash_bytes is None:
        return False

    tx = engine.snapshot.transactions.try_get(types.UInt256(tx_hash_bytes))
    if tx and not _is_traceable_block(engine.snapshot, tx.block_height):
        tx = None

    if tx is None:
        engine.push(vm.IntegerStackItem(-1))
    else:
        engine.push(payloads.Transaction.to_stack_item(engine.reference_counter))
    return True


@register("System.Blockchain.GetContract", 1000000, contracts.TriggerType.APPLICATION, contracts.native.CallFlags.NONE)
def blockchain_get_contract(engine: vm.ApplicationEngine) -> bool:
    # will throw exception if fails (like C# does)
    item = engine.current_context.evaluation_stack.pop()

    if not isinstance(item, (vm.PrimitiveType, vm.BufferStackItem)):
        raise ValueError()

    contract_hash = types.UInt160(item.to_array())
    contract = engine.snapshot.contracts.try_get(contract_hash)
    if contract is None:
        engine.push(vm.NullStackItem())
    else:
        has_storage = vm.BooleanStackItem(contracts.ContractFeatures.HAS_STORAGE in contract.manifest.features)
        payable = vm.BooleanStackItem(contracts.ContractFeatures.PAYABLE in contract.manifest.features)
        script = vm.ByteStringStackItem(contract.script)
        array = vm.ArrayStackItem(engine.reference_counter)
        array.append([script, has_storage, payable])
        engine.push(array)
    return True
