from __future__ import annotations
from neo3.network import payloads
from neo3.core import utils as core_utils
from neo3 import contracts, storage, vm, wallet
from neo3.contracts.interop.crypto import CHECKSIG_PRICE


def add_system_fee(tx: payloads.Transaction, snapshot: storage.Snapshot) -> None:
    tx.system_fee = calculate_system_fee(tx, snapshot)


def add_network_fee(tx: payloads.Transaction, snapshot: storage.Snapshot, account: wallet.Account) -> None:
    tx.network_fee = calculate_network_fee(tx, snapshot, account)


def calculate_system_fee(tx: payloads.Transaction, snapshot: storage.Snapshot) -> int:
    engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, tx, snapshot, 0, test_mode=True)
    engine.load_script(vm.Script(tx.script))
    if engine.execute() == vm.VMState.FAULT:
        raise ValueError("Transaction script execution failed")
    else:
        return engine.gas_consumed


def calculate_network_fee(tx: payloads.Transaction, snapshot: storage.Snapshot, account: wallet.Account) -> int:
    if len(tx.signers) == 0:
        raise ValueError("Cannot calculate the network fee without a sender in the transaction.")

    hashes = tx.get_script_hashes_for_verifying(snapshot)
    network_fee_size = (tx.HEADER_SIZE
                        + core_utils.get_var_size(tx.signers)  # type: ignore
                        + core_utils.get_var_size(tx.attributes)  # type: ignore
                        + core_utils.get_var_size(tx.script)  # type: ignore
                        + core_utils.get_var_size(len(hashes))  # type: ignore
                        )
    exec_fee_factor = contracts.PolicyContract().get_exec_fee_factor(snapshot)

    network_fee = 0
    for i, hash_ in enumerate(hashes):
        witness_script = None
        if hash_ == account.script_hash and account.contract and len(account.contract.script) > 0:
            witness_script = account.contract.script

        if witness_script is None and len(tx.witnesses) > 0:
            for witness in tx.witnesses:
                if witness.script_hash() == hash_:
                    witness_script = witness.verification_script
                    break

        if witness_script is None or (witness_script and len(witness_script) == 0):
            raise ValueError("Using a smart contract as a witness is not yet supported in mamba")

        elif contracts.Contract.is_signature_contract(witness_script):
            network_fee_size += 67 + core_utils.get_var_size(witness_script)  # type: ignore
            network_fee = exec_fee_factor * signature_contract_costs()
        elif contracts.Contract.is_multisig_contract(witness_script):
            _, threshold, public_keys = contracts.Contract.parse_as_multisig_contract(witness_script)
            invocation_script_size = 66 * threshold
            network_fee_size += (core_utils.get_var_size(invocation_script_size)  # type: ignore
                                 + invocation_script_size
                                 + core_utils.get_var_size(witness_script))  # type: ignore
            network_fee = exec_fee_factor * multisig_contract_costs(threshold, len(public_keys))

    network_fee += network_fee_size * contracts.PolicyContract().get_fee_per_byte(snapshot)
    return network_fee


def signature_contract_costs() -> int:
    return (contracts.ApplicationEngine.opcode_price(vm.OpCode.PUSHDATA1) * 2
            + contracts.ApplicationEngine.opcode_price(vm.OpCode.SYSCALL)
            + CHECKSIG_PRICE
            )


def multisig_contract_costs(threshold: int, public_key_count: int) -> int:
    fee = contracts.ApplicationEngine.opcode_price(vm.OpCode.PUSHDATA1) * (threshold + public_key_count)
    opcode = vm.OpCode(vm.ScriptBuilder().emit_push(threshold).to_array()[0])
    fee += contracts.ApplicationEngine.opcode_price(opcode)
    opcode = vm.OpCode(vm.ScriptBuilder().emit_push(public_key_count).to_array()[0])
    fee += contracts.ApplicationEngine.opcode_price(opcode)
    fee += contracts.ApplicationEngine.opcode_price(vm.OpCode.SYSCALL)
    fee += CHECKSIG_PRICE * public_key_count
    return fee
