"""
Convenience wrappers for calling smart contracts via RPC.

* The most specific wrappers in this module are for NEOs native contracts
  * NeoToken, GasToken TODO: add remaining contracts
* One step up are wrappers for contracts following the NEP-17 Token standard (`NEP17Contract`) and NEP-11 NFT standard
(`NEP11Contract`)
* As last resort there is the `GenericContract` which can be used for calling arbitrary functions on arbitrary contracts

Obtaining the results of the functions on the wrapped contracts is done through one of 3 methods
1. test_invoke() - does not persist to chain. Costs no gas.
2. invoke() - does persist to chain. Requires signing and costs gas.
3. estimate_gas - does not persist to chain. Costs no gas.

Example:
    neo = NeoToken(Config.dummy_config())
    result = await test_invoke(neo.candidates_registered())
"""

from __future__ import annotations
import asyncio
from typing import Callable, Any, TypeVar, Optional, cast
from neo3.api import noderpc, unwrap
from neo3.network.payloads import verification
from neo3.wallet import account, utils as walletutils
from neo3.core import types, cryptography, utils as coreutils
from neo3 import vm
from neo3.contracts import contract, callflags, utils as contractutils

# Do not call functions returning a ContractMethodFuture directly as you would a real Future.
# The Future usage is a workaround that allows to forward the annotated return type (ContractFuture[T]) of the
# annotated function "f" to a consumer function, without having to actually return an instance of T in the
# implementation of function "f"
# It has the nice property of failing when used incorrectly as opposed to a solution using
# class ContractMethodFuture(Generic[T]): pass
ContractMethodFuture = asyncio.Future


# result stack index
ItemIndex = int
ExecutionResultParser = Callable[[noderpc.ExecutionResult, ItemIndex], Any]

ReturnType = TypeVar('ReturnType')

_DEFAULT_RPC = "http://seed1.neo.org:10332"


class Config:
    # TODO: describe, organise
    def __init__(self,
                 sender: verification.Signer = None,
                 rpc_host: str = None,
                 acc: account.Account = None
                 ):
        self.sender = sender
        self.rpc_host = rpc_host
        self.account = acc
        self.signers = [sender]

    @classmethod
    def dummy_config(cls):
        acc = account.Account.watch_only_from_address("NU7nUXkVLybRA8Bt12dsLtZBrnfuirM57k")
        sender = verification.Signer(acc.script_hash)
        c = cls(sender, _DEFAULT_RPC, acc)
        return c


async def test_invoke(f: ContractMethodFuture[ReturnType],
                      signers: Optional[list[verification.Signer]] = None) -> ReturnType:
    """
    Call the contract method in read-only mode

    This does not persist any state on the actual chain and therefore does not require signing or paying GAS.

    See Also: invoke()
    """
    # just grabbing the exception to avoid runtime warnings. We're not supposed to call this future
    f.exception()

    async with noderpc.NeoRpcClient(Config.dummy_config().rpc_host) as client:
        script = getattr(f, "script", None)
        if script is None or not isinstance(script, bytes):
            raise ValueError(f"invalid script: {script}")
        res = await client.invoke_script(script, signers)

        if (func := getattr(f, "func", None)) is None or not callable(func):
            return res
        return func(res)


async def invoke(f: ContractMethodFuture[ReturnType],
                 signers: Optional[list[verification.Signer]] = None) -> types.UInt256:
    """
    Call the contract method in write-only mode

    This persists state on the actual chain and costs GAS

    Args:
        f:
        signers: override the list of signers

    Returns: transaction id if successful.
    """
    pass


async def estimate_gas(f: ContractMethodFuture,
                       signers: Optional[list[verification.Signer]] = None) -> int:
    """
    Estimates the gas price for calling the contract method
    """
    # just grabbing the exception to avoid runtime warnings as we're not supposed to use the actual future
    f.exception()

    async with noderpc.NeoRpcClient(Config.dummy_config().rpc_host) as client:
        script = getattr(f, "script", None)
        if script is None or not isinstance(script, bytes):
            raise ValueError(f"invalid script: {script}")

        res = await client.invoke_script(script, signers)
        return res.gas_consumed


def future_contract_method_result(script: bytes,
                                  func: Optional[ExecutionResultParser] = None) -> ContractMethodFuture:
    """
    Utility function to wrap a VM script into a format that can be consumed by testinvoke(), invoke() or estimate_gas()

    Args:
        script: VM opcodes as outputted by ScriptBuilder
        func: a function to call for postprocessing the script execution results
    """
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    setattr(fut, "script", script)
    setattr(fut, "func", func)
    fut.set_exception(ValueError("Do not call directly. Use testinvoke(), invoke() or estimate_gas()"))
    return cast(ContractMethodFuture, fut)


class GenericContract:
    """
    Generic class to call arbitrary methods on a smart contract
    """
    def __init__(self, contract_hash, config: Config):
        self.hash = contract_hash
        self.config = config

    def call_function(self, name, args=None) -> ContractMethodFuture[noderpc.ExecutionResult]:
        if args is None:
            script = vm.ScriptBuilder().emit_contract_call(self.hash, name).to_array()
        else:
            script = vm.ScriptBuilder().emit_contract_call_with_args(self.hash, name, args).to_array()
        return future_contract_method_result(script)


class NEP17Contract:
    """
    Base class for calling NEP-17 compliant smart contracts
    """
    def __init__(self, contract_hash: types.UInt160, config: Config):
        self.hash = contract_hash
        self.config = config

    def symbol(self) -> ContractMethodFuture[str]:
        """
        User-friendly name of the token
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "symbol").to_array()
        return future_contract_method_result(script, unwrap.as_str)

    def decimals(self) -> ContractMethodFuture[int]:
        """
        Get the amount of decimals

        Use this with the result of balance_of to display the correct user representation
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "decimals").to_array()
        return future_contract_method_result(script, unwrap.as_int)

    def total_supply(self) -> ContractMethodFuture[int]:
        """
        Get the total token supply in the NEO system
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "totalSupply").to_array()
        return future_contract_method_result(script, unwrap.as_int)

    def balance_of(self, account: types.UInt160) -> ContractMethodFuture[int]:
        """
        Get the balance for the given account

        Note: the returned value does not take the token decimals into account. e.g. for the GAS token you want to
        divide the result by 10**8 (as the Gas token has 8 decimals).
        """
        script = vm.ScriptBuilder().emit_contract_call_with_args(self.hash, "balanceOf", [account]).to_array()
        return future_contract_method_result(script, unwrap.as_int)

    def balance_of_friendly(self, account: types.UInt160) -> ContractMethodFuture[float]:
        """
        Get the balance for the given account and convert the result into the user representation

        Uses the token decimals to convert to the user end representation
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(self.hash, "balanceOf", [account])
        sb.emit_contract_call(self.hash, "decimals")

        def process(res: noderpc.ExecutionResult, _: int) -> float:
            unwrap.check_state_ok(res)
            balance = unwrap.as_int(res, 0)
            decimals = unwrap.as_int(res, 1)
            if balance == 0:
                return 0.0
            else:
                return balance / (10**decimals)
        return future_contract_method_result(sb.to_array(), process)

    def transfer(self,
                 source: types.UInt160,
                 destination: types.UInt160,
                 amount: int) -> ContractMethodFuture[bool]:
        """
        Transfer `amount` of tokens from `source` account to `destination` account.

        For this to pass while using `testinvoke()`, make sure to add a Signer with a script hash equal to the source
        account. i.e.

            source = <source_script_hash>
            signer = verification.Signer(source, payloads.WitnessScope.CALLED_BY_ENTRY)
            await testinvoke(token.transfer(source, destination, 10), signers=[signer]))

        Returns: True if funds transferred successful. False otherwise.
        """
        sb = vm.ScriptBuilder().emit_contract_call_with_args(self.hash, "transfer", [source, destination, amount, None])
        return future_contract_method_result(sb.to_array(), unwrap.as_bool)

    def transfer_multi(self,
                       source: types.UInt160,
                       destinations: list[types.UInt160],
                       amount: int,
                       abort_on_failure: bool = False) -> ContractMethodFuture[bool]:
        """
        Transfer `amount` of tokens from `source` to each account in `destinations`

        Args:
            source: account to take funds from
            destinations: accounts to send funds to
            amount: how much to transfer
            abort_on_failure: if True aborts the whole transaction if any of the transfers fails.

        Returns: True if all transfers are successful. False otherwise.
        """
        sb = vm.ScriptBuilder()
        for d in destinations:
            sb.emit_contract_call_with_args(self.hash, "transfer", [source, d, amount, None])
            if abort_on_failure:
                sb.emit(vm.OpCode.ASSERT)

        # when abort_on_failure is used the result of the `transfer()` call is consumed by the ASSERT opcode
        # and the `stack` will be empty. Therefore, we only check for the VM state
        def process_with_assert(res: noderpc.ExecutionResult, _: int) -> bool:
            unwrap.check_state_ok(res)
            return True

        # when abort_on_failure is not used we iterate over all transfer() results
        def process(res: noderpc.ExecutionResult, _: int) -> bool:
            unwrap.check_state_ok(res)
            for si in res.stack:
                if si.as_bool() is False:
                    return False
            return True

        if abort_on_failure:
            return future_contract_method_result(sb.to_array(), process_with_assert)
        else:
            return future_contract_method_result(sb.to_array(), process)


class GasToken(NEP17Contract):
    def __init__(self, config: Config):
        super(GasToken, self).__init__(contract.CONTRACT_HASHES.GAS_TOKEN, config)


class Candidate:
    """
    Container for holding consensus candidate voting results
    """
    def __init__(self, public_key: cryptography.ECPoint, votes: int):
        self.public_key = public_key
        self.votes = votes
        shash = coreutils.to_script_hash(contractutils.create_signature_redeemscript(self.public_key))
        self.address = walletutils.script_hash_to_address(shash)


class NeoToken(NEP17Contract):
    def __init__(self, config: Config):
        super(NeoToken, self).__init__(contract.CONTRACT_HASHES.NEO_TOKEN, config)

    def get_gas_per_block(self) -> ContractMethodFuture[int]:
        """
        Get the amount of GAS generated in each block
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "getGasPerBlock").to_array()
        return future_contract_method_result(script, unwrap.as_int)

    def get_unclaimed_gas(self, account: types.UInt160, end: Optional[int] = None) -> ContractMethodFuture[int]:
        """
        Get the amount of unclaimed GAS for `account`

        Args:
            end: up to which block height to calculate the GAS bonus. Omit to calculate to the current chain height
        """
        sb = vm.ScriptBuilder()
        if end is not None:
            sb.emit_contract_call_with_args(self.hash, "unclaimedGas", [account, end]).to_array()
            return future_contract_method_result(sb.to_array(), unwrap.as_int)
        else:
            sb.emit_contract_call(contract.CONTRACT_HASHES.LEDGER, "currentIndex")
            # first argument to "unclaimedGas" (second is already on the stack by the "currentIndex" call
            sb.emit_push(account)
            # length of arguments
            sb.emit_push(2)
            sb.emit(vm.OpCode.PACK)
            sb.emit_push(callflags.CallFlags.ALL)
            sb.emit_push("unclaimedGas")
            sb.emit_push(self.hash)
            sb.emit_syscall(vm.Syscalls.SYSTEM_CONTRACT_CALL)
            return future_contract_method_result(sb.to_array(), unwrap.as_int)

    def candidate_registration_price(self) -> ContractMethodFuture[int]:
        """
        Get the amount of GAS to pay to register as consensus candidate
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "getRegisterPrice").to_array()
        return future_contract_method_result(script, unwrap.as_int)

    def candidate_register(self, public_key: cryptography.ECPoint) -> ContractMethodFuture[bool]:
        """
        Register as a consensus candidate

        See Also: wallet.Account.public_key

        Returns: True if successful. False otherwise.
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(self.hash, "registerCandidate", [public_key]).to_array()
        return future_contract_method_result(sb.to_array(), unwrap.as_bool)

    def candidate_unregister(self, public_key: cryptography.ECPoint) -> ContractMethodFuture[bool]:
        """
        Unregister as a consensus candidate

        See Also: wallet.Account.public_key

        Returns: True if successful. False otherwise.
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(self.hash, "registerCandidate", [public_key]).to_array()
        return future_contract_method_result(sb.to_array(), unwrap.as_bool)

    def candidate_vote(self, voter: types.UInt160, candidate: cryptography.ECPoint) -> ContractMethodFuture[bool]:
        """
        Cast a vote for `candidate` to become a consensus node

        Args:
            voter: the account to vote from
            candidate: who to vote on

        Returns: True if vote cast successful. False otherwise.
        """
        script = vm.ScriptBuilder().emit_contract_call_with_args(self.hash, "vote", [voter, candidate]).to_array()
        return future_contract_method_result(script, unwrap.as_bool)

    def candidate_votes(self, candidate: cryptography.ECPoint) -> ContractMethodFuture[int]:
        """
        Get the total vote count for `candidate`
        """
        script = vm.ScriptBuilder().emit_contract_call_with_args(self.hash, "getCandidateVote", [candidate]).to_array()
        return future_contract_method_result(script, unwrap.as_int)

    def candidates_registered(self) -> ContractMethodFuture[list[Candidate]]:
        """
        Get the first 256 registered candidates
        Returns:

        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "getCandidates").to_array()

        def process(res: noderpc.ExecutionResult, _: int) -> list[Candidate]:
            raw_results: list[noderpc.StackItem] = unwrap.as_list(res)
            result = []

            for si in raw_results:
                if si.type != "Struct":
                    continue
                v = cast(list[noderpc.StackItem], si.value)
                result.append(Candidate(v[0].as_public_key(), v[1].as_int()))
            return result

        return future_contract_method_result(script, process)

