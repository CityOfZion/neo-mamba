"""
Convenience wrappers for calling smart contracts via RPC.

* The most specific wrappers in this module are for NEOs native contracts
  * NeoToken, GasToken TODO: add remaining contracts
* One step up are wrappers for contracts following the NEP-17 Token standard (`NEP17Contract`) and NEP-11 NFT standard
(`NEP11DivisibleContract` & `NEP11NonDivisibleContract`)
* As last resort there is the `GenericContract` which can be used for calling arbitrary functions on arbitrary contracts

Obtaining the execution results of the functions on the wrapped contracts is done through one of 3 methods on the
 ChainFacade class
1. test_invoke() - does not persist to chain. Costs no gas.
2. invoke() - does persist to chain. Requires signing and costs gas.
3. estimate_gas - does not persist to chain. Costs no gas.

Example:
    facade = ChainFacade.node_provider_mainnet()
    neo = NeoToken()
    result = await facade.test_invoke(neo.candidates_registered())
"""

from __future__ import annotations
from typing import Callable, Any, TypeVar, Optional, cast, Generic, TypeAlias
from collections.abc import Sequence
import asyncio
from neo3.api import noderpc, unwrap
from neo3.api.helpers import signing, txbuilder
from neo3.network.payloads import verification
from neo3.wallet import utils as walletutils
from neo3.wallet.types import NeoAddress
from neo3.core import types, cryptography, utils as coreutils
from neo3 import vm
from neo3.contracts import contract, callflags, utils as contractutils


# result stack index
ItemIndex: TypeAlias = int
ExecutionResultParser = Callable[[noderpc.ExecutionResult, ItemIndex], Any]

ReturnType = TypeVar("ReturnType")


class ContractMethodResult(Generic[ReturnType]):
    """
    A helper class around the script (VM opcodes) to be executed which allows to forward the annotated return type
    (ContractMethodResult[T]) of the annotated function "f" to a consumer function, without having to actually return
     an instance of T in the implementation of "f".

     Example:
         def get_name() -> ContractMethodResult[str]:
            script = vm.ScriptBuilder().emit_contract_call(some_hash, "name")
            return ContractMethodResult(script, unwrap.as_str)

        def consumer(f: ContractMethodResult[ReturnType]) -> ReturnType:
            res = rpc.invoke_script(f.script)
            return f.func(res) # unwraps the result as a string

        x = consumer(get_name())
        type(x) # str
    """

    def __init__(
        self,
        script: bytes,
        func: Optional[ExecutionResultParser] = None,
    ):
        """

        Args:
            script: VM opcodes to be executed
            func: post processor function
        """
        super(ContractMethodResult, self).__init__()
        self.script = script
        self.func = func

    def __call__(self, *args, **kwargs):
        pass


_DEFAULT_RPC = "http://seed1.neo.org:10332"

SigningPair: TypeAlias = tuple[signing.SigningFunction, verification.Signer]


class ChainFacade:
    """
    The gateway to the network.

    Abstracts away the logic for talking to the data provider (NodeRPC only atm)
    """

    def __init__(self, config: Config):
        self.config = config
        self._signing_func = None
        self.network = -1
        self.address_version = -1

    async def init(self) -> None:
        async with noderpc.NeoRpcClient(self.config.rpc_host) as client:
            res = await client.get_version()
            self.network = res.protocol.network
            self.address_version = res.protocol.address_version

    async def test_invoke(
        self,
        f: ContractMethodResult[ReturnType],
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> ReturnType:
        """
        Call the contract method in read-only mode

        This does not persist any state on the actual chain and therefore does not require signing or paying GAS.

        See Also: invoke()
        """
        return await self._test_invoke(f, signers)

    async def test_invoke_multi(
        self,
        f: list[ContractMethodResult],
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> tuple:
        """
        Call all contract methods in one go (concurrently) and return the list of results
        """
        return await asyncio.gather(*map(lambda c: self.test_invoke(c, signers), f))

    async def test_invoke_raw(
        self,
        f: ContractMethodResult[ReturnType],
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> noderpc.ExecutionResult:
        """
        Call the contract method in read-only mode

        This does not persist any state on the actual chain and therefore does not require signing or paying GAS.

        See Also: invoke()
        """
        return await self._test_invoke(f, signers, return_raw=True)

    async def _test_invoke(
        self,
        f: ContractMethodResult[ReturnType],
        signers: Optional[Sequence[verification.Signer]] = None,
        return_raw: Optional[bool] = False,
    ):
        """
        Call the contract method in read-only mode

        This does not persist any state on the actual chain and therefore does not require signing or paying GAS.

        See Also: invoke()
        """
        async with noderpc.NeoRpcClient(self.config.rpc_host) as client:
            res = await client.invoke_script(f.script, signers)
            if f.func is None or return_raw:
                return res
            return f.func(res, 0)

    async def invoke(
        self,
        f: ContractMethodResult[ReturnType],
        *,
        signers: Optional[Sequence[SigningPair]] = None,
        override_network_fee: int = 0,
        override_system_fee: int = 0,
        append_network_fee: int = 0,
        append_system_fee: int = 0,
    ) -> types.UInt256:
        async with noderpc.NeoRpcClient(self.config.rpc_host) as client:
            builder = txbuilder.TxBuilder(client, f.script)
            await builder.init()

            if signers:
                for func, signer in signers:
                    builder.add_signer(func, signer)
            else:
                for func, signer in zip(
                    self.config._signing_funcs, self.config.signers
                ):
                    builder.add_signer(func, signer)

            await builder.set_valid_until_block()

            if override_system_fee:
                builder.tx.system_fee = override_system_fee
            else:
                await builder.calculate_system_fee()
                builder.tx.system_fee += append_system_fee

            if override_network_fee:
                builder.tx.network_fee = override_network_fee
            else:
                await builder.calculate_network_fee()
                builder.tx.network_fee += append_network_fee

            tx = await builder.build_and_sign()
            return await client.send_transaction(tx)

    async def invoke_raw(
        self,
        f: ContractMethodResult[ReturnType],
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> noderpc.ExecutionResult:
        raise NotImplementedError

    async def estimate_gas(
        self,
        f: ContractMethodResult,
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> int:
        """
        Estimates the gas price for calling the contract method
        """
        async with noderpc.NeoRpcClient(self.config.rpc_host) as client:
            res = await client.invoke_script(f.script, signers)
            return res.gas_consumed

    @classmethod
    def node_provider_mainnet(cls):
        return cls(Config.standard_config())

    @classmethod
    def node_provider_testnet(cls):
        c = Config.standard_config()
        c.rpc_host = "http://seed1t5.neo.org:10332"
        return cls(c)


class Config:
    def __init__(self, rpc_host: str):
        self.rpc_host = rpc_host
        self.signers: list[verification.Signer] = []
        self._signing_funcs: list[signing.SigningFunction] = []
        self._test_invoke_signers: list[verification.Signer] = []

    @classmethod
    def standard_config(cls):
        return cls(_DEFAULT_RPC)

    def add_signer(self, func: signing.SigningFunction, signer: verification.Signer):
        self._signing_funcs.append(func)
        self.signers.append(signer)

    def add_test_invoke_signer(self, signer: verification.Signer):
        """
        These signers will be used with `test_invoke`
        """
        self._test_invoke_signers.append(signer)


class GenericContract:
    """
    Generic class to call arbitrary methods on a smart contract
    """

    def __init__(self, contract_hash):
        self.hash = contract_hash

    def call_function(
        self, name, args=None
    ) -> ContractMethodResult[noderpc.ExecutionResult]:
        if args is None:
            script = vm.ScriptBuilder().emit_contract_call(self.hash, name).to_array()
        else:
            script = (
                vm.ScriptBuilder()
                .emit_contract_call_with_args(self.hash, name, args)
                .to_array()
            )
        return ContractMethodResult(script)


class _TokenContract(GenericContract):
    """
    Base class for Fungible and Non-Fungible tokens
    """

    def symbol(self) -> ContractMethodResult[str]:
        """
        User-friendly name of the token
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "symbol").to_array()
        return ContractMethodResult(script, unwrap.as_str)

    def decimals(self) -> ContractMethodResult[int]:
        """
        Get the amount of decimals

        Use this with the result of balance_of to display the correct user representation
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "decimals").to_array()
        return ContractMethodResult(script, unwrap.as_int)

    def total_supply(self) -> ContractMethodResult[int]:
        """
        Get the total token supply in the NEO system
        """
        script = (
            vm.ScriptBuilder().emit_contract_call(self.hash, "totalSupply").to_array()
        )
        return ContractMethodResult(script, unwrap.as_int)


class NEP17Contract(_TokenContract):
    """
    Base class for calling NEP-17 compliant smart contracts
    """

    def balance_of(
        self, account: types.UInt160 | NeoAddress
    ) -> ContractMethodResult[int]:
        """
        Get the balance for the given account

        Note: the returned value does not take the token decimals into account. e.g. for the GAS token you want to
        divide the result by 10**8 (as the Gas token has 8 decimals).

        Raises:
            ValueError if `account` is an invalid NeoAddress format
        """
        account = _check_address_and_convert(account)
        script = (
            vm.ScriptBuilder()
            .emit_contract_call_with_args(self.hash, "balanceOf", [account])
            .to_array()
        )
        return ContractMethodResult(script, unwrap.as_int)

    def balance_of_friendly(
        self, account: types.UInt160 | NeoAddress
    ) -> ContractMethodResult[float]:
        """
        Get the balance for the given account and convert the result into the user representation

        Uses the token decimals to convert to the user end representation

        Raises:
            ValueError if `account` is an invalid NeoAddress format
        """
        account = _check_address_and_convert(account)

        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(self.hash, "balanceOf", [account])
        sb.emit_contract_call(self.hash, "decimals")

        def process(res: noderpc.ExecutionResult, _: int = 0) -> float:
            unwrap.check_state_ok(res)
            balance = unwrap.as_int(res, 0)
            decimals = unwrap.as_int(res, 1)
            if balance == 0:
                return 0.0
            else:
                return balance / (10**decimals)

        return ContractMethodResult(sb.to_array(), process)

    def transfer(
        self,
        source: types.UInt160 | NeoAddress,
        destination: types.UInt160 | NeoAddress,
        amount: int,
    ) -> ContractMethodResult[bool]:
        """
        Transfer `amount` of tokens from `source` account to `destination` account.

        For this to pass while using `test_invoke()`, make sure to add a Signer with a script hash equal to the source
        account. i.e.

            source = <source_script_hash>
            signer = verification.Signer(source, payloads.WitnessScope.CALLED_BY_ENTRY)
            await facade.test_invoke(token.transfer(source, destination, 10), signers=[signer]))

        Raises:
            ValueError if `source` or `destination` is an invalid NeoAddress format

        Returns: True if funds transferred successful. False otherwise.
        """
        source = _check_address_and_convert(source)
        destination = _check_address_and_convert(destination)

        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "transfer", [source, destination, amount, None]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_bool)

    def transfer_multi(
        self,
        source: types.UInt160 | NeoAddress,
        destinations: Sequence[types.UInt160 | NeoAddress],
        amount: int,
        abort_on_failure: bool = False,
    ) -> ContractMethodResult[bool]:
        """
        Transfer `amount` of tokens from `source` to each account in `destinations`

        Args:
            source: account to take funds from
            destinations: accounts to send funds to
            amount: how much to transfer
            abort_on_failure: if True aborts the whole transaction if any of the transfers fails.

        Raises:
            ValueError if any of the destinations is supplied as NeoAddress but is an invalid address format

        Returns: True if all transfers are successful. False otherwise.
        """
        sb = vm.ScriptBuilder()
        for d in destinations:
            d = _check_address_and_convert(d)
            sb.emit_contract_call_with_args(
                self.hash, "transfer", [source, d, amount, None]
            )
            if abort_on_failure:
                sb.emit(vm.OpCode.ASSERT)

        # when abort_on_failure is used the result of the `transfer()` call is consumed by the ASSERT opcode
        # and the `stack` will be empty. Therefore, we only check for the VM state
        def process_with_assert(res: noderpc.ExecutionResult, _: int = 0) -> bool:
            unwrap.check_state_ok(res)
            return True

        # when abort_on_failure is not used we iterate over all transfer() results
        def process(res: noderpc.ExecutionResult, _: int = 0) -> bool:
            unwrap.check_state_ok(res)
            for si in res.stack:
                if si.as_bool() is False:
                    return False
            return True

        if abort_on_failure:
            return ContractMethodResult(sb.to_array(), process_with_assert)
        else:
            return ContractMethodResult(sb.to_array(), process)


class GasToken(NEP17Contract):
    def __init__(self):
        super(GasToken, self).__init__(contract.CONTRACT_HASHES.GAS_TOKEN)


class Candidate:
    """
    Container for holding consensus candidate voting results
    """

    def __init__(self, public_key: cryptography.ECPoint, votes: int):
        self.public_key = public_key
        self.votes = votes
        shash = coreutils.to_script_hash(
            contractutils.create_signature_redeemscript(self.public_key)
        )
        self.address = walletutils.script_hash_to_address(shash)


class NeoToken(NEP17Contract):
    def __init__(self):
        super(NeoToken, self).__init__(contract.CONTRACT_HASHES.NEO_TOKEN)

    def get_gas_per_block(self) -> ContractMethodResult[int]:
        """
        Get the amount of GAS generated in each block
        """
        script = (
            vm.ScriptBuilder()
            .emit_contract_call(self.hash, "getGasPerBlock")
            .to_array()
        )
        return ContractMethodResult(script, unwrap.as_int)

    def get_unclaimed_gas(
        self, account: types.UInt160 | NeoAddress, end: Optional[int] = None
    ) -> ContractMethodResult[int]:
        """
        Get the amount of unclaimed GAS for `account`

        Args:
            end: up to which block height to calculate the GAS bonus. Omit to calculate to the current chain height

        Raises:
            ValueError if `account` is an invalid NeoAddress format
        """
        if not isinstance(account, types.UInt160):
            walletutils.validate_address(account)
            account = walletutils.address_to_script_hash(account)

        sb = vm.ScriptBuilder()
        if end is not None:
            sb.emit_contract_call_with_args(
                self.hash, "unclaimedGas", [account, end]
            ).to_array()
            return ContractMethodResult(sb.to_array(), unwrap.as_int)
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
            return ContractMethodResult(sb.to_array(), unwrap.as_int)

    def candidate_registration_price(self) -> ContractMethodResult[int]:
        """
        Get the amount of GAS to pay to register as consensus candidate
        """
        script = (
            vm.ScriptBuilder()
            .emit_contract_call(self.hash, "getRegisterPrice")
            .to_array()
        )
        return ContractMethodResult(script, unwrap.as_int)

    def candidate_register(
        self, public_key: cryptography.ECPoint
    ) -> ContractMethodResult[bool]:
        """
        Register as a consensus candidate

        See Also: wallet.Account.public_key

        Returns: True if successful. False otherwise.
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(
            self.hash, "registerCandidate", [public_key]
        ).to_array()
        return ContractMethodResult(sb.to_array(), unwrap.as_bool)

    def candidate_unregister(
        self, public_key: cryptography.ECPoint
    ) -> ContractMethodResult[bool]:
        """
        Unregister as a consensus candidate

        See Also: wallet.Account.public_key

        Returns: True if successful. False otherwise.
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(
            self.hash, "registerCandidate", [public_key]
        ).to_array()
        return ContractMethodResult(sb.to_array(), unwrap.as_bool)

    def candidate_vote(
        self, voter: types.UInt160 | NeoAddress, candidate: cryptography.ECPoint
    ) -> ContractMethodResult[bool]:
        """
        Cast a vote for `candidate` to become a consensus node

        Args:
            voter: the account to vote from
            candidate: who to vote on

        Raises:
            ValueError if `voter` is an invalid NeoAddress format

        Returns: True if vote cast successful. False otherwise.
        """
        voter = _check_address_and_convert(voter)
        script = (
            vm.ScriptBuilder()
            .emit_contract_call_with_args(self.hash, "vote", [voter, candidate])
            .to_array()
        )
        return ContractMethodResult(script, unwrap.as_bool)

    def candidate_votes(
        self, candidate: cryptography.ECPoint
    ) -> ContractMethodResult[int]:
        """
        Get the total vote count for `candidate`
        """
        script = (
            vm.ScriptBuilder()
            .emit_contract_call_with_args(self.hash, "getCandidateVote", [candidate])
            .to_array()
        )
        return ContractMethodResult(script, unwrap.as_int)

    def candidates_registered(self) -> ContractMethodResult[list[Candidate]]:
        """
        Get the first 256 registered candidates
        """
        script = (
            vm.ScriptBuilder().emit_contract_call(self.hash, "getCandidates").to_array()
        )

        def process(res: noderpc.ExecutionResult, _: int = 1) -> list[Candidate]:
            raw_results: list[noderpc.StackItem] = unwrap.as_list(res)
            result = []

            for si in raw_results:
                if si.type != noderpc.StackItemType.STRUCT:
                    continue
                v = cast(list[noderpc.StackItem], si.value)
                result.append(Candidate(v[0].as_public_key(), v[1].as_int()))
            return result

        return ContractMethodResult(script, process)


class _NEP11Contract(_TokenContract):
    """
    Base class for calling NEP-11 compliant smart contracts

    NFTs can be divisible or non-divisible which is determined by the value of `decimals()`

    Note: the following 2 common methods defined in the NEP-11 standard have different names to improve discoverability
         NEP-11 standard    This wrapper
      1. balanceOf       -> total_owned_by
      2. tokensOf        -> token_ids_owned_by
    """

    def decimals(self) -> ContractMethodResult[int]:
        """
        Get the amount of decimals

        A zero return value indicates a non-divisible NFT.
        A bigger than zero return value indicates a divisible NFTs.
        """
        return super(_NEP11Contract, self).decimals()

    def total_owned_by(
        self, owner: types.UInt160 | NeoAddress
    ) -> ContractMethodResult[int]:
        """
        Get the total amount of NFTs owned for the given account.

        Raises:
            ValueError if `owner` is an invalid NeoAddress format
        """
        owner = _check_address_and_convert(owner)
        script = (
            vm.ScriptBuilder()
            .emit_contract_call_with_args(self.hash, "balanceOf", [owner])
            .to_array()
        )
        return ContractMethodResult(script, unwrap.as_int)

    def token_ids_owned_by(
        self, owner: types.UInt160 | NeoAddress
    ) -> ContractMethodResult[list[bytes]]:
        """
        Get an iterator containing all token ids owned by the specified address

        Raises:
            ValueError if `owner` is an invalid NeoAddress format
        """
        owner = _check_address_and_convert(owner)
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args_and_unwrap_iterator(
            self.hash, "tokensOf", [owner]
        )

        def process(res: noderpc.ExecutionResult, _: int = 0) -> list[bytes]:
            raw_results: list[noderpc.StackItem] = unwrap.as_list(res)
            return [si.value for si in raw_results]

        return ContractMethodResult(sb.to_array(), process)

    def tokens(self) -> ContractMethodResult[list[bytes]]:
        """
        Get all tokens minted by the contract

        Note: this is an optional method and may not exist on the contract
        """

        def process(res: noderpc.ExecutionResult, _: int = 0) -> list[bytes]:
            raw_results: list[noderpc.StackItem] = unwrap.as_list(res)
            return [si.value for si in raw_results]

        sb = vm.ScriptBuilder().emit_contract_call_and_unwrap_iterator(
            self.hash, "tokens"
        )
        return ContractMethodResult(sb.to_array(), process)

    def properties(self, token_id: bytes) -> ContractMethodResult[dict]:
        """
        Get all properties for the given NFT

        Note: this is an optional method and may not exist on the contract
        """
        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "properties", [token_id]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_dict)


class NEP11DivisibleContract(_NEP11Contract):
    """
    Base class for divisible NFTs

    The NEP-11 `ownerOf` method is named `owners_of` in this wrapper
    """

    def transfer(
        self,
        source: types.UInt160 | NeoAddress,
        destination: types.UInt160 | NeoAddress,
        amount: int,
        token_id: bytes,
        data: Optional[list] = None,
    ) -> ContractMethodResult[bool]:
        """
        Transfer `amount` of `token_id` from `source` account to `destination` account.

        For this to pass while using `test_invoke()`, make sure to add a Signer with a script hash equal to the source
        account. i.e.

            source = <source_script_hash>
            signer = verification.Signer(source, payloads.WitnessScope.CALLED_BY_ENTRY)
            await facade.test_invoke(token.transfer(source, destination, 10), signers=[signer]))

        Raises:
            ValueError if `source` or `destination` is an invalid NeoAddress format

        Returns: True if token fractions transferred successful. False otherwise.
        """
        source = _check_address_and_convert(source)
        destination = _check_address_and_convert(destination)
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(
            self.hash, "transfer", [source, destination, amount, token_id, data]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_bool)

    def owners_of(self, token_id: bytes) -> ContractMethodResult[list[types.UInt160]]:
        """
        Get a list of account script hashes that own a part of `token_id`
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args_and_unwrap_iterator(
            self.hash, "ownerOf", [token_id]
        )

        def process(res: noderpc.ExecutionResult, _: int = 0) -> list[types.UInt160]:
            raw_results: list[noderpc.StackItem] = unwrap.as_list(res)
            return [si.as_uint160() for si in raw_results]

        return ContractMethodResult(sb.to_array(), process)

    def balance_of(
        self, owner: types.UInt160 | NeoAddress, token_id: bytes
    ) -> ContractMethodResult[int]:
        """
        Get the token balance for the given owner

        Raises:
            ValueError if `owner` is an invalid NeoAddress format
        """
        owner = _check_address_and_convert(owner)
        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "balanceOf", [owner, token_id]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_int)

    def balance_of_friendly(
        self, owner: types.UInt160 | NeoAddress, token_id: bytes
    ) -> ContractMethodResult[float]:
        """
        Get the balance for the given account and convert the result into the user representation

        Uses the token decimals to convert to the user end representation

        Raises:
            ValueError if `owner` is an invalid NeoAddress format
        """
        owner = _check_address_and_convert(owner)
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(self.hash, "balanceOf", [owner, token_id])
        sb.emit_contract_call(self.hash, "decimals")

        def process(res: noderpc.ExecutionResult, _: int = 0) -> float:
            unwrap.check_state_ok(res)
            balance = unwrap.as_int(res, 0)
            decimals = unwrap.as_int(res, 1)
            if balance == 0:
                return 0.0
            else:
                return balance / (10**decimals)

        return ContractMethodResult(sb.to_array(), process)


class NEP11NonDivisibleContract(_NEP11Contract):
    """Base class for non-divisible NFTs"""

    def transfer(
        self,
        destination: types.UInt160 | NeoAddress,
        token_id: str,
        data: Optional[list] = None,
    ) -> ContractMethodResult[bool]:
        """
        Transfer `token_id` to `destination` account.
        The source account will be the account that pays for the fees (a.k.a the transaction.sender)

        For this to pass while using `test_invoke()`, make sure to add a Signer with a script hash equal to the source
        account. i.e.

            signer = verification.Signer(source_account, payloads.WitnessScope.CALLED_BY_ENTRY)
            await facade.test_invoke(token.transfer(destination, token_id, 10), signers=[signer]))

        Raises:
            ValueError if `destination` is an invalid NeoAddress format

        Returns: True if the token transferred successful. False otherwise.
        """
        destination = _check_address_and_convert(destination)
        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "transfer", [destination, token_id, data]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_bool)

    def owner_of(self, token_id: bytes) -> ContractMethodResult[types.UInt160]:
        """
        Get the owner of the given token
        """
        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "ownerOf", [token_id]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_uint160)


def _check_address_and_convert(value: types.UInt160 | NeoAddress) -> types.UInt160:
    if isinstance(value, types.UInt160):
        return value
    walletutils.validate_address(value)
    return walletutils.address_to_script_hash(value)
