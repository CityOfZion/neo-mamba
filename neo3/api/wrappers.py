"""
Convenience wrappers for calling smart contracts via RPC.

The most specific wrappers in this module are for NEOs native contracts `NeoToken`, `GasToken`, `PolicyContract` and
 `RoleManagement`. The `ContractManagement` and `Ledger` contracts are not wrapped. See the FAQ for the reasons.

One step up are wrappers for contracts following the NEP-17 Token standard (`NEP17Contract`) and NEP-11 NFT standard
(`NEP11DivisibleContract` & `NEP11NonDivisibleContract`).
As last resort there is the `GenericContract` which can be used for calling arbitrary functions on arbitrary contracts.

Obtaining the execution results of the functions on the wrapped contracts is done through one of 3 methods on the
 ChainFacade class

1. `test_invoke()` - does not persist to chain. Costs no gas.
2. `invoke()` - does persist to chain. Requires signing and costs gas.
3. `estimate_gas()` - does not persist to chain. Costs no gas.

Example:
    facade = ChainFacade.node_provider_mainnet()

    neo = NeoToken()

    result = await facade.test_invoke(neo.candidates_registered())
"""

from __future__ import annotations
from typing import Callable, Any, TypeVar, Optional, cast, Generic, TypeAlias
from collections.abc import Sequence
import asyncio
from enum import IntEnum
from dataclasses import dataclass
from neo3.api import noderpc
from neo3.api.helpers import signing, txbuilder, unwrap
from neo3.network.payloads import verification
from neo3.wallet import utils as walletutils
from neo3.wallet.types import NeoAddress
from neo3.core import types, cryptography, utils as coreutils
from neo3 import vm
from neo3.contracts import contract, callflags, utils as contractutils, nef, manifest
from copy import deepcopy

# result stack index
ItemIndex: TypeAlias = int
ExecutionResultParser = Callable[[noderpc.ExecutionResult, ItemIndex], Any]

ReturnType = TypeVar("ReturnType")


class ContractMethodResult(Generic[ReturnType]):
    """
    A helper class around the `script` (VM opcodes) to be executed which allows to forward the annotated return type
    (`ContractMethodResult[T]`) of the annotated function `f` to a consumer function, without having to actually return
     an instance of `T` in the implementation of `f`.

     Example:
         def get_name() -> ContractMethodResult[str]:
            script = vm.ScriptBuilder().emit_contract_call(some_hash, "name")
            return ContractMethodResult(script, unwrap.as_str)

        def consumer(f: ContractMethodResult[ReturnType]) -> ReturnType:
            res = rpc.invoke_script(f.script)
            return f.execution_processor(res) # unwraps the result as a string

        x = consumer(get_name())
        type(x) # str
    """

    def __init__(
        self,
        script: bytes,
        execution_processor: Optional[ExecutionResultParser] = None,
        return_count: int = 1,
    ):
        """

        Args:
            script: VM opcodes to be executed.
            execution_processor: post processor function.
            return_count: number of items expected to be returned on the stack.
        """
        super(ContractMethodResult, self).__init__()
        self.script = script
        self.execution_processor = execution_processor
        self.return_count = return_count
        # TODO: add support for post processing notifications for functions that know will emit notifications
        self.notification_processor = None

    def __call__(self, *args, **kwargs):
        pass


_DEFAULT_MAINNET_RPC = "http://seed1.neo.org:10332"
_DEFAULT_TESTNET_RPC = "http://seed1t5.neo.org:20332"

SigningPair: TypeAlias = tuple[signing.SigningFunction, verification.Signer]


@dataclass
class InvokeReceipt(Generic[ReturnType]):
    """
    Transaction submission results.
    """

    #: Unique identifier.
    tx_hash: types.UInt256
    #: The block height/index the transaction is included in.
    included_in_block: int
    #: Number of blocks after accepting the transaction.
    confirmations: int
    #: The total gas cost for block inclusion and script execution.
    gas_consumed: int
    #: HALT = success, Others = failure.
    state: vm.VMState
    #: Virtual Machine exception.
    exception: Optional[str]
    #: Smart contract notifications.
    notifications: list[noderpc.Notification]
    #: Script excution result.
    result: ReturnType

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(tx_hash={str(self.tx_hash)}, included_in_block={self.included_in_block}, "
            f"confirmations={self.confirmations}, gas_consumed={self.gas_consumed}, state={self.state}, "
            f"exception={self.exception}, notifications={self.notifications}, result={self.result})"
        )


class ChainFacade:
    """
    The gateway to the network.

    Abstracts away the logic for talking to the data provider (NodeRPC only atm).
    """

    def __init__(
        self,
        rpc_host: str,
        receipt_retry_delay: Optional[float] = None,
        receipt_timeout: Optional[float] = None,
    ):
        """
        Args:
            rpc_host: Neo RPC node host address.
            receipt_retry_delay: time to wait in seconds between attempts to find the transaction on the chain.
            receipt_timeout: maximum time to wait in seconds to find the transaction on the chain.
        """
        self.rpc_host = rpc_host
        self._signing_func = None
        self.network = -1
        self.address_version = -1
        self.signers: list[verification.Signer] = []
        self._signing_funcs: list[signing.SigningFunction] = []
        self._receipt_retry_delay = receipt_retry_delay
        self._receipt_timeout = receipt_timeout

    async def test_invoke(
        self,
        f: ContractMethodResult[ReturnType],
        *,
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> ReturnType:
        """
        Call a contract method in read-only mode.
        This does not persist any state on the actual chain and therefore does not require signing or paying GAS.

        Args:
            f: function to call.
            signers: manually set the list of signers.

        See Also:
            `invoke()` - persists state.
        """
        if signers is None:
            signers = self.signers
        return await self._test_invoke(f, signers=signers)

    async def test_invoke_multi(
        self,
        f: list[ContractMethodResult],
        *,
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> tuple:
        """
        Call all contract methods in one go (concurrently) and return the list of results.

        Args:
            f: list of functions to call.
            signers: manually set the list of signers.

        See Also:
            `invoke_multi()` - persists state.
        """
        if signers is None:
            signers = self.signers
        return await asyncio.gather(
            *map(lambda c: self.test_invoke(c, signers=signers), f)
        )

    async def test_invoke_raw(
        self,
        f: ContractMethodResult[ReturnType],
        *,
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> noderpc.ExecutionResult:
        """
        Call a contract method in read-only mode.
        This does not persist any state on the actual chain and therefore does not require signing or paying GAS.
        Does not post process the execution results.

        Args:
            f: function to call.
            signers: manually set the list of signers.

        See Also:
            `invoke_raw()` - persists state.
        """
        if signers is None:
            signers = self.signers
        return await self._test_invoke(f, signers=signers, return_raw=True)

    async def _test_invoke(
        self,
        f: ContractMethodResult[ReturnType],
        *,
        signers: Optional[Sequence[verification.Signer]] = None,
        return_raw: Optional[bool] = False,
    ):
        """
        Args:
            f:
            signers:
            return_raw: whether to post process the execution result or not.
        """
        async with noderpc.NeoRpcClient(self.rpc_host) as client:
            res = await client.invoke_script(f.script, signers)
            if f.execution_processor is None or return_raw:
                return res
            return f.execution_processor(res, 0)

    async def invoke(
        self,
        f: ContractMethodResult[ReturnType],
        *,
        signers: Optional[Sequence[SigningPair]] = None,
        network_fee: int = 0,
        system_fee: int = 0,
        append_network_fee: int = 0,
        append_system_fee: int = 0,
    ) -> InvokeReceipt[ReturnType]:
        """
        Call a contract method and persist results on the chain. Costs GAS.
        Waits for tx to be included in a block. Automatically post processes the execution results according to the
        post-processing function of `f` if present.

        Args:
            f: function to call.
            signers: manually set the list of signers.
            network_fee: manually set the network fee.
            system_fee: manually set the system fee.
            append_network_fee: increase the calculated network fee with this amount.
            append_system_fee: increase the calculated system fee with this amount.

        Returns:
            A transaction receipt. The `state` field of the receipt indicates if the transaction script executed
            successfully. The remaining fields provide additional information such as notifications that happened
            in the contract.

        See Also:
            `invoke_fast()` - does not wait for a receipt.
            `invoke_raw()` - does not wait for a transaction receipt, does not perform post-processing of the execution
                           results.
        """
        delay, timeout = await self._get_receipt_time_values()
        async with noderpc.NeoRpcClient(self.rpc_host) as client:
            tx_id = await self.invoke_fast(
                f,
                signers=signers,
                network_fee=network_fee,
                system_fee=system_fee,
                append_network_fee=append_network_fee,
                append_system_fee=append_system_fee,
            )
            receipt = await client.wait_for_transaction_receipt(
                tx_id, timeout=timeout, retry_delay=delay
            )
            if f.execution_processor is not None:
                result = f.execution_processor(receipt.execution, 0)
            else:
                result = receipt.execution
            return InvokeReceipt[ReturnType](
                receipt.tx_hash,
                receipt.included_in_block,
                receipt.confirmations,
                receipt.execution.gas_consumed,
                receipt.execution.state,
                receipt.execution.exception,
                receipt.execution.notifications,
                result,
            )

    async def invoke_fast(
        self,
        f: ContractMethodResult[ReturnType],
        *,
        signers: Optional[Sequence[SigningPair]] = None,
        network_fee: int = 0,
        system_fee: int = 0,
        append_network_fee: int = 0,
        append_system_fee: int = 0,
    ) -> types.UInt256:
        """
        Call a contract method and persist results on the chain. Costs GAS.

        Args:
            f: function to call.
            signers: manually set the list of signers.
            network_fee: manually set the network fee.
            system_fee: manually set the system fee.
            append_network_fee: increase the calculated network fee with this amount.
            append_system_fee: increase the calculated system fee with this amount.

        Returns:
            a transaction ID if accepted by the network. Acceptance is does not guarantee successful execution.
            Acceptance means there are no transaction format errors. Use `invoke()` to wait for a receipt. The `state`
            field of the receipt indicates if the transaction script executed successfully.

        See Also:
            `invoke()` - waits for a transaction receipt, performs post-processing of the execution results.
            `invoke_raw()` - does not wait for a transaction receipt, does not perform post-processing of the execution
                           results.
        """
        if network_fee > 0 and append_network_fee > 0:
            raise ValueError(
                "network_fee and append_network_fee are mutually exclusive"
            )

        if system_fee > 0 and append_system_fee > 0:
            raise ValueError("system_fee and append_system_fee are mutually exclusive")

        async with noderpc.NeoRpcClient(self.rpc_host) as client:
            builder = txbuilder.TxBuilder(client, f.script)
            await builder.init()

            if signers:
                for func, signer in signers:
                    builder.add_signer(func, signer)
            else:
                for func, signer in zip(self._signing_funcs, self.signers):
                    builder.add_signer(func, signer)

            await builder.set_valid_until_block()

            if system_fee > 0:
                builder.tx.system_fee = system_fee
            else:
                await builder.calculate_system_fee()
                builder.tx.system_fee += append_system_fee

            if network_fee > 0:
                builder.tx.network_fee = network_fee
            else:
                # calculate network fee has a chicken/egg problem for light wallet sdk's.
                # in order to calculate the right network fees (especially multisig) the witnesses have to be constructed
                # which is done in `build_and_sign()`.
                # at the same time `network_fee` is part of the signed data.
                # So here we call build_and_sign() just for creating the witnesses, then calculate the real fee (which will
                # reset the witnesses) and then at the end of the function we build_and_sign() again to have a valid
                # signature over the right network_fee

                # if there were no witnesses prior to signging, then we should restore that after the tmp signing
                reset_witnesses = len(builder.tx.witnesses) == 0
                builder.tx.network_fee = 999
                await builder.build_and_sign()
                await builder.calculate_network_fee()

                if reset_witnesses:
                    builder.tx.witnesses = []

                builder.tx.network_fee += append_network_fee

            tx = await builder.build_and_sign()
            return await client.send_transaction(tx)

    async def invoke_raw(
        self,
        f: ContractMethodResult[ReturnType],
        *,
        signers: Optional[Sequence[SigningPair]] = None,
        network_fee: int = 0,
        system_fee: int = 0,
        append_network_fee: int = 0,
        append_system_fee: int = 0,
    ) -> InvokeReceipt[noderpc.ExecutionResult]:
        """
        Call a contract method and persist results on the chain. Costs GAS.
        Waits for tx to be included in a block. Does not post processes the execution results.

        Args:
            f: function to call.
            signers: manually set the list of signers.
            network_fee: manually set the network fee.
            system_fee: manually set the system fee.
            append_network_fee: increase the calculated network fee with this amount.
            append_system_fee: increase the calculated system fee with this amount.

        Returns:
            A transaction receipt. The `state` field of the receipt indicates if the transaction script executed
            successfully. The remaining fields provide additional information such as notifications that happened
            in the contract.

        See Also:
            `invoke()` - waits for a transaction receipt, performs post-processing of the execution results
            `invoke_fast()` - does not wait for a receipt.
        """
        delay, timeout = await self._get_receipt_time_values()
        async with noderpc.NeoRpcClient(self.rpc_host) as client:
            tx_id = await self.invoke_fast(
                f,
                signers=signers,
                network_fee=network_fee,
                system_fee=system_fee,
                append_network_fee=append_network_fee,
                append_system_fee=append_system_fee,
            )
            receipt = await client.wait_for_transaction_receipt(
                tx_id, timeout=timeout, retry_delay=delay
            )

            return InvokeReceipt[noderpc.ExecutionResult](
                receipt.tx_hash,
                receipt.included_in_block,
                receipt.confirmations,
                receipt.execution.gas_consumed,
                receipt.execution.state,
                receipt.execution.exception,
                receipt.execution.notifications,
                receipt.execution.stack,
            )

    async def invoke_multi(
        self,
        f: list[ContractMethodResult],
        *,
        signers: Optional[Sequence[SigningPair]] = None,
        network_fee: int = 0,
        system_fee: int = 0,
        append_network_fee: int = 0,
        append_system_fee: int = 0,
        _post_processing: bool = True,
    ) -> Sequence:
        """
        Call all contract methods (concatenated) in one go and persist results on the chain. Costs GAS.
        Waits for tx to be included in a block. Automatically post processes the execution results according to the
        post-processing function of `f` if present.

        Args:
            f: list of functions to call.
            signers: manually set the list of signers.
            network_fee: manually set the network fee.
            system_fee: manually set the system fee.
            append_network_fee: increase the calculated network fee with this amount.
            append_system_fee: increase the calculated system fee with this amount.

        Returns:
            a list with the results of all exected functions.

        See Also:
            `test_invoke_multi` - free equivalent for read only operations or testing.
            `invoke_multi_fast` - does not wait for a receipt.
            `invoke_multi_raw` - does not wait for a transaction receipt, does not perform post-processing of the
                execution results.
        """
        tx_id = await self.invoke_multi_fast(
            f,
            signers=signers,
            network_fee=network_fee,
            system_fee=system_fee,
            append_network_fee=append_network_fee,
            append_system_fee=append_system_fee,
        )

        delay, timeout = await self._get_receipt_time_values()
        async with noderpc.NeoRpcClient(self.rpc_host) as client:
            receipt = await client.wait_for_transaction_receipt(
                tx_id, timeout=timeout, retry_delay=delay
            )

        results = []
        stack_offset = 0
        for call in f:
            res_cpy = deepcopy(receipt.execution)
            # adjust the stack so that it becomes transparent for the post-processing functions.
            res_cpy.stack = res_cpy.stack[
                stack_offset : stack_offset + call.return_count
            ]
            if call.execution_processor is None or not _post_processing:
                results.append(res_cpy)
            else:
                results.append(call.execution_processor(res_cpy, 0))
            stack_offset += call.return_count
        return results

    async def invoke_multi_fast(
        self,
        f: list[ContractMethodResult],
        *,
        signers: Optional[Sequence[SigningPair]] = None,
        network_fee: int = 0,
        system_fee: int = 0,
        append_network_fee: int = 0,
        append_system_fee: int = 0,
    ) -> types.UInt256:
        """
        Call all contract methods (concatenated) in one go and persist results on the chain. Costs GAS.
        Does not wait for tx to be included in a block. Automatically post processes the execution results according to
        the post-processing function of `f` if present.

        Args:
            f: list of functions to call.
            signers: manually set the list of signers.
            network_fee: manually set the network fee.
            system_fee: manually set the system fee.
            append_network_fee: increase the calculated network fee with this amount.
            append_system_fee: increase the calculated system fee with this amount.

        Returns:
            a transaction ID if accepted by the network. Acceptance is does not guarantee successful execution.
            Acceptance means there are no transaction format errors. Use `invoke()` to wait for a receipt. The `state`
            field of the receipt indicates if the transaction script executed successfully.


        See Also:
            `test_invoke_fast` - free equivalent for read only operations or testing.
            `invoke_multi` - waits for a transaction receipt, performs post-processing of the execution results.
            `invoke_multi_raw` - does not wait for a transaction receipt, does not perform post-processing of the
                execution results.
        """
        script = bytearray()
        for call in f:  # type: ContractMethodResult
            script.extend(call.script)

        wrapped: ContractMethodResult[None] = ContractMethodResult(script)
        tx_id = await self.invoke_fast(
            wrapped,
            signers=signers,
            network_fee=network_fee,
            system_fee=system_fee,
            append_network_fee=append_network_fee,
            append_system_fee=append_system_fee,
        )
        return tx_id

    async def invoke_multi_raw(
        self,
        f: list[ContractMethodResult],
        *,
        signers: Optional[Sequence[SigningPair]] = None,
        network_fee: int = 0,
        system_fee: int = 0,
        append_network_fee: int = 0,
        append_system_fee: int = 0,
    ) -> Sequence:
        """
        Call all contract methods (concatenated) in one go and persist results on the chain. Costs GAS.
        Do not wait for tx to be included in a block. Do not post process the execution results according to
        the post-processing function of `f` if present.

        Args:
            f: list of functions to call.
            signers: manually set the list of signers.
            network_fee: manually set the network fee.
            system_fee: manually set the system fee.
            append_network_fee: increase the calculated network fee with this amount.
            append_system_fee: increase the calculated system fee with this amount.

        Returns:
            a list with the results of all exected functions.

        See Also:
            `test_invoke_raw` - free equivalent for read only operations or testing.
            `invoke_multi` - waits for a transaction receipt, performs post-processing of the execution results.
            `invoke_multi_fast` - does not wait for a receipt.
        """
        return await self.invoke_multi(
            f,
            signers=signers,
            network_fee=network_fee,
            system_fee=system_fee,
            append_network_fee=append_network_fee,
            append_system_fee=append_system_fee,
            _post_processing=False,
        )

    async def estimate_gas(
        self,
        f: ContractMethodResult,
        *,
        signers: Optional[Sequence[verification.Signer]] = None,
    ) -> int:
        """
        Estimate the gas price for calling the contract method.
        """
        async with noderpc.NeoRpcClient(self.rpc_host) as client:
            res = await client.invoke_script(f.script, signers)
            return res.gas_consumed

    async def _get_receipt_time_values(self) -> tuple[float, float]:
        if self._receipt_retry_delay is None or self._receipt_timeout is None:
            async with noderpc.NeoRpcClient(self.rpc_host) as client:
                result = await client.get_version()
                # 5 seems like a reasonable divider where on mainnet (with 15s blocks) at worst case
                # the RPC server is queried 5 times.
                delay = self._receipt_retry_delay = (
                    result.protocol.ms_per_block / 1000
                ) / 5
                timeout = self._receipt_timeout = (
                    result.protocol.ms_per_block + self._receipt_retry_delay
                )
                return delay, timeout
        else:
            return self._receipt_retry_delay, self._receipt_timeout

    def add_signer(self, func: signing.SigningFunction, signer: verification.Signer):
        """
        Add a `Signer` which will automatically be included when the various invoke functions.
        """
        self._signing_funcs.append(func)
        self.signers.append(signer)

    @classmethod
    def node_provider_mainnet(cls):
        """
        Create a facade pre-configured to N3 MainNet.
        """
        return cls(_DEFAULT_MAINNET_RPC)

    @classmethod
    def node_provider_testnet(cls):
        """
        Create a facade pre-configured to N3 TestNet.
        """
        return cls(_DEFAULT_TESTNET_RPC)


class GenericContract:
    """
    Generic class to call arbitrary methods on a smart contract.
    """

    def __init__(self, contract_hash: types.UInt160):
        self.hash = contract_hash

    def call_function(
        self,
        name,
        args: Optional[noderpc.ContractParameter] = None,
    ) -> ContractMethodResult[noderpc.ExecutionResult]:
        """
        Call a method on the contract.

        Args:
            name: the method name to call as defined in the manifest.
            args: optional list of arguments the function expects.
        """
        if args is None:
            script = vm.ScriptBuilder().emit_contract_call(self.hash, name).to_array()
        else:
            sb = vm.ScriptBuilder()
            sb.emit_contract_call_with_args(self.hash, name, args)
            script = sb.to_array()
        return ContractMethodResult(script)

    def update(
        self,
        update_method: str = "update",
        nef: Optional[nef.NEF] = None,
        manifest: Optional[manifest.ContractManifest] = None,
        data: Optional[noderpc.ContractParameter] = None,
    ) -> ContractMethodResult[None]:
        """
        Update this contract on chain with a new manifest and/or contract (NEF).

        Assumes the update method on the contract uses the standard arguments; nef, manifest and (optional) data.
        If it uses custom arguments use `call_function` instead.

        Args:
            update_method: override with name of the update function on the contract.
            nef: compiled contract.
            manifest: contract manifest.
            data: data that is passed to the `_deploy` method of the smart contract (if the method exists).
        """
        if nef is None and manifest is None:
            raise ValueError("NEF and manifest are both None. Nothing to update")

        m: Optional[str] = None
        if manifest is not None:
            # convert to the right format as expected by the management contract
            m = str(manifest)

        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(self.hash, update_method, [nef, m, data])

        return ContractMethodResult(sb.to_array(), unwrap.as_none)

    def destroy(self, destroy_method: str = "destroy") -> ContractMethodResult[None]:
        """
        Destroy the contract on chain.

        This will permanently block the contract hash on the network.

        Args:
            destroy_method: override with name of the destroy function on the contract. Default signature is `destroy()`.
        """
        sb = vm.ScriptBuilder().emit_contract_call(self.hash, destroy_method)
        return ContractMethodResult(sb.to_array(), unwrap.as_none)

    @staticmethod
    def deploy(
        nef: nef.NEF,
        manifest: manifest.ContractManifest,
        data: Optional[noderpc.ContractParameter] = None,
    ) -> ContractMethodResult[types.UInt160]:
        """
        Deploy a smart contract to the chain.

        Args:
            nef: compiled contract.
            manifest: contract manifest file.
            data: data that is passed to the `_deploy` method of the smart contract (if the method exists).

        Returns:
            contract hash.
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(
            contract.CONTRACT_HASHES.MANAGEMENT, "deploy", [nef, str(manifest), data]
        )

        def process(res, _):
            arr = unwrap.as_list(res)
            return arr[2].as_uint160()

        return ContractMethodResult(sb.to_array(), process)


class _TokenContract(GenericContract):
    """
    Base class for Fungible and Non-Fungible tokens
    """

    def symbol(self) -> ContractMethodResult[str]:
        """
        User-friendly name of the token.
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "symbol").to_array()
        return ContractMethodResult(script, unwrap.as_str)

    def decimals(self) -> ContractMethodResult[int]:
        """
        Get the amount of decimals.

        Use this with the result of balance_of to display the correct user representation.
        """
        script = vm.ScriptBuilder().emit_contract_call(self.hash, "decimals").to_array()
        return ContractMethodResult(script, unwrap.as_int)

    def total_supply(self) -> ContractMethodResult[int]:
        """
        Get the total token supply in the NEO system.
        """
        script = (
            vm.ScriptBuilder().emit_contract_call(self.hash, "totalSupply").to_array()
        )
        return ContractMethodResult(script, unwrap.as_int)


class NEP17Contract(_TokenContract):
    """
    Base class for calling NEP-17 compliant smart contracts.
    """

    def balance_of(
        self, account: types.UInt160 | NeoAddress
    ) -> ContractMethodResult[int]:
        """
        Get the balance for the given account.

        Note:
            The returned value does not take the token decimals into account. e.g. for the GAS token you want to
        divide the result by 10**8 (as the Gas token has 8 decimals).

        Raises:
            ValueError: if `account` is an invalid NeoAddress format.
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
        Get the balance for the given account while taking the token decimals into account.

        Uses the token decimals to convert to the user end representation.

        Raises:
            ValueError: if `account` is an invalid NeoAddress format.
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
        data: Optional[noderpc.ContractParameter] = None,
    ) -> ContractMethodResult[bool]:
        """
        Transfer `amount` of tokens from `source` account to `destination` account.
        Forward `data` to `onNEP17Payment` handler if applicable.

        For this to pass while using `test_invoke()`, make sure to add a Signer with a script hash equal to the source
        account. i.e.

            source = <source_script_hash>
            signer = verification.Signer(source, payloads.WitnessScope.CALLED_BY_ENTRY)
            await facade.test_invoke(token.transfer(source, destination, 10), signers=[signer]))

        Raises:
            ValueError: if `source` or `destination` is an invalid NeoAddress format

        Returns:
            The return value after invoking with `invoke()` or `test_invoke()` is
                `True` if the token transferred successful.
                `False` otherwise.
        """
        source = _check_address_and_convert(source)
        destination = _check_address_and_convert(destination)

        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "transfer", [source, destination, amount, data]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_bool)

    def transfer_friendly(
        self, source, dest, amount, data: Optional[noderpc.ContractParameter] = None
    ):
        """
        Transfer `amount` of tokens from `source` account to `destination` account.

        Same as `transfer` but does not require manually convert amount if the token uses decimals.

        Returns:
            The return value after invoking with `invoke()` or `test_invoke()` is
                `True` if the token transferred successful.
                `False` otherwise.
        """
        sb = vm.ScriptBuilder()
        sb.emit_push(data)
        sb.emit_push(10)  # multiplier base
        sb.emit_contract_call(self.hash, "decimals")
        sb.emit(vm.OpCode.POW)
        sb.emit_push(amount)
        sb.emit(vm.OpCode.MUL)
        sb.emit_push(dest)
        sb.emit_push(source)
        sb.emit_push(4)
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(callflags.CallFlags.ALL)
        sb.emit_push("transfer")
        sb.emit_push(self.hash)
        sb.emit_syscall(vm.Syscalls.SYSTEM_CONTRACT_CALL)

        return ContractMethodResult(sb.to_array(), unwrap.as_bool)

    def transfer_multi(
        self,
        source: types.UInt160 | NeoAddress,
        destinations: Sequence[types.UInt160 | NeoAddress],
        amount: int,
        data: Optional[noderpc.ContractParameter] = None,
        abort_on_failure: bool = False,
    ) -> ContractMethodResult[bool]:
        """
        Transfer `amount` of tokens from `source` to each account in `destinations`.

        Args:
            source: account to take funds from.
            destinations: accounts to send funds to.
            amount: how much to transfer.
            data: forward to `onNEP17Payment` handler if applicable.
            abort_on_failure: if True aborts the whole transaction if any of the transfers fails.

        Raises:
            ValueError: if any of the destinations is supplied as NeoAddress but is an invalid address format.

        Returns:
            The return value after invoking with `invoke()` or `test_invoke()` is
                `True` if all transfers are successful.
                `False` otherwise.
        """
        sb = vm.ScriptBuilder()
        source = _check_address_and_convert(source)
        for d in destinations:
            d = _check_address_and_convert(d)
            sb.emit_contract_call_with_args(
                self.hash, "transfer", [source, d, amount, data]
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
    """
    Wrapped GAS token contract.
    """

    def __init__(self):
        super(GasToken, self).__init__(contract.CONTRACT_HASHES.GAS_TOKEN)


class Candidate:
    """
    Container for holding consensus candidate voting results.
    """

    def __init__(self, public_key: cryptography.ECPoint, votes: int):
        #: public key of the candidate.
        self.public_key = public_key
        #: number of votes the candidate has.
        self.votes = votes
        shash = coreutils.to_script_hash(
            contractutils.create_signature_redeemscript(self.public_key)
        )
        #: NEO address of the candidate.
        self.address = walletutils.script_hash_to_address(shash)


class NeoToken(NEP17Contract):
    """
    Wrapped NEO token contract.
    """

    def __init__(self):
        super(NeoToken, self).__init__(contract.CONTRACT_HASHES.NEO_TOKEN)

    def get_gas_per_block(self) -> ContractMethodResult[int]:
        """
        Get the amount of GAS generated in each block.
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
        Get the amount of unclaimed GAS.

        Args:
            account: for whom.
            end: up to which block height to calculate the GAS bonus. Omit to calculate to the current chain height.

        Raises:
            ValueError: if `account` is an invalid NeoAddress format.
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
        Get the amount of GAS to pay to register as consensus candidate.
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
        Register as a consensus candidate.

        See Also:
            Account.public_key

        Returns:
            `True` if successful. `False` otherwise.
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
        Unregister as a consensus candidate.

        See Also:
            Account.public_key

        Returns:
            `True` if successful. `False` otherwise.
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
        Cast a vote for `candidate` to become a consensus node.

        Args:
            voter: the account to vote from.
            candidate: who to vote on.

        Raises:
            ValueError: if `voter` is an invalid NeoAddress format.

        Returns:
            `True` if vote cast successful. `False` otherwise.
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
        Get the total vote count for `candidate`.
        """
        script = (
            vm.ScriptBuilder()
            .emit_contract_call_with_args(self.hash, "getCandidateVote", [candidate])
            .to_array()
        )
        return ContractMethodResult(script, unwrap.as_int)

    def candidates_registered(self) -> ContractMethodResult[list[Candidate]]:
        """
        Get the first 256 registered candidates.
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
    Base class for calling NEP-11 compliant smart contracts.

    NFTs can be divisible or non-divisible which is determined by the value of `decimals()`.

    Note:
        The following 2 common methods defined in the NEP-11 standard have different names to improve discoverability
         NEP-11 standard    This wrapper
      1. balanceOf       -> total_owned_by
      2. tokensOf        -> token_ids_owned_by
    """

    def decimals(self) -> ContractMethodResult[int]:
        """
        Get the amount of decimals.

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
            ValueError: if `owner` is an invalid NeoAddress format.
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
        Get an iterator containing all token ids owned by the specified address.

        Raises:
            ValueError: if `owner` is an invalid NeoAddress format.
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

    def tokens(self, limit: int = 2000) -> ContractMethodResult[list[bytes]]:
        """
        Get all tokens minted by the contract.

        limit: the maximum tokens to return. Note: there is a limit on the virtual machine (default: 2048) to avoid too
        much compute being used. The limit is set slightly lower on purpose to allow other necessary items in the VM.
        If the contract returns more items you'll have to resort to retrieving them using RPC Session Iterators.

        Note:
            This is an optional method and may not exist on the contract.
        """

        def process(res: noderpc.ExecutionResult, _: int = 0) -> list[bytes]:
            raw_results: list[noderpc.StackItem] = unwrap.as_list(res)
            return [si.value for si in raw_results]

        sb = vm.ScriptBuilder().emit_contract_call_and_unwrap_iterator(
            self.hash, "tokens", unwrap_limit=limit
        )
        return ContractMethodResult(sb.to_array(), process)

    def properties(self, token_id: bytes) -> ContractMethodResult[dict]:
        """
        Get all properties for the given NFT.

        Note:
            This is an optional method and may not exist on the contract.
        """
        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "properties", [token_id]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_dict)


class NEP11DivisibleContract(_NEP11Contract):
    """
    Base class for divisible NFTs.

    The NEP-11 `ownerOf` method is named `owners_of` in this wrapper.
    """

    def transfer(
        self,
        source: types.UInt160 | NeoAddress,
        destination: types.UInt160 | NeoAddress,
        amount: int,
        token_id: bytes,
        data: Optional[noderpc.ContractParameter] = None,
    ) -> ContractMethodResult[bool]:
        """
        Transfer `amount` of `token_id` from `source` account to `destination` account.

        For this to pass while using `test_invoke()`, make sure to add a Signer with a script hash equal to the source
        account. i.e.

            source = <source_script_hash>
            signer = verification.Signer(source, payloads.WitnessScope.CALLED_BY_ENTRY)
            await facade.test_invoke(token.transfer(source, destination, 10), signers=[signer]))

        Raises:
            ValueError: if `source` or `destination` is an invalid NeoAddress format.

        Returns:
            True if token fractions transferred successful. False otherwise.
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
        Get a list of account script hashes that own a part of `token_id`.
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
        Get the token balance for the given owner.

        Raises:
            ValueError: if `owner` is an invalid NeoAddress format.
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
        Get the balance for the given account and convert the result into the user representation.

        Uses the token decimals to convert to the user end representation.

        Raises:
            ValueError: if `owner` is an invalid NeoAddress format.
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
    """Base class for non-divisible NFTs."""

    def transfer(
        self,
        destination: types.UInt160 | NeoAddress,
        token_id: bytes,
        data: Optional[noderpc.ContractParameter] = None,
    ) -> ContractMethodResult[bool]:
        """
        Transfer `token_id` to `destination` account.
        The source account will be the account that pays for the fees (a.k.a. the transaction.sender).

        For this to pass while using `test_invoke()`, make sure to add a Signer with a script hash equal to the source
        account. i.e.

            signer = verification.Signer(source_account, payloads.WitnessScope.CALLED_BY_ENTRY)
            await facade.test_invoke(token.transfer(destination, token_id, 10), signers=[signer]))

        Raises:
            ValueError: if `destination` is an invalid NeoAddress format.

        Returns:
            The return value after invoking with `invoke()` or `test_invoke()` is
                `True` if the token transferred successful.
                `False` otherwise.
        """
        destination = _check_address_and_convert(destination)
        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "transfer", [destination, token_id, data]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_bool)

    def transfer_multi(
        self,
        destinations: Sequence[types.UInt160 | NeoAddress],
        token_ids: list[bytes],
        data: Optional[noderpc.ContractParameter] = None,
        abort_on_failure: bool = False,
    ) -> ContractMethodResult[bool]:
        """
        Transfer multiple token_ids to multiple destinations. Destination and token_ids are paired in order.

        Args:
            destinations: accounts to send tokens to.
            token_ids: list of token ids.
            data: forward to `onNEP17Payment` handler if applicable.
            abort_on_failure: if `True` aborts the whole transaction if any of the transfers fails.

        Raises:
            ValueError: if any of the destinations is supplied as NeoAddress but is an invalid address format.

        Returns:
            The return value after invoking with `invoke()` or `test_invoke()` is
                `True` if all transfers are successful.
                `False` otherwise.
        """
        sb = vm.ScriptBuilder()
        for d, t in zip(destinations, token_ids):
            d = _check_address_and_convert(d)
            sb.emit_contract_call_with_args(self.hash, "transfer", [d, t, data])
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

    def owner_of(self, token_id: bytes) -> ContractMethodResult[types.UInt160]:
        """
        Get the owner of the given token.
        """
        sb = vm.ScriptBuilder().emit_contract_call_with_args(
            self.hash, "ownerOf", [token_id]
        )
        return ContractMethodResult(sb.to_array(), unwrap.as_uint160)


def _check_address_and_convert(value: types.UInt160 | NeoAddress) -> types.UInt160:
    if isinstance(value, types.UInt160):
        return value
    if not isinstance(value, str):
        raise ValueError(
            f"Input is of type {type(value)} expected UInt160 or NeoAddress(str)"
        )
    walletutils.validate_address(value)
    return walletutils.address_to_script_hash(value)


class PolicyContract(GenericContract):
    """
    Wrapper around the native contract that manages system policies.

    Note:
        Functions that only consensus committee members can use are not implemented.
    """

    def __init__(self):
        super(PolicyContract, self).__init__(contract.CONTRACT_HASHES.POLICY)

    def fee_per_byte(self) -> ContractMethodResult[int]:
        """
        The fee per transaction byte.
        """
        sb = vm.ScriptBuilder().emit_contract_call(self.hash, "getFeePerByte")
        return ContractMethodResult(sb.to_array(), unwrap.as_int)

    def exec_fee_factor(self) -> ContractMethodResult[int]:
        """
        The system fee multiplier for transactions.
        """
        sb = vm.ScriptBuilder().emit_contract_call(self.hash, "getExecFeeFactor")
        return ContractMethodResult(sb.to_array(), unwrap.as_int)

    def storage_price(self) -> ContractMethodResult[int]:
        """
        The price per byte of smart contract storage.
        """
        sb = vm.ScriptBuilder().emit_contract_call(self.hash, "getStoragePrice")
        return ContractMethodResult(sb.to_array(), unwrap.as_int)

    def is_blocked(self, script_hash: types.UInt160) -> ContractMethodResult[bool]:
        """
        Check if an account or contract is blocked on the network.
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(self.hash, "isBlocked", [script_hash])
        return ContractMethodResult(sb.to_array(), unwrap.as_bool)


class DesignateRole(IntEnum):
    """
    Special role that can be assigned to nodes in the network by the consensus committee.
    """

    STATE_VALIDATOR = 4
    ORACLE = 8
    NEO_FS_ALPHABET_NODE = 16


class RoleContract(GenericContract):
    """
    Wrapper around the native Role management contract.
    """

    def __init__(self):
        super(RoleContract, self).__init__(contract.CONTRACT_HASHES.ROLE_MANAGEMENT)

    def get_designated_by_role(
        self, role: DesignateRole, block_index: int
    ) -> ContractMethodResult[list[cryptography.ECPoint]]:
        """
        Gets the public keys registered for a given role at a given height.
        """
        sb = vm.ScriptBuilder()
        sb.emit_contract_call_with_args(
            self.hash, "getDesignatedByRole", [role, block_index]
        )

        def process(res: noderpc.ExecutionResult, _: int):
            arr = unwrap.as_list(res)
            return list(map(lambda x: x.as_public_key(), arr))

        return ContractMethodResult(sb.to_array(), process)
