import pathlib
import unittest
import asyncio
import signal
import re
import inspect
from typing import Optional, TypeVar, Type, Sequence, overload, Any
from neo3.core import types, cryptography
from neo3.wallet import account
from neo3.api.wrappers import GenericContract, NEP17Contract, ChainFacade, InvokeReceipt
from neo3.api import noderpc, StackItem
from neo3.network.payloads.verification import Signer
from neo3.api.helpers.signing import (
    sign_with_account,
    sign_with_multisig_account,
    no_signing,
)
from neo3.api.helpers import unwrap
from neo3.contracts import nef, manifest
from dataclasses import dataclass
from neo3.sctesting.node import NeoGoNode, RuntimeLog
from neo3.sctesting.storage import PostProcessor

ASSERT_REASON = re.compile(r".*Reason: (.*)")


class AssertException(Exception):
    pass


class AbortException(Exception):
    pass


# TODO: include ability to read gas consumption
# TODO: see how to test check_witness

T = TypeVar("T")

RawStack = list[StackItem]
ReturnType = (
    str
    | int
    | bool
    | dict
    | list
    | types.UInt160
    | types.UInt256
    | bytes
    | cryptography.ECPoint
    | None
    | RawStack
)


class SmartContractTestCase(unittest.IsolatedAsyncioTestCase):
    """
    A class for testing NEO3 smart contracts. It exposes utility functions for fast testing of public entry points,
    storage changes and event notifications.

    Note: it internally starts an in-memory full node to which the contract is deployed. Storage changes can persist
    between individual tests (if using a signing account) as long as the test are of the same test class itself.
    """

    node: NeoGoNode
    contract_hash: types.UInt160

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        # disable debug mode because it will warn about functions waiting longer than 0.1 seconds
        # which will be the case for all functions that persist state (e.g. transfer())
        asyncio.get_event_loop().set_debug(False)
        self.node.runtime_logs = []

    @property
    def facade(self) -> ChainFacade:
        return self.node.facade

    @property
    def runtime_logs(self) -> list[RuntimeLog]:
        return self.node.runtime_logs

    @classmethod
    def setUpClass(cls) -> None:
        cls.node = NeoGoNode()
        # these are called in reverse order
        cls.addClassCleanup(cls.node.reset)
        cls.addClassCleanup(cls.node.stop)

        def cleanup(unused_sig, unused_frame):
            cls.node.stop()
            cls.node.reset()

        signal.signal(signal.SIGINT, cleanup)
        cls.node.start()

    @overload
    @classmethod
    async def call(
        cls,
        method: str,
        args: Optional[list] = None,
        *,
        return_type: None,
        signing_accounts: Optional[Sequence[account.Account]] = None,
        signers: Optional[Sequence[Signer]] = None,
        target_contract: Optional[types.UInt160] = None,
    ) -> tuple[None, list[noderpc.Notification]]: ...

    @overload
    @classmethod
    async def call(
        cls,
        method: str,
        args: Optional[list] = None,
        *,
        return_type: Type[T],
        signing_accounts: Optional[Sequence[account.Account]] = None,
        signers: Optional[Sequence[Signer]] = None,
        target_contract: Optional[types.UInt160] = None,
    ) -> tuple[T, list[noderpc.Notification]]: ...

    @classmethod
    async def call(
        cls,
        method: str,
        args: Optional[list] = None,
        *,
        return_type,
        signing_accounts: Optional[Sequence[account.Account]] = None,
        signers: Optional[Sequence[Signer]] = None,
        target_contract: Optional[types.UInt160] = None,
    ) -> tuple[Any, list[noderpc.Notification]]:
        """
        Calls the contract specified by `contract_hash`

        Args:
            method: name of the method to call
            args: method arguments
            return_type: expected return type. Will be used to unwrap and cast the results.
            signing_accounts:
                If not specified a 'test_invoke' will be performed.
                If specified an 'invoke' (=state persisting) will be performed. The default witness scope is CALLED_BY_ENTRY.
                This can be overridden using the `signers` argument.
            signers: a list of custom signers. Must have the same length as `signing_account` if that is specified.
            target_contract: call a different contract than the one under test. e.g. NeoToken
        """
        if target_contract is None:
            contract = GenericContract(cls.contract_hash)
        else:
            contract = GenericContract(target_contract)

        facade = cls.node.facade

        if signing_accounts is not None:
            signing_pairs = []

            if signers is not None and len(signers) != len(signing_accounts):
                raise ValueError(f"signing_accounts and signers length must be equal")

            for i, signing_account in enumerate(signing_accounts):
                if signers is None:
                    signer = Signer(signing_account.script_hash)
                else:
                    # take it from the supplied list
                    signer = signers[i]
                if signing_account.is_multisig:
                    signing_pairs.append(
                        (sign_with_multisig_account(signing_account), signer)
                    )
                else:
                    signing_pairs.append((sign_with_account(signing_account), signer))
            receipt = await facade.invoke(
                contract.call_function(method, args), signers=signing_pairs
            )
        else:
            signing_pairs = None
            if signers is not None:
                signing_pairs = list(map(lambda s: (no_signing(), s), signers))
            receipt = await facade.test_invoke(
                contract.call_function(method, args), signers=signing_pairs
            )
        cls._check_vmstate(receipt)
        exec_result = receipt.result
        notifications = receipt.notifications

        if return_type is str:
            return unwrap.as_str(exec_result), notifications
        elif return_type is int:
            return unwrap.as_int(exec_result), notifications
        elif return_type is bool:
            return unwrap.as_bool(exec_result), notifications
        elif return_type is dict:
            return unwrap.as_dict(exec_result), notifications
        elif return_type is list:
            return unwrap.as_list(exec_result), notifications
        elif return_type is types.UInt160:
            return unwrap.as_uint160(exec_result), notifications
        elif return_type is types.UInt256:
            return unwrap.as_uint256(exec_result), notifications
        elif return_type is bytes:
            return unwrap.as_bytes(exec_result), notifications
        elif return_type is cryptography.ECPoint:
            return unwrap.as_public_key(exec_result), notifications
        elif return_type is None:
            return unwrap.as_none(exec_result), notifications
        elif return_type is RawStack:
            return exec_result.stack, notifications
        else:
            raise ValueError(f"unsupported return_type: {return_type}")

    @classmethod
    async def deploy(
        cls, path_to_nef: str, signing_account: account.Account
    ) -> tuple[types.UInt160, list[noderpc.Notification]]:
        # fix relative path resolving by looking up the call stack because the test might not get started from
        # the working directory that defines the tests e.g. when using `unittest discover`
        frame = inspect.stack()[1]
        nef_path = pathlib.Path(frame.filename).parent.joinpath(path_to_nef)
        if not nef_path.is_file() or not nef_path.suffix == ".nef":
            raise ValueError("invalid contract path specified")
        _nef = nef.NEF.from_file(str(nef_path.absolute()))

        manifest_path = nef_path.with_suffix(".manifest.json")
        if not pathlib.Path(manifest_path).is_file():
            raise ValueError(f"can't find manifest at {manifest_path}")
        _manifest = manifest.ContractManifest.from_file(str(manifest_path))

        if signing_account.is_multisig:
            sign_pair = (
                sign_with_multisig_account(signing_account),
                Signer(signing_account.script_hash),
            )

        else:
            sign_pair = (
                sign_with_account(signing_account),
                Signer(signing_account.script_hash),
            )
        receipt = await cls.node.facade.invoke(
            GenericContract.deploy(_nef, _manifest), signers=[sign_pair]
        )
        if receipt.state == "FAULT":
            exception = receipt.exception
            if exception is not None and "ASSERT" in exception:
                raise AssertException(cls._get_assert_reason(exception))
            elif exception is not None and "ABORT" in exception:
                raise AbortException(cls._get_assert_reason(exception))
            else:
                raise ValueError(exception)
        return receipt.result, receipt.notifications

    @classmethod
    async def transfer(
        cls,
        token: types.UInt160,
        source: types.UInt160,
        destination: types.UInt160,
        amount: int,
        decimals: int,
        signing_account: Optional[account.Account] = None,
        system_fee: int = 0,
    ) -> tuple[bool, list[noderpc.Notification]]:
        contract = NEP17Contract(token)
        if signing_account is None:
            signing_account = cls.node.account_committee

        if signing_account.is_multisig:
            sign_pair = (
                sign_with_multisig_account(signing_account),
                Signer(signing_account.script_hash),
            )

        else:
            sign_pair = (
                sign_with_account(signing_account),
                Signer(signing_account.script_hash),
            )

        receipt = await cls.node.facade.invoke(
            contract.transfer_friendly(source, destination, amount, decimals),
            signers=[sign_pair],
            system_fee=system_fee,
        )
        if receipt.state == "FAULT":
            exception = receipt.exception
            if exception is not None and "ASSERT" in exception:
                raise AssertException(cls._get_assert_reason(exception))
            elif exception is not None and "ABORT" in exception:
                raise AbortException(cls._get_assert_reason(exception))
            else:
                raise ValueError(exception)
        return receipt.result, receipt.notifications

    @classmethod
    async def get_storage(
        cls,
        prefix: Optional[bytes] = None,
        *,
        target_contract: Optional[types.UInt160] = None,
        remove_prefix: bool = False,
        key_post_processor: Optional[PostProcessor] = None,
        values_post_processor: Optional[PostProcessor] = None,
    ) -> dict[bytes, bytes]:
        """
        Gets the entries in the storage of the contract specified by `contract_hash`

        Args:
            prefix: prefix to filter the entries in the storage. Return the entire storage if not set.
            target_contract: gets the storage of a different contract than the one under test. e.g. NeoToken
            remove_prefix: whether the prefix should be removed from the output keys. False by default.
            key_post_processor: a function to post process the storage key before placing it in the dictionary.
            values_post_processor: a function to post process the storage value before placing it in the dictionary.
        """
        if target_contract is None:
            contract = GenericContract(cls.contract_hash)
        else:
            contract = GenericContract(target_contract)

        if not prefix and remove_prefix:
            remove_prefix = False

        results = {}
        async with noderpc.NeoRpcClient(cls.node.facade.rpc_host) as rpc_client:
            async for k, v in rpc_client.find_states(contract.hash, prefix):
                if remove_prefix:
                    k = k.removeprefix(prefix)
                if key_post_processor is not None:
                    k = key_post_processor(k)
                if values_post_processor is not None:
                    v = values_post_processor(v)
                results[k] = v

        return results

    @classmethod
    def _check_vmstate(cls, receipt):
        try:
            unwrap.check_state_ok(receipt)
        except ValueError as e:
            if "ASSERT" in receipt.exception:
                raise AssertException(cls._get_assert_reason(receipt.exception))
            elif "ABORT" in receipt.exception:
                raise AbortException(cls._get_assert_reason(receipt.exception))
            else:
                raise e

    @classmethod
    def _get_assert_reason(cls, exception: str):
        m = ASSERT_REASON.match(exception)
        if m is not None:
            return m.group(1)
        return ""


@dataclass
class Nep17TransferEvent:
    source: types.UInt160
    destination: types.UInt160
    amount: int

    @classmethod
    def from_notification(cls, n: noderpc.Notification):
        stack = n.state.as_list()
        source = stack[0].as_uint160()
        destination = stack[1].as_uint160()
        amount = stack[2].as_int()
        return cls(source, destination, amount)
