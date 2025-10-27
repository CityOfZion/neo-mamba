"""
Signing functions for use with `ChainFacade.invoke`.
"""
import os
from dataclasses import dataclass
from neo3.network.payloads import transaction
from typing import Callable, Awaitable
from neo3.wallet import account


@dataclass
class SigningDetails:
    network: int
    #: for which Signer we're adding a witness
    # witness_index: int


# The signing function adds a witness to the provided transaction
# SigningFunction = Callable[[transaction.Transaction, SigningDetails], None]
SigningFunction = Callable[[transaction.Transaction, SigningDetails], Awaitable]


def sign_with_account(acc: account.Account) -> SigningFunction:
    """
    Sign and add a witness using the account and the provided account password.
    """

    async def account_signer(tx: transaction.Transaction, details: SigningDetails):
        # this will automatically add a witness
        acc.sign_tx(tx, details.network)

    return account_signer


def sign_with_ledger() -> SigningFunction:
    raise NotImplementedError


def sign_on_remote_server() -> SigningFunction:
    async def remote_server_signer(
        tx: transaction.Transaction, details: SigningDetails
    ):
        # call some remote API to get the signature
        # and add a witness with the signature
        raise NotImplementedError

    return remote_server_signer


def sign_with_multisig_account(acc: account.Account) -> SigningFunction:
    """
    Sign and add a multi-signature witness.

    This only works for a 1 out of n multi-signature account.

    Args:
        acc: a multi-signature account
    """

    async def account_signer(tx: transaction.Transaction, details: SigningDetails):
        ctx = account.MultiSigContext()
        # this will automatically add a witness
        acc.sign_multisig_tx(tx, ctx, details.network)

    return account_signer


def no_signing() -> SigningFunction:
    """
    Dummy signing function to use with test invocations.
    """

    async def oh_noes(unused: transaction.Transaction, unused2: SigningDetails):
        raise Exception(
            "can't sign with dummy signing function. Did you add a test_signer to ChainFacade?"
        )

    return oh_noes
