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


def sign_insecure_with_account(acc: account.Account, password: str) -> SigningFunction:
    """
    Sign and add a witness using the account and the provided account password.
    """

    async def insecure_account_signer(
        tx: transaction.Transaction, details: SigningDetails
    ):
        # this will automatically add a witness
        acc.sign_tx(tx, password, details.network)

    return insecure_account_signer


def sign_secure_with_account(
    acc: account.Account, env_password_name: str
) -> SigningFunction:
    """
    Sign and add a witness using the account. The account password is read from the environment variables.
    """

    async def insecure_account_signer(
        tx: transaction.Transaction, details: SigningDetails
    ):
        # this will automatically add a witness
        acc.sign_tx(tx, os.environ[env_password_name], details.network)

    return insecure_account_signer


def sign_secure_with_ledger() -> SigningFunction:
    raise NotImplementedError


def sign_on_remote_server() -> SigningFunction:
    async def remote_server_signer(
        tx: transaction.Transaction, details: SigningDetails
    ):
        # call some remote API to get the signature
        # and add a witness with the signature
        raise NotImplementedError

    return remote_server_signer


def sign_insecure_with_multisig_account(
    acc: account.Account, password: str
) -> SigningFunction:
    """
    Sign and add a multi-signature witness.

    This only works for a 1 out of n multi-signature account.

    Args:
        acc: a multi-signature account
        password: the password of the account to sign with
    """

    async def insecure_account_signer(
        tx: transaction.Transaction, details: SigningDetails
    ):
        ctx = account.MultiSigContext()
        # this will automatically add a witness
        acc.sign_multisig_tx(tx, password, ctx, details.network)

    return insecure_account_signer
