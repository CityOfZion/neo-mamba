"""
Builder for creating a Transaction. Calculate fees, add signers and sign.
"""
from neo3.api import noderpc
from neo3.api.helpers import signing
from neo3.network.payloads import transaction, verification
from neo3.wallet import account
from typing import Optional


class TxBuilder:
    """
    Transaction builder.
    """

    def __init__(self, client: noderpc.NeoRpcClient, script: Optional[bytes] = None):
        self.client = client
        self.tx = transaction.Transaction(
            version=0,
            nonce=123,
            system_fee=0,
            network_fee=0,
            valid_until_block=0,
            attributes=[],
            signers=[],
            script=b"" if script is None else script,
        )
        self.signing_funcs: list[signing.SigningFunction] = []
        self.network = -1

    async def init(self) -> None:
        """
        Initialize the builder.
        """
        res = await self.client.get_version()
        self.network = res.protocol.network

    async def calculate_system_fee(self) -> None:
        """
        Calculates and set the system fee. Requires at least one signer.
        """
        if len(self.tx.signers) == 0:
            raise ValueError(
                "Need at least one signer (a.k.a the sender who pays for the transaction) or the "
                "fee calculation will be incorrect"
            )
        res = await self.client.invoke_script(self.tx.script, self.tx.signers)
        if res.state != "HALT":
            raise ValueError(f"Failed to get system fee: {res.exception}")
        self.tx.system_fee = res.gas_consumed

    async def set_valid_until_block(self) -> None:
        """
        Set maximum time the transaction is valid in the mempool. Defaults to about 24h for a network with 15s blocktime.
        """
        self.tx.valid_until_block = await self.client.get_block_count() + 1500

    async def calculate_network_fee(self) -> None:
        """
        Calculates and set the system fee. Requires at least one signer.
        """
        if len(self.tx.witnesses) == 0:
            if len(self.tx.signers) == 0:
                raise ValueError("Cannot calculate network fee without signers")
            # adding a witness(es) so we can calculate the network fee
            for _ in range(len(self.tx.signers)):
                self.tx.witnesses.append(TxBuilder._dummy_signing_witness())
            self.tx.network_fee = await self.client.calculate_network_fee(self.tx)
            # removing it here as it will be replaced by a proper one once we're signing
            self.tx.witnesses = []
        else:
            if len(self.tx.signers) == 0:
                raise ValueError("Cannot calculate network fee without signers")
            self.tx.network_fee = await self.client.calculate_network_fee(self.tx)

    @staticmethod
    def _dummy_signing_witness() -> verification.Witness:
        """single signature account witness"""
        acc = account.Account.create_new("abc")
        if acc.contract is None:
            raise Exception(
                "Unreachable"
            )  # we know this can't happen, but mypy doesn't
        return verification.Witness(
            invocation_script=b"", verification_script=acc.contract.script
        )

    async def build_and_sign(self) -> transaction.Transaction:
        """
        Sign the transaction with all signers and return the finalized result.
        """
        len_signers = len(self.tx.signers)
        if len_signers == 0:
            raise ValueError("Cannot sign transaction without signers")

        if self.network == -1:
            raise ValueError(
                "Network value not valid (-1). Call init() to automatically sync it from the network or set the `network` attribute"
            )

        for f, s in zip(self.signing_funcs, self.tx.signers):
            await f(self.tx, signing.SigningDetails(self.network))
        return self.tx

    def build_unsigned(self) -> transaction.Transaction:
        """
        Return the unsigned transaction. For example for use in an offline signing scenario.
        """
        return self.tx

    def add_signer(
        self, func: signing.SigningFunction, signer: verification.Signer
    ) -> None:
        """
        Add a Signer with scopes to the transaction and its signing function.

        Args:
            func: one of neo3.api.helpers.signing.
            signer: a Signer determining the validity of the signature.

        Returns:

        """
        for s in self.tx.signers:
            if signer.account == s.account:
                raise ValueError(
                    f"Signer with same account ({signer.account} already exists."
                )
        self.tx.signers.append(signer)
        self.signing_funcs.append(func)
