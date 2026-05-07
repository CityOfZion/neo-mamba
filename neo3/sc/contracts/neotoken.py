from typing import Any

from neo3.sc.compiletime import display_name, contract
from neo3.sc.types import ECPoint, UInt160, NeoAccountState
from neo3.sc.utils.iterator import Iterator


@contract("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")
class NeoToken:
    """
    Represents the NEO native contract.

    See:
        https://developers.neo.org/docs/n3/reference/scapi/framework/native/Neo
        for more details about this contract.
    """

    hash: UInt160

    @staticmethod
    def symbol() -> str:
        """
        Get the symbol of NEO.

        Example:
            >>> NeoToken.symbol()
            'NEO'

        Returns:
            str: The NEO symbol.
        """
        pass

    @staticmethod
    def decimals() -> int:
        """
        Gets the number of decimals used by NEO.

        Example:
            >>> NeoToken.decimals()
            0

        Returns:
            int: The number of decimals.
        """
        pass

    @staticmethod
    @display_name("totalSupply")
    def total_supply() -> int:
        """
        Get the total token supply deployed in the system.

        Example:
            >>> NeoToken.total_supply()
            100000000

        Returns:
            int: The total token supply.
        """
        pass

    @staticmethod
    @display_name("balanceOf")
    def balance_of(account: UInt160) -> int:
        """
        Get the current balance of an address.

        Example:
            >>> NeoToken.balance_of(UInt160(bytes(20)))
            0

        Args:
            account (UInt160): The account address.

        Returns:
            int: The account balance.
        """
        pass

    @staticmethod
    def transfer(
        from_address: UInt160, to_address: UInt160, amount: int, data: Any = None
    ) -> bool:
        """
        Transfer the amount of NEO from one account to another.

        If successful, this method fires the `Transfer` event and returns True,
        even if the amount is 0 or the sender and receiver are the same.

        Args:
            from_address (UInt160): The sender's address.
            to_address (UInt160): The receiver's address.
            amount (int): The amount of NEO to transfer.
            data (Any, optional): Additional data for the `onNEP17Payment` method.

        Returns:
            bool: True if the transfer was successful, False otherwise.

        Raises:
            Exception: If address lengths are invalid or amount is negative.
        """
        pass

    @staticmethod
    @display_name("getGasPerBlock")
    def get_gas_per_block() -> int:
        """
        Get the amount of GAS generated per block.

        Example:
            >>> NeoToken.get_gas_per_block()
            500000000

        Returns:
            int: The GAS generated per block.
        """
        pass

    @staticmethod
    @display_name("unclaimedGas")
    def unclaimed_gas(account: UInt160, end: int) -> int:
        """
        Get the amount of unclaimed GAS for an account.

        Args:
            account (UInt160): The account to check.
            end (int): The block index used in the calculation.

        Returns:
            int: The amount of unclaimed GAS.
        """
        pass

    @staticmethod
    @display_name("registerCandidate")
    def register_candidate(pubkey: ECPoint) -> bool:
        """
        Register an account as a candidate.

        Args:
            pubkey (ECPoint): The public key of the account.

        Returns:
            bool: True if registration succeeded, False otherwise.
        """
        pass

    @staticmethod
    @display_name("unregisterCandidate")
    def unregister_candidate(pubkey: ECPoint) -> bool:
        """
        Unregister an account as a candidate.

        Args:
            pubkey (ECPoint): The public key of the account.

        Returns:
            bool: True if unregistration succeeded, False otherwise.
        """
        pass

    @staticmethod
    def vote(account: UInt160, vote_to: ECPoint) -> bool:
        """
        Vote for a candidate.

        Args:
            account (UInt160): The voting account.
            vote_to (ECPoint): The candidate's public key.

        Returns:
            bool: True if the vote succeeded, False otherwise.
        """
        pass

    @staticmethod
    @display_name("getAllCandidates")
    def get_all_candidates() -> Iterator:
        """
        Get all registered candidates.

        Returns:
            Iterator: An iterator of candidates.
        """
        pass

    # @staticmethod
    # def un_vote( account: UInt160) -> bool:
    #     """
    #     Remove a vote from a candidate.
    #
    #     Equivalent to calling vote(account, None).
    #
    #     Args:
    #         account (UInt160): The account removing its vote.
    #
    #     Returns:
    #         bool: True if the operation succeeded, False otherwise.
    #     """
    #     pass

    @staticmethod
    @display_name("getCandidates")
    def get_candidates() -> list[tuple[ECPoint, int]]:
        """
        Get all registered candidates and their vote counts.

        Returns:
            list[tuple[ECPoint, int]]: A list of (public key, votes).
        """
        pass

    @staticmethod
    @display_name("getCandidateVote")
    def get_candidate_vote(pubkey: ECPoint) -> int:
        """
        Get the vote count for a specific candidate.

        Args:
            pubkey (ECPoint): The candidate's public key.

        Returns:
            int: The number of votes, or -1 if not found.
        """
        pass

    @staticmethod
    @display_name("getCommittee")
    def get_committee() -> list[ECPoint]:
        """
        Get the list of committee members.

        Returns:
            list[ECPoint]: The committee members' public keys.
        """
        pass

    @staticmethod
    @display_name("getCommitteeAddress")
    def get_committee_address() -> UInt160:
        """
        Get the committee address.

        Returns:
            UInt160: The committee address.
        """
        pass

    @staticmethod
    @display_name("getRegisterPrice")
    def get_register_price() -> int:
        """
        Get the fee required to register as a candidate.

        Returns:
            int: The registration fee.
        """
        pass

    @staticmethod
    @display_name("getNextBlockValidators")
    def get_next_block_validators() -> list[ECPoint]:
        """
        Gets the validators for the next block.

        Returns:
            list[ECPoint]: The validators' public keys.
        """
        pass

    @staticmethod
    @display_name("getAccountState")
    def get_account_state(account: UInt160) -> NeoAccountState:
        """
        Get the latest state of an account.

        Args:
            account (UInt160): The account to query.

        Returns:
            NeoAccountState: The account state.
        """
        pass
