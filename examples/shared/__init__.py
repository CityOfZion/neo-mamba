import pathlib
import asyncio
from neo3.wallet.wallet import Wallet, account
from neo3.core import types
from neo3.api.wrappers import GenericContract, NeoToken, GasToken
from neo3.api.helpers.signing import sign_with_account, sign_with_multisig_account
from neo3.contracts import nef, manifest
from neo3.network.payloads.verification import Signer
from boaconstructor import NeoGoNode

shared_dir = pathlib.Path("shared").resolve(strict=True)

user_wallet = Wallet.from_file(f"{shared_dir}/user-wallet.json", passwords=["123"])
coz_wallet = Wallet.from_file(f"{shared_dir}/coz-wallet.json", passwords=["123"])

coz_token_hash = types.UInt160.from_string("0x41ee5befd936c90f15893261abbd681f20ed0429")
# corresponds to the nep-11 token in the `/nep11-token/` dir and deployed with the `coz` account
nep11_token_hash = types.UInt160.from_string(
    "0x35de2913c480c19a7667da1cc3b2fe3e4c9de761"
)


class ExampleNode(NeoGoNode):
    @property
    def rpc_host(self) -> str:
        return self.facade.rpc_host

    def __enter__(self):
        self.start()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._setup_for_test())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    async def _setup_for_test(self):
        sign_pair = (
            sign_with_multisig_account(self.account_committee),
            Signer(self.account_committee.script_hash),
        )
        neo = NeoToken()
        gas = GasToken()
        coz_account = coz_wallet.account_default
        user_account = user_wallet.account_default
        await self.facade.invoke(
            neo.transfer_friendly(
                self.account_committee.script_hash, coz_account.script_hash, 50000000, 0
            ),
            signers=[sign_pair],
        )
        await self.facade.invoke(
            gas.transfer_friendly(
                self.account_committee.script_hash, coz_account.script_hash, 26000000, 8
            ),
            signers=[sign_pair],
        )
        await self.facade.invoke(
            neo.transfer_friendly(
                self.account_committee.script_hash,
                user_account.script_hash,
                50000000,
                0,
            ),
            signers=[sign_pair],
        )
        await self.facade.invoke(
            gas.transfer_friendly(
                self.account_committee.script_hash,
                user_account.script_hash,
                26000000,
                8,
            ),
            signers=[sign_pair],
        )

        await self._deploy_contract(
            f"{shared_dir}/nep17-token/nep17token.nef", coz_account
        )
        await self._deploy_contract(
            f"{shared_dir}/nep11-token/nep11-token.nef", coz_account
        )

        sign_with_user = (
            sign_with_account(user_account),
            Signer(user_account.script_hash),
        )

        await self.facade.invoke(
            neo.transfer_friendly(
                user_account.script_hash, "NgJ6aLeAi3wJAQ3JbgcWsHGwUT76bvcWMM", 100, 0
            ),
            signers=[sign_with_user],
        )

        sign_with_coz = (
            sign_with_account(coz_account),
            Signer(coz_account.script_hash),
        )
        await self.facade.invoke(
            neo.candidate_register(coz_account.public_key), signers=[sign_with_coz]
        )

    async def _deploy_contract(
        self, nef_path: str, signing_account: account.Account
    ) -> types.UInt160:
        _nef = nef.NEF.from_file(nef_path)
        manifest_path = nef_path.removesuffix(".nef") + ".manifest.json"
        _manifest = manifest.ContractManifest.from_file(manifest_path)

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

        receipt = await self.facade.invoke(
            GenericContract.deploy(_nef, _manifest), signers=[sign_pair]
        )
        return receipt.result
