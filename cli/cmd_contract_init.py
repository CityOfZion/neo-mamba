import argparse
from pathlib import Path

CONTRACT_TEMPLATE = """\
from typing import Any
from neo3.sc.compiletime import public
from neo3.sc import storage


@public
def _deploy(data: Any, update: bool) ->  None:
    storage.put(b'key', bytes("Hello World", encoding="utf-8"))

@public
def set_message(msg: str) -> None:
    storage.put(b'key', bytes(msg, encoding="utf-8"))

@public
def get_message() -> str:
    v = storage.get(b'key')
    if v is None:
        return ""
    return str(v)
"""

TEST_TEMPLATE = """\
import asyncio
from pathlib import Path
from neo3.sctesting import SmartContractTestCase
from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent
source = HERE / "{name}.py"

class TestAbort(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(source)
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.contract_hash, _ = await cls.deploy(str(HERE / "{name}.nef"), cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"{name}{{ext}}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_get_message(self) -> None:
        result, _ = await self.call("get_message", return_type=str)
        self.assertEqual("Hello World", result)

    async def test_set_message(self) -> None:
        new_message = "Hello You"
        await self.call("set_message", [new_message], return_type=None, signing_accounts=[self.genesis])
        result, _ = await self.call("get_message", [], return_type=str)
        self.assertEqual(new_message, result)
"""

CPM_TEMPLATE = """\
# settings that apply to all contracts unless explicitly overridden in the contracts section
defaults:
  contract-source-network: mainnet
  contract-destination: neo-express
  contract-generate-sdk: false
  contract-download: true
  # settings related to SDK generation for on chain contracts
  on-chain:
    # both languages and destinations take the same key values: csharp, go, java or python
    languages:
    - python
  off-chain:
    languages:
    - python

# which contracts to download with what options
#contracts:
    # Label can be anything that allows you to identify which contract this is 
    # (assuming you can't remember all contract hashes by heart)
  #- label: Props - puppet
    # the unique identifier used to download the contract
    #script-hash: '0x76a8f8a7a901b29a33013b469949f4b08db15756'
    # overrides the default for this contract specifically
    #generate-sdk: true

# which tools are available for contract downloading and/or generating SDKs
tools:
  neo-express:
    canGenerateSDK: false
    canDownloadContract: true
    executable-path: null
    config-path: default.neo-express
# list of networks with corresponding RPC server addresses to the networks used for source information downloading
networks:
  - label: mainnet
    hosts:
      - 'https://mainnet1.neo.coz.io:443'
      - 'http://seed1.neo.org:10332'
  - label: testnet
    hosts:
      - 'https://testnet1.neo.coz.io:443'
  - label: priv
    hosts:
      - 'http://127.0.0.1:10332'
"""


def scaffold_init(args: argparse.Namespace) -> int:
    name = args.name
    contract_path = Path(f"{name}.py")
    test_path = Path(f"test_{name}.py")
    cpm_path = Path("cpm.yaml")

    contract_path.write_text(CONTRACT_TEMPLATE)
    print(f"Created {contract_path}")

    test_path.write_text(TEST_TEMPLATE.format(name=name))
    print(f"Created {test_path}")

    if args.gen_cpm:
        cpm_path.write_text(CPM_TEMPLATE)
        print("Created cpm.yaml")

    return 0
