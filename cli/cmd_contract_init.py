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


def scaffold_init(args: argparse.Namespace) -> int:
    name = args.name
    contract_path = Path(f"{name}.py")
    test_path = Path(f"test_{name}.py")

    contract_path.write_text(CONTRACT_TEMPLATE)
    print(f"Created {contract_path}")

    test_path.write_text(TEST_TEMPLATE.format(name=name))
    print(f"Created {test_path}")

    return 0
