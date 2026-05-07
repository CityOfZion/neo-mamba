import asyncio
import json
import unittest
from pathlib import Path

from neo3.sctesting import SmartContractTestCase

from neo3.compiler import compile_to_nef

HERE = Path(__file__).parent


class TestEvent(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "event.py").read_text(),
            str(HERE / "event"),
        )
        g = cls.node.wallet.account_get_by_label("committee")
        if g is not None:
            cls.genesis = g
        cls.contract_hash, _ = await cls.deploy("./event.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for ext in (".nef", ".manifest.json"):
            (HERE / f"event{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    # ------------------------------------------------------------------
    # Bytecode / emit correctness
    # ------------------------------------------------------------------

    async def test_do_transfer_emits_transfer_event(self) -> None:
        from_ = self.genesis.script_hash
        to = self.genesis.script_hash
        _, notifications = await self.call(
            "do_transfer",
            [from_, to, 100],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        transfer = [n for n in notifications if n.contract == self.contract_hash]
        self.assertEqual(1, len(transfer))
        self.assertEqual("Transfer", transfer[0].event_name)

    async def test_do_transfer_state_contains_correct_values(self) -> None:
        from_ = self.genesis.script_hash
        to = self.genesis.script_hash
        amount = 42
        _, notifications = await self.call(
            "do_transfer",
            [from_, to, amount],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        ev = next(n for n in notifications if n.contract == self.contract_hash)
        state = ev.state.as_list()
        self.assertEqual(3, len(state))
        self.assertEqual(from_, state[0].as_uint160())
        self.assertEqual(to, state[1].as_uint160())
        self.assertEqual(amount, state[2].as_int())

    async def test_do_mint_passes_null_for_optional_from(self) -> None:
        to = self.genesis.script_hash
        _, notifications = await self.call(
            "do_mint",
            [to, 10],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        ev = next(n for n in notifications if n.contract == self.contract_hash)
        self.assertEqual("Transfer", ev.event_name)
        state = ev.state.as_list()
        self.assertIsNone(state[0].as_none())
        self.assertEqual(to, state[1].as_uint160())
        self.assertEqual(10, state[2].as_int())

    async def test_do_ping_emits_ping_event(self) -> None:
        _, notifications = await self.call(
            "do_ping",
            [7],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        ping = [n for n in notifications if n.contract == self.contract_hash]
        self.assertEqual(1, len(ping))
        self.assertEqual("Ping", ping[0].event_name)
        self.assertEqual(7, ping[0].state.as_list()[0].as_int())

    # ------------------------------------------------------------------
    # Manifest
    # ------------------------------------------------------------------

    def test_manifest_contains_transfer_event(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        self.assertIn("Transfer", events)

    def test_manifest_transfer_has_three_parameters(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        params = events["Transfer"]["parameters"]
        self.assertEqual(3, len(params))

    def test_manifest_from_param_is_renamed(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        param_names = [p["name"] for p in events["Transfer"]["parameters"]]
        self.assertIn("from", param_names)
        self.assertNotIn("from_", param_names)

    def test_manifest_optional_uint160_maps_to_hash160(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        params = {p["name"]: p for p in events["Transfer"]["parameters"]}
        self.assertEqual("Hash160", params["from"]["type"])
        self.assertEqual("Hash160", params["to"]["type"])

    def test_manifest_amount_maps_to_integer(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        params = {p["name"]: p for p in events["Transfer"]["parameters"]}
        self.assertEqual("Integer", params["amount"]["type"])

    def test_manifest_contains_ping_event(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        self.assertIn("Ping", events)
        params = events["Ping"]["parameters"]
        self.assertEqual(1, len(params))
        self.assertEqual("value", params[0]["name"])
        self.assertEqual("Integer", params[0]["type"])

    # ------------------------------------------------------------------
    # Extra event — bool, dict, UInt256, ECPoint
    # ------------------------------------------------------------------

    async def test_do_extra_emits_extra_event(self) -> None:
        pubkey = self.node.wallet.account_default.public_key.encode_point(True)
        _, notifications = await self.call(
            "do_extra",
            [True, {"k": 1}, bytes(32), pubkey],
            return_type=None,
            signing_accounts=[self.genesis],
        )
        extra = [n for n in notifications if n.contract == self.contract_hash]
        self.assertEqual(1, len(extra))
        self.assertEqual("Extra", extra[0].event_name)
        self.assertEqual(4, len(extra[0].state.as_list()))

    def test_manifest_extra_bool_maps_to_boolean(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        params = {p["name"]: p for p in events["Extra"]["parameters"]}
        self.assertEqual("Boolean", params["flag"]["type"])

    def test_manifest_extra_dict_maps_to_map(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        params = {p["name"]: p for p in events["Extra"]["parameters"]}
        self.assertEqual("Map", params["data"]["type"])

    def test_manifest_extra_uint256_maps_to_hash256(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        params = {p["name"]: p for p in events["Extra"]["parameters"]}
        self.assertEqual("Hash256", params["txid"]["type"])

    def test_manifest_extra_ecpoint_maps_to_publickey(self) -> None:
        manifest = json.loads((HERE / "event.manifest.json").read_text())
        events = {e["name"]: e for e in manifest["abi"]["events"]}
        params = {p["name"]: p for p in events["Extra"]["parameters"]}
        self.assertEqual("PublicKey", params["pubkey"]["type"])


if __name__ == "__main__":
    unittest.main()
