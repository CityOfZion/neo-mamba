import asyncio
import unittest
from pathlib import Path

from neo3.api import StackItem, noderpc
from neo3.compiler import compile_to_nef
from neo3.sctesting import SmartContractTestCase

HERE = Path(__file__).parent


class TestGetNotifications(SmartContractTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asyncio.run(cls.asyncSetupClass())

    @classmethod
    async def asyncSetupClass(cls) -> None:
        compile_to_nef(
            (HERE / "helper_notifier.py").read_text(),
            str(HERE / "helper_notifier"),
        )
        compile_to_nef(
            (HERE / "get_notifications.py").read_text(),
            str(HERE / "get_notifications"),
        )
        cls.genesis = cls.node.wallet.account_get_by_label("committee")
        cls.helper_hash, _ = await cls.deploy("./helper_notifier.nef", cls.genesis)
        cls.contract_hash, _ = await cls.deploy("./get_notifications.nef", cls.genesis)

    @classmethod
    def tearDownClass(cls) -> None:
        for name in ("helper_notifier", "get_notifications"):
            for ext in (".nef", ".manifest.json"):
                (HERE / f"{name}{ext}").unlink(missing_ok=True)
        super().tearDownClass()

    async def test_get_all_notifications_returns_both(self) -> None:
        result, notifs = await self.call(
            "get_all",
            [self.helper_hash],
            return_type=list,
            signing_accounts=[self.genesis],
        )
        contract_notifs = unwrap_as_notifications(result)
        self.assertEqual(2, len(contract_notifs))
        self.assertEqual(notifs, contract_notifs)

    async def test_get_filtered_notifications_returns_own_only(self) -> None:
        result, notifs = await self.call(
            "get_filtered",
            [self.helper_hash],
            return_type=list,
            signing_accounts=[self.genesis],
        )
        contract_notifs = unwrap_as_notifications(result)
        self.assertEqual(1, len(contract_notifs))
        self.assertEqual(notifs[0], contract_notifs[0])


def unwrap_as_notifications(arr: list[StackItem]) -> list[noderpc.Notification]:
    notifs = []
    for si in arr:
        elements = si.as_list()
        assert len(elements) == 3, "Invalid notification data"
        notifs.append(
            noderpc.Notification(
                elements[0].as_uint160(), elements[1].as_str(), elements[2]
            )
        )

    return notifs


if __name__ == "__main__":
    unittest.main()
