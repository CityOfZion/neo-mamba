import unittest
import base64
from neo3.network.payloads.transaction import Transaction


class TestPayloadIssues(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_witnesscondition_deserialization_of_tx_in_block_3367174(self):
        # ref: https://app.clickup.com/t/861mv391t
        # should not raise a ValueError
        try:
            raw_tx = base64.b64decode(
                "AE02bF6kD0ABAAAAAMjsAQAAAAAAJGEzAAG2cn7NBD7czWw0a+Oa4gSfyK4ROkABAQMCIBh8ns+7w1/Ttac3ifPmgPd4UTc4uQBeEQMtL9OkMAAAAAwUl6Y6Dqqt8iuCFxjZeiafFLqIGLkMFLZyfs0EPtzNbDRr45riBJ/IrhE6FMAfDAh0cmFuc2ZlcgwU6aNc0l5Z4RDGaj8d715RgxKfBJtBYn1bUgFCDEBEnZaxHmL9kNpS5XlIjdiJwiJWgw0GB9O1D4y0sGRe+rSaO0fZzaN2VfkJnxqR60oVEuf8xiE7cZD28cDifLUXKAwhA5FClptV/FtBBClyJ1f/+HKtWWUXMw6H3NcOZdzd2gcuQVbnsyc="
            )
            tx = Transaction.deserialize_from_bytes(raw_tx)
        except ValueError as e:
            if "Deserialization error - unknown witness condition" in str(e):
                self.assertTrue(False)
