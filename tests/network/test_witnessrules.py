import unittest
from neo3.network.payloads import verification
from neo3.core import types, cryptography


class WitnessRuleTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var w = new WitnessRule
        {
            Action = WitnessRuleAction.Allow,
            Condition = new BooleanCondition{ Expression = true }
        };

        Console.WriteLine(((ISerializable)w).Size);
        Console.WriteLine(w.ToArray().ToHexString());
        Console.WriteLine(w.ToJson());
        """
        cls.rule = verification.WitnessRule(
            verification.WitnessRuleAction.ALLOW, verification.ConditionBool(True)
        )

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 3
        self.assertEqual(expected_len, len(self.rule))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = bytes.fromhex("010001")
        self.assertEqual(expected_data, self.rule.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization
        # against
        deserialized_rule = verification.WitnessRule.deserialize_from_bytes(
            self.rule.to_array()
        )
        self.assertEqual(self.rule.action, deserialized_rule.action)
        self.assertEqual(self.rule.condition, deserialized_rule.condition)

    def test_to_json(self):
        expected = {
            "action": "Allow",
            "condition": {"type": "Boolean", "expression": True},
        }
        self.assertDictEqual(expected, self.rule.to_json())


class ConditionsTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_and(self):
        """
        var c = new AndCondition
        {
            Expressions = new WitnessCondition[]
            {
                new BooleanCondition { Expression = true },
                new BooleanCondition { Expression = false }
            }
        };
        Console.WriteLine(((ISerializable)c).Size);
        Console.WriteLine(c.ToArray().ToHexString());
        Console.WriteLine(c.ToJson());
        Console.WriteLine(c.Match(null));
        """
        expected_len = 6
        expected_data = bytes.fromhex("020200010000")
        expected_json = {
            "type": "And",
            "expressions": [
                {"type": "Boolean", "expression": True},
                {"type": "Boolean", "expression": False},
            ],
        }

        c = verification.ConditionAnd(
            [verification.ConditionBool(True), verification.ConditionBool(False)]
        )
        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())
        self.assertEqual(c, verification.ConditionAnd.from_json(c.to_json()))

        deserialized_c = verification.ConditionAnd.deserialize_from_bytes(c.to_array())
        self.assertEqual(c.expressions, deserialized_c.expressions)

        with self.assertRaises(ValueError) as context:
            c2 = verification.ConditionAnd([])
            verification.ConditionAnd.deserialize_from_bytes(c2.to_array())
        self.assertEqual("Cannot have 0 expressions", str(context.exception))

    def test_bool(self):
        """
        var c = new BooleanCondition { Expression = true };
        Console.WriteLine(((ISerializable)c).Size);
        Console.WriteLine(c.ToArray().ToHexString());
        Console.WriteLine(c.ToJson());
        """
        expected_len = 2
        expected_data = bytes.fromhex("0001")
        expected_json = {"type": "Boolean", "expression": True}
        c = verification.ConditionBool(True)
        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())
        self.assertEqual(c, verification.ConditionBool.from_json(c.to_json()))

        deserialized_c = verification.ConditionBool.deserialize_from_bytes(c.to_array())
        self.assertEqual(c, deserialized_c)

    def test_not(self):
        """
        var c = new NotCondition { Expression = new BooleanCondition { Expression = true } };
        Console.WriteLine(((ISerializable)c).Size);
        Console.WriteLine(c.ToArray().ToHexString());
        Console.WriteLine(c.ToJson());
        Console.WriteLine(c.Match(null));
        """
        expected_len = 3
        expected_data = bytes.fromhex("010001")
        expected_json = {
            "type": "Not",
            "expression": {"type": "Boolean", "expression": True},
        }
        c = verification.ConditionNot(verification.ConditionBool(True))
        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())
        self.assertEqual(c, verification.ConditionNot.from_json(c.to_json()))

        deserialized_c = verification.ConditionNot.deserialize_from_bytes(c.to_array())
        self.assertEqual(c, deserialized_c)

    def test_or(self):
        """
        var c = new OrCondition
        {
            Expressions = new WitnessCondition[]
            {
                new BooleanCondition { Expression = true },
                new BooleanCondition { Expression = false }
            }
        };
        Console.WriteLine(((ISerializable)c).Size);
        Console.WriteLine(c.ToArray().ToHexString());
        Console.WriteLine(c.ToJson());
        Console.WriteLine(c.Match(null));
        """
        expected_len = 6
        expected_data = bytes.fromhex("030200010000")
        expected_json = {
            "type": "Or",
            "expressions": [
                {"type": "Boolean", "expression": True},
                {"type": "Boolean", "expression": False},
            ],
        }

        c = verification.ConditionOr(
            [verification.ConditionBool(True), verification.ConditionBool(False)]
        )
        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())
        self.assertEqual(c, verification.ConditionOr.from_json(c.to_json()))

        deserialized_c = verification.ConditionOr.deserialize_from_bytes(c.to_array())
        self.assertEqual(c.expressions, deserialized_c.expressions)

        with self.assertRaises(ValueError) as context:
            c2 = verification.ConditionOr([])
            verification.ConditionOr.deserialize_from_bytes(c2.to_array())
        self.assertEqual("Cannot have 0 expressions", str(context.exception))

    def test_by_contract(self):
        """
        var c = new CalledByContractCondition
        {
            Hash = UInt160.Zero
        };
        Console.WriteLine(((ISerializable)c).Size);
        Console.WriteLine(c.ToArray().ToHexString());
        Console.WriteLine(c.ToJson());
        """
        expected_len = 21
        expected_data = bytes.fromhex("280000000000000000000000000000000000000000")
        expected_json = {
            "type": "CalledByContract",
            "hash": "0x0000000000000000000000000000000000000000",
        }

        c = verification.ConditionCalledByContract(types.UInt160.zero())

        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())
        self.assertEqual(
            c, verification.ConditionCalledByContract.from_json(c.to_json())
        )

        deserialized_c = verification.ConditionCalledByContract.deserialize_from_bytes(
            c.to_array()
        )
        self.assertEqual(c.hash_, deserialized_c.hash_)

    def test_by_entry(self):
        """
        var c = new CalledByEntryCondition();
        Console.WriteLine(((ISerializable)c).Size);
        Console.WriteLine(c.ToArray().ToHexString());
        Console.WriteLine(c.ToJson());
        """
        expected_len = 1
        expected_data = bytes.fromhex("20")
        expected_json = {"type": "CalledByEntry"}

        c = verification.ConditionCalledByEntry()

        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())
        self.assertEqual(c, verification.ConditionCalledByEntry.from_json(c.to_json()))

        deserialized_c = verification.ConditionCalledByEntry.deserialize_from_bytes(
            c.to_array()
        )
        self.assertEqual(c, deserialized_c)

    def test_called_by_group(self):
        """
        var c = new CalledByGroupCondition()
        {
            Group = ECPoint.Parse("02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765", ECCurve.Secp256r1)
        };
        Console.WriteLine(((ISerializable)c).Size);
        Console.WriteLine(c.ToArray().ToHexString());
        Console.WriteLine(c.ToJson());
        """
        expected_len = 34
        expected_data = bytes.fromhex(
            "2902158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765"
        )
        expected_json = {
            "type": "CalledByGroup",
            "group": "02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765",
        }
        point_data = expected_data[1:]

        group = cryptography.ECPoint.deserialize_from_bytes(point_data)
        c = verification.ConditionCalledByGroup(group)

        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())
        self.assertEqual(c, verification.ConditionCalledByGroup.from_json(c.to_json()))

        deserialized_c = verification.ConditionCalledByGroup.deserialize_from_bytes(
            c.to_array()
        )
        self.assertEqual(c, deserialized_c)

    def test_various(self):
        with self.assertRaises(ValueError) as context:
            verification.WitnessCondition.from_json({"type": "fake_type"})
        self.assertEqual(
            "fake_type cannot be converted to WitnessConditionType",
            str(context.exception),
        )
