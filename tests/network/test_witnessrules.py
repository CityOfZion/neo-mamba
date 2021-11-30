import unittest
from unittest import mock
from neo3.network import payloads
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
        cls.rule = payloads.WitnessRule(payloads.WitnessRuleAction.ALLOW, payloads.ConditionBool(True))

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
        deserialized_rule = payloads.WitnessRule.deserialize_from_bytes(self.rule.to_array())
        self.assertEqual(self.rule.action, deserialized_rule.action)
        self.assertEqual(self.rule.condition, deserialized_rule.condition)

    def test_to_json(self):
        expected = {"action":"Allow","condition":{"type":"Boolean","expression":True}}
        self.assertDictEqual(expected, self.rule.to_json())

    def test_from_json(self):
        with self.assertRaises(NotImplementedError):
            payloads.WitnessRule.from_json({})


class ConditionsTestCase(unittest.TestCase):
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
        expected_json = {"type":"And","expressions":[{"type":"Boolean","expression":True},{"type":"Boolean","expression":False}]}

        c = payloads.ConditionAnd([
            payloads.ConditionBool(True),
            payloads.ConditionBool(False)
        ])
        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())

        self.assertFalse(c.match(None))

        deserialized_c = payloads.ConditionAnd.deserialize_from_bytes(c.to_array())
        self.assertEqual(c.expressions, deserialized_c.expressions)

        with self.assertRaises(ValueError) as context:
            c2 = payloads.ConditionAnd([])
            payloads.ConditionAnd.deserialize_from_bytes(c2.to_array())
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
        expected_json = {"type":"Boolean","expression":True}
        c = payloads.ConditionBool(True)
        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())

        self.assertTrue(c.match(None))
        c2 = payloads.ConditionBool(False)
        self.assertFalse(c2.match(None))

        deserialized_c = payloads.ConditionBool.deserialize_from_bytes(c.to_array())
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
        expected_json = {"type":"Not","expression":{"type":"Boolean","expression":True}}
        c = payloads.ConditionNot(payloads.ConditionBool(True))
        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())

        self.assertFalse(c.match(None))

        deserialized_c = payloads.ConditionNot.deserialize_from_bytes(c.to_array())
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
        expected_json = {"type":"Or","expressions":[{"type":"Boolean","expression":True},{"type":"Boolean","expression":False}]}

        c = payloads.ConditionOr([
            payloads.ConditionBool(True),
            payloads.ConditionBool(False)
        ])
        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())

        self.assertTrue(c.match(None))

        deserialized_c = payloads.ConditionOr.deserialize_from_bytes(c.to_array())
        self.assertEqual(c.expressions, deserialized_c.expressions)

        with self.assertRaises(ValueError) as context:
            c2 = payloads.ConditionOr([])
            payloads.ConditionOr.deserialize_from_bytes(c2.to_array())
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
        expected_json = {"type":"CalledByContract","hash":"0x0000000000000000000000000000000000000000"}

        c = payloads.ConditionCalledByContract(types.UInt160.zero())

        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())

        engine = mock.Mock()
        # for some weird reason we must set the property on the type
        type(engine).calling_scripthash = mock.PropertyMock(spec=types.UInt160, return_value=types.UInt160.zero())
        self.assertTrue(c.match(engine))

        deserialized_c = payloads.ConditionCalledByContract.deserialize_from_bytes(c.to_array())
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
        expected_json = {"type":"CalledByEntry"}

        c = payloads.ConditionCalledByEntry()

        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())

        engine = mock.MagicMock()
        # the actual value doesn't have to be a UInt160 it's about the comparison
        type(engine).calling_scripthash = mock.PropertyMock(spec=types.UInt160, return_value=True)
        type(engine).entry_scripthash = mock.PropertyMock(spec=types.UInt160, return_value=True)
        engine.current_context.calling_scripthash_bytes.__len__.return_value = 1

        self.assertTrue(c.match(engine))
        type(engine).entry_scripthash = mock.PropertyMock(spec=types.UInt160, return_value=False)
        self.assertFalse(c.match(engine))

        deserialized_c = payloads.ConditionCalledByEntry.deserialize_from_bytes(c.to_array())
        self.assertEqual(c, deserialized_c)

    def test_called_by_group(self):
        expected_len = 34
        expected_data = bytes.fromhex("2902158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765")
        expected_json = {"type":"CalledByGroup","group":"02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765"}
        point_data = expected_data[1:]

        group = cryptography.ECPoint.deserialize_from_bytes(point_data)
        c = payloads.ConditionCalledByGroup(group)

        self.assertEqual(expected_len, len(c))
        self.assertEqual(expected_data, c.to_array())
        self.assertEqual(expected_json, c.to_json())

        deserialized_c = payloads.ConditionCalledByGroup.deserialize_from_bytes(c.to_array())
        self.assertEqual(c, deserialized_c)
