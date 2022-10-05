import unittest
from neo3.contracts import abi


class ContractParameterDefinitionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected = {"name": "Main", "type": "String"}

    def test_to_json(self):
        cpd = abi.ContractParameterDefinition("Main", abi.ContractParameterType.STRING)
        self.assertEqual(self.expected, cpd.to_json())

    def test_from_json(self):
        cpd = abi.ContractParameterDefinition.from_json(self.expected)
        self.assertEqual("Main", cpd.name)
        self.assertEqual(abi.ContractParameterType.STRING, cpd.type)

        with self.assertRaises(KeyError) as context:
            json_without_name = {"type": abi.ContractParameterType.ANY}
            abi.ContractParameterDefinition.from_json(json_without_name)
        self.assertIn("name", str(context.exception))

        with self.assertRaises(KeyError) as context:
            json_without_type = {"name": "Main"}
            abi.ContractParameterDefinition.from_json(json_without_type)
        self.assertIn("type", str(context.exception))

    def test_eq(self):
        cpd = abi.ContractParameterDefinition.from_json(self.expected)
        cpd2 = abi.ContractParameterDefinition.from_json(self.expected)
        self.assertFalse(cpd == object())
        self.assertTrue(cpd == cpd2)


class ContractEventDescriptorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected = {
            "name": "MainEvent",
            "parameters": [{"name": "param", "type": "String"}],
        }
        cls.parameters = [
            abi.ContractParameterDefinition("param", abi.ContractParameterType.STRING)
        ]

    def test_to_json(self):
        ced = abi.ContractEventDescriptor("MainEvent", self.parameters)
        self.assertEqual(self.expected, ced.to_json())

    def test_from_json(self):
        ced = abi.ContractEventDescriptor.from_json(self.expected)
        self.assertEqual("MainEvent", ced.name)
        self.assertEqual(self.parameters, ced.parameters)

        with self.assertRaises(KeyError) as context:
            json_without_name = self.expected.copy()
            json_without_name.pop("name")
            abi.ContractEventDescriptor.from_json(json_without_name)
        self.assertIn("name", str(context.exception))

        with self.assertRaises(KeyError) as context:
            json_without_param = self.expected.copy()
            json_without_param.pop("parameters")
            abi.ContractEventDescriptor.from_json(json_without_param)
        self.assertIn("parameters", str(context.exception))

    def test_eq(self):
        ced = abi.ContractEventDescriptor.from_json(self.expected)
        ced2 = abi.ContractEventDescriptor.from_json(self.expected)
        self.assertFalse(ced == object())
        self.assertTrue(ced == ced2)


class ContractMethodDescriptorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = [
            abi.ContractParameterDefinition("param", abi.ContractParameterType.STRING)
        ]
        cls.expected = {
            "name": "MainMethod",
            "offset": 0,
            "parameters": [cls.parameters[0].to_json()],
            "returntype": "Boolean",
            "safe": True,
        }

    def test_to_json(self):
        cmd = abi.ContractMethodDescriptor(
            "MainMethod", 0, self.parameters, abi.ContractParameterType.BOOLEAN, True
        )
        self.assertEqual(self.expected, cmd.to_json())

    def test_from_json(self):
        cmd = abi.ContractMethodDescriptor.from_json(self.expected)
        self.assertEqual("MainMethod", cmd.name)
        self.assertEqual(self.parameters, cmd.parameters)
        self.assertEqual(0, cmd.offset)
        self.assertEqual(abi.ContractParameterType.BOOLEAN, cmd.return_type)
        self.assertTrue(cmd.safe)

        with self.assertRaises(KeyError) as context:
            json_without_return_type = self.expected.copy()
            json_without_return_type.pop("returntype")
            abi.ContractMethodDescriptor.from_json(json_without_return_type)
        self.assertIn("returntype", str(context.exception))

    def test_eq(self):
        cmd = abi.ContractMethodDescriptor.from_json(self.expected)
        cmd2 = abi.ContractMethodDescriptor.from_json(self.expected)
        self.assertFalse(cmd == object())
        self.assertTrue(cmd == cmd2)


class AbiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var methods = new ContractMethodDescriptor[]
        {
            new ContractMethodDescriptor {
                Name = "main_entry",
                Offset = 0,
                Parameters = new ContractParameterDefinition[0],
                ReturnType = ContractParameterType.Integer,
                Safe = true
            }
        };
        var events = new ContractEventDescriptor[]
        {
            new ContractEventDescriptor() { Name = "main_event", Parameters = new ContractParameterDefinition[0]}
        };
        var abi = new ContractAbi()
        {
            Methods = methods,
            Events = events
        };
        Console.WriteLine(abi.ToJson());
        """
        cls.method1 = abi.ContractMethodDescriptor(
            name="main_entry",
            offset=0,
            parameters=[],
            return_type=abi.ContractParameterType.INTEGER,
            safe=True,
        )
        cls.methods = [cls.method1]
        cls.event = abi.ContractEventDescriptor(name="main_event", parameters=[])
        cls.events = [cls.event]
        # captured from C#
        cls.expected_json = {
            "methods": [
                {
                    "name": "main_entry",
                    "parameters": [],
                    "returntype": "Integer",
                    "offset": 0,
                    "safe": True,
                }
            ],
            "events": [{"name": "main_event", "parameters": []}],
        }

    def test_to_json(self):
        abi_ = abi.ContractABI(methods=self.methods, events=self.events)

        self.assertEqual(self.expected_json, abi_.to_json())

    def test_from_json(self):
        # if "test_to_json" passes, then we know we can use our defined class
        # attributes to validate the from_json() results
        abi_ = abi.ContractABI.from_json(self.expected_json)
        self.assertEqual(self.methods, abi_.methods)
        self.assertEqual(self.events, abi_.events)

    def test_eq(self):
        abi_ = abi.ContractABI.from_json(self.expected_json)
        abi2_ = abi.ContractABI.from_json(self.expected_json)
        self.assertFalse(abi_ == object())
        self.assertTrue(abi_ == abi2_)

    def test_get_method(self):
        abi_ = abi.ContractABI.from_json(self.expected_json)
        self.assertIsNone(abi_.get_method("bad_method", 0))
        method = abi_.get_method("main_entry", 0)
        self.assertIsInstance(method, abi.ContractMethodDescriptor)
        self.assertEqual("main_entry", method.name)
