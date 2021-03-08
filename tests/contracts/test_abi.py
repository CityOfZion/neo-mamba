import unittest
from neo3 import contracts
from neo3.core import types


class ContractParameterDefinitionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected = {'name': "Main", 'type': 'String'}

    def test_to_json(self):
        cpd = contracts.ContractParameterDefinition("Main", contracts.ContractParameterType.STRING)
        self.assertEqual(self.expected, cpd.to_json())

    def test_from_json(self):
        cpd = contracts.ContractParameterDefinition.from_json(self.expected)
        self.assertEqual("Main", cpd.name)
        self.assertEqual(contracts.ContractParameterType.STRING, cpd.type)

        with self.assertRaises(KeyError) as context:
            json_without_name = {'type': contracts.ContractParameterType.ANY}
            contracts.ContractParameterDefinition.from_json(json_without_name)
        self.assertIn('name', str(context.exception))

        with self.assertRaises(KeyError) as context:
            json_without_type = {'name': "Main"}
            contracts.ContractParameterDefinition.from_json(json_without_type)
        self.assertIn('type', str(context.exception))

    def test_eq(self):
        cpd = contracts.ContractParameterDefinition.from_json(self.expected)
        cpd2 = contracts.ContractParameterDefinition.from_json(self.expected)
        self.assertFalse(cpd == object())
        self.assertTrue(cpd == cpd2)


class ContractEventDescriptorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected = {"name": "MainEvent", "parameters": [{"name": "param", "type": "String"}]}
        cls.parameters = [contracts.ContractParameterDefinition("param", contracts.ContractParameterType.STRING)]

    def test_to_json(self):
        ced = contracts.ContractEventDescriptor("MainEvent", self.parameters)
        self.assertEqual(self.expected, ced.to_json())

    def test_from_json(self):
        ced = contracts.ContractEventDescriptor.from_json(self.expected)
        self.assertEqual("MainEvent", ced.name)
        self.assertEqual(self.parameters, ced.parameters)

        with self.assertRaises(KeyError) as context:
            json_without_name = self.expected.copy()
            json_without_name.pop('name')
            contracts.ContractEventDescriptor.from_json(json_without_name)
        self.assertIn('name', str(context.exception))

        with self.assertRaises(KeyError) as context:
            json_without_param = self.expected.copy()
            json_without_param.pop('parameters')
            contracts.ContractEventDescriptor.from_json(json_without_param)
        self.assertIn('parameters', str(context.exception))

    def test_eq(self):
        ced = contracts.ContractEventDescriptor.from_json(self.expected)
        ced2 = contracts.ContractEventDescriptor.from_json(self.expected)
        self.assertFalse(ced == object())
        self.assertTrue(ced == ced2)


class ContractMethodDescriptorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parameters = [contracts.ContractParameterDefinition("param", contracts.ContractParameterType.STRING)]
        cls.expected = {"name": "MainMethod",
                        "offset": 0,
                        "parameters": [cls.parameters[0].to_json()],
                        "returntype": "Boolean",
                        "safe": True}

    def test_to_json(self):
        cmd = contracts.ContractMethodDescriptor("MainMethod",
                                                 0,
                                                 self.parameters, contracts.ContractParameterType.BOOLEAN,
                                                 True
                                                 )
        self.assertEqual(self.expected, cmd.to_json())

    def test_from_json(self):
        cmd = contracts.ContractMethodDescriptor.from_json(self.expected)
        self.assertEqual("MainMethod", cmd.name)
        self.assertEqual(self.parameters, cmd.parameters)
        self.assertEqual(0, cmd.offset)
        self.assertEqual(contracts.ContractParameterType.BOOLEAN, cmd.return_type)
        self.assertTrue(cmd.safe)

        with self.assertRaises(KeyError) as context:
            json_without_return_type = self.expected.copy()
            json_without_return_type.pop('returntype')
            contracts.ContractMethodDescriptor.from_json(json_without_return_type)
        self.assertIn('returntype', str(context.exception))

    def test_eq(self):
        cmd = contracts.ContractMethodDescriptor.from_json(self.expected)
        cmd2 = contracts.ContractMethodDescriptor.from_json(self.expected)
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
        cls.method1 = contracts.ContractMethodDescriptor(
            name="main_entry",
            offset=0,
            parameters=[],
            return_type=contracts.ContractParameterType.INTEGER,
            safe=True
        )
        cls.methods = [cls.method1]
        cls.event = contracts.ContractEventDescriptor(
            name="main_event",
            parameters=[]
        )
        cls.events = [cls.event]
        # captured from C#
        cls.expected_json = {"methods":[{"name":"main_entry","parameters":[],"returntype":"Integer","offset":0,"safe":True}],"events":[{"name":"main_event","parameters":[]}]}

    def test_to_json(self):
        abi = contracts.ContractABI(
            methods=self.methods,
            events=self.events
        )

        self.assertEqual(self.expected_json, abi.to_json())

    def test_from_json(self):
        # if "test_to_json" passes, then we know we can use our defined class
        # attributes to validate the from_json() results
        abi = contracts.ContractABI.from_json(self.expected_json)
        self.assertEqual(self.methods, abi.methods)
        self.assertEqual(self.events, abi.events)

    def test_eq(self):
        abi = contracts.ContractABI.from_json(self.expected_json)
        abi2 = contracts.ContractABI.from_json(self.expected_json)
        self.assertFalse(abi == object())
        self.assertTrue(abi == abi2)

    def test_get_method(self):
        abi = contracts.ContractABI.from_json(self.expected_json)
        self.assertIsNone(abi.get_method("bad_method", 0))
        method = abi.get_method("main_entry", 0)
        self.assertIsInstance(method, contracts.ContractMethodDescriptor)
        self.assertEqual("main_entry", method.name)
