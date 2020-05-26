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
                        "parameters": [cls.parameters[0].to_json()],
                        "returnType": "Boolean"}

    def test_default_entry_point(self):
        cmd = contracts.ContractMethodDescriptor.default_entrypoint()
        self.assertEqual("Main", cmd.name)
        self.assertEqual(2, len(cmd.parameters))
        param1_from_json = contracts.ContractParameterDefinition.from_json({'name': 'operation', 'type': 'String'})
        self.assertEqual(param1_from_json, cmd.parameters[0])
        param2_from_json = contracts.ContractParameterDefinition.from_json({'name': 'args', 'type': 'Array'})
        self.assertEqual(param2_from_json, cmd.parameters[1])
        self.assertEqual(contracts.ContractParameterType.ANY, cmd.return_type)

    def test_to_json(self):
        cmd = contracts.ContractMethodDescriptor("MainMethod", self.parameters, contracts.ContractParameterType.BOOLEAN)
        self.assertEqual(self.expected, cmd.to_json())

    def test_from_json(self):
        cmd = contracts.ContractMethodDescriptor.from_json(self.expected)
        self.assertEqual("MainMethod", cmd.name)
        self.assertEqual(self.parameters, cmd.parameters)
        self.assertEqual(contracts.ContractParameterType.BOOLEAN, cmd.return_type)

        with self.assertRaises(KeyError) as context:
            json_without_return_type = self.expected.copy()
            json_without_return_type.pop('returnType')
            contracts.ContractMethodDescriptor.from_json(json_without_return_type)
        self.assertIn('returnType', str(context.exception))

    def test_eq(self):
        cmd = contracts.ContractMethodDescriptor.from_json(self.expected)
        cmd2 = contracts.ContractMethodDescriptor.from_json(self.expected)
        self.assertFalse(cmd == object())
        self.assertTrue(cmd == cmd2)


class AbiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var entry_point = ContractMethodDescriptor.DefaultEntryPoint;
        var methods = new ContractMethodDescriptor[]
        {
            new ContractMethodDescriptor {Name = "main_entry",
                Parameters = new ContractParameterDefinition[0],
                ReturnType = ContractParameterType.Integer}
        };
        var events = new ContractEventDescriptor[]
        {
            new ContractEventDescriptor() { Name = "main_event", Parameters = new ContractParameterDefinition[0]}
        };
        var abi = new ContractAbi()
        {
            Hash = UInt160.Zero,
            EntryPoint = entry_point,
            Methods = methods,
            Events = events
        };
        Console.WriteLine(abi.ToJson());
        """
        cls.entry_point = contracts.ContractMethodDescriptor.default_entrypoint()
        cls.method1 = contracts.ContractMethodDescriptor(
            name="main_entry",
            parameters=[],
            return_type=contracts.ContractParameterType.INTEGER
        )
        cls.methods = [cls.method1]
        cls.event = contracts.ContractEventDescriptor(
            name="main_event",
            parameters=[]
        )
        cls.events = [cls.event]
        # captured from C#
        cls.expected_json = {"hash": "0x0000000000000000000000000000000000000000","entryPoint":{"name":"Main","parameters":[{"name":"operation","type":"String"},{"name":"args","type":"Array"}],"returnType":"Any"},"methods":[{"name":"main_entry","parameters":[],"returnType":"Integer"}],"events":[{"name":"main_event","parameters":[]}]}

    def test_to_json(self):
        abi = contracts.ContractABI(
            contract_hash=types.UInt160.zero(),
            entry_point=self.entry_point,
            methods=self.methods,
            events=self.events
        )

        self.assertEqual(self.expected_json, abi.to_json())

    def test_from_json(self):
        # if "test_to_json" passes, then we know we can use our defined class
        # attributes to validate the from_json() results
        abi = contracts.ContractABI.from_json(self.expected_json)
        self.assertEqual(self.entry_point, abi.entry_point)

    def test_eq(self):
        abi = contracts.ContractABI.from_json(self.expected_json)
        abi2 = contracts.ContractABI.from_json(self.expected_json)
        self.assertFalse(abi == object())
        self.assertTrue(abi == abi2)
