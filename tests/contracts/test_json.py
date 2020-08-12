import json
import unittest
from neo3 import contracts, vm


class JSONParsingTestCase(unittest.TestCase):
    def _parse_and_dump(self, input):
        return contracts.NEOJson.dumps(contracts.NEOJson.loads(input))

    def test_wrong_json(self):
        data = [
            "[    ]XXXXXXX",
            "{   }XXXXXXX",
            "[,,,,]",
            "false,X",
            "false@@@",
            "{""length"":99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999}"  # noqa
        ]

        for entry in data:
            with self.assertRaises(json.decoder.JSONDecodeError):
                self._parse_and_dump(entry)

    def test_array(self):
        self.assertEqual("[]", self._parse_and_dump("[    ]"))

        expected = "[1,\"a==\",-1.3,null]"
        self.assertEqual(expected, self._parse_and_dump("[1,\"a==\",    -1.3 ,null] "))

    def test_bool(self):
        expected = "[true,false]"
        self.assertEqual(expected, self._parse_and_dump("[  true ,false ]"))

        with self.assertRaises(json.decoder.JSONDecodeError):
            self._parse_and_dump("[True,FALSE] ")

    def test_numbers(self):
        expected = "[1,-2,3.5]"
        self.assertEqual(expected, self._parse_and_dump("[  1, -2 , 3.5 ]"))

        expected = "[20050000,20050000,-1.1234e-100]"
        self.assertEqual(expected, self._parse_and_dump("[200.500000E+005,200.500000e+5,-1.1234e-100]"))

        data = [
            "[-]",
            "[1.]",
            "[.123]",
            "[--1.123]",
            "[+1.123]",
            "[1.12.3]",
            "[e--1]",
            "[e++1]",
            "[E- 1]",
            "[3e--1]",
            "[2e++1]",
            "[1E- 1]",
        ]

        for entry in data:
            with self.assertRaises(json.decoder.JSONDecodeError):
                self._parse_and_dump(entry)

    def test_string(self):
        expected = r'["","\b\f\t\n\r/\\"]'
        self.assertEqual(expected, self._parse_and_dump(r' ["" ,  "\b\f\t\n\r\/\\" ]'))

        expected = r'["\uD834\uDD1E"]'
        self.assertEqual(expected.lower(), self._parse_and_dump(expected))

        expected = r'["\\x00"]'
        self.assertEqual(expected, self._parse_and_dump(expected))

        data = [
            r'["]',
            r'[""\uaaa""]',
            r'["\uaa"]',
            r'["\ua"]',
            r'["\u"]',
        ]

        for entry in data:
            with self.assertRaises(json.decoder.JSONDecodeError):
                self._parse_and_dump(entry)

    def test_object(self):
        expected = "{\"test\":true}"
        self.assertEqual(expected, self._parse_and_dump(" {\"test\":   true}"))

        expected = r'{"\uaaaa":true}'
        self.assertEqual(expected, self._parse_and_dump(r' {"\uAAAA":   true}'))

        data = [
            "{\"a\":}",
            "{NULL}",
            "[\"a\":]"
        ]

        for entry in data:
            with self.assertRaises(json.JSONDecodeError):
                self._parse_and_dump(entry)

    def test_max_depth(self):
        data = r'{"1":{"2":2}}'
        with self.assertRaises(json.JSONDecodeError) as context:
            contracts.NEOJson.loads(data, max_depth=1)
        self.assertEqual("Maximum depth exceeded", str(context.exception))

        data = "[[1]]"
        with self.assertRaises(json.JSONDecodeError) as context:
            contracts.NEOJson.loads(data, max_depth=1)
        self.assertEqual("Maximum depth exceeded", str(context.exception))

        data = r'{"1":[[2]]}'
        with self.assertRaises(json.JSONDecodeError) as context:
            contracts.NEOJson.loads(data, max_depth=2)
        self.assertEqual("Maximum depth exceeded", str(context.exception))

    def test_duplicate_keys(self):
        # By default Python accepts this and just takes the last key found
        # NEO doesn't and throws an error
        data = r'{"a":123, "a":456}'
        with self.assertRaises(json.JSONDecodeError) as context:
            contracts.NEOJson.loads(data)
        self.assertEqual("Duplicate keys in objects are not allowed", str(context.exception))


class JSONSerializerTestCase(unittest.TestCase):
    def test_deserialization_basics(self):
        # test empty object
        item = contracts.JSONSerializer.deserialize(contracts.NEOJson.loads("{}"), vm.ReferenceCounter())
        self.assertIsInstance(item, vm.MapStackItem)
        self.assertEqual(0, len(item))

        # test empty array
        item = contracts.JSONSerializer.deserialize(contracts.NEOJson.loads("[]"), vm.ReferenceCounter())
        self.assertIsInstance(item, vm.ArrayStackItem)
        self.assertEqual(0, len(item))

    def test_deserialization_map(self):
        ref_ctr = vm.ReferenceCounter()
        item = contracts.JSONSerializer.deserialize(contracts.NEOJson.loads(r'{"test1":123, "test2": 321}'), ref_ctr)
        self.assertIsInstance(item, vm.MapStackItem)
        self.assertEqual(2, len(item))

        key1 = vm.ByteStringStackItem("test1")
        self.assertEqual(vm.BigInteger(123), item[key1].to_biginteger())
        key2 = vm.ByteStringStackItem("test2")
        self.assertEqual(vm.BigInteger(321), item[key2].to_biginteger())

    def test_deserialization_array_of_items(self):
        ref_ctr = vm.ReferenceCounter()
        array = contracts.JSONSerializer.deserialize(
            contracts.NEOJson.loads(
                r'[[true,"test1", 123, null],[false,"test2",321]]'
            ),
            ref_ctr
        )
        self.assertIsInstance(array, vm.ArrayStackItem)
        self.assertEqual(2, len(array))

        sub_array1 = array[0]
        self.assertIsInstance(sub_array1, vm.ArrayStackItem)
        self.assertEqual(4, len(sub_array1))

        self.assertIsInstance(sub_array1[0], vm.BooleanStackItem)
        self.assertTrue(sub_array1[0])

        self.assertIsInstance(sub_array1[1], vm.ByteStringStackItem)
        self.assertEqual(vm.ByteStringStackItem("test1"), sub_array1[1])

        self.assertIsInstance(sub_array1[2], vm.IntegerStackItem)
        self.assertEqual(vm.BigInteger(123), sub_array1[2].to_biginteger())

        self.assertIsInstance(sub_array1[3], vm.NullStackItem)

        sub_array2 = array[1]
        self.assertIsInstance(sub_array2, vm.ArrayStackItem)
        self.assertEqual(3, len(sub_array2))

        self.assertIsInstance(sub_array2[0], vm.BooleanStackItem)
        self.assertFalse(sub_array2[0])

        self.assertIsInstance(sub_array2[1], vm.ByteStringStackItem)
        self.assertEqual(vm.ByteStringStackItem("test2"), sub_array2[1])

        self.assertIsInstance(sub_array2[2], vm.IntegerStackItem)
        self.assertEqual(vm.BigInteger(321), sub_array2[2].to_biginteger())

    def test_deserialization_invalid_arguments(self):
        # invalid json_data, float is not part of JObject
        with self.assertRaises(ValueError):
            contracts.JSONSerializer.deserialize(float(1.2))

        with self.assertRaises(ValueError) as context:
            contracts.JSONSerializer.deserialize([1])
        self.assertEqual("Can't deserialize JSON array without reference counter", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.JSONSerializer.deserialize({})
        self.assertEqual("Can't deserialize JSON object without reference counter", str(context.exception))

    def test_serialization_basics(self):
        ref = vm.ReferenceCounter()
        m = vm.MapStackItem(ref)
        s = contracts.JSONSerializer.serialize(m, 999)
        self.assertEqual("{}", s)

        a = vm.ArrayStackItem(ref)
        s = contracts.JSONSerializer.serialize(a, 999)
        self.assertEqual(r'[]', s)

        i1 = vm.IntegerStackItem(1)
        i2 = vm.IntegerStackItem(9007199254740992)
        a.append([i1, i2])
        s = contracts.JSONSerializer.serialize(a, 999)
        self.assertEqual(r'[1,"9007199254740992"]', s)

    def test_serialization_map(self):
        ref = vm.ReferenceCounter()
        key1 = vm.ByteStringStackItem("test1")
        key2 = vm.ByteStringStackItem("test2")
        key3 = vm.ByteStringStackItem("test3")
        v1 = vm.IntegerStackItem(1)
        v2 = vm.IntegerStackItem(2)
        v3 = vm.IntegerStackItem(3)
        m = vm.MapStackItem(ref)
        m[key1] = v1
        m[key3] = v3
        m[key2] = v2
        s = contracts.JSONSerializer.serialize(m, 999)
        # this is a known deviation. NEO preserved key order, we don't
        # but shouldn't matter as it gets deserialized to a map stackitem
        expected = r'{"test1":1,"test2":2,"test3":3}'
        self.assertEqual(expected, s)

    def test_serialization_array(self):
        b = vm.BooleanStackItem(True)
        bs = vm.ByteStringStackItem("test")
        i = vm.IntegerStackItem(123)
        n = vm.NullStackItem()
        ref_ctr = vm.ReferenceCounter()
        a = vm.ArrayStackItem(ref_ctr)
        a.append([b, bs, i, n])
        expected = r'[true,"test",123,null]'
        self.assertEqual(expected, contracts.JSONSerializer.serialize(a, 999))

    def test_serialization_array_nested(self):
        bool_t = vm.BooleanStackItem(True)
        bool_f = vm.BooleanStackItem(False)
        bs1 = vm.ByteStringStackItem("test1")
        bs2 = vm.ByteStringStackItem("test2")

        i1 = vm.IntegerStackItem(123)
        i2 = vm.IntegerStackItem(321)
        ref_ctr = vm.ReferenceCounter()

        a1 = vm.ArrayStackItem(ref_ctr)
        a1.append([bool_t, bs1, i1])

        a2 = vm.ArrayStackItem(ref_ctr)
        a2.append([bool_f, bs2, i2])

        parent = vm.ArrayStackItem(ref_ctr)
        parent.append([a1, a2])
        expected = r'[[true,"test1",123],[false,"test2",321]]'
        self.assertEqual(expected, contracts.JSONSerializer.serialize(parent, 999))

    def test_serialization_invalid_type(self):
        s = vm.Script(b'')
        p = vm.PointerStackItem(s, 0)
        with self.assertRaises(TypeError) as context:
            contracts.JSONSerializer.serialize(p, 999)
        self.assertEqual("Object of type PointerStackItem is not JSON serializable", str(context.exception))

    def test_serialization_max_size(self):
        data = [True]
        expected = "[true]"
        s = contracts.JSONSerializer.serialize(data, max_size=len(expected))
        self.assertEqual(expected, s)

        with self.assertRaises(ValueError):
            contracts.JSONSerializer.serialize(data, max_size=len(expected) - 1)

    def test_serialization_map_with_integer_key(self):
        i = vm.IntegerStackItem(123)
        v = vm.IntegerStackItem(321)
        ref_ctr = vm.ReferenceCounter()
        m = vm.MapStackItem(ref_ctr)
        m[i] = v
        expected = r'{"123":321}'
        s = contracts.JSONSerializer.serialize(m, 999)
        self.assertEqual(expected, s)


