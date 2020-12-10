import json
import binascii
from neo3 import vm
from typing import Union, Any, TypeVar, Iterable, cast


class _JSONDecodeError(json.JSONDecodeError):
    """
    Custom version that doesn't require the document and position arguments

    Can still be caught with json.JSONDecodeError
    """
    def __init__(self, msg):
        ValueError.__init__(self, msg)

    def __reduce__(self):
        return self.__class__, ()  # pragma: no cover


class _NEOVMEncoder(json.JSONEncoder):
    def _encode(self, item):
        t = type(item)
        if t == vm.ArrayStackItem:
            a = []
            for i in item:
                a.append(self._encode(i))
            return a
        elif t == vm.ByteStringStackItem:
            return binascii.unhexlify(str(item).encode()).decode()
        elif t == vm.IntegerStackItem:
            i = item.to_biginteger()
            if i > JSONSerializer.MAX_SAFE_INTEGER or i < JSONSerializer.MIN_SAFE_INTEGER:
                return str(i)
            return int(i)
        elif t == vm.BooleanStackItem:
            return item.to_boolean()
        elif t == vm.NullStackItem:
            return None
        elif t == vm.MapStackItem:
            d = {}
            for k, v in item:
                if type(k) == vm.ByteStringStackItem:
                    d.update({k.to_array().decode(): self._encode(v)})
                else:
                    d.update({self._encode(k): self._encode(v)})
            return d
        else:
            raise ValueError

    def default(self, obj):
        try:
            return self._encode(obj)
        except ValueError:
            return json.JSONEncoder.default(self, obj)


class NEOJson:
    """
    JSON wrapper which follows NEOs JSON configuration.
    """
    @staticmethod
    def _float_hook(val):
        # C# strips .0 from floats
        val = float(val)
        if val.is_integer():
            return int(val)
        return val

    @staticmethod
    def _check_for_duplicate_keys(objects):
        # The C# implementation does not allow repeated key names in objects
        unique = dict()
        for pair in objects:
            if pair[0] in unique:
                raise _JSONDecodeError("Duplicate keys in objects are not allowed")
            else:
                unique.update({pair[0]: pair[1]})
        return unique

    @staticmethod
    def _calc_depth(json_input, max_depth, ctr=0):
        if not isinstance(json_input, Iterable):
            return ctr
        if ctr + 1 > max_depth:
            raise ValueError
        ctr += 1

        t = type(json_input)
        if t == list:
            _max = ctr
            for el in json_input:
                ctr = NEOJson._calc_depth(el, max_depth, ctr)
                _max = max(_max, ctr)
            return _max
        elif t == dict:
            _max = ctr
            for k, v in json_input.items():
                ctr = NEOJson._calc_depth(v, max_depth, ctr)
                _max = max(_max, ctr)
            return _max
        else:
            return ctr

    @staticmethod
    def loads(src: Union[str, bytes], max_depth: int = 100) -> Any:
        """
        Parse input into Python objects.

        This is a thin wrapper around the standard library JSON module with adjustments to match NEOs parsing rules.

        Args:
            src: JSON document
            max_depth: maximum nested object depth

        Raises:
            json.JSONDecodeError:
                - if max_depth is exceeded
                - if repeated keys are found
        """

        # Hooks don't get called when subclassing JSONDecoder and trying to provide the hooks from there.
        # so we'll have to stick with the work around until that's fixed.
        d = json.loads(src, parse_float=NEOJson._float_hook, object_pairs_hook=NEOJson._check_for_duplicate_keys)

        # Unfortunately Python does not provide hooks for JSON arrays, only for JSON objects. This means we cannot limit
        # the max depth while parsing and we have to calculate it once the JSON document is fully processed *shrug*
        # Regardless, we're always protected against an infinite recursion by Python's build in stack recursion limit.
        try:
            NEOJson._calc_depth(d, max_depth)
        except ValueError:
            raise _JSONDecodeError("Maximum depth exceeded")
        return d

    @staticmethod
    def dumps(src: dict) -> str:
        """
        Convert `src` to JSON formatted string.

        This is a thin wrapper around the standard library JSON module with adjustments to match NEOs formatting rules.

        Args:
            src: input data.
        """
        return json.dumps(src, cls=_NEOVMEncoder, separators=(',', ':'))


JObject = Union[dict, bool, None, int, list, str]


class JSONSerializer:
    """
    Interoperability layer JSON serialization support
    """
    MAX_SAFE_INTEGER = pow(2, 53) - 1
    MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER

    @staticmethod
    def deserialize(json_data: JObject, reference_counter: vm.ReferenceCounter = None) -> vm.StackItem:
        """
        Deserialize JSON into a virtual machine stack item
        """
        t = type(json_data)
        if t == dict:
            json_data = cast(dict, json_data)
            if reference_counter is None:
                raise ValueError("Can't deserialize JSON object without reference counter")
            map_item = vm.MapStackItem(reference_counter)
            for k, v in json_data.items():
                key = vm.ByteStringStackItem(k)
                value = JSONSerializer.deserialize(v, reference_counter)
                map_item[key] = value
            return map_item
        elif t == list:
            if reference_counter is None:
                raise ValueError("Can't deserialize JSON array without reference counter")
            array_item = vm.ArrayStackItem(reference_counter)
            json_data = cast(list, json_data)
            elements = [JSONSerializer.deserialize(e, reference_counter) for e in json_data]
            array_item.append(elements)
            return array_item
        elif json_data is None:
            return vm.NullStackItem()
        elif t == str:
            if json_data == "null":
                return vm.NullStackItem()
            return vm.ByteStringStackItem(json_data)  # type: ignore
        elif t == int:
            return vm.IntegerStackItem(json_data)  # type: ignore
        elif t == bool:
            json_data = cast(bool, json_data)
            return vm.BooleanStackItem(json_data)
        else:
            # should never happen or somebody ignored the type checker output
            raise ValueError()

    @staticmethod
    def serialize(item: vm.StackItem, max_size: int) -> str:
        """
        Serialize a stack item to a JSON formatted string.

        Args:
            item: a stack item instance.
            max_size: maximum length of serialized data.
        """
        s = json.dumps(item, cls=_NEOVMEncoder, separators=(',', ':'))
        if len(s) > max_size:
            raise ValueError
        return s
