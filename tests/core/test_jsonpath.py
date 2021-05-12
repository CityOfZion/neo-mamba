import unittest
from neo3.core import jsonpath

json_data = {
    "store": {
        "book": [
            {
                "category": "reference",
                "author": "Nigel Rees",
                "title": "Sayings of the Century",
                "price": 8.95
            },
            {
                "category": "fiction",
                "author": "Evelyn Waugh",
                "title": "Sword of Honour",
                "price": 12.99
            },
            {
                "category": "fiction",
                "author": "Herman Melville",
                "title": "Moby Dick",
                "isbn": "0-553-21311-3",
                "price": 8.99
            },
            {
                "category": "fiction",
                "author": "J. R. R. Tolkien",
                "title": "The Lord of the Rings",
                "isbn": "0-395-19395-8",
                "price": 22.99
            }
        ],
        "bicycle": {
            "color": "red",
            "price": 19.95
        },
    },
    "expensive": 10,
}


class JsonPathTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.json = jsonpath.JsonPath(json_data)

    def test_csharp_cases(self):
        self.assertEqual(['Nigel Rees', 'Evelyn Waugh', 'Herman Melville', 'J. R. R. Tolkien'], self.json.parse("$.store.book[*].author"))
        self.assertEqual(['Nigel Rees', 'Evelyn Waugh', 'Herman Melville', 'J. R. R. Tolkien'], self.json.parse("$..author"))
        self.assertEqual([19.95,8.95,12.99,8.99,22.99], self.json.parse("$.store..price"))
        self.assertEqual([{'category': 'fiction', 'author': 'Herman Melville', 'title': 'Moby Dick', 'isbn': '0-553-21311-3', 'price': 8.99}], self.json.parse("$..book[2]"))
        self.assertEqual([{'category': 'fiction', 'author': 'Herman Melville', 'title': 'Moby Dick', 'isbn': '0-553-21311-3', 'price': 8.99}], self.json.parse("$..book[-2]"))
        self.assertEqual([{'category': 'reference', 'author': 'Nigel Rees', 'title': 'Sayings of the Century', 'price': 8.95}, {'category': 'fiction', 'author': 'Evelyn Waugh', 'title': 'Sword of Honour', 'price': 12.99}], self.json.parse("$..book[0,1]"))
        self.assertEqual([{'category': 'reference', 'author': 'Nigel Rees', 'title': 'Sayings of the Century', 'price': 8.95}, {'category': 'fiction', 'author': 'Evelyn Waugh', 'title': 'Sword of Honour', 'price': 12.99}], self.json.parse("$..book[:2]"))
        self.assertEqual([{'category': 'fiction', 'author': 'Evelyn Waugh', 'title': 'Sword of Honour', 'price': 12.99}], self.json.parse("$..book[1:2]"))
        self.assertEqual([{'category': 'fiction', 'author': 'Herman Melville', 'title': 'Moby Dick', 'isbn': '0-553-21311-3', 'price': 8.99}, {'category': 'fiction', 'author': 'J. R. R. Tolkien', 'title': 'The Lord of the Rings', 'isbn': '0-395-19395-8', 'price': 22.99}], self.json.parse("$..book[-2:]"))
        self.assertEqual([{'category': 'fiction', 'author': 'Herman Melville', 'title': 'Moby Dick', 'isbn': '0-553-21311-3', 'price': 8.99}, {'category': 'fiction', 'author': 'J. R. R. Tolkien', 'title': 'The Lord of the Rings', 'isbn': '0-395-19395-8', 'price': 22.99}], self.json.parse("$..book[2:]"))
        self.assertEqual([{'book': [{'category': 'reference', 'author': 'Nigel Rees', 'title': 'Sayings of the Century', 'price': 8.95}, {'category': 'fiction', 'author': 'Evelyn Waugh', 'title': 'Sword of Honour', 'price': 12.99}, {'category': 'fiction', 'author': 'Herman Melville', 'title': 'Moby Dick', 'isbn': '0-553-21311-3', 'price': 8.99}, {'category': 'fiction', 'author': 'J. R. R. Tolkien', 'title': 'The Lord of the Rings', 'isbn': '0-395-19395-8', 'price': 22.99}], 'bicycle': {'color': 'red', 'price': 19.95}}, 10], self.json.parse("$.*"))



