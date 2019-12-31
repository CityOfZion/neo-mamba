import unittest
from neo3.network.ipfilter import IPFilter


class IPFilteringTestCase(unittest.TestCase):
    def test_nobody_allowed(self):
        filter = IPFilter()
        filter.load_config({
            'blacklist': [
                '0.0.0.0/0'
            ],
            'whitelist': [
            ]
        })

        self.assertFalse(filter.is_allowed('127.0.0.1'))
        self.assertFalse(filter.is_allowed('10.10.10.10'))

    def test_nobody_allowed_except_one(self):
        filter = IPFilter()
        filter.load_config({
            'blacklist': [
                '0.0.0.0/0'
            ],
            'whitelist': [
                '10.10.10.10'
            ]
        })

        self.assertFalse(filter.is_allowed('127.0.0.1'))
        self.assertFalse(filter.is_allowed('10.10.10.11'))
        self.assertTrue(filter.is_allowed('10.10.10.10'))

    def test_everybody_allowed(self):
        filter = IPFilter()
        filter.load_config({
            'blacklist': [
            ],
            'whitelist': [
            ]
        })

        self.assertTrue(filter.is_allowed('127.0.0.1'))
        self.assertTrue(filter.is_allowed('10.10.10.11'))
        self.assertTrue(filter.is_allowed('10.10.10.10'))

        filter.load_config({
            'blacklist': [
            ],
            'whitelist': [
                '0.0.0.0/0'
            ]
        })

        self.assertTrue(filter.is_allowed('127.0.0.1'))
        self.assertTrue(filter.is_allowed('10.10.10.11'))
        self.assertTrue(filter.is_allowed('10.10.10.10'))

        filter.load_config({
            'blacklist': [
                '0.0.0.0/0'
            ],
            'whitelist': [
                '0.0.0.0/0'
            ]
        })

        self.assertTrue(filter.is_allowed('127.0.0.1'))
        self.assertTrue(filter.is_allowed('10.10.10.11'))
        self.assertTrue(filter.is_allowed('10.10.10.10'))

    def test_everybody_allowed_except_one(self):
        filter = IPFilter()
        filter.load_config({
            'blacklist': [
                '127.0.0.1'
            ],
            'whitelist': [
            ]
        })

        self.assertFalse(filter.is_allowed('127.0.0.1'))
        self.assertTrue(filter.is_allowed('10.10.10.11'))
        self.assertTrue(filter.is_allowed('10.10.10.10'))

    def test_disallow_ip_range(self):
        filter = IPFilter()
        filter.load_config({
            'blacklist': [
                '127.0.0.0/24'
            ],
            'whitelist': [
            ]
        })

        self.assertFalse(filter.is_allowed('127.0.0.0'))
        self.assertFalse(filter.is_allowed('127.0.0.1'))
        self.assertFalse(filter.is_allowed('127.0.0.100'))
        self.assertFalse(filter.is_allowed('127.0.0.255'))
        self.assertTrue(filter.is_allowed('10.10.10.11'))
        self.assertTrue(filter.is_allowed('10.10.10.10'))

    def test_updating_blacklist(self):
        filter = IPFilter()
        filter.load_config({
            'blacklist': [
            ],
            'whitelist': [
            ]
        })

        self.assertTrue(filter.is_allowed('127.0.0.1'))

        filter.blacklist_add('127.0.0.0/24')
        self.assertFalse(filter.is_allowed('127.0.0.1'))
        # should have no effect, only exact matches
        filter.blacklist_remove('127.0.0.1')
        self.assertFalse(filter.is_allowed('127.0.0.1'))

        filter.blacklist_remove('127.0.0.0/24')
        self.assertTrue(filter.is_allowed('127.0.0.1'))

    def test_updating_whitelist(self):
        filter = IPFilter()
        filter.load_config({
            'blacklist': [
                '0.0.0.0/0'
            ],
            'whitelist': [
            ]
        })

        self.assertFalse(filter.is_allowed('127.0.0.1'))

        filter.whitelist_add('127.0.0.0/24')
        self.assertTrue(filter.is_allowed('127.0.0.1'))

        filter.whitelist_remove('127.0.0.1')
        # should have no effect, only exact matches
        self.assertTrue(filter.is_allowed('127.0.0.1'))

        filter.whitelist_remove('127.0.0.0/24')
        self.assertFalse(filter.is_allowed('127.0.0.1'))

    def test_invalid_config_loading(self):
        filter = IPFilter()
        # mandatory keys not present
        with self.assertRaises(ValueError) as ctx:
            filter.load_config({'blacklist':[]})
        self.assertEqual("whitelist key not found", str(ctx.exception))

        # mandatory key blacklist not present
        with self.assertRaises(ValueError) as ctx:
            filter.load_config({'whitelist':[]})
        self.assertEqual("blacklist key not found", str(ctx.exception))

    def test_config_reset(self):
        filter = IPFilter()
        filter.blacklist_add('127.0.0.1')
        self.assertEqual(1, len(filter._config['blacklist']))
        filter.reset()
        self.assertEqual(filter.default_config,filter._config)
