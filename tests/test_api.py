import unittest
from unittest.mock import Mock
from modules.api import API
from flask import json

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.av_core = Mock()
        self.config_manager = Mock()
        self.api = API(self.av_core, self.config_manager)
        self.client = self.api.app.test_client()

    def test_scan_endpoint(self):
        self.av_core.scan.return_value = ['threat1.txt', 'threat2.txt']
        response = self.client.post('/scan', json={'path': '/test/path'})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['threats'], ['threat1.txt', 'threat2.txt'])

    def test_update_endpoint(self):
        self.av_core.update.return_value = True
        response = self.client.post('/update')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['updated'])

    def test_scan_endpoint_no_path(self):
        response = self.client.post('/scan', json={})
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()