import unittest
from unittest.mock import mock_open, patch
from modules.config_manager import ConfigManager

class TestConfigManager(unittest.TestCase):
    @patch('builtins.open', new_callable=mock_open, read_data='{"test_key": "test_value"}')
    def setUp(self, mock_file):
        self.config_manager = ConfigManager('fake_path.yaml')

    def test_get_existing_key(self):
        self.assertEqual(self.config_manager.get('test_key'), 'test_value')

    def test_get_nonexistent_key(self):
        self.assertIsNone(self.config_manager.get('nonexistent_key'))

    def test_get_with_default(self):
        self.assertEqual(self.config_manager.get('nonexistent_key', 'default_value'), 'default_value')

    @patch('yaml.dump')
    def test_update(self, mock_dump):
        self.config_manager.update('new_key', 'new_value')
        self.assertEqual(self.config_manager.get('new_key'), 'new_value')
        mock_dump.assert_called_once()

if __name__ == '__main__':
    unittest.main()