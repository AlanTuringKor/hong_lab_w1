import unittest
from unittest.mock import Mock, patch
from modules.updater import Updater

class TestUpdater(unittest.TestCase):
    def setUp(self):
        self.config_manager = Mock()
        self.config_manager.get.return_value = 'https://example.com/updates'
        self.updater = Updater(self.config_manager)

    @patch('requests.get')
    def test_check_for_updates_available(self, mock_get):
        mock_get.return_value.json.return_value = {
            'latest_version': '2.0.0',
            'virus_db_version': '2023.10.01'
        }
        self.config_manager.get.side_effect = ['1.0.0', '2023.09.01']
        
        result = self.updater.check_and_update()
        self.assertTrue(result)

    @patch('requests.get')
    def test_check_for_updates_not_available(self, mock_get):
        mock_get.return_value.json.return_value = {
            'latest_version': '1.0.0',
            'virus_db_version': '2023.09.01'
        }
        self.config_manager.get.side_effect = ['1.0.0', '2023.09.01']
        
        result = self.updater.check_and_update()
        self.assertFalse(result)

    @patch('requests.get')
    def test_perform_updates(self, mock_get):
        update_info = {
            'latest_version': '2.0.0',
            'virus_db_version': '2023.10.01'
        }
        self.updater._perform_updates(update_info)
        self.assertEqual(mock_get.call_count, 2)  # One for software, one for virus DB

if __name__ == '__main__':
    unittest.main()