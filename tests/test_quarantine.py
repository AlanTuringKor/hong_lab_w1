import unittest
from unittest.mock import Mock, patch
import os
import shutil
from modules.quarantine import Quarantine

class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.config_manager = Mock()
        self.config_manager.get.return_value = '/tmp/test_quarantine'
        self.quarantine = Quarantine(self.config_manager)

    def tearDown(self):
        if os.path.exists('/tmp/test_quarantine'):
            shutil.rmtree('/tmp/test_quarantine')

    @patch('shutil.move')
    def test_isolate(self, mock_move):
        threats = ['/path/to/threat1.txt', '/path/to/threat2.txt']
        self.quarantine.isolate(threats)
        self.assertEqual(mock_move.call_count, 2)

    @patch('os.path.exists', return_value=True)
    @patch('os.remove')
    def test_restore(self, mock_remove, mock_exists):
        quarantined_file = os.path.join(self.quarantine.quarantine_dir, 'threat.txt')
        original_path = '/original/path/threat.txt'
        self.quarantine.restore(quarantined_file, original_path)
        mock_remove.assert_called_once_with(quarantined_file)

if __name__ == '__main__':
    unittest.main()