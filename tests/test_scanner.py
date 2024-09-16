import unittest
from unittest.mock import Mock, patch
from modules.scanner import Scanner

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.config_manager = Mock()
        self.scanner = Scanner(self.config_manager)

    @patch('os.walk')
    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data=b'Test VIRUS signature')
    def test_scan_detects_threat(self, mock_open, mock_walk):
        mock_walk.return_value = [
            ('/fake/path', (), ('infected_file.txt',))
        ]
        threats = self.scanner.scan('/fake/path')
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0], '/fake/path/infected_file.txt')

    @patch('os.walk')
    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data=b'Clean file content')
    def test_scan_no_threat(self, mock_open, mock_walk):
        mock_walk.return_value = [
            ('/fake/path', (), ('clean_file.txt',))
        ]
        threats = self.scanner.scan('/fake/path')
        self.assertEqual(len(threats), 0)

    def test_check_file(self):
        with patch('builtins.open', unittest.mock.mock_open(read_data=b'Test VIRUS signature')):
            self.assertTrue(self.scanner._check_file('/fake/path/infected_file.txt'))
        
        with patch('builtins.open', unittest.mock.mock_open(read_data=b'Clean file content')):
            self.assertFalse(self.scanner._check_file('/fake/path/clean_file.txt'))

if __name__ == '__main__':
    unittest.main()