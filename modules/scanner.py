import os
import hashlib
from utils.logger import setup_logger

class Scanner:
    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = setup_logger()
        self.signatures = self._load_signatures()

    def _load_signatures(self):
        # In a real scenario, this would load from a file or database
        return {
            'e1a00c4a1a19ec11618112e1d5fa0428': 'TestVirus1',
            '6f5902ac237024bdd0c176cb93063dc4': 'TestVirus2',
        }

    def scan(self, path):
        self.logger.info(f"Scanning {path}")
        threats = []
        if os.path.isfile(path):
            if self._check_file(path):
                threats.append(path)
        else:
            for root, dirs, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    if self._check_file(full_path):
                        threats.append(full_path)
        return threats

    def _check_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
                file_hash = hashlib.md5(content).hexdigest()
                if file_hash in self.signatures:
                    self.logger.warning(f"Detected {self.signatures[file_hash]} in {file_path}")
                    return True
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {str(e)}")
        return False