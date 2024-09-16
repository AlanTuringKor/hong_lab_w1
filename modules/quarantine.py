import os
import shutil
from utils.logger import setup_logger

class Quarantine:
    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = setup_logger()
        self.quarantine_dir = self.config.get('quarantine_dir', '/tmp/quarantine')
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def isolate(self, threats):
        for threat in threats:
            self._move_to_quarantine(threat)

    def _move_to_quarantine(self, file_path):
        try:
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, filename)
            shutil.move(file_path, quarantine_path)
            self.logger.info(f"Moved {file_path} to quarantine")
        except Exception as e:
            self.logger.error(f"Failed to quarantine {file_path}: {str(e)}")