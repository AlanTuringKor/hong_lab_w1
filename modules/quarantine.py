import os
import shutil
import json
import zipfile
import datetime
from utils.logger import setup_logger

class Quarantine:
    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = setup_logger()
        self.quarantine_dir = self.config.get('quarantine_dir', '/tmp/quarantine')
        self.metadata_file = os.path.join(self.quarantine_dir, 'metadata.json')
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.metadata = self._load_metadata()

    def _load_metadata(self):
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_metadata(self):
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)

    def isolate(self, threats):
        for threat in threats:
            self._quarantine_file(threat)

    def _quarantine_file(self, file_path):
        try:
            filename = os.path.basename(file_path)
            quarantine_name = f"{filename}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

            # Compress the file
            with zipfile.ZipFile(quarantine_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(file_path, filename)

            # Store metadata
            self.metadata[quarantine_name] = {
                'original_path': file_path,
                'quarantine_date': datetime.datetime.now().isoformat(),
                'original_size': os.path.getsize(file_path),
                'compressed_size': os.path.getsize(quarantine_path)
            }

            # Remove the original file
            os.remove(file_path)

            self._save_metadata()
            self.logger.info(f"Quarantined {file_path} to {quarantine_path}")
        except Exception as e:
            self.logger.error(f"Failed to quarantine {file_path}: {str(e)}")

    def restore(self, quarantine_name):
        if quarantine_name not in self.metadata:
            self.logger.error(f"No metadata found for {quarantine_name}")
            return False

        try:
            original_path = self.metadata[quarantine_name]['original_path']
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

            # Extract the file
            with zipfile.ZipFile(quarantine_path, 'r') as zipf:
                zipf.extractall(path=os.path.dirname(original_path))

            # Remove the quarantined zip file
            os.remove(quarantine_path)

            # Remove metadata
            del self.metadata[quarantine_name]
            self._save_metadata()

            self.logger.info(f"Restored {quarantine_name} to {original_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to restore {quarantine_name}: {str(e)}")
            return False

    def list_quarantined_files(self):
        return list(self.metadata.keys())

    def get_file_info(self, quarantine_name):
        return self.metadata.get(quarantine_name, None)