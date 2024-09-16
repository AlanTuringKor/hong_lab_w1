import requests
from utils.logger import setup_logger

class Updater:
    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = setup_logger()
        self.update_url = self.config.get('update_url', 'https://example.com/av-updates')

    def check_and_update(self):
        try:
            response = requests.get(f"{self.update_url}/latest-version")
            latest_version = response.json()['version']
            current_version = self.config.get('current_version', '1.0.0')
            
            if latest_version > current_version:
                self.logger.info(f"New version available: {latest_version}")
                self._download_update(latest_version)
                return True
            else:
                self.logger.info("Software is up to date")
                return False
        except Exception as e:
            self.logger.error(f"Update check failed: {str(e)}")
            return False

    def _download_update(self, version):
        try:
            response = requests.get(f"{self.update_url}/download/{version}")
            # Here you would typically save and apply the update
            self.logger.info(f"Downloaded update version {version}")
        except Exception as e:
            self.logger.error(f"Failed to download update: {str(e)}")