import yaml
from utils.logger import setup_logger

class ConfigManager:
    def __init__(self, config_path='config/config.yaml'):
        self.logger = setup_logger()
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self):
        try:
            with open(self.config_path, 'r') as file:
                return yaml.safe_load(file)
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            return {}

    def get(self, key, default=None):
        return self.config.get(key, default)