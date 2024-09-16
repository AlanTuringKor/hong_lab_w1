from modules.scanner import Scanner
from modules.quarantine import Quarantine
from modules.config_manager import ConfigManager
from modules.updater import Updater
from modules.api import API
from utils.logger import setup_logger

class AVCore:
    def __init__(self):
        self.logger = setup_logger()
        self.config_manager = ConfigManager()
        self.scanner = Scanner(self.config_manager)
        self.quarantine = Quarantine(self.config_manager)
        self.updater = Updater(self.config_manager)
        self.api = API(self)

    def start(self):
        self.logger.info("Starting Antivirus Core")
        self.api.start()

    def scan(self, path):
        self.logger.info(f"Initiating scan on {path}")
        threats = self.scanner.scan(path)
        if threats:
            self.quarantine.isolate(threats)
        return threats

    def update(self):
        self.logger.info("Checking for updates")
        return self.updater.check_and_update()