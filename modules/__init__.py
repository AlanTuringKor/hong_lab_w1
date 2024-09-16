from .scanner import Scanner
from .quarantine import Quarantine
from .config_manager import ConfigManager
from .updater import Updater
from .api import API
from .file_watcher import FileWatcher
from .reporter import Reporter

__all__ = ['Scanner', 'Quarantine', 'ConfigManager', 'Updater', 'API', 'FileWatcher', 'Reporter']

def initialize_modules(config):
    """Initialize all modules with the given configuration."""
    return {
        'scanner': Scanner(config),
        'quarantine': Quarantine(config),
        'updater': Updater(config),
        'api': API(config),
        'file_watcher': FileWatcher(config),
        'reporter': Reporter(config)
    }