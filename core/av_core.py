import threading
from modules.config_manager import ConfigManager
from modules.scanner import Scanner
from modules.quarantine import Quarantine
from modules.updater import Updater
from modules.reporter import Reporter
from modules.file_watcher import FileWatcher
from utils.logger import setup_logger

class AVCore:
    def __init__(self, config_path='config/config.yaml'):
        self.logger = setup_logger()
        self.config_manager = ConfigManager(config_path)
        self.scanner = Scanner(self.config_manager)
        self.quarantine = Quarantine(self.config_manager)
        self.updater = Updater(self.config_manager)
        self.reporter = Reporter(self.config_manager)
        self.file_watcher = FileWatcher(self.config_manager, self.scanner)
        self.is_running = False

    def start(self):
        self.logger.info("Starting W1 Antivirus Core")
        self.is_running = True
        self._start_file_watcher()
        self._start_periodic_scan()
        self._start_update_checker()

    def stop(self):
        self.logger.info("Stopping W1 Antivirus Core")
        self.is_running = False
        self.file_watcher.stop()

    def scan(self, path):
        self.logger.info(f"Initiating scan on {path}")
        threats = self.scanner.scan(path)
        if threats:
            self.quarantine.isolate(threats)
            self.reporter.generate_report({
                "scan_path": path,
                "threats_found": threats
            })
        return threats

    def update(self):
        self.logger.info("Checking for updates")
        return self.updater.check_and_update()

    def generate_report(self):
        return self.reporter.generate_summary()

    def _start_file_watcher(self):
        self.logger.info("Starting File Watcher")
        watcher_thread = threading.Thread(target=self.file_watcher.start)
        watcher_thread.start()

    def _start_periodic_scan(self):
        if not self.is_running:
            return
        
        scan_interval = self.config_manager.get('scan_interval', 86400)  # Default to 24 hours
        paths_to_scan = self.config_manager.get('scan_paths', ['/'])
        
        for path in paths_to_scan:
            self.scan(path)
        
        threading.Timer(scan_interval, self._start_periodic_scan).start()

    def _start_update_checker(self):
        if not self.is_running:
            return
        
        update_interval = self.config_manager.get('update_interval', 3600)  # Default to 1 hour
        
        if self.update():
            self.logger.info("Update successfully applied")
        else:
            self.logger.info("No updates available or update failed")
        
        threading.Timer(update_interval, self._start_update_checker).start()

    def on_file_event(self, event):
        if event.is_directory:
            return
        
        self.logger.info(f"File event detected: {event.src_path}")
        threats = self.scan(event.src_path)
        if threats:
            self.logger.warning(f"Threats found in {event.src_path}")
            self.quarantine.isolate(threats)

if __name__ == "__main__":
    av_core = AVCore()
    try:
        av_core.start()
        # Keep the main thread alive
        while True:
            pass
    except KeyboardInterrupt:
        av_core.stop()
        print("W1 Antivirus Core stopped.")