import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils.logger import setup_logger

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner
        self.logger = setup_logger()

    def on_created(self, event):
        if not event.is_directory:
            self.logger.info(f"File created: {event.src_path}")
            self._scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.logger.info(f"File modified: {event.src_path}")
            self._scan_file(event.src_path)

    def _scan_file(self, file_path):
        threats = self.scanner.scan(file_path)
        if threats:
            self.logger.warning(f"Threat detected in {file_path}")
            # Here you would trigger quarantine or other actions

class FileWatcher:
    def __init__(self, config_manager, scanner):
        self.config = config_manager
        self.scanner = scanner
        self.logger = setup_logger()
        self.watch_paths = self.config.get('watch_paths', [])
        self.observer = Observer()

    def start(self):
        event_handler = FileChangeHandler(self.scanner)
        for path in self.watch_paths:
            self.observer.schedule(event_handler, path, recursive=True)
        self.observer.start()
        self.logger.info("File watcher started")

    def stop(self):
        self.observer.stop()
        self.observer.join()
        self.logger.info("File watcher stopped")