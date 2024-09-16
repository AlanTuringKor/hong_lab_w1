import json
from datetime import datetime
from utils.logger import setup_logger

class Reporter:
    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = setup_logger()
        self.report_dir = self.config.get('report_dir', '/var/lib/antivirus/reports')

    def generate_report(self, scan_results):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = {
            "timestamp": timestamp,
            "total_files_scanned": scan_results.get("total_files", 0),
            "threats_detected": scan_results.get("threats", []),
            "scan_duration": scan_results.get("duration", 0)
        }
        
        report_path = f"{self.report_dir}/scan_report_{timestamp}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=4)
        
        self.logger.info(f"Report generated: {report_path}")
        return report_path

    def get_summary(self, days=7):
        # Implementation to summarize reports from the last 'days' days
        pass