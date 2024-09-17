import re
import math

class StaticAnalyzer:
    def __init__(self, logger):
        self.logger = logger

    def analyze(self, file_path):
        self.logger.info(f"Performing static analysis on {file_path}")
        return {
            "suspicious_strings": self._check_suspicious_strings(file_path),
            "file_entropy": self._calculate_file_entropy(file_path),
            "threat_level": self._calculate_threat_level(file_path)
        }

    def _check_suspicious_strings(self, file_path):
        suspicious_patterns = [
            r"(system|exec|eval|os\.)",
            r"(socket|urllib|requests)",
            r"(crypto|encrypt|decrypt)"
        ]
        suspicious_strings = []
        try:
            with open(file_path, 'r', errors='ignore') as file:
                content = file.read()
                for pattern in suspicious_patterns:
                    matches = re.findall(pattern, content)
                    suspicious_strings.extend(matches)
        except Exception as e:
            self.logger.error(f"Error checking suspicious strings in {file_path}: {str(e)}")
        return suspicious_strings

    def _calculate_file_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                data = file.read()
                if len(data) == 0:
                    return 0.0
                entropy = 0
                for x in range(256):
                    p_x = data.count(x) / len(data)
                    if p_x > 0:
                        entropy += - p_x * math.log2(p_x)
            return entropy
        except Exception as e:
            self.logger.error(f"Error calculating entropy for {file_path}: {str(e)}")
            return None

    def _calculate_threat_level(self, file_path):
        # This is a placeholder method. In a real scenario, you would implement
        # more sophisticated threat level calculation based on various static analysis results.
        suspicious_strings = self._check_suspicious_strings(file_path)
        entropy = self._calculate_file_entropy(file_path)
        
        threat_level = len(suspicious_strings) * 0.1  # Each suspicious string adds 0.1 to threat level
        if entropy and entropy > 7.0:
            threat_level += 0.5  # High entropy adds 0.5 to threat level
        
        return min(threat_level, 1.0)  # Ensure threat level is between 0 and 1