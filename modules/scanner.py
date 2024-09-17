import os
import hashlib
import yara
import pefile
from utils.logger import setup_logger
from signature_database import SignatureDatabase
from static_analyzer import StaticAnalyzer
from dynamic_analyzer import DynamicAnalyzer

class Scanner:
    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = setup_logger()
        self.signature_db = SignatureDatabase()
        self.static_analyzer = StaticAnalyzer(self.logger)
        self.dynamic_analyzer = DynamicAnalyzer(self.logger)
        self.yara_rules = self.load_yara_rules()

    def load_yara_rules(self):
        print("Loading YARA rules...")
        # In a real scenario, you would load these from files
        return yara.compile(sources={
            'quick_check': 'rule quick_check { strings: $a = "suspicious" condition: $a }'
        })

    def scan(self, path):
        print(f"\nStarting scan of {path}")
        threats = []
        potential_threats = []

        if os.path.isfile(path):
            print(f"Scanning single file: {path}")
            if self.quick_check(path):
                potential_threats.append(path)
        else:
            print(f"Scanning directory: {path}")
            for root, dirs, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    print(f"Quick checking: {full_path}")
                    if self.quick_check(full_path):
                        potential_threats.append(full_path)

        print(f"\nQuick check complete. {len(potential_threats)} potential threats found.")
        print("Starting thorough check on potential threats...")

        for file_path in potential_threats:
            print(f"\nThoroughly checking: {file_path}")
            if self.thorough_check(file_path):
                threats.append(file_path)

        print(f"\nScan complete. {len(threats)} threats found.")
        return threats

    def quick_check(self, file_path):
        try:
            # 1. Quick hash check
            with open(file_path, 'rb') as file:
                content = file.read()
                file_hash = hashlib.md5(content).hexdigest()
                if self.signature_db.check_signature(file_hash):
                    print(f"  Quick check: Hash match for {file_path}")
                    return True

            # 2. Quick YARA check
            if self.yara_rules.match(file_path):
                print(f"  Quick check: YARA match for {file_path}")
                return True

            # 3. Quick file size check
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # e.g., files larger than 100MB
                print(f"  Quick check: Large file size for {file_path}")
                return True

            # 4. Check for packing
            if self.is_packed(file_path):
                print(f"  Quick check: File appears to be packed: {file_path}")
                return True

        except Exception as e:
            print(f"  Error in quick check of {file_path}: {str(e)}")

        return False

    def is_packed(self, file_path):
        try:
            pe = pefile.PE(file_path)
            
            # Check for high entropy in sections
            for section in pe.sections:
                if section.get_entropy() > 7.0:
                    print(f"    Packed check: High entropy detected in {file_path}")
                    return True
            
            # Check for common packer section names
            packer_sections = [".aspack", ".pcle", ".crypt", ".upx", ".pkr", ".taz", ".ccg", ".upack"]
            for section in pe.sections:
                if section.Name.decode().rstrip("\x00") in packer_sections:
                    print(f"    Packed check: Packer section name detected in {file_path}")
                    return True
            
            # Check for low number of imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                if len(pe.DIRECTORY_ENTRY_IMPORT) < 3:
                    print(f"    Packed check: Low number of imports in {file_path}")
                    return True
            
            # Check for suspicious section names
            for section in pe.sections:
                if section.Name.decode().rstrip("\x00") == "UPX0":
                    print(f"    Packed check: UPX packer detected in {file_path}")
                    return True
            
            return False
        except Exception as e:
            print(f"    Error checking if file is packed {file_path}: {str(e)}")
            return False

    def thorough_check(self, file_path):
        try:
            # Static analysis
            print("  Performing static analysis...")
            static_results = self.static_analyzer.analyze(file_path)
            if self.evaluate_static_results(static_results):
                print(f"  Static analysis detected threat in {file_path}")
                return True

            # Dynamic analysis
            print("  Performing dynamic analysis...")
            dynamic_results = self.dynamic_analyzer.analyze(file_path)
            if self.evaluate_dynamic_results(dynamic_results):
                print(f"  Dynamic analysis detected threat in {file_path}")
                return True

        except Exception as e:
            print(f"  Error in thorough check of {file_path}: {str(e)}")

        print(f"  No threats detected in {file_path}")
        return False

    def evaluate_static_results(self, results):
        threat_level = results.get('threat_level', 0)
        print(f"    Static analysis threat level: {threat_level}")
        return threat_level > 0.7

    def evaluate_dynamic_results(self, results):
        malicious_behavior = results.get('malicious_behavior', False)
        print(f"    Dynamic analysis detected malicious behavior: {malicious_behavior}")
        return malicious_behavior