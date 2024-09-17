import json

class SignatureDatabase:
    def __init__(self, signature_file='signatures.json'):
        self.signatures = self._load_signatures(signature_file)

    def _load_signatures(self, signature_file):
        try:
            with open(signature_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Signature file {signature_file} not found. Using empty database.")
            return {}

    def check_signature(self, file_hash):
        return self.signatures.get(file_hash)

    def add_signature(self, file_hash, malware_name):
        self.signatures[file_hash] = malware_name

    def save_signatures(self, signature_file='signatures.json'):
        with open(signature_file, 'w') as f:
            json.dump(self.signatures, f, indent=2)