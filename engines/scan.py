from flask import Flask, request, jsonify
import hashlib
import os
import requests
import threading

app = Flask(__name__)

# Mock database for storing scan results
scan_results = {}

# Mock signature database
signature_db = {
    "malware1": "hash_of_malware1",
    "malware2": "hash_of_malware2"
}

# Mock heuristic rules
heuristic_rules = [
    {"pattern": "suspicious_pattern1", "score": 50},
    {"pattern": "suspicious_pattern2", "score": 30}
]

# Helper function to calculate file hash
def calculate_file_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Signature-based detection
def signature_based_detection(file_path):
    file_hash = calculate_file_hash(file_path)
    for malware, hash_value in signature_db.items():
        if file_hash == hash_value:
            return {"result": "Malware detected", "malware": malware}
    return {"result": "No malware detected"}

# Heuristic analysis
def heuristic_analysis(file_path):
    with open(file_path, 'r') as f:
        file_content = f.read()
        for rule in heuristic_rules:
            if rule["pattern"] in file_content:
                return {"result": "Suspicious pattern detected", "score": rule["score"]}
    return {"result": "No suspicious pattern detected"}

# Behavioral analysis (pseudo method)
def behavioral_analysis(process_id):
    # Simulate behavioral analysis
    # In a real scenario, this would involve monitoring the process behavior
    return {"result": "Behavioral analysis completed", "process_id": process_id}

# Scan a file
@app.route('/scan', methods=['POST'])
def scan_file():
    file = request.files['file']
    file_path = os.path.join('/tmp', file.filename)
    file.save(file_path)

    signature_result = signature_based_detection(file_path)
    heuristic_result = heuristic_analysis(file_path)

    scan_id = hashlib.md5(file_path.encode()).hexdigest()
    scan_results[scan_id] = {
        "file_path": file_path,
        "signature_result": signature_result,
        "heuristic_result": heuristic_result
    }

    # Trigger behavioral analysis in a separate thread
    threading.Thread(target=lambda: behavioral_analysis(scan_id)).start()

    return jsonify({"scan_id": scan_id, "results": scan_results[scan_id]})

# Get scan results
@app.route('/scan/results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({"error": "Scan ID not found"}), 404

# Get scan status
@app.route('/scan/status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    if scan_id in scan_results:
        return jsonify({"status": "Completed" if "behavioral_result" in scan_results[scan_id] else "In Progress"})
    else:
        return jsonify({"error": "Scan ID not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)