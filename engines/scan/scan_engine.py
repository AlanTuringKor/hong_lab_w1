from flask import Flask, request, jsonify
import pika
import hashlib
import os
import threading

app = Flask(__name__)

# RabbitMQ configuration
RABBITMQ_HOST = 'localhost'
QUEUE_NAME = 'scan_queue'

# Mock database for storing scan results
scan_results = {}

# Mock signature database
signature_db = {
    "malware1": "hash_of_malware1",
    "malware2": "hash_of_malware2"
}

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
def behavioral_analysis(scan_id):
    # Simulate behavioral analysis
    # In a real scenario, this would involve monitoring the process behavior
    scan_results[scan_id]["behavioral_result"] = {"result": "Behavioral analysis completed", "scan_id": scan_id}

# Function to publish scan task to RabbitMQ
def publish_scan_task(scan_id, file_path):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME)
    channel.basic_publish(exchange='', routing_key=QUEUE_NAME, body=f"{scan_id}|{file_path}")
    connection.close()

# Function to consume scan tasks from RabbitMQ
def consume_scan_tasks():
    def callback(ch, method, properties, body):
        scan_id, file_path = body.decode().split('|')
        signature_result = signature_based_detection(file_path)
        heuristic_result = heuristic_analysis(file_path)
        scan_results[scan_id].update({
            "file_path": file_path,
            "signature_result": signature_result,
            "heuristic_result": heuristic_result
        })
        threading.Thread(target=lambda: behavioral_analysis(scan_id)).start()
        ch.basic_ack(delivery_tag=method.delivery_tag)

    connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)
    channel.start_consuming()

# Start the RabbitMQ consumer in a separate thread
threading.Thread(target=consume_scan_tasks).start()

# Scan a file
@app.route('/scan', methods=['POST'])
def scan_file():
    file = request.files['file']
    file_path = os.path.join('/tmp', file.filename)
    file.save(file_path)

    scan_id = hashlib.md5(file_path.encode()).hexdigest()
    scan_results[scan_id] = {}

    publish_scan_task(scan_id, file_path)

    return jsonify({"scan_id": scan_id})

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