from flask import Flask, request, jsonify
from utils.logger import setup_logger

class API:
    def __init__(self, av_core):
        self.av_core = av_core
        self.logger = setup_logger()
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        @self.app.route('/scan', methods=['POST'])
        def scan():
            path = request.json.get('path')
            if not path:
                return jsonify({"error": "No path provided"}), 400
            threats = self.av_core.scan(path)
            return jsonify({"threats": threats})

        @self.app.route('/update', methods=['POST'])
        def update():
            updated = self.av_core.update()
            return jsonify({"updated": updated})

    def start(self):
        self.logger.info("Starting API server")
        self.app.run(debug=False, host='0.0.0.0', port=5000)