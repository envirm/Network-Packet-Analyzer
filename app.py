import subprocess
import threading
import queue
import json
import random
import time
import re
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS



app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return "✅ Flask Firewall Simulator with Multi-Agent System is Running. Use /analyze, /firewall_state, or /unblock/<ip>."

@app.route('/analyze', methods=['POST'])
def analyze_packet():
    # Endpoint to manually analyze a packet using JSON data.
    data = request.get_json()
    if not data or "src_ip" not in data:
        return jsonify({"error": "Invalid packet data."}), 400
    packet = Packet(
        data["src_ip"],
        data.get("dst_ip", ""),
        data.get("protocol", "N/A"),
        data.get("data", {})
    )
    decision = manager_agent.process_packet(packet)
    response = {
        "threat_detected": decision.threat_detected,
        "threat_type": decision.threat_type,
        "confidence": decision.confidence,
        "action": decision.action,
        "block_cidr": decision.block_cidr
    }
    return jsonify(response)

@app.route('/firewall_state', methods=['GET'])
def get_firewall_state():
    return jsonify(firewall_repo.get_state())

@app.route('/unblock/<ip>', methods=['DELETE'])
def unblock_ip(ip):
    if firewall_repo.unblock_ip(ip):
        return jsonify({"status": "success", "message": f"{ip} unblocked."})
    else:
        return jsonify({"status": "not_found", "message": f"{ip} is not currently blocked."}), 404

if __name__ == '__main__':
    app.run(debug=True)
