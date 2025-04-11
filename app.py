import random
import json
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app = Flask(__name__)

try:
    with open("firewall_state.json", "r") as f:
        firewall_state = json.load(f)
except FileNotFoundError:
    firewall_state = {"blocked_ips": [], "log": []}

# Define threat types
THREAT_SCENARIOS = [
    {
        "threat_type": "TCP SYN Flood Attack",
        "confidence": "High",
        "action": "BLOCK"
    },
    {
        "threat_type": "Slowloris DoS Attack",
        "confidence": "High",
        "action": "BLOCK"
    },
    {
        "threat_type": "SQL Injection Attempt",
        "confidence": "High",
        "action": "BLOCK"
    },
    {
        "threat_type": "Suspicious SSH Brute Force",
        "confidence": "High",
        "action": "BLOCK"
    },
    {
        "threat_type": "Excessive ICMP Requests (Ping Flood)",
        "confidence": "High",
        "action": "BLOCK"
    },
    {
        "threat_type": "Outbound Data Exfiltration (Beaconing)",
        "confidence": "High",
        "action": "BLOCK"
    },
    {
        "threat_type": "Normal traffic",
        "confidence": "Low",
        "action": "ALLOW"
    }
]


def save_firewall_state():
    with open("firewall_state.json", "w") as f:
        json.dump(firewall_state, f, indent=4)


@app.route('/analyze', methods=['POST'])
def analyze_packet():
    packet = request.get_json()

    # Simulate detection
    threat = random.choice(THREAT_SCENARIOS)
    ip = packet["src_ip"]

    response = {
        "threat_detected": threat["action"] == "BLOCK",
        "threat_type": threat["threat_type"],
        "confidence": threat["confidence"],
        "action": threat["action"],
        "block_cidr": f"{ip}/32" if threat["action"] == "BLOCK" else None
    }

    # Log and block
    if response["threat_detected"] and ip not in firewall_state["blocked_ips"]:
        firewall_state["blocked_ips"].append(ip)
        firewall_state["log"].append({
            "event": "Blocked IP",
            "ip": ip,
            "reason": threat["threat_type"],
            "confidence": threat["confidence"],
            "action": threat["action"],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        save_firewall_state()

    return jsonify(response)

@app.route('/firewall_state', methods=['GET'])
def get_firewall_state():
    return jsonify(firewall_state)

if __name__ == '__main__':
    app.run(debug=True)
