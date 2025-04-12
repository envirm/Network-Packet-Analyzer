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

#########################
# Domain Layer
#########################
class Packet:
    def __init__(self, src_ip, dst_ip, protocol, data, timestamp=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.data = data
        self.timestamp = timestamp or datetime.utcnow().isoformat() + "Z"

class ThreatDecision:
    def __init__(self, threat_detected, threat_type, confidence, action, block_cidr=None):
        self.threat_detected = threat_detected
        self.threat_type = threat_type
        self.confidence = confidence
        self.action = action
        self.block_cidr = block_cidr

#########################
# Infrastructure Layer
#########################
class FirewallRepository:
    """Persists firewall state in a JSON file."""
    def __init__(self, filepath="firewall_state.json"):
        self.filepath = filepath
        try:
            with open(filepath, "r") as f:
                self.state = json.load(f)
        except FileNotFoundError:
            self.state = {"blocked_ips": [], "log": []}
        self.lock = threading.Lock()

    def add_blocked_ip(self, ip, reason, confidence, action):
        with self.lock:
            if ip not in self.state["blocked_ips"]:
                self.state["blocked_ips"].append(ip)
                log_entry = {
                    "event": "Blocked IP",
                    "ip": ip,
                    "reason": reason,
                    "confidence": confidence,
                    "action": action,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                self.state["log"].append(log_entry)
                self.save()

    def unblock_ip(self, ip):
        with self.lock:
            if ip in self.state["blocked_ips"]:
                self.state["blocked_ips"].remove(ip)
                log_entry = {
                    "event": "Unblocked IP",
                    "ip": ip,
                    "reason": "Manual unblock",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                self.state["log"].append(log_entry)
                self.save()
                return True
            return False

    def get_state(self):
        with self.lock:
            return self.state

    def save(self):
        with open(self.filepath, "w") as f:
            json.dump(self.state, f, indent=4)

class TSharkCapture:
    """Uses TShark to capture packets and stream them into a pipeline queue."""
    def __init__(self, interface="eth0", filter_expr="ip", queue_obj=None):
        self.interface = interface
        self.filter_expr = filter_expr
        self.queue = queue_obj
        self.running = False

    def start_capture(self):
        self.running = True
        cmd = [
            "tshark",
            "-i", self.interface,
            "-f", self.filter_expr,
            "-l",              # Enable line-buffered output
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len"
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while self.running:
            line = proc.stdout.readline()
            if line:
                line = line.strip()
                if line:
                    # Parse TShark output (assumed to be whitespace separated)
                    fields = re.split(r'\s+', line)
                    if len(fields) >= 4:
                        src_ip, dst_ip, protocol, length = fields[:4]
                        packet = Packet(src_ip, dst_ip, protocol, data={"length": length})
                        self.queue.put(packet)
            else:
                time.sleep(0.1)
        proc.terminate()

    def stop_capture(self):
        self.running = False

class PacketPipeline:
    """A simple pipeline using a thread-safe queue to stream packets."""
    def __init__(self):
        self.queue = queue.Queue()

    def get_queue(self):
        return self.queue

#########################
# Use-Case (Application) Layer
#########################
class PacketProcessor:
    """Processes packets: extracts features, invokes threat detection, and triggers firewall actions."""
    def __init__(self, detector, firewall_repo):
        self.detector = detector
        self.firewall_repo = firewall_repo

    def process_packet(self, packet):
        # Feature extraction – in a real scenario, more sophisticated processing would occur.
        features = {
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "protocol": packet.protocol,
            "frame_length": int(packet.data.get("length", "0"))
        }
        decision = self.detector.evaluate(features)
        if decision.threat_detected:
            self.firewall_repo.add_blocked_ip(packet.src_ip, decision.threat_type, decision.confidence, decision.action)
        return decision

#########################
# Agent / Domain Logic
#########################
class ThreatDetector:
    """Simulates an AI-based threat detector.
    
       In a production system, this class would load a pre-trained machine learning model
       (for example, using scikit-learn, TensorFlow, or PyTorch) and evaluate packet features.
    """
    def __init__(self):
        self.THREAT_SCENARIOS = [
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

    def evaluate(self, features):
        # Here, a machine learning model would process the features.
        # For this example, we use a random choice to simulate a decision.
        threat = random.choice(self.THREAT_SCENARIOS)
        threat_detected = threat["action"] == "BLOCK"
        block_cidr = f"{features['src_ip']}/32" if threat_detected else None
        return ThreatDecision(
            threat_detected=threat_detected,
            threat_type=threat["threat_type"],
            confidence=threat["confidence"],
            action=threat["action"],
            block_cidr=block_cidr
        )

#########################
# Background Worker Threads
#########################
# Initialize repository, pipeline, detector, and processor.
firewall_repo = FirewallRepository()
pipeline = PacketPipeline()
detector = ThreatDetector()
processor = PacketProcessor(detector, firewall_repo)

# Create TShark capture instance to push packets into our pipeline.
ts_capture = TSharkCapture(interface="eth0", filter_expr="ip", queue_obj=pipeline.get_queue())

def capture_thread():
    ts_capture.start_capture()

def processing_thread():
    while True:
        try:
            packet = pipeline.get_queue().get(timeout=1)
            decision = processor.process_packet(packet)
            print(f"[{packet.timestamp}] Processed packet from {packet.src_ip} -> Decision: {decision.threat_type}")
        except queue.Empty:
            continue

# Start background threads for capture and processing.
threading.Thread(target=capture_thread, daemon=True).start()
threading.Thread(target=processing_thread, daemon=True).start()

#########################
# Presentation Layer (Flask API)
#########################
app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return "✅ Flask Firewall Simulator with Clean Architecture is Running. Use /analyze, /firewall_state, or /unblock/<ip>."

@app.route('/analyze', methods=['POST'])
def analyze_packet():
    # This endpoint allows manual analysis by posting packet JSON data.
    data = request.get_json()
    if not data or "src_ip" not in data:
        return jsonify({"error": "Invalid packet data."}), 400
    packet = Packet(data["src_ip"], data.get("dst_ip", ""), data.get("protocol", "N/A"), data.get("data", {}))
    decision = processor.process_packet(packet)
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
