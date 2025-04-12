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