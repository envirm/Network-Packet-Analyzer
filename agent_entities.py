class ModelAgent:
    """
    Agent that analyzes packets by extracting features and invoking the threat detector.
    """
    def __init__(self, detector: ThreatDetector):
        self.detector = detector

    def analyze_packet(self, packet: Packet) -> ThreatDecision:
        # Extract features to be analyzed by the threat detector.
        features = {
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "protocol": packet.protocol,
            "frame_length": int(packet.data.get("length", "0"))
        }
        decision = self.detector.evaluate(features)
        print(f"ModelAgent: Analyzed packet from {packet.src_ip} -> Decision: {decision.threat_type}")
        return decision

class FirewallAgent:
    """
    Agent that handles firewall actions such as blocking IP addresses.
    """
    def __init__(self, firewall_repo: FirewallRepository):
        self.firewall_repo = firewall_repo

    def block_ip(self, ip: str, decision: ThreatDecision):
        reason = decision.threat_type
        confidence = decision.confidence
        action = decision.action
        print(f"FirewallAgent: Blocking IP {ip} due to {reason} (Confidence: {confidence}).")
        self.firewall_repo.add_blocked_ip(ip, reason, confidence, action)

class ManagerAgent:
    """
    Manager that coordinates between the ModelAgent and the FirewallAgent.
    """
    def __init__(self, model_agent: ModelAgent, firewall_agent: FirewallAgent):
        self.model_agent = model_agent
        self.firewall_agent = firewall_agent

    def process_packet(self, packet: Packet) -> ThreatDecision:
        # Use ModelAgent to analyze the packet.
        decision = self.model_agent.analyze_packet(packet)
        # If a threat is detected, instruct FirewallAgent to block the source IP.
        if decision.threat_detected:
            self.firewall_agent.block_ip(packet.src_ip, decision)
        else:
            print(f"ManagerAgent: No threat detected for packet from {packet.src_ip}.")
        return decision