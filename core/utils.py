import random

THREAT_SCENARIOS = [
    {"threat_type": "TCP SYN Flood Attack", "confidence": "High", "action": "BLOCK"},
    {"threat_type": "Slowloris DoS Attack", "confidence": "High", "action": "BLOCK"},
    {"threat_type": "SQL Injection Attempt", "confidence": "High", "action": "BLOCK"},
    {"threat_type": "Suspicious SSH Brute Force", "confidence": "High", "action": "BLOCK"},
    {"threat_type": "Excessive ICMP Requests (Ping Flood)", "confidence": "High", "action": "BLOCK"},
    {"threat_type": "Outbound Data Exfiltration (Beaconing)", "confidence": "High", "action": "BLOCK"},
    {"threat_type": "Normal traffic", "confidence": "Low", "action": "ALLOW"},
]

def get_threat():
    return random.choice(THREAT_SCENARIOS)
