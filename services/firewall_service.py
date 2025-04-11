import random
from datetime import datetime
from models.packet import Packet
from repositories.firewall_repository import FirewallRepository
from core.utils import get_threat

class FirewallService:
    def __init__(self):
        self.repo = FirewallRepository()

    def analyze_packet(self, packet: Packet):
        ip = packet.src_ip
        threat = get_threat()

        response = {
            "threat_detected": threat["action"] == "BLOCK",
            "threat_type": threat["threat_type"],
            "confidence": threat["confidence"],
            "action": threat["action"],
            "block_cidr": f"{ip}/32" if threat["action"] == "BLOCK" else None
        }

        if response["threat_detected"] and ip not in self.repo.data["blocked_ips"]:
            self.repo.block_ip(ip, threat)

        return response

    def get_firewall_state(self):
        return self.repo.data

    def unblock_ip(self, ip):
        return self.repo.unblock_ip(ip)

    def unblock_all(self):
        return self.repo.unblock_all()

    def manual_block(self, ip):
        return self.repo.manual_block(ip)
