import json
from datetime import datetime

class FirewallRepository:
    def __init__(self):
        self.file_path = "data/firewall_state.json"
        try:
            with open(self.file_path, "r") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            self.data = {"blocked_ips": [], "log": []}
            self._save()

    def _save(self):
        with open(self.file_path, "w") as f:
            json.dump(self.data, f, indent=4)

    def block_ip(self, ip, threat):
        self.data["blocked_ips"].append(ip)
        self.data["log"].append({
            "event": "Blocked IP",
            "ip": ip,
            "reason": threat["threat_type"],
            "confidence": threat["confidence"],
            "action": threat["action"],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        self._save()

    def unblock_ip(self, ip):
        if ip in self.data["blocked_ips"]:
            self.data["blocked_ips"].remove(ip)
            self.data["log"].append({
                "event": "Unblocked IP",
                "ip": ip,
                "reason": "Manual unblock",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            self._save()
            return {"message": f"{ip} unblocked."}
        else:
            raise ValueError(f"{ip} not found.")

    def unblock_all(self):
        self.data["log"].append({
            "event": "Unblocked All",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        self.data["blocked_ips"] = []
        self._save()
        return {"message": "All IPs unblocked."}

    def manual_block(self, ip):
        if ip not in self.data["blocked_ips"]:
            self.data["blocked_ips"].append(ip)
            self.data["log"].append({
                "event": "Manually Blocked IP",
                "ip": ip,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            self._save()
        return {"message": f"{ip} blocked manually."}
