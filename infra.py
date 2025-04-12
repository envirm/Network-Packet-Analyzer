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
                print(f"FirewallRepository: Added {ip} to blocked list.")
            else:
                print(f"FirewallRepository: {ip} is already blocked.")

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