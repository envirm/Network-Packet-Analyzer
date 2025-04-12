# Create TShark capture instance to push packets into our pipeline.
from app import TSharkCapture


ts_capture = TSharkCapture(interface="eth0", filter_expr="ip", queue_obj=pipeline.get_queue())

def capture_thread():
    ts_capture.start_capture()

def processing_thread():
    while True:
        try:
            packet = pipeline.get_queue().get(timeout=1)
            decision = manager_agent.process_packet(packet)
            print(f"[{packet.timestamp}] Processed packet from {packet.src_ip} -> Decision: {decision.threat_type}")
        except queue.Empty:
            continue