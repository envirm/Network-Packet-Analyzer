# Start background threads for packet capture and processing.
import threading


threading.Thread(target=capture_thread, daemon=True).start()
threading.Thread(target=processing_thread, daemon=True).start()