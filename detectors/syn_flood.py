from scapy.layers.inet import TCP, IP
from collections import defaultdict
import time

class SYNFloodDetector:
    def __init__(self, alert_callback, threshold=100, interval=5):
        self.syn_counts = defaultdict(int)
        self.timestamps = defaultdict(list)
        self.threshold = threshold
        self.interval = interval
        self.alert_callback = alert_callback

    def analyze(self, packet):
        if not packet.haslayer(TCP) or packet[TCP].flags != "S":
            return

        src_ip = packet[IP].src
        now = time.time()
        self.timestamps[src_ip].append(now)

        # ลบ timestamp เก่าที่อยู่นอกช่วง interval
        self.timestamps[src_ip] = [t for t in self.timestamps[src_ip] if now - t <= self.interval]

        count = len(self.timestamps[src_ip])
        if count >= self.threshold:
            self.alert_callback(
                f"SYN Flood Detected from {src_ip} ({count} SYN packets in {self.interval} sec)"
            )
            self.timestamps[src_ip].clear()