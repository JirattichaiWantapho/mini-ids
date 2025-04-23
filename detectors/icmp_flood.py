from scapy.layers.inet import ICMP, IP
import time
from collections import defaultdict

class ICMPFloodDetector:
    def __init__(self, alert_callback, threshold=30, interval=5):
        self.icmp_counts = defaultdict(int)
        self.timestamps = defaultdict(list)
        self.threshold = threshold
        self.interval = interval
        self.alert_callback = alert_callback

    def analyze(self, packet):
        if not packet.haslayer(ICMP):
            return
        print(f"ICMP packet detected: {packet.summary()}")  # พิมพ์ข้อมูลแพ็กเก็ต ICMP
        src_ip = packet[IP].src
        now = time.time()
        self.timestamps[src_ip].append(now)

        # ลบ timestamp เก่าที่อยู่นอกช่วง interval
        self.timestamps[src_ip] = [t for t in self.timestamps[src_ip] if now - t <= self.interval]

        count = len(self.timestamps[src_ip])
        if count >= self.threshold:
            self.alert_callback(
                f"ICMP Flood Detected from {src_ip} ({count} packets in {self.interval} sec)"
            )
            self.timestamps[src_ip].clear()
