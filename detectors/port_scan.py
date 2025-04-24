from scapy.layers.inet import TCP, IP
from collections import defaultdict
import time

class PortScanDetector:
    def __init__(self, alert_callback, threshold=10, interval=5):
        self.scan_data = defaultdict(list)
        self.threshold = threshold
        self.interval = interval
        self.alert_callback = alert_callback

    def analyze(self, packet):
        if not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        now = time.time()

        self.scan_data[src_ip].append((dst_port, now))

        self.scan_data[src_ip] = [
            (port, timestamp) for port, timestamp in self.scan_data[src_ip]
            if now - timestamp <= self.interval
        ]

        scanned_ports = {port for port, _ in self.scan_data[src_ip]}
        if len(scanned_ports) >= self.threshold:
            self.alert_callback(
                f"Port Scan Detected from {src_ip} ({len(scanned_ports)} ports in {self.interval} sec)"
            )
            self.scan_data[src_ip].clear()