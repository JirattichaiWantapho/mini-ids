from collections import defaultdict
import time

class BruteForceDetector:
    def __init__(self, alert_callback, threshold=5, interval=10):
        self.login_attempts = defaultdict(list)
        self.threshold = threshold
        self.interval = interval
        self.alert_callback = alert_callback

    def analyze(self, packet):
        # สมมติว่า packet มีข้อมูลเกี่ยวกับการพยายามล็อกอิน
        if not hasattr(packet, "login_attempt"):
            return

        src_ip = packet.src_ip
        now = time.time()
        self.login_attempts[src_ip].append(now)

        # ลบข้อมูลเก่าที่อยู่นอกช่วงเวลา
        self.login_attempts[src_ip] = [
            t for t in self.login_attempts[src_ip] if now - t <= self.interval
        ]

        if len(self.login_attempts[src_ip]) >= self.threshold:
            self.alert_callback(
                f"Brute Force Attack Detected from {src_ip} ({len(self.login_attempts[src_ip])} attempts in {self.interval} sec)"
            )
            self.login_attempts[src_ip].clear()