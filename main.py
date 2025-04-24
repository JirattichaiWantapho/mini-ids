import tkinter as tk
from sniffer import PacketSniffer
from detectors.icmp_flood import ICMPFloodDetector
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SYNFloodDetector
from detectors.brute_force import BruteForceDetector
from logger import Logger
from gui import IDSApp
from alert import alert_console, init_webhook
from queue import Queue
import time

WEBHOOK_URL = "https://mini-ids-webhook.onrender.com/webhook"

init_webhook(WEBHOOK_URL)

logger = Logger()

def alert_callback(message):
    print(f"[DEBUG] alert_callback called with message: {message}")
    alert_console(message)
    app.alert_popup(message)

packet_queue = Queue()
sniffer = PacketSniffer(packet_queue)

icmp_flood_detector = ICMPFloodDetector(alert_callback)
port_scan_detector = PortScanDetector(alert_callback)
syn_flood_detector = SYNFloodDetector(alert_callback)
brute_force_detector = BruteForceDetector(alert_callback)

detectors = [icmp_flood_detector, port_scan_detector, syn_flood_detector, brute_force_detector]

root = tk.Tk()
app = IDSApp(root, sniffer, detectors, logger)

root.mainloop()

print("[+] Sniffer started. Press Ctrl+C to stop.")
