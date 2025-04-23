import tkinter as tk
from sniffer import PacketSniffer
from detectors.icmp_flood import ICMPFloodDetector
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SYNFloodDetector
from detectors.brute_force import BruteForceDetector
from logger import Logger
from gui import IDSApp
from alert import alert_console
from queue import Queue
import time

# เตรียม Logger
logger = Logger()

# เตรียม Alert Callback
def alert_callback(message):
    alert_console(message)  # แสดงใน console
    app.alert_popup(message)  # แสดงใน GUI

# เตรียม Packet Queue และ Sniffer
packet_queue = Queue()
sniffer = PacketSniffer(packet_queue)

# เตรียม Detectors
icmp_flood_detector = ICMPFloodDetector(alert_callback)
port_scan_detector = PortScanDetector(alert_callback)
syn_flood_detector = SYNFloodDetector(alert_callback)
brute_force_detector = BruteForceDetector(alert_callback)

detectors = [icmp_flood_detector, port_scan_detector, syn_flood_detector, brute_force_detector]

# สร้าง GUI
root = tk.Tk()
app = IDSApp(root, sniffer, detectors, logger)

# เริ่ม GUI
root.mainloop()


print("[+] Sniffer started. Press Ctrl+C to stop.")
