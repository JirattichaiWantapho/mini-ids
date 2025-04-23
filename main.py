import tkinter as tk
from sniffer import PacketSniffer
from detectors.icmp_flood import ICMPFloodDetector
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
detectors = [icmp_flood_detector]

# สร้าง GUI
root = tk.Tk()
app = IDSApp(root, sniffer, detectors, logger)

# เริ่ม GUI
root.mainloop()


print("[+] Sniffer started. Press Ctrl+C to stop.")
