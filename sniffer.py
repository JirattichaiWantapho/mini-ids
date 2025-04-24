from scapy.all import sniff
from queue import Queue
import threading

class PacketSniffer:
    def __init__(self, packet_queue):
        self.packet_queue = packet_queue
        self.running = False
        self.callback = None
        self.sniff_thread = None

    def set_callback(self, callback):
        self.callback = callback

    def start_sniffing(self, iface=None, bpf_filter=None):
        if self.running:
            print("[WARN] Sniffer already running")
            return
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff, args=(iface, bpf_filter), daemon=True)
        self.sniff_thread.start()
        print("[INFO] Sniffer started")

    def _sniff(self, iface, bpf_filter):
        try:
            print(f"[INFO] Sniffing on interface: {iface} with filter: {bpf_filter}")
            sniff(prn=self.process_packet, store=0, iface=iface, filter=bpf_filter, stop_filter=self.should_stop)
        except Exception as e:
            print(f"[ERROR] Sniffing error: {e}")

    def stop_sniffing(self):
        if not self.running:
            print("[WARN] Sniffer is not running")
            return
        self.running = False
        print("[INFO] Sniffer stopped")

    def should_stop(self, pkt):
        return not self.running

    def process_packet(self, packet):
        try:
            self.packet_queue.put(packet)
            if self.callback:
                self.callback(packet)
        except Exception as e:
            print(f"[ERROR] Failed to process packet: {e}")
