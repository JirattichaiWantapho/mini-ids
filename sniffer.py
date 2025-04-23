from scapy.all import sniff
from queue import Queue
import threading

class PacketSniffer:
    def __init__(self, packet_queue):
        self.packet_queue = packet_queue
        self.running = False
        self.callback = None # Callback function to process packets
    
    def set_callback(self, callback):
        """Set a callback function to process packets."""
        self.callback = callback

    def start_sniffing(self, iface=None):
        self.running = True
        threading.Thread(target=self._sniff, args=(iface,), daemon=True).start()

    def _sniff(self, iface):
        sniff(prn=self.process_packet, store=0, iface=iface, stop_filter=self.should_stop)

    def stop_sniffing(self):
        self.running = False

    def should_stop(self, pkt):
        return not self.running

    def process_packet(self, packet):
        try:
            self.packet_queue.put(packet)
            if self.callback:
                self.callback(packet)
        except Exception as e:
            print(f"[ERROR] Failed to process packet: {e}")
