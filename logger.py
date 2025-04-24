import datetime
from collections import defaultdict
from scapy.all import TCP, UDP, ICMP, IP

class Logger:
    def __init__(self, log_file="ids.log"):
        self.log_file = log_file
        self.packet_count = 0
        self.packet_types = defaultdict(int)
        self.src_ips = defaultdict(int)
        self.dst_ips = defaultdict(int)

    def log(self, message, level="INFO"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}\n"
        with open(self.log_file, "a") as f:
            f.write(log_message)
        return log_message

    def log_packet(self, packet):
        self.packet_count += 1
        
        if packet.haslayer(TCP):
            self.packet_types["TCP"] += 1
        elif packet.haslayer(UDP):
            self.packet_types["UDP"] += 1
        elif packet.haslayer(ICMP):
            self.packet_types["ICMP"] += 1
        
        if packet.haslayer(IP):
            self.src_ips[packet[IP].src] += 1
            self.dst_ips[packet[IP].dst] += 1

        stats = (
            f"Packet #{self.packet_count} | "
            f"Type: {packet.summary()} | "
            f"Total TCP: {self.packet_types['TCP']}, "
            f"UDP: {self.packet_types['UDP']}, "
            f"ICMP: {self.packet_types['ICMP']}"
        )
        return self.log("PACKET", stats)

    def get_statistics(self):
        stats = (
            f"Total Packets: {self.packet_count}\n"
            f"Packet Types: {dict(self.packet_types)}\n"
            f"Top Source IPs: {sorted(self.src_ips.items(), key=lambda x: x[1], reverse=True)[:5]}\n"
            f"Top Destination IPs: {sorted(self.dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]}"
        )
        return stats