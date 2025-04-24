import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP

class IDSApp:
    def __init__(self, master, sniffer, detectors, logger):
        self.master = master
        self.sniffer = sniffer
        self.detectors = detectors
        self.logger = logger
        self.alert_popup = self.show_alert 

        self.master.title("Mini IDS")
        self.master.geometry("900x650")

        self.create_widgets()

    def create_widgets(self):
        main_pane = tk.PanedWindow(self.master, orient=tk.VERTICAL)
        main_pane.pack(expand=True, fill='both')

        upper_pane = tk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
    
        live_frame = ttk.LabelFrame(upper_pane, text="Live Packets")
        live_header = ttk.Frame(live_frame)
        live_header.pack(fill='x', padx=5, pady=2)
        ttk.Button(live_header, text="Clear", command=lambda: self.packet_list.delete(1.0, tk.END)).pack(side='right')
        self.packet_list = tk.Text(live_frame, height=20)
        self.packet_list.pack(expand=True, fill='both', padx=5, pady=5)
        upper_pane.add(live_frame)

        alert_frame = ttk.LabelFrame(upper_pane, text="Alerts")
        alert_header = ttk.Frame(alert_frame)
        alert_header.pack(fill='x', padx=5, pady=2)
        ttk.Button(alert_header, text="Clear", command=lambda: self.alert_list.delete(1.0, tk.END)).pack(side='right')
        self.alert_list = tk.Text(alert_frame, height=20, fg="red")
        self.alert_list.pack(expand=True, fill='both', padx=5, pady=5)
        upper_pane.add(alert_frame)

        main_pane.add(upper_pane)

        log_frame = ttk.LabelFrame(main_pane, text="Logs")
        log_header = ttk.Frame(log_frame)
        log_header.pack(fill='x', padx=5, pady=2)
        ttk.Button(log_header, text="Clear", command=lambda: self.log_text.delete(1.0, tk.END)).pack(side='right')
        self.log_text = tk.Text(log_frame, height=10)
        self.log_text.pack(expand=True, fill='both', padx=5, pady=5)
        main_pane.add(log_frame)

        control_frame = ttk.LabelFrame(self.master, text="Sniffing Control")
        control_frame.pack(fill='x', padx=10, pady=10)

        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.interface_entry = ttk.Entry(control_frame)
        self.interface_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(control_frame, text="Filter:").grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.filter_entry = ttk.Entry(control_frame, width=40)
        self.filter_entry.grid(row=0, column=3, padx=5, pady=5)

        self.btn_start = ttk.Button(control_frame, text="Start", command=self.start_ids)
        self.btn_start.grid(row=0, column=4, padx=10, pady=5)

        self.btn_stop = ttk.Button(control_frame, text="Stop", command=self.stop_ids)
        self.btn_stop.grid(row=0, column=5, padx=10, pady=5)

    def show_alert(self, message):
        self.logger.log(message)
        self.log_text.insert(tk.END, f"[ALERT] {message}\n")
        self.log_text.see(tk.END)
        self.alert_list.insert(tk.END, f"[ALERT] {message}\n") 
        self.alert_list.see(tk.END)
        
    def start_ids(self):
        iface = self.interface_entry.get().strip() or None
        bpf_filter = self.filter_entry.get().strip() or None
        try:
            self.sniffer.set_callback(self.handle_packet)
            self.sniffer_thread = threading.Thread(target=self.sniffer.start_sniffing, kwargs={
                'iface': iface,
                'bpf_filter': bpf_filter
            })
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            self.log_text.insert(tk.END, "[INFO] IDS Started\n")
            self.update_statistics()
        except Exception as e:
            self.log_text.insert(tk.END, f"[ERROR] Failed to start IDS: {e}\n")
            self.log_text.see(tk.END)

    def stop_ids(self):
        try:
            self.sniffer.stop_sniffing()
            self.log_text.insert(tk.END, "[INFO] IDS Stopped\n")
        except Exception as e:
            self.log_text.insert(tk.END, f"[ERROR] Failed to stop IDS: {e}\n")
            self.log_text.see(tk.END)

    def handle_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "Other"
            
            if protocol in ["TCP", "UDP"]:
                layer = packet[TCP] if protocol == "TCP" else packet[UDP]
                src_port = layer.sport
                dst_port = layer.dport

                src_port = "https" if src_port == 443 else src_port
                dst_port = "https" if dst_port == 443 else dst_port
                packet_info = f"[{protocol}] {src_ip}:{src_port} → {dst_ip}:{dst_port}"
            else:
                packet_info = f"[{protocol}] {src_ip} → {dst_ip}"
            
            if protocol == "TCP":
                flags = []
                if packet[TCP].flags.A: flags.append("ACK")
                if packet[TCP].flags.S: flags.append("SYN")
                if packet[TCP].flags.F: flags.append("FIN")
                if packet[TCP].flags.R: flags.append("RST")
                if packet[TCP].flags.P: flags.append("PSH")
                if flags:
                    packet_info += f" [{','.join(flags)}]"

            timestamp = time.strftime("%H:%M:%S")
            formatted_packet = f"[{timestamp}] {packet_info}\n"
            
            self.packet_list.insert(tk.END, formatted_packet)
            self.packet_list.see(tk.END)

        self.logger.log_packet(packet)

        for detector in self.detectors:
            detector.analyze(packet)

    def update_statistics(self):
        stats = (
            "\n=== Statistics Update ===\n"
            f"Packets Captured: {self.logger.packet_count}\n"
            f"Protocol Distribution:\n"
            f"  TCP: {self.logger.packet_types['TCP']}\n"
            f"  UDP: {self.logger.packet_types['UDP']}\n"
            f"  ICMP: {self.logger.packet_types['ICMP']}\n"
            f"Top Source IPs (top 5):\n"
            f"{self._format_ip_stats(self.logger.src_ips)}\n"
            f"Top Destination IPs (top 5):\n"
            f"{self._format_ip_stats(self.logger.dst_ips)}\n"
            "========================\n"
        )
        self.log_text.insert(tk.END, stats)
        self.log_text.see(tk.END)
        self.master.after(5000, self.update_statistics)

    def _format_ip_stats(self, ip_dict):
        sorted_ips = sorted(ip_dict.items(), key=lambda x: x[1], reverse=True)[:5]
        return "\n".join([f"  {ip}: {count} packets" for ip, count in sorted_ips])
