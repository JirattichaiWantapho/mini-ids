import tkinter as tk
from tkinter import ttk, messagebox
import threading

class IDSApp:
    def __init__(self, master, sniffer, detectors, logger):
        self.master = master
        self.sniffer = sniffer
        self.detectors = detectors
        self.logger = logger

        self.master.title("Mini IDS")
        self.master.geometry("800x600")

        self.create_widgets()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.master)

        # Live Packets View
        self.live_tab = ttk.Frame(self.tab_control)
        self.packet_list = tk.Text(self.live_tab, height=30)
        self.packet_list.pack(expand=True, fill='both')
        self.tab_control.add(self.live_tab, text='Live Packets')

        # Logs tab
        self.log_tab = ttk.Frame(self.tab_control)
        self.log_text = tk.Text(self.log_tab, height=30)
        self.log_text.pack(expand=True, fill='both')
        self.tab_control.add(self.log_tab, text='Logs')

        # Alerts tab
        self.alert_tab = ttk.Frame(self.tab_control)
        self.alert_list = tk.Text(self.alert_tab, height=30, fg="red")
        self.alert_list.pack(expand=True, fill='both')
        self.tab_control.add(self.alert_tab, text='Alerts')

        # Statistics tab
        self.stats_tab = ttk.Frame(self.tab_control)
        self.stats_text = tk.Text(self.stats_tab, height=30)
        self.stats_text.pack(expand=True, fill='both')
        self.tab_control.add(self.stats_tab, text='Statistics')

        self.tab_control.pack(expand=True, fill='both')

        # Start / Stop buttons
        self.btn_frame = ttk.Frame(self.master)
        self.btn_start = ttk.Button(self.btn_frame, text="Start", command=self.start_ids)
        self.btn_stop = ttk.Button(self.btn_frame, text="Stop", command=self.stop_ids)
        self.btn_start.pack(side='left', padx=10, pady=10)
        self.btn_stop.pack(side='left', padx=10, pady=10)
        self.btn_frame.pack()

    def alert_popup(self, message):
        messagebox.showwarning("Alert", message)
        self.logger.log(message)
        self.log_text.insert(tk.END, f"[ALERT] {message}\n")
        self.log_text.see(tk.END)

    def start_ids(self):
        try:
            self.sniffer.set_callback(self.handle_packet)
            self.sniffer_thread = threading.Thread(target=self.sniffer.start_sniffing)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            self.log_text.insert(tk.END, "[INFO] IDS Started\n")
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
        # แสดงในหน้า GUI
        self.packet_list.insert(tk.END, f"{packet.summary()}\n")
        self.packet_list.see(tk.END)

        for detector in self.detectors:
            detector.analyze(packet)
