import tkinter as tk
from tkinter import messagebox

def alert_console(message):
    """แสดงข้อความแจ้งเตือนใน console"""
    print(f"[ALERT] {message}")

def alert_popup(self, message):
    """แสดงข้อความแจ้งเตือนใน GUI"""
    messagebox.showwarning("Alert", message)
    self.logger.log(message)
    self.log_text.insert(tk.END, f"[ALERT] {message}\n")
    self.log_text.see(tk.END)

    # เพิ่มข้อความแจ้งเตือนในแท็บ Alerts
    self.alert_list.insert(tk.END, f"{message}\n")
    self.alert_list.see(tk.END)