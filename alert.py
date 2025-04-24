import tkinter as tk
from tkinter import messagebox
from webhook.webhook_client import WebhookClient

webhook_client = None

def init_webhook(webhook_url):
    global webhook_client
    webhook_client = WebhookClient(webhook_url)

def alert_console(message):
    print(f"[DEBUG] alert_console called with message: {message}")
    if webhook_client:
        webhook_client.send_alert(message)
    else:
        print("[DEBUG] webhook_client is not initialized")
