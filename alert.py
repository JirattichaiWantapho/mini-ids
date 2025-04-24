import tkinter as tk
from tkinter import messagebox
from webhook.webhook_client import WebhookClient

# Webhook configuration
webhook_client = None

def init_webhook(webhook_url):
    """Initialize webhook client"""
    global webhook_client
    webhook_client = WebhookClient(webhook_url)

def alert_console(message):
    """Show alert in console and send to webhook"""
    print(f"[ALERT] {message}")
    if webhook_client:
        webhook_client.send_alert(message)
