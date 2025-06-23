import subprocess
import smtplib
import ssl
import time
import os
import json
import threading
from datetime import datetime
from flask import Flask, render_template_string, jsonify

import psutil

# === CONFIGURATION ===
SMTP_SERVER = '127.0.0.1'
SMTP_PORT = 1025
USERNAME = 'mojosindex@protonmail.com'
PASSWORD = '64PERLi7pFO30gWLGv5i8g'
FROM = USERNAME
TO = 'nate.mcdonald@att.net'

P2POOL_DIR = "X:\\Programs\\p2pool-v4.8-windows-x64"
P2POOL_EXE = "p2pool_min_payout_mod.exe"
WALLET = "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
LOG_FILE = os.path.join(P2POOL_DIR, "p2pool_log.txt")

latest_events = []

# === EMAIL FUNCTION ===
def send_email(subject, body):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"""\
From: {FROM}
To: {TO}
Subject: {subject}

[{timestamp}]
{body}
"""
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(USERNAME, PASSWORD)
            server.sendmail(FROM, TO, message)
            print(f"[+] Email sent ({subject})")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")
import re

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


# === MONITOR FUNCTION ===
def monitor_log():
    global latest_events

    print(f"[~] Waiting for '{LOG_FILE}'...")
    while not os.path.exists(LOG_FILE):
        time.sleep(1)

    print("[+] Monitoring p2pool_log.txt...")
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue

            clean_line = strip_ansi_codes(line).strip()
            l = clean_line.lower()
            event = None

            if "sidechain verified block" in l:
                event = "Sidechain Verified Block"
            elif "sidechain new chain tip" in l:
                event = "Sidechain New Chain Tip"
            elif "blocktemplate final reward" in l:
                event = "Final Block Reward"
            elif "found share" in l:
                event = "Found Share"
                send_email("Found Share", "Share has been found.")
            elif "found block" in l:
                event = "Found Block"
                send_email("Found Block", "Block has been found.")
            elif "p2pool caught sigint" in l or "p2pool stopping" in l:
                event = "P2Pool Stopped"

            if event:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                latest_events.insert(0, {"time": timestamp, "event": event, "line": line.strip()})
                latest_events = latest_events[:50]


# === START P2POOL IN ADMIN POWERSHELL ===
def start_p2pool():
    ps1_path = os.path.join(P2POOL_DIR, "launch_p2pool.ps1")
    log_path = os.path.join(P2POOL_DIR, "p2pool_log.txt")
    err_log = os.path.join(P2POOL_DIR, "p2pool_error_log.txt")

    ps_script = f"""
cd \"{P2POOL_DIR}\"
try {{
    .\\{P2POOL_EXE} --host 127.0.0.1 --wallet {WALLET} --mini --stratum 192.168.0.10:3333 --no-upnp 2>&1 |
    Tee-Object -FilePath \"{log_path}\"
}} catch {{
    $_ | Out-File \"{err_log}\" -Append
}}
pause
"""

    with open(ps1_path, "w") as f:
        f.write(ps_script)

    print(f"[~] Saved PowerShell launch script to {ps1_path}")
    try:
        subprocess.run([
            "powershell", "-Command",
            f"Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File \"{ps1_path}\"' -Verb RunAs"
        ])
    except Exception as e:
        print(f"[!] Failed to launch admin PowerShell: {e}")

# === FLASK SERVER ===
app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html><head><title>P2Pool Events</title>
<meta http-equiv="refresh" content="10">
<style>
body { font-family: Arial; margin: 40px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background-color: #444; color: white; }
</style></head>
<body>
<h2>P2Pool Event Monitor</h2>
<table>
<tr><th>Time</th><th>Event</th><th>Message</th></tr>
{% for e in events %}
<tr><td>{{ e.time }}</td><td>{{ e.event }}</td><td>{{ e.line }}</td></tr>
{% endfor %}
</table>
</body></html>
"""

@app.route("/")
def index():
    return render_template_string(HTML, events=latest_events)

def start_flask():
    app.run(host="0.0.0.0", port=5000)

# === MAIN ===
if __name__ == "__main__":
    threading.Thread(target=start_flask, daemon=True).start()
    start_p2pool()
    monitor_log()
