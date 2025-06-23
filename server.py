import subprocess
import smtplib
import ssl
import time
import os
import threading
import re
import queue
from datetime import datetime
from flask import Flask, render_template_string
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

EVENT_LOG = os.path.join(P2POOL_DIR, "event_log.txt")
RAW_LOG = os.path.join(P2POOL_DIR, "p2pool_raw_output.txt")
log_queue = queue.Queue()

# Wipe the event log at startup
open(EVENT_LOG, "w").close()
open(RAW_LOG, "w").close()

# === EMAIL FUNCTION ===
def send_email(subject, body):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"""From: {FROM}
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

# === STRIP ANSI CODES ===
def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# === START P2POOL DIRECTLY ===
def start_p2pool_direct():
    exe_path = os.path.join(P2POOL_DIR, P2POOL_EXE)
    if not os.path.exists(exe_path):
        print(f"[!] Executable not found at: {exe_path}")
        return None

    args = [
        exe_path,
        "--host", "127.0.0.1",
        "--wallet", WALLET,
        "--mini",
        "--stratum", "192.168.0.10:3333",
        "--no-upnp",
        "--no-color"
    ]

    print("[~] Launching P2Pool subprocess:")
    print(" ".join(args))

    try:
        proc = subprocess.Popen(
            args,
            cwd=P2POOL_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1  # Line buffered
        )

        def redirect_output(proc):
            with open(RAW_LOG, "a", encoding="utf-8") as log_file:
                for line in proc.stdout:
                    clean_line = strip_ansi_codes(line.strip())
                    log_file.write(clean_line + "\n")
                    log_file.flush()
                    print("[P2Pool]", clean_line)

        threading.Thread(target=redirect_output, args=(proc,), daemon=True).start()
        return True
    except Exception as e:
        print(f"[!] Failed to launch P2Pool: {e}")
        return False

def log_event_now(event_type, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_event(timestamp, event_type, message)

def log_event(timestamp, event_type, message):
    log_line = f"[{timestamp}] [{event_type}] {message}"
    log_queue.put(log_line)

def log_writer():
    with open(EVENT_LOG, "a", encoding="utf-8") as evlog:
        while True:
            try:
                while not log_queue.empty():
                    evlog.write(log_queue.get() + "\n")
                evlog.flush()
                time.sleep(0.1)
            except Exception as e:
                print(f"[!] Logging error: {e}")

def tail_p2pool_log():
    print(f"[~] Tailing {RAW_LOG}...")

    while not os.path.exists(RAW_LOG):
        time.sleep(0.5)

    with open(RAW_LOG, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        miner_data_block = []
        in_miner_data = False

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            clean_line = line.strip()
            lower_line = clean_line.lower()

            if "p2pool new miner data" in lower_line:
                in_miner_data = True
                miner_data_block = [clean_line]
                continue

            if in_miner_data:
                if clean_line == "" or clean_line.startswith("-"):
                    full_block = "\n".join(miner_data_block).strip()
                    log_event_now("New Miner Data", full_block)
                    in_miner_data = False
                    miner_data_block = []
                else:
                    miner_data_block.append(clean_line)
                continue

            if "sent new job" in lower_line:
                log_event_now("Sent Jobs", clean_line)
            elif "found share" in lower_line:
                log_event_now("Found Share", clean_line)
                send_email("Found Share", "Share has been found.")
            elif "found block" in lower_line:
                log_event_now("Found Block", clean_line)
                send_email("Found Block", "Block has been found.")
            elif "p2pool caught sigint" in lower_line or "p2pool stopping" in lower_line:
                log_event_now("P2Pool Stopped", clean_line)

# === FLASK SERVER ===
app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>P2Pool Events</title>
<meta http-equiv="refresh" content="10">
<style>
body { font-family: Arial; margin: 40px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background-color: #444; color: white; }
</style>
</head>
<body>
<h2>P2Pool Event Monitor</h2>
<table>
<tr><th>Time</th><th>Event</th><th>Message</th></tr>
{% for e in events %}
<tr><td>{{ e.time }}</td><td>{{ e.event }}</td><td>{{ e.line }}</td></tr>
{% endfor %}
</table>
</body>
</html>
"""

@app.route("/")
def index():
    events = []
    if os.path.exists(EVENT_LOG):
        with open(EVENT_LOG, "r", encoding="utf-8") as f:
            for line in list(f.readlines())[-50:]:
                match = re.match(r"\[(.*?)\] \[(.*?)\] (.*)", line)
                if match:
                    events.insert(0, {
                        "time": match.group(1),
                        "event": match.group(2),
                        "line": match.group(3)
                    })
    return render_template_string(HTML, events=events)

def start_flask():
    app.run(host="0.0.0.0", port=5000)

# === MAIN ===
if __name__ == "__main__":
    threading.Thread(target=start_flask, daemon=True).start()
    threading.Thread(target=log_writer, daemon=True).start()
    if start_p2pool_direct():
        tail_p2pool_log()
    else:
        print("[!] Could not start P2Pool. Exiting.")
