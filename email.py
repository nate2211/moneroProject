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
EVENT_LOG = os.path.join(P2POOL_DIR, "events.json")

latest_hashrate = ""
connected_miners = []

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

# === LOG EVENT FOR WEB UI ===
def log_event(event_type, message, event_time=None):
    if event_time is None:
        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event = {"time": event_time, "type": event_type, "message": message}
    events = []

    if os.path.exists(EVENT_LOG):
        with open(EVENT_LOG, "r") as f:
            try:
                events = json.load(f)
            except:
                pass

    events.insert(0, event)
    events = events[:100]

    with open(EVENT_LOG, "w") as f:
        json.dump(events, f, indent=2)

# === PARSE P2POOL OUTPUT ===
import re

def parse_p2pool_line(line):
    """Parse a line from the p2pool log and log interesting events."""
    # extract timestamp from line if present
    time_match = re.match(r"^\w+\s+(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})", line)
    event_time = None
    if time_match:
        event_time = f"{time_match.group(1)} {time_match.group(2)}"

    l = line.lower()

    if "sidechain verified block" in l:
        m = re.search(r"height\s*=\s*(\d+).*?id\s*=\s*([0-9a-f]+)", line)
        if m:
            height, bid = m.group(1), m.group(2)
            msg = f"verified block height {height} id {bid}"
        else:
            msg = line.strip()
        log_event("VerifiedBlock", msg, event_time)
        return
    if "sidechain new chain tip" in l:
        m = re.search(r"next height\s*=\s*(\d+).*?difficulty\s*=\s*(\d+)", line)
        if m:
            height, diff = m.group(1), m.group(2)
            msg = f"new tip height {height}, diff {diff}"
        else:
            msg = line.strip()
        log_event("ChainTip", msg, event_time)
        return
    if "blocktemplate final reward" in l:
        m = re.search(r"final reward =\s*([0-9.]+) XMR", line)
        if m:
            reward = m.group(1)
            msg = f"final reward {reward} XMR"
        else:
            msg = line.strip()
        log_event("BlockTemplate", msg, event_time)
        return
    if "p2pserver peer" in l and "banned" in l:
        m = re.search(r"peer ([0-9.:]+) banned for (\d+)", line)
        if m:
            ip, secs = m.group(1), m.group(2)
            msg = f"peer {ip} banned for {secs}s"
        else:
            msg = line.strip()
        log_event("PeerBanned", msg, event_time)
        return
    if "stratumserver sent new job" in l:
        log_event("NewJob", line.strip(), event_time)
        return

# === MONITOR FUNCTION ===
def monitor_log():
    global latest_hashrate, connected_miners

    print(f"[~] Waiting for '{LOG_FILE}'...")
    while not os.path.exists(LOG_FILE):
        time.sleep(1)

    print("[+] Monitoring p2pool_log.txt...")
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        buffer = []
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue

            l = line.lower().strip()
            buffer.append(line)

            handled = False
            if "found block" in l:
                send_email("P2Pool Block Found", line.strip())
                log_event("Block", line.strip())
                handled = True
            elif "found share" in l:
                send_email("P2Pool Share Found", line.strip())
                log_event("Share", line.strip())
                handled = True
            elif "hashrate:" in l:
                try:
                    hashrate_str = line.split("hashrate:")[1].split()[0]
                    latest_hashrate = hashrate_str + " H/s"
                except Exception as e:
                    print(f"[!] Failed to parse hashrate: {e}")
                handled = True
            elif "p2pool new miner data" in l:
                # look ahead to find IP or host info
                for i in range(10):
                    line2 = f.readline()
                    if not line2:
                        break
                    if "host =" in line2:
                        try:
                            ip = line2.split("host =")[1].strip().split(":")[0]
                            if ip not in connected_miners:
                                connected_miners.append(ip)
                        except Exception as e:
                            print(f"[!] Failed to parse host: {e}")
                        break
                handled = True

            if not handled:
                parse_p2pool_line(line)

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
<html><head><title>P2Pool Status</title>
<meta http-equiv="refresh" content="10">
<style>
body { font-family: Arial; margin: 40px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background-color: #444; color: white; }
</style></head>
<body>
<h2>P2Pool Mining Events</h2>
<table>
<tr><th>Time</th><th>Type</th><th>Message</th></tr>
{% for e in events %}
<tr><td>{{ e.time }}</td><td>{{ e.type }}</td><td>{{ e.message }}</td></tr>
{% endfor %}
</table>
<hr>
<h3>Live Hashrate</h3>
<p><span id="hashrate">Loading...</span></p>
<h3>Connected Miners</h3>
<ul id="miners"></ul>
<h3>System Status</h3>
<ul>
  <li>CPU Usage: <span id="cpu"></span>%</li>
  <li>RAM Usage: <span id="ram"></span>%</li>
</ul>
<script>
function updateData() {
  fetch('/hashrate').then(r => r.json()).then(data => {
    document.getElementById('hashrate').innerText = data.hashrate || "N/A";
  });
  fetch('/miners').then(r => r.json()).then(data => {
    let list = document.getElementById('miners');
    list.innerHTML = "";
    for (let m of data.miners) {
      let li = document.createElement('li');
      li.innerText = m;
      list.appendChild(li);
    }
  });
  fetch('/status').then(res => res.json()).then(data => {
    document.getElementById('cpu').innerText = data.cpu;
    document.getElementById('ram').innerText = data.ram;
  });
}
setInterval(updateData, 5000);
updateData();
</script>
</body></html>
"""

@app.route("/")
def index():
    try:
        with open(EVENT_LOG, "r") as f:
            events = json.load(f)
    except:
        events = []
    return render_template_string(HTML, events=events)

@app.route("/api")
def api():
    try:
        with open(EVENT_LOG, "r") as f:
            return jsonify(json.load(f))
    except:
        return jsonify([])

@app.route("/status")
def status():
    return jsonify({
        "cpu": psutil.cpu_percent(interval=1),
        "ram": psutil.virtual_memory().percent
    })

@app.route("/hashrate")
def hashrate():
    return jsonify({"hashrate": latest_hashrate})

@app.route("/miners")
def miners():
    return jsonify({"miners": connected_miners})

def start_flask():
    app.run(host="0.0.0.0", port=5000)

# === MAIN ===
if __name__ == "__main__":
    threading.Thread(target=start_flask, daemon=True).start()
    start_p2pool()
    monitor_log()
