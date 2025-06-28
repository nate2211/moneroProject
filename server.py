import subprocess
import smtplib
import ssl
import time
import os
import threading
import re
import queue
from datetime import datetime
from flask import Flask, render_template_string, request
import psutil

P2POOL_DIR = "X:\\Programs\\p2pool-v4.8-windows-x64"
P2POOL_EXE = "p2pool.exe"
WALLET = "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
p2pool_proc = None
p2pool_status_output = ""
client_hashrates = {}
client_newjobs = {}
EVENT_LOG = os.path.join(P2POOL_DIR, "event_log.txt")
RAW_LOG = os.path.join(P2POOL_DIR, "p2pool_raw_output.txt")
log_queue = queue.Queue()
current_hashrate = 0.0

open(EVENT_LOG, "w").close()
open(RAW_LOG, "w").close()


def handle_user_input(proc):
    """
    Waits for user input in the console and forwards it to the p2pool process.
    """
    print("\n[+] P2Pool is running in the background.")
    print("[+] Type commands here and press Enter to send them to P2Pool (e.g., 'status').")
    print("[+] Type 'exit' or 'quit' to stop P2Pool and the script.")
    while True:
        try:
            user_input = input()
            if user_input.lower() in ["exit", "quit"]:
                print("[!] Shutting down P2Pool...")
                proc.terminate()  # or proc.kill()
                break


            proc.stdin.write(user_input + '\n')
            proc.stdin.flush()
        except (IOError, OSError) as e:
            print(f"[!] Lost connection to P2Pool process: {e}")
            break
        except Exception as e:
            print(f"[!] An error occurred: {e}")
            break

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def start_p2pool_direct():
    global p2pool_proc
    exe_path = os.path.join(P2POOL_DIR, P2POOL_EXE)
    if not os.path.exists(exe_path):
        print(f"[!] Executable not found at: {exe_path}")
        return None

    args = [
        exe_path, "--host", "127.0.0.1", "--wallet", WALLET,
        "--mini", "--stratum", "192.168.0.10:3333", "--no-upnp", "--no-color", "--p2p", "0.0.0.0:37888"
    ]

    try:
        p2pool_proc = subprocess.Popen(
            args,
            cwd=P2POOL_DIR,
            stdin=subprocess.PIPE,  # ✅ this is what allows status commands
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        def redirect_output(proc):
            with open(RAW_LOG, "a", encoding="utf-8") as log_file:
                for line in proc.stdout:
                    clean_line = strip_ansi_codes(line.strip())
                    log_file.write(clean_line + "\n")
                    log_file.flush()
                    print("[P2Pool]", clean_line)

        threading.Thread(target=redirect_output, args=(p2pool_proc,), daemon=True).start()
        return True
    except Exception as e:
        print(f"[!] Failed to launch P2Pool: {e}")
        return False

def log_event_now(event_type, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_queue.put(f"[{timestamp}] [{event_type}] {message}")

def log_writer():
    with open(EVENT_LOG, "a", encoding="utf-8") as evlog:
        while True:
            while not log_queue.empty():
                evlog.write(log_queue.get() + "\n")
            evlog.flush()
            time.sleep(0.1)

def tail_p2pool_log():
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
                else:
                    miner_data_block.append(clean_line)
                continue

            if "sent new job" in lower_line:
                log_event_now("Sent Jobs", clean_line)
            elif "share found" in lower_line:
                log_event_now("Found Share", clean_line)
            elif "block found" in lower_line:
                log_event_now("Found Block", clean_line)
            elif "p2pool caught sigint" in lower_line or "p2pool stopping" in lower_line:
                log_event_now("P2Pool Stopped", clean_line)


# === FLASK ===
app = Flask(__name__)





HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>P2Pool Monitor</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            background-color: #ffffff;
            color: #000000;
        }
        .container { padding: 20px 40px; }
        h2 {
            color: #000000;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #e0e0e0;
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #f5f5f5;
            color: #000000;
            font-weight: bold;
        }
        tr { background-color: #ffffff; }
        tr:nth-child(even) { background-color: #fafafa; }
        tr:hover { background-color: #f0f0f0; }

        .status-button {
            background-color: #222222;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }
        .status-button:hover { background-color: #444444; }
        .status-button:disabled { background-color: #cccccc; color: #666666; cursor: not-allowed; }

        #status-container {
            margin-top: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            background-color: #fafafa;
        }
        .status-section {
            padding: 15px;
            border-bottom: 1px solid #e0e0e0;
        }
        .status-section:last-child { border-bottom: none; }
        .status-section h3 {
            margin-top: 0;
            margin-bottom: 15px;
            color: #333;
        }
        .status-grid {
            display: grid;
            grid-template-columns: max-content 1fr;
            gap: 8px 20px;
            font-family: 'Consolas', 'Monaco', 'monospace';
            font-size: 14px;
        }
        .status-grid .key {
            font-weight: bold;
            color: #555;
        }
        .status-grid .value { color: #000; }
    </style>
</head>
<body>
<div class="container">
    <h2>P2Pool Status</h2>
    <button id="status-btn" class="status-button" onclick="fetchStatus()">Get Status</button>

    <div id="status-container"></div>

    <h2>Client Stats</h2>
    <table>
        <tr><th>Client ID</th><th>Hashrate</th><th>Difficulty</th><th>Height</th><th>Algo</th><th>TX Count</th><th>IP</th></tr>
        {% for cid, rate in hashrates.items() %}
        <tr>
            <td>{{ cid }}</td>
            <td>{{ rate }} H/s</td>
            <td>{{ newjobs[cid]["difficulty"] if cid in newjobs else '—' }}</td>
            <td>{{ newjobs[cid]["height"] if cid in newjobs else '—' }}</td>
            <td>{{ newjobs[cid]["algo"] if cid in newjobs else '—' }}</td>
            <td>{{ newjobs[cid]["tx_count"] if cid in newjobs else '—' }}</td>
            <td>{{ newjobs[cid]["ip"] if cid in newjobs else '—' }}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>Recent Events</h2>
    <table>
    <h2>Shares Found</h2>
    <table>
        <tr><th>Time</th><th>Message</th></tr>
        {% for s in shares %}
        <tr>
            <td>{{ s.time }}</td>
            <td>{{ s.message }}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>Jobs Sent</h2>
    <table>
        <tr><th>Time</th><th>Message</th></tr>
        {% for j in jobs %}
        <tr>
            <td>{{ j.time }}</td>
            <td>{{ j.message }}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>New Miner Data</h2>
    <table>
        <tr><th>Time</th><th>Message</th></tr>
        {% for m in miners %}
        <tr>
            <td>{{ m.time }}</td>
            <td><pre style="background:none; border:none; padding:0; margin:0; font-family: inherit;">{{ m.message }}</pre></td>
        </tr>
        {% endfor %}
    </table>
    </table>
    </div>

<script>
function renderStatus(data) {
    const container = document.getElementById('status-container');
    container.innerHTML = ''; // Clear previous content

    if (data.error || data.message) {
        container.innerHTML = `<div class="status-section"><p>${data.error || data.message}</p></div>`;
        return;
    }

    const sectionTitles = {
        sidechain: "SideChain Status",
        stratum: "Stratum Server Status",
        p2p: "P2P Server Status"
    };

    for (const sectionKey in data) {
        const sectionData = data[sectionKey];
        if (Object.keys(sectionData).length === 0) continue;

        const sectionDiv = document.createElement('div');
        sectionDiv.className = 'status-section';

        const title = document.createElement('h3');
        title.textContent = sectionTitles[sectionKey] || sectionKey;
        sectionDiv.appendChild(title);

        const gridDiv = document.createElement('div');
        gridDiv.className = 'status-grid';

        for (const key in sectionData) {
            const keySpan = document.createElement('span');
            keySpan.className = 'key';
            keySpan.textContent = key;

            const valueSpan = document.createElement('span');
            valueSpan.className = 'value';
            valueSpan.textContent = sectionData[key];

            gridDiv.appendChild(keySpan);
            gridDiv.appendChild(valueSpan);
        }

        sectionDiv.appendChild(gridDiv);
        container.appendChild(sectionDiv);
    }
}

function fetchStatus() {
    const statusBtn = document.getElementById('status-btn');
    const container = document.getElementById('status-container');

    statusBtn.disabled = true;
    statusBtn.textContent = 'Fetching...';

    fetch('/status', { method: 'POST' })
        .then(response => response.json()) // Expect a JSON response
        .then(data => {
            renderStatus(data); // Render the data into a beautiful table
        })
        .catch(error => {
            renderStatus({ error: "Failed to fetch or parse status. " + error.message });
        })
        .finally(() => {
            statusBtn.disabled = false;
            statusBtn.textContent = 'Get Status';
        });
}

// Initial render for the placeholder message
document.addEventListener('DOMContentLoaded', () => {
    renderStatus({{ status_output | tojson }});
});
</script>

</body>
</html>
"""

def parse_p2pool_status(raw_text):
    """
    Parses the raw multi-line status text from P2Pool into a structured dictionary.
    """
    if not raw_text.strip():
        return {"error": "Received empty status from P2Pool."}

    data = {"sidechain": {}, "stratum": {}, "p2p": {}}
    current_section = None

    lines = raw_text.strip().split('\n')
    for line in lines:
        line_lower = line.lower()
        if "sidechain status" in line_lower:
            current_section = "sidechain"
            continue
        elif "stratumserver status" in line_lower:
            current_section = "stratum"
            continue
        elif "p2pserver status" in line_lower:
            current_section = "p2p"
            continue

        if current_section:
            # Regex to find "Key = Value" pairs, allowing for varied spacing
            match = re.match(r'^\s*(.*?)\s*=\s*(.*)$', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                data[current_section][key] = value
    return data


@app.route("/status", methods=["POST"])
def get_status_output():
    global p2pool_proc, p2pool_status_output

    if p2pool_proc and p2pool_proc.stdin:
        try:
            # 1. Send the command to the process as before.
            p2pool_proc.stdin.write("status\n")
            p2pool_proc.stdin.flush()

            # 2. Give the redirect_output thread a moment to write the log file.
            time.sleep(0.5)

            # 3. Read the entire log file to find the LATEST status report.
            with open(RAW_LOG, "r", encoding="utf-8") as f:
                log_content = f.read()

            # Find the position of the last status report
            last_status_pos = log_content.rfind("SideChain status")
            if last_status_pos == -1:
                p2pool_status_output = {"error": "Status report not found in logs yet."}
                return p2pool_status_output, 404

            # Extract the text from the last status report to the end of the file
            raw_text = log_content[last_status_pos:]

            # 4. Parse the text you just read from the file.
            p2pool_status_output = parse_p2pool_status(raw_text)

            # Return the parsed data as JSON
            return p2pool_status_output

        except Exception as e:
            p2pool_status_output = {"error": str(e)}
            return p2pool_status_output, 500
    else:
        p2pool_status_output = {"error": "P2Pool is not running."}
        return p2pool_status_output, 503

# ... (Your other routes and main execution block) ...
@app.route("/")
def index():
    # Create separate lists for each event type
    shares_found = []
    jobs_sent = []
    miner_data = []
    other_events = []

    if os.path.exists(EVENT_LOG):
        with open(EVENT_LOG, "r", encoding="utf-8") as f:
            # Read the last 100 lines to ensure we have enough events to categorize
            for line in list(f.readlines())[-100:]:
                match = re.match(r"\[(.*?)\] \[(.*?)\] (.*)", line, re.DOTALL)
                if match:
                    event = {
                        "time": match.group(1),
                        "type": match.group(2),
                        "message": match.group(3).strip()
                    }
                    # Categorize the event based on its type
                    if event["type"] == "Found Share":
                        shares_found.insert(0, event)
                    elif event["type"] == "Sent Jobs":
                        jobs_sent.insert(0, event)
                    elif event["type"] == "New Miner Data":
                        miner_data.insert(0, event)
                    else:
                        other_events.insert(0, event)

    # Pass the categorized lists to the template
    return render_template_string(HTML,
                                  hashrates=client_hashrates,
                                  newjobs=client_newjobs,
                                  status_output=p2pool_status_output,
                                  shares=shares_found,
                                  jobs=jobs_sent,
                                  miners=miner_data)

@app.route("/hashrate", methods=["POST"])
def receive_hashrate():
    data = request.get_json()
    if data and "hashrate" in data and "client_id" in data:
        client_hashrates[data["client_id"]] = data["hashrate"]
        return "OK", 200
    return "Bad Request", 400

@app.route("/newjob", methods=["POST"])
def receive_newjob():
    data = request.get_json()
    if data and "newjob" in data and "client_id" in data:
        client_newjobs[data["client_id"]] = data
        return "OK", 200
    return "Bad Request", 400

def start_flask():
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":

    threading.Thread(target=start_flask, daemon=True).start()
    threading.Thread(target=log_writer, daemon=True).start()
    if start_p2pool_direct():
        threading.Thread(target=tail_p2pool_log, daemon=True).start()
        handle_user_input(p2pool_proc)
    else:
        print("[!] Could not start P2Pool. Exiting.")