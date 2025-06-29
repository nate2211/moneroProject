import subprocess
import smtplib
import ssl
import time
import os
import threading
import re
import queue
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
import psutil

P2POOL_DIR = "X:\\Programs\\p2pool-v4.8-windows-x64"
P2POOL_EXE = "p2pool.exe"
WALLET = "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
p2pool_proc = None
p2pool_status_output = ""
client_hashrates = {}
client_newjobs = {}
client_threads = {}
client_last_seen = {}
client_temps = {} # New dictionary for CPU temps
client_status = {}
client_cpu_shares = {}
client_nvidia_shares = {}
client_gpu_stats = {}

COMMAND_QUEUE = {} # Holds pending commands, e.g., {"Miner1": {"command": "set_threads", "threads": 8}}
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


def time_ago(timestamp):
    """Converts a Unix timestamp into a 'time ago' string."""
    now = datetime.now()
    dt = datetime.fromtimestamp(timestamp)
    diff = now - dt

    seconds = diff.total_seconds()

    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    else:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days > 1 else ''} ago"

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
        
                /* --- Modal Styles --- */
        .modal {
            display: none; /* This is the critical rule that hides the modal by default */
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.5);
            animation: fadeIn 0.3s;
        }
        .modal-content { background-color: #fff; margin: 10% auto; padding: 0; width: 90%; max-width: 450px; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
        .modal-header { padding: 16px 24px; background-color: #007bff; color: white; border-radius: 8px 8px 0 0; display: flex; justify-content: space-between; align-items: center; }
        .modal-header h3 { margin: 0; font-size: 20px; }
        .modal-body { padding: 24px; }
        .modal-footer { padding: 16px 24px; text-align: right; background-color: #f1f1f1; border-radius: 0 0 8px 8px; }
        .close-button { color: #fff; font-size: 28px; font-weight: bold; cursor: pointer; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: .5rem; }
        .form-group input { display: block; width: 95%; padding: .5rem .75rem; font-size: 1rem; border: 1px solid #ced4da; border-radius: .25rem; }
    </style>
</head>
<body>
<div class="container">
    <h2>P2Pool Status</h2>
    <button id="status-btn" class="status-button" onclick="fetchStatus()">Get Status</button>

    <div id="status-container"></div>
   <h2>Client Dashboard</h2>
    <table>
        <thead>
            <tr>
                <th>Client ID</th>
                <th>Hashrate</th>
                <th>CPU Temp</th>
                <th>Threads</th>
                <th>Last Seen</th>
                <th>CPU Shares / GPU Shares</th>
                <th>GPU Stats</th>
                <th>Job Difficulty</th>
                <th>Job Height</th>
                <th>Algo</th>
                <th>TXs</th>
                <th>Pool IP</th>
                <th>Set Threads</th>
                <th>Control Pool</th>
            </tr>
        </thead>
        <tbody>
            {% for cid, rate in hashrates.items() %}
            <tr>
                <td><span class="status-online">●</span> {{ cid }}</td>
                <td><strong>{{ "%.2f"|format(rate) }} H/s</strong></td>
                <td>{{ temps.get(cid, 'N/A') }}</td>
                <td>{{ threads.get(cid, 'N/A') }}</td>
                <td>{{client_last_seen[cid]}}</td>
                <td>{{ client_cpu_shares[cid] }} / {{ client_nvidia_shares[cid] }}</td>
                <td>{{ client_gpu_stats[cid].temp }} | {{ client_gpu_stats[cid].fan }}</td>
                <td>{{ newjobs[cid].difficulty if cid in newjobs and newjobs[cid].difficulty else '—' }}</td>
                <td>{{ newjobs[cid].height if cid in newjobs and newjobs[cid].height else '—' }}</td>
                <td>{{ newjobs[cid].algo if cid in newjobs and newjobs[cid].algo else '—' }}</td>
                <td>{{ newjobs[cid].tx_count if cid in newjobs and newjobs[cid].tx_count else '—' }}</td>
                <td>{{ newjobs[cid].ip if cid in newjobs and newjobs[cid].ip else '—' }}</td>
                <td>
                    <form action="{{ url_for('set_threads', client_id=cid) }}" method="post" class="form-inline">
                        <input type="number" name="threads" min="1" placeholder="{{ threads.get(cid, '1') }}" required>
                        <button type="submit">Set</button>
                    </form>
                </td>
                <td>
                    {% if client_status.get(cid) == 'Started' %}
                        <button class="action-button stop" onclick="stopMiner('{{ cid }}')">Stop</button>
                    {% else %}
                        <button class="action-button" onclick="openStartModal('{{ cid }}')">Start</button>
                    {% endif %}
                </td>
                <div id="startMinerModal" class="modal">
                      <div class="modal-content">
                        <div class="modal-header">
                          <span class="close-button" onclick="closeStartModal()">&times;</span>
                          <h3>Start Miner</h3>
                        </div>
                        <form id="startMinerForm" method="post">
                            <div class="modal-body">
                                <div class="form-group">
                                    <label for="pool_url">Pool URL</label>
                                    <input type="text" id="pool_url" name="pool" placeholder="e.g., 192.168.0.10:3333" required>
                                </div>
                                <div class="form-group">
                                    <label for="threads">Threads</label>
                                    <input type="number" id="threads" name="threads" min="1" placeholder="e.g., 4" required>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="submit" class="action-button">Send Start Command</button>
                            </div>
                        </form>
                      </div>
                </div>
            </tr>
            {% else %}
            <tr>
                <td colspan="10" style="text-align: center;" class="text-muted">No clients have connected yet.</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
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
        <h2>Other Events</h2>
    <table>
        <tr><th>Time</th><th>Type</th><th>Message</th></tr>
        {% for o in other %}
        <tr>
            <td>{{ o.time }}</td>
            <td>{{ o.type }}</td>
            <td>{{ o.message }}</td>
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
    </table>
    </div>

<script>
    const modal = document.getElementById('startMinerModal');
    const form = document.getElementById('startMinerForm');
    function openStartModal(clientId) {
        form.action = '/start_miner/' + clientId;
        modal.style.display = 'block';
    }
    function closeStartModal() {
        modal.style.display = 'none';
    }
    window.onclick = function(event) {
        if (event.target == modal) {
            closeStartModal();
        }
    }

    // NEW: JavaScript function to handle the stop command
    function stopMiner(clientId) {
        if (!confirm(`Are you sure you want to stop miner: ${clientId}?`)) {
            return;
        }
        fetch(`/stop_miner/${clientId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            console.log(data.message);
            // Reload the page to see the updated status
            window.location.reload();
        })
        .catch(error => {
            console.error('Error stopping miner:', error);
            alert('Failed to stop the miner.');
        });
    }
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


# NEW: Endpoint for clients to report their status (e.g., "started" or "stopped")
@app.route("/miners/<client_id>", methods=["POST"])
def update_miner_status(client_id):
    """
    Endpoint for clients to report their running status.
    """
    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({"error": "Invalid payload. 'status' is required."}), 400

    status = data['status']

    print(f"[+] Received status update from '{client_id}': {status}")
    client_status[client_id] = status
    # If stopped, also clear hashrate
    if status in ['Stopped', 'Error']:
        client_hashrates[client_id] = 0

    return jsonify({"message": "Status updated successfully"}), 200


# NEW: Endpoints to queue start/stop commands
@app.route("/start_miner/<client_id>", methods=["POST"])
def start_miner(client_id):
    pool = request.form.get("pool")
    threads = request.form.get("threads")
    if not pool or not threads:
        return "Pool and threads are required.", 400

    COMMAND_QUEUE[client_id] = {
        "command": "start",
        "pool": pool,
        "threads": int(threads)
    }
    print(f"[+] Queued START command for '{client_id}'")
    return redirect(url_for('index'))


@app.route("/stop_miner/<client_id>", methods=["POST"])
def stop_miner(client_id):
    COMMAND_QUEUE[client_id] = {"command": "stop"}
    client_status[client_id] = 'Stopped'  # Optimistically update UI
    client_hashrates[client_id] = 0
    print(f"[+] Queued STOP command for '{client_id}'")
    return jsonify({"status": "ok", "message": f"Stop command queued for {client_id}"})


@app.route("/set_threads/<client_id>", methods=["POST"])
def set_threads(client_id):
    """Adds a 'set_threads' command to the queue for a specific client."""
    try:
        new_threads = int(request.form["threads"])
    except (ValueError, KeyError):
        return "Invalid thread count provided", 400

    COMMAND_QUEUE[client_id] = {"command": "set_threads", "threads": new_threads}
    print(f"[+] Command queued for '{client_id}': Set threads to {new_threads}")
    return redirect(url_for('index'))
@app.route("/get_command/<client_id>", methods=["GET"])
def get_command(client_id):
    """Allows clients to poll for and receive commands."""
    command = COMMAND_QUEUE.pop(client_id, None)
    return jsonify(command) if command else jsonify({})
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
            # Read the last 200 lines to ensure we have enough events to categorize
            for line in list(f.readlines())[-200:]:
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

    # ✅ THE FIX: Limit the number of events passed to the template
    # This takes the first 10 items from each list (which are the newest)
    limit = 1000
    # --- NEW: Format the 'last seen' timestamps ---
    client_last_seen_formatted = {}
    for cid, timestamp in client_last_seen.items():
        client_last_seen_formatted[cid] = time_ago(timestamp)
    # Pass the categorized and LIMITED lists to the template
    return render_template_string(HTML,
                                  hashrates=client_hashrates,
                                  newjobs=client_newjobs,
                                  client_last_seen=client_last_seen_formatted,
                                  client_status=client_status,
                                  client_cpu_shares=client_cpu_shares,
                                  client_gpu_stats=client_gpu_stats,
                                  client_nvidia_shares=client_nvidia_shares,
                                  status_output=p2pool_status_output,
                                  threads=client_threads,
                                  temps=client_temps,
                                  shares=shares_found[:limit],
                                  jobs=jobs_sent[:limit],
                                  miners=miner_data[:limit],
                                  other=other_events[:limit])


@app.route("/hashrate", methods=["POST"])
def receive_hashrate():
    data = request.get_json()
    if not data or "client_id" not in data:
        return "Bad Request", 400

    client_id = data["client_id"]
    if client_status.get(client_id) == "Disconnected":
        print(f"[+] Client '{client_id}' reconnected.")

    # Update all data from the client's heartbeat
    client_hashrates[client_id] = data.get("hashrate", 0)
    client_threads[client_id] = data.get("threads", 0)
    client_temps[client_id] = data.get("cpu_temp", "N/A")
    client_last_seen[client_id] = time.time()

    # NEW: Store the detailed stats from the new payload
    client_cpu_shares[client_id] = data.get("cpu_accepted_shares", 0)
    client_nvidia_shares[client_id] = data.get("nvidia_accepted_shares", 0)
    client_gpu_stats[client_id] = {
        "temp": data.get("gpu_temp", "N/A"),
        "fan": data.get("gpu_fan", "N/A")
    }

    # This endpoint can also send back commands, making the system more efficient
    command = COMMAND_QUEUE.pop(client_id, None)
    return jsonify(command) if command else jsonify({"message": "ok"})

@app.route("/newjob", methods=["POST"])
def receive_newjob():
    data = request.get_json()
    # FIX: Remove the check for "newjob". Only check for the essential client_id.
    if data and "client_id" in data:
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