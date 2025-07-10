import subprocess
import smtplib
import ssl
import sys
import time
import os
import threading
import re
import queue
from datetime import datetime, timezone
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
import psutil


P2POOL_DIR = os.path.dirname(sys.executable)
P2POOL_EXE = "p2pool.exe"
WALLET = "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
p2pool_proc = None
p2pool_status_output = {"message": "P2Pool status not yet available."}  # Initialize with a message
client_hashrates = {}
client_newjobs = {}
client_threads = {}
client_last_seen = {}
client_temps = {}
client_status = {}
client_cpu_shares = {}
client_nvidia_shares = {}
client_gpu_stats = {}
client_power_draws = {}
client_start_times = {}
client_costs = {}
ELECTRICITY_RATE_PER_KWH = 0.13
COMMAND_QUEUE = {}
EVENT_LOG = os.path.join(P2POOL_DIR, "event_log.txt")
RAW_LOG = os.path.join(P2POOL_DIR, "p2pool_raw_output.txt")
log_queue = queue.Queue()
current_hashrate = 0.0


# Removed: open(EVENT_LOG, "w").close() and open(RAW_LOG, "w").close()

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
                proc.terminate()
                break

            # Check if stdin pipe is still open before writing
            if proc.poll() is None:  # None means process is still running
                proc.stdin.write(user_input + '\n')
                proc.stdin.flush()
            else:
                print("[!] P2Pool process has already terminated.")
                break
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
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        def redirect_output(proc):
            # 'a' mode creates the file if it doesn't exist
            with open(RAW_LOG, "a", encoding="utf-8") as log_file:
                for line in proc.stdout:
                    clean_line = strip_ansi_codes(line.strip())
                    log_file.write(clean_line + "\n")
                    log_file.flush()
                    print("[P2Pool]", clean_line)
            # Log that the process ended, if this function exits
            log_event_now("P2Pool Process", "P2Pool stdout stream ended.")

        threading.Thread(target=redirect_output, args=(p2pool_proc,), daemon=True).start()
        return True
    except Exception as e:
        print(f"[!] Failed to launch P2Pool: {e}")
        return False


def log_event_now(event_type, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_queue.put(f"[{timestamp}] [{event_type}] {message}")


def log_writer():
    # 'a' mode creates the file if it doesn't exist
    with open(EVENT_LOG, "a", encoding="utf-8") as evlog:
        while True:
            # Continuously try to get items from the queue without blocking indefinitely
            try:
                log_entry = log_queue.get(timeout=0.5)  # Wait up to 0.5 seconds
                evlog.write(log_entry + "\n")
                evlog.flush()
            except queue.Empty:
                pass  # No logs in queue, continue loop
            time.sleep(0.1)  # Short delay to prevent busy-waiting


def tail_p2pool_log():
    # Wait for the RAW_LOG file to exist, but with a timeout to prevent infinite loops
    # if P2Pool never creates it.
    timeout_start = time.time()
    timeout_seconds = 60  # Wait up to 60 seconds for the log file
    while not os.path.exists(RAW_LOG):
        if time.time() - timeout_start > timeout_seconds:
            print(f"[!] Timeout: RAW_LOG file '{RAW_LOG}' did not appear within {timeout_seconds} seconds.")
            return  # Exit the thread if file doesn't appear
        time.sleep(0.5)

    try:
        with open(RAW_LOG, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)  # Start reading from the end

            miner_data_block = []
            in_miner_data = False

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)  # Wait for new content
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
                # NEW: Specific classification for sidechain add_block messages
                elif "sidechain add_block" in lower_line:
                    log_event_now("Sidechain Block Added", clean_line)
                # FIX: Corrected boolean logic for "p2pool stopping"
                elif "p2pool caught sigint" in lower_line or "p2pool stopping" in lower_line:
                    log_event_now("P2Pool Stopped", clean_line)
                else: # Fallback for any other messages
                    log_event_now("Other P2Pool Event", clean_line)
    except FileNotFoundError:
        print(f"[!] Error: RAW_LOG file '{RAW_LOG}' not found during tailing. It might have been deleted.")
    except Exception as e:
        print(f"[!] An error occurred while tailing P2Pool log: {e}")


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

@app.route("/connect_wifi", methods=["POST"])
def connect_wifi():
    data = request.get_json()
    ssid = data.get("ssid")
    password = data.get("password")

    if not ssid or not password:
        return jsonify({"status": "error", "message": "SSID and password are required."}), 400

    # These commands are Windows-specific and require administrative privileges.
    # It's crucial that the script running this Flask app has admin rights.
    try:
        # 1. Delete existing profile for this SSID (optional, but good for clean reconnect)
        # Using a subprocess.run with capture_output=True to get stdout/stderr
        # and text=True to decode it.
        # We don't check=True for deletion as it might fail if profile doesn't exist.
        delete_command = f'netsh wlan delete profile name="{ssid}"'
        delete_result = subprocess.run(delete_command, shell=True, capture_output=True, text=True)
        if delete_result.returncode == 0:
            log_event_now("Network Control", f"Deleted existing Wi-Fi profile for '{ssid}'.")
        else:
            # It's common for deletion to fail if the profile doesn't exist, not an error.
            if "profile \"" + ssid + "\" is not found" not in delete_result.stderr:
                log_event_now("Network Control", f"Warning: Failed to delete Wi-Fi profile for '{ssid}': {delete_result.stderr.strip()}")

        # 2. Create a temporary XML profile for the network
        # This is the most reliable way to connect to a new Wi-Fi network with a password
        profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

        # Save the XML to a temporary file
        temp_xml_path = os.path.join(P2POOL_DIR, f"{ssid}_profile.xml")
        with open(temp_xml_path, "w", encoding="utf-8") as f:
            f.write(profile_xml)

        # 3. Add the profile
        add_profile_command = f'netsh wlan add profile filename="{temp_xml_path}"'
        subprocess.run(add_profile_command, shell=True, check=True)
        log_event_now("Network Control", f"Added Wi-Fi profile for '{ssid}'.")

        # 4. Connect to the profile
        connect_command = f'netsh wlan connect name="{ssid}" ssid="{ssid}"' # ssid param sometimes needed
        subprocess.run(connect_command, shell=True, check=True)
        log_event_now("Network Control", f"Attempted to connect to Wi-Fi network: '{ssid}'.")

        # Clean up the temporary XML file
        os.remove(temp_xml_path)

        return jsonify({"status": "success", "message": f"Attempted to connect to Wi-Fi network: {ssid}. Check network status."})

    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to connect to Wi-Fi network '{ssid}'. Error: {e.stderr.strip()}. Ensure script is run as administrator."
        log_event_now("Network Control", error_msg)
        # Attempt to clean up XML even on error
        if os.path.exists(temp_xml_path):
            os.remove(temp_xml_path)
        return jsonify({"status": "error", "message": error_msg}), 500
    except Exception as e:
        error_msg = f"An unexpected error occurred during Wi-Fi connection: {e}"
        log_event_now("Network Control", error_msg)
        if os.path.exists(temp_xml_path):
            os.remove(temp_xml_path)
        return jsonify({"status": "error", "message": error_msg}), 500
@app.route("/restart_p2pool", methods=["POST"])
def restart_p2pool():
    global p2pool_proc, p2pool_status_output

    if p2pool_proc and p2pool_proc.poll() is None:
        print("[!] Attempting to restart P2Pool: Terminating existing process...")
        try:
            # Send SIGTERM to allow for graceful shutdown
            p2pool_proc.terminate()
            p2pool_proc.wait(timeout=10) # Wait for process to terminate
            print("[+] Existing P2Pool process terminated.")
        except subprocess.TimeoutExpired:
            print("[!] P2Pool process did not terminate gracefully, forcing kill.")
            p2pool_proc.kill()
        except Exception as e:
            print(f"[!] Error terminating P2Pool process: {e}")

    # Clear previous status to indicate restart
    p2pool_status_output = {"message": "P2Pool is restarting..."}

    # Attempt to start a new P2Pool process
    success = start_p2pool_direct()
    if success:
        print("[+] P2Pool restarted successfully.")
        log_event_now("P2Pool Control", "P2Pool process restarted.")
        return jsonify({"status": "success", "message": "P2Pool restarted successfully."})
    else:
        print("[!] Failed to restart P2Pool.")
        p2pool_status_output = {"error": "Failed to restart P2Pool. Check logs."}
        log_event_now("P2Pool Control", "Failed to restart P2Pool process.")
        return jsonify({"status": "error", "message": "Failed to restart P2Pool."}), 500

# Modify the `handle_user_input` function to clean up the raw log on exit
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
                proc.terminate()
                # Wait for the process to actually terminate
                proc.wait(timeout=5)
                # Clean up raw log file before exiting
                if os.path.exists(RAW_LOG):
                    os.remove(RAW_LOG)
                    print(f"[+] Removed raw log file: {RAW_LOG}")
                break

            # Check if stdin pipe is still open before writing
            if proc.poll() is None:  # None means process is still running
                proc.stdin.write(user_input + '\n')
                proc.stdin.flush()
            else:
                print("[!] P2Pool process has already terminated.")
                break
        except (IOError, OSError) as e:
            print(f"[!] Lost connection to P2Pool process: {e}")
            break
        except Exception as e:
            print(f"[!] An error occurred: {e}")
            break


# HTML content remains the same, ensuring robust error handling in JS and Python
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
    <h2>System Totals</h2>
    <table>
        <tr><th>Total Hashrate</th><td>{{ total_hashrate }} H/s</td></tr>
        <tr><th>Total CPU Shares</th><td>{{ total_cpu_shares }}</td></tr>
        <tr><th>Total GPU Shares</th><td>{{ total_gpu_shares }}</td></tr>
        <tr><th>Total Power Draw</th><td>{{ total_power_draw }} W</td></tr>
        <tr><th>Total Cost</th><td>${{ total_cost }}</td></tr>
    </table>

   <h2>Client Dashboard</h2>
    <table>
        <thead>
            <tr>
                <th>Client ID</th>
                <th>Hashrate</th>
                <th>CPU Temp</th>
                <th>Threads</th>
                <th>Power Draw</th>
                <th>Cost</th>
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
                <td>{{ client_power_draws.get(cid, "N/A") }}</td>
                <td>${{ client_costs.get(cid, 0.0) }}</td>
                <td>{{ client_last_seen.get(cid, "N/A") }}</td>
                <td>{{ client_cpu_shares.get(cid, 0) }} / {{ client_nvidia_shares.get(cid, 0) }}</td>
                <td>{{ client_gpu_stats.get(cid, {}).get('temp', 'N/A') }} | {{ client_gpu_stats.get(cid, {}).get('fan', 'N/A') }}</td>
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
    <h2>Blocks Found</h2>
    <table>
        <tr><th>Time</th><th>Type</th><th>Message</th></tr>
        {% for o in blocks %}
        <tr>
            <td>{{ o.time }}</td>
            <td>{{ o.message }}</td>
        </tr>
        {% endfor %}
    </table>
    <h2>System Control</h2>
    <table>
        <tr>
            <th>Restart P2Pool</th>
            <td>
                <button id="restart-p2pool-btn" class="status-button" onclick="restartP2Pool()">Restart</button>
            </td>
        </tr>
         <tr>
            <th>Connect to Wi-Fi</th>
            <td>
                <input type="text" id="wifi-ssid" placeholder="Network SSID (e.g., ARRIS-7d41-5g)" value="ARRIS-7D41-5G" style="width: 250px;">
                <input type="password" id="wifi-password" placeholder="Password" value="535102108332" style="width: 250px; margin-left: 10px;">
                <button class="status-button" onclick="connectToWifi()" style="margin-left: 10px;">Connect</button>
            </td>
        </tr>
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
        function connectToWifi() {
        const ssid = document.getElementById('wifi-ssid').value.trim();
        const password = document.getElementById('wifi-password').value.trim();

        if (!ssid || !password) {
            alert("Please enter both Wi-Fi SSID and Password.");
            return;
        }

        if (!confirm(`Attempt to connect to Wi-Fi network "${ssid}"? This might temporarily disconnect your current connection.`)) {
            return;
        }

        const connectBtn = document.querySelector('#wifi-ssid ~ button'); // Select the connect button
        connectBtn.disabled = true;
        connectBtn.textContent = 'Connecting...';

        fetch('/connect_wifi', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ssid: ssid, password: password })
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            console.log(data.message);
        })
        .catch(error => {
            console.error('Error connecting to Wi-Fi:', error);
            alert('Failed to connect to Wi-Fi. Check console for details and ensure the script has administrative privileges.');
        })
        .finally(() => {
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect';
            // You might want to automatically refresh status or wait a bit
            // and then check connectivity
            // setTimeout(fetchStatus, 5000);
        });
    }

    function restartP2Pool() {
    if (!confirm("Are you sure you want to restart P2Pool? This will temporarily stop mining.")) {
        return;
    }

    const restartBtn = document.getElementById('restart-p2pool-btn');
    restartBtn.disabled = true;
    restartBtn.textContent = 'Restarting...';

    fetch('/restart_p2pool', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        console.log(data.message);
        // You might want to automatically fetch status after a short delay
        // to see the new P2Pool status
        setTimeout(fetchStatus, 3000); // Fetch status after 3 seconds
    })
    .catch(error => {
        console.error('Error restarting P2Pool:', error);
        alert('Failed to restart P2Pool. Check console for details.');
    })
    .finally(() => {
        restartBtn.disabled = false;
        restartBtn.textContent = 'Restart P2Pool';
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
        .then(response => {
            if (!response.ok) {
                // If response is not OK, try to read error message from body
                return response.json().then(errorData => {
                    throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
                });
            }
            return response.json(); // Expect a JSON response
        })
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
    // Correctly initialize status_output with a JSON string if it's not a dict
    renderStatus({{ status_output | tojson }});
});
</script>

</body>
</html>
"""


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
    client_status[client_id] = 'Stopped'
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
    return f"Command 'set_threads' queued for client '{client_id}' with {new_threads} threads.", 200


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
            match = re.match(r'^\s*(.*?)\s*=\s*(.*)$', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                data[current_section][key] = value
    return data


@app.route("/status", methods=["POST"])
def get_status_output():
    global p2pool_proc, p2pool_status_output

    if p2pool_proc and p2pool_proc.poll() is None and p2pool_proc.stdin:
        try:
            p2pool_proc.stdin.write("status\n")
            p2pool_proc.stdin.flush()

            time.sleep(0.5)  # Give the redirect_output thread a moment to write

            if not os.path.exists(RAW_LOG):
                p2pool_status_output = {"error": "P2Pool raw log file does not exist yet."}
                return jsonify(p2pool_status_output), 503

            with open(RAW_LOG, "r", encoding="utf-8") as f:
                log_content = f.read()

            last_status_pos = log_content.rfind("SideChain status")
            if last_status_pos == -1:
                p2pool_status_output = {"error": "Status report not found in logs yet. P2Pool might be starting up."}
                return jsonify(p2pool_status_output), 404

            raw_text = log_content[last_status_pos:]
            p2pool_status_output = parse_p2pool_status(raw_text)
            return jsonify(p2pool_status_output)

        except FileNotFoundError:
            p2pool_status_output = {"error": f"P2Pool raw log file '{RAW_LOG}' not found."}
            return jsonify(p2pool_status_output), 500
        except Exception as e:
            p2pool_status_output = {"error": str(e)}
            return jsonify(p2pool_status_output), 500
    else:
        p2pool_status_output = {"error": "P2Pool is not running or its stdin pipe is closed."}
        return jsonify(p2pool_status_output), 503


@app.route("/")
def index():
    shares_found = []
    jobs_sent = []
    miner_data = []
    blocks_found = []
    other_events = []

    if os.path.exists(EVENT_LOG):  # Check if the event log file exists
        with open(EVENT_LOG, "r", encoding="utf-8") as f:
            for line in list(f.readlines()):
                match = re.match(r"\[(.*?)\] \[(.*?)\] (.*)", line, re.DOTALL)
                if match:
                    event = {
                        "time": match.group(1),
                        "type": match.group(2),
                        "message": match.group(3).strip()
                    }
                    if event["type"] == "Found Share":
                        shares_found.insert(0, event)
                    elif event["type"] == "Sent Jobs":
                        jobs_sent.insert(0, event)
                    elif event["type"] == "New Miner Data":
                        miner_data.insert(0, event)
                    elif event["type"] == "Found Block":  # This is where "Found Block" is classified
                        blocks_found.insert(0, event)
                    else:
                        other_events.insert(0, event)

    total_hashrate = round(sum(client_hashrates.values()), 2)
    total_cpu_shares = sum(client_cpu_shares.values())
    total_gpu_shares = sum(client_nvidia_shares.values())
    total_power_draw_values = [p for p in client_power_draws.values() if isinstance(p, (int, float)) and p != "N/A"]
    total_power_draw = round(sum(total_power_draw_values), 2) if total_power_draw_values else "N/A"

    # Calculate average CPU temp if available
    valid_cpu_temps = []
    for temp_str in client_temps.values():
        if isinstance(temp_str, str) and '°C' in temp_str:
            try:
                # Extract numerical part before °C
                temp_c = float(temp_str.split('°C')[0].strip())
                valid_cpu_temps.append(temp_c)
            except ValueError:
                continue  # Skip if parsing fails
    average_temp = round(sum(valid_cpu_temps) / len(valid_cpu_temps), 1) if valid_cpu_temps else "N/A"

    total_cost = round(sum(client_costs.values()), 4)

    limit = 500
    joblimit = 20
    minerlimit = 20

    client_last_seen_formatted = {}
    for cid, timestamp in client_last_seen.items():
        client_last_seen_formatted[cid] = time_ago(timestamp)

    return render_template_string(HTML,
                                  hashrates=client_hashrates,
                                  newjobs=client_newjobs,
                                  client_power_draws=client_power_draws,
                                  client_costs=client_costs,
                                  client_last_seen=client_last_seen_formatted,
                                  client_status=client_status,
                                  client_cpu_shares=client_cpu_shares,
                                  client_gpu_stats=client_gpu_stats,
                                  client_nvidia_shares=client_nvidia_shares,
                                  status_output=p2pool_status_output,
                                  threads=client_threads,
                                  temps=client_temps,
                                  total_cost=total_cost,
                                  total_hashrate=total_hashrate,
                                  total_cpu_shares=total_cpu_shares,
                                  total_gpu_shares=total_gpu_shares,
                                  total_power_draw=total_power_draw,
                                  average_temp=average_temp,  # Pass average temp
                                  shares=shares_found[:limit],
                                  jobs=jobs_sent[:joblimit],
                                  miners=miner_data[:minerlimit],
                                  blocks=blocks_found[:minerlimit],
                                  other=other_events[:minerlimit])


@app.route("/hashrate", methods=["POST"])
def receive_hashrate():
    data = request.get_json()
    if not data or "client_id" not in data:
        return "Bad Request", 400

    client_id = data["client_id"]
    if client_status.get(client_id) == "Disconnected":
        print(f"[+] Client '{client_id}' reconnected.")

    client_hashrates[client_id] = data.get("hashrate", 0)
    client_threads[client_id] = data.get("threads", 0)
    client_temps[client_id] = data.get("cpu_temp", "N/A")
    client_last_seen[client_id] = time.time()

    client_cpu_shares[client_id] = data.get("cpu_accepted_shares", 0)
    client_nvidia_shares[client_id] = data.get("nvidia_accepted_shares", 0)
    client_gpu_stats[client_id] = {
        "temp": data.get("gpu_temp", "N/A"),
        "fan": data.get("gpu_fan", "N/A")
    }
    client_power_draws[client_id] = data.get("power_draw", "N/A")

    if client_id not in client_start_times:
        client_start_times[client_id] = time.time()

    elapsed_hours = (time.time() - client_start_times[client_id]) / 3600

    power_watts = data.get("power_draw", 0)
    if isinstance(power_watts, (int, float)) and power_watts != "N/A" and power_watts > 0:
        kilowatts = power_watts / 1000
        kwh_used = kilowatts * elapsed_hours
        cost = kwh_used * ELECTRICITY_RATE_PER_KWH
        client_costs[client_id] = round(cost, 4)
    else:
        client_costs[client_id] = 0.0

    command = COMMAND_QUEUE.pop(client_id, None)
    return jsonify(command) if command else jsonify({"message": "ok"})


@app.route("/newjob", methods=["POST"])
def receive_newjob():
    data = request.get_json()
    if data and "client_id" in data:
        client_newjobs[data["client_id"]] = data
        return "OK", 200
    return "Bad Request", 400


def start_flask():
    # Use a more robust way to get local IP if 0.0.0.0 is not desired for display
    # host_ip = "0.0.0.0" # Listen on all interfaces
    # You might want to get the actual LAN IP for display purposes if multiple interfaces
    # import socket
    # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # try:
    #     s.connect(("8.8.8.8", 80)) # Doesn't actually send data
    #     host_ip = s.getsockname()[0]
    # except Exception:
    #     pass
    # finally:
    #     s.close()
    app.run(host="0.0.0.0", port=5000, debug=False)  # Set debug=False for production

def clear_all_client_data():
    """
    Clears all data associated with connected clients.
    Call this on startup to ensure a fresh dashboard state.
    """
    global client_hashrates, client_newjobs, client_threads, client_last_seen, \
           client_temps, client_status, client_cpu_shares, client_nvidia_shares, \
           client_gpu_stats, client_power_draws, client_start_times, client_costs, \
           COMMAND_QUEUE

    print("[!] Clearing all existing client data on startup...")
    client_hashrates.clear()
    client_newjobs.clear()
    client_threads.clear()
    client_last_seen.clear()
    client_temps.clear()
    client_status.clear()
    client_cpu_shares.clear()
    client_nvidia_shares.clear()
    client_gpu_stats.clear()
    client_power_draws.clear()
    client_start_times.clear()
    client_costs.clear()
    COMMAND_QUEUE.clear() # Clear any commands from a previous run
    log_event_now("System Startup", "All client data cleared.")
    print("[+] Client data cleared successfully.")

if __name__ == "__main__":
    clear_all_client_data()
    # Start Flask server first, as it's the main interface
    threading.Thread(target=start_flask, daemon=True).start()
    # Start the log writer thread. It will create EVENT_LOG if it doesn't exist.
    threading.Thread(target=log_writer, daemon=True).start()

    # Attempt to start P2Pool
    if start_p2pool_direct():
        # Start the P2Pool log tailer only if P2Pool was successfully launched.
        # It will wait for RAW_LOG to be created.
        threading.Thread(target=tail_p2pool_log, daemon=True).start()
        handle_user_input(p2pool_proc)
    else:
        print("[!] Could not start P2Pool. Exiting.")
        # If P2Pool doesn't start, gracefully exit after a brief pause
        time.sleep(5)  # Give Flask a moment to be accessible if needed for error viewing
        os._exit(1)  # Force exit if P2Pool didn't start