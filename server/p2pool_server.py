import subprocess
import sys
import time
import os
import threading
import re
from flask import Flask, request, jsonify, redirect, url_for, render_template

from p2pool_data import P2poolData
from client_data import ClientData
p2pooldata = P2poolData()
clientdata = ClientData()
ELECTRICITY_RATE_PER_KWH = 0.13
COMMAND_QUEUE = {}

current_hashrate = 0.0
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # Running in a PyInstaller bundle
    BASE_DIR = sys._MEIPASS
else:
    # Running as a normal Python script
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))


# === FLASK ===
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)

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
            p2pooldata.log_event_now("Network Control", f"Deleted existing Wi-Fi profile for '{ssid}'.")
        else:
            # It's common for deletion to fail if the profile doesn't exist, not an error.
            if "profile \"" + ssid + "\" is not found" not in delete_result.stderr:
                p2pooldata.log_event_now("Network Control", f"Warning: Failed to delete Wi-Fi profile for '{ssid}': {delete_result.stderr.strip()}")

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
        temp_xml_path = os.path.join(p2pooldata.P2POOL_DIR, f"{ssid}_profile.xml")
        with open(temp_xml_path, "w", encoding="utf-8") as f:
            f.write(profile_xml)

        # 3. Add the profile
        add_profile_command = f'netsh wlan add profile filename="{temp_xml_path}"'
        subprocess.run(add_profile_command, shell=True, check=True)
        p2pooldata.log_event_now("Network Control", f"Added Wi-Fi profile for '{ssid}'.")

        # 4. Connect to the profile
        connect_command = f'netsh wlan connect name="{ssid}" ssid="{ssid}"' # ssid param sometimes needed
        subprocess.run(connect_command, shell=True, check=True)
        p2pooldata.log_event_now("Network Control", f"Attempted to connect to Wi-Fi network: '{ssid}'.")

        # Clean up the temporary XML file
        os.remove(temp_xml_path)

        return jsonify({"status": "success", "message": f"Attempted to connect to Wi-Fi network: {ssid}. Check network status."})

    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to connect to Wi-Fi network '{ssid}'. Error: {e.stderr.strip()}. Ensure script is run as administrator."
        p2pooldata.log_event_now("Network Control", error_msg)
        # Attempt to clean up XML even on error
        if os.path.exists(temp_xml_path):
            os.remove(temp_xml_path)
        return jsonify({"status": "error", "message": error_msg}), 500
    except Exception as e:
        error_msg = f"An unexpected error occurred during Wi-Fi connection: {e}"
        p2pooldata.log_event_now("Network Control", error_msg)
        if os.path.exists(temp_xml_path):
            os.remove(temp_xml_path)
        return jsonify({"status": "error", "message": error_msg}), 500
@app.route("/restart_p2pool", methods=["POST"])
def restart_p2pool():


    if p2pooldata.p2pool_proc and p2pooldata.p2pool_proc.poll() is None:
        print("[!] Attempting to restart P2Pool: Terminating existing process...")
        try:
            # Send SIGTERM to allow for graceful shutdown
            p2pooldata.p2pool_proc.terminate()
            p2pooldata.p2pool_proc.wait(timeout=10) # Wait for process to terminate
            print("[+] Existing P2Pool process terminated.")
        except subprocess.TimeoutExpired:
            print("[!] P2Pool process did not terminate gracefully, forcing kill.")
            p2pooldata.p2pool_proc.kill()
        except Exception as e:
            print(f"[!] Error terminating P2Pool process: {e}")

    # Clear previous status to indicate restart
    p2pool_status_output = {"message": "P2Pool is restarting..."}

    # Attempt to start a new P2Pool process
    success = p2pooldata.start_p2pool_direct()
    if success:
        print("[+] P2Pool restarted successfully.")
        p2pooldata.log_event_now("P2Pool Control", "P2Pool process restarted.")
        return jsonify({"status": "success", "message": "P2Pool restarted successfully."})
    else:
        print("[!] Failed to restart P2Pool.")
        p2pool_status_output = {"error": "Failed to restart P2Pool. Check logs."}
        p2pooldata.log_event_now("P2Pool Control", "Failed to restart P2Pool process.")
        return jsonify({"status": "error", "message": "Failed to restart P2Pool."}), 500


@app.route("/api/clients", methods=["GET"])
def get_clients():
    client_last_seen_formatted = {
        cid: p2pooldata.time_ago(ts) for cid, ts in clientdata.client_last_seen.items()
    }

    data = {
        "hashrates": clientdata.client_hashrates,
        "threads": clientdata.client_threads,
        "temps": clientdata.client_temps,
        "power_draws": clientdata.client_power_draws,
        "costs": clientdata.client_costs,
        "status": clientdata.client_status,
        "cpu_shares": clientdata.client_cpu_shares,
        "nvidia_shares": clientdata.client_nvidia_shares,
        "gpu_stats": clientdata.client_gpu_stats,
        "last_seen": client_last_seen_formatted,
        "newjobs": {
            cid: {
                "difficulty": j.difficulty if hasattr(j, "difficulty") else None,
                "height": j.height if hasattr(j, "height") else None,
                "algo": j.algo if hasattr(j, "algo") else None,
                "tx_count": j.tx_count if hasattr(j, "tx_count") else None,
                "ip": j.ip if hasattr(j, "ip") else None,
            } for cid, j in clientdata.client_newjobs.items()
        }
    }
    return jsonify(data)

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
    clientdata.client_status[client_id] = status
    # If stopped, also clear hashrate
    if status in ['Stopped', 'Error']:
        clientdata.client_hashrates[client_id] = 0

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
    clientdata.client_status[client_id] = 'Stopped'
    clientdata.client_hashrates[client_id] = 0
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

    if p2pooldata.p2pool_proc and p2pooldata.p2pool_proc.poll() is None and p2pooldata.p2pool_proc.stdin:
        try:
            p2pooldata.p2pool_proc.stdin.write("status\n")
            p2pooldata.p2pool_proc.stdin.flush()

            time.sleep(0.5)  # Give the redirect_output thread a moment to write

            if not os.path.exists(p2pooldata.RAW_LOG):
                p2pool_status_output = {"error": "P2Pool raw log file does not exist yet."}
                return jsonify(p2pool_status_output), 503

            with open(p2pooldata.RAW_LOG, "r", encoding="utf-8") as f:
                log_content = f.read()

            last_status_pos = log_content.rfind("SideChain status")
            if last_status_pos == -1:
                p2pool_status_output = {"error": "Status report not found in logs yet. P2Pool might be starting up."}
                return jsonify(p2pool_status_output), 404

            raw_text = log_content[last_status_pos:]
            p2pool_status_output = parse_p2pool_status(raw_text)
            return jsonify(p2pool_status_output)

        except FileNotFoundError:
            p2pool_status_output = {"error": f"P2Pool raw log file '{p2pooldata.RAW_LOG}' not found."}
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

    if os.path.exists(p2pooldata.EVENT_LOG):  # Check if the event log file exists
        with open(p2pooldata.EVENT_LOG, "r", encoding="utf-8") as f:
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

    total_hashrate = round(sum(clientdata.client_hashrates.values()), 2)
    total_cpu_shares = sum(clientdata.client_cpu_shares.values())
    total_gpu_shares = sum(clientdata.client_nvidia_shares.values())
    total_power_draw_values = [p for p in clientdata.client_power_draws.values() if isinstance(p, (int, float)) and p != "N/A"]
    total_power_draw = round(sum(total_power_draw_values), 2) if total_power_draw_values else "N/A"

    # Calculate average CPU temp if available
    valid_cpu_temps = []
    for temp_str in clientdata.client_temps.values():
        if isinstance(temp_str, str) and '°C' in temp_str:
            try:
                # Extract numerical part before °C
                temp_c = float(temp_str.split('°C')[0].strip())
                valid_cpu_temps.append(temp_c)
            except ValueError:
                continue  # Skip if parsing fails
    average_temp = round(sum(valid_cpu_temps) / len(valid_cpu_temps), 1) if valid_cpu_temps else "N/A"

    total_cost = round(sum(clientdata.client_costs.values()), 4)

    limit = 500
    joblimit = 20
    minerlimit = 20

    client_last_seen_formatted = {}
    for cid, timestamp in clientdata.client_last_seen.items():
        client_last_seen_formatted[cid] = p2pooldata.time_ago(timestamp)

    return render_template("frontend.html",
                                  hashrates=clientdata.client_hashrates,
                                  newjobs=clientdata.client_newjobs,
                                  client_power_draws=clientdata.client_power_draws,
                                  client_costs=clientdata.client_costs,
                                  client_last_seen=client_last_seen_formatted,
                                  client_status=clientdata.client_status,
                                  client_cpu_shares=clientdata.client_cpu_shares,
                                  client_gpu_stats=clientdata.client_gpu_stats,
                                  client_nvidia_shares=clientdata.client_nvidia_shares,
                                  status_output=p2pooldata.p2pool_status_output,
                                  threads=clientdata.client_threads,
                                  temps=clientdata.client_temps,
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
    if clientdata.client_status.get(client_id) == "Disconnected":
        print(f"[+] Client '{client_id}' reconnected.")

    clientdata.client_hashrates[client_id] = data.get("hashrate", 0)
    clientdata.client_threads[client_id] = data.get("threads", 0)
    clientdata.client_temps[client_id] = data.get("cpu_temp", "N/A")
    clientdata.client_last_seen[client_id] = time.time()

    clientdata.client_cpu_shares[client_id] = data.get("cpu_accepted_shares", 0)
    clientdata.client_nvidia_shares[client_id] = data.get("nvidia_accepted_shares", 0)
    clientdata.client_gpu_stats[client_id] = {
        "temp": data.get("gpu_temp", "N/A"),
        "fan": data.get("gpu_fan", "N/A")
    }
    clientdata.client_power_draws[client_id] = data.get("power_draw", "N/A")

    if client_id not in clientdata.client_start_times:
        clientdata.client_start_times[client_id] = time.time()

    elapsed_hours = (time.time() - clientdata.client_start_times[client_id]) / 3600

    power_watts = data.get("power_draw", 0)
    if isinstance(power_watts, (int, float)) and power_watts != "N/A" and power_watts > 0:
        kilowatts = power_watts / 1000
        kwh_used = kilowatts * elapsed_hours
        cost = kwh_used * ELECTRICITY_RATE_PER_KWH
        clientdata.client_costs[client_id] = round(cost, 4)
    else:
        clientdata.client_costs[client_id] = 0.0

    command = COMMAND_QUEUE.pop(client_id, None)
    return jsonify(command) if command else jsonify({"message": "ok"})


@app.route("/newjob", methods=["POST"])
def receive_newjob():
    data = request.get_json()
    if data and "client_id" in data:
        clientdata.client_newjobs[data["client_id"]] = data
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


    print("[!] Clearing all existing client data on startup...")
    clientdata.client_hashrates.clear()
    clientdata.client_newjobs.clear()
    clientdata.client_threads.clear()
    clientdata.client_last_seen.clear()
    clientdata.client_temps.clear()
    clientdata.client_status.clear()
    clientdata.client_cpu_shares.clear()
    clientdata.client_nvidia_shares.clear()
    clientdata.client_gpu_stats.clear()
    clientdata.client_power_draws.clear()
    clientdata.client_start_times.clear()
    clientdata.client_costs.clear()
    COMMAND_QUEUE.clear() # Clear any commands from a previous run
    p2pooldata.log_event_now("System Startup", "All client data cleared.")
    print("[+] Client data cleared successfully.")

if __name__ == "__main__":
    clear_all_client_data()
    # Start Flask server first, as it's the main interface
    threading.Thread(target=start_flask, daemon=True).start()
    # Start the log writer thread. It will create EVENT_LOG if it doesn't exist.
    threading.Thread(target=p2pooldata.log_writer, daemon=True).start()

    # Attempt to start P2Pool
    if p2pooldata.start_p2pool_direct():
        # Start the P2Pool log tailer only if P2Pool was successfully launched.
        # It will wait for RAW_LOG to be created.
        threading.Thread(target=p2pooldata.tail_p2pool_log, daemon=True).start()
        p2pooldata.handle_user_input(p2pooldata.p2pool_proc)
    else:
        print("[!] Could not start P2Pool. Exiting.")
        # If P2Pool doesn't start, gracefully exit after a brief pause
        time.sleep(5)  # Give Flask a moment to be accessible if needed for error viewing
        os._exit(1)  # Force exit if P2Pool didn't start