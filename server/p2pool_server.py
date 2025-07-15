import asyncio
import subprocess
import sys
import time
import os
import threading
import re
from flask import Flask, request, jsonify, redirect, url_for, render_template, send_from_directory
from flask_cors import CORS
from p2pool_data import P2poolData, EventProcessor, RawLogProcessor, P2PoolProcessor, AsyncEventLogger
from client_data import ClientData
from waitress import serve

asyncio_main_loop = None
p2pooldata = P2poolData()
clientdata = ClientData()
event_processor = EventProcessor(p2pooldata)
raw_log_processor = RawLogProcessor(p2pooldata)
processor = P2PoolProcessor(p2pooldata)
ELECTRICITY_RATE_PER_KWH = 0.13
COMMAND_QUEUE = {}

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # Running in a PyInstaller bundle
    BASE_DIR = sys._MEIPASS
else:
    # Running as a normal Python script
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# === FLASK ===
app = Flask(
    __name__,
    static_folder='p2pool-dashboard/dist'
)
CORS(app)


def queue_command(client_id, command_data):
    """
    Safely adds a command to a client's command list in the queue.
    Initializes the list if the client is new.
    """
    # If the client doesn't have a queue yet, create one.
    if client_id not in COMMAND_QUEUE:
        COMMAND_QUEUE[client_id] = []

    # Append the new command to the client's list.
    COMMAND_QUEUE[client_id].append(command_data)
    print(f"[+] Queued command for '{client_id}': {command_data}")

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
                p2pooldata.log_event_now("Network Control",
                                         f"Warning: Failed to delete Wi-Fi profile for '{ssid}': {delete_result.stderr.strip()}")

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
        connect_command = f'netsh wlan connect name="{ssid}" ssid="{ssid}"'  # ssid param sometimes needed
        subprocess.run(connect_command, shell=True, check=True)
        p2pooldata.log_event_now("Network Control", f"Attempted to connect to Wi-Fi network: '{ssid}'.")

        # Clean up the temporary XML file
        os.remove(temp_xml_path)

        return jsonify(
            {"status": "success", "message": f"Attempted to connect to Wi-Fi network: {ssid}. Check network status."})

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
    global asyncio_main_loop

    async def restart_async():
        if p2pooldata.p2pool_proc and p2pooldata.p2pool_proc.returncode is None:
            print("[!] Attempting to restart P2Pool: Terminating existing process...")
            try:
                await processor.stop_p2pool()
                print("[+] Existing P2Pool process terminated.")
                clear_file_contents(p2pooldata.RAW_LOG)
            except Exception as e:
                print(f"[!] Error terminating P2Pool process: {e}")

        try:
            success = await processor.start_p2pool()
            if success:
                print("[+] P2Pool restarted successfully.")
                return jsonify({"status": "success", "message": "P2Pool restarted successfully."})
            else:
                raise RuntimeError("start_p2pool returned False")
        except Exception as e:
            print(f"[!] Failed to restart P2Pool: {e}")
            p2pooldata.log_event_now("P2Pool Control", f"Failed to restart P2Pool process: {e}")
            return jsonify({"status": "error", "message": f"Failed to restart P2Pool: {e}"}), 500

    try:
        asyncio_main_loop.create_task(restart_async())
        return jsonify({"status": "pending", "message": "Restart initiated in background."})
    except RuntimeError:
        # fallback for sync-only environment (rare in your case)
        asyncio_main_loop.run(restart_async())
        return jsonify({"status": "success", "message": "Restart completed synchronously."})

@app.route("/api/memory", methods=["GET"])
def get_memory():

    return jsonify({"cpu_usage": processor.cpu_usage, "ram_usage": processor.ram_usage_mb, "vms_usage": processor.vms_usage_mb, "num_page_faults": processor.num_page_faults, "paged_pool": processor.paged_pool_mb, "page_file": processor.page_file_mb})


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
                "difficulty": j.get("difficulty"),
                "height": j.get("height"),
                "algo": j.get("algo"),
                "tx_count": j.get("tx_count"),
                "ip": j.get("ip"),
            } for cid, j in clientdata.client_newjobs.items()
        }
    }
    return jsonify(data)


@app.route("/miners/<client_id>", methods=["POST"])
def update_miner_status(client_id):
    """
    Endpoint for clients to report their running status.
    Clears stale metrics on stopped/error clients.
    """
    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({"error": "Invalid payload. 'status' is required."}), 400

    status = data['status'].strip().capitalize()

    print(f"[+] Received status update from '{client_id}': {status}")
    clientdata.client_status[client_id] = status

    return jsonify({"message": "Status updated successfully"}), 200


@app.route("/start_miner/<client_id>", methods=["POST"])
def start_miner(client_id):
    pool = request.form.get("pool")
    threads = request.form.get("threads")
    if not pool or not threads:
        return "Pool and threads are required.", 400

    command_data = {
        "command": "start",
        "pool": pool,
        "threads": int(threads)
    }
    queue_command(client_id, command_data)
    print(f"[+] Queued START command for '{client_id}'")

    return jsonify({"status": "success", "message": f"Start command queued for {client_id}"})

@app.route("/stop_miner/<client_id>", methods=["POST"])
def stop_miner(client_id):
    queue_command(client_id, {"command": "stop"})
    print(f"[+] Queued STOP command for '{client_id}'")
    return jsonify({"status": "ok", "message": f"Stop command queued for {client_id}"})


@app.route("/set_threads/<client_id>", methods=["POST"])
def set_threads(client_id):
    try:
        new_threads = int(request.form["threads"])
    except (ValueError, KeyError):
        return jsonify({"status": "error", "message": "Invalid thread count provided"}), 400

    command_data = {"command": "set_threads", "threads": new_threads}
    queue_command(client_id, command_data)
    print(f"[+] Command queued for '{client_id}': Set threads to {new_threads}")
    return jsonify({"status": "ok", "message": f"Set thread command queued for {client_id}"})


@app.route("/get_command/<client_id>", methods=["GET"])
def get_command(client_id):
    """
    Allows clients to poll for and receive the oldest command in their queue.
    """
    if client_id in COMMAND_QUEUE and COMMAND_QUEUE[client_id]:
        # Pop the oldest command (at index 0) from the list
        command = COMMAND_QUEUE[client_id].pop(0)
        p2pooldata.log_event_now("Command", f"sent command to '{client_id}': {command}")
        print(f"[-] De-queued and sent command to '{client_id}': {command}")
        return jsonify(command)

    # Return an empty object if no command is available
    return jsonify({})



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
    global asyncio_main_loop

    # Check if the process is running using the processor instance
    if p2pooldata.p2pool_proc and p2pooldata.p2pool_proc.returncode is None:
        try:
            # Asynchronously send the 'status' command.
            # The processor.write_to_stdin method handles the encoding.
            future = asyncio.run_coroutine_threadsafe(processor.write_to_stdin("status"), asyncio_main_loop)
            success = future.result(timeout=5) # Wait for the command to be sent

            if not success:
                raise Exception("Failed to write to P2Pool stdin. Pipe may be closed.")

            time.sleep(0.5)  # Give redirect thread time to write to log

            # The rest of your file-reading logic is correct
            if not os.path.exists(p2pooldata.RAW_LOG):
                return jsonify({"error": "P2Pool raw log file does not exist yet."}), 503

            with open(p2pooldata.RAW_LOG, "r", encoding="utf-8") as f:
                log_content = f.read()

            last_status_pos = log_content.rfind("SideChain status")
            if last_status_pos == -1:
                return jsonify({"error": "Status not found in logs. P2Pool may be starting."}), 404

            raw_text = log_content[last_status_pos:]
            return jsonify(parse_p2pool_status(raw_text))

        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "P2Pool is not running."}), 503




@app.route("/api/lastseen", methods=["GET"])
def get_last_seen():
    client_last_seen_formatted = {}
    for cid, timestamp in clientdata.client_last_seen.items():
        client_last_seen_formatted[cid] = p2pooldata.time_ago(timestamp)
    return jsonify({"client_last_seen_formatted": client_last_seen_formatted})
@app.route("/api/totals", methods=["GET"])
def get_totals():
    total_hashrate = round(sum(clientdata.client_hashrates.values()), 2)
    total_cpu_shares = sum(clientdata.client_cpu_shares.values())
    total_gpu_shares = sum(clientdata.client_nvidia_shares.values())
    total_power_draw_values = [p for p in clientdata.client_power_draws.values() if
                               isinstance(p, (int, float)) and p != "N/A"]
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
    return jsonify({"total_hashrate":total_hashrate, "total_cpu_shares":total_cpu_shares,"total_gpu_shares":total_gpu_shares, "total_temp":average_temp, "total_cost":total_cost, "total_power_draw":total_power_draw})
@app.route("/api/events", methods=["GET"])
def get_events():
    """
    Efficiently gets the latest events from the in-memory cache
    managed by the EventProcessor.
    """
    # Allow the client to request a different number of events
    try:
        limit = int(request.args.get('limit', 10))
    except (ValueError, TypeError):
        limit = 10

    events = event_processor.get_all_events(limit=limit)
    return jsonify(events)
@app.route("/hashrate", methods=["POST"])
def receive_hashrate():
    data = request.get_json()
    if not data or "client_id" not in data:
        return "Bad Request", 400

    client_id = data["client_id"]

    # Record the client's start time on their very first report
    if client_id not in clientdata.client_start_times:
        print(f"[+] First report from new client '{client_id}'. Recording start time.")
        clientdata.client_start_times[client_id] = time.time()

    # --- ✅ Sanitize Power Draw Input ---
    power_watts = 0.0
    power_draw_raw = data.get("power_draw", "0.0")

    # Check if the power draw data is a string that needs cleaning
    if isinstance(power_draw_raw, str):
        # Remove the "W" and any extra whitespace before converting
        cleaned_str = power_draw_raw.replace("W", "", 2).strip()
        try:
            power_watts = float(cleaned_str)
        except (ValueError, TypeError):
            # If conversion fails after cleaning, default to 0
            power_watts = 0.0
    # If it's already a number, use it directly
    elif isinstance(power_draw_raw, (int, float)):
        power_watts = float(power_draw_raw)

    # --- Update Basic Client Data ---
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
    # Store the cleaned numerical value
    clientdata.client_power_draws[client_id] = power_watts

    # --- Cost Calculation Based on Total Uptime ---
    start_time = clientdata.client_start_times.get(client_id)

    if start_time:
        # Calculate total uptime in hours
        total_uptime_seconds = time.time() - start_time
        total_uptime_hours = total_uptime_seconds / 3600

        # Calculate total energy consumed in kWh and the total cost
        if power_watts > 0 and total_uptime_hours > 0:
            total_kwh_used = (power_watts / 1000) * total_uptime_hours
            total_cost = total_kwh_used * ELECTRICITY_RATE_PER_KWH

            # Update the client's total cost
            clientdata.client_costs[client_id] = total_cost

    return jsonify({"message": "ok"})

@app.route("/newjob", methods=["POST"])
def receive_newjob():
    data = request.get_json()
    if data and "client_id" in data:
        clientdata.client_newjobs[data["client_id"]] = data
        return "OK", 200
    return "Bad Request", 400


# --- NEW UPDATE CLIENT ENDPOINT ---
@app.route("/update_client/<client_id>", methods=["POST"])
def update_client(client_id):
    """Queues a remote 'update' command for a specific client."""
    if client_id not in clientdata.client_status:
        return jsonify({"status": "error", "message": "Client not found."}), 404

    download_url = f"http://192.168.0.10:5000/download/client"

    command = {
        "command": "update",
        "url": download_url
    }
    queue_command(client_id, command)
    print(f"[+] Queued UPDATE command for '{client_id}'")
    message = f"Update command queued for client '{client_id}."

    return jsonify({"status": "success", "message": message})


# --- NEW DOWNLOAD ENDPOINT ---
@app.route("/download/client")
def download_client():
    """Endpoint to serve the client.exe file for updates."""
    # IMPORTANT: This path is hardcoded as per the request.
    # For better portability, consider making this path configurable.
    directory = r"X:\Users\natem\PycharmProjects\moneroProject\dist"
    filename = "client.exe"

    # Security check: Ensure the file exists before attempting to send it.
    if not os.path.exists(os.path.join(directory, filename)):
        p2pooldata.log_event_now("File Server",
                                 f"Error: Client download failed. File not found at {directory}\\{filename}")
        return "File not found.", 404

    p2pooldata.log_event_now("File Server", f"Client download initiated for {filename}.")
    return send_from_directory(directory, filename, as_attachment=True)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')
def start_flask():

    serve(app, host="0.0.0.0", port=5000)


def clear_file_contents(filepath):
    """
    Clears the content of a file. If the file does not exist, it will be created.
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.truncate(0)  # Ensures the file is empty, even if opened in r+ mode
        print(f"[+] Cleared contents of: {filepath}")
    except Exception as e:
        print(f"[!] Error clearing file {filepath}: {e}")


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
    COMMAND_QUEUE.clear()  # Clear any commands from a previous run
    p2pooldata.log_event_now("System Startup", "All client data cleared.")
    print("[+] Client data cleared successfully.")


async def main():
    global asyncio_main_loop
    """Main async function to run the application."""
    print("[+] Initializing application...")

    # --- Startup Tasks ---
    clear_file_contents(p2pooldata.EVENT_LOG)
    clear_file_contents(p2pooldata.RAW_LOG)

    asyncio_main_loop = asyncio.get_running_loop()
    async_event_logger = AsyncEventLogger(p2pooldata, asyncio_main_loop)
    # --- Start Background Services (Threads) ---
    # These can remain as standard threads
    raw_log_thread = threading.Thread(target=raw_log_processor.run_in_background, daemon=True)
    raw_log_thread.start()
    print("[+] Raw log processor thread started.")

    log_writer_thread = threading.Thread(target=async_event_logger.start, daemon=True)
    log_writer_thread.start()
    print("[+] Log writer thread started.")

    event_processor_thread = threading.Thread(target=event_processor.run_in_background, daemon=True)
    event_processor_thread.start()
    print("[+] Event processor thread started.")

    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    print("[+] Flask server thread started.")

    # --- P2Pool Process Handling using the new async class ---

    if not await processor.start_p2pool():
        print("[!] CRITICAL: Could not start P2Pool. Shutting down.")
        return # Exit if P2Pool fails to start

    # --- Main Loop to Keep Server Running ---
    print("[+] Server is running. Press CTRL+C to shut down.")
    try:
        while True:
            # Use asyncio.sleep to prevent blocking the event loop
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal (Ctrl+C) received...")
    finally:
        # Gracefully stop the P2Pool process
        await processor.stop_p2pool()
        print("[+] Shutdown complete.")

if __name__ == "__main__":
    # Use asyncio.run() to start the main async function
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # This handles Ctrl+C if it happens during initial setup before the main loop
        print("\n[!] Application startup interrupted.")
