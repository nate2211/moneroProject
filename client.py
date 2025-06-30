import json
import subprocess
import threading
import ctypes
import sys
import os
import time
import queue
import re
import requests
import wmi
import pythoncom
# === CONFIGURATION ===
XMRIG_PATH = os.path.join(os.getcwd(), "xmrig.exe")
CONFIG_PATH = os.path.join(os.getcwd(), "config.json")
# Prevent system from sleeping
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)

# === GLOBALS ===
xmrig_process = None
output_queue = queue.Queue()
FLASK_SERVER_URL = None
client_id = None
miner_lock = threading.Lock()
last_known_pool_url = None
last_known_thread_count = None
client_id = None
custom_pool_url = None
client_status = None
threads = None
# === HELPER FUNCTIONS ===
def get_cpu_temperature():
    """
    Gets CPU temperature on Windows using WMI.
    Returns a formatted string in Fahrenheit or 'N/A'.
    MUST be run with Administrator privileges.
    """
    try:
        # The linter will not complain about this line
        pythoncom.CoInitialize()  # noqa

        # Connect to the WMI namespace that contains thermal data
        c = wmi.WMI(namespace="root\\wmi")
        # Query for the thermal zone information
        temp_info = c.MSAcpi_ThermalZoneTemperature()

        if not temp_info:
            return "N/A"

        # The temperature is given in tenths of a Kelvin.
        # Convert to Celsius: (temp_in_kelvin / 10) - 273.15
        temp_kelvin = temp_info[0].CurrentTemperature
        temp_celsius = (temp_kelvin / 10.0) - 273.15

        # 1. Convert Celsius to Fahrenheit
        temp_fahrenheit = (temp_celsius * 9 / 5) + 32

        # 2. Return the temperature in Fahrenheit
        return f"{temp_fahrenheit:.1f}°F"

    except Exception as e:
        # This error often occurs if the script is not run as an administrator
        print(f"[!] WMI Error: {e}", file=sys.stderr)
        print("[!] Could not get CPU temp. Try running this script as an Administrator.", file=sys.stderr)
        return "N/A"


def get_current_threads_from_config():
    with miner_lock:
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return len(json.load(f).get("cpu", {}).get("rx", []))
        except (IOError, json.JSONDecodeError):
            return 0

def update_config_threads(thread_count):
    with miner_lock:
        try:
            with open(CONFIG_PATH, "r+", encoding="utf-8") as f:
                config = json.load(f)
                config.setdefault("cpu", {})["rx"] = list(range(thread_count))
                f.seek(0)
                json.dump(config, f, indent=4)
                f.truncate()
            print(f"[+] Config updated to {thread_count} threads.")
            return True
        except Exception as e:
            print(f"[!] Failed to update config: {e}")
            return False
# === CORE MINER AND REPORTING LOGIC ===
def monitor_output(process):
    global client_id

    cpu_accepted_shares = 0
    nvidia_accepted_shares = 0
    gpu_temp = ""
    gpu_fan = ""
    hashrate = 0

    for line in iter(process.stdout.readline, b''):
        decoded = line.decode("utf-8", errors="ignore").strip()
        print(f"[XMRIG] {decoded}")
        if "error" in decoded.lower():
            stop_miner()
            time.sleep(30)
            start_miner(custom_pool_url, threads)
        # --- Parse CPU Accepted Shares ---
        if "cpu" in decoded.lower() and "accepted" in decoded.lower():
            match = re.search(r"accepted\s+\((\d+)/\d+\)",decoded.lower())
            if match:
                cpu_accepted_shares = int(match.group(1))

        # --- Parse NVIDIA Accepted Shares ---
        if "nvidia" in decoded.lower() and "accepted" in decoded.lower():
            match = re.search(r"accepted\s+\((\d+)/\d+\)", decoded.lower())
            if match:
                nvidia_accepted_shares = int(match.group(1))

        # --- Parse NVIDIA GPU Stats ---
        if "nvidia" in decoded.lower() and "c" in decoded.lower():
            # Example: [2025-06-29 12:12:06.507]  nvidia   #0 0b:00.0 185W 77C 1905/9251 MHz fan0:75%
            temp_match = re.search(r"(\d+c)", decoded.lower())
            fan_match = re.search(r"fan\d+:(\d+%)", decoded.lower())
            if temp_match:
                gpu_temp = temp_match.group(1)
            if fan_match:
                gpu_fan = fan_match.group(1)
        if "miner" in decoded.lower() and "speed" in decoded.lower():
            match = re.search(r"speed\s+\d+s/\d+s/\d+m\s+([\d.]+)\s+", decoded)
            if match:
                hashrate = float(match.group(1))
        elif "gpu" in decoded.lower() and "compute error" in decoded.lower():
            stop_miner()
            time.sleep(30)
            start_miner(custom_pool_url, threads)
        elif "new job from" in decoded.lower():
            try:
                match = re.search(r"new job from ([\d.:]+).*?diff (\d+).*?algo ([^\s]+).*?height (\d+).*?\((\d+) tx\)", decoded)
                if match:
                    job_info = {
                        "client_id": client_id,
                        "ip": match.group(1),
                        "difficulty": int(match.group(2)),
                        "algo": match.group(3),
                        "height": int(match.group(4)),
                        "tx_count": int(match.group(5))
                    }
                    requests.post(f"{FLASK_SERVER_URL}/newjob", json=job_info, timeout=10)
            except Exception:
                pass
        if hashrate is not None or gpu_temp or gpu_fan or cpu_accepted_shares or nvidia_accepted_shares:
            payload = {
                "client_id": client_id,
                "hashrate": hashrate,
                "threads": get_current_threads_from_config(),
                "cpu_temp": get_cpu_temperature(),
                "gpu_temp": gpu_temp,
                "gpu_fan": gpu_fan,
                "cpu_accepted_shares": cpu_accepted_shares,
                "nvidia_accepted_shares": nvidia_accepted_shares,
            }
            try:
                requests.post(f"{FLASK_SERVER_URL}/hashrate", json=payload, timeout=10)
            except Exception:
                pass
def start_miner(pool_url = "", thread_count = None):
    global xmrig_process, threads, custom_pool_url, client_id, client_status

    if xmrig_process is not None:
        print("[!] Miner already running.")
        return
    if(thread_count == None):
        try:
            threads = int(input("Enter thread count (e.g., 4): ").strip())
            if threads <= 0:
                raise ValueError
        except ValueError:
            print("[!] Invalid thread count.")
            return
    if(pool_url == ""):
        custom_pool_url = input("Enter custom pool URL (e.g., 192.168.0.10:3333): ").strip()
        if not custom_pool_url:
            print("[!] No pool URL provided.")
            return

    config_path = os.path.join(os.getcwd(), "config.json")
    if not os.path.exists(config_path):
        print("[!] config.json not found.")
        return
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        # Set algo fields
        config["algo"] = "rx"
        if "randomx" in config:
            config["randomx"]["algo"] = "rx"

        # Enable CUDA
        config.setdefault("cuda", {})
        config["cuda"]["enabled"] = True

        # Set CPU rx array to number of threads
        if "cpu" in config:
            config["cpu"]["enabled"] = True
            config["cpu"]["rx"] = list(range(threads))

        # Remove legacy conflicting keys
        for key in ["rx/wow"]:
            config["cpu"].pop(key, None)

        # Ensure pool config matches user input
        if config.get("pools") and isinstance(config["pools"], list):
            for pool in config["pools"]:
                pool["url"] = custom_pool_url
                pool["algo"] = "rx/0"
                pool["coin"] = "XMR"
                pool["keepalive"] = True

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)

        print(f"[+] Updated config.json with {threads} threads and pool: {custom_pool_url}")

    except Exception as e:
        print(f"[!] Failed to update config.json: {e}")
        return
    client_status = "Started"
    payload = {"status": client_status}

    print("[+] Starting miner...")
    requests.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload, timeout=10)
    DETACHED_PROCESS = 0x00000008
    xmrig_process = subprocess.Popen(
        [XMRIG_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW | DETACHED_PROCESS
    )

    threading.Thread(target=monitor_output, args=(xmrig_process,), daemon=True).start()


def stop_miner():
    global xmrig_process, client_status
    # Check if the process variable exists and if the process is currently running
    if xmrig_process and xmrig_process.poll() is None:
        print("[+] Stopping miner...")
        xmrig_process.terminate()
        client_status = "Stopped"
        payload = {"status": client_status}
        requests.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload, timeout=10)
        try:
            # Wait for the process to terminate
            xmrig_process.wait(timeout=5)
            print("[+] Miner stopped.")
        except subprocess.TimeoutExpired:
            print("[!] Miner did not stop in time, killing process.")
            xmrig_process.kill()
            print("[+] Miner process killed.")

        # FIX: Reset the state variable to None after stopping the miner.
        xmrig_process = None
    else:
        print("[!] Miner is not running.")
        # FIX: Also reset the variable here to clean up any old, dead processes.
        xmrig_process = None

def command_loop():
    print("Type 'start' to launch miner, 'stop' to terminate it, 'exit' to quit.")
    while True:
        cmd = input("> ").strip().lower()
        if cmd == "start":
            start_miner()
        elif cmd == "stop":
            stop_miner()
        elif cmd == "exit":
            stop_miner()
            break
        else:
            print("Unknown command.")


# NEW: The new heart of the client.
def poll_server():
    global client_stats
    """Main loop to send status heartbeat and receive commands."""
    while True:
        try:
            payload = {"status": client_status}
            requests.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload, timeout=10)
            cmd_response = requests.get(f"{FLASK_SERVER_URL}/get_command/{client_id}", timeout=10)
            if cmd_response.ok and cmd_response.json():
                command = cmd_response.json()
                print(f"\n[+] Received command from server: '{command.get('command')}'")
                if command.get("command") == "start":
                    start_miner(command["pool"], command["threads"])
                if command.get("command") == "stop":
                    stop_miner()
                if command.get("command") == "set_threads":
                    new_threads = int(command["threads"])
                    print(f"\n[+] Received command: Setting threads to {new_threads}.")
                    threading.Thread(target=update_config_threads, args=(new_threads,)).start()
        except requests.RequestException:
            print(f"[!] Cannot connect to server at {FLASK_SERVER_URL}. Retrying...")
        except Exception as e:
            print(f"[!] An error occurred during polling: {e}")

        # Wait before the next poll
        time.sleep(5)
if __name__ == "__main__":

    if not os.path.exists(XMRIG_PATH):
        print(f"[!] XMRig not found at {XMRIG_PATH}")
        sys.exit(1)

    # Ask user for target hashrate reporting URL
    FLASK_SERVER_URL = input("Enter Flask server URL to send requests (e.g., http://127.0.0.1:5000): ").strip()
    if not FLASK_SERVER_URL:
        print("[!] No URL provided. Exiting.")
        sys.exit(1)

    client_id = input("Enter a unique client ID (e.g., Miner1): ").strip()
    if not client_id:
        print("[!] No client ID provided. Exiting.")
        sys.exit(1)
    # 1. Create and start the background thread for server polling
    poll_thread = threading.Thread(target=poll_server, daemon=True)
    poll_thread.start()

    try:
        command_loop()
    except KeyboardInterrupt:
        stop_miner()
        print("\n[!] Interrupted. Exiting.")
