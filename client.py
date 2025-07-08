import json
import asyncio
import subprocess
import ctypes
import sys
import os
import time
import queue
import re
import aiohttp
import clr

try:
    clr.AddReference("LibreHardwareMonitorLib")
except Exception as e:
    print(f"[!] Could not load LibreHardwareMonitorLib: {e}")
    sys.exit(1)

from LibreHardwareMonitor.Hardware import Computer, HardwareType, SensorType

# === CONFIGURATION ===
XMRIG_PATH = os.path.join(os.getcwd(), "xmrig.exe")
CONFIG_PATH = os.path.join(os.getcwd(), "config.json")

# How often (in seconds) to send stats to the Flask server
REPORT_INTERVAL_SECONDS = 5

# Prevent system from sleeping (This is synchronous, keep as is for now at startup)
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)

# === GLOBALS ===
xmrig_process = None
output_queue = asyncio.Queue()
FLASK_SERVER_URL = None
client_id = None
miner_lock = asyncio.Lock()
last_known_pool_url = None
last_known_thread_count = None
custom_pool_url = None
client_status = "Stopped"
threads = None

# NEW GLOBAL for the single AIOHTTP session
aiohttp_client_session = None

# NEW GLOBALS for latest parsed metrics (to be read by periodic_reporter)
_latest_hashrate = 0.0
_latest_cpu_accepted_shares = 0
_latest_nvidia_accepted_shares = 0
_latest_gpu_temp = "N/A"
_latest_gpu_fan = "N/A"
_latest_cpu_temp = "N/A"
_latest_power_draw_value = "N/A"


# === HELPER FUNCTIONS ===

async def get_power_draw_async():
    """Wrapper to run synchronous get_power_draw in a separate thread."""
    return await asyncio.to_thread(get_power_draw_sync)


def get_power_draw_sync():
    """
    Synchronous function to get total power draw using LibreHardwareMonitorLib.
    This function is intended to be run in a separate thread via asyncio.to_thread.
    """
    try:
        c = Computer()
        c.IsCpuEnabled = True
        c.IsGpuEnabled = True
        c.IsMemoryEnabled = True
        c.IsMotherboardEnabled = True
        c.IsControllerEnabled = True
        c.IsNetworkEnabled = True
        c.IsStorageEnabled = True
        c.Open()

        total_power_draw = 0.0
        found_power_sensor = False

        for hardware in c.Hardware:
            hardware.Update()
            for sensor in hardware.Sensors:
                if sensor.SensorType == SensorType.Power:
                    if sensor.Value is not None:
                        total_power_draw += sensor.Value
                        found_power_sensor = True
            for subhardware in hardware.SubHardware:
                subhardware.Update()
                for sensor in subhardware.Sensors:
                    if sensor.SensorType == SensorType.Power and sensor.Value is not None:
                        total_power_draw += sensor.Value
                        found_power_sensor = True

        c.Close()
        return round(total_power_draw, 2) if found_power_sensor else "N/A"

    except Exception as e:
        print(f"[!] Power draw error: {e}")
        return "N/A"


async def get_cpu_temperature_async():
    """Wrapper to run synchronous get_cpu_temperature_lhm in a separate thread."""
    return await asyncio.to_thread(get_cpu_temperature_lhm_sync)


def get_cpu_temperature_lhm_sync():
    """
    Gets CPU temperatures using LibreHardwareMonitorLib.
    Opens Computer, reads CPU temperature sensors, and closes Computer.
    Returns the maximum observed CPU core temperature.
    """
    try:
        c = Computer()
        c.IsCpuEnabled = True  # Only enable CPU for CPU temp reading
        c.Open()

        cpu_temperatures = []
        for hardware in c.Hardware:
            if hardware.HardwareType == HardwareType.Cpu:
                hardware.Update()
                for sensor in hardware.Sensors:
                    if sensor.SensorType == SensorType.Temperature and sensor.Value is not None:
                        cpu_temperatures.append(sensor.Value)
        c.Close()

        if not cpu_temperatures:
            return "N/A"

        max_temp_celsius = max(cpu_temperatures)
        max_temp_fahrenheit = (max_temp_celsius * 9 / 5) + 32

        return f"{max_temp_celsius:.1f}°C / {max_temp_fahrenheit:.1f}°F"

    except Exception as e:
        print(f"[!] Error getting CPU temp via LibreHardwareMonitorLib: {e}", file=sys.stderr)
        return "N/A"


async def get_current_threads_from_config_async():
    async with miner_lock:
        try:
            return await asyncio.to_thread(get_current_threads_from_config_sync)
        except (IOError, json.JSONDecodeError):
            return 0


def get_current_threads_from_config_sync():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return len(json.load(f).get("cpu", {}).get("rx", []))


async def update_config_threads_async(thread_count):
    async with miner_lock:
        return await asyncio.to_thread(update_config_threads_sync, thread_count)


def update_config_threads_sync(thread_count):
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
async def monitor_output(process):
    global client_id, FLASK_SERVER_URL, custom_pool_url, threads
    global _latest_hashrate, _latest_cpu_accepted_shares, _latest_nvidia_accepted_shares
    global _latest_gpu_temp, _latest_gpu_fan, _latest_cpu_temp, _latest_power_draw_value, aiohttp_client_session

    async for line_bytes in process.stdout:
        decoded = line_bytes.decode("utf-8", errors="ignore").strip()
        print(f"[XMRIG] {decoded}")

        if "error" in decoded.lower():
            await stop_miner()
            await asyncio.sleep(30)
            await start_miner(custom_pool_url, threads)

        if "cpu" in decoded.lower() and "accepted" in decoded.lower():
            match = re.search(r"accepted\s+\((\d+)/\d+\)", decoded.lower())
            if match:
                _latest_cpu_accepted_shares = int(match.group(1))

        if "nvidia" in decoded.lower() and "accepted" in decoded.lower():
            match = re.search(r"accepted\s+\((\d+)/\d+\)", decoded.lower())
            if match:
                _latest_nvidia_accepted_shares = int(match.group(1))

        if "nvidia" in decoded.lower() and "c" in decoded.lower():
            temp_match = re.search(r"(\d+c)", decoded.lower())
            fan_match = re.search(r"fan\d+:(\d+%)", decoded.lower())
            if temp_match:
                _latest_gpu_temp = temp_match.group(1)
            if fan_match:
                _latest_gpu_fan = fan_match.group(1)

        if "miner" in decoded.lower() and "speed" in decoded.lower():
            match = re.search(r"speed\s+\d+s/\d+s/\d+m\s+([\d.]+)\s+", decoded)
            if match:
                _latest_hashrate = float(match.group(1))
        elif "gpu" in decoded.lower() and "compute error" in decoded.lower():
            await stop_miner()
            await asyncio.sleep(30)
            await start_miner(custom_pool_url, threads)
        elif "new job from" in decoded.lower():
            try:
                match = re.search(r"new job from ([\d.:]+).*?diff (\d+).*?algo ([^\s]+).*?height (\d+).*?\((\d+) tx\)",
                                  decoded)
                if match:
                    job_info = {
                        "client_id": client_id,
                        "ip": match.group(1),
                        "difficulty": int(match.group(2)),
                        "algo": match.group(3),
                        "height": int(match.group(4)),
                        "tx_count": int(match.group(5))
                    }
                    # Use the shared session here
                    await aiohttp_client_session.post(f"{FLASK_SERVER_URL}/newjob", json=job_info,
                                                      timeout=aiohttp.ClientTimeout(total=10))
            except Exception as e:
                print(f"[!] Error sending new job info: {e}")
                pass

        # Power draw and CPU temp are fetched on demand by the periodic reporter
        # because they involve synchronous calls in separate threads, which are heavier
        # than just updating a variable.


# NEW: Periodic reporter task
async def periodic_reporter(session: aiohttp.ClientSession):
    global client_id, FLASK_SERVER_URL
    global _latest_hashrate, _latest_cpu_accepted_shares, _latest_nvidia_accepted_shares
    global _latest_gpu_temp, _latest_gpu_fan  # These are read directly from globals updated by monitor_output

    while True:
        await asyncio.sleep(REPORT_INTERVAL_SECONDS)

        # Get the latest values for the report.
        # CPU temp and Power draw still involve synchronous calls in a separate thread.
        current_cpu_temp = await get_cpu_temperature_async()
        current_power_draw = await get_power_draw_async()
        current_threads = await get_current_threads_from_config_async()

        payload = {
            "client_id": client_id,
            "hashrate": _latest_hashrate,
            "threads": current_threads,
            "cpu_temp": current_cpu_temp,
            "gpu_temp": _latest_gpu_temp,
            "gpu_fan": _latest_gpu_fan,
            "cpu_accepted_shares": _latest_cpu_accepted_shares,
            "nvidia_accepted_shares": _latest_nvidia_accepted_shares,
            "power_draw": current_power_draw
        }

        try:
            # Use the shared session here
            await session.post(f"{FLASK_SERVER_URL}/hashrate", json=payload,
                               timeout=aiohttp.ClientTimeout(total=10))
            # print(f"[+] Sent periodic report: Hashrate={_latest_hashrate}, CPU Temp={current_cpu_temp}") # For debugging
        except aiohttp.ClientError as e:
            print(f"[!] Error sending periodic hashrate report: {e}")
        except Exception as e:
            print(f"[!] Unexpected error during periodic hashrate report send: {e}")


async def start_miner(pool_url="", thread_count=None):
    global xmrig_process, threads, custom_pool_url, client_id, client_status, FLASK_SERVER_URL, aiohttp_client_session

    if xmrig_process is not None and xmrig_process.returncode is None:
        print("[!] Miner already running.")
        return

    if thread_count is None:
        try:
            input_threads = await asyncio.to_thread(input, "Enter thread count (e.g., 4): ")
            threads = int(input_threads.strip())
            if threads <= 0:
                raise ValueError
        except ValueError:
            print("[!] Invalid thread count.")
            return

    if pool_url == "":
        input_pool_url = await asyncio.to_thread(input, "Enter custom pool URL (e.g., 192.168.0.10:3333): ")
        custom_pool_url = input_pool_url.strip()
        if not custom_pool_url:
            print("[!] No pool URL provided.")
            return
    else:
        custom_pool_url = pool_url

    if not os.path.exists(CONFIG_PATH):
        print("[!] config.json not found.")
        return

    try:
        await asyncio.to_thread(update_config_file_sync, custom_pool_url, threads)

    except Exception as e:
        print(f"[!] Failed to update config.json: {e}")
        return

    client_status = "Started"
    payload = {"status": client_status}

    print("[+] Starting miner...")
    try:
        # Use the shared session here
        await aiohttp_client_session.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload,
                                          timeout=aiohttp.ClientTimeout(total=10))
    except aiohttp.ClientError as e:
        print(f"[!] Error reporting miner status: {e}")

    xmrig_process = await asyncio.create_subprocess_exec(
        XMRIG_PATH,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        # universal_newlines=False is the default and required if you pipe stdout/stderr and want bytes
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    asyncio.create_task(monitor_output(xmrig_process))


def update_config_file_sync(pool_url, thread_count):
    with open(CONFIG_PATH, "r+", encoding="utf-8") as f:
        config = json.load(f)

        config["algo"] = "rx"
        if "randomx" in config:
            config["randomx"]["algo"] = "rx"

        config.setdefault("cuda", {})
        config["cuda"]["enabled"] = True

        if "cpu" in config:
            config["cpu"]["enabled"] = True
            config["cpu"]["rx"] = list(range(thread_count))

        for key in ["rx/wow"]:
            config["cpu"].pop(key, None)

        if config.get("pools") and isinstance(config["pools"], list):
            for pool in config["pools"]:
                pool["url"] = pool_url
                pool["algo"] = "rx/0"
                pool["coin"] = "XMR"
                pool["keepalive"] = True

        f.seek(0)
        json.dump(config, f, indent=4)
        f.truncate()
    print(f"[+] Updated config.json with {thread_count} threads and pool: {pool_url}")


async def stop_miner():
    global xmrig_process, client_status, aiohttp_client_session
    if xmrig_process and xmrig_process.returncode is None:
        print("[+] Stopping miner...")
        xmrig_process.terminate()
        client_status = "Stopped"
        payload = {"status": client_status}
        try:
            # Use the shared session here
            await aiohttp_client_session.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload,
                                              timeout=aiohttp.ClientTimeout(total=10))
        except aiohttp.ClientError as e:
            print(f"[!] Error reporting miner status: {e}")

        try:
            await asyncio.wait_for(xmrig_process.wait(), timeout=5)
            print("[+] Miner stopped.")
        except asyncio.TimeoutError:
            print("[!] Miner did not stop in time, killing process.")
            xmrig_process.kill()
            print("[+] Miner process killed.")
        finally:
            xmrig_process = None
    else:
        print("[!] Miner is not running.")
        client_status = "Stopped"
        xmrig_process = None


async def command_loop():
    print("Type 'start' to launch miner, 'stop' to terminate it, 'exit' to quit.")
    while True:
        cmd = await asyncio.to_thread(input, "> ")
        cmd = cmd.strip().lower()
        if cmd == "start":
            await start_miner()
        elif cmd == "stop":
            await stop_miner()
        elif cmd == "exit":
            await stop_miner()
            break
        else:
            print("Unknown command.")


async def poll_server(session: aiohttp.ClientSession):
    global client_status, FLASK_SERVER_URL, custom_pool_url, threads, client_id
    """Main loop to send status heartbeat and receive commands."""
    while True:
        try:
            payload = {"status": client_status}
            # Use the shared session here
            await session.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload,
                               timeout=aiohttp.ClientTimeout(total=10))

            # Use the shared session here
            async with session.get(f"{FLASK_SERVER_URL}/get_command/{client_id}",
                                   timeout=aiohttp.ClientTimeout(total=10)) as response:
                response.raise_for_status()
                command = await response.json()

            if command:
                print(f"\n[+] Received command from server: '{command.get('command')}'")
                if command.get("command") == "start":
                    await stop_miner()
                    custom_pool_url = command.get("pool", custom_pool_url)
                    threads = command.get("threads", threads)
                    await start_miner(custom_pool_url, threads)
                elif command.get("command") == "stop":
                    await stop_miner()
                elif command.get("command") == "set_threads":
                    new_threads = int(command["threads"])
                    print(f"\n[+] Received command: Setting threads to {new_threads}.")
                    await update_config_threads_async(new_threads)

        except aiohttp.ClientError as e:
            print(f"[!] Cannot connect to server at {FLASK_SERVER_URL} or HTTP error: {e}. Retrying...")
        except Exception as e:
            print(f"[!] An unexpected error occurred during polling: {e}")

        await asyncio.sleep(5)


async def main():
    global FLASK_SERVER_URL, client_id, aiohttp_client_session

    if not os.path.exists(XMRIG_PATH):
        print(f"[!] XMRig not found at {XMRIG_PATH}")
        sys.exit(1)

    FLASK_SERVER_URL = await asyncio.to_thread(input,
                                               "Enter Flask server URL to send requests (e.g., http://192.168.0.10:5000): ")
    FLASK_SERVER_URL = FLASK_SERVER_URL.strip()
    if not FLASK_SERVER_URL:
        print("[!] No URL provided. Exiting.")
        sys.exit(1)

    client_id = await asyncio.to_thread(input, "Enter a unique client ID (e.g., Miner1): ")
    client_id = client_id.strip()
    if not client_id:
        print("[!] No client ID provided. Exiting.")
        sys.exit(1)

    # Initialize the single aiohttp ClientSession
    aiohttp_client_session = aiohttp.ClientSession()

    # Start the background tasks, passing the shared session
    asyncio.create_task(poll_server(aiohttp_client_session))
    asyncio.create_task(periodic_reporter(aiohttp_client_session))

    try:
        await command_loop()
    finally:
        # Ensure the aiohttp session is closed when the main loop finishes or is interrupted
        await aiohttp_client_session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting.")