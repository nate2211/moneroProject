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
import logging
import signal  # For more robust process termination

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='',
                    handlers=[
                        logging.StreamHandler(sys.stdout)
                    ])

# === CONFIGURATION ===
XMRIG_PATH = os.path.join(os.getcwd(), "xmrig.exe")
CONFIG_PATH = os.path.join(os.getcwd(), "config.json")

# How often (in seconds) to send stats to the Flask server
REPORT_INTERVAL_SECONDS = 5
POLL_INTERVAL_SECONDS = 5  # Interval for polling Flask server for commands

# Prevent system from sleeping (This is synchronous, keep as is for now at startup)
try:
    ES_CONTINUOUS = 0x80000000
    ES_SYSTEM_REQUIRED = 0x00000001
    ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
    logging.info("[SYSTEM] System sleep prevention enabled.")
except AttributeError:  # Not on Windows
    logging.warning("[SYSTEM] Could not set system sleep state (non-Windows OS or permission issue).")
except Exception as e:
    logging.error(f"[SYSTEM] Error setting system sleep state: {e}")

# === GLOBALS ===
xmrig_process = None
FLASK_SERVER_URL = None
client_id = None
miner_lock = asyncio.Lock()
last_known_pool_url = None  # This is what xmrig is actually configured with
last_known_thread_count = None  # This is what xmrig is actually configured with
current_miner_status = "Stopped"  # Renamed to avoid confusion with Flask client_status

# Single AIOHTTP session
aiohttp_client_session: aiohttp.ClientSession = None

# Latest parsed metrics (to be read by periodic_reporter)
_latest_hashrate = 0.0
_latest_cpu_accepted_shares = 0
_latest_nvidia_accepted_shares = 0
_latest_gpu_temp = "N/A"
_latest_gpu_fan = "N/A"
_latest_cpu_temp = "N/A"
_latest_power_draw_value = "N/A"
_libre_hardware_monitor_available = False  # Flag to check if LHM loaded successfully

# Initialize LibreHardwareMonitorLib
try:
    import clr

    clr.AddReference("LibreHardwareMonitorLib")
    from LibreHardwareMonitor.Hardware import Computer, HardwareType, SensorType

    _libre_hardware_monitor_available = True
    logging.info("[LHM] LibreHardwareMonitorLib loaded successfully.")
except Exception as e:
    logging.warning(f"[LHM] Could not load LibreHardwareMonitorLib: {e}. Hardware monitoring will be limited.")



# === HELPER FUNCTIONS ===

async def get_power_draw():
    """Asynchronously gets total power draw using LibreHardwareMonitorLib."""
    if not _libre_hardware_monitor_available:
        return "N/A"
    return await asyncio.to_thread(get_power_draw_sync)


def get_power_draw_sync():
    """Synchronous function to get total power draw using LibreHardwareMonitorLib."""
    try:
        c = Computer()
        c.IsCpuEnabled = True
        c.IsGpuEnabled = True
        c.Open()  # Open only once for all sensors

        total_power_draw = 0.0
        found_power_sensor = False

        for hardware in c.Hardware:
            hardware.Update()
            for sensor in hardware.Sensors:
                if sensor.SensorType == SensorType.Power and sensor.Value is not None:
                    total_power_draw += sensor.Value
                    found_power_sensor = True
            for subhardware in hardware.SubHardware:  # Check subhardware too (e.g., specific GPU components)
                subhardware.Update()
                for sensor in subhardware.Sensors:
                    if sensor.SensorType == SensorType.Power and sensor.Value is not None:
                        total_power_draw += sensor.Value
                        found_power_sensor = True
        c.Close()
        return round(total_power_draw, 2) if found_power_sensor else "N/A"

    except Exception as e:
        logging.error(f"[LHM] Error getting power draw: {e}")
        return "N/A"


async def get_cpu_temperature():
    """Asynchronously gets CPU temperatures using LibreHardwareMonitorLib."""
    if not _libre_hardware_monitor_available:
        return "N/A"
    return await asyncio.to_thread(get_cpu_temperature_lhm_sync)


def get_cpu_temperature_lhm_sync():
    """Synchronous function to get CPU temperatures using LibreHardwareMonitorLib."""
    try:
        c = Computer()
        c.IsCpuEnabled = True
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
        logging.error(f"[LHM] Error getting CPU temp via LibreHardwareMonitorLib: {e}")
        return "N/A"


async def get_current_threads_from_config():
    async with miner_lock:
        try:
            return await asyncio.to_thread(get_current_threads_from_config_sync)
        except (IOError, json.JSONDecodeError) as e:
            logging.error(f"[CONFIG] Error reading threads from config: {e}")
            return 0  # Default to 0 if config is unreadable or malformed


def get_current_threads_from_config_sync():
    if not os.path.exists(CONFIG_PATH):
        return 0
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)
        return len(config.get("cpu", {}).get("rx", []))


async def update_config_threads(thread_count):
    global last_known_thread_count
    async with miner_lock:
        success = await asyncio.to_thread(update_config_threads_sync, thread_count)
        if success:
            last_known_thread_count = thread_count  # Update global only on success
        return success


def update_config_threads_sync(thread_count):
    try:
        with open(CONFIG_PATH, "r+", encoding="utf-8") as f:
            config = json.load(f)
            config.setdefault("cpu", {})["rx"] = list(range(thread_count))
            f.seek(0)
            json.dump(config, f, indent=4)
            f.truncate()
        logging.info(f"[CONFIG] Config updated to {thread_count} threads.")
        return True
    except Exception as e:
        logging.error(f"[CONFIG] Failed to update config: {e}")
        return False


# NEW HELPER FUNCTION: Check for NVIDIA GPU
def check_nvidia_gpu_sync():
    """Synchronous function to check for NVIDIA GPU using LibreHardwareMonitorLib."""
    if not _libre_hardware_monitor_available:
        logging.debug("[LHM] LibreHardwareMonitorLib not available, skipping GPU check.")
        return False
    try:
        c = Computer()
        c.IsGpuEnabled = True
        c.Open()

        found_nvidia = False
        logging.debug("[LHM] Checking for GPUs...")
        for hardware in c.Hardware:
            logging.debug(f"[LHM] Found hardware: {hardware.Name}, Type: {hardware.HardwareType}")
            if str(hardware.HardwareType) == "GpuNvidia":
                found_nvidia = True
        c.Close()
        if not found_nvidia:
            logging.info("[LHM] No NVIDIA GPU detected by LibreHardwareMonitorLib.")
        return found_nvidia
    except Exception as e:
        logging.error(f"[LHM] Error checking for NVIDIA GPU: {e}", exc_info=True) # Add exc_info for full traceback
        return False

def update_config_file_sync(pool_url, thread_count):
    global last_known_pool_url, last_known_thread_count
    try:
        with open(CONFIG_PATH, "r+", encoding="utf-8") as f:
            config = json.load(f)

            config["algo"] = "rx/0"  # Ensure algo is set for XMRig
            if "randomx" not in config:  # Add randomx section if missing
                config["randomx"] = {"algo": "rx/0"}
            else:
                config["randomx"]["algo"] = "rx/0"

            # Detect NVIDIA GPU internally and set CUDA enabled
            has_nvidia_gpu = check_nvidia_gpu_sync()
            config.setdefault("cuda", {})["enabled"] = has_nvidia_gpu  # Use setdefault and direct assignment

            if "cpu" not in config:  # Ensure CPU section exists
                config["cpu"] = {}
            config["cpu"]["enabled"] = True
            config["cpu"]["rx"] = list(range(thread_count))

            # Ensure 'pools' section exists and is a list
            if not config.get("pools") or not isinstance(config["pools"], list):
                config["pools"] = [{}]  # Initialize with a default empty pool config

            # Update the first pool entry, or add if no pools exist
            if not config["pools"]:
                config["pools"].append({})

            pool = config["pools"][0]
            pool["url"] = pool_url
            pool["algo"] = "rx/0"  # Explicitly set algo for the pool as well
            pool["coin"] = "XMR"
            pool["keepalive"] = True
            # Optional: Add your wallet here if not already in config
            # pool["user"] = "YOUR_WALLET_ADDRESS"
            # pool["pass"] = "x" # Or your worker name

            f.seek(0)
            json.dump(config, f, indent=4)
            f.truncate()
        logging.info(
            f"[CONFIG] Updated config.json with {thread_count} threads, pool: {pool_url}, CUDA enabled: {has_nvidia_gpu}")
        last_known_pool_url = pool_url
        last_known_thread_count = thread_count
        return True
    except Exception as e:
        logging.error(f"[CONFIG] Failed to update config.json: {e}")
        return False


# === CORE MINER AND REPORTING LOGIC ===
async def monitor_output(process: asyncio.subprocess.Process):
    global client_id, FLASK_SERVER_URL, current_miner_status
    global _latest_hashrate, _latest_cpu_accepted_shares, _latest_nvidia_accepted_shares
    global _latest_gpu_temp, _latest_gpu_fan, aiohttp_client_session

    try:
        while True:
            line_bytes = await process.stdout.readline()
            if not line_bytes:  # EOF, process exited
                break

            decoded = line_bytes.decode("utf-8", errors="ignore").strip()
            logging.info(f"[XMRIG] {decoded}")  # Log raw output for debugging

            # Check for specific patterns and update globals
            if "accepted" in decoded.lower():
                cpu_match = re.search(r"cpu\s+\d+\/\d+\s+accepted\s+\((\d+)\/\d+\)", decoded.lower())
                nvidia_match = re.search(r"nvidia\s+\d+\/\d+\s+accepted\s+\((\d+)\/\d+\)", decoded.lower())
                if cpu_match:
                    _latest_cpu_accepted_shares = int(cpu_match.group(1))
                if nvidia_match:
                    _latest_nvidia_accepted_shares = int(nvidia_match.group(1))

            # NVIDIA GPU Temp/Fan (example pattern, adjust if needed)
            if "nvidia" in decoded.lower():
                temp_match = re.search(r"nvidia\s+\d+:\s+(\d+C)", decoded)  # Example: NVIDIA 0: 60C
                fan_match = re.search(r"nvidia\s+\d+:\s+\d+C\s+(\d+%)", decoded)  # Example: NVIDIA 0: 60C 75%
                if temp_match:
                    _latest_gpu_temp = temp_match.group(1)
                if fan_match:
                    _latest_gpu_fan = fan_match.group(1)

            if "speed" in decoded.lower() and "h/s" in decoded.lower():
                # Adjusted regex for typical XMRig speed output (e.g., speed 10s/60s/15m 1234.5 H/s)
                match = re.search(r"speed\s+\S+\s+([\d.]+)\s+H\/s", decoded)
                if match:
                    _latest_hashrate = float(match.group(1))

            elif "new job from" in decoded.lower():
                try:
                    # Regex for new job info: (IP:Port), diff (int), algo (str), height (int), (tx_count int)
                    match = re.search(
                        r"new job from ([\d.:]+).*?diff (\d+).*?algo ([^\s]+).*?height (\d+).*?\((\d+) tx\)", decoded)
                    if match:
                        job_info = {
                            "client_id": client_id,
                            "ip": match.group(1),
                            "difficulty": int(match.group(2)),
                            "algo": match.group(3),
                            "height": int(match.group(4)),
                            "tx_count": int(match.group(5))
                        }
                        await aiohttp_client_session.post(f"{FLASK_SERVER_URL}/newjob", json=job_info,
                                                          timeout=aiohttp.ClientTimeout(total=5))
                except aiohttp.ClientError as e:
                    logging.warning(f"[XMRIG] Error sending new job info to Flask server: {e}")
                except Exception as e:
                    logging.error(f"[XMRIG] Unexpected error parsing/sending new job info: {e}")

            elif "gpu" in decoded.lower() and "compute error" in decoded.lower():
                logging.error(f"[XMRIG] GPU Compute Error detected: {decoded}. Attempting restart...")
                await stop_miner()
                await asyncio.sleep(10)  # Shorter sleep before restart
                await start_miner(last_known_pool_url, last_known_thread_count)  # Use last known config
            elif "error" in decoded.lower() and "unspecified launch failure" in decoded.lower():
                logging.error(f"[XMRIG] NVIDIA unspecified launch failure: {decoded}. Attempting restart...")
                await stop_miner()
                await asyncio.sleep(10)
                await start_miner(last_known_pool_url, last_known_thread_count)
            elif "daemon is busy" in decoded.lower():
                logging.warning(f"[XMRIG] Daemon is busy warning: {decoded}. Miner might be temporarily stalled.")
                # Could implement a retry logic here if it persists

    except asyncio.CancelledError:
        logging.info("[XMRIG Monitor] Output monitoring task cancelled.")
    except Exception as e:
        logging.critical(f"[XMRIG Monitor] Unhandled exception in monitor_output: {e}")
    finally:
        logging.info("[XMRIG Monitor] Output monitoring task finished.")


async def periodic_reporter(session: aiohttp.ClientSession):
    global client_id, FLASK_SERVER_URL
    global _latest_hashrate, _latest_cpu_accepted_shares, _latest_nvidia_accepted_shares
    global _latest_gpu_temp, _latest_gpu_fan, _latest_cpu_temp, _latest_power_draw_value
    global last_known_thread_count  # Use the latest configured thread count

    while True:
        try:
            await asyncio.sleep(REPORT_INTERVAL_SECONDS)

            # Get the latest values for the report.
            current_cpu_temp = await get_cpu_temperature()
            current_power_draw = await get_power_draw()

            payload = {
                "client_id": client_id,
                "hashrate": _latest_hashrate,
                "threads": last_known_thread_count,  # Use the global for config
                "cpu_temp": current_cpu_temp,
                "gpu_temp": _latest_gpu_temp,
                "gpu_fan": _latest_gpu_fan,
                "cpu_accepted_shares": _latest_cpu_accepted_shares,
                "nvidia_accepted_shares": _latest_nvidia_accepted_shares,
                "power_draw": current_power_draw
            }

            try:
                async with session.post(f"{FLASK_SERVER_URL}/hashrate", json=payload,
                                        timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    resp.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            except aiohttp.ClientError as e:
                logging.warning(f"[Reporter] Error sending periodic hashrate report: {e}")
            except Exception as e:
                logging.error(f"[Reporter] Unexpected error during periodic hashrate report send: {e}")

        except asyncio.CancelledError:
            logging.info("[Reporter] Periodic reporter task cancelled.")
            break
        except Exception as e:
            logging.critical(f"[Reporter] Unhandled exception in periodic_reporter: {e}")


async def start_miner(pool_url: str = None, thread_count: int = None):
    global xmrig_process, current_miner_status, last_known_pool_url, last_known_thread_count, client_id, FLASK_SERVER_URL, aiohttp_client_session

    async with miner_lock:
        if xmrig_process is not None and xmrig_process.returncode is None:
            logging.info("[Miner] Miner already running.")
            return

        if not os.path.exists(XMRIG_PATH):
            logging.error(f"[Miner] XMRig executable not found at {XMRIG_PATH}. Cannot start miner.")
            return

        if not os.path.exists(CONFIG_PATH):
            logging.error(f"[Miner] config.json not found at {CONFIG_PATH}. Please create a base config.json.")
            return

        # Prompt for missing info if not provided
        if pool_url is None:
            pool_url_input = await asyncio.to_thread(input, "Enter custom pool URL (e.g., 192.168.0.10:3333): ")
            pool_url = pool_url_input.strip()
            if not pool_url:
                logging.warning("[Miner] No pool URL provided. Cannot start miner.")
                return

        if thread_count is None:
            try:
                threads_input = await asyncio.to_thread(input, "Enter thread count (e.g., 4): ")
                thread_count = int(threads_input.strip())
                if thread_count <= 0:
                    raise ValueError("Thread count must be positive.")
            except ValueError as e:
                logging.warning(f"[Miner] Invalid thread count provided: {e}. Cannot start miner.")
                return

        # Update config file with the latest settings
        if not await asyncio.to_thread(update_config_file_sync, pool_url, thread_count):
            logging.error("[Miner] Failed to update config.json. Miner not started.")
            return

        logging.info(f"[Miner] Attempting to start miner with pool: {pool_url}, threads: {thread_count}...")

        try:
            xmrig_process = await asyncio.create_subprocess_exec(
                XMRIG_PATH,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                # universal_newlines=False is the default and required for bytes output
                creationflags=subprocess.CREATE_NO_WINDOW  # Hide console window
            )
            current_miner_status = "Started"
            logging.info(f"[Miner] XMRig process started successfully (PID: {xmrig_process.pid}).")

            # Report status to Flask server
            payload = {"status": current_miner_status}
            try:
                await aiohttp_client_session.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload,
                                                  timeout=aiohttp.ClientTimeout(total=5))
            except aiohttp.ClientError as e:
                logging.warning(f"[Miner] Error reporting miner start status to Flask server: {e}")

            asyncio.create_task(monitor_output(xmrig_process))  # Start monitoring XMRig output

        except FileNotFoundError:
            logging.critical(f"[Miner] XMRig executable not found at {XMRIG_PATH}. Double-check path.")
            current_miner_status = "Error"
        except Exception as e:
            logging.critical(f"[Miner] Failed to launch XMRig process: {e}")
            current_miner_status = "Error"

        # Always report final status after attempting to start
        payload = {"status": current_miner_status}
        try:
            await aiohttp_client_session.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload,
                                              timeout=aiohttp.ClientTimeout(total=5))
        except aiohttp.ClientError as e:
            logging.warning(f"[Miner] Error reporting final miner start status to Flask server: {e}")


async def stop_miner():
    global xmrig_process, current_miner_status, aiohttp_client_session

    async with miner_lock:
        if xmrig_process is None or xmrig_process.returncode is not None:
            logging.info("[Miner] Miner is not running or already stopped.")
            current_miner_status = "Stopped"  # Ensure consistent state
            return

        logging.info("[Miner] Stopping miner process...")
        try:
            # Use SIGTERM for graceful shutdown first
            xmrig_process.terminate()
            try:
                await asyncio.wait_for(xmrig_process.wait(), timeout=10)  # Give it 10 seconds to terminate
                logging.info("[Miner] Miner stopped gracefully.")
            except asyncio.TimeoutError:
                logging.warning("[Miner] Miner did not terminate gracefully, killing process.")
                xmrig_process.kill()  # Force kill if it doesn't respond to terminate
                await xmrig_process.wait()  # Wait for it to be truly killed
                logging.info("[Miner] Miner process killed.")
        except Exception as e:
            logging.error(f"[Miner] Error stopping miner process: {e}")
        finally:
            xmrig_process = None
            current_miner_status = "Stopped"
            # Report status to Flask server regardless of how it stopped
            payload = {"status": current_miner_status}
            try:
                await aiohttp_client_session.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload,
                                                  timeout=aiohttp.ClientTimeout(total=5))
            except aiohttp.ClientError as e:
                logging.warning(f"[Miner] Error reporting miner stop status to Flask server: {e}")


async def command_line_interface():
    """Provides a basic command-line interface for local control."""
    logging.info("Type 'start' to launch miner, 'stop' to terminate it, 'exit' to quit.")
    while True:
        cmd = (await asyncio.to_thread(input, "Miner CLI > ")).strip().lower()
        if cmd == "start":
            await start_miner()  # Will prompt for pool/threads if not set
        elif cmd == "stop":
            await stop_miner()
        elif cmd == "exit":
            logging.info("[CLI] Exiting command-line interface.")
            break
        else:
            logging.info("Unknown command. Use 'start', 'stop', or 'exit'.")


async def poll_server(session: aiohttp.ClientSession):
    global current_miner_status, FLASK_SERVER_URL, client_id, last_known_pool_url, last_known_thread_count
    """Main loop to send status heartbeat and receive commands."""
    while True:
        try:
            # Send heartbeat/status
            payload = {"status": current_miner_status}
            async with session.post(f"{FLASK_SERVER_URL}/miners/{client_id}", json=payload,
                                    timeout=aiohttp.ClientTimeout(total=5)) as resp:
                resp.raise_for_status()

            # Poll for commands
            async with session.get(f"{FLASK_SERVER_URL}/get_command/{client_id}",
                                   timeout=aiohttp.ClientTimeout(total=5)) as response:
                response.raise_for_status()  # Raise exception for 4xx/5xx responses
                command = await response.json()

            if command:
                cmd_type = command.get("command")
                logging.info(f"[Server Poll] Received command from server: '{cmd_type}'")
                if cmd_type == "start":
                    pool_url = command.get("pool")
                    threads = command.get("threads")
                    if not pool_url or not threads:
                        logging.warning("[Server Poll] 'start' command missing pool URL or threads.")
                        continue  # Skip if command is incomplete

                    # Store these for potential auto-restart on error
                    last_known_pool_url = pool_url
                    last_known_thread_count = threads
                    await start_miner(pool_url, threads)

                elif cmd_type == "stop":
                    await stop_miner()

                elif cmd_type == "set_threads":
                    new_threads = command.get("threads")
                    if new_threads is None:
                        logging.warning("[Server Poll] 'set_threads' command missing thread count.")
                        continue

                    try:
                        new_threads = int(new_threads)
                        if new_threads <= 0:
                            raise ValueError("Thread count must be positive.")
                        logging.info(f"[Server Poll] Setting threads to {new_threads}.")
                        # Update config and then restart miner to apply changes if running
                        await update_config_threads(new_threads)
                        if current_miner_status == "Started" and xmrig_process is not None:
                            logging.info("[Server Poll] Miner running, restarting to apply new thread count.")
                            await stop_miner()
                            # Use the new thread count and the *last known* pool URL to restart
                            await start_miner(last_known_pool_url, new_threads)
                        else:
                            logging.info(
                                "[Server Poll] Miner not running, threads updated in config. Will apply on next start.")

                    except ValueError as ve:
                        logging.warning(f"[Server Poll] Invalid thread count for 'set_threads' command: {ve}")

        except aiohttp.ClientError as e:
            logging.warning(
                f"[Server Poll] Cannot connect to server at {FLASK_SERVER_URL} or HTTP error: {e}. Retrying...")
        except asyncio.CancelledError:
            logging.info("[Server Poll] Server polling task cancelled.")
            break
        except Exception as e:
            logging.critical(f"[Server Poll] Unhandled exception in poll_server: {e}")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def application_shutdown():
    """Handles graceful shutdown of all tasks and resources."""
    logging.info("[Shutdown] Initiating graceful shutdown...")

    # Stop the miner first
    await stop_miner()

    # Cancel all running asyncio tasks except the current one
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()

    # Wait for tasks to complete their cancellation (with timeout)
    await asyncio.gather(*tasks, return_exceptions=True)  # return_exceptions so one task error doesn't block others

    # Close the aiohttp client session
    if aiohttp_client_session:
        logging.info("[Shutdown] Closing aiohttp client session...")
        await aiohttp_client_session.close()

    logging.info("[Shutdown] Application shutdown complete.")


async def main():
    global FLASK_SERVER_URL, client_id, aiohttp_client_session, last_known_pool_url, last_known_thread_count

    logging.info("Starting XMRig Manager Client...")

    FLASK_SERVER_URL = (await asyncio.to_thread(input,
                                                "Enter Flask server URL to send requests (e.g., http://192.168.0.10:5000): ")).strip()
    if not FLASK_SERVER_URL:
        logging.critical("[Startup] No Flask server URL provided. Exiting.")
        sys.exit(1)

    client_id = (await asyncio.to_thread(input, "Enter a unique client ID (e.g., Miner1): ")).strip()
    if not client_id:
        logging.critical("[Startup] No client ID provided. Exiting.")
        sys.exit(1)

    # Load initial config settings if config.json exists
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config = json.load(f)
                # Attempt to get pool URL and threads from existing config
                if config.get("pools") and isinstance(config["pools"], list) and config["pools"]:
                    last_known_pool_url = config["pools"][0].get("url")
                if config.get("cpu") and config["cpu"].get("enabled") and config["cpu"].get("rx") is not None:
                    last_known_thread_count = len(config["cpu"]["rx"])
                logging.info("[Startup] Loaded initial miner configuration from config.json.")
        except (IOError, json.JSONDecodeError) as e:
            logging.warning(f"[Startup] Could not read or parse existing config.json: {e}. Starting with defaults.")
            last_known_pool_url = None
            last_known_thread_count = None
    else:
        logging.warning("[Startup] config.json not found. Miner will prompt for pool/threads on first start.")
        last_known_pool_url = None
        last_known_thread_count = None

    aiohttp_client_session = aiohttp.ClientSession()

    # Create a TaskGroup to manage long-running background tasks
    async with asyncio.TaskGroup() as tg:
        tg.create_task(poll_server(aiohttp_client_session))
        tg.create_task(periodic_reporter(aiohttp_client_session))
        tg.create_task(command_line_interface())
        # The main loop of the application is now managed by the TaskGroup.
        # If any of these tasks raise an unhandled exception, TaskGroup will
        # cancel the others and propagate the exception.

    logging.info("[Main] All main tasks have completed or were cancelled.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("\n[Main] KeyboardInterrupt received. Initiating graceful shutdown...")
        # asyncio.run() cleans up the event loop; we need to explicitly run shutdown tasks
        # within the loop. The `finally` block in `main` (if `main` was a normal func)
        # or the `application_shutdown` handler would be called.
        # For a clean exit, ensure `application_shutdown` is called.
        # If `main()` exits due to TaskGroup, it's already handled.
        # If KeyboardInterrupt happens outside TaskGroup, we still want to clean up.
        # A simple way for `asyncio.run` is to wrap the call and handle the exception.
        pass  # `application_shutdown` is called implicitly on normal exit or explicit KeyboardInterrupt for TaskGroup
    except Exception as e:
        logging.critical(f"[Main] Unhandled exception in main: {e}", exc_info=True)
    finally:
        # This finally block is executed when `asyncio.run(main())` finishes,
        # either normally or due to an exception (including KeyboardInterrupt caught by asyncio.run)
        # It's a good place to ensure final cleanup.
        # However, `application_shutdown` needs an active event loop, so calling it here directly
        # might not work if the loop is already closed by `asyncio.run`.
        # The best practice is to let `asyncio.TaskGroup` handle the lifecycle
        # or call `application_shutdown` *before* `asyncio.run` exits if it's external.
        # For this setup, TaskGroup handles it mostly, but a final aiohttp close ensures it.
        # Let's ensure aiohttp_client_session is closed if `main` finished prematurely.
        if aiohttp_client_session and not aiohttp_client_session.closed:
            try:
                asyncio.run(aiohttp_client_session.close())
                logging.info("[Main] Explicitly closed aiohttp session during final cleanup.")
            except Exception as e:
                logging.error(f"[Main] Error closing aiohttp session during final cleanup: {e}")