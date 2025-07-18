import asyncio
import json
import os
import subprocess
import re
import traceback
from typing import Callable
import aiohttp
import anyio
import psutil
from typing_extensions import Awaitable
import re


REPORT_INTERVAL_SECONDS = 5


class PeriodicReporter:
    """
    Handles the periodic reporting of miner statistics to a remote server.
    """

    def __init__(self,
                 xmrig_miner,
                 xmrig_data,
                 logger,):

        self.xmrig_data = xmrig_data
        self.logger = logger
        self.xmrig_miner = xmrig_miner
    async def run(self, update_signal, session: aiohttp.ClientSession):
        while True:
            # This outer try/except block protects the entire loop
            try:
                await asyncio.sleep(REPORT_INTERVAL_SECONDS)

                # --- Data Gathering ---
                current_cpu_temp = await self.xmrig_data.get_cpu_temperature_async()
                current_power_draw = await self.xmrig_data.get_power_draw_async()
                current_threads = await self.xmrig_miner.get_current_threads_from_config_async()

                # --- Payload Creation ---
                if self.xmrig_data.client_status == "Started":
                    payload = {
                        "client_id": self.xmrig_data.client_id, "hashrate": self.xmrig_data._latest_hashrate,
                        "threads": current_threads, "cpu_temp": current_cpu_temp,
                        "gpu_temp": self.xmrig_data._latest_gpu_temp, "gpu_fan": self.xmrig_data._latest_gpu_fan,
                        "cpu_accepted_shares": self.xmrig_data._latest_cpu_accepted_shares,
                        "nvidia_accepted_shares": self.xmrig_data._latest_nvidia_accepted_shares,
                        "power_draw": current_power_draw
                    }
                else:
                    payload = {
                        "client_id": self.xmrig_data.client_id, "hashrate": 0, "threads": current_threads,
                        "cpu_temp": current_cpu_temp, "gpu_temp": self.xmrig_data._latest_gpu_temp,
                        "gpu_fan": self.xmrig_data._latest_gpu_fan, "cpu_accepted_shares": 0,
                        "nvidia_accepted_shares": 0, "power_draw": current_power_draw
                    }

                # --- GUI and Network ---
                update_signal.emit(payload)
                await session.post(
                    f"{self.xmrig_data.FLASK_SERVER_URL}/hashrate",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                )

            except aiohttp.ClientError as e:
                self.logger.log_message(f"[!] Network error in PeriodicReporter: {e}")
            except Exception as e:
                # This will now catch any error, including from data gathering
                self.logger.log_message("[!] CRITICAL ERROR IN PERIODIC REPORTER:")
                self.logger.log_message(traceback.format_exc())


class ServerPoller:

    def __init__(self,
                 xmrig_miner,
                 xmrig_data,
                 logger):
        self.xmrig_data = xmrig_data
        self.xmrig_miner = xmrig_miner
        self.logger = logger
    async def run(self, force_update_signal, session: aiohttp.ClientSession):
        while True:
            try:
                # Report current status
                if self.xmrig_data.xmrig_process is not None and self.xmrig_data.xmrig_process.returncode is None:
                    self.xmrig_data.client_status = "Started"
                else:
                    self.xmrig_data.client_status = "Stopped"
                payload = {"status": self.xmrig_data.client_status}
                await session.post(
                    f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                )

                # Get command
                async with session.get(
                        f"{self.xmrig_data.FLASK_SERVER_URL}/get_command/{self.xmrig_data.client_id}",
                        timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    response.raise_for_status()  # Raises an exception for bad status codes (4xx or 5xx)
                    command = await response.json()

                # Process command
                if command:
                    self.logger.log_message(f"\n[+] Received command from server: '{command.get('command')}'")
                    cmd = command.get("command")
                    if cmd == "start":
                        pool = command.get("pool", self.xmrig_data.custom_pool_url)
                        threads = command.get("threads", self.xmrig_data.threads)
                        await self.xmrig_miner.stop_miner()
                        await self.xmrig_miner.start_miner(pool, threads)
                    elif cmd == "stop":
                        await self.xmrig_miner.stop_miner()
                    elif cmd == "set_threads":
                        new_threads = int(command["threads"])  # This can cause KeyError or ValueError
                        await self.xmrig_miner.update_config_threads_async(new_threads)
                    elif cmd == "update":
                        update_url = command.get("url")
                        if update_url:
                            force_update_signal.emit(update_url)

            # --- MODIFIED ERROR HANDLING ---
            except json.JSONDecodeError:
                self.logger.log_message("[!] ServerPoller Error: Received invalid JSON from server.")
            except (KeyError, ValueError) as e:
                self.logger.log_message(
                    f"[!] ServerPoller Error: Received malformed command from server. Details: {e}")
            except aiohttp.ClientError as e:
                self.logger.log_message(f"[!] ServerPoller Network Error: Cannot connect to server. Details: {e}")
            except Exception as e:
                self.logger.log_message("[!] An unexpected critical error occurred in ServerPoller:")
                self.logger.log_message(traceback.format_exc())

            await asyncio.sleep(5)
class OutputMonitor:

    def __init__(self, xmrig_miner, xmrig_data, logger):

        self.xmrig_data = xmrig_data
        self.logger = logger
        self.xmrig_miner = xmrig_miner

    async def monitor_process(self, process):

        async for line_bytes in process.stdout:
            decoded = line_bytes.decode("utf-8", errors="ignore").strip()
            if not decoded or decoded.isspace() or len(decoded.strip()) == 0:
                continue

            lines = re.split(r'\r\n|\r|\n', decoded)

            for line in lines:
                clean_line = line.strip()
                if not clean_line:
                    continue
                decoded = clean_line
            self.logger.log_message(f"[XMRIG] {decoded}")

            # --- Handle Error and Restart Conditions ---
            if "error" in decoded.lower() or "compute error" in decoded.lower():
                self.logger.log_message("[!] Error detected in miner output. Restarting miner...")
                await self.xmrig_miner.stop_miner()
                await asyncio.sleep(30)
                await self.xmrig_miner.start_miner(self.xmrig_data.custom_pool_url, self.xmrig_data.threads)
                break # Stop monitoring the old, dead process

            # --- Parse Statistics ---
            if "accepted" in decoded.lower():
                self._parse_accepted_shares(decoded)

            if "nvidia" in decoded.lower() and "c" in decoded.lower():
                self._parse_gpu_stats(decoded)

            if "miner" in decoded.lower() and "speed" in decoded.lower():
                self._parse_hashrate(decoded)

            # --- Parse New Job Information ---
            if "new job from" in decoded.lower():
                await self._handle_new_job(decoded)

    def _parse_accepted_shares(self, line):
        if "cpu" in line.lower():
            match = re.search(r"accepted\s+\((\d+)/\d+\)", line.lower())
            if match:
                self.xmrig_data._latest_cpu_accepted_shares = int(match.group(1))
        if "nvidia" in line.lower():
            match = re.search(r"accepted\s+\((\d+)/\d+\)", line.lower())
            if match:
                self.xmrig_data._latest_nvidia_accepted_shares = int(match.group(1))

    def _parse_gpu_stats(self, line):
        temp_match = re.search(r"(\d+c)", line.lower())
        fan_match = re.search(r"fan\d+:(\d+%)", line.lower())
        if temp_match:
            self.xmrig_data._latest_gpu_temp = temp_match.group(1)
        if fan_match:
            self.xmrig_data._latest_gpu_fan = fan_match.group(1)

    def _parse_hashrate(self, line):
        match = re.search(r"speed\s+\d+s/\d+s/\d+m\s+([\d.]+)\s+", line)
        if match:
            self.xmrig_data._latest_hashrate = float(match.group(1))

    async def _handle_new_job(self, line):
        try:
            match = re.search(
                r"new job from ([\d.:]+).*?diff (\d+).*?algo ([^\s]+).*?height (\d+).*?\((\d+) tx\)",
                line
            )
            if match:
                job_info = {
                    "client_id": self.xmrig_data.client_id,
                    "ip": match.group(1),
                    "difficulty": int(match.group(2)),
                    "algo": match.group(3),
                    "height": int(match.group(4)),
                    "tx_count": int(match.group(5))
                }
                await self.xmrig_data.aiohttp_client_session.post(
                    f"{self.xmrig_data.FLASK_SERVER_URL}/newjob",
                    json=job_info,
                    timeout=aiohttp.ClientTimeout(total=10)
                )
        except Exception as e:
            self.logger.log_message(f"[!] Error sending new job info: {e}")
class XmrigMiner:

    def __init__(self, XmrigData, Logger):
        self.xmrig_data = XmrigData
        self.logger = Logger
        self.periodic_reporter = PeriodicReporter(self, self.xmrig_data, self.logger)
        self.server_poller = ServerPoller(self, self.xmrig_data, self.logger)
        self.monitor = OutputMonitor(self, self.xmrig_data, self.logger)
        self.priority = False
        self.cpu_priority = 2
        self.cpu_yield = False
        self.cpu_affinity = 1
        self.psutil_xmrig = None
        self.io_priority = None
        self.memory_usage_min = None
        self.memory_usage_max = None
        self.priority_boost = False
        self.pl1_pl2 = None
        self.cpu_info_flags = set()
        try:
            from cpuinfo import get_cpu_info
            self.cpu_info_flags = set(get_cpu_info().get("flags", []))
        except Exception:
            self.logger.log_message("[!] Failed to detect CPU features")


    async def start_miner(self, pool_url="", thread_count=None):
        await self.kill_all_xmrig_processes()

        if self.xmrig_data.xmrig_process is not None and self.xmrig_data.xmrig_process.returncode is None:
            self.logger.log_message("[!] Miner already running.")
            return

        if thread_count is None:
            try:
                input_threads = await anyio.to_thread.run_sync(input, "Enter thread count (e.g., 4): ")
                self.xmrig_data.threads = int(input_threads.strip())
                if self.xmrig_data.threads <= 0:
                    raise ValueError
            except ValueError:
                self.logger.log_message("[!] Invalid thread count.")
                return
        else:
            self.xmrig_data.threads = thread_count

        if not pool_url:
            input_pool_url = await anyio.to_thread.run_sync(input, "Enter custom pool URL (e.g., 192.168.0.10:3333): ")
            self.xmrig_data.custom_pool_url = input_pool_url.strip()
            if not self.xmrig_data.custom_pool_url:
                self.logger.log_message("[!] No pool URL provided.")
                return
        else:
            self.xmrig_data.custom_pool_url = pool_url

        if not os.path.exists(self.xmrig_data.CONFIG_PATH):
            self.logger.log_message("[!] config.json not found.")
            return

        try:
            await anyio.to_thread.run_sync(
                self.update_config_file_sync,
                self.xmrig_data.custom_pool_url,
                self.xmrig_data.threads
            )
        except Exception as e:
            self.logger.log_message(f"[!] Failed to update config.json: {e}")
            return

        self.xmrig_data.client_status = "Started"
        self.logger.log_message("[+] Starting miner...")

        payload = {"status": self.xmrig_data.client_status}
        try:
            await self.xmrig_data.aiohttp_client_session.post(
                f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            )
        except aiohttp.ClientError as e:
            self.logger.log_message(f"[!] Error reporting miner status: {e}")

        # --- Start miner process using anyio ---
        try:
            self.xmrig_data.xmrig_process = await anyio.open_process(
                [self.xmrig_data.XMRIG_PATH],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.psutil_xmrig = psutil.Process(self.xmrig_data.xmrig_process.pid)
        except Exception as e:
            self.logger.log_message(f"[!] Failed to start XMRig: {e}")
            return

        # --- Set priority if needed ---
        try:
            if self.priority:
                self.psutil_xmrig.nice(psutil.HIGH_PRIORITY_CLASS)
                self.logger.log_message(f"[+] Set XMRig process (PID: {self.psutil_xmrig.pid}) to high priority.")
            if self.cpu_affinity > 0:
                self.psutil_xmrig.cpu_affinity(list(range(self.cpu_affinity)))
                self.logger.log_message(f"[+] Set XMRig process (PID: {self.psutil_xmrig.pid}) to affinity level {self.cpu_affinity}.")
            if self.io_priority and self.priority == False and self.cpu_priority < 3:
                self.psutil_xmrig.ionice(self.io_priority)
                self.logger.log_message(f"[+] Set XMRig process (PID: {self.psutil_xmrig.pid}) to io priority level {str(self.io_priority)}.")
            if self.memory_usage_max:
                self.xmrig_data.process_manager.set_working_set_size(self.psutil_xmrig.pid, self.memory_usage_min, self.memory_usage_max)
                self.logger.log_message(f"[+] Set XMRig process (PID: {self.psutil_xmrig.pid}) to memory usage Min: {str(self.memory_usage_min)} Max:{str(self.memory_usage_max)}.")
            self.xmrig_data.process_manager.set_priority_boost(self.psutil_xmrig.pid, self.priority_boost)
            self.logger.log_message(
                f"[+] Set XMRig process (PID: {self.psutil_xmrig.pid}) to priority boost {self.priority_boost}.")
            if self.xmrig_data.is_intel_cpu and self.pl1_pl2:
                self.xmrig_data.msr_manager.set_pl1_pl2(self.pl1_pl2)
                self.logger.log_message(
                    f"[+] Set XMRig process (PID: {self.psutil_xmrig.pid}) to pl1 and pl2 {self.pl1_pl2}.")

        except psutil.Error as e:
            self.logger.log_message(f"[!] Could not set psutils process settings. Try running as admin/root. {e}")

        # Start monitoring
        await self.monitor.monitor_process(self.xmrig_data.xmrig_process)

    async def stop_miner(self):

        await self.kill_all_xmrig_processes()
        self.logger.log_message("[+] Stopped Miner now reporting")
        self.xmrig_data.client_status = "Stopped"
        payload = {"status": self.xmrig_data.client_status}
        try:
            # Use the shared session here
            await self.xmrig_data.aiohttp_client_session.post(
                f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}", json=payload,
                timeout=aiohttp.ClientTimeout(total=10))
        except aiohttp.ClientError as e:
            self.logger.log_message(f"[!] Error reporting miner status: {e}")

            self.xmrig_data.xmrig_process = None

    async def get_current_threads_from_config_async(self):
        async with self.xmrig_data.miner_lock:
            try:
                return await asyncio.to_thread(self.get_current_threads_from_config_sync)
            except (IOError, json.JSONDecodeError):
                return 0


    def get_current_threads_from_config_sync(self):
        with open(self.xmrig_data.CONFIG_PATH, "r", encoding="utf-8") as f:
            return len(json.load(f).get("cpu", {}).get("rx", []))


    async def update_config_threads_async(self, thread_count):
        async with self.xmrig_data.miner_lock:
            return await asyncio.to_thread(self.update_config_threads_sync, thread_count)


    def update_config_threads_sync(self, thread_count):
        try:
            with open(self.xmrig_data.CONFIG_PATH, "r+", encoding="utf-8") as f:
                config = json.load(f)
                config.setdefault("cpu", {})["rx"] = list(range(thread_count))
                f.seek(0)
                json.dump(config, f, indent=4)
                f.truncate()
            self.logger.log_message(f"[+] Config updated to {thread_count} threads.")
            return True
        except Exception as e:
            self.logger.log_message(f"[!] Failed to update config: {e}")
            return False

    def update_config_file_sync(self, pool_url, thread_count):  # Removed enable_cuda parameter
        with open(self.xmrig_data.CONFIG_PATH, "r+", encoding="utf-8") as f:
            config = json.load(f)

            config["algo"] = "rx"
            if "randomx" in config:
                config["randomx"]["algo"] = "rx"


            flags = self.cpu_info_flags

            supports_avx2 = "avx2" in flags
            supports_aes = "aes" in flags
            supports_sse2 = "sse2" in flags or "sse3" in flags

            config["cpu"]["asm"] = supports_avx2 or supports_sse2
            config["cpu"]["hw-aes"] = supports_aes
            config["cpu"]["priority"] = self.cpu_priority
            config["cpu"]["yield"] = self.cpu_yield

            self.logger.log_message(f"[+] ASM optimization: {'enabled' if config['cpu']['asm'] else 'disabled'}")
            self.logger.log_message(
                f"[+] AES-NI hardware acceleration: {'enabled' if config['cpu']['hw-aes'] else 'disabled'}")
            self.logger.log_message(f"[+] Miner thread priority set to: {config['cpu']['priority']}")
            self.logger.log_message(f"[+] Thread yielding: {'enabled' if config['cpu']['yield'] else 'disabled'}")


            has_nvidia_gpu = False
            if self.xmrig_data.hardware_monitor:
                has_nvidia_gpu = self.xmrig_data.hardware_monitor.has_nvidia_gpu

            config.setdefault("cuda", {})
            config["cuda"]["enabled"] = has_nvidia_gpu  # Set CUDA enabled based on internal detection
            if has_nvidia_gpu:

                if self.xmrig_data.hardware_monitor.tuner:
                    config["cuda"]["rx"] = [{
                        "index": 0,
                        "threads": self.xmrig_data.hardware_monitor.tuner["threads"],
                        "blocks": self.xmrig_data.hardware_monitor.tuner["blocks"],
                        "bfactor": self.xmrig_data.hardware_monitor.tuner["bfactor"],
                        "bsleep": self.xmrig_data.hardware_monitor.tuner["bsleep"],
                        "affinity": -1,
                        "dataset_host": False
                    }]
                    self.logger.log_message(f"[+] Auto CUDA tuning applied: {self.xmrig_data.hardware_monitor.tuner}")
                else:
                    self.logger.log_message("[!] Failed to determine optimal CUDA tuning")
            if "cpu" in config:
                config["cpu"]["enabled"] = True
                config["cpu"]["rx"] = list(range(thread_count))

            if config.get("pools") and isinstance(config["pools"], list):
                for pool in config["pools"]:
                    pool["url"] = pool_url
                    pool["algo"] = "rx/0"
                    pool["coin"] = "XMR"
                    pool["keepalive"] = True

            f.seek(0)
            json.dump(config, f, indent=4)
            f.truncate()
        self.logger.log_message(f"[+] Updated config.json with {thread_count} threads, pool: {pool_url}, CUDA enabled: {has_nvidia_gpu}")

# --- New function to kill existing xmrig processes ---
    async def kill_all_xmrig_processes(self):
        self.logger.log_message("[!] Checking for and terminating existing XMRig processes...")
        current_pid = os.getpid() # Get the PID of the current script
        running_xmrigs=[]
        found_and_killed = False
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Check if the process name contains 'xmrig' (case-insensitive)
                # and it's not the current script's process
                process_name_lower = proc.info['name'].lower()
                if 'xmrig' in process_name_lower and (process_name_lower.endswith('xmrig') or process_name_lower.endswith('xmrig.exe')) and proc.pid != current_pid:
                    self.logger.log_message(f"    - Found XMRig process (PID: {proc.info['pid']}, Name: {proc.info['name']}). Terminating...")
                    proc.terminate() # Send SIGTERM
                    found_and_killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Ignore processes that no longer exist, or cannot be accessed
                continue

        if found_and_killed:
            self.logger.log_message("[!] Waiting for XMRig processes to terminate...")
            # Wait for processes to actually terminate (with a timeout)
            # Filter for xmrig processes again, excluding the current script
            for _ in range(5): # Try for up to 5 seconds

                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        process_name_lower = proc.info['name'].lower()
                        if 'xmrig' in process_name_lower and (process_name_lower.endswith('xmrig') or process_name_lower.endswith('xmrig.exe')) and proc.pid != current_pid:
                            running_xmrigs.append(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                if not running_xmrigs:
                    self.logger.log_message("[+] All identified XMRig processes terminated.")
                    return
                await asyncio.sleep(1) # Wait a bit before re-checking

            # If loop finishes and processes are still there, try to kill forcefully
            for proc in running_xmrigs:
                if proc.is_running():
                    self.logger.log_message(f"[!] XMRig process (PID: {proc.info['pid']}) still running. Forcing kill.")
                    try:
                        proc.kill() # Send SIGKILL
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass # Already gone or inaccessible

        if not found_and_killed:
            self.logger.log_message("[+] No existing XMRig processes found to terminate.")