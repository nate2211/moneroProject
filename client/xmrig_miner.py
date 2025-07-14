import asyncio
import json
import os
import subprocess
import re
import aiohttp
import psutil

REPORT_INTERVAL_SECONDS = 5

class XmrigMiner:

    def __init__(self, XmrigData, Logger):
        self.xmrig_data = XmrigData
        self.logger = Logger

    async def monitor_output(self, process):
        async for line_bytes in process.stdout:
            decoded = line_bytes.decode("utf-8", errors="ignore").strip()

            self.logger.log_message(f"[XMRIG] {decoded}")
            if "error" in decoded.lower():
                await self.stop_miner()
                await asyncio.sleep(30)
                await self.start_miner(self.xmrig_data.custom_pool_url, self.xmrig_data.threads)

            if "cpu" in decoded.lower() and "accepted" in decoded.lower():
                match = re.search(r"accepted\s+\((\d+)/\d+\)", decoded.lower())
                if match:
                    self.xmrig_data._latest_cpu_accepted_shares = int(match.group(1))

            if "nvidia" in decoded.lower() and "accepted" in decoded.lower():
                match = re.search(r"accepted\s+\((\d+)/\d+\)", decoded.lower())
                if match:
                    self.xmrig_data._latest_nvidia_accepted_shares = int(match.group(1))

            if "nvidia" in decoded.lower() and "c" in decoded.lower():
                temp_match = re.search(r"(\d+c)", decoded.lower())
                fan_match = re.search(r"fan\d+:(\d+%)", decoded.lower())
                if temp_match:
                    self.xmrig_data._latest_gpu_temp = temp_match.group(1)
                if fan_match:
                    self.xmrig_data._latest_gpu_fan = fan_match.group(1)

            if "miner" in decoded.lower() and "speed" in decoded.lower():
                match = re.search(r"speed\s+\d+s/\d+s/\d+m\s+([\d.]+)\s+", decoded)
                if match:
                    self.xmrig_data._latest_hashrate = float(match.group(1))
            elif "gpu" in decoded.lower() and "compute error" in decoded.lower():
                await self.stop_miner()
                await asyncio.sleep(30)
                await self.start_miner(self.xmrig_data.custom_pool_url, self.xmrig_data.threads)
            elif "new job from" in decoded.lower():
                try:
                    match = re.search(
                        r"new job from ([\d.:]+).*?diff (\d+).*?algo ([^\s]+).*?height (\d+).*?\((\d+) tx\)",
                        decoded)
                    if match:
                        job_info = {
                            "client_id": self.xmrig_data.client_id,
                            "ip": match.group(1),
                            "difficulty": int(match.group(2)),
                            "algo": match.group(3),
                            "height": int(match.group(4)),
                            "tx_count": int(match.group(5))
                        }
                        # Use the shared session here
                        await self.xmrig_data.aiohttp_client_session.post(f"{self.xmrig_data.FLASK_SERVER_URL}/newjob",
                                                                     json=job_info,
                                                                     timeout=aiohttp.ClientTimeout(total=10))
                except Exception as e:
                    self.logger.log_message(f"[!] Error sending new job info: {e}")
                    pass

    async def periodic_reporter(self, session: aiohttp.ClientSession, ui_signal):

        while True:
                await asyncio.sleep(REPORT_INTERVAL_SECONDS)

                current_cpu_temp = await self.xmrig_data.get_cpu_temperature_async()
                current_power_draw = await self.xmrig_data.get_power_draw_async()
                current_threads = await self.get_current_threads_from_config_async()
                payload = {}
                if self.xmrig_data.client_status == "Started":
                    payload = {
                        "client_id": self.xmrig_data.client_id,
                        "hashrate": self.xmrig_data._latest_hashrate,
                        "threads": current_threads,
                        "cpu_temp": current_cpu_temp,
                        "gpu_temp": self.xmrig_data._latest_gpu_temp,
                        "gpu_fan": self.xmrig_data._latest_gpu_fan,
                        "cpu_accepted_shares": self.xmrig_data._latest_cpu_accepted_shares,
                        "nvidia_accepted_shares": self.xmrig_data._latest_nvidia_accepted_shares,
                        "power_draw": current_power_draw
                    }
                else:
                    payload = {
                        "client_id": self.xmrig_data.client_id,
                        "hashrate": 0,
                        "threads": current_threads,
                        "cpu_temp": current_cpu_temp,
                        "gpu_temp": self.xmrig_data._latest_gpu_temp,
                        "gpu_fan": self.xmrig_data._latest_gpu_fan,
                        "cpu_accepted_shares": 0,
                        "nvidia_accepted_shares": 0,
                        "power_draw": current_power_draw
                    }
                ui_signal.emit(payload)
                try:

                    await session.post(f"{self.xmrig_data.FLASK_SERVER_URL}/hashrate", json=payload,
                                       timeout=aiohttp.ClientTimeout(total=10))
                except aiohttp.ClientError as e:
                    self.logger.log_message(f"[!] Error sending periodic hashrate report: {e}")
                except Exception as e:
                    self.logger.log_message(f"[!] Unexpected error during periodic hashrate report send: {e}")

    async def start_miner(self, pool_url="", thread_count=None):

        await self.kill_all_xmrig_processes()
        if self.xmrig_data.xmrig_process is not None and self.xmrig_data.xmrig_process.returncode is None:
            self.logger.log_message("[!] Miner already running.")
            return

        if thread_count is None:
            try:
                input_threads = await asyncio.to_thread(input, "Enter thread count (e.g., 4): ")
                self.xmrig_data.threads = int(input_threads.strip())
                if self.xmrig_data.threads <= 0:
                    raise ValueError
            except ValueError:
                self.logger.log_message("[!] Invalid thread count.")
                return
        else:
            self.xmrig_data.threads = thread_count

        if pool_url == "":
            input_pool_url = await asyncio.to_thread(input, "Enter custom pool URL (e.g., 192.168.0.10:3333): ")
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
            await asyncio.to_thread(self.update_config_file_sync, self.xmrig_data.custom_pool_url, self.xmrig_data.threads)

        except Exception as e:
            self.logger.log_message(f"[!] Failed to update config.json: {e}")
            return

        self.xmrig_data.client_status = "Started"
        payload = {"status": self.xmrig_data.client_status}

        self.logger.log_message("[+] Starting miner...")
        try:
            # Use the shared session here
            await self.xmrig_data.aiohttp_client_session.post(f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}", json=payload,
                                              timeout=aiohttp.ClientTimeout(total=10))
        except aiohttp.ClientError as e:
            self.logger.log_message(f"[!] Error reporting miner status: {e}")

        self.xmrig_data.xmrig_process = await asyncio.create_subprocess_exec(
            self.xmrig_data.XMRIG_PATH,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        # --- Add this section to set priority ---
        try:
            p = psutil.Process(self.xmrig_data.xmrig_process.pid)
            p.nice(psutil.HIGH_PRIORITY_CLASS)  # For Windows
            # On Linux, you might use: p.nice(-10) # Lower number is higher priority
            self.logger.log_message(f"[+] Set XMRig process (PID: {p.pid}) to high priority.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.logger.log_message("[!] Could not set XMRig process priority. Run as admin/root for best results.")

        asyncio.create_task(self.monitor_output(self.xmrig_data.xmrig_process))


    async def stop_miner(self):

        await self.kill_all_xmrig_processes()
        self.logger.log_message("[+] Stopped Miner now reporting")
        self.xmrig_data.client_status = "Stopped"
        payload = {"status": self.xmrig_data.client_status}
        try:
            # Use the shared session here
            await self.xmrig_data.aiohttp_client_session.post(f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}", json=payload,
                                              timeout=aiohttp.ClientTimeout(total=10))
        except aiohttp.ClientError as e:
            self.logger.log_message(f"[!] Error reporting miner status: {e}")

            self.xmrig_data.xmrig_process = None

    async def poll_server(self, session: aiohttp.ClientSession, force_update_signal):

        while True:
            try:
                if self.xmrig_data.xmrig_process is not None and self.xmrig_data.xmrig_process.returncode is None:
                    self.xmrig_data.client_status = "Started"
                else:
                    self.xmrig_data.client_status = "Stopped"
                payload = {"status": self.xmrig_data.client_status}
                # Use the shared session here
                await session.post(f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}",
                                         json=payload,
                                         timeout=aiohttp.ClientTimeout(total=10))


                async with session.get(f"{self.xmrig_data.FLASK_SERVER_URL}/get_command/{self.xmrig_data.client_id}",
                                       timeout=aiohttp.ClientTimeout(total=10)) as response:
                    response.raise_for_status()
                    command = await response.json()
                if command:
                    self.logger.log_message(f"\n[+] Received command from server: '{command.get('command')}'")
                    if command.get("command") == "start":
                        await self.stop_miner()
                        self.xmrig_data.custom_pool_url = command.get("pool", self.xmrig_data.custom_pool_url)
                        self.xmrig_data.threads = command.get("threads", self.xmrig_data.threads)
                        await self.start_miner(self.xmrig_data.custom_pool_url, self.xmrig_data.threads)
                    elif command.get("command") == "stop":
                        await self.stop_miner()
                    elif command.get("command") == "set_threads":
                        new_threads = int(command["threads"])
                        await self.update_config_threads_async(new_threads)
                    elif command.get("command") == "update":
                        update_url = command.get("url")
                        if update_url:
                            force_update_signal.emit(update_url)
            except aiohttp.ClientError as e:
                self.logger.log_message(f"[!] Cannot connect to server at {self.xmrig_data.FLASK_SERVER_URL} or HTTP error: {e}. Retrying...")
            except Exception as e:
                self.logger.log_message(f"[!] An unexpected error occurred during polling: {e}")

            await asyncio.sleep(5)

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


            has_nvidia_gpu = False
            if self.xmrig_data.hardware_monitor:
                has_nvidia_gpu = self.xmrig_data.hardware_monitor.has_nvidia_gpu

            config.setdefault("cuda", {})
            config["cuda"]["enabled"] = has_nvidia_gpu  # Set CUDA enabled based on internal detection

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