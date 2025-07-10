import asyncio
import json
import os
import subprocess
import re
import aiohttp



class XmrigMiner:

    def __init__(self, XmrigData):
        self.xmrig_data = XmrigData

    async def monitor_output(self, process):

        async for line_bytes in process.stdout:
            decoded = line_bytes.decode("utf-8", errors="ignore").strip()
            print(f"[XMRIG] {decoded}")

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
                    print(f"[!] Error sending new job info: {e}")
                    pass

    async def start_miner(self, pool_url="", thread_count=None):


        if self.xmrig_data.xmrig_process is not None and self.xmrig_data.xmrig_process.returncode is None:
            print("[!] Miner already running.")
            return

        if thread_count is None:
            try:
                input_threads = await asyncio.to_thread(input, "Enter thread count (e.g., 4): ")
                self.xmrig_data.threads = int(input_threads.strip())
                if self.xmrig_data.threads <= 0:
                    raise ValueError
            except ValueError:
                print("[!] Invalid thread count.")
                return

        if pool_url == "":
            input_pool_url = await asyncio.to_thread(input, "Enter custom pool URL (e.g., 192.168.0.10:3333): ")
            self.xmrig_data.custom_pool_url = input_pool_url.strip()
            if not self.xmrig_data.custom_pool_url:
                print("[!] No pool URL provided.")
                return
        else:
            self.xmrig_data.custom_pool_url = pool_url

        if not os.path.exists(self.xmrig_data.CONFIG_PATH):
            print("[!] config.json not found.")
            return

        try:
            await asyncio.to_thread(self.update_config_file_sync, self.xmrig_data.custom_pool_url, self.xmrig_data.threads)

        except Exception as e:
            print(f"[!] Failed to update config.json: {e}")
            return

        self.xmrig_data.client_status = "Started"
        payload = {"status": self.xmrig_data.client_status}

        print("[+] Starting miner...")
        try:
            # Use the shared session here
            await self.xmrig_data.aiohttp_client_session.post(f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}", json=payload,
                                              timeout=aiohttp.ClientTimeout(total=10))
        except aiohttp.ClientError as e:
            print(f"[!] Error reporting miner status: {e}")

        self.xmrig_data.xmrig_process = await asyncio.create_subprocess_exec(
            self.xmrig_data.XMRIG_PATH,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            # universal_newlines=False is the default and required if you pipe stdout/stderr and want bytes
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        asyncio.create_task(self.monitor_output(self.xmrig_data.xmrig_process))


    async def stop_miner(self):

        if self.xmrig_data.xmrig_process and self.xmrig_data.xmrig_process.returncode is None:
            print("[+] Stopping miner...")
            self.xmrig_data.xmrig_process.terminate()
            self.xmrig_data.client_status = "Stopped"
            payload = {"status": self.xmrig_data.client_status}
            try:
                # Use the shared session here
                await self.xmrig_data.aiohttp_client_session.post(f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}", json=payload,
                                                  timeout=aiohttp.ClientTimeout(total=10))
            except aiohttp.ClientError as e:
                print(f"[!] Error reporting miner status: {e}")

            try:
                await asyncio.wait_for(self.xmrig_data.xmrig_process.wait(), timeout=5)
                print("[+] Miner stopped.")
            except asyncio.TimeoutError:
                print("[!] Miner did not stop in time, killing process.")
                self.xmrig_data.xmrig_process.kill()
                print("[+] Miner process killed.")
            finally:
                self.xmrig_data.xmrig_process = None
        else:
            print("[!] Miner is not running.")
            self.xmrig_data.client_status = "Stopped"
            self.xmrig_data.xmrig_process = None

    async def poll_server(self, session: aiohttp.ClientSession):

        while True:
            try:
                payload = {"status": self.xmrig_data.client_status}
                # Use the shared session here
                await session.post(f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}", json=payload,
                                   timeout=aiohttp.ClientTimeout(total=10))

                # Use the shared session here
                async with session.get(f"{self.xmrig_data.FLASK_SERVER_URL}/get_command/{self.xmrig_data.client_id}",
                                       timeout=aiohttp.ClientTimeout(total=10)) as response:
                    response.raise_for_status()
                    command = await response.json()

                if command:
                    print(f"\n[+] Received command from server: '{command.get('command')}'")
                    if command.get("command") == "start":
                        await self.stop_miner()
                        self.xmrig_data.custom_pool_url = command.get("pool", self.xmrig_data.custom_pool_url)
                        self.xmrig_data.threads = command.get("threads", self.xmrig_data.threads)
                        await self.start_miner(self.xmrig_data.custom_pool_url, self.xmrig_data.threads)
                    elif command.get("command") == "stop":
                        await self.stop_miner()
                    elif command.get("command") == "set_threads":
                        new_threads = int(command["threads"])
                        print(f"\n[+] Received command: Setting threads to {new_threads}.")
                        await self.update_config_threads_async(new_threads)

            except aiohttp.ClientError as e:
                print(f"[!] Cannot connect to server at {self.xmrig_data.FLASK_SERVER_URL} or HTTP error: {e}. Retrying...")
            except Exception as e:
                print(f"[!] An unexpected error occurred during polling: {e}")

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
            print(f"[+] Config updated to {thread_count} threads.")
            return True
        except Exception as e:
            print(f"[!] Failed to update config: {e}")
            return False

    def update_config_file_sync(self, pool_url, thread_count):  # Removed enable_cuda parameter
        with open(self.xmrig_data.CONFIG_PATH, "r+", encoding="utf-8") as f:
            config = json.load(f)

            config["algo"] = "rx"
            if "randomx" in config:
                config["randomx"]["algo"] = "rx"

            # Detect NVIDIA GPU internally
            has_nvidia_gpu = self.xmrig_data.check_nvidia_gpu_sync()
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
        print(f"[+] Updated config.json with {thread_count} threads, pool: {pool_url}, CUDA enabled: {has_nvidia_gpu}")


