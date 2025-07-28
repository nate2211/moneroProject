import asyncio
import os
import socket
import sys
import subprocess
import threading
import queue
import datetime
import re
import time
from collections import deque

import psutil


class AsyncEventLogger:
    def __init__(self, P2poolData, asyncio_main_loop, logger):
        self.p2pool_data = P2poolData
        self.asyncio_main_loop = asyncio_main_loop
        self.logger = logger

    async def writer_loop(self):
        os.makedirs(os.path.dirname(self.p2pool_data.EVENT_LOG), exist_ok=True)
        try:
            with open(self.p2pool_data.EVENT_LOG, "a", encoding="utf-8") as f:
                while True:
                    line = await self.p2pool_data.log_queue.get()
                    f.write(line + "\n")
                    f.flush()
        except asyncio.CancelledError:
            self.logger.log_message("[AsyncEventLogger] Logging task cancelled.")
        except Exception as e:
            self.logger.log_message(f"[AsyncEventLogger] Failed to write log: {e}")

    def start(self):
        asyncio.run_coroutine_threadsafe(self.writer_loop(), self.asyncio_main_loop)


class P2PoolProcessor:
    """
    Manages the P2Pool subprocess asynchronously, including resource monitoring.
    """

    def __init__(self, p2pooldata_instance, logger, stop_event):
        self.p2pool_data = p2pooldata_instance
        self.cpu_usage = 0
        self.ram_usage_mb = 0
        self.vms_usage_mb = 0
        self.num_page_faults = 0
        self.paged_pool_mb = 0
        self.page_file_mb = 0
        self.psutil_proc = None
        self.redirect_task = None
        self.monitor_task = None  # Task for the new stats monitor
        self.logger = logger
        # Store the IP P2Pool is currently bound to
        self.current_stratum_bind_ip = None
        self.stop_event = stop_event
        self.proc_lock = asyncio.Lock()
    def strip_ansi_codes(self, text: str) -> str:
        """Removes ANSI escape codes from a string."""
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    def _is_ip_bindable(self, ip_address: str) -> bool:
        """
        Creates a temporary socket to check if an IP is available for binding.
        """
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Bind to the specified IP and an ephemeral port (port 0)
            temp_socket.bind((ip_address, 0))
            self.logger.log_message(f"[+] IP Check: Address {ip_address} is bindable on this machine.")
            return True
        except OSError:
            # This error occurs if the IP is not local to the machine
            self.logger.log_message(f"[!] IP Check: Address {ip_address} is NOT bindable. Will use fallback.")
            return False
        finally:
            # Ensure the socket is always closed
            temp_socket.close()

    async def start_p2pool(self) -> bool:
        """
        Checks for a bindable static IP and starts P2Pool with the correct configuration.
        """
        exe_path = os.path.join(self.p2pool_data.P2POOL_DIR, self.p2pool_data.P2POOL_EXE)
        if not os.path.exists(exe_path):
            self.logger.log_message(f"[!] Executable not found at: {exe_path}")
            return False

        # --- Perform the IP check before building the command ---
        preferred_ip = "192.168.0.10"
        if self._is_ip_bindable(preferred_ip):
            stratum_host = preferred_ip
        else:
            stratum_host = "0.0.0.0"

        # --- Build the final arguments with the chosen IP ---
        args = [
            exe_path,
            "--host", "127.0.0.1",
            "--wallet", self.p2pool_data.WALLET,
            "--mini",
            "--stratum", f"{stratum_host}:3333",  # Use the determined host
            "--no-upnp",
            "--no-color",
            "--p2p", "0.0.0.0:37888"
        ]

        try:
            self.p2pool_data.p2pool_proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=self.p2pool_data.P2POOL_DIR,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.logger.log_message(
                f"[+] P2Pool process started successfully with PID: {self.p2pool_data.p2pool_proc.pid}")
            self.p2pool_data.log_event_now("P2Pool Process", "P2Pool process started successfully")

            # Attach psutil for monitoring
            try:
                pid = self.p2pool_data.p2pool_proc.pid
                self.psutil_proc = psutil.Process(pid)
                self.psutil_proc.nice(psutil.HIGH_PRIORITY_CLASS)
                self.psutil_proc.cpu_percent(interval=None)
            except psutil.NoSuchProcess:
                self.logger.log_message(f"[!] Failed to attach psutil to PID {pid}. Stats will not be monitored.")
                self.psutil_proc = None

            # Start background tasks, respecting the main stop event
            if self.stop_event:  # Check if the event is set
                self.redirect_task = asyncio.create_task(
                    self._redirect_output(self.stop_event)
                )
                if self.psutil_proc:
                    self.monitor_task = asyncio.create_task(
                        self._monitor_stats(self.stop_event)
                    )
            else:
                self.logger.log_message(
                    "[!] P2PoolProcessor: main stop_event not set, background tasks might not stop gracefully.")
                # Fallback to tasks that don't check a stop event if not provided
                self.redirect_task = asyncio.create_task(self._redirect_output(threading.Event()))  # Pass a dummy event
                if self.psutil_proc:
                    self.monitor_task = asyncio.create_task(
                        self._monitor_stats(threading.Event()))  # Pass a dummy event

            return True
        except Exception as e:
            self.logger.log_message(f"[!] Failed to launch P2Pool: {e}")
            return False

    async def _monitor_stats(self, stop_event: threading.Event):  # Added stop_event parameter
        """Asynchronously monitors the process's CPU and RAM usage."""
        p = self.psutil_proc
        self.logger.log_message("[+] Stats monitor started.")
        try:
            while not stop_event.is_set():  # Check stop event in loop
                with p.oneshot():
                    cpu = p.cpu_percent(interval=None)
                    memoryinfo = p.memory_info()
                    ram_mb = memoryinfo.rss / (1024 * 1024)
                    vms_usage_mb = memoryinfo.vms / (1024 * 1024)
                    num_page_faults = memoryinfo.num_page_faults / (1024 * 1024)
                    paged_pool_mb = memoryinfo.paged_pool / (1024 * 1024)
                    page_file_mb = memoryinfo.pagefile / (1024 * 1024)

                self.cpu_usage = round(cpu, 2)
                self.ram_usage_mb = round(ram_mb, 2)
                self.vms_usage_mb = round(vms_usage_mb, 2)
                self.num_page_faults = round(num_page_faults, 5)
                self.paged_pool_mb = round(paged_pool_mb, 2)
                self.page_file_mb = round(page_file_mb, 2)
                await asyncio.sleep(5)
        except psutil.NoSuchProcess:
            self.logger.log_message("[!] Stats monitor: P2Pool process not found. Stopping monitor.")
        except asyncio.CancelledError:
            self.logger.log_message("[+] Stats monitor task was cancelled.")
        except Exception as e:
            self.logger.log_message(f"[!] An error occurred in the stats monitor: {e}")
        finally:
            self.logger.log_message("[-] Stats monitor stopped.")
            self.cpu_usage = 0.0
            self.ram_usage_mb = 0.0
            self.vms_usage_mb = 0.0
            self.num_page_faults = 0
            self.paged_pool_mb = 0
            self.page_file_mb = 0

    async def stop_p2pool(self):
        """
        Stops the P2Pool process gracefully and cleans up monitoring tasks.
        """
        # Acquire the lock to ensure atomicity
        async with self.proc_lock:
            if not self.p2pool_data.p2pool_proc or self.p2pool_data.p2pool_proc.returncode is not None:
                self.logger.log_message("[!] P2Pool is not running.")
                return

            self.logger.log_message("[!] Attempting to terminate P2Pool process...")
            try:
                # Signal background tasks to stop
                if self.redirect_task and not self.redirect_task.done():
                    self.redirect_task.cancel()
                if self.monitor_task and not self.monitor_task.done():
                    self.monitor_task.cancel()

                self.p2pool_data.p2pool_proc.terminate()
                await asyncio.wait_for(self.p2pool_data.p2pool_proc.wait(), timeout=5.0)
                self.p2pool_data.log_event_now("P2Pool Process", "P2Pool process ended successfully")
                self.logger.log_message("[+] P2Pool process terminated gracefully.")
            except asyncio.TimeoutError:
                self.logger.log_message("[!] P2Pool did not terminate gracefully, forcing kill.")
                self.p2pool_data.p2pool_proc.kill()
                await self.p2pool_data.p2pool_proc.wait()
            except Exception as e:
                self.logger.log_message(f"[!] Error stopping P2Pool: {e}")
            finally:
                # Clean up resources
                self.psutil_proc = None
                self.p2pool_data.p2pool_proc = None

    async def _redirect_output(self, stop_event: threading.Event):  # Added stop_event parameter
        """Asynchronously reads stdout and writes it to the raw log file."""
        if not self.p2pool_data.p2pool_proc or not self.p2pool_data.p2pool_proc.stdout:
            return

        try:
            with open(self.p2pool_data.RAW_LOG, "a", encoding="utf-8") as log_file:
                while not stop_event.is_set():  # Check stop event in loop
                    try:
                        line_bytes = await asyncio.wait_for(self.p2pool_data.p2pool_proc.stdout.readline(),
                                                            timeout=1.0)  # Add timeout
                        if not line_bytes:
                            # If no line and process is done, break. Otherwise, continue waiting.
                            if self.p2pool_data.p2pool_proc.returncode is not None:
                                break
                            await asyncio.sleep(0.1)  # Prevent busy-waiting
                            continue
                        line = line_bytes.decode('utf-8', errors='ignore').strip()
                        clean_line = self.strip_ansi_codes(line)
                        log_file.write(clean_line + "\n")
                        log_file.flush()
                        self.logger.log_message(f"[P2Pool] {clean_line}")
                    except asyncio.TimeoutError:
                        # Timeout occurred, loop again and check stop_event
                        continue
        except asyncio.CancelledError:
            self.logger.log_message("[P2Pool] Output redirection task was cancelled.")
        except Exception as e:
            self.p2pool_data.log_event_now("P2pool Process", f"Redirect output error: {e}")
        finally:
            self.p2pool_data.log_event_now("P2Pool Process", "P2Pool stdout stream ended.")

    async def write_to_stdin(self, command: str) -> bool:
        """Asynchronously writes a command to the process's stdin."""
        async with self.proc_lock:
            proc = self.p2pool_data.p2pool_proc
            if proc and proc.stdin and not proc.stdin.is_closing():
                try:
                    proc.stdin.write(f"{command}\n".encode('utf-8'))
                    await proc.stdin.drain()
                    return True
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    self.p2pool_data.log_event_now("P2Pool Process", f"Error writing to stdin: {e}")
                    return False
        return False


class RawLogProcessor:
    """
    Tails the raw P2Pool log file, parses its output, and queues structured
    events to be written to the main event log by the log_writer.
    """

    def __init__(self, p2pooldata_instance, logger, stop_event):
        """
        Initializes the raw log processor.

        Args:
            p2pooldata_instance (P2poolData): The main data object.
        """
        self.p2pool_data = p2pooldata_instance
        self.logger = logger
        self.stop_event = stop_event

    def run_in_background(self):
        """
        The main loop for this thread. Tails the raw P2Pool log file continuously.
        """
        raw_log_path = self.p2pool_data.RAW_LOG
        self.logger.log_message(f"[*] RawLogProcessor thread started. Tailing: {raw_log_path}")

        while not os.path.exists(raw_log_path):
            self.logger.log_message("[!] Raw log file does not exist yet, waiting...")
            time.sleep(2)

        try:
            with open(raw_log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while not self.stop_event.is_set():
                    miner_data_block = []
                    in_miner_data = False

                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(0.1)  # Wait for new content
                            continue

                        clean_line = line.strip()
                        if not clean_line:
                            continue

                        lower_line = clean_line.lower()

                        if "p2pool new miner data" in lower_line:
                            in_miner_data = True
                            miner_data_block = [clean_line]
                            continue

                        if in_miner_data:
                            if clean_line == "" or clean_line.startswith("-"):
                                full_block = "\n".join(miner_data_block).strip()
                                self.p2pool_data.log_event_now("New Miner Data", full_block)
                                in_miner_data = False
                            else:
                                miner_data_block.append(clean_line)
                            continue

                        if "sent new job" in lower_line:
                            self.p2pool_data.log_event_now("Sent Jobs", clean_line)
                        elif "share found" in lower_line:
                            self.p2pool_data.log_event_now("Found Share", clean_line)
                        elif "block found" in lower_line:
                            self.p2pool_data.log_event_now("Found Block", clean_line)
                        elif "sidechain add_block" in lower_line:
                            self.p2pool_data.log_event_now("Sidechain Block Added", clean_line)
                        elif "p2pool caught sigint" in lower_line or "p2pool stopping" in lower_line:
                            self.p2pool_data.log_event_now("P2Pool Stopped", clean_line)

        except Exception as e:
            error_msg = f"RawLogProcessor thread terminated with error: {e}"
            self.logger.log_message(f"[!] {error_msg}")
            self.p2pool_data.log_event_now("RawLogProcessor Error", error_msg)


class EventProcessor:
    """
    Tails the event log file in a background thread, parsing and categorizing
    events into in-memory deques for fast API access.
    """

    def __init__(self, P2poolData, logger, stop_event, max_events_per_category=50):
        """
        Initializes the event processor.

        Args:
            p2pooldata_instance (P2poolData): The main data object.
            max_events_per_category (int): Max number of events to keep for each category.
        """
        self.p2pool_data = P2poolData
        self.max_events = max_events_per_category
        self.lock = threading.Lock()
        self.logger = logger
        # Use deque with maxlen for efficient, automatically capped lists
        self.shares_found = deque(maxlen=self.max_events)
        self.jobs_sent = deque(maxlen=self.max_events)
        self.miner_data = deque(maxlen=self.max_events)
        self.blocks_found = deque(maxlen=self.max_events)
        self.other_events = deque(maxlen=self.max_events)
        self.sidechain_events = deque(maxlen=self.max_events)
        self.stop_event = stop_event

    def _parse_and_categorize_line(self, line):
        """Parses a single log line and adds it to the correct category deque."""
        match = re.match(r"\[(.*?)\] \[(.*?)\] (.*)", line, re.DOTALL)
        if not match:
            return

        event = {
            "time": match.group(1),
            "type": match.group(2),
            "message": match.group(3).strip()
        }

        # Use a lock to ensure thread-safe writes to the deques
        with self.lock:
            event_type = event["type"]
            if event_type == "Found Share":
                self.shares_found.appendleft(event)
            elif event_type == "Sent Jobs":
                self.jobs_sent.appendleft(event)
            elif event_type == "New Miner Data":
                self.miner_data.appendleft(event)
            elif event_type == "Found Block":
                self.blocks_found.appendleft(event)
            elif "Sidechain" in event_type:
                self.sidechain_events.appendleft(event)
            else:
                self.other_events.appendleft(event)

    def run_in_background(self):
        """
        The main loop for this thread. Tails the event log file continuously.
        """
        event_log_path = self.p2pool_data.EVENT_LOG
        self.logger.log_message(f"[*] EventProcessor thread started. Tailing: {event_log_path}")

        while not os.path.exists(event_log_path):
            self.logger.log_message("[!] Event log does not exist yet, waiting...")
            time.sleep(2)

        try:
            with open(event_log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)  # Start at the end of the file
                while not self.stop_event.is_set():
                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(0.2)  # No new lines, wait a bit
                            continue
                        self._parse_and_categorize_line(line)
        except Exception as e:
            error_msg = f"EventProcessor thread terminated with error: {e}"
            self.logger.log_message(f"[!] {error_msg}")
            self.p2pool_data.log_event_now("EventProcessor Error", error_msg)

    def get_all_events(self, limit=10):
        """Returns a snapshot of the current events for the API."""
        with self.lock:
            return {
                "shares_found": list(self.shares_found)[:limit],
                "jobs_sent": list(self.jobs_sent)[:limit],
                "miner_data": list(self.miner_data)[:limit],
                "blocks_found": list(self.blocks_found)[:limit],
                "sidechain_events": list(self.sidechain_events)[:limit],
                "other_events": list(self.other_events)[:limit]
            }


class P2poolData:

    def __init__(self, logger):

        if getattr(sys, 'frozen', False):
            # Running in PyInstaller bundle
            self.P2POOL_DIR = os.path.join(sys._MEIPASS, 'tools')
        else:
            # Running in development
            self.P2POOL_DIR = os.path.join(os.path.dirname(__file__), 'tools')
        self.P2POOL_EXE = "p2pool.exe"
        self.WALLET = "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
        self.p2pool_proc = None
        self.EVENT_LOG = os.path.join(self.P2POOL_DIR, "event_log.txt")
        self.RAW_LOG = os.path.join(self.P2POOL_DIR, "p2pool_raw_output.txt")
        self.log_queue = asyncio.Queue()
        self.logger = logger


    def time_ago(self, timestamp):
        """Converts a Unix timestamp into a 'time ago' string."""
        now = datetime.datetime.now()
        dt = datetime.datetime.fromtimestamp(timestamp)
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

    def log_event_now(self, event_type, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put_nowait(f"[{timestamp}] [{event_type}] {message}")