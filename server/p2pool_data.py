import asyncio
import os
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
    def __init__(self, P2poolData, asyncio_main_loop):
        self.p2pool_data = P2poolData
        self.asyncio_main_loop = asyncio_main_loop

    async def writer_loop(self):
        os.makedirs(os.path.dirname(self.p2pool_data.EVENT_LOG), exist_ok=True)
        try:
            with open(self.p2pool_data.EVENT_LOG, "a", encoding="utf-8") as f:
                while True:
                    line = await self.p2pool_data.log_queue.get()
                    f.write(line + "\n")
                    f.flush()
        except asyncio.CancelledError:
            print("[AsyncEventLogger] Logging task cancelled.")
        except Exception as e:
            print(f"[AsyncEventLogger] Failed to write log: {e}")

    def start(self):
        asyncio.run_coroutine_threadsafe(self.writer_loop(), self.asyncio_main_loop)


class P2PoolProcessor:
    """
    Manages the P2Pool subprocess asynchronously, including resource monitoring.
    """

    def __init__(self, p2pooldata_instance):
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

    def strip_ansi_codes(self, text: str) -> str:
        """Removes ANSI escape codes from a string."""
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    async def start_p2pool(self) -> bool:
        """
        Starts the P2Pool process and begins redirecting its output and monitoring its stats.
        """
        exe_path = os.path.join(self.p2pool_data.P2POOL_DIR, self.p2pool_data.P2POOL_EXE)
        if not os.path.exists(exe_path):
            print(f"[!] Executable not found at: {exe_path}")
            return False

        args = [
            exe_path, "--host", "127.0.0.1", "--wallet", self.p2pool_data.WALLET,
            "--mini", "--stratum", "192.168.0.10:3333", "--no-upnp", "--no-color", "--p2p", "0.0.0.0:37888"
        ]

        try:
            self.p2pool_data.p2pool_proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=self.p2pool_data.P2POOL_DIR,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags = subprocess.CREATE_NO_WINDOW
            )
            print(f"[+] P2Pool process started successfully with PID: {self.p2pool_data.p2pool_proc.pid}")
            self.p2pool_data.log_event_now("P2Pool Process", "P2Pool process started successfully")

            # --- ✅ Attach psutil for monitoring ---
            try:
                pid = self.p2pool_data.p2pool_proc.pid
                self.psutil_proc = psutil.Process(pid)
                self.psutil_proc.nice(psutil.HIGH_PRIORITY_CLASS)
                # This initializes the cpu_percent calculation.
                self.psutil_proc.cpu_percent(interval=None)
            except psutil.NoSuchProcess:
                print(f"[!] Failed to attach psutil to PID {pid}. Stats will not be monitored.")
                self.psutil_proc = None

            # --- Start background tasks ---
            self.redirect_task = asyncio.create_task(self._redirect_output())
            if self.psutil_proc:
                self.monitor_task = asyncio.create_task(self._monitor_stats())

            return True
        except Exception as e:
            print(f"[!] Failed to launch P2Pool: {e}")
            return False

    async def _monitor_stats(self):
        """Asynchronously monitors the process's CPU and RAM usage."""
        p = self.psutil_proc
        print("[+] Stats monitor started.")
        try:
            while True:
                with p.oneshot():
                    # Get stats from psutil object
                    cpu = p.cpu_percent(interval=None)
                    memoryinfo = p.memory_info()
                    # RSS: Resident Set Size (non-swapped physical memory)
                    ram_mb = memoryinfo.rss / (1024 * 1024)
                    vms_usage_mb = memoryinfo.vms / (1024 * 1024)
                    num_page_faults = memoryinfo.num_page_faults / (1024 * 1024)
                    paged_pool_mb = memoryinfo.paged_pool / (1024 * 1024)
                    page_file_mb = memoryinfo.pagefile / (1024 * 1024)

                # Update the central data object (assuming these attributes exist)
                self.cpu_usage = round(cpu, 2)
                self.ram_usage_mb = round(ram_mb, 2)
                self.vms_usage_mb = round(vms_usage_mb, 2)
                self.num_page_faults = round(num_page_faults, 5)
                self.paged_pool_mb = round(paged_pool_mb, 2)
                self.page_file_mb = round(page_file_mb, 2)
                # Update stats every 5 seconds without blocking the event loop
                await asyncio.sleep(5)
        except psutil.NoSuchProcess:
            print("[!] Stats monitor: P2Pool process not found. Stopping monitor.")
        except asyncio.CancelledError:
            print("[+] Stats monitor task was cancelled.")
        except Exception as e:
            print(f"[!] An error occurred in the stats monitor: {e}")
        finally:
            print("[-] Stats monitor stopped.")
            # Clear stats on exit
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
        if not self.p2pool_data.p2pool_proc or self.p2pool_data.p2pool_proc.returncode is not None:
            print("[!] P2Pool is not running.")
            return

        print("[!] Attempting to terminate P2Pool process...")
        try:
            self.p2pool_data.p2pool_proc.terminate()
            await asyncio.wait_for(self.p2pool_data.p2pool_proc.wait(), timeout=5.0)
            self.p2pool_data.log_event_now("P2Pool Process", "P2Pool process ended successfully")
            print("[+] P2Pool process terminated gracefully.")
        except asyncio.TimeoutError:
            print("[!] P2Pool did not terminate gracefully, forcing kill.")
            self.p2pool_data.p2pool_proc.kill()
            await self.p2pool_data.p2pool_proc.wait()
        except Exception as e:
            print(f"[!] Error stopping P2Pool: {e}")
        finally:
            # Cancel all background tasks associated with the process
            if self.redirect_task and not self.redirect_task.done():
                self.redirect_task.cancel()
            if self.monitor_task and not self.monitor_task.done():
                self.monitor_task.cancel()

            self.p2pool_data.p2pool_psutil_proc = None
            self.p2pool_data.p2pool_proc = None

    async def _redirect_output(self):
        """Asynchronously reads stdout and writes it to the raw log file."""
        if not self.p2pool_data.p2pool_proc or not self.p2pool_data.p2pool_proc.stdout:
            return

        try:
            with open(self.p2pool_data.RAW_LOG, "a", encoding="utf-8") as log_file:
                while True:
                    line_bytes = await self.p2pool_data.p2pool_proc.stdout.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode('utf-8', errors='ignore').strip()
                    clean_line = self.strip_ansi_codes(line)
                    log_file.write(clean_line + "\n")
                    log_file.flush()
                    print("[P2Pool]", clean_line)
        except asyncio.CancelledError:
            print("[P2Pool] Output redirection task was cancelled.")
        except Exception as e:
            self.p2pool_data.log_event_now("P2pool Process", f"Redirect output error: {e}")
        finally:
            self.p2pool_data.log_event_now("P2Pool Process", "P2Pool stdout stream ended.")

    async def write_to_stdin(self, command: str) -> bool:
        """Asynchronously writes a command to the process's stdin."""
        if self.p2pool_data.p2pool_proc and self.p2pool_data.p2pool_proc.stdin:
            try:
                self.p2pool_data.p2pool_proc.stdin.write(f"{command}\n".encode('utf-8'))
                await self.p2pool_data.p2pool_proc.stdin.drain()
                return True
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                # FIX: Corrected typo from p2pool_data.p2pool_data to p2pool_data
                self.p2pool_data.log_event_now("P2Pool Process", f"Error writing to stdin: {e}")
                return False
        return False
class RawLogProcessor:
    """
    Tails the raw P2Pool log file, parses its output, and queues structured
    events to be written to the main event log by the log_writer.
    """

    def __init__(self, p2pooldata_instance):
        """
        Initializes the raw log processor.

        Args:
            p2pooldata_instance (P2poolData): The main data object.
        """
        self.p2pool_data = p2pooldata_instance

    def run_in_background(self):
        """
        The main loop for this thread. Tails the raw P2Pool log file continuously.
        """
        raw_log_path = self.p2pool_data.RAW_LOG
        print(f"[*] RawLogProcessor thread started. Tailing: {raw_log_path}")

        while not os.path.exists(raw_log_path):
            print("[!] Raw log file does not exist yet, waiting...")
            time.sleep(2)

        try:
            with open(raw_log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
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
            print(f"[!] {error_msg}")
            self.p2pool_data.log_event_now("RawLogProcessor Error", error_msg)


class EventProcessor:
    """
    Tails the event log file in a background thread, parsing and categorizing
    events into in-memory deques for fast API access.
    """
    def __init__(self, P2poolData, max_events_per_category=50):
        """
        Initializes the event processor.

        Args:
            p2pooldata_instance (P2poolData): The main data object.
            max_events_per_category (int): Max number of events to keep for each category.
        """
        self.p2pool_data = P2poolData
        self.max_events = max_events_per_category
        self.lock = threading.Lock()

        # Use deque with maxlen for efficient, automatically capped lists
        self.shares_found = deque(maxlen=self.max_events)
        self.jobs_sent = deque(maxlen=self.max_events)
        self.miner_data = deque(maxlen=self.max_events)
        self.blocks_found = deque(maxlen=self.max_events)
        self.other_events = deque(maxlen=self.max_events)
        self.sidechain_events = deque(maxlen=self.max_events)
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
        print(f"[*] EventProcessor thread started. Tailing: {event_log_path}")

        while not os.path.exists(event_log_path):
            print("[!] Event log does not exist yet, waiting...")
            time.sleep(2)

        try:
            with open(event_log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)  # Start at the end of the file
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)  # No new lines, wait a bit
                        continue
                    self._parse_and_categorize_line(line)
        except Exception as e:
            error_msg = f"EventProcessor thread terminated with error: {e}"
            print(f"[!] {error_msg}")
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

    def __init__(self):
        self.P2POOL_DIR = os.path.dirname(sys.executable)
        self.P2POOL_EXE = "p2pool.exe"
        self.WALLET = "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
        self.p2pool_proc = None
        self.EVENT_LOG = os.path.join(self.P2POOL_DIR, "event_log.txt")
        self.RAW_LOG = os.path.join(self.P2POOL_DIR, "p2pool_raw_output.txt")
        self.log_queue = asyncio.Queue()

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