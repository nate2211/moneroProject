from __future__ import annotations

import asyncio
import contextlib
import datetime
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from typing import Optional

import psutil


class AsyncEventLogger:
    """
    Writes structured event lines from a thread-safe queue to disk on the main asyncio loop.
    """

    def __init__(self, p2pool_data, asyncio_main_loop, logger, stop_event: Optional[threading.Event] = None):
        self.p2pool_data = p2pool_data
        self.asyncio_main_loop = asyncio_main_loop
        self.logger = logger
        self.stop_event = stop_event or threading.Event()
        self._future = None

    async def writer_loop(self):
        os.makedirs(os.path.dirname(self.p2pool_data.EVENT_LOG), exist_ok=True)

        try:
            with open(self.p2pool_data.EVENT_LOG, "a", encoding="utf-8") as f:
                while not self.stop_event.is_set() or not self.p2pool_data.log_queue.empty():
                    try:
                        line = await asyncio.to_thread(self.p2pool_data.log_queue.get, True, 0.5)
                    except queue.Empty:
                        continue

                    f.write(line + "\n")
                    f.flush()

        except asyncio.CancelledError:
            self.logger.log_message("[AsyncEventLogger] Logging task cancelled.")
        except Exception as e:
            self.logger.log_message(f"[AsyncEventLogger] Failed to write log: {e}")

    def start(self):
        self._future = asyncio.run_coroutine_threadsafe(self.writer_loop(), self.asyncio_main_loop)

    def stop(self):
        if self._future and not self._future.done():
            self._future.cancel()


class P2PoolProcessor:
    """
    Manages the P2Pool subprocess and its monitoring tasks.
    """

    def __init__(self, p2pooldata_instance, logger, stop_event, preferred_stratum_ip: str = "192.168.0.10"):
        self.p2pool_data = p2pooldata_instance
        self.logger = logger
        self.stop_event = stop_event
        self.preferred_stratum_ip = preferred_stratum_ip

        self.cpu_usage = 0.0
        self.ram_usage_mb = 0.0
        self.vms_usage_mb = 0.0
        self.num_page_faults = 0
        self.paged_pool_mb = 0.0
        self.page_file_mb = 0.0

        self.psutil_proc = None
        self.redirect_task = None
        self.monitor_task = None
        self.watch_task = None

        self.current_stratum_bind_ip = None
        self.proc_lock = asyncio.Lock()

        self._expected_stop = False
        self._restart_attempts = 0
        self._max_restart_backoff = 60

        self.last_start_ts = None
        self.last_stop_ts = None
        self.last_output_ts = None
        self.restart_count = 0

    def strip_ansi_codes(self, text: str) -> str:
        ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
        return ansi_escape.sub("", text)

    def _is_ip_bindable(self, ip_address: str) -> bool:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            temp_socket.bind((ip_address, 0))
            self.logger.log_message(f"[+] IP Check: Address {ip_address} is bindable on this machine.")
            return True
        except OSError:
            self.logger.log_message(f"[!] IP Check: Address {ip_address} is NOT bindable. Will use fallback.")
            return False
        finally:
            temp_socket.close()

    async def _cancel_task(self, task, label: str):
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            self.logger.log_message(f"[+] Cancelled task: {label}")

    def _build_args(self):
        exe_path = os.path.join(self.p2pool_data.P2POOL_DIR, self.p2pool_data.P2POOL_EXE)
        if not os.path.exists(exe_path):
            return None, None

        if self.preferred_stratum_ip and self._is_ip_bindable(self.preferred_stratum_ip):
            stratum_host = self.preferred_stratum_ip
        else:
            stratum_host = "0.0.0.0"

        args = [
            exe_path,
            "--host", "127.0.0.1",
            "--wallet", self.p2pool_data.WALLET,
            "--mini",
            "--stratum", f"{stratum_host}:3333",
            "--no-upnp",
            "--no-color",
            "--p2p", "0.0.0.0:37888",
        ]
        return exe_path, (stratum_host, args)

    async def start_p2pool(self) -> bool:
        async with self.proc_lock:
            proc = self.p2pool_data.p2pool_proc
            if proc and proc.returncode is None:
                self.logger.log_message("[!] P2Pool is already running.")
                return True

            exe_path, build_result = self._build_args()
            if not exe_path or not build_result:
                self.logger.log_message(
                    f"[!] Executable not found at: {os.path.join(self.p2pool_data.P2POOL_DIR, self.p2pool_data.P2POOL_EXE)}"
                )
                return False

            stratum_host, args = build_result
            self.current_stratum_bind_ip = stratum_host
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            try:
                self._expected_stop = False
                os.makedirs(self.p2pool_data.P2POOL_DIR, exist_ok=True)

                proc = await asyncio.create_subprocess_exec(
                    *args,
                    cwd=self.p2pool_data.P2POOL_DIR,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    creationflags=creationflags,
                )

                self.p2pool_data.p2pool_proc = proc
                self.last_start_ts = time.time()
                self.restart_count += 1

                self.logger.log_message(f"[+] P2Pool process started successfully with PID: {proc.pid}")
                self.p2pool_data.log_event_now("P2Pool Process", "P2Pool process started successfully")

                try:
                    self.psutil_proc = psutil.Process(proc.pid)
                    try:
                        self.psutil_proc.nice(psutil.ABOVE_NORMAL_PRIORITY_CLASS)
                    except Exception:
                        pass
                    self.psutil_proc.cpu_percent(interval=None)
                except psutil.NoSuchProcess:
                    self.logger.log_message(f"[!] Failed to attach psutil to PID {proc.pid}. Stats will not be monitored.")
                    self.psutil_proc = None

                self.redirect_task = asyncio.create_task(self._redirect_output(self.stop_event))
                if self.psutil_proc:
                    self.monitor_task = asyncio.create_task(self._monitor_stats(self.stop_event))
                self.watch_task = asyncio.create_task(self._watch_process(proc))

                self._restart_attempts = 0
                return True

            except Exception as e:
                self.logger.log_message(f"[!] Failed to launch P2Pool: {e}")
                self.p2pool_data.p2pool_proc = None
                self.psutil_proc = None
                self.redirect_task = None
                self.monitor_task = None
                self.watch_task = None
                return False

    async def _watch_process(self, proc):
        try:
            return_code = await proc.wait()

            async with self.proc_lock:
                if self.p2pool_data.p2pool_proc is proc:
                    self.p2pool_data.p2pool_proc = None
                self.psutil_proc = None

            if self._expected_stop or self.stop_event.is_set():
                self.logger.log_message(f"[+] P2Pool process exited normally with code {return_code}.")
                return

            self.logger.log_message(f"[!] P2Pool exited unexpectedly with code {return_code}.")
            self.p2pool_data.log_event_now("P2Pool Process", f"Exited unexpectedly with code {return_code}")

            self._restart_attempts += 1
            delay = min(self._max_restart_backoff, 2 ** min(self._restart_attempts, 6))
            self.logger.log_message(f"[!] Restarting P2Pool after crash in {delay} seconds...")

            await asyncio.sleep(delay)

            if not self.stop_event.is_set():
                await self.start_p2pool()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.log_message(f"[!] Watchdog failed: {e}")

    async def _monitor_stats(self, stop_event: threading.Event):
        p = self.psutil_proc
        if not p:
            return

        self.logger.log_message("[+] Stats monitor started.")
        try:
            while not stop_event.is_set():
                with p.oneshot():
                    cpu = p.cpu_percent(interval=None)
                    memoryinfo = p.memory_info()

                    ram_mb = getattr(memoryinfo, "rss", 0) / (1024 * 1024)
                    vms_usage_mb = getattr(memoryinfo, "vms", 0) / (1024 * 1024)
                    num_page_faults = getattr(memoryinfo, "num_page_faults", 0)
                    paged_pool_mb = getattr(memoryinfo, "paged_pool", 0) / (1024 * 1024)
                    page_file_mb = getattr(memoryinfo, "pagefile", 0) / (1024 * 1024)

                self.cpu_usage = round(cpu, 2)
                self.ram_usage_mb = round(ram_mb, 2)
                self.vms_usage_mb = round(vms_usage_mb, 2)
                self.num_page_faults = int(num_page_faults)
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
            self.paged_pool_mb = 0.0
            self.page_file_mb = 0.0

    async def stop_p2pool(self, reason: str = "manual_stop"):
        async with self.proc_lock:
            proc = self.p2pool_data.p2pool_proc
            if not proc or proc.returncode is not None:
                self.logger.log_message("[!] P2Pool is not running.")
                return

            self.logger.log_message(f"[!] Attempting to terminate P2Pool process... Reason: {reason}")
            self._expected_stop = True

            try:
                await self._cancel_task(self.watch_task, "watch_task")
                self.watch_task = None

                await self._cancel_task(self.redirect_task, "redirect_task")
                self.redirect_task = None

                await self._cancel_task(self.monitor_task, "monitor_task")
                self.monitor_task = None

                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5.0)

                self.p2pool_data.log_event_now("P2Pool Process", "P2Pool process ended successfully")
                self.logger.log_message("[+] P2Pool process terminated gracefully.")

            except asyncio.TimeoutError:
                self.logger.log_message("[!] P2Pool did not terminate gracefully, forcing kill.")
                proc.kill()
                await proc.wait()

            except Exception as e:
                self.logger.log_message(f"[!] Error stopping P2Pool: {e}")

            finally:
                self.last_stop_ts = time.time()
                self.psutil_proc = None
                self.p2pool_data.p2pool_proc = None
                self.redirect_task = None
                self.monitor_task = None
                self.watch_task = None
                self.cpu_usage = 0.0
                self.ram_usage_mb = 0.0
                self.vms_usage_mb = 0.0
                self.num_page_faults = 0
                self.paged_pool_mb = 0.0
                self.page_file_mb = 0.0

    async def _redirect_output(self, stop_event: threading.Event):
        proc = self.p2pool_data.p2pool_proc
        if not proc or not proc.stdout:
            return

        os.makedirs(os.path.dirname(self.p2pool_data.RAW_LOG), exist_ok=True)

        try:
            with open(self.p2pool_data.RAW_LOG, "a", encoding="utf-8") as log_file:
                while not stop_event.is_set():
                    try:
                        line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                    except asyncio.TimeoutError:
                        if proc.returncode is not None:
                            break
                        continue

                    if not line_bytes:
                        if proc.returncode is not None:
                            break
                        await asyncio.sleep(0.1)
                        continue

                    line = line_bytes.decode("utf-8", errors="ignore").strip()
                    clean_line = self.strip_ansi_codes(line)
                    self.last_output_ts = time.time()

                    log_file.write(clean_line + "\n")
                    log_file.flush()

                    self.logger.log_message(f"[P2Pool] {clean_line}")

        except asyncio.CancelledError:
            self.logger.log_message("[P2Pool] Output redirection task was cancelled.")
        except Exception as e:
            self.p2pool_data.log_event_now("P2Pool Process", f"Redirect output error: {e}")
        finally:
            self.p2pool_data.log_event_now("P2Pool Process", "P2Pool stdout stream ended.")

    async def write_to_stdin(self, command: str) -> bool:
        async with self.proc_lock:
            proc = self.p2pool_data.p2pool_proc
            if proc and proc.stdin and not proc.stdin.is_closing():
                try:
                    proc.stdin.write(f"{command}\n".encode("utf-8"))
                    await proc.stdin.drain()
                    return True
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    self.p2pool_data.log_event_now("P2Pool Process", f"Error writing to stdin: {e}")
                    return False
        return False


class RawLogProcessor:
    def __init__(self, p2pooldata_instance, logger, stop_event):
        self.p2pool_data = p2pooldata_instance
        self.logger = logger
        self.stop_event = stop_event

    def run_in_background(self):
        raw_log_path = self.p2pool_data.RAW_LOG
        self.logger.log_message(f"[*] RawLogProcessor thread started. Tailing: {raw_log_path}")

        while not self.stop_event.is_set() and not os.path.exists(raw_log_path):
            self.logger.log_message("[!] Raw log file does not exist yet, waiting...")
            time.sleep(1)

        if self.stop_event.is_set():
            return

        try:
            with open(raw_log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)

                miner_data_block = []
                in_miner_data = False

                while not self.stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    clean_line = line.rstrip("\r\n")
                    stripped = clean_line.strip()
                    lower_line = stripped.lower()

                    if in_miner_data:
                        if not stripped or stripped.startswith("-"):
                            full_block = "\n".join(miner_data_block).strip()
                            if full_block:
                                self.p2pool_data.log_event_now("New Miner Data", full_block)
                            miner_data_block = []
                            in_miner_data = False
                            continue

                        miner_data_block.append(clean_line)
                        continue

                    if not stripped:
                        continue

                    if "p2pool new miner data" in lower_line:
                        in_miner_data = True
                        miner_data_block = [clean_line]
                    elif "sent new job" in lower_line:
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
    def __init__(self, p2pool_data, logger, stop_event, max_events_per_category=50):
        self.p2pool_data = p2pool_data
        self.max_events = max_events_per_category
        self.lock = threading.Lock()
        self.logger = logger

        self.shares_found = deque(maxlen=self.max_events)
        self.jobs_sent = deque(maxlen=self.max_events)
        self.miner_data = deque(maxlen=self.max_events)
        self.blocks_found = deque(maxlen=self.max_events)
        self.other_events = deque(maxlen=self.max_events)
        self.sidechain_events = deque(maxlen=self.max_events)

        self.stop_event = stop_event

    def _parse_and_categorize_line(self, line):
        match = re.match(r"\[(.*?)\] \[(.*?)\] (.*)", line, re.DOTALL)
        if not match:
            return

        event = {
            "time": match.group(1),
            "type": match.group(2),
            "message": match.group(3).strip(),
        }

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
        event_log_path = self.p2pool_data.EVENT_LOG
        self.logger.log_message(f"[*] EventProcessor thread started. Tailing: {event_log_path}")

        while not self.stop_event.is_set() and not os.path.exists(event_log_path):
            self.logger.log_message("[!] Event log does not exist yet, waiting...")
            time.sleep(1)

        if self.stop_event.is_set():
            return

        try:
            with open(event_log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)

                while not self.stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    self._parse_and_categorize_line(line)

        except Exception as e:
            error_msg = f"EventProcessor thread terminated with error: {e}"
            self.logger.log_message(f"[!] {error_msg}")
            self.p2pool_data.log_event_now("EventProcessor Error", error_msg)

    def get_all_events(self, limit=10):
        with self.lock:
            return {
                "shares_found": list(self.shares_found)[:limit],
                "jobs_sent": list(self.jobs_sent)[:limit],
                "miner_data": list(self.miner_data)[:limit],
                "blocks_found": list(self.blocks_found)[:limit],
                "sidechain_events": list(self.sidechain_events)[:limit],
                "other_events": list(self.other_events)[:limit],
            }


class P2poolData:
    def __init__(self, logger):
        if getattr(sys, "frozen", False):
            self.P2POOL_DIR = os.path.join(sys._MEIPASS, "tools")
        else:
            self.P2POOL_DIR = os.path.join(os.path.dirname(__file__), "tools")

        self.P2POOL_EXE = "p2pool.exe"
        self.WALLET = "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
        self.p2pool_proc = None

        self.EVENT_LOG = os.path.join(self.P2POOL_DIR, "event_log.txt")
        self.RAW_LOG = os.path.join(self.P2POOL_DIR, "p2pool_raw_output.txt")

        self.log_queue = queue.Queue(maxsize=50000)
        self.logger = logger

    def time_ago(self, timestamp):
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
        line = f"[{timestamp}] [{event_type}] {message}"

        try:
            self.log_queue.put_nowait(line)
        except queue.Full:
            try:
                self.logger.log_message("[!] Event log queue is full; dropping log line.")
            except Exception:
                pass