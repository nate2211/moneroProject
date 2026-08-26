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
    def __init__(self, p2pooldata_instance, logger, stop_event, preferred_stratum_ip: str = "auto"):
        self.p2pool_data = p2pooldata_instance
        self.logger = logger
        self.stop_event = stop_event
        # "auto" is intentionally the default.  Older builds hard-coded
        # 192.168.0.10, which fails on ATT Internet Air IP-passthrough hosts and
        # on any LAN using a different subnet.  Auto binds the Stratum listener
        # to all local IPv4 addresses unless the operator requests a specific
        # local/public address.
        initial_bind = str(preferred_stratum_ip or "auto").strip()
        self.preferred_stratum_ip = initial_bind
        self.stratum_bind_mode = (
            "auto"
            if initial_bind.casefold() in {"", "auto", "all", "0.0.0.0", "*"}
            else "explicit"
        )
        self.stratum_port = 3333

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
        self._manual_stop_latched = False
        self._last_stop_reason = None
        self._restart_attempts = 0
        self._max_restart_backoff = 60

    def strip_ansi_codes(self, text: str) -> str:
        ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
        return ansi_escape.sub("", text)

    def _is_manual_stop_reason(self, reason: Optional[str]) -> bool:
        r = str(reason or "").strip().lower()
        return r in {"manual_stop", "gui_stop", "frontend_stop", "user_stop"} or r.startswith("manual_stop:")

    def manual_stop_latched(self) -> bool:
        return bool(self._manual_stop_latched)

    def clear_manual_stop_latch(self):
        if self._manual_stop_latched:
            self.logger.log_message("[P2PoolProcessor] Clearing manual-stop latch for explicit start request.")
        self._manual_stop_latched = False

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

    @staticmethod
    def _usable_ipv4(ip_address: str) -> bool:
        try:
            import ipaddress
            ip_obj = ipaddress.IPv4Address(str(ip_address).split("%", 1)[0])
            return not (
                ip_obj.is_unspecified
                or ip_obj.is_loopback
                or ip_obj.is_multicast
                or ip_obj.is_link_local
            )
        except Exception:
            return False

    def _local_ipv4_candidates(self):
        """Return active local IPv4 addresses with public addresses first.

        ATT Internet Air IP passthrough can place a public IPv4 directly on the
        Windows adapter.  That address is a valid local bind target; it must not
        be confused with the public address reported by an external web service.
        """
        candidates = []
        try:
            stats = psutil.net_if_stats()
            for iface, addrs in psutil.net_if_addrs().items():
                stat = stats.get(iface)
                if stat is not None and not stat.isup:
                    continue
                for addr in addrs:
                    if getattr(addr, "family", None) != socket.AF_INET:
                        continue
                    ip_text = str(getattr(addr, "address", "") or "").split("%", 1)[0]
                    if not self._usable_ipv4(ip_text):
                        continue
                    try:
                        import ipaddress
                        ip_obj = ipaddress.IPv4Address(ip_text)
                        rank = 0 if ip_obj.is_global else 1 if ip_obj.is_private else 2
                    except Exception:
                        rank = 3
                    candidates.append((rank, str(iface), ip_text))
        except Exception as exc:
            self.logger.log_message(f"[P2PoolProcessor] Could not enumerate local IPv4 addresses: {exc}")

        seen = set()
        ordered = []
        for _rank, iface, ip_text in sorted(candidates, key=lambda item: (item[0], item[1], item[2])):
            if ip_text in seen:
                continue
            seen.add(ip_text)
            ordered.append((iface, ip_text))
        return ordered

    def configure_stratum_bind(self, bind_mode: str = "auto", bind_ip: Optional[str] = None, port: int = 3333):
        mode = str(bind_mode or "auto").strip().casefold()
        if mode not in {"auto", "passthrough", "lan", "explicit", "all"}:
            raise ValueError("P2Pool Stratum bind mode must be auto, passthrough, lan, explicit, or all.")
        parsed_port = int(port)
        if not 1 <= parsed_port <= 65535:
            raise ValueError("P2Pool Stratum port must be between 1 and 65535.")
        explicit = str(bind_ip or "").strip()
        if mode == "explicit" and not self._usable_ipv4(explicit):
            raise ValueError("Explicit P2Pool Stratum bind IPv4 is invalid or unusable.")
        self.stratum_bind_mode = mode
        self.preferred_stratum_ip = explicit if mode == "explicit" else mode
        self.stratum_port = parsed_port

    def _select_stratum_bind_ip(self) -> str:
        mode = str(getattr(self, "stratum_bind_mode", "auto") or "auto").strip().casefold()
        requested = str(self.preferred_stratum_ip or "auto").strip()
        requested_cf = requested.casefold()

        if mode in {"auto", "all"} or requested_cf in {"", "auto", "all", "0.0.0.0", "*"}:
            # Binding all local addresses is the most reliable choice for a
            # computer that simultaneously owns an ATT passthrough/public IPv4
            # and one or more private LAN/Hyper-V addresses.
            return "0.0.0.0"

        candidates = self._local_ipv4_candidates()
        if mode == "explicit" or requested_cf not in {"passthrough", "public", "lan", "private"}:
            if self._usable_ipv4(requested) and self._is_ip_bindable(requested):
                return requested
            self.logger.log_message(
                f"[P2PoolProcessor] Requested bind address {requested!r} is not assigned locally; using all interfaces."
            )
            return "0.0.0.0"

        try:
            import ipaddress
            if mode == "passthrough" or requested_cf in {"passthrough", "public"}:
                for iface, ip_text in candidates:
                    if ipaddress.IPv4Address(ip_text).is_global and self._is_ip_bindable(ip_text):
                        self.logger.log_message(
                            f"[P2PoolProcessor] ATT passthrough bind selected {ip_text} on {iface}."
                        )
                        return ip_text
            if mode == "lan" or requested_cf in {"lan", "private"}:
                for iface, ip_text in candidates:
                    if ipaddress.IPv4Address(ip_text).is_private and self._is_ip_bindable(ip_text):
                        self.logger.log_message(
                            f"[P2PoolProcessor] LAN bind selected {ip_text} on {iface}."
                        )
                        return ip_text
        except Exception as exc:
            self.logger.log_message(f"[P2PoolProcessor] Automatic bind selection failed: {exc}")

        self.logger.log_message(
            "[P2PoolProcessor] No requested local address was bindable; using 0.0.0.0 so public-passthrough and LAN adapters remain reachable."
        )
        return "0.0.0.0"

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

        stratum_host = self._select_stratum_bind_ip()
        args = [
            exe_path,
            "--host", "127.0.0.1",
            "--wallet", self.p2pool_data.WALLET,
            "--mini",
            "--stratum", f"{stratum_host}:{int(self.stratum_port)}",
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
                self.logger.log_message(f"[!] Executable not found at: {os.path.join(self.p2pool_data.P2POOL_DIR, self.p2pool_data.P2POOL_EXE)}")
                return False

            stratum_host, args = build_result
            self.current_stratum_bind_ip = stratum_host
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            try:
                self.clear_manual_stop_latch()
                self._expected_stop = False
                self._last_stop_reason = None
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
                self.logger.log_message(f"[+] P2Pool process started successfully with PID: {proc.pid}")
                self.p2pool_data.log_event_now("P2Pool Process", "P2Pool process started successfully")

                try:
                    self.psutil_proc = psutil.Process(proc.pid)
                    self.psutil_proc.cpu_percent(interval=None)
                except psutil.NoSuchProcess:
                    self.logger.log_message(f"[!] Failed to attach psutil to PID {proc.pid}.")
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

            if self._expected_stop or self.stop_event.is_set() or self._manual_stop_latched:
                self.logger.log_message(
                    f"[+] P2Pool process exited without auto-restart (code {return_code}, "
                    f"expected_stop={self._expected_stop}, manual_stop_latched={self._manual_stop_latched})."
                )
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

        try:
            while not stop_event.is_set():
                with p.oneshot():
                    cpu = p.cpu_percent(interval=None)
                    memoryinfo = p.memory_info()

                self.cpu_usage = round(cpu, 2)
                self.ram_usage_mb = round(getattr(memoryinfo, "rss", 0) / (1024 * 1024), 2)
                self.vms_usage_mb = round(getattr(memoryinfo, "vms", 0) / (1024 * 1024), 2)
                self.num_page_faults = int(getattr(memoryinfo, "num_page_faults", 0))
                self.paged_pool_mb = round(getattr(memoryinfo, "paged_pool", 0) / (1024 * 1024), 2)
                self.page_file_mb = round(getattr(memoryinfo, "pagefile", 0) / (1024 * 1024), 2)
                await asyncio.sleep(5)
        except psutil.NoSuchProcess:
            self.logger.log_message("[!] Stats monitor: P2Pool process not found.")
        except asyncio.CancelledError:
            pass
        finally:
            self.cpu_usage = 0.0
            self.ram_usage_mb = 0.0
            self.vms_usage_mb = 0.0
            self.num_page_faults = 0
            self.paged_pool_mb = 0.0
            self.page_file_mb = 0.0

    async def stop_p2pool(self, reason: str = "manual_stop"):
        async with self.proc_lock:
            proc = self.p2pool_data.p2pool_proc
            manual_stop = self._is_manual_stop_reason(reason)
            self._last_stop_reason = reason
            if manual_stop:
                self._manual_stop_latched = True

            if not proc or proc.returncode is not None:
                self.logger.log_message("[!] P2Pool is not running.")
                return

            self.logger.log_message(
                f"[P2PoolProcessor] Stopping P2Pool (reason={reason}, manual_stop={manual_stop})."
            )
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
                self.p2pool_data.log_event_now("P2Pool Process", f"P2Pool process ended successfully ({reason})")
                self.logger.log_message(
                    f"[P2PoolProcessor] P2Pool stopped cleanly (reason={reason}, manual_stop_latched={self._manual_stop_latched})."
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
            finally:
                self.psutil_proc = None
                self.p2pool_data.p2pool_proc = None
                self.redirect_task = None
                self.monitor_task = None
                self.watch_task = None

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

                    line = self.strip_ansi_codes(line_bytes.decode("utf-8", errors="ignore").rstrip("\r\n"))
                    log_file.write(line + "\n")
                    log_file.flush()
                    self.logger.log_message(f"[P2Pool] {line}")
        except asyncio.CancelledError:
            pass
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


class RawLogProcessor:
    EVENT_PATTERNS = (
        ("P2Pool Share Candidate", re.compile(r"p2pool share candidate", re.IGNORECASE)),
        ("P2Pool Credited Share", re.compile(r"p2pool block template credited share|p2pool sidechain share credited", re.IGNORECASE)),
        ("P2Pool Share Not Credited", re.compile(r"p2pool block template share not credited|p2pool sidechain share not credited", re.IGNORECASE)),
        ("P2Pool Payout Context", re.compile(r"p2pool payout context", re.IGNORECASE)),
        ("P2Pool Peer Events", re.compile(r"p2pool peer status|p2pool peer connectivity lost|p2pool peer connectivity restored|p2pool peer gate login reject|temporarily disconnected from p2pool peers", re.IGNORECASE)),
        ("P2Pool Peer Blocks", re.compile(r"p2pool peer block accepted|p2pool peer block rejected|p2pool peer block needs parents|p2pool block relay", re.IGNORECASE)),
        ("Stratum Work", re.compile(r"stratum work start|stratum job dispatch", re.IGNORECASE)),
        ("Stratum Shares", re.compile(r"share received|share classified|p2pool share verify start|p2pool share verify ok|stratum share accepted|stratum result sent|invalid share", re.IGNORECASE)),
        ("Mainchain Block Found", re.compile(r"mainchain block found|monero block found|\bfound a mainchain block\b|\bblock found\b", re.IGNORECASE)),
        ("Sidechain Block Added", re.compile(r"sidechain add_block|p2pool sidechain block accepted|side chain add_block", re.IGNORECASE)),
        ("Sent Jobs", re.compile(r"sent new job", re.IGNORECASE)),
        ("P2Pool Process", re.compile(r"p2pool caught sigint|p2pool stopping|p2pool stopped|p2pool process", re.IGNORECASE)),
    )

    def __init__(self, p2pooldata_instance, logger, stop_event):
        self.p2pool_data = p2pooldata_instance
        self.logger = logger
        self.stop_event = stop_event

    def _classify_line(self, clean_line: str) -> Optional[str]:
        lower_line = clean_line.lower()
        if "p2pool new miner data" in lower_line:
            return "New Miner Data"

        for event_type, pattern in self.EVENT_PATTERNS:
            if pattern.search(clean_line):
                return event_type

        if "share found" in lower_line:
            return "Found Share"
        if "block found" in lower_line:
            return "Found Block"
        return None

    def run_in_background(self):
        raw_log_path = self.p2pool_data.RAW_LOG
        while not self.stop_event.is_set() and not os.path.exists(raw_log_path):
            time.sleep(1)

        if self.stop_event.is_set():
            return

        try:
            with open(raw_log_path, "r", encoding="utf-8") as f:
                f.seek(0)

                miner_data_block = []
                in_miner_data = False

                while not self.stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    clean_line = line.rstrip("\r\n")
                    stripped = clean_line.strip()

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

                    event_type = self._classify_line(clean_line)
                    if event_type == "New Miner Data":
                        in_miner_data = True
                        miner_data_block = [clean_line]
                        continue

                    if event_type:
                        self.p2pool_data.log_event_now(event_type, clean_line)

        except Exception as e:
            error_msg = f"RawLogProcessor thread terminated with error: {e}"
            self.logger.log_message(f"[!] {error_msg}")
            self.p2pool_data.log_event_now("RawLogProcessor Error", error_msg)


class EventProcessor:
    EVENT_RE = re.compile(r"\[(.*?)\] \[(.*?)\] (.*)", re.DOTALL)

    def __init__(self, p2pool_data, logger, stop_event, max_events_per_category=50):
        self.p2pool_data = p2pool_data
        self.max_events = max_events_per_category
        self.lock = threading.Lock()
        self.logger = logger
        self.stop_event = stop_event

        self.share_candidates = deque(maxlen=self.max_events)
        self.credited_shares = deque(maxlen=self.max_events)
        self.not_credited_shares = deque(maxlen=self.max_events)
        self.payout_context = deque(maxlen=self.max_events)
        self.peer_events = deque(maxlen=self.max_events)
        self.peer_blocks = deque(maxlen=self.max_events)
        self.stratum_work = deque(maxlen=self.max_events)
        self.stratum_shares = deque(maxlen=self.max_events)
        self.mainchain_blocks = deque(maxlen=self.max_events)
        self.sidechain_blocks = deque(maxlen=self.max_events)
        self.jobs_sent = deque(maxlen=self.max_events)
        self.miner_data = deque(maxlen=self.max_events)
        self.process_events = deque(maxlen=self.max_events)
        self.other_events = deque(maxlen=self.max_events)

        self.total_share_candidates = 0
        self.total_credited_shares = 0
        self.total_not_credited_shares = 0
        self.total_payout_context = 0
        self.total_peer_events = 0
        self.total_peer_blocks = 0
        self.total_stratum_work = 0
        self.total_stratum_shares = 0
        self.total_mainchain_blocks = 0
        self.total_sidechain_blocks = 0

    def _push(self, deq: deque, event: dict):
        deq.appendleft(event)

    def _parse_and_categorize_line(self, line: str):
        match = self.EVENT_RE.match(line.strip())
        if not match:
            return

        event = {"time": match.group(1), "type": match.group(2), "message": match.group(3).strip()}
        event_type = event["type"]

        with self.lock:
            if event_type == "P2Pool Share Candidate":
                self.total_share_candidates += 1
                self._push(self.share_candidates, event)
            elif event_type == "P2Pool Credited Share":
                self.total_credited_shares += 1
                self._push(self.credited_shares, event)
            elif event_type == "P2Pool Share Not Credited":
                self.total_not_credited_shares += 1
                self._push(self.not_credited_shares, event)
            elif event_type == "P2Pool Payout Context":
                self.total_payout_context += 1
                self._push(self.payout_context, event)
            elif event_type == "P2Pool Peer Events":
                self.total_peer_events += 1
                self._push(self.peer_events, event)
            elif event_type == "P2Pool Peer Blocks":
                self.total_peer_blocks += 1
                self._push(self.peer_blocks, event)
            elif event_type == "Stratum Work":
                self.total_stratum_work += 1
                self._push(self.stratum_work, event)
            elif event_type == "Stratum Shares":
                self.total_stratum_shares += 1
                self._push(self.stratum_shares, event)
            elif event_type == "Mainchain Block Found":
                self.total_mainchain_blocks += 1
                self._push(self.mainchain_blocks, event)
            elif event_type == "Sidechain Block Added":
                self.total_sidechain_blocks += 1
                self._push(self.sidechain_blocks, event)
            elif event_type == "Sent Jobs":
                self._push(self.jobs_sent, event)
            elif event_type == "New Miner Data":
                self._push(self.miner_data, event)
            elif event_type in {"P2Pool Process", "RawLogProcessor Error", "EventProcessor Error"}:
                self._push(self.process_events, event)
            elif event_type == "Found Share":
                self.total_share_candidates += 1
                self._push(self.share_candidates, event)
            elif event_type == "Found Block":
                self.total_mainchain_blocks += 1
                self._push(self.mainchain_blocks, event)
            else:
                self._push(self.other_events, event)

    def _hydrate_from_existing_file(self, event_log_path: str, bootstrap_lines: int = 5000):
        try:
            with open(event_log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-bootstrap_lines:]
            for line in lines:
                self._parse_and_categorize_line(line)
        except FileNotFoundError:
            return
        except Exception as e:
            self.logger.log_message(f"[!] Failed to hydrate event cache: {e}")

    def run_in_background(self):
        event_log_path = self.p2pool_data.EVENT_LOG
        while not self.stop_event.is_set() and not os.path.exists(event_log_path):
            time.sleep(1)

        if self.stop_event.is_set():
            return

        self._hydrate_from_existing_file(event_log_path)

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
                "share_candidates": list(self.share_candidates)[:limit],
                "credited_shares": list(self.credited_shares)[:limit],
                "not_credited_shares": list(self.not_credited_shares)[:limit],
                "payout_context": list(self.payout_context)[:limit],
                "peer_events": list(self.peer_events)[:limit],
                "peer_blocks": list(self.peer_blocks)[:limit],
                "stratum_work": list(self.stratum_work)[:limit],
                "stratum_shares": list(self.stratum_shares)[:limit],
                "mainchain_blocks": list(self.mainchain_blocks)[:limit],
                "sidechain_blocks": list(self.sidechain_blocks)[:limit],
                "jobs_sent": list(self.jobs_sent)[:limit],
                "miner_data": list(self.miner_data)[:limit],
                "process_events": list(self.process_events)[:limit],
                "other_events": list(self.other_events)[:limit],
                "shares_found": list(self.share_candidates)[:limit],
                "blocks_found": list(self.mainchain_blocks)[:limit],
                "sidechain_events": list(self.sidechain_blocks)[:limit],
            }

    def get_summary(self):
        with self.lock:
            return {
                "share_candidates": self.total_share_candidates,
                "credited_shares": self.total_credited_shares,
                "not_credited_shares": self.total_not_credited_shares,
                "payout_context": self.total_payout_context,
                "peer_events": self.total_peer_events,
                "peer_blocks": self.total_peer_blocks,
                "stratum_work": self.total_stratum_work,
                "stratum_shares": self.total_stratum_shares,
                "mainchain_blocks": self.total_mainchain_blocks,
                "sidechain_blocks": self.total_sidechain_blocks,
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
        if seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        if seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
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
