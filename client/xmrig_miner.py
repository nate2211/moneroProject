import asyncio
import json
import os
import subprocess
import traceback
import aiohttp
import anyio
import psutil
import re
import time

from contextlib import suppress
from xmrig_managers import AsyncPsutilManager

REPORT_INTERVAL_SECONDS = 5
SERVER_POLL_INTERVAL_SECONDS = 5
SERVER_POST_TIMEOUT_SECONDS = 10
SUPERVISOR_QUIET_TIMEOUT_SECONDS = 90
SUPERVISOR_POLL_SECONDS = 5
POOL_RESTART_ERROR_STREAK = 8
POOL_RESTART_STALL_SECONDS = 120
POOL_BOOTSTRAP_RESTART_SECONDS = 180

_FATAL_OUTPUT_PATTERNS = (
    "compute error",
    "cuda error",
    "opencl error",
    "fatal error",
    "access violation",
    "segmentation fault",
    "illegal memory access",
)

_TRANSIENT_POOL_ERROR_PATTERNS = (
    "connect error",
    "connection refused",
    "connection reset",
    "connection closed",
    "job timeout",
    "retry after",
    "retry in",
    "reconnect",
    "read error",
    "write error",
    "socket error",
    "timed out",
    "dns error",
    "network error",
    "pool login failed",
    "invalid connection",
    "no active pools",
)

_POOL_ACTIVITY_PATTERNS = (
    "new job from",
    "accepted",
    "use pool",
    "connected to",
    "new diff",
    "login succeeded",
)


class MinerRestartRequested(Exception):
    pass


class PeriodicReporter:
    """
    Periodically reports miner statistics to the remote server.

    Important:
    - Reporter failures should not immediately kill mining.
    - Reporter problems must never require the user to restart the GUI.
    """

    def __init__(self, xmrig_miner, xmrig_data, logger):
        self.xmrig_data = xmrig_data
        self.logger = logger
        self.xmrig_miner = xmrig_miner

    async def run(self, update_signal, session: aiohttp.ClientSession):
        consecutive_internal_failures = 0

        while True:
            try:
                await asyncio.sleep(REPORT_INTERVAL_SECONDS)

                current_cpu_temp = await self.xmrig_data.get_cpu_temperature_async()
                current_power_draw = await self.xmrig_data.get_power_draw_async()
                current_threads = await self.xmrig_miner.get_current_threads_from_config_async()

                if self.xmrig_miner.is_running():
                    payload = {
                        "client_id": self.xmrig_data.client_id,
                        "hashrate": self.xmrig_data._latest_hashrate,
                        "threads": current_threads,
                        "cpu_temp": current_cpu_temp,
                        "gpu_temp": self.xmrig_data._latest_gpu_temp,
                        "gpu_fan": self.xmrig_data._latest_gpu_fan,
                        "cpu_accepted_shares": self.xmrig_data._latest_cpu_accepted_shares,
                        "nvidia_accepted_shares": self.xmrig_data._latest_nvidia_accepted_shares,
                        "power_draw": current_power_draw,
                    }
                else:
                    payload = {
                        "client_id": self.xmrig_data.client_id,
                        "hashrate": 0,
                        "threads": 0,
                        "cpu_temp": current_cpu_temp,
                        "gpu_temp": self.xmrig_data._latest_gpu_temp,
                        "gpu_fan": self.xmrig_data._latest_gpu_fan,
                        "cpu_accepted_shares": 0,
                        "nvidia_accepted_shares": 0,
                        "power_draw": current_power_draw,
                    }

                update_signal.emit(payload)

                await session.post(
                    f"{self.xmrig_data.FLASK_SERVER_URL}/hashrate",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=SERVER_POST_TIMEOUT_SECONDS),
                )

                self.xmrig_data.last_server_ok_at = time.monotonic()
                self.xmrig_data.last_server_error = ""
                consecutive_internal_failures = 0

            except asyncio.CancelledError:
                raise

            except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError) as e:
                self.xmrig_data.last_server_error_at = time.monotonic()
                self.xmrig_data.last_server_error = str(e)
                self.logger.log_message(f"[!] Network error in PeriodicReporter: {e}")

            except Exception:
                consecutive_internal_failures += 1
                self.logger.log_message("[!] CRITICAL ERROR IN PERIODIC REPORTER:")
                self.logger.log_message(traceback.format_exc())

                if consecutive_internal_failures >= 3:
                    consecutive_internal_failures = 0
                    await self.xmrig_miner.request_restart("PeriodicReporter repeated failures")


class ServerPoller:
    def __init__(self, xmrig_miner, xmrig_data, logger):
        self.xmrig_data = xmrig_data
        self.xmrig_miner = xmrig_miner
        self.logger = logger

    async def post_gui_settings(self, session: aiohttp.ClientSession):
        try:
            payload = {"pl1_pl2": self.xmrig_miner.pl1_pl2}
            await session.post(
                f"{self.xmrig_data.FLASK_SERVER_URL}/miners_gui_settings/{self.xmrig_data.client_id}",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=SERVER_POST_TIMEOUT_SECONDS),
            )
            self.xmrig_data.last_server_ok_at = time.monotonic()
            self.xmrig_data.last_server_error = ""
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError) as e:
            self.xmrig_data.last_server_error_at = time.monotonic()
            self.xmrig_data.last_server_error = str(e)
            self.logger.log_message(f"[!] Exception in post_gui_settings: {e}")
        except Exception as e:
            self.logger.log_message(f"[!] Exception in post_gui_settings: {e}")

    async def run(self, force_update_signal, session: aiohttp.ClientSession):
        while True:
            try:
                self.xmrig_data.client_status = "Started" if self.xmrig_miner.is_running() else "Stopped"

                await session.post(
                    f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}",
                    json={"status": self.xmrig_data.client_status},
                    timeout=aiohttp.ClientTimeout(total=SERVER_POST_TIMEOUT_SECONDS),
                )

                async with session.get(
                    f"{self.xmrig_data.FLASK_SERVER_URL}/get_command/{self.xmrig_data.client_id}",
                    timeout=aiohttp.ClientTimeout(total=SERVER_POST_TIMEOUT_SECONDS),
                ) as response:
                    response.raise_for_status()
                    command = await response.json()

                self.xmrig_data.last_server_ok_at = time.monotonic()
                self.xmrig_data.last_server_error = ""

                if command:
                    cmd = command.get("command")
                    self.logger.log_message(f"\n[+] Received command from server: '{cmd}'")

                    if cmd == "start":
                        pool = command.get("pool", self.xmrig_data.custom_pool_url)
                        threads = int(command.get("threads", self.xmrig_data.threads))
                        await self.xmrig_miner.start_miner(pool, threads)

                    elif cmd == "stop":
                        await self.xmrig_miner.stop_miner()

                    elif cmd == "set_threads":
                        new_threads = int(command["threads"])
                        ok = await self.xmrig_miner.update_config_threads_async(new_threads)
                        if ok:
                            self.xmrig_data.threads = new_threads
                            if self.xmrig_miner.is_running():
                                await self.xmrig_miner.request_restart("threads changed by server")

                    elif cmd == "set_pl1_pl2":
                        new_pl1_pl2 = int(command["pl1_pl2"])
                        self.xmrig_miner.pl1_pl2 = new_pl1_pl2

                        if self.xmrig_miner.is_running() and self.xmrig_miner.psutil_xmrig is not None:
                            try:
                                if self.xmrig_data.brand == "intel":
                                    if await self.xmrig_data.msr_manager.set_pl1_pl2(new_pl1_pl2):
                                        self.logger.log_message(
                                            f"[+] Set XMRig process (PID: {self.xmrig_miner.psutil_xmrig.pid}) "
                                            f"to PL1/PL2={new_pl1_pl2} for INTEL."
                                        )
                                else:
                                    if await self.xmrig_data.ryzen_manager.set_ppt_limit(new_pl1_pl2):
                                        self.logger.log_message(
                                            f"[+] Set XMRig process (PID: {self.xmrig_miner.psutil_xmrig.pid}) "
                                            f"to PPT={new_pl1_pl2} for AMD."
                                        )
                            except Exception as e:
                                self.logger.log_message(f"[!] Failed applying PL1/PL2 immediately: {e}")

                        await self.post_gui_settings(session)

                    elif cmd == "update":
                        update_url = command.get("url")
                        if update_url:
                            force_update_signal.emit(update_url)

            except asyncio.CancelledError:
                raise

            except json.JSONDecodeError:
                self.logger.log_message("[!] ServerPoller Error: Received invalid JSON from server.")

            except (KeyError, ValueError) as e:
                self.logger.log_message(
                    f"[!] ServerPoller Error: Received malformed command from server. Details: {e}"
                )

            except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError) as e:
                self.xmrig_data.last_server_error_at = time.monotonic()
                self.xmrig_data.last_server_error = str(e)
                self.logger.log_message(
                    f"[!] ServerPoller Network Error: Cannot connect to server. Details: {e}"
                )

            except Exception:
                self.logger.log_message("[!] An unexpected critical error occurred in ServerPoller:")
                self.logger.log_message(traceback.format_exc())

            await asyncio.sleep(SERVER_POLL_INTERVAL_SECONDS)


class OutputMonitor:
    """
    Parses miner output only.

    Important:
    - Transient pool/network errors must not force the user to restart the app.
    - Hard compute/runtime failures should still request a restart.
    """

    def __init__(self, xmrig_miner, xmrig_data, logger):
        self.xmrig_data = xmrig_data
        self.logger = logger
        self.xmrig_miner = xmrig_miner
        self.reset_runtime_state()

    def reset_runtime_state(self):
        now = time.monotonic()
        self.process_started_at = now
        self.last_output_at = now
        self.last_pool_activity_at = 0.0
        self.last_share_at = 0.0
        self.last_pool_error_at = 0.0
        self.last_restart_request_at = 0.0
        self.consecutive_pool_errors = 0
        self.connected_once = False
        self.current_pool = ""
        self.last_pool_error = ""

    def mark_process_started(self):
        self.reset_runtime_state()

    async def handle_line(self, line_bytes: bytes):
        decoded = line_bytes.decode("utf-8", errors="ignore").strip()
        if not decoded:
            return None

        lines = re.split(r"\r\n|\r|\n", decoded)

        for line in lines:
            clean_line = line.strip()
            if not clean_line:
                continue

            decoded = clean_line
            self.logger.log_message(f"[XMRIG] {decoded}")

            low = decoded.lower()
            now = time.monotonic()
            self.last_output_at = now

            if self._is_fatal_output(low):
                self.logger.log_message("[!] Fatal miner output detected. Restart requested.")
                return "restart"

            if self._is_pool_activity(low):
                self.last_pool_activity_at = now
                self.connected_once = True
                self.consecutive_pool_errors = 0
                self.last_pool_error = ""

            if "accepted" in low:
                self.last_share_at = now
                self._parse_accepted_shares(decoded)

            if "nvidia" in low and "c" in low:
                self._parse_gpu_stats(decoded)

            if "miner" in low and "speed" in low:
                self._parse_hashrate(decoded)

            if "new job from" in low:
                await self._handle_new_job(decoded)

            if self._is_transient_pool_error(low):
                self.last_pool_error_at = now
                self.consecutive_pool_errors += 1
                self.last_pool_error = decoded
                self.xmrig_data.last_pool_error_at = now
                self.xmrig_data.last_pool_error = decoded

                if self.should_force_pool_recovery(now):
                    self.last_restart_request_at = now
                    self.logger.log_message(
                        "[!] Pool connectivity looks wedged. Requesting managed miner restart."
                    )
                    return "restart"

        return None

    def should_force_pool_recovery(self, now=None) -> bool:
        now = time.monotonic() if now is None else now

        if self.last_pool_error_at <= 0:
            return False

        if self.last_restart_request_at and (now - self.last_restart_request_at) < 15:
            return False

        process_age = now - self.process_started_at
        last_good_activity = max(self.last_pool_activity_at, self.last_share_at)

        if self.consecutive_pool_errors >= POOL_RESTART_ERROR_STREAK:
            if last_good_activity <= 0 and process_age >= POOL_BOOTSTRAP_RESTART_SECONDS:
                return True
            if last_good_activity > 0 and (now - last_good_activity) >= POOL_RESTART_STALL_SECONDS:
                return True

        return False

    @staticmethod
    def _is_fatal_output(low: str) -> bool:
        return any(pattern in low for pattern in _FATAL_OUTPUT_PATTERNS)

    @staticmethod
    def _is_transient_pool_error(low: str) -> bool:
        if "compute error" in low:
            return False
        return any(pattern in low for pattern in _TRANSIENT_POOL_ERROR_PATTERNS)

    @staticmethod
    def _is_pool_activity(low: str) -> bool:
        return any(pattern in low for pattern in _POOL_ACTIVITY_PATTERNS)

    def _parse_accepted_shares(self, line):
        low = line.lower()

        if "cpu" in low:
            match = re.search(r"accepted\s+\((\d+)/\d+\)", low)
            if match:
                self.xmrig_data._latest_cpu_accepted_shares = int(match.group(1))

        if "nvidia" in low:
            match = re.search(r"accepted\s+\((\d+)/\d+\)", low)
            if match:
                self.xmrig_data._latest_nvidia_accepted_shares = int(match.group(1))

    def _parse_gpu_stats(self, line):
        low = line.lower()
        temp_match = re.search(r"(\d+c)", low)
        fan_match = re.search(r"fan\d+:(\d+%)", low)

        if temp_match:
            self.xmrig_data._latest_gpu_temp = temp_match.group(1)
        if fan_match:
            self.xmrig_data._latest_gpu_fan = fan_match.group(1)

    def _parse_hashrate(self, line):
        match = re.search(r"speed\s+\d+s/\d+s/\d+m\s+([\d.]+)\s+", line)
        if match:
            self.xmrig_data._latest_hashrate = float(match.group(1))

    async def _handle_new_job(self, line):
        self.xmrig_data.last_pool_job_at = time.monotonic()

        try:
            session = self.xmrig_data.aiohttp_client_session
            if session is None or session.closed:
                return

            match = re.search(
                r"new job from ([\d.:]+).*?diff (\d+).*?algo ([^\s]+).*?height (\d+).*?\((\d+) tx\)",
                line,
            )
            if match:
                job_info = {
                    "client_id": self.xmrig_data.client_id,
                    "ip": match.group(1),
                    "difficulty": int(match.group(2)),
                    "algo": match.group(3),
                    "height": int(match.group(4)),
                    "tx_count": int(match.group(5)),
                }
                await session.post(
                    f"{self.xmrig_data.FLASK_SERVER_URL}/newjob",
                    json=job_info,
                    timeout=aiohttp.ClientTimeout(total=SERVER_POST_TIMEOUT_SECONDS),
                )
                self.xmrig_data.last_server_ok_at = time.monotonic()
                self.xmrig_data.last_server_error = ""
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError) as e:
            self.xmrig_data.last_server_error_at = time.monotonic()
            self.xmrig_data.last_server_error = str(e)
            self.logger.log_message(f"[!] Error sending new job info: {e}")
        except Exception as e:
            self.logger.log_message(f"[!] Error sending new job info: {e}")


class XmrigSupervisor:
    """
    Single owner of the XMRig process lifecycle.
    No other component should directly stop/start the process pairwise.
    """

    def __init__(self, miner, quiet_timeout_sec: int = SUPERVISOR_QUIET_TIMEOUT_SECONDS, poll_sec: int = SUPERVISOR_POLL_SECONDS):
        self.miner = miner
        self.xmrig_data = miner.xmrig_data
        self.logger = miner.logger

        self.quiet_timeout_sec = max(10, int(quiet_timeout_sec))
        self.poll_sec = max(1, int(poll_sec))

        self._control_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._runner_task = None

        self._desired_running = False
        self._manual_stop = False
        self._pool_url = ""
        self._thread_count = None
        self._generation = 0
        self._closed = False

    async def start(self, pool_url="", thread_count=None):
        async with self._control_lock:
            self._desired_running = True
            self._manual_stop = False

            if pool_url:
                self._pool_url = str(pool_url).strip()
            elif not self._pool_url:
                self._pool_url = str(self.xmrig_data.custom_pool_url or "").strip()

            if thread_count is not None:
                self._thread_count = int(thread_count)
            elif self._thread_count is None:
                self._thread_count = self.xmrig_data.threads

            if self._runner_task is None or self._runner_task.done():
                self._runner_task = asyncio.create_task(self._run_forever())

            self._wake.set()

    async def stop(self):
        async with self._control_lock:
            self._desired_running = False
            self._manual_stop = True
            self._generation += 1
            self._wake.set()

        await self.miner._terminate_current_process()

    async def restart(self, reason="unspecified"):
        async with self._control_lock:
            self._desired_running = True
            self._manual_stop = False
            self._generation += 1
            self._wake.set()

        self.logger.log_message(f"[Supervisor] Restart requested: {reason}")
        await self.miner._terminate_current_process()

    async def close(self):
        self._closed = True
        await self.stop()

        if self._runner_task:
            self._runner_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._runner_task

    async def _run_forever(self):
        restart_attempt = 0

        while not self._closed:
            await self._wake.wait()
            self._wake.clear()

            while self._desired_running and not self._closed:
                current_generation = self._generation

                try:
                    proc = await self.miner._spawn_miner_process(
                        pool_url=self._pool_url,
                        thread_count=self._thread_count,
                    )

                    await self._watch_process(proc, current_generation)

                    if self._desired_running and not self._manual_stop:
                        raise MinerRestartRequested("miner exited unexpectedly")

                    restart_attempt = 0

                except asyncio.CancelledError:
                    raise

                except MinerRestartRequested as e:
                    if not self._desired_running or self._manual_stop:
                        break

                    restart_attempt += 1
                    delay = min(60, 2 ** min(restart_attempt, 5))
                    self.logger.log_message(f"[Supervisor] Restarting miner in {delay}s ({e})")

                    try:
                        await asyncio.wait_for(self._wake.wait(), timeout=delay)
                        self._wake.clear()
                    except asyncio.TimeoutError:
                        pass

                except Exception as e:
                    restart_attempt += 1
                    delay = min(60, 2 ** min(restart_attempt, 5))
                    self.logger.log_message(f"[Supervisor] Fatal lifecycle error: {e}")
                    self.logger.log_message(traceback.format_exc())
                    self.logger.log_message(f"[Supervisor] Retrying start in {delay}s")

                    try:
                        await asyncio.wait_for(self._wake.wait(), timeout=delay)
                        self._wake.clear()
                    except asyncio.TimeoutError:
                        pass

    async def _watch_process(self, process, generation: int):
        last_output_time = time.monotonic()
        restart_reason = None
        restart_event = asyncio.Event()

        async def stdout_reader():
            nonlocal last_output_time, restart_reason

            if process.stdout is None:
                restart_reason = "stdout unavailable"
                restart_event.set()
                return

            while True:
                if generation != self._generation:
                    return

                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    return

                last_output_time = time.monotonic()

                action = await self.miner.monitor.handle_line(line_bytes)
                if action == "restart":
                    restart_reason = "output monitor requested restart"
                    restart_event.set()
                    return

        async def quiet_watchdog():
            nonlocal restart_reason

            await asyncio.sleep(0.1)

            while True:
                if generation != self._generation:
                    return

                if process.returncode is not None:
                    return

                quiet_for = time.monotonic() - last_output_time
                if quiet_for >= self.quiet_timeout_sec:
                    restart_reason = f"no miner output for >= {self.quiet_timeout_sec}s"
                    self.logger.log_message(
                        f"[Watchdog] No miner output for >= {self.quiet_timeout_sec}s. Restart requested."
                    )
                    restart_event.set()
                    return

                await asyncio.sleep(self.poll_sec)

        async def pool_recovery_watchdog():
            nonlocal restart_reason

            await asyncio.sleep(self.poll_sec)

            while True:
                if generation != self._generation:
                    return

                if process.returncode is not None:
                    return

                if self.miner.monitor.should_force_pool_recovery():
                    restart_reason = (
                        f"pool recovery restart after repeated connection failures: "
                        f"{self.miner.monitor.last_pool_error or 'unknown pool error'}"
                    )
                    self.logger.log_message(f"[Watchdog] {restart_reason}")
                    restart_event.set()
                    return

                await asyncio.sleep(self.poll_sec)

        wait_task = asyncio.create_task(process.wait())
        reader_task = asyncio.create_task(stdout_reader())
        watchdog_task = asyncio.create_task(quiet_watchdog())
        pool_watchdog_task = asyncio.create_task(pool_recovery_watchdog())
        restart_wait_task = asyncio.create_task(restart_event.wait())

        try:
            done, pending = await asyncio.wait(
                {wait_task, reader_task, watchdog_task, pool_watchdog_task, restart_wait_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if restart_wait_task in done and restart_event.is_set():
                await self.miner._terminate_current_process()
                with suppress(Exception):
                    await wait_task
                raise MinerRestartRequested(restart_reason or "restart requested")

            if wait_task in done:
                return

            if reader_task in done or watchdog_task in done or pool_watchdog_task in done:
                if self.miner.is_running():
                    await self.miner._terminate_current_process()
                    with suppress(Exception):
                        await wait_task
                    raise MinerRestartRequested("monitor task ended unexpectedly")
                return

        finally:
            for task in (wait_task, reader_task, watchdog_task, pool_watchdog_task, restart_wait_task):
                if not task.done():
                    task.cancel()
            with suppress(Exception):
                await asyncio.gather(
                    wait_task,
                    reader_task,
                    watchdog_task,
                    pool_watchdog_task,
                    restart_wait_task,
                    return_exceptions=True,
                )


class XmrigMiner:
    def __init__(self, XmrigData, Logger):
        self.xmrig_data = XmrigData
        self.logger = Logger

        self.psutil_xmrig_manager = None
        self.psutil_xmrig = None

        self.periodic_reporter = PeriodicReporter(self, self.xmrig_data, self.logger)
        self.server_poller = ServerPoller(self, self.xmrig_data, self.logger)
        self.monitor = OutputMonitor(self, self.xmrig_data, self.logger)
        self.supervisor = XmrigSupervisor(
            self,
            quiet_timeout_sec=SUPERVISOR_QUIET_TIMEOUT_SECONDS,
            poll_sec=SUPERVISOR_POLL_SECONDS,
        )

        self.priority = False
        self.cpu_priority = 2
        self.cpu_yield = False
        self.cpu_affinity = 1
        self.io_priority = None
        self.memory_usage_min = None
        self.memory_usage_max = None
        self.priority_boost = False
        self.pl1_pl2 = None
        self.xmrig_msr = False
        self.cpu_info_flags = set()

        self._spawn_lock = asyncio.Lock()
        self._terminate_lock = asyncio.Lock()

        try:
            from cpuinfo import get_cpu_info
            self.cpu_info_flags = set(get_cpu_info().get("flags", []))
        except Exception:
            self.logger.log_message("[!] Failed to detect CPU features")

    def is_running(self) -> bool:
        proc = self.xmrig_data.xmrig_process
        return proc is not None and proc.returncode is None

    async def start_miner(self, pool_url="", thread_count=None):
        await self.supervisor.start(pool_url, thread_count)

    async def stop_miner(self):
        await self.supervisor.stop()

    async def request_restart(self, reason="unspecified"):
        await self.supervisor.restart(reason)

    async def close(self):
        await self.supervisor.close()

    async def _spawn_miner_process(self, pool_url="", thread_count=None):
        async with self._spawn_lock:
            await self.kill_all_xmrig_processes()

            if self.is_running():
                self.logger.log_message("[!] Miner already running.")
                return self.xmrig_data.xmrig_process

            if thread_count is None:
                try:
                    input_threads = await anyio.to_thread.run_sync(input, "Enter thread count (e.g., 4): ")
                    thread_count = int(str(input_threads).strip())
                    if thread_count <= 0:
                        raise ValueError
                except ValueError:
                    raise RuntimeError("Invalid thread count.")
            else:
                thread_count = int(thread_count)

            self.xmrig_data.threads = thread_count

            if not pool_url:
                input_pool_url = await anyio.to_thread.run_sync(
                    input,
                    "Enter custom pool URL (e.g., 192.168.0.10:3333): ",
                )
                pool_url = str(input_pool_url).strip()
                if not pool_url:
                    raise RuntimeError("No pool URL provided.")
            else:
                pool_url = str(pool_url).strip()

            self.xmrig_data.custom_pool_url = pool_url

            if not os.path.exists(self.xmrig_data.CONFIG_PATH):
                raise FileNotFoundError("config.json not found.")

            async with self.xmrig_data.miner_lock:
                await asyncio.to_thread(
                    self.update_config_file_sync,
                    self.xmrig_data.custom_pool_url,
                    self.xmrig_data.threads,
                )

            self.logger.log_message("[+] Starting miner...")

            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            proc = await asyncio.create_subprocess_exec(
                self.xmrig_data.XMRIG_PATH,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                creationflags=creationflags,
            )

            self.monitor.mark_process_started()
            self.xmrig_data.xmrig_process = proc
            self.psutil_xmrig_manager = AsyncPsutilManager(proc.pid, self.logger)
            self.psutil_xmrig = self.psutil_xmrig_manager.proc
            self.xmrig_data.client_status = "Started"

            try:
                await self._apply_process_settings()
            except Exception as e:
                self.logger.log_message(f"[!] Failed applying process settings: {e}")

            session = self.xmrig_data.aiohttp_client_session
            if session is not None and not session.closed:
                try:
                    await session.post(
                        f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}",
                        json={"status": self.xmrig_data.client_status},
                        timeout=aiohttp.ClientTimeout(total=SERVER_POST_TIMEOUT_SECONDS),
                    )
                    self.xmrig_data.last_server_ok_at = time.monotonic()
                    self.xmrig_data.last_server_error = ""
                except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError) as e:
                    self.xmrig_data.last_server_error_at = time.monotonic()
                    self.xmrig_data.last_server_error = str(e)
                    self.logger.log_message(f"[!] Error reporting miner status: {e}")

            return proc

    async def _apply_process_settings(self):
        if self.psutil_xmrig_manager is None:
            return

        try:
            if self.priority:
                await self.psutil_xmrig_manager.set_high_priority()

            if self.cpu_affinity > 0:
                await self.psutil_xmrig_manager.set_cpu_affinity(self.cpu_affinity)

            if self.io_priority and not self.priority and self.cpu_priority < 3:
                await self.psutil_xmrig_manager.set_io_priority(self.io_priority)

            ok = await self.xmrig_data.process_manager.set_working_set_size_async(
                self.psutil_xmrig_manager.proc.pid,
                self.memory_usage_min,
                self.memory_usage_max,
            )
            if ok:
                self.logger.log_message(
                    f"[+] Set XMRig (PID {self.psutil_xmrig_manager.proc.pid}) "
                    f"working-set min={self.memory_usage_min} MB max={self.memory_usage_max} MB."
                )

            ok = await self.xmrig_data.process_manager.set_priority_boost_async(
                self.psutil_xmrig_manager.proc.pid,
                self.priority_boost,
            )
            if ok:
                self.logger.log_message(
                    f"[+] Priority-boost for PID {self.psutil_xmrig_manager.proc.pid} set to {self.priority_boost}."
                )

            if self.pl1_pl2:
                if self.xmrig_data.brand == "intel":
                    if await self.xmrig_data.msr_manager.set_pl1_pl2(self.pl1_pl2):
                        self.logger.log_message(
                            f"[+] Set XMRig process (PID: {self.psutil_xmrig_manager.proc.pid}) "
                            f"to PL1/PL2={self.pl1_pl2} for INTEL."
                        )
                else:
                    if await self.xmrig_data.ryzen_manager.set_ppt_limit(self.pl1_pl2):
                        self.logger.log_message(
                            f"[+] Set XMRig process (PID: {self.psutil_xmrig_manager.proc.pid}) "
                            f"to PPT={self.pl1_pl2} for AMD."
                        )

            session = self.xmrig_data.aiohttp_client_session
            if session is not None and not session.closed:
                await self.server_poller.post_gui_settings(session)

        except psutil.Error as e:
            self.logger.log_message(
                f"[!] Could not set psutil process settings. Try running as admin/root. {e}"
            )

    async def _terminate_current_process(self):
        async with self._terminate_lock:
            proc = self.xmrig_data.xmrig_process

            if proc is not None:
                try:
                    if proc.returncode is None:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), timeout=5)
                except ProcessLookupError:
                    pass
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    with suppress(Exception):
                        await asyncio.wait_for(proc.wait(), timeout=5)
                except Exception as e:
                    self.logger.log_message(f"[!] Error terminating managed XMRig process: {e}")

            await self.kill_all_xmrig_processes()

            self.xmrig_data.xmrig_process = None
            self.psutil_xmrig_manager = None
            self.psutil_xmrig = None
            self.xmrig_data.client_status = "Stopped"

            self.logger.log_message("[+] Stopped Miner now reporting")

            session = self.xmrig_data.aiohttp_client_session
            if session is not None and not session.closed:
                try:
                    await session.post(
                        f"{self.xmrig_data.FLASK_SERVER_URL}/miners/{self.xmrig_data.client_id}",
                        json={"status": self.xmrig_data.client_status},
                        timeout=aiohttp.ClientTimeout(total=SERVER_POST_TIMEOUT_SECONDS),
                    )
                    self.xmrig_data.last_server_ok_at = time.monotonic()
                    self.xmrig_data.last_server_error = ""
                except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError) as e:
                    self.xmrig_data.last_server_error_at = time.monotonic()
                    self.xmrig_data.last_server_error = str(e)
                    self.logger.log_message(f"[!] Error reporting miner status: {e}")

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
            thread_count = int(thread_count)
            if thread_count <= 0:
                raise ValueError("thread_count must be > 0")

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

    def update_config_file_sync(self, pool_url, thread_count):
        with open(self.xmrig_data.CONFIG_PATH, "r+", encoding="utf-8") as f:
            config = json.load(f)

            config["algo"] = "rx"
            config.setdefault("randomx", {})
            config["randomx"]["algo"] = "rx"

            flags = self.cpu_info_flags
            supports_aes = "aes" in flags

            config.setdefault("cpu", {})
            config["cpu"]["asm"] = self.xmrig_data.brand
            config["cpu"]["hw-aes"] = supports_aes
            config["cpu"]["priority"] = self.cpu_priority
            config["cpu"]["yield"] = self.cpu_yield

            self.logger.log_message(f"[+] ASM optimization: {self.xmrig_data.brand}")
            self.logger.log_message(
                f"[+] AES-NI hardware acceleration: {'enabled' if config['cpu']['hw-aes'] else 'disabled'}"
            )
            self.logger.log_message(f"[+] Miner thread priority set to: {config['cpu']['priority']}")
            self.logger.log_message(f"[+] Thread yielding: {'enabled' if config['cpu']['yield'] else 'disabled'}")

            has_nvidia_gpu = False
            if getattr(self.xmrig_data, "hardware_monitor", None):
                has_nvidia_gpu = bool(self.xmrig_data.hardware_monitor.has_nvidia_gpu)

            config.setdefault("cuda", {})
            config["cuda"]["enabled"] = has_nvidia_gpu

            if has_nvidia_gpu:
                if self.xmrig_data.hardware_monitor.tuner:
                    config["cuda"]["rx"] = [{
                        "index": 0,
                        "threads": self.xmrig_data.hardware_monitor.tuner["threads"],
                        "blocks": self.xmrig_data.hardware_monitor.tuner["blocks"],
                        "bfactor": self.xmrig_data.hardware_monitor.tuner["bfactor"],
                        "bsleep": self.xmrig_data.hardware_monitor.tuner["bsleep"],
                        "affinity": -1,
                        "dataset_host": False,
                    }]
                    self.logger.log_message(
                        f"[+] Auto CUDA tuning applied: {self.xmrig_data.hardware_monitor.tuner}"
                    )
                else:
                    config["cuda"]["rx"] = []
                    self.logger.log_message("[!] Failed to determine optimal CUDA tuning")
            else:
                config["cuda"]["rx"] = []

            config["cpu"]["enabled"] = True
            config["cpu"]["rx"] = list(range(int(thread_count)))

            if config.get("pools") and isinstance(config["pools"], list):
                for pool in config["pools"]:
                    pool["url"] = pool_url
                    pool["algo"] = "rx/0"
                    pool["coin"] = "XMR"
                    pool["keepalive"] = True

            config["randomx"]["wrmsr"] = self.xmrig_msr

            f.seek(0)
            json.dump(config, f, indent=4)
            f.truncate()

        self.logger.log_message(
            f"[+] Updated config.json with {thread_count} threads, pool: {pool_url}, "
            f"CUDA enabled: {has_nvidia_gpu}"
        )

    async def kill_all_xmrig_processes(self):
        self.logger.log_message("[!] Checking for and terminating existing XMRig processes...")
        current_pid = os.getpid()
        found_and_killed = False

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.info["name"] or "").lower()
                if "xmrig" in name and (name.endswith("xmrig") or name.endswith("xmrig.exe")) and proc.pid != current_pid:
                    self.logger.log_message(
                        f"    - Found XMRig process (PID: {proc.info['pid']}, Name: {proc.info['name']}). Terminating..."
                    )
                    proc.terminate()
                    found_and_killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if found_and_killed:
            self.logger.log_message("[!] Waiting for XMRig processes to terminate...")

            for _ in range(5):
                running_xmrigs = []

                for proc in psutil.process_iter(["pid", "name"]):
                    try:
                        name = (proc.info["name"] or "").lower()
                        if "xmrig" in name and (name.endswith("xmrig") or name.endswith("xmrig.exe")) and proc.pid != current_pid:
                            running_xmrigs.append(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                if not running_xmrigs:
                    self.logger.log_message("[+] All identified XMRig processes terminated.")
                    return

                await asyncio.sleep(1)

            for proc in running_xmrigs:
                try:
                    if proc.is_running():
                        self.logger.log_message(
                            f"[!] XMRig process (PID: {proc.pid}) still running. Forcing kill."
                        )
                        proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        else:
            self.logger.log_message("[+] No existing XMRig processes found to terminate.")