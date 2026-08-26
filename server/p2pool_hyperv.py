# HyperVManager.py
import atexit
import ctypes
import os
import queue
import signal
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Optional

import pywintypes
import win32api
import win32file
import win32pipe
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from win32con import GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING

# Optional imports kept for compatibility with the rest of your app
from PyQt5.QtCore import QObject  # noqa: F401
from scapy.config import conf

# ----------------- small helpers -----------------

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [ctypes.c_void_p]
_CloseHandle.restype = ctypes.c_int

_PIPE_RETRY_WINERRORS = {
    2,    # file not found / pipe not created yet
    53,   # bad network path
    121,  # semaphore timeout
    231,  # all pipe instances are busy
}

_PIPE_DISCONNECT_WINERRORS = {
    109,  # broken pipe
    232,  # pipe being closed
    233,  # no process on other end
}


def _winerror(exc) -> int:
    try:
        return int(getattr(exc, "winerror", 0) or 0)
    except Exception:
        return 0


def _is_retry_pipe_error(exc) -> bool:
    return _winerror(exc) in _PIPE_RETRY_WINERRORS


def _is_disconnect_pipe_error(exc) -> bool:
    return _winerror(exc) in _PIPE_DISCONNECT_WINERRORS


def _close_win_handle(h) -> None:
    if not h:
        return
    try:
        win32file.CloseHandle(h)
        return
    except Exception:
        pass
    try:
        win32api.CloseHandle(h)
        return
    except Exception:
        pass
    try:
        _CloseHandle(int(h))
    except Exception:
        pass


def _normalize_pipe_payload(packet_obj) -> Optional[bytes]:
    if packet_obj is None:
        return None

    if isinstance(packet_obj, (bytes, bytearray, memoryview)):
        return bytes(packet_obj)

    if isinstance(packet_obj, str):
        s = packet_obj.strip().lower()
        for ch in (" ", ":", "-", "\n", "\r", "\t"):
            s = s.replace(ch, "")
        if s.startswith("0x"):
            s = s[2:]
        try:
            return bytes.fromhex(s)
        except ValueError:
            return None

    if isinstance(packet_obj, (list, tuple)):
        try:
            return bytes(packet_obj)
        except Exception:
            return None

    if hasattr(packet_obj, "original"):
        try:
            return bytes(packet_obj.original)
        except Exception:
            pass

    for meth in ("build", "to_bytes"):
        if hasattr(packet_obj, meth):
            try:
                return bytes(getattr(packet_obj, meth)())
            except Exception:
                pass

    try:
        return bytes(packet_obj)
    except Exception:
        return None


def _coerce_chunk_bytes(chunk) -> bytes:
    if chunk is None:
        return b""
    if isinstance(chunk, bytes):
        return chunk
    if isinstance(chunk, bytearray):
        return bytes(chunk)
    if isinstance(chunk, memoryview):
        return chunk.tobytes()
    if isinstance(chunk, str):
        return chunk.encode("latin1", errors="ignore")
    try:
        return bytes(chunk)
    except Exception:
        return b""


# ----------------- logging -----------------


class CppLogger:
    def __init__(self, logger):
        self._logger = logger
        self._prefix = "[C++]"
        self._lock = threading.Lock()
        self._closing = False
        self._window_seconds = 1.0
        self._max_lines_per_window = 60
        self._window_start = time.monotonic()
        self._lines_in_window = 0
        self._suppressed_in_window = 0
        self._max_line_length = 4000

    def set_prefix(self, prefix: str):
        self._prefix = prefix

    @staticmethod
    def _is_important_line(text: str) -> bool:
        lowered = str(text or "").casefold()
        return any(token in lowered for token in (
            "error", "exception", "failed", "crash", "exit", "disconnect",
            "dhcp", "lease", "tls", "handshake", "alert", "reject", "drop",
            "route", "gateway", "pipe", "packet", "warning", "⚠", "❌",
        ))

    def _format_line(self, msg: str) -> str:
        text = str(msg).rstrip()
        if len(text) > self._max_line_length:
            text = text[: self._max_line_length] + " ... [truncated]"
        if self._prefix == "":
            return text
        return f"{self._prefix} {text}"

    def _emit_summary_locked(self):
        if self._suppressed_in_window > 0 and self._logger:
            try:
                self._logger.log_message(
                    f"{self._prefix} [GUI] ⚠️ Suppressed {self._suppressed_in_window} C++ log lines to protect the UI."
                )
            except Exception:
                pass
            self._suppressed_in_window = 0

    def log_message(self, msg: str):
        try:
            if not self._logger:
                return

            line = self._format_line(msg)
            if not line:
                return

            now = time.monotonic()

            with self._lock:
                if self._closing:
                    return

                if (now - self._window_start) >= self._window_seconds:
                    self._emit_summary_locked()
                    self._window_start = now
                    self._lines_in_window = 0

                important = self._is_important_line(line)
                if self._lines_in_window >= self._max_lines_per_window and not important:
                    self._suppressed_in_window += 1
                    return

                self._lines_in_window += 1

            self._logger.log_message(line)

        except Exception:
            pass

    def shutdown(self):
        try:
            with self._lock:
                self._closing = True
                self._emit_summary_locked()
        except Exception:
            pass


# ----------------- HyperV process manager -----------------


class HyperVManager:
    """
    Runs HyperVProject.exe as a subprocess and manages the outbound packet pipe.

    Startup/stability goals:
      - router startup does not depend on packet pipe already existing
      - packet pipe maintainer reconnects in background
      - idempotent teardown
      - no noisy exit logging on intentional shutdown
    """

    _EXPECTED_WINDOWS_EXITS = {
        0,
        1,
        -1,
        3221225786,   # 0xC000013A
        -1073741510,  # signed 0xC000013A
    }

    _PACKET_PIPE_NAME = r"\\.\pipe\vmrouter_packets"

    def __init__(
        self,
        logger: Any,
        exe_name: str = "tools/Linux/HyperVProject/HyperVProject.exe",
        linux_dir_arg: str = ".",
        stop_timeout_soft: float = 5.0,
        stop_timeout_hard: float = 3.0,
        packet_pipe_connect_timeout: float = 2.0,
        packet_pipe_maintain_interval: float = 1.0,
    ):
        self._logger = CppLogger(logger)
        self._exe_path = self._resolve_exe_path(exe_name)
        self._linux_dir_arg = str(linux_dir_arg)

        self._proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None

        self._proc_lock = threading.RLock()
        self._packet_pipe_lock = threading.RLock()

        self._pipe_handle = None
        self._packet_pipe_connect_timeout = max(0.25, float(packet_pipe_connect_timeout))
        self._packet_pipe_maintain_interval = max(0.25, float(packet_pipe_maintain_interval))
        self._packet_pipe_stop = threading.Event()
        self._packet_pipe_thread: Optional[threading.Thread] = None

        # The router hot path must never wait for a named pipe.  One dedicated
        # writer owns the C++ pipe and drains this bounded byte-aware queue.
        # When pressure is sustained, oldest frames are discarded so current
        # traffic continues moving instead of allowing stale traffic to wedge
        # the router and Qt log thread.
        self._packet_tx_cv = threading.Condition(threading.RLock())
        self._packet_tx_q = deque()
        self._packet_tx_bytes = 0
        self._packet_tx_max_frames = 4096
        self._packet_tx_max_bytes = 64 * 1024 * 1024
        self._packet_tx_thread: Optional[threading.Thread] = None
        self._packet_tx_stop = threading.Event()
        self._packet_tx_retries = 2
        self._packet_tx_retry_backoff = 0.05
        self._packet_tx_max_age_sec = 3.0
        self._packet_tx_stats = {
            "accepted": 0,
            "written": 0,
            "write_failures": 0,
            "dropped_pressure": 0,
            "dropped_shutdown": 0,
            "reconnects": 0,
        }
        self._packet_tx_last_log = {}

        self._stop_timeout_soft = float(stop_timeout_soft)
        self._stop_timeout_hard = float(stop_timeout_hard)

        self._stopping = False
        self._started_by_us = False
        self._suppress_exit_log = False
        self._last_exit_code: Optional[int] = None
        self._exit_logged = False
        self._auto_restart = True
        self._restart_stop = threading.Event()
        self._restart_lock = threading.RLock()
        self._restart_thread: Optional[threading.Thread] = None
        self._restart_history = deque(maxlen=32)
        self._restart_base_backoff = 0.75
        self._restart_max_backoff = 15.0
        self._restart_window_sec = 120.0
        self._restart_limit_per_window = 8

        atexit.register(self.teardown)


    # ---------- helpers ----------

    def _resolve_exe_path(self, exe_name: str) -> Path:
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            base_path = Path(sys._MEIPASS)
        else:
            base_path = Path(__file__).parent
        return base_path.joinpath(exe_name)

    def _is_expected_exit(self, rc: Optional[int]) -> bool:
        if rc is None:
            return False
        try:
            return int(rc) in self._EXPECTED_WINDOWS_EXITS
        except Exception:
            return False

    @staticmethod
    def _format_exit_code(rc: Optional[int]) -> str:
        if rc is None:
            return "unknown"
        value = int(rc)
        unsigned = value & 0xFFFFFFFF
        signed = unsigned if unsigned < 0x80000000 else unsigned - 0x100000000
        return f"{value} (signed={signed}, hex=0x{unsigned:08X})"

    def _schedule_restart(self, rc: Optional[int]) -> None:
        if self._stopping or self._restart_stop.is_set() or not self._auto_restart:
            return
        with self._restart_lock:
            if self._restart_thread and self._restart_thread.is_alive():
                return
            now = time.monotonic()
            while self._restart_history and now - self._restart_history[0] > self._restart_window_sec:
                self._restart_history.popleft()
            if len(self._restart_history) >= self._restart_limit_per_window:
                self._logger.log_message(
                    "[HyperV] ❌ Restart circuit open after repeated exits; router remains alive without the C++ helper."
                )
                return
            attempt = len(self._restart_history) + 1
            delay = min(self._restart_max_backoff, self._restart_base_backoff * (2 ** max(0, attempt - 1)))
            self._restart_history.append(now)
            self._restart_thread = threading.Thread(
                target=self._restart_worker,
                args=(delay, rc, attempt),
                name="HyperVRestartSupervisor",
                daemon=True,
            )
            self._restart_thread.start()

    def _restart_worker(self, delay: float, rc: Optional[int], attempt: int) -> None:
        self._logger.log_message(
            f"[HyperV] ⚠️ Helper exited with {self._format_exit_code(rc)}; restart attempt {attempt} scheduled in {delay:.2f}s."
        )
        retry = False
        if self._restart_stop.wait(delay) or self._stopping:
            with self._restart_lock:
                self._restart_thread = None
            return
        try:
            if self.start():
                self._logger.log_message("[HyperV] ✅ Helper restarted; router processing continued without a process-level crash.")
            else:
                retry = True
                self._logger.log_message("[HyperV] ⚠️ Helper restart failed; another supervised attempt will be made.")
        except Exception as exc:
            retry = True
            self._logger.log_message(f"[HyperV] ⚠️ Restart supervisor caught: {exc}")
        finally:
            with self._restart_lock:
                self._restart_thread = None
        if retry and not self._restart_stop.is_set() and not self._stopping:
            self._schedule_restart(rc)

    def _log_exit(self, rc: Optional[int]) -> None:
        with self._proc_lock:
            if self._exit_logged:
                return
            self._exit_logged = True
            self._last_exit_code = rc

        if rc is None:
            return

        if self._suppress_exit_log or (self._stopping and self._is_expected_exit(rc)):
            self._logger.log_message(f"[HyperV] Process stopped cleanly (exit={self._format_exit_code(rc)}).")
            return

        if self._stopping:
            self._logger.log_message(f"[HyperV] Process stopped during teardown (exit={self._format_exit_code(rc)}).")
            return

        self._logger.log_message(f"[HyperV] Process exited unexpectedly with code {self._format_exit_code(rc)}.")

    def _wait_proc(self, proc: Optional[subprocess.Popen], timeout: float) -> Optional[int]:
        if not proc:
            return None
        try:
            return proc.wait(timeout=timeout)
        except Exception:
            try:
                return proc.poll()
            except Exception:
                return None

    def _pump_stdout(self):
        with self._proc_lock:
            proc = self._proc

        if proc is None:
            return

        stream = proc.stdout
        if not stream:
            return

        try:
            for line in stream:
                if line is None:
                    break
                line = line.rstrip("\r\n")
                if line:
                    self._logger.log_message(line)
        except Exception as e:
            if not self._stopping:
                self._logger.log_message(f"[HyperV] stdout pump error: {e}")
        finally:
            rc = self._wait_proc(proc, 1.0)
            with self._proc_lock:
                if self._proc is proc:
                    self._proc = None
                    self._reader_thread = None
            with self._packet_pipe_lock:
                self._close_packet_pipe_locked()
            self._log_exit(rc)
            if not self._stopping and not self._restart_stop.is_set():
                self._schedule_restart(rc)

    def _safe_close_stdin(self) -> None:
        with self._proc_lock:
            proc = self._proc
        if not proc or not proc.stdin:
            return
        try:
            proc.stdin.flush()
        except Exception:
            pass
        try:
            proc.stdin.close()
        except Exception:
            pass

    def _close_packet_pipe_locked(self) -> None:
        h = self._pipe_handle
        self._pipe_handle = None
        if h:
            _close_win_handle(h)

    def _open_packet_pipe_locked(self, timeout: Optional[float] = None):
        if self._pipe_handle is not None:
            return self._pipe_handle

        connect_timeout = self._packet_pipe_connect_timeout if timeout is None else max(0.0, float(timeout))
        deadline = time.monotonic() + connect_timeout

        while not self._packet_pipe_stop.is_set():
            if not self.is_running():
                return None

            try:
                win32pipe.WaitNamedPipe(self._PACKET_PIPE_NAME, 250)
            except pywintypes.error as e:
                if time.monotonic() >= deadline:
                    return None
                if _is_retry_pipe_error(e):
                    self._packet_pipe_stop.wait(0.05)
                    continue
                self._packet_pipe_stop.wait(0.05)
                continue

            if self._packet_pipe_stop.is_set() or not self.is_running():
                return None

            try:
                h = win32file.CreateFile(
                    self._PACKET_PIPE_NAME,
                    GENERIC_WRITE,
                    0,
                    None,
                    OPEN_EXISTING,
                    0,
                    None,
                )
                self._pipe_handle = h
                self._packet_tx_stats["reconnects"] += 1
                return h
            except pywintypes.error:
                if time.monotonic() >= deadline:
                    return None
                self._packet_pipe_stop.wait(0.05)

        return None

    def _packet_pipe_maintainer(self):
        last_state = None

        while not self._packet_pipe_stop.is_set():
            try:
                with self._packet_pipe_lock:
                    h = self._pipe_handle
                    running = self.is_running()

                    if not running:
                        if h is not None:
                            self._close_packet_pipe_locked()
                        state = "down"
                    else:
                        if h is None:
                            opened = self._open_packet_pipe_locked(timeout=0.50)
                            state = "connected" if opened is not None else "waiting"
                        else:
                            state = "connected"

                if state != last_state:
                    if state == "connected":
                        self._logger.log_message("[HyperV][PIPE] Packet pipe connected.")
                    elif state == "waiting":
                        self._logger.log_message("[HyperV][PIPE] Waiting for packet pipe server...")
                    elif state == "down":
                        self._logger.log_message("[HyperV][PIPE] Packet pipe maintainer idle (process not running).")
                    last_state = state

            except Exception as e:
                self._logger.log_message(f"[HyperV][PIPE] Maintainer error: {e}")

            self._packet_pipe_stop.wait(self._packet_pipe_maintain_interval)

    def _start_packet_pipe_maintainer(self):
        with self._packet_pipe_lock:
            thr = self._packet_pipe_thread
            if thr is not None and thr.is_alive():
                return

            self._packet_pipe_stop.clear()
            self._packet_pipe_thread = threading.Thread(
                target=self._packet_pipe_maintainer,
                name="HyperVPacketPipeMaintainer",
                daemon=True,
            )
            self._packet_pipe_thread.start()

    def _stop_packet_pipe_maintainer(self):
        self._packet_pipe_stop.set()
        with self._packet_pipe_lock:
            self._close_packet_pipe_locked()
            thr = self._packet_pipe_thread

        if thr and thr.is_alive():
            try:
                thr.join(timeout=2.0)
            except Exception:
                pass

        with self._packet_pipe_lock:
            self._packet_pipe_thread = None

    # ---------- non-blocking packet writer ----------

    def _pipe_log_sparse(self, key: str, message: str, every: float = 2.0) -> None:
        now = time.monotonic()
        last = float(self._packet_tx_last_log.get(key, 0.0) or 0.0)
        if now - last < max(0.1, float(every)):
            return
        self._packet_tx_last_log[key] = now
        self._logger.log_message(message)

    def _start_packet_writer(self) -> None:
        with self._packet_tx_cv:
            thr = self._packet_tx_thread
            if thr is not None and thr.is_alive():
                return
            self._packet_tx_stop.clear()
            self._packet_tx_thread = threading.Thread(
                target=self._packet_writer_loop,
                name="HyperVPacketPipeWriter",
                daemon=True,
            )
            self._packet_tx_thread.start()

    def _stop_packet_writer(self, *, discard: bool = True) -> None:
        self._packet_tx_stop.set()
        with self._packet_tx_cv:
            if discard and self._packet_tx_q:
                self._packet_tx_stats["dropped_shutdown"] += len(self._packet_tx_q)
                self._packet_tx_q.clear()
                self._packet_tx_bytes = 0
            self._packet_tx_cv.notify_all()
            thr = self._packet_tx_thread

        if thr and thr.is_alive() and thr is not threading.current_thread():
            try:
                thr.join(timeout=3.0)
            except Exception:
                pass

        with self._packet_tx_cv:
            self._packet_tx_thread = None

    def _enqueue_packet_payload(self, payload: bytes) -> bool:
        n = len(payload)
        if n <= 4 or n > (4 * 1024 * 1024):
            return False

        with self._packet_tx_cv:
            if self._packet_tx_stop.is_set() or self._stopping:
                return False

            dropped = 0
            while self._packet_tx_q and (
                len(self._packet_tx_q) >= self._packet_tx_max_frames
                or self._packet_tx_bytes + n > self._packet_tx_max_bytes
            ):
                old_payload, _old_ts = self._packet_tx_q.popleft()
                self._packet_tx_bytes = max(0, self._packet_tx_bytes - len(old_payload))
                dropped += 1

            if len(self._packet_tx_q) >= self._packet_tx_max_frames or self._packet_tx_bytes + n > self._packet_tx_max_bytes:
                self._packet_tx_stats["dropped_pressure"] += 1
                self._pipe_log_sparse(
                    "queue-hard-full",
                    "[HyperV][PIPE] ⚠️ outbound pipe queue at hard limit; newest frame dropped.",
                )
                return False

            if dropped:
                self._packet_tx_stats["dropped_pressure"] += dropped
                self._pipe_log_sparse(
                    "queue-pressure",
                    f"[HyperV][PIPE] ⚠️ outbound queue pressure; dropped_oldest={dropped} "
                    f"queued={len(self._packet_tx_q)} bytes={self._packet_tx_bytes}.",
                )

            self._packet_tx_q.append((payload, time.monotonic()))
            self._packet_tx_bytes += n
            self._packet_tx_stats["accepted"] += 1
            self._packet_tx_cv.notify()
            return True

    def _dequeue_packet_payload(self) -> Optional[tuple[bytes, float]]:
        with self._packet_tx_cv:
            while not self._packet_tx_q and not self._packet_tx_stop.is_set():
                self._packet_tx_cv.wait(timeout=0.25)
            if not self._packet_tx_q:
                return None
            payload, queued_at = self._packet_tx_q.popleft()
            self._packet_tx_bytes = max(0, self._packet_tx_bytes - len(payload))
            return payload, float(queued_at)

    @staticmethod
    def _write_result_count(result, expected: int) -> int:
        try:
            if isinstance(result, tuple) and len(result) >= 2:
                value = result[1]
                if isinstance(value, int):
                    return int(value)
                if isinstance(value, (bytes, bytearray, memoryview)):
                    return len(value)
            if isinstance(result, int):
                return int(result)
        except Exception:
            pass
        # Synchronous pywin32 WriteFile commonly reports success with a tuple
        # whose second value is implementation-dependent.  No exception means
        # the complete buffer was accepted by the byte-mode pipe.
        return int(expected)

    def _write_pipe_payload(self, payload: bytes) -> bool:
        with self._packet_pipe_lock:
            h = self._open_packet_pipe_locked(timeout=0.35)
            if h is None:
                return False
            try:
                result = win32file.WriteFile(h, payload)
                written = self._write_result_count(result, len(payload))
                if written != len(payload):
                    raise OSError(f"short pipe write {written}/{len(payload)}")
                return True
            except Exception:
                self._close_packet_pipe_locked()
                raise

    def _packet_writer_loop(self) -> None:
        current: Optional[tuple[bytes, float]] = None
        retry_count = 0

        while not self._packet_tx_stop.is_set():
            if current is None:
                current = self._dequeue_packet_payload()
                retry_count = 0
                if current is None:
                    continue

            payload, queued_at = current
            if (time.monotonic() - queued_at) > self._packet_tx_max_age_sec:
                self._packet_tx_stats["dropped_pressure"] += 1
                current = None
                retry_count = 0
                self._pipe_log_sparse(
                    "stale-drop",
                    "[HyperV][PIPE] ⚠️ dropped stale outbound frame while pipe was unavailable.",
                    every=2.0,
                )
                continue

            if not self.is_running():
                if self._packet_tx_stop.wait(0.10):
                    break
                continue

            try:
                if self._write_pipe_payload(payload):
                    self._packet_tx_stats["written"] += 1
                    current = None
                    retry_count = 0
                    continue
            except Exception as exc:
                self._packet_tx_stats["write_failures"] += 1
                self._pipe_log_sparse(
                    "write-failed",
                    f"[HyperV][PIPE] Write failed; reconnecting without blocking router: "
                    f"{type(exc).__name__}: {exc}",
                )

            retry_count += 1
            if retry_count > self._packet_tx_retries:
                self._packet_tx_stats["dropped_pressure"] += 1
                current = None
                retry_count = 0
            else:
                self._packet_tx_stop.wait(self._packet_tx_retry_backoff * retry_count)

        if current is not None:
            self._packet_tx_stats["dropped_shutdown"] += 1

    def get_pipe_stats(self) -> dict:
        with self._packet_tx_cv:
            out = dict(self._packet_tx_stats)
            out.update({
                "queued_frames": len(self._packet_tx_q),
                "queued_bytes": self._packet_tx_bytes,
                "connected": self._pipe_handle is not None,
                "process_running": self.is_running(),
                "writer_alive": bool(self._packet_tx_thread and self._packet_tx_thread.is_alive()),
            })
            return out

    # ---------- public API ----------

    def start(self) -> bool:
        self._restart_stop.clear()
        with self._proc_lock:
            if self._proc and self._proc.poll() is None:
                self._logger.log_message("[HyperV] Process already running.")
                self._start_packet_pipe_maintainer()
                self._start_packet_writer()
                return True

            if not self._exe_path.exists():
                self._logger.log_message(f"[HyperV] Error: executable not found at {self._exe_path}")
                return False

            self._stopping = False
            self._suppress_exit_log = False
            self._last_exit_code = None
            self._exit_logged = False

            try:
                creationflags = 0
                if os.name == "nt":
                    creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

                self._proc = subprocess.Popen(
                    [str(self._exe_path), self._linux_dir_arg],
                    cwd=str(self._exe_path.parent),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    creationflags=creationflags,
                )

                self._started_by_us = True
                self._reader_thread = threading.Thread(
                    target=self._pump_stdout,
                    name="HyperVStdoutPump",
                    daemon=True,
                )
                self._reader_thread.start()
                self._start_packet_pipe_maintainer()
                self._start_packet_writer()

                self._logger.log_message(f"[HyperV] Started {self._exe_path.name} (pid {self._proc.pid})")
                return True

            except Exception as e:
                self._proc = None
                self._reader_thread = None
                self._stop_packet_writer(discard=True)
                self._stop_packet_pipe_maintainer()
                self._logger.log_message(f"[HyperV] Error starting process: {e}")
                return False

    def is_running(self) -> bool:
        with self._proc_lock:
            proc = self._proc
        return proc is not None and proc.poll() is None

    def send_enter(self) -> None:
        with self._proc_lock:
            proc = self._proc
        if not proc or not proc.stdin:
            return
        try:
            proc.stdin.write("\n")
            proc.stdin.flush()
        except Exception:
            pass

    def close_pipe(self) -> None:
        with self._packet_pipe_lock:
            self._close_packet_pipe_locked()

    def teardown(self) -> None:
        self._restart_stop.set()
        with self._proc_lock:
            proc = self._proc
            if not proc:
                self._stopping = True
                self._stop_packet_writer(discard=True)
                self._stop_packet_pipe_maintainer()
                self._stopping = False
                return
            if self._stopping:
                return
            self._stopping = True
            self._suppress_exit_log = True

        self._stop_packet_writer(discard=True)
        self._stop_packet_pipe_maintainer()

        self.send_enter()
        rc = self._wait_proc(proc, self._stop_timeout_soft)
        if rc is not None:
            self._safe_close_stdin()
        else:
            if os.name == "nt":
                try:
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                except Exception:
                    pass
                rc = self._wait_proc(proc, self._stop_timeout_soft)

            if rc is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
                rc = self._wait_proc(proc, self._stop_timeout_hard)

            if rc is None:
                try:
                    proc.kill()
                except Exception:
                    pass
                rc = self._wait_proc(proc, self._stop_timeout_hard)

            self._safe_close_stdin()

        thr = self._reader_thread
        if thr and thr.is_alive():
            try:
                thr.join(timeout=2.0)
            except Exception:
                pass

        self._log_exit(proc.poll())

        with self._proc_lock:
            self._proc = None
            self._reader_thread = None
            self._stopping = False
            self._started_by_us = False

        self._logger.log_message("[HyperV] Teardown complete.")

    def send_packet(self, packet, connect_timeout: float = 3.0) -> bool:
        """Queue a framed packet for C++ without blocking the routing thread.

        ``connect_timeout`` remains in the public signature for compatibility,
        but connection/reconnection is owned by the writer thread.
        """
        frame = _normalize_pipe_payload(packet)
        if not frame:
            self._pipe_log_sparse(
                "normalize-failed",
                "[HyperV][PIPE] Could not normalize packet to bytes.",
            )
            return False
        if len(frame) > (4 * 1024 * 1024):
            self._pipe_log_sparse(
                "oversize",
                f"[HyperV][PIPE] Refusing oversized frame len={len(frame)}.",
            )
            return False

        if not self.is_running():
            return False

        self._start_packet_writer()
        payload = struct.pack("<I", len(frame)) + frame
        return self._enqueue_packet_payload(payload)


# ----------------- shared pipe reader base -----------------


class _PipeFrameReaderBase:
    """
    Stable named-pipe frame reader.

    Startup behavior:
      - manager start succeeds even if router handler or pipe is not ready yet
      - header wait is persistent: idle time does NOT count as disconnect
      - reconnect only on real disconnect, malformed header, or stalled partial payload
      - reader thread alone owns/closes the live pipe handle
      - processor thread serializes process_packet(...)
    """

    VIRTUAL_IFACE_NAME = "VirtualPipe"
    DEFAULT_PIPE_NAME = r"\\.\pipe\virtual_to_python"
    LOG_PREFIX = "Pipe"

    _ROUTER_PROCESS_LOCK = threading.RLock()

    def __init__(
        self,
        router_manager,
        code_output_manager=None,
        *,
        pipe_name: str,
        idle_timeout: float = 2.0,          # compatibility only; used as poll baseline
        payload_timeout: float = 15.0,      # timeout only after header is received
        header_wait_log_every: float = 30.0,
        handler_wait_timeout: float = 15.0,
        max_frames_per_batch: int = 128,
        max_bytes_per_batch: int = (1 << 19),
    ):
        try:
            conf.max_list_count = max(int(getattr(conf, "max_list_count", 0) or 0), 2048)
        except Exception:
            pass

        self.router_manager = router_manager
        self.logger = getattr(router_manager, "router_logger", None)
        self.code_output_manager = code_output_manager
        self.pipe_name = str(pipe_name)

        self._stop_event = threading.Event()
        self._connected_event = threading.Event()
        self._state_lock = threading.RLock()

        self._reader_thread = None
        self._processor_thread = None

        self._poll_sleep = max(0.005, min(0.050, float(idle_timeout) / 200.0 if idle_timeout else 0.01))
        self._payload_timeout = max(1.0, float(payload_timeout))
        self._header_wait_log_every = max(5.0, float(header_wait_log_every))
        self._handler_wait_timeout = max(1.0, float(handler_wait_timeout))

        self._max_frames = max(1, int(max_frames_per_batch))
        self._max_bytes = max(4096, int(max_bytes_per_batch))
        # Match the outbound framing limit.  A malformed larger prefix still
        # forces reconnect, but valid captures are not rejected merely because
        # they exceed the legacy 65,535-byte cap.
        self._max_frame_size = 4 * 1024 * 1024

        self._pipe_handle = None
        self._pipe_handle_lock = threading.Lock()

        self._q_cv = threading.Condition()
        self._q = deque()
        self._q_bytes = 0
        self._q_max_frames = max(256, self._max_frames * 8)
        self._q_max_bytes = max((2 << 20), self._max_bytes * 8)

        self.frames_read = 0
        self.frames_enqueued = 0
        self.frames_processed = 0
        self.frames_badlen = 0
        self.frames_dropped_queuefull = 0
        self.frames_delivery_errors = 0
        self.frames_dropped_no_handler = 0
        self.reconnect_count = 0
        self.start_failures = 0

        self._last_log_ts = 0.0
        self._log_every = 0.5
        self._badlen_last_log = 0.0
        self._badlen_log_every = 5.0
        self._drop_last_log = 0.0
        self._drop_log_every = 2.0
        self._disconnect_last_log = 0.0
        self._disconnect_log_every = 1.0
        self._header_wait_last_log = 0.0
        self._queue_pressure_last_log = 0.0
        self._queue_pressure_log_every = 2.0
        self._handler_wait_last_log = 0.0
        self._handler_wait_log_every = 5.0

        # compatibility placeholders
        self._frag_db = {}
        self._frag_timeout_sec = 5.0
        self._frag_max_streams = 1024
        self._frag_max_per_stream = 128

        self._frag6_db = {}
        self._frag6_timeout_sec = 5.0
        self._frag6_max_streams = 1024
        self._frag6_max_per_stream = 128

    # ---------- lifecycle ----------
    def _should_drop_local_noise_frame(self, frame: bytes) -> bool:

        try:
            pkt = Ether(frame)
        except Exception:
            return False

        try:
            if pkt.haslayer(ARP):
                return True
        except Exception:
            pass

        try:
            dst_mac = str(getattr(pkt, "dst", "") or "").lower()
            if dst_mac == "ff:ff:ff:ff:ff:ff":
                return True
            if dst_mac.startswith("01:00:5e:"):
                return True
            if dst_mac.startswith("33:33:"):
                return True
        except Exception:
            pass

        try:
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                if sport in {137, 138} or dport in {137, 138}:
                    return True
        except Exception:
            pass

        try:
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is not None:
                dst_ip = str(getattr(ip, "dst", "") or "").lower()
                if dst_ip == "255.255.255.255":
                    return True
                if dst_ip.startswith("224."):
                    return True
                if dst_ip.startswith("ff"):
                    return True
        except Exception:
            pass

        return False
    def start(self):
        with self._state_lock:
            if self._reader_thread and self._reader_thread.is_alive():
                return True
            if self._processor_thread and self._processor_thread.is_alive():
                return True

            self._stop_event.clear()
            self._connected_event.clear()

            try:
                self._processor_thread = threading.Thread(
                    target=self._processor_loop,
                    name=f"{self.LOG_PREFIX}Processor",
                    daemon=True,
                )
                self._reader_thread = threading.Thread(
                    target=self._reader_loop,
                    name=f"{self.LOG_PREFIX}Reader",
                    daemon=True,
                )

                self._processor_thread.start()
                self._reader_thread.start()

                self._log(f"[{self.LOG_PREFIX}] Started manager (startup-safe persistent pipe mode).")
                return True

            except Exception as e:
                self.start_failures += 1
                self._stop_event.set()
                self._log(f"[{self.LOG_PREFIX}] ❌ failed to start threads: {e}")

                try:
                    if self._reader_thread and self._reader_thread.is_alive():
                        self._reader_thread.join(timeout=1.0)
                except Exception:
                    pass

                try:
                    if self._processor_thread and self._processor_thread.is_alive():
                        self._processor_thread.join(timeout=1.0)
                except Exception:
                    pass

                self._reader_thread = None
                self._processor_thread = None
                return False

    def stop(self):
        with self._state_lock:
            reader_alive = self._reader_thread and self._reader_thread.is_alive()
            proc_alive = self._processor_thread and self._processor_thread.is_alive()

            if not reader_alive and not proc_alive:
                self._log(f"[{self.LOG_PREFIX}] Manager already stopped.")
                return

            self._log(f"[{self.LOG_PREFIX}] Stopping manager...")
            self._stop_event.set()

            with self._q_cv:
                self._q_cv.notify_all()

        try:
            if self._reader_thread and self._reader_thread.is_alive():
                self._reader_thread.join(timeout=5.0)
        except Exception:
            pass

        try:
            if self._processor_thread and self._processor_thread.is_alive():
                self._processor_thread.join(timeout=5.0)
        except Exception:
            pass

        with self._q_cv:
            self._q.clear()
            self._q_bytes = 0

        with self._state_lock:
            self._reader_thread = None
            self._processor_thread = None
            self._connected_event.clear()

        self._log(f"[{self.LOG_PREFIX}] Manager stopped successfully.")

    shutdown = stop

    def is_connected(self) -> bool:
        return self._connected_event.is_set()

    # ---------- router handler ----------

    def _get_process_packet(self):
        try:
            for name in ("enqueue_ingress_packet", "process_packet"):
                fn = getattr(self.router_manager, name, None)
                if callable(fn):
                    return fn
            return None
        except Exception:
            return None

    def _wait_for_process_handler(self) -> Optional[Any]:
        deadline = time.monotonic() + self._handler_wait_timeout

        while not self._stop_event.is_set():
            fn = self._get_process_packet()
            if fn is not None:
                return fn

            now = time.monotonic()
            if (now - self._handler_wait_last_log) >= self._handler_wait_log_every:
                self._handler_wait_last_log = now
                self._log(f"[{self.LOG_PREFIX}] ⏳ waiting for router_manager.process_packet to become available...")

            if now >= deadline:
                return None

            self._stop_event.wait(0.05)

        return None

    # ---------- pipe helpers ----------

    def _set_pipe_handle(self, h):
        with self._pipe_handle_lock:
            self._pipe_handle = h
            if h:
                self._connected_event.set()
            else:
                self._connected_event.clear()

    def _clear_pipe_handle_if(self, h):
        with self._pipe_handle_lock:
            if self._pipe_handle == h:
                self._pipe_handle = None
                self._connected_event.clear()

    def _close_reader_owned_handle(self, h):
        if not h:
            return
        self._clear_pipe_handle_if(h)
        try:
            _close_win_handle(h)
        except Exception:
            pass

    def _connect_pipe(self):
        while not self._stop_event.is_set():
            try:
                win32pipe.WaitNamedPipe(self.pipe_name, 250)
            except pywintypes.error as e:
                if _is_retry_pipe_error(e):
                    self._stop_event.wait(0.05)
                    continue
                self._stop_event.wait(0.05)
                continue
            except Exception:
                self._stop_event.wait(0.05)
                continue

            if self._stop_event.is_set():
                return None

            try:
                h = win32file.CreateFile(
                    self.pipe_name,
                    GENERIC_READ,
                    0,
                    None,
                    OPEN_EXISTING,
                    0,
                    None,
                )

                try:
                    PIPE_READMODE_BYTE = 0x00000000
                    win32pipe.SetNamedPipeHandleState(h, PIPE_READMODE_BYTE, None, None)
                except Exception:
                    pass

                self._set_pipe_handle(h)
                return h

            except pywintypes.error:
                self._stop_event.wait(0.05)
            except Exception:
                self._stop_event.wait(0.05)

        return None

    def _peek_available(self, h):
        try:
            peek = win32pipe.PeekNamedPipe(h, 0)
            return int(peek[1]) if len(peek) > 1 else 0, None
        except pywintypes.error as e:
            return 0, e
        except Exception as e:
            return 0, e

    def _wait_for_header(self, h):
        while not self._stop_event.is_set():
            avail, err = self._peek_available(h)
            if err is not None:
                if _is_disconnect_pipe_error(err):
                    return None, "broken pipe while waiting for header"
                if _is_retry_pipe_error(err):
                    self._stop_event.wait(self._poll_sleep)
                    continue
                return None, f"peek failed while waiting for header: {err}"

            if avail < 4:
                now = time.monotonic()
                if (now - self._header_wait_last_log) >= self._header_wait_log_every:
                    self._header_wait_last_log = now
                    self._log(f"[{self.LOG_PREFIX}] ⏳ pipe idle; waiting for next frame header...")
                self._stop_event.wait(self._poll_sleep)
                continue

            try:
                _hr, hdr = win32file.ReadFile(h, 4, None)
            except pywintypes.error as e:
                if _is_disconnect_pipe_error(e):
                    return None, "broken pipe during header read"
                if _is_retry_pipe_error(e):
                    self._stop_event.wait(self._poll_sleep)
                    continue
                return None, f"header read failed: {e}"
            except Exception as e:
                return None, f"header read exception: {e}"

            hdr = _coerce_chunk_bytes(hdr)
            if len(hdr) != 4:
                return None, f"short header read ({len(hdr)} bytes)"

            return hdr, None

        return None, "stop requested"

    def _read_exact_payload(self, h, want: int):
        if want <= 0:
            return b"", None

        out = bytearray()
        deadline = time.monotonic() + self._payload_timeout

        while len(out) < want and not self._stop_event.is_set():
            avail, err = self._peek_available(h)
            if err is not None:
                if _is_disconnect_pipe_error(err):
                    return None, "broken pipe during payload wait"
                if _is_retry_pipe_error(err):
                    self._stop_event.wait(self._poll_sleep)
                    continue
                return None, f"peek failed during payload wait: {err}"

            if avail <= 0:
                if time.monotonic() >= deadline:
                    return None, f"payload stalled for {self._payload_timeout:.1f}s"
                self._stop_event.wait(self._poll_sleep)
                continue

            to_read = min(want - len(out), avail, 65536)

            try:
                _hr, chunk = win32file.ReadFile(h, to_read, None)
            except pywintypes.error as e:
                if _is_disconnect_pipe_error(e):
                    return None, "broken pipe during payload read"
                if _is_retry_pipe_error(e):
                    self._stop_event.wait(self._poll_sleep)
                    continue
                return None, f"payload read failed: {e}"
            except Exception as e:
                return None, f"payload read exception: {e}"

            chunk = _coerce_chunk_bytes(chunk)
            if not chunk:
                return None, "empty payload chunk"

            out.extend(chunk)
            deadline = time.monotonic() + self._payload_timeout

        if self._stop_event.is_set():
            return None, "stop requested"

        if len(out) != want:
            return None, f"incomplete payload {len(out)}/{want}"

        return bytes(out), None

    # ---------- queue ----------

    def _enqueue_frame(self, frame: bytes):
        if not frame or self._stop_event.is_set():
            return False

        frame = bytes(frame)
        n = len(frame)

        if not (14 <= n <= self._max_frame_size):
            self.frames_badlen += 1
            self._maybe_log_badlen_sample()
            return False

        with self._q_cv:
            dropped_now = 0
            while self._q and (
                    len(self._q) >= self._q_max_frames
                    or (self._q_bytes + n) > self._q_max_bytes
            ):
                old = self._q.popleft()
                self._q_bytes = max(0, self._q_bytes - len(old))
                self.frames_dropped_queuefull += 1
                dropped_now += 1

            if len(self._q) >= self._q_max_frames or (self._q_bytes + n) > self._q_max_bytes:
                self.frames_dropped_queuefull += 1
                return False

            if dropped_now:
                now = time.monotonic()
                if (now - self._drop_last_log) >= self._drop_log_every:
                    self._drop_last_log = now
                    self._log(
                        f"[{self.LOG_PREFIX}] ⚠️ queue pressure; dropped_oldest={dropped_now} "
                        f"total_dropped={self.frames_dropped_queuefull} queued={len(self._q)} bytes={self._q_bytes}"
                    )

            self._q.append(frame)
            self._q_bytes += n
            self.frames_enqueued += 1
            self._q_cv.notify()

            now = time.monotonic()
            if len(self._q) >= max(64, self._q_max_frames // 4):
                if (now - self._queue_pressure_last_log) >= self._queue_pressure_log_every:
                    self._queue_pressure_last_log = now
                    self._log(
                        f"[{self.LOG_PREFIX}] ⚠️ processor backlog building: "
                        f"queued={len(self._q)} bytes={self._q_bytes} processed={self.frames_processed}"
                    )

        return True

    def _dequeue_frame(self):
        with self._q_cv:
            while not self._q:
                if self._stop_event.is_set():
                    return None
                self._q_cv.wait(timeout=0.25)

            frame = self._q.popleft()
            self._q_bytes -= len(frame)
            if self._q_bytes < 0:
                self._q_bytes = 0
            return frame

    # ---------- threads ----------

    def _reader_loop(self):
        while not self._stop_event.is_set():
            h = None
            disconnect_reason = None

            try:
                self._log(f"[{self.LOG_PREFIX}] 🔎 Waiting for pipe: {self.pipe_name}")
                h = self._connect_pipe()
                if h is None:
                    break

                self.reconnect_count += 1
                self._header_wait_last_log = 0.0
                self._log(f"[{self.LOG_PREFIX}] ✅ Pipe connected.")

                while not self._stop_event.is_set():
                    hdr, hdr_err = self._wait_for_header(h)
                    if hdr is None:
                        disconnect_reason = hdr_err or "header wait ended"
                        break

                    pkt_len = int.from_bytes(hdr, "little", signed=False)
                    if not (14 <= pkt_len <= self._max_frame_size):
                        self.frames_badlen += 1
                        self._maybe_log_badlen_sample()
                        disconnect_reason = f"bad length prefix {pkt_len}"
                        break

                    frame, frame_err = self._read_exact_payload(h, pkt_len)
                    if frame is None:
                        disconnect_reason = frame_err or f"payload read ended for {pkt_len} bytes"
                        break

                    self.frames_read += 1
                    self._enqueue_frame(frame)
                    self._maybe_log_progress()

            except Exception as e:
                disconnect_reason = f"reader exception: {e}"
            finally:
                if h:
                    self._close_reader_owned_handle(h)

                if disconnect_reason and not self._stop_event.is_set():
                    now = time.monotonic()
                    if (now - self._disconnect_last_log) >= self._disconnect_log_every:
                        self._disconnect_last_log = now
                        self._log(f"[{self.LOG_PREFIX}] Pipe disconnected ({disconnect_reason}). Reconnecting...")

                if not self._stop_event.is_set():
                    self._stop_event.wait(0.05)

        self._connected_event.clear()
        self._log(f"[{self.LOG_PREFIX}] Reader thread stopped.")

    def _processor_loop(self):
        self._log(f"[{self.LOG_PREFIX}] Processor thread started.")

        while True:
            frame = self._dequeue_frame()
            if frame is None:
                if self._stop_event.is_set():
                    break
                continue
            if self._should_drop_local_noise_frame(frame):
                continue
            fn = self._wait_for_process_handler()
            if fn is None:
                self.frames_dropped_no_handler += 1
                self._log(
                    f"[{self.LOG_PREFIX}] ⚠️ dropping frame because router_manager.process_packet "
                    f"was unavailable during startup/shutdown."
                )
                continue

            try:
                with self._ROUTER_PROCESS_LOCK:
                    fn(frame, self.VIRTUAL_IFACE_NAME)
                self.frames_processed += 1
            except Exception as e:
                self.frames_delivery_errors += 1
                self._log(f"[{self.LOG_PREFIX}] ❗ process_packet error on {self.VIRTUAL_IFACE_NAME}: {e}")

        self._log(f"[{self.LOG_PREFIX}] Processor thread stopped.")

    # ---------- logs ----------

    def _maybe_log_progress(self):
        now = time.monotonic()
        if now - self._last_log_ts < self._log_every:
            return
        self._last_log_ts = now

        with self._q_cv:
            q_frames = len(self._q)
            q_bytes = self._q_bytes

        self._log(
            f"[{self.LOG_PREFIX}] frames_read={self.frames_read} "
            f"enq={self.frames_enqueued} ok={self.frames_processed} "
            f"badlen={self.frames_badlen} qdrop={self.frames_dropped_queuefull} "
            f"nohandler={self.frames_dropped_no_handler} derr={self.frames_delivery_errors} "
            f"q={q_frames}/{q_bytes}B"
        )

    def _maybe_log_badlen_sample(self):
        now = time.monotonic()
        if now - self._badlen_last_log >= self._badlen_log_every:
            self._badlen_last_log = now
            self._log(f"[{self.LOG_PREFIX}] ⚠️ bad length prefix count={self.frames_badlen}")

    def _log(self, msg: str):
        try:
            if self.logger:
                self.logger.log_message(msg)
                return
        except Exception:
            pass
        print(msg)


# ----------------- concrete managers -----------------


class WinDivertManager(_PipeFrameReaderBase):
    """
    Pipe reader for WinDivert frames that stays connected across idle periods
    and does not make router startup brittle.
    """
    VIRTUAL_IFACE_NAME = "WinDivertBridge"
    DEFAULT_PIPE_NAME = r"\\.\pipe\windivert_to_python"
    LOG_PREFIX = "WinDivert"

    def __init__(
        self,
        router_manager,
        code_output_manager=None,
        pipe_name=DEFAULT_PIPE_NAME,
        idle_timeout=2.0,
        payload_timeout=15.0,
        header_wait_log_every=30.0,
        handler_wait_timeout=15.0,
        max_frames_per_batch=128,
        max_bytes_per_batch=(1 << 19),
    ):
        super().__init__(
            router_manager,
            code_output_manager,
            pipe_name=pipe_name,
            idle_timeout=idle_timeout,
            payload_timeout=payload_timeout,
            header_wait_log_every=header_wait_log_every,
            handler_wait_timeout=handler_wait_timeout,
            max_frames_per_batch=max_frames_per_batch,
            max_bytes_per_batch=max_bytes_per_batch,
        )


class WinTunManager(_PipeFrameReaderBase):
    """
    Pipe reader for WintunPacket frames that stays connected across idle periods
    and does not make router startup brittle.
    """
    VIRTUAL_IFACE_NAME = "Nate's Tunnel"
    DEFAULT_PIPE_NAME = r"\\.\pipe\wintun_to_python"
    LOG_PREFIX = "WinTun"

    def __init__(
        self,
        router_manager,
        code_output_manager=None,
        *,
        pipe_name=DEFAULT_PIPE_NAME,
        idle_timeout=2.0,
        payload_timeout=15.0,
        header_wait_log_every=30.0,
        handler_wait_timeout=15.0,
        max_frames_per_batch=128,
        max_bytes_per_batch=(1 << 19),
    ):
        super().__init__(
            router_manager,
            code_output_manager,
            pipe_name=pipe_name,
            idle_timeout=idle_timeout,
            payload_timeout=payload_timeout,
            header_wait_log_every=header_wait_log_every,
            handler_wait_timeout=handler_wait_timeout,
            max_frames_per_batch=max_frames_per_batch,
            max_bytes_per_batch=max_bytes_per_batch,
        )