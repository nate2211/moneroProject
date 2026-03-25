# HyperVManager.py
import atexit
import ctypes
import os
import signal
import struct
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Optional

import pywintypes
import win32api
import win32con
import win32event
import win32file
import win32pipe
from win32con import FILE_FLAG_OVERLAPPED, GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING
from winerror import ERROR_OPERATION_ABORTED, ERROR_IO_PENDING

# Optional imports kept for compatibility with the rest of your app
from PyQt5.QtCore import QObject
from scapy.config import conf

# ----------------- small helpers -----------------

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_OpenThread = _kernel32.OpenThread
_OpenThread.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
_OpenThread.restype = ctypes.c_void_p

_CancelSyncIo = _kernel32.CancelSynchronousIo
_CancelSyncIo.argtypes = [ctypes.c_void_p]
_CancelSyncIo.restype = ctypes.c_int

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [ctypes.c_void_p]
_CloseHandle.restype = ctypes.c_int

try:
    _pywin32_cancel_io_ex = win32file.CancelIoEx
except AttributeError:
    _pywin32_cancel_io_ex = None

_CancelIoEx = _kernel32.CancelIoEx
_CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
_CancelIoEx.restype = wintypes.BOOL


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


# ----------------- logging -----------------


class CppLogger(QObject):
    def __init__(self, logger):
        super().__init__()
        self._logger = logger
        self._prefix = "[C++]"

    def set_prefix(self, prefix: str):
        self._prefix = prefix

    def log_message(self, msg: str):
        try:
            if not self._logger:
                return
            if self._prefix == "":
                formatted_message = f"{msg}"
            else:
                formatted_message = f"{self._prefix} {msg}"
            self._logger.log_message(formatted_message)
        except Exception:
            pass


# ----------------- HyperV process manager -----------------


class HyperVManager:
    """
    Runs HyperVProject.exe as a subprocess and pipes output to the logger.

    Main goals:
      - no noisy/random exit-code logging on intentional shutdown
      - idempotent teardown
      - consistent Windows process-group handling
      - pipe close before process break/terminate
      - no Python buffered file object for named-pipe writes
    """

    _EXPECTED_WINDOWS_EXITS = {
        0,
        1,
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
    ):
        self._logger = CppLogger(logger)
        self._exe_path = self._resolve_exe_path(exe_name)
        self._linux_dir_arg = str(linux_dir_arg)

        self._proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None

        self._proc_lock = threading.RLock()
        self._pipe_lock = threading.RLock()

        # Win32 pipe handle, not Python file object
        self._pipe_handle = None

        self._stop_timeout_soft = float(stop_timeout_soft)
        self._stop_timeout_hard = float(stop_timeout_hard)

        self._stopping = False
        self._started_by_us = False
        self._suppress_exit_log = False
        self._last_exit_code: Optional[int] = None
        self._exit_logged = False

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

    def _log_exit(self, rc: Optional[int]) -> None:
        with self._proc_lock:
            if self._exit_logged:
                return
            self._exit_logged = True
            self._last_exit_code = rc

        if rc is None:
            return

        if self._suppress_exit_log or (self._stopping and self._is_expected_exit(rc)):
            self._logger.log_message(f"[HyperV] Process stopped cleanly (exit={rc}).")
            return

        if self._stopping:
            self._logger.log_message(f"[HyperV] Process stopped during teardown (exit={rc}).")
            return

        self._logger.log_message(f"[HyperV] Process exited unexpectedly with code {rc}.")

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
            self._log_exit(rc)

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

    def _close_packet_pipe_locked(self, graceful: bool) -> None:
        h = self._pipe_handle
        self._pipe_handle = None
        if not h:
            return

        if graceful:
            try:
                win32file.WriteFile(h, struct.pack("<I", 0))
            except Exception:
                pass

        _close_win_handle(h)

    def _ensure_packet_pipe_locked(self, connect_timeout: float):
        deadline = time.time() + max(0.0, float(connect_timeout))
        while self._pipe_handle is None:
            try:
                win32pipe.WaitNamedPipe(self._PACKET_PIPE_NAME, 250)
            except pywintypes.error as e:
                if time.time() >= deadline:
                    raise TimeoutError(f"Could not wait for pipe: {e}")
                time.sleep(0.05)
                continue

            try:
                self._pipe_handle = win32file.CreateFile(
                    self._PACKET_PIPE_NAME,
                    GENERIC_WRITE,
                    0,
                    None,
                    OPEN_EXISTING,
                    0,
                    None,
                )
                return
            except pywintypes.error as e:
                if time.time() >= deadline:
                    raise TimeoutError(f"Could not connect: {e}")
                time.sleep(0.05)

    # ---------- public API ----------

    def start(self) -> bool:
        with self._proc_lock:
            if self._proc and self._proc.poll() is None:
                self._logger.log_message("[HyperV] Process already running.")
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

                self._logger.log_message(f"[HyperV] Started {self._exe_path.name} (pid {self._proc.pid})")
                return True

            except Exception as e:
                self._proc = None
                self._reader_thread = None
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

    def close_pipe(self, graceful: bool = True) -> None:
        with self._pipe_lock:
            self._close_packet_pipe_locked(graceful)

    def teardown(self) -> None:
        with self._proc_lock:
            proc = self._proc
            if not proc:
                return
            if self._stopping:
                return
            self._stopping = True
            self._suppress_exit_log = True

        try:
            self.close_pipe(graceful=True)
        except Exception:
            pass

        # Step 1: let the app exit on stdin if it supports that
        self.send_enter()
        rc = self._wait_proc(proc, self._stop_timeout_soft)
        if rc is not None:
            self._safe_close_stdin()
        else:
            # Step 2: ask the process group nicely
            if os.name == "nt":
                try:
                    os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
                except Exception:
                    pass
                rc = self._wait_proc(proc, self._stop_timeout_soft)

            # Step 3: terminate, then kill if needed
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
        frame = _normalize_pipe_payload(packet)
        if not frame:
            self._logger.log_message("[HyperV][PIPE] Could not normalize packet to bytes")
            return False

        payload = struct.pack("<I", len(frame)) + frame

        with self._pipe_lock:
            try:
                self._ensure_packet_pipe_locked(connect_timeout)
            except Exception as e:
                self._logger.log_message(f"[HyperV][PIPE] Could not connect: {e}")
                return False

            try:
                win32file.WriteFile(self._pipe_handle, payload)
                return True
            except Exception as e:
                self._close_packet_pipe_locked(graceful=False)
                self._logger.log_message(f"[HyperV][PIPE] Write failed, handle reset: {e}")
                return False


# ----------------- shared pipe reader base -----------------


class _PipeFrameReaderBase:
    """
    Common cancel-safe BYTE-mode named-pipe reader.
    The reader thread is the sole owner/closer of ph/ev/ovl.
    stop() only signals + cancels + nudges.
    """

    VIRTUAL_IFACE_NAME = "VirtualPipe"
    DEFAULT_PIPE_NAME = r"\\.\pipe\virtual_to_python"
    LOG_PREFIX = "Pipe"

    def __init__(
        self,
        router_manager,
        code_output_manager=None,
        *,
        pipe_name: str,
        idle_timeout: float = 2.0,
        max_frames_per_batch: int = 1024,
        max_bytes_per_batch: int = (1 << 20),
    ):
        conf.max_list_count = 2048

        self.router_manager = router_manager
        self.logger = getattr(router_manager, "router_logger", None)
        self.code_output_manager = code_output_manager
        self.pipe_name = pipe_name

        self._pipe_handle = None
        self._ovl_event = None
        self._ovl = None

        self._stop_event = threading.Event()
        self._reader_thread = None
        self._reader_tid = None

        self._idle_timeout = float(idle_timeout)
        self._max_frames = int(max_frames_per_batch)
        self._max_bytes = int(max_bytes_per_batch)

        self._hdl_lock = threading.Lock()

        self.frames_read = 0
        self.frames_processed = 0
        self.frames_badlen = 0

        self._last_log_ts = 0.0
        self._log_every = 0.5
        self._quiet_log_after = 2.0

        self._badlen_last_log = 0.0
        self._badlen_log_every = 5.0

        # kept for compatibility with external code that may inspect these
        self._frag_db = {}
        self._frag_timeout_sec = 5.0
        self._frag_max_streams = 1024
        self._frag_max_per_stream = 128

        self._frag6_db = {}
        self._frag6_timeout_sec = 5.0
        self._frag6_max_streams = 1024
        self._frag6_max_per_stream = 128

    def start(self):
        if self._reader_thread and self._reader_thread.is_alive():
            return
        self._log(f"[{self.LOG_PREFIX}] Starting manager (immediate processing, no queue)...")
        self._stop_event.clear()
        self._reader_thread = threading.Thread(
            target=self._pipe_reader_loop,
            name=f"{self.LOG_PREFIX}Reader",
            daemon=True,
        )
        self._reader_thread.start()

    def stop(self):
        if not self._reader_thread or not self._reader_thread.is_alive():
            self._log(f"[{self.LOG_PREFIX}] Manager already stopped.")
            return

        self._log(f"[{self.LOG_PREFIX}] Stopping manager...")
        self._stop_event.set()
        self._cancel_pending_io()

        try:
            with self._hdl_lock:
                ev = self._ovl_event
            if ev:
                win32event.SetEvent(ev)
        except Exception:
            pass

        self._unblock_pipe_wait()

        try:
            self._reader_thread.join(timeout=5.0)
        except Exception:
            pass

        self._log(f"[{self.LOG_PREFIX}] Manager stopped successfully.")

    def _cancel_pending_io(self):
        try:
            with self._hdl_lock:
                h = self._pipe_handle
                ovl = self._ovl
                tid = self._reader_tid
        except Exception:
            h = ovl = tid = None

        if h and ovl:
            try:
                if _pywin32_cancel_io_ex:
                    _pywin32_cancel_io_ex(h, ovl)
                else:
                    _CancelIoEx(int(h), None)
            except Exception:
                pass

        if tid:
            try:
                th = _OpenThread(THREAD_QUERY_LIMITED_INFORMATION, False, tid)
                if th:
                    try:
                        _CancelSyncIo(th)
                    finally:
                        _CloseHandle(th)
            except Exception:
                pass

    def _pipe_reader_loop(self):
        try:
            self._reader_tid = win32api.GetCurrentThreadId()
        except Exception:
            self._reader_tid = None

        while not self._stop_event.is_set():
            ph = None
            ev = None
            ovl = None
            try:
                try:
                    win32pipe.WaitNamedPipe(self.pipe_name, 250)
                except pywintypes.error as e:
                    if e.winerror == 2:
                        self._stop_event.wait(0.10)
                        continue
                    self._stop_event.wait(0.05)
                    continue

                if self._stop_event.is_set():
                    break

                self._log(f"[{self.LOG_PREFIX}] 🔎 Connecting to pipe: {self.pipe_name}")
                ph = win32file.CreateFile(
                    self.pipe_name,
                    GENERIC_READ,
                    0,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    None,
                )
                self._log(f"[{self.LOG_PREFIX}] ✅ Pipe connected (OVERLAPPED, BYTE mode).")

                try:
                    PIPE_READMODE_BYTE = 0x00000000
                    win32pipe.SetNamedPipeHandleState(ph, PIPE_READMODE_BYTE, None, None)
                except pywintypes.error:
                    pass

                ev = win32event.CreateEvent(None, True, False, None)
                ovl = win32file.OVERLAPPED()
                ovl.hEvent = ev

                with self._hdl_lock:
                    self._pipe_handle = ph
                    self._ovl_event = ev
                    self._ovl = ovl

                while not self._stop_event.is_set():
                    keep = self._read_and_process_frames_overlapped(
                        ph,
                        ev,
                        ovl,
                        idle_timeout=self._idle_timeout,
                        max_frames=self._max_frames,
                        max_bytes=self._max_bytes,
                    )
                    if not keep:
                        break

            except pywintypes.error as e:
                if not self._stop_event.is_set():
                    self._log(f"[{self.LOG_PREFIX}] Connection/read error ({e.winerror}). Retrying...")
                self._stop_event.wait(0.05)
            except Exception as e:
                if not self._stop_event.is_set():
                    self._log(f"[{self.LOG_PREFIX}] ❗ Reader error: {e}. Retrying...")
                self._stop_event.wait(0.05)
            finally:
                with self._hdl_lock:
                    self._pipe_handle = None
                    self._ovl_event = None
                    self._ovl = None

                if ph:
                    _close_win_handle(ph)
                    ph = None
                    if not self._stop_event.is_set():
                        self._log(f"[{self.LOG_PREFIX}] Pipe disconnected.")

                if ev:
                    _close_win_handle(ev)
                    ev = None

                ovl = None

    def _read_and_process_frames_overlapped(self, ph, ev, ovl, idle_timeout=2.0, max_frames=1024, max_bytes=(1 << 20)):
        buf = bytearray()
        frames_this_batch = 0
        bytes_read_total = 0
        deadline = time.monotonic() + idle_timeout
        max_frames_per_pass = 2024

        last_progress_ts = time.monotonic()
        last_frames_read = self.frames_read

        def _reset_event():
            if ev:
                try:
                    win32event.ResetEvent(ev)
                except Exception:
                    pass

        while (
            not self._stop_event.is_set()
            and frames_this_batch < max_frames
            and bytes_read_total < max_bytes
            and time.monotonic() < deadline
        ):
            try:
                _reset_event()
                data = None

                try:
                    _hr, data = win32file.ReadFile(ph, win32file.AllocateReadBuffer(65536), ovl)
                except pywintypes.error as e:
                    if e.winerror != ERROR_IO_PENDING:
                        return False

                    ms = max(1, int((deadline - time.monotonic()) * 1000))
                    rc = win32event.WaitForSingleObject(ev, ms)

                    if rc == WAIT_TIMEOUT:
                        self._maybe_log_idle(frames_this_batch, bytes_read_total, buf_len=len(buf))
                        continue

                    if self._stop_event.is_set():
                        return False

                    try:
                        _hr, data = win32file.GetOverlappedResult(ph, ovl, False)
                    except pywintypes.error as ge:
                        if ge.winerror in (ERROR_OPERATION_ABORTED, 995):
                            return False
                        if ge.winerror == ERROR_IO_PENDING:
                            continue
                        return False

                if isinstance(data, str):
                    data = data.encode("latin1")
                elif isinstance(data, memoryview):
                    data = data.tobytes()
                elif isinstance(data, bytearray):
                    data = bytes(data)

                if not data:
                    return False

                buf.extend(data)
                bytes_read_total += len(data)
                deadline = time.monotonic() + idle_timeout

            except Exception:
                return False

            parsed_this_pass = 0
            while parsed_this_pass < max_frames_per_pass:
                if self._stop_event.is_set():
                    return False
                if len(buf) < 4:
                    break

                pkt_len = int.from_bytes(buf[0:4], "little", signed=False)

                if not (14 <= pkt_len <= 65535):
                    del buf[:4]
                    self.frames_badlen += 1
                    self._maybe_log_badlen_sample()
                    continue

                if len(buf) < 4 + pkt_len:
                    break

                packet_bytes = bytes(buf[4: 4 + pkt_len])
                del buf[:4 + pkt_len]

                self.frames_read += 1
                parsed_this_pass += 1
                frames_this_batch += 1

                now = time.monotonic()
                if self.frames_read != last_frames_read:
                    last_progress_ts = now
                    last_frames_read = self.frames_read

                if packet_bytes:
                    try:
                        self.router_manager.process_packet(packet_bytes, self.VIRTUAL_IFACE_NAME)
                        self.frames_processed += 1
                    except Exception as e:
                        self._log(f"[{self.LOG_PREFIX}] ❗ process_packet error: {e}")

            self._maybe_log_progress(frames_this_batch, bytes_read_total, buf_len=len(buf), last_progress_ts=last_progress_ts)

        return True

    def _maybe_log_progress(self, frames_this_batch, bytes_read_total, buf_len, last_progress_ts):
        now = time.monotonic()
        if now - self._last_log_ts < self._log_every:
            return
        self._last_log_ts = now
        stalled = (now - last_progress_ts) >= self._quiet_log_after
        if stalled or buf_len > 0:
            self._log(
                f"[{self.LOG_PREFIX}] Reader: frames+={frames_this_batch} bytes+={bytes_read_total} "
                f"buf={buf_len}B {'(stalled?)' if stalled else ''}"
            )

    def _maybe_log_idle(self, frames_this_batch, bytes_read_total, buf_len):
        now = time.monotonic()
        if now - self._last_log_ts >= self._log_every:
            self._last_log_ts = now
            self._log(
                f"[{self.LOG_PREFIX}] Reader idle: frames+={frames_this_batch} bytes+={bytes_read_total} buf={buf_len}B"
            )

    def _maybe_log_badlen_sample(self):
        now = time.monotonic()
        if now - self._badlen_last_log >= self._badlen_log_every:
            self._badlen_last_log = now
            self._log(f"[{self.LOG_PREFIX}] ⚠️ bad length prefix count={self.frames_badlen}")

    def _unblock_pipe_wait(self):
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
            _close_win_handle(h)
        except pywintypes.error:
            pass

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
    Pipe reader for WinDivert frames that processes packets immediately (no queue).
    """
    VIRTUAL_IFACE_NAME = "WinDivertBridge"
    DEFAULT_PIPE_NAME = r"\\.\pipe\windivert_to_python"
    LOG_PREFIX = "WinDivert"

    def __init__(self, router_manager, code_output_manager, pipe_name=DEFAULT_PIPE_NAME,
                 idle_timeout=2.0, max_frames_per_batch=1024, max_bytes_per_batch=(1 << 20)):
        super().__init__(
            router_manager,
            code_output_manager,
            pipe_name=pipe_name,
            idle_timeout=idle_timeout,
            max_frames_per_batch=max_frames_per_batch,
            max_bytes_per_batch=max_bytes_per_batch,
        )


class WinTunManager(_PipeFrameReaderBase):
    """
    Pipe reader for WintunPacket frames that processes packets immediately (no queue).
    """
    VIRTUAL_IFACE_NAME = "Nate's Tunnel"
    DEFAULT_PIPE_NAME = r"\\.\pipe\wintun_to_python"
    LOG_PREFIX = "WinTun"

    def __init__(self, router_manager, code_output_manager=None, *,
                 pipe_name=DEFAULT_PIPE_NAME,
                 idle_timeout=2.0,
                 max_frames_per_batch=1024,
                 max_bytes_per_batch=(1 << 20)):
        super().__init__(
            router_manager,
            code_output_manager,
            pipe_name=pipe_name,
            idle_timeout=idle_timeout,
            max_frames_per_batch=max_frames_per_batch,
            max_bytes_per_batch=max_bytes_per_batch,
        )