# HyperVManager.py
import ctypes
import gc
import io
import os
import pstats
import queue
import sys
import atexit
import signal
import subprocess
import threading
from ctypes import wintypes
from pathlib import Path
from typing import Any, Optional
import cProfile
import win32con
import win32event
import win32file
import win32pipe
import pywintypes
import time
import struct
from PyQt5.QtCore import QObject, pyqtSignal, Qt, QCoreApplication
from scapy.config import conf
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
import win32api
from winerror import ERROR_OPERATION_ABORTED, ERROR_IO_PENDING
from win32con import GENERIC_READ, OPEN_EXISTING, FILE_FLAG_OVERLAPPED
from tools.pythontools import yield_no_gil

class CppLogger(QObject):
    def __init__(self, logger):
        super().__init__()
        self._logger = logger
        self._prefix = "[C++]"

    def set_prefix(self, prefix: str):
        self._prefix = prefix

    def log_message(self, msg: str):
        if self._logger:
            formatted_message = ""
            if self._prefix == "":
                formatted_message = f"{msg}"
            else:
                formatted_message = f"{self._prefix} {msg}"
            self._logger.log_message(formatted_message)


class HyperVManager:
    """
    Runs HyperVProject.exe as a subprocess and pipes output to the logger.
    """

    def __init__(
        self,
        logger: Any,
        exe_name: str = "tools/Linux/HyperVProject/HyperVProject.exe",
        linux_dir_arg: str = ".",           # passed to the exe, like your CLI example
    ):
        self._logger = CppLogger(logger)
        self._exe_path = self._resolve_exe_path(exe_name)
        self._linux_dir_arg = str(linux_dir_arg)

        self._proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None


        atexit.register(self.teardown)

    # ---------- helpers ----------

    def _resolve_exe_path(self, exe_name: str) -> Path:
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            base_path = Path(sys._MEIPASS)
        else:
            base_path = Path(__file__).parent
        return base_path.joinpath(exe_name)

    def _pump_stdout(self):
        assert self._proc is not None
        stream = self._proc.stdout
        if not stream:
            return

        for line in stream:
            line = line.rstrip("\r\n")
            if line:
                self._logger.log_message(line)

        # Wait for real exit code after stream ends
        rc = self._proc.wait()
        self._logger.log_message(f"process exited with code {rc}")

    # ---------- public API ----------

    def start(self) -> bool:
        if self._proc and self._proc.poll() is None:
            self._logger.log_message("Process already running.")
            return True

        if not self._exe_path.exists():
            self._logger.log_message(f"Error: executable not found at {self._exe_path}")
            return False

        try:
            creationflags = 0
            if os.name == "nt":

                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            self._proc = subprocess.Popen(
                [str(self._exe_path), self._linux_dir_arg],
                cwd=str(self._exe_path.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,  # line-buffered
                creationflags=creationflags,
            )

            self._reader_thread = threading.Thread(target=self._pump_stdout, daemon=True)
            self._reader_thread.start()

            self._logger.log_message(f"Started {self._exe_path.name} (pid {self._proc.pid})")
            return True

        except Exception as e:
            self._logger.log_message(f"Error starting process: {e}")
            return False

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def send_enter(self) -> None:
        """
        Signals the app to continue/quit where it waits on std::cin.get().
        """
        if not self._proc or not self._proc.stdin:
            return
        try:
            self._proc.stdin.write("\n")
            self._proc.stdin.flush()
        except Exception:
            pass

    def teardown(self) -> None:

        try:
            self.close_pipe(graceful=True)
        except Exception:
            pass
        proc = self._proc
        if not proc:
            self._logger.log_message("Teardown called with no running process.")
            return

        # 1) Gentle: send ENTER to stdin (the exe waits on std::cin.get())
        self.send_enter()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

        # 2) Ask nicely on Windows: CTRL_BREAK_EVENT to the process group
        if proc.poll() is None and os.name == "nt":
            try:
                os.kill(proc.pid, signal.CTRL_BREAK_EVENT)  # requires CREATE_NEW_PROCESS_GROUP
                proc.wait(timeout=5)
            except Exception:
                pass

        # 3) Terminate/kill if still alive
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        # Join reader thread
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=1)

        self._proc = None
        self._reader_thread = None
        self._logger.log_message("Successfully tore down the virtual machine and cleaned up.")

    def close_pipe(self, graceful: bool = True) -> None:
        """
        Gracefully disconnect from \\\\.\\pipe\\vmrouter_packets and drop the handle.
        If 'graceful' is True, send a 0-length frame first so the C++ reader
        exits its loop without error.
        """
        import struct
        if not hasattr(self, "_pipe_lock"):
            return
        with self._pipe_lock:
            h = getattr(self, "_pipe_handle", None)
            if not h:
                return
            if graceful:
                try:
                    # Our wire format is <uint32 LE len> + data; len=0 asks server to stop reading.
                    h.write(struct.pack('<I', 0))
                    h.flush()
                except Exception:
                    pass
            try:
                h.close()
            except Exception:
                pass
            self._pipe_handle = None
    def send_packet(self, packet, connect_timeout: float = 3.0) -> bool:
        PIPE_NAME = r'\\.\pipe\vmrouter_packets'

        # --- normalize input to raw bytes ---
        def _to_bytes(obj):
            if obj is None:
                return None

            if isinstance(obj, (bytes, bytearray, memoryview)):
                return bytes(obj)

            if isinstance(obj, str):
                s = obj.strip().lower()
                for ch in (" ", ":", "-", "\n", "\r", "\t"):
                    s = s.replace(ch, "")
                if s.startswith("0x"):
                    s = s[2:]
                try:
                    return bytes.fromhex(s)
                except ValueError:
                    return None

            if isinstance(obj, (list, tuple)):
                try:
                    return bytes(obj)
                except Exception:
                    return None

            if hasattr(obj, "original"):
                try:
                    return bytes(obj.original)
                except Exception:
                    pass

            for meth in ("build", "to_bytes"):
                if hasattr(obj, meth):
                    try:
                        b = getattr(obj, meth)()
                        if not isinstance(b, (bytes, bytearray, memoryview)):
                            b = bytes(b)
                        return bytes(b)
                    except Exception:
                        pass

            try:
                return bytes(obj)
            except Exception:
                return None

        frame = _to_bytes(packet)
        if not frame:
            self._logger.log_message("[PYPIPE] Could not normalize packet to bytes")
            return False

        import struct, time
        payload = struct.pack('<I', len(frame)) + frame

        # Cache a handle/file object across calls
        if not hasattr(self, "_pipe_handle"):
            self._pipe_handle = None
        if not hasattr(self, "_pipe_lock"):
            import threading
            self._pipe_lock = threading.Lock()

        with self._pipe_lock:
            deadline = time.time() + max(0.0, connect_timeout)

            # Connect if needed (simple retry loop)
            while self._pipe_handle is None:
                try:
                    # Opening a named pipe with built-in open() works once the server is ready
                    self._pipe_handle = open(PIPE_NAME, "wb", buffering=0)
                except Exception as e:
                    if time.time() >= deadline:
                        self._logger.log_message(f"[PYPIPE] Could not connect to pipe: {e}")
                        return False
                    time.sleep(0.1)
                    continue

            # Write the payload
            try:
                self._pipe_handle.write(payload)
                self._pipe_handle.flush()
                return True
            except Exception as e:
                # Likely broken pipe; drop handle so we reconnect next time
                try:
                    if self._pipe_handle:
                        self._pipe_handle.close()
                except Exception:
                    pass
                finally:
                    self._pipe_handle = None

                self._logger.log_message(f"[PYPIPE] Write failed (handle reset): {e}")
                return False


# --- Kernel32 bindings (you already had these) ---
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

# Prefer pywin32 CancelIoEx; fall back to ctypes if needed
try:
    _pywin32_cancel_io_ex = win32file.CancelIoEx
except AttributeError:
    _pywin32_cancel_io_ex = None

_CancelIoEx = _kernel32.CancelIoEx
_CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]  # (HANDLE, LPOVERLAPPED)
_CancelIoEx.restype = wintypes.BOOL

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102

THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_ALL_ACCESS = 0x1FFFFF


class WinDivertManager:
    """
    Pipe reader for WinDivert frames that processes packets immediately (no queue).
    - Overlapped, cancelable reads (true CancelIoEx on stop)
    - Backpressure: we only read when we're ready; C++ will batch & time out safely
    - Reader thread is the sole owner/closer of handles (no double-close)
    - Aligned with C++ server: PIPE_TYPE_BYTE (length-prefixed frames)
    """
    VIRTUAL_IFACE_NAME = "WinDivertBridge"
    DEFAULT_PIPE_NAME = r'\\.\pipe\windivert_to_python'

    def __init__(self, router_manager, code_output_manager, pipe_name=DEFAULT_PIPE_NAME,
                 idle_timeout=2.0, max_frames_per_batch=1024, max_bytes_per_batch=(1 << 20)):

        # Allow deep chains of IPv6 ext headers without Scapy aborts.
        conf.max_list_count = 2048

        self.router_manager = router_manager
        self.logger = router_manager.router_logger
        self.code_output_manager = code_output_manager
        self.pipe_name = pipe_name

        # handles/state (owned/closed by reader thread)
        self._pipe_handle = None
        self._ovl_event = None
        self._ovl = None

        self._stop_event = threading.Event()
        self._reader_thread = None
        self._reader_tid = None

        # tuning
        self._idle_timeout = float(idle_timeout)
        self._max_frames = int(max_frames_per_batch)
        self._max_bytes = int(max_bytes_per_batch)

        # avoid races on shared handles
        self._hdl_lock = threading.Lock()

        # stats
        self.frames_read = 0
        self.frames_processed = 0
        self.frames_badlen = 0

        # light telemetry
        self._last_log_ts = 0.0
        self._log_every = 0.5        # seconds - fine-grained beacons
        self._quiet_log_after = 2.0  # if no frames for this long, log why

        # IPv4/IPv6 defrag placeholders (kept for parity; router may use them later)
        self._frag_db = {}
        self._frag_timeout_sec = 5.0
        self._frag_max_streams = 1024
        self._frag_max_per_stream = 128

        self._frag6_db = {}
        self._frag6_timeout_sec = 5.0
        self._frag6_max_streams = 1024
        self._frag6_max_per_stream = 128

        # Rate-limited malformed logs
        self._ipv6_bad_counter = 0
        self._ipv6_bad_last_log = 0.0
        self._ipv6_bad_log_every = 5.0

        self._ipv4_bad_counter = 0
        self._ipv4_bad_last_log = 0.0
        self._ipv4_bad_log_every = 5.0

    # ---------------- public control ----------------

    def start(self):
        if self._reader_thread and self._reader_thread.is_alive():
            return
        self.logger.log_message("[WinDivert] Starting manager (immediate processing, no queue)...")
        self._stop_event.clear()

        self._reader_thread = threading.Thread(
            target=self._pipe_reader_loop, name="WinDivertReader", daemon=True
        )
        self._reader_thread.start()

    def stop(self):
        """Signal stop and attempt a graceful shutdown to prevent race conditions."""
        if not self._reader_thread or not self._reader_thread.is_alive():
            self.logger.log_message("[WinDivert] Manager already stopped.")
            return
        self.logger.log_message("[WinDivert] Stopping manager...")

        self._stop_event.set()

        # Try to cancel any pending overlapped ReadFile cleanly
        self._cancel_pending_io()

        # Also poke the event so a wait unblocks immediately
        try:
            with self._hdl_lock:
                ev = self._ovl_event
            if ev:
                win32event.SetEvent(ev)
        except Exception:
            pass

        # If the server is waiting for a client, connect once to break WaitNamedPipe/CreateFile races
        self._unblock_pipe_wait()

        self._reader_thread.join(timeout=5.0)
        self.logger.log_message("[WinDivert] Manager stopped successfully.")
        gc.collect()

    # ---------------- core: read & process immediately ----------------
    def _read_and_process_frames_overlapped(self, ph, ev, ovl,
                                            idle_timeout=2.0, max_frames=1024, max_bytes=(1 << 20)):
        buf = bytearray()
        frames_this_batch = 0
        bytes_read_total = 0
        deadline = time.monotonic() + idle_timeout
        MAX_FRAMES_PER_PASS = 2024

        last_progress_ts = time.monotonic()
        last_frames_read = self.frames_read

        def _reset_event():
            if ev:
                win32event.ResetEvent(ev)

        while (not self._stop_event.is_set()
               and frames_this_batch < max_frames
               and bytes_read_total < max_bytes
               and time.monotonic() < deadline):

            # --- ISSUE OVERLAPPED READ (BYTE mode; C++ length-prefixed) ---
            try:
                _reset_event()
                try:
                    hr, data = win32file.ReadFile(ph, win32file.AllocateReadBuffer(65536), ovl)
                except pywintypes.error as e:
                    if e.winerror != ERROR_IO_PENDING:
                        # hard failure: disconnect and reconnect outside
                        return False
                    ms = max(1, int((deadline - time.monotonic()) * 1000))
                    rc = win32event.WaitForSingleObject(ev, ms)
                    if rc == WAIT_TIMEOUT:
                        # keep the loop alive; micro-idle beacon if needed
                        self._maybe_log_idle(frames_this_batch, bytes_read_total, buf_len=len(buf))
                        continue
                    try:
                        hr, data = win32file.GetOverlappedResult(ph, ovl, True)
                    except pywintypes.error as ge:
                        # 995 = ERROR_OPERATION_ABORTED when we cancelled at stop()
                        if ge.winerror in (ERROR_OPERATION_ABORTED, 995):
                            return False
                        return False

                if isinstance(data, str):
                    # rare pywin32 quirk: immediate completion returns a str
                    # latin-1 is a 1:1 mapping 0..255 -> U+0000..U+00FF (lossless for raw bytes)
                    data = data.encode("latin1")
                elif isinstance(data, memoryview):
                    data = data.tobytes()
                elif isinstance(data, bytearray):
                    data = bytes(data)
                if not data:
                    # Peer closed or end of stream
                    return False

                buf.extend(data)
                bytes_read_total += len(data)
                deadline = time.monotonic() + idle_timeout

            except Exception:
                # Any unexpected error → force reconnect
                return False

            # --- FAST EXTRACT: LEN(4 LE) + PAYLOAD ---
            parsed_this_pass = 0
            while parsed_this_pass < MAX_FRAMES_PER_PASS:
                if self._stop_event.is_set():
                    return False
                if len(buf) < 4:
                    break

                pkt_len = int.from_bytes(buf[0:4], "little", signed=False)

                # BYTE-mode sanity: WinDivert network frames are 20..65535-ish
                if not (14 <= pkt_len <= 65535):
                    del buf[:4]  # drop bogus length, attempt resync next iteration
                    self.frames_badlen += 1
                    self._maybe_log_badlen_sample()
                    continue

                if len(buf) < 4 + pkt_len:
                    break  # need more bytes

                packet_bytes = bytes(buf[4: 4 + pkt_len])
                del buf[:4 + pkt_len]

                self.frames_read += 1
                parsed_this_pass += 1
                frames_this_batch += 1

                # Progress beacon (matches C++ micro-heartbeats spirit)
                now = time.monotonic()
                if self.frames_read != last_frames_read:
                    last_progress_ts = now
                    last_frames_read = self.frames_read

                if packet_bytes:
                    self.router_manager.process_packet(packet_bytes, self.VIRTUAL_IFACE_NAME)

            # Lightweight periodic status (no spam)
            self._maybe_log_progress(frames_this_batch, bytes_read_total, buf_len=len(buf), last_progress_ts=last_progress_ts)

        return True

    # ---------------- reader thread ----------------

    def _pipe_reader_loop(self):
        try:
            self._reader_tid = win32api.GetCurrentThreadId()
        except Exception:
            self._reader_tid = None

        while not self._stop_event.is_set():
            ph = ev = ovl = None
            try:
                # Reconnect loop (small wait keeps UI logs responsive)
                try:
                    win32pipe.WaitNamedPipe(self.pipe_name, 250)
                except pywintypes.error as e:
                    # 2 = ERROR_FILE_NOT_FOUND (server not up yet)
                    if e.winerror == 2:
                        self._stop_event.wait(0.10)
                        continue
                    # Anything else: brief backoff
                    self._stop_event.wait(0.05)
                    continue

                if self._stop_event.is_set():
                    break

                self.logger.log_message(f"[WinDivert] 🔎 Connecting to pipe: {self.pipe_name}")
                ph = win32file.CreateFile(
                    self.pipe_name,
                    win32file.GENERIC_READ,  # client reads; server is PIPE_ACCESS_OUTBOUND
                    0, None,
                    win32file.OPEN_EXISTING,
                    win32con.FILE_FLAG_OVERLAPPED,
                    None
                )
                self.logger.log_message("[WinDivert] ✅ Pipe connected (OVERLAPPED, BYTE mode).")

                # Server is PIPE_TYPE_BYTE; setting MESSAGE mode would fail (OK).
                # We *could* set PIPE_READMODE_BYTE explicitly (0), but it’s already byte.
                try:
                    PIPE_READMODE_BYTE = 0x00000000
                    win32pipe.SetNamedPipeHandleState(ph, PIPE_READMODE_BYTE, None, None)
                except pywintypes.error:
                    # Ignore; byte mode is enforced by server type.
                    pass

                # Prepare one reusable OVERLAPPED for all reads
                ev = win32event.CreateEvent(None, True, False, None)
                ovl = win32file.OVERLAPPED()
                ovl.hEvent = ev

                with self._hdl_lock:
                    self._pipe_handle = ph
                    self._ovl_event = ev
                    self._ovl = ovl

                while not self._stop_event.is_set():
                    keep = self._read_and_process_frames_overlapped(
                        ph, ev, ovl,
                        idle_timeout=self._idle_timeout,
                        max_frames=self._max_frames,
                        max_bytes=self._max_bytes
                    )
                    if not keep:
                        break

            except pywintypes.error as e:
                if not self._stop_event.is_set():
                    self.logger.log_message(f"[WinDivert] Connection/read error ({e.winerror}). Retrying...")
                self._stop_event.wait(0.05)
            except Exception as e:
                if not self._stop_event.is_set():
                    self.logger.log_message(f"[WinDivert] ❗ Reader error: {e}. Retrying...")
                self._stop_event.wait(0.05)
            finally:
                with self._hdl_lock:
                    self._pipe_handle = None
                    self._ovl_event = None
                    self._ovl = None

                if ph:
                    try:
                        win32file.CloseHandle(ph)
                    except Exception:
                        pass
                    ph = None
                    if not self._stop_event.is_set():
                        self.logger.log_message("[WinDivert] Pipe disconnected.")
                if ev:
                    try:
                        win32api.CloseHandle(ev)
                    except Exception:
                        pass
                    ev = None
                ovl = None

    # ---------------- cancellation & logging helpers ----------------

    def _cancel_pending_io(self):
        """Cancel outstanding overlapped ReadFile cleanly (matches C++ overlapped writes)."""
        try:
            with self._hdl_lock:
                h = self._pipe_handle
                ovl = self._ovl
                tid = self._reader_tid
        except Exception:
            h = ovl = tid = None

        # Best: CancelIoEx on the specific overlapped
        if h and ovl:
            try:
                if _pywin32_cancel_io_ex:
                    _pywin32_cancel_io_ex(h, ovl)   # pywin32 path
                else:
                    # ctypes fallback
                    _CancelIoEx(int(h), None)
            except Exception:
                pass

        # Extra: cancel synchronous I/O if any (safety net)
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

        # Wake up any waiters on the event
        try:
            with self._hdl_lock:
                ev = self._ovl_event
            if ev:
                win32event.SetEvent(ev)
        except Exception:
            pass

    def _maybe_log_progress(self, frames_this_batch, bytes_read_total, buf_len, last_progress_ts):
        now = time.monotonic()
        if now - self._last_log_ts < self._log_every:
            return
        self._last_log_ts = now

        # If we’re actively draining, log at a low cadence
        # If we’re stalled or idle, log a hint for visibility
        stalled = (now - last_progress_ts) >= self._quiet_log_after
        if stalled or buf_len > 0:
            self.logger.log_message(
                f"[WinDivert] Reader: frames+={frames_this_batch} bytes+={bytes_read_total} "
                f"buf={buf_len}B {'(stalled?)' if stalled else ''}"
            )

    def _maybe_log_idle(self, frames_this_batch, bytes_read_total, buf_len):
        # Called on read timeouts to provide a lightweight beacon
        now = time.monotonic()
        if now - self._last_log_ts >= self._log_every:
            self._last_log_ts = now
            self.logger.log_message(
                f"[WinDivert] Reader idle: frames+={frames_this_batch} bytes+={bytes_read_total} buf={buf_len}B"
            )

    def _maybe_log_badlen_sample(self):
        now = time.monotonic()
        if now - self._ipv4_bad_last_log >= self._ipv4_bad_log_every:
            self._ipv4_bad_last_log = now
            self.logger.log_message(f"[WinDivert] ⚠️ bad length prefix count={self.frames_badlen}")

    # ---------------- misc ----------------
    def _unblock_pipe_wait(self):
        # If server is waiting for a client, a quick connect/close can break WaitNamedPipe races.
        try:
            h = win32file.CreateFile(
                self.pipe_name, win32file.GENERIC_READ, 0, None,
                win32file.OPEN_EXISTING, 0, None
            )
            win32file.CloseHandle(h)
        except pywintypes.error:
            pass
class WinTunManager:
    """
    Pipe reader for WintunPacket frames that processes packets immediately (no queue).

    - Connects to C++ WintunPacket named-pipe server (PIPE_TYPE_BYTE, length-prefixed frames)
    - Overlapped, cancelable reads with true CancelIoEx on stop
    - Applies backpressure by reading only as fast as we can process
    - Reader thread owns/cleans up the OS handles

    router_manager requirements:
      - router_manager.router_logger.log_message(str)
      - router_manager.process_packet(bytes, iface_label)
    """
    VIRTUAL_IFACE_NAME = "Nate's Tunnel"
    DEFAULT_PIPE_NAME = r'\\.\pipe\wintun_to_python'

    def __init__(self, router_manager, code_output_manager=None, *,
                 pipe_name=DEFAULT_PIPE_NAME,
                 idle_timeout=2.0,
                 max_frames_per_batch=1024,
                 max_bytes_per_batch=(1 << 20)):

        self.router_manager = router_manager
        self.logger = getattr(router_manager, "router_logger", None)
        self.code_output_manager = code_output_manager
        self.pipe_name = pipe_name

        # handles/state (owned/closed by reader thread)
        self._pipe_handle = None
        self._ovl_event = None
        self._ovl = None

        self._stop_event = threading.Event()
        self._reader_thread = None
        self._reader_tid = None

        # tuning
        self._idle_timeout = float(idle_timeout)
        self._max_frames = int(max_frames_per_batch)
        self._max_bytes = int(max_bytes_per_batch)

        # avoid races on shared handles
        self._hdl_lock = threading.Lock()

        # stats
        self.frames_read = 0
        self.frames_badlen = 0

        # light telemetry
        self._last_log_ts = 0.0
        self._log_every = 0.5        # seconds
        self._quiet_log_after = 2.0  # seconds without progress => note stall

        # rate-limited malformed logs
        self._badlen_last_log = 0.0
        self._badlen_log_every = 5.0

    # ---------------- public control ----------------

    def start(self):
        if self._reader_thread and self._reader_thread.is_alive():
            return
        self._log("[WinTun] Starting manager (immediate processing, no queue)...")
        self._stop_event.clear()
        self._reader_thread = threading.Thread(
            target=self._pipe_reader_loop, name="WinTunReader", daemon=True
        )
        self._reader_thread.start()

    def stop(self):
        """Signal stop and attempt a graceful shutdown to prevent race conditions."""
        if not self._reader_thread or not self._reader_thread.is_alive():
            self._log("[WinTun] Manager already stopped.")
            return
        self._log("[WinTun] Stopping manager...")

        self._stop_event.set()
        self._cancel_pending_io()

        # Poke the event so a wait unblocks immediately
        try:
            with self._hdl_lock:
                ev = self._ovl_event
            if ev:
                win32event.SetEvent(ev)
        except Exception:
            pass

        # If the server is waiting for a client, connect once to break WaitNamedPipe races
        self._unblock_pipe_wait()

        self._reader_thread.join(timeout=5.0)
        self._log("[WinTun] Manager stopped successfully.")
        gc.collect()

    # ---------------- core: read & process immediately ----------------
    def _read_and_process_frames_overlapped(self, ph, ev, ovl,
                                            idle_timeout=2.0, max_frames=1024, max_bytes=(1 << 20)):
        buf = bytearray()
        frames_this_batch = 0
        bytes_read_total = 0
        deadline = time.monotonic() + idle_timeout
        MAX_FRAMES_PER_PASS = 2024

        last_progress_ts = time.monotonic()
        last_frames_read = self.frames_read

        def _reset_event():
            if ev:
                win32event.ResetEvent(ev)

        while (not self._stop_event.is_set()
               and frames_this_batch < max_frames
               and bytes_read_total < max_bytes
               and time.monotonic() < deadline):

            # --- ISSUE OVERLAPPED READ (BYTE mode; C++ length-prefixed frames) ---
            try:
                _reset_event()
                try:
                    hr, data = win32file.ReadFile(ph, win32file.AllocateReadBuffer(65536), ovl)
                except pywintypes.error as e:
                    if e.winerror != ERROR_IO_PENDING:
                        # hard failure: disconnect and reconnect outside
                        return False
                    ms = max(1, int((deadline - time.monotonic()) * 1000))
                    rc = win32event.WaitForSingleObject(ev, ms)
                    if rc == WAIT_TIMEOUT:
                        # keep the loop alive; micro-idle beacon if needed
                        self._maybe_log_idle(frames_this_batch, bytes_read_total, buf_len=len(buf))
                        continue
                    try:
                        hr, data = win32file.GetOverlappedResult(ph, ovl, True)
                    except pywintypes.error as ge:
                        # 995 = ERROR_OPERATION_ABORTED when we cancelled at stop()
                        if ge.winerror in (ERROR_OPERATION_ABORTED, 995):
                            return False
                        return False
                if isinstance(data, str):
                    # rare pywin32 quirk: immediate completion returns a str
                    # latin-1 is a 1:1 mapping 0..255 -> U+0000..U+00FF (lossless for raw bytes)
                    data = data.encode("latin1")
                elif isinstance(data, memoryview):
                    data = data.tobytes()
                elif isinstance(data, bytearray):
                    data = bytes(data)
                if not data:
                    # Peer closed or end of stream
                    return False

                buf.extend(data)
                bytes_read_total += len(data)
                deadline = time.monotonic() + idle_timeout

            except Exception:
                # Any unexpected error → force reconnect
                return False

            # --- FAST EXTRACT: LEN(4 LE) + PAYLOAD ---
            parsed_this_pass = 0
            while parsed_this_pass < MAX_FRAMES_PER_PASS:
                if self._stop_event.is_set():
                    return False
                if len(buf) < 4:
                    break

                pkt_len = int.from_bytes(buf[0:4], "little", signed=False)

                # BYTE-mode sanity: raw L3 frames typically 20..65535
                if not (14 <= pkt_len <= 65535):
                    del buf[:4]  # drop bogus length, attempt resync next iteration
                    self.frames_badlen += 1
                    self._maybe_log_badlen_sample()
                    continue

                if len(buf) < 4 + pkt_len:
                    break  # need more bytes

                packet_bytes = bytes(buf[4: 4 + pkt_len])
                del buf[:4 + pkt_len]

                self.frames_read += 1
                parsed_this_pass += 1
                frames_this_batch += 1

                # Progress beacon (matches C++ micro-heartbeats spirit)
                now = time.monotonic()
                if self.frames_read != last_frames_read:
                    last_progress_ts = now
                    last_frames_read = self.frames_read

                if packet_bytes:
                    # Forward straight to your pipeline
                    self.router_manager.process_packet(packet_bytes, self.VIRTUAL_IFACE_NAME)

            # Lightweight periodic status (no spam)
            self._maybe_log_progress(frames_this_batch, bytes_read_total, buf_len=len(buf),
                                     last_progress_ts=last_progress_ts)

        return True

    # ---------------- reader thread ----------------

    def _pipe_reader_loop(self):
        try:
            self._reader_tid = win32api.GetCurrentThreadId()
        except Exception:
            self._reader_tid = None

        while not self._stop_event.is_set():
            ph = ev = ovl = None
            try:
                # Reconnect loop (small wait keeps UI logs responsive)
                try:
                    win32pipe.WaitNamedPipe(self.pipe_name, 250)
                except pywintypes.error as e:
                    # 2 = ERROR_FILE_NOT_FOUND (server not up yet)
                    if e.winerror == 2:
                        self._stop_event.wait(0.10)
                        continue
                    # Anything else: brief backoff
                    self._stop_event.wait(0.05)
                    continue

                if self._stop_event.is_set():
                    break

                self._log(f"[WinTun] 🔎 Connecting to pipe: {self.pipe_name}")
                ph = win32file.CreateFile(
                    self.pipe_name,
                    GENERIC_READ,  # client reads; server is PIPE_ACCESS_OUTBOUND
                    0, None,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    None
                )
                self._log("[WinTun] ✅ Pipe connected (OVERLAPPED, BYTE mode).")

                # Server is PIPE_TYPE_BYTE; setting MESSAGE mode would fail (OK).
                try:
                    PIPE_READMODE_BYTE = 0x00000000
                    win32pipe.SetNamedPipeHandleState(ph, PIPE_READMODE_BYTE, None, None)
                except pywintypes.error:
                    pass  # already byte mode

                # Prepare one reusable OVERLAPPED for all reads
                ev = win32event.CreateEvent(None, True, False, None)
                ovl = win32file.OVERLAPPED()
                ovl.hEvent = ev

                with self._hdl_lock:
                    self._pipe_handle = ph
                    self._ovl_event = ev
                    self._ovl = ovl

                while not self._stop_event.is_set():
                    keep = self._read_and_process_frames_overlapped(
                        ph, ev, ovl,
                        idle_timeout=self._idle_timeout,
                        max_frames=self._max_frames,
                        max_bytes=self._max_bytes
                    )
                    if not keep:
                        break

            except pywintypes.error as e:
                if not self._stop_event.is_set():
                    self._log(f"[WinTun] Connection/read error ({e.winerror}). Retrying...")
                self._stop_event.wait(0.05)
            except Exception as e:
                if not self._stop_event.is_set():
                    self._log(f"[WinTun] ❗ Reader error: {e}. Retrying...")
                self._stop_event.wait(0.05)
            finally:
                with self._hdl_lock:
                    self._pipe_handle = None
                    self._ovl_event = None
                    self._ovl = None

                if ph:
                    try:
                        win32file.CloseHandle(ph)
                    except Exception:
                        pass
                    ph = None
                    if not self._stop_event.is_set():
                        self._log("[WinTun] Pipe disconnected.")
                if ev:
                    try:
                        win32api.CloseHandle(ev)
                    except Exception:
                        pass
                    ev = None
                ovl = None

    # ---------------- cancellation & logging helpers ----------------

    def _cancel_pending_io(self):
        """Cancel outstanding overlapped ReadFile cleanly."""
        try:
            with self._hdl_lock:
                h = self._pipe_handle
                ovl = self._ovl
                tid = self._reader_tid
        except Exception:
            h = ovl = tid = None

        # Best: CancelIoEx on the specific overlapped
        if h and ovl:
            try:
                if _pywin32_cancel_io_ex:
                    _pywin32_cancel_io_ex(h, ovl)   # pywin32 path
                else:
                    # ctypes fallback
                    _CancelIoEx(int(h), None)
            except Exception:
                pass

        # Extra: cancel synchronous I/O if any (safety net)
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

        # Wake up any waiters on the event
        try:
            with self._hdl_lock:
                ev = self._ovl_event
            if ev:
                win32event.SetEvent(ev)
        except Exception:
            pass

    def _maybe_log_progress(self, frames_this_batch, bytes_read_total, buf_len, last_progress_ts):
        now = time.monotonic()
        if now - self._last_log_ts < self._log_every:
            return
        self._last_log_ts = now

        stalled = (now - last_progress_ts) >= self._quiet_log_after
        if stalled or buf_len > 0:
            self._log(
                f"[WinTun] Reader: frames+={frames_this_batch} bytes+={bytes_read_total} "
                f"buf={buf_len}B {'(stalled?)' if stalled else ''}"
            )

    def _maybe_log_idle(self, frames_this_batch, bytes_read_total, buf_len):
        now = time.monotonic()
        if now - self._last_log_ts >= self._log_every:
            self._last_log_ts = now
            self._log(
                f"[WinTun] Reader idle: frames+={frames_this_batch} bytes+={bytes_read_total} buf={buf_len}B"
            )

    def _maybe_log_badlen_sample(self):
        now = time.monotonic()
        if now - self._badlen_last_log >= self._badlen_log_every:
            self._badlen_last_log = now
            self._log(f"[WinTun] ⚠️ bad length prefix count={self.frames_badlen}")

    def _unblock_pipe_wait(self):
        # If server is waiting for a client, a quick connect/close can break WaitNamedPipe races.
        try:
            h = win32file.CreateFile(
                self.pipe_name, GENERIC_READ, 0, None,
                OPEN_EXISTING, 0, None
            )
            win32file.CloseHandle(h)
        except pywintypes.error:
            pass

    # central logging shim
    def _log(self, msg: str):
        try:
            if self.logger:
                self.logger.log_message(msg)
                return
        except Exception:
            pass
        print(msg)
