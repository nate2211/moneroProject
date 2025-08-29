# HyperVManager.py
import ctypes
import gc
import os
import queue
import sys
import atexit
import signal
import subprocess
import threading
from ctypes import wintypes
from pathlib import Path
from typing import Any, Optional

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
    - Overlapped, cancelable reads
    - Backpressure: we only read when we're ready to process; C++ blocks naturally
    - Reader thread is the sole owner/closer of handles (no double-close)
    """
    VIRTUAL_IFACE_NAME = "WinDivertBridge"
    DEFAULT_PIPE_NAME = r'\\.\pipe\windivert_to_python'

    def __init__(self, router_manager, code_output_manager, pipe_name=DEFAULT_PIPE_NAME,
                 idle_timeout=2.0, max_frames_per_batch=1024, max_bytes_per_batch=(1 << 20)):

        # --- FIX 1: Handle long IPv6 extension header chains ---
        # Increase Scapy's default limit for dissecting chained packet layers.
        # This prevents the "Maximum amount of items reached" error.
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

        # --- STAGE 1: Graceful Shutdown ---
        # 1. Signal the thread that it's time to stop.
        self._stop_event.set()

        # 2. Gently wake the thread if it's in a long wait. This helps it
        #    see the stop_event sooner.
        try:
            with self._hdl_lock:
                ev = self._ovl_event
            if ev:
                win32event.SetEvent(ev)
        except Exception:
            pass
        self._unblock_pipe_wait()


        self._reader_thread.join(timeout=5.0)

        self.logger.log_message("[WinDivert] Manager stopped successfully.")
        # Hint to GC to clean up now that the thread is confirmed dead.
        gc.collect()

    # ---------------- internal helpers ----------------

    def _unblock_pipe_wait(self):
        try:
            h = win32file.CreateFile(
                self.pipe_name, win32file.GENERIC_READ, 0, None,
                win32file.OPEN_EXISTING, 0, None
            )
            win32file.CloseHandle(h)
        except pywintypes.error:
            pass

    # ---------------- reader thread ----------------

    def _pipe_reader_loop(self):
        try:
            self._reader_tid = win32api.GetCurrentThreadId()
        except Exception:
            self._reader_tid = None

        while not self._stop_event.is_set():
            ph = ev = ovl = None
            try:
                # wait up to 1s for a pipe instance
                try:
                    win32pipe.WaitNamedPipe(self.pipe_name, 1000)
                except pywintypes.error as e:
                    if e.winerror == 2:  # not created yet
                        self._stop_event.wait(0.25)
                        continue
                    raise

                if self._stop_event.is_set():
                    break

                self.logger.log_message(f"[WinDivert] 🔎 Connecting to pipe: {self.pipe_name}")
                ph = win32file.CreateFile(
                    self.pipe_name,
                    win32file.GENERIC_READ,
                    0, None,
                    win32file.OPEN_EXISTING,
                    win32con.FILE_FLAG_OVERLAPPED,  # overlapped -> cancelable & backpressure
                    None
                )
                self.logger.log_message("[WinDivert] ✅ Pipe connected (OVERLAPPED, immediate processing).")

                # message mode (avoid NOWAIT with overlapped)
                try:
                    PIPE_READMODE_MESSAGE = 0x00000002
                    win32pipe.SetNamedPipeHandleState(ph, PIPE_READMODE_MESSAGE, None, None)
                except pywintypes.error:
                    pass

                # per-connection event + OVERLAPPED
                ev = win32event.CreateEvent(None, True, False, None)
                ovl = pywintypes.OVERLAPPED()
                ovl.hEvent = ev

                # publish to shared (for stop() cancellation)
                with self._hdl_lock:
                    self._pipe_handle = ph
                    self._ovl_event = ev
                    self._ovl = ovl

                # main read/process loop
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
                # sole close point
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

    # ---------------- core: read & process immediately ----------------

    def _read_and_process_frames_overlapped(self, ph, ev, ovl,
                                            idle_timeout=2.0, max_frames=1024, max_bytes=(1 << 20)):
        """
        Overlapped, cancelable batch read.
        Processes each frame immediately in this thread (no queue).
        Returns False on server close/error to trigger reconnect/exit.
        """
        buf = bytearray()
        frames_this_batch = 0
        bytes_read_total = 0
        deadline = time.monotonic() + idle_timeout
        MAX_FRAMES_PER_PASS = 256

        def _reset_event():
            if ev:
                win32event.ResetEvent(ev)

        while (not self._stop_event.is_set()
               and frames_this_batch < max_frames
               and bytes_read_total < max_bytes
               and time.monotonic() < deadline):

            try:
                _reset_event()
                try:
                    hr, data = win32file.ReadFile(ph, 65536, ovl)
                except pywintypes.error as e:
                    if e.winerror != win32con.ERROR_IO_PENDING:
                        return False
                    ms = max(1, int((deadline - time.monotonic()) * 1000))
                    rc = win32event.WaitForSingleObject(ev, ms)
                    if rc == WAIT_TIMEOUT:
                        continue
                    try:
                        hr, data = win32file.GetOverlappedResult(ph, ovl, True)
                    except pywintypes.error as ge:
                        if ge.winerror in (win32con.ERROR_OPERATION_ABORTED, 995):
                            return False
                        return False

                if not data:
                    return False

                buf.extend(data)
                bytes_read_total += len(data)
                deadline = time.monotonic() + idle_timeout

                parsed_this_pass = 0
                while parsed_this_pass < MAX_FRAMES_PER_PASS:
                    if self._stop_event.is_set():
                        return False
                    if len(buf) < 4:
                        break

                    pkt_len = int.from_bytes(buf[0:4], "little", signed=False)
                    if not (14 <= pkt_len <= 65535):
                        del buf[:4]
                        self.frames_badlen += 1
                        continue

                    if len(buf) < 4 + pkt_len:
                        break

                    mv = memoryview(buf)
                    pkt = bytes(mv[4:4 + pkt_len])
                    del mv
                    del buf[:4 + pkt_len]

                    self.frames_read += 1
                    try:
                        if pkt:
                            yield_no_gil(0.01)
                            ver = pkt[0] >> 4
                            if ver == 4:
                                # --- FIX 2: Prevent Scapy from parsing truncated ("runt") packets ---
                                # A valid IPv4 header is at least 20 bytes.
                                if len(pkt) < 20:
                                    self.logger.log_message(
                                        f"[WinDivert] ❗ Skipping runt IPv4 packet of {len(pkt)} bytes.")
                                    self.code_output_manager.submit_packet(pkt, inbound_iface="win-divert",
                                                                           phase="skipping-runt-ipv4", component="win-divert-manager")
                                    continue

                                self.router_manager.process_packet(IP(pkt), self.VIRTUAL_IFACE_NAME)
                                self.code_output_manager.submit_packet(pkt, inbound_iface="win-divert",
                                                                       phase="process-ipv4",
                                                                       component="win-divert-manager")
                                self.logger.log_message(f"[WinDivert] Processing IPv4 Packet")

                            elif ver == 6:
                                # --- FIX 2: Prevent Scapy from parsing truncated ("runt") packets ---
                                # A valid IPv6 header is 40 bytes.
                                if len(pkt) < 40:
                                    self.logger.log_message(
                                        f"[WinDivert] ❗ Skipping runt IPv6 packet of {len(pkt)} bytes.")
                                    self.code_output_manager.submit_packet(pkt, inbound_iface="win-divert",
                                                                           phase="skipping-runt-ipv6", component="win-divert-manager")
                                    continue

                                self.router_manager.process_packet(IPv6(pkt), self.VIRTUAL_IFACE_NAME)
                                self.code_output_manager.submit_packet(pkt, inbound_iface="win-divert",
                                                                       phase="process-ipv6",
                                                                       component="win-divert-manager")
                                self.logger.log_message(f"[WinDivert] Processing IPv6 Packet")

                        self.frames_processed += 1
                    except Exception as e:
                        self.logger.log_message(
                            f"[WinDivert] ❗ process_packet error: '{e}' on packet data: {pkt.hex()}"
                        )
                        self.code_output_manager.submit_packet(pkt, inbound_iface="win-divert",
                                                               phase="packet-error",
                                                               component="win-divert-manager")

                    frames_this_batch += 1
                    parsed_this_pass += 1

            except MemoryError:
                buf.clear()
            except pywintypes.error:
                return False
            except Exception:
                return False

        return True