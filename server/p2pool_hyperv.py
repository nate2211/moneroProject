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

        # IPv4 defrag state
        self._frag_db = {}
        self._frag_timeout_sec = 5.0
        self._frag_max_streams = 1024
        self._frag_max_per_stream = 128

        # IPv6 defrag state
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
        gc.collect()

    # ---------------- core: read & process immediately ----------------
    def _read_and_process_frames_overlapped(self, ph, ev, ovl,
                                            idle_timeout=2.0, max_frames=1024, max_bytes=(1 << 20)):
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
                        if not pkt:
                            frames_this_batch += 1
                            parsed_this_pass += 1
                            continue

                        ver = pkt[0] >> 4
                        skip = False

                        if ver == 4:
                            ok, usable_len, is_frag = self._ipv4_sane(pkt)
                            if not ok:
                                # Attempt salvage
                                salv = self._ipv4_salvage(pkt)
                                if salv is None:
                                    self._log_ipv4_malformed(len(pkt), "malformed")
                                    skip = True
                                else:
                                    pkt = salv
                                    # fall-through to normal processing (not a fragment anymore)
                                    is_frag = False
                            else:
                                if usable_len != len(pkt):
                                    pkt = pkt[:usable_len]

                            if not skip:
                                if is_frag:
                                    reassembled = self._ipv4_defrag_add(pkt)
                                    if (self.frames_read & 0x3FF) == 0:
                                        self._frag_gc()
                                    if reassembled is None:
                                        skip = True
                                    else:
                                        pkt = reassembled
                                        self.code_output_manager.submit_packet(
                                            pkt, inbound_iface="win-divert",
                                            phase="reassembled-ipv4", component="win-divert-manager"
                                        )

                            if not skip:
                                try:
                                    self.router_manager.process_packet(IP(pkt), self.VIRTUAL_IFACE_NAME)
                                except Exception:
                                    # Last-chance: parse as Raw under a minimal IP shell
                                    pkt = self._ipv4_wrap_raw(pkt)
                                    self.router_manager.process_packet(IP(pkt), self.VIRTUAL_IFACE_NAME)
                                self.code_output_manager.submit_packet(
                                    pkt, inbound_iface="win-divert",
                                    phase="process-ipv4", component="win-divert-manager"
                                )
                                self.logger.log_message("[WinDivert] Processing IPv4 Packet")

                        elif ver == 6:
                            ok, usable_len, is_runt = self._ipv6_sane(pkt)
                            if not ok:
                                if is_runt:
                                    # True runt (<40B) — try salvage by padding to 40 and zero payload.
                                    salv = self._ipv6_salvage(pkt)
                                    if salv is None:
                                        # drop silently: too broken to salvage
                                        skip = True
                                    else:
                                        pkt = salv
                                        ok, usable_len, _ = self._ipv6_sane(pkt)
                                else:
                                    # Truncated (payload_len > actual). Try clamping/surgery.
                                    salv = self._ipv6_salvage(pkt)
                                    if salv is None:
                                        self._log_ipv6_malformed(len(pkt), "truncated")
                                        skip = True
                                    else:
                                        pkt = salv
                                        ok, usable_len, _ = self._ipv6_sane(pkt)

                            if not skip:
                                if usable_len != len(pkt):
                                    pkt = pkt[:usable_len]

                                rebuilt = self._ipv6_defrag_add(pkt)  # returns pkt if not fragmented
                                if (self.frames_read & 0x3FF) == 0:
                                    self._frag6_gc()
                                if rebuilt is None:
                                    # If fragmented but incomplete: try to salvage first fragment payload
                                    if self._maybe_ipv6_first_fragment(pkt):
                                        salv = self._ipv6_salvage_first_frag(pkt)
                                        if salv is None:
                                            skip = True
                                        else:
                                            pkt = salv
                                    else:
                                        skip = True
                                else:
                                    if rebuilt is not pkt:
                                        pkt = rebuilt
                                        self.code_output_manager.submit_packet(
                                            pkt, inbound_iface="win-divert",
                                            phase="reassembled-ipv6", component="win-divert-manager"
                                        )

                            if not skip:
                                try:
                                    self.router_manager.process_packet(IPv6(pkt), self.VIRTUAL_IFACE_NAME)
                                except Exception:
                                    # Last-chance: wrap remaining bytes as Raw after a minimal IPv6 header
                                    pkt = self._ipv6_wrap_raw(pkt)
                                    self.router_manager.process_packet(IPv6(pkt), self.VIRTUAL_IFACE_NAME)
                                self.code_output_manager.submit_packet(
                                    pkt, inbound_iface="win-divert",
                                    phase="process-ipv6", component="win-divert-manager"
                                )
                                self.logger.log_message("[WinDivert] Processing IPv6 Packet")

                        else:
                            # Unknown/unsupported L3 — count and skip quietly
                            self.frames_processed += 1
                            skip = True

                        frames_this_batch += 1
                        parsed_this_pass += 1
                        if skip:
                            continue

                    except Exception as e:
                        try:
                            hex_preview = pkt.hex() if isinstance(pkt, (bytes, bytearray)) else "<no-bytes>"
                        except Exception:
                            hex_preview = "<unavailable>"
                        self.logger.log_message(
                            f"[WinDivert] ❗ process_packet error: '{type(e).__name__}: {e}' on packet data: {hex_preview}"
                        )
                        self.code_output_manager.submit_packet(
                            pkt if isinstance(pkt, (bytes, bytearray)) else b"",
                            inbound_iface="win-divert",
                            phase="packet-error",
                            component="win-divert-manager"
                        )
                        frames_this_batch += 1
                        parsed_this_pass += 1

            except MemoryError:
                buf.clear()
            except pywintypes.error:
                return False
            except Exception:
                return False

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
                try:
                    win32pipe.WaitNamedPipe(self.pipe_name, 1000)
                except pywintypes.error as e:
                    if e.winerror == 2:
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
                    win32con.FILE_FLAG_OVERLAPPED,
                    None
                )
                self.logger.log_message("[WinDivert] ✅ Pipe connected (OVERLAPPED, immediate processing).")

                try:
                    PIPE_READMODE_MESSAGE = 0x00000002
                    win32pipe.SetNamedPipeHandleState(ph, PIPE_READMODE_MESSAGE, None, None)
                except pywintypes.error:
                    pass

                ev = win32event.CreateEvent(None, True, False, None)
                ovl = pywintypes.OVERLAPPED()
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

    # ---------------- IPv4 sanity, salvage & defrag ----------------

    def _ipv4_sane(self, pkt: bytes) -> tuple[bool, int, bool]:
        if len(pkt) < 20:
            return False, 0, False
        ver_ihl = pkt[0]
        if (ver_ihl >> 4) != 4:
            return False, 0, False
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(pkt) < ihl:
            return False, 0, False
        total_len = int.from_bytes(pkt[2:4], "big")
        frag_raw = int.from_bytes(pkt[6:8], "big")
        mf = (frag_raw & 0x2000) != 0
        off = (frag_raw & 0x1FFF) != 0
        is_frag = mf or off
        if total_len and total_len >= ihl:
            usable = min(len(pkt), total_len)
            return True, usable, is_frag
        return True, len(pkt), is_frag

    def _log_ipv4_malformed(self, nbytes: int, tag: str = "malformed"):
        import time as _t
        self._ipv4_bad_counter += 1
        now = _t.monotonic()
        if (now - self._ipv4_bad_last_log) >= self._ipv4_bad_log_every:
            self._ipv4_bad_last_log = now
            self.logger.log_message(
                f"[WinDivert] ❗ Skipping IPv4 {tag} packets "
                f"(last={nbytes}B, total={self._ipv4_bad_counter})"
            )

    def _ipv4_salvage(self, pkt: bytes) -> bytes | None:
        """
        Best-effort repair of malformed IPv4 header:
        - ensure IHL >= 20 and available
        - clamp/expand header to IHL; if IHL invalid, drop options and use 20
        - fix Total Length to available bytes (<=65535)
        - zero and recompute header checksum
        """
        if not pkt:
            return None
        b = bytearray(pkt)
        n = len(b)
        ver = (b[0] >> 4)
        if ver != 4:
            return None

        ihl_nib = b[0] & 0x0F
        ihl = ihl_nib * 4
        if ihl_nib < 5:  # invalid options length → drop to 20 bytes
            ihl = 20
            b[0] = (4 << 4) | 5
        if n < ihl:
            # pad header up to ihl with zeros
            b.extend(b"\x00" * (ihl - n))
            n = ihl
        # Clamp total length to actual bytes we have (up to 65535)
        total_len = min(max(n, ihl), 65535)
        b[2:4] = total_len.to_bytes(2, "big")
        # reset flags/offset if header was obviously corrupt (optional, but safer)
        # keep as-is to not break real fragments; only fix checksum
        b[10:12] = b"\x00\x00"
        csum = self._ipv4_hdr_checksum(bytes(b[:ihl]))
        b[10:12] = csum.to_bytes(2, "big")
        # Trim to total length if we padded header
        b = b[:total_len]
        return bytes(b)

    def _ipv4_wrap_raw(self, pkt: bytes) -> bytes:
        """
        Last-chance: build a minimal IPv4 header around an opaque payload.
        Src/Dst left zero; protocol set to 59 (No Next Header-ish fallback).
        """
        ihl = 20
        tot = min(ihl + len(pkt), 65535)
        hdr = bytearray(ihl)
        hdr[0] = (4 << 4) | 5
        hdr[1] = 0
        hdr[2:4] = tot.to_bytes(2, "big")
        hdr[6:8] = (0).to_bytes(2, "big")
        hdr[8] = 64
        hdr[9] = 59  # No Next Header equivalent
        hdr[10:12] = b"\x00\x00"
        csum = self._ipv4_hdr_checksum(bytes(hdr))
        hdr[10:12] = csum.to_bytes(2, "big")
        return bytes(hdr) + pkt[: tot - ihl]

    # defrag helpers (unchanged from your version)
    def _ipv4_fragment_key(self, pkt: bytes) -> tuple:
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        ident = int.from_bytes(pkt[4:6], "big")
        src = pkt[12:16]
        dst = pkt[16:20]
        return (src, dst, proto, ident)

    def _ipv4_frag_info(self, pkt: bytes) -> tuple[int, int, bool, int]:
        ihl = (pkt[0] & 0x0F) * 4
        flg_off = int.from_bytes(pkt[6:8], "big")
        mf = (flg_off & 0x2000) != 0
        off8 = (flg_off & 0x1FFF)
        data_off = off8 * 8
        total_len = int.from_bytes(pkt[2:4], "big")
        frag_payload_len = max(0, min(len(pkt) - ihl, total_len - ihl if total_len >= ihl else len(pkt) - ihl))
        return ihl, data_off, (not mf), frag_payload_len

    def _frag_gc(self):
        now = time.monotonic()
        drop = [k for k, v in self._frag_db.items() if (now - v.get('last', now)) > self._frag_timeout_sec]
        for k in drop:
            self._frag_db.pop(k, None)
        if len(self._frag_db) > self._frag_max_streams:
            for k in list(self._frag_db.keys())[:len(self._frag_db) - self._frag_max_streams]:
                self._frag_db.pop(k, None)

    def _ipv4_defrag_add(self, pkt: bytes) -> bytes | None:
        key = self._ipv4_fragment_key(pkt)
        ihl, data_off, is_last, frag_len = self._ipv4_frag_info(pkt)
        now = time.monotonic()

        st = self._frag_db.get(key)
        if st is None:
            st = {
                'created': now, 'last': now,
                'frags': {}, 'have_last': False,
                'total_len': None,
                'base_hdr': pkt[:ihl],
            }
            self._frag_db[key] = st
            if len(self._frag_db) > self._frag_max_streams:
                self._frag_gc()

        frags = st['frags']
        if len(frags) >= self._frag_max_per_stream:
            self._frag_db.pop(key, None)
            return None

        payload = pkt[ihl:ihl + frag_len] if frag_len > 0 else b""
        frags[data_off] = payload
        st['last'] = now
        if is_last:
            st['have_last'] = True

        if st['have_last']:
            max_end = 0
            for off, pl in frags.items():
                max_end = max(max_end, off + len(pl))
            st['total_len'] = max_end

        total = st['total_len']
        if total is None:
            return None

        needed = 0
        parts = []
        while needed < total:
            chunk = frags.get(needed)
            if chunk is None:
                return None
            parts.append(chunk)
            needed += len(chunk)

        full_payload = b"".join(parts)
        base_hdr = bytearray(st['base_hdr'])
        base_hdr[6] = 0
        base_hdr[7] = 0
        tot = len(base_hdr) + len(full_payload)
        base_hdr[2:4] = tot.to_bytes(2, "big")
        base_hdr[10:12] = b"\x00\x00"
        csum = self._ipv4_hdr_checksum(bytes(base_hdr))
        base_hdr[10:12] = csum.to_bytes(2, "big")

        self._frag_db.pop(key, None)
        return bytes(base_hdr) + full_payload

    def _ipv4_hdr_checksum(self, hdr: bytes) -> int:
        s = 0
        for i in range(0, len(hdr), 2):
            w = hdr[i] << 8
            if i + 1 < len(hdr):
                w |= hdr[i + 1]
            s += w
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    # ---------------- IPv6 sanity, salvage & defrag ----------------

    def _ipv6_sane(self, pkt: bytes) -> tuple[bool, int, bool]:
        n = len(pkt)
        if n < 1:
            return False, 0, True
        if (pkt[0] >> 4) != 6:
            return False, 0, False
        if n < 40:
            return False, 0, True
        payload_len = int.from_bytes(pkt[4:6], "big")
        total = 40 + payload_len
        if total <= n:
            return True, total, False
        return False, 0, False

    def _log_ipv6_malformed(self, nbytes: int, tag: str = "malformed"):
        import time as _t
        self._ipv6_bad_counter += 1
        now = _t.monotonic()
        if (now - self._ipv6_bad_last_log) >= self._ipv6_bad_log_every:
            self._ipv6_bad_last_log = now
            self.logger.log_message(
                f"[WinDivert] ❗ Skipping IPv6 {tag} packets "
                f"(last={nbytes}B, total={self._ipv6_bad_counter})"
            )

    def _ipv6_find_fragment(self, pkt: bytes):
        try:
            if len(pkt) < 40 or (pkt[0] >> 4) != 6:
                return False, None, None, None, None
            nh = pkt[6]
            offset = 40
            prev_nh_index = 6
            EXT_STD = {0, 43, 60}
            AH = 51
            FRAG = 44

            while True:
                if nh == FRAG:
                    if offset + 8 > len(pkt):
                        return False, None, None, None, None
                    frag_nh = pkt[offset]
                    return True, offset, prev_nh_index, frag_nh, offset
                if nh not in EXT_STD and nh != AH:
                    return True, None, None, None, None
                if nh in EXT_STD:
                    if offset + 2 > len(pkt):
                        return False, None, None, None, None
                    hdr_len_units = pkt[offset + 1]
                    hdr_len = 8 + (hdr_len_units * 8)
                    if offset + hdr_len > len(pkt):
                        return False, None, None, None, None
                    prev_nh_index = offset
                    nh = pkt[offset]
                    offset += hdr_len
                    continue
                if nh == AH:
                    if offset + 2 > len(pkt):
                        return False, None, None, None, None
                    ah_len_words = pkt[offset + 1]
                    hdr_len = (ah_len_words + 2) * 4
                    if offset + hdr_len > len(pkt):
                        return False, None, None, None, None
                    prev_nh_index = offset
                    nh = pkt[offset]
                    offset += hdr_len
                    continue
        except Exception:
            return False, None, None, None, None

    def _maybe_ipv6_first_fragment(self, pkt: bytes) -> bool:
        ok, frag_off, *_ = self._ipv6_find_fragment(pkt)
        if not ok or frag_off is None:
            return False
        # M flag may be set; we only care that offset==0 (first fragment)
        off_res_m = int.from_bytes(pkt[frag_off + 2: frag_off + 4], "big")
        off8 = (off_res_m >> 3) & 0x1FFF
        return off8 == 0

    def _ipv6_salvage_first_frag(self, pkt: bytes) -> bytes | None:
        """
        Best-effort: take first fragment and strip the Fragment header,
        forward the payload as if complete (upper layers may still parse).
        """
        ok, frag_off, prev_nh_index, frag_nh, _ = self._ipv6_find_fragment(pkt)
        if not ok or frag_off is None:
            return None
        # offset must be 0
        off_res_m = int.from_bytes(pkt[frag_off + 2: frag_off + 4], "big")
        off8 = (off_res_m >> 3) & 0x1FFF
        if off8 != 0:
            return None

        payload_len = int.from_bytes(pkt[4:6], "big")
        before = (frag_off - 40) + 8
        if payload_len < before:
            return None
        frag_len = min(payload_len - before, len(pkt) - (frag_off + 8))
        if frag_len < 0:
            return None

        pre_hdrs = bytearray(pkt[:frag_off])
        if 0 <= prev_nh_index < len(pre_hdrs):
            pre_hdrs[prev_nh_index] = frag_nh
        body = pkt[frag_off + 8: frag_off + 8 + frag_len]

        new_plen = (len(pre_hdrs) - 40) + len(body)
        pre_hdrs[4:6] = new_plen.to_bytes(2, "big")
        return bytes(pre_hdrs) + body

    def _ipv6_salvage(self, pkt: bytes) -> bytes | None:
        """
        Clamp/correct IPv6 header lengths; if extension chain truncates,
        cut at the last valid header and set NH to 59 (No Next Header).
        """
        if not pkt:
            return None
        b = bytearray(pkt)
        n = len(b)
        if n < 1 or (b[0] >> 4) != 6:
            return None
        if n < 40:
            # pad header up to 40, payload zero
            b.extend(b"\x00" * (40 - n))
            b[4:6] = (0).to_bytes(2, "big")
            return bytes(b[:40])

        # Try to walk headers; when we can't continue, we terminate chain.
        try:
            nh = b[6]
            offset = 40
            prev_nh_index = 6
            EXT_STD = {0, 43, 60}
            AH = 51
            FRAG = 44

            while True:
                if nh == FRAG:
                    if offset + 8 > n:
                        # Truncated frag header → cut chain here
                        b[prev_nh_index] = 59  # No Next Header
                        plen = offset - 40
                        b[4:6] = plen.to_bytes(2, "big")
                        return bytes(b[:offset])
                    # Otherwise, leave to defragmenter; just ensure declared PLEN fits bytes
                    break

                if nh not in EXT_STD and nh != AH:
                    # upper layer reached
                    break

                if nh in EXT_STD:
                    if offset + 2 > n:
                        b[prev_nh_index] = 59
                        plen = offset - 40
                        b[4:6] = plen.to_bytes(2, "big")
                        return bytes(b[:offset])
                    hdr_len_units = b[offset + 1]
                    hdr_len = 8 + (hdr_len_units * 8)
                    if offset + hdr_len > n:
                        b[prev_nh_index] = 59
                        plen = offset - 40
                        b[4:6] = plen.to_bytes(2, "big")
                        return bytes(b[:offset])
                    prev_nh_index = offset
                    nh = b[offset]
                    offset += hdr_len
                    continue

                if nh == AH:
                    if offset + 2 > n:
                        b[prev_nh_index] = 59
                        plen = offset - 40
                        b[4:6] = plen.to_bytes(2, "big")
                        return bytes(b[:offset])
                    ah_len_words = b[offset + 1]
                    hdr_len = (ah_len_words + 2) * 4
                    if offset + hdr_len > n:
                        b[prev_nh_index] = 59
                        plen = offset - 40
                        b[4:6] = plen.to_bytes(2, "big")
                        return bytes(b[:offset])
                    prev_nh_index = offset
                    nh = b[offset]
                    offset += hdr_len
                    continue

            # Clamp payload length to real bytes we have.
            real_plen = max(0, n - 40)
            b[4:6] = real_plen.to_bytes(2, "big")
            return bytes(b[:40 + real_plen])

        except Exception:
            # On any parsing error, just clamp PLEN to available bytes
            real_plen = max(0, n - 40)
            b[4:6] = real_plen.to_bytes(2, "big")
            return bytes(b[:40 + real_plen])

    def _ipv6_wrap_raw(self, pkt: bytes) -> bytes:
        """
        Last-chance: minimal IPv6 header (No Next Header) + raw payload (clamped).
        """
        base = bytearray(40)
        base[0] = (6 << 4)  # v6, TC=0, Flow=0
        # Next Header 59 (No Next Header)
        base[6] = 59
        base[7] = 64  # Hop Limit
        plen = min(len(pkt), 65535)
        base[4:6] = plen.to_bytes(2, "big")
        return bytes(base) + pkt[:plen]

    # ---------------- IPv6 defrag core (unchanged in spirit) ----------------

    def _ipv6_fragment_key(self, pkt: bytes, frag_off: int, frag_nh: int):
        src = pkt[8:24]
        dst = pkt[24:40]
        ident = pkt[frag_off + 4: frag_off + 8]
        return (src, dst, ident, frag_nh)

    def _ipv6_frag_info(self, pkt: bytes, frag_off: int):
        off_res_m = int.from_bytes(pkt[frag_off + 2: frag_off + 4], "big")
        m_flag = (off_res_m & 0x1) != 0
        off8 = (off_res_m >> 3) & 0x1FFF
        data_off = off8 * 8
        payload_len = int.from_bytes(pkt[4:6], "big")
        before = (frag_off - 40) + 8
        frag_len = 0 if payload_len < before else (payload_len - before)
        pre_frag_hdrs_len = frag_off
        return data_off, (not m_flag), frag_len, pre_frag_hdrs_len

    def _frag6_gc(self):
        now = time.monotonic()
        drop = [k for k, v in self._frag6_db.items() if (now - v.get('last', now)) > self._frag6_timeout_sec]
        for k in drop:
            self._frag6_db.pop(k, None)
        if len(self._frag6_db) > self._frag6_max_streams:
            for k in list(self._frag6_db.keys())[:len(self._frag6_db) - self._frag6_max_streams]:
                self._frag6_db.pop(k, None)

    def _ipv6_defrag_add(self, pkt: bytes) -> bytes | None:
        ok, frag_off, prev_nh_index, frag_nh, pre_len = self._ipv6_find_fragment(pkt)
        if not ok:
            return None
        if frag_off is None:
            return pkt

        data_off, is_last, frag_len, pre_frag_hdrs_len = self._ipv6_frag_info(pkt, frag_off)
        if frag_len < 0:
            return None
        frag_payload = pkt[frag_off + 8: frag_off + 8 + frag_len]

        key = self._ipv6_fragment_key(pkt, frag_off, frag_nh)
        now = time.monotonic()
        st = self._frag6_db.get(key)
        if st is None:
            pre_hdrs = pkt[:frag_off]
            st = {
                'created': now, 'last': now,
                'frags': {},
                'have_last': False,
                'total_len': None,
                'pre_frag_hdrs': pre_hdrs,
                'prev_nh_index': prev_nh_index,
                'frag_nh': frag_nh,
            }
            self._frag6_db[key] = st
            if len(self._frag6_db) > self._frag6_max_streams:
                self._frag6_gc()

        frags = st['frags']
        if len(frags) >= self._frag6_max_per_stream:
            self._frag6_db.pop(key, None)
            return None

        frags[data_off] = frag_payload
        st['last'] = now
        if is_last:
            st['have_last'] = True

        if st['have_last']:
            max_end = 0
            for off, pl in frags.items():
                max_end = max(max_end, off + len(pl))
            st['total_len'] = max_end

        total = st['total_len']
        if total is None:
            return None

        needed = 0
        parts = []
        while needed < total:
            chunk = frags.get(needed)
            if chunk is None:
                return None
            parts.append(chunk)
            needed += len(chunk)

        pre_hdrs = bytearray(st['pre_frag_hdrs'])
        if 0 <= st['prev_nh_index'] < len(pre_hdrs):
            pre_hdrs[st['prev_nh_index']] = st['frag_nh']

        reassembled_payload = b"".join(parts)
        payload_len = len(pre_hdrs) - 40 + len(reassembled_payload)
        pre_hdrs[4:6] = payload_len.to_bytes(2, "big")
        full_pkt = bytes(pre_hdrs) + reassembled_payload
        self._frag6_db.pop(key, None)
        return full_pkt

    # ---------------- misc ----------------
    def _unblock_pipe_wait(self):
        try:
            h = win32file.CreateFile(
                self.pipe_name, win32file.GENERIC_READ, 0, None,
                win32file.OPEN_EXISTING, 0, None
            )
            win32file.CloseHandle(h)
        except pywintypes.error:
            pass
