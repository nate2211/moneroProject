# HyperVManager.py
import os
import sys
import atexit
import signal
import subprocess
import threading
from pathlib import Path
from typing import Any, Optional
import win32file
import win32pipe
import pywintypes
import time
import struct
from PyQt5.QtCore import QObject, pyqtSignal, Qt, QCoreApplication


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
        """
        Send a raw Ethernet frame into the C++ named pipe (\\.\pipe\vmrouter_packets)
        using only the Python standard library (no pywin32).

        Accepts many 'packet' forms and normalizes to bytes:
          - bytes/bytearray/memoryview
          - str hex: "01 23 ab cd", "0123ABCD", with ':', '-', '0x' allowed
          - list/tuple of ints (0..255)
          - objects with .original, .build(), .to_bytes(), or __bytes__()

        Wire format: <uint32 little-endian length> + <frame bytes>
        """
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

