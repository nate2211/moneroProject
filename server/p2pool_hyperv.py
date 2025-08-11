# HyperVManager.py
import os
import sys
import atexit
import signal
import subprocess
import threading
from pathlib import Path
from typing import Any, Optional

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



