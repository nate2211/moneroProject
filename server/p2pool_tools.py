import asyncio
import atexit
import base64
import binascii
import gc
import json
import os
import platform
import sys
import ctypes
import threading
import time
from collections import deque
from ctypes import wintypes
from pathlib import Path
from typing import Callable, Any, Dict, List, Set, Tuple, Optional

import numpy as np
import psutil
from PyQt5.QtCore import QObject


class CSharpLogger(QObject):
    def __init__(self, logger):
        super().__init__()
        self._logger = logger
        self._prefix = "[C#]"

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

class _NativeDllBase:
    """Small frozen-safe loader for optional bundled native router helpers."""

    def __init__(self, logger, relative_path: str):
        self.logger = logger
        self.relative_path = str(relative_path)
        self.path = self._resolve_path(self.relative_path)
        self.dll = None
        self.last_error = ""
        self._load()

    @staticmethod
    def _runtime_roots() -> List[str]:
        roots: List[str] = []
        if getattr(sys, "frozen", False):
            roots.append(os.path.dirname(sys.executable))
        if hasattr(sys, "_MEIPASS"):
            roots.append(str(sys._MEIPASS))
        roots.append(os.path.dirname(os.path.abspath(__file__)))
        out: List[str] = []
        for root in roots:
            normalized = os.path.abspath(root)
            if normalized not in out:
                out.append(normalized)
        return out

    @classmethod
    def _resolve_path(cls, relative_path: str) -> str:
        normalized = str(relative_path).replace("\\", os.sep).replace("/", os.sep)
        for root in cls._runtime_roots():
            candidate = os.path.abspath(os.path.join(root, normalized))
            if os.path.exists(candidate):
                return candidate
        return os.path.abspath(os.path.join(cls._runtime_roots()[0], normalized))

    def _log(self, message: str) -> None:
        try:
            self.logger.log_message(str(message))
        except Exception:
            pass

    def _load(self) -> bool:
        if self.dll is not None:
            return True
        if os.name != "nt":
            self.last_error = "native Windows DLL is inactive on this platform"
            return False
        if not os.path.exists(self.path):
            self.last_error = f"DLL not found: {self.path}"
            self._log(f"[NativeRouter] ⚠️ {self.last_error}")
            return False
        try:
            self.dll = ctypes.CDLL(self.path)
            return True
        except Exception as exc:
            self.last_error = str(exc)
            self._log(f"[NativeRouter] ❌ Could not load {os.path.basename(self.path)}: {exc}")
            return False

    @property
    def available(self) -> bool:
        return self.dll is not None


class NativeProcessPacketTap(_NativeDllBase):
    """Native parser/filter used by ProcessInterface for every attributed frame.

    WinDivert/Npcap remains the capture owner.  This helper performs a bounded
    native inspection pass and can also accept packet frames produced by other
    C++ process-output helpers, forwarding them to ProcessManager through a
    stable callback ABI.
    """

    PacketCallbackEx = ctypes.CFUNCTYPE(
        None, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_char_p
    )

    class Stats(ctypes.Structure):
        _fields_ = [
            ("observed", ctypes.c_uint64), ("emitted", ctypes.c_uint64),
            ("rejected", ctypes.c_uint64), ("bytes", ctypes.c_uint64),
            ("ipv4", ctypes.c_uint64), ("ipv6", ctypes.c_uint64),
            ("tcp", ctypes.c_uint64), ("udp", ctypes.c_uint64),
            ("other", ctypes.c_uint64), ("last_pid", ctypes.c_uint64),
        ]

    def __init__(self, logger, relative_path: str = "tools/ProcessPacketTap.dll"):
        self._packet_callback = None
        self._callback_wrapper = None
        self._callback_source = "ProcessPacketTap.dll"
        self._callback_pid = None
        self._lock = threading.RLock()
        self._stopped = False
        super().__init__(logger, relative_path)
        if self.available:
            self._configure_exports()
            self._log(f"[ProcessInterface][NativeTap] ✅ Loaded {self.path}")

    def _configure_exports(self) -> None:
        d = self.dll
        d.ProcessTapSetPacketCallbackEx.argtypes = [self.PacketCallbackEx]
        d.ProcessTapConfigure.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint16), ctypes.c_uint32,
        ]
        d.ProcessTapConfigure.restype = ctypes.c_int
        for name in ("ProcessTapObservePacket", "ProcessTapSubmitPacket"):
            fn = getattr(d, name)
            fn.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
            fn.restype = ctypes.c_int
        d.ProcessTapGetStats.argtypes = [ctypes.POINTER(self.Stats)]
        d.ProcessTapGetStats.restype = ctypes.c_int

    @staticmethod
    def _packet_bytes(packet) -> bytes:
        if packet is None:
            return b""
        if isinstance(packet, bytes):
            return packet
        if isinstance(packet, (bytearray, memoryview)):
            return bytes(packet)
        try:
            return bytes(packet)
        except Exception:
            return b""

    def configure(self, pid: Optional[int], mode: str = "all", ports=None) -> bool:
        if not self.available:
            return False
        mode_id = {"stratum": 1, "all": 2, "observe": 3}.get(str(mode).casefold(), 2)
        normalized = sorted({int(p) for p in (ports or []) if 0 < int(p) <= 65535})[:128]
        array_type = ctypes.c_uint16 * max(1, len(normalized))
        values = array_type(*(normalized or [0]))
        return bool(self.dll.ProcessTapConfigure(
            ctypes.c_uint32(int(pid or 0)), ctypes.c_uint32(mode_id),
            values, ctypes.c_uint32(len(normalized)),
        ))

    def _call_packet(self, export: str, packet, *, pid=None, direction=0, if_index=0) -> bool:
        if not self.available:
            return False
        data = self._packet_bytes(packet)
        if not data:
            return False
        buf = ctypes.create_string_buffer(data, len(data))
        fn = getattr(self.dll, export)
        return bool(fn(
            ctypes.cast(buf, ctypes.c_void_p), ctypes.c_uint64(len(data)),
            ctypes.c_uint32(int(pid or 0)), ctypes.c_uint32(int(direction or 0)),
            ctypes.c_uint32(int(if_index or 0)),
        ))

    def observe_packet(self, packet, *, pid=None, direction=0, if_index=0) -> bool:
        return self._call_packet(
            "ProcessTapObservePacket", packet, pid=pid,
            direction=direction, if_index=if_index,
        )

    def emit_packet(self, packet, *, pid=None, direction=0, if_index=0) -> bool:
        return self._call_packet(
            "ProcessTapSubmitPacket", packet, pid=pid,
            direction=direction, if_index=if_index,
        )

    submit_packet = emit_packet
    submit_native_packet = emit_packet

    def set_packet_callback(self, callback, *, source="ProcessPacketTap.dll", pid=None) -> bool:
        with self._lock:
            self._packet_callback = callback if callable(callback) else None
            if self._packet_callback is not None:
                self._stopped = False
            self._callback_source = str(source or "ProcessPacketTap.dll")
            self._callback_pid = int(pid) if pid is not None else None
        if not self.available:
            return False
        if self._packet_callback is None:
            self._callback_wrapper = self.PacketCallbackEx()
            self.dll.ProcessTapSetPacketCallbackEx(self._callback_wrapper)
            return False

        @self.PacketCallbackEx
        def _bridge(ptr, length, native_pid, metadata_json):
            try:
                data = ctypes.string_at(ptr, int(length)) if ptr and length else b""
                metadata = {}
                if metadata_json:
                    try:
                        metadata = json.loads(metadata_json.decode("utf-8", "replace"))
                    except Exception:
                        metadata = {"native_metadata": metadata_json.decode("utf-8", "replace")[:2048]}
                metadata.setdefault("native_tap", True)
                callback_pid = int(native_pid or self._callback_pid or 0) or None
                cb = self._packet_callback
                if cb:
                    cb(data, len(data), source=self._callback_source, pid=callback_pid, metadata=metadata)
            except Exception as exc:
                self._log(f"[ProcessInterface][NativeTap] callback error: {exc}")

        self._callback_wrapper = _bridge
        self.dll.ProcessTapSetPacketCallbackEx(self._callback_wrapper)
        return True

    register_packet_callback = set_packet_callback
    add_packet_callback = set_packet_callback
    set_output_callback = set_packet_callback

    def stats(self) -> Dict[str, int]:
        if not self.available:
            return {"available": 0, "error": self.last_error}
        value = self.Stats()
        if not self.dll.ProcessTapGetStats(ctypes.byref(value)):
            return {"available": 1, "error": "ProcessTapGetStats failed"}
        out = {name: int(getattr(value, name)) for name, _ in value._fields_}
        out["available"] = 1
        return out

    get_stats = stats

    def stop(self) -> None:
        """Detach callbacks and disable PID filtering without unloading the DLL."""
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        try:
            self.configure(None, "all", [])
        except Exception:
            pass
        try:
            self.set_packet_callback(None)
        except Exception:
            pass

    close = stop


class NativeCodeOutputControl(_NativeDllBase):
    """Native CodeOutput stream registry and explicit-frame callback bridge."""

    PacketCallbackEx = ctypes.CFUNCTYPE(
        None, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_char_p
    )

    class Stats(ctypes.Structure):
        _fields_ = [
            ("observed", ctypes.c_uint64), ("emitted", ctypes.c_uint64),
            ("rejected", ctypes.c_uint64), ("bytes", ctypes.c_uint64),
            ("streams_opened", ctypes.c_uint64), ("streams_closed", ctypes.c_uint64),
            ("probes_built", ctypes.c_uint64),
        ]

    def __init__(self, logger, relative_path: str = "tools/CodeOutputControl.dll"):
        self._packet_callback = None
        self._callback_wrapper = None
        self._lock = threading.RLock()
        self._stopped = False
        super().__init__(logger, relative_path)
        if self.available:
            self._configure_exports()
            self._log(f"[CodeOutput][NativeControl] ✅ Loaded {self.path}")

    def _configure_exports(self) -> None:
        d = self.dll
        d.CodeOutputSetPacketCallbackEx.argtypes = [self.PacketCallbackEx]
        d.CodeOutputOpenStream.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
        d.CodeOutputOpenStream.restype = ctypes.c_uint32
        d.CodeOutputCloseStream.argtypes = [ctypes.c_uint32]
        d.CodeOutputCloseStream.restype = ctypes.c_int
        d.CodeOutputSetStreamPolicy.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
        d.CodeOutputSetStreamPolicy.restype = ctypes.c_int
        d.CodeOutputObserveFrame.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]
        d.CodeOutputObserveFrame.restype = ctypes.c_int
        d.CodeOutputSubmitFrame.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32]
        d.CodeOutputSubmitFrame.restype = ctypes.c_int
        d.CodeOutputGetStats.argtypes = [ctypes.POINTER(self.Stats)]
        d.CodeOutputGetStats.restype = ctypes.c_int

    @staticmethod
    def _packet_bytes(packet) -> bytes:
        try:
            return bytes(packet)
        except Exception:
            return b""

    def set_packet_callback(self, callback) -> bool:
        with self._lock:
            self._packet_callback = callback if callable(callback) else None
            if self._packet_callback is not None:
                self._stopped = False
        if not self.available:
            return False
        if self._packet_callback is None:
            self._callback_wrapper = self.PacketCallbackEx()
            self.dll.CodeOutputSetPacketCallbackEx(self._callback_wrapper)
            return False

        @self.PacketCallbackEx
        def _bridge(ptr, length, pid, metadata_json):
            try:
                data = ctypes.string_at(ptr, int(length)) if ptr and length else b""
                metadata = {}
                if metadata_json:
                    try:
                        metadata = json.loads(metadata_json.decode("utf-8", "replace"))
                    except Exception:
                        metadata = {"native_metadata": metadata_json.decode("utf-8", "replace")[:2048]}
                metadata.setdefault("source", "CodeOutputControl.dll")
                metadata.setdefault("explicit", True)
                cb = self._packet_callback
                if cb:
                    cb(data, metadata=metadata, pid=int(pid or 0) or None)
            except Exception as exc:
                self._log(f"[CodeOutput][NativeControl] callback error: {exc}")

        self._callback_wrapper = _bridge
        self.dll.CodeOutputSetPacketCallbackEx(self._callback_wrapper)
        return True

    def open_stream(self, protocol: int = 0, direction: int = 0, flags: int = 0) -> int:
        if not self.available:
            return 0
        return int(self.dll.CodeOutputOpenStream(protocol, direction, flags))

    def close_stream(self, stream_id: int) -> bool:
        return bool(self.available and self.dll.CodeOutputCloseStream(int(stream_id)))

    def set_stream_policy(self, stream_id: int, *, protocol=0, direction=0, flags=0) -> bool:
        return bool(self.available and self.dll.CodeOutputSetStreamPolicy(
            int(stream_id), int(protocol), int(direction), int(flags)
        ))

    def observe_frame(self, packet, stream_id: int = 0) -> bool:
        if not self.available:
            return False
        data = self._packet_bytes(packet)
        if not data:
            return False
        buf = ctypes.create_string_buffer(data, len(data))
        return bool(self.dll.CodeOutputObserveFrame(
            ctypes.cast(buf, ctypes.c_void_p), len(data), int(stream_id)
        ))

    def submit_frame(self, packet, *, stream_id: int = 0, pid: Optional[int] = None) -> bool:
        if not self.available:
            return False
        data = self._packet_bytes(packet)
        if not data:
            return False
        buf = ctypes.create_string_buffer(data, len(data))
        return bool(self.dll.CodeOutputSubmitFrame(
            ctypes.cast(buf, ctypes.c_void_p), len(data), int(stream_id), int(pid or 0)
        ))

    submit_packet = submit_frame

    def stats(self) -> Dict[str, int]:
        if not self.available:
            return {"available": 0, "error": self.last_error}
        value = self.Stats()
        if not self.dll.CodeOutputGetStats(ctypes.byref(value)):
            return {"available": 1, "error": "CodeOutputGetStats failed"}
        out = {name: int(getattr(value, name)) for name, _ in value._fields_}
        out["available"] = 1
        return out

    get_stats = stats

    def stop(self) -> None:
        """Detach the callback. Stream ownership is closed by CodeOutputManager."""
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        try:
            self.set_packet_callback(None)
        except Exception:
            pass

    close = stop


class ParallelPythonTool:
    PythonCallback = ctypes.CFUNCTYPE(None)
    IntCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_int))
    BoolCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_bool))
    DoubleCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_double))
    StringCallback = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int)

    # Optional packet-output ABIs supported by bundled C/C++ helpers.  The
    # two-argument ABI is the portable default.  The extended ABI adds a PID
    # and a UTF-8 metadata JSON string without changing packet ownership.
    NativePacketCallback = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
    NativePacketExCallback = ctypes.CFUNCTYPE(
        None, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_char_p
    )

    class PythonCallDescriptor(ctypes.Structure):
        _fields_ = [
            ("FuncPtr", ctypes.c_void_p),
            ("ResultPtr", ctypes.c_void_p),
            ("BufferSize", ctypes.c_int),
            ("Type", ctypes.c_int)
        ]

    _RETURN_TYPE_MAP = {
        'void': 0,
        'int': 1,
        'bool': 2,
        'double': 3,
        'string': 4,
    }

    def __init__(self, logger, dll_relative_path: str = 'tools\\ParallelPython.dll'):
        self.logger = logger
        self._dll_path = self._resolve_dll_path(dll_relative_path)
        self._dll = None
        self._registered_callbacks: Dict[str, Callable] = {}
        self._callback_wrappers: Dict[str, Any] = {}
        self._parallel_queues: Dict[str, list[tuple]] = {}  # name → list of (wrapper, type, result_obj)
        self.csharp_logger = CSharpLogger(self.logger)
        self._process = psutil.Process(os.getpid())
        self._cpu_usage_history = deque(maxlen=10)
        self._ram_buffer = None  # Attribute to hold allocated memory

        # Native process-output packet bridge.  The callback is intentionally
        # invoked synchronously only long enough for ProcessManager to enqueue
        # the frame; no packet analysis or router work occurs on a DLL thread.
        self._packet_callback: Optional[Callable[..., Any]] = None
        self._packet_callback_wrapper = None
        self._packet_callback_ex_wrapper = None
        self._packet_callback_lock = threading.RLock()
        self._packet_source = "ParallelPython.dll"
        self._packet_pid: Optional[int] = None
        self._packet_stats = {
            "received": 0, "accepted": 0, "rejected": 0, "errors": 0, "bytes": 0,
        }
        self._last_packet_error_log = 0.0
        self._stopped = False

        self._load_dll()

        atexit.register(self.stop)
        self.logger.log_message("[C#] [Python] ParallelPythonTool initialized for native interop.")

    def __del__(self):
        self.stop()

    def get_resource_usage(self) -> dict:
        """
        Returns a dictionary with current CPU and memory usage of the process.
        Normalizes CPU usage to a 0–100% scale based on total logical cores.
        """
        # interval=None/0.0 is non-blocking.  A one-second sampling interval
        # previously stalled whichever router/GUI thread requested statistics.
        cpu_percent_raw = self._process.cpu_percent(interval=None)
        memory_info = self._process.memory_info()
        logical_cores = psutil.cpu_count(logical=True)
        max_possible = 100 * logical_cores if logical_cores else 100
        cpu_percent_normalized = min((cpu_percent_raw / max_possible) * 100, 100.0) if max_possible > 0 else 0.0

        return {
            "cpu_percent": cpu_percent_normalized,
            "memory_usage_mb": memory_info.rss / (1024 * 1024)
        }

    def _burn_worker(self, stop_evt: threading.Event, busy_fraction: float, period_sec: float) -> None:
        """
        One worker that uses a fixed duty cycle:
        - busy for (busy_fraction * period_sec)
        - sleep for the remainder
        """
        busy_time = max(0.0, min(1.0, busy_fraction)) * period_sec
        idle_time = max(0.0, period_sec - busy_time)

        # A tight spin that avoids function call overhead inside the loop
        while not stop_evt.is_set():
            start = time.perf_counter()
            # Busy phase
            while (time.perf_counter() - start) < busy_time and not stop_evt.is_set():
                pass
            # Idle phase
            if idle_time > 0:
                stop_evt.wait(idle_time)

    def _burn_cpu_in_this_process(self, target_percent: float,
                                  duration_sec: Optional[float],
                                  workers: Optional[int],
                                  period_ms: int = 100) -> None:
        """
        Create N threads that collectively approximate the requested CPU utilization.
        - target_percent: 0..100 (per *process*, across all logical cores)
        - duration_sec: None = run until stop_evt is set externally (not exposed here);
                        otherwise run for given seconds and stop automatically
        - workers: number of worker threads; default = os.cpu_count() or 1
        - period_ms: control loop period (smaller -> smoother but more overhead)
        """
        logical_cores = os.cpu_count() or 1
        workers = workers or logical_cores
        workers = max(1, workers)

        # Normalize the total busy fraction across workers.
        # Example: on 8 cores, 400% target means roughly 4 full-busy threads.
        # Clamp to a sane range.
        total_core_percent = max(0.0, min(100.0, float(target_percent))) * logical_cores / 100.0
        per_worker_busy = max(0.0, min(1.0, total_core_percent / workers))

        stop_evt = threading.Event()
        threads = []
        for _ in range(workers):
            t = threading.Thread(
                target=self._burn_worker,
                args=(stop_evt, per_worker_busy, period_ms / 1000.0),
                daemon=True
            )
            t.start()
            threads.append(t)

        try:
            if duration_sec is None:
                # Run until externally stopped (not exposed by this simple helper)
                while True:
                    time.sleep(1)
            else:
                time.sleep(max(0.0, float(duration_sec)))
        finally:
            stop_evt.set()
            for t in threads:
                t.join(timeout=1.0)

    def raise_cpu_usage_for_process_name(self, process_name: str = "Nate's Server",
                                         target_percent: float = 300.0,
                                         duration_sec: float = 10.0,
                                         workers: Optional[int] = None,
                                         logger=None) -> bool:
        """
        If the CURRENT process's executable name matches `process_name`,
        spin up worker threads to increase CPU usage for `duration_sec`.

        Returns True if load was applied; False if names didn't match.

        Notes:
          • This does NOT inject into other processes. It only burns CPU in *this*
            process when its name matches `process_name`. That keeps it safe and
            transparent.
          • `target_percent` is across all cores (e.g., 300 on an 8-core box is ~3 fully-busy cores).
          • If you're running from python.exe during development, this will only run
            automatically when your frozen/bundled exe is actually named
            'Nate's Server' (or whatever you pass in). While developing, either:
              - rename the check to match "python.exe", or
              - explicitly call `_burn_cpu_in_this_process(...)` instead.
        """
        try:
            me = psutil.Process(os.getpid())
            # Try both friendly name and basename of the exe path
            current_name = (me.name() or "").strip()
            exe_basename = (me.exe() or "").split(os.sep)[-1]

            matches = {current_name.lower(), exe_basename.lower()}
            want = process_name.lower()

            if want in matches:
                if logger:
                    logger.log_message(f"[CPU] Attaching to current process '{current_name}' (PID {me.pid}) "
                                       f"to raise CPU for {duration_sec}s at ~{target_percent}%...")
                self._burn_cpu_in_this_process(target_percent, duration_sec, workers)
                if logger:
                    logger.log_message("[CPU] Done raising CPU usage.")
                return True
            else:
                if logger:
                    logger.log_message(
                        f"[CPU] Skipped: current process is '{current_name}' (exe='{exe_basename}'), "
                        f"not '{process_name}'."
                    )
                return False
        except Exception as e:
            if logger:
                logger.log_message(f"[CPU] Error while attempting to raise CPU: {e}")
            else:
                print(f"[CPU] Error: {e}")
            return False
    # --------------------------- NEW RAM USAGE METHODS ---------------------------
    def increase_ram_usage(self, megabytes: int):
        """
        Allocates a large bytearray to increase the process's resident memory usage.
        psutil is used here to report the memory usage before and after.
        """
        if self._ram_buffer:
            self.logger.log_message(f"[RAM] ⚠️ Releasing existing RAM buffer before allocating a new one.")
            self.release_ram_usage()

        self.logger.log_message(f"[RAM] 📈 Attempting to allocate {megabytes} MB of RAM...")
        try:
            num_bytes = megabytes * 1024 * 1024

            # Get memory usage before allocation
            mem_before = self._process.memory_info().rss / (1024 * 1024)

            # Allocate the memory by creating a large bytearray
            self._ram_buffer = bytearray(num_bytes)

            # Get memory usage after allocation
            mem_after = self._process.memory_info().rss / (1024 * 1024)

            self.logger.log_message(
                f"[RAM] ✅ Successfully allocated buffer. Memory usage increased from {mem_before:.2f} MB to {mem_after:.2f} MB.")

        except MemoryError:
            self.logger.log_message(
                f"[RAM] ❌ MemoryError: Failed to allocate {megabytes} MB. The system may be out of memory.")
            self._ram_buffer = None
        except Exception as e:
            self.logger.log_message(f"[RAM] ❌ An unexpected error occurred during RAM allocation: {e}")
            self._ram_buffer = None

    def release_ram_usage(self):
        """
        Releases the memory allocated by `increase_ram_usage`.
        """
        if not self._ram_buffer:
            self.logger.log_message("[RAM] ℹ️ No RAM buffer to release.")
            return

        self.logger.log_message("[RAM] 📉 Releasing allocated RAM buffer...")
        mem_before = self._process.memory_info().rss / (1024 * 1024)

        # Setting the buffer to None allows the garbage collector to reclaim it
        self._ram_buffer = None
        gc.collect()  # Encourage garbage collection to run sooner

        mem_after = self._process.memory_info().rss / (1024 * 1024)
        self.logger.log_message(
            f"[RAM] ✅ RAM buffer released. Memory usage changed from {mem_before:.2f} MB to {mem_after:.2f} MB.")

    # -------------------------------------------------------------------------

    # -------------------- NATIVE PACKET OUTPUT BRIDGE --------------------
    @staticmethod
    def _coerce_packet_bytes(payload, length: Optional[int] = None) -> bytes:
        if payload is None:
            return b""
        try:
            normalized_length = None if length is None else max(0, int(getattr(length, "value", length)))
        except Exception:
            normalized_length = None

        if isinstance(payload, bytes):
            data = payload
        elif isinstance(payload, (bytearray, memoryview)):
            data = bytes(payload)
        elif isinstance(payload, (list, tuple)):
            data = bytes(payload)
        else:
            pointer_value = payload if isinstance(payload, int) else getattr(payload, "value", None)
            if isinstance(pointer_value, int) and pointer_value and normalized_length:
                data = ctypes.string_at(pointer_value, normalized_length)
            else:
                try:
                    data = bytes(payload)
                except Exception:
                    return b""
        return data[:normalized_length] if normalized_length is not None else data

    @staticmethod
    def _decode_packet_metadata(metadata) -> Dict[str, Any]:
        if metadata is None:
            return {}
        if isinstance(metadata, dict):
            return dict(metadata)
        if isinstance(metadata, ctypes.c_char_p):
            metadata = metadata.value
        if isinstance(metadata, bytes):
            text = metadata.decode("utf-8", "replace").strip()
        else:
            text = str(metadata).strip()
        if not text:
            return {}
        try:
            value = json.loads(text)
            return value if isinstance(value, dict) else {"native_metadata": value}
        except Exception:
            return {"native_metadata": text[:2048]}

    def set_packet_callback(
            self, callback: Optional[Callable[..., Any]], *,
            source: str = "ParallelPython.dll", pid: Optional[int] = None,
    ) -> bool:
        """Attach the nonblocking ProcessManager packet sink and bind optional DLL exports."""
        with self._packet_callback_lock:
            self._packet_callback = callback if callable(callback) else None
            self._packet_source = str(source or "ParallelPython.dll")
            self._packet_pid = int(pid) if pid is not None else None
        if self._packet_callback is None:
            self._unbind_native_packet_exports()
            return False
        self._bind_native_packet_exports()
        self.logger.log_message(
            f"[C#] [ProcessInterface] Native packet sink attached source={self._packet_source}."
        )
        return True

    # Common names recognized by ProcessManager.register_native_packet_source().
    register_packet_callback = set_packet_callback
    add_packet_callback = set_packet_callback
    set_output_callback = set_packet_callback

    def emit_native_packet(
            self, payload, length: Optional[int] = None, *, pid: Optional[int] = None,
            metadata: Optional[Dict[str, Any]] = None, source: Optional[str] = None,
    ) -> bool:
        """Submit one packet from a Python wrapper or native callback without blocking router work."""
        data = self._coerce_packet_bytes(payload, length)
        if not data:
            self._packet_stats["rejected"] += 1
            return False
        with self._packet_callback_lock:
            callback = self._packet_callback
            default_source = self._packet_source
            default_pid = self._packet_pid
        self._packet_stats["received"] += 1
        self._packet_stats["bytes"] += len(data)
        if not callable(callback):
            self._packet_stats["rejected"] += 1
            return False
        context = dict(metadata or {})
        context.setdefault("producer", "ParallelPythonTool")
        context.setdefault("native_process_output", True)
        try:
            try:
                accepted = callback(
                    data, len(data), source=str(source or default_source),
                    pid=pid if pid is not None else default_pid, metadata=context,
                )
            except TypeError:
                # Compatibility with simple callback(payload, length) consumers.
                accepted = callback(data, len(data))
            accepted = True if accepted is None else bool(accepted)
            self._packet_stats["accepted" if accepted else "rejected"] += 1
            return accepted
        except Exception as exc:
            self._packet_stats["errors"] += 1
            now = time.monotonic()
            if now - self._last_packet_error_log >= 5.0:
                self._last_packet_error_log = now
                self.logger.log_message(f"[C#] [ProcessInterface] Packet callback error: {exc}")
            return False

    submit_packet = emit_native_packet
    submit_native_packet = emit_native_packet

    def _native_packet_callback(self, payload_ptr, payload_length) -> None:
        self.emit_native_packet(
            payload_ptr, payload_length,
            metadata={"callback_abi": "void_ptr_size_t"},
        )

    def _native_packet_ex_callback(self, payload_ptr, payload_length, pid, metadata_json) -> None:
        metadata = self._decode_packet_metadata(metadata_json)
        metadata["callback_abi"] = "void_ptr_size_t_pid_json"
        self.emit_native_packet(payload_ptr, payload_length, pid=int(pid or 0) or None, metadata=metadata)

    def _bind_optional_callback_export(self, names, wrapper, argtype) -> Optional[str]:
        if self._dll is None:
            return None
        for name in names:
            fn = getattr(self._dll, name, None)
            if fn is None:
                continue
            try:
                fn.argtypes = [argtype]
                # Setters in existing helpers variously return void, BOOL, or int.
                # Do not inspect the return value; invoking the setter is sufficient.
                fn(wrapper)
                return name
            except Exception as exc:
                self.logger.log_message(f"[C#] [ProcessInterface] Callback export {name} failed: {exc}")
        return None

    def _bind_native_packet_exports(self) -> bool:
        if self._dll is None or self._packet_callback is None:
            return False
        self._packet_callback_wrapper = self.NativePacketCallback(self._native_packet_callback)
        self._packet_callback_ex_wrapper = self.NativePacketExCallback(self._native_packet_ex_callback)
        bound = []
        name = self._bind_optional_callback_export(
            ("set_packet_callback", "register_packet_callback", "SetPacketCallback",
             "RegisterPacketCallback", "set_output_packet_callback", "SetOutputPacketCallback"),
            self._packet_callback_wrapper, self.NativePacketCallback,
        )
        if name:
            bound.append(name)
        name = self._bind_optional_callback_export(
            ("set_packet_callback_ex", "register_packet_callback_ex", "SetPacketCallbackEx",
             "RegisterPacketCallbackEx", "set_output_packet_callback_ex"),
            self._packet_callback_ex_wrapper, self.NativePacketExCallback,
        )
        if name:
            bound.append(name)
        if bound:
            self.logger.log_message(
                f"[C#] [ProcessInterface] ✅ Native packet callback export bound: {', '.join(bound)}"
            )
        else:
            self.logger.log_message(
                "[C#] [ProcessInterface] No packet callback export found; Python wrappers may still call emit_native_packet()."
            )
        return bool(bound)

    def _unbind_native_packet_exports(self) -> None:
        if self._dll is not None:
            for name in (
                    "set_packet_callback", "register_packet_callback", "SetPacketCallback",
                    "RegisterPacketCallback", "set_output_packet_callback", "SetOutputPacketCallback",
                    "set_packet_callback_ex", "register_packet_callback_ex", "SetPacketCallbackEx",
                    "RegisterPacketCallbackEx", "set_output_packet_callback_ex",
            ):
                fn = getattr(self._dll, name, None)
                if fn is None:
                    continue
                try:
                    fn(ctypes.c_void_p())
                except Exception:
                    pass
        self._packet_callback_wrapper = None
        self._packet_callback_ex_wrapper = None

    def detach_packet_callback(self) -> None:
        """Stop native packet delivery while keeping ParallelPython restart-safe."""
        self._unbind_native_packet_exports()
        with self._packet_callback_lock:
            self._packet_callback = None

    def packet_stats(self) -> Dict[str, int]:
        return dict(self._packet_stats)

    def inject_into(self, target_obj: object, primary_attr: str = 'logger',
                    fallback_attr: str = 'router_logger') -> bool:
        if hasattr(target_obj, primary_attr):
            setattr(target_obj, primary_attr, self.csharp_logger)
            return True
        elif hasattr(target_obj, fallback_attr):
            setattr(target_obj, fallback_attr, self.csharp_logger)
            return True
        return False

    def _resolve_dll_path(self, relative_path: str) -> str:
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))

        resolved_path = os.path.abspath(os.path.join(base_path, relative_path))
        if not os.path.exists(resolved_path):
            self.logger.log_message(f"[DLL Loader] ❌ DLL not found at: {resolved_path}")
        return resolved_path

    def _load_dll(self) -> bool:
        if self._dll:
            return True
        if not self._dll_path or not os.path.exists(self._dll_path):
            return False
        try:
            self.logger.log_message(f"[C#] [Python] 🚀 Loading C# DLL from: {self._dll_path}")
            self._dll = ctypes.cdll.LoadLibrary(str(self._dll_path))

            self._dll.invoke_python_callback.argtypes = [ctypes.c_void_p]
            self._dll.invoke_python_int.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            self._dll.invoke_python_bool.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_bool)]
            self._dll.invoke_python_double.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_double)]
            self._dll.invoke_python_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]

            self._dll.invoke_all_parallel.argtypes = [ctypes.c_void_p, ctypes.c_int]
            self._dll.invoke_all_parallel.restype = None

            if self._packet_callback is not None:
                self._bind_native_packet_exports()
            self.logger.log_message("[C#] [Python] ✅ C# DLL loaded successfully.")
            return True
        except Exception as e:
            self.logger.log_message(f"[C#] [Python] ❌ Failed to load DLL: {e}")
            return False

    def _create_callback_wrapper(self, func: Callable, return_type: str) -> tuple:
        if return_type not in self._RETURN_TYPE_MAP:
            raise ValueError(f"Invalid return type: {return_type}")

        if return_type == 'void':
            wrapper = self.PythonCallback(func)
            return wrapper, None
        elif return_type == 'int':
            result = ctypes.c_int()
            wrapper = self.IntCallback(lambda res_ptr: res_ptr.contents.__setattr__('value', func()))
            return wrapper, result
        elif return_type == 'bool':
            result = ctypes.c_bool()
            wrapper = self.BoolCallback(lambda res_ptr: res_ptr.contents.__setattr__('value', func()))
            return wrapper, result
        elif return_type == 'double':
            result = ctypes.c_double()
            wrapper = self.DoubleCallback(lambda res_ptr: res_ptr.contents.__setattr__('value', func()))
            return wrapper, result
        elif return_type == 'string':
            buffer_size = 1024
            buffer = ctypes.create_string_buffer(buffer_size)

            def string_cb(buf, size):
                encoded = func().encode('utf-8')
                ctypes.memmove(buf, encoded, min(len(encoded), size))

            wrapper = self.StringCallback(string_cb)
            return wrapper, buffer

    def register_callback(self, name: str, func: Callable, return_type: str = 'void') -> None:
        wrapper, _ = self._create_callback_wrapper(func, return_type)
        self._registered_callbacks[name] = func
        self._callback_wrappers[name] = wrapper
        self.logger.log_message(f"[C#] [Python] ✅ Registered callback: '{name}'")

    def run_all_parallel(self, funcs: list[tuple[Callable, tuple]], return_type: str = 'void') -> None:
        if not self._load_dll():
            return

        if return_type not in self._RETURN_TYPE_MAP:
            raise ValueError(f"Invalid return_type: {return_type}")
        descriptors = []
        typ = self._RETURN_TYPE_MAP[return_type]

        for func, args in funcs:
            wrapped_func = lambda f=func, a=args: f(*a)
            wrapper, result = self._create_callback_wrapper(wrapped_func, return_type)

            func_ptr = ctypes.cast(wrapper, ctypes.c_void_p)
            result_ptr = None
            buffer_size = 0

            if typ in [1, 2, 3]:
                result_ptr = ctypes.cast(ctypes.pointer(result), ctypes.c_void_p)
            elif typ == 4:
                result_ptr = ctypes.cast(result, ctypes.c_void_p)
                buffer_size = len(result)

            desc = self.PythonCallDescriptor(func_ptr, result_ptr, buffer_size, typ)
            descriptors.append(desc)

        count = len(descriptors)
        DescriptorArrayType = self.PythonCallDescriptor * count
        descriptor_array = DescriptorArrayType(*descriptors)

        self._dll.invoke_all_parallel(ctypes.cast(descriptor_array, ctypes.c_void_p), count)
        self.logger.log_message(f"[C#] [Python] 🚀 Ran {count} callbacks in batch via run_all_parallel()")

    def run_parallel(self, func: Callable, *args: Any, return_type: str = 'void', queue_name: str = None,
                     count_to_call=10) -> Any:
        if not self._load_dll():
            return
        if return_type == 'all':
            wrapped_func = lambda: func(*args)
            wrapper, result = self._create_callback_wrapper(wrapped_func, 'void')
            queue_key = queue_name or func.__name__

            if queue_key not in self._parallel_queues:
                self._parallel_queues[queue_key] = []

            self._parallel_queues[queue_key].append((wrapper, self._RETURN_TYPE_MAP['void'], result))
            self.logger.log_message(
                f"[C#] [Python] 📝 Queued '{queue_key}' parallel call ({len(self._parallel_queues[queue_key])}/{count_to_call})")

            if len(self._parallel_queues[queue_key]) >= count_to_call:
                self.csharp_logger.set_prefix("[C#]")
                self._flush_parallel_queue(queue_key)
            return None

        wrapped_func = lambda: func(*args)
        wrapper, result = self._create_callback_wrapper(wrapped_func, return_type)
        func_ptr = ctypes.cast(wrapper, ctypes.c_void_p)
        self.logger.log_message(
            f"[C#] [Python] ⚡ Running immediate callback (return_type='{return_type}') for '{func.__name__}'")

        if return_type == 'void':
            self._dll.invoke_python_callback(func_ptr)
            return None
        elif return_type == 'int':
            res = ctypes.c_int()
            self._dll.invoke_python_int(func_ptr, ctypes.byref(res))
            return res.value
        elif return_type == 'bool':
            res = ctypes.c_bool()
            self._dll.invoke_python_bool(func_ptr, ctypes.byref(res))
            return res.value
        elif return_type == 'double':
            res = ctypes.c_double()
            self._dll.invoke_python_double(func_ptr, ctypes.byref(res))
            return res.value
        elif return_type == 'string':
            buffer_size = 1024
            buffer = ctypes.create_string_buffer(buffer_size)
            self._dll.invoke_python_string(func_ptr, buffer, buffer_size)
            return buffer.value.decode('utf-8', errors='ignore')
        else:
            raise ValueError(f"Invalid return_type '{return_type}'")

    def _flush_parallel_queue(self, queue_key: str) -> None:
        self.csharp_logger.set_prefix("[C#]")
        if queue_key not in self._parallel_queues or not self._parallel_queues[queue_key]:
            return
        queue = self._parallel_queues[queue_key]
        count = len(queue)
        descriptors = []

        for wrapper, typ, result in queue:
            func_ptr = ctypes.cast(wrapper, ctypes.c_void_p)
            result_ptr = None
            buffer_size = 0

            if typ in [1, 2, 3]:
                result_ptr = ctypes.cast(ctypes.pointer(result), ctypes.c_void_p)
            elif typ == 4:
                result_ptr = ctypes.cast(result, ctypes.c_void_p)
                buffer_size = len(result)

            desc = self.PythonCallDescriptor(func_ptr, result_ptr, buffer_size, typ)
            descriptors.append(desc)

        DescriptorArrayType = self.PythonCallDescriptor * count
        descriptor_array = DescriptorArrayType(*descriptors)

        self._dll.invoke_all_parallel(ctypes.cast(descriptor_array, ctypes.c_void_p), count)
        self.logger.log_message(f"[C#] [Python] 🚀 Flushed {count} callbacks for '{queue_key}'")
        self._parallel_queues[queue_key] = []

    def run_normal(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        try:
            self.csharp_logger.set_prefix("")
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            self.logger.log_message(f"Error running function '{func.__name__}' normally: {e}")
            raise

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        # Release any allocated RAM before unloading the DLL.
        self.release_ram_usage()
        self._unbind_native_packet_exports()
        with self._packet_callback_lock:
            self._packet_callback = None

        if self._dll:
            try:
                if os.name == 'nt':
                    from ctypes import wintypes
                    hmodule = ctypes.c_void_p(self._dll._handle)
                    FreeLibrary = ctypes.windll.kernel32.FreeLibrary
                    FreeLibrary.argtypes = [wintypes.HMODULE]
                    FreeLibrary.restype = wintypes.BOOL
                    success = FreeLibrary(hmodule)
                    if not success:
                        raise ctypes.WinError()
                self.logger.log_message("[C#] [Python] ✅ C# DLL unloaded.")
            except Exception as e:
                self.logger.log_message(f"[C#] [Python] ⚠️ Failed to unload DLL: {e}")
            finally:
                self._dll = None


