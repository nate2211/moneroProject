"""Crash-isolated ctypes integration for PythonRuntime.dll and PythonUsage.dll.

Safety model
============

* XMRig is launched before this module starts any optional native service.
* Both DLLs live only inside a disposable helper process.
* PythonUsage follows the JIT worker's conservative pattern: keep one strong
  callback reference, serialize SetCallback/RunOnce, and invoke RunOnce from
  the helper's Python thread.  StartWorker is deliberately never used because
  a native background thread entering Python during shutdown can race callback
  lifetime and produce 0xC0000005 access violations.
* PythonRuntime keeps each ctypes input buffer alive until the corresponding
  asynchronous job is released.  The miner stdout path never waits for a DLL.

These services are diagnostics only.  XMRig remains the hashing process.
"""
from __future__ import annotations

import ctypes
import multiprocessing
import os
import queue
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

PYR_JOB_COPY = 1
_MAX_RUNTIME_PAYLOAD = 4096
_MAX_RUNTIME_RESULT = 64 * 1024
_RUNTIME_JOB_TIMEOUT_SEC = 30.0
_MIN_USAGE_INTERVAL_MS = 250
_MAX_USAGE_INTERVAL_MS = 60_000


class PyrConfig(ctypes.Structure):
    _fields_ = [
        ("worker_threads", ctypes.c_uint32),
        ("queue_capacity", ctypes.c_uint32),
        ("max_result_bytes", ctypes.c_uint32),
        ("max_jobs", ctypes.c_uint32),
    ]


class PyrJobInfo(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int32),
        ("finished", ctypes.c_uint8),
        ("cancelled", ctypes.c_uint8),
        ("reserved", ctypes.c_uint16),
        ("result_size", ctypes.c_uint32),
    ]


class PyrStats(ctypes.Structure):
    _fields_ = [(f"value_{index}", ctypes.c_uint64) for index in range(8)]


@dataclass
class _PendingRuntimeJob:
    """Own the native input memory for the complete asynchronous job lifetime."""

    buffer: ctypes.Array
    size: int
    submitted_at: float


@dataclass(frozen=True)
class DllState:
    available: bool
    enabled: bool
    path: str = ""
    error: str = ""


def _candidate_paths(filename: str) -> list[str]:
    roots: list[Path] = []
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.extend((Path(meipass), Path(meipass) / "tools"))
    here = Path(__file__).resolve().parent
    roots.extend((here, here / "tools", here.parent / "tools"))

    result: list[str] = []
    for root in roots:
        try:
            candidate = str((root / filename).resolve())
        except Exception:
            continue
        if candidate not in result:
            result.append(candidate)
    return result


def _open_dll(path: str) -> tuple[ctypes.CDLL, object | None]:
    """Load a DLL while keeping its dependency directory registered."""

    directory_handle = None
    if os.name == "nt":
        dll_dir = os.path.dirname(path)
        if dll_dir and hasattr(os, "add_dll_directory"):
            try:
                directory_handle = os.add_dll_directory(dll_dir)
            except Exception:
                directory_handle = None
    try:
        return ctypes.CDLL(path), directory_handle
    except BaseException:
        if directory_handle is not None:
            try:
                directory_handle.close()
            except Exception:
                pass
        raise


class PythonRuntimeBridge:
    """Single-thread-owned wrapper around PythonRuntime.dll."""

    def __init__(self, logger=None):
        self.logger = logger
        self.dll: Optional[ctypes.CDLL] = None
        self._dll_dir_handle = None
        self.path = ""
        self.load_error = ""
        self.handle: Optional[int] = None
        self.enabled = False
        self.pending: dict[int, _PendingRuntimeJob] = {}
        self.submitted = 0
        self.completed = 0
        self.failed = 0
        self.dropped = 0
        self.timed_out = 0
        self._lock = threading.RLock()

    def _log(self, message: str) -> None:
        if self.logger is not None:
            try:
                self.logger.log_message(message)
            except Exception:
                pass

    def _load(self) -> bool:
        if self.dll is not None:
            return True
        if os.name != "nt":
            self.load_error = "PythonRuntime.dll is Windows-only"
            return False

        errors: list[str] = []
        for path in _candidate_paths("PythonRuntime.dll"):
            if not os.path.exists(path):
                continue
            directory_handle = None
            try:
                dll, directory_handle = _open_dll(path)
                self._bind(dll)
                self.dll = dll
                self._dll_dir_handle = directory_handle
                self.path = path
                self._log(f"[PythonRuntime] Loaded from {path}")
                return True
            except BaseException as exc:
                if directory_handle is not None:
                    try:
                        directory_handle.close()
                    except Exception:
                        pass
                errors.append(f"{path}: {exc}")

        self.load_error = "; ".join(errors) if errors else "PythonRuntime.dll not found"
        self._log(f"[PythonRuntime] Optional DLL unavailable: {self.load_error}")
        return False

    @classmethod
    def _bind(cls, dll: ctypes.CDLL) -> None:
        dll.pyr_create.argtypes = [ctypes.POINTER(PyrConfig)]
        dll.pyr_create.restype = ctypes.c_void_p
        dll.pyr_destroy.argtypes = [ctypes.c_void_p]
        dll.pyr_destroy.restype = None
        dll.pyr_submit.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
        dll.pyr_submit.restype = ctypes.c_uint64
        dll.pyr_query_job.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(PyrJobInfo)]
        dll.pyr_query_job.restype = ctypes.c_int32
        dll.pyr_wait_job.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(PyrJobInfo)]
        dll.pyr_wait_job.restype = ctypes.c_int32
        dll.pyr_copy_result.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        dll.pyr_copy_result.restype = ctypes.c_int32
        dll.pyr_release_job.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        dll.pyr_release_job.restype = ctypes.c_int32
        dll.pyr_cancel.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        dll.pyr_cancel.restype = ctypes.c_int32
        dll.pyr_get_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(PyrStats)]
        dll.pyr_get_stats.restype = ctypes.c_int32
        dll.pyr_get_last_error_copy.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        dll.pyr_get_last_error_copy.restype = ctypes.c_int32
        dll.pyr_status_string.argtypes = [ctypes.c_int32]
        dll.pyr_status_string.restype = ctypes.c_char_p

    def set_enabled(self, enabled: bool) -> bool:
        with self._lock:
            if not enabled:
                self.close()
                return True
            if self.enabled and self.handle:
                return True
            if not self._load():
                return False

            config = PyrConfig(
                worker_threads=1,
                queue_capacity=128,
                max_result_bytes=_MAX_RUNTIME_RESULT,
                max_jobs=128,
            )
            try:
                raw_handle = self.dll.pyr_create(ctypes.byref(config)) if self.dll else None
            except BaseException as exc:
                self.load_error = f"pyr_create raised {type(exc).__name__}: {exc}"
                return False

            handle = int(raw_handle or 0)
            if not handle:
                self.load_error = self.last_error() or "pyr_create returned null"
                self._log(f"[PythonRuntime] Start failed: {self.load_error}")
                return False

            self.handle = handle
            self.enabled = True
            self.pending.clear()
            self._log("[PythonRuntime] Isolated asynchronous diagnostics queue enabled.")
            return True

    def observe(self, text: str) -> None:
        if not self.enabled or not self.handle or not self.dll or not text:
            return

        payload = text.encode("utf-8", errors="replace")[:_MAX_RUNTIME_PAYLOAD]
        if not payload:
            return

        with self._lock:
            self.poll(max_jobs=8)
            if len(self.pending) >= 64:
                self.dropped += 1
                return

            # Keep this object in self.pending until release_job.  Even if the DLL
            # defers its copy, it never receives a pointer to freed Python memory.
            buffer = ctypes.create_string_buffer(payload, len(payload))
            try:
                job_id = int(
                    self.dll.pyr_submit(
                        ctypes.c_void_p(self.handle),
                        ctypes.c_int32(PYR_JOB_COPY),
                        ctypes.cast(buffer, ctypes.c_void_p),
                        ctypes.c_uint32(len(payload)),
                    )
                )
            except BaseException:
                self.failed += 1
                return

            if job_id <= 0:
                self.failed += 1
                return

            self.pending[job_id] = _PendingRuntimeJob(
                buffer=buffer,
                size=len(payload),
                submitted_at=time.monotonic(),
            )
            self.submitted += 1

    def _release(self, job_id: int, *, cancel: bool = False) -> None:
        if not self.dll or not self.handle:
            self.pending.pop(job_id, None)
            return
        try:
            if cancel:
                self.dll.pyr_cancel(ctypes.c_void_p(self.handle), ctypes.c_uint64(job_id))
        except BaseException:
            pass
        try:
            self.dll.pyr_release_job(ctypes.c_void_p(self.handle), ctypes.c_uint64(job_id))
        except BaseException:
            pass
        finally:
            # Releasing the Python buffer only after the native job is released is
            # the core lifetime guarantee.
            self.pending.pop(job_id, None)

    def poll(self, max_jobs: int = 16) -> None:
        if not self.enabled or not self.handle or not self.dll:
            return

        now = time.monotonic()
        for job_id in list(self.pending)[: max(1, int(max_jobs))]:
            pending = self.pending.get(job_id)
            if pending is None:
                continue
            if now - pending.submitted_at > _RUNTIME_JOB_TIMEOUT_SEC:
                self.timed_out += 1
                self._release(job_id, cancel=True)
                continue

            info = PyrJobInfo()
            try:
                status = int(
                    self.dll.pyr_query_job(
                        ctypes.c_void_p(self.handle),
                        ctypes.c_uint64(job_id),
                        ctypes.byref(info),
                    )
                )
            except BaseException:
                self.failed += 1
                self._release(job_id, cancel=True)
                continue

            if status < 0:
                self.failed += 1
                self._release(job_id)
                continue
            if not bool(info.finished):
                continue

            result_size = max(0, int(info.result_size))
            if result_size > _MAX_RUNTIME_RESULT:
                self.failed += 1
                self._release(job_id, cancel=True)
                continue

            if result_size:
                written = ctypes.c_uint32(0)
                result = ctypes.create_string_buffer(result_size)
                try:
                    copy_status = int(
                        self.dll.pyr_copy_result(
                            ctypes.c_void_p(self.handle),
                            ctypes.c_uint64(job_id),
                            ctypes.cast(result, ctypes.c_void_p),
                            ctypes.c_uint32(result_size),
                            ctypes.byref(written),
                        )
                    )
                except BaseException:
                    copy_status = -1
                if copy_status < 0:
                    self.failed += 1
                else:
                    self.completed += 1
            else:
                self.completed += 1

            self._release(job_id)

    def last_error(self) -> str:
        if not self.dll or not self.handle:
            return self.load_error
        buffer = ctypes.create_string_buffer(1024)
        written = ctypes.c_uint32(0)
        try:
            self.dll.pyr_get_last_error_copy(
                ctypes.c_void_p(self.handle),
                ctypes.cast(buffer, ctypes.c_void_p),
                ctypes.c_uint32(len(buffer)),
                ctypes.byref(written),
            )
            return buffer.value.decode("utf-8", errors="replace")
        except BaseException:
            return self.load_error

    def close(self) -> None:
        with self._lock:
            if self.dll and self.handle:
                for job_id in list(self.pending):
                    self._release(job_id, cancel=True)
                try:
                    self.dll.pyr_destroy(ctypes.c_void_p(self.handle))
                except BaseException as exc:
                    self._log(f"[PythonRuntime] Shutdown warning: {exc}")
            self.pending.clear()
            self.handle = None
            self.enabled = False
            # Do not force FreeLibrary.  The disposable helper process owns the
            # module until process exit, avoiding unload races with native state.

    @property
    def state(self) -> DllState:
        return DllState(self.dll is not None, self.enabled, self.path, self.load_error)


class PythonUsageBridge:
    """One-shot PythonUsage wrapper modeled after jit_worker.py.

    The DLL's StartWorker export is intentionally not called.  All native calls
    are serialized on the helper's Python thread, and the callback object remains
    strongly referenced until the helper process exits.
    """

    CALLBACK = ctypes.CFUNCTYPE(ctypes.c_int32)

    def __init__(self, logger=None):
        self.logger = logger
        self.dll: Optional[ctypes.CDLL] = None
        self._dll_dir_handle = None
        self.path = ""
        self.load_error = ""
        self.enabled = False
        self._provider: Callable[[], int] = lambda: 0
        self._callback = None
        self._callback_address = 0
        self._lock = threading.RLock()
        self.calls = 0
        self.failures = 0
        self.last_result = 0
        self.preflight_result = 0
        self.abi_version = 0

    def _log(self, message: str) -> None:
        if self.logger is not None:
            try:
                self.logger.log_message(message)
            except Exception:
                pass

    def _load(self) -> bool:
        if self.dll is not None:
            return True
        if os.name != "nt":
            self.load_error = "PythonUsage.dll is Windows-only"
            return False

        errors: list[str] = []
        for path in _candidate_paths("PythonUsage.dll"):
            if not os.path.exists(path):
                continue
            directory_handle = None
            try:
                dll, directory_handle = _open_dll(path)
                self._bind(dll)
                version = int(dll.GetPythonUsageVersion())
                if version < 2:
                    raise RuntimeError(
                        f"unsafe PythonUsage ABI version {version}; "
                        "ABI v1 is quarantined because its SetCallback can access-violate"
                    )
                self.abi_version = version
                self.dll = dll
                self._dll_dir_handle = directory_handle
                self.path = path
                self._log(f"[PythonUsage] Loaded from {path}")
                return True
            except BaseException as exc:
                if directory_handle is not None:
                    try:
                        directory_handle.close()
                    except Exception:
                        pass
                errors.append(f"{path}: {exc}")

        self.load_error = "; ".join(errors) if errors else "PythonUsage.dll not found"
        self._log(f"[PythonUsage] Optional DLL unavailable: {self.load_error}")
        return False

    @classmethod
    def _bind(cls, dll: ctypes.CDLL) -> None:
        dll.GetPythonUsageVersion.argtypes = []
        dll.GetPythonUsageVersion.restype = ctypes.c_int32
        # Bind the exact header ABI: typedef int (__cdecl *PythonCallback)();
        # Passing the typed callback lets ctypes validate the trampoline type.
        dll.SetCallback.argtypes = [cls.CALLBACK]
        dll.SetCallback.restype = ctypes.c_int32
        dll.RunOnce.argtypes = []
        dll.RunOnce.restype = ctypes.c_int32
        dll.RunMany.argtypes = [ctypes.c_int32]
        dll.RunMany.restype = ctypes.c_int32
        dll.StartWorker.argtypes = [ctypes.c_int32]
        dll.StartWorker.restype = ctypes.c_int32
        dll.StopWorker.argtypes = []
        dll.StopWorker.restype = ctypes.c_int32
        dll.IsWorkerRunning.argtypes = []
        dll.IsWorkerRunning.restype = ctypes.c_int32
        dll.GetCallCount.argtypes = []
        dll.GetCallCount.restype = ctypes.c_uint64
        dll.GetLastResult.argtypes = []
        dll.GetLastResult.restype = ctypes.c_int32
        dll.ResetStats.argtypes = []
        dll.ResetStats.restype = None

    def set_function(self, provider: Callable[[], int]) -> bool:
        """Bind one long-lived callback, matching jit_worker's set/run pattern."""

        with self._lock:
            if not self._load():
                return False
            if provider is None or not callable(provider):
                self.load_error = "PythonUsage provider is not callable"
                return False

            self._provider = provider

            @self.CALLBACK
            def callback() -> int:
                try:
                    value = int(self._provider())
                except BaseException:
                    return -1
                return max(-2_147_483_648, min(2_147_483_647, value))

            # Store the callback before publishing its address to native code.
            # The DLL may retain this address globally after SetCallback returns.
            self._callback = callback
            self._callback_address = int(ctypes.cast(callback, ctypes.c_void_p).value or 0)
            if not self._callback_address:
                self.load_error = "ctypes produced a null PythonUsage callback"
                return False

            try:
                rc = int(self.dll.SetCallback(callback))
            except BaseException as exc:
                self.load_error = f"SetCallback raised {type(exc).__name__}: {exc}"
                return False
            if rc != 1:
                self.load_error = f"SetCallback failed with result {rc}"
                return False

            try:
                self.dll.ResetStats()
            except BaseException:
                pass
            self.enabled = True
            return True

    def run_once(self) -> int:
        """Invoke the callback synchronously from the helper's Python thread."""

        with self._lock:
            if not self.enabled or self.dll is None or self._callback is None:
                raise RuntimeError("PythonUsage callback is not configured")
            try:
                result = int(self.dll.RunOnce())
            except BaseException as exc:
                self.failures += 1
                raise RuntimeError(f"PythonUsage RunOnce failed: {type(exc).__name__}: {exc}") from exc

            self.calls += 1
            self.last_result = result
            return result

    def set_enabled(self, enabled: bool, provider: Callable[[], int], interval_ms: int = 1000) -> bool:
        """Compatibility API; interval is scheduled by Python, never StartWorker."""

        del interval_ms
        with self._lock:
            if not enabled:
                self.stop()
                return True
            if not self.set_function(provider):
                return False
            # A single synchronous preflight catches ABI/callback problems inside
            # the already-isolated helper before it reports ready.
            self.preflight_result = self.run_once()
            self._log("[PythonUsage] Safe one-shot callback mode enabled; native StartWorker is disabled.")
            return True

    def stop(self) -> None:
        with self._lock:
            self.enabled = False
            # Deliberately retain _callback. SetCallback rejects null and the DLL
            # stores the address globally. Keeping the object alive until process
            # exit makes an accidental late RunOnce harmless instead of jumping
            # through a freed callback trampoline.

    def snapshot(self) -> dict[str, int | bool]:
        with self._lock:
            dll_calls = self.calls
            dll_last = self.last_result
            if self.dll is not None:
                try:
                    dll_calls = int(self.dll.GetCallCount())
                except BaseException:
                    pass
                try:
                    dll_last = int(self.dll.GetLastResult())
                except BaseException:
                    pass
            return {
                "running": False,
                "one_shot_mode": True,
                "callback_bound": bool(self._callback_address),
                "call_count": int(dll_calls),
                "last_result": int(dll_last),
                "failures": int(self.failures),
                "abi_version": int(self.abi_version),
            }

    @property
    def state(self) -> DllState:
        return DllState(self.dll is not None, self.enabled, self.path, self.load_error)


def _safe_status_put(status_queue, message) -> None:
    try:
        status_queue.put_nowait(message)
    except BaseException:
        pass


def _optional_dll_worker(
    command_queue,
    status_queue,
    stop_event,
    runtime_enabled: bool,
    usage_enabled: bool,
    usage_interval_ms: int,
) -> None:
    """Own both third-party DLLs in a disposable, single-native-call thread."""

    runtime = PythonRuntimeBridge(logger=None)
    usage = PythonUsageBridge(logger=None)
    current_hashrate = 0
    usage_interval_sec = max(
        _MIN_USAGE_INTERVAL_MS,
        min(_MAX_USAGE_INTERVAL_MS, int(usage_interval_ms)),
    ) / 1000.0
    next_usage_call = time.monotonic() + usage_interval_sec

    try:
        runtime_ok = False
        usage_ok = False

        if runtime_enabled:
            try:
                runtime_ok = bool(runtime.set_enabled(True))
            except BaseException as exc:
                runtime.load_error = f"worker initialization error: {type(exc).__name__}: {exc}"

        if usage_enabled:
            try:
                usage_ok = bool(usage.set_enabled(True, lambda: int(current_hashrate)))
            except BaseException as exc:
                usage.load_error = f"worker initialization error: {type(exc).__name__}: {exc}"

        _safe_status_put(
            status_queue,
            {
                "type": "ready",
                "runtime_enabled": runtime_ok,
                "usage_enabled": usage_ok,
                "runtime_error": runtime.load_error,
                "usage_error": usage.load_error,
                "usage_mode": "python_scheduled_run_once",
                "usage_preflight_result": usage.preflight_result,
            },
        )

        while not stop_event.is_set():
            timeout = 0.10
            if usage_ok:
                timeout = max(0.01, min(timeout, next_usage_call - time.monotonic()))

            try:
                message = command_queue.get(timeout=timeout)
            except queue.Empty:
                message = None
            except (EOFError, OSError):
                break

            if message:
                kind = message[0]
                if kind == "stop":
                    break
                if kind == "line" and runtime_ok:
                    runtime.observe(str(message[1]))
                elif kind == "hashrate":
                    try:
                        current_hashrate = max(0, min(2_147_483_647, int(message[1])))
                    except (TypeError, ValueError):
                        pass

            if runtime_ok:
                try:
                    runtime.poll(max_jobs=32)
                except BaseException as exc:
                    runtime_ok = False
                    runtime.load_error = f"runtime disabled after poll error: {type(exc).__name__}: {exc}"
                    _safe_status_put(
                        status_queue,
                        {"type": "runtime_disabled", "error": runtime.load_error},
                    )

            now = time.monotonic()
            if usage_ok and now >= next_usage_call:
                next_usage_call = now + usage_interval_sec
                try:
                    usage.run_once()
                except BaseException as exc:
                    usage_ok = False
                    usage.stop()
                    usage.load_error = f"usage disabled after RunOnce error: {type(exc).__name__}: {exc}"
                    _safe_status_put(
                        status_queue,
                        {"type": "usage_disabled", "error": usage.load_error},
                    )

        _safe_status_put(
            status_queue,
            {
                "type": "stopping",
                "runtime_submitted": runtime.submitted,
                "runtime_completed": runtime.completed,
                "runtime_failed": runtime.failed,
                "runtime_dropped": runtime.dropped,
                "runtime_timed_out": runtime.timed_out,
                "usage": usage.snapshot(),
            },
        )
    except BaseException as exc:
        _safe_status_put(
            status_queue,
            {"type": "crashed", "error": f"{type(exc).__name__}: {exc}"},
        )
    finally:
        try:
            usage.stop()
        except BaseException:
            pass
        try:
            runtime.close()
        except BaseException:
            pass


def _decode_process_exit(exit_code) -> tuple[str, bool]:
    if exit_code is None:
        return "still running", False
    try:
        signed = int(exit_code)
    except Exception:
        return str(exit_code), False
    unsigned = signed & 0xFFFFFFFF
    known = {
        0xC0000005: "access violation (0xC0000005)",
        0xC000001D: "illegal instruction (0xC000001D)",
        0xC0000094: "integer divide by zero (0xC0000094)",
        0xC0000409: "stack buffer overrun / fast-fail (0xC0000409)",
    }
    if unsigned in known:
        return known[unsigned], unsigned == 0xC0000005
    return f"exit code {signed} (0x{unsigned:08X})", False


class OptionalPythonDllServices:
    """Best-effort controller whose errors never escape into mining."""

    def __init__(self, logger=None):
        self.logger = logger
        self._ctx = multiprocessing.get_context("spawn")
        self._process = None
        self._command_queue = None
        self._status_queue = None
        self._stop_event = None
        self._usage_provider: Callable[[], int] = lambda: 0
        self._runtime_requested = False
        self._usage_requested = False
        self._runtime_active = False
        self._usage_active = False
        self._last_usage_push = 0.0
        self._dropped_messages = 0
        self._last_error = ""
        self._last_status = {}
        self._exit_reported = False
        self._access_violation_detected = False
        self._lock = threading.RLock()

    def _log(self, message: str) -> None:
        if self.logger is not None:
            try:
                self.logger.log_message(message)
            except Exception:
                pass

    def _drain_status(self) -> None:
        status_queue = self._status_queue
        if status_queue is None:
            return

        while True:
            try:
                status = status_queue.get_nowait()
            except queue.Empty:
                break
            except BaseException:
                break

            if not isinstance(status, dict):
                continue
            self._last_status = status
            kind = status.get("type")

            if kind == "ready":
                self._runtime_active = bool(status.get("runtime_enabled"))
                self._usage_active = bool(status.get("usage_enabled"))
                runtime_error = str(status.get("runtime_error") or "")
                usage_error = str(status.get("usage_error") or "")
                if self._runtime_requested and not self._runtime_active:
                    self._log(
                        "[PythonRuntime] Isolated helper could not enable the DLL; "
                        f"mining continues normally. {runtime_error}"
                    )
                if self._usage_requested and not self._usage_active:
                    self._log(
                        "[PythonUsage] Safe one-shot preflight failed; "
                        f"mining continues normally. {usage_error}"
                    )
                if self._runtime_active and self._usage_active:
                    self._log(
                        "[Optional DLLs] Isolated helper active: PythonRuntime enabled; "
                        "safe PythonUsage ABI v2 enabled in serialized RunOnce mode."
                    )
                elif self._runtime_active:
                    self._log(
                        "[Optional DLLs] Isolated helper active for PythonRuntime only; "
                        "PythonUsage is disabled."
                    )
                elif self._usage_active:
                    self._log(
                        "[Optional DLLs] Isolated helper active for safe PythonUsage ABI v2 "
                        "in serialized RunOnce mode."
                    )
            elif kind == "usage_disabled":
                self._usage_active = False
                self._last_error = str(status.get("error") or "PythonUsage disabled")
                self._log(f"[PythonUsage] Disabled safely inside helper: {self._last_error}")
            elif kind == "runtime_disabled":
                self._runtime_active = False
                self._last_error = str(status.get("error") or "PythonRuntime disabled")
                self._log(f"[PythonRuntime] Disabled safely inside helper: {self._last_error}")
            elif kind == "crashed":
                self._last_error = str(status.get("error") or "unknown helper failure")
                self._runtime_active = False
                self._usage_active = False
                self._log(
                    "[Optional DLLs] Helper stopped unexpectedly; mining is unaffected. "
                    f"{self._last_error}"
                )

    def _put_nowait(self, message) -> bool:
        command_queue = self._command_queue
        process = self._process
        if command_queue is None or process is None or not process.is_alive():
            return False
        try:
            command_queue.put_nowait(message)
            return True
        except queue.Full:
            self._dropped_messages += 1
            return False
        except BaseException:
            return False

    def configure(
        self,
        runtime_enabled: bool,
        usage_enabled: bool,
        usage_interval_ms: int,
        usage_provider: Callable[[], int],
    ) -> None:
        with self._lock:
            try:
                self.stop_active()
                self._runtime_requested = bool(runtime_enabled)
                self._usage_requested = bool(usage_enabled)
                self._runtime_active = False
                self._usage_active = False
                self._usage_provider = usage_provider or (lambda: 0)
                self._last_error = ""
                self._last_status = {}
                self._exit_reported = False
                self._access_violation_detected = False
                self._dropped_messages = 0
                self._last_usage_push = 0.0

                if not self._runtime_requested and not self._usage_requested:
                    return

                self._command_queue = self._ctx.Queue(maxsize=256)
                self._status_queue = self._ctx.Queue(maxsize=32)
                self._stop_event = self._ctx.Event()
                self._process = self._ctx.Process(
                    target=_optional_dll_worker,
                    args=(
                        self._command_queue,
                        self._status_queue,
                        self._stop_event,
                        self._runtime_requested,
                        self._usage_requested,
                        max(
                            _MIN_USAGE_INTERVAL_MS,
                            min(_MAX_USAGE_INTERVAL_MS, int(usage_interval_ms)),
                        ),
                    ),
                    name="XmrigOptionalDllHost",
                    daemon=True,
                )
                self._process.start()
                self._log("[Optional DLLs] Started crash-isolated helper after XMRig launch.")
            except BaseException as exc:
                self._last_error = repr(exc)
                self._runtime_active = False
                self._usage_active = False
                self._log(
                    "[Optional DLLs] Helper could not start; mining continues without it. "
                    f"{self._last_error}"
                )
                self.stop_active()

    def _check_process(self) -> bool:
        process = self._process
        if process is None:
            return False
        if process.is_alive():
            return True
        if not self._exit_reported:
            self._exit_reported = True
            description, is_access_violation = _decode_process_exit(process.exitcode)
            self._access_violation_detected = is_access_violation
            self._last_error = f"helper {description}"
            if is_access_violation:
                self._log(
                    "[Optional DLLs] Helper encountered a native access violation and was "
                    "quarantined. XMRig remains running and the DLLs will not be retried "
                    "during this mining session."
                )
            else:
                self._log(
                    "[Optional DLLs] Helper exited; optional services are disabled while "
                    f"XMRig keeps running ({description})."
                )
        self._runtime_active = False
        self._usage_active = False
        return False

    def observe_output(self, text: str) -> None:
        try:
            self._drain_status()
            if not self._check_process():
                return

            if self._runtime_requested and text:
                self._put_nowait(("line", str(text)[:_MAX_RUNTIME_PAYLOAD]))

            now = time.monotonic()
            if self._usage_requested and now - self._last_usage_push >= 0.25:
                self._last_usage_push = now
                try:
                    sample = int(self._usage_provider())
                except BaseException:
                    sample = 0
                self._put_nowait(("hashrate", sample))
        except BaseException:
            return

    def update_hashrate(self, value) -> None:
        try:
            self._drain_status()
            if self._usage_requested and self._check_process():
                self._put_nowait(("hashrate", int(float(value or 0))))
        except BaseException:
            pass

    def stop_active(self) -> None:
        with self._lock:
            process = self._process
            try:
                if self._stop_event is not None:
                    self._stop_event.set()
                self._put_nowait(("stop",))
                if process is not None and process.is_alive():
                    process.join(timeout=2.0)
                if process is not None and process.is_alive():
                    process.terminate()
                    process.join(timeout=1.0)
            except BaseException:
                pass
            finally:
                self._drain_status()
                for managed_queue in (self._command_queue, self._status_queue):
                    if managed_queue is not None:
                        try:
                            managed_queue.close()
                            managed_queue.cancel_join_thread()
                        except BaseException:
                            pass
                self._process = None
                self._command_queue = None
                self._status_queue = None
                self._stop_event = None
                self._runtime_active = False
                self._usage_active = False

    def shutdown(self) -> None:
        self.stop_active()

    def status_snapshot(self) -> dict[str, int | bool | str | None]:
        self._drain_status()
        process_alive = bool(self._process is not None and self._process.is_alive())
        exit_code = self._process.exitcode if self._process is not None else None
        return {
            "helper_process_alive": process_alive,
            "helper_exit_code": exit_code,
            "python_runtime_requested": self._runtime_requested,
            "python_runtime_enabled": self._runtime_active,
            "python_usage_requested": self._usage_requested,
            "python_usage_enabled": self._usage_active,
            "python_usage_mode": "python_scheduled_run_once_abi_v2",
            "native_startworker_used": False,
            "access_violation_detected": self._access_violation_detected,
            "dropped_messages": self._dropped_messages,
            "last_error": self._last_error,
        }
