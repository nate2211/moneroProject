import asyncio
import atexit
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



class ParallelPythonTool:
    PythonCallback = ctypes.CFUNCTYPE(None)
    IntCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_int))
    BoolCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_bool))
    DoubleCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_double))
    StringCallback = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int)

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
        self._parallel_queues: Dict[str, list[tuple]] = {}  # name → list of (wrapper, type, result_obj)\
        self.csharp_logger = CSharpLogger(self.logger)
        self._process = psutil.Process(os.getpid())
        self._cpu_usage_history = deque(maxlen=10)
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
        cpu_percent_raw = self._process.cpu_percent(interval=1)
        memory_info = self._process.memory_info()
        logical_cores = psutil.cpu_count(logical=True)  # e.g., 32
        max_possible = 100 * logical_cores
        cpu_percent_normalized = min((cpu_percent_raw / max_possible) * 100, 100.0)

        return {
            "cpu_percent": cpu_percent_normalized,
            "memory_usage_mb": memory_info.rss / (1024 * 1024)
        }
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
        """
        Resolves the correct absolute path to the DLL file.
        Handles PyInstaller (_MEIPASS) and development environments.
        """

        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # If running in a PyInstaller bundle
            base_path = sys._MEIPASS
        else:
            # Dev mode: base path is the script's directory, not current working dir
            base_path = os.path.dirname(os.path.abspath(__file__))

        resolved_path = os.path.abspath(os.path.join(base_path, relative_path))

        if not os.path.exists(resolved_path):
            self.logger.log_message(f"[DLL Loader] ❌ DLL not found at: {resolved_path}")


        return resolved_path

    def _load_dll(self) -> bool:
        if self._dll:
            return True
        if not self._dll_path:
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
        """
        Accepts a list of (function, args) tuples and invokes them all at once using the C# parallel batch interface.

        Args:
            funcs (list): List of tuples where each is (callable_function, args_tuple)
            return_type (str): Return type for all functions: 'void', 'int', 'bool', 'double', or 'string'
        """
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

            if typ in [1, 2, 3]:  # int, bool, double
                result_ptr = ctypes.cast(ctypes.pointer(result), ctypes.c_void_p)
            elif typ == 4:  # string
                result_ptr = ctypes.cast(result, ctypes.c_void_p)
                buffer_size = len(result)

            desc = self.PythonCallDescriptor(func_ptr, result_ptr, buffer_size, typ)
            descriptors.append(desc)

        count = len(descriptors)
        DescriptorArrayType = self.PythonCallDescriptor * count
        descriptor_array = DescriptorArrayType(*descriptors)

        self._dll.invoke_all_parallel(ctypes.cast(descriptor_array, ctypes.c_void_p), count)
        self.logger.log_message(f"[C#] [Python] 🚀 Ran {count} callbacks in batch via run_all_parallel()")

    def run_parallel(self, func: Callable, *args: Any, return_type: str = 'void', queue_name: str = None, count_to_call = 10) -> Any:
        if not self._load_dll():
            return
        # Handle special "all" case for batching
        if return_type == 'all':
            wrapped_func = lambda: func(*args)
            wrapper, result = self._create_callback_wrapper(wrapped_func, 'void')  # Treat as void
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

        # Otherwise: execute immediately via corresponding invoke_* call
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

            if typ in [1, 2, 3]:  # int, bool, double
                result_ptr = ctypes.cast(ctypes.pointer(result), ctypes.c_void_p)
            elif typ == 4:  # string
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
        """
        Runs a Python function normally, setting the CSharpLogger prefix to "" during execution
        and resetting it afterwards.

        Args:
            func (Callable): The function to execute.
            *args: Positional arguments to pass to the function.
            **kwargs: Keyword arguments to pass to the function.
        """
        try:
            self.csharp_logger.set_prefix("")
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            self.logger.log_message(f"Error running function '{func.__name__}' normally: {e}")
            raise  # Re-raise the exception after logging


    def stop(self) -> None:
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


WORD       = getattr(wintypes, "WORD", ctypes.c_ushort)
DWORD      = getattr(wintypes, "DWORD", ctypes.c_ulong)
BOOL       = getattr(wintypes, "BOOL", ctypes.c_int)
HANDLE     = getattr(wintypes, "HANDLE", ctypes.c_void_p)
ULONG_PTR  = getattr(wintypes, "ULONG_PTR", ctypes.c_size_t)
DWORD_PTR  = getattr(wintypes, "DWORD_PTR", ctypes.c_size_t)

class AsyncSnifferManager:
    """
    Async wrapper around a synchronous sniffer with per-thread CPU affinity control.
    Adds Windows 'unhinge' on first affinity set:
      - optional Job breakaway (escape CPU hard cap)
      - disable Eco/Efficiency throttling
      - raise process priority
      - optional process-wide affinity mask
    """

    # ---- Win GROUP_AFFINITY for >64 LPs ----
    class GROUP_AFFINITY(ctypes.Structure):
        _fields_ = [("Mask", ULONG_PTR), ("Group", WORD), ("Reserved", WORD * 3)]

    # ---- Windows constants / structs ----
    kernel32 = ctypes.windll.kernel32
    HIGH_PRIORITY_CLASS = 0x00000080

    # Process power throttling
    ProcessPowerThrottling = 0x00000009
    PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1
    class PROCESS_POWER_THROTTLING_STATE(ctypes.Structure):
        _fields_ = [("Version", ctypes.c_uint32),
                    ("ControlMask", ctypes.c_uint32),
                    ("StateMask", ctypes.c_uint32)]

    # Job CPU cap
    JobObjectCpuRateControlInformation = 15
    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE   = 0x1
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4

    # CreateProcess flags for breakaway
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000
    CREATE_NEW_PROCESS_GROUP  = 0x00000200
    DETACHED_PROCESS          = 0x00000008

    def __init__(self, owner,
                 *,
                 allow_job_breakaway: bool = False,
                 process_affinity_cores: Optional[List[int]] = None):
        """
        owner must provide:
          - _start_single_sniffer(iface_name)
          - _sniff_threads: dict[iface_name, threading.Thread]
          - router_logger.log_message(str)
          - _stop_sniffing_event or per-iface _sniff_stop_events[iface]
        allow_job_breakaway: if True, will relaunch process with BREAKAWAY if a CPU hard cap is detected
        process_affinity_cores: optional process-wide affinity list to apply when unhinging
        """
        self.owner = owner
        if not hasattr(self.owner, "_sniff_threads"):
            self.owner._sniff_threads: Dict[str, threading.Thread] = {}

        self._started_ifaces: Set[str] = set()
        self._thread_native_ids: Dict[str, int] = {}

        # Original affinity bookkeeping
        self._orig_mask_by_iface: Dict[str, int] = {}
        self._orig_group_aff_by_iface: Dict[str, Tuple[int, int]] = {}

        # Unhinge config/state
        self._allow_job_breakaway = allow_job_breakaway
        self._process_affinity_cores = process_affinity_cores
        self._unhinged_once = False

    # ------------------------- Async lifecycle -------------------------

    async def start(self, iface_name: str, *, wait_alive_ms: int = 1000) -> bool:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.owner._start_single_sniffer, iface_name)
        self._started_ifaces.add(iface_name)

        deadline = loop.time() + (wait_alive_ms / 1000.0)
        while loop.time() < deadline:
            th = self.owner._sniff_threads.get(iface_name)
            if th is not None and th.is_alive():
                native_id = getattr(th, "native_id", None)
                if native_id is None:
                    self.owner.router_logger.log_message(
                        "[PsutilTool] ⚠️ native_id unavailable; per-thread affinity not supported on this Python."
                    )
                else:
                    self._thread_native_ids[iface_name] = native_id
                    self.owner.router_logger.log_message(
                        f"[PsutilTool] Tracked sniffer native thread id {native_id} for '{iface_name}'."
                    )
                return True
            await asyncio.sleep(0.02)
        return False

    async def stop(self, iface_name: str, *, timeout: float = 2.5) -> bool:
        loop = asyncio.get_running_loop()
        await self.reset_sniffer_affinity(iface_name)

        stop_evt = None
        if hasattr(self.owner, "_sniff_stop_events"):
            stop_evt = getattr(self.owner, "_sniff_stop_events", {}).get(iface_name)
        if stop_evt is not None:
            stop_evt.set()
        elif hasattr(self.owner, "_stop_sniffing_event"):
            self.owner._stop_sniffing_event.set()

        th = self.owner._sniff_threads.get(iface_name)
        if th is None or not th.is_alive():
            self._cleanup_iface(iface_name)
            return True

        def _join():
            th.join(timeout=timeout)
            return not th.is_alive()

        ok = await loop.run_in_executor(None, _join)
        if not ok:
            self.owner.router_logger.log_message(
                f"[Router] Stop timed out for {iface_name.split('_')[-1]}; will exit on next packet (stop_filter)."
            )
        else:
            self._cleanup_iface(iface_name)
        return ok

    async def stop_all(self, *, timeout: float = 2.5) -> None:
        global_only = hasattr(self.owner, "_stop_sniffing_event") and not hasattr(self.owner, "_sniff_stop_events")
        if global_only:
            self.owner._stop_sniffing_event.set()
        tasks = [self.stop(iface, timeout=timeout) for iface in list(self._started_ifaces)]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _cleanup_iface(self, iface_name: str) -> None:
        self._started_ifaces.discard(iface_name)
        self._thread_native_ids.pop(iface_name, None)
        self._orig_mask_by_iface.pop(iface_name, None)
        self._orig_group_aff_by_iface.pop(iface_name, None)

    # ------------------------- Unhinge (process-level, run once) -------------------------

    def _mask_from_cores(self, cores: List[int]) -> int:
        m = 0
        for c in cores:
            if c >= 0:
                m |= (1 << c)
        return m

    def _unhinge_once(self):
        """Run once, on first affinity set. Safe if called multiple times."""
        if self._unhinged_once or os.name != "nt":
            return
        try:
            # 1) Escape Job CPU hard cap (if any, and if breakaway allowed)
            if self._allow_job_breakaway and self._is_job_capped():
                self._relaunch_breakaway()
                # If relaunch succeeded, current process exits; if not, continue.

            # 2) Disable Eco/Efficiency throttling (process)
            self._disable_process_power_throttling()

            # 3) Raise process priority
            self.kernel32.SetPriorityClass(self.kernel32.GetCurrentProcess(), self.HIGH_PRIORITY_CLASS)

            # 4) Optional: set process-wide affinity
            if self._process_affinity_cores:
                mask = DWORD_PTR(self._mask_from_cores(self._process_affinity_cores))
                self.kernel32.SetProcessAffinityMask(self.kernel32.GetCurrentProcess(), mask)

            self._unhinged_once = True
            self.owner.router_logger.log_message("[WinSanity] Unhinge applied (priority ↑, eco off, breakaway attempted).")
        except Exception as e:
            self.owner.router_logger.log_message(f"[WinSanity] ⚠️ Unhinge failed: {e}")

    def _is_job_capped(self) -> bool:
        in_job = ctypes.c_int(0)
        self.kernel32.IsProcessInJob(self.kernel32.GetCurrentProcess(), None, ctypes.byref(in_job))
        if not in_job.value:
            return False
        class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
            _fields_ = [("ControlFlags", ctypes.c_uint32), ("CpuRate", ctypes.c_uint32)]
        info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
        ok = self.kernel32.QueryInformationJobObject(
            None, self.JobObjectCpuRateControlInformation,
            ctypes.byref(info), ctypes.sizeof(info), None
        )
        if not ok:
            return False
        return bool((info.ControlFlags & self.JOB_OBJECT_CPU_RATE_CONTROL_ENABLE) and
                    (info.ControlFlags & self.JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) and
                    0 < info.CpuRate < 10000)

    def _relaunch_breakaway(self):
        # Relaunch ourselves with BREAKAWAY flags; exit current if success.
        class STARTUPINFO(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_uint32), ("lpReserved", ctypes.c_wchar_p),
                        ("lpDesktop", ctypes.c_wchar_p), ("lpTitle", ctypes.c_wchar_p),
                        ("dwX", ctypes.c_uint32), ("dwY", ctypes.c_uint32),
                        ("dwXSize", ctypes.c_uint32), ("dwYSize", ctypes.c_uint32),
                        ("dwXCountChars", ctypes.c_uint32), ("dwYCountChars", ctypes.c_uint32),
                        ("dwFillAttribute", ctypes.c_uint32), ("dwFlags", ctypes.c_uint32),
                        ("wShowWindow", ctypes.c_ushort), ("cbReserved2", ctypes.c_ushort),
                        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
                        ("hStdInput", ctypes.c_void_p), ("hStdOutput", ctypes.c_void_p),
                        ("hStdError", ctypes.c_void_p)]
        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
                        ("dwProcessId", ctypes.c_uint32), ("dwThreadId", ctypes.c_uint32)]
        si, pi = STARTUPINFO(), PROCESS_INFORMATION()
        si.cb = ctypes.sizeof(si)
        flags = self.CREATE_BREAKAWAY_FROM_JOB | self.CREATE_NEW_PROCESS_GROUP | self.DETACHED_PROCESS
        cmdline = " ".join([sys.executable] + sys.argv)
        ok = self.kernel32.CreateProcessW(
            ctypes.c_wchar_p(sys.executable), ctypes.c_wchar_p(cmdline),
            None, None, False, flags, None, None, ctypes.byref(si), ctypes.byref(pi)
        )
        if ok:
            self.kernel32.CloseHandle(pi.hThread)
            self.kernel32.CloseHandle(pi.hProcess)
            os._exit(0)

    def _disable_process_power_throttling(self):
        state = self.PROCESS_POWER_THROTTLING_STATE()
        state.Version = 1
        state.ControlMask = self.PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        state.StateMask = 0
        self.kernel32.SetProcessInformation(
            self.kernel32.GetCurrentProcess(),
            self.ProcessPowerThrottling,
            ctypes.byref(state),
            ctypes.sizeof(state)
        )

    # ------------------------- Affinity control (Windows) -------------------------

    def _win_open_thread(self, native_id: int):
        OpenThread = self.kernel32.OpenThread
        THREAD_SET_INFORMATION   = 0x0020
        THREAD_QUERY_INFORMATION = 0x0040
        THREAD_SET_LIMITED_INFORMATION   = 0x0400
        THREAD_QUERY_LIMITED_INFORMATION = 0x0800
        access = THREAD_SET_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION
        hThread = OpenThread(access, False, ctypes.c_ulong(native_id))
        if not hThread:
            access = 0x1F03FF  # THREAD_ALL_ACCESS fallback
            hThread = OpenThread(access, False, ctypes.c_ulong(native_id))
        return hThread

    async def set_sniffer_affinity(self, iface_name: str, cores: List[int]) -> bool:
        """
        Pin sniffer thread (current processor group). Also 'unhinges' the process the first time this is called.
        """
        if iface_name not in self._thread_native_ids:
            self.owner.router_logger.log_message(
                f"[PsutilTool] ⚠️ Sniffer for '{iface_name}' not tracked yet; start() must succeed first."
            )
            return False

        # Unhinge the process once (breakaway/eco/prio/process affinity)
        self._unhinge_once()

        native_id = self._thread_native_ids[iface_name]
        ok, prev_mask = self._win_set_thread_affinity(native_id, cores)
        if ok:
            self._orig_mask_by_iface.setdefault(iface_name, prev_mask)
            self.owner.router_logger.log_message(
                f"[PsutilTool] ✅ Set Windows thread affinity for '{iface_name}' to {cores} (mask=0x{self._mask_from_cores(cores):X})."
            )
        return ok

    async def set_sniffer_affinity_grouped(self, iface_name: str, group: int, cores_in_group: List[int]) -> bool:
        """
        Pin sniffer thread to a specific processor GROUP (>64 LP systems).
        Also 'unhinges' the process the first time this is called.
        """
        if iface_name not in self._thread_native_ids:
            self.owner.router_logger.log_message(
                f"[PsutilTool] ⚠️ Sniffer for '{iface_name}' not tracked yet; start() must succeed first."
            )
            return False

        self._unhinge_once()

        native_id = self._thread_native_ids[iface_name]
        ok, prev_group, prev_mask = self._win_set_thread_group_affinity(native_id, group, cores_in_group)
        if ok:
            self._orig_group_aff_by_iface.setdefault(iface_name, (prev_group, prev_mask))
            self.owner.router_logger.log_message(
                f"[PsutilTool] ✅ Set GroupAffinity for '{iface_name}' -> Group {group}, Cores {cores_in_group}."
            )
        return ok

    async def reset_sniffer_affinity(self, iface_name: str) -> bool:
        native_id = self._thread_native_ids.get(iface_name)
        if native_id is None:
            return False

        prev = self._orig_group_aff_by_iface.get(iface_name)
        if prev:
            group, mask = prev
            ok = self._win_reset_thread_group_affinity(native_id, group, mask)
            if ok:
                self._orig_group_aff_by_iface.pop(iface_name, None)
                self.owner.router_logger.log_message("[PsutilTool] ✅ Restored Windows thread GROUP affinity.")
            return True

        prev_mask = self._orig_mask_by_iface.get(iface_name)
        if prev_mask is not None:
            ok = self._win_reset_thread_affinity(native_id, prev_mask)
            if ok:
                self._orig_mask_by_iface.pop(iface_name, None)
                self.owner.router_logger.log_message("[PsutilTool] ✅ Restored Windows thread affinity mask.")
            return bool(ok)

        return False

    # ------------------------- Win native calls -------------------------

    def _win_set_thread_affinity(self, native_id: int, cores: List[int]) -> Tuple[bool, int]:
        try:
            hThread = self._win_open_thread(native_id)
            if not hThread:
                self.owner.router_logger.log_message("[PsutilTool] ❌ OpenThread failed.")
                return False, 0
            mask = ctypes.c_size_t(self._mask_from_cores(cores))
            prev = self.kernel32.SetThreadAffinityMask(hThread, mask)
            self.kernel32.CloseHandle(hThread)
            if prev == 0:
                self.owner.router_logger.log_message("[PsutilTool] ❌ SetThreadAffinityMask failed.")
                return False, 0
            return True, int(prev)
        except Exception as e:
            self.owner.router_logger.log_message(f"[PsutilTool] ❌ Windows affinity error: {e}")
            return False, 0

    def _win_reset_thread_affinity(self, native_id: int, prev_mask: int) -> bool:
        try:
            hThread = self._win_open_thread(native_id)
            if not hThread:
                self.owner.router_logger.log_message("[PsutilTool] ❌ OpenThread failed (reset).")
                return False
            ok = self.kernel32.SetThreadAffinityMask(hThread, ctypes.c_size_t(prev_mask)) != 0
            self.kernel32.CloseHandle(hThread)
            return bool(ok)
        except Exception as e:
            self.owner.router_logger.log_message(f"[PsutilTool] ❌ Windows affinity reset error: {e}")
            return False

    def _win_set_thread_group_affinity(self, native_id: int, group: int, cores_in_group: List[int]) -> Tuple[bool, int, int]:
        try:
            hThread = self._win_open_thread(native_id)
            if not hThread:
                self.owner.router_logger.log_message("[PsutilTool] ❌ OpenThread failed (group).")
                return False, 0, 0

            ga = AsyncSnifferManager.GROUP_AFFINITY()
            ga.Group = group
            ga.Mask = self._mask_from_cores(cores_in_group)
            ga.Reserved = (0, 0, 0)

            prev = AsyncSnifferManager.GROUP_AFFINITY()
            ok = self.kernel32.SetThreadGroupAffinity(hThread, ctypes.byref(ga), ctypes.byref(prev))
            self.kernel32.CloseHandle(hThread)
            if not ok:
                self.owner.router_logger.log_message("[PsutilTool] ❌ SetThreadGroupAffinity failed.")
                return False, 0, 0

            return True, int(prev.Group), int(prev.Mask)
        except Exception as e:
            self.owner.router_logger.log_message(f"[PsutilTool] ❌ Group affinity error: {e}")
            return False, 0, 0

    def _win_reset_thread_group_affinity(self, native_id: int, prev_group: int, prev_mask: int) -> bool:
        try:
            hThread = self._win_open_thread(native_id)
            if not hThread:
                self.owner.router_logger.log_message("[PsutilTool] ❌ OpenThread failed (group reset).")
                return False
            ga = AsyncSnifferManager.GROUP_AFFINITY()
            ga.Group = prev_group
            ga.Mask = prev_mask
            ga.Reserved = (0, 0, 0)
            ok = self.kernel32.SetThreadGroupAffinity(hThread, ctypes.byref(ga), None)
            self.kernel32.CloseHandle(hThread)
            return bool(ok)
        except Exception as e:
            self.owner.router_logger.log_message(f"[PsutilTool] ❌ Group affinity reset error: {e}")
            return False

