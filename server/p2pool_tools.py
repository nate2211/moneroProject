import asyncio
import atexit
import binascii
import gc
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
        self._parallel_queues: Dict[str, list[tuple]] = {}  # name → list of (wrapper, type, result_obj)
        self.csharp_logger = CSharpLogger(self.logger)
        self._process = psutil.Process(os.getpid())
        self._cpu_usage_history = deque(maxlen=10)
        self._ram_buffer = None  # Attribute to hold allocated memory
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
        logical_cores = psutil.cpu_count(logical=True)
        max_possible = 100 * logical_cores if logical_cores else 100
        cpu_percent_normalized = min((cpu_percent_raw / max_possible) * 100, 100.0) if max_possible > 0 else 0.0

        return {
            "cpu_percent": cpu_percent_normalized,
            "memory_usage_mb": memory_info.rss / (1024 * 1024)
        }

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
        # Release any allocated RAM before unloading the DLL
        self.release_ram_usage()

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


class RandomXFlags:
    """Mirrors the randomx_flags enum from randomx.h for clarity."""
    DEFAULT = 0x0
    LARGE_PAGES = 0x1
    HARD_AES = 0x2
    FULL_MEM = 0x4
    JIT = 0x8
    SECURE = 0x10
    ARGON2_SSSE3 = 0x20
    ARGON2_AVX2 = 0x40


def _resolve_path(relpath: str) -> Path:
    """Finds the library file, works in dev and PyInstaller."""
    base = getattr(sys, "_MEIPASS", None)
    base = Path(base) if base else Path(__file__).resolve().parent
    return (base / relpath).resolve()


class RandomXLoader:
    """
    Robust Python wrapper for the RandomX C/C++ library that matches the
    interface expected by the share worker:
      - calculate_hash(...) -> int (little-endian)
      - calculate_hash_first/next/last(...) pipelined API (emulated)
    """
    # ---- C API names we rely on ----
    _FN_RANDOMX_GET_FLAGS = "randomx_get_flags"
    _FN_RANDOMX_ALLOC_CACHE = "randomx_alloc_cache"
    _FN_RANDOMX_INIT_CACHE = "randomx_init_cache"
    _FN_RANDOMX_RELEASE_CACHE = "randomx_release_cache"
    _FN_RANDOMX_CREATE_VM = "randomx_create_vm"
    _FN_RANDOMX_DESTROY_VM = "randomx_destroy_vm"
    _FN_RANDOMX_CALCULATE_HASH = "randomx_calculate_hash"

    def __init__(self, dll_rel_path: str = "randomx.dll", flags: Optional[int] = None, logger=None):
        self._dll_path = _resolve_path(dll_rel_path)
        self._init_flags = flags
        self._logger = logger

        self._dll: Optional[ctypes.CDLL] = None
        self._cache = None
        self._dataset = None  # not used here; wire it up if you add full dataset support
        self._vm = None

        self._lock = threading.Lock()
        self._started = False

        # ---- pipeline emulation state (thread-safe behind _lock) ----
        self._pipe_prev_digest: Optional[int] = None
        self._pipe_has_prev: bool = False

    # --------------- logging ---------------
    def _log(self, msg: str):
        if self._logger:
            try:
                self._logger.log_message(msg)
                return
            except Exception:
                pass
        print(msg)

    # --------------- DLL load/verify ---------------
    def _load_and_verify_dll(self):
        if self._dll:
            return
        if not self._dll_path.exists():
            raise FileNotFoundError(f"RandomX library not found at: {self._dll_path}")

        try:
            self._dll = ctypes.CDLL(str(self._dll_path))
        except Exception as e:
            raise RuntimeError(f"Failed to load {self._dll_path}: {e}")

        # Bind and type the subset of functions we use.
        def _bind(name, argtypes, restype):
            if not hasattr(self._dll, name):
                raise AttributeError(f"Function '{name}' not found in DLL exports.")
            fn = getattr(self._dll, name)
            fn.argtypes = argtypes
            fn.restype = restype
            return fn

        self._rx_get_flags = _bind(self._FN_RANDOMX_GET_FLAGS, [], ctypes.c_int)
        self._rx_alloc_cache = _bind(self._FN_RANDOMX_ALLOC_CACHE, [ctypes.c_int], ctypes.c_void_p)
        self._rx_init_cache = _bind(self._FN_RANDOMX_INIT_CACHE,
                                    [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t], None)
        self._rx_release_cache = _bind(self._FN_RANDOMX_RELEASE_CACHE, [ctypes.c_void_p], None)
        self._rx_create_vm = _bind(self._FN_RANDOMX_CREATE_VM,
                                   [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p)
        self._rx_destroy_vm = _bind(self._FN_RANDOMX_DESTROY_VM, [ctypes.c_void_p], None)
        self._rx_calculate_hash = _bind(self._FN_RANDOMX_CALCULATE_HASH,
                                        [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p], None)

    # --------------- lifecycle ---------------
    @property
    def started(self) -> bool:
        return self._started

    def ensure_started(self, seed: bytes, use_dataset: bool = False):
        """
        Initialize or re-seed the VM. Safe to call when already started.
        """
        if not isinstance(seed, (bytes, bytearray, memoryview)):
            raise TypeError("seed must be bytes-like")

        with self._lock:
            self._load_and_verify_dll()

            # If already running, just re-init the cache with the new seed.
            if self._started and self._cache:
                seed_buf = (ctypes.c_ubyte * len(seed)).from_buffer_copy(seed)
                self._rx_init_cache(self._cache, ctypes.cast(seed_buf, ctypes.c_void_p), len(seed))
                self._reset_pipeline_locked()
                self._log("[RandomX] ✅ VM cache re-initialized with new seed.")
                return

            flags = self._init_flags if self._init_flags is not None else int(self._rx_get_flags())
            if use_dataset:
                flags |= RandomXFlags.FULL_MEM  # optional, depending on your build/setup

            # Allocate and initialize cache
            self._cache = self._rx_alloc_cache(flags)
            if not self._cache:
                raise RuntimeError("randomx_alloc_cache failed (returned NULL)")

            seed_buf = (ctypes.c_ubyte * len(seed)).from_buffer_copy(seed)
            self._rx_init_cache(self._cache, ctypes.cast(seed_buf, ctypes.c_void_p), len(seed))

            # Create VM (dataset not wired; you can create/attach if desired)
            self._vm = self._rx_create_vm(flags, self._cache, self._dataset)
            if not self._vm:
                # Clean up cache if VM creation failed
                self._rx_release_cache(self._cache)
                self._cache = None
                raise RuntimeError("randomx_create_vm failed (returned NULL)")

            self._started = True
            self._reset_pipeline_locked()
            mode = "Full Dataset" if self._dataset else "Light Cache"
            self._log(f"[RandomX] ✅ VM ready ({mode} Mode, Flags: {hex(flags)})")

    def destroy(self):
        with self._lock:
            if not self._started:
                return
            try:
                if self._vm:
                    self._rx_destroy_vm(self._vm)
            finally:
                self._vm = None
                if self._cache:
                    self._rx_release_cache(self._cache)
                    self._cache = None
                # (If you add dataset support, release it here as well)
                self._started = False
                self._reset_pipeline_locked()
                self._log("[RandomX] 🛑 VM and resources destroyed.")

    # --------------- hashing: scalar ---------------
    def calculate_hash(self, blob: bytes) -> int:
        """
        Compute digest for 'blob' and return as a little-endian integer (32 bytes).
        Matches the comparison semantics used in _share_worker (dig <= target).
        """
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started() first.")
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("blob must be bytes-like")

        out = (ctypes.c_ubyte * 32)()
        with self._lock:
            in_buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
            self._rx_calculate_hash(self._vm,
                                    ctypes.cast(in_buf, ctypes.c_void_p),
                                    len(blob),
                                    ctypes.cast(out, ctypes.c_void_p))
        # Return as little-endian integer for direct target comparison
        return int.from_bytes(bytes(out), "little")

    # --------------- hashing: pipelined (emulated) ---------------
    def calculate_hash_first(self, blob: bytes) -> None:
        """
        Start a pipeline batch. We emulate pipelining by computing immediately
        and buffering the digest; 'next' returns the previous digest.
        """
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("blob must be bytes-like")
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started() first.")
        with self._lock:
            self._pipe_prev_digest = self._calc_locked(blob)
            self._pipe_has_prev = True

    def calculate_hash_next(self, blob: bytes) -> int:
        """
        Return the digest of the *previous* blob in the current pipeline batch,
        and compute/store the digest for 'blob' as the new previous.
        """
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("blob must be bytes-like")
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started() first.")
        with self._lock:
            if not self._pipe_has_prev:
                raise RuntimeError("Pipeline not started. Call calculate_hash_first() first.")
            # emit previous, compute new
            prev = self._pipe_prev_digest
            self._pipe_prev_digest = self._calc_locked(blob)
            return int(prev)

    def calculate_hash_last(self) -> int:
        """
        Finish the pipeline batch and return the digest for the last blob submitted.
        """
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started() first.")
        with self._lock:
            if not self._pipe_has_prev:
                raise RuntimeError("Pipeline not started. Call calculate_hash_first() first.")
            last = self._pipe_prev_digest
            # reset pipeline state
            self._reset_pipeline_locked()
            return int(last)

    # --------------- helpers (internal) ---------------
    def _calc_locked(self, blob: bytes) -> int:
        """Assumes _lock is held; returns little-endian int digest."""
        out = (ctypes.c_ubyte * 32)()
        in_buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        self._rx_calculate_hash(self._vm,
                                ctypes.cast(in_buf, ctypes.c_void_p),
                                len(blob),
                                ctypes.cast(out, ctypes.c_void_p))
        return int.from_bytes(bytes(out), "little")

    def _reset_pipeline_locked(self):
        self._pipe_prev_digest = None
        self._pipe_has_prev = False
