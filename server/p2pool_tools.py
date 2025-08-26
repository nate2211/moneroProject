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
    # This function determines the base path to correctly locate the DLL,
    # whether the script is running from source or as a bundled executable.
    base = getattr(sys, "_MEIPASS", None)
    base = Path(base) if base else Path(__file__).resolve().parent
    return (base / relpath).resolve()


class RandomXLoader:
    """
    A robust Python wrapper for the RandomX C++ library.
    This class handles loading the DLL, managing memory, and providing
    easy-to-use hashing functions.
    """

    def __init__(self, dll_rel_path: str = "randomx.dll", flags: Optional[int] = None, logger=None):
        """
        Initializes the loader.
        Note: The DLL is not loaded until ensure_started() is called.

        Args:
            dll_rel_path: Relative path to the randomx.dll file.
            flags: Optional override for RandomX initialization flags. If None,
                   the best flags for the CPU will be detected automatically.
            logger: An optional logger object with a `log_message` method.
        """
        self._dll_path = _resolve_path(dll_rel_path)
        self._init_flags = flags
        self._logger = logger
        self._dll: Optional[ctypes.CDLL] = None
        self._cache = None
        self._dataset = None
        self._vm = None
        self._lock = threading.Lock()
        self._started = False

    def _log(self, msg: str):
        """Logs a message using the provided logger or prints to console."""
        if self._logger:
            self._logger.log_message(msg)
        else:
            print(msg)

    def _load_and_verify_dll(self):
        """
        Loads the DLL and sets up the function prototypes.
        This internal method verifies that all required functions are present
        in the DLL, preventing crashes from a misconfigured build.
        """
        if self._dll:
            return
        if not self._dll_path.exists():
            raise FileNotFoundError(f"RandomX library not found at: {self._dll_path}")

        try:
            # Use CDLL on all platforms as RandomX uses the standard cdecl calling convention.
            self._dll = ctypes.CDLL(str(self._dll_path))
        except Exception as e:
            raise RuntimeError(f"Failed to load {self._dll_path}: {e}")

        # Define all function prototypes and verify their existence.
        funcs_to_define = {
            "randomx_get_flags": ([], ctypes.c_int),
            "randomx_alloc_cache": ([ctypes.c_int], ctypes.c_void_p),
            "randomx_init_cache": ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t], None),
            "randomx_release_cache": ([ctypes.c_void_p], None),
            "randomx_create_vm": ([ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p),
            "randomx_destroy_vm": ([ctypes.c_void_p], None),
            "randomx_calculate_hash": ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p], None),
            "randomx_calculate_hash_first": ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t], None),
            "randomx_calculate_hash_next": ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p], None),
            "randomx_calculate_hash_last": ([ctypes.c_void_p, ctypes.c_void_p], None),
        }

        for name, (argtypes, restype) in funcs_to_define.items():
            if not hasattr(self._dll, name):
                raise AttributeError(f"Function '{name}' not found in DLL. Check C++ build exports.")
            func = getattr(self._dll, name)
            func.argtypes = argtypes
            func.restype = restype

    def ensure_started(self, seed: bytes, use_dataset: bool = False):
        """
        Initializes the RandomX cache and VM. Idempotent and thread-safe.
        This must be called before any hashing operations.

        Args:
            seed: The seed (usually a block hash) to initialize the cache with.
            use_dataset: If True, allocates and initializes the full dataset for
                         faster hashing (requires >2GB RAM).
        """
        with self._lock:
            if self._started:
                return

            try:
                self._load_and_verify_dll()
                d = self._dll

                flags = self._init_flags if self._init_flags is not None else d.randomx_get_flags()
                if use_dataset:
                    flags |= RandomXFlags.FULL_MEM

                self._cache = d.randomx_alloc_cache(flags)
                if not self._cache:
                    raise RuntimeError("randomx_alloc_cache failed (returned NULL)")

                seed_buf = (ctypes.c_ubyte * len(seed)).from_buffer_copy(seed)
                d.randomx_init_cache(self._cache, ctypes.cast(seed_buf, ctypes.c_void_p), len(seed))

                if use_dataset and hasattr(d, "randomx_alloc_dataset"):
                    d.randomx_alloc_dataset.argtypes = [ctypes.c_int]
                    d.randomx_alloc_dataset.restype = ctypes.c_void_p
                    d.randomx_dataset_item_count.restype = ctypes.c_uint64
                    d.randomx_init_dataset.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
                                                       ctypes.c_uint64]

                    self._dataset = d.randomx_alloc_dataset(flags)
                    if self._dataset:
                        count = d.randomx_dataset_item_count()
                        d.randomx_init_dataset(self._dataset, self._cache, 0, count)
                    else:
                        self._log("[RandomX] ⚠️ Dataset allocation failed, continuing in light mode.")

                self._vm = d.randomx_create_vm(flags, self._cache, self._dataset)
                if not self._vm:
                    raise RuntimeError("randomx_create_vm failed (returned NULL)")

                self._started = True
                mode = "Full Dataset" if self._dataset else "Light Cache"
                self._log(f"[RandomX] ✅ VM ready ({mode} Mode, Flags: {hex(flags)})")

            except (FileNotFoundError, RuntimeError, AttributeError) as e:
                error_message = f"[RandomX] ❌ Initialization failed: {e}"
                self._log(error_message)
                raise RuntimeError(error_message) from e

    def calculate_hash(self, blob: bytes) -> bytes:
        """Calculates a single hash. Less efficient for multiple hashes."""
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started() first.")

        out = (ctypes.c_ubyte * 32)()
        with self._lock:
            in_buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
            self._dll.randomx_calculate_hash(self._vm, ctypes.cast(in_buf, ctypes.c_void_p), len(blob),
                                             ctypes.cast(out, ctypes.c_void_p))
        return bytes(out)

    def calculate_hash_hex(self, blob_hex: str) -> str:
        """
        Calculates a single hash from a hex string and returns a hex string.
        This is a convenience wrapper for the calculate_hash method.
        """
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started(seed, ...) first.")

        # Convert hex string input to bytes
        data = binascii.unhexlify(blob_hex)

        # Call the primary hash function
        hash_bytes = self.calculate_hash(data)

        # Convert the resulting bytes back to a hex string
        return hash_bytes.hex()

    def calculate_hash_first(self, blob: bytes):
        """Starts a batch hash sequence."""
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started() first.")
        with self._lock:
            in_buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
            self._dll.randomx_calculate_hash_first(self._vm, ctypes.cast(in_buf, ctypes.c_void_p), len(blob))

    def calculate_hash_next(self, next_blob: bytes) -> bytes:
        """
        Calculates hash of the PREVIOUS blob and prepares for the next one.
        Returns the hash of the blob from the prior `first` or `next` call.
        """
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started() first.")

        out = (ctypes.c_ubyte * 32)()
        with self._lock:
            in_buf = (ctypes.c_ubyte * len(next_blob)).from_buffer_copy(next_blob)
            self._dll.randomx_calculate_hash_next(self._vm, ctypes.cast(in_buf, ctypes.c_void_p), len(next_blob),
                                                  ctypes.cast(out, ctypes.c_void_p))
        return bytes(out)

    def calculate_hash_last(self) -> bytes:
        """Calculates and returns the hash of the final blob in a sequence."""
        if not self._started:
            raise RuntimeError("RandomX not started. Call ensure_started() first.")

        out = (ctypes.c_ubyte * 32)()
        with self._lock:
            self._dll.randomx_calculate_hash_last(self._vm, ctypes.cast(out, ctypes.c_void_p))
        return bytes(out)

    def destroy(self):
        """Releases all RandomX resources."""
        with self._lock:
            if not self._started:
                return
            if self._vm: self._dll.randomx_destroy_vm(self._vm)
            if self._dataset and hasattr(self._dll, "randomx_release_dataset"):
                self._dll.randomx_release_dataset.argtypes = [ctypes.c_void_p]
                self._dll.randomx_release_dataset(self._dataset)
            if self._cache: self._dll.randomx_release_cache(self._cache)

            self._vm = self._dataset = self._cache = None
            self._started = False
            self._log("[RandomX] 🛑 VM and resources destroyed.")

