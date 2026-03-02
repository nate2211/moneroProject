from __future__ import annotations

import os
import sys
import threading
import time
from ctypes import (
    CDLL,
    c_int,
    c_void_p,
    c_size_t,
    c_uint64,
    c_ubyte,
    create_string_buffer,
)
from ctypes.util import find_library
from typing import Optional


class RandomX:
    def __init__(self, logger=None) -> None:
        """
        logger: expected to have .log_message(str)
        If None, logging is disabled.
        """
        self.logger = logger
        self._log("[RandomX] Loading DLL...")
        self.lib = self._load_randomx()
        self._log(f"[RandomX] DLL Loaded: {self.lib}")

        self._bind()

        self._lock = threading.RLock()
        self._seed: bytes = b""
        self._flags: int = int(self.randomx_get_flags())

        self._cache = None
        self._dataset = None

        self._dataset_items: int = int(self.randomx_dataset_item_count())
        self._log(f"[RandomX] Flags: {self._flags}, Dataset Items: {self._dataset_items}")

    def _log(self, msg: str) -> None:
        try:
            if self.logger and hasattr(self.logger, "log_message"):
                self.logger.log_message(msg)
        except Exception:
            pass

    @staticmethod
    def _base_path() -> str:
        """
        - normal run: folder of this file
        - PyInstaller onefile/onedir: extraction dir (sys._MEIPASS)
        """
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))

    def _load_randomx(self) -> CDLL:
        # Prefer the fixed location you requested: tools/randomx.dll
        base = self._base_path()
        tools_dir = os.path.join(base, "tools")
        dll_in_tools = os.path.join(tools_dir, "randomx.dll")

        # On Windows, help the loader find deps that sit next to the DLL
        if os.name == "nt" and hasattr(os, "add_dll_directory"):
            try:
                if os.path.isdir(tools_dir):
                    os.add_dll_directory(tools_dir)
                os.add_dll_directory(base)
            except Exception:
                pass

        # 1) Env override still allowed
        env = os.environ.get("RANDOMX_LIB", "").strip()
        if env:
            try:
                return CDLL(env)
            except Exception as e:
                self._log(f"[RandomX] Warning: Could not load from RANDOMX_LIB={env}: {e}")

        # 2) Try your requested path first
        candidates = [
            dll_in_tools,                              # <--- tools/randomx.dll (PyInstaller-friendly)
            os.path.join(base, "randomx.dll"),          # fallback: next to exe/script
            "./randomx-dll.dll",                        # fallback legacy
            "randomx.dll",                              # fallback PATH
            "librandomx.so",
            "librandomx.dylib",
        ]

        # 3) System loader lookup (last resort)
        sys_lib = find_library("randomx")
        if sys_lib:
            candidates.append(sys_lib)

        last_err = None
        for c in candidates:
            try:
                if not c:
                    continue
                return CDLL(c)
            except Exception as e:
                last_err = e

        raise RuntimeError(
            "FATAL: Could not find randomx.dll.\n"
            f"Expected (preferred): {dll_in_tools}\n"
            f"Last error: {last_err}"
        )

    def _bind(self) -> None:
        L = self.lib

        # restype
        L.randomx_get_flags.restype = c_int
        L.randomx_alloc_cache.restype = c_void_p
        L.randomx_alloc_dataset.restype = c_void_p
        L.randomx_dataset_item_count.restype = c_uint64
        L.randomx_create_vm.restype = c_void_p

        # map
        self.randomx_get_flags = L.randomx_get_flags
        self.randomx_alloc_cache = L.randomx_alloc_cache
        self.randomx_init_cache = L.randomx_init_cache
        self.randomx_release_cache = L.randomx_release_cache
        self.randomx_alloc_dataset = L.randomx_alloc_dataset
        self.randomx_dataset_item_count = L.randomx_dataset_item_count
        self.randomx_init_dataset = L.randomx_init_dataset
        self.randomx_release_dataset = L.randomx_release_dataset
        self.randomx_create_vm = L.randomx_create_vm
        self.randomx_destroy_vm = L.randomx_destroy_vm
        self.randomx_calculate_hash = L.randomx_calculate_hash

        # argtypes
        self.randomx_alloc_cache.argtypes = [c_int]
        self.randomx_init_cache.argtypes = [c_void_p, c_void_p, c_size_t]
        self.randomx_release_cache.argtypes = [c_void_p]

        self.randomx_alloc_dataset.argtypes = [c_int]
        self.randomx_init_dataset.argtypes = [c_void_p, c_void_p, c_uint64, c_uint64]
        self.randomx_release_dataset.argtypes = [c_void_p]

        self.randomx_create_vm.argtypes = [c_int, c_void_p, c_void_p]
        self.randomx_destroy_vm.argtypes = [c_void_p]
        self.randomx_calculate_hash.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p]

    def ensure_seed(self, seed_hash: bytes) -> None:
        seed_hash = bytes(seed_hash or b"")
        if not seed_hash:
            raise ValueError("empty seed_hash")

        with self._lock:
            if seed_hash == self._seed and self._cache is not None and self._dataset is not None:
                return

            self._log("[RandomX] New Seed Detected! Initializing Dataset (this takes time)...")
            t0 = time.time()

            if self._dataset is not None:
                self.randomx_release_dataset(self._dataset)
                self._dataset = None
            if self._cache is not None:
                self.randomx_release_cache(self._cache)
                self._cache = None

            self._cache = self.randomx_alloc_cache(self._flags)
            if not self._cache:
                raise MemoryError("Failed to allocate RandomX Cache")

            seed_buf = (c_ubyte * len(seed_hash)).from_buffer_copy(seed_hash)
            self.randomx_init_cache(self._cache, seed_buf, c_size_t(len(seed_hash)))

            self._dataset = self.randomx_alloc_dataset(self._flags)
            if not self._dataset:
                raise MemoryError("Failed to allocate RandomX Dataset (Do you have 3GB+ RAM free?)")

            self._log("[RandomX] Building Dataset... (Please Wait)")
            self.randomx_init_dataset(self._dataset, self._cache, c_uint64(0), c_uint64(self._dataset_items))

            self._seed = seed_hash
            dt = time.time() - t0
            self._log(f"[RandomX] Dataset Ready! (Took {dt:.2f} seconds)")

    def create_vm(self) -> c_void_p:
        with self._lock:
            if self._cache is None or self._dataset is None:
                raise RuntimeError("seed not initialized")

            vm = self.randomx_create_vm(self._flags, self._cache, self._dataset)
            if not vm:
                raise RuntimeError("randomx_create_vm returned NULL")
            return vm

    def destroy_vm(self, vm: c_void_p) -> None:
        try:
            if vm:
                self.randomx_destroy_vm(vm)
        except Exception:
            pass

    def hash(self, vm: c_void_p, data: bytes) -> bytes:
        out = create_string_buffer(32)
        buf = (c_ubyte * len(data)).from_buffer_copy(data)
        self.randomx_calculate_hash(vm, buf, c_size_t(len(data)), out)
        return out.raw


class RxUtils:
    @staticmethod
    def norm_hex(h: Optional[str]) -> Optional[str]:
        if not h or not isinstance(h, str):
            return None
        s = h.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        s = "".join(c for c in s if c in "0123456789abcdef")
        return s or None

    @staticmethod
    def target_from_difficulty_int(diff: int) -> int:
        if not isinstance(diff, int) or diff <= 0:
            raise ValueError("difficulty must be positive int")
        max256 = (1 << 256) - 1
        return max256 // diff

    @staticmethod
    def target_hex_from_difficulty(diff: int) -> str:
        t = RxUtils.target_from_difficulty_int(diff)
        return int(t).to_bytes(32, "little", signed=False).hex()