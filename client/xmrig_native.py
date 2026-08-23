"""ctypes bridge for NateMiningNative.dll.

The DLL is optional.  The miner retains its Python fallbacks if it cannot be
loaded, which is important for development runs and non-Windows hosts.
"""
from __future__ import annotations

import ctypes
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

ABI_VERSION = 1

EVENT_OUTPUT = 1 << 0
EVENT_POOL_ACTIVITY = 1 << 1
EVENT_JOB = 1 << 2
EVENT_SHARE = 1 << 3
EVENT_HASHRATE = 1 << 4
EVENT_TRANSIENT_ERROR = 1 << 5
EVENT_FATAL_ERROR = 1 << 6
EVENT_GPU_STATS = 1 << 7

RESTART_NONE = 0
RESTART_FATAL_OUTPUT = 1
RESTART_POOL_ERROR_STREAK = 2
RESTART_POOL_STALL = 3
RESTART_QUIET = 4


class XmrigEvent(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("accepted", ctypes.c_uint32),
        ("rejected", ctypes.c_uint32),
        ("gpu_temp_c", ctypes.c_uint32),
        ("gpu_fan_percent", ctypes.c_uint32),
        ("error_class", ctypes.c_uint32),
        ("difficulty", ctypes.c_uint64),
        ("height", ctypes.c_uint64),
        ("hashrate_hs", ctypes.c_double),
        ("algorithm", ctypes.c_char * 32),
        ("pool", ctypes.c_char * 128),
    ]


class WatchdogPolicy(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("error_streak_limit", ctypes.c_uint32),
        ("bootstrap_restart_ms", ctypes.c_uint32),
        ("pool_stall_restart_ms", ctypes.c_uint32),
        ("quiet_restart_ms", ctypes.c_uint32),
        ("restart_cooldown_ms", ctypes.c_uint32),
    ]


class WatchdogState(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("process_started_ms", ctypes.c_uint64),
        ("last_output_ms", ctypes.c_uint64),
        ("last_pool_activity_ms", ctypes.c_uint64),
        ("last_share_ms", ctypes.c_uint64),
        ("last_pool_error_ms", ctypes.c_uint64),
        ("last_restart_request_ms", ctypes.c_uint64),
        ("consecutive_pool_errors", ctypes.c_uint32),
        ("connected_once", ctypes.c_uint32),
        ("fatal_seen", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class CpuInfo(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("logical_processors", ctypes.c_uint32),
        ("physical_cores", ctypes.c_uint32),
        ("l3_bytes", ctypes.c_uint64),
        ("has_aes", ctypes.c_uint32),
        ("has_avx2", ctypes.c_uint32),
        ("recommended_threads_balanced", ctypes.c_uint32),
        ("recommended_threads_max", ctypes.c_uint32),
        ("vendor", ctypes.c_char * 16),
        ("brand", ctypes.c_char * 64),
    ]


class PoolProfile(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("is_moneroocean", ctypes.c_uint32),
        ("use_tls", ctypes.c_uint32),
        ("use_sni", ctypes.c_uint32),
        ("allow_algo_negotiation", ctypes.c_uint32),
        ("primary_port", ctypes.c_uint32),
        ("fallback_plain_port", ctypes.c_uint32),
        ("fallback_tls_port", ctypes.c_uint32),
        ("host", ctypes.c_char * 128),
        ("normalized_url", ctypes.c_char * 192),
    ]


def _decode(buf: Any) -> str:
    value = bytes(buf).split(b"\0", 1)[0]
    return value.decode("utf-8", errors="replace")


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


def _candidate_paths() -> list[str]:
    names = ["NateMiningNative.dll"]
    roots: list[str] = []
    if getattr(sys, "frozen", False):
        roots.append(os.path.dirname(sys.executable))
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.extend([meipass, os.path.join(meipass, "tools")])
    here = os.path.abspath(os.path.dirname(__file__))
    roots.extend([here, os.path.join(here, "tools"), os.path.join(os.path.dirname(here), "tools")])
    result: list[str] = []
    for root in roots:
        for name in names:
            path = os.path.normpath(os.path.join(root, name))
            if path not in result:
                result.append(path)
    return result


@dataclass(frozen=True)
class NativeStatus:
    available: bool
    path: Optional[str]
    version: str
    error: str = ""


class NativeMiningEngine:
    def __init__(self, logger=None):
        self.logger = logger
        self.dll: Optional[ctypes.CDLL] = None
        self.path: Optional[str] = None
        self.load_error = ""
        self.watchdog_state = WatchdogState()
        self._load()

    def _log(self, message: str) -> None:
        if self.logger is not None:
            try:
                self.logger.log_message(message)
            except Exception:
                pass

    def _load(self) -> None:
        if os.name != "nt":
            self.load_error = "native helper is Windows-only"
            return
        errors = []
        for path in _candidate_paths():
            if not os.path.exists(path):
                continue
            try:
                dll = ctypes.CDLL(path)
                self._bind(dll)
                if dll.NMN_GetAbiVersion() != ABI_VERSION:
                    raise RuntimeError("ABI version mismatch")
                if dll.NMN_SelfTest() != 1:
                    raise RuntimeError("native self-test failed")
                self.dll = dll
                self.path = path
                self._log(f"[Native] Loaded {self.version} from {path}")
                return
            except Exception as exc:
                errors.append(f"{path}: {exc}")
        self.load_error = "; ".join(errors) if errors else "NateMiningNative.dll not found"
        self._log(f"[Native] Optional helper unavailable: {self.load_error}")

    @staticmethod
    def _bind(dll: ctypes.CDLL) -> None:
        dll.NMN_GetAbiVersion.argtypes = []
        dll.NMN_GetAbiVersion.restype = ctypes.c_uint32
        dll.NMN_GetVersionString.argtypes = []
        dll.NMN_GetVersionString.restype = ctypes.c_char_p
        dll.NMN_SelfTest.argtypes = []
        dll.NMN_SelfTest.restype = ctypes.c_int
        dll.NMN_ParseXmrigLine.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(XmrigEvent)]
        dll.NMN_ParseXmrigLine.restype = ctypes.c_int
        dll.NMN_WatchdogReset.argtypes = [ctypes.POINTER(WatchdogState), ctypes.c_uint64]
        dll.NMN_WatchdogReset.restype = None
        dll.NMN_WatchdogObserve.argtypes = [ctypes.POINTER(WatchdogState), ctypes.POINTER(XmrigEvent), ctypes.c_uint64]
        dll.NMN_WatchdogObserve.restype = None
        dll.NMN_WatchdogShouldRestart.argtypes = [ctypes.POINTER(WatchdogState), ctypes.POINTER(WatchdogPolicy), ctypes.c_uint64]
        dll.NMN_WatchdogShouldRestart.restype = ctypes.c_uint32
        dll.NMN_DetectCpu.argtypes = [ctypes.POINTER(CpuInfo)]
        dll.NMN_DetectCpu.restype = ctypes.c_int
        dll.NMN_RecommendRandomXThreads.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint32]
        dll.NMN_RecommendRandomXThreads.restype = ctypes.c_uint32
        dll.NMN_BuildPoolProfile.argtypes = [ctypes.c_char_p, ctypes.POINTER(PoolProfile)]
        dll.NMN_BuildPoolProfile.restype = ctypes.c_int

    @property
    def available(self) -> bool:
        return self.dll is not None

    @property
    def version(self) -> str:
        if not self.dll:
            return "unavailable"
        value = self.dll.NMN_GetVersionString()
        return value.decode("ascii", errors="replace") if value else "unknown"

    @property
    def status(self) -> NativeStatus:
        return NativeStatus(self.available, self.path, self.version, self.load_error)

    def parse_line(self, text: str) -> Optional[Dict[str, Any]]:
        if not self.dll or not text:
            return None
        encoded = text.encode("utf-8", errors="replace")
        event = XmrigEvent()
        if self.dll.NMN_ParseXmrigLine(encoded, len(encoded), ctypes.byref(event)) != 1:
            return None
        self.dll.NMN_WatchdogObserve(ctypes.byref(self.watchdog_state), ctypes.byref(event), _now_ms())
        return {
            "flags": int(event.flags),
            "accepted": int(event.accepted),
            "rejected": int(event.rejected),
            "gpu_temp_c": int(event.gpu_temp_c),
            "gpu_fan_percent": int(event.gpu_fan_percent),
            "difficulty": int(event.difficulty),
            "height": int(event.height),
            "hashrate_hs": float(event.hashrate_hs),
            "algorithm": _decode(event.algorithm),
            "pool": _decode(event.pool),
            "fatal": bool(event.flags & EVENT_FATAL_ERROR),
            "transient_error": bool(event.flags & EVENT_TRANSIENT_ERROR),
            "pool_activity": bool(event.flags & EVENT_POOL_ACTIVITY),
            "share": bool(event.flags & EVENT_SHARE),
            "job": bool(event.flags & EVENT_JOB),
            "hashrate": bool(event.flags & EVENT_HASHRATE),
        }

    def watchdog_reset(self) -> None:
        if self.dll:
            self.dll.NMN_WatchdogReset(ctypes.byref(self.watchdog_state), _now_ms())

    def watchdog_restart_reason(
        self,
        error_streak_limit: int = 8,
        bootstrap_seconds: int = 180,
        pool_stall_seconds: int = 120,
        quiet_seconds: int = 0,
        cooldown_seconds: int = 15,
    ) -> int:
        if not self.dll:
            return RESTART_NONE
        policy = WatchdogPolicy(
            ctypes.sizeof(WatchdogPolicy), ABI_VERSION,
            max(1, int(error_streak_limit)),
            max(1, int(bootstrap_seconds)) * 1000,
            max(1, int(pool_stall_seconds)) * 1000,
            max(0, int(quiet_seconds)) * 1000,
            max(0, int(cooldown_seconds)) * 1000,
        )
        return int(self.dll.NMN_WatchdogShouldRestart(
            ctypes.byref(self.watchdog_state), ctypes.byref(policy), _now_ms()))

    def cpu_info(self) -> Optional[Dict[str, Any]]:
        if not self.dll:
            return None
        info = CpuInfo()
        if self.dll.NMN_DetectCpu(ctypes.byref(info)) != 1:
            return None
        return {
            "logical_processors": int(info.logical_processors),
            "physical_cores": int(info.physical_cores),
            "l3_bytes": int(info.l3_bytes),
            "has_aes": bool(info.has_aes),
            "has_avx2": bool(info.has_avx2),
            "recommended_threads_balanced": int(info.recommended_threads_balanced),
            "recommended_threads_max": int(info.recommended_threads_max),
            "vendor": _decode(info.vendor),
            "brand": _decode(info.brand).strip(),
        }

    def pool_profile(self, pool_url: str) -> Optional[Dict[str, Any]]:
        if not self.dll or not pool_url:
            return None
        profile = PoolProfile()
        encoded = pool_url.encode("utf-8", errors="strict")
        if self.dll.NMN_BuildPoolProfile(encoded, ctypes.byref(profile)) != 1:
            return None
        return {
            "is_moneroocean": bool(profile.is_moneroocean),
            "tls": bool(profile.use_tls),
            "sni": bool(profile.use_sni),
            "allow_algo_negotiation": bool(profile.allow_algo_negotiation),
            "primary_port": int(profile.primary_port),
            "fallback_plain_port": int(profile.fallback_plain_port),
            "fallback_tls_port": int(profile.fallback_tls_port),
            "host": _decode(profile.host),
            "normalized_url": _decode(profile.normalized_url),
        }


def python_pool_profile(pool_url: str) -> Dict[str, Any]:
    """Fallback profile builder used when the optional DLL cannot load."""
    value = (pool_url or "").strip()
    lower = value.lower()
    tls = lower.startswith(("stratum+ssl://", "stratum+tls://"))
    without_scheme = value.split("://", 1)[-1]
    host = without_scheme
    port = 0
    if without_scheme.startswith("[") and "]" in without_scheme:
        close = without_scheme.index("]")
        host = without_scheme[1:close]
        if len(without_scheme) > close + 1 and without_scheme[close + 1] == ":":
            try:
                port = int(without_scheme[close + 2:])
            except ValueError:
                port = 0
    elif ":" in without_scheme:
        host, raw_port = without_scheme.rsplit(":", 1)
        try:
            port = int(raw_port)
        except ValueError:
            port = 0
    if not port:
        port = 20128 if tls else 10128
    tls = tls or port in (20128, 443)
    is_mo = host.lower().endswith("moneroocean.stream")
    prefix = "stratum+ssl://" if tls else ""
    return {
        "is_moneroocean": is_mo,
        "tls": tls,
        "sni": tls,
        "allow_algo_negotiation": is_mo,
        "primary_port": port,
        "fallback_plain_port": 10128,
        "fallback_tls_port": 20128,
        "host": host,
        "normalized_url": f"{prefix}{host}:{port}",
    }
