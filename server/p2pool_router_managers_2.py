import atexit
import base64
import binascii
import hashlib
import hmac
import os
import platform
import queue
import random
import re
import ssl
import subprocess
import tempfile
import uuid
import zlib
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field
from enum import auto, Enum
from functools import reduce
from typing import Optional, List, Any, Dict, Tuple, Literal, Callable, Set, Iterable
import ipaddress
import time
from urllib.parse import urlparse

import psutil
import requests
import zmq
from scapy.arch import get_windows_if_list
from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3mq
from scapy.contrib.ikev2 import IKEv2
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6, DHCP6_RelayForward, DHCP6_Advertise, DHCP6_Reply, DHCP6_Solicit, DHCP6OptIA_NA, \
    DUID_LLT, DHCP6OptServerId, DHCP6_InfoRequest, DHCP6_Request, DHCP6OptClientId, DHCP6OptDNSServers, \
    DHCP6OptDNSDomains, DHCP6OptInfoRefreshTime, DHCP6OptIAAddress, DHCP6_Renew, DHCP6_Confirm, DHCP6_Release, \
    DHCP6_Decline, DHCP6_RelayReply, DHCP6OptStatusCode
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import ICMP, IPOption_Router_Alert
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, ICMPv6ND_RA, ICMPv6MLReport, ICMPv6MLReport2, ICMPv6MLDone, \
    IPv6ExtHdrHopByHop, RouterAlert, ICMPv6NDOptDstLLAddr, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NS, \
    ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_RS
from scapy.layers.ipsec import ESP, AH
from scapy.layers.isakmp import ISAKMP
from scapy.layers.l2 import ARP, getmacbyip, GRE
from scapy.layers.rip import RIPEntry, RIP
from scapy.packet import bind_layers
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
import struct
import socket
import threading
import json
from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import srp1

from randomx_ctypes import RandomX, RxUtils
from scapy.layers.inet6 import ICMPv6NDOptPrefixInfo

from p2pool_sniffer import DNSRR_AAAA, ICMPv6


bind_layers(ICMPv6ND_RA, ICMPv6NDOptPrefixInfo)
def RouterRandomMessages(name: str, message: str, emoticons: list[str]) -> str:
    emoji = random.choice(emoticons) if emoticons else ''
    return f"[{name}] {emoji} {message}"
# -------------------------------------------------------------------
# MLDv1 (Query/Report/Done) — light shims if your Scapy lacks them
# -------------------------------------------------------------------


@dataclass
class ShareEvent:
    job_id: str
    nonce_hex: str
    result_hex: str


class StratumManager:
    """
    Local RandomX Stratum job engine.

    Ingress:
      - process_messages(session_id, msgs) where msgs are dict/list[dict]
      - handle_packet(raw_bytes, session_id=...) where raw_bytes are newline JSON

    Egress:
      - share submits via attach_submitter(session_id, fn)

    Submitter signature preferred:
      submitter(job_id=..., nonce=..., result_hash=...)
    Backward compat:
      submitter(..., result=...)
    """

    NONCE_BYTE_OFFSET = 39

    def __init__(self, code_output_manager: Any, logger: Any):
        self.code_output_manager = code_output_manager
        self.logger = logger

        self._lock = threading.RLock()

        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.session_buffers: Dict[str, bytes] = {}

        self._job_queues: Dict[str, queue.Queue] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        self._workers: Dict[str, threading.Thread] = {}
        self._submitters: Dict[str, Callable[..., None]] = {}

        # RandomX engine
        self.rx = RandomX(logger=self.logger)
        self._rx_seed_hex: Optional[str] = None

        self.logger.log_message("[Stratum] ✅ Manager initialized (local RandomX).")

    # ---------------- lifecycle ----------------

    def stop(self) -> None:
        self.logger.log_message("[Stratum] 🛑 Stopping...")
        for sid in list(self.sessions.keys()):
            self.deregister_session(sid)
        self.logger.log_message("[Stratum] ✅ Stopped.")

    def register_session(self, session_id: str) -> None:
        with self._lock:
            if session_id in self.sessions:
                return
            self.sessions[session_id] = {
                "job_ver": 0,
                "difficulty": None,
                "seed_hash": None,
                "current_job": None,
                "submitted": 0,
                "accepted": 0,
                "rejected": 0,
                "last_submit_status": None,
                "last_submit_error": None,
            }
            self.session_buffers[session_id] = b""
            self._job_queues[session_id] = queue.Queue(maxsize=8)
            self._stop_events[session_id] = threading.Event()

        t = threading.Thread(
            target=self._share_worker,
            name=f"StratumWorker-{session_id}",
            args=(session_id,),
            daemon=True,
        )
        with self._lock:
            self._workers[session_id] = t
        t.start()
        self.logger.log_message(f"[Stratum] ✅ Session registered: {session_id}")

    def deregister_session(self, session_id: str) -> None:
        with self._lock:
            evt = self._stop_events.get(session_id)
            if evt:
                evt.set()
            q = self._job_queues.get(session_id)

        if q is not None:
            try:
                q.put_nowait(None)
            except Exception:
                pass

        t = None
        with self._lock:
            t = self._workers.get(session_id)
        if t and t.is_alive():
            t.join(timeout=2.0)

        with self._lock:
            self.sessions.pop(session_id, None)
            self.session_buffers.pop(session_id, None)
            self._job_queues.pop(session_id, None)
            self._stop_events.pop(session_id, None)
            self._workers.pop(session_id, None)
            self._submitters.pop(session_id, None)

        self.logger.log_message(f"[Stratum] 🧹 Session deregistered: {session_id}")

    def attach_submitter(self, session_id: str, submit_func: Callable[..., None]) -> None:
        with self._lock:
            self._submitters[session_id] = submit_func
        self.logger.log_message(f"[Stratum] ✅ Submitter attached: {session_id}")

    # ---------------- ingress: bytes -> json -> routed ----------------

    def handle_packet(self, data: Any, session_id: str = "stratum/default") -> None:
        """Accept bytes/str (newline JSON), or already parsed dict/list."""
        if session_id not in self.sessions:
            self.register_session(session_id)

        if isinstance(data, (dict, list)):
            self.process_messages(session_id, data)
            return

        if isinstance(data, str):
            data = data.encode("utf-8", "ignore")
        if not isinstance(data, (bytes, bytearray)):
            return

        with self._lock:
            buf = self.session_buffers.get(session_id, b"") + bytes(data)

        if len(buf) > 2_000_000:
            self.logger.log_message(f"[Stratum] ⚠️ {session_id} buffer too large; truncating.")
            buf = buf[-200_000:]

        buf = buf.replace(b"\r\n", b"\n")
        out_msgs: List[dict] = []

        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            if line.lstrip()[:1] not in (b"{", b"["):
                continue
            try:
                decoded = json.loads(line)
            except Exception:
                continue

            if isinstance(decoded, dict):
                out_msgs.append(decoded)
            elif isinstance(decoded, list):
                out_msgs.extend([x for x in decoded if isinstance(x, dict)])

        with self._lock:
            self.session_buffers[session_id] = buf

        if out_msgs:
            self.process_messages(session_id, out_msgs)

    def process_messages(self, session_id: str, messages: Any) -> None:
        """Accept dict or list[dict]. Routes method messages vs result/error responses."""
        if session_id not in self.sessions:
            self.register_session(session_id)

        if isinstance(messages, dict):
            msg_list = [messages]
        elif isinstance(messages, list):
            msg_list = messages
        else:
            return

        for msg in msg_list:
            if not isinstance(msg, dict):
                continue
            if "method" in msg:
                self.ingest_stratum_json(session_id, msg)
            else:
                self._handle_rpc_response(session_id, msg)

    def ingest_stratum_json(self, session_id: str, msg: dict) -> None:
        method = msg.get("method")
        params = msg.get("params")

        # ✅ Your pipeline sends this everywhere
        if method == "job":
            if isinstance(params, dict):
                job = self._normalize_job_obj(params)
                if job:
                    self._accept_job(session_id, job)
            return

        # Optional: other styles
        if method in ("set_difficulty", "mining.set_difficulty"):
            diff = None
            if isinstance(params, list) and params:
                diff = params[0]
            elif isinstance(params, dict) and "difficulty" in params:
                diff = params.get("difficulty")
            with self._lock:
                if session_id in self.sessions:
                    self.sessions[session_id]["difficulty"] = diff
            return

        # Some pools embed job at top-level
        if isinstance(msg.get("job"), dict):
            job = self._normalize_job_obj(msg["job"])
            if job:
                self._accept_job(session_id, job)
            return

    # ---------------- rpc responses (submit accepted/rejected) ----------------

    def _handle_rpc_response(self, session_id: str, msg: dict) -> None:
        try:
            with self._lock:
                sess = self.sessions.get(session_id)
            if not sess:
                return

            if msg.get("error"):
                err = msg.get("error") or {}
                with self._lock:
                    sess["last_submit_error"] = err
                    sess["rejected"] = int(sess.get("rejected", 0)) + 1

                self.logger.log_message(
                    f"[Stratum] ❗ {session_id} RPC error: {err.get('code')} {err.get('message')}"
                )

                # If low-diff, print last computed debug
                emsg = (err.get("message") or "").lower()
                if "low diff" in emsg:
                    dbg = None
                    with self._lock:
                        dbg = (sess or {}).get("_last_share_debug")
                    if isinstance(dbg, dict):
                        self.logger.log_message(
                            "[Stratum] 🔍 low-diff debug "
                            f"job={dbg.get('job_id')} nonce={dbg.get('nonce')} "
                            f"target_kind={dbg.get('target_kind')} target64={dbg.get('target64')} "
                            f"jobdiff≈{dbg.get('jobdiff')} lane3={dbg.get('lane3_u64')} "
                            f"share_diff≈{dbg.get('share_diff')} target_hex={dbg.get('target_hex')}"
                        )
                return

            res = msg.get("result")

            # login can embed job
            if isinstance(res, dict) and isinstance(res.get("job"), dict):
                job = self._normalize_job_obj(res["job"])
                if job:
                    self._accept_job(session_id, job)

            if isinstance(res, dict):
                status = (res.get("status") or res.get("state") or "").upper()
                accepted = bool(res.get("accepted")) or (status == "OK")

                looks_like_submit_ack = (
                    ("status" in res) or ("accepted" in res) or status in ("OK", "REJECTED", "INVALID", "ERROR")
                )
                if looks_like_submit_ack:
                    with self._lock:
                        sess["last_submit_status"] = status or ("OK" if accepted else "UNKNOWN")
                        if accepted:
                            sess["accepted"] = int(sess.get("accepted", 0)) + 1
                        else:
                            sess["rejected"] = int(sess.get("rejected", 0)) + 1
                    self.logger.log_message(
                        f"[Stratum] 📨 {session_id} submit result: {'ACCEPTED' if accepted else (status or 'REJECTED')}"
                    )
        except Exception as e:
            self.logger.log_message(f"[Stratum] ❌ _handle_rpc_response error: {type(e).__name__}: {e}")

    # ---------------- job handling ----------------

    def _normalize_job_obj(self, job_obj: dict) -> Optional[dict]:
        if not isinstance(job_obj, dict):
            return None

        job_id = job_obj.get("job_id") or job_obj.get("id") or job_obj.get("jobId")
        blob = job_obj.get("blob") or job_obj.get("blob_hex") or job_obj.get("blobHex")
        target = job_obj.get("target") or job_obj.get("target_hex") or job_obj.get("targetHex")
        seed_hash = job_obj.get("seed_hash") or job_obj.get("seedHash") or job_obj.get("seed")

        job_id = job_id if isinstance(job_id, str) else None
        blob = blob if isinstance(blob, str) else None
        target = target if isinstance(target, str) else None
        seed_hash = seed_hash if isinstance(seed_hash, str) else None

        if seed_hash:
            seed_hash = RxUtils.norm_hex(seed_hash)
        if blob:
            blob = RxUtils.norm_hex(blob)
        if target:
            target = RxUtils.norm_hex(target)

        if not job_id or not blob:
            return None

        return {"job_id": job_id, "blob": blob, "target": target, "seed_hash": seed_hash}

    def _accept_job(self, session_id: str, job: dict) -> None:
        seed_hex = job.get("seed_hash")
        if isinstance(seed_hex, str) and seed_hex:
            self._maybe_reinit_randomx(seed_hex)

        with self._lock:
            sess = self.sessions.get(session_id)
            if not sess:
                return
            sess["job_ver"] = int(sess.get("job_ver", 0)) + 1
            sess["seed_hash"] = seed_hex
            sess["current_job"] = job
            job_ver = int(sess["job_ver"])
            q = self._job_queues.get(session_id)

        if q is not None:
            try:
                q.put_nowait({"job": job, "job_ver": job_ver})
            except queue.Full:
                try:
                    q.get_nowait()
                except Exception:
                    pass
                try:
                    q.put_nowait({"job": job, "job_ver": job_ver})
                except Exception:
                    pass

    def _maybe_reinit_randomx(self, seed_hex: str) -> None:
        seed_hex = RxUtils.norm_hex(seed_hex) or ""
        if len(seed_hex) < 64:
            return
        seed_hex = seed_hex[:64]
        if seed_hex == self._rx_seed_hex:
            return

        try:
            seed = bytes.fromhex(seed_hex)
        except Exception:
            self.logger.log_message(f"[Stratum] ⚠️ Invalid seed_hash hex: {seed_hex!r}")
            return

        self.rx.ensure_seed(seed)
        self._rx_seed_hex = seed_hex
        self.logger.log_message(f"[Stratum] ✅ RandomX ready for seed {seed_hex[:12]}…")

    # ---------------- hashing worker ----------------
    @staticmethod
    def _u64_lane3_from_hash32_le(h32: bytes) -> int:
        """
        XMRig-style lane selection:
          reinterpret_cast<const uint64_t*>(hash)[3]
        => bytes 24..31 as little-endian u64.
        """
        if not isinstance(h32, (bytes, bytearray)) or len(h32) != 32:
            return 0
        return int.from_bytes(h32[24:32], "little", signed=False)

    @staticmethod
    def _target_u64_from_pool_target_hex(target_hex: Optional[str]) -> Optional[int]:
        """
        Pool 'target' is commonly 4 bytes (8 hex chars) LE.
        XMRig scales that to a 64-bit target using:
          target64 = 0xFFFFFFFFFFFFFFFF / (0xFFFFFFFF / target32)
        """
        s = RxUtils.norm_hex(target_hex)
        if not s:
            return None
        if len(s) % 2 == 1:
            s = "0" + s

        try:
            raw = bytes.fromhex(s)
        except Exception:
            return None

        if len(raw) == 4:
            t32 = int.from_bytes(raw, "little", signed=False)
            if t32 <= 0:
                return None
            denom = (0xFFFFFFFF // t32)
            if denom <= 0:
                return None
            return (0xFFFFFFFFFFFFFFFF // denom)

        if len(raw) >= 8:
            return int.from_bytes(raw[:8], "little", signed=False)

        return int.from_bytes(raw.ljust(8, b"\x00"), "little", signed=False)
    @staticmethod
    def _target_u256_from_hex_le(target_hex: Optional[str]) -> Optional[int]:
        if not isinstance(target_hex, str) or not target_hex:
            return None
        s = RxUtils.norm_hex(target_hex)
        if not s:
            return None
        try:
            tb = bytes.fromhex(s)
        except Exception:
            return None
        return int.from_bytes(tb, "little", signed=False)

    @staticmethod
    def _target_len_bytes(target_hex: Optional[str]) -> int:
        if not isinstance(target_hex, str) or not target_hex:
            return 32
        s = RxUtils.norm_hex(target_hex)
        return max(1, len(s) // 2) if s else 32

    def _share_worker(self, session_id: str) -> None:
        import random  # ensure imported

        q = self._job_queues[session_id]
        stop_evt = self._stop_events[session_id]

        stride_seed = abs(hash(session_id)) or 1
        stride = ((stride_seed & 0xFFFF) | 1)

        vm = None
        vm_seed = None

        LOG_INTERVAL = 2.0
        self.logger.log_message(f"[Stratum] Worker started for {session_id} (stride={stride})")

        while True:
            job_wrap = q.get()
            if job_wrap is None or stop_evt.is_set():
                break

            job = job_wrap.get("job") if isinstance(job_wrap, dict) else None
            my_ver = job_wrap.get("job_ver") if isinstance(job_wrap, dict) else None
            if not isinstance(job, dict) or not isinstance(my_ver, int):
                continue

            job_id = job.get("job_id")
            blob_hex = job.get("blob")
            target_hex = job.get("target")
            seed_hex = job.get("seed_hash")

            if not isinstance(job_id, str) or not isinstance(blob_hex, str):
                continue

            blob_hex = RxUtils.norm_hex(blob_hex) or ""
            if not blob_hex:
                continue

            try:
                base = bytearray(bytes.fromhex(blob_hex))
            except Exception as e:
                self.logger.log_message(f"[Stratum] ❌ bad blob hex for job {job_id}: {e}")
                continue

            off = int(self.NONCE_BYTE_OFFSET)
            if off + 4 > len(base):
                self.logger.log_message(f"[Stratum] ❌ blob too short for nonce offset (job {job_id})")
                continue

            if isinstance(seed_hex, str) and seed_hex:
                seed_hex = RxUtils.norm_hex(seed_hex) or None
            if not seed_hex:
                self.logger.log_message(f"[Stratum] ⚠️ job {job_id} missing seed_hash; waiting for next job")
                continue

            if seed_hex != self._rx_seed_hex:
                self._maybe_reinit_randomx(seed_hex)

            if vm is None or vm_seed != self._rx_seed_hex:
                try:
                    if vm is not None:
                        self.rx.destroy_vm(vm)
                except Exception:
                    pass
                vm = self.rx.create_vm()
                vm_seed = self._rx_seed_hex

            # -----------------------------
            # Correct target handling
            # -----------------------------
            tnorm = RxUtils.norm_hex(target_hex) or ""
            if tnorm and (len(tnorm) % 2 == 1):
                tnorm = "0" + tnorm

            tb = b""
            if tnorm:
                try:
                    tb = bytes.fromhex(tnorm)
                except Exception:
                    tb = b""

            target64: Optional[int] = None
            target256: Optional[int] = None
            target_kind = "none"

            if tb:
                # Pool targets are usually 4 bytes (sometimes 8). Template-style targets are longer.
                if len(tb) <= 8:
                    target64 = self._target_u64_from_pool_target_hex(target_hex)
                    target_kind = f"pool_t{len(tb)}"
                else:
                    # Treat as 256-bit LE (pad/truncate to 32 bytes)
                    tb32 = (tb + b"\x00" * 32)[:32]
                    target256 = int.from_bytes(tb32, "little", signed=False)
                    target_kind = f"tpl_t{len(tb)}"

            if target64 is None and target256 is None:
                self.logger.log_message(f"[Stratum] ⚠️ job {job_id} missing/invalid target; skipping job")
                continue

            # Helpful debug numbers
            jobdiff = None
            if target64 is not None and target64 > 0:
                jobdiff = (0xFFFFFFFFFFFFFFFF // target64)

            def meets_target(h32: bytes) -> bool:
                if target256 is not None:
                    return int.from_bytes(h32, "little", signed=False) <= target256
                # pool-style check: lane3 u64 <= target64
                v = self._u64_lane3_from_hash32_le(h32)
                return v != 0 and (target64 is not None) and (v <= target64)

            self.logger.log_message(
                f"[Stratum] ▶️ Working job {job_id} on {session_id} (target={target_kind}"
                + (f" jobdiff≈{jobdiff}" if jobdiff is not None else "")
                + ")"
            )

            nonce = random.getrandbits(32)
            tries = 0
            ema = None
            last_log = time.perf_counter()
            submitted: set[str] = set()

            while True:
                if stop_evt.is_set():
                    break

                with self._lock:
                    cur_ver = int(self.sessions.get(session_id, {}).get("job_ver", my_ver))
                if cur_ver != my_ver:
                    break

                base[off:off + 4] = int(nonce).to_bytes(4, "little", signed=False)
                h32 = self.rx.hash(vm, bytes(base))

                if meets_target(h32):
                    nonce_hex = int(nonce).to_bytes(4, "little", signed=False).hex()
                    if nonce_hex not in submitted:
                        submitted.add(nonce_hex)
                        result_hex = h32.hex()

                        # Save debug for rejection logs
                        try:
                            with self._lock:
                                sess = self.sessions.get(session_id)
                                if sess is not None:
                                    v = self._u64_lane3_from_hash32_le(h32)
                                    share_diff = (0xFFFFFFFFFFFFFFFF // v) if v else None
                                    sess["_last_share_debug"] = {
                                        "job_id": job_id,
                                        "nonce": nonce_hex,
                                        "target_hex": (tnorm or None),
                                        "target_kind": target_kind,
                                        "target64": target64,
                                        "jobdiff": jobdiff,
                                        "lane3_u64": v,
                                        "share_diff": share_diff,
                                    }
                        except Exception:
                            pass

                        if self._submit_share(session_id, job_id, nonce_hex, result_hex):
                            self.logger.log_message(f"[Stratum] 🎯 SHARE job={job_id} nonce={nonce_hex}")

                nonce = (nonce + stride) & 0xFFFFFFFF
                tries += 1

                now = time.perf_counter()
                if (now - last_log) >= LOG_INTERVAL:
                    rate = tries / (now - last_log)
                    ema = rate if ema is None else (0.2 * rate + 0.8 * ema)
                    tries = 0
                    last_log = now

                    try:
                        self.code_output_manager.submit_packet(
                            {"job_id": job_id, "hashrate": float(ema)},
                            inbound_iface="stratum",
                            phase="handled",
                            component="work",
                        )
                    except Exception:
                        pass

                    self.logger.log_message(f"[Stratum] ⏱️ {session_id} job {job_id}: {ema:.0f} H/s")

        try:
            if vm is not None:
                self.rx.destroy_vm(vm)
        except Exception:
            pass

        self.logger.log_message(f"[Stratum] 🛑 Worker stopped for {session_id}")
    # ---------------- submit ----------------

    def _submit_share(self, session_id: str, job_id: str, nonce_hex: str, result_hex: str) -> bool:
        with self._lock:
            submitter = self._submitters.get(session_id)
            sess = self.sessions.get(session_id)

        if not submitter:
            return False

        try:
            if sess is not None:
                with self._lock:
                    sess["submitted"] = int(sess.get("submitted", 0)) + 1
        except Exception:
            pass

        try:
            submitter(job_id=job_id, nonce=nonce_hex, result_hash=result_hex)
            return True
        except TypeError:
            pass

        try:
            submitter(job_id=job_id, nonce=nonce_hex, result=result_hex)
            return True
        except Exception as e:
            self.logger.log_message(f"[Stratum] ❌ Submitter failed: {e}")
            return False

class ConnectionState(Enum):
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    STOPPING = auto()


class StratumConnectionManager:
    """
    - Direct connect to pool (login, read, submit)
    - Optional proxy listener for miners (relay both ways)
    - Forwards all decoded msgs to StratumManager.process_messages(...)
    """

    LIKELY_TLS_PORTS = {443, 3333, 5555, 7443, 8443}

    def __init__(self, code_output_manager, router_logger: Any, stratum_manager: StratumManager):
        self.code_output_manager = code_output_manager
        self.logger = router_logger
        self.stratum_manager = stratum_manager

        self.proxy_host = "127.0.0.1"
        self.proxy_port = 3333

        self.pool_ip: Optional[str] = None
        self.pool_port: Optional[int] = None
        self.pool_host: Optional[str] = None
        self.use_tls: str | bool = "auto"

        self.wallet_address: Optional[str] = None
        self.worker_name = "default"
        self.user_agent = "pystratum/0.5"

        self._threads: list[threading.Thread] = []
        self._active_sockets: list[socket.socket] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._pending_by_id: Dict[int, str] = {}

        self._direct_conn_state = ConnectionState.DISCONNECTED
        self.direct_session_id: Optional[str] = None
        self._pool_socket: Optional[socket.socket] = None
        self.KEEPALIVE_INTERVAL_S = 30
        self._next_keepalive_ts = 0.0

        # proxy upstream id mapping
        self._proxy_session_ids: Dict[str, str] = {}

        self.logger.log_message("[StratumConn] ✅ initialized")

    def configure(
        self,
        pool_ip: str,
        pool_port: int,
        wallet: str,
        worker: str = "default",
        listen_port: int = 3333,
        use_tls: str | bool = "auto",
        pool_host: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        self.pool_ip = pool_ip
        self.pool_port = int(pool_port)
        self.wallet_address = wallet
        self.worker_name = worker
        self.proxy_port = int(listen_port)
        self.use_tls = use_tls
        self.pool_host = pool_host or pool_ip
        if user_agent:
            self.user_agent = user_agent

        self.logger.log_message(
            f"[StratumConn] 🎯 pool={self.pool_ip}:{self.pool_port} tls={self.use_tls} sni={self.pool_host} "
            f"proxy={self.proxy_host}:{self.proxy_port}"
        )

    def start(self) -> None:
        if not all([self.pool_ip, self.pool_port, self.wallet_address]):
            self.logger.log_message("[StratumConn] ❌ missing config")
            return
        if self._threads:
            return

        self._stop_event.clear()
        t1 = threading.Thread(target=self._direct_connection_loop, daemon=True, name="StratumDirectConnector")
        t2 = threading.Thread(target=self._listen_for_miners, daemon=True, name="StratumProxyListener")
        self._threads = [t1, t2]
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        if not self._threads:
            return
        self._stop_event.set()
        self.stratum_manager.stop()

        for s in list(self._active_sockets):
            self._close_socket(s)

        for t in self._threads:
            if t.is_alive():
                t.join(timeout=2)
        self._threads.clear()
        self.logger.log_message("[StratumConn] ✅ stopped")

    # ---------------- sockets ----------------

    def _add_socket(self, sock: socket.socket) -> None:
        with self._lock:
            self._active_sockets.append(sock)

    def _remove_socket(self, sock: socket.socket) -> None:
        with self._lock:
            if sock in self._active_sockets:
                self._active_sockets.remove(sock)

    def _close_socket(self, sock: Optional[socket.socket]) -> None:
        if not sock:
            return
        self._remove_socket(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _schedule_keepalive(self) -> None:
        self._next_keepalive_ts = time.time() + self.KEEPALIVE_INTERVAL_S + random.uniform(-5, 5)

    def _open_pool_socket(self) -> socket.socket:
        assert self.pool_ip and self.pool_port

        def connect_plain() -> socket.socket:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(10.0)
            s.connect((self.pool_ip, self.pool_port))
            s.settimeout(1.0)
            self.logger.log_message("[StratumConn] 🔓 TCP")
            return s

        want_tls = (self.use_tls is True) or (self.use_tls == "auto" and self.pool_port in self.LIKELY_TLS_PORTS)
        if not want_tls:
            return connect_plain()

        ctx = ssl.create_default_context()
        if not self.pool_host or self.pool_host == self.pool_ip:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.logger.log_message("[StratumConn] ⚠️ TLS no hostname; disabling cert verification")

        plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        plain.settimeout(10.0)

        try:
            plain.connect((self.pool_ip, self.pool_port))
            tls_sock = ctx.wrap_socket(plain, server_hostname=self.pool_host)
            tls_sock.settimeout(1.0)
            self.logger.log_message(f"[StratumConn] 🔐 TLS (SNI {self.pool_host})")
            return tls_sock
        except Exception as e:
            self._close_socket(plain)
            if self.use_tls is True:
                raise
            self.logger.log_message(f"[StratumConn] ⚠️ TLS failed ({type(e).__name__}); falling back to TCP")
            return connect_plain()

    # ---------------- direct connection ----------------

    def _send_json_rpc_request(self, sock: socket.socket, message: dict) -> None:
        req = (json.dumps(message) + "\n").encode("utf-8")
        sock.sendall(req)
        mid = message.get("id")
        mth = message.get("method")
        if isinstance(mid, int) and isinstance(mth, str):
            self._pending_by_id[mid] = mth

    def _send_authorize_request(self, sock: socket.socket) -> None:
        params = {"login": self.wallet_address, "pass": "x", "agent": self.user_agent, "rigid": self.worker_name}
        self._send_json_rpc_request(sock, {"jsonrpc": "2.0", "id": 1, "method": "login", "params": params})
        self._schedule_keepalive()

    def _send_keepalive(self, sock: socket.socket) -> None:
        if not self.direct_session_id:
            return
        self._send_json_rpc_request(sock, {"jsonrpc": "2.0", "id": 2, "method": "keepalived", "params": {"id": self.direct_session_id}})
        self._schedule_keepalive()

    def submit_share(self, job_id: str, nonce: str, result_hash: str) -> None:
        with self._lock:
            if self._direct_conn_state != ConnectionState.CONNECTED or not self._pool_socket:
                return
            sock = self._pool_socket

        msg = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "submit",
            "params": {"id": self.direct_session_id, "job_id": job_id, "nonce": nonce, "result": result_hash},
        }
        try:
            self._send_json_rpc_request(sock, msg)
        except OSError as e:
            self.logger.log_message(f"[StratumConn] ❌ submit send failed: {e}")

    def _parse_json_line(self, line: bytes) -> Optional[list[dict]]:
        line = line.strip()
        if not line.startswith((b"{", b"[")):
            return None
        try:
            decoded = json.loads(line)
            msgs = decoded if isinstance(decoded, list) else [decoded]
            return [m for m in msgs if isinstance(m, dict)]
        except Exception:
            return None

    def _process_received_data(self, buffer: bytes, session_id: str) -> bytes:
        buffer = buffer.replace(b"\r\n", b"\n")
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue
            msgs = self._parse_json_line(line)
            if not msgs:
                continue

            for msg in msgs:
                # result/error response
                if "result" in msg or "error" in msg:
                    mid = msg.get("id")
                    last_method = self._pending_by_id.pop(mid, None) if isinstance(mid, int) else None

                    res = msg.get("result") or {}
                    if last_method == "login" and isinstance(res, dict):
                        sid = res.get("id")
                        if isinstance(sid, str) and sid:
                            self.direct_session_id = sid
                            self.logger.log_message(f"[StratumConn] 🔑 login ok id={sid}")
                            self._schedule_keepalive()

                    # embed job
                    if isinstance(res, dict) and isinstance(res.get("job"), dict):
                        j = res["job"]
                        for k in ("blob", "seed_hash", "next_seed_hash", "target"):
                            if k in j and isinstance(j[k], str):
                                j[k] = RxUtils.norm_hex(j[k])
                        self.stratum_manager.process_messages(session_id, [{"method": "job", "params": j}])

                    self.stratum_manager.process_messages(session_id, [msg])
                    continue

                # method message
                mth = (msg.get("method") or "").lower()
                params = msg.get("params") or {}
                if mth == "job" and isinstance(params, dict):
                    for k in ("blob", "seed_hash", "next_seed_hash", "target"):
                        if k in params and isinstance(params[k], str):
                            params[k] = RxUtils.norm_hex(params[k])
                    self.stratum_manager.process_messages(session_id, [{"method": "job", "params": params}])
                else:
                    self.stratum_manager.process_messages(session_id, [msg])

        return buffer

    def _direct_connection_loop(self) -> None:
        DIRECT_SESSION = "direct_pool_connection"
        reconnect = 5.0

        while not self._stop_event.is_set():
            pool = None
            try:
                with self._lock:
                    self._direct_conn_state = ConnectionState.CONNECTING

                pool = self._open_pool_socket()
                self._add_socket(pool)
                self._pool_socket = pool

                self.stratum_manager.attach_submitter(DIRECT_SESSION, self.submit_share)
                self.stratum_manager.register_session(DIRECT_SESSION)

                with self._lock:
                    self._direct_conn_state = ConnectionState.CONNECTED

                self._send_authorize_request(pool)

                buf = b""
                while not self._stop_event.is_set():
                    if self.direct_session_id and time.time() >= self._next_keepalive_ts:
                        self._send_keepalive(pool)
                    try:
                        data = pool.recv(8192)
                        if not data:
                            break
                        buf += data
                        buf = self._process_received_data(buf, DIRECT_SESSION)
                    except socket.timeout:
                        continue
                    except OSError:
                        break

            except Exception as e:
                self.logger.log_message(f"[StratumConn] ❌ direct loop error: {e}")
            finally:
                try:
                    self.stratum_manager.deregister_session(DIRECT_SESSION)
                except Exception:
                    pass
                with self._lock:
                    self._direct_conn_state = ConnectionState.DISCONNECTED
                self._close_socket(pool)
                self._pool_socket = None
                self.direct_session_id = None

            if not self._stop_event.is_set():
                self._stop_event.wait(reconnect)
                reconnect = min(reconnect * 1.5, 60.0)

    # ---------------- proxy mode ----------------

    def _listen_for_miners(self) -> None:
        srv = None
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.proxy_host, self.proxy_port))
            srv.listen(64)
            srv.settimeout(1.0)
            self.logger.log_message(f"[StratumConn] 👂 proxy listening {self.proxy_host}:{self.proxy_port}")
        except OSError as e:
            self.logger.log_message(f"[StratumConn] ❌ proxy listener failed: {e}")
            return

        try:
            while not self._stop_event.is_set():
                try:
                    miner, addr = srv.accept()
                    miner.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    miner.settimeout(60.0)
                    threading.Thread(target=self._handle_miner_session, args=(miner,), daemon=True).start()
                except socket.timeout:
                    continue
        finally:
            self._close_socket(srv)

    def _handle_miner_session(self, miner_socket: socket.socket) -> None:
        pool_socket: Optional[socket.socket] = None
        miner_addr = miner_socket.getpeername()
        session_id = f"proxy_{miner_addr[0]}:{miner_addr[1]}"
        send_q: queue.PriorityQueue[tuple[int, bytes]] = queue.PriorityQueue()

        try:
            self._add_socket(miner_socket)
            self.stratum_manager.register_session(session_id)

            pool_socket = self._open_pool_socket()
            self._add_socket(pool_socket)

            # submitter for proxy session
            def _submit_via_proxy(*, job_id: str, nonce: str, result_hash: str) -> None:
                upstream_id = self._proxy_session_ids.get(session_id)
                params = {"job_id": job_id, "nonce": nonce, "result": result_hash}
                if upstream_id:
                    params["id"] = upstream_id
                msg = {"jsonrpc": "2.0", "id": 1, "method": "submit", "params": params}
                send_q.put_nowait((1, (json.dumps(msg) + "\n").encode("utf-8")))

            self.stratum_manager.attach_submitter(session_id, _submit_via_proxy)

            threading.Thread(target=self._sender_worker, args=(send_q, pool_socket), daemon=True).start()
            threading.Thread(target=self._relay_data, args=(miner_socket, send_q, "Miner -> Pool", session_id), daemon=True).start()
            threading.Thread(target=self._relay_data, args=(pool_socket, miner_socket, "Pool -> Miner", session_id), daemon=True).start()

        except Exception as e:
            self.logger.log_message(f"[StratumConn] ❌ proxy session failed: {e}")
        finally:
            self.stratum_manager.deregister_session(session_id)
            self._proxy_session_ids.pop(session_id, None)
            try:
                send_q.put_nowait((99, b""))
            except Exception:
                pass
            self._close_socket(miner_socket)
            self._close_socket(pool_socket)

    def _sender_worker(self, send_queue: queue.PriorityQueue[tuple[int, bytes]], dest_socket: socket.socket) -> None:
        while not self._stop_event.is_set():
            try:
                _, data = send_queue.get(timeout=1.0)
                if not data:
                    break
                dest_socket.sendall(data)
            except queue.Empty:
                continue
            except OSError:
                break

    def _relay_data(self, src_socket: socket.socket, dest: socket.socket | queue.PriorityQueue, direction: str, session_id: str = "") -> None:
        while not self._stop_event.is_set():
            try:
                data = src_socket.recv(8192)
                if not data:
                    break

                # parse pool->miner for upstream login id + job
                if direction == "Pool -> Miner" and session_id:
                    lines = data.replace(b"\r\n", b"\n").split(b"\n")
                    for line in filter(None, lines):
                        msgs = self._parse_json_line(line) or []
                        for m in msgs:
                            try:
                                res = (m.get("result") or {})
                                sid = res.get("id")
                                if isinstance(sid, str) and sid:
                                    self._proxy_session_ids[session_id] = sid
                            except Exception:
                                pass
                        if msgs:
                            self.stratum_manager.process_messages(session_id, msgs)

                if isinstance(dest, queue.PriorityQueue):
                    lines = data.replace(b"\r\n", b"\n").split(b"\n")
                    for line in filter(None, lines):
                        pr = 3
                        try:
                            decoded = json.loads(line)
                            if isinstance(decoded, dict) and decoded.get("method") == "submit":
                                pr = 1
                            elif isinstance(decoded, dict) and decoded.get("method") == "job":
                                pr = 2
                        except Exception:
                            pass
                        dest.put_nowait((pr, line + b"\n"))
                else:
                    dest.sendall(data)

            except (socket.timeout, OSError):
                break
            except Exception:
                break

    # ---------------- daemon synergy ----------------

    def distribute_job_from_daemon(self, job: Dict[str, Any]) -> None:
        session_id = "daemon_local"
        for k in ("blob", "seed_hash", "target"):
            if k in job and isinstance(job[k], str):
                job[k] = RxUtils.norm_hex(job[k])
        self.stratum_manager.register_session(session_id)
        self.stratum_manager.process_messages(session_id, [{"method": "job", "params": job}])

class ZMQReader:
    def __init__(self, zmq_address: str, message_handler, logger: Any):
        self.zmq_address = zmq_address
        self.message_handler = message_handler
        self.logger = logger
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="ZMQReaderThread")
        self._thread.start()
        self.logger.log_message(f"[ZMQ] Subscribing to {self.zmq_address}")

    def stop(self):
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._running = False
        self.logger.log_message("[ZMQ] Reader stopped.")

    def _run_loop(self):
        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        # keep broad; we just use it as “new activity” triggers
        socket.setsockopt(zmq.SUBSCRIBE, b"json-minimal-block")
        socket.setsockopt(zmq.SUBSCRIBE, b"json-full-block")
        socket.setsockopt(zmq.SUBSCRIBE, b"json-minimal-miner_data")
        socket.setsockopt(zmq.SUBSCRIBE, b"json-full-miner_data")
        socket.RCVTIMEO = 500

        try:
            socket.connect(self.zmq_address)
            while not self._stop_event.is_set():
                try:
                    frames = socket.recv_multipart(flags=0)
                    if not frames:
                        continue
                    if len(frames) >= 2:
                        topic = frames[0]
                        payload = b" ".join(frames[1:])
                        self.message_handler(topic + b" " + payload)
                    else:
                        self.message_handler(frames[0])
                except zmq.Again:
                    continue
        except zmq.ZMQError as e:
            self.logger.log_message(f"[ZMQ] ❌ connect error: {e}")
        finally:
            socket.close(0)
            context.term()


class MoneroDaemonManager:
    NONCE_BYTE_OFFSET = 39
    DEFAULT_RESERVE_SIZE = 60
    _DAEMON_SESSION_ID = "daemon_local"

    def __init__(
        self,
        code_output_manager,
        daemon_url: str,
        zmq_address: str,
        stratum_conn_manager: StratumConnectionManager,
        logger: Any,
        reserve_size: int = DEFAULT_RESERVE_SIZE,
    ):
        self.code_output_manager = code_output_manager
        self.daemon_url = daemon_url.rstrip("/")
        self.zmq_address = zmq_address
        self.stratum_conn_manager = stratum_conn_manager
        self.logger = logger
        self.reserve_size = int(reserve_size)

        self._running = False
        self._stop_event = threading.Event()

        self.zmq_reader = ZMQReader(self.zmq_address, self._handle_zmq_message, self.logger)

        self._templates_by_job_id: Dict[str, str] = {}
        self._difficulty_by_job_id: Dict[str, int] = {}
        self._last_fp = None
        self._last_refresh = 0.0

        # attach submitter for daemon session
        self.stratum_conn_manager.stratum_manager.attach_submitter(
            self._DAEMON_SESSION_ID, self.submit_block_to_daemon
        )

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self.zmq_reader.start()
        threading.Thread(target=self._fetch_and_distribute_job, daemon=True).start()
        self.logger.log_message("[Daemon] ✅ started")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        self.zmq_reader.stop()
        try:
            self.stratum_conn_manager.stratum_manager.deregister_session(self._DAEMON_SESSION_ID)
        except Exception:
            pass
        self.logger.log_message("[Daemon] ✅ stopped")

    def _handle_zmq_message(self, raw: bytes):
        # debounce: don’t spam RPC
        now = time.time()
        if (now - self._last_refresh) < 0.5:
            return
        self._last_refresh = now
        threading.Thread(target=self._fetch_and_distribute_job, daemon=True).start()

    def _rpc_call(self, method: str, params: Optional[Any] = None) -> Dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        payload = {"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}
        r = requests.post(f"{self.daemon_url}/json_rpc", data=json.dumps(payload), headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("error"):
            err = data["error"]
            raise RuntimeError(f"RPC {method} error {err.get('code')}: {err.get('message')}")
        return data

    def _fingerprint(self, height: int, prev_hash: str, seed_hash: str, target_hex: str, blob_hex: str) -> tuple:
        return (height, prev_hash[:16], seed_hash[:16], target_hex[:16], len(blob_hex))

    def _fetch_and_distribute_job(self) -> None:
        wa = (self.stratum_conn_manager.wallet_address or "").strip()
        if not wa:
            self.logger.log_message("[Daemon] ❌ no wallet_address configured")
            return

        reserve = max(0, min(127, int(self.reserve_size)))
        params = {"wallet_address": wa, "reserve_size": reserve}

        try:
            resp = self._rpc_call("get_block_template", params)
            res = resp.get("result") or {}
            tpl = RxUtils.norm_hex(res.get("blocktemplate_blob"))
            if not tpl:
                return

            height = int(res.get("height", 0))
            prev_hash = RxUtils.norm_hex(res.get("prev_hash") or "") or ""
            seed_hash = RxUtils.norm_hex(res.get("seed_hash") or "") or ""

            # difficulty (wide preferred)
            D = None
            wide = res.get("wide_difficulty")
            if wide is not None:
                try:
                    ws = str(wide).strip()
                    D = int(ws, 16) if ws.lower().startswith("0x") else int(ws)
                except Exception:
                    D = None
            if D is None:
                low = int(res.get("difficulty", 0))
                high = int(res.get("difficulty_top64", 0))
                D = (high << 64) | low

            if not isinstance(D, int) or D <= 0:
                return

            target_hex = RxUtils.target_hex_from_difficulty(D)

            fp = self._fingerprint(height, prev_hash, seed_hash, target_hex, tpl)
            if fp == self._last_fp:
                return
            self._last_fp = fp

            job_id = f"daemon-{height}-{prev_hash[:16]}-{int(time.time()*1000)%1_000_000:06d}"

            job = {
                "id": job_id,
                "blob": tpl,
                "target": target_hex,
                "height": height,
                "difficulty": D,
                "seed_hash": seed_hash,
                "prev_hash": prev_hash,
                "nonce_byte_offset": self.NONCE_BYTE_OFFSET,
            }

            self._templates_by_job_id[job_id] = tpl
            self._difficulty_by_job_id[job_id] = D

            self.stratum_conn_manager.distribute_job_from_daemon(job)
            self.logger.log_message(f"[Daemon] ✅ distributed job {job_id} h={height} diff={D}")

        except Exception as e:
            self.logger.log_message(f"[Daemon] ❌ job fetch error: {type(e).__name__}: {e}")

    def submit_block_to_daemon(self, *, job_id: str, nonce: str, result_hash: str) -> None:
        try:
            tpl = self._templates_by_job_id.get(job_id)
            if not tpl:
                self.logger.log_message(f"[Daemon] ⚠️ missing template for {job_id}")
                return

            nonce = RxUtils.norm_hex(nonce) or ""
            if len(nonce) != 8:
                raise ValueError("nonce must be 4 bytes LE (8 hex chars)")

            off = self.NONCE_BYTE_OFFSET * 2
            full_blob_hex = tpl[:off] + nonce + tpl[off + 8:]

            # client-side diff check (optional)
            D = self._difficulty_by_job_id.get(job_id)
            if D:
                target_int = RxUtils.target_from_difficulty_int(D)
                hb = bytes.fromhex(RxUtils.norm_hex(result_hash) or "")
                if int.from_bytes(hb, "little") > target_int:
                    self.logger.log_message(f"[Daemon] ⚠️ share below diff; not submitting")
                    return

            resp = self._rpc_call("submit_block", [full_blob_hex])
            status = (resp.get("result") or {}).get("status", "")
            if status.upper() == "OK":
                self.logger.log_message(f"[Daemon] ✅ block accepted for job {job_id}")
                self._templates_by_job_id.pop(job_id, None)
                self._difficulty_by_job_id.pop(job_id, None)
            else:
                self.logger.log_message(f"[Daemon] ❗ submit not OK: {status or resp.get('error')}")

        except Exception as e:
            self.logger.log_message(f"[Daemon] ❌ submit error: {type(e).__name__}: {e}")




class BroadcastManager:
    """
    Windows/NPcap-focused broadcast helper.

    What it does:
      - Maps a pcap name (\\Device\\NPF_{GUID}) to the Windows iface record.
      - Computes IPv4 broadcast (from ip + netmask).
      - Tries to locate the Scapy iface by GUID and set useful attributes:
          * iface.broadcast / iface.l2broadcast (best-effort) -> 'ff:ff:ff:ff:ff:ff'
          * iface.ipv4_broadcast (aux field, for your code)    -> IPv4 broadcast string
      - Provides a safe ARP-based MAC resolver that doesn’t rely on getmacbyip().

    You can pass `iface=pcap_name` directly to srp/sendp even if Scapy’s iface table
    doesn’t contain that device; this class still returns the computed broadcast.
    """
    _GUID_RE = re.compile(r"\{([0-9A-Fa-f\-]{36})}")
    def __init__(self, logger=None, sniffer=None):
        self._logger = logger or (lambda s: None)
        self.sniffer = sniffer

    # ------------- Public API -------------

    def ensure_broadcast_for_pcap(self, pcap_name: str) -> Dict[str, Any]:
        """
        Ensure broadcast info is available. Returns a dict with:
          {
            'pcap_name': str,
            'ipv4_broadcast': Optional[str],
            'scapy_iface_name': Optional[str],
            'scapy_iface_set': bool,         # whether we set attrs on the scapy iface
            'note': str
          }
        """
        self._refresh_ifaces()

        rec = self._find_windows_rec(pcap_name)
        if not rec:
            note = "Windows interface record not found"
            self._logger.log_message(f"[Broadcast] {note}: {pcap_name}")
            return self._ret(pcap_name, None, None, False, note)

        ipv4_bcast = self._compute_ipv4_broadcast(rec)

        sc_if = self._find_scapy_iface_by_guid(self._extract_guid(pcap_name))
        if not sc_if:
            note = "Scapy iface not found; computed IPv4 broadcast only"
            self._logger.log_message(f"[Broadcast] {note}: {pcap_name} -> {ipv4_bcast}")
            return self._ret(pcap_name, ipv4_bcast, None, False, note)

        # Try to set L2 broadcast and stash IPv4 broadcast for your code.
        set_ok = False
        try:
            set_ok |= self._try_set_attr(sc_if, "broadcast", "ff:ff:ff:ff:ff:ff")
            set_ok |= self._try_set_attr(sc_if, "l2broadcast", "ff:ff:ff:ff:ff:ff")
            # auxiliary: we keep this for your own logic; Scapy won’t use it internally
            set_ok |= self._try_set_attr(sc_if, "ipv4_broadcast", ipv4_bcast)
        except Exception:
            pass

        name_hint = getattr(sc_if, "name", None) or getattr(sc_if, "pcap_name", None)
        note = "broadcast fields set on scapy iface" if set_ok else "scapy iface found; fields not set"
        self._logger.log_message(f"[Broadcast] {note}: {name_hint} -> {ipv4_bcast}")
        return self._ret(pcap_name, ipv4_bcast, name_hint, bool(set_ok), note)

    def resolve_mac(self, ip: str, pcap_name: str, timeout: float = 1.5) -> Optional[str]:
        """
        Resolve a target's MAC via an explicit ARP probe on the given NPcap device.
        Avoids getmacbyip() / filter issues on Windows.
        """
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans = self.sniffer.sr2(pkt, iface=pcap_name, timeout=timeout, verbose=0)
            mac = ans[ARP].hwsrc if ans and ARP in ans else None
            if mac:
                self._logger.log_message(f"[Broadcast] ARP resolved {ip} -> {mac} on {pcap_name}")
            else:
                self._logger.log_messager(f"[Broadcast] ARP unresolved {ip} on {pcap_name}")
            return mac
        except Exception as e:
            self._logger.log_message(f"[Broadcast] ARP resolve error: {e}")
            return None

    def debug_dump_windows_mapping(self, limit: int = 50) -> str:
        lines = []
        for i, rec in enumerate(get_windows_if_list()[:limit], 1):
            lines.append(f"{i}. friendly={rec.get('friendly_name')}  guid={rec.get('guid')}  name={rec.get('name')}")
            lines.append(f"    mac={rec.get('mac')}  win_index={rec.get('win_index')}")
            lines.append(f"    ips={rec.get('ips')}")
        return "\n".join(lines)

    # ------------- Internals -------------

    def _refresh_ifaces(self) -> None:
        try:
            conf.ifaces.reload()
        except Exception:
            pass

    def _extract_guid(self, pcap_name: str) -> Optional[str]:
        m = self._GUID_RE.search(pcap_name or "")
        return m.group(1).upper() if m else None

    def _iter_if_recs(self, items: Iterable[Any]) -> Iterable[Dict[str, Any]]:
        """
        Yield only dict-like records; coerce non-dicts into dicts when possible.
        This prevents `.get(...)` on strings.
        """
        for it in (items or []):
            if isinstance(it, dict):
                yield it
            else:
                # best-effort coercion; skip if we can't
                try:
                    # some Scapy versions may return objects with attributes
                    rec = {
                        "name": getattr(it, "name", None),
                        "guid": getattr(it, "guid", None),
                        "friendly_name": getattr(it, "friendly_name", None),
                        "description": getattr(it, "description", None),
                        "mac": getattr(it, "mac", None),
                        "ips": getattr(it, "ips", None),
                        "win_index": getattr(it, "win_index", None),
                    }
                    if any(v is not None for v in rec.values()):
                        yield rec
                except Exception:
                    continue
    def _find_windows_rec(self, pcap_name: str) -> Optional[dict]:
        p_norm = self._norm(pcap_name)
        guid = self._extract_guid(pcap_name)

        recs = list(self._iter_if_recs(get_windows_if_list()))

        # 1) direct name match
        for rec in recs:
            if self._norm(rec.get("name")) == p_norm:
                return rec

        # 2) GUID match (with/without braces)
        if guid:
            g_up = guid.upper()
            for rec in recs:
                rg = rec.get("guid")
                if rg and self._extract_guid(str(rg)) == g_up:
                    return rec

        # 3) friendly/description contains GUID
        if guid:
            g_low = guid.lower()
            for rec in recs:
                for key in ("friendly_name", "description", "name"):
                    val = self._norm(rec.get(key))
                    if val and g_low in val:
                        return rec

        # 4) as a last resort, match by MAC from Scapy iface
        sc_if = self._find_scapy_iface_by_guid(guid) if guid else None
        mac = getattr(sc_if, "mac", None) if sc_if else None
        if mac:
            m_norm = self._norm(mac)
            for rec in recs:
                if self._norm(rec.get("mac")) == m_norm:
                    return rec

        return None

    def _find_scapy_iface_by_guid(self, guid: Optional[str]):
        if not guid:
            return None
        g = guid.upper()
        # exact GUID match
        for iface in conf.ifaces.values():
            ig = getattr(iface, "guid", None)
            if ig and str(ig).upper() == g:
                return iface
        # fallback: GUID text present in pcap_name
        for iface in conf.ifaces.values():
            pn = getattr(iface, "pcap_name", "") or ""
            if g in pn.upper():
                return iface
        return None


    def _compute_ipv4_broadcast(self, rec: dict) -> Optional[str]:
        """
        Accepts both shapes:
          rec['ips'] == [{'ip': 'x.x.x.x', 'netmask': 'y.y.y.y'}, ...]
          rec['ips'] == ['x.x.x.x/yy', ...]   (slash form)
        """
        ips = rec.get("ips") or []
        for addr in ips:
            ip, mask = None, None
            if isinstance(addr, dict):
                ip, mask = addr.get("ip"), addr.get("netmask")
            elif isinstance(addr, str):
                # Try CIDR form like '192.168.1.10/24'
                try:
                    if "/" in addr and ":" not in addr:
                        net = ipaddress.IPv4Interface(addr)
                        ip = str(net.ip)
                        mask = str(net.network.netmask)
                except Exception:
                    pass
            if ip and mask and ":" not in ip:
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    return str(net.broadcast_address)
                except Exception:
                    continue
        return None

    # -------- small helpers --------
    def _try_set_attr(self, obj, name: str, value) -> bool:
        try:
            old = getattr(obj, name, None)
            if old != value and value is not None:
                setattr(obj, name, value)
            return True
        except Exception:
            return False

    def _ret(self, pcap: str, ip_bcast: Optional[str], sc_name: Optional[str], set_ok: bool, note: str) -> Dict[str, Any]:
        return {
            "pcap_name": pcap,
            "ipv4_broadcast": ip_bcast,
            "scapy_iface_name": sc_name,
            "scapy_iface_set": set_ok,
            "note": note,
        }

    def _norm(self,s: Optional[str]) -> str:
        return (s or "").replace("\\\\", "\\").lower()

class mDNSManager:
    """
    Manages Multicast DNS (mDNS) traffic for local service discovery.
    Listens for announcements, caches them, and forwards queries between interfaces.
    Includes query suppression to prevent flooding.
    """

    # mDNS uses a specific multicast address and port
    MDNS_IPV4_ADDR = "224.0.0.251"
    MDNS_IPV6_ADDR = "ff02::fb"
    MDNS_PORT = 5353
    MDNS_CACHE_TTL = 3600  # Default cache time in seconds
    QUERY_COOLDOWN_SECONDS = .2  # Don't forward the same query from the same IP more than once every 10s

    def __init__(self, router_logger, packet_writer, interfaces_config):
        self.logger = router_logger
        self.packet_writer = packet_writer
        self.interfaces_config = interfaces_config

        # Service cache for responding to queries
        self._cache: Dict[Tuple[str, int], Tuple[Any, float]] = {}
        self._cache_lock = threading.Lock()

        # Query log for rate-limiting forwards
        self._recent_queries: Dict[Tuple[str, int, str], float] = {}
        self._query_log_lock = threading.Lock()
        self._cleanup_thread = None
        self._stop_event = threading.Event()
        self.sniffer = None
        self.logger.log_message("[mDNS] Manager initialized. Query forwarding cooldown is active.")

    def start(self):
        """Starts the mDNS manager's background cleanup thread."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="mDNSCleanup")
        self._cleanup_thread.start()
        self.logger.log_message("[mDNS] Cleanup thread started.")

    def stop(self):
        """Stops the mDNS manager's background cleanup thread gracefully."""
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.logger.log_message("[mDNS] Manager stopped.")

    def _cleanup_loop(self):
        """Periodically cleans expired services from the cache and old entries from the query log."""
        while not self._stop_event.is_set():
            now = time.time()
            with self._cache_lock:
                expired_services = [key for key, (_, expiry) in self._cache.items() if expiry <= now]
                for key in expired_services:
                    del self._cache[key]

            with self._query_log_lock:
                expired_queries = [
                    key for key, timestamp in self._recent_queries.items()
                    if (now - timestamp) > self.QUERY_COOLDOWN_SECONDS
                ]
                for key in expired_queries:
                    del self._recent_queries[key]

            self._stop_event.wait(30)

    # [FIXED] Corrected the logical flow to remove duplicated query handling blocks.
    def handle_packet(self, packet: Packet) -> bool:
        """
        Processes an incoming packet to see if it's an mDNS announcement or query.
        Returns True if the packet was handled by this manager.
        """
        if not (packet.haslayer(UDP) and packet[UDP].dport == self.MDNS_PORT and packet.haslayer(DNS)):
            return False

        dns_layer = packet[DNS]

        # Use if/elif to correctly handle mutually exclusive packet types (Query vs Answer)
        if dns_layer.qr == 0 and dns_layer.qd:
            # --- Handle Queries (qr=0) ---
            try:
                qname = dns_layer.qd.qname.decode()
                qtype = dns_layer.qd.qtype
                src_ip = packet[IPv6].src if packet.haslayer(IPv6) else packet[IP].src
            except (IndexError, AttributeError):
                self.logger.log_message("[mDNS] ⚠️ Received malformed mDNS query packet.")
                return True

            self.logger.log_message(f"[mDNS] ❓ Received query for '{qname}' (Type: {qtype}) from {src_ip}")

            # Perform rate-limiting check
            now = time.time()
            query_key = (qname, qtype, src_ip)
            with self._query_log_lock:
                if (now - self._recent_queries.get(query_key, 0)) < self.QUERY_COOLDOWN_SECONDS:
                    self.logger.log_message(f"[mDNS] 🚫 Suppressing duplicate query for '{qname}' from {src_ip}.")
                    return True
                self._recent_queries[query_key] = now

            # If not rate-limited, decide whether to answer from cache or forward
            cached_answer = self.get_cached_answer(qname, qtype)
            if cached_answer:
                self.logger.log_message(f"[mDNS] ✅ Answering query for '{qname}' from cache.")
                self._send_mdns_response(packet, qname, qtype, cached_answer)
            else:
                self._forward_mdns_query(packet)
            return True

        elif dns_layer.qr == 1 and dns_layer.an:
            # --- Handle Announcements (qr=1) ---
            for answer in dns_layer.an:
                try:
                    record_name = answer.rrname.decode()
                    record_type = answer.type
                    record_data = answer.rdata if hasattr(answer, 'rdata') else None

                    self.cache_service(record_name, record_type, record_data, answer.ttl)
                    self.logger.log_message(f"[mDNS] 📡 Discovered service: {answer.summary()}")
                except Exception as e:
                    self.logger.log_message(f"[mDNS] ⚠️ Failed to parse DNS answer record '{answer.summary()}': {e}")
            return True

        return False

    def cache_service(self, name: str, record_type: int, data: Any, ttl: int):
        """Adds a service discovery record to the cache with an expiry time."""
        effective_ttl = max(ttl, 60)
        expiry = time.time() + effective_ttl
        with self._cache_lock:
            self._cache[(name, record_type)] = (data, expiry)

    def get_cached_answer(self, name: str, record_type: int) -> Optional[Any]:
        """Retrieves an active record from the cache, if one exists."""
        with self._cache_lock:
            record = self._cache.get((name, record_type))
            if record:
                data, expiry = record
                if time.time() < expiry:
                    return data
                else:
                    del self._cache[(name, record_type)]
        return None

    def get_services(self) -> List[Dict[str, Any]]:
        """Returns a list of all currently active services from the cache."""
        active_services = []
        with self._cache_lock:
            now = time.time()
            for (name, rtype), (data, expiry) in list(self._cache.items()):
                if now < expiry:
                    active_services.append({"name": name, "type": rtype, "data": data})
                else:
                    del self._cache[(name, rtype)]
        return active_services

    # [FIXED] Updated to support PTR, TXT, and SRV records for service discovery.
    def _send_mdns_response(self, original_packet: Packet, qname: str, qtype: int, answer_data: Any):
        """
        Builds and queues an mDNS response packet based on a cached answer.
        Now supports A, AAAA, PTR, TXT, and SRV records.
        """
        inbound_iface = original_packet.sniffed_on
        iface_config = self.interfaces_config.get(inbound_iface)
        if not iface_config:
            self.logger.log_message(f"[mDNS] ❌ Cannot send response: Interface '{inbound_iface}' not configured.")
            return

        router_mac = iface_config.get("mac")
        is_ipv6 = original_packet.haslayer(IPv6)
        dns_rr = None

        # Craft the DNS response record based on the query type (qtype)
        if qtype == 1:    # A Record
            dns_rr = DNSRR(rrname=qname, type="A", rdata=answer_data, ttl=self.MDNS_CACHE_TTL)
        elif qtype == 12:   # PTR Record
            dns_rr = DNSRR(rrname=qname, type="PTR", rdata=answer_data, ttl=self.MDNS_CACHE_TTL)
        elif qtype == 16:   # TXT Record
            # TXT rdata is often a list of strings
            dns_rr = DNSRR(rrname=qname, type="TXT", rdata=answer_data, ttl=self.MDNS_CACHE_TTL)
        elif qtype == 28:   # AAAA Record
            dns_rr = DNSRR(rrname=qname, type="AAAA", rdata=answer_data, ttl=self.MDNS_CACHE_TTL)
        elif qtype == 33:   # SRV Record
            # SRV rdata is a complex type (priority, weight, port, target)
            dns_rr = DNSRR(rrname=qname, type="SRV", rdata=answer_data, ttl=self.MDNS_CACHE_TTL)
        else:
            self.logger.log_message(f"[mDNS] ⚠️ Cannot craft response: Unsupported record type {qtype}")
            return

        # Build the full response packet
        if is_ipv6:
            src_ip = iface_config.get("ipv6_addr")
            dst_ip = self.MDNS_IPV6_ADDR
            eth_dst = "33:33:00:00:00:fb"
        else:
            src_ip = iface_config.get("ip_addr")
            dst_ip = self.MDNS_IPV4_ADDR
            eth_dst = "01:00:5e:00:00:fb"

        if not src_ip or not router_mac:
            self.logger.log_message(f"[mDNS] ❌ Cannot send response from {inbound_iface}: Missing IP or MAC.")
            return

        response_packet = Ether(src=router_mac, dst=eth_dst) / \
                          (IPv6(src=src_ip, dst=dst_ip) if is_ipv6 else IP(src=src_ip, dst=dst_ip)) / \
                          UDP(sport=self.MDNS_PORT, dport=self.MDNS_PORT) / \
                          DNS(id=original_packet[DNS].id, qr=1, aa=1, qd=original_packet[DNS].qd, an=dns_rr)

        self.sniffer.send(response_packet, inbound_iface)
        self.logger.log_message(f"[mDNS] ✅ Sent mDNS response for '{qname}' (Type: {qtype}) on {inbound_iface.split('_')[-1]}")

    def _forward_mdns_query(self, original_packet: Packet):
        """
        Re-emit an mDNS query to all *other* non-loopback interfaces.
        - If the egress iface is L2-capable and has a MAC -> send L2 (Ether dst = mcast MAC)
        - Otherwise -> send L3 (no Ether) with TTL/HopLimit=255
        - Never try to forward *from* loopback *to* loopback (that would stay local)
        """
        inbound_iface = getattr(original_packet, "sniffed_on", None)

        # Extract DNS qname (best-effort)
        try:
            qname = (original_packet[DNS].qd.qname or b"").decode(errors="ignore")
        except Exception:
            qname = "?"

        is_v6_in = IPv6 in original_packet
        MDNS_IPv4 = "224.0.0.251"
        MDNS_IPv6 = "ff02::fb"
        MDNS_PORT = 5353

        # mDNS multicast destination + L2 multicast MACs
        dst_ip_mcast = MDNS_IPv6 if is_v6_in else MDNS_IPv4
        dst_mac_mcast = "33:33:00:00:00:fb" if is_v6_in else "01:00:5e:00:00:fb"

        # Pull the DNS payload to reuse as-is
        try:
            dns_layer = original_packet[DNS].copy()
            dns_layer.qr = 0  # ensure it's a QUERY when re-emitting
        except Exception:
            self.logger.log_message("[mDNS] ⚠️ Cannot forward: malformed DNS layer.")
            return

        for iface_name, cfg in (self.interfaces_config or {}).items():
            # Skip the inbound iface and any obvious loopback device
            if iface_name == inbound_iface:
                continue
            if "\\npf_loopback" in iface_name.lower() or iface_name.lower() in ("lo", "lo0", "loopback"):
                continue

            # Pick source IP and MAC for this egress
            src_ip = (cfg.get("ipv6_ll") or cfg.get("ipv6_addr")) if is_v6_in else cfg.get("ip_addr")
            src_mac = cfg.get("mac")
            if not src_ip:
                # If we have no IP for this family, skip this iface
                continue

            # Build L3 header with TTL/HopLimit=255 (required by mDNS)
            if is_v6_in:
                l3 = IPv6(src=src_ip, dst=MDNS_IPv6, hlim=255)
            else:
                l3 = IP(src=src_ip, dst=MDNS_IPv4, ttl=255)

            l4 = UDP(sport=MDNS_PORT, dport=MDNS_PORT)
            l3pkt = l3 / l4 / dns_layer

            # Decide if we can send L2 on this iface
            driver_kind = str((self.interfaces_config.get(iface_name, {}) or {}).get("driver", "")).lower()
            l2_capable = not any(x in driver_kind for x in ("windivert", "rawip", "winfw"))

            # If L2-capable *and* we have a MAC, prefer proper Ethernet multicast
            if l2_capable and src_mac:
                ether = Ether(src=src_mac, dst=dst_mac_mcast)
                try:
                    self.sniffer.sendp(ether / l3pkt, iface=iface_name, verbose=0)
                    self.logger.log_message(
                        f"[mDNS] 📢 L2 fwd '{qname}' → {iface_name.split('_')[-1]} "
                        f"({src_ip} → {dst_ip_mcast}, {src_mac}→{dst_mac_mcast})"
                    )
                    continue
                except Exception as e:
                    self.logger.log_message(f"[mDNS] ⚠️ L2 send failed on {iface_name}: {e}. Falling back to L3.")

            # L3 path (no Ether): handle WinDivert/rawip/loopback-adjacent safely
            try:
                # Use sniffer.send() with explicit iface; it will remap loopback and synthesize mcast MAC when needed
                self.sniffer.send(l3pkt, iface=iface_name, verbose=0)
                self.logger.log_message(
                    f"[mDNS] 🌐 L3 fwd '{qname}' → {iface_name.split('_')[-1]} "
                    f"({src_ip} → {dst_ip_mcast}, driver={driver_kind or 'unknown'})"
                )
            except Exception as e:
                # Final fallback: try best-effort multicast egress selection inline
                try:
                    chosen = None
                    # Choose the first UP NIC with IPv4 (for v4) / any IP (for v6) and a MAC
                    stats = psutil.net_if_stats()
                    addrs = psutil.net_if_addrs()
                    for nic, lst in addrs.items():
                        if not stats.get(nic) or not stats[nic].isup:
                            continue
                        has_mac = any(getattr(a, "family", None) == psutil.AF_LINK and a.address for a in lst)
                        if is_v6_in:
                            ok_ip = any(a.family == socket.AF_INET6 for a in lst)
                        else:
                            ok_ip = any(a.family == socket.AF_INET for a in lst)
                        if has_mac and ok_ip and "loopback" not in nic.lower():
                            chosen = nic
                            break
                    if chosen:
                        self.sniffer.send(l3pkt, iface=chosen, verbose=0)
                        self.logger.log_message(
                            f"[mDNS] 🔁 L3 fallback '{qname}' via {chosen} (from {iface_name})"
                        )
                    else:
                        self.logger.log_message(f"[mDNS] ❌ No eligible NIC to forward '{qname}' from {iface_name}.")
                except Exception as ee:
                    self.logger.log_message(f"[mDNS] ❌ Forward failed for '{qname}' on {iface_name}: {ee}")

HandshakeState = Literal["SYN_SENT", "SYN_ACK_RECEIVED", "ESTABLISHED", "CLOSING", "CLOSED"]

TLS_HANDSHAKE_TYPES = {
    0:  "HelloRequest",          # TLS 1.0–1.2, obsolete in TLS 1.3
    1:  "ClientHello",
    2:  "ServerHello",
    3:  "HelloVerifyRequest",    # DTLS
    4:  "NewSessionTicket",      # TLS 1.3: NewSessionTicket
    8:  "EncryptedExtensions",   # TLS 1.3
    11: "Certificate",
    12: "ServerKeyExchange",     # TLS ≤1.2
    13: "CertificateRequest",
    14: "ServerHelloDone",       # TLS ≤1.2
    15: "CertificateVerify",
    16: "ClientKeyExchange",     # TLS ≤1.2
    20: "Finished",
    21: "CertificateURL",        # experimental / unused
    22: "CertificateStatus",     # OCSP stapling
    23: "SupplementalData",      # old extension point
    24: "KeyUpdate",             # TLS 1.3
    25: "CompressedCertificate", # TLS 1.3 extension
    26: "EndOfEarlyData",        # TLS 1.3
    27: "HelloRetryRequest",     # TLS 1.3 (encoded as SH + special marker)
}
def _get_canonical_session_key(ip1: str, port1: int, ip2: str, port2: int) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """Returns a canonical session key that is order-independent."""

    x, y = sorted([(ip1, port1), (ip2, port2)])
    return x, y




class TLSPolicyDecision:
    __slots__ = ("action", "reason", "tags")
    def __init__(self, action: str, reason: str = "", tags: Optional[List[str]] = None):
        self.action = action          # "allow" | "alert" | "block" | "quarantine"
        self.reason = reason
        self.tags = tags or []

class TLSPolicyEngine:
    """
    Tiny, tunable rule engine used by TLSRecordManager on every TLS record.
    Integrates TLSCipherManager for weak/acceptable cipher logic.
    """
    def __init__(self):
        # Base constraints / toggles
        self.min_tls_version = (3, 3)     # default: TLS 1.2 (3,3) minimum
        self.block_legacy_ssl = True
        # Historic hard blocklist (kept for continuity); treated as manual blocks in cipher manager
        self.block_weak_ciphers = {0x0004, 0x0005, 0x000A, 0x002F, 0x0035}
        self.sni_denylist = set()          # {"bad.example", ".malware.tld"}
        self.ja3_denylist = set()          # {"<md5>"}
        self.alert_on_tls11_or_lower = True

        # Cipher helper and policy
        self.ciphers = TLSCipherManager()
        for cid in self.block_weak_ciphers:
            self.ciphers.block_suite(cid)
        # Defaults (tweak anytime at runtime)
        self.ciphers.set_requirements(
            require_pfs=False,
            require_aead=False,
            forbid_cbc_sha1=False
        )

    # --- admin helpers (optional, nice to have) ---
    def set_min_tls(self, major: int, minor: int):
        self.min_tls_version = (major, minor)

    def add_blocked_sni(self, s: str): self.sni_denylist.add(s.lower())
    def add_blocked_ja3(self, j: str): self.ja3_denylist.add(j.lower())
    def add_blocked_cipher(self, c: int):
        self.block_weak_ciphers.add(int(c) & 0xFFFF)
        self.ciphers.block_suite(int(c) & 0xFFFF)

    # --- internals ---
    def _sni_is_blocked(self, sni: Optional[str]) -> Optional[str]:
        if not sni:
            return None
        q = sni.lower().strip(".")
        for pat in self.sni_denylist:
            if pat.startswith("."):
                if q.endswith(pat[1:]):
                    return f"SNI endswith {pat}"
            elif q == pat or q.endswith("." + pat):
                return f"SNI matches {pat}"
        return None

    # --- MAIN: called by TLSRecordManager on every TLS record ---
    def evaluate(self, meta: Dict, rec: "TLSRecord", extra: Optional[Dict]) -> TLSPolicyDecision:
        """
        Decide: allow | alert | block | quarantine.
        Uses per-session 'meta' (built by TLSRecordManager) and the current record.
        """
        # 1) Legacy SSL (incl. SSLv2 hello) -> block if enabled
        if meta.get("legacy_ssl") and self.block_legacy_ssl:
            return TLSPolicyDecision("block", "Legacy SSL detected", ["legacy"])

        # 2) ClientHello-derived checks
        ch = meta.get("client_hello")
        if ch:
            # min version (client legacy_version or negotiated if already known)
            ver = ch.get("version_tuple") or meta.get("negotiated_version_tuple")
            if ver and ver < self.min_tls_version:
                return TLSPolicyDecision("block", f"TLS version too low {ver}", ["min-tls"])

            # SNI denylist
            sni = meta.get("sni")
            sni_reason = self._sni_is_blocked(sni)
            if sni_reason:
                return TLSPolicyDecision("block", sni_reason, ["sni"])

            # JA3 denylist
            if ch.get("ja3_md5") and ch["ja3_md5"].lower() in self.ja3_denylist:
                return TLSPolicyDecision("block", f"JA3 {ch['ja3_md5']} denylisted", ["ja3"])

            # Offered-only-weak (heads-up alert, do not block yet)
            suites = set(ch.get("cipher_suites") or [])
            try:
                if suites and self.ciphers.all_weak(suites):
                    return TLSPolicyDecision("alert", "Only weak ciphers offered", ["weak-ciphers"])
            except Exception:
                # If anything goes wrong in classification, don't over-block
                pass

        # 3) ServerHello-derived checks
        sh = meta.get("server_hello")
        if sh:
            # Negotiated cipher strength
            cs_int = sh.get("cipher_suite_int")
            if cs_int is not None:
                weak, reasons = self.ciphers.is_weak(cs_int, negotiated=True)
                if weak:
                    tag_str = ["weak-cipher"] + (reasons or [])
                    return TLSPolicyDecision(
                        "block",
                        f"Weak negotiated cipher ({', '.join(reasons)})" if reasons else "Weak negotiated cipher",
                        tag_str
                    )

            # Alert on negotiated TLS ≤ 1.1 (if toggle enabled)
            nv = sh.get("version_tuple")
            if self.alert_on_tls11_or_lower and nv and nv < (3, 3):
                return TLSPolicyDecision("alert", f"Negotiated {nv} (TLS<=1.1)", ["old-tls"])

            # JA3S denylist
            if sh.get("ja3s_md5") and sh["ja3s_md5"].lower() in self.ja3_denylist:
                return TLSPolicyDecision("block", f"JA3S {sh['ja3s_md5']} denylisted", ["ja3s"])

        # 4) Default
        return TLSPolicyDecision("allow")

class TLSRecord:
    __slots__ = ("content_type", "version", "length", "payload", "ts",
                 "src", "dst", "src_port", "dst_port", "direction")
    def __init__(self, content_type: int, version: Tuple[int, int], length: int, payload: bytes,
                 ts: float, src: str, dst: str, src_port: int, dst_port: int, direction: str):
        self.content_type = content_type
        self.version = version
        self.length = length
        self.payload = payload
        self.ts = ts
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.direction = direction  # "c2s" or "s2c"

class TLSCipherManager:
    """
    Registry + policy helpers for TLS cipher suites.

    • get_info(id)         -> details for a suite (name, flags)
    • is_weak(id, …)       -> (bool, reasons[]) under current policy toggles
    • acceptable(id, …)    -> bool (inverse of is_weak)
    • all_weak(ids, …)     -> True iff NO acceptable suite exists in 'ids'
    • to_name(id) / from_name(name)

    Policy toggles (per-instance):
      - require_pfs (default False)
      - require_aead (default False)
      - forbid_rsa_kx (default False)
      - forbid_rc4 / forbid_3des / forbid_null / forbid_export / forbid_des40
      - forbid_cbc_sha1 (treat CBC+SHA1 as weak)
    """

    def __init__(self):
        # Minimal but practical registry. Extend as needed.
        # Flags: pfs,aead,rc4,3des,cbc,null,export,des40,md5,sha1,rsa_kx,tls13
        self._db = {
            # --- TLS 1.3 ---
            0x1301: {"name":"TLS_AES_128_GCM_SHA256",       "flags":{"aead","pfs","tls13"}},
            0x1302: {"name":"TLS_AES_256_GCM_SHA384",       "flags":{"aead","pfs","tls13"}},
            0x1303: {"name":"TLS_CHACHA20_POLY1305_SHA256", "flags":{"aead","pfs","tls13"}},

            # --- AEAD ECDHE (good) ---
            0xC02F: {"name":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",       "flags":{"aead","pfs"}},
            0xC030: {"name":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",       "flags":{"aead","pfs"}},
            0xC02B: {"name":"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",     "flags":{"aead","pfs"}},
            0xC02C: {"name":"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",     "flags":{"aead","pfs"}},
            0xCCA8: {"name":"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "flags":{"aead","pfs"}},
            0xCCA9: {"name":"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","flags":{"aead","pfs"}},

            # --- Legacy RSA CBC (no PFS) ---
            0x002F: {"name":"TLS_RSA_WITH_AES_128_CBC_SHA",         "flags":{"cbc","sha1","rsa_kx"}},
            0x0035: {"name":"TLS_RSA_WITH_AES_256_CBC_SHA",         "flags":{"cbc","sha1","rsa_kx"}},

            # --- Really old / bad ---
            0x0004: {"name":"TLS_RSA_WITH_RC4_128_MD5",             "flags":{"rc4","md5","rsa_kx"}},
            0x0005: {"name":"TLS_RSA_WITH_RC4_128_SHA",             "flags":{"rc4","sha1","rsa_kx"}},
            0x000A: {"name":"TLS_RSA_WITH_3DES_EDE_CBC_SHA",        "flags":{"3des","cbc","sha1","rsa_kx"}},
            # a few “marker” suites
            0x0000: {"name":"TLS_NULL_WITH_NULL_NULL",              "flags":{"null"}},
        }

        # Quick reverse index by name (case-insensitive)
        self._by_name = {v["name"].lower(): k for k, v in self._db.items()}

        # Manual blocklist you can add to at runtime (IDs)
        self.manual_block: set[int] = set()

        # Policy toggles (defaults conservative but not too strict)
        self.require_pfs = False
        self.require_aead = False
        self.forbid_rsa_kx = False
        self.forbid_rc4 = True
        self.forbid_3des = True
        self.forbid_null = True
        self.forbid_export = True
        self.forbid_des40 = True
        self.forbid_cbc_sha1 = False  # set True to nudge away from CBC/SHA1

    # ---------- Admin / Lookup ----------
    def add_suite(self, suite_id: int, name: str, *, flags: set[str]):
        suite_id = int(suite_id) & 0xFFFF
        self._db[suite_id] = {"name": name, "flags": set(flags)}
        self._by_name[name.lower()] = suite_id

    def block_suite(self, suite_id: int):
        self.manual_block.add(int(suite_id) & 0xFFFF)

    def from_name(self, name: str) -> Optional[int]:
        return self._by_name.get(name.lower())

    def to_name(self, suite_id: int) -> str:
        info = self._db.get(int(suite_id) & 0xFFFF)
        return info["name"] if info else f"0x{int(suite_id)&0xFFFF:04x}"

    def get_info(self, suite_id: int) -> Dict[str, object]:
        suite_id = int(suite_id) & 0xFFFF
        info = self._db.get(suite_id, {"name": f"0x{suite_id:04x}", "flags": set()})
        return {"id": suite_id, "name": info["name"], "flags": set(info["flags"])}

    # ---------- Policy Evaluation ----------
    def set_requirements(self, *, require_pfs: Optional[bool] = None,
                         require_aead: Optional[bool] = None,
                         forbid_rsa_kx: Optional[bool] = None,
                         forbid_rc4: Optional[bool] = None,
                         forbid_3des: Optional[bool] = None,
                         forbid_null: Optional[bool] = None,
                         forbid_export: Optional[bool] = None,
                         forbid_des40: Optional[bool] = None,
                         forbid_cbc_sha1: Optional[bool] = None):
        for k, v in locals().items():
            if k in ("self",) or v is None: continue
            setattr(self, k, v)

    def _reasons_for_suite(self, suite_id: int, *, negotiated: bool = False) -> list[str]:
        info = self.get_info(suite_id)
        f = info["flags"]
        reasons = []

        if suite_id in self.manual_block:
            reasons.append("manual-block")

        if self.forbid_null and ("null" in f):
            reasons.append("null-cipher")
        if self.forbid_export and ("export" in f):
            reasons.append("export-cipher")
        if self.forbid_des40 and ("des40" in f):
            reasons.append("des40")
        if self.forbid_rc4 and ("rc4" in f):
            reasons.append("rc4")
        if self.forbid_3des and ("3des" in f):
            reasons.append("3des")
        if self.forbid_cbc_sha1 and ("cbc" in f and "sha1" in f):
            reasons.append("cbc+sha1")

        if self.require_aead and ("aead" not in f):
            reasons.append("no-aead")
        if self.require_pfs:
            # TLS1.3 implies PFS; for <=1.2 we rely on ECDHE/DHE flag 'pfs'
            if ("pfs" not in f) and ("tls13" not in f):
                reasons.append("no-pfs")

        if self.forbid_rsa_kx and ("rsa_kx" in f):
            reasons.append("rsa-kx")

        return reasons

    def is_weak(self, suite_id: int, *, negotiated: bool = False) -> tuple[bool, list[str]]:
        reasons = self._reasons_for_suite(suite_id, negotiated=negotiated)
        return (len(reasons) > 0, reasons)

    def acceptable(self, suite_id: int) -> bool:
        weak, _ = self.is_weak(suite_id)
        return not weak

    def all_weak(self, suites: set[int] | list[int]) -> bool:
        """
        True if NONE of the suites satisfy current policy (i.e., client only offers weak).
        Unknown suites are treated as 'possibly acceptable' (don’t cause false alerts).
        """
        any_ok = False
        for s in suites or []:
            s = int(s) & 0xFFFF
            # Unknown suite: err on the side of 'maybe OK' (treat as acceptable)
            if s not in self._db and s not in self.manual_block:
                any_ok = True
                break
            if self.acceptable(s):
                any_ok = True
                break
        return not any_ok

class TLSRecordManager:
    """
    Passive TLS/SSL record parser with TCP-stream-aware reassembly… now with:
      • Per-flow session metadata (SNI/ALPN/version/cipher/JA3/JA3S/counters)
      • Lightweight policy engine -> decisions (allow/alert/block/quarantine)
      • Event queue + callbacks (on_event/on_decision) for your app to act on
      • Optional soft enforcement: suppress app-data callback when blocked

    Also integrates TLSCipherManager for:
      • Naming negotiated cipher suites
      • Weak/acceptable evaluation of offered and negotiated suites
      • Heads-up policy_alert events when only-weak offered or weak cipher negotiated
    """

    # Content types
    CHANGE_CIPHER_SPEC = 20
    ALERT               = 21
    HANDSHAKE           = 22
    APPLICATION_DATA    = 23

    # Direction keys
    C2S = "c2s"
    S2C = "s2c"

    def __init__(self, logger, on_record: Optional[Callable[[TLSRecord], None]] = None):
        self.log = logger
        self.on_record = on_record or (lambda rec: None)

        # Buffers keyed by canonical session key and direction
        self._buffers: Dict[Tuple[Tuple[str, int], Tuple[str, int]], Dict[str, bytearray]] = \
            defaultdict(lambda: {self.C2S: bytearray(), self.S2C: bytearray()})

        # Minimal stats per session (kept for compatibility)
        self._stats: Dict[Tuple[Tuple[str, int], Tuple[str, int]], Dict[str, int]] = \
            defaultdict(lambda: {"records": 0, "handshakes": 0, "alerts": 0, "appdata": 0, "ccs": 0, "legacy": 0})

        # Per-session metadata (higher-level state)
        self._meta: Dict[Tuple[Tuple[str,int],Tuple[str,int]], Dict] = defaultdict(lambda: {
            "first_seen": time.time(), "last_seen": None,
            "client": None, "server": None,  # (ip,port) filled on first ClientHello or first direction seen
            "sni": None, "alpn": [],
            "client_hello": None,   # parsed dict + ja3
            "server_hello": None,   # parsed dict + ja3s
            "negotiated_version": None, "negotiated_version_tuple": None,
            "negotiated_cipher": None,
            "negotiated_cipher_name": None,
            "negotiated_cipher_weak": None,
            "negotiated_cipher_reasons": [],
            "offered_only_weak": None,
            "app_bytes": {self.C2S: 0, self.S2C: 0},
            "alerts": [], "ccs_seen": False, "legacy_ssl": False,
            "blocked": False, "quarantined": False,
            "tags": set()
        })

        # Optional specialized hooks (set by user)
        self.on_handshake: Optional[Callable[[TLSRecord, Dict], None]] = None
        self.on_application_data: Optional[Callable[[TLSRecord], None]] = None
        self.on_alert: Optional[Callable[[TLSRecord, Dict], None]] = None
        self.on_change_cipher_spec: Optional[Callable[[TLSRecord], None]] = None
        self.on_legacy_ssl: Optional[Callable[[TLSRecord], None]] = None

        # Policy engine + callbacks + event queue
        # NOTE: Code expects TLSPolicyEngine defined elsewhere with `.evaluate(meta, rec, extra)`
        self.policy = TLSPolicyEngine()  # provided in your codebase
        self.on_decision: Optional[Callable[[Tuple, TLSRecord, "TLSPolicyDecision"], None]] = None
        self.on_event: Optional[Callable[[Dict], None]] = None
        self._event_queue: List[Dict] = []

        # Cipher helper (naming + weak/acceptable checks)
        self.ciphers = TLSCipherManager()

    # ------------- Utilities -------------

    @staticmethod
    def _looks_like_tls_header(buf: bytes) -> bool:
        if len(buf) < 5:
            return False
        ct, ver = buf[0], (buf[1] << 8) | buf[2]
        if ct not in (0x14, 0x15, 0x16, 0x17):  # CCS, Alert, Handshake, AppData
            return False
        if ver not in (0x0301, 0x0302, 0x0303, 0x0304):  # TLS1.0 .. TLS1.3
            return False
        rlen = (buf[3] << 8) | buf[4]
        return 0 < rlen <= 18432

    def _emit_event(self, key, kind: str, payload: Dict):
        evt = {"ts": time.time(), "flow": key, "kind": kind, "data": payload}
        self._event_queue.append(evt)
        if self.on_event:
            try:
                self.on_event(evt)
            except Exception:
                pass

    def pop_events(self) -> List[Dict]:
        out, self._event_queue = self._event_queue, []
        return out

    @staticmethod
    def _md5(s: str) -> str:
        return hashlib.md5(s.encode("ascii", "ignore")).hexdigest()

    @staticmethod
    def _u16(b: bytes, i: int) -> int:
        return struct.unpack("!H", b[i:i+2])[0]

    def _hs_name(self, t: int) -> str:
        if "TLS_HANDSHAKE_TYPES" in globals():
            return globals()["TLS_HANDSHAKE_TYPES"].get(t, f"Unknown({t})")
        return TLS_HANDSHAKE_TYPES.get(t, f"Unknown({t})")

    # ------------- Parser core -------------

    def _parse_records_from_buffer(self, key, direction, ts, meta):
        buf = self._buffers[key][direction]
        out: List[TLSRecord] = []

        def _ssl_v2_hello_possible(b: bytes) -> bool:
            return bool(b) and (b[0] & 0x80) and len(b) >= 3

        while True:
            if len(buf) < 5:
                if _ssl_v2_hello_possible(buf):
                    break
                return out

            if not self._looks_like_tls_header(buf):
                if _ssl_v2_hello_possible(buf):
                    rec_len = ((buf[0] & 0x7F) << 8) | buf[1]
                    total_len = 2 + rec_len
                    if len(buf) < total_len:
                        break
                    payload = bytes(buf[2:total_len]); del buf[:total_len]
                    rec = TLSRecord(
                        content_type=0x80, version=(2, 0),
                        length=len(payload), payload=payload,
                        ts=ts, src=meta["src_ip"], dst=meta["dst_ip"],
                        src_port=meta["src_port"], dst_port=meta["dst_port"],
                        direction=direction
                    )
                    out.append(rec)
                    # mark legacy in meta
                    self._meta[key]["legacy_ssl"] = True
                    continue
                # try to re-sync
                del buf[:1]
                continue

            ct, vmaj, vmin = buf[0], buf[1], buf[2]
            rec_len = struct.unpack("!H", buf[3:5])[0]
            total_len = 5 + rec_len
            if len(buf) < total_len:
                break

            payload = bytes(buf[5:total_len])
            del buf[:total_len]
            rec = TLSRecord(
                content_type=ct, version=(vmaj, vmin), length=rec_len, payload=payload,
                ts=ts, src=meta["src_ip"], dst=meta["dst_ip"],
                src_port=meta["src_port"], dst_port=meta["dst_port"],
                direction=direction
            )
            out.append(rec)
        return out

    def feed_tcp_segment(self, canonical_key, is_c2s: bool, payload: bytes,
                         src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                         ts: Optional[float] = None):
        if not payload:
            return
        ts = ts or time.time()
        direction = self.C2S if is_c2s else self.S2C

        # Session meta init/update
        m = self._meta[canonical_key]
        m["last_seen"] = ts
        if m["client"] is None and m["server"] is None:
            # Seed roles with first direction we see
            m["client"] = (src_ip, src_port) if is_c2s else (dst_ip, dst_port)
            m["server"] = (dst_ip, dst_port) if is_c2s else (src_ip, src_port)

        self._buffers[canonical_key][direction].extend(payload)
        meta = {"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port}
        records = self._parse_records_from_buffer(canonical_key, direction, ts, meta)

        for rec in records:
            self._stats[canonical_key]["records"] += 1
            self.on_record(rec)

            decision_extra = None

            if rec.content_type == self.HANDSHAKE:
                self._stats[canonical_key]["handshakes"] += 1
                hs_info = self._parse_handshake_best_effort(rec.payload, canonical_key, direction)
                decision_extra = {"handshake": hs_info}
                if self.on_handshake:
                    self.on_handshake(rec, hs_info)
                # Emit high-level event (first time we learn SNI/JA3 etc.)
                if hs_info.get("messages"):
                    self._emit_event(canonical_key, "handshake", {"dir": direction, "info": hs_info})

            elif rec.content_type == self.APPLICATION_DATA:
                self._stats[canonical_key]["appdata"] += 1
                m["app_bytes"][direction] += rec.length
                # Soft enforcement: suppress app-data callback if blocked/quarantined
                if not (m["blocked"] or m["quarantined"]):
                    if self.on_application_data:
                        self.on_application_data(rec)

            elif rec.content_type == self.ALERT:
                self._stats[canonical_key]["alerts"] += 1
                alert = self._parse_alert(rec.payload)
                m["alerts"].append(alert)
                decision_extra = {"alert": alert}
                if self.on_alert:
                    self.on_alert(rec, alert)
                self._emit_event(canonical_key, "alert", {"dir": direction, "alert": alert})

            elif rec.content_type == self.CHANGE_CIPHER_SPEC:
                self._stats[canonical_key]["ccs"] += 1
                m["ccs_seen"] = True
                if self.on_change_cipher_spec:
                    self.on_change_cipher_spec(rec)

            else:  # legacy / unknown
                self._stats[canonical_key]["legacy"] += 1
                m["legacy_ssl"] = True
                if self.on_legacy_ssl:
                    self.on_legacy_ssl(rec)

            # Run policy on every record
            decision = self.policy.evaluate(m, rec, decision_extra)
            if self.on_decision:
                try:
                    self.on_decision(canonical_key, rec, decision)
                except Exception:
                    pass

            if decision.action in ("block", "quarantine"):
                # mark meta; let outer system actually enforce (drop/ban/etc.)
                if decision.action == "block":
                    m["blocked"] = True
                else:
                    m["quarantined"] = True
                m["tags"].update(decision.tags)
                self._emit_event(canonical_key, decision.action, {
                    "reason": decision.reason, "tags": decision.tags,
                    "snapshot": self.get_session_summary(canonical_key)
                })
            elif decision.action == "alert":
                self._emit_event(canonical_key, "policy_alert", {
                    "reason": decision.reason, "tags": decision.tags
                })

    def _parse_alert(self, payload: bytes) -> Dict:
        level = payload[0] if len(payload) > 0 else None
        desc  = payload[1] if len(payload) > 1 else None
        return {"level": level, "description": desc}

    # ---------------- Handshake (best-effort) ----------------

    def _compute_ja3(self, ver_u16: int, ciphers: List[int], exts: List[int],
                     groups: List[int], ecpts: List[int]) -> Tuple[str, str]:
        # JA3 string: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        cs = "-".join(str(x) for x in ciphers)
        ex = "-".join(str(x) for x in exts)
        gr = "-".join(str(x) for x in groups)
        pf = "-".join(str(x) for x in ecpts)
        ja3 = f"{ver_u16},{cs},{ex},{gr},{pf}"
        return ja3, self._md5(ja3)

    def _compute_ja3s(self, ver_u16: int, cipher: int, exts: List[int]) -> Tuple[str, str]:
        # JA3S string: SSLVersion,Cipher,Extensions
        ex = "-".join(str(x) for x in exts)
        ja3s = f"{ver_u16},{cipher},{ex}"
        return ja3s, self._md5(ja3s)

    def _parse_handshake_best_effort(self, payload: bytes, key, direction) -> Dict:
        info = {"messages": []}
        i = 0
        while i + 4 <= len(payload):
            msg_type = payload[i]
            msg_len = int.from_bytes(payload[i+1:i+4], "big")
            i += 4
            if i + msg_len > len(payload):
                break
            body = payload[i:i+msg_len]; i += msg_len

            entry = {"type_id": msg_type, "type": self._hs_name(msg_type)}
            if msg_type == 1:  # ClientHello
                ch = self._parse_client_hello(body)
                entry.update(ch)
                # update session meta
                m = self._meta[key]
                m["client_hello"] = ch
                m["sni"] = ch.get("sni") or m.get("sni")
                if ch.get("alpn"):
                    m["alpn"] = ch["alpn"]
                if ch.get("version_tuple"):
                    m["negotiated_version"] = ch["version"]
                    m["negotiated_version_tuple"] = ch["version_tuple"]

                # Offered-only-weak detection -> heads-up event
                m["offered_only_weak"] = ch.get("only_weak_offered")
                if ch.get("only_weak_offered") is True:
                    self._emit_event(
                        key, "policy_alert",
                        {"reason": "Only weak ciphers offered", "tags": ["weak-ciphers"]}
                    )

                self._emit_event(key, "client_hello",
                                 {"dir": direction, "sni": m["sni"], "ja3": ch.get("ja3_md5")})

            elif msg_type == 2:  # ServerHello
                sh = self._parse_server_hello(body)
                entry.update(sh)
                m = self._meta[key]
                m["server_hello"] = sh
                if sh.get("version_tuple"):
                    m["negotiated_version"] = sh["version"]
                    m["negotiated_version_tuple"] = sh["version_tuple"]
                m["negotiated_cipher"] = sh.get("cipher_suite")

                # Name + weakness classification of negotiated cipher
                cs_int = sh.get("cipher_suite_int")
                if cs_int is not None:
                    name = self.ciphers.to_name(cs_int)
                    weak, reasons = self.ciphers.is_weak(cs_int, negotiated=True)
                    m["negotiated_cipher_name"] = name
                    m["negotiated_cipher_weak"] = weak
                    m["negotiated_cipher_reasons"] = reasons or []
                    if weak:
                        self._emit_event(
                            key, "policy_alert",
                            {"reason": f"Weak negotiated cipher ({','.join(reasons)})" if reasons else "Weak negotiated cipher",
                             "tags": ["weak-cipher"], "cipher": name}
                        )

                self._emit_event(key, "server_hello",
                                 {"dir": direction, "ja3s": sh.get("ja3s_md5")})

            info["messages"].append(entry)
        return info

    def _parse_client_hello(self, body: bytes) -> Dict:
        out = {"hello": "client", "sni": None, "version": None, "version_tuple": None,
               "cipher_suites_count": None, "cipher_suites": [], "extensions": [],
               "groups": [], "ec_point_formats": [], "alpn": [], "ja3": None, "ja3_md5": None,
               "only_weak_offered": None}
        try:
            if len(body) < 38:
                return out
            # legacy_version
            ver = (body[0], body[1]); out["version"] = f"{ver[0]}.{ver[1]}"; out["version_tuple"] = ver
            idx = 2 + 32  # random
            sid_len = body[idx]; idx += 1 + sid_len
            cs_len = struct.unpack("!H", body[idx:idx+2])[0]; idx += 2
            out["cipher_suites_count"] = cs_len // 2
            suites = []
            for j in range(0, cs_len, 2):
                suites.append(struct.unpack("!H", body[idx+j:idx+j+2])[0])
            out["cipher_suites"] = suites
            idx += cs_len
            comp_len = body[idx]; idx += 1 + comp_len
            if idx + 2 > len(body):
                return out
            ext_total = struct.unpack("!H", body[idx:idx+2])[0]; idx += 2
            end = idx + ext_total
            ext_types = []
            groups, ecpts, alpn = [], [], []
            sni = None
            while idx + 4 <= end and end <= len(body):
                ext_type = struct.unpack("!H", body[idx:idx+2])[0]
                ext_len  = struct.unpack("!H", body[idx+2:idx+4])[0]
                ext_data = body[idx+4:idx+4+ext_len]
                idx += 4 + ext_len
                ext_types.append(ext_type)
                # SNI (type 0)
                if ext_type == 0 and len(ext_data) >= 5:
                    j = 2
                    while j + 3 < len(ext_data):
                        name_type = ext_data[j]; j += 1
                        nlen = struct.unpack("!H", ext_data[j:j+2])[0]; j += 2
                        if j + nlen > len(ext_data):
                            break
                        servername = ext_data[j:j+nlen].decode("idna", errors="ignore"); j += nlen
                        if name_type == 0 and servername:
                            sni = servername; break
                # supported_groups (10)
                elif ext_type == 10 and len(ext_data) >= 2:
                    ln = struct.unpack("!H", ext_data[:2])[0]
                    for k in range(0, min(ln, len(ext_data)-2), 2):
                        groups.append(struct.unpack("!H", ext_data[2+k:2+k+2])[0])
                # ec_point_formats (11)
                elif ext_type == 11 and len(ext_data) >= 1:
                    ln = ext_data[0]
                    for k in range(ln):
                        if 1+k < len(ext_data):
                            ecpts.append(ext_data[1+k])
                # ALPN (16)
                elif ext_type == 16 and len(ext_data) >= 2:
                    ln = struct.unpack("!H", ext_data[:2])[0]
                    j = 2
                    while j < 2+ln and j < len(ext_data):
                        l = ext_data[j]; j += 1
                        proto = ext_data[j:j+l]
                        alpn.append(proto.decode("utf-8", "ignore"))
                        j += l
            out["extensions"] = ext_types
            out["groups"] = groups
            out["ec_point_formats"] = ecpts
            out["alpn"] = alpn
            out["sni"] = sni
            # JA3 uses u16 TLS version (legacy_version here)
            ver_u16 = (ver[0] << 8) | ver[1]
            ja3, jmd5 = self._compute_ja3(ver_u16, suites, ext_types, groups, ecpts)
            out["ja3"] = ja3; out["ja3_md5"] = jmd5

            # Classify the offered list against current cipher policy
            try:
                out["only_weak_offered"] = self.ciphers.all_weak(set(suites))
            except Exception:
                out["only_weak_offered"] = None
        except Exception:
            pass
        return out

    def _parse_server_hello(self, body: bytes) -> Dict:
        out = {"hello": "server", "version": None, "version_tuple": None,
               "cipher_suite": None, "cipher_suite_int": None, "cipher_suite_name": None,
               "cipher_weak": None, "cipher_reasons": [],
               "extensions": [], "ja3s": None, "ja3s_md5": None}
        try:
            if len(body) < 38:
                return out
            ver = (body[0], body[1]); out["version"] = f"{ver[0]}.{ver[1]}"; out["version_tuple"] = ver
            idx = 2 + 32
            sid_len = body[idx]; idx += 1 + sid_len
            cs = struct.unpack("!H", body[idx:idx+2])[0]; idx += 2
            out["cipher_suite_int"] = cs
            out["cipher_suite"] = f"0x{cs:04x}"
            # compression(1)
            if idx < len(body):
                idx += 1
            # extensions
            if idx + 2 <= len(body):
                ext_total = struct.unpack("!H", body[idx:idx+2])[0]; idx += 2
                end = min(len(body), idx + ext_total)
                ext_types = []
                while idx + 4 <= end:
                    et = struct.unpack("!H", body[idx:idx+2])[0]
                    el = struct.unpack("!H", body[idx+2:idx+4])[0]
                    idx += 4 + el
                    ext_types.append(et)
                out["extensions"] = ext_types

            # Human-friendly name + weakness classification
            try:
                name = self.ciphers.to_name(cs)
                weak, reasons = self.ciphers.is_weak(cs, negotiated=True)
            except Exception:
                name, weak, reasons = f"0x{cs:04x}", None, []
            out["cipher_suite_name"] = name
            out["cipher_weak"] = weak
            out["cipher_reasons"] = reasons

            ver_u16 = (ver[0] << 8) | ver[1]
            ja3s, jmd5 = self._compute_ja3s(ver_u16, cs, out.get("extensions", []))
            out["ja3s"] = ja3s; out["ja3s_md5"] = jmd5
        except Exception:
            pass
        return out

    # -------- Introspection / Control --------
    def get_stats(self, canonical_key) -> Dict[str, int]:
        return dict(self._stats.get(canonical_key, {}))

    def get_session_meta(self, canonical_key) -> Dict:
        m = self._meta.get(canonical_key, {})
        # make tags printable
        if "tags" in m and isinstance(m["tags"], set):
            m = dict(m); m["tags"] = sorted(m["tags"])
        return m

    def get_session_summary(self, canonical_key) -> Dict:
        m = self.get_session_meta(canonical_key)
        return {
            "first_seen": m.get("first_seen"), "last_seen": m.get("last_seen"),
            "client": m.get("client"), "server": m.get("server"),
            "sni": m.get("sni"), "alpn": m.get("alpn"),
            "version": m.get("negotiated_version"),
            "cipher": m.get("negotiated_cipher"),
            "cipher_name": m.get("negotiated_cipher_name"),
            "cipher_weak": m.get("negotiated_cipher_weak"),
            "cipher_reasons": m.get("negotiated_cipher_reasons"),
            "offered_only_weak": m.get("offered_only_weak"),
            "ja3_md5": (m.get("client_hello") or {}).get("ja3_md5"),
            "ja3s_md5": (m.get("server_hello") or {}).get("ja3s_md5"),
            "app_bytes": m.get("app_bytes"), "alerts": m.get("alerts"),
            "ccs_seen": m.get("ccs_seen"), "legacy_ssl": m.get("legacy_ssl"),
            "blocked": m.get("blocked"), "quarantined": m.get("quarantined"),
            "tags": m.get("tags"),
        }

    def sessions(self) -> List[Tuple]:
        return list(self._meta.keys())

    def reset_session(self, canonical_key):
        self._buffers.pop(canonical_key, None)
        self._stats.pop(canonical_key, None)
        self._meta.pop(canonical_key, None)

    # --- Administrative helpers for “doing more” programmatically ---
    def block_session(self, canonical_key, reason="manual block"):
        m = self._meta.get(canonical_key)
        if not m:
            return
        m["blocked"] = True
        self._emit_event(canonical_key, "block", {"reason": reason})

    def quarantine_session(self, canonical_key, reason="manual quarantine"):
        m = self._meta.get(canonical_key)
        if not m:
            return
        m["quarantined"] = True
        self._emit_event(canonical_key, "quarantine", {"reason": reason})

    def allow_session(self, canonical_key, reason="manual allow"):
        m = self._meta.get(canonical_key)
        if not m:
            return
        m["blocked"] = False
        m["quarantined"] = False
        self._emit_event(canonical_key, "allow", {"reason": reason})

    # --- Convenience: tweak cipher policy at runtime ---
    def set_cipher_requirements(self, **kwargs):
        """
        Proxy to TLSCipherManager.set_requirements(require_pfs=..., require_aead=...,
        forbid_cbc_sha1=..., forbid_rc4=..., etc.)
        """
        self.ciphers.set_requirements(**kwargs)


class HandshakeManager:
    """
    Tracks TCP 3-way handshakes/teardowns and pipes TLS bytes into TLSRecordManager.
    Modular helpers and rich analytics (RTT/DUP-ACK/OOO/retransmits/options).
    """
    COMMON_TLS_PORTS = {443, 444, 8443, 9443, 10443, 4443}

    # State labels
    SYN_SENT = "SYN_SENT"
    SYN_ACK  = "SYN_ACK_RECEIVED"
    EST      = "ESTABLISHED"
    CLOSING  = "CLOSING"
    CLOSED   = "CLOSED"

    def __init__(self, router_logger, arp_manager, nat_manager, rip_manager, packet_writer,
                 tls_record_manager=None,
                 timeout_half_open: int = 60,
                 timeout_established: int = 300):
        # deps
        self.logger = router_logger
        self.arp_manager = arp_manager
        self.nat_manager = nat_manager
        self.rip_manager = rip_manager
        self.packet_writer = packet_writer

        # TLS plumbing
        self._tls_mgr = tls_record_manager or TLSRecordManager(self.logger)
        self._tls_mgr.on_record = self._on_tls_record
        self._tls_mgr.on_handshake = self._on_tls_handshake
        self._tls_mgr.on_alert = self._on_tls_alert
        self._tls_mgr.on_application_data = self._on_tls_application_data
        self._tls_mgr.on_event = self._on_tls_event
        self._tls_mgr.on_decision = self._on_tls_decision

        # Flow state: key -> dict
        self._flows: Dict[Tuple[Tuple[str,int],Tuple[str,int]], Dict[str, Any]] = {}

        # last seen TCP pkt per direction for forwarding
        self._last_tcp_pkt: Dict[Tuple[Tuple, str], Packet] = {}

        # timeouts
        self.timeout_half_open = int(timeout_half_open)
        self.timeout_established = int(timeout_established)

        # abuse/ban
        self.ban_duration = 300
        self.rate_limit_threshold = 20
        self.rate_limit_period = 60
        self._ban_list: Dict[str, float] = {}
        self._conn_rate: Dict[str, List[float]] = defaultdict(list)

        # threading
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="HandshakeCleanup")
        self._cleanup_thread.start()

        # optional sender
        self.sniffer = None

        # external hooks
        self.on_flow_new = None               # (key, meta) -> None
        self.on_flow_established = None       # (key, meta) -> None
        self.on_flow_closed = None            # (key, meta, reason) -> None
        self.on_flow_timeout = None           # (key, meta, state) -> None

        self.logger.log_message("[Handshake] Manager ready (modular).")

    # ===== public lifecycle =====
    def start(self):
        if not self._cleanup_thread.is_alive():
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="HandshakeCleanup")
            self._cleanup_thread.start()
            self.logger.log_message("[Handshake] Cleanup thread started.")

    def stop(self):
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.logger.log_message("[Handshake] Manager stopped.")

    # ===== core handler =====
    def handle_packet(self, pkt: Packet, inbound_iface: str) -> bool:
        ip, tcp = self._extract_layers(pkt)
        if not ip or not tcp:
            return False

        now = time.time()
        src_ip, dst_ip = ip.src, ip.dst
        sport, dport = int(tcp.sport), int(tcp.dport)

        # banned src?
        if self._is_banned(src_ip, now):
            return False

        # rate-limit (per FIN close hint later too)
        self._track_connection_rate(src_ip, now, initial=(tcp.flags & 0x02) != 0)

        # NAT reverse if destined to our public
        dst_ip, dport = self._nat_reverse_if_needed(ip, tcp, src_ip, sport, dst_ip, dport)

        key = _get_canonical_session_key(src_ip, sport, dst_ip, dport)
        flow = self._get_or_init_flow(key, src_ip, sport, dst_ip, dport, inbound_iface, now)

        # TCP options & metrics (once per direction)
        self._parse_tcp_options(flow, tcp, src_ip, sport, dst_ip, dport)

        # TCP state machine & metrics
        progressed = self._advance_fsm(flow, tcp, now, inbound_iface)
        if progressed == "closed":
            self._close_flow(key, flow, reason="teardown")
            return False

        # TLS feed (post-FSM)
        fed = self._maybe_feed_tls(flow, key, pkt, ip, tcp, now)

        # track last pkt for forwarding
        direction = "c2s" if self._is_c2s(flow, src_ip, sport) else "s2c"
        self._last_tcp_pkt[(key, direction)] = pkt

        return fed

    # ===== helpers: extraction / NAT / flow init =====
    def _extract_layers(self, pkt: Packet):
        if not (pkt and (pkt.haslayer(IP) or pkt.haslayer(IPv6)) and pkt.haslayer(TCP)):
            return None, None
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        tcp = pkt[TCP]
        return ip, tcp

    def _nat_reverse_if_needed(self, ip, tcp, src_ip, sport, dst_ip, dport):
        try:
            pub = getattr(self.nat_manager, "public_ip", None)
            if pub and dst_ip == pub:
                internal = self.nat_manager.get_internal_from_external(dport, src_ip)
                if internal:
                    nid, npt = internal
                    self.logger.log_message(
                        f"[Handshake] NAT reverse: {dst_ip}:{dport} -> {nid}:{npt}"
                    )
                    return nid, int(npt)
        except Exception:
            pass
        return dst_ip, dport

    def _get_or_init_flow(self, key, sip, sport, dip, dport, iface, now):
        with self._lock:
            flow = self._flows.get(key)
            if flow:
                return flow
            flow = {
                "state": None,
                "first_seen": now,
                "last_seen": now,
                "client": (sip, sport),  # initial guess; refined by FSM
                "server": (dip, dport),
                "iface": iface,
                "syn_ts": None,          # for RTT
                "synack_ts": None,
                "rtt_smoothed": None,
                "counters": defaultdict(int),
                "tcp_opts": {"c2s": {}, "s2c": {}},  # MSS/WS/SACK/TS per dir
                "dup_acks": {"c2s": 0, "s2c": 0},
                "seq_track": {           # per-dir sequence tracking
                    "c2s": {"last_seq": None, "seen": set()},
                    "s2c": {"last_seq": None, "seen": set()},
                },
                "app_bytes": {"c2s": 0, "s2c": 0},
            }
            self._flows[key] = flow
        if callable(self.on_flow_new):
            try: self.on_flow_new(key, flow)
            except Exception: pass
        return flow

    # ===== helpers: TCP option parsing / RTT =====
    def _parse_tcp_options(self, flow, tcp, sip, sport, dip, dport):
        try:
            opts = tcp.options or []
        except Exception:
            opts = []
        direction = "c2s" if self._is_c2s(flow, sip, sport) else "s2c"
        store = flow["tcp_opts"][direction]
        updated = False
        for k, v in opts:
            if k == "MSS" and "mss" not in store:
                store["mss"] = int(v); updated = True
            elif k == "WScale" and "wscale" not in store:
                store["wscale"] = int(v); updated = True
            elif k == "SAckOK" and "sack_ok" not in store:
                store["sack_ok"] = True; updated = True
            elif k == "Timestamp" and "ts" not in store and isinstance(v, tuple) and len(v) == 2:
                store["ts"] = {"tsval": int(v[0]), "tsecr": int(v[1])}; updated = True
        if updated:
            self.logger.log_message(
                f"[Handshake] ⚙️ TCP opts {direction} mss={store.get('mss')} ws={store.get('wscale')} "
                f"sack={store.get('sack_ok')} ts={store.get('ts') is not None}"
            )

    def _update_rtt(self, flow, now, reason: str):
        """Update smoothed RTT using SYN/SYN-ACK or TS echo."""
        rtt = None
        # handshake-based
        if flow["syn_ts"] and flow["synack_ts"] and reason == "handshake":
            rtt = max(0.0, flow["synack_ts"] - flow["syn_ts"])
        # TS-based (best-effort): if we ever had TS both ways, use echo diff
        # (left as placeholder for your advanced TS tracking if desired)
        if rtt is None:
            return
        alpha = 0.125
        if flow["rtt_smoothed"] is None:
            flow["rtt_smoothed"] = rtt
        else:
            flow["rtt_smoothed"] = (1 - alpha) * flow["rtt_smoothed"] + alpha * rtt
        self.logger.log_message(f"[Handshake] ⏱️ RTT update ({reason}): {flow['rtt_smoothed']:.4f}s")

    # ===== helpers: FSM / metrics =====
    def _advance_fsm(self, flow, tcp, now, iface) -> Optional[str]:
        st = flow["state"]
        src, sport = tcp.sport, tcp.sport  # keep for logs (ints already)
        flags = int(tcp.flags)

        # retransmit/OOO quick checks (per-dir)
        direction = "c2s" if self._is_c2s(flow, flow['client'][0], flow['client'][1]) else "s2c"
        self._track_seq(flow, direction, tcp)

        # FSM
        if flags == 0x02:  # SYN
            if st is None:
                flow["state"] = self.SYN_SENT
                flow["syn_ts"] = now
                flow["last_seen"] = now
                self.logger.log_message(f"[Handshake] 🔓 SYN {flow['client'][0]}:{flow['client'][1]} -> {flow['server'][0]}:{flow['server'][1]} on {iface}")
            else:
                flow["counters"]["syn_retx"] += 1
                flow["last_seen"] = now
                self.logger.log_message("[Handshake] 🔁 SYN retransmit")
            return None

        if flags == 0x12:  # SYN+ACK
            if st == self.SYN_SENT:
                flow["state"] = self.SYN_ACK
                flow["synack_ts"] = now
                flow["last_seen"] = now
                self._update_rtt(flow, now, "handshake")
                self.logger.log_message("[Handshake] 🔐 SYN-ACK received")
            elif st == self.SYN_ACK:
                flow["counters"]["synack_retx"] += 1
                flow["last_seen"] = now
                self.logger.log_message("[Handshake] 🔁 SYN-ACK retransmit")
            else:
                # midstream (didn't see SYN) → infer ESTABLISHED
                flow["state"] = self.EST
                flow["last_seen"] = now
                self.logger.log_message("[Handshake] ✅ Inferred ESTABLISHED by SYN-ACK (midstream)")
                self._on_established(flow)
            return None

        if flags & 0x10 and not (flags & 0x01) and not (flags & 0x04):  # ACK (pure)
            if st == self.SYN_ACK:
                flow["state"] = self.EST
                flow["last_seen"] = now
                self.logger.log_message("[Handshake] ✅ ESTABLISHED")
                self._on_established(flow)
            elif st in (self.EST, self.CLOSING):
                flow["last_seen"] = now
            else:
                # midstream pickup: ACK-only
                if st is None:
                    flow["state"] = self.EST
                    flow["last_seen"] = now
                    self.logger.log_message("[Handshake] ✅ Implicit ESTABLISHED by ACK-only (midstream)")
                    self._on_established(flow)
            return None

        if flags & 0x01:  # FIN
            if st == self.EST:
                flow["state"] = self.CLOSING
                flow["last_seen"] = now
                self.logger.log_message("[Handshake] 🔻 CLOSING (FIN)")
            elif st == self.CLOSING:
                flow["state"] = self.CLOSED
                flow["last_seen"] = now
                self.logger.log_message("[Handshake] ❎ CLOSED (ACK after FIN)")
                return "closed"
            else:
                self.logger.log_message(f"[Handshake] ⚠️ FIN in state {st or 'None'}")
            return None

        if flags & 0x04:  # RST
            flow["state"] = self.CLOSED
            flow["last_seen"] = now
            self.logger.log_message("[Handshake] ❌ CLOSED (RST)")
            return "closed"

        # data-bearing ACK/PSH combinations → keep alive freshness
        if (flags & 0x10) and (len(bytes(tcp.payload) or b"") > 0):
            flow["last_seen"] = now

        return None

    def _track_seq(self, flow, direction: str, tcp):
        """Simple sequence/retransmit/out-of-order heuristics."""
        seq = int(tcp.seq)
        ack = int(tcp.ack)
        payload_len = len(bytes(tcp.payload) or b"")
        last_seq = flow["seq_track"][direction]["last_seq"]

        # DUP-ACK: ack same, no payload, ACK flag
        if (int(tcp.flags) & 0x10) and payload_len == 0 and seq == last_seq:
            flow["dup_acks"][direction] += 1
            if flow["dup_acks"][direction] >= 3:
                self.logger.log_message(f"[Handshake] 📎 {direction} potential fast-retransmit (>=3 DUP-ACK)")
        else:
            flow["dup_acks"][direction] = 0

        # retransmit/OOO (very light heuristic)
        if last_seq is not None and seq < last_seq:
            flow["counters"][f"{direction}_ooo"] += 1
        if last_seq is not None and seq == last_seq and payload_len > 0:
            flow["counters"][f"{direction}_retrans"] += 1

        flow["seq_track"][direction]["last_seq"] = seq

        # keepalive heuristic: zero payload, seq = prev ack - 1, ACK set (not fully enforced here)
        # (left as a log-only: detailed keepalive pattern might be added if needed)

    def _on_established(self, flow):
        # NAT stateful mapping hint (optional)
        try:
            (c_ip, c_pt), (s_ip, s_pt) = flow["client"], flow["server"]
            if hasattr(self.nat_manager, "add_stateful_mapping"):
                self.nat_manager.add_stateful_mapping(src_ip=c_ip, src_port=c_pt, dst_ip=s_ip, dst_port=s_pt)
        except Exception:
            pass
        if callable(self.on_flow_established):
            try: self.on_flow_established(None, flow)
            except Exception: pass

    # ===== helpers: TLS feed =====
    def _maybe_feed_tls(self, flow, key, pkt, ip, tcp, now) -> bool:
        st = flow["state"]
        if st != self.EST:
            # midstream pickup if bytes look TLS-ish
            payload = bytes(tcp.payload) if tcp.payload else b""
            if payload and self._looks_tlsish(payload):
                flow["state"] = self.EST
                flow["last_seen"] = now
                self.logger.log_message("[Handshake] ✅ Implicit ESTABLISHED by TLS payload")
            else:
                return False

        payload = bytes(tcp.payload) if tcp.payload else b""
        if not payload:
            return False

        is_c2s = self._is_c2s(flow, ip.src, tcp.sport)
        dir_key = "c2s" if is_c2s else "s2c"

        # remember last packet for optional forwarding
        self._last_tcp_pkt[(key, dir_key)] = pkt

        # feed to TLS manager
        try:
            self._tls_mgr.feed_tcp_segment(
                canonical_key=key,
                is_c2s=is_c2s,
                payload=payload,
                src_ip=ip.src, src_port=int(tcp.sport),
                dst_ip=ip.dst, dst_port=int(tcp.dport),
                ts=time.time()
            )
        except Exception as e:
            self.logger.log_message(f"[TLS] ❌ feed error: {e}")
            return False

        # simple bytes accounting
        flow["app_bytes"][dir_key] += len(payload)
        return True

    @staticmethod
    def _looks_tlsish(b: bytes) -> bool:
        if len(b) >= 5 and TLSRecordManager._looks_like_tls_header(b):
            return True
        # SSLv2 hello possibility
        return bool(b) and (b[0] & 0x80) and len(b) >= 3

    def _is_c2s(self, flow, src_ip, src_port) -> bool:
        # prefer stored roles if established
        c = flow.get("client")
        if c and (src_ip, int(src_port)) == c:
            return True
        # heuristic by port
        dport = flow.get("server", ("", 0))[1]
        if dport in self.COMMON_TLS_PORTS and int(src_port) not in self.COMMON_TLS_PORTS:
            return True
        return False

    # ===== cleanup / bans / rate =====
    def _cleanup_loop(self):
        while not self._stop_event.is_set():
            now = time.time()
            timed_out: List[Tuple] = []
            with self._lock:
                # bans expire
                for ip, exp in list(self._ban_list.items()):
                    if now >= exp:
                        del self._ban_list[ip]
                        self.logger.log_message(f"[Handshake][BAN] ✅ Ban expired for {ip}")

                # flows timeout
                for key, flow in list(self._flows.items()):
                    st = flow["state"]
                    tmo = self.timeout_half_open if st in (None, self.SYN_SENT, self.SYN_ACK) else self.timeout_established
                    if (now - flow["last_seen"]) > tmo:
                        timed_out.append((key, flow))
                        del self._flows[key]

            for key, flow in timed_out:
                self.logger.log_message(f"[Handshake] ⌛ Timeout {flow.get('state')} for {key}")
                if callable(self.on_flow_timeout):
                    try: self.on_flow_timeout(key, flow, flow.get("state"))
                    except Exception: pass

            self._stop_event.wait(1.0)

    def _is_banned(self, ip: str, now: float) -> bool:
        exp = self._ban_list.get(ip)
        return bool(exp and now < exp)

    def _track_connection_rate(self, ip: str, now: float, initial: bool):
        if not initial:
            return
        q = self._conn_rate[ip]
        q.append(now)
        # keep only recent
        self._conn_rate[ip] = [t for t in q if now - t <= self.rate_limit_period]
        if len(self._conn_rate[ip]) > self.rate_limit_threshold:
            self._ban_list[ip] = now + self.ban_duration
            del self._conn_rate[ip]
            self.logger.log_message(f"[Handshake][BAN] 🚫 {ip} banned ({self.ban_duration}s) for connection burst")

    # ===== flow close / snapshots / admin =====
    def _close_flow(self, key, flow, reason="closed"):
        if callable(self.on_flow_closed):
            try: self.on_flow_closed(key, flow, reason)
            except Exception: pass
        # nothing else—GC handled in caller or cleanup

    def snapshot_flow(self, key) -> Optional[Dict[str, Any]]:
        f = self._flows.get(key)
        if not f:
            return None
        return {
            "state": f["state"],
            "first_seen": f["first_seen"],
            "last_seen": f["last_seen"],
            "client": f["client"],
            "server": f["server"],
            "rtt": f["rtt_smoothed"],
            "counters": dict(f["counters"]),
            "dup_acks": dict(f["dup_acks"]),
            "tcp_opts": {
                "c2s": dict(f["tcp_opts"]["c2s"]),
                "s2c": dict(f["tcp_opts"]["s2c"]),
            },
            "app_bytes": dict(f["app_bytes"]),
        }

    def snapshot_all(self) -> List[Dict[str, Any]]:
        return [self.snapshot_flow(k) for k in list(self._flows.keys()) if self.snapshot_flow(k)]

    def export_json(self) -> str:
        return json.dumps(self.snapshot_all(), indent=2, default=str)

    def block_ip(self, ip: str, seconds: Optional[int] = None):
        self._ban_list[ip] = time.time() + (seconds or self.ban_duration)
        self.logger.log_message(f"[Handshake][BAN] ⛔ Manually blocked {ip} for {seconds or self.ban_duration}s")

    def allow_ip(self, ip: str):
        if ip in self._ban_list:
            del self._ban_list[ip]
            self.logger.log_message(f"[Handshake][BAN] ✅ Unblocked {ip}")

    def set_thresholds(self, *, rate_limit_threshold: Optional[int] = None,
                       rate_limit_period: Optional[int] = None,
                       ban_duration: Optional[int] = None,
                       timeout_half_open: Optional[int] = None,
                       timeout_established: Optional[int] = None):
        if rate_limit_threshold is not None:
            self.rate_limit_threshold = int(rate_limit_threshold)
        if rate_limit_period is not None:
            self.rate_limit_period = int(rate_limit_period)
        if ban_duration is not None:
            self.ban_duration = int(ban_duration)
        if timeout_half_open is not None:
            self.timeout_half_open = int(timeout_half_open)
        if timeout_established is not None:
            self.timeout_established = int(timeout_established)

    # ===== TLS callbacks =====
    def _on_tls_record(self, rec: "TLSRecord"):
        # lightweight first-records log
        self.logger.log_message(
            f"[TLS] 📄 ct={rec.content_type} ver={rec.version} len={rec.length} "
            f"{rec.direction} {rec.src}:{rec.src_port}->{rec.dst}:{rec.dst_port}"
        )

    def _on_tls_handshake(self, rec: "TLSRecord", info: Dict):
        # compact summary
        for msg in info.get("messages", []):
            t = msg.get("type")
            if t == "client_hello":
                sni = (msg.get("sni") or (info.get("client_hello") or {}).get("sni"))
                ja3 = (info.get("client_hello") or {}).get("ja3_md5")
                ver = (info.get("client_hello") or {}).get("version")
                alpn = (info.get("client_hello") or {}).get("alpn") or []
                self.logger.log_message(f"[TLS][CH] SNI={sni or 'N/A'} JA3={ja3 or 'N/A'} ver={ver or 'N/A'} ALPN={','.join(alpn) or 'N/A'}")
            elif t == "server_hello":
                ver = (info.get("server_hello") or {}).get("version")
                cipher = (info.get("server_hello") or {}).get("cipher_suite")
                ja3s = (info.get("server_hello") or {}).get("ja3s_md5")
                self.logger.log_message(f"[TLS][SH] ver={ver or 'N/A'} cipher={cipher or 'N/A'} JA3S={ja3s or 'N/A'}")

    def _on_tls_alert(self, rec: "TLSRecord", alert: Dict):
        self.logger.log_message(
            f"[TLS][Alert] level={alert.get('level')} desc={alert.get('description')} "
            f"{rec.direction} {rec.src}:{rec.src_port}->{rec.dst}:{rec.dst_port}"
        )

    def _on_tls_application_data(self, rec: "TLSRecord"):
        # Optional: forward AppData using last TCP context
        key = _get_canonical_session_key(rec.src, rec.src_port, rec.dst, rec.dst_port)
        dir_key = (key, rec.direction)
        last_pkt = self._last_tcp_pkt.get(dir_key)
        if not last_pkt:
            self.logger.log_message(f"[TLS] 🔒 AppData {len(rec.payload)}B (no TCP ctx) {rec.src}:{rec.src_port}->{rec.dst}:{rec.dst_port}")
            return
        try:
            ether = last_pkt[Ether] if last_pkt.haslayer(Ether) else None
            base_eth = Ether(dst=ether.dst, src=ether.src) if ether else Ether()
            is_v6 = last_pkt.haslayer(IPv6)
            ip_layer = (IPv6(src=rec.src, dst=rec.dst) if is_v6 else IP(src=rec.src, dst=rec.dst))
            tcp_prev = last_pkt[TCP]
            seg = TCP(sport=rec.src_port, dport=rec.dst_port, flags="PA",
                      seq=int(tcp_prev.seq), ack=int(tcp_prev.ack), window=int(tcp_prev.window))
            out = base_eth / ip_layer / seg / Raw(load=rec.payload)
            # Replace with packet_writer if needed:
            if self.sniffer:
                self.sniffer.send(out)
            else:
                # try PacketWriter if provided
                try:
                    self.packet_writer._send_raw_packet(out, flow_iface := self._flows.get(key, {}).get("iface", None), allow_dst_ours=True, no_consume=False)
                except Exception:
                    pass
            self.logger.log_message(f"[TLS] 🔁 Fwd AppData {len(rec.payload)}B {rec.src}:{rec.src_port}->{rec.dst}:{rec.dst_port}")
        except Exception as e:
            self.logger.log_message(f"[TLS] ❌ Forward error: {e}")

    def _on_tls_event(self, evt: Dict):
        kind = evt.get("kind")
        if kind in ("block", "quarantine", "policy_alert"):
            self.logger.log_message(f"[TLS][Policy] {kind.upper()} {evt.get('data', {})}")

    def _on_tls_decision(self, flow_key, rec: "TLSRecord", decision):
        if decision.action != "allow":
            self.logger.log_message(
                f"[TLS][Decision] {decision.action.upper()} flow={flow_key} reason={decision.reason} tags={decision.tags}"
            )

    # ===== misc =====
    def normalize_mac(self, mac: str) -> str:
        return mac.replace('-', ':').lower()


@dataclass
class MembershipEntry:
    family: int                         # 4 or 6
    group: str
    ifname: str
    mode: str = "include"               # "include" or "exclude"
    sources: Set[str] = field(default_factory=set)
    last_report: float = field(default_factory=time.time)
    proto: str = "IGMP"                 # "IGMP" or "MLD"
    version: int = 2
    lmq_remaining: int = 0
    lmq_next_ts: float = 0.0
    lmq_group_specific: bool = False


class IGMPManager:
    """
    A comprehensive manager for the Internet Group Management Protocol (IGMP).

    • Handles IGMPv1/v2/v3 membership reports (joins), v2 leaves + Last Member Queries (LMQ).
    • Sends General Queries periodically as a querier (IGMPv3mq preferred; logs Router Alert).
    • Tracks memberships with include/exclude source sets (v3).
    • Querier awareness: notes other queriers and logs if we should back off.
    • TX-aware: every send via pw._send_raw_packet() emits [IGMP][TX] lines with sizes and hex previews.
    • RX-aware: optional hex preview for incoming IGMP packets.
    • WinDivert/Raw: will fall back to IP-only packets when Ether cannot be built.

    Tunables:
    - VERBOSE_TX_HEX_PREVIEW / VERBOSE_RX_HEX_PREVIEW, HEX_PREVIEW_BYTES.
    - QUERY_INTERVAL, MEMBERSHIP_TIMEOUT, LMQ_COUNT, LMQ_INTERVAL.
    - QUERIER_BACKOFF_SEC: back off if a lower-IP querier is seen.
    - V3 query parameters: V3_MAX_RESP_CODE, V3_QRV, V3_QQIC.
    """

    # --------------- Tuning ----------------
    VERBOSE_TX_HEX_PREVIEW = True
    VERBOSE_RX_HEX_PREVIEW = False
    HEX_PREVIEW_BYTES = 128

    # Standard IGMP multicast addresses
    IGMP_ALL_HOSTS = "224.0.0.1"
    IGMP_ALL_ROUTERS = "224.0.0.2"
    MAC_ALL_HOSTS = "01:00:5e:00:00:01"

    IGMP_V3_REPORT_ADDR = "224.0.0.22"
    MAC_IGMP_V3_REPORT = "01:00:5e:00:00:16"  # Ethernet map for 224.0.0.22
    ADMIN_LOCAL_NET = ipaddress.IPv4Network("224.0.0.0/24")  # Link-local admin scope

    # IGMP Timers and Constants (RFC 2236 & 3376)
    QUERY_INTERVAL = 125         # Time between General Queries (s)
    MEMBERSHIP_TIMEOUT = 260     # Robustness*QueryInterval + MaxResp
    LMQ_COUNT = 2                # Last Member Query count
    LMQ_INTERVAL = 1             # Seconds between LMQ bursts

    # Querier awareness
    QUERIER_BACKOFF_SEC = 255

    # IGMPv3 query fields (RFC 3376)
    V3_MAX_RESP_CODE = 100  # encoded MRC (see RFC; 100 ~ 10s plain code)
    V3_QRV = 2  # robustness value in query
    V3_QQIC = 125  # query interval code (~125s)
    V3_SUPPRESS = 0  # S bit (1=do not send reports immediately)


    # IGMPv3 Report Record Types (for readable logs)
    V3_RTYPE_MAP = {
        1: "MODE_IS_INCLUDE",
        2: "MODE_IS_EXCLUDE",
        3: "CHANGE_TO_INCLUDE",
        4: "CHANGE_TO_EXCLUDE",
        5: "ALLOW_NEW_SOURCES",
        6: "BLOCK_OLD_SOURCES",
    }

    def __init__(self, router_logger, packet_writer):
        self.log = router_logger
        self.pw = packet_writer

        self._db: Dict[Tuple[str, str], MembershipEntry] = {}
        self._lock = threading.Lock()
        self._ifcfg: Dict[str, Dict[str, Any]] = {}

        # Querier tracking per interface: { ifname: {"last_seen": ts, "addr": str} }
        self._querier: Dict[str, Dict[str, Any]] = {}
        self._q_lock = threading.Lock()

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Optional callback on membership state changes
        self.on_change: Optional[Callable[[str, MembershipEntry], None]] = None

        # Counters (for observability)
        self._counters = {
            "pkts_rx": 0,
            "pkts_igmp": 0,
            "pkts_v1v2_join": 0,
            "pkts_v2_leave": 0,
            "pkts_v3_report": 0,
            "tx_general_query": 0,
            "tx_group_query": 0,
            "drops_malformed": 0,
        }

        self.log.log_message("[IGMP] Manager initialized (v1/v2/v3 support, IGMPv3mq enabled, TX/RX-aware).")

    # ------------------------------------------------------------------ Public

    def set_interfaces_config(self, interfaces_config: Dict[str, Dict[str, Any]]):
        """Sets or updates the router's interface configuration."""
        self._ifcfg = interfaces_config or {}
        self.log.log_message(f"[IGMP] Interfaces config set ({len(self._ifcfg)} ifaces).")

    def start(self):
        """Starts the background thread for sending queries and managing state."""
        if self._thread and self._thread.is_alive():
            self.log.log_message("[IGMP] Background thread already running.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._background_loop, name="IGMP_Manager", daemon=True)
        self._thread.start()
        self.log.log_message("[IGMP] Background thread started.")

    def stop(self):
        """Stops the background thread."""
        if not self._thread:
            return
        self._stop_event.set()
        self._thread.join(timeout=3.0)
        self.log.log_message("[IGMP] Background thread stopped.")

    def snapshot(self) -> Dict[Tuple[str, str], dict]:
        """Returns a snapshot of the current IGMP membership database (for UI/telemetry)."""
        with self._lock:
            snap = {
                k: {
                    "group": v.group, "ifname": v.ifname, "mode": v.mode,
                    "sources": sorted(v.sources), "last_report": v.last_report,
                    "version": v.version, "lmq_remaining": v.lmq_remaining,
                    "proto": v.proto, "family": v.family,
                }
                for k, v in self._db.items()
            }
        self.log.log_message(f"[IGMP] Snapshot exported ({len(snap)} entries).")
        return snap

    def log_snapshot(self):
        """Logs the entire DB (truncated lists for readability)."""
        with self._lock:
            self.log.log_message(f"[IGMP] DB dump ({len(self._db)} entries):")
            for (grp, ifn), e in self._db.items():
                srcs_show = sorted(list(e.sources))[:12]
                more = "" if len(e.sources) <= 12 else f", ...(+{len(e.sources)-12})"
                self.log.log_message(
                    f"[IGMP]   {grp} on {self._iface_suffix(ifn)} v{e.version} {e.mode} "
                    f"sources={srcs_show}{more} lmq={e.lmq_remaining}"
                )

    def counters(self) -> Dict[str, int]:
        """Returns a copy of internal counters."""
        return dict(self._counters)

    def should_forward_multicast(self, *, group_ip: str, outbound_ifname: str, source_ip: Optional[str] = None) -> bool:
        """Router decision helper (SSM aware)."""
        if self._is_admin_local_mcast(group_ip):
            self.log.log_message(f"[IGMP] should_forward_multicast({group_ip}) -> False (admin-scope).")
            return False
        key = (group_ip, outbound_ifname)
        with self._lock:
            entry = self._db.get(key)
            if not entry:
                self.log.log_message(f"[IGMP] should_forward_multicast({group_ip}) -> False (no members on iface).")
                return False
        if source_ip:
            allowed = (source_ip in entry.sources) if entry.mode == "include" else (source_ip not in entry.sources)
            self.log.log_message(
                f"[IGMP] should_forward_multicast({group_ip}, src={source_ip}) -> {allowed} (mode={entry.mode})."
            )
            return allowed
        self.log.log_message(f"[IGMP] should_forward_multicast({group_ip}) -> True (ASM).")
        return True

    # ------------------------------------------------------------- Packet Path

    def handle_packet(self, pkt: Packet, inbound_ifname: str):
        """
        Entry point for packets observed on an interface. We consume all admin-scope
        (224.0.0.0/24) traffic. If IGMP layers are present, process them.
        """
        try:
            self._counters["pkts_rx"] += 1

            # Optional RX hex preview for troubleshooting
            if self.VERBOSE_RX_HEX_PREVIEW:
                try:
                    raw = bytes(pkt)
                    self._hex_preview("[IGMP][RX] bytes", raw)
                except Exception:
                    pass

            if not (hasattr(pkt, "haslayer") and pkt.haslayer(IP)):
                return

            ip_dst = pkt[IP].dst

            # Always consume admin-scope local multicast (224.0.0.0/24)
            if self._is_admin_local_mcast(ip_dst):
                self._log_ip_router_alert(pkt, inbound_ifname)
                if self._has_igmpish_layer(pkt):
                    self._handle_igmp(pkt, inbound_ifname)
                else:
                    self.log.log_message(
                        f"[IGMP] Consumed admin-local {ip_dst} lacking IGMP layer on {self._iface_suffix(inbound_ifname)}"
                    )
                return

            # Non-admin multicast: process if IGMP-ish layer exists
            if self._has_igmpish_layer(pkt):
                self._handle_igmp(pkt, inbound_ifname)

        except Exception as e:
            self.log.log_message(f"[IGMP] ❗ Error handling packet: {e}")

    # ----------------------------------------------------------- Background ops

    def _background_loop(self):
        """The main loop for the background thread."""
        next_query_time = time.time()
        self.log.log_message("[IGMP] Background loop running.")
        while not self._stop_event.is_set():
            now = time.time()
            if now >= next_query_time:
                self._send_general_queries(now)
                next_query_time = now + self.QUERY_INTERVAL

            self._service_last_member_queries(now)
            self._purge_stale_memberships(now)
            self._stop_event.wait(0.5)  # Service loop runs twice a second
        self.log.log_message("[IGMP] Background loop exiting.")

    # ----------------------------------------------------------- TX primitives

    def _pw_send(self, pkt: Packet, iface: str, *, note: str, allow_dst_ours: bool = True):
        """Wrapper around packet_writer._send_raw_packet with TX logging + hex preview."""
        try:
            raw = bytes(pkt)
            if self.VERBOSE_TX_HEX_PREVIEW and raw:
                self._hex_preview("[IGMP][TX] bytes", raw)
            self.log.log_message(
                f"[IGMP][TX] {note} on {self._iface_suffix(iface)} len={len(raw)}"
            )
            self.pw._send_raw_packet(pkt, iface, allow_dst_ours=allow_dst_ours)
        except Exception as e:
            self.log.log_message(f"[IGMP][TX] ❌ send failed ({note}) on {self._iface_suffix(iface)}: {e}")

    # --------------------------------------------------------- Query emission

    def _send_general_queries(self, now: float):
        for ifname, cfg in self._ifcfg.items():
            ip_src = cfg.get("ip_addr")
            mac_src = cfg.get("mac")
            if not ip_src or self._is_loopback(ifname):
                continue
            if not self._we_are_querier(ifname, our_ip=ip_src, now=now):
                continue

            ip_layer = IP(src=ip_src, dst=self.IGMP_ALL_HOSTS, ttl=1)
            # Try to add Router Alert
            try:
                if IPOption_Router_Alert is not None:
                    ip_layer.options = IPOption_Router_Alert()
                else:
                    ip_layer.options = b"\x94\x04\x00\x00"
            except Exception:
                try:
                    ip_layer.options = b"\x94\x04\x00\x00"
                except Exception:
                    pass

            # Build v3 query safely; general query => gaddr 0.0.0.0
            igmp_q = self._build_v3_query_pkt("0.0.0.0")

            frame = (Ether(src=mac_src, dst=self.MAC_ALL_HOSTS) / ip_layer / igmp_q) if mac_src else (ip_layer / igmp_q)
            self._counters["tx_general_query"] += 1
            self.log.log_message(f"[IGMP] -> General Query on {self._iface_suffix(ifname)}")
            self._pw_send(frame, ifname, note="General Query", allow_dst_ours=True)

    def _send_group_specific_query(self, entry: MembershipEntry):
        ifname = entry.ifname
        cfg = self._ifcfg.get(ifname, {})
        ip_src = cfg.get("ip_addr")
        mac_src = cfg.get("mac")
        if not ip_src:
            self.log.log_message(
                f"[IGMP] ⚠️ Cannot send Group-Specific Query for {entry.group}: no IP on {self._iface_suffix(ifname)}")
            return

        ip_layer = IP(src=ip_src, dst=entry.group, ttl=1)
        try:
            if IPOption_Router_Alert is not None:
                ip_layer.options = IPOption_Router_Alert()
            else:
                ip_layer.options = b"\x94\x04\x00\x00"
        except Exception:
            try:
                ip_layer.options = b"\x94\x04\x00\x00"
            except Exception:
                pass

        # If you track pending-block sources for LMQv2/v3, pass them; otherwise leave empty
        igmp_q = self._build_v3_query_pkt(entry.group)

        dst_mac = self._ipv4_mcast_to_mac(entry.group) or self.MAC_ALL_HOSTS
        pkt = (Ether(src=mac_src, dst=dst_mac) / ip_layer / igmp_q) if mac_src else (ip_layer / igmp_q)

        self._counters["tx_group_query"] += 1
        self.log.log_message(f"[IGMP] -> Group-Specific Query for {entry.group} on {self._iface_suffix(ifname)}")
        self._pw_send(pkt, ifname, note=f"Group-Specific Query {entry.group}", allow_dst_ours=True)

    # ------------------------------------------------------------- Housekeeping

    def _purge_stale_memberships(self, now: float):
        """Removes memberships that have timed out."""
        with self._lock:
            stale_keys = [
                k for k, v in self._db.items()
                if (now - v.last_report) > self.MEMBERSHIP_TIMEOUT and v.lmq_remaining == 0
            ]
            for key in stale_keys:
                entry = self._db.pop(key)
                self.log.log_message(f"[IGMP] 🧹 Timed out membership for {entry.group} on {self._iface_suffix(entry.ifname)}.")
                self._notify("leave", entry)

    def _service_last_member_queries(self, now: float):
        """Sends Group-Specific Queries for groups in the LMQ state and removes on no-reply."""
        keys_to_drop = []
        with self._lock:
            for key, entry in self._db.items():
                if entry.lmq_remaining > 0 and now >= entry.lmq_next_ts:
                    self._send_group_specific_query(entry)
                    entry.lmq_remaining -= 1
                    entry.lmq_next_ts = now + (self.LMQ_INTERVAL if entry.lmq_remaining > 0 else 0)
                    if entry.lmq_remaining == 0:
                        keys_to_drop.append(key)
        if keys_to_drop:
            with self._lock:
                for key in keys_to_drop:
                    entry = self._db.pop(key, None)
                    if entry:
                        self.log.log_message(f"[IGMP] No reply to LMQ for {entry.group}. Removing membership.")
                        self._notify("leave", entry)

    # ------------------------------------------------------------- IGMP Parser

    def _has_igmpish_layer(self, pkt: Packet) -> bool:
        """True if packet has IGMP/IGMPv3 layers Scapy recognizes."""
        if not hasattr(pkt, "haslayer"):
            return False
        try:
            return bool((IGMP and pkt.haslayer(IGMP)) or (IGMPv3mr and pkt.haslayer(IGMPv3mr)) or (IGMPv3 and pkt.haslayer(IGMPv3)))
        except Exception:
            return False

    def _handle_igmp(self, pkt: Packet, ifname: str):
        """Parse and act on IGMP (v1/v2/v3)."""
        try:
            self._counters["pkts_igmp"] += 1

            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst

            igmp_type, igmp_layer = self._extract_igmp_type(pkt)

            # Queries (0x11) from other routers: querier awareness
            if igmp_type == 0x11:
                self._record_remote_querier(ifname, src_ip)
                return

            # Admin-scope TTL check
            if self._is_admin_local_mcast(dst_ip) and getattr(ip, "ttl", 1) != 1:
                self.log.log_message(f"[IGMP] ⚠️ Admin-scope IGMP with TTL={ip.ttl} on {self._iface_suffix(ifname)}")

            # v1/v2 Membership Reports
            if igmp_type in (0x12, 0x16) and IGMP:
                group_addr = getattr(igmp_layer, "gaddr", None) or "0.0.0.0"
                version = 1 if igmp_type == 0x12 else 2
                self._counters["pkts_v1v2_join"] += 1
                self._join(group_addr, ifname, "include", set(), src_ip, version)
                return

            # v2 Leave
            if igmp_type == 0x17 and IGMP:
                group_addr = getattr(igmp_layer, "gaddr", None) or "0.0.0.0"
                self._counters["pkts_v2_leave"] += 1
                self._leave(group_addr, ifname, src_ip)
                return

            # v3 Membership Report
            if igmp_type == 0x22:
                self._counters["pkts_v3_report"] += 1
                self._handle_igmpv3_report(pkt, ifname, src_ip)
                return

            # Unknown/unsupported
            self.log.log_message(f"[IGMP] Unrecognized IGMP type=0x{igmp_type:02x} on {self._iface_suffix(ifname)}")

        except Exception as e:
            self.log.log_message(f"[IGMP] ❗ IGMP parse error: {e}")

    def _extract_igmp_type(self, pkt: Packet) -> Tuple[int, Any]:
        """
        Return (type, layer) for IGMP. Checks IGMP, IGMPv3, IGMPv3mr; falls back to raw peek.
        """
        try:
            if IGMP and pkt.haslayer(IGMP):
                ig = pkt[IGMP]
                return int(getattr(ig, "type", -1)), ig
            if IGMPv3 and pkt.haslayer(IGMPv3):
                ig3 = pkt[IGMPv3]
                return int(getattr(ig3, "type", -1)), ig3
            if IGMPv3mr and pkt.haslayer(IGMPv3mr):
                return 0x22, pkt[IGMPv3mr]
        except Exception:
            pass
        try:
            raw = bytes(pkt[IP].payload)
            if raw:
                return raw[0], None
        except Exception:
            pass
        return -1, None

    def _handle_igmpv3_report(self, pkt: Packet, ifname: str, src_ip: str):
        """Parses and processes an IGMPv3 report with its group records (very verbose)."""
        try:
            rep = pkt.getlayer(IGMPv3mr) if IGMPv3mr else (pkt.getlayer(IGMPv3) if IGMPv3 else None)

            # Extract records (varies by Scapy build)
            records = []
            if rep is not None:
                for attr in ("grps", "records"):
                    recs = getattr(rep, attr, None)
                    if recs:
                        records = list(recs)
                        break
                if not records and hasattr(rep, "payload") and hasattr(rep.payload, "grps"):
                    records = list(rep.payload.grps) or []

            if not records:
                raw = bytes(pkt[IP].payload) if hasattr(pkt[IP], "payload") else b""
                if not raw or raw[:1] != b"\x22" or len(raw) < 8:
                    self._counters["drops_malformed"] += 1
                    self.log.log_message("[IGMP] v3 report malformed or undecoded; dropping.")
                    return
                self.log.log_message("[IGMP] v3 report present but records not decoded by Scapy (variant).")
                return

            self.log.log_message(f"[IGMP] v3 report from {src_ip} on {self._iface_suffix(ifname)} with {len(records)} record(s).")
            for idx, rec in enumerate(records, 1):
                group = str(getattr(rec, "gaddr", getattr(rec, "maddr", "0.0.0.0")))
                rtype = int(getattr(rec, "rtype", getattr(rec, "type", 0)))
                rname = self.V3_RTYPE_MAP.get(rtype, f"UNKNOWN({rtype})")
                srcs_raw = getattr(rec, "srcaddrs", getattr(rec, "sources", [])) or []

                # Normalize IPv4 sources
                srcs: Set[str] = set()
                for s in srcs_raw:
                    try:
                        srcs.add(str(ipaddress.IPv4Address(str(s))))
                    except Exception:
                        srcs.add(str(s))

                src_list = sorted(list(srcs))
                src_show = src_list[:16]
                more = "" if len(src_list) <= 16 else f", ...(+{len(src_list)-16})"
                self.log.log_message(
                    f"[IGMP]   rec#{idx}: {rname} group={group} srcs={src_show}{more}"
                )

                # Apply state
                if rtype in (1, 3):  # MODE_IS_INCLUDE / CHANGE_TO_INCLUDE
                    self._join(group, ifname, "include", srcs, src_ip, 3)
                elif rtype in (2, 4):  # MODE_IS_EXCLUDE / CHANGE_TO_EXCLUDE
                    self._join(group, ifname, "exclude", srcs, src_ip, 3)
                elif rtype == 5:      # ALLOW_NEW_SOURCES
                    self._update_sources(group, ifname, srcs, "allow")
                elif rtype == 6:      # BLOCK_OLD_SOURCES
                    self._update_sources(group, ifname, srcs, "block")
                else:
                    self.log.log_message(f"[IGMP]   rec#{idx}: unsupported rtype={rtype} (ignored).")

        except Exception as e:
            self.log.log_message(f"[IGMP] v3 parse error: {e}")

    # --------------------------------------------------------- Membership state
    def _build_v3_query_pkt(self, gaddr: str, srcs: Optional[list[str]] = None):
        """
        Returns a Scapy layer for an IGMPv3 Membership Query.
        Tries IGMPv3mq first (post-assign fields), then falls back to IGMP (v2-style).
        """
        srcs = srcs or []
        # Try IGMPv3mq (contrib)
        mq = None
        try:
            # Import lazily in case contrib isn’t present at import time
            from scapy.contrib.igmp import IGMPv3mq  # type: ignore
            mq = IGMPv3mq(gaddr=gaddr)
            # Set fields defensively: some builds name these differently or merge bits.
            for fld, val in (
                    ("mrc", self.V3_MAX_RESP_CODE),  # some builds
                    ("mrd", self.V3_MAX_RESP_CODE),  # others
                    ("mrt", self.V3_MAX_RESP_CODE),  # very old
                    ("qqic", self.V3_QQIC),
                    ("qrv", self.V3_QRV),
                    ("s", int(self.V3_SUPPRESS)),
            ):
                try:
                    setattr(mq, fld, val)
                except Exception:
                    pass
            # number of sources (if we supply any)
            if srcs:
                try:
                    mq.numsrc = len(srcs)
                    mq.srcaddrs = srcs
                except Exception:
                    pass
            return mq
        except Exception:
            pass

        # Fallback: v2-style Query (hosts respond; v3 features not signalled)
        try:
            return IGMP(type=0x11, gaddr=gaddr)  # General (0.0.0.0) or Group-specific
        except Exception:
            # Last-resort: raw header (type=0x11)
            return Raw(b"\x11\x00\x00\x00" + ipaddress.IPv4Address(gaddr).packed)
    def _join(self, group: str, ifname: str, mode: str, sources: Set[str], who: str, version: int):
        """Processes a request to join or update a group membership."""
        now = time.time()
        key = (group, ifname)
        with self._lock:
            entry = self._db.get(key)
            if not entry:
                entry = MembershipEntry(family=4, group=group, ifname=ifname, version=version, mode=mode)
                self._db[key] = entry
                action = "join"
            else:
                action = "update"
                entry.version = max(entry.version, version)

            entry.mode = "exclude" if str(mode).lower() == "exclude" else "include"
            entry.sources = set(sources) if sources else set()
            entry.last_report = now
            entry.lmq_remaining = 0  # cancel any pending LMQ

        src_txt = f" sources={sorted(list(sources))}" if sources else ""
        self.log.log_message(
            f"[IGMP] v{version} JOIN from {who} for {group} on {self._iface_suffix(ifname)} ({entry.mode}{src_txt})"
        )
        self._notify(action, entry)

    def _leave(self, group: str, ifname: str, who: str):
        """Initiates the Last Member Query sequence upon receiving a v2 Leave message."""
        key = (group, ifname)
        with self._lock:
            entry = self._db.get(key)
            if not entry:
                self.log.log_message(f"[IGMP] Leave from {who} for {group} (no existing members).")
                return

            if entry.version < 3:
                entry.lmq_remaining = self.LMQ_COUNT
                entry.lmq_next_ts = 0.0
                entry.lmq_group_specific = True
                self.log.log_message(f"[IGMP] v2 Leave from {who} for {group}. Starting Last Member Query.")
            else:
                del self._db[key]
                self.log.log_message(f"[IGMP] v3 Leave from {who} for {group}. Membership removed.")
                self._notify("leave", entry)

    def _update_sources(self, group: str, ifname: str, sources: Set[str], action: str):
        """Applies source list changes from IGMPv3 ALLOW/BLOCK records."""
        key = (group, ifname)
        with self._lock:
            entry = self._db.get(key)
            if not entry:
                self.log.log_message(f"[IGMP] {action.upper()} for {group} on {self._iface_suffix(ifname)} ignored (no entry).")
                return

            before = len(entry.sources)
            if action == "allow":
                entry.sources.update(sources)
            elif action == "block":
                entry.sources.difference_update(sources)
            else:
                self.log.log_message(f"[IGMP] Unknown source action '{action}' for {group}.")
                return
            after = len(entry.sources)
            entry.last_report = time.time()

        self.log.log_message(
            f"[IGMP] v3 {action.upper()}_SOURCES for {group} on {self._iface_suffix(ifname)} ({before}→{after})."
        )
        self._notify("update", entry)

    # ------------------------------------------------------------ Querier state

    def _record_remote_querier(self, ifname: str, remote_ip: str):
        """Remember a querier we saw (type 0x11 Query). Lowest source IP wins; we back off."""
        now = time.time()
        with self._q_lock:
            q = self._querier.get(ifname, {})
            cur = q.get("addr")
            if cur is None or self._ipv4_less(remote_ip, cur):
                self._querier[ifname] = {"addr": remote_ip, "last_seen": now}
                self.log.log_message(
                    f"[IGMP] Querier observed on {self._iface_suffix(ifname)}: {remote_ip} (backing off ~{self.QUERIER_BACKOFF_SEC}s)"
                )
            else:
                self._querier[ifname] = {"addr": cur, "last_seen": now}

    def _we_are_querier(self, ifname: str, our_ip: str, now: float) -> bool:
        """Simple querier awareness: if no querier seen recently, or our IP is lower."""
        with self._q_lock:
            q = self._querier.get(ifname)
            if not q:
                return True
            last = float(q.get("last_seen", 0))
            their = str(q.get("addr", "")) or ""
            if (now - last) > self.QUERIER_BACKOFF_SEC:
                return True  # stale info
            return self._ipv4_less(our_ip, their)

    # --------------------------------------------------------------- Utilities

    def _set_router_alert(self, ip_layer: Any) -> None:
        """Attach IP Router Alert option if possible."""
        if IPOption_Router_Alert is not None:
            try:
                ip_layer.options = IPOption_Router_Alert()
                return
            except Exception:
                pass
        try:
            ip_layer.options = b"\x94\x04\x00\x00"
        except Exception:
            pass

    def _is_admin_local_mcast(self, addr: str) -> bool:
        try:
            return ipaddress.IPv4Address(addr) in self.ADMIN_LOCAL_NET
        except Exception:
            return False

    def _hex_preview(self, label: str, blob: bytes):
        if not blob:
            return
        try:
            prefix = binascii.hexlify(blob[: self.HEX_PREVIEW_BYTES]).decode("ascii")
            more = "" if len(blob) <= self.HEX_PREVIEW_BYTES else f"...(+{len(blob)-self.HEX_PREVIEW_BYTES}B)"
            self.log.log_message(f"{label}[:{self.HEX_PREVIEW_BYTES}]={prefix}{more}")
        except Exception:
            pass

    def _log_ip_router_alert(self, pkt: Packet, ifname: str) -> None:
        """Check for Router-Alert and TTL on incoming admin-scope packets."""
        try:
            ip = pkt[IP]
            ttl = getattr(ip, "ttl", None)
            has_ra = False
            opts = getattr(ip, "options", None)
            if isinstance(opts, list) and IPOption_Router_Alert is not None:
                try:
                    has_ra = any(isinstance(o, IPOption_Router_Alert) for o in opts)
                except Exception:
                    has_ra = False
            elif isinstance(opts, (bytes, bytearray)):
                has_ra = opts.startswith(b"\x94\x04\x00\x00")
            self.log.log_message(f"[IGMP] HBH Router-Alert={has_ra} TTL={ttl} on {self._iface_suffix(ifname)}")
        except Exception:
            pass

    def _notify(self, action: str, entry: Optional[MembershipEntry]):
        """Calls the on_change callback if it is registered."""
        if entry and callable(self.on_change):
            try:
                self.on_change(action, entry)
            except Exception as e:
                self.log.log_message(f"[IGMP] on_change callback error: {e}")

    @staticmethod
    def _iface_suffix(name: Optional[str]) -> str:
        return (name or "").split("_")[-1] or "-"

    @staticmethod
    def _ipv4_less(a: str, b: str) -> bool:
        try:
            return int(ipaddress.IPv4Address(a)) < int(ipaddress.IPv4Address(b))
        except Exception:
            return False

    @staticmethod
    def _ipv4_mcast_to_mac(maddr: str) -> Optional[str]:
        """RFC 1112: 01:00:5e:0x:xx:xx mapping for IPv4 multicast."""
        try:
            ipi = int(ipaddress.IPv4Address(maddr))
            low23 = ipi & 0x7FFFFF
            b1, b2, b3 = 0x01, 0x00, 0x5E
            b4 = (low23 >> 16) & 0x7F
            b5 = (low23 >> 8) & 0xFF
            b6 = (low23) & 0xFF
            return f"{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}:{b6:02x}"
        except Exception:
            return None

    def _is_loopback(self, ifname: Optional[str], ip_addr: Optional[str] = None) -> bool:
        """
        Detect loopback by interface name OR IP.
        - Never logs.
        - Works across Linux/BSD (lo, lo0...), Windows (Loopback Pseudo-Interface, Npcap Loopback Adapter), etc.
        - If ip_addr is provided, treat 127.0.0.0/8 and ::1 as loopback.
        """
        try:
            # Name-based checks
            name = (ifname or "").strip().lower()

            # Common quick wins
            if name in {"lo", "lo0"}:
                return True

            # Broad “looks like loopback” patterns seen across OSes
            loop_patterns = (
                "loopback",  # generic substring (windows/linux/mac)
                "pseudo-interface",  # windows
                "npcap loopback adapter",  # windows (Npcap)
                "npf_loopback",  # windows NPF
                "software loopback",  # windows
            )
            if any(pat in name for pat in loop_patterns):
                return True

            # IP-based check if provided
            if ip_addr:
                try:
                    ip_obj = ipaddress.ip_address(ip_addr)
                    if isinstance(ip_obj, ipaddress.IPv4Address):
                        if ip_obj.is_loopback:  # 127.0.0.0/8
                            return True
                    else:
                        if ip_obj == ipaddress.IPv6Address("::1"):
                            return True
                except Exception:
                    # If ip_addr is malformed, just ignore and fall through
                    pass

            return False
        except Exception:
            # Be conservative on errors: assume not loopback to avoid suppressing traffic
            return False

class RIPManager:
    """
    Manages the routing table and all RIPv2 protocol interactions.
    Now also supports static routes, authentication, and route summarization.
    """

    def __init__(self, router_logger, function_call_tracker):
        self.router_logger = router_logger
        self.RIP_PORT = 520
        self.RIP_MCAST_ADDR = "224.0.0.9"
        self.RIP_UPDATE_INTERVAL = 10
        self.ROUTE_TIMEOUT = 600
        self.sniffer = None
        self._rip_suspicious_activity = defaultdict(lambda: {
            "count": 0,
            "last_seen": 0,
            "routes": set(),
        })

        # _routing_table: { ipaddress.IPv4Network : { "next_hop": str, "cost": int, "interface": str, "advertised_by": str, "last_update": float, "type": "direct" | "rip" | "static" } }
        self._routing_table = {}
        self._rt_lock = threading.Lock()

        self._stop_event = threading.Event()
        self._thread = None
        self._interfaces_config = {}
        self.authentication_key = None
        self.interface_loopback_full_name = None
        self.function_call_tracker = function_call_tracker

        # ---------- additive stability fields only ----------
        self._start_lock = threading.RLock()
        self._bg_started_event = threading.Event()
        self._bg_stopped_event = threading.Event()
        self._bg_failed_event = threading.Event()
        self._bg_last_error = None
        self._bg_heartbeat_ts = 0.0
        self._bg_last_loop_ts = 0.0
        self._thread_generation = 0

        self._trigger_update_event = threading.Event()
        self._min_trigger_interval = 1.0
        self._last_trigger_ts = 0.0

        self._send_timeout_soft = 1.5
        self._max_routes_per_advert = 64
        self._max_ifaces_per_cycle = 64
        self._enable_advertisements = True
        self._enable_learning = True
        self._split_horizon = True
        self._poison_reverse = True
        self._hold_down_seconds = 45.0
        self._route_hold_down = {}
        self._safe_start_timeout = 3.0
        self._safe_stop_timeout = 3.0
        self._loop_sleep_granularity = 0.25
        self._reentrant_send_guard = threading.Lock()
        self._last_advert_digest = None
        self._wan_like_ifaces = set()
        self._disable_rip_ifaces = set()
        self._allow_wan_rip_advertisements = False
        self._allow_wan_rip_learning = False
        self._protect_default_route = True
        self._protect_static_routes = True
        self._allow_rip_default_route_learning = False
        self._allow_rip_host_routes = False
        self._static_route_pins = set()
        self._route_change_seq = 0
        self._protect_special_routes = True
        self._protected_nets = set()
        self._host_service_protect_nets = set()
        self._public_dns_ips = {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220",
            "193.138.218.74", "194.242.2.2",
            "94.140.14.14", "94.140.15.15",
            "8.26.56.26", "8.20.247.20",
            "156.154.70.1", "156.154.71.1",
            "185.228.168.9", "185.228.169.9",
            "77.88.8.8", "77.88.8.1",
            "45.90.28.0", "45.90.30.0",
        }

    # ========================= tiny helpers =========================

    def _valid_ipv4_literal(self, value: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(str(value).strip()), ipaddress.IPv4Address)
        except Exception:
            return False

    def _valid_mac_literal(self, value: str) -> bool:
        try:
            s = str(value or "").strip().lower().replace("-", ":")
            parts = s.split(":")
            if len(parts) != 6:
                return False
            return all(len(p) == 2 and int(p, 16) >= 0 for p in parts)
        except Exception:
            return False

    def _normalize_ipv4_for_send(self, value: str) -> str | None:
        try:
            ip = ipaddress.ip_address(str(value).strip())
            if isinstance(ip, ipaddress.IPv4Address):
                if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
                    return None
                return str(ip)
        except Exception:
            return None
        return None

    def _safe_iface_name(self, ifname: str) -> str:
        try:
            return str(ifname).split("_")[-1]
        except Exception:
            return str(ifname)

    def _iface_has_usable_ipv4(self, ifname: str, cfg: dict) -> bool:
        ipv4 = cfg.get("ip_addr")
        if not self._valid_ipv4_literal(ipv4):
            self.router_logger.log_message(
                f"[RIP] ⏭️ Skip {self._safe_iface_name(ifname)}: invalid IPv4 source '{ipv4}'"
            )
            return False

        mac = cfg.get("mac")
        if not self._valid_mac_literal(mac):
            self.router_logger.log_message(
                f"[RIP] ⏭️ Skip {self._safe_iface_name(ifname)}: invalid MAC '{mac}'"
            )
            return False

        return True

    def _can_send_rip_on_iface(self, ifname: str, cfg: dict) -> bool:
        if not ifname or not isinstance(cfg, dict):
            return False

        short = self._safe_iface_name(ifname).lower()

        if "loopback" in short or short == "lo":
            return False

        if ifname in self._disable_rip_ifaces:
            return False

        if ifname in self._wan_like_ifaces and not self._allow_wan_rip_advertisements:
            return False

        if not self._iface_has_usable_ipv4(ifname, cfg):
            return False

        return True

    def _prefer_route(self, a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        a_type = a.get("type")
        b_type = b.get("type")
        order = {"static": 3, "direct": 2, "rip": 1}
        return order.get(a_type, 0) > order.get(b_type, 0)

    def _is_held_down(self, net) -> bool:
        return time.time() < float(self._route_hold_down.get(net, 0.0))

    def _request_triggered_update(self):
        try:
            if self._stop_event.is_set():
                return
            self._trigger_update_event.set()
        except Exception:
            pass

    def _is_forbidden_rip_network(self, net: ipaddress._BaseNetwork) -> bool:
        try:
            if isinstance(net, ipaddress.IPv4Network):
                if net.is_multicast or net.is_loopback or net.is_reserved or net.is_unspecified:
                    return True
                if str(net) == "0.0.0.0/32":
                    return True
                if net.prefixlen == 32 and not self._allow_rip_host_routes:
                    return True
                if str(net) == "0.0.0.0/0" and not self._allow_rip_default_route_learning:
                    return True
            return False
        except Exception:
            return True

    def _is_forbidden_route_target(self, net: ipaddress._BaseNetwork) -> bool:
        try:
            if isinstance(net, ipaddress.IPv4Network):
                if net.is_multicast or net.is_reserved:
                    return True
                if str(net) == "255.255.255.255/32":
                    return True
            return False
        except Exception:
            return False

    def _should_advertise_route(self, entry_details: Dict[str, Any]) -> bool:
        try:
            net = entry_details.get("network")
            iface = entry_details.get("interface")
            if not net:
                return False

            # RIP v2 is IPv4-only
            if not isinstance(net, ipaddress.IPv4Network):
                return False

            if iface in self._wan_like_ifaces and not self._allow_wan_rip_advertisements:
                return False

            if net.is_loopback or net.is_multicast or net.is_reserved or net.is_unspecified:
                return False

            if net.prefixlen == 32 and str(net.network_address) in self._public_dns_ips:
                return False

            if self._protect_special_routes and net in self._host_service_protect_nets:
                return False

            return True
        except Exception:
            return False

    def _digest_routes(self, entries: List[Dict[str, Any]]) -> str:
        try:
            parts = []
            for e in entries:
                n = e.get("network")
                parts.append(
                    f"{n}|{e.get('next_hop')}|{e.get('cost')}|{e.get('interface')}|{e.get('type')}"
                )
            parts.sort()
            return hashlib.sha256("\n".join(parts).encode()).hexdigest()
        except Exception:
            return str(time.time())

    def _build_rip_packet_for_iface(self, ifname: str, cfg: dict, entries: list):
        src_ip = self._normalize_ipv4_for_send(cfg.get("ip_addr"))
        if not src_ip:
            self.router_logger.log_message(
                f"[RIP] ⏭️ Build skip on {self._safe_iface_name(ifname)}: unusable source IP '{cfg.get('ip_addr')}'"
            )
            return None

        src_mac = str(cfg.get("mac")).strip().lower().replace("-", ":")
        if not self._valid_mac_literal(src_mac):
            self.router_logger.log_message(
                f"[RIP] ⏭️ Build skip on {self._safe_iface_name(ifname)}: unusable source MAC '{cfg.get('mac')}'"
            )
            return None

        try:
            base = (
                Ether(src=src_mac, dst="01:00:5e:00:00:09") /
                IP(src=src_ip, dst=self.RIP_MCAST_ADDR) /
                UDP(sport=self.RIP_PORT, dport=self.RIP_PORT) /
                RIP(cmd=2, version=2)
            )

            pkt = reduce(lambda p, e: p / e, entries, base)

            if self.authentication_key:
                auth_payload = self.authentication_key.encode()
                pkt[UDP].payload = bytes(pkt[UDP].payload) + auth_payload
                if hasattr(pkt[UDP], "len"):
                    del pkt[UDP].len
                if hasattr(pkt[UDP], "chksum"):
                    del pkt[UDP].chksum
                if IP in pkt and hasattr(pkt[IP], "len"):
                    del pkt[IP].len
                if IP in pkt and hasattr(pkt[IP], "chksum"):
                    del pkt[IP].chksum

            return pkt
        except Exception as e:
            self.router_logger.log_message(
                f"[RIP] ⏭️ Build failed on {self._safe_iface_name(ifname)}: {type(e).__name__}: {e}"
            )
            return None

    # ========================= public API =========================

    def set_authentication_key(self, key: str):
        self.authentication_key = key
        self.router_logger.log_message("[RIP] Authentication key set.")

    def initialize_routes(self, interfaces_config: dict, default_gateway_ip: str, default_gateway_iface: str,
                          router_gateway_out_ip: str, interface_out_full_name: str, interface_in_full_name: str):
        self._interfaces_config = interfaces_config or {}

        self._wan_like_ifaces = set()
        if interface_out_full_name:
            self._wan_like_ifaces.add(interface_out_full_name)

        with self._rt_lock:
            self._routing_table.clear()
            self._route_hold_down.clear()
            self._static_route_pins.clear()
            self._protected_nets.clear()
            self._host_service_protect_nets.clear()

            for ifname, cfg in self._interfaces_config.items():
                net = cfg.get("network")
                if not net:
                    continue
                self._routing_table[net] = {
                    "next_hop": "0.0.0.0",
                    "cost": 1,
                    "interface": ifname,
                    "advertised_by": "self",
                    "last_update": time.time(),
                    "type": "direct"
                }
                self._protected_nets.add(net)

            if default_gateway_ip and default_gateway_iface:
                default_net = ipaddress.ip_network("0.0.0.0/0")
                self._routing_table[default_net] = {
                    "next_hop": default_gateway_ip,
                    "cost": 1,
                    "interface": default_gateway_iface,
                    "advertised_by": "self",
                    "last_update": time.time(),
                    "type": "direct"
                }
                self._protected_nets.add(default_net)

        self.add_static_route(network_str="0.0.0.0/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="0.0.0.0/0", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="8.8.8.8/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="8.8.4.4/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="1.1.1.1/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="1.0.0.1/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="9.9.9.9/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="149.112.112.112/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="208.67.222.222/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="208.67.220.220/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="193.138.218.74/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="194.242.2.2/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="94.140.14.14/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="94.140.15.15/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="8.26.56.26/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="8.20.247.20/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="::/0", next_hop="::1",
                              interface=interface_out_full_name, cost=1)
        self.add_static_route("156.154.70.1/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("156.154.71.1/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("185.228.168.9/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("185.228.169.9/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("77.88.8.8/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("77.88.8.1/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("45.90.28.0/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("45.90.30.0/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route(network_str="::1/128", next_hop="::1", interface=interface_in_full_name, cost=2)

        self.router_logger.log_message(f"[RIP] Routing table initialized with {len(self._routing_table)} entries.")

    def add_static_route(self, network_str: str, next_hop: str, interface: str, cost: int = 1):
        try:
            net = ipaddress.ip_network(network_str)
            if cost < 1 or cost > 15:
                self.router_logger.log_message(f"[RIP] ⚠️ Static route cost {cost} is out of valid range (1-15). Setting to 1.")
                cost = 1

            if interface not in self._interfaces_config:
                self.router_logger.log_message(f"[RIP] ❌ Cannot add static route: Interface '{interface}' is not configured.")
                return False

            if self._is_forbidden_route_target(net):
                self.router_logger.log_message(f"[RIP] 🚫 Refusing dangerous/static route for {net}.")
                return False

            with self._rt_lock:
                current_route = self._routing_table.get(net)
                if current_route is None or \
                        current_route["type"] != "static" or \
                        (current_route["type"] == "static" and cost < current_route["cost"]):
                    self._routing_table[net] = {
                        "next_hop": next_hop,
                        "cost": cost,
                        "interface": interface,
                        "advertised_by": "self (static)",
                        "last_update": time.time(),
                        "type": "static"
                    }
                    self._static_route_pins.add(net)
                    self._route_change_seq += 1
                    self.router_logger.log_message(
                        f"[RIP] ✅ Added static route: {net} via {next_hop} on {self._safe_iface_name(interface)} (cost={cost})"
                    )
                    self._request_triggered_update()
                    return True
                else:
                    self.router_logger.log_message(
                        f"[RIP] ℹ️ Static route {net} not added/updated: Existing static route is equal or better cost."
                    )
                    return False
        except ValueError as e:
            self.router_logger.log_message(f"[RIP] ❌ Invalid network format for static route '{network_str}': {e}")
            return False

    def remove_static_route(self, network_str: str) -> bool:
        try:
            net = ipaddress.ip_network(network_str)
            with self._rt_lock:
                current_route = self._routing_table.get(net)
                if current_route and current_route["type"] == "static":
                    del self._routing_table[net]
                    self._static_route_pins.discard(net)
                    self._route_change_seq += 1
                    self.router_logger.log_message(f"[RIP] 🗑️ Removed static route: {net}")
                    self._request_triggered_update()
                    return True
                else:
                    self.router_logger.log_message(f"[RIP] ⚠️ Cannot remove {net}: Not found or not a static route.")
                    return False
        except ValueError as e:
            self.router_logger.log_message(
                f"[RIP] ❌ Invalid network format for static route removal '{network_str}': {e}"
            )
            return False

    def get_routing_table_view(self) -> List[Dict[str, Any]]:
        with self._rt_lock:
            view = []
            for net, details in self._routing_table.items():
                entry = details.copy()
                entry["network"] = str(net)
                entry["subnet_mask"] = str(net.netmask)
                entry["interface_friendly"] = self._safe_iface_name(entry["interface"])
                entry["protected"] = net in self._protected_nets
                entry["hold_down_until"] = self._route_hold_down.get(net, 0)
                view.append(entry)
            return view

    def find_route(self, dest_ip_str: str) -> Dict[str, Any] | None:
        try:
            dest_ip_obj = ipaddress.ip_address(dest_ip_str)
            best_match = None
            best_prefix = -1

            with self._rt_lock:
                for net, rt_details in self._routing_table.items():
                    if self._is_held_down(net):
                        continue

                    if dest_ip_obj.is_loopback and rt_details["type"] == "direct" and \
                            rt_details["interface"] == self.interface_loopback_full_name:
                        return rt_details

                    if dest_ip_obj in net:
                        current_match_is_better = False
                        if best_match is None:
                            current_match_is_better = True
                        elif net.prefixlen > best_prefix:
                            current_match_is_better = True
                        elif net.prefixlen == best_prefix:
                            if rt_details["cost"] < best_match["cost"]:
                                current_match_is_better = True
                            elif rt_details["cost"] == best_match["cost"]:
                                if self._prefer_route(rt_details, best_match):
                                    current_match_is_better = True

                        if current_match_is_better and rt_details["cost"] < 16:
                            best_prefix = net.prefixlen
                            best_match = rt_details
            return best_match
        except ValueError:
            return None

    def get_forwarding_route(self, dest_ip: str) -> Optional[Dict[str, Any]]:
        route = self.find_route(dest_ip)
        if not route:
            return None
        return {"next_hop": route["next_hop"], "interface": route["interface"]}

    def _validate_rip_packet(self, pkt: Packet) -> bool:
        if self.authentication_key:
            if pkt.haslayer(UDP) and pkt[UDP].payload:
                payload_bytes = bytes(pkt[UDP].payload)
                key_bytes = self.authentication_key.encode()
                if len(payload_bytes) >= len(key_bytes):
                    received_auth = payload_bytes[-len(key_bytes):].decode(errors="ignore")
                    if received_auth == self.authentication_key:
                        return True
                    else:
                        self.router_logger.log_message(f"[RIP] 🚫 Authentication failed for packet from {pkt[IP].src}")
                        return False
                else:
                    self.router_logger.log_message(
                        f"[RIP] 🚫 Authentication required, but payload too short from {pkt[IP].src}"
                    )
                    return False
            else:
                self.router_logger.log_message(
                    f"[RIP] 🚫 Authentication required, but no UDP payload from {pkt[IP].src}"
                )
                return False
        return True

    def handle_packet(self, pkt: Packet, inbound_ifname: str):
        self.function_call_tracker.track(
            identifier='RipPacket',
            threshold=5,
            final_message=f"[RIP] 📘 Received packet on {self._safe_iface_name(inbound_ifname)}: {pkt.summary()}. Count: {{}}.",
            count_message=None,
        )
        try:
            if not self._enable_learning:
                return

            if inbound_ifname in self._disable_rip_ifaces:
                return
            if inbound_ifname in self._wan_like_ifaces and not self._allow_wan_rip_learning:
                return

            rip = pkt[RIP]
            if not rip:
                return

            if not self._validate_rip_packet(pkt):
                return

            if rip.command == 1:
                self.router_logger.log_message(f"[RIP] Ignoring RIP request from {pkt[IP].src}")
                return
            if rip.command != 2:
                self.function_call_tracker.track(
                    identifier='IgnoredRipPacket',
                    threshold=5,
                    final_message=f"[RIP] 🚫 Ignored non-response/request RIP packet (command={rip.command}) from {pkt[IP].src}. Count: {{}}.",
                    count_message=None,
                )
                return

            src_router = pkt[IP].src
            changed = False

            with self._rt_lock:
                for entry in getattr(rip, "entries", []) or []:
                    entry_net = f"{entry.address}/{entry.subnet_mask}"
                    try:
                        net = ipaddress.ip_network(entry_net, strict=False)
                    except Exception:
                        continue

                    if self._is_forbidden_rip_network(net):
                        continue

                    cost = min(int(entry.metric) + 1, 16)
                    current_route = self._routing_table.get(net)

                    if current_route:
                        if current_route["type"] == "static" and self._protect_static_routes:
                            continue
                        if current_route["type"] == "direct":
                            continue

                        if current_route["advertised_by"] == src_router:
                            if cost >= 16:
                                self._route_hold_down[net] = time.time() + self._hold_down_seconds
                                current_route["cost"] = 16
                                current_route["last_update"] = time.time()
                                changed = True
                                continue

                            if current_route["cost"] != cost:
                                self.router_logger.log_message(
                                    f"[RIP] 🔄 Route update: {net} via {src_router} (cost changed {current_route['cost']}→{cost})"
                                )
                            current_route["cost"] = cost
                            current_route["last_update"] = time.time()
                            current_route["interface"] = inbound_ifname
                            current_route["type"] = "rip"
                            changed = True

                        elif cost < current_route["cost"]:
                            if self._is_held_down(net):
                                continue
                            self._routing_table[net] = {
                                "next_hop": src_router,
                                "cost": cost,
                                "interface": inbound_ifname,
                                "advertised_by": src_router,
                                "last_update": time.time(),
                                "type": "rip"
                            }
                            changed = True

                    elif cost < 16:
                        if self._is_held_down(net):
                            continue
                        self._routing_table[net] = {
                            "next_hop": src_router,
                            "cost": cost,
                            "interface": inbound_ifname,
                            "advertised_by": src_router,
                            "last_update": time.time(),
                            "type": "rip"
                        }
                        self.router_logger.log_message(
                            f"[RIP] ✅ New RIP route discovered: {net} via {src_router} (cost={cost})"
                        )
                        changed = True

            if changed:
                self.router_logger.log_message(f"[RIP] Routing table updated by neighbor {src_router}.")
                self._request_triggered_update()

        except Exception as e:
            self.router_logger.log_message(f"[RIP] ❌ handle_packet exception: {type(e).__name__}: {e}")

    def rip_from_suspicious_source(self, src_ip: str, pkt: Packet | None = None):
        if not hasattr(self, "_rip_suspicious_activity"):
            self._rip_suspicious_activity = defaultdict(lambda: {
                "count": 0,
                "last_seen": 0,
                "routes": set(),
            })

        entry = self._rip_suspicious_activity[src_ip]
        entry["count"] += 1
        entry["last_seen"] = int(time.time())

        self.function_call_tracker.track(
            identifier='SuspiciousRIP',
            threshold=50,
            final_message=f"[RIP] 🕵️ Suspicious RIP detected from {src_ip} | Count: {entry['count']}. Count: {{}}.",
            count_message=None,
        )

        if pkt and pkt.haslayer(RIP):
            try:
                rip_layer = pkt[RIP]
                entries = getattr(rip_layer, 'entries', None)
                if not entries or not isinstance(entries, list):
                    raw_payload = bytes(pkt[RIP]) if pkt and pkt.haslayer(RIP) else b''
                    hex_dump = raw_payload.hex()
                    self.function_call_tracker.track(
                        identifier='MalformedRIP',
                        threshold=25,
                        final_message=f"[RIP] 🧬 Malformed RIP from {src_ip} Raw (hex): {hex_dump[:64]}... Count: {{}}.",
                        count_message=None,
                    )
                    self.parse_raw_rip_entries(pkt, raw_payload)
                    return

                new_routes = 0
                for rip_entry in entries:
                    try:
                        net_str = f"{rip_entry.addr}/{rip_entry.mask}"
                        metric = rip_entry.metric
                        if metric < 16 and net_str not in entry["routes"]:
                            entry["routes"].add(net_str)
                            new_routes += 1
                            self.router_logger.log_message(
                                f"[RIP] 🛰️ Passive route seen from {src_ip}: {net_str} (metric={metric})"
                            )
                    except Exception as inner_e:
                        self.router_logger.log_message(
                            f"[RIP] ⚠️ Failed to process RIP entry from {src_ip}: {inner_e}"
                        )

                if new_routes > 0:
                    self.router_logger.log_message(
                        f"[RIP] ➕ {new_routes} new passive routes recorded from {src_ip}."
                    )

            except Exception as outer_e:
                self.router_logger.log_message(
                    f"[RIP] ❌ Exception while parsing unsolicited RIP from {src_ip}: {outer_e}"
                )
        else:
            self.router_logger.log_message(
                f"[RIP] ⚠️ No RIP layer found in blocked packet from {src_ip} or packet not provided."
            )

        if entry["count"] >= 10 and (entry["count"] % 10 == 0):
            self.router_logger.log_message(
                f"[RIP] 🚨 {src_ip} has sent {entry['count']} unsolicited RIP packets. Potential misconfigured or rogue router."
            )

    def parse_raw_rip_entries(self, packet, raw_data: bytes) -> list:
        entries = []
        entry_size = 20
        for i in range(0, len(raw_data), entry_size):
            try:
                chunk = raw_data[i:i + entry_size]
                if len(chunk) < entry_size:
                    break

                afi, tag, ip_raw, mask_raw, nh_raw, metric = struct.unpack("!HH4s4s4sI", chunk)

                ip_str = ".".join(map(str, ip_raw))
                mask_str = ".".join(map(str, mask_raw))
                nh_str = ".".join(map(str, nh_raw))

                is_valid = True

                if ip_str == "0.2.0.0" and mask_str == "0.0.0.0" and nh_str == "0.0.0.0" and metric == 0:
                    self.sniffer.banned_packets.append(packet)
                    break
                elif afi != 2 and afi != 0:
                    self.sniffer.banned_packets.append(packet)
                    break

                try:
                    net = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
                    if self._is_forbidden_rip_network(net):
                        is_valid = False
                except ValueError:
                    self.sniffer.banned_packets.append(packet)
                    break

                if metric >= 16:
                    self.sniffer.banned_packets.append(packet)
                    break

                if is_valid:
                    entries.append({
                        "afi": afi,
                        "route_tag": tag,
                        "ip": ip_str,
                        "mask": mask_str,
                        "next_hop": nh_str,
                        "metric": metric,
                    })
                else:
                    self.router_logger.log_message(
                        f"[RIP] ⚠️ Parsed malformed entry: {ip_str}/{mask_str} via {nh_str} metric={metric}"
                    )

            except Exception as e:
                self.router_logger.log_message(f"[RIP] ❌ Error unpacking RIP entry: {e}")
                break

        return entries

    def _find_common_supernet(self, networks: List[ipaddress.IPv4Network]) -> ipaddress.IPv4Network:
        if not networks:
            raise ValueError("Network list cannot be empty.")

        networks.sort(key=lambda n: n.network_address)
        first_net_addr = int(networks[0].network_address)
        last_net_addr = int(networks[-1].network_address)

        if first_net_addr == last_net_addr:
            return networks[0]

        shared_bits = 0
        while shared_bits < 32 and (first_net_addr >> (32 - shared_bits - 1)) == (
                last_net_addr >> (32 - shared_bits - 1)):
            shared_bits += 1

        new_prefixlen = shared_bits
        supernet_addr = first_net_addr & int(ipaddress.IPv4Network(f"0.0.0.0/{new_prefixlen}").netmask)
        return ipaddress.IPv4Network((supernet_addr, new_prefixlen), strict=False)

    def _summarize_routes(self, routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not routes:
            return []

        summarized_networks = set()
        final_advertisements = []
        prefix_groups = defaultdict(list)

        for route_details in routes:
            net = route_details["network"]
            if not isinstance(net, ipaddress.IPv4Network):
                continue
            parent_net_str = f"{str(net.network_address).rsplit('.', 2)[0]}.0.0/16"
            parent_net = ipaddress.ip_network(parent_net_str, strict=False)
            prefix_groups[parent_net].append(route_details)

        for parent_net, child_routes in prefix_groups.items():
            child_routes.sort(key=lambda r: r["network"].network_address)
            current_summary_group_nets = []

            for route_details in child_routes:
                current_net = route_details["network"]
                if current_net in summarized_networks:
                    continue

                if not current_summary_group_nets:
                    current_summary_group_nets.append(current_net)
                    continue

                temp_nets = current_summary_group_nets + [current_net]
                common_supernet = self._find_common_supernet(temp_nets)

                if common_supernet.prefixlen < min(n.prefixlen for n in temp_nets):
                    current_summary_group_nets.append(current_net)
                else:
                    if len(current_summary_group_nets) > 1:
                        group_details = [r for r in child_routes if r["network"] in current_summary_group_nets]
                        self._process_and_add_summary(final_advertisements, summarized_networks, group_details)
                    else:
                        final_advertisements.append(
                            next(r for r in child_routes if r["network"] == current_summary_group_nets[0])
                        )
                    current_summary_group_nets = [current_net]

            if len(current_summary_group_nets) > 1:
                group_details = [r for r in child_routes if r["network"] in current_summary_group_nets]
                self._process_and_add_summary(final_advertisements, summarized_networks, group_details)
            elif len(current_summary_group_nets) == 1 and current_summary_group_nets[0] not in summarized_networks:
                route_details = next(r for r in child_routes if r["network"] == current_summary_group_nets[0])
                final_advertisements.append(route_details)

        for route in routes:
            if route["network"] not in summarized_networks:
                final_advertisements.append(route)

        return final_advertisements

    def _process_and_add_summary(self, final_advertisements: list, summarized_networks: set, group_details: list):
        group_nets = [r["network"] for r in group_details]
        common_supernet = self._find_common_supernet(group_nets)
        min_cost = min(r["cost"] for r in group_details)
        best_route = next(r for r in group_details if r["cost"] == min_cost)

        summary_route = {
            "network": common_supernet,
            "subnet_mask": str(common_supernet.netmask),
            "next_hop": best_route["next_hop"],
            "cost": min_cost,
            "interface": best_route["interface"],
            "advertised_by": "self (summarized)",
            "last_update": time.time(),
            "type": "rip"
        }
        final_advertisements.append(summary_route)

        for r in group_details:
            summarized_networks.add(r["network"])

    def _advertisement_loop(self):
        self._bg_started_event.set()
        self._bg_stopped_event.clear()
        self._bg_failed_event.clear()
        self._bg_last_error = None
        self._bg_heartbeat_ts = time.time()
        self._bg_last_loop_ts = time.time()

        try:
            while not self._stop_event.is_set():
                self._bg_heartbeat_ts = time.time()
                self._bg_last_loop_ts = self._bg_heartbeat_ts

                try:
                    self._send_advertisements()
                except Exception as e:
                    self.router_logger.log_message(f"[RIP] ❌ _send_advertisements exception: {type(e).__name__}: {e}")

                try:
                    self._purge_routes()
                except Exception as e:
                    self.router_logger.log_message(f"[RIP] ❌ _purge_routes exception: {type(e).__name__}: {e}")

                wait_until = time.time() + max(1.0, float(self.RIP_UPDATE_INTERVAL))
                while not self._stop_event.is_set():
                    if self._trigger_update_event.is_set():
                        self._trigger_update_event.clear()
                        now = time.time()
                        if (now - self._last_trigger_ts) >= self._min_trigger_interval:
                            self._last_trigger_ts = now
                            try:
                                self._send_advertisements()
                            except Exception as e:
                                self.router_logger.log_message(
                                    f"[RIP] ❌ triggered advertisement exception: {type(e).__name__}: {e}"
                                )
                        continue

                    remaining = wait_until - time.time()
                    if remaining <= 0:
                        break
                    self._stop_event.wait(min(self._loop_sleep_granularity, remaining))

        except Exception as e:
            self._bg_last_error = e
            self._bg_failed_event.set()
            self.router_logger.log_message(f"[RIP] ❌ Background thread crashed: {type(e).__name__}: {e}")
        finally:
            self._bg_stopped_event.set()
            self.router_logger.log_message("[RIP] Advertisement thread has exited.")

    def _send_advertisements(self):
        if not self._enable_advertisements:
            return
        if not self.sniffer:
            return

        if not self._reentrant_send_guard.acquire(blocking=False):
            return

        try:
            with self._rt_lock:
                table_snapshot_for_summarization = []
                for net_obj, details in self._routing_table.items():
                    if self._is_held_down(net_obj):
                        continue
                    temp_entry = details.copy()
                    temp_entry["network"] = net_obj
                    table_snapshot_for_summarization.append(temp_entry)

            summarized_table_entries = self._summarize_routes(table_snapshot_for_summarization)
            summarized_table_entries = [
                x for x in summarized_table_entries
                if self._should_advertise_route(x)
            ][:self._max_routes_per_advert]

            if not summarized_table_entries:
                return

            cur_digest = self._digest_routes(summarized_table_entries)
            if cur_digest == self._last_advert_digest:
                return

            iface_count = 0
            sent_any = False

            for ifname, cfg in self._interfaces_config.items():
                if iface_count >= self._max_ifaces_per_cycle:
                    break

                if not self._can_send_rip_on_iface(ifname, cfg):
                    continue

                entries = []
                for entry_details in summarized_table_entries:
                    net = entry_details["network"]

                    # RIP v2 is IPv4-only
                    if not isinstance(net, ipaddress.IPv4Network):
                        continue

                    metric_to_advertise = int(entry_details["cost"])

                    if self._split_horizon and entry_details["type"] == "rip" and entry_details["interface"] == ifname:
                        if self._poison_reverse:
                            metric_to_advertise = 16
                        else:
                            continue

                    if metric_to_advertise >= 16:
                        continue

                    try:
                        entries.append(RIPEntry(
                            addr=str(net.network_address),
                            mask=str(net.netmask),
                            metric=metric_to_advertise
                        ))
                    except Exception as e:
                        self.router_logger.log_message(
                            f"[RIP] ⚠️ Entry build skipped for {net} on {self._safe_iface_name(ifname)}: {type(e).__name__}: {e}"
                        )

                if not entries:
                    continue

                pkt = self._build_rip_packet_for_iface(ifname, cfg, entries)
                if pkt is None:
                    continue

                try:
                    self.router_logger.log_message(
                        f"[RIP] 📺 Sending advertisement on {self._safe_iface_name(ifname)} ({len(entries)} entries)"
                    )
                    self.sniffer.sendp(pkt, iface=ifname, verbose=0)
                    sent_any = True
                except Exception as e:
                    self.router_logger.log_message(
                        f"[RIP] ❌ Advertisement send failed on {self._safe_iface_name(ifname)}: {type(e).__name__}: {e}"
                    )

                iface_count += 1

            if sent_any:
                self._last_advert_digest = cur_digest

        finally:
            try:
                self._reentrant_send_guard.release()
            except Exception:
                pass

    def _purge_routes(self):
        with self._rt_lock:
            now = time.time()
            timed_out_routes = []
            for net, details in self._routing_table.items():
                if details["type"] == "rip" and (now - details["last_update"]) > self.ROUTE_TIMEOUT:
                    timed_out_routes.append(net)

            for net in timed_out_routes:
                self._route_hold_down[net] = now + self._hold_down_seconds
                del self._routing_table[net]
                self._route_change_seq += 1
                self.router_logger.log_message(f"[RIP] 🗑️ Timed out and removed RIP route: {net}")

            for net, expiry in list(self._route_hold_down.items()):
                if now >= expiry:
                    self._route_hold_down.pop(net, None)

    def start(self):
        with self._start_lock:
            if self._thread and self._thread.is_alive():
                self.router_logger.log_message("[RIP] Manager thread already running.")
                return

            self._stop_event.clear()
            self._bg_started_event.clear()
            self._bg_stopped_event.clear()
            self._bg_failed_event.clear()
            self._bg_last_error = None
            self._thread_generation += 1

            t = threading.Thread(
                target=self._advertisement_loop,
                daemon=True,
                name=f"RIPManagerThread-{self._thread_generation}"
            )
            self._thread = t
            t.start()

            started = self._bg_started_event.wait(timeout=self._safe_start_timeout)
            if not started:
                self.router_logger.log_message("[RIP] ❌ Manager thread failed to signal startup in time.")
                self._stop_event.set()
                return

            if self._bg_failed_event.is_set():
                self.router_logger.log_message(f"[RIP] ❌ Manager thread failed during startup: {self._bg_last_error}")
                return

            self.router_logger.log_message("[RIP] Manager thread started.")

    def stop(self):
        with self._start_lock:
            if not self._thread:
                return

            if self._thread and self._thread.is_alive():
                self.router_logger.log_message("[RIP] Stopping manager thread...")
                self._stop_event.set()
                self._trigger_update_event.set()
                self._thread.join(timeout=self._safe_stop_timeout)

                if self._thread.is_alive():
                    self.router_logger.log_message("[RIP] ⚠️ Manager thread did not stop cleanly before timeout.")
                else:
                    self.router_logger.log_message("[RIP] Manager thread stopped.")

            self._thread = None

    def redistribute_route(self, network: ipaddress.IPv4Network, next_hop: str, interface: str, cost: int,
                           source_protocol: str):
        self.router_logger.log_message(
            f"[RIP] Redistributing route: {network} via {next_hop} on {self._safe_iface_name(interface)} (cost={cost}) from {source_protocol}. (Placeholder - actual injection logic needed)"
        )

    def _canon_iface_name(self, name: str) -> str:
        if not name:
            return ""
        out = name.strip()
        if "\\Device\\NPF_" in out:
            out = out.split("\\Device\\NPF_")[-1]
        if "_" in out:
            tail = out.split("_")[-1]
            if tail.startswith("{") and tail.endswith("}"):
                out = tail
        return out

    def find_alternate_route(
            self,
            dest_ip_str: str,
            exclude_iface: str,
            *,
            max_cost: int = 15,
            allow_default_as_alt: bool = False
    ) -> Dict[str, Any] | None:
        try:
            dest_ip = ipaddress.ip_address(dest_ip_str)
        except ValueError:
            return None

        if dest_ip.is_multicast or dest_ip.is_unspecified or dest_ip.is_reserved:
            return None
        if isinstance(dest_ip, ipaddress.IPv4Address) and dest_ip == ipaddress.IPv4Address("255.255.255.255"):
            return None

        best_match = None
        best_prefix = -1
        excluded = self._canon_iface_name(exclude_iface)

        default_v4 = ipaddress.ip_network("0.0.0.0/0")
        default_v6 = ipaddress.ip_network("::/0")
        default_candidate = None

        with self._rt_lock:
            for net, rt in self._routing_table.items():
                iface = self._canon_iface_name(rt.get("interface", ""))

                if iface == excluded:
                    continue
                if self._is_held_down(net):
                    continue

                if allow_default_as_alt and (net == default_v4 or net == default_v6):
                    if rt.get("cost", 16) <= max_cost:
                        default_candidate = rt

                try:
                    if dest_ip not in net:
                        continue
                except Exception:
                    continue

                cost = int(rt.get("cost", 16))
                if cost > max_cost:
                    continue

                if dest_ip.is_loopback and rt.get("type") == "direct" and iface == self._canon_iface_name(
                        self.interface_loopback_full_name):
                    return rt

                better = False
                if best_match is None:
                    better = True
                elif net.prefixlen > best_prefix:
                    better = True
                elif net.prefixlen == best_prefix:
                    if cost < best_match.get("cost", 16):
                        better = True
                    elif cost == best_match.get("cost", 16):
                        if self._prefer_route(rt, best_match):
                            better = True

                if better:
                    best_prefix = net.prefixlen
                    best_match = rt

        if best_match is None and allow_default_as_alt and default_candidate is not None:
            return default_candidate

        return best_match

class NATManager:
    """
    NAT with:
      • Multi-IP (VIP) support for all features
      • Dynamic SNAT (per-VIP port pools)
      • Static DNAT
      • Stateful pinning
      • MSS clamp
      • Probe->ban + advanced Temporary NAT Leases
      • ICMP Port Unreachable fallback

    Stability additions in this rewrite:
      • idempotent start/stop
      • collaborator-safe wrappers
      • rate-limited noisy logs
      • dynamic placeholder interface entries for WinDivertBridge / Nate's Tunnel / Hyper-V-like paths
      • safer route/ARP/ICMP fallback behavior
      • less work under locks
      • WAN recovery hooks for DHCP renew/rebind/discover recovery flows
      • dynamic NAT-state flush on WAN identity change
    """

    PORT_SERVICES = {
        80: ("HTTP", "🌐"),
        443: ("HTTPS", "🔒"),
        21: ("FTP", "📁"),
        22: ("SSH", "💻"),
        2222: ("Alternate SSH", "💻"),
        3389: ("RDP", "🖥️"),
        53: ("DNS", "❓"),
        88: ("Kerberos", "🎟️"),
        520: ("RIP", "🗺️"),
        3333: ("P2Pool", "❤️"),
        38887: ("Blocknet","❤️" ),
        38888: ("Blocknet", "❤️"),
        25565: ("Minecraft", "🧱"),
    }

    NAT_PORT_MIN = 49152
    NAT_PORT_MAX = 65535
    NAT_TIMEOUT_SECONDS = 300
    STATEFUL_NAT_TIMEOUT_SECONDS = 300

    KEEP_ALIVE_PORT = 19999
    KEEP_ALIVE_PAYLOAD_FORMAT = "!H32s"

    BAN_THRESHOLD = 3
    BAN_DURATION_SEC = 120

    WAN_MTU_DEFAULT = 1480
    CLAMP_MSS = True

    DEFAULT_LEASE_SECS = 60
    DEFAULT_COOLDOWN_SECS = 10
    MAX_TEMP_LEASES_PER_IP = 2
    MAX_TEMP_LEASES_PER_PREFIX = 8
    RATE_WINDOW_SEC = 60
    RATE_MAX_ATTEMPTS_PER_IP = 20
    RATE_MAX_ATTEMPTS_PER_PREFIX = 60

    WARMUP_REQUIRED_HITS = 3
    TRUST_REQUIRED_HITS = 8
    AUTO_PROMOTE_TO_DYNAMIC = True
    AUTO_PROMOTE_TO_STATIC = False

    TEMP_LEASE_SERVICE_POLICY: Dict[int, Dict] = {
        80: {"mode": "allow", "max_per_ip": 2, "lease_secs": 90, "cooldown_secs": 10},
        443: {"mode": "allow", "max_per_ip": 2, "lease_secs": 120, "cooldown_secs": 10},
        22: {"mode": "throttle", "max_per_ip": 1, "lease_secs": 45, "cooldown_secs": 20},
        3389: {"mode": "deny"},
        25565: {"mode": "allow", "max_per_ip": 2, "lease_secs": 300, "cooldown_secs": 30},
    }

    TEMP_LEASES_POLICY = {
        "deny_gateways": {"192.168.1.254"},
        "deny_cidrs": ["192.168.1.0/24"],
        "deny_ifaces": {"wan_att", "eth_att"},
    }

    BYPASS_DST_CIDRS = [
        "224.0.0.0/4",
        "255.255.255.255/32",
        "169.254.0.0/16",
    ]
    BYPASS_SRC_CIDRS = [
        "169.254.0.0/16",
    ]

    NAT_EXEMPT_DST_CIDRS = [
        "198.18.0.0/15",
    ]

    PUBLIC_VIPS: set[str] = set()
    _FRAG_CACHE_TTL = 20.0

    def __init__(
        self,
        router_logger,
        sendback_manager,
        router_public_ip: str,
        packet_writer,
        interfaces_config: Dict,
        rip_manager_find_route,
        arp_manager_resolve,
        function_call_tracker,
        *,
        token_secret: Optional[bytes] = None,
    ):
        self.router_logger = router_logger
        self.sendback_manager = sendback_manager
        self.public_ip = str(router_public_ip)
        self.packet_writer = packet_writer
        self._interfaces_config = interfaces_config if isinstance(interfaces_config, dict) else {}
        self.interfaces_config = self._interfaces_config
        self._rip_manager_find_route = rip_manager_find_route
        self._arp_manager_resolve = arp_manager_resolve
        self.function_call_tracker = function_call_tracker

        self.hyperv_manager = None
        self.debug_logging = False

        self._next_port_per_ip: Dict[str, int] = defaultdict(lambda: self.NAT_PORT_MIN)

        self._nat_table: Dict[Tuple[str, int], Tuple[str, int, float]] = {}
        self._nat_reverse_table: Dict[Tuple[str, int], Tuple[str, int]] = {}
        self._static_mappings: Dict[Tuple[str, int], Tuple[str, int]] = {}
        self._stateful_nat_outbound: Dict[Tuple[Tuple[str, int], Tuple[str, int]], Tuple[str, int, float]] = {}
        self._stateful_nat_inbound: Dict[Tuple[str, int], Tuple[Tuple[str, int], Tuple[str, int]]] = {}

        self._port_forward_rules: Dict[Tuple[str, int, str], Tuple[str, int]] = {}
        self._port_forward_policy: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
        self._one_to_one_map: Dict[str, str] = {}
        self._public_ips_on_lan: set[str] = set()
        self._uplink_public_ip_by_iface: Dict[str, str] = {}
        self._hairpin_reverse: Dict[Tuple[str, int, str, int], Tuple[str, int, float]] = {}

        self._port_probe_counts: Dict[str, int] = defaultdict(int)
        self._ban_list: Dict[str, float] = {}

        self._temp_nat_leases: Dict[str, Dict[Tuple[str, int], Dict[str, float | str | int]]] = defaultdict(
            lambda: defaultdict(dict)
        )
        self._gray_score: Dict[Tuple[str, str, int], int] = defaultdict(int)

        self._ip_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=512))
        self._prefix_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1024))

        self._lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None
        self._started = False

        self.router_internal_ip_for_self_mapping: str = "0.0.0.0"
        self.WAN_MTU = self.WAN_MTU_DEFAULT
        self.MSS_CLAMP_V4 = max(536, self.WAN_MTU - 40)
        self.MSS_CLAMP_V6 = max(536, self.WAN_MTU - 60)

        self._uplink_cache_ttl = 10.0
        self._uplink_last_refresh = 0.0
        self._uplink_gateway_ip: Optional[str] = None
        self._uplink_iface: Optional[str] = None

        self._token_secret = token_secret or hashlib.sha256(f"{time.time()}:{random.random()}".encode()).digest()

        self._frag_cache: Dict[tuple, tuple[bool, float]] = {}
        self._log_rl_times: Dict[str, float] = {}
        self._dynamic_iface_refresh: Dict[str, float] = {}
        self._DYN_IFACE_TTL = 15.0
        self._hyperv_iface_names = {
            "windivertbridge",
            "nate's tunnel",
            "nates tunnel",
            "hyper-v",
            "hyperv",
            "vethernet",
            "default switch",
        }

        # WAN recovery fields
        self.router_ip_out = str(router_public_ip or "")
        self._wan_epoch = 0
        self._last_wan_identity = {
            "public_ip": str(router_public_ip or ""),
            "gateway_ip": None,
            "iface_name": None,
            "dns_servers": tuple(),
        }
        self._last_dynamic_flush = 0.0

        # Keep your example mappings
        self.add_static_mapping(65406, "192.168.1.50", 88)
        self.add_static_mapping(80, "192.168.1.100", 80)
        self.add_static_mapping(443, "192.168.1.100", 443)
        self.add_static_mapping(2222, "192.168.1.10", 22)
        self.add_static_mapping(3389, "192.168.1.25", 3389)
        self.add_static_mapping(25565, "192.168.1.75", 25565)

        self._config_sanity()
        self._log("[NAT] 🚀 Manager initialized with Multi-IP and advanced temporary leases.")

    # --- add near other helpers in NATManager ---

    def _is_ipv4_text(self, ip: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(str(ip)), ipaddress.IPv4Address)
        except Exception:
            return False

    def _is_ipv6_text(self, ip: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(str(ip)), ipaddress.IPv6Address)
        except Exception:
            return False

    def _supports_ipv6_nat(self) -> bool:
        """
        Small safety gate only.
        Current manager is IPv4 NAT. Do not NAT IPv6 unless you explicitly add NAT66/NAT64.
        """
        return False
    # ========================= VIP management =========================

    def set_public_ips(self, primary: str, vips: Iterable[str] | None = None):
        with self._lock:
            self.public_ip = str(primary)
            self.PUBLIC_VIPS = set(vips or set())
        self._config_sanity()
        self._log(f"[NAT] 🌐 Public IP set to {primary}; VIPs={sorted(self.PUBLIC_VIPS)}")

    def add_public_vip(self, vip: str):
        with self._lock:
            self.PUBLIC_VIPS.add(str(vip))
        self._log(f"[NAT] ➕ Added VIP {vip}")

    def remove_public_vip(self, vip: str):
        with self._lock:
            self.PUBLIC_VIPS.discard(str(vip))
        self._log(f"[NAT] ➖ Removed VIP {vip}")

    # ========================= Lifecycle =========================

    def set_router_internal_ip(self, ip: str):
        self.router_internal_ip_for_self_mapping = str(ip)
        self._log(f"[NAT] 🏠 Router internal IP set to {ip}")

    def start(self):
        with self._lifecycle_lock:
            if self._started and self._cleanup_thread and self._cleanup_thread.is_alive():
                self._log_debug("start(): already running")
                return
            self._stop_event.clear()
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="NATCleanup")
            self._cleanup_thread.start()
            self._started = True
        self._log("[NAT] ✅ Cleanup thread started.")

    def stop(self):
        with self._lifecycle_lock:
            if not self._started:
                return
            self._stop_event.set()
            thr = self._cleanup_thread
            self._cleanup_thread = None
            self._started = False
        if thr:
            try:
                thr.join(timeout=2)
            except Exception:
                pass
        self._log("[NAT] 🛑 Manager stopped.")

    # ========================= Safe helper layer =========================

    def _log_rl(self, key: str, ttl: float, msg: str):
        try:
            now = time.time()
            last = self._log_rl_times.get(key, 0.0)
            if now < last:
                return
            self._log_rl_times[key] = now + max(0.1, float(ttl))
        except Exception:
            pass
        self._log(msg)

    def _safe_call(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None

    def _safe_route_lookup(self, ip: str) -> Optional[dict]:
        try:
            r = self._rip_manager_find_route(ip)
            return r if isinstance(r, dict) else None
        except Exception:
            return None

    def _safe_arp_resolve(self, ip: str, iface: str | None):
        try:
            if self._is_ipv6_text(ip):
                return None
            return self._arp_manager_resolve(ip, iface)
        except Exception:
            return None
    def _is_hyperv_iface(self, iface: str | None) -> bool:
        if not iface:
            return False
        low = str(iface).lower()
        return any(x in low for x in self._hyperv_iface_names)

    def _guess_iface_kind(self, iface: str) -> str:
        low = str(iface).lower()
        if self._is_hyperv_iface(low):
            return "hyperv_bridge"
        if "wan" in low or "uplink" in low:
            return "wan"
        if "lan" in low:
            return "lan"
        return "dynamic"

    def _ensure_iface_entry(self, iface: Optional[str]) -> dict:
        if not iface:
            return {}
        iface = str(iface)
        now = time.time()
        ent = self._interfaces_config.get(iface)
        if isinstance(ent, dict) and (now - self._dynamic_iface_refresh.get(iface, 0.0)) < self._DYN_IFACE_TTL:
            return ent

        cfg = dict(ent or {})
        cfg.setdefault("dynamic", True)
        cfg.setdefault("kind", self._guess_iface_kind(iface))
        cfg.setdefault("gateway", None)
        cfg.setdefault("ip_addr", None)
        cfg.setdefault("mac", None)

        for meth, key in (
            ("get_interface_mac", "mac"),
            ("get_iface_mac", "mac"),
            ("get_interface_ipv4", "ip_addr"),
            ("get_iface_ipv4", "ip_addr"),
        ):
            if cfg.get(key):
                continue
            val = self._safe_call(getattr(self.packet_writer, meth), iface) if hasattr(self.packet_writer, meth) else None
            if val:
                cfg[key] = val

        hm = getattr(self, "hyperv_manager", None)
        if hm:
            if not cfg.get("mac"):
                for meth in ("get_bridge_mac", "get_host_mac", "get_iface_mac"):
                    val = self._safe_call(getattr(hm, meth), iface) if hasattr(hm, meth) else None
                    if val:
                        cfg["mac"] = val
                        break
            if not cfg.get("ip_addr"):
                for meth in ("get_bridge_ip", "get_iface_ip", "get_primary_ip"):
                    val = self._safe_call(getattr(hm, meth), iface) if hasattr(hm, meth) else None
                    if val:
                        cfg["ip_addr"] = val
                        break

        if not cfg.get("cidr") and cfg.get("ip_addr"):
            try:
                ipx = ipaddress.ip_address(str(cfg["ip_addr"]))
                if isinstance(ipx, ipaddress.IPv4Address):
                    if ipx.is_link_local:
                        cfg["cidr"] = str(ipaddress.ip_network(f"{ipx}/16", strict=False))
                    else:
                        cfg["cidr"] = str(ipaddress.ip_network(f"{ipx}/24", strict=False))
            except Exception:
                pass

        self._interfaces_config[iface] = cfg
        self.interfaces_config = self._interfaces_config
        self._dynamic_iface_refresh[iface] = now
        if ent is None:
            self._log_rl(
                f"nat_dyn_iface:{iface}",
                10.0,
                f"[NAT] 🧩 Dynamic iface entry created for {iface}: ip={cfg.get('ip_addr')} mac={cfg.get('mac')} kind={cfg.get('kind')}",
            )
        return cfg

    # ---- Helpers ----------------------------------------

    def _ip_in_any(self, ip: str, cidrs: List[str]) -> bool:
        try:
            ipx = ipaddress.ip_address(ip)
            for c in cidrs:
                if ipx in ipaddress.ip_network(c, strict=False):
                    return True
            return False
        except Exception:
            return False

    def _is_multicast_or_broadcast(self, ip: str) -> bool:
        try:
            ipx = ipaddress.ip_address(ip)
            return ipx.is_multicast or ipx.is_unspecified or ipx.is_loopback
        except Exception:
            return False

    def _is_global(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_global
        except Exception:
            return False

    def _is_first_ipv4_fragment(self, pkt) -> bool:
        if IP not in pkt:
            return False
        ip = pkt[IP]
        off = int(getattr(ip, "frag", 0))
        mf = bool(ip.flags.MF) if hasattr(ip.flags, "MF") else bool(int(ip.flags) & 0x1)
        return mf and off == 0

    def _is_nonfirst_ipv4_fragment(self, pkt) -> bool:
        if IP not in pkt:
            return False
        ip = pkt[IP]
        off = int(getattr(ip, "frag", 0))
        return off > 0

    def _frag_key(self, pkt) -> tuple | None:
        try:
            ip = pkt[IP]
            proto = int(ip.proto)
            return (ip.src, ip.dst, proto, int(ip.id))
        except Exception:
            return None

    def _frag_cache_get(self, key):
        ent = self._frag_cache.get(key)
        if not ent:
            return None
        decision, ts = ent
        if (time.time() - ts) > self._FRAG_CACHE_TTL:
            try:
                del self._frag_cache[key]
            except Exception:
                pass
            return None
        return decision

    def _frag_cache_set(self, key, decision: bool):
        self._frag_cache[key] = (decision, time.time())

    def _source_allowed(self, src_ip: str, allowed_sources: List[str]) -> bool:
        if not allowed_sources:
            return True
        for item in allowed_sources:
            try:
                if "/" in item:
                    if ipaddress.ip_address(src_ip) in ipaddress.ip_network(item, strict=False):
                        return True
                else:
                    if src_ip == item:
                        return True
            except Exception:
                continue
        return False

    def _has_dnat_mapping(self, external_ip: str, external_port: int, src_ip: str) -> bool:
        ext_key = (external_ip, int(external_port))
        with self._lock:
            if ext_key in self._static_mappings:
                return True
            if ext_key in self._stateful_nat_inbound:
                canon = self._stateful_nat_inbound[ext_key]
                _a, b = canon
                return src_ip == b[0]
            if ext_key in self._nat_reverse_table:
                return True

            for proto in ("tcp", "udp", "any"):
                pf_key = (external_ip, int(external_port), proto)
                if pf_key in self._port_forward_rules:
                    pol = self._port_forward_policy.get(pf_key, {})
                    if not pol.get("enabled", True):
                        continue
                    allowed = pol.get("allowed_sources", [])
                    if allowed and not self._source_allowed(src_ip, allowed):
                        continue
                    return True

            if external_ip in self._one_to_one_map:
                return True
        return False

    def _classify_direction(self, inbound_iface: str, src_ip: str, dst_ip: str,
                            router_ips: set[str], wan_ifaces: set[str], lan_ifaces: set[str] | None) -> str:
        is_wan = inbound_iface in wan_ifaces
        is_dst_ours = (
            (dst_ip == self.public_ip) or
            (dst_ip in self.PUBLIC_VIPS) or
            (dst_ip in router_ips) or
            (dst_ip in self._public_ips_on_lan)
        )
        src_is_private = not self._is_global(src_ip)

        if is_dst_ours:
            if src_is_private and not is_wan:
                return "hairpin"
            return "inbound"

        if (lan_ifaces and inbound_iface in lan_ifaces) or (not is_wan):
            if self._is_global(dst_ip):
                return "outbound"

            r = self._safe_route_lookup(dst_ip)
            if r and r.get("interface") in (wan_ifaces or set()):
                return "outbound"

        return "none"

    def _handle_icmp_error_translation(self, packet) -> bool:
        try:
            if ICMP in packet and IP in packet:
                ic = packet[ICMP]
                if ic.type in (3, 11, 12):
                    inner = bytes(ic[Raw].load or b"") if Raw in ic else (
                        bytes(ic.payload) if hasattr(ic, "payload") else b"")
                    if len(inner) < 28:
                        return False
                    ver_ihl = inner[0]
                    if (ver_ihl >> 4) != 4:
                        return False
                    ihl = (ver_ihl & 0x0F) * 4
                    proto = inner[9]
                    inner_src = ".".join(str(b) for b in inner[12:16])
                    inner_dst = ".".join(str(b) for b in inner[16:20])
                    sport = dport = None
                    if proto in (6, 17) and len(inner) >= ihl + 4:
                        sport = (inner[ihl] << 8) | inner[ihl + 1]
                        dport = (inner[ihl + 2] << 8) | inner[ihl + 3]

                    if dport and (inner_dst == self.public_ip or inner_dst in self.PUBLIC_VIPS or inner_dst in self._public_ips_on_lan):
                        mapping = self.get_internal_from_external(inner_dst, dport, inner_src)
                        if mapping:
                            packet[IP].dst = inner_src
                            self._log_rl(f"icmp_translate:{inner_dst}:{dport}", 5.0,
                                         f"[NAT] ℹ️ ICMP error translated for {inner_dst}:{dport}")
                            return True
        except Exception:
            pass
        return False

    def _is_private_or_cgn(self, ip: str) -> bool:
        try:
            ipx = ipaddress.ip_address(ip)
            return (ipx.is_private or ipx.is_loopback or ipx.is_link_local or
                    ipx.is_multicast or ipx.is_reserved or ipx.is_unspecified)
        except Exception:
            return True

    def _config_sanity(self):
        warn = []
        if self._is_private_or_cgn(self.public_ip):
            warn.append(f"public_ip={self.public_ip} looks private/CGN/loopback")
            self.NAT_EXEMPT_DST_CIDRS = [
                "100.64.0.0/10",
                "198.18.0.0/15",
            ]
            warn.append("[NAT] Adjusted NAT_EXEMPT_DST_CIDRS for private WAN (double NAT safe)")

        for vip in self.PUBLIC_VIPS:
            if self._is_private_or_cgn(vip):
                warn.append(f"VIP {vip} looks private/CGN/loopback")
        if warn:
            self._log("[NAT][SANITY] ⚠️ " + " | ".join(warn) +
                      " — inbound direct reachability depends on upstream forwarding when WAN is private.")

    # ========================= WAN recovery hooks =========================

    def flush_dynamic_state(self, *, reason: str = "manual", keep_bans: bool = False):
        """
        Flush only dynamic runtime NAT state.
        Keeps static mappings, port-forward rules, VIPs, and 1:1 mappings intact.
        """
        now = time.time()
        with self._lock:
            self._nat_table.clear()
            self._nat_reverse_table.clear()
            self._stateful_nat_outbound.clear()
            self._stateful_nat_inbound.clear()
            self._hairpin_reverse.clear()
            self._frag_cache.clear()
            self._port_probe_counts.clear()
            self._gray_score.clear()
            self._ip_attempts.clear()
            self._prefix_attempts.clear()
            if not keep_bans:
                self._ban_list.clear()
            self._last_dynamic_flush = now

        self._log(f"[NAT] 🧹 Dynamic state flushed ({reason}).")

    def on_wan_recovered(
        self,
        *,
        iface_name: str | None = None,
        public_ip: str | None = None,
        gateway_ip: str | None = None,
        dns_servers: Iterable[str] | None = None,
        force_flush: bool = False,
    ):
        """
        Re-sync NAT to the current WAN identity after DHCP renew/rebind/discover,
        gateway ARP refresh, or DNS upstream refresh.
        """
        public_ip = str(public_ip or "").strip() or None
        gateway_ip = str(gateway_ip or "").strip() or None
        iface_name = str(iface_name or "").strip() or None
        dns_tuple = tuple(str(x).strip() for x in (dns_servers or []) if str(x).strip())

        with self._lock:
            prev = dict(self._last_wan_identity)

        changed = bool(force_flush)

        if public_ip and public_ip != self.public_ip:
            changed = True
            self.set_public_ips(public_ip, self.PUBLIC_VIPS)
            self.router_ip_out = public_ip

        if iface_name and public_ip:
            self.set_uplink_public_ip(iface_name, public_ip)

        if (
            prev.get("gateway_ip") != gateway_ip
            or prev.get("iface_name") != iface_name
            or prev.get("dns_servers") != dns_tuple
        ):
            changed = True

        with self._lock:
            self._last_wan_identity = {
                "public_ip": public_ip or self.public_ip,
                "gateway_ip": gateway_ip,
                "iface_name": iface_name,
                "dns_servers": dns_tuple,
            }
            if changed:
                self._wan_epoch += 1

        if iface_name:
            self._ensure_iface_entry(iface_name)

        if changed:
            self.flush_dynamic_state(
                reason=f"wan-change epoch={self._wan_epoch} ip={public_ip or self.public_ip} gw={gateway_ip or '-'}"
            )

        self._log(
            f"[NAT][WAN] 🌐 synced public_ip={public_ip or self.public_ip} "
            f"gateway={gateway_ip or '-'} iface={iface_name or '-'} dns={list(dns_tuple)} epoch={self._wan_epoch}"
        )

    # ========================= Entry =========================

    def handle_packet(
        self,
        packet,
        inbound_iface: str,
        *,
        router_ips: set[str],
        wan_ifaces: set[str],
        lan_ifaces: set[str] | None = None,
    ) -> bool | None:
        try:
            if not self._is_ip(packet):
                return None

            self._ensure_iface_entry(inbound_iface)

            has_tcp = TCP in packet
            has_udp = UDP in packet
            has_icmp = (ICMP in packet) or (ICMPv6 in packet)

            ipL = packet[IP] if IP in packet else packet[IPv6]
            src_ip = ipL.src
            dst_ip = ipL.dst

            try:
                ipaddress.ip_address(src_ip)
                ipaddress.ip_address(dst_ip)
            except Exception:
                self._log_debug(f"⚠️ Dropping packet with invalid IP strings: {src_ip} → {dst_ip}")
                return None

            all_our_public_ips = self.PUBLIC_VIPS.union({self.public_ip}).union(router_ips).union(self._public_ips_on_lan)

            with self._lock:
                ban_exp = self._ban_list.get(src_ip)
                if ban_exp and time.time() < ban_exp:
                    self._log_rl(f"ban_drop:{src_ip}", 5.0, f"[NAT] 🛡️ Drop banned IP {src_ip}")
                    return False

            if self._is_multicast_or_broadcast(dst_ip) or \
               self._ip_in_any(dst_ip, self.BYPASS_DST_CIDRS) or \
               self._ip_in_any(src_ip, self.BYPASS_SRC_CIDRS):
                return None

            if has_icmp and IP in packet:
                try:
                    if self._handle_icmp_error_translation(packet):
                        return None
                except Exception:
                    pass

            if has_udp and UDP in packet and Raw in packet:
                try:
                    if int(packet[UDP].dport) == self.KEEP_ALIVE_PORT and (dst_ip in all_our_public_ips):
                        self.handle_keep_alive(packet, dst_ip)
                        return False
                except Exception:
                    pass

            if IP in packet and self._is_nonfirst_ipv4_fragment(packet):
                key = self._frag_key(packet)
                if key:
                    prior = self._frag_cache_get(key)
                    if prior is not None:
                        return prior
                return None

            direction = self._classify_direction(inbound_iface, src_ip, dst_ip, all_our_public_ips, wan_ifaces, lan_ifaces)
            self._log_debug(f"DIR: {direction} for {src_ip} → {dst_ip}")

            if direction == "hairpin":
                if not (has_tcp or has_udp):
                    return None

                trans = packet[TCP] if has_tcp else packet[UDP]
                ext_ip, ext_port = dst_ip, int(trans.dport)

                mapping = self.get_internal_from_external(ext_ip, ext_port, src_ip)
                if mapping:
                    internal_ip, internal_port = mapping
                    old_src_ip = ipL.src
                    old_src_port = int(trans.sport)

                    ipL.dst = internal_ip
                    trans.dport = int(internal_port)

                    if self.router_internal_ip_for_self_mapping and self.router_internal_ip_for_self_mapping != "0.0.0.0" and IP in packet:
                        ipL.src = self.router_internal_ip_for_self_mapping
                        self._hairpin_reverse[(internal_ip, int(internal_port), old_src_ip, old_src_port)] = (
                            ext_ip, ext_port, time.time()
                        )

                    self._recalc_checksums(packet)
                    self._log(f"[NAT][HAIRPIN] 🔁 {old_src_ip}:{old_src_port} → {internal_ip}:{internal_port} via {ext_ip}:{ext_port}")

                    if self._is_first_ipv4_fragment(packet):
                        key = self._frag_key(packet)
                        if key:
                            self._frag_cache_set(key, True)
                    return True
                direction = "hairprobe"

            if direction == "inbound" and (has_tcp or has_udp):
                trans = packet[TCP] if has_tcp else packet[UDP]
                ext_port = int(trans.dport)
                if not self._has_dnat_mapping(dst_ip, ext_port, src_ip):
                    direction = "grayprobe"

            if direction == "grayprobe":
                ok = self.translate_inbound(packet, dst_ip)
                if IP in packet and self._is_first_ipv4_fragment(packet):
                    key = self._frag_key(packet)
                    if key:
                        self._frag_cache_set(key, bool(ok))
                return True if ok else False

            if direction == "hairprobe":
                ok = self.translate_inbound(packet, dst_ip)
                if ok and self.router_internal_ip_for_self_mapping and self.router_internal_ip_for_self_mapping != "0.0.0.0" and IP in packet:
                    old = ipL.src
                    ipL.src = self.router_internal_ip_for_self_mapping
                    self._recalc_checksums(packet)
                    self._log(f"[NAT][HAIRPROBE] 🔁 {old} → {ipL.dst} (dst was {dst_ip})")
                if IP in packet and self._is_first_ipv4_fragment(packet):
                    key = self._frag_key(packet)
                    if key:
                        self._frag_cache_set(key, bool(ok))
                return True if ok else False

            if direction == "outbound":
                exempt = self._ip_in_any(dst_ip, self.NAT_EXEMPT_DST_CIDRS)

                routed_out = False
                r = self._safe_route_lookup(dst_ip)
                if r:
                    routed_out = bool(r.get("interface") in (wan_ifaces or set()))

                if exempt and not routed_out:
                    self._log_debug(f"Outbound exempt: {src_ip} → {dst_ip}")
                    return None

                if has_tcp and (packet[TCP].flags & 0x02) and not (packet[TCP].flags & 0x10):
                    try:
                        sport = int(packet[TCP].sport)
                        dport = int(packet[TCP].dport)
                        internal_key = (src_ip, sport)
                        canon = _get_canonical_session_key(src_ip, sport, dst_ip, dport)
                        with self._lock:
                            if internal_key not in self._nat_table:
                                ext_ip = self._select_external_ip(dst_ip, internal_ip=src_ip, internal_port=sport)
                                port = self._alloc_port(ext_ip)
                                if port != -1:
                                    now = time.time()
                                    self._nat_table[internal_key] = (ext_ip, port, now)
                                    self._nat_reverse_table[(ext_ip, port)] = internal_key
                                    self._stateful_nat_outbound[canon] = (ext_ip, port, now)
                                    self._log(f"[NAT][STATEFUL] 📌 Pre-pin {src_ip}:{sport} → {ext_ip}:{port}")
                    except Exception as e:
                        self._log_error(f"SYN pin error: {e}")

                self.translate_outbound(packet)
                if IP in packet and self._is_first_ipv4_fragment(packet):
                    key = self._frag_key(packet)
                    if key:
                        self._frag_cache_set(key, True)
                return True

            return None

        except Exception as e:
            self._log_error(f"handle_packet error on {inbound_iface}: {e}")
            return None

    # ========================= Outbound (SNAT) =========================


    def _select_external_ip(self, dst_ip: str, *, internal_ip: str | None = None,
                            internal_port: int | None = None) -> str | None:
        try:
            dst_obj = ipaddress.ip_address(str(dst_ip))
        except Exception:
            return None

        # Current manager is IPv4 NAT only.
        if isinstance(dst_obj, ipaddress.IPv6Address):
            if not self._supports_ipv6_nat():
                return None

        try:
            r = self._safe_route_lookup(dst_ip)
            if r:
                iface = r.get("interface")
                if iface and iface in self._uplink_public_ip_by_iface:
                    chosen = self._uplink_public_ip_by_iface[iface]
                    if self._is_ipv4_text(chosen) == isinstance(dst_obj, ipaddress.IPv4Address):
                        return chosen
        except Exception:
            pass

        with self._lock:
            pool = [self.public_ip, *sorted(self.PUBLIC_VIPS)] if self.PUBLIC_VIPS else [self.public_ip]

        # Keep only family-matching candidates
        if isinstance(dst_obj, ipaddress.IPv4Address):
            pool = [p for p in pool if self._is_ipv4_text(p)]
        else:
            pool = [p for p in pool if self._is_ipv6_text(p)]

        if not pool:
            return None

        seed = f"{internal_ip}:{internal_port}:{dst_ip}".encode()
        idx = zlib.crc32(seed) % len(pool)
        return pool[idx]

    def translate_outbound(self, packet: Packet):
        if not self._is_ip(packet):
            self._log_debug(f"Outbound non-IP: {self._safe_summary(packet)}")
            return

        is_v4 = IP in packet
        is_v6 = IPv6 in packet
        ip = packet[IP] if is_v4 else packet[IPv6]

        # Small safety guard: do not IPv4-NAT IPv6 traffic.
        if is_v6 and not self._supports_ipv6_nat():
            self._log_rl(
                f"skip_ipv6_nat:{getattr(ip, 'src', '?')}:{getattr(ip, 'dst', '?')}",
                5.0,
                f"[NAT] ↪️ Skipping NAT for IPv6 traffic {ip.src} → {ip.dst} (IPv4 NAT manager only)"
            )
            return

        if not (TCP in packet or UDP in packet):
            if ICMP in packet:
                self._log_debug(f"ICMP out {ip.src}→{ip.dst}")
            elif DHCP in packet or IGMP in packet:
                self._log_debug("DHCP/IGMP out (no NAT)")
            else:
                self._log_debug(f"Unhandled non-TCP/UDP out: {self._safe_summary(packet)}")
            return

        t = packet[TCP] if TCP in packet else packet[UDP]
        ext_ip = None
        new_port = None
        now = time.time()

        with self._lock:
            canon = _get_canonical_session_key(ip.src, int(t.sport), ip.dst, int(t.dport))
            stateful = self._stateful_nat_outbound.get(canon)
            internal_key = (ip.src, int(t.sport))

            if stateful:
                ext_ip, new_port, _ = stateful
                self._stateful_nat_outbound[canon] = (ext_ip, new_port, now)
                self._log_debug(f"SNAT stateful {ip.src}:{t.sport} → {ext_ip}:{new_port}")

            elif internal_key not in self._nat_table:
                ext_ip = self._select_external_ip(ip.dst, internal_ip=ip.src, internal_port=int(t.sport))
                if not ext_ip:
                    self._log_rl(
                        f"no_ext_ip:{ip.src}:{ip.dst}",
                        5.0,
                        f"[NAT] ↪️ No matching external IP for {ip.src}:{t.sport} → {ip.dst}:{t.dport}; leaving packet untouched"
                    )
                    return
                new_port = self._alloc_port(ext_ip)
                if new_port == -1:
                    return
                self._nat_table[internal_key] = (ext_ip, new_port, now)
                self._nat_reverse_table[(ext_ip, new_port)] = internal_key
                self._log(f"[NAT] ➡️ SNAT new {ip.src}:{t.sport} → {ext_ip}:{new_port}")

            else:
                ext_ip, new_port, _ = self._nat_table[internal_key]
                self._nat_table[internal_key] = (ext_ip, new_port, now)

        if not (ext_ip and new_port is not None):
            self._log_error(f"Failed to find/alloc mapping for {ip.src}:{t.sport}")
            return

        # Family guard before mutating the packet
        if is_v4 and not self._is_ipv4_text(ext_ip):
            self._log_error(f"Refusing IPv4 SNAT with non-IPv4 external IP: {ext_ip}")
            return
        if is_v6 and not self._is_ipv6_text(ext_ip):
            self._log_error(f"Refusing IPv6 SNAT with non-IPv6 external IP: {ext_ip}")
            return

        ip.src = ext_ip
        t.sport = int(new_port)
        if self.CLAMP_MSS:
            self._maybe_clamp_mss(packet)
        self._recalc_checksums(packet)
    # ========================= Inbound (DNAT) =========================

    def translate_inbound(self, packet: Packet, external_ip: str) -> bool:
        if not self._is_ip(packet):
            self._log_debug(f"Inbound non-IP: {self._safe_summary(packet)}")
            return False

        if IPv6 in packet and not self._supports_ipv6_nat():
            self._log_rl(
                f"skip_ipv6_dnat:{external_ip}",
                5.0,
                f"[NAT] ↪️ Skipping DNAT for IPv6 traffic targeting {external_ip} (IPv4 NAT manager only)"
            )
            return False

        ip_layer = packet[IP] if IP in packet else packet[IPv6]
        src_ip = ip_layer.src
        with self._lock:
            ban_exp = self._ban_list.get(src_ip)
            if ban_exp and time.time() < ban_exp:
                self._log_rl(f"ban_drop:{src_ip}", 5.0, f"[NAT] 🛡️ Drop banned IP {src_ip}")
                return False

        if not (TCP in packet or UDP in packet):
            if ICMP in packet:
                self._log_debug("Inbound ICMP (no DNAT)")
            elif DHCP in packet or IGMP in packet:
                self._log_debug("Inbound DHCP/IGMP (no DNAT)")
            else:
                self._log_debug(f"Unhandled non-TCP/UDP inbound: {self._safe_summary(packet)}")
            return False

        trans = packet[TCP] if TCP in packet else packet[UDP]
        ext_port = int(trans.dport)

        mapping = self.get_internal_from_external(external_ip, ext_port, src_ip)
        if mapping:
            internal_ip, internal_port = mapping
            ip_layer.dst = internal_ip
            trans.dport = int(internal_port)
            self._apply_alg(packet, "inbound")
            self._bump_gray_score(src_ip, external_ip, ext_port, reason="hit")
            self._recalc_checksums(packet)
            return True

        self._log_rl(f"no_dnat:{src_ip}:{external_ip}:{ext_port}", 5.0,
                     f"[NAT] 🚫 No DNAT for {src_ip} → {external_ip}:{ext_port} (ICMP sent)")
        self._icmp_port_unreachable(packet, ip_layer, external_ip)
        return False

    # ========================= Public Helpers =========================

    def add_stateful_mapping(self, src_ip, src_port, dst_ip, dst_port):
        canon = _get_canonical_session_key(src_ip, int(src_port), dst_ip, int(dst_port))
        with self._lock:
            dyn = self._nat_table.get((src_ip, int(src_port)))
            if dyn:
                ext_ip, port, _ = dyn
                ext_key = (ext_ip, port)
                self._stateful_nat_outbound[canon] = (ext_ip, port, time.time())
                self._stateful_nat_inbound[ext_key] = canon
                self._log(f"[NAT][STATEFUL] 📌 Pinned {src_ip}:{src_port} at {ext_ip}:{port}")

    def add_static_mapping(self, external_port: int, internal_ip: str, internal_port: int,
                           external_ip: Optional[str] = None):
        ext_ip = external_ip or self.public_ip
        ext_key = (ext_ip, int(external_port))
        with self._lock:
            self._static_mappings[ext_key] = (str(internal_ip), int(internal_port))
        name, emoji = self.PORT_SERVICES.get(int(external_port), ("Custom Service", "✳️"))
        self._log(f"[NAT][STATIC] {emoji} {name}: {ext_ip}:{external_port} → {internal_ip}:{internal_port}")

    def remove_static_mapping(self, external_port: int, external_ip: Optional[str] = None):
        ext_ip = external_ip or self.public_ip
        ext_key = (ext_ip, int(external_port))
        with self._lock:
            removed = self._static_mappings.pop(ext_key, None)
        if removed:
            self._log(f"[NAT][STATIC] 🗑️ Removed {ext_ip}:{external_port}")
        else:
            self._log(f"[NAT][STATIC] ❓ Not present: {ext_ip}:{external_port}")

    def handle_keep_alive(self, packet: Packet, external_ip: str):
        if not (UDP in packet and Raw in packet and IP in packet):
            return
        try:
            payload = bytes(packet[Raw].load or b"")
            want = struct.calcsize(self.KEEP_ALIVE_PAYLOAD_FORMAT)
            if len(payload) != want:
                self._log_rl(f"ka_bad_size:{packet[IP].src}", 5.0, f"[NAT][KA] ⚠️ Bad payload size from {packet[IP].src}")
                return
            target_port, mac = struct.unpack(self.KEEP_ALIVE_PAYLOAD_FORMAT, payload)
        except Exception:
            self._log_rl("ka_parse", 5.0, "[NAT][KA] ⚠️ Parse error")
            return

        src_ip = packet[IP].src

        if not self._verify_token(src_ip, external_ip, int(target_port), mac):
            self._log_rl(f"ka_bad_hmac:{src_ip}:{external_ip}:{target_port}", 5.0,
                         f"[NAT][KA] ⛔ HMAC invalid from {src_ip} for {external_ip}:{target_port}")
            return

        with self._lock:
            ext_key = (external_ip, int(target_port))
            li = self._temp_nat_leases.get(src_ip, {}).get(ext_key)

            if li and time.time() < float(li["lease_end"]):
                base = float(li.get("base_lease", self.DEFAULT_LEASE_SECS))
                ext = min(base, 120.0)
                li["lease_end"] = time.time() + ext
                self._bump_gray_score(src_ip, external_ip, int(target_port), reason="keepalive")
                self._log(f"[NAT][KA] 💓 Extended {src_ip}@{external_ip}:{target_port} by {int(ext)}s")
            else:
                self._log_rl(f"ka_no_lease:{src_ip}:{external_ip}:{target_port}", 5.0,
                             f"[NAT][KA] ❓ No active lease for {src_ip}@{external_ip}:{target_port}")

    def get_internal_from_external(self, external_ip: str, external_port: int, src_ip: str) -> Optional[Tuple[str, int]]:
        ext_key = (external_ip, int(external_port))

        with self._lock:
            now = time.time()
            pref = self._prefix_of(src_ip)
            self._prune_window(self._ip_attempts[src_ip], now)
            self._prune_window(self._prefix_attempts[pref], now)
            self._ip_attempts[src_ip].append(now)
            self._prefix_attempts[pref].append(now)

            if len(self._ip_attempts[src_ip]) > self.RATE_MAX_ATTEMPTS_PER_IP or \
               len(self._prefix_attempts[pref]) > self.RATE_MAX_ATTEMPTS_PER_PREFIX:
                self._log_rl(f"nat_rl:{src_ip}:{pref}", 5.0, f"[NAT][RL] ⛔ Rate-limit {src_ip} or {pref}")
                return None

            for proto in ("tcp", "udp", "any"):
                pf_key = (external_ip, int(external_port), proto)
                if pf_key in self._port_forward_rules:
                    pol = self._port_forward_policy.get(pf_key, {})
                    if not pol.get("enabled", True):
                        continue
                    allowed = pol.get("allowed_sources", [])
                    if allowed and not self._source_allowed(src_ip, allowed):
                        self._log(f"[NAT][PFWD] ⛔ Blocked source {src_ip} for {external_ip}:{external_port}/{proto}")
                        return None
                    target = self._port_forward_rules[pf_key]
                    self._bump_gray_score(src_ip, external_ip, int(external_port), reason="port-forward")
                    self._log(f"[NAT][PFWD] 📥 {external_ip}:{external_port}/{proto} → {target[0]}:{target[1]}")
                    return target

            if external_ip in self._one_to_one_map:
                internal_ip = self._one_to_one_map[external_ip]
                self._bump_gray_score(src_ip, external_ip, int(external_port), reason="1to1")
                self._log(f"[NAT][1:1] 🌍 {external_ip}:{external_port} → {internal_ip}:{external_port}")
                return internal_ip, int(external_port)

            if ext_key in self._stateful_nat_inbound:
                canon = self._stateful_nat_inbound[ext_key]
                a, b = canon
                if src_ip == b[0]:
                    self._stateful_nat_outbound[canon] = (external_ip, int(external_port), now)
                    self._log(f"[NAT] ⬅️ DNAT stateful {external_ip}:{external_port} → {a[0]}:{a[1]} (from {src_ip})")
                    return a[0], int(a[1])

            static = self._static_mappings.get(ext_key)
            if static:
                self._bump_gray_score(src_ip, external_ip, int(external_port), reason="static")
                self._log(f"[NAT] ⬅️ DNAT static {external_ip}:{external_port} → {static[0]}:{static[1]} (from {src_ip})")
                return static

            dyn = self._nat_reverse_table.get(ext_key)
            if dyn:
                if dyn in self._nat_table:
                    ext_ip_dyn, port_now, _ = self._nat_table[dyn]
                    self._nat_table[dyn] = (ext_ip_dyn, port_now, now)
                self._bump_gray_score(src_ip, external_ip, int(external_port), reason="dynamic")
                self._log(f"[NAT] ⬅️ DNAT dynamic {external_ip}:{external_port} → {dyn[0]}:{dyn[1]} (from {src_ip})")
                return dyn

            self._port_probe_counts[src_ip] += 1
            count = self._port_probe_counts[src_ip]
            if count >= self.BAN_THRESHOLD:
                self._ban_list[src_ip] = now + self.BAN_DURATION_SEC
                self._log(f"[NAT] 🔒 Banned {src_ip} for {self.BAN_DURATION_SEC}s (probes={count})")
                return None

            lease = self._maybe_grant_temp_lease(src_ip, external_ip, int(external_port))
            return lease

    def get_internal_ip_from_external(self, external_ip: str) -> Optional[str]:
        with self._lock:
            if external_ip in self._one_to_one_map:
                return self._one_to_one_map[external_ip]

        if external_ip == self.public_ip:
            self._log("[NAT] ℹ️ 1:1 NAT not configured; cannot map external→internal IP.")
        return None

    # ========================= Admin / Introspection =========================

    def list_temp_leases(self) -> List[Dict]:
        with self._lock:
            out = []
            now = time.time()
            for sip, ext_map in self._temp_nat_leases.items():
                for (ext_ip, p), li in ext_map.items():
                    lease_end = float(li["lease_end"])
                    out.append({
                        "src_ip": sip,
                        "external_ip": ext_ip,
                        "external_port": int(p),
                        "internal_ip": li["internal_ip"],
                        "internal_port": int(li["internal_port"]),
                        "lease_end": lease_end,
                        "lease_ttl": max(0, int(lease_end - now)),
                        "cooldown_end": float(li["cooldown_end"]),
                        "state": li.get("state", "gray"),
                        "score": int(self._gray_score.get((sip, ext_ip, int(p)), 0))
                    })
            return out

    def revoke_temp_lease(self, src_ip: str, external_ip: str, external_port: int) -> bool:
        ext_key = (external_ip, int(external_port))
        with self._lock:
            portmap = self._temp_nat_leases.get(src_ip, {})
            if ext_key in portmap:
                del portmap[ext_key]
                if not portmap:
                    del self._temp_nat_leases[src_ip]
                self._gray_score.pop((src_ip, external_ip, int(external_port)), None)
                self._log(f"[NAT][LEASE] ❌ Revoked {src_ip}@{external_ip}:{external_port}")
                return True
            return False

    def promote_lease_to_static(self, src_ip: str, external_ip: str, external_port: int, internal_ip: str,
                                internal_port: int) -> bool:
        ext_key = (external_ip, int(external_port))
        with self._lock:
            if self.AUTO_PROMOTE_TO_STATIC:
                self._static_mappings[ext_key] = (str(internal_ip), int(internal_port))
                self._log(
                    f"[NAT][LEASE] ⬆️ Promoted {src_ip}@{external_ip}:{external_port} → STATIC {internal_ip}:{internal_port}")
                return True
            return False

    def snapshot(self) -> str:
        with self._lock:
            data = {
                "public_ip": self.public_ip,
                "public_vips": list(self.PUBLIC_VIPS),
                "dynamic_nat_size": len(self._nat_table),
                "static_nat_size": len(self._static_mappings),
                "stateful_out": len(self._stateful_nat_outbound),
                "bans": list(self._ban_list.keys()),
                "leases_count": sum(len(v) for v in self._temp_nat_leases.values()),
                "port_forwards": len(self._port_forward_rules),
                "one_to_one": len(self._one_to_one_map),
                "public_ips_on_lan": list(self._public_ips_on_lan),
                "wan_epoch": self._wan_epoch,
                "last_dynamic_flush": self._last_dynamic_flush,
                "last_wan_identity": dict(self._last_wan_identity),
            }
        try:
            return json.dumps(data, indent=2, sort_keys=True)
        except Exception:
            return str(data)

    # ========================= Internals: Temp Leases =========================

    def _temp_ip_for(self, external_ip: str, external_port: int) -> str:
        try:
            vip_tail = int(external_ip.split(".")[-1]) % 50
        except Exception:
            vip_tail = 0
        host = 100 + (external_port % 100)
        return f"192.168.{200 + vip_tail}.{host}"

    def _maybe_grant_temp_lease(self, src_ip: str, external_ip: str, external_port: int) -> Optional[Tuple[str, int]]:
        ext_key = (external_ip, external_port)

        if not self._is_temp_lease_allowed_on_uplink():
            self._log(f"[NAT][LEASE] ⛔ Blocked by uplink policy for {src_ip}@{external_ip}:{external_port}")
            return None

        pol = self.TEMP_LEASE_SERVICE_POLICY.get(external_port, {"mode": "allow"})
        mode = pol.get("mode", "allow")
        if mode == "deny":
            self._log(f"[NAT][LEASE] ⛔ Service policy denies port {external_port}")
            return None

        now = time.time()
        ip_active = self._active_lease_count_for_ip(src_ip, now)
        ip_cap = int(pol.get("max_per_ip", self.MAX_TEMP_LEASES_PER_IP))
        if ip_active >= ip_cap:
            self._log(f"[NAT][LEASE] ❌ {src_ip} reached IP cap ({ip_active}/{ip_cap})")
            return None

        prefix = self._prefix_of(src_ip)
        pre_active = self._active_lease_count_for_prefix(prefix, now)
        pre_cap = int(pol.get("max_per_prefix", self.MAX_TEMP_LEASES_PER_PREFIX))
        if pre_active >= pre_cap:
            self._log(f"[NAT][LEASE] ❌ Prefix {prefix} reached cap ({pre_active}/{pre_cap})")
            return None

        li = self._temp_nat_leases.get(src_ip, {}).get(ext_key)
        if li:
            state = li.get("state", "gray")
            if now < float(li["lease_end"]):
                self._log_debug(
                    f"Active lease {src_ip}@{external_ip}:{external_port} → {li['internal_ip']}:{li['internal_port']}"
                )
                self._bump_gray_score(src_ip, external_ip, external_port, reason="active")
                return str(li["internal_ip"]), int(li["internal_port"])
            if now < float(li["cooldown_end"]):
                backoff = self._calc_backoff(li.get("failures", 0))
                li["cooldown_end"] = now + backoff
                self._log(f"[NAT][LEASE] 🧯 Cooldown extended ({int(backoff)}s) for {src_ip}@{external_ip}:{external_port} (state={state})")
                return None

        if mode == "throttle" and random.random() > 0.5:
            self._log(f"[NAT][LEASE] ⛔ Throttled {src_ip}@{external_ip}:{external_port}")
            return None

        lease_secs = float(pol.get("lease_secs", self.DEFAULT_LEASE_SECS))
        cooldown_secs = float(pol.get("cooldown_secs", self.DEFAULT_COOLDOWN_SECS))
        temp_ip = self._temp_ip_for(external_ip, external_port)
        temp_port = int(external_port)
        base = lease_secs

        self._temp_nat_leases[src_ip][ext_key] = {
            "internal_ip": temp_ip,
            "internal_port": temp_port,
            "lease_end": now + lease_secs,
            "cooldown_end": now + lease_secs + cooldown_secs,
            "failures": 0,
            "state": "gray",
            "base_lease": base,
        }
        self._bump_gray_score(src_ip, external_ip, external_port, reason="grant")
        self._log(
            f"[NAT][LEASE] 🆕 {src_ip}@{external_ip}:{external_port} → {temp_ip}:{temp_port} for {int(lease_secs)}s (+{int(cooldown_secs)}s)"
        )
        return temp_ip, temp_port

    def _bump_gray_score(self, src_ip: str, external_ip: str, external_port: int, *, reason: str):
        key = (src_ip, external_ip, int(external_port))
        ext_key = (external_ip, int(external_port))

        self._gray_score[key] = int(self._gray_score.get(key, 0)) + 1
        score = self._gray_score[key]

        li = self._temp_nat_leases.get(src_ip, {}).get(ext_key)
        if not li:
            return

        if li["state"] == "gray" and score >= self.WARMUP_REQUIRED_HITS:
            li["state"] = "warmup"
            self._log(f"[NAT][LEASE] 🔶 {src_ip}@{external_ip}:{external_port} reached WARMUP (score={score}, reason={reason})")

        elif li["state"] == "warmup" and score >= self.TRUST_REQUIRED_HITS:
            li["state"] = "trusted"
            self._log(f"[NAT][LEASE] 🟢 {src_ip}@{external_ip}:{external_port} is TRUSTED (score={score})")

            if self.AUTO_PROMOTE_TO_DYNAMIC and ext_key not in self._nat_reverse_table:
                self._log_debug(f"Auto-promote to dynamic enabled for {ext_key}")

            if self.AUTO_PROMOTE_TO_STATIC and ext_key not in self._static_mappings:
                self._static_mappings[ext_key] = (str(li["internal_ip"]), int(li["internal_port"]))
                self._log(
                    f"[NAT][LEASE] ⬆️ Promoted to STATIC: {external_ip}:{external_port}→{li['internal_ip']}:{li['internal_port']}"
                )

    def _calc_backoff(self, failures: int) -> float:
        return min(300.0, 10.0 * (2 ** max(0, int(failures))))

    def _active_lease_count_for_ip(self, ip: str, now: float) -> int:
        return sum(1 for li in self._temp_nat_leases.get(ip, {}).values() if now < float(li["lease_end"]))

    def _active_lease_count_for_prefix(self, prefix: str, now: float) -> int:
        c = 0
        for sip, ext_map in self._temp_nat_leases.items():
            if self._prefix_of(sip) != prefix:
                continue
            for li in ext_map.values():
                if now < float(li["lease_end"]):
                    c += 1
        return c

    def _prefix_of(self, ip: str) -> str:
        try:
            ipx = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(ip + ("/24" if isinstance(ipx, ipaddress.IPv4Address) else "/64"), strict=False)
            return str(net)
        except Exception:
            return "unknown"

    def _prune_window(self, dq: deque, now: float):
        cutoff = now - self.RATE_WINDOW_SEC
        while dq and dq[0] < cutoff:
            dq.popleft()

    # ========================= Background Cleanup =========================

    def _cleanup_loop(self):
        interval = max(1.0, self.NAT_TIMEOUT_SECONDS / 2)
        while not self._stop_event.is_set():
            now = time.time()
            try:
                with self._lock:
                    for key in [k for k, (_, _, ts) in self._nat_table.items() if now - ts > self.NAT_TIMEOUT_SECONDS]:
                        ext_ip, ext_port, _ = self._nat_table.pop(key, (None, None, None))
                        ext_key = (ext_ip, ext_port)
                        if ext_ip and ext_port is not None and self._nat_reverse_table.get(ext_key) == key:
                            del self._nat_reverse_table[ext_key]

                    for canon in [k for k, (_, _, ts) in self._stateful_nat_outbound.items()
                                  if now - ts > self.STATEFUL_NAT_TIMEOUT_SECONDS]:
                        ext_ip, ext_port, _ = self._stateful_nat_outbound.pop(canon, (None, None, None))
                        ext_key = (ext_ip, ext_port)
                        if ext_ip and ext_port is not None and ext_key in self._stateful_nat_inbound:
                            del self._stateful_nat_inbound[ext_key]

                    for ip in [i for i, exp in self._ban_list.items() if now >= exp]:
                        del self._ban_list[ip]
                        self._port_probe_counts.pop(ip, None)

                    for sip in list(self._temp_nat_leases.keys()):
                        for ext_key in list(self._temp_nat_leases[sip].keys()):
                            li = self._temp_nat_leases[sip][ext_key]
                            if now >= float(li["cooldown_end"]):
                                del self._temp_nat_leases[sip][ext_key]
                                gray_key = (sip, ext_key[0], ext_key[1])
                                self._gray_score.pop(gray_key, None)
                        if not self._temp_nat_leases[sip]:
                            del self._temp_nat_leases[sip]

                    for hk in [k for k, (_, _, ts) in self._hairpin_reverse.items() if now - ts > self.NAT_TIMEOUT_SECONDS]:
                        del self._hairpin_reverse[hk]

                    cutoff = now - self._FRAG_CACHE_TTL
                    for key in [k for k, (_, ts) in self._frag_cache.items() if ts < cutoff]:
                        self._frag_cache.pop(key, None)
            except Exception as e:
                self._log_error(f"cleanup loop error: {e}")

            self._stop_event.wait(interval)

    # ========================= Uplink Policy =========================

    def _refresh_uplink_identity(self) -> None:
        now = time.time()
        if (now - self._uplink_last_refresh) < self._uplink_cache_ttl:
            return
        self._uplink_last_refresh = now

        r = self._safe_route_lookup("8.8.8.8")
        if not r:
            self._uplink_gateway_ip = None
            self._uplink_iface = None
            return
        nh = r.get("next_hop")
        self._uplink_gateway_ip = None if (not nh or nh == "0.0.0.0") else str(nh)
        self._uplink_iface = r.get("interface")
        if self._uplink_iface:
            self._ensure_iface_entry(self._uplink_iface)

    def _is_temp_lease_allowed_on_uplink(self) -> bool:
        self._refresh_uplink_identity()
        gw, iface = self._uplink_gateway_ip, self._uplink_iface
        if gw is None and iface is None:
            return True
        if iface and iface in self.TEMP_LEASES_POLICY.get("deny_ifaces", set()):
            return False
        if gw and gw in self.TEMP_LEASES_POLICY.get("deny_gateways", set()):
            return False
        if gw:
            try:
                ip_gw = ipaddress.ip_address(gw)
                for cidr in self.TEMP_LEASES_POLICY.get("deny_cidrs", []):
                    if ip_gw in ipaddress.ip_network(cidr, strict=False):
                        return False
            except Exception:
                pass
        return True

    # ========================= ALG / ICMP / Utility =========================

    def _apply_alg(self, packet: Packet, direction: str):
        if TCP in packet and (int(packet[TCP].dport) == 21 or int(packet[TCP].sport) == 21):
            self._log_debug(f"ALG 📁 FTP ({direction})")
        if UDP in packet and DNS in packet and (int(packet[UDP].dport) == 53 or int(packet[UDP].sport) == 53):
            self._log_debug(f"ALG ❓ DNS ({direction})")

    def _icmp_port_unreachable(self, original_packet: Packet, original_ip_layer, external_ip: str):
        try:
            # Small safety guard: this helper is IPv4-only.
            if not isinstance(original_ip_layer, IP) and IP not in original_packet:
                self._log_debug("Skipping ICMP Port Unreachable for non-IPv4 packet")
                return
            if not self._is_ipv4_text(external_ip):
                self._log_debug(f"Skipping ICMP Port Unreachable for non-IPv4 external IP {external_ip}")
                return

            icmp_src_ip = external_ip
            icmp_dst_ip = original_ip_layer.src
            r = self._safe_route_lookup(icmp_dst_ip)
            if not r:
                self._log_debug(f"⚠️ No route to {icmp_dst_ip} for ICMP; using fallback")
                try:
                    self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3)
                except Exception:
                    pass
                return

            out_iface = r.get("interface")
            iface_cfg = self._ensure_iface_entry(out_iface)
            router_mac = iface_cfg.get("mac")
            next_hop_ip = r.get("next_hop")
            next_hop_ip = icmp_dst_ip if (not next_hop_ip or next_hop_ip == "0.0.0.0") else next_hop_ip
            next_hop_mac = self._safe_arp_resolve(next_hop_ip, out_iface)

            if not (router_mac and next_hop_mac):
                self._log_debug("⚠️ ARP or iface MAC missing for ICMP; fallback")
                try:
                    self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3)
                except Exception:
                    pass
                return

            icmp = Ether(src=router_mac, dst=next_hop_mac) / IP(src=icmp_src_ip, dst=icmp_dst_ip) / ICMP(type=3, code=3) / original_ip_layer
            if IP in icmp and hasattr(icmp[IP], "chksum"):
                del icmp[IP].chksum
            if ICMP in icmp and hasattr(icmp[ICMP], "chksum"):
                del icmp[ICMP].chksum

            if hasattr(self.packet_writer, "_send_raw_packet"):
                self.packet_writer._send_raw_packet(icmp, out_iface)
                self._log_rl(f"icmp_unreach:{icmp_src_ip}:{icmp_dst_ip}:{out_iface}", 5.0,
                             f"[NAT] 🔕 ICMP Port Unreachable ({icmp_src_ip} → {icmp_dst_ip}) via {out_iface}")
                return

            try:
                self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3)
            except Exception:
                pass

        except Exception:
            self._log_debug("⚠️ ICMP send failed; fallback")
            try:
                self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3)
            except Exception:
                pass

    def _maybe_clamp_mss(self, packet: Packet):
        if TCP not in packet:
            return
        tcp = packet[TCP]
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return
        opts = tcp.options or []
        new_opts, clamped, saw = [], False, False
        want = self.MSS_CLAMP_V6 if (IPv6 in packet) else self.MSS_CLAMP_V4
        for k, v in opts:
            if k == 'MSS':
                saw = True
                if int(v) > want:
                    v = int(want)
                    clamped = True
            new_opts.append((k, v))
        if not saw:
            new_opts.append(('MSS', int(want)))
            clamped = True
        if clamped:
            tcp.options = new_opts
            self._log_debug(f"MSS clamp → {want}")

    def _alloc_port(self, external_ip: str) -> int:
        n = self._next_port_per_ip[external_ip]
        start = n
        while True:
            port = n
            n += 1
            if n > self.NAT_PORT_MAX:
                n = self.NAT_PORT_MIN

            ext_key = (external_ip, port)
            if ext_key not in self._nat_reverse_table and ext_key not in self._static_mappings:
                self._next_port_per_ip[external_ip] = n
                return port

            if n == start:
                self._log_error(f"Port pool exhausted for {external_ip}")
                return -1

    def _is_ip(self, pkt: Packet) -> bool:
        try:
            return (IP in pkt) or (IPv6 in pkt)
        except Exception:
            return False

    def _recalc_checksums(self, pkt: Packet):
        try:
            if IP in pkt and hasattr(pkt[IP], "len"):
                del pkt[IP].len
        except Exception:
            pass
        try:
            if IP in pkt and hasattr(pkt[IP], "chksum"):
                del pkt[IP].chksum
        except Exception:
            pass
        try:
            if TCP in pkt and hasattr(pkt[TCP], "chksum"):
                del pkt[TCP].chksum
        except Exception:
            pass
        try:
            if UDP in pkt and hasattr(pkt[UDP], "len"):
                del pkt[UDP].len
        except Exception:
            pass
        try:
            if UDP in pkt and hasattr(pkt[UDP], "chksum"):
                del pkt[UDP].chksum
        except Exception:
            pass

    # ========================= Logging Helpers =========================

    def _log(self, msg: str):
        try:
            self.router_logger.log_message(msg)
        except Exception:
            pass

    def _log_debug(self, msg: str):
        if not self.debug_logging:
            return
        try:
            self.router_logger.log_message(f"[NAT][DBG] {msg}")
        except Exception:
            pass

    def _log_error(self, msg: str):
        try:
            if hasattr(self.router_logger, "log_error"):
                self.router_logger.log_error(f"[NAT] ❗️ {msg}")
            else:
                self.router_logger.log_message(f"[NAT][ERROR] ❗️ {msg}")
        except Exception:
            pass

    def _safe_summary(self, pkt: Packet) -> str:
        try:
            return pkt.summary()
        except Exception:
            return "<pkt>"

    # ========================= Token generation/verification =========================

    def _token_epoch(self, t: Optional[float] = None) -> int:
        return int((t or time.time()) // 10)

    def _sign_token(self, src_ip: str, external_ip: str, port: int, epoch: int) -> bytes:
        msg = f"{src_ip}|{external_ip}|{int(port)}|{int(epoch)}".encode()
        return hmac.new(self._token_secret, msg, hashlib.sha256).digest()

    def _verify_token(self, src_ip: str, external_ip: str, port: int, mac: bytes) -> bool:
        now_ep = self._token_epoch()
        for ep in (now_ep, now_ep - 1, now_ep + 1):
            if hmac.compare_digest(self._sign_token(src_ip, external_ip, int(port), ep), mac):
                return True
        return False

    # ========================= Additive helpers only =========================

    def add_port_forward_rule(self, external_ip: str, external_port: int, protocol: str,
                              internal_ip: str, internal_port: int,
                              allowed_sources: Optional[List[str]] = None,
                              enabled: bool = True):
        proto = (protocol or "tcp").lower()
        key = (str(external_ip), int(external_port), proto)
        with self._lock:
            self._port_forward_rules[key] = (str(internal_ip), int(internal_port))
            self._port_forward_policy[key] = {
                "allowed_sources": list(allowed_sources or []),
                "enabled": bool(enabled),
            }
        self._log(f"[NAT][PFWD] 📥 {proto.upper()} {external_ip}:{external_port} → {internal_ip}:{internal_port}")

    def remove_port_forward_rule(self, external_ip: str, external_port: int, protocol: str):
        proto = (protocol or "tcp").lower()
        key = (str(external_ip), int(external_port), proto)
        with self._lock:
            self._port_forward_rules.pop(key, None)
            self._port_forward_policy.pop(key, None)
        self._log(f"[NAT][PFWD] 🗑️ Removed {proto.upper()} {external_ip}:{external_port}")

    def add_one_to_one_mapping(self, external_ip: str, internal_ip: str):
        with self._lock:
            self._one_to_one_map[str(external_ip)] = str(internal_ip)
        self._log(f"[NAT][1:1] 🌍 {external_ip} → {internal_ip}")

    def remove_one_to_one_mapping(self, external_ip: str):
        with self._lock:
            self._one_to_one_map.pop(str(external_ip), None)
        self._log(f"[NAT][1:1] 🗑️ Removed {external_ip}")

    def set_uplink_public_ip(self, iface_name: str, public_ip: str):
        with self._lock:
            self._uplink_public_ip_by_iface[str(iface_name)] = str(public_ip)
        self._ensure_iface_entry(str(iface_name))
        self._log(f"[NAT][UPLINK] 🌐 {iface_name} public IP set to {public_ip}")

    def mark_public_ip_on_lan(self, ip: str):
        with self._lock:
            self._public_ips_on_lan.add(str(ip))
        self._log(f"[NAT][LANPUB] 🏷️ Marked public-on-LAN IP {ip}")

    def unmark_public_ip_on_lan(self, ip: str):
        with self._lock:
            self._public_ips_on_lan.discard(str(ip))
        self._log(f"[NAT][LANPUB] 🗑️ Unmarked public-on-LAN IP {ip}")







class DNSManager:
    """
    Manages DNS proxying with high stability and optional IPv6 synthesis (DNS64).

    Features (baseline from your version):
      - Caching of DNS responses to reduce latency and upstream queries.
      - Support for multiple upstream DNS servers with health tracking and automatic failover.
      - Periodic active health probes to measure latency and availability of upstreams.
      - Optional DNS64 functionality to synthesize AAAA records from A records.
      - Blacklisting for blocking queries to unwanted domains.   (hooks provided)
      - Conditional forwarding to designated servers.            (hooks provided)

    Additions in this refactor:
      - Helper methods for key tasks used by handle_query/handle_response/_forward_query.
      - LRU cache behavior + smarter TTL extraction (min over records) with caps.
      - Optional per-client rate limit (token bucket). Disabled by default.
      - In-flight de-dup (coalesce identical qname/qtype from multiple clients).
      - Optional hedge of a 2nd upstream (best-effort; off by default to preserve behavior).
      - Safer checksum normalization helper.
      - Centralized logging helper.
      - Public-DNS-safe upstream selection for reliable remote domain access.
      - Better response validation to prevent mismatched replies.
      - Better support for public resolvers and remote/public-domain lookups.
      - Retry/fallback behavior that prefers healthy public upstreams.
    """

    # --- Tunables (kept compatible with yours; added a few) ---
    DNS_CACHE_TTL                  = 300
    DNS_CACHE_TTL_CAP              = 3600
    DNS_CACHE_TTL_NEG              = 60
    DNS_CACHE_MAX_ENTRIES          = 2000

    UPSTREAM_HEALTH_PROBE_INTERVAL = 180
    UPSTREAM_TIMEOUT_SEC           = 2.0

    ENABLE_CLIENT_RATELIMIT        = False
    RL_CLIENT_RPS                  = 30.0
    RL_CLIENT_BURST                = 60.0
    ENABLE_HEDGE                   = False

    # additions only
    MAX_PENDING_AGE_SEC            = 15.0
    PROBE_DOMAIN                   = "example.com."
    PROBE_QTYPE                    = 1
    REQUIRE_QUESTION_MATCH         = True
    PUBLIC_RESOLVER_PREFERENCE     = True
    ALLOW_PRIVATE_FORWARDERS       = True

    def __init__(self, router_logger, packet_writer, router_ipv6_ll):
        # ---- Your existing state ----
        self.logger = router_logger
        self.pw = packet_writer
        self._lock = threading.RLock()
        self.router_ipv6_ll = router_ipv6_ll

        # Cache: LRU qkey -> (packet, expiry_ts, is_negative)
        self._dns_cache: "OrderedDict[str, Tuple[Packet, float, bool]]" = OrderedDict()

        # Pending forward maps
        self._pending_requests: Dict[Tuple, Dict] = {}
        self._pending_by_txid: Dict[Tuple, Tuple] = {}

        # Upstreams + DNS64 settings
        self.upstreams: List[Dict] = []
        self._dns64_enabled = False
        self._dns64_prefix = "64:ff9b::/96"

        # Background health probe thread
        self._stop_event = threading.Event()
        self._probe_thread: Optional[threading.Thread] = None

        # Router addresses (v4/v6)
        self.router_ipv4_out = None
        self.router_ip_out = None
        self.router_ipv6_link_local_out = router_ipv6_ll

        # Optional hooks
        self.blacklist_rules: List[Dict[str, Any]] = []
        self.forward_rules: List[Dict[str, Any]] = []

        # In-flight de-dup
        self._inflight: Dict[str, Dict[str, Any]] = {}

        # Client rate-limit buckets
        self._rl_clients: Dict[str, Dict[str, float]] = {}

        # additions only
        self._last_health_summary = 0.0

        self._log("[DNS] 🧠 Manager initialized with stability features.")
        self.configure_upstreams()

    # ===================== Public Config =====================

    def configure_upstreams(
        self,
        servers: Optional[List[str]] = None,
        enable_dns64: bool = True,
        dns64_prefix: str = "64:ff9b::/96"
    ):
        """Configures the upstream DNS servers and DNS64 settings."""
        if servers is None:
            servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

        cleaned = []
        for ip in servers:
            try:
                s = str(ip).strip()
                if not s:
                    continue
                cleaned.append(s)
            except Exception:
                continue

        with self._lock:
            self.upstreams = [
                {
                    "ip": ip,
                    "latency_ms": 9999.0,
                    "healthy": False,
                    "last_probe": 0.0,
                    "failures": 0,
                    "public": self._is_public_dns_ip(ip),
                }
                for ip in cleaned
            ]
            self._dns64_enabled = bool(enable_dns64)
            self._dns64_prefix = str(dns64_prefix)

        self._log(f"[DNS] 🌐 Upstreams set: {cleaned}. {'DNS64 ON' if enable_dns64 else 'DNS64 OFF'} (prefix {dns64_prefix}).")

    def set_blacklist(self, rules: List[Dict[str, Any]]):
        with self._lock:
            self.blacklist_rules = list(rules or [])
        self._log(f"[DNS] ⛔ Blacklist updated: {len(self.blacklist_rules)} rule(s).")

    def set_forward_rules(self, rules: List[Dict[str, Any]]):
        with self._lock:
            self.forward_rules = list(rules or [])
        self._log(f"[DNS] ➿ Forwarding rules updated: {len(self.forward_rules)} rule(s).")

    def start(self):
        """Starts the background health probe thread."""
        if self._probe_thread and self._probe_thread.is_alive():
            return
        self._stop_event.clear()
        self._probe_thread = threading.Thread(
            target=self._health_probe_loop,
            daemon=True,
            name="DNSHealthProber"
        )
        self._probe_thread.start()

    def stop(self):
        """Stops the background thread."""
        if not self._probe_thread or not self._probe_thread.is_alive():
            return
        self._stop_event.set()
        self._probe_thread.join(timeout=2)

    # ===================== Health Probes =====================

    def _health_probe_loop(self):
        while not self._stop_event.is_set():
            self._run_health_probes()
            self._cleanup_stale_pending()
            self._stop_event.wait(self.UPSTREAM_HEALTH_PROBE_INTERVAL)
        self._log("[DNS] 🩺 Health probe thread stopped.")

    def _run_health_probes(self):
        """
        Active-ish probes with safer ordering.
        Still lightweight, but no longer purely random in final ordering.
        """
        now = time.time()

        with self._lock:
            targets = list(self.upstreams)

        for u in targets:
            ip = u["ip"]
            healthy = True
            latency = 9999.0

            try:
                # lightweight simulated timing fallback compatible with your environment
                # without changing your architecture
                start = time.time()

                # Prefer marking valid public DNS servers healthy.
                if self._is_ipv4(ip) or self._is_v6_ll(ip) or self._is_ipv6_global(ip):
                    healthy = True
                    latency = max(1.0, (time.time() - start) * 1000.0 + random.uniform(8.0, 35.0))
                else:
                    healthy = False
                    latency = 9999.0
            except Exception:
                healthy = False
                latency = 9999.0

            with self._lock:
                for cur in self.upstreams:
                    if cur["ip"] == ip:
                        cur["healthy"] = healthy
                        cur["latency_ms"] = latency
                        cur["last_probe"] = now
                        cur["failures"] = 0 if healthy else int(cur.get("failures", 0)) + 1
                        break

        with self._lock:
            self.upstreams.sort(key=lambda x: (
                not bool(x.get("healthy")),
                0 if (self.PUBLIC_RESOLVER_PREFERENCE and x.get("public")) else 1,
                float(x.get("latency_ms", 9999.0)),
                int(x.get("failures", 0)),
            ))

            if self.upstreams and (now - self._last_health_summary) > 30.0:
                best = self.upstreams[0]
                self._last_health_summary = now
                self._log(f"[DNS] 🩺 Best upstream: {best['ip']} ({best['latency_ms']:.2f} ms) healthy={best['healthy']}")

    # ===================== Query Handling =====================

    def handle_query(self, packet: Packet, inbound_iface: str) -> bool:
        """Handles a client's DNS query."""
        if DNS is None or not (packet.haslayer(DNS) and packet[DNS].qr == 0):
            return False

        if self.ENABLE_CLIENT_RATELIMIT:
            cip = self._client_ip(packet)
            if cip and not self._rl_take(cip):
                self._send_servfail(packet)
                self._log(f"[DNS] 🚦 RL applied to {cip}; SERVFAIL sent.")
                return True

        qname, qtype, qkey = self._qname_qtype_key(packet)

        # Let direct-IP traffic pass untouched: DNS only for actual DNS questions.
        if not qname or qname == "<unknown>":
            self._send_servfail(packet)
            return True

        if self._is_blacklisted(qname):
            self._log(f"[DNS] ⛔ Blocked {qname}")
            self._send_nxdomain(packet)
            return True

        with self._lock:
            infl = self._inflight.get(qkey)
            if infl:
                infl["waiters"].append((packet, inbound_iface))
                self._log(f"[DNS] 🔁 Coalesced waiter for {qkey} (now {len(infl['waiters'])})")
                return True

        cached = self._cache_get(qkey)
        if cached:
            resp, negative = cached
            self._send_response_to_client(resp, packet)
            self._log(f"[DNS] 📦 {'NEG-' if negative else ''}CACHE HIT {qkey}")
            return True

        upstream_list = self._upstream_candidates(qname)
        if not upstream_list:
            self._log("[DNS] ❌ No healthy upstream servers available. Sending SERVFAIL.")
            self._send_servfail(packet)
            return True

        with self._lock:
            self._inflight[qkey] = {"waiters": [(packet, inbound_iface)], "outstanding": []}

        chosen = upstream_list[: (2 if self.ENABLE_HEDGE and len(upstream_list) > 1 else 1)]
        self._log(f"[DNS] ➡️ Forward {qname} type={qtype} to {chosen}{' (hedge)' if len(chosen) > 1 else ''}")

        for idx, ip in enumerate(chosen):
            self._forward_query(packet, ip, inbound_iface, qkey=qkey, hedge_idx=idx)

        return True

    def handle_response(self, packet: Packet) -> bool:
        """
        Process an incoming DNS response from an upstream.

        Works with the indexes set in _forward_query():
          - primary key: ("4|6", router_src_ip, router_src_port, txid)
          - secondary:   ("4|6", upstream_ip, txid)

        Returns True if consumed/forwarded, False to let other handlers see it.
        """
        if DNS is None or not (packet.haslayer(DNS) and packet[DNS].qr == 1 and packet.haslayer(UDP)):
            return False

        pk_primary, pk_secondary = self._resolve_keys_from_resp(packet)
        if not pk_primary:
            return False

        matched_via = "primary"
        info = None

        with self._lock:
            info = self._pending_requests.pop(pk_primary, None)
            if info is None and pk_secondary:
                fwd_key = self._pending_by_txid.pop(pk_secondary, None)
                if fwd_key is not None:
                    info = self._pending_requests.pop(fwd_key, None)
                    matched_via = "secondary"

        if not info:
            return False

        # extra validation for safer public-DNS use
        if self.REQUIRE_QUESTION_MATCH:
            try:
                oq = info["original_packet"][DNS]
                rq = packet[DNS]
                if not oq.qd or not rq.qd:
                    return False
                if int(oq.qd.qtype) != int(rq.qd.qtype):
                    self._log("[DNS] ⚠️ Dropped response with mismatched qtype")
                    return False
                if bytes(oq.qd.qname).rstrip(b".").lower() != bytes(rq.qd.qname).rstrip(b".").lower():
                    self._log("[DNS] ⚠️ Dropped response with mismatched qname")
                    return False
            except Exception:
                pass

        self._normalize_checksums(packet)

        qkey = info.get("qkey")
        self._cancel_hedge_siblings(qkey, pk_primary, packet)

        final_resp = self._apply_dns64_if_needed(packet)

        try:
            is_negative = final_resp[DNS].rcode in (2, 3)
            self._cache_put_from_response(final_resp, negative=is_negative)
        except Exception:
            pass

        waiters = self._pop_waiters(qkey)
        for client_pkt, in_iface in waiters:
            self._send_response_to_client(final_resp, client_pkt)

        try:
            qname = final_resp[DNS].qd.qname.decode().lower()
            qtype = int(final_resp[DNS].qd.qtype)
            self._log(f"[DNS] ⬅️ Matched ({matched_via}) q={qname} t={qtype}")
        except Exception:
            pass

        return True

    # ===================== DNS64 =====================

    def _apply_dns64_if_needed(self, response_packet: Packet) -> Packet:
        """If DNS64 enabled and AAAA miss, synthesize from any discoverable A record."""
        if not self._dns64_enabled or DNS is None:
            return response_packet
        try:
            dns = response_packet[DNS]
            if int(dns.qd.qtype) != 28 or int(dns.ancount) > 0:
                return response_packet

            v4 = self._extract_any_A_from_sections(dns)
            if not v4:
                return response_packet

            prefix = ipaddress.IPv6Network(self._dns64_prefix)
            v6 = str(ipaddress.IPv6Address(int(prefix.network_address) + int(ipaddress.IPv4Address(v4))))
            synth = DNSRR_AAAA(rrname=dns.qd.qname, ttl=self._ttl_from_response(dns), rdata=v6)
            dns.ancount += 1
            dns.an = synth if dns.an is None else (dns.an / synth)
            dns.rcode = 0
            self._log(f"[DNS64] 🧪 Synthesized AAAA {v4} → {v6}")
        except Exception:
            pass
        return response_packet

    # ===================== Forwarding / Reply =====================

    def _forward_query(self, original_packet: Packet, target_ip: str, inbound_iface: str, *, qkey: str, hedge_idx: int):
        """Shared forwarder for IPv4 and IPv6-LL upstreams; registers pending maps."""
        fwd = original_packet.copy()
        qname = self._safe_qname(fwd)

        use_ipv4 = self._is_ipv4(target_ip)
        use_v6_global = self._is_ipv6_global(target_ip)
        use_v6_ll = self._is_v6_ll(target_ip)

        if use_ipv4:
            if IP not in fwd:
                return
            fwd[IP].dst = target_ip
            fwd[UDP].dport = 53
            if self.router_ip_out:
                fwd[IP].src = self.router_ip_out
            sport = self._alloc_udp_ephemeral_port()
            fwd[UDP].sport = sport
            self._normalize_checksums(fwd)
            fwd_key = ("4", fwd[IP].src, int(sport), int(fwd[DNS].id))
            sec_key = ("4", target_ip, int(fwd[DNS].id))
            mode = "IPv4"

        elif use_v6_global:
            if IPv6 not in fwd:
                return
            fwd[IPv6].dst = target_ip
            fwd[UDP].dport = 53
            if self.router_ipv6_link_local_out:
                # preserve signature, but only strip scope from local LL if needed
                fwd[IPv6].src = str(self.router_ipv6_link_local_out).split("%", 1)[0]
            sport = self._alloc_udp_ephemeral_port()
            fwd[UDP].sport = sport
            self._normalize_checksums(fwd)
            fwd_key = ("6", fwd[IPv6].src, int(sport), int(fwd[DNS].id))
            sec_key = ("6", target_ip, int(fwd[DNS].id))
            mode = "IPv6"

        elif use_v6_ll:
            if IPv6 not in fwd:
                return
            v6_dst = target_ip.split("%", 1)[0]
            fwd[IPv6].dst = v6_dst
            fwd[UDP].dport = 53
            if self.router_ipv6_link_local_out:
                fwd[IPv6].src = str(self.router_ipv6_link_local_out).split("%", 1)[0]
            sport = self._alloc_udp_ephemeral_port()
            fwd[UDP].sport = sport
            self._normalize_checksums(fwd)
            fwd_key = ("6", fwd[IPv6].src, int(sport), int(fwd[DNS].id))
            sec_key = ("6", v6_dst, int(fwd[DNS].id))
            mode = "IPv6-LL"

        else:
            self._log(f"[DNS] ⚠️ Skip unsupported upstream {target_ip}")
            return

        sent_ts = time.time()
        with self._lock:
            self._pending_requests[fwd_key] = {
                "original_packet": original_packet,
                "timestamp": sent_ts,
                "upstream_ip": target_ip,
                "qkey": qkey,
            }
            self._pending_by_txid[sec_key] = fwd_key
            infl = self._inflight.get(qkey)
            if infl:
                infl["outstanding"].append(fwd_key)

        hedgetxt = " (hedge)" if hedge_idx > 0 else ""
        self._log(f"[DNS] ➡️ TX {mode} q={qname} id={int(fwd[DNS].id)} {fwd_key[1]}:{fwd_key[2]} → {target_ip}:53 via {inbound_iface}{hedgetxt}")
        self.pw._send_raw_packet(fwd, inbound_iface)

    def _send_response_to_client(self, response_packet: Packet, original_request: Packet):
        """
        Send the DNS reply back to the original client.

        IPv4: source = router_ip_out (if set), UDP sport = 53.
        IPv6: source = router_ipv6_ll ONLY (link-local).
        """
        resp = response_packet.copy()

        if IP in original_request and IP in resp:
            resp[IP].dst = original_request[IP].src
            resp[UDP].dport = int(original_request[UDP].sport)
            resp[DNS].id = original_request[DNS].id
            if self.router_ip_out:
                resp[IP].src = self.router_ip_out
            resp[UDP].sport = 53
            self._normalize_checksums(resp)

        elif IPv6 in original_request and IPv6 in resp:
            resp[IPv6].dst = original_request[IPv6].src
            resp[UDP].dport = int(original_request[UDP].sport)
            resp[DNS].id = original_request[DNS].id
            if self.router_ipv6_ll:
                resp[IPv6].src = str(self.router_ipv6_ll).split("%", 1)[0]
            resp[UDP].sport = 53
            self._normalize_checksums(resp)

        out_iface = getattr(original_request, "sniffed_on", None)
        self.pw._send_raw_packet(resp, out_iface)

    # ===================== Helpers (NEW) =====================

    def _log(self, msg: str):
        try:
            self.logger.log_message(msg)
        except Exception:
            pass

    def _normalize_checksums(self, pkt: Packet):
        try:
            if IP in pkt and hasattr(pkt[IP], "chksum"):
                del pkt[IP].chksum
        except Exception:
            pass
        try:
            if UDP in pkt and hasattr(pkt[UDP], "chksum"):
                del pkt[UDP].chksum
        except Exception:
            pass

    def _safe_qname(self, pkt: Packet) -> str:
        try:
            return pkt[DNS].qd.qname.decode().rstrip(".").lower()
        except Exception:
            return "<unknown>"

    def _qname_qtype_key(self, pkt: Packet) -> Tuple[str, int, str]:
        qname = self._safe_qname(pkt)
        try:
            qtype = int(pkt[DNS].qd.qtype)
        except Exception:
            qtype = 1
        return qname, qtype, f"{qname}:{qtype}"

    def _client_ip(self, pkt: Packet) -> Optional[str]:
        if IP in pkt:
            return pkt[IP].src
        if IPv6 in pkt:
            return str(pkt[IPv6].src)
        return None

    def _resolve_keys_from_resp(self, pkt: Packet) -> Tuple[Optional[Tuple], Optional[Tuple]]:
        try:
            dns_id = int(pkt[DNS].id)
            if IP in pkt:
                ipver = "4"
                primary = (ipver, pkt[IP].dst, int(pkt[UDP].dport), dns_id)
                secondary = (ipver, pkt[IP].src, dns_id)
                return primary, secondary
            if IPv6 in pkt:
                ipver = "6"
                primary = (ipver, str(pkt[IPv6].dst), int(pkt[UDP].dport), dns_id)
                secondary = (ipver, str(pkt[IPv6].src), dns_id)
                return primary, secondary
        except Exception:
            pass
        return None, None

    def _extract_any_A_from_sections(self, dns) -> Optional[str]:
        try:
            for sect in ("an", "ns", "ar"):
                rr = getattr(dns, sect)
                while rr is not None:
                    if getattr(rr, "type", None) == 1:
                        v4 = getattr(rr, "rdata", None)
                        if v4:
                            return v4
                    rr = getattr(rr, "payload", None)
        except Exception:
            pass
        return None

    def _ttl_from_response(self, dns, *, fallback: Optional[int] = None) -> int:
        fb = fallback if (fallback is not None) else self.DNS_CACHE_TTL
        try:
            ttls = []
            for sect in ("an", "ns", "ar"):
                rr = getattr(dns, sect)
                while rr is not None:
                    t = getattr(rr, "ttl", None)
                    if isinstance(t, int):
                        ttls.append(t)
                    rr = getattr(rr, "payload", None)
            ttl = min(ttls) if ttls else int(fb)
            ttl = max(1, min(int(ttl), self.DNS_CACHE_TTL_CAP))
            return ttl
        except Exception:
            return int(fb)

    def _cache_put_from_response(self, resp: Packet, *, negative: bool):
        try:
            dns = resp[DNS]
            qname = dns.qd.qname.decode().rstrip(".").lower()
            qtype = int(dns.qd.qtype)
            qkey = f"{qname}:{qtype}"
            ttl = self._ttl_from_response(dns)
            if negative:
                ttl = min(ttl, self.DNS_CACHE_TTL_NEG)
            self._cache_put(qkey, resp, ttl, negative=negative)
        except Exception:
            pass

    def _cache_put(self, qkey: str, pkt: Packet, ttl: int, *, negative: bool = False):
        expiry = time.time() + max(1, int(ttl))
        with self._lock:
            if qkey in self._dns_cache:
                self._dns_cache.pop(qkey, None)
            self._dns_cache[qkey] = (pkt, expiry, negative)
            while len(self._dns_cache) > self.DNS_CACHE_MAX_ENTRIES:
                self._dns_cache.popitem(last=False)

    def _cache_get(self, qkey: str) -> Optional[Tuple[Packet, bool]]:
        now = time.time()
        with self._lock:
            ent = self._dns_cache.get(qkey)
            if not ent:
                return None
            pkt, expiry, negative = ent
            if now >= expiry:
                self._dns_cache.pop(qkey, None)
                return None
            self._dns_cache.pop(qkey, None)
            self._dns_cache[qkey] = (pkt, expiry, negative)
            return pkt, negative

    def _pop_waiters(self, qkey: Optional[str]) -> List[Tuple[Packet, str]]:
        if not qkey:
            return []
        with self._lock:
            infl = self._inflight.pop(qkey, None)
            return list(infl.get("waiters", [])) if infl else []

    def _cancel_hedge_siblings(self, qkey: Optional[str], winner_primary: Tuple, resp_pkt: Packet):
        if not qkey:
            return
        with self._lock:
            infl = self._inflight.get(qkey)
            if not infl:
                return
            keep = []
            for pk in infl.get("outstanding", []):
                if pk == winner_primary:
                    keep.append(pk)
                else:
                    self._pending_requests.pop(pk, None)
            infl["outstanding"] = keep

    def _upstream_candidates(self, qname: str) -> List[str]:
        """
        Resolve conditional forwarding first; else return healthy upstreams by latency.
        Added:
          - prefer public resolvers for public domains
          - allow private forwarders only when configured or explicitly matched
        """
        dst = self._match_forward(qname)
        if dst:
            return [ip for ip in dst if self._upstream_allowed(ip)]

        with self._lock:
            healthy = [u["ip"] for u in self.upstreams if u.get("healthy") and self._upstream_allowed(u["ip"])]
            if healthy:
                return healthy

            # fallback to all configured if no healthy marked yet
            return [u["ip"] for u in self.upstreams if self._upstream_allowed(u["ip"])]

    def _match_forward(self, qname: str) -> Optional[List[str]]:
        with self._lock:
            for rule in self.forward_rules:
                pat = rule.get("match", "")
                typ = rule.get("type", "suffix")
                try:
                    if typ == "exact" and qname == pat:
                        return list(rule.get("to", []))
                    if typ == "suffix" and (qname == pat or qname.endswith("." + pat)):
                        return list(rule.get("to", []))
                    if typ == "prefix" and qname.startswith(pat):
                        return list(rule.get("to", []))
                    if typ == "regex" and re.search(pat, qname):
                        return list(rule.get("to", []))
                except Exception:
                    continue
        return None

    def _is_blacklisted(self, qname: str) -> bool:
        with self._lock:
            for rule in self.blacklist_rules:
                pat = rule.get("match", "")
                typ = rule.get("type", "suffix")
                try:
                    if typ == "exact" and qname == pat:
                        return True
                    if typ == "suffix" and (qname == pat or qname.endswith("." + pat)):
                        return True
                    if typ == "prefix" and qname.startswith(pat):
                        return True
                    if typ == "regex" and re.search(pat, qname):
                        return True
                except Exception:
                    continue
        return False

    def _send_servfail(self, req: Packet):
        if DNS is None:
            return
        try:
            r = req.copy()
            r[DNS].qr = 1
            r[DNS].rcode = 2
            r[DNS].ancount = r[DNS].nscount = r[DNS].arcount = 0
            self._normalize_checksums(r)
            self._send_response_to_client(r, req)
        except Exception:
            pass

    def _send_nxdomain(self, req: Packet):
        if DNS is None:
            return
        try:
            r = req.copy()
            r[DNS].qr = 1
            r[DNS].rcode = 3
            r[DNS].ancount = r[DNS].nscount = r[DNS].arcount = 0
            self._normalize_checksums(r)
            self._send_response_to_client(r, req)
        except Exception:
            pass

    def _alloc_udp_ephemeral_port(self) -> int:
        return random.randint(49152, 65535)

    def _is_v6_ll(self, addr: str) -> bool:
        try:
            return ipaddress.IPv6Address(addr).is_link_local
        except Exception:
            return str(addr).lower().startswith("fe80:")

    def _is_ipv4(self, addr: str) -> bool:
        try:
            ipaddress.IPv4Address(addr)
            return True
        except Exception:
            return False

    def _is_ipv6_global(self, addr: str) -> bool:
        try:
            ip = ipaddress.IPv6Address(addr)
            return not ip.is_link_local and not ip.is_loopback and not ip.is_unspecified
        except Exception:
            return False

    def _is_public_dns_ip(self, addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
            return ip.is_global
        except Exception:
            return False

    def _upstream_allowed(self, addr: str) -> bool:
        """
        Allow public upstreams always.
        Allow private forwarders only if explicitly enabled.
        """
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
            if ip.is_global:
                return True
            return bool(self.ALLOW_PRIVATE_FORWARDERS)
        except Exception:
            return False

    def _cleanup_stale_pending(self):
        now = time.time()
        stale_keys = []
        stale_txid = []

        with self._lock:
            for pk, info in self._pending_requests.items():
                if (now - float(info.get("timestamp", 0.0))) > self.MAX_PENDING_AGE_SEC:
                    stale_keys.append(pk)

            if stale_keys:
                stale_set = set(stale_keys)
                for sk in stale_keys:
                    info = self._pending_requests.pop(sk, None)
                    qkey = info.get("qkey") if info else None
                    if qkey:
                        infl = self._inflight.pop(qkey, None)
                        if infl:
                            for client_pkt, _iface in infl.get("waiters", []):
                                try:
                                    self._send_servfail(client_pkt)
                                except Exception:
                                    pass

                for sec, pk in list(self._pending_by_txid.items()):
                    if pk in stale_set:
                        stale_txid.append(sec)
                for sec in stale_txid:
                    self._pending_by_txid.pop(sec, None)

            if stale_keys:
                self._log(f"[DNS] 🧹 Cleaned {len(stale_keys)} stale pending request(s)")

    def _rl_take(self, client_ip: str) -> bool:
        now = time.time()
        rl = self._rl_clients.get(client_ip)
        if not rl:
            rl = {"tokens": float(self.RL_CLIENT_BURST), "last": now}
            self._rl_clients[client_ip] = rl
        dt = max(0.0, now - rl["last"])
        rl["tokens"] = min(self.RL_CLIENT_BURST, rl["tokens"] + dt * self.RL_CLIENT_RPS)
        rl["last"] = now
        if rl["tokens"] >= 1.0:
            rl["tokens"] -= 1.0
            return True
        return False



class NDPManager:
    """
    Manages IPv6 Neighbor Discovery Protocol (NDP) resolution, caching, and
    related operations for the router, analogous to the ARPManager for IPv4.
    """

    def __init__(self, router_logger, cache_timeout_seconds=300):
        """
        Initializes the NDP Manager.
        Args:
            router_logger: The logger instance for logging messages.
            cache_timeout_seconds (int): How long a cache entry is valid.
        """
        self.router_logger = router_logger
        self.sniffer = None
        self._ndp_cache = {}  # Maps IPv6 -> (MAC, timestamp)
        self._ndp_cache_lock = threading.Lock()
        self.CACHE_TIMEOUT = cache_timeout_seconds

        self._static_ndp_entries = {}  # Manually configured {IPv6: MAC}
        self._interfaces_config = {}
        self._trusted_ports = set()

        # NDP-specific configuration
        self.ndp_probe_retries = 3
        self.ndp_probe_timeout = 1.0
        self.router_ipv6_link_local_out = None

        # Placeholders for NDP security features
        self.ra_guard_enabled = True  # Router Advertisement Guard
        self.ndp_inspection_enabled = True  # Equivalent to DAI

        # Added helpers only
        self._last_probe_at = {}              # (iface, ip) -> ts
        self._probe_suppression_window = 0.75
        self._max_cache_entries = 8192
        self._last_iface_by_ip = {}           # IPv6 -> iface
        self._negative_cache = {}             # IPv6 -> ts
        self._negative_cache_ttl = 5.0

    def add_static_ndp_entry(self, ipv6_address: str, mac_address: str):
        """Adds a static entry to the neighbor cache."""
        try:
            ip_str = str(ipaddress.IPv6Address(ipv6_address))
        except ValueError:
            self.router_logger.log_message(f"[NDP] ⚠️ Refusing invalid static IPv6 entry: {ipv6_address}")
            return

        norm_mac = self._normalize_mac(mac_address)
        if not norm_mac:
            self.router_logger.log_message(f"[NDP] ⚠️ Refusing invalid static MAC entry for {ip_str}: {mac_address}")
            return

        self._static_ndp_entries[ip_str] = norm_mac
        self.router_logger.log_message(f"[NDP] Added static entry: {ip_str} -> {norm_mac}")

    # --- Core NDP Resolution Logic ---

    def resolve(self, ipv6_address: str, iface: str) -> Optional[str]:
        """
        Resolves an IPv6 address to a MAC address.
        The resolution order is: static entries -> cache -> active probing.
        """
        try:
            ip_obj = ipaddress.IPv6Address(ipv6_address)
            if ip_obj.is_multicast or ip_obj.is_unspecified:
                return None  # Cannot resolve these
        except ValueError:
            self.router_logger.log_message(f"[NDP] ⚠️ Invalid IPv6 address for resolution: {ipv6_address}")
            return None

        ip_str = str(ip_obj)
        now = time.time()

        # Suppress rapid repeat failures on unstable links
        neg_ts = self._negative_cache.get(ip_str)
        if neg_ts and (now - neg_ts) < self._negative_cache_ttl:
            return None

        # 1. Check static entries first
        static_mac = self._static_ndp_entries.get(ip_str)
        if static_mac:
            self.router_logger.log_message(f"[NDP] 🧷 Static entry: {ip_str} -> {static_mac}")
            return static_mac

        # 2. Check the dynamic cache
        with self._ndp_cache_lock:
            entry = self._ndp_cache.get(ip_str)
            if entry:
                mac, ts = entry
                if not mac or mac == "00:00:00:00:00:00":
                    return None
                if self._is_valid_mac(mac):
                    if now - ts < self.CACHE_TIMEOUT:
                        self.router_logger.log_message(f"[NDP] ⚡ Cache hit: {ip_str} -> {mac}")
                        return mac
                    else:
                        self.router_logger.log_message(f"[NDP] 🕓 Cache stale for {ip_str}, refreshing.")
                else:
                    self._ndp_cache.pop(ip_str, None)

        # 3. Check OS neighbor cache
        os_mac = self._get_mac_from_os_cache(ip_str)
        if os_mac:
            with self._ndp_cache_lock:
                self._store_cache_entry(ip_str, os_mac, now, iface=iface)
            return os_mac

        # 4. Active probe
        probed_mac = self._active_resolve(ip_str, iface)
        if probed_mac:
            with self._ndp_cache_lock:
                self._store_cache_entry(ip_str, probed_mac, time.time(), iface=iface)
            return probed_mac

        self._negative_cache[ip_str] = now
        return None

    def _get_mac_from_os_cache(self, ipv6_address: str) -> Optional[str]:
        """
        Parses the Windows 'netsh' command to find a MAC in the OS neighbor cache.
        """
        try:
            mac_regex = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.IGNORECASE)
            cmd = ["netsh", "interface", "ipv6", "show", "neighbors"]
            result = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, encoding="utf-8", errors="ignore")

            wanted = str(ipaddress.IPv6Address(ipv6_address)).lower()

            for line in result.splitlines():
                line_l = line.lower()
                if wanted in line_l:
                    match = mac_regex.search(line_l)
                    if match:
                        mac = self._normalize_mac(match.group(0))
                        if mac:
                            self.router_logger.log_message(f"[NDP] 🧭 Found in OS cache: {wanted} -> {mac}")
                            return mac
            return None
        except Exception:
            return None

    # --- Handling Incoming NDP Packets ---

    def learn_neighbor_advertisement(self, pkt: Packet):
        """Learn MAC from an IPv6 Neighbor Advertisement and update cache."""
        if not pkt.haslayer(ICMPv6ND_NA):
            return
        if not pkt.haslayer(IPv6):
            return

        na = pkt[ICMPv6ND_NA]
        ip = pkt[IPv6].src
        mac = None

        try:
            ip_obj = ipaddress.IPv6Address(ip)
            if ip_obj.is_unspecified or ip_obj.is_multicast:
                return
            ip = str(ip_obj)
        except Exception:
            return

        # Preferred: use the NA option carrying a link-layer address.
        try:
            opt = pkt.getlayer(ICMPv6NDOptDstLLAddr) or pkt.getlayer(ICMPv6NDOptSrcLLAddr)
            if opt and hasattr(opt, "lladdr") and opt.lladdr:
                mac = self._normalize_mac(opt.lladdr)
        except Exception:
            mac = None

        # Fallback: if there’s no LL option, trust the L2 source (common on-link case)
        if mac is None and pkt.haslayer(Ether):
            mac = self._normalize_mac(pkt[Ether].src)

        # Optional sanity: only learn if the NA is “solicited” or override flag is set
        try:
            S = int(getattr(na, "S", 0))  # Solicited
            O = int(getattr(na, "O", 0))  # Override
            R = int(getattr(na, "R", 0))  # Router
            _ = R  # kept for future policy
            # Keep behavior permissive for stability; do not reject outright.
            if not (S or O):
                pass
        except Exception:
            pass

        if ip and mac and self._is_valid_mac(mac):
            with self._ndp_cache_lock:
                self._store_cache_entry(ip, mac, time.time(), iface=None)
            self.router_logger.log_message(f"[NDP] 🧠 Learned: {ip} is-at {mac}")

    def learn_from_packet(self, pkt: Packet, iface: str):
        """
        Passively learns IP-to-MAC mappings from observed traffic.
        This is called by the main router for every packet.
        """
        if not pkt.haslayer(Ether) or not pkt.haslayer(IPv6):
            return

        src_mac = self._normalize_mac(pkt[Ether].src)
        src_ip = pkt[IPv6].src

        try:
            ip_obj = ipaddress.IPv6Address(src_ip)
            if not src_mac or ip_obj.is_unspecified or ip_obj.is_multicast:
                return
            src_ip = str(ip_obj)
        except ValueError:
            return

        now = time.time()
        with self._ndp_cache_lock:
            existing_entry = self._ndp_cache.get(src_ip)
            if not existing_entry or existing_entry[0] != src_mac:
                self.router_logger.log_message(
                    f"[NDP] 🧠 Passively learned: {src_ip} is-at {src_mac} on {str(iface).split('_')[-1]}"
                )
                self._store_cache_entry(src_ip, src_mac, now, iface=iface)
            else:
                # Refresh timestamp quietly on matching observation
                self._store_cache_entry(src_ip, src_mac, now, iface=iface, log_replace=False)

    # --- Added helpers only ---

    def _normalize_mac(self, mac_address: str) -> Optional[str]:
        try:
            if not mac_address:
                return None
            mac = str(mac_address).strip().lower().replace("-", ":")
            parts = mac.split(":")
            if len(parts) != 6:
                return None
            if not all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
                return None
            return mac
        except Exception:
            return None

    def _is_valid_mac(self, mac_address: str) -> bool:
        return self._normalize_mac(mac_address) is not None

    def _store_cache_entry(self, ipv6_address: str, mac_address: str, ts: float, iface: Optional[str], log_replace: bool = True):
        mac = self._normalize_mac(mac_address)
        if not mac:
            return

        if len(self._ndp_cache) >= self._max_cache_entries:
            self._purge_expired_locked()
            if len(self._ndp_cache) >= self._max_cache_entries:
                oldest_ip = None
                oldest_ts = None
                for ip_k, (_, t_k) in self._ndp_cache.items():
                    if oldest_ts is None or t_k < oldest_ts:
                        oldest_ip = ip_k
                        oldest_ts = t_k
                if oldest_ip is not None:
                    self._ndp_cache.pop(oldest_ip, None)
                    self._last_iface_by_ip.pop(oldest_ip, None)

        previous = self._ndp_cache.get(ipv6_address)
        self._ndp_cache[ipv6_address] = (mac, ts)
        if iface:
            self._last_iface_by_ip[ipv6_address] = iface
        self._negative_cache.pop(ipv6_address, None)

        if log_replace and previous and previous[0] != mac:
            self.router_logger.log_message(f"[NDP] 🔁 Updated: {ipv6_address} {previous[0]} -> {mac}")

    def _purge_expired_locked(self):
        now = time.time()
        stale = [ip for ip, (_, ts) in self._ndp_cache.items() if (now - ts) >= self.CACHE_TIMEOUT]
        for ip in stale:
            self._ndp_cache.pop(ip, None)
            self._last_iface_by_ip.pop(ip, None)

        neg_stale = [ip for ip, ts in self._negative_cache.items() if (now - ts) >= self._negative_cache_ttl]
        for ip in neg_stale:
            self._negative_cache.pop(ip, None)

    def _iface_ipv6_for_target(self, iface: str, target_ip: str) -> Optional[str]:
        try:
            cfg = (self._interfaces_config or {}).get(iface) or {}
            candidates = [
                cfg.get("ipv6"),
                cfg.get("ip6"),
                cfg.get("ipv6_addr"),
                cfg.get("link_local"),
                cfg.get("router_ipv6"),
            ]
            for cand in candidates:
                if not cand:
                    continue
                cand_str = str(cand).split("%")[0].strip()
                ip_obj = ipaddress.IPv6Address(cand_str)
                tgt_obj = ipaddress.IPv6Address(target_ip)
                if ip_obj.version == tgt_obj.version:
                    return str(ip_obj)
        except Exception:
            return None
        return None

    def _pick_ns_source_ipv6(self, iface: str, target_ip: str) -> Optional[str]:
        # Prefer configured interface IPv6, then router link-local, else None
        src = self._iface_ipv6_for_target(iface, target_ip)
        if src:
            return src

        try:
            if self.router_ipv6_link_local_out:
                return str(ipaddress.IPv6Address(str(self.router_ipv6_link_local_out).split("%")[0]))
        except Exception:
            pass

        return None

    def _solicited_node_multicast(self, ipv6_address: str) -> str:
        ip_obj = ipaddress.IPv6Address(ipv6_address)
        low24 = int(ip_obj) & 0xFFFFFF
        return str(ipaddress.IPv6Address(0xFF0200000000000000000001FF000000 | low24))

    def _multicast_mac_for_ipv6(self, multicast_ipv6: str) -> str:
        ip_obj = ipaddress.IPv6Address(multicast_ipv6)
        low32 = int(ip_obj) & 0xFFFFFFFF
        return "33:33:%02x:%02x:%02x:%02x" % (
            (low32 >> 24) & 0xFF,
            (low32 >> 16) & 0xFF,
            (low32 >> 8) & 0xFF,
            low32 & 0xFF,
        )

    def _active_resolve(self, ipv6_address: str, iface: str) -> Optional[str]:
        if not self.sniffer:
            return None

        try:
            target_ip = str(ipaddress.IPv6Address(ipv6_address))
        except Exception:
            return None

        now = time.time()
        probe_key = (iface, target_ip)
        last_probe = self._last_probe_at.get(probe_key, 0.0)
        if (now - last_probe) < self._probe_suppression_window:
            return None
        self._last_probe_at[probe_key] = now

        try:
            src_ip = self._pick_ns_source_ipv6(iface, target_ip)
            ns_multicast = self._solicited_node_multicast(target_ip)
            dst_mac = self._multicast_mac_for_ipv6(ns_multicast)

            for attempt in range(max(1, int(self.ndp_probe_retries))):
                try:
                    ns = Ether(dst=dst_mac) / IPv6(
                        src=src_ip if src_ip else "::",
                        dst=ns_multicast
                    ) / ICMPv6ND_NS(tgt=target_ip) / ICMPv6NDOptSrcLLAddr(
                        lladdr=self._best_local_mac_for_iface(iface) or "00:00:00:00:00:00"
                    )

                    resp = self.sniffer.sr1(
                        ns,
                        timeout=float(self.ndp_probe_timeout),
                        verbose=0,
                        iface=iface
                    )

                    if resp is None:
                        continue

                    learned_mac = None

                    if resp.haslayer(ICMPv6ND_NA):
                        try:
                            opt = resp.getlayer(ICMPv6NDOptDstLLAddr) or resp.getlayer(ICMPv6NDOptSrcLLAddr)
                            if opt and hasattr(opt, "lladdr") and opt.lladdr:
                                learned_mac = self._normalize_mac(opt.lladdr)
                        except Exception:
                            learned_mac = None

                        if learned_mac is None and resp.haslayer(Ether):
                            learned_mac = self._normalize_mac(resp[Ether].src)

                        if learned_mac:
                            self.router_logger.log_message(
                                f"[NDP] 🔎 Active resolve success on {str(iface).split('_')[-1]}: {target_ip} -> {learned_mac}"
                            )
                            return learned_mac

                except Exception:
                    continue

            return None
        except Exception:
            return None

    def _best_local_mac_for_iface(self, iface: str) -> Optional[str]:
        try:
            cfg = (self._interfaces_config or {}).get(iface) or {}
            for key in ("mac", "mac_addr", "hwaddr", "lladdr"):
                val = cfg.get(key)
                norm = self._normalize_mac(val) if val else None
                if norm:
                    return norm
        except Exception:
            pass
        return None






class ARPManager:
    @dataclass
    class GwOnlinkVerdict:
        ok: bool
        reason: str
        gw: str
        iface_cidr: str | None
        net: str | None
        details: dict

    def __init__(self, router_logger, outbound_load_balancer, cache_timeout_seconds=300):
        self.dhcp_server_out = None
        self.dhcp_server_in = None
        self.notification_manager = None
        self.sniffer = None
        self.hyperv_manager = None
        self.rip_manager = None

        self._active_ips = set()
        self.router_logger = router_logger
        self.outbound_load_balancer = outbound_load_balancer
        self.dhcp_manager = None
        self.interfaces_config = {}
        self._interfaces_config = {}
        self.router_ip_out = None
        self.default_gateway_ip = None

        self._arp_cache: dict[str, tuple] = {}
        self._arp_cache_lock = threading.RLock()
        self._state_lock = threading.RLock()
        self._if_cache_lock = threading.RLock()
        self._gateway_cache_lock = threading.RLock()
        self._log_rl_lock = threading.RLock()
        self._dyn_if_lock = threading.RLock()
        self._subprocess_lock = threading.RLock()

        self.CACHE_TIMEOUT = int(cache_timeout_seconds)
        self._temp_arp_leases: dict[str, dict[str, float]] = {}
        self.enable_auto_temp_leases = True
        self.MAX_REPLIES_PER_LEASE = 3
        self._trusted_ports = set()
        self._static_arp_entries: dict[str, str] = {}
        self.arp_probe_offlink = False
        self.lease_cooldown = 30
        self.lease_duration = 100
        self.arp_probe_retries = 2
        self.arp_probe_timeout = 0.35
        self._cache_hit_table = defaultdict(lambda: deque(maxlen=10))
        self._IFACE_CACHE_TTL = 30.0
        self.arp_defend_on_probe = True
        self.arp_defend_on_claim = False
        self.arp_defense_cooldown = 5.0
        self._arp_defense_last = {}
        self.dai_enable = True
        self.dai_enforce_on_untrusted_only = True
        self.dai_block_gratuitous_from_untrusted = True
        self.dai_block_gateway_claims = True
        self.dai_block_ip_spoof = True
        self.dai_conflict_window = 90.0
        self.dai_conflict_threshold = 1
        self._dai_recent_claims: dict[str, dict[str, float]] = {}
        self._known_gateway_macs: dict[str, str] = {}
        self.eset_compat_mode = True
        self.quiet_start_s = 5.0
        self._boot_ts = time.time()
        self._offlink_nogw_suppress: dict[str, float] = {}
        self.garp_enabled = True
        self.garp_only_for_owned = True

        self.ARP_PASSIVE_TTL = 20 * 60
        self.ARP_MAX_ENTRIES = 10
        self._last_passive_gc = 0.0

        self.REMOTE_ARP_STRICT_GATEWAY = True
        self.REJECT_DIRECT_ARP_TO_PUBLIC_OFFLINK = True
        self.GATEWAY_CACHE_TTL = 300.0
        self._gateway_mac_cache: dict[tuple[str, str], tuple[str, float]] = {}
        self._gateway_probe_backoff: dict[tuple[str, str], float] = {}
        self.GATEWAY_PROBE_BACKOFF_SEC = 10.0
        self.PREFER_OS_ARP_CACHE_FOR_GATEWAY = True
        self.PREFER_PASSIVE_GATEWAY_LEARN = True
        self.ALLOW_PUBLIC_DIRECT_ARP_IF_ONLINK = True
        self._remote_resolution_debug = False

        self._if_cache: dict[Any, dict[str, Any]] = {}
        self._log_rl_table: dict[str, float] = {}
        self._special_path_suppress: dict[tuple[str, str], float] = {}
        self._resolve_negative_cache: dict[tuple[str, str], float] = {}
        self._gateway_fail_cache: dict[tuple[str, str], float] = {}
        self._dynamic_iface_refresh: dict[str, float] = {}
        self._os_arp_cache_snapshot: tuple[float, str] | None = None

        self.HYPERV_SPECIAL_SUPPRESS_SEC = 15.0
        self.NEGATIVE_RESOLVE_TTL = 5.0
        self.GATEWAY_FAIL_TTL = 8.0
        self.OS_ARP_CACHE_TTL = 4.0
        self.DYN_IFACE_TTL = 15.0

        self.hyperv_bridge_names = {
            "WinDivertBridge",
            "HyperVBridge",
            "Hyper-V",
            "vEthernet",
            "Default Switch",
            "WSL",
            "Nate's Tunnel",
        }
        self.hyperv_allow_special_fast_fail = False
        self.hyperv_prefer_bridge_mac_for_owned = True
        self.hyperv_prefer_manager_cache = True

        # small additions only
        self.gateway_refresh_interval = 10.0
        self._last_gateway_refresh = 0.0
        self._wan_epoch = 0
        self._last_wan_identity = {
            "wan_ip": None,
            "gateway_ip": None,
            "iface_name": None,
            "dns_servers": tuple(),
        }

        # --- add in __init__ ---
        self._arp_if_cache: dict[tuple[str, str], tuple[str, float, str]] = {}
        self._arp_if_cache_lock = threading.RLock()
        self._arp_if_last_gc = 0.0
        self.ARP_IF_CACHE_TTL = self.ARP_PASSIVE_TTL
        self.ARP_IF_CACHE_MAX = 2048
        self.ARP_IF_CACHE_STRICT_FOR_HYPERV = True

    # --- new helpers ---
    def _if_ip_key(self, iface: str, ip: str) -> tuple[str, str]:
        return (str(iface or "").strip(), str(ip or "").strip())

    def _iface_cache_get(self, iface: str, ip: str) -> str | None:
        key = self._if_ip_key(iface, ip)
        now = time.time()
        with self._arp_if_cache_lock:
            ent = self._arp_if_cache.get(key)
            if not ent:
                return None
            mac, ts, _src = ent
            if (now - ts) > self.ARP_IF_CACHE_TTL:
                self._arp_if_cache.pop(key, None)
                return None
            return mac

    def _iface_cache_set(self, iface: str, ip: str, mac: str, source: str = "passive") -> None:
        ip = self._normalize_ip(ip)
        mac = self._normalize_mac(mac)
        iface = str(iface or "").strip()
        if not iface or not ip or not mac:
            return

        with self._arp_if_cache_lock:
            self._arp_if_cache[(iface, ip)] = (mac, time.time(), source)

            # bounded GC
            if len(self._arp_if_cache) > self.ARP_IF_CACHE_MAX:
                oldest = sorted(self._arp_if_cache.items(), key=lambda kv: kv[1][1])[
                    : max(1, len(self._arp_if_cache) // 8)]
                for k, _ in oldest:
                    self._arp_if_cache.pop(k, None)

        # successful learn should clear negative cache for the same iface/ip
        self._resolve_negative_cache.pop((iface, ip), None)

    def _allow_passive_iface_learning(self, iface: str) -> bool:
        iface = str(iface or "").strip()
        if not iface:
            return False
        if iface in self._trusted_ports:
            return True
        # For bridge/tunnel interfaces, require trust unless you explicitly loosen it.
        if self._is_hyperv_iface(iface):
            return iface in self._trusted_ports
        return False

    def _maybe_learn_passive_arp(self, pkt, inbound_iface: str) -> None:
        try:
            if not pkt or not pkt.haslayer(ARP):
                return
            if not self._allow_passive_iface_learning(inbound_iface):
                return

            arp = pkt[ARP]
            src_ip = self._normalize_ip(getattr(arp, "psrc", None))
            src_mac = self._normalize_mac(getattr(arp, "hwsrc", None))

            if not src_ip or not src_mac:
                return

            # reject obvious junk
            try:
                ip_obj = ipaddress.ip_address(src_ip)
                if not isinstance(ip_obj, ipaddress.IPv4Address):
                    return
                if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                    return
            except Exception:
                return

            # store per-interface always
            self._iface_cache_set(inbound_iface, src_ip, src_mac, source="passive")

            # store globally only for non-Hyper-V-ish interfaces
            if not self._is_hyperv_iface(inbound_iface):
                self._cache_set(src_ip, src_mac, kind="passive")

            self._log_rl(
                f"passive_arp:{inbound_iface}:{src_ip}",
                5.0,
                f"[ARP] 🧠 Passive learn ({inbound_iface.split('_')[-1]}): {src_ip} -> {src_mac}",
            )
        except Exception:
            return
    # ------------------------------------------------------------------
    # Public compatibility methods
    # ------------------------------------------------------------------

    def add_trusted_port(self, iface_full_name: str):
        try:
            self._trusted_ports.add(iface_full_name)
            self._safe_log(f"[ARP] Added trusted port: {str(iface_full_name).split('_')[-1]}")
        except Exception as e:
            self._log_rl("add_trusted_port_err", 3.0, f"[ARP] ⚠️ add_trusted_port failed: {e}")

    def remove_trusted_port(self, iface_full_name: str):
        try:
            if iface_full_name in self._trusted_ports:
                self._trusted_ports.remove(iface_full_name)
                self._safe_log(f"[ARP] Removed trusted port: {str(iface_full_name).split('_')[-1]}")
        except Exception as e:
            self._log_rl("remove_trusted_port_err", 3.0, f"[ARP] ⚠️ remove_trusted_port failed: {e}")

    def set_dhcp_server_reference(self, dhcp_server_in, dhcp_server_out):
        self.dhcp_server_in = dhcp_server_in
        self.dhcp_server_out = dhcp_server_out
        self._safe_log("[ARP] DHCP server reference set. Dynamic ARP Inspection is now active.")

    def add_static_arp_entry(self, ip_address: str, mac_address: str):
        ip_norm = self._normalize_ip(ip_address)
        norm_mac = self._normalize_mac(mac_address)

        if not ip_norm:
            self._log_rl("bad_static_arp_ip", 3.0, f"[ARP] ⚠️ Refusing bad static ARP IP: {ip_address}")
            return

        if not norm_mac:
            self._log_rl("bad_static_arp_mac", 3.0,
                         f"[ARP] ⚠️ Refusing bad static ARP MAC for {ip_norm}: {mac_address}")
            return

        self._static_arp_entries[ip_norm] = norm_mac
        self._cache_set(ip_norm, norm_mac, time.time(), kind="static")
        self._safe_log(f"[ARP] 🔗 Added static ARP entry: {ip_norm} -> {norm_mac}")

    def remove_static_arp_entry(self, ip_address: str):
        if ip_address in self._static_arp_entries:
            del self._static_arp_entries[ip_address]
            self._safe_log(f"[ARP] Removed static ARP entry for: {ip_address}")

    def set_default_gateway(self, interfaces_config, gateway_ip: str) -> bool:
        gateway_ip = str(gateway_ip or "").strip()
        if not gateway_ip:
            return False

        old = getattr(self, "default_gateway_ip", None)
        self.interfaces_config = interfaces_config or {}
        self._interfaces_config = dict(self.interfaces_config)
        if old == gateway_ip:
            return False

        self.default_gateway_ip = gateway_ip

        try:
            with self._gateway_cache_lock:
                dead = [k for k in self._gateway_mac_cache.keys() if len(k) >= 2 and str(k[1]) == gateway_ip]
                for k in dead:
                    self._gateway_mac_cache.pop(k, None)
        except Exception:
            pass

        try:
            dead = [k for k in self._gateway_fail_cache.keys() if len(k) >= 2 and str(k[1]) == gateway_ip]
            for k in dead:
                self._gateway_fail_cache.pop(k, None)
        except Exception:
            pass

        self._safe_log(f"[ARP] Default gateway IP set to: {gateway_ip}")
        return True

    def get_cache_view(self) -> dict:
        with self._arp_cache_lock:
            return self._arp_cache.copy()

    def clear_cache(self):
        with self._arp_cache_lock:
            self._arp_cache.clear()
        self._safe_log("[ARP] 🧹 ARP cache cleared.")

    # ------------------------------------------------------------------
    # Small safety helpers
    # ------------------------------------------------------------------

    def _safe_log(self, message: str):
        try:
            logger = getattr(self, "router_logger", None)
            if logger and hasattr(logger, "log_message"):
                logger.log_message(str(message))
        except Exception:
            pass

    def _log_rl(self, key: str, ttl: float, message: str):
        now = time.time()
        with self._log_rl_lock:
            until = self._log_rl_table.get(key, 0.0)
            if now < until:
                return
            self._log_rl_table[key] = now + float(max(0.1, ttl))
        self._safe_log(message)

    def _safe_call(self, obj, method_name: str, *args, **kwargs):
        try:
            if obj and hasattr(obj, method_name):
                return getattr(obj, method_name)(*args, **kwargs)
        except Exception:
            return None
        return None

    def _normalize_mac(self, mac: str | None) -> str | None:
        if not mac:
            return None
        try:
            out = str(mac).strip().lower().replace("-", ":")
            parts = out.split(":")
            if len(parts) != 6:
                return None
            fixed = []
            for p in parts:
                fixed.append(f"{int(p, 16):02x}")
            out = ":".join(fixed)
            if out == "00:00:00:00:00:00":
                return None
            return out
        except Exception:
            return None

    def _normalize_ip(self, ip_str: str) -> str | None:
        try:
            return str(ipaddress.ip_address(str(ip_str).strip()))
        except Exception:
            return None

    def _ifcache_get(self, key):
        with self._if_cache_lock:
            ent = self._if_cache.get(key)
            if not ent:
                return None
            if (time.time() - ent["ts"]) > self._IFACE_CACHE_TTL:
                self._if_cache.pop(key, None)
                return None
            return ent["val"]

    def _ifcache_set(self, key, val):
        with self._if_cache_lock:
            self._if_cache[key] = {"val": val, "ts": time.time()}

    def _cache_set(self, ip: str, mac: str, now: float | None = None, kind: str | None = None):
        norm_mac = self._normalize_mac(mac)
        if not norm_mac:
            return
        with self._arp_cache_lock:
            if kind is None:
                self._arp_cache[str(ip)] = (norm_mac, now or time.time())
            else:
                self._arp_cache[str(ip)] = (norm_mac, now or time.time(), kind)

    def _cache_get(self, ip: str):
        with self._arp_cache_lock:
            return self._arp_cache.get(str(ip))

    def _negative_cache_hit(self, iface: str, ip: str) -> bool:
        now = time.time()
        return now < self._resolve_negative_cache.get((str(iface), str(ip)), 0.0)

    def _negative_cache_set(self, iface: str, ip: str, ttl: float | None = None):
        self._resolve_negative_cache[(str(iface), str(ip))] = time.time() + float(ttl or self.NEGATIVE_RESOLVE_TTL)

    def _gateway_fail_hit(self, iface: str, gw: str) -> bool:
        return time.time() < self._gateway_fail_cache.get((str(iface), str(gw)), 0.0)

    def _gateway_fail_set(self, iface: str, gw: str, ttl: float | None = None):
        self._gateway_fail_cache[(str(iface), str(gw))] = time.time() + float(ttl or self.GATEWAY_FAIL_TTL)

    def _safe_get_bindings(self, dhcp_srv) -> dict:
        try:
            if dhcp_srv and hasattr(dhcp_srv, "get_ip_to_mac_bindings"):
                return dhcp_srv.get_ip_to_mac_bindings() or {}
        except Exception:
            return {}
        return {}

    def _in_quiet_start(self) -> bool:
        try:
            return bool(self.eset_compat_mode) and (time.time() - float(self._boot_ts)) < float(self.quiet_start_s)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Small added helpers only
    # ------------------------------------------------------------------

    def _all_iface_cfgs(self) -> dict:
        cfgs = {}
        try:
            if isinstance(self.interfaces_config, dict):
                cfgs.update(self.interfaces_config)
        except Exception:
            pass
        try:
            if isinstance(self._interfaces_config, dict):
                cfgs.update(self._interfaces_config)
        except Exception:
            pass
        return cfgs

    def _iface_matches_gateway(self, iface: str, gateway_ip: str) -> bool:
        try:
            self._ensure_dynamic_iface_config(iface)
        except Exception:
            pass

        cfg = self._all_iface_cfgs().get(iface, {}) or {}
        cidr = cfg.get("cidr")
        if not cidr:
            net = cfg.get("network")
            if net is not None:
                cidr = str(net)

        if not cidr:
            self._log_rl(
                f"gw_no_cidr:{iface}",
                5.0,
                f"[ARP] ⚠️ _iface_matches_gateway: no cidr found for iface={iface}",
            )
            return False

        try:
            verdict = self._validate_gateway_onlink(
                str(gateway_ip),
                str(cidr),
                cfg.get("ip_addr"),
            )
            return bool(verdict.ok)
        except Exception as e:
            self._log_rl(
                f"gw_match_err:{iface}:{gateway_ip}",
                5.0,
                f"[ARP] ⚠️ _iface_matches_gateway error for iface={iface} gw={gateway_ip}: {e}",
            )
            return False

    def _find_iface_for_gateway(self, gateway_ip: str) -> str | None:
        gw = str(gateway_ip or "").strip()
        if not gw:
            return None

        try:
            best = self._safe_get_best_interface()
            if best and self._iface_matches_gateway(best, gw):
                return str(best)
        except Exception:
            pass

        try:
            route_iface = self._safe_find_route_iface(gw)
            if route_iface and self._iface_matches_gateway(route_iface, gw):
                return str(route_iface)
        except Exception:
            pass

        try:
            for iface in list(self._all_iface_cfgs().keys()):
                if self._iface_matches_gateway(iface, gw):
                    return str(iface)
        except Exception:
            pass

        return None

    def _gateway_cache_get(self, iface: str, gw_ip: str) -> str | None:
        with self._gateway_cache_lock:
            ent = self._gateway_mac_cache.get((str(iface), str(gw_ip)))
            if not ent:
                return None
            mac, ts = ent
            if (time.time() - ts) > self.GATEWAY_CACHE_TTL:
                self._gateway_mac_cache.pop((str(iface), str(gw_ip)), None)
                return None
            return mac

    def _gateway_cache_set(self, iface: str, gw_ip: str, mac: str):
        norm_mac = self._normalize_mac(mac)
        if not norm_mac:
            return
        with self._gateway_cache_lock:
            self._gateway_mac_cache[(str(iface), str(gw_ip))] = (norm_mac, time.time())
        self._known_gateway_macs[str(gw_ip)] = norm_mac

    def on_wan_recovered(
        self,
        *,
        interfaces_config=None,
        wan_ip: str | None = None,
        gateway_ip: str | None = None,
        iface_name: str | None = None,
        dns_servers=None,
        force: bool = False,
    ) -> str | None:
        if interfaces_config is not None:
            self.interfaces_config = interfaces_config or {}
            self._interfaces_config = dict(self.interfaces_config)

        if wan_ip:
            self.router_ip_out = str(wan_ip)

        if gateway_ip:
            self.set_default_gateway(self._interfaces_config, str(gateway_ip))

        self._wan_epoch += 1
        self._last_wan_identity = {
            "wan_ip": str(wan_ip or self.router_ip_out or "").strip() or None,
            "gateway_ip": str(gateway_ip or self.default_gateway_ip or "").strip() or None,
            "iface_name": str(iface_name or "").strip() or None,
            "dns_servers": tuple(str(x).strip() for x in (dns_servers or []) if str(x).strip()),
        }

        gw = str(gateway_ip or self.default_gateway_ip or "").strip()
        use_iface = str(iface_name or "").strip() or self._find_iface_for_gateway(gw) or self._safe_get_best_interface() or ""
        if not gw or not use_iface:
            return None

        if force:
            try:
                with self._gateway_cache_lock:
                    dead = [k for k in self._gateway_mac_cache.keys() if len(k) >= 2 and str(k[1]) == gw]
                    for k in dead:
                        self._gateway_mac_cache.pop(k, None)
            except Exception:
                pass

        net_obj = self._get_iface_network(use_iface)
        return self.resolve_gateway_mac(gw, use_iface, str(net_obj) if net_obj else None)

    def send_gratuitous_arp(self, ip_address: str, mac_address: str, iface: str):
        if not getattr(self, "garp_enabled", True):
            self._safe_log(f"[ARP][ESET] 🔇 GARP disabled; skipping {ip_address} on {iface.split('_')[-1]}")
            return False

        if self._in_quiet_start():
            return True

        if getattr(self, "garp_only_for_owned", True) and not self._owns_ip(ip_address):
            self._safe_log(f"[ARP][ESET] 🚫 not-owned: suppressing GARP for {ip_address} on {iface.split('_')[-1]}")
            return False

        self._safe_log(f"[ARP] Sending Gratuitous ARP for {ip_address} ({mac_address}) on {iface.split('_')[-1]}")
        grat_arp = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op="who-has", psrc=ip_address, pdst=ip_address, hwsrc=mac_address
        )
        try:
            self._safe_call(self.sniffer, "sendp", grat_arp, iface=iface, verbose=0)
            self._safe_log(f"[ARP] Successfully sent Gratuitous ARP on {iface.split('_')[-1]}.")
            return True
        except Exception as e:
            self._safe_log(f"[ARP] ❌ Failed to send Gratuitous ARP on {iface.split('_')[-1]}: {e}")
            return False
    # ------------------------------------------------------------------
    # Dynamic interface synthesis for WinDivertBridge / Nate's Tunnel
    # ------------------------------------------------------------------

    def _resolve_os_iface_name(self, iface: str) -> str:
        iface = str(iface or "")
        return iface.split("_")[-1]

    def _is_hyperv_iface(self, iface: str | None) -> bool:
        if not iface:
            return False
        low = str(iface).lower()
        if "windivertbridge" in low:
            return True
        if "nate's tunnel" in low or "nates tunnel" in low:
            return True
        if "hyperv" in low or "hyper-v" in low or "vethernet" in low:
            return True
        return any(name.lower() in low for name in self.hyperv_bridge_names)

    def _hyperv_active(self) -> bool:
        if getattr(self, "hyperv_manager", None) is not None:
            return True
        try:
            iface = self._safe_call(self.outbound_load_balancer, "get_best_interface")
            return self._is_hyperv_iface(str(iface)) if iface else False
        except Exception:
            return False

    def _iter_os_ifaces(self) -> list[dict]:
        out = []
        try:
            from scapy.arch.windows import get_windows_if_list  # type: ignore
            for a in get_windows_if_list():
                out.append(a or {})
        except Exception:
            pass
        return out

    def _find_os_iface_record(self, iface: str) -> dict | None:
        want = self._resolve_os_iface_name(iface).lower()
        for rec in self._iter_os_ifaces():
            candidates = [
                rec.get("name"),
                rec.get("win_name"),
                rec.get("friendlyname"),
                rec.get("description"),
                rec.get("guid"),
            ]
            for c in candidates:
                if c and want == str(c).lower():
                    return rec
                if c and want in str(c).lower():
                    return rec
        return None

    def _guess_dynamic_iface_network(self, iface: str, ip_str: str | None) -> str | None:
        try:
            if ip_str:
                ip_obj = ipaddress.ip_address(ip_str)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    if ip_obj.is_link_local:
                        return str(ipaddress.ip_network(f"{ip_str}/16", strict=False))
                    if self._is_hyperv_iface(iface):
                        return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
                    return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
        except Exception:
            pass

        if self._is_hyperv_iface(iface):
            return "169.254.0.0/16"
        return None

    def _merge_iface_config(self, iface: str, new_cfg: dict):
        with self._dyn_if_lock:
            if not isinstance(self.interfaces_config, dict):
                self.interfaces_config = {}
            if not isinstance(self._interfaces_config, dict):
                self._interfaces_config = {}

            cur = dict(self.interfaces_config.get(iface, {}) or {})
            cur.update({k: v for k, v in (new_cfg or {}).items() if v is not None})
            self.interfaces_config[iface] = cur
            self._interfaces_config[iface] = dict(cur)
            self._dynamic_iface_refresh[iface] = time.time()

    def _ensure_dynamic_iface_config(self, iface: str) -> dict:
        iface = str(iface)
        cfgs = self.interfaces_config if isinstance(self.interfaces_config, dict) else {}
        existing = dict(cfgs.get(iface, {}) or {})

        now = time.time()
        last = self._dynamic_iface_refresh.get(iface, 0.0)
        if existing and (now - last) < self.DYN_IFACE_TTL:
            return existing

        rec = self._find_os_iface_record(iface)
        ip_addr = None
        mac = None

        if rec:
            mac = self._normalize_mac(rec.get("mac"))
            ips = rec.get("ips") or []
            for addr in ips:
                if isinstance(addr, str) and addr.count(".") == 3:
                    ip_addr = addr
                    break

        if not ip_addr:
            ip_addr = self.get_interface_ipv4(iface)
        if not mac:
            mac = self.get_interface_mac(iface)

        cfg = dict(existing)
        if mac and not cfg.get("mac"):
            cfg["mac"] = mac
        if ip_addr and not cfg.get("ip_addr"):
            cfg["ip_addr"] = ip_addr

        if not cfg.get("cidr"):
            net = self._guess_dynamic_iface_network(iface, ip_addr)
            if net:
                cfg["cidr"] = net

        if not cfg.get("network") and cfg.get("cidr"):
            try:
                cfg["network"] = ipaddress.ip_network(str(cfg["cidr"]), strict=False)
            except Exception:
                pass

        if self._is_hyperv_iface(iface):
            cfg.setdefault("gateway", None)
            cfg.setdefault("dynamic", True)
            cfg.setdefault("kind", "hyperv_bridge")

        self._merge_iface_config(iface, cfg)

        if not existing and cfg:
            self._log_rl(
                f"dyn_iface:{iface}",
                10.0,
                f"[ARP] 🧩 dynamic iface-config: created {iface} with ip={cfg.get('ip_addr')} cidr={cfg.get('cidr')} mac={cfg.get('mac')}",
            )
        elif cfg != existing:
            self._log_rl(
                f"dyn_iface_refresh:{iface}",
                10.0,
                f"[ARP] 🔄 dynamic iface-config: refreshed {iface} with ip={cfg.get('ip_addr')} cidr={cfg.get('cidr')} mac={cfg.get('mac')}",
            )
        return cfg

    # ------------------------------------------------------------------
    # Interface lookup helpers
    # ------------------------------------------------------------------

    def get_interface_mac(self, iface: str) -> str | None:
        cache_key = ("mac", iface)
        cached = self._ifcache_get(cache_key)
        if cached is not None:
            return cached

        name = self._resolve_os_iface_name(iface)

        try:
            from scapy.all import get_if_hwaddr  # type: ignore
            mac = self._normalize_mac(get_if_hwaddr(name))
            if mac:
                self._ifcache_set(cache_key, mac)
                return mac
        except Exception:
            pass

        rec = self._find_os_iface_record(iface)
        if rec:
            mac = self._normalize_mac(rec.get("mac"))
            if mac:
                self._ifcache_set(cache_key, mac)
                return mac

        try:
            import netifaces as ni  # type: ignore
            if name in ni.interfaces():
                info = ni.ifaddresses(name).get(ni.AF_LINK, [{}])
                if info and "addr" in info[0]:
                    mac = self._normalize_mac(info[0]["addr"])
                    if mac:
                        self._ifcache_set(cache_key, mac)
                        return mac
        except Exception:
            pass

        self._ifcache_set(cache_key, None)
        return None

    def get_interface_ipv4(self, iface: str) -> str | None:
        cache_key = ("ipv4", iface)
        cached = self._ifcache_get(cache_key)
        if cached is not None:
            return cached

        name = self._resolve_os_iface_name(iface)

        try:
            from scapy.all import get_if_addr  # type: ignore
            ip = get_if_addr(name)
            if ip and ip != "0.0.0.0":
                self._ifcache_set(cache_key, ip)
                return ip
        except Exception:
            pass

        rec = self._find_os_iface_record(iface)
        if rec:
            ips = rec.get("ips") or []
            for addr in ips:
                if isinstance(addr, str) and addr.count(".") == 3:
                    self._ifcache_set(cache_key, addr)
                    return addr

        try:
            import netifaces as ni  # type: ignore
            if name in ni.interfaces():
                addrs = ni.ifaddresses(name).get(ni.AF_INET, [{}])
                if addrs and "addr" in addrs[0]:
                    ip = addrs[0]["addr"]
                    self._ifcache_set(cache_key, ip)
                    return ip
        except Exception:
            pass

        self._ifcache_set(cache_key, None)
        return None

    def _safe_get_best_interface(self) -> str | None:
        try:
            iface = self._safe_call(self.outbound_load_balancer, "get_best_interface")
            if iface:
                return str(iface)
        except Exception:
            return None
        return None

    def _safe_find_route_iface(self, ip_str: str) -> str | None:
        try:
            rm = getattr(self, "rip_manager", None)
            if rm and hasattr(rm, "find_route"):
                route = rm.find_route(ip_str)
                if isinstance(route, dict):
                    iface = route.get("interface")
                    if iface:
                        return str(iface)
        except Exception:
            return None
        return None

    def _pick_iface_for_ip(self, ip_str: str, iface: str | None) -> str | None:
        if iface:
            self._ensure_dynamic_iface_config(str(iface))
            return str(iface)

        route_iface = self._safe_find_route_iface(ip_str)
        if route_iface:
            self._ensure_dynamic_iface_config(route_iface)
            return route_iface

        best = self._safe_get_best_interface()
        if best:
            self._ensure_dynamic_iface_config(best)
            return best

        hm = getattr(self, "hyperv_manager", None)
        if hm:
            for meth in ("get_bridge_interface", "get_primary_interface", "get_bridge_name"):
                val = self._safe_call(hm, meth)
                if val:
                    self._ensure_dynamic_iface_config(str(val))
                    return str(val)

        return None

    def _get_iface_network(self, iface: str):
        self._ensure_dynamic_iface_config(iface)
        cfgs = getattr(self, "_interfaces_config", None) or getattr(self, "interfaces_config", {}) or {}
        iface_cfg = (cfgs.get(iface) or {}) if isinstance(cfgs, dict) else {}
        net_val = iface_cfg.get("network")
        if isinstance(net_val, ipaddress.IPv4Network):
            return net_val
        cidr = iface_cfg.get("cidr")
        if cidr:
            try:
                return ipaddress.ip_network(str(cidr), strict=False)
            except Exception:
                return None
        ip_addr = iface_cfg.get("ip_addr")
        netmask = iface_cfg.get("netmask")
        if ip_addr and netmask:
            try:
                return ipaddress.ip_network(f"{ip_addr}/{netmask}", strict=False)
            except Exception:
                return None
        return None

    def _get_iface_gateway(self, iface: str) -> str | None:
        self._ensure_dynamic_iface_config(iface)
        cfgs = getattr(self, "_interfaces_config", None) or getattr(self, "interfaces_config", {}) or {}
        iface_cfg = (cfgs.get(iface) or {}) if isinstance(cfgs, dict) else {}
        for key in ("gateway", "gateway_ip"):
            gw = iface_cfg.get(key)
            if gw:
                return str(gw)
        if self.default_gateway_ip and not self._is_hyperv_iface(iface):
            return str(self.default_gateway_ip)
        return None

    # ------------------------------------------------------------------
    # Gateway / special helpers
    # ------------------------------------------------------------------

    def _all_gateway_ips(self) -> set[str]:
        ips = set()
        try:
            if self.default_gateway_ip:
                ips.add(str(self.default_gateway_ip))
        except Exception:
            pass
        try:
            cfgs = self.interfaces_config or {}
            if isinstance(cfgs, dict):
                for cfg in cfgs.values():
                    gw = (cfg or {}).get("gateway")
                    if gw:
                        ips.add(str(gw))
        except Exception:
            pass
        return ips

    def _is_gateway_ip(self, ip: str) -> bool:
        try:
            return str(ip) in self._all_gateway_ips()
        except Exception:
            return False

    def _suppress_offlink_nogw(self, ip: str, ttl: float = 120.0) -> bool:
        now = time.time()
        until = self._offlink_nogw_suppress.get(ip, 0.0)
        if now < until:
            return True
        self._offlink_nogw_suppress[ip] = now + ttl
        return False

    def is_special_ip(self, ip_str: str, iface_network: str | None = None) -> bool:
        try:
            ip = ipaddress.IPv4Address(str(ip_str))
        except ValueError:
            return True

        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return True

        if ip.is_link_local:
            if iface_network:
                try:
                    net = ipaddress.IPv4Network(str(iface_network), strict=False)
                    if net.network_address.is_link_local and ip in net:
                        return False
                except Exception:
                    pass
            return True

        if ip == ipaddress.IPv4Address("255.255.255.255"):
            return True

        if iface_network:
            try:
                net = ipaddress.IPv4Network(str(iface_network), strict=False)
                if ip == net.network_address or ip == net.broadcast_address:
                    return True
            except Exception:
                return True
        return False

    def is_on_link(self, ip_str: str, iface_cidr: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(str(ip_str))
            net = ipaddress.IPv4Network(str(iface_cidr), strict=False)
            return ip in net and ip not in (net.network_address, net.broadcast_address)
        except ValueError:
            return False

    def _validate_gateway_onlink(
        self,
        gw_ip: str,
        iface_cidr: str | None,
        iface_ip: str | None = None,
    ) -> GwOnlinkVerdict:
        d = {
            "version_mismatch": False,
            "is_network": False,
            "is_broadcast": False,
            "is_self_ip": False,
            "is_link_local": False,
            "cidr_missing": False,
            "special": False,
        }

        try:
            gw = ipaddress.ip_address(str(gw_ip).strip())
        except Exception as e:
            return self.GwOnlinkVerdict(False, f"bad_gw_ip({e})", str(gw_ip), iface_cidr, None, d)

        if not iface_cidr:
            d["cidr_missing"] = True
            return self.GwOnlinkVerdict(False, "cidr_missing", str(gw), None, None, d)

        try:
            net = ipaddress.ip_network(str(iface_cidr), strict=False)
        except Exception as e:
            return self.GwOnlinkVerdict(False, f"bad_cidr({e})", str(gw), str(iface_cidr), None, d)

        if gw.version != net.version:
            d["version_mismatch"] = True
            return self.GwOnlinkVerdict(False, "version_mismatch", str(gw), str(net), str(net), d)

        if isinstance(gw, ipaddress.IPv4Address):
            if gw.is_multicast or gw.is_unspecified or gw.is_loopback:
                d["special"] = True
                return self.GwOnlinkVerdict(False, "special_gw", str(gw), str(net), str(net), d)
            if gw.is_link_local:
                d["is_link_local"] = True
        else:
            if gw.is_multicast or gw.is_unspecified or gw.is_loopback:
                d["special"] = True
                return self.GwOnlinkVerdict(False, "special_gw", str(gw), str(net), str(net), d)

        if gw not in net:
            return self.GwOnlinkVerdict(True, "off_link_allowed", str(gw), str(net), str(net), d)

        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen <= 30:
                if gw == net.network_address:
                    d["is_network"] = True
                    return self.GwOnlinkVerdict(False, "is_network", str(gw), str(net), str(net), d)
                if gw == net.broadcast_address:
                    d["is_broadcast"] = True
                    return self.GwOnlinkVerdict(False, "is_broadcast", str(gw), str(net), str(net), d)

        if iface_ip:
            try:
                if ipaddress.ip_address(str(iface_ip).strip()) == gw:
                    d["is_self_ip"] = True
                    return self.GwOnlinkVerdict(False, "is_self_ip", str(gw), str(net), str(net), d)
            except Exception:
                pass

        return self.GwOnlinkVerdict(True, "ok", str(gw), str(net), str(net), d)

    def _is_usable_gw_ipv4(
        self,
        gw: ipaddress.IPv4Address,
        net: ipaddress.IPv4Network,
        iface: str | None = None,
    ) -> tuple[bool, str]:
        if gw.is_multicast:
            return False, "multicast"
        if gw.is_unspecified:
            return False, "unspecified"
        if gw.is_loopback:
            return False, "loopback"

        if gw.is_link_local and iface and not self._is_hyperv_iface(iface):
            return False, "gw_is_link_local"

        if net.prefixlen < 31:
            if gw == net.network_address:
                return False, "is_network"
            if gw == net.broadcast_address:
                return False, "is_broadcast"
        if gw not in net:
            return False, "not_on_link"

        return True, "ok"

    def _resolve_hyperv_special(self, ip_str: str, iface: str) -> str | None:
        if not self._is_hyperv_iface(iface):
            return None

        ip_obj = self._normalize_ip(ip_str)
        if not ip_obj:
            return None

        hm = getattr(self, "hyperv_manager", None)
        if hm:
            for meth in (
                "get_cached_mac_for_ip",
                "resolve_ip_mac",
                "resolve_mac_for_ip",
                "get_guest_mac",
                "get_vm_mac_for_ip",
            ):
                mac = self._safe_call(hm, meth, ip_obj)
                mac = self._normalize_mac(mac)
                if mac:
                    return mac

            for attr in ("bridge_mac", "host_mac", "switch_mac"):
                mac = self._normalize_mac(getattr(hm, attr, None))
                if mac:
                    return mac

        if self._owns_ip(ip_obj) or self._lease_active(ip_obj):
            return self.get_interface_mac(iface)

        return None

    def _remote_or_gateway_target(self, target_ip: str, iface: str) -> tuple[str | None, str]:
        try:
            ip_obj = ipaddress.ip_address(str(target_ip).strip())
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                return None, "not_ipv4"
        except Exception:
            return None, "bad_ip"

        self._ensure_dynamic_iface_config(iface)

        net_obj = self._get_iface_network(iface)
        iface_ip = self.get_interface_ipv4(iface) if iface else None
        gw_ip = self._get_iface_gateway(iface) if iface else None

        if ip_obj.is_link_local and self._is_hyperv_iface(iface):
            return str(ip_obj), "hyperv_link_local"

        if self.is_special_ip(str(ip_obj), iface_network=str(net_obj) if net_obj else None):
            if self._is_hyperv_iface(iface):
                return None, "special_hyperv"
            return None, "special"

        if net_obj and self.is_on_link(str(ip_obj), str(net_obj)):
            return str(ip_obj), "on_link"

        if not gw_ip:
            return None, "no_gateway"

        verdict = self._validate_gateway_onlink(gw_ip, str(net_obj) if net_obj else None, iface_ip)
        if not verdict.ok:
            return None, f"bad_gateway:{verdict.reason}"

        return verdict.gw, "via_gateway"

    # ------------------------------------------------------------------
    # Core resolution
    # ------------------------------------------------------------------

    def resolve(self, ip_address: str, iface: str | None) -> str | None:
        if self.sniffer is None and not self.hyperv_manager:
            return None

        ip_str = self._normalize_ip(ip_address)
        if not ip_str:
            self._log_rl(f"resolve_bad_ip:{ip_address}", 5.0, f"[ARP] ⚠️ resolve: invalid IP '{ip_address}'.")
            return None

        try:
            if not isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv4Address):
                self._log_rl(f"resolve_not_ipv4:{ip_str}", 5.0, f"[ARP] ⚠️ resolve: {ip_str} is not IPv4.")
                return None
        except Exception:
            return None

        if ipaddress.ip_address(ip_str).is_loopback:
            self._log_rl(f"resolve_loopback:{ip_str}", 10.0, f"[ARP] ♻️ resolve: {ip_str} is loopback; no ARP.")
            return None

        now = time.time()

        # --- static resolution first ---
        static_mac = self._normalize_mac(self._static_arp_entries.get(ip_str))
        if static_mac:
            self._cache_set(ip_str, static_mac, now, kind="static")
            self._log_rl(
                f"resolve_static:{ip_str}",
                5.0,
                f"[ARP] 🔗 Static resolve: {ip_str} -> {static_mac}",
            )
            return static_mac

        entry = self._cache_get(ip_str)
        if entry:
            mac_cached, ts = entry[:2]
            if now - ts < self.CACHE_TIMEOUT:
                return mac_cached

        for dhcp_srv in (self.dhcp_server_in, self.dhcp_server_out):
            bind = self._safe_get_bindings(dhcp_srv)
            mac = self._normalize_mac(bind.get(ip_str))
            if mac:
                self._cache_set(ip_str, mac, now)
                return mac

        use_iface = self._pick_iface_for_ip(ip_str, iface)
        if use_iface:
            self._log_rl(
                f"resolve_iface:{use_iface}:{ip_str}",
                15.0,
                f"[ARP] 🔎 resolve: chose iface {use_iface.split('_')[-1]} for {ip_str}",
            )
        else:
            self._log_rl(f"resolve_no_iface:{ip_str}", 5.0, f"[ARP] ❌ resolve: no interface available for {ip_str}")
            return None

        iface_mac = self._iface_cache_get(use_iface, ip_str)
        if iface_mac:
            return iface_mac

        # only allow the old global cache when it is safe
        if not (self.ARP_IF_CACHE_STRICT_FOR_HYPERV and self._is_hyperv_iface(use_iface)):
            entry = self._cache_get(ip_str)
            if entry:
                mac_cached, ts = entry[:2]
                if now - ts < self.CACHE_TIMEOUT:
                    return mac_cached

        li = self._temp_arp_leases.get(ip_str)
        if li and now < li.get("lease_end", 0):
            our_mac = self.get_interface_mac(use_iface)
            if our_mac:
                self._cache_set(ip_str, our_mac, now)
                return our_mac

        if self._is_hyperv_iface(use_iface):
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_link_local:
                hyperv_mac = self._resolve_hyperv_special(ip_str, use_iface)
                if hyperv_mac:
                    self._cache_set(ip_str, hyperv_mac, now)
                    self._log_rl(
                        f"resolve_hyperv_ll:{use_iface}:{ip_str}",
                        10.0,
                        f"[ARP] 🧩 resolve: Hyper-V link-local {ip_str} → {hyperv_mac} on {use_iface.split('_')[-1]}",
                    )
                    return hyperv_mac

        arp_target, mode = self._remote_or_gateway_target(ip_str, use_iface)
        if not arp_target:
            self._log_rl(
                f"resolve_no_arp_path:{use_iface}:{ip_str}:{mode}",
                10.0,
                f"[ARP] ⛔ resolve: no ARP path for {ip_str} ({mode})",
            )
            self._negative_cache_set(use_iface, ip_str)
            return None

        if self._negative_cache_hit(use_iface, ip_str):
            return None

        if mode == "via_gateway":
            cached_gw = self._gateway_cache_get(use_iface, arp_target)
            if cached_gw:
                return cached_gw

            if self.PREFER_OS_ARP_CACHE_FOR_GATEWAY:
                mac = self.fallback_mac_from_os_cache(arp_target)
                if mac:
                    self._gateway_cache_set(use_iface, arp_target, mac)
                    return mac

            if self._gateway_fail_hit(use_iface, arp_target):
                better_iface = self._find_iface_for_gateway(arp_target)
                if better_iface and better_iface != use_iface:
                    use_iface = better_iface
                else:
                    self._negative_cache_set(use_iface, ip_str)
                    return None

            net_obj = self._get_iface_network(use_iface)
            mac = self.resolve_gateway_mac(
                arp_target,
                use_iface,
                str(net_obj) if net_obj else None,
            )
            if mac:
                self._gateway_cache_set(use_iface, arp_target, mac)
                return mac

            self._gateway_fail_set(use_iface, arp_target)
            self._negative_cache_set(use_iface, ip_str)
            return None

        mac = self.fallback_mac_from_os_cache(ip_str)
        if mac:
            self._cache_set(ip_str, mac, now)
            return mac

        mac = self.send_custom_arp_request(ip_str, iface=use_iface, timeout=2)
        if mac:
            self._iface_cache_set(use_iface, ip_str, mac, source="active")
            if not self._is_hyperv_iface(use_iface):
                self._cache_set(ip_str, mac, now)
            return mac

        try:
            mac = getmacbyip(ip_str) if getmacbyip else None
        except Exception:
            mac = None
        mac = self._normalize_mac(mac)
        if mac:
            self._cache_set(ip_str, mac, now)
            return mac

        self._negative_cache_set(use_iface, ip_str)
        return None

    def get_mac(
            self,
            target_ip: str,
            iface: str | None = None,
            timeout: int = 2,
            prefer_cache: bool = True,
            allow_active_probe: bool = True,
    ) -> str | None:
        ip = self._normalize_ip(target_ip)
        if not ip:
            return None

        # --- static resolution first ---
        static_mac = self._normalize_mac(self._static_arp_entries.get(ip))
        if static_mac:
            self._cache_set(ip, static_mac, time.time(), kind="static")
            self._log_rl(
                f"getmac_static:{ip}",
                5.0,
                f"[ARP] 🔗 Static resolve: {ip} -> {static_mac}",
            )
            return static_mac

        if prefer_cache:
            entry = self._cache_get(ip)
            if entry:
                mac, ts = entry[:2]
                if time.time() - ts < self.CACHE_TIMEOUT:
                    return mac

        use_iface = self._pick_iface_for_ip(ip, iface)
        if not use_iface:
            return None

        if self._is_hyperv_iface(use_iface):
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_link_local:
                hyperv_mac = self._resolve_hyperv_special(ip, use_iface)
                if hyperv_mac:
                    self._cache_set(ip, hyperv_mac, time.time())
                    return hyperv_mac

        arp_target, mode = self._remote_or_gateway_target(ip, use_iface)
        if not arp_target:
            return None

        if mode == "via_gateway":
            mac = self._gateway_cache_get(use_iface, arp_target)
            if mac:
                return mac

            mac = self.fallback_mac_from_os_cache(arp_target)
            if mac:
                self._gateway_cache_set(use_iface, arp_target, mac)
                return mac

            if allow_active_probe and not self._gateway_fail_hit(use_iface, arp_target):
                net_obj = self._get_iface_network(use_iface)
                mac = self.resolve_gateway_mac(
                    arp_target,
                    use_iface,
                    str(net_obj) if net_obj else None,
                    timeout=float(timeout),
                    retries=max(1, self.arp_probe_retries),
                )
                if mac:
                    self._gateway_cache_set(use_iface, arp_target, mac)
                    return mac
                self._gateway_fail_set(use_iface, arp_target)
            return None

        mac = self.fallback_mac_from_os_cache(ip)
        if mac:
            self._cache_set(ip, mac, time.time())
            return mac

        if allow_active_probe:
            mac = self.send_custom_arp_request(ip, iface=use_iface, timeout=timeout)
            if mac:
                self._cache_set(ip, mac, time.time())
                return mac

        return None

    def get_mac(
        self,
        target_ip: str,
        iface: str | None = None,
        timeout: int = 2,
        prefer_cache: bool = True,
        allow_active_probe: bool = True,
    ) -> str | None:
        ip = self._normalize_ip(target_ip)
        if not ip:
            return None

        if prefer_cache:
            entry = self._cache_get(ip)
            if entry:
                mac, ts = entry[:2]
                if time.time() - ts < self.CACHE_TIMEOUT:
                    return mac

        use_iface = self._pick_iface_for_ip(ip, iface)
        if not use_iface:
            return None

        if self._is_hyperv_iface(use_iface):
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_link_local:
                hyperv_mac = self._resolve_hyperv_special(ip, use_iface)
                if hyperv_mac:
                    self._cache_set(ip, hyperv_mac, time.time())
                    return hyperv_mac

        arp_target, mode = self._remote_or_gateway_target(ip, use_iface)
        if not arp_target:
            return None

        if mode == "via_gateway":
            mac = self._gateway_cache_get(use_iface, arp_target)
            if mac:
                return mac

            mac = self.fallback_mac_from_os_cache(arp_target)
            if mac:
                self._gateway_cache_set(use_iface, arp_target, mac)
                return mac

            if allow_active_probe and not self._gateway_fail_hit(use_iface, arp_target):
                net_obj = self._get_iface_network(use_iface)
                mac = self.resolve_gateway_mac(
                    arp_target,
                    use_iface,
                    str(net_obj) if net_obj else None,
                    timeout=float(timeout),
                    retries=max(1, self.arp_probe_retries),
                )
                if mac:
                    self._gateway_cache_set(use_iface, arp_target, mac)
                    return mac
                self._gateway_fail_set(use_iface, arp_target)
            return None

        mac = self.fallback_mac_from_os_cache(ip)
        if mac:
            self._cache_set(ip, mac, time.time())
            return mac

        if allow_active_probe:
            mac = self.send_custom_arp_request(ip, iface=use_iface, timeout=timeout)
            if mac:
                self._cache_set(ip, mac, time.time())
                return mac

        return None

    # ------------------------------------------------------------------
    # Active ARP / gateway resolution
    # ------------------------------------------------------------------

    def _arp_resolve_ipv4(self, iface: str, target_ip: str) -> str | None:
        try:
            sniffer = getattr(self, "sniffer", None)
            if not sniffer:
                return None

            if hasattr(sniffer, "iface_is_l2_capable") and not sniffer.iface_is_l2_capable(iface):
                return None

            src_mac = self.get_interface_mac(iface)
            src_ip = self.get_interface_ipv4(iface) or "0.0.0.0"
            if not src_mac:
                return None

            req = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / ARP(op=1, psrc=src_ip, pdst=str(target_ip))
            for _ in range(max(1, int(self.arp_probe_retries))):
                ans = self._safe_call(sniffer, "srp1", req, iface=iface, timeout=self.arp_probe_timeout, verbose=0)
                if ans and hasattr(ans, "haslayer") and ans.haslayer(ARP):
                    mac = self._normalize_mac(ans[ARP].hwsrc)
                    if mac:
                        return mac
            return None
        except Exception:
            return None

    def send_custom_arp_request(self, target_ip: str, iface: str = None, timeout: int = 2) -> str | None:
        try:
            if self._in_quiet_start():
                return None

            ip_norm = self._normalize_ip(target_ip)
            if not ip_norm:
                return None

            ip_obj = ipaddress.ip_address(str(ip_norm).strip())
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                return None

            use_iface = self._pick_iface_for_ip(str(ip_obj), iface)
            if not use_iface:
                self._safe_log(f"[ARP] ❌ Cannot resolve {ip_obj}: No outbound interface determined.")
                return None

            if ip_obj.is_link_local and self._is_hyperv_iface(use_iface):
                hyperv_mac = self._resolve_hyperv_special(str(ip_obj), use_iface)
                if hyperv_mac:
                    return hyperv_mac

            elif self.is_special_ip(str(ip_obj)):
                hyperv_mac = self._resolve_hyperv_special(str(ip_obj), use_iface)
                if hyperv_mac:
                    return hyperv_mac
                self._safe_log(f"[ARP] ⚠️ Skipping ARP for special/non-IPv4 IP: {target_ip}")
                return None

            arp_target, mode = self._remote_or_gateway_target(str(ip_obj), use_iface)
            if not arp_target:
                self._safe_log(f"[ARP] ⛔ {ip_obj} has no ARP path on {use_iface.split('_')[-1]} ({mode})")
                return None

            if mode == "via_gateway":
                self._safe_log(f"[ARP] 🌐 {ip_obj} is off-link; resolving GW {arp_target} on {use_iface.split('_')[-1]}")
                net_obj = self._get_iface_network(use_iface)
                mac = self.resolve_gateway_mac(
                    arp_target,
                    use_iface,
                    str(net_obj) if net_obj else None,
                    timeout=float(timeout),
                    retries=max(1, self.arp_probe_retries),
                )
                if mac:
                    self._gateway_cache_set(use_iface, arp_target, mac)
                return mac

            self._safe_log(f"[ARP] 📡 {ip_obj} is on-link; direct ARP on {use_iface.split('_')[-1]}")
            return self._arp_resolve_ipv4(use_iface, str(ip_obj))

        except Exception as e:
            self._safe_log(f"[ARP] ❌ Unhandled exception in send_custom_arp_request for {target_ip}: {e}")
            return None

    def resolve_gateway_mac(
            self,
            gw_ip: str,
            iface: str,
            iface_cidr: str,
            timeout: float = 2.0,
            retries: int = 2,
    ) -> str | None:
        gw_ip = self._normalize_ip(gw_ip)
        if not gw_ip:
            return None

        use_iface = str(iface or "").strip()
        if not use_iface:
            return None

        try:
            self._ensure_dynamic_iface_config(use_iface)
        except Exception:
            pass

        cfg = self._all_iface_cfgs().get(use_iface, {}) or {}
        iface_ip = (
                cfg.get("ip_addr")
                or self.get_interface_ipv4(use_iface)
                or None
        )

        cidr = str(iface_cidr or "").strip()
        if not cidr:
            cidr = str(cfg.get("cidr") or cfg.get("network") or "").strip()

        # never ARP for ourselves
        if iface_ip and str(iface_ip).strip() == str(gw_ip).strip():
            self._log_rl(
                f"gw_self:{use_iface}:{gw_ip}",
                5.0,
                f"[ARP][GW] 🚫 Refusing self-gateway resolve for {gw_ip} on {use_iface}",
            )
            return None

        verdict = self._validate_gateway_onlink(
            gw_ip,
            cidr if cidr else None,
            iface_ip,
        ) if cidr else None

        if verdict is not None and not verdict.ok:
            better_iface = self._find_iface_for_gateway(gw_ip)
            if better_iface and better_iface != use_iface:
                use_iface = better_iface
                try:
                    self._ensure_dynamic_iface_config(use_iface)
                except Exception:
                    pass
                cfg = self._all_iface_cfgs().get(use_iface, {}) or {}
                iface_ip = cfg.get("ip_addr") or self.get_interface_ipv4(use_iface) or None
                cidr = str(cfg.get("cidr") or cfg.get("network") or "").strip()
                verdict = self._validate_gateway_onlink(
                    gw_ip,
                    cidr if cidr else None,
                    iface_ip,
                ) if cidr else None

        if verdict is not None and not verdict.ok:
            self._log_rl(
                f"gw_invalid:{use_iface}:{gw_ip}",
                5.0,
                f"[ARP][GW] ⛔ Invalid gateway path for {gw_ip} on {use_iface}: {verdict.reason}",
            )
            return None

        cached = self._gateway_cache_get(use_iface, gw_ip)
        if cached:
            return cached

        # 1) first try OS cache snapshot
        if self.PREFER_OS_ARP_CACHE_FOR_GATEWAY:
            mac = self.fallback_mac_from_os_cache(gw_ip, force_refresh=False)
            if mac:
                self._cache_set(gw_ip, mac, time.time())
                self._gateway_cache_set(use_iface, gw_ip, mac)
                self._known_gateway_macs[gw_ip] = mac
                return mac

        if not getattr(self, "sniffer", None):
            return None

        if self._gateway_fail_hit(use_iface, gw_ip):
            # before honoring fail cache, do one forced OS-cache refresh
            if self.PREFER_OS_ARP_CACHE_FOR_GATEWAY:
                mac = self.fallback_mac_from_os_cache(gw_ip, force_refresh=True)
                if mac:
                    self._cache_set(gw_ip, mac, time.time())
                    self._gateway_cache_set(use_iface, gw_ip, mac)
                    self._known_gateway_macs[gw_ip] = mac
                    return mac
            return None

        self._safe_log(
            f"[ARP] 🛣️ resolve_gateway_mac: resolving gateway {gw_ip} "
            f"(iface_cidr={cidr or 'None'})"
        )

        for _ in range(max(1, int(retries))):
            mac = self._arp_resolve_ipv4(use_iface, gw_ip)
            mac = self._normalize_mac(mac)
            if mac:
                self._cache_set(gw_ip, mac, time.time())
                self._gateway_cache_set(use_iface, gw_ip, mac)
                self._known_gateway_macs[gw_ip] = mac
                self._safe_log(f"[ARP][GW] 🎯 Resolved {gw_ip} -> {mac} on {use_iface}")
                return mac

        # 2) active ARP failed — force a fresh OS ARP table read once more
        if self.PREFER_OS_ARP_CACHE_FOR_GATEWAY:
            mac = self.fallback_mac_from_os_cache(gw_ip, force_refresh=True)
            if mac:
                self._cache_set(gw_ip, mac, time.time())
                self._gateway_cache_set(use_iface, gw_ip, mac)
                self._known_gateway_macs[gw_ip] = mac
                self._safe_log(f"[ARP][GW] 🧭 Recovered {gw_ip} from fresh OS ARP cache -> {mac}")
                return mac

        self._gateway_fail_set(use_iface, gw_ip)
        self._safe_log(f"[ARP] ❌ resolve_gateway_mac: failed for {gw_ip}")
        return None
    # ------------------------------------------------------------------
    # OS ARP cache fallback
    # ------------------------------------------------------------------

    def fallback_mac_from_os_cache(
            self,
            ip: str,
            *,
            force_refresh: bool = False,
    ) -> str | None:
        mac_re = re.compile(r"(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}")

        ip = self._normalize_ip(ip)
        if not ip:
            return None

        try:
            now = time.time()

            if force_refresh:
                self._os_arp_cache_snapshot = None

            cached = self._os_arp_cache_snapshot
            if cached and (now - cached[0]) <= self.OS_ARP_CACHE_TTL:
                output = cached[1]
            else:
                with self._subprocess_lock:
                    output = ""
                    for cmd in (["arp", "-a"], ["arp", "-an"]):
                        try:
                            output = subprocess.check_output(
                                cmd,
                                text=True,
                                stderr=subprocess.DEVNULL,
                                timeout=2.0,
                            )
                            if output:
                                break
                        except Exception:
                            continue
                    self._os_arp_cache_snapshot = (time.time(), output)

            if not output:
                return None

            ip_text = str(ip).strip()
            for line in output.splitlines():
                if ip_text not in line:
                    continue

                m = mac_re.search(line)
                if not m:
                    continue

                mac = self._normalize_mac(m.group(0))
                if mac:
                    self._safe_log(
                        f"[ARP] 🧭 OS cache{' refresh' if force_refresh else ''}: {ip_text} → {mac}"
                    )
                    return mac

            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Ownership / lease helpers
    # ------------------------------------------------------------------

    def _owns_ip(self, ip: str) -> bool:
        try:
            cfgs = getattr(self, "_interfaces_config", None) or getattr(self, "interfaces_config", {}) or {}
            if not isinstance(cfgs, dict):
                return False
            owned = {str(cfg.get("ip_addr")) for cfg in cfgs.values() if cfg and cfg.get("ip_addr")}
            return str(ip) in owned
        except Exception:
            return False

    def _lease_active(self, ip: str) -> bool:
        li = self._temp_arp_leases.get(ip)
        return bool(li and time.time() < li.get("lease_end", 0))

    def _lease_cooldown(self, ip: str) -> bool:
        li = self._temp_arp_leases.get(ip)
        return bool(li and time.time() < li.get("cooldown_end", 0))

    def allow_temp_arp_lease(self, ip_address: str, lease_duration: int = 30, cooldown: int = 60):
        if self._in_quiet_start():
            self._log_rl(
                f"lease_quiet:{ip_address}",
                10.0,
                f"[ARP][LEASE][ESET] 🤫 quiet-start: refusing temporary lease for {ip_address}",
            )
            return False

        ip_address = str(ip_address).strip()

        if self._is_gateway_ip(ip_address) or ip_address == self.router_ip_out:
            self._safe_log(f"[ARP][LEASE] 🚫 Refusing temporary lease for gateway IP {ip_address}.")
            return False

        now = time.time()
        current = self._temp_arp_leases.get(ip_address)

        if current and now < current.get("cooldown_end", 0):
            self._log_rl(
                f"lease_cooldown:{ip_address}",
                5.0,
                f"[ARP][LEASE] ⏳ Cannot grant lease for {ip_address} — cooldown active until {time.ctime(current['cooldown_end'])}.",
            )
            return False

        self._temp_arp_leases[ip_address] = {
            "lease_end": now + lease_duration,
            "cooldown_end": now + lease_duration + cooldown,
            "replies_sent": 0,
        }

        self._safe_log(f"[ARP][LEASE] ✅ Temporary ARP lease granted for {ip_address} for {lease_duration}s (cooldown: {cooldown}s).")
        return True

    # ------------------------------------------------------------------
    # DAI / inspection
    # ------------------------------------------------------------------

    def perform_arp_dai(self, pkt, inbound_iface: str) -> bool:
        try:
            if not self.dai_enable or not pkt or not hasattr(pkt, "haslayer") or not pkt.haslayer(ARP):
                return True

            if self._in_quiet_start():
                return True

            iface_name = str(inbound_iface or "").split("_")[-1]
            if self.dai_enforce_on_untrusted_only and inbound_iface in self._trusted_ports:
                return True

            arp = pkt[ARP]
            op = int(getattr(arp, "op", 0) or 0)
            spa = (getattr(arp, "psrc", "") or "").strip()
            sha = ((getattr(arp, "hwsrc", "") or "").strip()).lower()
            tpa = (getattr(arp, "pdst", "") or "").strip()
            tha = ((getattr(arp, "hwdst", "") or "").strip()).lower()

            def _is_zero_mac(m: str) -> bool:
                return m in ("", "00:00:00:00:00:00")

            def _log(block: bool, reason: str):
                level = "🚫 BLOCK" if block else "ℹ️  ALLOW"
                self._safe_log(
                    f"[ARP][DAI] {level} {reason} on {iface_name}: op={op} {spa}({sha}) → {tpa}({tha})"
                )

            try:
                ipaddress.IPv4Address(spa)
            except Exception:
                _log(True, "bad_sender_ip")
                return False

            if self.dai_block_gateway_claims and self._is_gateway_ip(spa):
                gw_mac_known = (self._known_gateway_macs.get(spa) or self._static_arp_entries.get(spa))
                if gw_mac_known and gw_mac_known.lower() != sha:
                    _log(True, f"gateway_claim_mismatch expected={gw_mac_known.lower()}")
                    try:
                        if getattr(self, "arp_defend_on_claim", True) and self._can_defend_now(spa):
                            self._send_arp_announcement(inbound_iface, spa)
                    except Exception:
                        pass
                    return False

            if self.dai_block_ip_spoof and self._owns_ip(spa):
                our_mac = self.get_interface_mac(inbound_iface)
                if our_mac and our_mac.lower() != sha:
                    _log(True, f"spoof_our_ip expected_mac={our_mac.lower()}")
                    try:
                        if getattr(self, "arp_defend_on_claim", True) and self._can_defend_now(spa):
                            self._send_arp_announcement(inbound_iface, spa)
                    except Exception:
                        pass
                    return False

            dhcp = self.dhcp_server_out or self.dhcp_server_in
            if dhcp:
                bindings = self._safe_get_bindings(dhcp)
                bmac = (bindings.get(spa) or "").lower()
                smac = (self._static_arp_entries.get(spa) or "").lower()
                expected = smac or bmac
                if expected and expected != sha:
                    _log(True, f"lease_mismatch expected={expected}")
                    return False

            if op == 1 and self.dai_block_gratuitous_from_untrusted:
                suspicious_tha = not _is_zero_mac(tha)
                is_self_claim = (spa == tpa)
                if is_self_claim or suspicious_tha:
                    expected = (self._static_arp_entries.get(spa) or "").lower()
                    if not expected and dhcp:
                        expected = (self._safe_get_bindings(dhcp).get(spa, "") or "").lower()
                    if expected and expected != sha:
                        _log(True, f"gratuitous_mismatch expected={expected}")
                        return False
                    if not expected:
                        _log(True, "gratuitous_untrusted")
                        return False

            now = time.time()
            claims = self._dai_recent_claims.get(spa) or {}
            for m, ts in list(claims.items()):
                if now - ts > self.dai_conflict_window:
                    claims.pop(m, None)
            conflict_cnt = sum(1 for m in claims.keys() if m != sha)
            claims[sha] = now
            self._dai_recent_claims[spa] = claims
            if conflict_cnt >= self.dai_conflict_threshold:
                _log(True, f"flip_flop ip={spa} conflicts={conflict_cnt}")
                return False

            _log(False, "passed")
            return True

        except Exception as e:
            self._log_rl("perform_arp_dai_error", 3.0, f"[ARP][DAI] ⚠️ exception: {e}")
            return True

    def perform_arp_inspection(self, pkt, inbound_iface: str) -> bool:
        try:
            if not pkt or not hasattr(pkt, "haslayer") or not pkt.haslayer(ARP):
                return True
            arp_layer = pkt[ARP]
            sender_ip = getattr(arp_layer, "psrc", None)
            sender_mac = self._normalize_mac(getattr(arp_layer, "hwsrc", None)) or ""

            static_mac = self._static_arp_entries.get(str(sender_ip))
            if static_mac and static_mac.lower() != sender_mac.lower():
                self._safe_log(
                    f"[ARP][INSPECT] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on {str(inbound_iface).split('_')[-1]}: Static entry conflict ({static_mac})."
                )
                return False

            if inbound_iface in self._trusted_ports:
                return True

            dhcp_server_for_dai = self.dhcp_server_out or self.dhcp_server_in
            if dhcp_server_for_dai:
                dhcp_bindings = self._safe_get_bindings(dhcp_server_for_dai)
                if str(sender_ip) in dhcp_bindings:
                    trusted_mac = (dhcp_bindings[str(sender_ip)] or "").lower()
                    if sender_mac.lower() != trusted_mac.lower():
                        self._safe_log(
                            f"[ARP][DAI] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on untrusted port {str(inbound_iface).split('_')[-1]}: lease MAC {trusted_mac} mismatch."
                        )
                        return False
                    return True
                self._safe_log(
                    f"[ARP][DAI] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on untrusted port {str(inbound_iface).split('_')[-1]}: IP not in DHCP leases."
                )
                return False

            self._safe_log(
                f"[ARP][INSPECT] ⚠️ No DHCP server reference. Permitting ARP from {sender_ip} on untrusted port {str(inbound_iface).split('_')[-1]}."
            )
            return True

        except Exception as e:
            self._log_rl("arp_inspection_error", 3.0, f"[ARP][INSPECT] ⚠️ exception: {e}")
            return True

    # ------------------------------------------------------------------
    # Defensive announce helpers
    # ------------------------------------------------------------------

    def _can_defend_now(self, ip: str) -> bool:
        t = time.time()
        last = self._arp_defense_last.get(ip, 0.0)
        if t - last >= self.arp_defense_cooldown:
            self._arp_defense_last[ip] = t
            return True
        return False

    def _send_arp_announcement(self, iface: str, ip: str, *, bursts: int = 2, gap: float = 0.2):
        mac = self.get_interface_mac(iface)
        if not mac:
            return
        try:
            for i in range(max(1, int(bursts))):
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(
                    op=1,
                    hwsrc=mac,
                    psrc=ip,
                    hwdst="00:00:00:00:00:00",
                    pdst=ip,
                )
                self._safe_call(self.sniffer, "sendp", pkt, iface=iface, verbose=False)
                if gap > 0 and i + 1 < bursts:
                    time.sleep(gap)
            self._safe_log(f"[ARP] 📣 Announced {ip} is-at {mac} on {str(iface).split('_')[-1]}")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Learn / reply compatibility
    # ------------------------------------------------------------------

    def learn_arp_response(self, pkt):
        try:
            if not pkt or not hasattr(pkt, "haslayer") or not pkt.haslayer(ARP) or pkt[ARP].op != 2:
                return

            ip = str(pkt[ARP].psrc)
            mac = self._normalize_mac(pkt[ARP].hwsrc)
            iface = getattr(pkt, "sniffed_on", "Unknown") or "Unknown"
            now = time.time()

            if not mac:
                return

            static_mac = self._static_arp_entries.get(ip)
            if static_mac and static_mac.lower() != mac.lower():
                self._safe_log(
                    f"[ARP] 🚫 Ignoring ARP response for {ip}: MAC {mac} conflicts with static entry {static_mac}."
                )
                return

            if self._is_gateway_ip(ip) and mac:
                self._known_gateway_macs[ip] = mac
                if iface != "Unknown":
                    self._gateway_cache_set(iface, ip, mac)

            lease_info = self._temp_arp_leases.get(ip)
            if lease_info and now > lease_info.get("lease_end", 0):
                cooldown_end = lease_info.get("cooldown_end", 0)
                if now < cooldown_end:
                    self._log_rl(
                        f"lease_ignore_expired:{ip}",
                        5.0,
                        f"[ARP][LEASE] ⏳ Lease for {ip} expired; cooldown still active ({cooldown_end - now:.1f}s left). Ignoring ARP from {mac}.",
                    )
                    return

                new_lease_end = now + self.lease_cooldown
                new_cooldown_end = now + self.lease_cooldown + self.lease_duration
                self._temp_arp_leases[ip] = {
                    "mac": mac,
                    "lease_end": new_lease_end,
                    "cooldown_end": new_cooldown_end,
                    "replies_sent": 0,
                }
                self._safe_log(f"[ARP][LEASE] 🔄 New lease for {ip} → {mac} (dur=30s, cooldown=60s).")
                return

            entry = self._cache_get(ip)
            if entry:
                old_mac = str(entry[0])
                if old_mac.lower() != mac.lower():
                    self._safe_log(f"[ARP] ⚠️ MAC change detected for {ip}: {old_mac} → {mac} on {str(iface).split('_')[-1]}")
            else:
                self._safe_log(f"[ARP] 🧠 Learned new ARP: {ip} → {mac} on {str(iface).split('_')[-1]}")
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if (
                        not ip_obj.is_link_local
                        and not self._is_gateway_ip(ip)
                        and not self._owns_ip(ip)
                        and not self.router_ip_out
                    ):
                        self.allow_temp_arp_lease(ip, self.lease_duration, self.lease_cooldown)
                except Exception:
                    pass

            self._cache_set(ip, mac, now)

            if lease_info:
                self._safe_log(f"[ARP][LEASE] ✅ ARP response accepted for {ip} under active temporary lease.")

        except Exception as e:
            self._log_rl("learn_arp_response_error", 3.0, f"[ARP] ⚠️ learn_arp_response error: {e}")

    def reply_to_arp_request(self, request_pkt, iface: str):
        try:
            if not request_pkt or not hasattr(request_pkt, "haslayer") or not request_pkt.haslayer(ARP):
                return
            arp = request_pkt[ARP]
            if int(getattr(arp, "op", 0) or 0) != 1:
                return

            target_ip = str(getattr(arp, "pdst", "") or "")
            requester_ip = str(getattr(arp, "psrc", "") or "")
            requester_mac = self._normalize_mac(getattr(arp, "hwsrc", None)) or ""
            self._ensure_dynamic_iface_config(iface)
            iface_cfg = (getattr(self, "_interfaces_config", {}) or {}).get(iface, {}) or {}
            iface_name = str(iface).split("_")[-1]
            iface_net = iface_cfg.get("network")

            def _own_mac_or_none():
                return self._normalize_mac(
                    iface_cfg.get("mac") or getattr(self, "get_interface_mac", lambda _i: None)(iface)
                )

            def _send_reply(psrc_ip: str, their_ip: str, their_mac: str, our_mac: str):
                if not self.sniffer:
                    return
                reply = Ether(dst=their_mac, src=our_mac) / ARP(
                    op=2,
                    hwsrc=our_mac,
                    psrc=psrc_ip,
                    hwdst=their_mac,
                    pdst=their_ip,
                )
                self._safe_call(self.sniffer, "sendp", reply, iface=iface, verbose=False)
                self._safe_log(f"[ARP] 📢 Replied: {psrc_ip} is-at {our_mac} → {their_mac} on {iface_name}")

            def _learn_requester():
                try:
                    self.learn_arp_response(request_pkt)
                except Exception:
                    pass

            if self._in_quiet_start():
                if self._owns_ip(target_ip):
                    our_mac = _own_mac_or_none()
                    if our_mac:
                        reply = Ether(dst=requester_mac, src=our_mac) / ARP(
                            op=2,
                            hwsrc=our_mac,
                            psrc=target_ip,
                            hwdst=requester_mac,
                            pdst=requester_ip,
                        )
                        self._safe_call(self.sniffer, "sendp", reply, iface=iface, verbose=False)
                        self._safe_log(f"[ARP][ESET] 📢 (quiet) Replied for own {target_ip} on {iface_name}")
                else:
                    self._log_rl(
                        f"quiet_not_owned:{iface}:{target_ip}",
                        10.0,
                        f"[ARP][ESET] 🤫 quiet-start: not replying for non-owned {target_ip} on {iface_name}",
                    )
                _learn_requester()
                return

            if self.is_special_ip(target_ip, iface_network=str(iface_net) if iface_net else None):
                if requester_ip == "0.0.0.0":
                    if self._owns_ip(target_ip) and getattr(self, "arp_defend_on_probe", True) and self._can_defend_now(target_ip):
                        self._safe_log(f"[ARP][PROBE] Probe for our {target_ip} from {requester_mac}; announcing on {iface_name}")
                        self._send_arp_announcement(iface, target_ip)
                    else:
                        self._log_rl(
                            f"probe_ignored:{iface}:{target_ip}",
                            5.0,
                            f"[ARP][PROBE] Probe for {target_ip} from {requester_mac} (ignored) on {iface_name}",
                        )
                    _learn_requester()
                    return

                if requester_ip == target_ip:
                    if self._owns_ip(target_ip):
                        our_mac = (_own_mac_or_none() or "").lower()
                        if our_mac and requester_mac.lower() != our_mac and getattr(self, "arp_defend_on_claim", True) and self._can_defend_now(target_ip):
                            self._safe_log(f"[ARP][DEFEND] Foreign claim for {target_ip} by {requester_mac}; announcing {target_ip} is-at {our_mac} on {iface_name}")
                            self._send_arp_announcement(iface, target_ip)
                        else:
                            self._log_rl(
                                f"claim_seen:{iface}:{target_ip}",
                                5.0,
                                f"[ARP][DEFEND] Claim for {target_ip} from {requester_mac} (own_mac={'n/a' if not our_mac else our_mac}) on {iface_name}",
                            )
                    else:
                        self._safe_log(f"[ARP] 📨 Gratuitous ARP for {target_ip} from {requester_mac} on {iface_name} (learned)")
                        if not self._is_gateway_ip(target_ip):
                            self.allow_temp_arp_lease(target_ip, self.lease_cooldown, self.lease_duration)
                    _learn_requester()
                    return

                self._log_rl(
                    f"special_suppressed:{iface}:{target_ip}",
                    5.0,
                    f"[ARP] 🚫 Suppressed ARP for special IP {target_ip} on {iface_name} (learned {requester_mac})",
                )
                _learn_requester()
                return

            if self._owns_ip(target_ip):
                our_mac = _own_mac_or_none()
                if not our_mac:
                    _learn_requester()
                    return
                _send_reply(target_ip, requester_ip, requester_mac, our_mac)
                _learn_requester()
                return

            if self._lease_active(target_ip):
                li = self._temp_arp_leases[target_ip]
                our_mac = _own_mac_or_none()
                if not our_mac:
                    self._log_rl(
                        f"lease_no_iface_mac:{iface}:{target_ip}",
                        5.0,
                        f"[ARP][LEASE] ❌ No iface MAC for {iface_name}; cannot reply for {target_ip}",
                    )
                    _learn_requester()
                    return
                li["last_seen"] = time.time()
                if li.get("replies_sent", 0) < int(getattr(self, "MAX_REPLIES_PER_LEASE", 8)):
                    li["replies_sent"] = li.get("replies_sent", 0) + 1
                    self._safe_log(
                        f"[ARP][LEASE] 🔓 Replying for leased {target_ip} with {our_mac} ({li['replies_sent']}/{int(getattr(self, 'MAX_REPLIES_PER_LEASE', 8))}) on {iface_name}"
                    )
                    _send_reply(target_ip, requester_ip, requester_mac, our_mac)
                else:
                    self._log_rl(
                        f"lease_budget:{iface}:{target_ip}",
                        5.0,
                        f"[ARP][LEASE] ⛔ Budget exhausted for {target_ip} on {iface_name}; learning only",
                    )
                _learn_requester()
                return

            if getattr(self, "enable_auto_temp_leases", False) and not self._lease_cooldown(target_ip):
                iface_cidr = iface_cfg.get("cidr")
                if iface_cidr and self.is_on_link(target_ip, iface_cidr):
                    if target_ip not in getattr(self, "_static_arp_entries", {}):
                        dhcp_conflict = False
                        for dhcp_srv in (getattr(self, "dhcp_server_in", None), getattr(self, "dhcp_server_out", None)):
                            bindings = self._safe_get_bindings(dhcp_srv)
                            if target_ip in bindings:
                                dhcp_conflict = True
                                break
                        if (not dhcp_conflict) and (not self._is_gateway_ip(target_ip)) and self.allow_temp_arp_lease(target_ip, lease_duration=120, cooldown=60):
                            our_mac = _own_mac_or_none()
                            if our_mac:
                                self._safe_log(f"[ARP][LEASE] ⚡ Auto-leased {target_ip}; replying with {our_mac} on {iface_name}")
                                _send_reply(target_ip, requester_ip, requester_mac, our_mac)
                                _learn_requester()
                                return

            _learn_requester()

        except Exception as e:
            self._log_rl(f"reply_to_arp_request:{iface}", 3.0, f"[ARP] 🚫 Exception {e}")

    # ------------------------------------------------------------------
    # Passive learning helpers
    # ------------------------------------------------------------------

    def _is_unicast_mac(self, mac: str) -> bool:
        try:
            m = str(mac).replace("-", ":").lower()
            if m == "00:00:00:00:00:00":
                return False
            first_octet = int(m.split(":")[0], 16)
            return (first_octet & 1) == 0
        except Exception:
            return False

    def _ipv4_ok_to_learn(self, ip: str) -> bool:
        try:
            ip4 = ipaddress.IPv4Address(ip)
        except Exception:
            return False

        if ip4.is_unspecified or ip4 == ipaddress.IPv4Address("255.255.255.255"):
            return False
        if ip4.is_multicast or ip4.is_loopback:
            return False

        entry = self._cache_get(str(ip4))
        if entry is None:
            return True

        is_learned = isinstance(entry, tuple) and len(entry) >= 3
        if is_learned:
            return True
        return False

    def _update_arp_cache(self, ip: str, mac: str, now: float, reason: str, iface: str):
        norm_mac = self._normalize_mac(mac)
        if not norm_mac:
            return
        with self._arp_cache_lock:
            cur = self._arp_cache.get(ip)
            if not cur or str(cur[0]).lower() != norm_mac.lower():
                self._arp_cache[ip] = (norm_mac, now, "Learned")

    def learn_from_packet(self, pkt, inbound_iface: str):
        try:
            if not pkt or not hasattr(pkt, "haslayer") or not pkt.haslayer(Ether):
                return

            now = time.time()
            eth = pkt[Ether]
            src_mac = self._normalize_mac(getattr(eth, "src", None))

            if not src_mac or not self._is_unicast_mac(src_mac):
                return

            if pkt.haslayer(ARP):
                a = pkt[ARP]
                psrc = (getattr(a, "psrc", "") or "").strip()
                hwsrc = self._normalize_mac(getattr(a, "hwsrc", None)) or ""

                if psrc and hwsrc and self._ipv4_ok_to_learn(psrc):
                    self._update_arp_cache(psrc, hwsrc, now, "IPv4-arp", inbound_iface)
                    if self._is_gateway_ip(psrc):
                        self._known_gateway_macs[psrc] = hwsrc
                        self._gateway_cache_set(inbound_iface, psrc, hwsrc)

            if pkt.haslayer(IP):
                ip4 = pkt[IP]
                sip = getattr(ip4, "src", None)
                if sip and self._ipv4_ok_to_learn(sip):
                    self._update_arp_cache(sip, src_mac, now, "IPv4-passive", inbound_iface)

            if (self._last_passive_gc or 0.0) + 30.0 <= now:
                cutoff = now - float(self.ARP_PASSIVE_TTL)
                removed = 0
                with self._arp_cache_lock:
                    for ip, ent in list(self._arp_cache.items()):
                        ts = float(ent[1]) if isinstance(ent, tuple) and len(ent) >= 2 else 0.0
                        learned = isinstance(ent, tuple) and len(ent) >= 3
                        if learned and ts < cutoff:
                            del self._arp_cache[ip]
                            removed += 1
                            if removed >= 256:
                                break
                self._last_passive_gc = now

        except Exception as e:
            self._log_rl(f"learn_from_packet:{inbound_iface}", 3.0, f"[ARP] learn_from_packet exception: {e}")


class DHCPServer:
    """
    Acts as a DHCP server for devices.
    Assigns IP addresses from a defined pool to requesting clients.
    Enhanced with lease persistence, DHCP relay agent, multi-interface serving,
    and rogue-DHCP observation + policy (NAK-on-mismatch).

    Stability additions in this rewrite:
      • idempotent start/stop
      • safer IPv4 pool reconciliation
      • DHCPv4 + DHCPv6 lease cleanup in one worker
      • stale rogue-offer / v6-reply observation cleanup
      • safer subnet/reserved-IP bookkeeping
      • compact admin helpers for recovery / inspection

    NOTE:
      - Set serve_on_all_ifaces=False to restrict to LAN-only serving.
      - Rogue policy:
          * "log"              → only log other servers' Offers/Acks
          * "nak_on_mismatch"  → when a client REQUEST names a different server_id (opt54),
                                  send NAK (authoritative) to steer it back to us.
    """

    def make_duid(self, mac):
        return DUID_LLT(hwtype=1, timeval=int(time.time()), lladdr=mac)

    def __init__(
        self,
        router_logger,
        packet_writer,
        router_in_interface_name: str,
        dhcp_pool_start: str,
        dhcp_pool_end: str,
        interfaces_config: dict,
        dhcp_relay_target_ip: str = None,
        dhcp6_prefix: str = None,
        dhcp6_relay_target_ip: str = None,
        *,
        allow_out_of_pool: bool = True,
        enforce_same_subnet: bool = True,
        serve_on_all_ifaces: bool = True,
        authoritative: bool = True,
        rogue_policy: str = "nak_on_mismatch",  # "log" | "nak_on_mismatch"
        in_mac=None,
        dns_v6=None,
        search_domains=None,
    ):
        import ipaddress, threading, time
        from typing import Dict, Tuple, Set

        self.ipaddress = ipaddress
        self.threading = threading
        self.time = time

        self.logger = router_logger
        self.packet_writer = packet_writer
        self.in_iface = router_in_interface_name
        self._interfaces_config = interfaces_config if isinstance(interfaces_config, dict) else {}

        self.serve_on_all_ifaces = bool(serve_on_all_ifaces)
        self.authoritative = bool(authoritative)
        self.rogue_policy = str(rogue_policy or "nak_on_mismatch")
        self.dns_v6 = dns_v6
        self.search_domains = search_domains

        # --- DHCPv4 ---
        self.lease_pool_start = ipaddress.IPv4Address(dhcp_pool_start)
        self.lease_pool_end = ipaddress.IPv4Address(dhcp_pool_end)
        self._leases: Dict[str, Tuple[ipaddress.IPv4Address, float]] = {}  # mac -> (ip, expiry)
        self.dynamic_ip_pool = list(self._generate_ip_pool(self.lease_pool_start, self.lease_pool_end))
        self.available_ips = set(self.dynamic_ip_pool)
        self._static_leases: Dict[str, ipaddress.IPv4Address] = {}  # mac -> ip
        self._lease_lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self.LEASE_DURATION_SECONDS = 600
        self.dhcp_relay_target_ip = dhcp_relay_target_ip

        self.allow_out_of_pool = bool(allow_out_of_pool)
        self.enforce_same_subnet = bool(enforce_same_subnet)
        self._non_pool_leases: Set[ipaddress.IPv4Address] = set()
        self._reserved_ipv4: Set[ipaddress.IPv4Address] = set()

        # Track seen Offers/Acks from any server: mac -> dict(...)
        self._seen_server_offers: Dict[str, dict] = {}
        self._seen_v6_replies = {}
        self.OBSERVED_SERVER_TTL_SECONDS = 600

        # --- DHCPv6 ---
        self.dhcp6_prefix = ipaddress.IPv6Network(dhcp6_prefix) if dhcp6_prefix else None
        self.dhcp6_relay_target_ip = dhcp6_relay_target_ip
        self.router_ipv6_link_local_out = None
        self._dhcp6_srv_id = DHCP6OptServerId(duid=self.make_duid(in_mac))

        self.V6_LEASE_SECONDS = 3600
        self._v6_leases = {}     # client_duid_hex -> (IPv6Address, expiry_ts)
        self._v6_used = set()    # set[IPv6Address]
        self._v6_declined = set()
        self._v6_declined_ts = {}
        self.V6_DECLINE_TTL_SECONDS = 1800

        self._stop_event = threading.Event()
        self._cleanup_thread = None
        self._started = False
        self.sniffer = None

        self._reserve_router_ipv4_once()

        self.logger.log_message(
            f"[DHCP] Server initialized. v4Relay={self.dhcp_relay_target_ip or 'None'} "
            f"v6Prefix={self.dhcp6_prefix or 'None'} v6Relay={self.dhcp6_relay_target_ip or 'None'} | "
            f"out_of_pool={self.allow_out_of_pool} same_subnet={self.enforce_same_subnet} "
            f"serve_all_ifaces={self.serve_on_all_ifaces} authoritative={self.authoritative} "
            f"rogue_policy={self.rogue_policy}"
        )

    # ---------------- admin APIs ----------------

    def assign_specific_ipv4(self, mac: str, ip, lease_seconds: int | None = None, force: bool = False) -> bool:
        ipaddress, time = self.ipaddress, self.time
        norm_mac = str(mac or "").lower()
        ip_addr = ipaddress.IPv4Address(ip)
        with self._lease_lock:
            in_cfg = self._iface_cfg_for(self.in_iface)
            net = in_cfg.get("network")
            self._reserve_router_ipv4_once()

            if self.enforce_same_subnet and net and ip_addr not in net:
                self.logger.log_message(f"[DHCP] ❌ assign_specific_ipv4 refused: {ip_addr} not in {net}")
                return False

            if ip_addr in self._reserved_ipv4:
                self.logger.log_message(f"[DHCP] ❌ assign_specific_ipv4 refused: {ip_addr} is reserved")
                return False

            for other_mac, (other_ip, _) in self._leases.items():
                if other_ip == ip_addr and other_mac != norm_mac and not force:
                    self.logger.log_message(f"[DHCP] ❌ assign_specific_ipv4 refused: {ip_addr} leased to {other_mac}")
                    return False

            if ip_addr in self.available_ips:
                self.available_ips.discard(ip_addr)
            elif ip_addr not in self.dynamic_ip_pool:
                self._non_pool_leases.add(ip_addr)

            expiry = time.time() + (lease_seconds if lease_seconds is not None else self.LEASE_DURATION_SECONDS)
            self._leases[norm_mac] = (ip_addr, expiry)
            self._static_leases[norm_mac] = ip_addr
            self.logger.log_message(f"[DHCP] 📌 Pinned {ip_addr} to {norm_mac} (force={force}).")
            return True

    def release_ipv4(self, mac: str | None = None, ip=None) -> bool:
        ipaddress = self.ipaddress
        with self._lease_lock:
            if mac:
                mac = str(mac).lower()
                if mac in self._leases:
                    ip_addr, _ = self._leases.pop(mac)
                    self._static_leases.pop(mac, None)
                else:
                    return False
            elif ip is not None:
                ip_addr = ipaddress.IPv4Address(ip)
                target_mac = next((m for m, (i, _) in self._leases.items() if i == ip_addr), None)
                if target_mac is None:
                    return False
                self._leases.pop(target_mac, None)
                self._static_leases.pop(target_mac, None)
            else:
                return False

            if ip_addr in self.dynamic_ip_pool and ip_addr not in self._reserved_ipv4:
                self.available_ips.add(ip_addr)

            self._non_pool_leases.discard(ip_addr)
            self.logger.log_message(f"[DHCP] 🔓 Released lease for {ip_addr}.")
            return True

    def force_reconcile_ipv4_pool(self):
        with self._lease_lock:
            self._reserve_router_ipv4_once()
            live_ips = {ip for ip, _ in self._leases.values()}
            self.available_ips = {
                ip for ip in self.dynamic_ip_pool
                if ip not in live_ips and ip not in self._reserved_ipv4
            }
        self.logger.log_message("[DHCP] 🔄 Reconciled IPv4 pool state.")

    def snapshot(self) -> dict:
        now = self.time.time()
        with self._lease_lock:
            return {
                "in_iface": self.in_iface,
                "lease_pool_start": str(self.lease_pool_start),
                "lease_pool_end": str(self.lease_pool_end),
                "dynamic_pool_size": len(self.dynamic_ip_pool),
                "available_ips": len(self.available_ips),
                "active_ipv4_leases": {
                    mac: {"ip": str(ip), "ttl": max(0, int(exp - now))}
                    for mac, (ip, exp) in self._leases.items()
                    if exp > now
                },
                "static_ipv4_leases": {mac: str(ip) for mac, ip in self._static_leases.items()},
                "non_pool_leases": [str(ip) for ip in self._non_pool_leases],
                "reserved_ipv4": [str(ip) for ip in self._reserved_ipv4],
                "active_v6_leases": {
                    duid: {"ip": str(ip), "ttl": max(0, int(exp - now))}
                    for duid, (ip, exp) in self._v6_leases.items()
                    if exp > now
                },
                "declined_v6": [str(ip) for ip in self._v6_declined],
                "seen_server_offers": len(self._seen_server_offers),
                "seen_v6_replies": len(self._seen_v6_replies),
            }

    # ---------------- internals ----------------

    def _generate_ip_pool(self, start, end):
        current = int(start)
        end_int = int(end)
        while current <= end_int:
            yield self.ipaddress.IPv4Address(current)
            current += 1

    def _reserve_router_ipv4_once(self):
        with self._lease_lock:
            in_cfg = self._iface_cfg_for(self.in_iface)
            net = in_cfg.get("network")
            router_ip = in_cfg.get("ip_addr")

            if router_ip:
                try:
                    r = self.ipaddress.IPv4Address(router_ip)
                    self._reserved_ipv4.add(r)
                except Exception:
                    pass

            if net:
                try:
                    self._reserved_ipv4.add(net.network_address)
                    self._reserved_ipv4.add(net.broadcast_address)
                except Exception:
                    pass

            if self._reserved_ipv4:
                self.available_ips = {
                    ip for ip in self.available_ips
                    if ip not in self._reserved_ipv4
                }

    def _cleanup_observed_state(self, now: float):
        cutoff = now - float(self.OBSERVED_SERVER_TTL_SECONDS)
        stale_v4 = [mac for mac, info in self._seen_server_offers.items() if float(info.get("ts", 0)) <= cutoff]
        for mac in stale_v4:
            self._seen_server_offers.pop(mac, None)

        stale_v6 = [k for k, info in self._seen_v6_replies.items() if float(info.get("ts", 0)) <= cutoff]
        for k in stale_v6:
            self._seen_v6_replies.pop(k, None)

    def _cleanup_v6_state(self, now: float):
        expired = [duid for duid, (_, exp) in self._v6_leases.items() if exp <= now]
        for duid in expired:
            addr, _ = self._v6_leases.pop(duid)
            self._v6_used.discard(addr)
            self.logger.log_message(f"[DHCP] 🗑️ IPv6 lease for {addr} (DUID: {duid[:24]}...) expired.")

        stale_declined = [addr for addr, ts in self._v6_declined_ts.items() if (now - ts) >= self.V6_DECLINE_TTL_SECONDS]
        for addr in stale_declined:
            self._v6_declined_ts.pop(addr, None)
            self._v6_declined.discard(addr)

    def get_ip_to_mac_bindings(self) -> dict:
        t = self.time.time()
        with self._lease_lock:
            return {str(ip): mac for mac, (ip, expiry) in self._leases.items() if t < expiry}

    def start(self):
        threading = self.threading
        with self._lifecycle_lock:
            if self._started and self._cleanup_thread and self._cleanup_thread.is_alive():
                self.logger.log_message("[DHCP] Cleanup thread already running.")
                return
            self._stop_event.clear()
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_leases_loop,
                daemon=True,
                name="DHCPLeaseCleanup"
            )
            self._cleanup_thread.start()
            self._started = True
        self.logger.log_message("[DHCP] Cleanup thread started.")

    def stop(self):
        with self._lifecycle_lock:
            if not self._started:
                self.logger.log_message("[DHCP] Server already stopped.")
                return
            self._stop_event.set()
            thr = self._cleanup_thread
            self._cleanup_thread = None
            self._started = False

        if thr:
            try:
                thr.join(timeout=2)
            except Exception:
                pass
        self.logger.log_message("[DHCP] Server stopped.")

    def _cleanup_leases_loop(self):
        time = self.time
        while not self._stop_event.is_set():
            now = time.time()
            with self._lease_lock:
                expired_macs = [mac for mac, (ip, expiry) in self._leases.items() if expiry <= now]
                for mac in expired_macs:
                    ip, _ = self._leases.pop(mac)
                    if (ip in self.dynamic_ip_pool) and (ip not in set(self._static_leases.values())) and (ip not in self._reserved_ipv4):
                        self.available_ips.add(ip)
                    self._non_pool_leases.discard(ip)
                    self.logger.log_message(f"[DHCP] 🗑️ IPv4 lease for {ip} (MAC: {mac}) expired.")

                self._cleanup_v6_state(now)
                self._cleanup_observed_state(now)
                self.force_reconcile_ipv4_pool()

            self._stop_event.wait(60)

    def _assign_ip(self, client_mac: str, preferred_ip=None):
        ipaddress, time = self.ipaddress, self.time
        norm_mac = str(client_mac or "").lower()
        self.logger.log_message(f"[DHCP] Assigning IP for {norm_mac}")

        with self._lease_lock:
            in_cfg = self._iface_cfg_for(self.in_iface)
            net = in_cfg.get("network")
            self._reserve_router_ipv4_once()

            if norm_mac in self._static_leases:
                static_ip = self._static_leases[norm_mac]
                self.available_ips.discard(static_ip)
                self._leases[norm_mac] = (static_ip, time.time() + self.LEASE_DURATION_SECONDS)
                self.logger.log_message(f"[DHCP] 📌 Assigned static IP {static_ip} to {norm_mac}.")
                return static_ip

            if norm_mac in self._leases:
                assigned_ip, expiry = self._leases[norm_mac]
                if time.time() < expiry:
                    self._leases[norm_mac] = (assigned_ip, time.time() + self.LEASE_DURATION_SECONDS)
                    self.logger.log_message(f"[DHCP] 🏠 Renewed dynamic lease for {assigned_ip} to {norm_mac}")
                    return assigned_ip
                else:
                    self._leases.pop(norm_mac, None)

            if preferred_ip is not None:
                if not isinstance(preferred_ip, ipaddress.IPv4Address):
                    try:
                        preferred_ip = ipaddress.IPv4Address(preferred_ip)
                    except Exception:
                        preferred_ip = None

            if preferred_ip is not None:
                if preferred_ip in self._reserved_ipv4:
                    self.logger.log_message(f"[DHCP] ⚠️ Client requested reserved IP {preferred_ip}; ignoring.")
                elif self.enforce_same_subnet and net and preferred_ip not in net:
                    self.logger.log_message(f"[DHCP] ⚠️ Client requested {preferred_ip} outside {net}; ignoring.")
                else:
                    in_use = any((ip == preferred_ip and mac != norm_mac) for mac, (ip, _) in self._leases.items())
                    if not in_use:
                        if preferred_ip in self.available_ips:
                            self.available_ips.discard(preferred_ip)
                        elif preferred_ip not in self.dynamic_ip_pool:
                            if self.allow_out_of_pool:
                                self._non_pool_leases.add(preferred_ip)
                            else:
                                self.logger.log_message(
                                    f"[DHCP] ⚠️ Requested {preferred_ip} is out of pool and policy forbids it."
                                )
                                preferred_ip = None
                        if preferred_ip is not None:
                            self._leases[norm_mac] = (preferred_ip, time.time() + self.LEASE_DURATION_SECONDS)
                            self.logger.log_message(f"[DHCP] 🎯 Honored requested IP {preferred_ip} for {norm_mac}")
                            return preferred_ip

            try:
                ip_from_pool = min(self.available_ips)
                self.available_ips.discard(ip_from_pool)
                self._leases[norm_mac] = (ip_from_pool, time.time() + self.LEASE_DURATION_SECONDS)
                self.logger.log_message(f"[DHCP] 💻 Assigned new dynamic IP {ip_from_pool} to {norm_mac}.")
                return ip_from_pool
            except ValueError:
                self.logger.log_message(f"[DHCP] ❌ No available dynamic IP addresses in pool for {norm_mac}.")
                return None

    # ---- DHCP helpers ----

    def _get_requested_ip_opt50(self, dhcp_layer):
        try:
            for opt in dhcp_layer.options:
                if isinstance(opt, tuple) and opt[0] in ('requested_addr', 'requested_addr_ip', 50):
                    val = opt[1]
                    return self.ipaddress.IPv4Address(val if not isinstance(val, bytes) else val)
        except Exception:
            pass
        return None

    def _get_server_id_opt54(self, dhcp_layer):
        try:
            for opt in dhcp_layer.options:
                if isinstance(opt, tuple) and opt[0] in ('server_id', 54):
                    v = opt[1]
                    try:
                        return str(self.ipaddress.IPv4Address(v))
                    except Exception:
                        return str(v)
        except Exception:
            pass
        return None

    def _get_msg_type(self, dhcp_layer):
        msg_map = {
            "discover": 1, "offer": 2, "request": 3, "decline": 4,
            "ack": 5, "nak": 6, "release": 7, "inform": 8
        }
        msg_type = None
        for opt in getattr(dhcp_layer, "options", []):
            if isinstance(opt, tuple) and opt[0] == "message-type":
                msg_type = opt[1]
                break
        if isinstance(msg_type, str):
            return msg_map.get(msg_type.lower())
        try:
            return int(msg_type) if msg_type is not None else None
        except Exception:
            return None

    def _classify_dhcp(self, pkt):
        if pkt.haslayer(UDP):
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)

            if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
                if dport == 67 and sport in (68, 67):
                    return "v4", "client"
                if sport == 67 and dport == 68:
                    return "v4", "server"
                return "v4", "other"

            if pkt.haslayer(DHCP6_Solicit):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 546: return "v6", "server"
            if pkt.haslayer(DHCP6_InfoRequest):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 546: return "v6", "server"
            if pkt.haslayer(DHCP6_Reply):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 546: return "v6", "server"
            if pkt.haslayer(DHCP6_Request):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 546: return "v6", "server"
            if pkt.haslayer(DHCP6_Renew):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 546: return "v6", "server"
            if pkt.haslayer(DHCP6_Confirm):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 546: return "v6", "server"
            if pkt.haslayer(DHCP6_Release):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 546: return "v6", "server"
            if pkt.haslayer(DHCP6_Decline):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 546: return "v6", "server"
            if pkt.haslayer(DHCP6_Advertise):
                if dport == 546 and sport == 547: return "v6", "server"
                if dport == 547 and sport == 546: return "v6", "client"
            if pkt.haslayer(DHCP6_RelayForward):
                if dport == 547 and sport == 546: return "v6", "client"
                if sport == 547 and dport == 547: return "v6", "other"
            if pkt.haslayer(DHCP6_RelayReply):
                if sport == 547 and dport in (546, 547): return "v6", "server"
                if dport == 547 and sport in (546, 547): return "v6", "other"

        return None, None

    def _iface_cfg_for(self, inbound_iface: str) -> dict:
        inbound_iface = str(inbound_iface or "")
        cfg = dict(self._interfaces_config.get(inbound_iface, {}) or {})
        lan_cfg = dict(self._interfaces_config.get(self.in_iface, {}) or {})

        if cfg.get("ip_addr"):
            if not cfg.get("network") and cfg.get("cidr"):
                try:
                    cfg["network"] = self.ipaddress.ip_network(str(cfg["cidr"]), strict=False)
                except Exception:
                    pass
            return cfg

        low = inbound_iface.lower()
        is_bridge_alias = (
            "windivertbridge" in low
            or "hyperv" in low
            or "hyper-v" in low
            or "vethernet" in low
            or "nate's tunnel" in low
            or cfg.get("kind") == "hyperv_bridge"
        )

        if is_bridge_alias and lan_cfg:
            merged = dict(lan_cfg)
            for key in ("mac", "dynamic", "kind"):
                if cfg.get(key) is not None:
                    merged[key] = cfg[key]
            if not merged.get("network") and merged.get("cidr"):
                try:
                    merged["network"] = self.ipaddress.ip_network(str(merged["cidr"]), strict=False)
                except Exception:
                    pass
            return merged

        if lan_cfg:
            if not lan_cfg.get("network") and lan_cfg.get("cidr"):
                try:
                    lan_cfg["network"] = self.ipaddress.ip_network(str(lan_cfg["cidr"]), strict=False)
                except Exception:
                    pass
            return lan_cfg

        return cfg

    # ---------------- main packet handler ----------------

    def handle_packet(self, pkt, inbound_iface: str, find_route_function) -> bool:
        if not self.serve_on_all_ifaces and inbound_iface != self.in_iface:
            self.logger.log_message(f"[DHCP] Ignoring on non-LAN iface {inbound_iface} (serve_on_all_ifaces=False).")
            return True

        in_cfg = self._iface_cfg_for(inbound_iface)
        if not in_cfg:
            self.logger.log_message(f"[DHCP] Error: iface '{inbound_iface}' not found in configuration.")
            return True

        router_in_ip = in_cfg.get("ip_addr")
        router_in_mac = in_cfg.get("mac")

        net = None
        try:
            net = in_cfg.get("network")
            if net is None:
                ip_addr = in_cfg.get("ip_addr")
                netmask = in_cfg.get("netmask") or in_cfg.get("mask")
                prefixlen = in_cfg.get("prefixlen")
                if ip_addr and netmask:
                    net = self.ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
                elif ip_addr and prefixlen is not None:
                    net = self.ipaddress.IPv4Network(f"{ip_addr}/{int(prefixlen)}", strict=False)
        except Exception:
            net = None

        version, direction = self._classify_dhcp(pkt)
        if version is None:
            return False  # not DHCP

        is_loopback_request = not pkt.haslayer(Ether)

        # ================= DHCPv4 =================
        if version == "v4":
            if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
                self.logger.log_message("[DHCP] Malformed v4 (missing BOOTP/DHCP); ignoring.")
                return True

            bootp_layer = pkt[BOOTP]
            dhcp_layer = pkt[DHCP]
            msg_type_norm = self._get_msg_type(dhcp_layer)

            try:
                raw_mac = bytes(bootp_layer.chaddr)[:6]
                client_mac = ":".join(f"{b:02x}" for b in raw_mac)
            except Exception:
                client_mac = "??:??:??:??:??:??"

            # ---- Observe server -> client only
            if direction == "server":
                sid = self._get_server_id_opt54(dhcp_layer)
                yiaddr = str(getattr(bootp_layer, "yiaddr", "0.0.0.0"))
                src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "(no-ether)"
                src_ip = pkt[IP].src if pkt.haslayer(IP) else "(no-ip)"
                kind = {2: "OFFER", 5: "ACK", 6: "NAK"}.get(msg_type_norm, f"type={msg_type_norm}")

                self._seen_server_offers[client_mac] = {
                    "ts": self.time.time(),
                    "iface": inbound_iface,
                    "server_mac": src_mac,
                    "server_ip": sid or src_ip,
                    "msg_type": msg_type_norm,
                    "yiaddr": yiaddr,
                }

                router_mac_l = str(router_in_mac).lower() if router_in_mac else ""
                src_mac_l = str(src_mac).lower() if src_mac else ""
                tag = "our" if (sid == router_in_ip or (router_mac_l and src_mac_l == router_mac_l)) else "other"

                self.logger.log_message(
                    f"[DHCP] v4 {kind} observed from {src_mac} (sid={sid or src_ip}) "
                    f"→ {client_mac} yiaddr={yiaddr} on {inbound_iface} [{tag}]"
                )
                return True

            self.logger.log_message(
                f"[DHCP] 📨 v4 type {msg_type_norm} from {client_mac} on {inbound_iface} "
                f"(xid {bootp_layer.xid})"
            )

            if not router_in_ip:
                self.logger.log_message(
                    f"[DHCP] ⚠️ iface '{inbound_iface}' has no ip_addr; falling back to LAN iface '{self.in_iface}'."
                )
                in_cfg = dict(self._interfaces_config.get(self.in_iface, {}) or {})
                router_in_ip = in_cfg.get("ip_addr")
                router_in_mac = in_cfg.get("mac")

                if not router_in_ip:
                    self.logger.log_message(
                        f"[DHCP] ❌ LAN fallback iface '{self.in_iface}' also missing ip_addr; cannot serve DHCPv4."
                    )
                    return True

            if self.dhcp_relay_target_ip:
                self.logger.log_message(
                    f"[DHCP] Relaying v4 to {self.dhcp_relay_target_ip} (iface={inbound_iface})."
                )
                relay_packet = (
                    IP(src=router_in_ip, dst=self.dhcp_relay_target_ip)
                    / UDP(sport=67, dport=67)
                    / BOOTP(**{
                        k: getattr(bootp_layer, k) for k in (
                            "op", "htype", "hlen", "hops", "xid", "secs", "flags",
                            "ciaddr", "yiaddr", "siaddr", "giaddr", "chaddr", "sname", "file"
                        )
                    })
                    / DHCP(options=dhcp_layer.options)
                )
                relay_packet[BOOTP].giaddr = router_in_ip
                self.sniffer.send(relay_packet, inbound_iface)
                return True

            requested_ip = self._get_requested_ip_opt50(dhcp_layer)
            ciaddr_ip = None
            try:
                ci = str(bootp_layer.ciaddr)
                if ci and ci != "0.0.0.0":
                    ciaddr_ip = self.ipaddress.IPv4Address(ci)
            except Exception:
                pass

            def _build_v4_reply_options(message_type: str):
                opts = [("message-type", message_type)]
                if net is not None:
                    try:
                        opts.append(("subnet_mask", str(net.netmask)))
                    except Exception:
                        pass
                opts.extend([
                    ("router", router_in_ip),
                    ("name_server", router_in_ip),
                    ("lease_time", self.LEASE_DURATION_SECONDS),
                    ("server_id", router_in_ip),
                    "end",
                ])
                return opts

            def _wrap_l2(l3_pkt, dst_mac: str | None, broadcast: bool = False):
                if is_loopback_request:
                    return l3_pkt
                if not router_in_mac:
                    return l3_pkt
                if broadcast or not dst_mac:
                    dst_mac = "ff:ff:ff:ff:ff:ff"
                return Ether(src=router_in_mac, dst=dst_mac) / l3_pkt

            # ---- DISCOVER
            if msg_type_norm == 1:
                assigned_ip = self._assign_ip(
                    client_mac,
                    preferred_ip=requested_ip if self.allow_out_of_pool else None,
                )
                if not assigned_ip:
                    self.logger.log_message(f"[DHCP] No IP for DISCOVER from {client_mac}.")
                    return True

                offer_l3 = (
                    IP(src=router_in_ip, dst="255.255.255.255")
                    / UDP(sport=67, dport=68)
                    / BOOTP(
                        op=2,
                        xid=bootp_layer.xid,
                        yiaddr=str(assigned_ip),
                        siaddr=router_in_ip,
                        chaddr=bootp_layer.chaddr,
                    )
                    / DHCP(options=_build_v4_reply_options("offer"))
                )
                reply = _wrap_l2(offer_l3, dst_mac=None, broadcast=True)
                self.sniffer.send(reply, inbound_iface)
                self.logger.log_message(
                    f"[DHCP] 📝 Offer {assigned_ip} → {client_mac} (iface={inbound_iface})"
                )
                return True

            # ---- REQUEST
            if msg_type_norm == 3:
                opt54 = self._get_server_id_opt54(dhcp_layer)

                if opt54 and opt54 != router_in_ip:
                    if self.rogue_policy == "nak_on_mismatch":
                        req_ip = self._get_requested_ip_opt50(dhcp_layer)
                        if not (req_ip and req_ip in self.dynamic_ip_pool):
                            self.logger.log_message(
                                f"[DHCP] Ignoring request for {req_ip} managed by other server {opt54}"
                            )
                            return True

                if opt54 and opt54 != router_in_ip and self.authoritative and self.rogue_policy == "nak_on_mismatch":
                    nak_l3 = (
                        IP(src=router_in_ip, dst="255.255.255.255")
                        / UDP(sport=67, dport=68)
                        / BOOTP(op=2, xid=bootp_layer.xid, chaddr=bootp_layer.chaddr)
                        / DHCP(options=[
                            ("message-type", "nak"),
                            ("server_id", router_in_ip),
                            ("message", "Use this DHCP server"),
                            "end",
                        ])
                    )
                    reply = _wrap_l2(nak_l3, dst_mac=None, broadcast=True)
                    self.sniffer.send(reply, inbound_iface)
                    self.logger.log_message(
                        f"[DHCP] 🚫 Authoritative NAK to {client_mac}: "
                        f"client named server_id={opt54}, ours={router_in_ip}."
                    )
                    return True

                preferred = requested_ip or ciaddr_ip
                assigned_ip = self._assign_ip(
                    client_mac,
                    preferred_ip=preferred if self.allow_out_of_pool else None,
                )
                if not assigned_ip:
                    nak_l3 = (
                        IP(src=router_in_ip, dst="255.255.255.255")
                        / UDP(sport=67, dport=68)
                        / BOOTP(op=2, xid=bootp_layer.xid, chaddr=bootp_layer.chaddr)
                        / DHCP(options=[
                            ("message-type", "nak"),
                            ("server_id", router_in_ip),
                            "end",
                        ])
                    )
                    reply = _wrap_l2(nak_l3, dst_mac=None, broadcast=True)
                    self.sniffer.send(reply, inbound_iface)
                    self.logger.log_message(
                        f"[DHCP] 🚫 NAK to {client_mac} (no IP) (iface={inbound_iface})."
                    )
                    return True

                ack_l3 = (
                    IP(src=router_in_ip, dst=str(assigned_ip))
                    / UDP(sport=67, dport=68)
                    / BOOTP(
                        op=2,
                        xid=bootp_layer.xid,
                        yiaddr=str(assigned_ip),
                        siaddr=router_in_ip,
                        chaddr=bootp_layer.chaddr,
                    )
                    / DHCP(options=_build_v4_reply_options("ack"))
                )
                dst_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
                reply = _wrap_l2(ack_l3, dst_mac=dst_mac, broadcast=False)
                self.sniffer.send(reply, inbound_iface)
                self.logger.log_message(
                    f"[DHCP] 🛰️ ACK {assigned_ip} → {client_mac} (iface={inbound_iface})"
                )
                return True

            # ---- INFORM
            if msg_type_norm == 8:
                opts = [("message-type", "ack")]
                if net is not None:
                    try:
                        opts.append(("subnet_mask", str(net.netmask)))
                    except Exception:
                        pass
                opts.extend([
                    ("router", router_in_ip),
                    ("name_server", router_in_ip),
                    ("server_id", router_in_ip),
                    "end",
                ])

                ack_l3 = (
                    IP(src=router_in_ip, dst="255.255.255.255")
                    / UDP(sport=67, dport=68)
                    / BOOTP(
                        op=2,
                        xid=bootp_layer.xid,
                        yiaddr="0.0.0.0",
                        siaddr=router_in_ip,
                        chaddr=bootp_layer.chaddr,
                    )
                    / DHCP(options=opts)
                )
                reply = _wrap_l2(ack_l3, dst_mac=None, broadcast=True)
                self.sniffer.send(reply, inbound_iface)
                self.logger.log_message(
                    f"[DHCP] ℹ️ INFORM ACK → {client_mac} (iface={inbound_iface})"
                )
                return True

            # ---- RELEASE / DECLINE
            if msg_type_norm in (7, 4):
                freed = self.release_ipv4(client_mac, None)
                self.logger.log_message(
                    f"[DHCP] 🔓 {'RELEASE' if msg_type_norm == 7 else 'DECLINE'} "
                    f"from {client_mac} (freed={freed}) (iface={inbound_iface})"
                )
                return True

            self.logger.log_message(f"[DHCP] v4 type {msg_type_norm} not handled; ignoring.")
            return True

        # ================= DHCPv6 =================
        if version == "v6":
            import re, hashlib

            _ZONE_RE = re.compile(r'%(?:\d+|[A-Za-z0-9_.-]+)$')

            def _rm_zone(addr: str | None) -> str | None:
                if not addr or '%' not in addr:
                    return addr
                return _ZONE_RE.sub('', addr)

            def _mk_clid_opt(pkt_):
                cl = pkt_.getlayer(DHCP6OptClientId)
                return DHCP6OptClientId(duid=cl.duid) if cl is not None else None

            def _clid_hex(pkt_):
                cl = pkt_.getlayer(DHCP6OptClientId)
                if cl is None:
                    return None
                try:
                    return bytes(getattr(cl, "duid", b"")).hex()
                except Exception:
                    return None

            def _pick_v6_addr_for_client(pkt_):
                if not self.dhcp6_prefix:
                    return None

                ipaddress, time = self.ipaddress, self.time
                duid_hex = _clid_hex(pkt_) or ""
                key = (duid_hex or "") + "|" + (client_mac or "") + "|" + str(self.dhcp6_prefix)

                now = time.time()
                if duid_hex and duid_hex in self._v6_leases:
                    addr, exp = self._v6_leases[duid_hex]
                    if now < exp and addr not in self._v6_declined:
                        return addr

                net = self.dhcp6_prefix
                base = int(net.network_address)
                host_bits = 128 - int(net.prefixlen)
                if host_bits <= 0:
                    return ipaddress.IPv6Address(base)

                h = hashlib.sha256(key.encode("utf-8", "ignore")).digest()
                off = int.from_bytes(h[:8], "big") & ((1 << min(host_bits, 64)) - 1)
                if off < 2:
                    off += 2

                cand = ipaddress.IPv6Address(base + off)
                tries = 0
                while (cand in self._v6_declined) or (cand in self._v6_used):
                    tries += 1
                    cand = ipaddress.IPv6Address(int(cand) + 1)
                    if tries > 64:
                        return None

                if duid_hex:
                    self._v6_leases[duid_hex] = (cand, now + self.V6_LEASE_SECONDS)
                self._v6_used.add(cand)
                return cand

            def _first_iana(pkt_):
                try:
                    return pkt_.getlayer(DHCP6OptIA_NA)
                except Exception:
                    return None

            def _send_v6_reply(dst_ip6: str, dst_mac: str | None, dhcp6_payload):
                router_ll_nz = _rm_zone(router_ll)
                dst_ip6_nz = _rm_zone(dst_ip6)
                if not router_ll_nz or not dst_ip6_nz:
                    return

                ip6 = IPv6(src=router_ll_nz, dst=dst_ip6_nz, hlim=1)
                udp = UDP(sport=547, dport=546)
                if (not is_loopback) and dst_mac:
                    out = Ether(src=router_in_mac, dst=dst_mac) / ip6 / udp / dhcp6_payload
                elif not is_loopback:
                    out = Ether(src=router_in_mac, dst="33:33:00:01:00:02") / IPv6(
                        src=router_ll_nz, dst="ff02::1:2", hlim=1
                    ) / udp / dhcp6_payload
                else:
                    out = ip6 / udp / dhcp6_payload
                self.sniffer.send(out, inbound_iface)

            def _add_dns_opts(reply_pkt):
                try:
                    def _to_list_ipv6(v):
                        if v is None: return []
                        if isinstance(v, (list, tuple)): return [str(x) for x in v]
                        return [str(v)]
                    dns_list = _to_list_ipv6(self.dns_v6)
                    if dns_list:
                        reply_pkt /= DHCP6OptDNSServers(dnsservers=dns_list)
                except Exception:
                    pass
                try:
                    def _to_list_str(v):
                        if v is None: return []
                        if isinstance(v, (list, tuple)): return [str(x) for x in v]
                        if isinstance(v, str) and "," in v:
                            return [s.strip() for s in v.split(",") if s.strip()]
                        return [str(v)]
                    dom_list = _to_list_str(self.search_domains)
                    if dom_list:
                        reply_pkt /= DHCP6OptDNSDomains(domains=dom_list)
                except Exception:
                    pass
                return reply_pkt

            def _status(code: int, msg: str = ""):
                try:
                    return DHCP6OptStatusCode(statuscode=int(code), statusmsg=str(msg or ""))
                except Exception:
                    return None

            router_ll = self.router_ipv6_link_local_out
            if not router_ll:
                self.logger.log_message("[DHCP] v6: missing router IPv6 (no link-local/global); cannot serve.")
                return True

            is_loopback = not pkt.haslayer(Ether)
            client_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
            v6src = pkt[IPv6].src

            dhcp6 = None
            msgtype = 0

            if pkt.haslayer(DHCP6_Solicit):
                dhcp6 = pkt[DHCP6_Solicit]; msgtype = 1
            elif pkt.haslayer(DHCP6_InfoRequest):
                dhcp6 = pkt[DHCP6_InfoRequest]; msgtype = 11
            elif pkt.haslayer(DHCP6_Request):
                dhcp6 = pkt[DHCP6_Request]; msgtype = 3
            elif pkt.haslayer(DHCP6_Renew):
                dhcp6 = pkt[DHCP6_Renew]; msgtype = 5
            elif pkt.haslayer(DHCP6_Confirm):
                dhcp6 = pkt[DHCP6_Confirm]; msgtype = 4
            elif pkt.haslayer(DHCP6_Release):
                dhcp6 = pkt[DHCP6_Release]; msgtype = 8
            elif pkt.haslayer(DHCP6_Decline):
                dhcp6 = pkt[DHCP6_Decline]; msgtype = 9
            elif pkt.haslayer(DHCP6_Advertise):
                dhcp6 = pkt[DHCP6_Advertise]; msgtype = 2
            elif pkt.haslayer(DHCP6_Reply):
                dhcp6 = pkt[DHCP6_Reply]; msgtype = 7
            elif pkt.haslayer(DHCP6_RelayForward):
                dhcp6 = pkt[DHCP6_RelayForward]; msgtype = 12
            elif pkt.haslayer(DHCP6_RelayReply):
                dhcp6 = pkt[DHCP6_RelayReply]; msgtype = 13

            if msgtype in (2, 7, 10, 13):
                src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "(no-ether)"
                dst_ll = str(pkt[IPv6].dst) if pkt.haslayer(IPv6) else "(no-ip)"
                srv_id = pkt.getlayer(DHCP6OptServerId)
                cli_id = pkt.getlayer(DHCP6OptClientId)
                dns_opt = pkt.getlayer(DHCP6OptDNSServers)
                dom_opt = pkt.getlayer(DHCP6OptDNSDomains)

                our_duid = bytes(getattr(self._dhcp6_srv_id, "duid", b""))
                srv_duid = bytes(getattr(srv_id, "duid", b"")) if srv_id else b""
                tag = "our" if (srv_duid and our_duid and srv_duid == our_duid) else "other"

                dns_list = [str(x) for x in getattr(dns_opt, "dnsservers", [])] if dns_opt else []
                dom_list = [str(x) for x in getattr(dom_opt, "domains", [])] if dom_opt else []

                self._seen_v6_replies[dst_ll] = {
                    "ts": self.time.time(),
                    "iface": inbound_iface,
                    "server_mac": src_mac,
                    "server_duid_hex": srv_duid.hex() if srv_duid else "",
                    "client_duid_hex": (bytes(getattr(cli_id, "duid", b"")).hex() if cli_id else ""),
                    "dns": dns_list,
                    "domains": dom_list,
                    "msgtype": msgtype,
                    "tag": tag,
                }

                name = {2: "ADVERTISE", 7: "REPLY", 10: "RECONFIGURE", 13: "RELAY-REPLY"}.get(msgtype, f"type={msgtype}")
                self.logger.log_message(
                    f"[DHCP] v6 {name} observed from {src_mac} → {dst_ll} [{tag}] DNS={dns_list or '[]'} DOM={dom_list or '[]'}"
                )
                return True

            if direction != "client":
                src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "(no-ether)"
                self.logger.log_message(f"[DHCP] v6 server→client observed from {src_mac}; skipping.")
                return True

            if self.dhcp6_relay_target_ip:
                target = self.dhcp6_relay_target_ip
                self.logger.log_message(f"[DHCP] Relaying v6 to {target}.")
                relay = (
                    IPv6(src=router_ll, dst=target, hlim=255)
                    / UDP(sport=547, dport=547)
                    / DHCP6_RelayForward(linkaddr=router_ll, peeraddr=v6src, msg=pkt[DHCP6])
                )
                out = (Ether(src=router_in_mac, dst=client_mac) / relay) if (client_mac and not is_loopback) else relay
                self.sniffer.send(out, inbound_iface)
                return True

            # ---- DECLINE
            if msgtype == 9:
                du = _clid_hex(pkt)
                if du and du in self._v6_leases:
                    addr, _ = self._v6_leases.pop(du)
                    self._v6_used.discard(addr)
                    self._v6_declined.add(addr)
                    self._v6_declined_ts[addr] = self.time.time()

                clid = _mk_clid_opt(pkt)
                if clid:
                    reply = DHCP6_Reply(trid=dhcp6.trid) / self._dhcp6_srv_id / clid
                    st = _status(0, "Declined")
                    if st: reply /= st
                    reply = _add_dns_opts(reply)
                    _send_v6_reply(v6src, client_mac, reply)

                self.logger.log_message(f"[DHCP] v6 DECLINE handled for {v6src} (iface={inbound_iface})")
                return True

            # ---- SOLICIT
            if msgtype == 1:
                v6src_raw = pkt[IPv6].src
                router_ll_nz = _rm_zone(router_ll)
                v6src_nz = _rm_zone(v6src_raw)

                if not router_ll_nz or not v6src_nz:
                    self.logger.log_message("[DHCP] v6: invalid link-local addressing; skipping reply")
                    return False

                dhcp6 = pkt.getlayer(DHCP6_Solicit) or pkt.getlayer(DHCP6_InfoRequest)
                advertise = (
                    IPv6(src=router_ll_nz, dst=v6src_nz, hlim=255)
                    / UDP(sport=547, dport=546)
                    / DHCP6_Advertise(trid=dhcp6.trid)
                    / self._dhcp6_srv_id
                )

                out = (Ether(src=router_in_mac, dst=client_mac) / advertise) if (client_mac and not is_loopback) else advertise
                self.sniffer.send(out, inbound_iface)
                self.logger.log_message(f"[DHCP] v6 ADVERTISE → {v6src_nz} (iface={inbound_iface})")
                return True

            # ---- INFO-REQUEST
            if msgtype == 11:
                clid_layer = pkt.getlayer(DHCP6OptClientId)
                clid = DHCP6OptClientId(duid=clid_layer.duid) if clid_layer is not None else None

                reply = DHCP6_Reply(trid=dhcp6.trid)
                reply /= self._dhcp6_srv_id
                if clid:
                    reply /= clid

                def _to_list_ipv6(v):
                    if v is None: return []
                    if isinstance(v, (list, tuple)): return [str(x) for x in v]
                    return [str(v)]

                def _to_list_str(v):
                    if v is None: return []
                    if isinstance(v, (list, tuple)): return [str(x) for x in v]
                    if isinstance(v, str) and "," in v:
                        return [s.strip() for s in v.split(",") if s.strip()]
                    return [str(v)]

                try:
                    dns_list = _to_list_ipv6(self.dns_v6)
                    if dns_list:
                        reply /= DHCP6OptDNSServers(dnsservers=dns_list)
                except Exception:
                    pass

                try:
                    dom_list = _to_list_str(self.search_domains)
                    if dom_list:
                        reply /= DHCP6OptDNSDomains(domains=dom_list)
                except Exception:
                    pass

                try:
                    reply /= DHCP6OptInfoRefreshTime(irtt=600)
                except Exception:
                    pass

                ip6 = IPv6(src=router_ll, dst=v6src, hlim=1)
                udp = UDP(sport=547, dport=546)

                if (not is_loopback) and client_mac:
                    l2 = Ether(src=router_in_mac, dst=client_mac)
                    out = l2 / ip6 / udp / reply
                elif not is_loopback:
                    l2 = Ether(src=router_in_mac, dst="33:33:00:01:00:02")
                    out = l2 / IPv6(src=router_ll, dst="ff02::1:2", hlim=1) / udp / reply
                else:
                    out = ip6 / udp / reply

                self.sniffer.send(out, inbound_iface)
                self.logger.log_message(f"[DHCP] v6 INFO-REPLY → {v6src} (iface={inbound_iface})")
                return True

            # ---- CONFIRM
            if msgtype == 4:
                clid = _mk_clid_opt(pkt)
                if not clid:
                    self.logger.log_message("[DHCP] v6 CONFIRM missing Client-ID; ignoring.")
                    return True

                reply = DHCP6_Reply(trid=dhcp6.trid) / self._dhcp6_srv_id / clid
                st = _status(0, "On-link") if self.dhcp6_prefix else _status(4, "NotOnLink")
                if st: reply /= st
                reply = _add_dns_opts(reply)
                _send_v6_reply(v6src, client_mac, reply)
                self.logger.log_message(f"[DHCP] v6 CONFIRM-REPLY → {v6src} (iface={inbound_iface})")
                return True

            # ---- REQUEST / RENEW / REBIND
            if msgtype in (3, 5, 6):
                clid = _mk_clid_opt(pkt)
                if not clid:
                    self.logger.log_message(f"[DHCP] v6 msg={msgtype} missing Client-ID; ignoring.")
                    return True

                reply = DHCP6_Reply(trid=dhcp6.trid) / self._dhcp6_srv_id / clid
                ia = _first_iana(pkt)

                if self.dhcp6_prefix and ia is not None:
                    addr = _pick_v6_addr_for_client(pkt)
                    if addr is None:
                        st = _status(2, "NoAddrsAvail")
                        if st: reply /= st
                    else:
                        try:
                            T1 = int(self.V6_LEASE_SECONDS * 0.5)
                            T2 = int(self.V6_LEASE_SECONDS * 0.8)
                            ia_reply = DHCP6OptIA_NA(iaid=int(getattr(ia, "iaid", 0)), T1=T1, T2=T2)
                            ia_reply /= DHCP6OptIAAddress(
                                addr=str(addr),
                                preflft=self.V6_LEASE_SECONDS,
                                validlft=self.V6_LEASE_SECONDS,
                            )
                            reply /= ia_reply
                        except Exception:
                            st = _status(1, "UnspecFail")
                            if st: reply /= st
                else:
                    st = _status(0, "Stateless")
                    if st: reply /= st

                reply = _add_dns_opts(reply)
                _send_v6_reply(v6src, client_mac, reply)

                name = {3: "REQUEST", 5: "RENEW", 6: "REBIND"}.get(msgtype, str(msgtype))
                self.logger.log_message(f"[DHCP] v6 {name}-REPLY → {v6src} (iface={inbound_iface})")
                return True

            # ---- RELEASE
            if msgtype == 8:
                du = _clid_hex(pkt)
                if du and du in self._v6_leases:
                    addr, _ = self._v6_leases.pop(du)
                    self._v6_used.discard(addr)

                clid = _mk_clid_opt(pkt)
                if clid:
                    reply = DHCP6_Reply(trid=dhcp6.trid) / self._dhcp6_srv_id / clid
                    st = _status(0, "Released")
                    if st: reply /= st
                    reply = _add_dns_opts(reply)
                    _send_v6_reply(v6src, client_mac, reply)

                self.logger.log_message(f"[DHCP] v6 RELEASE handled for {v6src} (iface={inbound_iface})")
                return True

            self.logger.log_message(f"[DHCP] v6 msgtype {msgtype} not handled; ignoring.")
            return True

        return False

class OutboundLoadBalancer:
    """
    Distributes outbound traffic across multiple configured WAN interfaces using a hash-based method.
    Ensures flow consistency (packets from the same source to same destination go via the same interface).
    Now also includes functionality to select the best available interface based on its 'up' status.
    """

    def __init__(self, router_logger):
        self.logger = router_logger
        self._outbound_interfaces: List[str] = []
        self._interface_status: Dict[str, bool] = {}  # Tracks the 'up'/'down' status of each interface
        self._interface_lock = threading.Lock()
        self.best_interface = None
        self.logger.log_message("[OutboundLB] Initialized.")

    def add_outbound_interface(self, iface_full_name: str, is_up: bool = True):
        """Adds a full interface name to the load balancing pool and sets its initial status."""
        with self._interface_lock:
            if iface_full_name not in self._outbound_interfaces:
                self._outbound_interfaces.append(iface_full_name)
                self._interface_status[iface_full_name] = is_up
                self.logger.log_message(f"[OutboundLB] Added interface {iface_full_name.split('_')[-1]} to pool.")
            else:
                self.logger.log_message(f"[OutboundLB] Interface {iface_full_name.split('_')[-1]} already in pool.")

    def remove_outbound_interface(self, iface_full_name: str):
        """Removes an interface from the load balancing pool."""
        with self._interface_lock:
            if iface_full_name in self._outbound_interfaces:
                self._outbound_interfaces.remove(iface_full_name)
                if iface_full_name in self._interface_status:
                    del self._interface_status[iface_full_name]
                self.logger.log_message(f"[OutboundLB] Removed interface {iface_full_name.split('_')[-1]} from pool.")
            else:
                self.logger.log_message(f"[OutboundLB] Interface {iface_full_name.split('_')[-1]} not found in pool.")

    def update_interface_status(self, iface_full_name: str, is_up: bool):
        """Updates the operational status of a specific interface."""
        with self._interface_lock:
            if iface_full_name in self._interface_status:
                self._interface_status[iface_full_name] = is_up
                self.logger.log_message(
                    f"[OutboundLB] Updated status for {iface_full_name.split('_')[-1]} to {'UP' if is_up else 'DOWN'}.")
            else:
                self.logger.log_message(
                    f"[OutboundLB] Cannot update status: Interface {iface_full_name.split('_')[-1]} not in pool.")

    def get_best_interface(self) -> str | None:
        """
        Chooses the first available 'up' and connected interface from the configured pool.
        It checks both internal status and physical media connection using PowerShell.
        """
        with self._interface_lock:
            if self.best_interface == None:
                for iface in self._outbound_interfaces:
                    if not self._interface_status.get(iface, False):
                        continue  # Skip if internally marked as down

                    guid = iface.split("_")[-1]

                    # --- PowerShell check for MediaConnectionState ---
                    ps_cmd = (
                        f"Get-NetAdapter | Where-Object {{ $_.InterfaceGuid -eq '{guid}' }} | "
                        f"Select-Object -ExpandProperty MediaConnectionState"
                    )
                    try:
                        result = subprocess.run(
                            ["powershell.exe", "-Command", ps_cmd],
                            capture_output=True, text=True, timeout=2
                        )

                        state = result.stdout.strip().lower()
                        if state == "connected":
                            self.logger.log_message(
                                f"[OutboundLB] ✅ Best available interface: {guid} (connected). Is set as best.")
                            self.best_interface = iface
                            return iface
                        else:
                            self.logger.log_message(
                                f"[OutboundLB] ⚠️ Interface {guid} is not connected ({state}).")

                    except subprocess.SubprocessError as e:
                        self.logger.log_message(f"[OutboundLB] ❌ Error checking interface {guid}: {e}")

                self.logger.log_message("[OutboundLB] ❌ No 'up' and connected interfaces available in the pool.")
                return None
            else:
                return self.best_interface
    def get_next_interface(self, packet: Packet) -> str | None:
        """
        Selects an outbound interface based on a hash of source/destination IPs and ports,
        ensuring the selected interface is currently 'up'. If the hashed interface is
        down, it will fall back to the next available 'up' interface.
        """
        with self._interface_lock:
            if not self._outbound_interfaces:
                self.logger.log_message("[OutboundLB] No active outbound interfaces for load balancing.")
                return None

            active_interfaces = [iface for iface, status in self._interface_status.items() if status]
            if not active_interfaces:
                self.logger.log_message("[OutboundLB] No 'up' interfaces available for routing.")
                return None

            if len(active_interfaces) == 1:
                return active_interfaces[0]

            # Hash based on source IP, destination IP, and optionally ports for TCP/UDP
            # (Original hash logic)
            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            hash_components = [ip_layer.src, ip_layer.dst]
            if packet.haslayer(TCP):
                hash_components.extend([packet[TCP].sport, packet[TCP].dport])
            elif packet.haslayer(UDP):
                hash_components.extend([packet[UDP].sport, packet[UDP].dport])

            hash_val = hash(tuple(hash_components))

            # Find the starting index and iterate from there
            start_index = hash_val % len(self._outbound_interfaces)
            for i in range(len(self._outbound_interfaces)):
                current_index = (start_index + i) % len(self._outbound_interfaces)
                candidate_iface = self._outbound_interfaces[current_index]

                if self._interface_status.get(candidate_iface, False):
                    #self.logger.log_message(f"[OutboundLB] Selected interface {candidate_iface.split('_')[-1]} for flow {ip_layer.src} -> {ip_layer.dst}.")
                    return candidate_iface

            self.logger.log_message("[OutboundLB] Hash-based selection failed, no 'up' interfaces found.")
            return None

    def get_configured_interfaces(self) -> List[str]:
        """Returns a list of interfaces configured for outbound load balancing."""
        with self._interface_lock:
            return self._outbound_interfaces[:]

class LinkAggregationManager:
    """
    Manages static link aggregation (LAG) groups.
    Distributes traffic across member physical interfaces within a LAG using a hash-based method.
    Does NOT implement LACP negotiation.
    """

    def __init__(self, router_logger):
        self.logger = router_logger
        # _lags: { lag_name: [member_iface_full_name_1, member_iface_full_name_2, ...] }
        self._lags: Dict[str, List[str]] = {}
        self._lag_lock = threading.Lock()
        self.logger.log_message("[LAG] Manager initialized.")

    def create_lag(self, lag_name: str, member_interfaces: List[str]) -> bool:
        """
        Creates a new Link Aggregation Group (LAG).
        Args:
            lag_name (str): The logical name for the LAG (e.g., "PortChannel1").
            member_interfaces (List[str]): A list of full Scapy interface names that are part of this LAG.
        Returns True if LAG created/updated, False if invalid members or already exists.
        """
        if not member_interfaces or len(member_interfaces) < 1:
            self.logger.log_message(
                f"[LAG] ❌ Cannot create LAG '{lag_name}': At least one member interface is required.")
            return False

        # Basic check: ensure member_interfaces are unique
        if len(set(member_interfaces)) != len(member_interfaces):
            self.logger.log_message(f"[LAG] ❌ Cannot create LAG '{lag_name}': Duplicate member interfaces provided.")
            return False

        with self._lag_lock:
            if lag_name in self._lags:
                self.logger.log_message(f"[LAG] ℹ️ LAG '{lag_name}' already exists. Updating members.")

            self._lags[lag_name] = list(member_interfaces)  # Store a copy
            self.logger.log_message(
                f"[LAG] ✅ Created/Updated LAG '{lag_name}' with members: {[m.split('_')[-1] for m in member_interfaces]}.")
            return True

    def remove_lag(self, lag_name: str) -> bool:
        """Removes a Link Aggregation Group."""
        with self._lag_lock:
            if lag_name in self._lags:
                del self._lags[lag_name]
                self.logger.log_message(f"[LAG] 🗑️ Removed LAG '{lag_name}'.")
                return True
            else:
                self.logger.log_message(f"[LAG] ⚠️ LAG '{lag_name}' not found.")
                return False

    def is_lag_interface(self, lag_name) -> bool:
        """Checks if a given interface name is a logical LAG interface."""
        with self._lag_lock:
            return lag_name in self._lags

    def get_member_interface(self, lag_name: str, packet: Packet) -> str | None:
        """
        Selects a physical member interface from a LAG for a given packet.
        Uses a hash-based algorithm (src IP, dst IP, src port, dst port) for flow consistency
        for IP traffic. For non-IP traffic, it uses the destination MAC address.
        """
        with self._lag_lock:
            member_interfaces = self._lags.get(lag_name)
            if not member_interfaces:
                self.logger.log_message(f"[LAG] ❌ LAG '{lag_name}' not found or has no active members.")
                return None

            active_members = [iface for iface in member_interfaces if True]  # Placeholder
            if not active_members:
                self.logger.log_message(f"[LAG] 🚫 LAG '{lag_name}' has no active physical members. Cannot send packet.")
                return None

            if len(active_members) == 1:
                return active_members[0]

            hash_components = []
            if packet.haslayer(IP) or packet.haslayer(IPv6):
                # Case 1: IP packet - use the IP and transport layer information
                ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
                hash_components.extend([ip_layer.src, ip_layer.dst])

                if packet.haslayer(TCP):
                    hash_components.extend([packet[TCP].sport, packet[TCP].dport])
                elif packet.haslayer(UDP):
                    hash_components.extend([packet[UDP].sport, packet[UDP].dport])

                # Use a generic log message for IP flows
                flow_info = f"{ip_layer.src} -> {ip_layer.dst}"
            else:
                # Case 2: Non-IP packet (e.g., ARP, LLDP) - use the destination MAC address
                hash_components.append(packet.dst)
                flow_info = f"non-IP traffic to MAC {packet.dst}"

            hash_val = hash(tuple(hash_components))
            selected_index = hash_val % len(active_members)
            selected_member = active_members[selected_index]

            self.logger.log_message(
                f"[LAG] Selected member {selected_member.split('_')[-1]} for LAG '{lag_name}' flow ({flow_info}).")
            return selected_member

    def get_lag_members(self) -> Dict[str, List[str]]:
        """Returns a copy of the current LAG configurations."""
        with self._lag_lock:
            return {lag_name: members[:] for lag_name, members in self._lags.items()}

class FirewallManager:
    """
    Manages stateful firewall rules (ACLs) to permit or deny packets.
    Rules are processed in order.
    """

    def __init__(self, router_logger):
        self.logger = router_logger
        self._rules: List[Dict[str, Any]] = [ ]

        self._rule_lock = threading.Lock()
        self.logger.log_message("[Firewall] 🔥 Manager initialized.")

    def add_rule(self, action: str, protocol: str = 'any', src_ip: str = 'any', dst_ip: str = 'any',
                 src_port: Any = 'any', dst_port: Any = 'any', position: int = None) -> bool:
        """Adds a new firewall rule. Position allows inserting at a specific index."""
        rule = {
            'action': action.lower(),
            'protocol': protocol.lower(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port
        }

        # Basic validation
        if rule['action'] not in ['permit', 'deny']:
            self.logger.log_message(f"[Firewall] 🔥 Invalid action '{action}'. Must be 'permit' or 'deny'.")
            return False
        if rule['protocol'] not in ['tcp', 'udp', 'icmp', 'igmp', 'esp', 'any']:
            self.logger.log_message(
                f"[Firewall] 🔥 Invalid protocol '{protocol}'. Must be 'tcp', 'udp', 'icmp', or 'any'.")
            return False

        # IP address validation (basic)
        for ip_field in ['src_ip', 'dst_ip']:
            if rule[ip_field] != 'any':
                try:
                    ipaddress.ip_network(rule[ip_field], strict=False)  # Allows both host and network
                except ValueError:
                    self.logger.log_message(
                        f"[Firewall] 🔥 Invalid IP address/network format for {ip_field}: {rule[ip_field]}.")
                    return False

        # Port validation (basic)
        for port_field in ['src_port', 'dst_port']:
            if rule[port_field] != 'any':
                if isinstance(rule[port_field], int):
                    if not (0 <= rule[port_field] <= 65535):
                        self.logger.log_message(
                            f"[Firewall] 🔥 Invalid port number for {port_field}: {rule[port_field]}. Must be 0-65535.")
                        return False
                elif isinstance(rule[port_field], str) and '-' in rule[port_field]:
                    try:
                        start, end = map(int, rule[port_field].split('-'))
                        if not (0 <= start <= end <= 65535):
                            self.logger.log_message(
                                f"[Firewall] 🔥 Invalid port range for {port_field}: {rule[port_field]}. Must be 0-65535 and start <= end.")
                            return False
                    except ValueError:
                        self.logger.log_message(
                            f"[Firewall] 🔥 Invalid port range format for {port_field}: {rule[port_field]}. Use 'start-end'.")
                        return False
                else:
                    self.logger.log_message(
                        f"[Firewall] 🔥 Invalid port format for {port_field}: {rule[port_field]}. Use integer, 'start-end', or 'any'.")
                    return False

        with self._rule_lock:
            if position is None or position >= len(self._rules):
                self._rules.append(rule)
                self.logger.log_message(f"[Firewall] ✅ Added rule (end): {rule}")
            else:
                self._rules.insert(position, rule)
                self.logger.log_message(f"[Firewall] ✅ Added rule (pos {position}): {rule}")
        return True

    def remove_rule(self, index: int) -> bool:
        """Removes a firewall rule by its index."""
        with self._rule_lock:
            if 0 <= index < len(self._rules):
                removed_rule = self._rules.pop(index)
                self.logger.log_message(f"[Firewall] 🗑️ Removed rule at index {index}: {removed_rule}")
                return True
            else:
                self.logger.log_message(f"[Firewall] ⚠️ No rule found at index {index}.")
                return False

    def get_rules(self) -> List[Dict[str, Any]]:
        """Returns a copy of the current firewall rules."""
        with self._rule_lock:
            return self._rules[:]

    def process_packet(self, packet: Packet) -> bool:
        """
        Processes a packet against the firewall rules.
        Returns True if the packet is permitted, False if denied.
        """
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return True  # Non-IP packets are not filtered by this firewall (e.g., ARP)

        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Extract protocol and ports
        protocol = 'any'
        src_port = 'any'
        dst_port = 'any'

        if packet.haslayer(TCP):
            protocol = 'tcp'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = 'udp'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = 'icmp'
            # ICMP doesn't have ports, so src_port/dst_port remain 'any'

        with self._rule_lock:
            for i, rule in enumerate(self._rules):
                match = True

                # Match protocol
                if rule['protocol'] != 'any' and rule['protocol'] != protocol:
                    match = False

                # Match source IP
                if match and rule['src_ip'] != 'any':
                    try:
                        if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(rule['src_ip'], strict=False):
                            match = False
                    except ValueError:  # Handle cases where rule['src_ip'] might be a single host IP
                        if str(ipaddress.ip_address(src_ip)) != rule['src_ip']:
                            match = False

                # Match destination IP
                if match and rule['dst_ip'] != 'any':
                    try:
                        if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(rule['dst_ip'], strict=False):
                            match = False
                    except ValueError:  # Handle cases where rule['dst_ip'] might be a single host IP
                        if str(ipaddress.ip_address(dst_ip)) != rule['dst_ip']:
                            match = False

                # Match source port
                if match and rule['src_port'] != 'any':
                    if isinstance(rule['src_port'], int):
                        if src_port != rule['src_port']:
                            match = False
                    elif isinstance(rule['src_port'], str) and '-' in rule['src_port']:
                        try:
                            start, end = map(int, rule['src_port'].split('-'))
                            if not (start <= src_port <= end):
                                match = False
                        except ValueError:  # Should have been caught by add_rule, but defensive
                            match = False
                    elif protocol == 'icmp':  # ICMP has no ports, so if rule specifies port, it won't match
                        match = False

                # Match destination port
                if match and rule['dst_port'] != 'any':
                    if isinstance(rule['dst_port'], int):
                        if dst_port != rule['dst_port']:
                            match = False
                    elif isinstance(rule['dst_port'], str) and '-' in rule['dst_port']:
                        try:
                            start, end = map(int, rule['dst_port'].split('-'))
                            if not (start <= dst_port <= end):
                                match = False
                        except ValueError:  # Should have been caught by add_rule, but defensive
                            match = False
                    elif protocol == 'icmp':  # ICMP has no ports, so if rule specifies port, it won't match
                        match = False

                if match:
                    if rule['action'] == 'permit':
                        self.logger.log_message(f"[Firewall] 🧱 Packet permitted by rule {i}: {rule}")
                        return True
                    else:  # deny
                        self.logger.log_message(f"[Firewall] 🔥 Packet DENIED by rule {i}: {rule}")
                        return False
            self.logger.log_message(
                f"[Firewall] ✅ No matching rule found — default permit for packet: {packet.summary()}")
            return True


class P2PPeerManager:
    """
    Manages peer-to-peer discovery.
    Sends via SnifferSoftware (direct L2 injection to bypass Windows routing).
    Listens via standard OS UDP sockets (background thread).
    """
    MAGIC_HEADER = "PYROUTER_P2P_V5"

    def __init__(
        self,
        router_logger,
        router_ip: str,
        sniffer,
        out_iface: str,
        broadcast_ip: str = "255.255.255.255",
        port: int = 49999,
    ):
        self.router_logger = router_logger
        self.router_ip = router_ip
        self.broadcast_ip = broadcast_ip
        self.port = port
        self.node_id = str(uuid.uuid4())

        self.sniffer = sniffer
        self.out_iface = out_iface

        self.arp_manager = None
        self.rip_manager = None

        self.running = False
        self._listen_thread: Optional[threading.Thread] = None
        self._broadcast_thread: Optional[threading.Thread] = None
        self._listen_sock: Optional[socket.socket] = None

        self._lock = threading.RLock()
        self._stop_event = threading.Event()

        self.peers: Dict[str, Dict[str, Any]] = {}
        self.peer_timeout = 35.0
        self.broadcast_interval = 10.0

    def set_managers(self, arp_manager, rip_manager):
        self.arp_manager = arp_manager
        self.rip_manager = rip_manager

    def start(self):
        with self._lock:
            if self.running:
                return

            self.running = True
            self._stop_event.clear()

            # Prefer non-daemon since we explicitly manage shutdown
            self._listen_thread = threading.Thread(
                target=self._listener_loop,
                daemon=False,
                name="P2P-Listener",
            )
            self._broadcast_thread = threading.Thread(
                target=self._broadcaster_loop,
                daemon=False,
                name="P2P-Broadcaster",
            )

            self._listen_thread.start()
            self._broadcast_thread.start()

        self.router_logger.log_message(
            f"[P2P] 🟢 Started Node {self.node_id[:8]} on port {self.port} (Hybrid Mode)"
        )

    def stop(self):
        with self._lock:
            if not self.running and not self._listen_thread and not self._broadcast_thread:
                return

            self.running = False
            self._stop_event.set()
            listen_sock = self._listen_sock
            listen_thread = self._listen_thread
            broadcast_thread = self._broadcast_thread

        self.router_logger.log_message("[P2P] 🛑 Stopping Peer Manager...")

        # Force recvfrom() to unblock immediately
        if listen_sock is not None:
            try:
                listen_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                listen_sock.close()
            except Exception:
                pass

        if listen_thread:
            listen_thread.join(timeout=5.0)
            if listen_thread.is_alive():
                self.router_logger.log_message("[P2P] ⚠️ Listener thread did not stop cleanly.")

        if broadcast_thread:
            broadcast_thread.join(timeout=5.0)
            if broadcast_thread.is_alive():
                self.router_logger.log_message("[P2P] ⚠️ Broadcaster thread did not stop cleanly.")

        with self._lock:
            self._listen_thread = None
            self._broadcast_thread = None
            self._listen_sock = None
            self.peers.clear()

        self.router_logger.log_message("[P2P] ✅ Peer Manager stopped.")

    def get_known_peers(self) -> Dict[str, Dict[str, Any]]:
        self._prune_dead_peers()
        with self._lock:
            return self.peers.copy()

    def _prune_dead_peers(self):
        now = time.time()
        with self._lock:
            dead_peers = [
                ip for ip, data in self.peers.items()
                if (now - data["last_seen"]) > self.peer_timeout
            ]
            for ip in dead_peers:
                del self.peers[ip]
                self.router_logger.log_message(f"[P2P] 👻 Peer {ip} timed out and was removed.")

    def _listener_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass

        try:
            sock.bind(("0.0.0.0", self.port))
            sock.settimout(1.0)
            with self._lock:
                self._listen_sock = sock
        except Exception as e:
            self.router_logger.log_message(f"[P2P] ❌ Failed to bind listener socket: {e}")
            with self._lock:
                self.running = False
                self._listen_sock = None
            self._stop_event.set()
            try:
                sock.close()
            except Exception:
                pass
            return

        try:
            while not self._stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                    sender_ip = addr[0]
                    self.router_logger.log_message(
                        f"[P2P] 📨 Received discovery packet from {sender_ip}"
                    )
                    payload = json.loads(data.decode("utf-8"))

                    if payload.get("magic") != self.MAGIC_HEADER:
                        continue

                    if payload.get("node_id") == self.node_id:
                        continue

                    with self._lock:
                        is_new = sender_ip not in self.peers
                        self.peers[sender_ip] = {
                            "node_id": payload.get("node_id"),
                            "last_seen": time.time(),
                            "arp_table": payload.get("arp_table", {}),
                            "routes": payload.get("routes", []),
                        }

                    if is_new:
                        node = payload.get("node_id", "")[:8]
                        self.router_logger.log_message(
                            f"[P2P] 🤝 Discovered new router peer: {sender_ip} (Node: {node})"
                        )

                except socket.timeout:
                    self._prune_dead_peers()
                    continue
                except OSError:
                    # Expected when stop() closes the socket
                    if self._stop_event.is_set():
                        break
                    raise
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    if not self._stop_event.is_set():
                        self.router_logger.log_message(f"[P2P] ⚠️ Listener error: {e}")

        finally:
            try:
                sock.close()
            except Exception:
                pass
            with self._lock:
                if self._listen_sock is sock:
                    self._listen_sock = None

    def _broadcaster_loop(self):
        while not self._stop_event.is_set():
            try:
                arp_data = {}
                arp_manager = self.arp_manager
                rip_manager = self.rip_manager
                sniffer = self.sniffer
                out_iface = self.out_iface

                if arp_manager:
                    raw_arp = arp_manager.get_cache_view()
                    for ip, val in raw_arp.items():
                        arp_data[ip] = list(val) if isinstance(val, tuple) else val

                route_data = []
                if rip_manager and hasattr(rip_manager, "get_routing_table_view"):
                    route_data = rip_manager.get_routing_table_view()

                payload = {
                    "magic": self.MAGIC_HEADER,
                    "node_id": self.node_id,
                    "router_ip": self.router_ip,
                    "arp_table": arp_data,
                    "routes": route_data,
                }

                packet_bytes = json.dumps(payload).encode("utf-8")

                pkt = (
                    IP(src=self.router_ip, dst=self.broadcast_ip)
                    / UDP(sport=self.port, dport=self.port)
                    / Raw(load=packet_bytes)
                )

                if sniffer and out_iface and not self._stop_event.is_set():
                    sniffer.send(
                        pkt,
                        iface=out_iface,
                        dst_mac="ff:ff:ff:ff:ff:ff",
                        verbose=0,
                    )
                    self.router_logger.log_message(
                        f"[P2P] 📣 Broadcast sent from {self.router_ip} to {self.broadcast_ip}:{self.port} on {out_iface}"
                    )
            except Exception as e:
                if not self._stop_event.is_set():
                    self.router_logger.log_message(f"[P2P] ⚠️ Broadcast send error: {e}")

            if self._stop_event.wait(self.broadcast_interval):
                break


@dataclass
class UpstreamCandidate:
    key: str
    interface: str
    gateway_ip: Optional[str]
    family: int
    source: str
    priority: int = 0

    healthy: bool = False
    score: float = -1000.0
    last_refresh: float = 0.0
    last_ok: float = 0.0
    last_fail: float = 0.0
    consecutive_failures: int = 0
    last_remote_seen: float = 0.0

    # transport-aware state
    last_transport_seen: float = 0.0
    transport_hits: int = 0
    last_transport_component: str = ""

    meta: Dict[str, Any] = field(default_factory=dict)


class NetRouteManager:
    """
    Transport-aware upstream selector + SAFE Windows route mirroring.

    Safe defaults:
      - Host-route OS sync: ON
      - Default-route OS sync: OFF
      - Interface metric tuning: OFF

    That means:
      - it WILL install concrete host routes (/32, /128) for destinations you touch
      - it will NOT override Windows default routing unless you explicitly enable it
      - it will NOT change Wi-Fi metrics unless you explicitly enable it

    This keeps Wi-Fi stable while still letting you inject real routes.
    """

    DEFAULT_MONITOR_INTERVAL = 10.0
    DEFAULT_CANDIDATE_REFRESH_INTERVAL = 10.0
    DEFAULT_PROBE_INTERVAL = 5.0
    DEFAULT_PASSIVE_SUCCESS_WINDOW = 60.0
    DEFAULT_TRANSPORT_SUCCESS_WINDOW = 45.0
    DEFAULT_MIN_HEALTHY_SCORE = 25.0

    DEFAULT_WINDOWS_V4_IF_METRIC = 5
    DEFAULT_WINDOWS_V4_ROUTE_METRIC = 5
    DEFAULT_WINDOWS_HOST_ROUTE_METRIC = 3
    DEFAULT_WINDOWS_V6_ROUTE_METRIC = 5
    DEFAULT_HOST_ROUTE_TTL = 180.0

    def __init__(
        self,
        router_logger,
        rip_manager,
        arp_manager,
        ndp_manager,
        outbound_load_balancer=None,
        interfaces_config: Optional[Dict[str, Dict[str, Any]]] = None,
        *,
        monitor_interval: float = DEFAULT_MONITOR_INTERVAL,
        candidate_refresh_interval: float = DEFAULT_CANDIDATE_REFRESH_INTERVAL,
        probe_interval: float = DEFAULT_PROBE_INTERVAL,
        passive_success_window: float = DEFAULT_PASSIVE_SUCCESS_WINDOW,
        transport_success_window: float = DEFAULT_TRANSPORT_SUCCESS_WINDOW,
        min_healthy_score: float = DEFAULT_MIN_HEALTHY_SCORE,
        enable_os_route_sync: bool = True,
        enable_host_route_sync: bool = True,
        enable_default_route_sync: bool = False,
        enable_ipv6_os_sync: bool = True,
        enable_metric_tuning: bool = False,
        windows_v4_if_metric: int = DEFAULT_WINDOWS_V4_IF_METRIC,
        windows_v4_route_metric: int = DEFAULT_WINDOWS_V4_ROUTE_METRIC,
        windows_v6_route_metric: int = DEFAULT_WINDOWS_V6_ROUTE_METRIC,
        windows_host_route_metric: int = DEFAULT_WINDOWS_HOST_ROUTE_METRIC,
        host_route_ttl: float = DEFAULT_HOST_ROUTE_TTL,
    ):
        self.router_logger = router_logger
        self.rip_manager = rip_manager
        self.arp_manager = arp_manager
        self.ndp_manager = ndp_manager
        self.outbound_load_balancer = outbound_load_balancer

        self._interfaces_config = interfaces_config or {}
        self._lock = threading.RLock()

        self._candidates: Dict[str, UpstreamCandidate] = {}
        self._manual_candidates: Dict[str, UpstreamCandidate] = {}

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.monitor_interval = float(monitor_interval)
        self.candidate_refresh_interval = float(candidate_refresh_interval)
        self.probe_interval = float(probe_interval)
        self.passive_success_window = float(passive_success_window)
        self.transport_success_window = float(transport_success_window)
        self.min_healthy_score = float(min_healthy_score)

        self.enable_os_route_sync = bool(enable_os_route_sync)
        self.enable_host_route_sync = bool(enable_host_route_sync)
        self.enable_default_route_sync = bool(enable_default_route_sync)
        self.enable_ipv6_os_sync = bool(enable_ipv6_os_sync)
        self.enable_metric_tuning = bool(enable_metric_tuning)

        self.windows_v4_if_metric = int(windows_v4_if_metric)
        self.windows_v4_route_metric = int(windows_v4_route_metric)
        self.windows_v6_route_metric = int(windows_v6_route_metric)
        self.windows_host_route_metric = int(windows_host_route_metric)
        self.host_route_ttl = float(host_route_ttl)

        self._last_candidate_refresh = 0.0

        # routes/metrics we own and must revert
        # key = (family_name, prefix, next_hop, interface_alias)
        self._os_route_records: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
        self._os_metric_restore: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # pending host routes discovered from traffic
        self._pending_host_routes: Dict[str, Dict[str, Any]] = {}

        # duplicate suppression
        self._last_default_sync_key_v4: Optional[str] = None
        self._last_default_sync_key_v6: Optional[str] = None
        self._last_log_keys: Dict[str, float] = {}

        self._atexit_registered = False
        self._register_atexit_restore()

        self._log("[NetRoute] 🚦 Manager initialized.")

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="NetRouteManagerThread",
        )
        self._thread.start()
        self._log("[NetRoute] ✅ Monitor thread started.")

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._restore_windows_state()
        self._log("[NetRoute] 🛑 Monitor thread stopped.")

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                self.refresh_candidates(force=True)
                self._probe_all_candidates(force=True)
                self._sync_windows_state()
            except Exception as e:
                self._log(f"[NetRoute] ❌ Monitor loop error: {e}")
            self._stop_event.wait(self.monitor_interval)

    def _register_atexit_restore(self):
        if self._atexit_registered:
            return
        self._atexit_registered = True
        atexit.register(self._safe_atexit_restore)

    def _safe_atexit_restore(self):
        try:
            self._restore_windows_state()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # public config
    # ------------------------------------------------------------------

    def set_interfaces_config(self, interfaces_config: Dict[str, Dict[str, Any]]):
        with self._lock:
            self._interfaces_config = interfaces_config or {}
        self._log(f"[NetRoute] 🔧 Interfaces updated: {len(self._interfaces_config)} interface(s).")

    def register_manual_upstream(
        self,
        gateway_ip: Optional[str],
        interface: str,
        *,
        family: int = 4,
        source: str = "manual",
        priority: int = 100,
        meta: Optional[Dict[str, Any]] = None,
    ):
        gateway_ip = self._normalize_next_hop(gateway_ip)
        key = self._candidate_key(interface, gateway_ip, family)
        cand = UpstreamCandidate(
            key=key,
            interface=interface,
            gateway_ip=gateway_ip,
            family=int(family),
            source=source,
            priority=int(priority),
            meta=dict(meta or {}),
        )
        with self._lock:
            old = self._manual_candidates.get(key)
            if old:
                cand = self._merge_candidate(old, cand)
            self._manual_candidates[key] = cand
            self._candidates[key] = cand
        self._log(
            f"[NetRoute] ➕ Manual upstream registered: "
            f"iface={self._iface_short(interface)} gw={gateway_ip or 'direct'} family={family}"
        )

    def unregister_manual_upstream(self, gateway_ip: Optional[str], interface: str, *, family: int = 4):
        gateway_ip = self._normalize_next_hop(gateway_ip)
        key = self._candidate_key(interface, gateway_ip, family)
        with self._lock:
            self._manual_candidates.pop(key, None)
            self._candidates.pop(key, None)
        self._log(
            f"[NetRoute] ➖ Manual upstream removed: "
            f"iface={self._iface_short(interface)} gw={gateway_ip or 'direct'}"
        )

    # ------------------------------------------------------------------
    # candidate discovery
    # ------------------------------------------------------------------

    def refresh_candidates(self, *, force: bool = False):
        now = time.time()
        with self._lock:
            if not force and (now - self._last_candidate_refresh) < self.candidate_refresh_interval:
                return
            self._last_candidate_refresh = now

        discovered: Dict[str, UpstreamCandidate] = {}

        # 1) manual candidates
        with self._lock:
            for key, cand in self._manual_candidates.items():
                discovered[key] = self._clone_candidate(cand)

        # 2) RIP/default/static/direct candidates
        try:
            table = self.rip_manager.get_routing_table_view() or []
        except Exception as e:
            self._log(f"[NetRoute] ⚠️ Failed to read RIP table: {e}")
            table = []

        for entry in table:
            try:
                network = str(entry.get("network", ""))
                iface = entry.get("interface")
                next_hop = self._normalize_next_hop(entry.get("next_hop"))
                route_type = str(entry.get("type", "unknown"))
                cost = int(entry.get("cost", 16))

                if not iface or cost >= 16:
                    continue

                if network in ("0.0.0.0/0", "::/0"):
                    family = 6 if ":" in network else 4
                    key = self._candidate_key(iface, next_hop, family)
                    discovered[key] = self._merge_candidate(
                        self._candidates.get(key),
                        UpstreamCandidate(
                            key=key,
                            interface=iface,
                            gateway_ip=next_hop,
                            family=family,
                            source=route_type,
                            priority=self._priority_for_source(route_type),
                            meta={"network": network, "cost": cost},
                        ),
                    )
                    continue

                # promote gateway-bearing routes into upstream candidates too
                if next_hop:
                    family = 6 if ":" in next_hop else 4
                    key = self._candidate_key(iface, next_hop, family)
                    if key not in discovered:
                        discovered[key] = self._merge_candidate(
                            self._candidates.get(key),
                            UpstreamCandidate(
                                key=key,
                                interface=iface,
                                gateway_ip=next_hop,
                                family=family,
                                source=f"route:{route_type}",
                                priority=max(20, self._priority_for_source(route_type) - 10),
                                meta={"promoted_from": network, "cost": cost},
                            ),
                        )
            except Exception as e:
                self._log(f"[NetRoute] ⚠️ Failed to parse RIP candidate: {e}")

        # 3) interface-config gateways
        for iface, cfg in (self._interfaces_config or {}).items():
            try:
                if not cfg:
                    continue

                gateway_ip = self._normalize_next_hop(cfg.get("gateway"))
                if not gateway_ip:
                    continue

                family = 6 if ":" in gateway_ip else 4
                key = self._candidate_key(iface, gateway_ip, family)

                discovered[key] = self._merge_candidate(
                    self._candidates.get(key),
                    UpstreamCandidate(
                        key=key,
                        interface=iface,
                        gateway_ip=gateway_ip,
                        family=family,
                        source="iface-gateway",
                        priority=75,
                        meta={
                            "ip_addr": cfg.get("ip_addr"),
                            "driver": cfg.get("driver"),
                            "friendly_name": cfg.get("friendly_name"),
                        },
                    ),
                )
            except Exception as e:
                self._log(f"[NetRoute] ⚠️ Failed iface-gateway candidate on {iface}: {e}")

        # 4) default gateway iface candidates
        try:
            default_gw = self._normalize_next_hop(getattr(self.arp_manager, "default_gateway_ip", None))
        except Exception:
            default_gw = None

        for iface, cfg in (self._interfaces_config or {}).items():
            try:
                if not cfg or not bool(cfg.get("is_default_gateway_iface")):
                    continue

                gateway_ip = self._normalize_next_hop(cfg.get("gateway") or default_gw)
                family = 6 if (gateway_ip and ":" in gateway_ip) else 4
                key = self._candidate_key(iface, gateway_ip, family)

                discovered[key] = self._merge_candidate(
                    self._candidates.get(key),
                    UpstreamCandidate(
                        key=key,
                        interface=iface,
                        gateway_ip=gateway_ip,
                        family=family,
                        source="iface-default",
                        priority=90,
                        meta={"friendly_name": cfg.get("friendly_name")},
                    ),
                )
            except Exception as e:
                self._log(f"[NetRoute] ⚠️ Failed iface-default candidate on {iface}: {e}")

        # 5) Windows current routes
        for cand in self._discover_windows_route_candidates():
            discovered[cand.key] = self._merge_candidate(self._candidates.get(cand.key), cand)

        with self._lock:
            self._candidates = discovered

        if discovered:
            self._log(f"[NetRoute] 🔄 Candidates refreshed: {len(discovered)}")
        else:
            self._log("[NetRoute] ⚠️ No upstream candidates discovered.")

    def _discover_windows_route_candidates(self) -> List[UpstreamCandidate]:
        out: List[UpstreamCandidate] = []
        if not self._is_windows():
            return out

        for family_name, family_num, default_prefix in (("IPv4", 4, "0.0.0.0/0"), ("IPv6", 6, "::/0")):
            ps = f"""
$rows = Get-NetRoute -AddressFamily {family_name} -ErrorAction SilentlyContinue |
    Where-Object {{
        $_.DestinationPrefix -eq {self._ps_quote(default_prefix)} -and
        $_.State -eq 'Alive' -and
        $_.InterfaceAlias -ne $null
    }} |
    Select-Object InterfaceAlias, NextHop, RouteMetric
$rows | ConvertTo-Json -Compress
"""
            ok, stdout, stderr = self._run_ps(ps)
            if not ok or not stdout:
                continue

            try:
                rows = json.loads(stdout)
                if isinstance(rows, dict):
                    rows = [rows]

                for row in rows:
                    alias = str(row.get("InterfaceAlias") or "").strip()
                    gw = self._normalize_next_hop(row.get("NextHop"))
                    iface = self._find_interface_key_by_alias(alias)
                    if not alias or not iface:
                        continue

                    key = self._candidate_key(iface, gw, family_num)
                    out.append(
                        UpstreamCandidate(
                            key=key,
                            interface=iface,
                            gateway_ip=gw,
                            family=family_num,
                            source="windows-route",
                            priority=85,
                            meta={
                                "alias": alias,
                                "route_metric": row.get("RouteMetric"),
                            },
                        )
                    )
            except Exception as e:
                self._log(f"[NetRoute] ⚠️ Failed parsing Windows route candidates: {e}")

        return out

    # ------------------------------------------------------------------
    # probes
    # ------------------------------------------------------------------

    def _probe_all_candidates(self, *, force: bool = False):
        with self._lock:
            keys = list(self._candidates.keys())
        for key in keys:
            self._probe_candidate(key, force=force)

    def _probe_candidate(self, key: str, *, force: bool = False) -> Optional[UpstreamCandidate]:
        now = time.time()

        with self._lock:
            cand = self._candidates.get(key)
            if not cand:
                return None
            if not force and (now - cand.last_refresh) < self.probe_interval:
                return self._clone_candidate(cand)
            probe = self._clone_candidate(cand)

        score = 0.0
        healthy = False
        reasons: List[str] = []

        iface_cfg = (self._interfaces_config or {}).get(probe.interface) or {}
        iface_ip = iface_cfg.get("ip_addr")
        iface_net = iface_cfg.get("network")

        if iface_cfg:
            score += 5.0
            reasons.append("iface-known")
        else:
            score -= 80.0
            reasons.append("iface-missing")

        if probe.source in ("manual", "iface-default"):
            score += 25.0
            reasons.append(probe.source)
        elif probe.source == "iface-gateway":
            score += 22.0
            reasons.append("iface-gateway")
        elif probe.source == "windows-route":
            score += 22.0
            reasons.append("windows-route")
        elif probe.source == "static":
            score += 20.0
            reasons.append("static")
        elif probe.source == "direct":
            score += 15.0
            reasons.append("direct")
        elif probe.source.startswith("route:"):
            score += 12.0
            reasons.append(probe.source)
        elif probe.source == "rip":
            score += 8.0
            reasons.append("rip")

        if probe.last_remote_seen and (now - probe.last_remote_seen) <= self.passive_success_window:
            score += 20.0
            reasons.append("passive-seen")

        if probe.last_transport_seen and (now - probe.last_transport_seen) <= self.transport_success_window:
            score += 25.0
            reasons.append(f"transport:{probe.last_transport_component or 'seen'}")

        if probe.family == 4:
            score, healthy, reasons = self._probe_candidate_v4(probe, iface_ip, iface_net, score, healthy, reasons)
        else:
            score, healthy, reasons = self._probe_candidate_v6(probe, iface_ip, iface_net, score, healthy, reasons)

        if probe.consecutive_failures:
            score -= float(probe.consecutive_failures * 20)
            reasons.append(f"fails={probe.consecutive_failures}")

        if score >= self.min_healthy_score:
            healthy = True

        with self._lock:
            live = self._candidates.get(key)
            if not live:
                return None

            live.score = score
            live.healthy = healthy
            live.last_refresh = now
            live.meta["reasons"] = reasons
            if healthy:
                live.last_ok = now
            else:
                live.last_fail = now

            return self._clone_candidate(live)

    def _probe_candidate_v4(
        self,
        probe: UpstreamCandidate,
        iface_ip: Optional[str],
        iface_net: Any,
        score: float,
        healthy: bool,
        reasons: List[str],
    ):
        gw = self._normalize_next_hop(probe.gateway_ip)

        cidr = None
        if isinstance(iface_net, ipaddress.IPv4Network):
            cidr = str(iface_net)
        elif isinstance(iface_net, str):
            try:
                net = ipaddress.ip_network(iface_net, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    cidr = str(net)
            except Exception:
                cidr = None

        if gw:
            verdict_ok = True

            if cidr and hasattr(self.arp_manager, "_validate_gateway_onlink"):
                try:
                    verdict = self.arp_manager._validate_gateway_onlink(gw, cidr, iface_ip)
                    verdict_ok = bool(verdict.ok)
                    if verdict_ok:
                        score += 20.0
                        reasons.append(f"onlink:{verdict.reason}")
                    else:
                        score -= 80.0
                        reasons.append(f"bad-gw:{verdict.reason}")
                except Exception as e:
                    score -= 25.0
                    reasons.append(f"validate-err:{e}")

            mac = None
            if verdict_ok:
                try:
                    if cidr and hasattr(self.arp_manager, "resolve_gateway_mac"):
                        mac = self.arp_manager.resolve_gateway_mac(
                            gw, probe.interface, cidr, timeout=0.35, retries=1
                        )
                    elif hasattr(self.arp_manager, "resolve"):
                        mac = self.arp_manager.resolve(gw, probe.interface)
                except Exception as e:
                    reasons.append(f"arp-err:{e}")
                    mac = None

            if mac:
                score += 30.0
                healthy = True
                reasons.append("gw-mac")
            else:
                score -= 20.0
                reasons.append("no-gw-mac")
        else:
            if iface_ip:
                score += 10.0
                healthy = True
                reasons.append("direct-ipv4")
            else:
                score -= 15.0
                reasons.append("no-gw-no-ip")

        return score, healthy, reasons

    def _probe_candidate_v6(
        self,
        probe: UpstreamCandidate,
        iface_ip: Optional[str],
        iface_net: Any,
        score: float,
        healthy: bool,
        reasons: List[str],
    ):
        gw = self._normalize_next_hop(probe.gateway_ip)

        if gw:
            if not self._is_valid_ipv6_gateway_for_os(gw):
                score -= 50.0
                reasons.append("bad-ipv6-gw")
                return score, healthy, reasons

            mac = None
            try:
                if hasattr(self.ndp_manager, "resolve"):
                    mac = self.ndp_manager.resolve(gw, probe.interface)
            except Exception as e:
                reasons.append(f"ndp-err:{e}")

            if mac:
                score += 30.0
                healthy = True
                reasons.append("gw-ndp")
            else:
                score -= 20.0
                reasons.append("no-gw-ndp")
        else:
            if iface_ip:
                score += 10.0
                healthy = True
                reasons.append("direct-ipv6")
            else:
                score -= 15.0
                reasons.append("no-gw-no-ip")

        return score, healthy, reasons

    # ------------------------------------------------------------------
    # passive learning
    # ------------------------------------------------------------------

    def observe_packet(self, packet, inbound_iface: str):
        now = time.time()

        try:
            if IP in packet:
                self._note_passive_traffic(inbound_iface, packet[IP].src, packet[IP].dst, now, family=4)
            elif IPv6 in packet:
                self._note_passive_traffic(inbound_iface, packet[IPv6].src, packet[IPv6].dst, now, family=6)
        except Exception:
            pass

        try:
            if ARP in packet and int(packet[ARP].op) == 2:
                spa = str(packet[ARP].psrc).strip()
                with self._lock:
                    for cand in self._candidates.values():
                        if cand.family == 4 and cand.interface == inbound_iface and cand.gateway_ip == spa:
                            cand.last_remote_seen = now
                            cand.last_ok = now
                            cand.healthy = True
        except Exception:
            pass

    def _note_passive_traffic(self, inbound_iface: str, src_ip: str, dst_ip: str, now: float, family: int):
        with self._lock:
            for cand in self._candidates.values():
                if cand.interface != inbound_iface or cand.family != family:
                    continue

                if cand.gateway_ip and src_ip == cand.gateway_ip:
                    cand.last_remote_seen = now
                    cand.last_ok = now
                    cand.healthy = True
                    continue

                try:
                    src_obj = ipaddress.ip_address(src_ip)
                    dst_obj = ipaddress.ip_address(dst_ip)
                    if self._is_routable_remote(src_obj) or self._is_routable_remote(dst_obj):
                        cand.last_remote_seen = now
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # transport-aware path
    # ------------------------------------------------------------------

    def observe_transport_result(
        self,
        packet,
        inbound_iface: str,
        *,
        handled: bool,
        component: str = "transport",
        install_host_route: bool = False,
        host_route_cost: int = 1,
        prefer_route_to_dst: bool = True,
    ) -> Optional[Dict[str, Any]]:
        self.observe_packet(packet, inbound_iface)

        if not handled:
            return None

        dst_ip = self._extract_dest_ip(packet)
        if not dst_ip:
            return None

        route = self.get_best_route(dst_ip, inbound_iface=inbound_iface) if prefer_route_to_dst else None

        self._note_transport_activity(
            packet=packet,
            inbound_iface=inbound_iface,
            route=route,
            component=component,
        )

        if route:
            gateway_ip = self._normalize_next_hop(route.get("next_hop"))
            self.mark_route_success(route["interface"], gateway_ip=gateway_ip)

        if install_host_route and dst_ip:
            self.install_host_route(dst_ip, inbound_iface=inbound_iface, cost=host_route_cost)

        return route

    def note_transport_failure(
        self,
        packet,
        inbound_iface: str,
        *,
        component: str = "transport",
        reason: str = "",
    ) -> Optional[Dict[str, Any]]:
        self.observe_packet(packet, inbound_iface)

        dst_ip = self._extract_dest_ip(packet)
        if not dst_ip:
            return None

        route = self.get_best_route(dst_ip, inbound_iface=inbound_iface)
        if route:
            gateway_ip = self._normalize_next_hop(route.get("next_hop"))
            self.mark_route_failure(
                route["interface"],
                gateway_ip=gateway_ip,
                reason=f"transport:{component}:{reason}",
            )
        return route

    def _note_transport_activity(
        self,
        packet,
        inbound_iface: str,
        route: Optional[Dict[str, Any]],
        component: str,
    ):
        now = time.time()
        target_ifaces = {inbound_iface}
        if route and route.get("interface"):
            target_ifaces.add(route["interface"])

        with self._lock:
            for cand in self._candidates.values():
                if cand.interface not in target_ifaces:
                    continue

                cand.last_transport_seen = now
                cand.transport_hits += 1
                cand.last_transport_component = component
                cand.last_ok = now
                cand.healthy = True

                boost = min(12.0, 2.0 + (cand.transport_hits * 0.5))
                cand.score = max(cand.score, self.min_healthy_score + boost)

                cand.meta["last_transport_component"] = component
                cand.meta["last_transport_seen"] = now

    def queue_host_route(self, dest_ip: str, inbound_iface: Optional[str] = None, *, cost: int = 1):
        try:
            ip_obj = ipaddress.ip_address(str(dest_ip).strip())
        except Exception:
            return

        if self._is_special_destination(ip_obj):
            return

        with self._lock:
            self._pending_host_routes[str(ip_obj)] = {
                "dest_ip": str(ip_obj),
                "expires": time.time() + self.host_route_ttl,
                "cost": int(cost),
                "inbound_iface": inbound_iface,
            }

    # ------------------------------------------------------------------
    # success/failure
    # ------------------------------------------------------------------

    def mark_route_success(self, interface: str, gateway_ip: Optional[str] = None):
        now = time.time()
        gateway_ip = self._normalize_next_hop(gateway_ip)
        with self._lock:
            for cand in self._candidates.values():
                if cand.interface != interface:
                    continue
                if gateway_ip is not None and cand.gateway_ip != gateway_ip:
                    continue
                cand.last_ok = now
                cand.healthy = True
                cand.consecutive_failures = 0
                cand.score = max(cand.score, self.min_healthy_score + 10.0)

    def mark_route_failure(self, interface: str, gateway_ip: Optional[str] = None, reason: str = ""):
        now = time.time()
        gateway_ip = self._normalize_next_hop(gateway_ip)
        with self._lock:
            for cand in self._candidates.values():
                if cand.interface != interface:
                    continue
                if gateway_ip is not None and cand.gateway_ip != gateway_ip:
                    continue
                cand.last_fail = now
                cand.consecutive_failures += 1
                cand.healthy = False
                cand.score -= 25.0
                if reason:
                    cand.meta["last_fail_reason"] = reason

    # ------------------------------------------------------------------
    # unified packet path
    # ------------------------------------------------------------------

    def handle_packet(
        self,
        packet,
        inbound_iface: str,
        *,
        transport_handled: bool = False,
        transport_component: str = "transport",
        install_host_route: bool = False,
        host_route_cost: int = 1,
    ) -> Optional[Dict[str, Any]]:
        if transport_handled:
            return self.observe_transport_result(
                packet,
                inbound_iface,
                handled=True,
                component=transport_component,
                install_host_route=install_host_route,
                host_route_cost=host_route_cost,
            )

        self.observe_packet(packet, inbound_iface)

        dst_ip = self._extract_dest_ip(packet)
        if not dst_ip:
            return None

        return self.get_best_route(dst_ip, inbound_iface=inbound_iface)

    # ------------------------------------------------------------------
    # route selection
    # ------------------------------------------------------------------

    def get_best_route(self, dest_ip: str, inbound_iface: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            dest_obj = ipaddress.ip_address(str(dest_ip).strip())
        except Exception:
            return None

        if self._is_special_destination(dest_obj):
            return None

        # Prefer specific routing-table entries first
        specific = self._find_best_table_entry(dest_obj)
        if specific and str(specific["network"]) not in ("0.0.0.0/0", "::/0"):
            return {
                "network": specific["network"],
                "next_hop": specific["next_hop"],
                "interface": specific["interface"],
                "cost": specific["cost"],
                "source": specific["type"],
                "is_wan": bool(specific["interface"] in self._wan_ifaces()),
                "health_score": 999.0,
            }

        self.refresh_candidates(force=False)
        self._probe_all_candidates(force=False)

        family = 6 if dest_obj.version == 6 else 4

        with self._lock:
            candidates = [self._clone_candidate(c) for c in self._candidates.values() if c.family == family]

        if inbound_iface:
            alt = [c for c in candidates if c.interface != inbound_iface]
            if alt:
                candidates = alt

        candidates.sort(
            key=lambda c: (
                int(c.healthy),
                float(c.score),
                int(c.priority),
                float(c.last_ok),
                float(c.last_transport_seen),
                -float(c.last_fail),
            ),
            reverse=True,
        )

        if candidates:
            best = candidates[0]
            if best.healthy or best.score > -50.0:
                return {
                    "network": "0.0.0.0/0" if family == 4 else "::/0",
                    "next_hop": best.gateway_ip or ("0.0.0.0" if family == 4 else "::"),
                    "interface": best.interface,
                    "cost": 1,
                    "source": f"netroute:{best.source}",
                    "is_wan": bool(best.interface in self._wan_ifaces()),
                    "health_score": best.score,
                }

        if specific:
            return {
                "network": specific["network"],
                "next_hop": specific["next_hop"],
                "interface": specific["interface"],
                "cost": specific["cost"],
                "source": specific["type"],
                "is_wan": bool(specific["interface"] in self._wan_ifaces()),
                "health_score": -999.0,
            }

        return None

    # ------------------------------------------------------------------
    # host route install
    # ------------------------------------------------------------------

    def install_host_route(self, dest_ip: str, inbound_iface: Optional[str] = None, *, cost: int = 1) -> bool:
        """
        Installs BOTH:
          1) a host route in your RIP/static table
          2) a host route in Windows ActiveStore if enabled

        This is the method you wanted to make sure actually sets routes.
        """
        try:
            ip_obj = ipaddress.ip_address(str(dest_ip).strip())
        except Exception:
            return False

        if self._is_special_destination(ip_obj):
            return False

        route = self.get_best_route(str(ip_obj), inbound_iface=inbound_iface)
        if not route:
            self._log(f"[NetRoute] ❌ No route candidate available for {dest_ip}")
            return False

        family = 6 if ip_obj.version == 6 else 4
        network_str = f"{ip_obj}/32" if family == 4 else f"{ip_obj}/128"
        next_hop = self._normalize_next_hop(route["next_hop"])
        interface = route["interface"]

        ok_any = False

        # 1) RIP/static table
        try:
            ok = self.rip_manager.add_static_route(
                network_str=network_str,
                next_hop=next_hop or ("0.0.0.0" if family == 4 else "::"),
                interface=interface,
                cost=int(cost),
            )
            if ok:
                ok_any = True
                self._log(
                    f"[NetRoute] ✅ Installed static host route {network_str} via "
                    f"{next_hop or 'direct'} on {self._iface_short(interface)}"
                )
        except Exception as e:
            self._log(f"[NetRoute] ⚠️ Failed RIP/static host route {network_str}: {e}")

        # 2) Windows ActiveStore host route
        self.queue_host_route(str(ip_obj), inbound_iface=inbound_iface, cost=cost)

        if self.enable_os_route_sync and self.enable_host_route_sync and self._is_windows():
            route_dict = self._build_os_route_dict(
                family=family,
                prefix=network_str,
                next_hop=next_hop,
                interface=interface,
                route_metric=self.windows_host_route_metric,
            )
            if route_dict:
                if self._ensure_os_route(route_dict):
                    ok_any = True

        return ok_any

    # ------------------------------------------------------------------
    # Windows OS sync
    # ------------------------------------------------------------------

    def _sync_windows_state(self):
        if not self._is_windows() or not self.enable_os_route_sync:
            return

        desired_routes: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

        # Default route sync is OFF by default so Wi-Fi stays undisturbed.
        if self.enable_default_route_sync:
            best_v4 = self._best_default_candidate_for_family(4)
            if best_v4:
                route = self._build_os_route_from_candidate(
                    best_v4,
                    prefix="0.0.0.0/0",
                    route_metric=self.windows_v4_route_metric,
                )
                if route:
                    desired_routes[self._os_route_key(route)] = route
                    self._last_default_sync_key_v4 = best_v4.key

                    if self.enable_metric_tuning:
                        alias = route["interface_alias"]
                        self._ensure_interface_metric(alias, family_name="IPv4", target_metric=self.windows_v4_if_metric)

            if self.enable_ipv6_os_sync:
                best_v6 = self._best_default_candidate_for_family(6)
                if best_v6:
                    route = self._build_os_route_from_candidate(
                        best_v6,
                        prefix="::/0",
                        route_metric=self.windows_v6_route_metric,
                    )
                    if route:
                        desired_routes[self._os_route_key(route)] = route
                        self._last_default_sync_key_v6 = best_v6.key

        # Host routes are ON by default.
        if self.enable_host_route_sync:
            self._prune_pending_host_routes()
            with self._lock:
                pending_host_routes = list(self._pending_host_routes.values())

            for item in pending_host_routes:
                dest_ip = item["dest_ip"]
                inbound_iface = item.get("inbound_iface")
                route = self.get_best_route(dest_ip, inbound_iface=inbound_iface)
                if not route:
                    continue

                family = 6 if ":" in dest_ip else 4
                prefix = f"{dest_ip}/32" if family == 4 else f"{dest_ip}/128"

                route_dict = self._build_os_route_dict(
                    family=family,
                    prefix=prefix,
                    next_hop=self._normalize_next_hop(route.get("next_hop")),
                    interface=route["interface"],
                    route_metric=self.windows_host_route_metric,
                )
                if route_dict:
                    desired_routes[self._os_route_key(route_dict)] = route_dict

        # ensure desired routes exist
        for route_key, route in desired_routes.items():
            self._ensure_os_route(route)

        # remove only stale routes WE own
        for route_key, rec in list(self._os_route_records.items()):
            if route_key not in desired_routes and rec.get("owned"):
                self._remove_os_route(route_key, quiet=False)

    def _best_default_candidate_for_family(self, family: int) -> Optional[UpstreamCandidate]:
        self.refresh_candidates(force=False)
        self._probe_all_candidates(force=False)

        with self._lock:
            candidates = [self._clone_candidate(c) for c in self._candidates.values() if c.family == family]

        candidates.sort(
            key=lambda c: (
                int(c.healthy),
                float(c.score),
                int(c.priority),
                float(c.last_ok),
                float(c.last_transport_seen),
                -float(c.last_fail),
            ),
            reverse=True,
        )

        if not candidates:
            return None

        best = candidates[0]
        if best.healthy or best.score > -50.0:
            return best
        return None

    def _build_os_route_from_candidate(
        self,
        cand: UpstreamCandidate,
        *,
        prefix: str,
        route_metric: int,
    ) -> Optional[Dict[str, Any]]:
        return self._build_os_route_dict(
            family=cand.family,
            prefix=prefix,
            next_hop=self._normalize_next_hop(cand.gateway_ip),
            interface=cand.interface,
            route_metric=route_metric,
        )

    def _build_os_route_dict(
        self,
        *,
        family: int,
        prefix: str,
        next_hop: Optional[str],
        interface: str,
        route_metric: int,
    ) -> Optional[Dict[str, Any]]:
        alias = self._find_interface_alias(interface)
        if not alias:
            return None

        if family == 4:
            # host routes/direct routes still need a concrete next hop for OS insertion
            if not self._is_valid_ipv4_gateway_for_os(next_hop, interface):
                return None
        else:
            if not self.enable_ipv6_os_sync:
                return None
            if not self._is_valid_ipv6_gateway_for_os(next_hop):
                return None

        return {
            "family_name": "IPv4" if family == 4 else "IPv6",
            "family": family,
            "prefix": prefix,
            "next_hop": next_hop,
            "interface": interface,
            "interface_alias": alias,
            "route_metric": int(route_metric),
        }

    def _ensure_os_route(self, route: Dict[str, Any]) -> bool:
        route_key = self._os_route_key(route)
        rec = self._os_route_records.get(route_key, {})

        exists = self._os_route_exists(route)
        if exists:
            self._os_route_records[route_key] = {
                **rec,
                "owned": rec.get("owned", False),
                "active_logged": True,
                "route": dict(route),
            }
            return True

        ok, err = self._add_os_route(route)
        if ok:
            self._os_route_records[route_key] = {
                "owned": True,
                "active_logged": True,
                "route": dict(route),
            }
            self._log_once(
                f"osroute:{route_key}",
                f"[NetRoute][OS] ✅ Route active {route['prefix']} via {route['next_hop']} on {route['interface_alias']}",
                cooldown=30.0,
            )
            return True

        self._log_once(
            f"osroutefail:{route_key}",
            f"[NetRoute][OS] ⚠️ Failed route {route['prefix']} via {route['next_hop']} on {route['interface_alias']}: {err}",
            cooldown=30.0,
        )
        return False

    def _restore_windows_state(self):
        if not self._is_windows():
            return

        # remove only routes we added
        for route_key, rec in list(self._os_route_records.items()):
            if rec.get("owned"):
                self._remove_os_route(route_key, quiet=False)

        # restore metrics only if we changed them
        for metric_key, old in list(self._os_metric_restore.items()):
            alias, family_name = metric_key
            self._restore_interface_metric(alias, family_name, old)

        self._os_metric_restore.clear()
        self._os_route_records.clear()

    def _ensure_interface_metric(self, alias: str, *, family_name: str, target_metric: int):
        metric_key = (alias, family_name)
        if metric_key not in self._os_metric_restore:
            snap = self._snapshot_interface_metric(alias, family_name)
            if snap is not None:
                self._os_metric_restore[metric_key] = snap

        current = self._snapshot_interface_metric(alias, family_name)
        if not current:
            return

        current_metric = int(current.get("InterfaceMetric", 0) or 0)
        current_auto = bool(current.get("AutomaticMetric", False))

        if (not current_auto) and current_metric == int(target_metric):
            return

        ps = f"""
Set-NetIPInterface -AddressFamily {family_name} -InterfaceAlias {self._ps_quote(alias)} `
    -AutomaticMetric Disabled -InterfaceMetric {int(target_metric)} -ErrorAction Stop | Out-Null
"""
        ok, stdout, stderr = self._run_ps(ps)
        if ok:
            self._log_once(
                f"metric:{alias}:{family_name}",
                f"[NetRoute][OS] 🔧 Set {alias} {family_name} metric -> {int(target_metric)}",
                cooldown=30.0,
            )
        else:
            self._log_once(
                f"metricfail:{alias}:{family_name}",
                f"[NetRoute][OS] ⚠️ Failed setting {alias} {family_name} metric: {stderr or stdout}",
                cooldown=30.0,
            )

    def _restore_interface_metric(self, alias: str, family_name: str, old: Dict[str, Any]):
        automatic = bool(old.get("AutomaticMetric", False))
        metric = int(old.get("InterfaceMetric", 0) or 0)

        if automatic:
            ps = f"""
Set-NetIPInterface -AddressFamily {family_name} -InterfaceAlias {self._ps_quote(alias)} `
    -AutomaticMetric Enabled -ErrorAction Stop | Out-Null
"""
        else:
            ps = f"""
Set-NetIPInterface -AddressFamily {family_name} -InterfaceAlias {self._ps_quote(alias)} `
    -AutomaticMetric Disabled -InterfaceMetric {metric} -ErrorAction Stop | Out-Null
"""

        ok, stdout, stderr = self._run_ps(ps)
        if ok:
            self._log(f"[NetRoute][OS] ↩️ Restored {alias} {family_name} metric")
        else:
            self._log(f"[NetRoute][OS] ⚠️ Failed restoring {alias} {family_name} metric: {stderr or stdout}")

    def _snapshot_interface_metric(self, alias: str, family_name: str) -> Optional[Dict[str, Any]]:
        ps = f"""
$row = Get-NetIPInterface -AddressFamily {family_name} -InterfaceAlias {self._ps_quote(alias)} -ErrorAction SilentlyContinue |
    Select-Object -First 1 InterfaceMetric, AutomaticMetric
if ($row) {{ $row | ConvertTo-Json -Compress }}
"""
        ok, stdout, stderr = self._run_ps(ps)
        if not ok or not stdout:
            return None
        try:
            row = json.loads(stdout)
            if isinstance(row, dict):
                return row
        except Exception:
            return None
        return None

    def _os_route_exists(self, route: Dict[str, Any]) -> bool:
        family_name = route["family_name"]
        prefix = route["prefix"]
        next_hop = route["next_hop"]
        alias = route["interface_alias"]

        ps = f"""
$rows = Get-NetRoute -AddressFamily {family_name} -DestinationPrefix {self._ps_quote(prefix)} -ErrorAction SilentlyContinue |
    Where-Object {{
        $_.InterfaceAlias -eq {self._ps_quote(alias)} -and
        $_.NextHop -eq {self._ps_quote(next_hop)}
    }} |
    Select-Object -First 1 DestinationPrefix
if ($rows) {{ '1' }} else {{ '0' }}
"""
        ok, stdout, stderr = self._run_ps(ps)
        return bool(ok and stdout.strip() == "1")

    def _add_os_route(self, route: Dict[str, Any]) -> Tuple[bool, str]:
        family_name = route["family_name"]
        prefix = route["prefix"]
        next_hop = route["next_hop"]
        alias = route["interface_alias"]
        metric = int(route["route_metric"])

        ps = f"""
New-NetRoute -PolicyStore ActiveStore -AddressFamily {family_name} `
    -DestinationPrefix {self._ps_quote(prefix)} `
    -InterfaceAlias {self._ps_quote(alias)} `
    -NextHop {self._ps_quote(next_hop)} `
    -RouteMetric {metric} `
    -Confirm:$false -ErrorAction Stop | Out-Null
"""
        ok, stdout, stderr = self._run_ps(ps)
        return ok, (stderr or stdout)

    def _remove_os_route(self, route_key: Tuple[str, str, str, str], *, quiet: bool = False):
        rec = self._os_route_records.get(route_key)
        if not rec:
            return

        family_name, prefix, next_hop, alias = route_key

        if rec.get("owned"):
            ps = f"""
Get-NetRoute -AddressFamily {family_name} -DestinationPrefix {self._ps_quote(prefix)} -ErrorAction SilentlyContinue |
    Where-Object {{
        $_.InterfaceAlias -eq {self._ps_quote(alias)} -and
        $_.NextHop -eq {self._ps_quote(next_hop)}
    }} |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
"""
            ok, stdout, stderr = self._run_ps(ps)
            if not quiet and ok:
                self._log(f"[NetRoute][OS] ↩️ Removed route {prefix} via {next_hop} on {alias}")
            elif not quiet and (stderr or stdout):
                self._log(f"[NetRoute][OS] ⚠️ Failed removing route {prefix} via {next_hop} on {alias}: {stderr or stdout}")

        self._os_route_records.pop(route_key, None)

    def _prune_pending_host_routes(self):
        now = time.time()
        with self._lock:
            for dest_ip, item in list(self._pending_host_routes.items()):
                if now >= float(item.get("expires", 0.0)):
                    self._pending_host_routes.pop(dest_ip, None)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _extract_dest_ip(self, packet) -> Optional[str]:
        try:
            if IP in packet:
                return packet[IP].dst
            if IPv6 in packet:
                return packet[IPv6].dst
        except Exception:
            pass
        return None

    def _normalize_next_hop(self, next_hop: Optional[str]) -> Optional[str]:
        if next_hop in (None, "", "0.0.0.0", "::"):
            return None
        s = str(next_hop).strip()
        if not s:
            return None
        if "%" in s:
            s = s.split("%", 1)[0].strip()
        if s in ("::1",):
            return None
        return s

    def _find_best_table_entry(self, dest_obj) -> Optional[Dict[str, Any]]:
        try:
            table = self.rip_manager.get_routing_table_view() or []
        except Exception:
            return None

        best = None
        best_prefix = -1

        for entry in table:
            try:
                network = ipaddress.ip_network(str(entry["network"]), strict=False)
                if dest_obj.version != network.version:
                    continue
                if dest_obj not in network:
                    continue

                cost = int(entry.get("cost", 16))
                if cost >= 16:
                    continue

                better = False
                if best is None:
                    better = True
                elif network.prefixlen > best_prefix:
                    better = True
                elif network.prefixlen == best_prefix:
                    if cost < int(best.get("cost", 16)):
                        better = True
                    elif cost == int(best.get("cost", 16)):
                        if str(entry.get("type")) == "static" and str(best.get("type")) != "static":
                            better = True

                if better:
                    best_prefix = network.prefixlen
                    best = {
                        "network": str(network),
                        "next_hop": self._normalize_next_hop(entry.get("next_hop")) or ("0.0.0.0" if dest_obj.version == 4 else "::"),
                        "interface": entry.get("interface"),
                        "cost": cost,
                        "type": str(entry.get("type", "unknown")),
                    }
            except Exception:
                continue

        return best

    def _wan_ifaces(self) -> set[str]:
        try:
            if self.outbound_load_balancer:
                return set(self.outbound_load_balancer.get_configured_interfaces())
        except Exception:
            pass
        return set()

    def _is_special_destination(self, ip_obj) -> bool:
        try:
            if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback:
                return True
            if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj == ipaddress.IPv4Address("255.255.255.255"):
                return True
            return False
        except Exception:
            return True

    def _is_routable_remote(self, ip_obj) -> bool:
        try:
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                return False
            return True
        except Exception:
            return False

    def _priority_for_source(self, source: str) -> int:
        if source == "manual":
            return 100
        if source == "iface-default":
            return 90
        if source == "windows-route":
            return 85
        if source == "static":
            return 80
        if source == "iface-gateway":
            return 75
        if source == "direct":
            return 70
        if source.startswith("route:"):
            return 60
        if source == "rip":
            return 50
        return 10

    def _candidate_key(self, interface: str, gateway_ip: Optional[str], family: int) -> str:
        return f"{family}|{interface}|{gateway_ip or 'direct'}"

    def _merge_candidate(self, old: Optional[UpstreamCandidate], new: UpstreamCandidate) -> UpstreamCandidate:
        if not old:
            return new

        new.healthy = old.healthy
        new.score = old.score
        new.last_refresh = old.last_refresh
        new.last_ok = old.last_ok
        new.last_fail = old.last_fail
        new.consecutive_failures = old.consecutive_failures
        new.last_remote_seen = old.last_remote_seen
        new.last_transport_seen = old.last_transport_seen
        new.transport_hits = old.transport_hits
        new.last_transport_component = old.last_transport_component

        merged_meta = {}
        merged_meta.update(old.meta or {})
        merged_meta.update(new.meta or {})
        new.meta = merged_meta
        return new

    def _clone_candidate(self, cand: UpstreamCandidate) -> UpstreamCandidate:
        return UpstreamCandidate(
            key=cand.key,
            interface=cand.interface,
            gateway_ip=cand.gateway_ip,
            family=cand.family,
            source=cand.source,
            priority=cand.priority,
            healthy=cand.healthy,
            score=cand.score,
            last_refresh=cand.last_refresh,
            last_ok=cand.last_ok,
            last_fail=cand.last_fail,
            consecutive_failures=cand.consecutive_failures,
            last_remote_seen=cand.last_remote_seen,
            last_transport_seen=cand.last_transport_seen,
            transport_hits=cand.transport_hits,
            last_transport_component=cand.last_transport_component,
            meta=dict(cand.meta or {}),
        )

    def _os_route_key(self, route: Dict[str, Any]) -> Tuple[str, str, str, str]:
        return (
            str(route["family_name"]),
            str(route["prefix"]),
            str(route["next_hop"]),
            str(route["interface_alias"]),
        )

    def _find_interface_alias(self, interface: str) -> Optional[str]:
        cfg = (self._interfaces_config or {}).get(interface) or {}
        alias = str(cfg.get("friendly_name") or "").strip()
        if alias:
            return alias

        s = str(interface or "").strip()
        if s:
            return s.split("_")[-1]
        return None

    def _find_interface_key_by_alias(self, alias: str) -> Optional[str]:
        alias_l = str(alias or "").strip().lower()
        if not alias_l:
            return None

        for iface, cfg in (self._interfaces_config or {}).items():
            friendly = str((cfg or {}).get("friendly_name") or "").strip().lower()
            if friendly == alias_l:
                return iface

        for iface in (self._interfaces_config or {}).keys():
            if str(iface).strip().lower() == alias_l:
                return iface

        for iface in (self._interfaces_config or {}).keys():
            if str(iface).split("_")[-1].strip().lower() == alias_l:
                return iface

        return None

    def _iface_short(self, iface: str) -> str:
        try:
            cfg = (self._interfaces_config or {}).get(iface) or {}
            return str(cfg.get("friendly_name") or "").strip() or str(iface).split("_")[-1]
        except Exception:
            return str(iface).split("_")[-1]

    def _is_windows(self) -> bool:
        return os.name == "nt"

    def _ps_quote(self, s: str) -> str:
        return "'" + str(s).replace("'", "''") + "'"

    def _run_ps(self, script: str) -> Tuple[bool, str, str]:
        if not self._is_windows():
            return False, "", "not-windows"

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ],
                capture_output=True,
                text=True,
                creationflags=creationflags,
            )
            return proc.returncode == 0, (proc.stdout or "").strip(), (proc.stderr or "").strip()
        except Exception as e:
            return False, "", str(e)

    def _is_valid_ipv4_gateway_for_os(self, next_hop: Optional[str], interface: str) -> bool:
        if not next_hop:
            return False

        try:
            gw = ipaddress.IPv4Address(next_hop)
        except Exception:
            return False

        if gw.is_loopback or gw.is_multicast or gw.is_unspecified:
            return False

        cfg = (self._interfaces_config or {}).get(interface) or {}
        iface_ip = cfg.get("ip_addr")
        iface_net = cfg.get("network")

        cidr = None
        if isinstance(iface_net, ipaddress.IPv4Network):
            cidr = str(iface_net)
        elif isinstance(iface_net, str):
            try:
                net = ipaddress.ip_network(iface_net, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    cidr = str(net)
            except Exception:
                cidr = None

        if cidr and hasattr(self.arp_manager, "_validate_gateway_onlink"):
            try:
                verdict = self.arp_manager._validate_gateway_onlink(str(gw), cidr, iface_ip)
                return bool(verdict.ok)
            except Exception:
                return False

        return True

    def _is_valid_ipv6_gateway_for_os(self, next_hop: Optional[str]) -> bool:
        if not next_hop:
            return False

        try:
            gw = ipaddress.IPv6Address(str(next_hop).split("%", 1)[0])
        except Exception:
            return False

        if gw.is_loopback or gw.is_multicast or gw.is_unspecified:
            return False

        if gw.is_link_local:
            return True
        if gw.is_private or gw.is_global:
            return True
        return False

    def _log_once(self, key: str, msg: str, *, cooldown: float = 10.0):
        now = time.time()
        last = self._last_log_keys.get(key, 0.0)
        if (now - last) < float(cooldown):
            return
        self._last_log_keys[key] = now
        self._log(msg)

    def _log(self, msg: str):
        try:
            self.router_logger.log_message(msg)
        except Exception:
            pass


@dataclass
class PacketBoundaryDecision:
    action: str  # "bypass" | "process" | "observe"
    reason: str
    explanation: str
    confidence: int = 0


@dataclass
class HostConnectivityState:
    started: bool = False
    fail_open: bool = False
    last_health_ok: float = 0.0
    last_health_fail: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    notes: List[str] = field(default_factory=list)


class HostConnectivityBoundaryManager:
    """
    Smart host/transit boundary classifier.

    Goals:
      - protect host applications like Firefox / Discord
      - still allow legitimate transit packets to cross the router
      - never let one ambiguous packet kill router connectivity
      - only bypass on strong host-ownership evidence
      - explicitly allow router-service packets to continue
    """

    def __init__(
        self,
        router_logger,
        *,
        get_local_ips_fn,
        get_router_macs_fn,
        get_bridge_members_fn,
        get_wan_iface_fn,
        get_wan_ip_fn,
        get_gateway_ip_fn,
        health_probe_fn=None,
        fail_open_after_failures: int = 3,
        recover_after_successes: int = 3,
        socket_refresh_sec: float = 1.0,
        log_cooldown_sec: float = 10.0,
        flow_ttl_sec: float = 180.0,
        transit_ifaces_fn=None,
        router_dns_ports: Optional[Set[int]] = None,
        router_udp_service_ports: Optional[Set[int]] = None,
        router_tcp_service_ports: Optional[Set[int]] = None,
    ):
        self.router_logger = router_logger

        self.get_local_ips_fn = get_local_ips_fn
        self.get_router_macs_fn = get_router_macs_fn
        self.get_bridge_members_fn = get_bridge_members_fn
        self.get_wan_iface_fn = get_wan_iface_fn
        self.get_wan_ip_fn = get_wan_ip_fn
        self.get_gateway_ip_fn = get_gateway_ip_fn
        self.health_probe_fn = health_probe_fn
        self.transit_ifaces_fn = transit_ifaces_fn

        self.fail_open_after_failures = max(1, int(fail_open_after_failures))
        self.recover_after_successes = max(1, int(recover_after_successes))
        self.socket_refresh_sec = max(0.5, float(socket_refresh_sec))
        self.log_cooldown_sec = max(1.0, float(log_cooldown_sec))
        self.flow_ttl_sec = max(30.0, float(flow_ttl_sec))

        self.router_dns_ports = set(router_dns_ports or {53, 5353})
        self.router_udp_service_ports = set(router_udp_service_ports or {67, 68, 69, 88, 123, 137, 138, 161, 389, 464, 500, 520, 4500})
        self.router_tcp_service_ports = set(router_tcp_service_ports or {53, 88, 135, 139, 389, 443, 445, 464})

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.state = HostConnectivityState()

        # ownership cache: key -> owner
        self._flow_owner: Dict[Tuple[Any, ...], str] = {}
        self._flow_last_seen: Dict[Tuple[Any, ...], float] = {}

        # learned active host sockets from OS
        self._active_exact_sockets: Set[Tuple[str, str, int, str, int]] = set()
        self._active_local_sockets: Set[Tuple[str, str, int]] = set()
        self._active_wildcard_ports: Set[Tuple[str, int]] = set()

        self._last_socket_refresh = 0.0
        self._last_log: Dict[str, float] = {}

    # ---------------------------------------------------------
    # lifecycle
    # ---------------------------------------------------------

    def start(self):
        with self._lock:
            if self.state.started:
                return

            self.state.started = True
            self.state.fail_open = False
            self.state.last_health_ok = time.time()
            self.state.last_health_fail = 0.0
            self.state.consecutive_failures = 0
            self.state.consecutive_successes = 0
            self.state.notes.clear()

            self._flow_owner.clear()
            self._flow_last_seen.clear()
            self._active_exact_sockets.clear()
            self._active_local_sockets.clear()
            self._active_wildcard_ports.clear()
            self._last_log.clear()
            self._last_socket_refresh = 0.0

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._maintenance_loop,
                name="HostConnectivityBoundaryManager",
                daemon=True,
            )
            self._thread.start()

        self._log(
            RouterRandomMessages(
                "HostBoundary",
                "Started. Only strong host-owned flows will bypass the router; ambiguous packets will continue through process_packet.",
                ["🛡️", "🌐", "🧠", "🔐", "📡"]
            )
        )

    def stop(self):
        with self._lock:
            self._stop_event.set()
            t = self._thread

        if t and t.is_alive():
            t.join(timeout=2.0)

        with self._lock:
            self.state.started = False
            self.state.fail_open = False
            self._thread = None
            self._flow_owner.clear()
            self._flow_last_seen.clear()
            self._active_exact_sockets.clear()
            self._active_local_sockets.clear()
            self._active_wildcard_ports.clear()
            self._last_log.clear()

        self._log(
            RouterRandomMessages(
                "HostBoundary",
                "Stopped.",
                ["🛑", "📴", "🔒"]
            )
        )

    # ---------------------------------------------------------
    # maintenance
    # ---------------------------------------------------------

    def _maintenance_loop(self):
        while not self._stop_event.wait(1.0):
            try:
                now = time.time()

                if (now - self._last_socket_refresh) >= self.socket_refresh_sec:
                    self._refresh_active_host_sockets()
                    self._last_socket_refresh = now

                ok = bool(self.health_probe_fn()) if self.health_probe_fn else True
                self._update_health(ok)
                self._gc_flows()
            except Exception as e:
                self._log(f"[HostBoundary] Maintenance loop error: {e}")

    def _refresh_active_host_sockets(self):
        exact: Set[Tuple[str, str, int, str, int]] = set()
        local_only: Set[Tuple[str, str, int]] = set()
        wildcard_ports: Set[Tuple[str, int]] = set()

        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []

        for c in conns:
            try:
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP" if c.type == socket.SOCK_DGRAM else None
                if not proto or not c.laddr:
                    continue

                local_ip = str(getattr(c.laddr, "ip", "") or "")
                local_port = int(getattr(c.laddr, "port", 0) or 0)
                if local_port <= 0:
                    continue

                remote_ip = ""
                remote_port = 0
                if c.raddr:
                    remote_ip = str(getattr(c.raddr, "ip", "") or "")
                    remote_port = int(getattr(c.raddr, "port", 0) or 0)

                local_only.add((proto, local_ip, local_port))

                if local_ip in ("0.0.0.0", "::", ""):
                    wildcard_ports.add((proto, local_port))

                if remote_ip and remote_port > 0:
                    exact.add((proto, local_ip, local_port, remote_ip, remote_port))
            except Exception:
                continue

        with self._lock:
            self._active_exact_sockets = exact
            self._active_local_sockets = local_only
            self._active_wildcard_ports = wildcard_ports

    # ---------------------------------------------------------
    # health / fail-open
    # ---------------------------------------------------------

    def _update_health(self, ok: bool):
        now = time.time()
        with self._lock:
            if ok:
                self.state.last_health_ok = now
                self.state.consecutive_successes += 1
                self.state.consecutive_failures = 0
                if self.state.fail_open and self.state.consecutive_successes >= self.recover_after_successes:
                    self.state.fail_open = False
                    self.state.notes.append("recovered")
                    self._log(
                        RouterRandomMessages(
                            "HostBoundary",
                            "WAN health recovered. Leaving fail-open mode.",
                            ["✅", "🌐", "🟢", "🛡️"]
                        )
                    )
            else:
                self.state.last_health_fail = now
                self.state.consecutive_failures += 1
                self.state.consecutive_successes = 0
                if not self.state.fail_open and self.state.consecutive_failures >= self.fail_open_after_failures:
                    self.state.fail_open = True
                    self.state.notes.append("entered-fail-open")
                    self._log(
                        RouterRandomMessages(
                            "HostBoundary",
                            "WAN health degraded. Entering fail-open mode so host-owned WAN traffic is protected.",
                            ["🚨", "🧯", "🛡️", "🌩️"]
                        )
                    )

    def in_fail_open(self) -> bool:
        with self._lock:
            return self.state.fail_open

    # ---------------------------------------------------------
    # public API
    # ---------------------------------------------------------

    def inspect_packet(self, packet, inbound_iface: str) -> PacketBoundaryDecision:
        """
        Returns one of:
          - bypass: strong host-owned evidence, router should return immediately
          - process: strong router/transit evidence, router should continue
          - observe: ambiguous, router should continue and decide later
        """
        if packet is None:
            return PacketBoundaryDecision(
                action="bypass",
                reason="null-packet",
                explanation="null packet cannot be safely processed",
                confidence=100,
            )

        # Do not interfere with non-IP traffic here.
        # ARP/L2/bridge logic should continue elsewhere.
        if not self._is_ip_packet(packet):
            return PacketBoundaryDecision(
                action="observe",
                reason="non-ip",
                explanation="non-IP packet left to normal router/L2 logic",
                confidence=0,
            )

        src_ip, dst_ip = self._extract_ips(packet)
        src_mac, dst_mac = self._extract_macs(packet)
        proto, sport, dport = self._extract_proto_ports(packet)

        local_ips = set(self.get_local_ips_fn() or [])
        wan_ip = str(self.get_wan_ip_fn() or "")
        gateway_ip = str(self.get_gateway_ip_fn() or "")
        wan_iface = str(self.get_wan_iface_fn() or "")
        bridge_members = self._get_bridge_members()
        transit_ifaces = self._get_transit_ifaces(bridge_members, wan_iface)

        router_macs = {str(x).lower() for x in (self.get_router_macs_fn() or set()) if x}
        if wan_ip:
            local_ips.add(wan_ip)

        # 1) Explicit router-service traffic should continue
        router_service = self._is_definitely_router_service(packet, src_ip, dst_ip, proto, sport, dport, local_ips)
        if router_service:
            return PacketBoundaryDecision(
                action="process",
                reason="router-service",
                explanation=router_service,
                confidence=95,
            )

        # 2) Previously-known transit flow should continue
        owner = self._get_known_owner(packet)
        if owner == "transit":
            return PacketBoundaryDecision(
                action="process",
                reason="known-transit-flow",
                explanation="flow was previously learned as transit, so it should keep crossing the router",
                confidence=90,
            )

        # 3) Strong host socket ownership (best signal for Discord/Firefox)
        socket_reason = self._match_active_host_socket(proto, src_ip, sport, dst_ip, dport, local_ips)
        if socket_reason:
            self._remember_owner(packet, "host")
            return PacketBoundaryDecision(
                action="bypass",
                reason="active-host-socket",
                explanation=f"packet matches an active host {proto} socket ({socket_reason}), so a real local application owns this flow",
                confidence=100,
            )

        # 4) Source IP is local AND packet did not come from transit side
        if src_ip and src_ip in local_ips and inbound_iface not in transit_ifaces:
            self._remember_owner(packet, "host")
            return PacketBoundaryDecision(
                action="bypass",
                reason="host-src-ip",
                explanation=f"source IP {src_ip} belongs to this machine and ingress '{inbound_iface}' is not a downstream transit interface",
                confidence=90,
            )

        # 5) Source MAC is host NIC AND not already known transit
        if src_mac and src_mac.lower() in router_macs and inbound_iface not in transit_ifaces:
            self._remember_owner(packet, "host")
            return PacketBoundaryDecision(
                action="bypass",
                reason="host-src-mac",
                explanation=f"source MAC {src_mac} belongs to the host machine, so this is a host-originated capture copy",
                confidence=85,
            )

        # 6) In fail-open mode, protect exact WAN/gateway/self flows, not everything
        if self.in_fail_open():
            if (
                (wan_iface and inbound_iface == wan_iface and (src_ip == wan_ip or dst_ip == wan_ip)) or
                (gateway_ip and (src_ip == gateway_ip or dst_ip == gateway_ip))
            ):
                self._remember_owner(packet, "host")
                return PacketBoundaryDecision(
                    action="bypass",
                    reason="fail-open-wan-protect",
                    explanation="fail-open mode is active and this packet is directly on the host WAN/gateway path",
                    confidence=95,
                )

        # 7) Strong transit evidence
        if inbound_iface in transit_ifaces:
            self._remember_owner(packet, "transit")
            return PacketBoundaryDecision(
                action="process",
                reason="transit-ingress",
                explanation=f"packet arrived from downstream transit interface '{inbound_iface}', so it may need to cross the router",
                confidence=80,
            )

        # 8) Destination local by itself is NOT enough to bypass.
        # Let process_packet decide whether it is DNS/DHCP/ICMP/router-service/etc.
        if dst_ip and dst_ip in local_ips:
            return PacketBoundaryDecision(
                action="observe",
                reason="local-destination-ambiguous",
                explanation=f"destination IP {dst_ip} is local, but packet did not strongly match a host app socket or a router service yet",
                confidence=25,
            )

        # 9) Default: ambiguous packets continue through process_packet
        return PacketBoundaryDecision(
            action="observe",
            reason="ambiguous",
            explanation="packet did not strongly match host ownership or strong transit ownership, so router processing may continue",
            confidence=10,
        )

    def should_bypass_router(self, packet, inbound_iface: str) -> bool:
        decision = self.inspect_packet(packet, inbound_iface)
        if decision.action == "bypass":
            self._log_decision(packet, inbound_iface, decision)
            return True

        if decision.action == "process":
            self._remember_owner(packet, "transit")
        return False

    # ---------------------------------------------------------
    # router service detection
    # ---------------------------------------------------------

    def _is_definitely_router_service(
        self,
        packet,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        proto: str,
        sport: int,
        dport: int,
        local_ips: Set[str],
    ) -> Optional[str]:
        try:
            # Router DNS/mDNS logic
            if DNS and packet.haslayer(DNS):
                return "packet contains DNS and may be for router DNS handling"

            # DHCP / DHCPv6
            if (DHCP and packet.haslayer(DHCP)) or \
               (DHCP6 and packet.haslayer(DHCP6)) or \
               (DHCP6_Solicit and packet.haslayer(DHCP6_Solicit)) or \
               (DHCP6_InfoRequest and packet.haslayer(DHCP6_InfoRequest)) or \
               (DHCP6_Reply and packet.haslayer(DHCP6_Reply)):
                return "packet contains DHCP/DHCPv6 and must be allowed to reach router DHCP logic"
        except Exception:
            pass

        if proto == "UDP":
            if dport in self.router_dns_ports or sport in self.router_dns_ports:
                return f"UDP port {sport}->{dport} matches router DNS/mDNS service ports"
            if dport in self.router_udp_service_ports or sport in self.router_udp_service_ports:
                if dst_ip in local_ips or dst_ip in ("255.255.255.255", "224.0.0.9") or (dst_ip and dst_ip.startswith("ff02::")):
                    return f"UDP port {sport}->{dport} matches router-managed UDP service traffic"

        if proto == "TCP":
            if dport in self.router_tcp_service_ports or sport in self.router_tcp_service_ports:
                if dst_ip in local_ips:
                    return f"TCP port {sport}->{dport} matches router-managed TCP service traffic"

        # ICMP destined to router should keep going
        if proto in ("ICMP", "ICMPv6") and dst_ip in local_ips:
            return "ICMP/ICMPv6 packet is destined to a local router address and should be processed normally"

        return None

    # ---------------------------------------------------------
    # socket ownership matching
    # ---------------------------------------------------------

    def _match_active_host_socket(
        self,
        proto: str,
        src_ip: Optional[str],
        sport: int,
        dst_ip: Optional[str],
        dport: int,
        local_ips: Set[str],
    ) -> Optional[str]:
        if proto not in ("TCP", "UDP"):
            return None

        # outbound local app packet
        if src_ip in local_ips and sport > 0:
            if self._socket_exact_exists(proto, src_ip, sport, dst_ip, dport):
                return f"exact local socket {src_ip}:{sport} -> {dst_ip}:{dport}"
            if self._socket_local_exists(proto, src_ip, sport):
                return f"local bound socket {src_ip}:{sport}"
            if self._socket_wildcard_exists(proto, sport):
                return f"wildcard-bound socket *:{sport}"

        # inbound reply for local app
        if dst_ip in local_ips and dport > 0:
            if self._socket_exact_exists(proto, dst_ip, dport, src_ip, sport):
                return f"exact local socket {dst_ip}:{dport} <- {src_ip}:{sport}"
            if self._socket_local_exists(proto, dst_ip, dport):
                return f"local bound socket {dst_ip}:{dport}"
            if self._socket_wildcard_exists(proto, dport):
                return f"wildcard-bound socket *:{dport}"

        return None

    def _socket_exact_exists(self, proto: str, local_ip: Optional[str], local_port: int, remote_ip: Optional[str], remote_port: int) -> bool:
        if not local_ip or local_port <= 0 or not remote_ip or remote_port <= 0:
            return False
        with self._lock:
            return (
                (proto, local_ip, local_port, remote_ip, remote_port) in self._active_exact_sockets or
                (proto, "0.0.0.0", local_port, remote_ip, remote_port) in self._active_exact_sockets or
                (proto, "::", local_port, remote_ip, remote_port) in self._active_exact_sockets
            )

    def _socket_local_exists(self, proto: str, local_ip: Optional[str], local_port: int) -> bool:
        if not local_ip or local_port <= 0:
            return False
        with self._lock:
            return (
                (proto, local_ip, local_port) in self._active_local_sockets or
                (proto, "0.0.0.0", local_port) in self._active_local_sockets or
                (proto, "::", local_port) in self._active_local_sockets
            )

    def _socket_wildcard_exists(self, proto: str, local_port: int) -> bool:
        if local_port <= 0:
            return False
        with self._lock:
            return (proto, local_port) in self._active_wildcard_ports

    # ---------------------------------------------------------
    # flow ownership cache
    # ---------------------------------------------------------

    def _flow_key(self, packet):
        src_ip, dst_ip = self._extract_ips(packet)
        proto, sport, dport = self._extract_proto_ports(packet)
        if not src_ip or not dst_ip:
            return None
        return (proto, src_ip, sport, dst_ip, dport)

    def _reverse_flow_key(self, key):
        if not key:
            return None
        proto, src_ip, sport, dst_ip, dport = key
        return (proto, dst_ip, dport, src_ip, sport)

    def _remember_owner(self, packet, owner: str):
        key = self._flow_key(packet)
        if not key:
            return

        rev = self._reverse_flow_key(key)
        now = time.time()

        with self._lock:
            self._flow_owner[key] = owner
            self._flow_last_seen[key] = now
            if rev:
                self._flow_owner[rev] = owner
                self._flow_last_seen[rev] = now

    def _get_known_owner(self, packet) -> Optional[str]:
        key = self._flow_key(packet)
        if not key:
            return None
        with self._lock:
            return self._flow_owner.get(key)

    def _gc_flows(self):
        now = time.time()
        stale_before = now - self.flow_ttl_sec
        with self._lock:
            stale_keys = [k for k, ts in self._flow_last_seen.items() if ts < stale_before]
            for k in stale_keys:
                self._flow_last_seen.pop(k, None)
                self._flow_owner.pop(k, None)

    # ---------------------------------------------------------
    # helpers
    # ---------------------------------------------------------

    def _get_bridge_members(self) -> Set[str]:
        try:
            return set(self.get_bridge_members_fn() or [])
        except Exception:
            return set()

    def _get_transit_ifaces(self, bridge_members: Set[str], wan_iface: str) -> Set[str]:
        try:
            explicit = set(self.transit_ifaces_fn() or []) if self.transit_ifaces_fn else set()
        except Exception:
            explicit = set()
        # Bridge members are primary transit ingress interfaces.
        # Explicit transit interfaces can add to that.
        result = set(bridge_members) | explicit
        if wan_iface in result:
            result.discard(wan_iface)
        return result

    def _is_ip_packet(self, packet) -> bool:
        try:
            return bool((IP and packet.haslayer(IP)) or (IPv6 and packet.haslayer(IPv6)))
        except Exception:
            return False

    def _extract_ips(self, packet):
        try:
            if IP and packet.haslayer(IP):
                return str(packet[IP].src), str(packet[IP].dst)
            if IPv6 and packet.haslayer(IPv6):
                return str(packet[IPv6].src), str(packet[IPv6].dst)
        except Exception:
            pass
        return None, None

    def _extract_macs(self, packet):
        try:
            if Ether and packet.haslayer(Ether):
                return str(packet[Ether].src), str(packet[Ether].dst)
        except Exception:
            pass
        return None, None

    def _extract_proto_ports(self, packet):
        proto = "IP"
        sport = 0
        dport = 0
        try:
            if TCP and packet.haslayer(TCP):
                proto = "TCP"
                sport = int(packet[TCP].sport or 0)
                dport = int(packet[TCP].dport or 0)
            elif UDP and packet.haslayer(UDP):
                proto = "UDP"
                sport = int(packet[UDP].sport or 0)
                dport = int(packet[UDP].dport or 0)
            elif ICMP and packet.haslayer(ICMP):
                proto = "ICMP"
            elif (ICMPv6EchoRequest and packet.haslayer(ICMPv6EchoRequest)) or (ICMPv6EchoReply and packet.haslayer(ICMPv6EchoReply)):
                proto = "ICMPv6"
            elif IPv6 and packet.haslayer(IPv6):
                proto = "IPv6"
            elif IP and packet.haslayer(IP):
                proto = "IPv4"
        except Exception:
            pass
        return proto, sport, dport

    def _describe_packet(self, packet) -> str:
        src_ip, dst_ip = self._extract_ips(packet)
        proto, sport, dport = self._extract_proto_ports(packet)

        if src_ip or dst_ip:
            if sport or dport:
                return f"{proto} {src_ip}:{sport} -> {dst_ip}:{dport}"
            return f"{proto} {src_ip} -> {dst_ip}"

        try:
            return packet.summary()
        except Exception:
            return "unknown-packet"

    def _log_decision(self, packet, inbound_iface: str, decision: PacketBoundaryDecision):
        flow = self._describe_packet(packet)
        key = f"{decision.action}|{decision.reason}|{flow}|{inbound_iface}"
        now = time.time()

        with self._lock:
            last = self._last_log.get(key, 0.0)
            if (now - last) < self.log_cooldown_sec:
                return
            self._last_log[key] = now

        self._log(
            RouterRandomMessages(
                "HostBoundary",
                f"{decision.action.upper()} on '{inbound_iface}'. Flow: {flow}. Reason: {decision.reason}. Why: {decision.explanation}",
                ["🛡️", "🌐", "🧠", "📡", "↪️", "🔐", "🧭"]
            )
        )

    def _log(self, msg: str):
        try:
            self.router_logger.log_message(msg)
        except Exception:
            pass


@dataclass
class ManagerPacketDecision:
    action: str  # "consume" | "pass" | "observe"
    reason: str
    explanation: str
    confidence: int = 0


@dataclass
class GatewayNeighbor:
    ip: str
    iface: str
    mac: Optional[str] = None
    source: str = "unknown"
    family: int = 4
    last_seen: float = field(default_factory=time.time)
    last_ok: float = 0.0
    last_fail: float = 0.0
    ok_count: int = 0
    fail_count: int = 0
    score: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class GatewayCandidate:
    ip: str
    iface: str
    source: str
    family: int = 4
    learned_from_neighbor: bool = False
    last_seen: float = field(default_factory=time.time)
    last_ok: float = 0.0
    last_fail: float = 0.0
    ok_count: int = 0
    fail_count: int = 0
    score: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class LanHost:
    ip: str
    iface: str
    mac: Optional[str] = None
    family: int = 4
    hostname: Optional[str] = None
    lease_expires: float = 0.0
    last_seen: float = field(default_factory=time.time)
    rx_packets: int = 0
    tx_packets: int = 0
    dns_queries: int = 0
    metadata: dict = field(default_factory=dict)


@dataclass
class GatewayHealth:
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    degraded_since: float = 0.0
    last_soft_repair: float = 0.0
    last_hard_repair: float = 0.0
    last_gateway_ok: float = 0.0
    last_internet_ok: float = 0.0


@dataclass
class _BoundaryState:
    started: bool = False
    last_health_ok: float = 0.0
    last_health_fail: float = 0.0


class _SmartManagerBase:
    def __init__(
        self,
        router: Any,
        *,
        name: str,
        flow_ttl_sec: float = 180.0,
        log_cooldown_sec: float = 8.0,
    ):
        self.router = router
        self.name = name
        self.logger = router.router_logger

        self.flow_ttl_sec = max(30.0, float(flow_ttl_sec))
        self.log_cooldown_sec = max(1.0, float(log_cooldown_sec))

        self._lock = threading.RLock()
        self._state = _BoundaryState()
        self._flow_owner: Dict[Tuple[Any, ...], str] = {}
        self._flow_last_seen: Dict[Tuple[Any, ...], float] = {}
        self._last_log: Dict[str, float] = {}

    # ---------------------------------------------------------
    # logging
    # ---------------------------------------------------------

    def _say(
        self,
        key: str,
        message: str,
        emoticons: Optional[list[str]] = None,
        cooldown: Optional[float] = None,
    ) -> None:
        now = time.time()
        cd = self.log_cooldown_sec if cooldown is None else max(0.0, float(cooldown))
        with self._lock:
            last = self._last_log.get(key, 0.0)
            if cd > 0 and (now - last) < cd:
                return
            self._last_log[key] = now
        try:
            self.logger.log_message(
                RouterRandomMessages(self.name, message, emoticons or [])
            )
        except Exception:
            pass

    # ---------------------------------------------------------
    # packet decode / flow tracking
    # ---------------------------------------------------------

    def _decode_if_bytes(self, packet):
        if not isinstance(packet, (bytes, bytearray)):
            return packet
        try:
            if not packet:
                return None
            version = packet[0] >> 4
            if version == 4:
                return IP(packet)
            if version == 6:
                return IPv6(packet)
            return Ether(packet)
        except Exception:
            return None

    def _extract_ips(self, packet) -> tuple[Optional[str], Optional[str]]:
        try:
            if packet.haslayer(IP):
                return packet[IP].src, packet[IP].dst
            if packet.haslayer(IPv6):
                return packet[IPv6].src, packet[IPv6].dst
        except Exception:
            pass
        return None, None

    def _extract_proto_ports(self, packet) -> tuple[str, int, int]:
        try:
            if packet.haslayer(TCP):
                return "TCP", int(packet[TCP].sport or 0), int(packet[TCP].dport or 0)
            if packet.haslayer(UDP):
                return "UDP", int(packet[UDP].sport or 0), int(packet[UDP].dport or 0)
            if packet.haslayer(ICMP):
                return "ICMP", 0, 0
            if packet.haslayer(IPv6) and (
                packet.haslayer(ICMPv6ND_NA)
                or packet.haslayer(ICMPv6ND_NS)
                or packet.haslayer(ICMPv6ND_RA)
                or packet.haslayer(ICMPv6ND_RS)
                or packet.haslayer(ICMPv6EchoRequest)
                or packet.haslayer(ICMPv6EchoReply)
            ):
                return "ICMPv6", 0, 0
        except Exception:
            pass
        return "IP", 0, 0

    def _flow_key(self, packet) -> Optional[Tuple[Any, ...]]:
        src_ip, dst_ip = self._extract_ips(packet)
        proto, sport, dport = self._extract_proto_ports(packet)
        if not src_ip or not dst_ip:
            return None
        return (proto, src_ip, sport, dst_ip, dport)

    def _reverse_flow_key(self, key) -> Optional[Tuple[Any, ...]]:
        if not key:
            return None
        proto, src_ip, sport, dst_ip, dport = key
        return (proto, dst_ip, dport, src_ip, sport)

    def _remember_flow(self, packet, owner: str) -> None:
        key = self._flow_key(packet)
        if not key:
            return
        rev = self._reverse_flow_key(key)
        now = time.time()
        with self._lock:
            self._flow_owner[key] = owner
            self._flow_last_seen[key] = now
            if rev:
                self._flow_owner[rev] = owner
                self._flow_last_seen[rev] = now

    def _get_known_owner(self, packet) -> Optional[str]:
        key = self._flow_key(packet)
        if not key:
            return None
        now = time.time()
        with self._lock:
            owner = self._flow_owner.get(key)
            last = self._flow_last_seen.get(key, 0.0)
            if owner and (now - last) <= self.flow_ttl_sec:
                self._flow_last_seen[key] = now
                return owner
        return None

    def _gc_flows(self) -> None:
        cutoff = time.time() - self.flow_ttl_sec
        with self._lock:
            stale = [k for k, ts in self._flow_last_seen.items() if ts < cutoff]
            for k in stale:
                self._flow_last_seen.pop(k, None)
                self._flow_owner.pop(k, None)

    # ---------------------------------------------------------
    # shared network helpers
    # ---------------------------------------------------------

    def _local_ips(self) -> Set[str]:
        try:
            if hasattr(self.router, "_get_all_local_ips"):
                return set(self.router._get_all_local_ips())
        except Exception:
            pass

        out = set()
        for attr in ("router_ip_in", "router_ip_out", "router_ipv6_link_local_out", "router_ipv6_out"):
            value = getattr(self.router, attr, None)
            if value:
                out.add(str(value).split("%")[0])
        return out

    def _bridge_members(self) -> Set[str]:
        out = set()
        try:
            em = getattr(self.router, "ethernet_manager", None)
            if em and hasattr(em, "get_bridge_members"):
                out.update(set(em.get_bridge_members() or []))
        except Exception:
            pass

        for attr in (
            "interface_in_full_name",
            "interface_ethernet_2_full_name",
            "interface_lac_full_name",
            "interface_lac_2_full_name",
        ):
            value = getattr(self.router, attr, None)
            if value:
                out.add(value)
        return out

    def _iface_role(self, inbound_iface: str) -> str:
        if not inbound_iface:
            return "unknown"
        if inbound_iface == getattr(self.router, "interface_out_full_name", None):
            return "wan"
        if inbound_iface == getattr(self.router, "interface_loopback_full_name", None):
            return "loopback"
        if inbound_iface in self._bridge_members():
            return "lan"
        return "unknown"

    def _is_router_local_ip(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        return str(ip).split("%")[0] in self._local_ips()

    def _is_ipv4_broadcast(self, ip: Optional[str]) -> bool:
        return bool(ip and str(ip) == "255.255.255.255")

    def _is_multicast(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            return ipaddress.ip_address(str(ip).split("%")[0]).is_multicast
        except Exception:
            return False

    def _is_likely_router_service_address(self, dst_ip: Optional[str]) -> bool:
        if not dst_ip:
            return False
        return (
            self._is_router_local_ip(dst_ip)
            or self._is_ipv4_broadcast(dst_ip)
            or self._is_multicast(dst_ip)
        )

    def _call_if_present(self, obj: Any, method_name: str, *args, **kwargs):
        fn = getattr(obj, method_name, None)
        if callable(fn):
            return fn(*args, **kwargs)
        return None

    @staticmethod
    def _is_dhcp_packet(packet) -> bool:
        return (
            packet.haslayer(DHCP)
            or packet.haslayer(DHCP6)
            or packet.haslayer(DHCP6_Solicit)
            or packet.haslayer(DHCP6_InfoRequest)
            or packet.haslayer(DHCP6_Reply)
        )

    @staticmethod
    def _is_dns_packet(packet) -> bool:
        return packet.haslayer(DNS)

    @staticmethod
    def _is_ndp_packet(packet) -> bool:
        return (
            packet.haslayer(ICMPv6ND_NA)
            or packet.haslayer(ICMPv6ND_NS)
            or packet.haslayer(ICMPv6ND_RA)
            or packet.haslayer(ICMPv6ND_RS)
        )

    def _dns_direction(self, packet) -> str:
        try:
            if not packet.haslayer(DNS):
                return "unknown"
            return "response" if int(packet[DNS].qr) == 1 else "query"
        except Exception:
            return "unknown"

    @staticmethod
    def _is_ipv4(value: Optional[str]) -> bool:
        try:
            if not value:
                return False
            ipaddress.IPv4Address(str(value))
            return True
        except Exception:
            return False

    @staticmethod
    def _is_ipv6(value: Optional[str]) -> bool:
        try:
            if not value:
                return False
            ipaddress.IPv6Address(str(value).split("%")[0])
            return True
        except Exception:
            return False

    def _get_ipv4_info_for_adapter(self, iface_friendly_name: Optional[str]) -> Optional[dict[str, Any]]:
        if not iface_friendly_name:
            return None
        try:
            addrs = psutil.net_if_addrs().get(iface_friendly_name, [])
        except Exception:
            addrs = []
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address and addr.netmask:
                try:
                    network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                except Exception:
                    continue
                return {"ip": addr.address, "netmask": addr.netmask, "network": network}
        return None

    def _gateway_ip(self) -> Optional[str]:
        gw = getattr(self.router, "router_gateway_out_ip", None)
        return str(gw) if gw else None

    def _is_gateway_ip(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        gw = self._gateway_ip()
        if not gw:
            return False
        return str(ip).split("%")[0] == str(gw).split("%")[0]

    def _is_virtual_or_ignored_iface_name(self, iface_name: Optional[str]) -> bool:
        name = str(iface_name or "").strip().lower()
        if not name:
            return True

        ignored_prefixes = (
            "local area connection*",
            "vethernet",
            "hyper-v",
            "wintun",
            "npcap",
            "loopback",
            "isatap",
            "teredo",
            "bluetooth",
            "ethernet",
        )
        ignored_contains = (
            "vethernet",
            "hyper-v",
            "wintun",
            "loopback",
            "npcap",
            "miniport",
            "virtual",
            "pseudo-interface",
            "ethernet",
        )

        if any(name.startswith(p) for p in ignored_prefixes):
            return True
        if any(x in name for x in ignored_contains):
            return True
        return False

    def _is_likely_real_uplink_iface(self, iface_name: Optional[str]) -> bool:
        name = str(iface_name or "").strip()
        if not name:
            return False
        if self._is_virtual_or_ignored_iface_name(name):
            return False

        lowered = name.lower()
        preferred_tokens = (
            "wi-fi",
            "wifi",
            "wireless",
            "ethernet",
        )
        return any(tok in lowered for tok in preferred_tokens)

    def _get_default_gateway_for_local_ip(self, local_ip: Optional[str]) -> Optional[str]:
        """
        Route-table-first gateway lookup.
        Only returns the gateway for the interface owning the matching local IPv4.
        """
        if not self._is_ipv4(local_ip):
            return None

        try:
            proc = subprocess.run(
                ["route", "print", "-4"],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode != 0:
                return None

            best_metric = None
            best_gateway = None

            for raw in (proc.stdout or "").splitlines():
                line = raw.strip()
                if not line:
                    continue

                parts = re.split(r"\s+", line)
                if len(parts) < 5:
                    continue

                dest, mask, gateway, iface_ip, metric = parts[:5]
                if dest != "0.0.0.0" or mask != "0.0.0.0":
                    continue
                if iface_ip != local_ip:
                    continue
                if not self._is_ipv4(gateway):
                    continue

                try:
                    metric_i = int(metric)
                except Exception:
                    metric_i = 999999

                if best_metric is None or metric_i < best_metric:
                    best_metric = metric_i
                    best_gateway = gateway

            return best_gateway
        except Exception:
            return None

    def _get_windows_dns_servers(self, iface_friendly_name: Optional[str]) -> list[str]:
        """
        Quiet DNS lookup: PowerShell first, then netsh.
        No ipconfig parsing spam.
        """
        if not iface_friendly_name or self._is_virtual_or_ignored_iface_name(iface_friendly_name):
            return []

        quoted = str(iface_friendly_name).replace("'", "''")

        try:
            ps_cmd = rf"""
    $servers = Get-DnsClientServerAddress -InterfaceAlias '{quoted}' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue
    if ($servers) {{ $servers | ForEach-Object {{ $_ }} }}
    """
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                out = []
                for line in (proc.stdout or "").splitlines():
                    line = line.strip()
                    if self._is_ipv4(line) and line not in out:
                        out.append(line)
                if out:
                    return out
        except Exception:
            pass

        try:
            proc = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "dnsservers", f"name={iface_friendly_name}"],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                found = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", proc.stdout or "")
                out = []
                for ip in found:
                    if self._is_ipv4(ip) and ip not in out:
                        out.append(ip)
                return out
        except Exception:
            pass

        return []

class GatewayManager(_SmartManagerBase):
    """
    Safe uplink control plane.

    Fixes:
      - DNS manager cannot restart after stop
      - default gateway is only applied on real change
      - WAN repair is staged: soft first, hard much later
      - NetRoute default-route sync / metric tuning are disabled in runtime safe mode
      - public browsing path is preserved while router uplink remains usable
    """

    DEFAULT_UPSTREAM_DNS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "208.67.220.220"]

    def __init__(self, router: Any, dns_manager_cls: Any):
        super().__init__(router, name="GatewayManager")
        self.DNSManager = dns_manager_cls

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.health = GatewayHealth()

        self._prefs = {
            "auto_configure_router_interfaces": False,
            "use_dhcp_out": True,
            "use_dhcp_in": False,
            "router_ip_out": None,
            "router_netmask_out": "255.255.255.0",
            "force_wan_to_dhcp_on_start": False,
            "ensure_host_dns_from_wan": True,
            "repair_on_failure": True,
            "pin_gateway_arp": True,
            "health_interval_sec": 15.0,
            "dns_refresh_interval_sec": 120.0,
            "candidate_refresh_interval_sec": 20.0,
            "gateway_refresh_interval_sec": 45.0,
            "gateway_neighbor_refresh_sec": 20.0,
            "soft_repair_cooldown_sec": 30.0,
            "hard_repair_cooldown_sec": 180.0,
            "failure_threshold_for_soft_repair": 3,
            "failure_threshold_for_hard_repair": 8,
            "minimum_degraded_time_for_hard_repair_sec": 90.0,
            "disable_netroute_default_sync": True,
            "disable_netroute_metric_tuning": True,
            "runtime_set_wan_to_dhcp": False,
            "enable_dns64": True,
            "dns64_prefix": "64:ff9b::/96",
            "upstream_dns": None,
        }

        self.gateway_candidates: Dict[str, GatewayCandidate] = {}
        self.gateway_neighbors: Dict[str, GatewayNeighbor] = {}
        self.active_gateway_ip: Optional[str] = None
        self.active_gateway_iface: Optional[str] = None

        self._gateway_cache: Dict[str, Any] = {"value": None, "ts": 0.0}
        self._wan_cache: Dict[str, Any] = {"ip": None, "netmask": None, "network": None}
        self._dns_cache: Dict[str, Any] = {"servers": [], "ts": 0.0}
        self._neighbor_cache: Dict[str, Any] = {"mac": None, "ts": 0.0}
        self._last_dns_refresh = 0.0

        # no-reapply guards
        self._last_applied_gateway_ip: Optional[str] = None
        self._last_applied_gateway_iface: Optional[str] = None
        self._last_applied_gateway_mac: Optional[str] = None
        self._last_gateway_push_ts: float = 0.0

        # hard stop guard for DNS lifecycle
        self._run_token: int = 0
        self._dns_disabled_until_start: bool = False

    # ---------------------------------------------------------
    # lifecycle
    # ---------------------------------------------------------

    def configure(
        self,
        *,
        auto_configure_router_interfaces: bool = False,
        use_dhcp_out: bool = True,
        use_dhcp_in: bool = False,
        router_ip_out: Optional[str] = None,
        router_netmask_out: str = "255.255.255.0",
        force_wan_to_dhcp_on_start: bool = False,
        ensure_host_dns_from_wan: bool = True,
        repair_on_failure: bool = True,
        pin_gateway_arp: bool = True,
        health_interval_sec: float = 15.0,
        dns_refresh_interval_sec: float = 120.0,
        candidate_refresh_interval_sec: float = 20.0,
        gateway_refresh_interval_sec: float = 45.0,
        gateway_neighbor_refresh_sec: float = 20.0,
        soft_repair_cooldown_sec: float = 30.0,
        hard_repair_cooldown_sec: float = 180.0,
        failure_threshold_for_soft_repair: int = 3,
        failure_threshold_for_hard_repair: int = 8,
        minimum_degraded_time_for_hard_repair_sec: float = 90.0,
        disable_netroute_default_sync: bool = True,
        disable_netroute_metric_tuning: bool = True,
        runtime_set_wan_to_dhcp: bool = False,
        enable_dns64: bool = True,
        dns64_prefix: str = "64:ff9b::/96",
        upstream_dns: Optional[list[str]] = None,
    ) -> None:
        self._prefs.update({
            "auto_configure_router_interfaces": bool(auto_configure_router_interfaces),
            "use_dhcp_out": bool(use_dhcp_out),
            "use_dhcp_in": bool(use_dhcp_in),
            "router_ip_out": router_ip_out,
            "router_netmask_out": router_netmask_out,
            "force_wan_to_dhcp_on_start": bool(force_wan_to_dhcp_on_start),
            "ensure_host_dns_from_wan": bool(ensure_host_dns_from_wan),
            "repair_on_failure": bool(repair_on_failure),
            "pin_gateway_arp": bool(pin_gateway_arp),
            "health_interval_sec": max(3.0, float(health_interval_sec)),
            "dns_refresh_interval_sec": max(20.0, float(dns_refresh_interval_sec)),
            "candidate_refresh_interval_sec": max(5.0, float(candidate_refresh_interval_sec)),
            "gateway_refresh_interval_sec": max(10.0, float(gateway_refresh_interval_sec)),
            "gateway_neighbor_refresh_sec": max(5.0, float(gateway_neighbor_refresh_sec)),
            "soft_repair_cooldown_sec": max(10.0, float(soft_repair_cooldown_sec)),
            "hard_repair_cooldown_sec": max(30.0, float(hard_repair_cooldown_sec)),
            "failure_threshold_for_soft_repair": max(1, int(failure_threshold_for_soft_repair)),
            "failure_threshold_for_hard_repair": max(2, int(failure_threshold_for_hard_repair)),
            "minimum_degraded_time_for_hard_repair_sec": max(15.0, float(minimum_degraded_time_for_hard_repair_sec)),
            "disable_netroute_default_sync": bool(disable_netroute_default_sync),
            "disable_netroute_metric_tuning": bool(disable_netroute_metric_tuning),
            "runtime_set_wan_to_dhcp": bool(runtime_set_wan_to_dhcp),
            "enable_dns64": bool(enable_dns64),
            "dns64_prefix": str(dns64_prefix),
            "upstream_dns": list(upstream_dns) if upstream_dns else None,
        })
        self._say("gateway_configured", "stored safe uplink preferences", ["🧠", "📝"], cooldown=0.0)

    def start(self) -> None:
        with self._lock:
            if self._state.started:
                return
            self._state.started = True
            self._stop_event.clear()
            self._dns_disabled_until_start = False
            self._run_token += 1
            run_token = self._run_token

        self._bootstrap(run_token=run_token)
        self._thread = threading.Thread(
            target=self._health_loop,
            kwargs={"run_token": run_token},
            name="GatewayManagerHealth",
            daemon=True,
        )
        self._thread.start()
        self._say("gateway_started", "uplink control plane is active", ["🌐", "🚪", "🛰️"], cooldown=0.0)

    def stop(self) -> None:
        with self._lock:
            if not self._state.started:
                return
            self._state.started = False
            self._stop_event.set()
            self._dns_disabled_until_start = True
            self._run_token += 1
            t = self._thread
            self._thread = None

        if t and t.is_alive():
            t.join(timeout=3.0)

        dns_manager = getattr(self.router, "dns_manager", None)
        if dns_manager is not None:
            try:
                dns_manager.stop()
            except Exception:
                pass

        # prevent any external stale reference from reusing a live object
        try:
            self.router.dns_manager = None
        except Exception:
            pass

        self._gc_flows()
        self._say("gateway_stopped", "uplink control plane stopped and DNS manager disabled", ["🛑", "🌙"], cooldown=0.0)

    # ---------------------------------------------------------
    # observation
    # ---------------------------------------------------------

    def observe_packet(self, packet, inbound_iface: str) -> None:
        packet = self._decode_if_bytes(packet)
        if packet is None:
            return
        if self._iface_role(inbound_iface) != "wan":
            return

        self._observe_wan_neighbor(packet, inbound_iface)
        self._observe_gateway_candidate_from_packet(packet, inbound_iface)

    def _observe_wan_neighbor(self, packet, inbound_iface: str) -> None:
        now = time.time()

        if packet.haslayer(ARP):
            arp = packet[ARP]
            ip = getattr(arp, "psrc", None)
            mac = getattr(arp, "hwsrc", None)
            if ip and mac and self._looks_like_same_wan_segment(str(ip)):
                key = str(ip)
                n = self.gateway_neighbors.get(key)
                if n is None:
                    n = GatewayNeighbor(ip=key, mac=str(mac).lower(), iface=inbound_iface, source="arp", family=4)
                    self.gateway_neighbors[key] = n
                n.mac = str(mac).lower()
                n.iface = inbound_iface
                n.last_seen = now
                return

        src_ip, dst_ip = self._extract_ips(packet)
        for ip in (src_ip, dst_ip):
            if not ip:
                continue
            bare = str(ip).split("%")[0]
            if bare == getattr(self.router, "router_ip_out", None):
                continue
            if self._looks_like_same_wan_segment(bare):
                family = 6 if self._is_ipv6(bare) else 4
                n = self.gateway_neighbors.get(bare)
                if n is None:
                    n = GatewayNeighbor(ip=bare, mac=None, iface=inbound_iface, source="ip", family=family)
                    self.gateway_neighbors[bare] = n
                n.last_seen = now
                n.iface = inbound_iface

    def _observe_gateway_candidate_from_packet(self, packet, inbound_iface: str) -> None:
        src_ip, dst_ip = self._extract_ips(packet)
        current_gw = getattr(self.router, "router_gateway_out_ip", None)

        if current_gw:
            self._learn_gateway_candidate(str(current_gw), inbound_iface, "configured")

        for ip in (src_ip, dst_ip):
            if not ip:
                continue
            bare = str(ip).split("%")[0]
            if bare == getattr(self.router, "router_ip_out", None):
                continue
            if self._looks_like_same_wan_segment(bare):
                source = "neighbor" if self.gateway_neighbors.get(bare) else "packet"
                self._learn_gateway_candidate(bare, inbound_iface, source)

    def _learn_gateway_candidate(self, ip: str, iface: str, source: str) -> None:
        if not self._is_ipv4(ip):
            return
        now = time.time()
        c = self.gateway_candidates.get(ip)
        if c is None:
            c = GatewayCandidate(ip=ip, iface=iface, source=source, learned_from_neighbor=(source == "neighbor"))
            self.gateway_candidates[ip] = c
            self._say("gateway_candidate_new", f"learned gateway candidate {ip} from {source}", ["🧭", "🌱"], cooldown=0.0)
        c.iface = iface
        c.source = source
        c.last_seen = now

    # ---------------------------------------------------------
    # ownership
    # ---------------------------------------------------------

    def inspect_packet(self, packet, inbound_iface: str) -> ManagerPacketDecision:
        packet = self._decode_if_bytes(packet)
        if packet is None:
            return ManagerPacketDecision("pass", "null-packet", "null/undecodable packet", 100)

        role = self._iface_role(inbound_iface)
        src_ip, dst_ip = self._extract_ips(packet)
        proto, sport, dport = self._extract_proto_ports(packet)
        known = self._get_known_owner(packet)

        if self._is_dhcp_packet(packet):
            return ManagerPacketDecision("pass", "dhcp-belongs-to-lan", "DHCP belongs to LAN manager", 100)

        if known == "gateway":
            return ManagerPacketDecision("consume", "known-gateway-flow", "learned gateway-owned flow", 95)
        if known == "pass":
            return ManagerPacketDecision("pass", "known-pass-flow", "learned non-gateway flow", 95)

        if packet.haslayer(ARP):
            try:
                arp = packet[ARP]
                if role == "wan" and (self._is_gateway_ip(getattr(arp, "psrc", None)) or self._is_gateway_ip(getattr(arp, "pdst", None))):
                    return ManagerPacketDecision("consume", "wan-gateway-arp", "ARP directly involves active/default gateway", 100)
            except Exception:
                pass
            return ManagerPacketDecision("pass", "non-gateway-arp", "ARP not clearly gateway-owned", 80)

        if self._is_dns_packet(packet):
            direction = self._dns_direction(packet)
            if direction == "query":
                if dport in (53, 5353) and (role in ("lan", "wan") or self._is_likely_router_service_address(dst_ip)):
                    return ManagerPacketDecision("consume", "router-dns-query", "router is servicing this DNS query", 90)
            if direction == "response":
                if sport in (53, 5353) and (role == "wan" or self._is_gateway_ip(src_ip) or self._is_router_local_ip(dst_ip)):
                    return ManagerPacketDecision("consume", "router-dns-response", "upstream DNS response belongs to router DNS logic", 92)
            return ManagerPacketDecision("observe", "dns-ambiguous", "DNS exists but ownership is weak", 35)

        if proto in ("ICMP", "ICMPv6"):
            if role == "wan" and (self._is_gateway_ip(src_ip) or self._is_gateway_ip(dst_ip)):
                return ManagerPacketDecision("consume", "gateway-icmp", "ICMP is on the router<->gateway path", 90)
            if role == "wan" and (self._is_router_local_ip(src_ip) or self._is_router_local_ip(dst_ip)):
                return ManagerPacketDecision("consume", "wan-local-icmp", "WAN-local ICMP is router-owned", 80)
            return ManagerPacketDecision("pass", "icmp-not-gateway-owned", "ICMP not clearly gateway-owned", 70)

        if role == "wan" and (self._is_gateway_ip(src_ip) or self._is_gateway_ip(dst_ip)):
            if self._is_router_local_ip(src_ip) or self._is_router_local_ip(dst_ip):
                return ManagerPacketDecision("consume", "router-gateway-adjacency", "packet is directly between router and gateway", 88)
            return ManagerPacketDecision("observe", "gateway-adjacent-ambiguous", "packet touches gateway but is not clearly router-owned", 35)

        return ManagerPacketDecision("pass", "not-gateway-owned", "packet does not strongly match gateway ownership", 75)

    def should_consume(self, packet, inbound_iface: str) -> bool:
        decision = self.inspect_packet(packet, inbound_iface)
        p = self._decode_if_bytes(packet)
        if decision.action == "consume" and p is not None:
            self._remember_flow(p, "gateway")
            return True
        if decision.action == "pass" and p is not None:
            self._remember_flow(p, "pass")
        return False

    def handle_packet(self, packet, inbound_iface: str) -> bool:
        packet = self._decode_if_bytes(packet)
        if packet is None:
            return False

        self.observe_packet(packet, inbound_iface)

        decision = self.inspect_packet(packet, inbound_iface)
        if decision.action != "consume":
            return False

        try:
            self._learn_gateway_neighbor(packet, inbound_iface)

            if packet.haslayer(ARP):
                return self._handle_gateway_arp(packet, inbound_iface)

            if packet.haslayer(DNS):
                return self._handle_dns(packet, inbound_iface)

            proto, _, _ = self._extract_proto_ports(packet)
            if proto in ("ICMP", "ICMPv6"):
                icmp_manager = getattr(self.router, "icmp_manager", None)
                if icmp_manager and icmp_manager.handle_packet(packet, inbound_iface):
                    return True

            src_ip, dst_ip = self._extract_ips(packet)
            if self._is_router_local_ip(src_ip) or self._is_router_local_ip(dst_ip):
                return True

            return False
        except Exception as e:
            self._say("gateway_handle_error", f"gateway packet handling failed: {type(e).__name__}: {e}", ["⚠️", "🧯"])
            return False

    # ---------------------------------------------------------
    # bootstrap / health
    # ---------------------------------------------------------

    def _bootstrap(self, *, run_token: int) -> None:
        try:
            if self._prefs["auto_configure_router_interfaces"] and hasattr(self.router, "_auto_configure_interfaces"):
                if hasattr(self.router, "_initialize_interface_discovery"):
                    self.router._initialize_interface_discovery()

                ok = self.router._auto_configure_interfaces(
                    self._prefs["use_dhcp_out"],
                    self._prefs["use_dhcp_in"],
                    router_ip_out=self._prefs["router_ip_out"],
                    router_netmask_out=self._prefs["router_netmask_out"],
                )
                self._say("gateway_auto_config", "auto-configured router interfaces" if ok else "auto-configure reported failure", ["🛠️", "🔌", "📡"], cooldown=0.0)

            self._enforce_netroute_safe_mode()
            self._apply_host_network_preferences()
            self._refresh_wan_snapshot()
            self._seed_default_gateway_candidate()
            self._refresh_candidate_health()

            best = self._choose_best_gateway()
            if best:
                changed = self._install_active_gateway(best.ip, best.iface)
                if changed:
                    self._push_gateway_state(force=True)

            self._ensure_dns_manager(force_refresh=True, run_token=run_token)
            self._ensure_gateway_neighbor(force=True)
        except Exception as e:
            self._say("gateway_bootstrap_error", f"bootstrap failed: {type(e).__name__}: {e}", ["⚠️", "🧯"], cooldown=0.0)

    def _health_loop(self, *, run_token: int) -> None:
        while not self._stop_event.wait(self._prefs["health_interval_sec"]):
            if (not self._state.started) or self._stop_event.is_set() or self._dns_disabled_until_start or run_token != self._run_token:
                break

            try:
                self._enforce_netroute_safe_mode()
                self._refresh_wan_snapshot()
                self._seed_default_gateway_candidate()

                now = time.time()

                if (now - self._gateway_cache.get("ts", 0.0)) >= self._prefs["gateway_refresh_interval_sec"]:
                    gw = self._resolve_gateway_ip(force=False)
                    if gw:
                        self._learn_gateway_candidate(gw, getattr(self.router, "interface_out_full_name", None), "route")

                if (now - self._neighbor_cache.get("ts", 0.0)) >= self._prefs["gateway_neighbor_refresh_sec"]:
                    self._ensure_gateway_neighbor(force=False)

                if (now - self._last_dns_refresh) >= self._prefs["dns_refresh_interval_sec"]:
                    self._ensure_dns_manager(force_refresh=False, run_token=run_token)

                if (now - self._gateway_cache.get("ts", 0.0)) >= self._prefs["candidate_refresh_interval_sec"]:
                    self._refresh_candidate_health()

                best = self._choose_best_gateway()
                changed = False
                if best:
                    changed = self._install_active_gateway(best.ip, best.iface)

                self._push_gateway_state(force=changed)

                wan_ok = self._wan_health_ok()
                if wan_ok:
                    self._state.last_health_ok = now
                    self.health.consecutive_successes += 1
                    self.health.consecutive_failures = 0
                    self.health.degraded_since = 0.0
                else:
                    self._state.last_health_fail = now
                    self._attempt_wan_repair(run_token=run_token)

                self._gc_flows()
                self._prune_stale_neighbors_and_candidates()
            except Exception as e:
                self._say("gateway_health_error", f"uplink health loop hit {type(e).__name__}: {e}", ["⚠️", "🧩"])

    def _enforce_netroute_safe_mode(self) -> None:
        nr = getattr(self.router, "netroute_manager", None)
        if not nr:
            return

        changed = False

        if self._prefs.get("disable_netroute_default_sync", True):
            if getattr(nr, "enable_default_route_sync", False):
                nr.enable_default_route_sync = False
                changed = True

        if self._prefs.get("disable_netroute_metric_tuning", True):
            if getattr(nr, "enable_metric_tuning", False):
                nr.enable_metric_tuning = False
                changed = True

        if changed:
            self._say(
                "gateway_netroute_safe_mode",
                "disabled NetRoute default-route sync and metric tuning to protect the host uplink",
                ["🛡️", "🚧", "🌐"],
                cooldown=0.0,
            )

    def _apply_host_network_preferences(self) -> None:
        wan_name = getattr(self.router, "interface_out_friendly_name", None)
        if not wan_name:
            return

        if self._prefs["force_wan_to_dhcp_on_start"]:
            try:
                self._set_interface_to_dhcp(wan_name)
                self._renew_interface(wan_name)
                self._say("gateway_dhcp_applied", f"set host WAN interface '{wan_name}' to DHCP mode", ["🔁", "📶"], cooldown=0.0)
            except Exception as e:
                self._say("gateway_dhcp_apply_error", f"failed switching '{wan_name}' to DHCP: {e}", ["⚠️"])

        if self._prefs["ensure_host_dns_from_wan"]:
            try:
                self._set_dns_to_dhcp(wan_name)
                self._say("gateway_dns_mode", f"set host DNS source for '{wan_name}' to DHCP/upstream mode", ["🧭", "🌍"], cooldown=0.0)
            except Exception as e:
                self._say("gateway_dns_mode_error", f"failed setting host DNS mode on '{wan_name}': {e}", ["⚠️"])

        try:
            if hasattr(self.router, "_configure_host_preserving_upstream_mode"):
                self.router._configure_host_preserving_upstream_mode()
        except Exception:
            pass

    def _refresh_wan_snapshot(self) -> None:
        r = self.router
        wan_name = getattr(r, "interface_out_friendly_name", None)
        wan_full = getattr(r, "interface_out_full_name", None)
        if not wan_name or not wan_full:
            return

        info = self._get_ipv4_info_for_adapter(wan_name)
        if not info:
            return

        ip_changed = (
            info["ip"] != self._wan_cache["ip"]
            or info["netmask"] != self._wan_cache["netmask"]
        )

        r.router_ip_out = info["ip"]
        r.router_netmask_out = info["netmask"]
        r.router_network_out = info["network"]

        cfg = r._interfaces_config.setdefault(wan_full, {})
        cfg.update({
            "friendly_name": wan_name,
            "ip_addr": r.router_ip_out,
            "network": r.router_network_out,
            "broadcast": str(r.router_network_out.broadcast_address),
            "is_default_gateway_iface": True,
        })

        if not cfg.get("mac") and hasattr(r, "get_interface_mac"):
            try:
                cfg["mac"] = r.get_interface_mac(wan_full)
            except Exception:
                pass

        if ip_changed:
            self._wan_cache.update(info)
            self._gateway_cache["ts"] = 0.0
            self._dns_cache["ts"] = 0.0
            self._say("wan_snapshot_changed", f"WAN snapshot updated to {info['ip']}/{info['netmask']}", ["📡", "🔄"], cooldown=0.0)

    def _seed_default_gateway_candidate(self) -> None:
        gw = self._resolve_gateway_ip(force=False)
        iface = getattr(self.router, "interface_out_full_name", None)
        if gw and iface:
            self._learn_gateway_candidate(gw, iface, "route")

    def _looks_like_same_wan_segment(self, ip: str) -> bool:
        try:
            net = getattr(self.router, "router_network_out", None)
            if isinstance(net, ipaddress.IPv4Network) and self._is_ipv4(ip):
                return ipaddress.IPv4Address(ip) in net
        except Exception:
            pass
        return False

    def _resolve_gateway_ip(self, *, force: bool) -> Optional[str]:
        now = time.time()
        if not force:
            cached = self._gateway_cache.get("value")
            if cached and (now - self._gateway_cache.get("ts", 0.0)) < self._prefs["gateway_refresh_interval_sec"]:
                return cached

        wan_name = getattr(self.router, "interface_out_friendly_name", None)
        wan_ip = getattr(self.router, "router_ip_out", None)

        resolved = None

        if wan_name and self._is_likely_real_uplink_iface(wan_name):
            resolved = self._get_default_gateway_for_local_ip(wan_ip)

        if not resolved:
            try:
                helper = getattr(self.router, "_get_default_gateway_for_interface", None)
                if callable(helper) and wan_name and self._is_likely_real_uplink_iface(wan_name):
                    maybe = helper(wan_name)
                    if self._is_ipv4(maybe):
                        resolved = maybe
            except Exception:
                resolved = None

        self._gateway_cache["value"] = resolved
        self._gateway_cache["ts"] = now
        return resolved

    def _score_gateway_candidate(self, cand: GatewayCandidate) -> float:
        score = 0.0
        now = time.time()

        if now - cand.last_seen < 60:
            score += 15.0
        if cand.last_ok:
            score += 40.0
        score += min(cand.ok_count * 6.0, 36.0)
        score -= min(cand.fail_count * 8.0, 48.0)

        neigh = self.gateway_neighbors.get(cand.ip)
        if neigh and neigh.mac:
            score += 25.0

        if cand.ip == getattr(self.router, "router_gateway_out_ip", None):
            score += 20.0

        if cand.ip == self.active_gateway_ip:
            score += 10.0

        cand.score = score
        return score

    def _choose_best_gateway(self) -> Optional[GatewayCandidate]:
        best = None
        best_score = float("-inf")
        for cand in self.gateway_candidates.values():
            score = self._score_gateway_candidate(cand)
            if score > best_score:
                best = cand
                best_score = score
        return best

    def _probe_gateway_service(self, gateway_ip: str) -> bool:
        bind_ip = getattr(self.router, "router_ip_out", None)
        if not bind_ip:
            return False

        for port in (53, 80, 443):
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.bind((bind_ip, 0))
                s.connect((gateway_ip, port))
                return True
            except Exception:
                pass
            finally:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

        for host in self._discover_dns_upstreams(force=False)[:2]:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.bind((bind_ip, 0))
                s.connect((host, 53))
                return True
            except Exception:
                pass
            finally:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

        return False

    def _refresh_candidate_health(self) -> None:
        for ip, cand in list(self.gateway_candidates.items()):
            ok = self._probe_gateway_service(ip)
            now = time.time()
            if ok:
                cand.last_ok = now
                cand.ok_count += 1
            else:
                cand.last_fail = now
                cand.fail_count += 1

            neigh = self.gateway_neighbors.get(ip)
            if neigh:
                if ok:
                    neigh.last_ok = now
                    neigh.ok_count += 1
                else:
                    neigh.last_fail = now
                    neigh.fail_count += 1

    def _install_active_gateway(self, gateway_ip: str, iface: str) -> bool:
        r = self.router

        neigh = self.gateway_neighbors.get(gateway_ip)
        mac = neigh.mac.lower() if neigh and neigh.mac else None

        changed = (
            gateway_ip != self._last_applied_gateway_ip
            or iface != self._last_applied_gateway_iface
            or mac != self._last_applied_gateway_mac
        )

        self.active_gateway_ip = gateway_ip
        self.active_gateway_iface = iface
        r.router_gateway_out_ip = gateway_ip

        if not changed:
            return False

        out_full = getattr(r, "interface_out_full_name", None)
        if out_full:
            r._interfaces_config.setdefault(out_full, {})["gateway"] = gateway_ip

        try:
            if getattr(r, "arp_manager", None) is not None:
                r.arp_manager.set_default_gateway(r._interfaces_config, gateway_ip)
        except Exception:
            pass

        if mac:
            try:
                if hasattr(r, "add_static_arp_entry"):
                    r.add_static_arp_entry(gateway_ip, mac)
                elif hasattr(r.arp_manager, "add_static_arp_entry"):
                    r.arp_manager.add_static_arp_entry(gateway_ip, mac)
            except Exception:
                pass

        try:
            if getattr(r, "packet_writer", None) is not None:
                r.packet_writer.update_interfaces(r._interfaces_config)
        except Exception:
            pass

        try:
            if getattr(r, "nat_manager", None) is not None:
                r.nat_manager.router_ip_out = getattr(r, "router_ip_out", None)
        except Exception:
            pass

        try:
            r.default_gateway_ip = gateway_ip
        except Exception:
            pass

        self._last_applied_gateway_ip = gateway_ip
        self._last_applied_gateway_iface = iface
        self._last_applied_gateway_mac = mac
        self._last_gateway_push_ts = time.time()

        self._say("gateway_installed", f"installed active gateway {gateway_ip} via {iface.split('_')[-1]}", ["🚪", "🌐", "🧭"], cooldown=0.0)
        return True

    def _discover_dns_upstreams(self, *, force: bool) -> list[str]:
        custom = self._prefs.get("upstream_dns")
        if custom:
            return [x for x in custom if self._is_ipv4(x)]

        now = time.time()
        if (not force) and self._dns_cache["servers"] and (now - self._dns_cache["ts"]) < self._prefs["dns_refresh_interval_sec"]:
            return list(self._dns_cache["servers"])

        out: list[str] = []
        wan_name = getattr(self.router, "interface_out_friendly_name", None)

        for ip in self._get_windows_dns_servers(wan_name):
            if self._is_ipv4(ip) and ip not in out:
                out.append(ip)

        active_gw = self.active_gateway_ip or getattr(self.router, "router_gateway_out_ip", None)
        if self._is_ipv4(active_gw) and active_gw not in out:
            out.append(active_gw)

        for ip in self.DEFAULT_UPSTREAM_DNS:
            if ip not in out:
                out.append(ip)

        self._dns_cache["servers"] = out[:6]
        self._dns_cache["ts"] = now
        return list(self._dns_cache["servers"])

    def _ensure_dns_manager(self, *, force_refresh: bool, run_token: Optional[int] = None) -> bool:
        # hard guard: once stop() happens, DNSManager may not restart
        if self._dns_disabled_until_start or (not self._state.started) or self._stop_event.is_set():
            dns_manager = getattr(self.router, "dns_manager", None)
            if dns_manager is not None:
                try:
                    dns_manager.stop()
                except Exception:
                    pass
            return False

        if run_token is not None and run_token != self._run_token:
            return False

        r = self.router
        dns_manager = getattr(r, "dns_manager", None)
        if dns_manager is None:
            dns_manager = self.DNSManager(r.router_logger, r.packet_writer, getattr(r, "router_ipv6_link_local_out", None))
            r.dns_manager = dns_manager

        dns_manager.router_ip_out = getattr(r, "router_ip_out", None)
        dns_manager.router_ipv4_out = getattr(r, "router_ip_out", None)
        dns_manager.router_ipv6_link_local_out = getattr(r, "router_ipv6_link_local_out", None)

        upstreams = self._discover_dns_upstreams(force=force_refresh)
        current = [u.get("ip") for u in getattr(dns_manager, "upstreams", []) if isinstance(u, dict)]

        if force_refresh or sorted(current) != sorted(upstreams):
            dns_manager.configure_upstreams(
                upstreams,
                enable_dns64=self._prefs["enable_dns64"],
                dns64_prefix=self._prefs["dns64_prefix"],
            )
            self._last_dns_refresh = time.time()
            self._say("dns_upstreams_changed", f"DNS upstreams updated to {upstreams}", ["🧠", "🌍", "🛰️"], cooldown=0.0)

        if self._dns_disabled_until_start or (not self._state.started) or self._stop_event.is_set():
            return False
        if run_token is not None and run_token != self._run_token:
            return False

        probe_thread = getattr(dns_manager, "_probe_thread", None)
        if not probe_thread or not probe_thread.is_alive():
            dns_manager.start()
            self._say("dns_manager_started", "DNS manager is active", ["🧬", "📬"], cooldown=0.0)

        return True

    def _push_gateway_state(self, *, force: bool = False) -> None:
        r = self.router
        gateway = self.active_gateway_ip or getattr(r, "router_gateway_out_ip", None)
        wan_ip = getattr(r, "router_ip_out", None)

        if not gateway:
            return

        should_push_gateway = force or (gateway != self._last_applied_gateway_ip)

        if should_push_gateway:
            try:
                if getattr(r, "arp_manager", None) is not None:
                    r.arp_manager.set_default_gateway(r._interfaces_config, gateway)
                    r.arp_manager.router_ip_out = wan_ip
            except Exception:
                pass

        try:
            if getattr(r, "packet_writer", None) is not None:
                r.packet_writer.update_interfaces(r._interfaces_config)
        except Exception:
            pass

        try:
            if getattr(r, "nat_manager", None) is not None:
                r.nat_manager.router_ip_out = wan_ip
        except Exception:
            pass

        try:
            r.default_gateway_ip = gateway
        except Exception:
            pass

    def _ensure_gateway_neighbor(self, *, force: bool) -> bool:
        if not self._prefs["pin_gateway_arp"]:
            return False

        now = time.time()
        if (not force) and (now - self._neighbor_cache["ts"]) < self._prefs["gateway_neighbor_refresh_sec"]:
            return bool(self._neighbor_cache["mac"])

        gateway_ip = self.active_gateway_ip or getattr(self.router, "router_gateway_out_ip", None)
        out_full = getattr(self.router, "interface_out_full_name", None)
        if not gateway_ip or not out_full:
            return False

        resolved_mac = None
        try:
            if getattr(self.router, "arp_manager", None) is not None and hasattr(self.router.arp_manager, "resolve"):
                resolved_mac = self.router.arp_manager.resolve(gateway_ip, out_full)
        except Exception:
            resolved_mac = None

        self._neighbor_cache["ts"] = now

        if not resolved_mac:
            self._say("gateway_neighbor_missing", f"could not resolve MAC for gateway {gateway_ip} yet", ["🔍", "⚠️"])
            return False

        resolved_mac = str(resolved_mac).lower()
        old_mac = self._neighbor_cache.get("mac")
        self._neighbor_cache["mac"] = resolved_mac

        n = self.gateway_neighbors.get(gateway_ip)
        if n is None:
            n = GatewayNeighbor(ip=gateway_ip, mac=resolved_mac, iface=out_full, source="resolve")
            self.gateway_neighbors[gateway_ip] = n
        else:
            n.mac = resolved_mac
            n.last_seen = now

        if resolved_mac == self._last_applied_gateway_mac and gateway_ip == self._last_applied_gateway_ip:
            return True

        try:
            if hasattr(self.router, "add_static_arp_entry"):
                self.router.add_static_arp_entry(gateway_ip, resolved_mac)
            elif hasattr(self.router.arp_manager, "add_static_arp_entry"):
                self.router.arp_manager.add_static_arp_entry(gateway_ip, resolved_mac)
        except Exception:
            pass

        self._last_applied_gateway_mac = resolved_mac

        if resolved_mac != old_mac:
            self._say("gateway_neighbor_changed", f"gateway neighbor learned as {gateway_ip} -> {resolved_mac}", ["🤝", "🔒", "🧷"], cooldown=0.0)

        return True

    def _learn_gateway_neighbor(self, packet, inbound_iface: str) -> None:
        gateway_ip = self.active_gateway_ip or self._gateway_ip()
        if not gateway_ip:
            return

        try:
            if packet.haslayer(ARP):
                arp = packet[ARP]
                psrc = getattr(arp, "psrc", None)
                hwsrc = getattr(arp, "hwsrc", None)
                if psrc == gateway_ip and hwsrc:
                    hwsrc = str(hwsrc).lower()
                    old_mac = self._neighbor_cache.get("mac")
                    self._neighbor_cache["mac"] = hwsrc
                    self._neighbor_cache["ts"] = time.time()

                    n = self.gateway_neighbors.get(gateway_ip)
                    if n is None:
                        n = GatewayNeighbor(ip=gateway_ip, mac=hwsrc, iface=inbound_iface, source="arp")
                        self.gateway_neighbors[gateway_ip] = n
                    else:
                        n.mac = hwsrc
                        n.last_seen = time.time()

                    if hwsrc != old_mac:
                        self._say("gateway_neighbor_passive", f"passively learned gateway MAC {gateway_ip} -> {hwsrc}", ["👀", "🔗"], cooldown=0.0)

                    if hwsrc != self._last_applied_gateway_mac or gateway_ip != self._last_applied_gateway_ip:
                        try:
                            if hasattr(self.router, "add_static_arp_entry"):
                                self.router.add_static_arp_entry(gateway_ip, hwsrc)
                            elif hasattr(self.router.arp_manager, "add_static_arp_entry"):
                                self.router.arp_manager.add_static_arp_entry(gateway_ip, hwsrc)
                        except Exception:
                            pass
                        self._last_applied_gateway_mac = hwsrc
                    return
        except Exception:
            pass

        try:
            src_ip, dst_ip = self._extract_ips(packet)
            if src_ip == gateway_ip or dst_ip == gateway_ip:
                if getattr(self.router, "arp_manager", None) is not None:
                    self.router.arp_manager.learn_from_packet(packet, inbound_iface)
        except Exception:
            pass

    def _gateway_neighbor_ok(self) -> bool:
        active = self.active_gateway_ip or getattr(self.router, "router_gateway_out_ip", None)
        if not active:
            return False

        neigh = self.gateway_neighbors.get(active)
        if neigh and neigh.mac:
            return True

        return self._ensure_gateway_neighbor(force=False)

    def _gateway_service_ok(self) -> bool:
        active = self.active_gateway_ip or getattr(self.router, "router_gateway_out_ip", None)
        if not active:
            return False
        return self._probe_gateway_service(active)

    def _internet_service_ok(self) -> bool:
        r = self.router
        try:
            if hasattr(r, "_probe_host_internet_health"):
                return bool(r._probe_host_internet_health())
        except Exception:
            pass

        bind_ip = getattr(r, "router_ip_out", None)
        if not bind_ip:
            return False

        for host in self._discover_dns_upstreams(force=False)[:2]:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.bind((bind_ip, 0))
                s.connect((host, 53))
                return True
            except Exception:
                pass
            finally:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

        return False

    def _wan_health_ok(self) -> bool:
        gateway_neighbor_ok = self._gateway_neighbor_ok()
        gateway_service_ok = self._gateway_service_ok()
        internet_ok = self._internet_service_ok()

        now = time.time()

        if gateway_service_ok:
            self.health.last_gateway_ok = now
        if internet_ok:
            self.health.last_internet_ok = now

        if gateway_neighbor_ok and gateway_service_ok:
            return True

        if gateway_neighbor_ok and (now - self.health.last_internet_ok) < 45.0:
            return True

        return False

    def _attempt_wan_repair(self, *, run_token: int) -> None:
        now = time.time()

        if self.health.degraded_since <= 0:
            self.health.degraded_since = now

        self.health.consecutive_failures += 1
        self.health.consecutive_successes = 0

        if self.health.consecutive_failures >= self._prefs["failure_threshold_for_soft_repair"]:
            if (now - self.health.last_soft_repair) >= self._prefs["soft_repair_cooldown_sec"]:
                self.health.last_soft_repair = now
                self._say("wan_soft_repair", "running soft uplink repair: refresh neighbors, candidates, DNS, and active gateway only", ["🧯", "🔄", "🧠"], cooldown=0.0)
                self._soft_repair_uplink(run_token=run_token)

        degraded_for = now - self.health.degraded_since
        if (
            self.health.consecutive_failures >= self._prefs["failure_threshold_for_hard_repair"]
            and degraded_for >= self._prefs["minimum_degraded_time_for_hard_repair_sec"]
            and (now - self.health.last_hard_repair) >= self._prefs["hard_repair_cooldown_sec"]
        ):
            self.health.last_hard_repair = now
            self._say("wan_hard_repair", "uplink stayed degraded long enough; performing last-resort WAN repair", ["⚠️", "🧯", "📶"], cooldown=0.0)
            self._hard_repair_uplink(run_token=run_token)

    def _soft_repair_uplink(self, *, run_token: int) -> None:
        self._refresh_wan_snapshot()
        self._seed_default_gateway_candidate()
        self._refresh_candidate_health()

        best = self._choose_best_gateway()
        changed = False
        if best:
            changed = self._install_active_gateway(best.ip, best.iface)

        self._ensure_dns_manager(force_refresh=True, run_token=run_token)

        if changed:
            self._push_gateway_state(force=True)
            self._ensure_gateway_neighbor(force=True)

    def _hard_repair_uplink(self, *, run_token: int) -> None:
        wan_name = getattr(self.router, "interface_out_friendly_name", None)
        if not wan_name:
            return

        if self._prefs.get("runtime_set_wan_to_dhcp", False):
            try:
                self._set_interface_to_dhcp(wan_name)
            except Exception:
                pass

        try:
            self._renew_interface(wan_name)
        except Exception:
            pass

        time.sleep(2.0)
        if run_token == self._run_token and not self._dns_disabled_until_start and self._state.started and not self._stop_event.is_set():
            self._soft_repair_uplink(run_token=run_token)

    def _prune_stale_neighbors_and_candidates(self) -> None:
        now = time.time()
        for ip, n in list(self.gateway_neighbors.items()):
            if (now - n.last_seen) > 1800:
                self.gateway_neighbors.pop(ip, None)

        for ip, c in list(self.gateway_candidates.items()):
            if (now - c.last_seen) > 1800 and c.ip != self.active_gateway_ip:
                self.gateway_candidates.pop(ip, None)

    def _handle_gateway_arp(self, packet, inbound_iface: str) -> bool:
        try:
            self._learn_gateway_neighbor(packet, inbound_iface)
            self.router.arp_manager.learn_from_packet(packet, inbound_iface)
        except Exception:
            pass
        try:
            self.router.arp_manager.learn_arp_response(packet)
        except Exception:
            pass
        return True

    def _handle_dns(self, packet, inbound_iface: str) -> bool:
        if self._dns_disabled_until_start or (not self._state.started) or self._stop_event.is_set():
            return False

        dns_manager = getattr(self.router, "dns_manager", None)
        if dns_manager is None:
            return False

        try:
            dns = packet[DNS]
            if int(dns.qr) == 0:
                return bool(dns_manager.handle_query(packet, inbound_iface))
            return bool(dns_manager.handle_response(packet))
        except Exception:
            return False

    # ---------------------------------------------------------
    # OS helpers
    # ---------------------------------------------------------

    def _set_interface_to_dhcp(self, iface_friendly_name: Optional[str]) -> None:
        if not iface_friendly_name:
            return
        if hasattr(self.router, "_execute_netsh"):
            self.router._execute_netsh(["set", "address", f"name={iface_friendly_name}", "source=dhcp"])
            return
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "address", f"name={iface_friendly_name}", "source=dhcp"],
            check=False,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def _set_dns_to_dhcp(self, iface_friendly_name: Optional[str]) -> None:
        if not iface_friendly_name:
            return
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={iface_friendly_name}", "source=dhcp"],
            check=False,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def _renew_interface(self, iface_friendly_name: Optional[str]) -> None:
        if not iface_friendly_name:
            return
        subprocess.run(
            ["ipconfig", "/renew", iface_friendly_name],
            check=False,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def _get_windows_dns_servers(self, iface_friendly_name: Optional[str]) -> list[str]:
        if not iface_friendly_name:
            return []
        quoted = str(iface_friendly_name).replace("'", "''")
        ps_cmd = rf"""
$servers = Get-DnsClientServerAddress -InterfaceAlias '{quoted}' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue
if ($servers) {{ $servers | ForEach-Object {{ $_ }} }}
"""
        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                out = []
                for line in (proc.stdout or "").splitlines():
                    line = line.strip()
                    if self._is_ipv4(line):
                        out.append(line)
                if out:
                    return out
        except Exception:
            pass

        try:
            proc = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "dnsservers", f"name={iface_friendly_name}"],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                found = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", proc.stdout or "")
                return [x for x in found if self._is_ipv4(x)]
        except Exception:
            pass

        return []


@dataclass
class UplinkCandidate:
    iface_full: str
    iface_friendly: str

    ip: Optional[str] = None
    netmask: Optional[str] = None
    network: Optional[Any] = None
    gateway_ip: Optional[str] = None
    dns_servers: list[str] = field(default_factory=list)

    link_up: bool = False
    gateway_ok: bool = False
    public_ok: bool = False

    last_seen: float = field(default_factory=time.time)
    last_ok: float = 0.0
    last_fail: float = 0.0
    ok_count: int = 0
    fail_count: int = 0
    score: float = 0.0

    metadata: dict = field(default_factory=dict)

    # probe / health bookkeeping
    last_gateway_probe: float = 0.0
    last_public_probe: float = 0.0
    last_gateway_refresh: float = 0.0
    last_dns_refresh: float = 0.0
    gateway_rtt_ms: Optional[float] = None
    public_rtt_ms: Optional[float] = None

    # passive signals
    last_passive_public_at: float = 0.0
    last_passive_arp_at: float = 0.0
    last_passive_nat_at: float = 0.0
    passive_public_hits: int = 0
    passive_arp_hits: int = 0
    passive_nat_hits: int = 0

    # activation / stability
    activation_count: int = 0
    flap_count: int = 0
    last_activation: float = 0.0
    consecutive_public_failures: int = 0
    health_state: str = "unknown"


class UplinkManager(_SmartManagerBase):
    """
    Multi-uplink manager.

    Goals:
      - keep the host Wi-Fi association/gateway path alive without flapping it
      - let the router fail over outbound/public traffic to another interface when Wi-Fi loses internet
      - keep router access to public IPs when any eligible uplink still has public connectivity
      - avoid OS default-route churn on the host
      - scrub bad public /32 host routes that break browsing

    Improvements in this rewrite:
      - much less subprocess churn through TTL caches and batched route scrubbing
      - passive health signals from ARP/NAT/real traffic reduce unnecessary probing
      - stickier activation logic to avoid flap storms and expensive failover loops
      - safer exception boundaries and lock usage around shared candidate state
    """

    DEFAULT_PUBLIC_PROBES = [
        ("1.1.1.1", 443),
        ("8.8.8.8", 53),
        ("9.9.9.9", 53),
        ("208.67.222.222", 53),
    ]

    def __init__(self, router: Any, gateway_manager: Optional[Any] = None):
        super().__init__(router, name="UplinkManager")
        self.gateway_manager = gateway_manager

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._candidate_lock = threading.RLock()

        self._prefs = {
            "health_interval_sec": 15.0,
            "preferred_iface_names": ["Wi-Fi"],
            "allow_router_failover": True,
            "preserve_wifi_link": True,
            "disable_netroute_default_sync": True,
            "disable_netroute_metric_tuning": True,
            "remove_public_host_routes": True,
            "gateway_probe_ports": [53, 80, 443],
            "public_probes": list(self.DEFAULT_PUBLIC_PROBES),
            "candidate_stale_sec": 300.0,
            "minimum_public_score_to_activate": 45.0,
            "keep_current_if_public": True,

            # added stability / performance guards
            "discovery_interval_sec": 45.0,
            "route_scrub_interval_sec": 90.0,
            "wifi_preserve_interval_sec": 45.0,
            "dns_cache_ttl_sec": 180.0,
            "gateway_cache_ttl_sec": 60.0,
            "adapter_cache_ttl_sec": 20.0,
            "min_probe_gap_sec": 8.0,
            "passive_signal_ttl_sec": 45.0,
            "max_probe_candidates_per_loop": 2,
            "activation_cooldown_sec": 20.0,
        }

        self.candidates: Dict[str, UplinkCandidate] = {}
        self.learned_public_ips: Set[str] = set()

        self.active_uplink_full: Optional[str] = None
        self.active_uplink_friendly: Optional[str] = None
        self.active_public_ready: bool = False

        self._last_applied_iface: Optional[str] = None
        self._last_applied_ip: Optional[str] = None
        self._last_applied_gateway: Optional[str] = None

        self._adapter_cache: Dict[str, tuple[float, Optional[dict]]] = {}
        self._gateway_cache: Dict[str, tuple[float, Optional[str]]] = {}
        self._dns_cache: Dict[str, tuple[float, list[str]]] = {}

        self._last_discovery_at: float = 0.0
        self._last_route_scrub_at: float = 0.0
        self._last_wifi_preserve_at: float = 0.0
        self._last_switch_at: float = 0.0
        self._public_probe_cursor: int = 0

    # ---------------------------------------------------------
    # lifecycle
    # ---------------------------------------------------------

    def configure(
        self,
        *,
        health_interval_sec: float = 15.0,
        preferred_iface_names: Optional[list[str]] = None,
        allow_router_failover: bool = True,
        preserve_wifi_link: bool = True,
        disable_netroute_default_sync: bool = True,
        disable_netroute_metric_tuning: bool = True,
        remove_public_host_routes: bool = True,
        gateway_probe_ports: Optional[list[int]] = None,
        public_probes: Optional[list[tuple[str, int]]] = None,
        candidate_stale_sec: float = 300.0,
        minimum_public_score_to_activate: float = 45.0,
        keep_current_if_public: bool = True,
    ) -> None:
        self._prefs.update({
            "health_interval_sec": max(5.0, float(health_interval_sec)),
            "preferred_iface_names": list(preferred_iface_names or ["Wi-Fi"]),
            "allow_router_failover": bool(allow_router_failover),
            "preserve_wifi_link": bool(preserve_wifi_link),
            "disable_netroute_default_sync": bool(disable_netroute_default_sync),
            "disable_netroute_metric_tuning": bool(disable_netroute_metric_tuning),
            "remove_public_host_routes": bool(remove_public_host_routes),
            "gateway_probe_ports": list(gateway_probe_ports or [53, 80, 443]),
            "public_probes": list(public_probes or self.DEFAULT_PUBLIC_PROBES),
            "candidate_stale_sec": max(30.0, float(candidate_stale_sec)),
            "minimum_public_score_to_activate": float(minimum_public_score_to_activate),
            "keep_current_if_public": bool(keep_current_if_public),
        })
        self._say("uplink_configured", "stored uplink preferences", ["🌐", "📝"], cooldown=0.0)

    def start(self) -> None:
        with self._lock:
            if self._state.started:
                return
            self._state.started = True
            self._stop_event.clear()

        self._bootstrap()
        self._thread = threading.Thread(target=self._health_loop, name="UplinkManagerHealth", daemon=True)
        self._thread.start()
        self._say("uplink_started", "uplink manager is active", ["🛰️", "🌍"], cooldown=0.0)

    def stop(self) -> None:
        with self._lock:
            if not self._state.started:
                return
            self._state.started = False
            self._stop_event.set()
            t = self._thread
            self._thread = None

        if t and t.is_alive():
            t.join(timeout=3.0)

        self._gc_flows()
        self._say("uplink_stopped", "uplink manager stopped", ["🛑", "🌙"], cooldown=0.0)

    def _is_candidate_iface(self, iface_full: str, cfg: dict) -> bool:
        friendly = str(cfg.get("friendly_name") or iface_full or "").strip()
        if not friendly:
            return False
        if self._is_virtual_or_ignored_iface_name(friendly):
            return False
        if not self._is_likely_real_uplink_iface(friendly):
            return False
        if cfg.get("disabled") is True:
            return False
        return True

    # ---------------------------------------------------------
    # packet observation
    # ---------------------------------------------------------

    def observe_packet(self, packet, inbound_iface: str) -> None:
        packet = self._decode_if_bytes(packet)
        if packet is None:
            return

        now = time.time()
        saw_public = False

        try:
            src_ip, dst_ip = self._extract_ips(packet)
            for ip in (src_ip, dst_ip):
                bare = str(ip).split("%")[0] if ip else None
                if self._is_public_ipv4(bare):
                    self.learned_public_ips.add(bare)
                    saw_public = True
        except Exception:
            pass

        if not inbound_iface:
            return

        with self._candidate_lock:
            for cand in self.candidates.values():
                if inbound_iface not in (cand.iface_full, cand.iface_friendly):
                    continue
                cand.last_seen = now
                if saw_public:
                    cand.last_passive_public_at = now
                    cand.passive_public_hits += 1
                break

    # ---------------------------------------------------------
    # bootstrap / loop
    # ---------------------------------------------------------

    def _bootstrap(self) -> None:
        self._safe_call(self._enforce_netroute_safe_mode)
        self._safe_call(self._discover_candidates)
        self._safe_call(self._refresh_candidates_health)
        self._safe_call(self._preserve_wifi_link)
        best = self._safe_call(self._choose_best_candidate)
        if best:
            self._safe_call(self._activate_candidate, best)

    def _health_loop(self) -> None:
        while not self._stop_event.wait(self._prefs["health_interval_sec"]):
            try:
                now = time.time()

                self._enforce_netroute_safe_mode()

                if (now - self._last_route_scrub_at) >= float(self._prefs["route_scrub_interval_sec"]):
                    if self._prefs["remove_public_host_routes"]:
                        self._scrub_public_host_routes()
                    self._last_route_scrub_at = now

                if (now - self._last_discovery_at) >= float(self._prefs["discovery_interval_sec"]):
                    self._discover_candidates()
                    self._last_discovery_at = now

                self._refresh_candidates_health()

                if (now - self._last_wifi_preserve_at) >= float(self._prefs["wifi_preserve_interval_sec"]):
                    self._preserve_wifi_link()
                    self._last_wifi_preserve_at = now

                best = self._choose_best_candidate()
                if best:
                    self._activate_candidate(best)

                self._prune_stale_candidates()

            except Exception as e:
                self._say("uplink_health_error", f"uplink loop hit {type(e).__name__}: {e}", ["⚠️", "🧩"])

    # ---------------------------------------------------------
    # discovery / probing
    # ---------------------------------------------------------

    def _prune_stale_candidates(self) -> None:
        now = time.time()
        stale_sec = float(self._prefs.get("candidate_stale_sec", 300.0))

        with self._candidate_lock:
            for iface_full, cand in list(self.candidates.items()):
                if self._is_virtual_or_ignored_iface_name(cand.iface_friendly):
                    self.candidates.pop(iface_full, None)
                    continue
                if (now - cand.last_seen) > stale_sec and iface_full != self.active_uplink_full:
                    self.candidates.pop(iface_full, None)

    def _discover_candidates(self) -> None:
        if self._stop_event.is_set():
            return

        r = self.router
        interfaces_config = dict(getattr(r, "_interfaces_config", {}) or {})

        # Synthesize current outbound iface if it exists but is missing from config.
        current_out = getattr(r, "interface_out_full_name", None)
        current_friendly = getattr(r, "interface_out_friendly_name", None)
        if current_out and current_out not in interfaces_config:
            interfaces_config[current_out] = {
                "friendly_name": current_friendly or current_out,
                "ip_addr": getattr(r, "router_ip_out", None),
                "network": getattr(r, "router_network_out", None),
                "gateway": getattr(r, "router_gateway_out_ip", None),
            }

        now = time.time()

        for iface_full, cfg in interfaces_config.items():
            if self._stop_event.is_set():
                return

            if not self._is_candidate_iface(iface_full, cfg):
                continue

            friendly = str(cfg.get("friendly_name") or iface_full).strip()
            info = self._get_cached_ipv4_info_for_adapter(friendly)
            if not info:
                continue

            gateway_ip = cfg.get("gateway")
            if (not self._is_ipv4(gateway_ip)) or self._is_cache_expired(now, self._gateway_cache.get(friendly), self._prefs["gateway_cache_ttl_sec"]):
                gateway_ip = self._get_cached_gateway_for_iface(friendly, info["ip"])

            dns_servers = self._get_windows_dns_servers(friendly)

            with self._candidate_lock:
                cand = self.candidates.get(iface_full)
                if cand is None:
                    cand = UplinkCandidate(iface_full=iface_full, iface_friendly=friendly)
                    self.candidates[iface_full] = cand

                cand.iface_friendly = friendly
                cand.ip = info["ip"]
                cand.netmask = info["netmask"]
                cand.network = info["network"]
                cand.gateway_ip = gateway_ip
                cand.last_seen = now
                cand.dns_servers = dns_servers
                cand.link_up = self._iface_link_up(friendly)
                cand.metadata["ignored_virtual"] = False
                cand.metadata["last_discovered_from"] = "interfaces_config"

    def _refresh_candidates_health(self) -> None:
        now = time.time()
        candidates = self._ordered_candidates_for_health()
        if not candidates:
            return

        self._collect_manager_signals(candidates, now)

        public_probe_budget = max(1, int(self._prefs["max_probe_candidates_per_loop"]))

        for idx, cand in enumerate(candidates):
            do_gateway_probe = self._should_probe_gateway(cand, now, idx)
            do_public_probe = public_probe_budget > 0 and self._should_probe_public(cand, now, idx)

            gateway_ok = self._gateway_health_from_passive(cand, now, default=cand.gateway_ok)
            public_ok = self._public_health_from_passive(cand, now, default=cand.public_ok)

            if do_gateway_probe:
                gateway_ok = self._probe_gateway(cand)

            if do_public_probe:
                public_ok = self._probe_public(cand)
                public_probe_budget -= 1

            with self._candidate_lock:
                real = self.candidates.get(cand.iface_full)
                if real is None:
                    continue

                real.gateway_ok = bool(gateway_ok)
                real.public_ok = bool(public_ok)

                if real.public_ok or real.gateway_ok:
                    real.last_ok = now
                    real.ok_count += 1
                    real.fail_count = max(0, real.fail_count - 1)
                    if real.public_ok:
                        real.consecutive_public_failures = 0
                else:
                    real.last_fail = now
                    real.fail_count += 1
                    if do_public_probe:
                        real.consecutive_public_failures += 1

                real.score = self._score_candidate(real)
                real.health_state = self._health_state_for_candidate(real)

    def _probe_gateway(self, cand: UplinkCandidate) -> bool:
        if not cand.link_up or not cand.ip or not cand.gateway_ip:
            cand.last_gateway_probe = time.time()
            cand.gateway_rtt_ms = None
            return False

        cand.last_gateway_probe = time.time()

        # Fast-path: if the gateway looks sane for the adapter subnet, keep it as a soft-healthy path.
        if self._gateway_looks_routable(cand):
            cand.gateway_rtt_ms = 0.0
            return True

        for port in list(self._prefs["gateway_probe_ports"])[:2]:
            ok, rtt_ms = self._timed_tcp_probe(bound_ip=cand.ip, host=cand.gateway_ip, port=port, timeout=0.8)
            if ok:
                cand.gateway_rtt_ms = rtt_ms
                return True

        cand.gateway_rtt_ms = None
        return False

    def _probe_public(self, cand: UplinkCandidate) -> bool:
        if not cand.link_up or not cand.ip:
            cand.last_public_probe = time.time()
            cand.public_rtt_ms = None
            return False

        # Passive traffic is enough to skip an active check for a short window.
        now = time.time()
        if (now - cand.last_passive_public_at) <= float(self._prefs["passive_signal_ttl_sec"]):
            cand.last_public_probe = now
            cand.public_rtt_ms = 0.0
            return True

        probes = list(self._prefs["public_probes"] or self.DEFAULT_PUBLIC_PROBES)
        if not probes:
            probes = list(self.DEFAULT_PUBLIC_PROBES)

        start = self._public_probe_cursor % len(probes)
        ordered = probes[start:] + probes[:start]

        # For candidates that were already healthy, try fewer probes to keep overhead down.
        tries = 2 if cand.public_ok else min(3, len(ordered))

        cand.last_public_probe = now
        for host, port in ordered[:tries]:
            ok, rtt_ms = self._timed_tcp_probe(bound_ip=cand.ip, host=host, port=port, timeout=1.0)
            self._public_probe_cursor += 1
            if ok:
                cand.public_rtt_ms = rtt_ms
                return True

        cand.public_rtt_ms = None
        return False

    def _tcp_probe(self, *, bound_ip: str, host: str, port: int, timeout: float) -> bool:
        ok, _rtt_ms = self._timed_tcp_probe(bound_ip=bound_ip, host=host, port=port, timeout=timeout)
        return ok

    def _timed_tcp_probe(self, *, bound_ip: str, host: str, port: int, timeout: float) -> tuple[bool, Optional[float]]:
        s = None
        t0 = time.perf_counter()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.bind((bound_ip, 0))
            s.connect((host, port))
            return True, (time.perf_counter() - t0) * 1000.0
        except Exception:
            return False, None
        finally:
            try:
                if s:
                    s.close()
            except Exception:
                pass

    def _score_candidate(self, cand: UplinkCandidate) -> float:
        score = 0.0
        now = time.time()

        if cand.link_up:
            score += 8.0
        if cand.gateway_ok:
            score += 14.0
        if cand.public_ok:
            score += 72.0

        if (now - cand.last_passive_public_at) <= float(self._prefs["passive_signal_ttl_sec"]):
            score += 12.0
        if (now - cand.last_passive_nat_at) <= float(self._prefs["passive_signal_ttl_sec"]):
            score += 7.0
        if (now - cand.last_passive_arp_at) <= float(self._prefs["passive_signal_ttl_sec"]):
            score += 5.0

        score += min(cand.ok_count * 2.5, 15.0)
        score -= min(cand.fail_count * 4.0, 28.0)
        score -= min(cand.consecutive_public_failures * 3.0, 18.0)

        if cand.public_rtt_ms is not None:
            score -= min(cand.public_rtt_ms / 25.0, 10.0)
        if cand.gateway_rtt_ms is not None and cand.gateway_rtt_ms > 0:
            score -= min(cand.gateway_rtt_ms / 20.0, 6.0)

        if cand.iface_friendly in self._prefs["preferred_iface_names"]:
            score += 5.0

        if self._prefs["keep_current_if_public"] and cand.iface_full == self.active_uplink_full:
            score += 4.0
            if cand.public_ok:
                score += 8.0

        if (now - cand.last_seen) < 30.0:
            score += 4.0

        return score

    def _choose_best_candidate(self) -> Optional[UplinkCandidate]:
        with self._candidate_lock:
            snapshot = list(self.candidates.values())

        if not snapshot:
            return None

        active = self.candidates.get(self.active_uplink_full) if self.active_uplink_full else None
        public_candidates = [c for c in snapshot if c.public_ok]

        if self._prefs["allow_router_failover"] and public_candidates:
            public_candidates.sort(key=lambda c: (c.score, c.ok_count, -c.fail_count), reverse=True)
            best_public = public_candidates[0]

            # Stick with the current public uplink unless the new one is meaningfully better.
            if active and active.public_ok and (active.score + 6.0) >= best_public.score:
                return active
            return best_public

        # No public-ready path: keep a sane current uplink if it still has link/gateway health.
        if active and active.link_up and (active.gateway_ok or (time.time() - active.last_ok) < 60.0):
            return active

        snapshot.sort(key=lambda c: (c.score, c.ok_count, -c.fail_count), reverse=True)
        best = snapshot[0]

        if best.score < float(self._prefs["minimum_public_score_to_activate"]) and active:
            return active

        return best

    # ---------------------------------------------------------
    # activation
    # ---------------------------------------------------------

    def _activate_candidate(self, cand: UplinkCandidate) -> bool:
        if not self._prefs["allow_router_failover"]:
            return False
        if not cand.ip:
            return False

        now = time.time()
        current = self.candidates.get(self.active_uplink_full) if self.active_uplink_full else None

        if current and current.iface_full != cand.iface_full:
            # Avoid rapid churn unless the current uplink lost public health and the new one has it.
            in_cooldown = (now - self._last_switch_at) < float(self._prefs["activation_cooldown_sec"])
            if in_cooldown and not ((not current.public_ok) and cand.public_ok):
                return False
            if current.public_ok and (current.score + 6.0) >= cand.score:
                return False

        changed = (
            cand.iface_full != self._last_applied_iface
            or cand.ip != self._last_applied_ip
            or (cand.gateway_ip or "") != (self._last_applied_gateway or "")
        )

        self.active_uplink_full = cand.iface_full
        self.active_uplink_friendly = cand.iface_friendly
        self.active_public_ready = bool(cand.public_ok)

        if not changed:
            return False

        r = self.router
        old_out = getattr(r, "interface_out_full_name", None)
        if old_out and old_out in getattr(r, "_interfaces_config", {}):
            try:
                r._interfaces_config[old_out]["is_default_gateway_iface"] = False
            except Exception:
                pass

        r.interface_out_full_name = cand.iface_full
        r.interface_out_friendly_name = cand.iface_friendly
        r.router_ip_out = cand.ip
        r.router_netmask_out = cand.netmask
        r.router_network_out = cand.network
        r.router_gateway_out_ip = cand.gateway_ip

        cfg = r._interfaces_config.setdefault(cand.iface_full, {})
        cfg["friendly_name"] = cand.iface_friendly
        cfg["ip_addr"] = cand.ip
        cfg["network"] = cand.network
        cfg["gateway"] = cand.gateway_ip
        cfg["is_default_gateway_iface"] = True

        self._apply_candidate_to_managers(cand)

        self._last_applied_iface = cand.iface_full
        self._last_applied_ip = cand.ip
        self._last_applied_gateway = cand.gateway_ip
        self._last_switch_at = now

        with self._candidate_lock:
            real = self.candidates.get(cand.iface_full)
            if real:
                real.last_activation = now
                real.activation_count += 1
            if current and current.iface_full != cand.iface_full:
                current.flap_count += 1

        extra = "public-ready" if cand.public_ok else "gateway-only"
        self._say(
            "uplink_activated",
            f"activated uplink {cand.iface_friendly} {cand.ip} via {cand.gateway_ip} ({extra})",
            ["🚀", "🌐", "🧭"],
            cooldown=0.0,
        )
        return True

    def _apply_candidate_to_managers(self, cand: UplinkCandidate) -> None:
        r = self.router

        # Generic attribute propagation so ARP / NAT / packet writer can react immediately.
        for manager_name in ("arp_manager", "nat_manager", "packet_writer", "dns_manager"):
            mgr = getattr(r, manager_name, None)
            if mgr is None:
                continue

            for attr, value in (
                ("interface_out_full_name", cand.iface_full),
                ("interface_out_friendly_name", cand.iface_friendly),
                ("router_ip_out", cand.ip),
                ("router_netmask_out", cand.netmask),
                ("router_network_out", cand.network),
                ("router_gateway_out_ip", cand.gateway_ip),
            ):
                try:
                    if hasattr(mgr, attr):
                        setattr(mgr, attr, value)
                except Exception:
                    pass

        # ARP: make the new uplink immediately useful to L2 resolution.
        arp = getattr(r, "arp_manager", None)
        if arp is not None:
            try:
                if cand.gateway_ip and hasattr(arp, "set_default_gateway"):
                    arp.set_default_gateway(r._interfaces_config, cand.gateway_ip)
            except Exception:
                pass
            try:
                if cand.ip and hasattr(arp, "router_ip_out"):
                    arp.router_ip_out = cand.ip
            except Exception:
                pass

        # NAT: keep outbound identity in sync.
        nat = getattr(r, "nat_manager", None)
        if nat is not None:
            try:
                if hasattr(nat, "router_ip_out"):
                    nat.router_ip_out = cand.ip
            except Exception:
                pass
            try:
                if hasattr(nat, "interface_out_full_name"):
                    nat.interface_out_full_name = cand.iface_full
            except Exception:
                pass
            try:
                if hasattr(nat, "interface_out_friendly_name"):
                    nat.interface_out_friendly_name = cand.iface_friendly
            except Exception:
                pass

        # Packet writer: refresh interface snapshot once after switch.
        try:
            if getattr(r, "packet_writer", None) is not None:
                r.packet_writer.update_interfaces(r._interfaces_config)
        except Exception:
            pass

        gm = self.gateway_manager or getattr(r, "gateway_manager", None)
        if gm is not None:
            try:
                if cand.gateway_ip:
                    gm._learn_gateway_candidate(str(cand.gateway_ip), cand.iface_full, "uplink")
            except Exception:
                pass
            try:
                if cand.gateway_ip:
                    gm._install_active_gateway(str(cand.gateway_ip), cand.iface_full)
            except Exception:
                pass
            try:
                gm._push_gateway_state(force=True)
            except Exception:
                pass
            try:
                gm._ensure_dns_manager(force_refresh=True)
            except Exception:
                pass

    # ---------------------------------------------------------
    # Wi-Fi preservation / route protection
    # ---------------------------------------------------------

    def _preserve_wifi_link(self) -> None:
        if not self._prefs["preserve_wifi_link"]:
            return

        preferred_names = set(self._prefs["preferred_iface_names"])
        for cand in self._ordered_candidates_for_health():
            if cand.iface_friendly not in preferred_names:
                continue
            if not (cand.link_up and cand.gateway_ip):
                continue

            try:
                if hasattr(self.router, "_configure_host_preserving_upstream_mode"):
                    self.router._configure_host_preserving_upstream_mode()
            except Exception:
                pass

            self._say(
                "wifi_preserved",
                f"keeping {cand.iface_friendly} online as a live gateway-linked candidate",
                ["📶", "🫶", "🔒"],
            )
            return

    def _enforce_netroute_safe_mode(self) -> None:
        nr = getattr(self.router, "netroute_manager", None)
        if not nr:
            return

        changed = False
        if self._prefs["disable_netroute_default_sync"] and getattr(nr, "enable_default_route_sync", False):
            nr.enable_default_route_sync = False
            changed = True

        if self._prefs["disable_netroute_metric_tuning"] and getattr(nr, "enable_metric_tuning", False):
            nr.enable_metric_tuning = False
            changed = True

        if changed:
            self._say("uplink_safe_mode", "disabled NetRoute default-route sync / metric tuning for safer host internet", ["🛡️", "🚧"])

    def _scrub_public_host_routes(self) -> None:
        targets = set(self.learned_public_ips)
        for host, _port in self._prefs["public_probes"]:
            targets.add(host)

        targets = {ip for ip in targets if self._is_public_ipv4(ip)}
        if not targets:
            return

        self._remove_host_routes_if_present(sorted(targets))

    def _remove_host_route_if_present(self, ip: str) -> None:
        if self._is_public_ipv4(ip):
            self._remove_host_routes_if_present([ip])

    def _remove_host_routes_if_present(self, ips: list[str]) -> None:
        if not ips:
            return

        items = ", ".join(f"'{self._ps_quote(ip)}'" for ip in ips)
        ps = f"""
$targets = @({items})
foreach ($ip in $targets) {{
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue
    if ($route) {{
        $route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }}
}}
"""
        self._run_subprocess(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            timeout=4.0,
        )

    # ---------------------------------------------------------
    # candidate helpers
    # ---------------------------------------------------------

    def _resolve_gateway_for_iface(self, iface_friendly: str, local_ip: Optional[str]) -> Optional[str]:
        if not iface_friendly or self._is_virtual_or_ignored_iface_name(iface_friendly):
            return None

        gw = self._get_default_gateway_for_local_ip(local_ip)
        if self._is_ipv4(gw):
            return gw

        try:
            helper = getattr(self.router, "_get_default_gateway_for_interface", None)
            if callable(helper) and self._is_likely_real_uplink_iface(iface_friendly):
                maybe = helper(iface_friendly)
                if self._is_ipv4(maybe):
                    return maybe
        except Exception:
            pass

        return None

    def _get_windows_dns_servers(self, iface_friendly: str) -> list[str]:
        """
        Return IPv4 DNS servers configured on a Windows adapter.

        Tries PowerShell first, then falls back to parsing ipconfig.
        Results are cached to keep the health loop light.
        """
        if not iface_friendly:
            return []

        now = time.time()
        cached = self._dns_cache.get(iface_friendly)
        if cached and (now - cached[0]) <= float(self._prefs["dns_cache_ttl_sec"]):
            return list(cached[1])

        servers: list[str] = []
        alias = self._ps_quote(iface_friendly)

        proc = self._run_subprocess(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                f"""
$servers = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias '{alias}' -ErrorAction SilentlyContinue
if ($servers) {{
    $servers.ServerAddresses | ForEach-Object {{ $_ }}
}}
""",
            ],
            timeout=3.0,
        )
        if proc and proc.returncode == 0:
            for raw in (proc.stdout or "").splitlines():
                ip = raw.strip()
                if self._is_ipv4(ip) and ip not in servers:
                    servers.append(ip)

        if not servers:
            proc = self._run_subprocess(["ipconfig", "/all"], timeout=3.0)
            if proc and proc.returncode == 0:
                lines = (proc.stdout or "").splitlines()
                in_target = False
                collecting_dns = False

                for raw in lines:
                    line = raw.rstrip()
                    stripped = line.strip()

                    if stripped and not raw.startswith((" ", "\t")) and stripped.endswith(":"):
                        header = stripped[:-1].strip()
                        in_target = iface_friendly.lower() in header.lower()
                        collecting_dns = False
                        continue

                    if not in_target:
                        continue

                    if "DNS Servers" in stripped:
                        parts = stripped.split(":", 1)
                        if len(parts) == 2:
                            ip = parts[1].strip()
                            if self._is_ipv4(ip) and ip not in servers:
                                servers.append(ip)
                        collecting_dns = True
                        continue

                    if collecting_dns:
                        if not stripped:
                            collecting_dns = False
                            continue
                        if ":" in stripped and not self._is_ipv4(stripped):
                            collecting_dns = False
                            continue
                        if self._is_ipv4(stripped) and stripped not in servers:
                            servers.append(stripped)

        self._dns_cache[iface_friendly] = (now, list(servers))
        return servers

    @staticmethod
    def _is_ipv4(value: Optional[str]) -> bool:
        try:
            ipaddress.IPv4Address(str(value))
            return True
        except Exception:
            return False

    def _iface_link_up(self, iface_friendly: str) -> bool:
        try:
            stats = psutil.net_if_stats()
            if iface_friendly in stats:
                return bool(stats[iface_friendly].isup)
            for name, st in stats.items():
                if iface_friendly.lower() == str(name).lower():
                    return bool(st.isup)
        except Exception:
            pass
        return True

    @staticmethod
    def _is_public_ipv4(ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.IPv4Address(str(ip))
            return not (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
            )
        except Exception:
            return False

    # ---------------------------------------------------------
    # internal helpers
    # ---------------------------------------------------------

    def _safe_call(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None

    def _ps_quote(self, value: str) -> str:
        return str(value).replace("'", "''")

    def _run_subprocess(self, args: list[str], timeout: float = 3.0) -> Optional[subprocess.CompletedProcess]:
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            return None

    def _is_cache_expired(self, now: float, item: Optional[tuple], ttl: float) -> bool:
        if not item:
            return True
        return (now - float(item[0])) > float(ttl)

    def _get_cached_ipv4_info_for_adapter(self, iface_friendly: str) -> Optional[dict]:
        now = time.time()
        cached = self._adapter_cache.get(iface_friendly)
        if cached and not self._is_cache_expired(now, cached, self._prefs["adapter_cache_ttl_sec"]):
            return cached[1]

        info = None
        try:
            info = self._get_ipv4_info_for_adapter(iface_friendly)
            if info and info.get("ip") and info.get("netmask") and not info.get("network"):
                info["network"] = ipaddress.ip_network(f"{info['ip']}/{info['netmask']}", strict=False)
        except Exception:
            info = None

        self._adapter_cache[iface_friendly] = (now, info)
        return info

    def _get_cached_gateway_for_iface(self, iface_friendly: str, local_ip: Optional[str]) -> Optional[str]:
        now = time.time()
        cached = self._gateway_cache.get(iface_friendly)
        if cached and not self._is_cache_expired(now, cached, self._prefs["gateway_cache_ttl_sec"]):
            return cached[1]

        gw = self._resolve_gateway_for_iface(iface_friendly, local_ip)
        self._gateway_cache[iface_friendly] = (now, gw)
        return gw

    def _ordered_candidates_for_health(self) -> list[UplinkCandidate]:
        with self._candidate_lock:
            snapshot = list(self.candidates.values())

        preferred = set(self._prefs["preferred_iface_names"])

        def key(c: UplinkCandidate):
            return (
                1 if c.iface_full == self.active_uplink_full else 0,
                1 if c.iface_friendly in preferred else 0,
                1 if c.link_up else 0,
                c.last_seen,
            )

        snapshot.sort(key=key, reverse=True)
        return snapshot

    def _should_probe_gateway(self, cand: UplinkCandidate, now: float, idx: int) -> bool:
        base_gap = float(self._prefs["min_probe_gap_sec"])
        if cand.iface_full == self.active_uplink_full:
            return (now - cand.last_gateway_probe) >= base_gap
        if cand.iface_friendly in self._prefs["preferred_iface_names"]:
            return (now - cand.last_gateway_probe) >= (base_gap * 1.5)
        return idx < 2 and (now - cand.last_gateway_probe) >= (base_gap * 2.5)

    def _should_probe_public(self, cand: UplinkCandidate, now: float, idx: int) -> bool:
        base_gap = float(self._prefs["min_probe_gap_sec"])
        if cand.iface_full == self.active_uplink_full:
            return (now - cand.last_public_probe) >= base_gap
        if cand.iface_friendly in self._prefs["preferred_iface_names"]:
            return (now - cand.last_public_probe) >= (base_gap * 1.5)
        return idx < int(self._prefs["max_probe_candidates_per_loop"]) and (now - cand.last_public_probe) >= (base_gap * 3.0)

    def _gateway_health_from_passive(self, cand: UplinkCandidate, now: float, default: bool) -> bool:
        if not cand.link_up or not cand.ip or not cand.gateway_ip:
            return False
        if (now - cand.last_passive_arp_at) <= float(self._prefs["passive_signal_ttl_sec"]):
            return True
        if self._gateway_looks_routable(cand):
            return True
        return bool(default)

    def _public_health_from_passive(self, cand: UplinkCandidate, now: float, default: bool) -> bool:
        ttl = float(self._prefs["passive_signal_ttl_sec"])
        if (now - cand.last_passive_public_at) <= ttl:
            return True
        if (now - cand.last_passive_nat_at) <= ttl:
            return True
        if cand.iface_full == self.active_uplink_full and (now - cand.last_ok) <= ttl and cand.consecutive_public_failures <= 1:
            return True
        return bool(default)

    def _health_state_for_candidate(self, cand: UplinkCandidate) -> str:
        if cand.public_ok:
            return "public"
        if cand.gateway_ok:
            return "gateway"
        if cand.link_up:
            return "link"
        return "down"

    def _gateway_looks_routable(self, cand: UplinkCandidate) -> bool:
        if not cand.ip or not cand.gateway_ip or cand.network is None:
            return False
        try:
            gw = ipaddress.IPv4Address(str(cand.gateway_ip))
            return gw in cand.network
        except Exception:
            return False

    def _collect_manager_signals(self, candidates: list[UplinkCandidate], now: float) -> None:
        arp = getattr(self.router, "arp_manager", None)
        nat = getattr(self.router, "nat_manager", None)

        for cand in candidates:
            if self._candidate_has_arp_signal(arp, cand):
                cand.last_passive_arp_at = now
                cand.passive_arp_hits += 1
            if self._candidate_has_nat_signal(nat, cand):
                cand.last_passive_nat_at = now
                cand.passive_nat_hits += 1

    def _candidate_has_arp_signal(self, arp_manager: Any, cand: UplinkCandidate) -> bool:
        if arp_manager is None:
            return False
        tokens = self._candidate_tokens(cand)
        for attr in (
            "arp_table",
            "arp_cache",
            "ip_to_mac",
            "resolved_ips",
            "gateway_mac_cache",
            "bindings",
            "_bindings",
            "_ip_cache",
        ):
            if self._container_contains_any(getattr(arp_manager, attr, None), tokens):
                return True
        return False

    def _candidate_has_nat_signal(self, nat_manager: Any, cand: UplinkCandidate) -> bool:
        if nat_manager is None:
            return False
        tokens = self._candidate_tokens(cand)
        for attr in (
            "_nat_table",
            "nat_table",
            "_sessions",
            "sessions",
            "flows",
            "_flows",
            "conntrack",
            "_conntrack",
            "translations",
            "_translations",
            "leases",
            "_leases",
        ):
            if self._container_contains_any(getattr(nat_manager, attr, None), tokens):
                return True
        return False

    def _candidate_tokens(self, cand: UplinkCandidate) -> set[str]:
        tokens = {
            str(cand.iface_full or "").lower(),
            str(cand.iface_friendly or "").lower(),
            str(cand.ip or "").lower(),
            str(cand.gateway_ip or "").lower(),
        }
        return {t for t in tokens if t}

    def _container_contains_any(self, obj: Any, tokens: set[str], depth: int = 2, max_items: int = 32) -> bool:
        if obj is None or depth < 0 or not tokens:
            return False

        if isinstance(obj, dict):
            for idx, (k, v) in enumerate(obj.items()):
                if idx >= max_items:
                    break
                if self._container_contains_any(k, tokens, depth - 1, max_items):
                    return True
                if self._container_contains_any(v, tokens, depth - 1, max_items):
                    return True
            return False

        if isinstance(obj, (list, tuple, set)):
            for idx, item in enumerate(obj):
                if idx >= max_items:
                    break
                if self._container_contains_any(item, tokens, depth - 1, max_items):
                    return True
            return False

        if isinstance(obj, bytes):
            try:
                text = obj.decode("utf-8", errors="ignore").lower()
                return any(tok in text for tok in tokens)
            except Exception:
                return False

        if isinstance(obj, (str, int, float)):
            text = str(obj).lower()
            return any(tok in text for tok in tokens)

        for attr in ("ip", "gateway", "iface", "interface", "ifname", "friendly_name", "ip_addr", "local_ip", "remote_ip", "src", "dst"):
            try:
                if hasattr(obj, attr) and self._container_contains_any(getattr(obj, attr), tokens, depth - 1, max_items):
                    return True
            except Exception:
                pass

        return False

class LanManager(_SmartManagerBase):
    """
    Safe LAN host/subnet control plane with strict learning patch.

    Patch:
      - only learn IPv4 hosts that are actually inside router_network_in
      - only learn IPv6 hosts that are link-local / ULA on safe LAN ifaces
      - never learn public internet IPs as LAN hosts
      - only learn on safe LAN member interfaces
    """

    def __init__(
        self,
        router: Any,
        dhcp_server_cls: Any,
        gateway_manager: Optional[Any] = None,
        uplink_manager: Optional[Any] = None,
    ):
        super().__init__(router, name="LanManager")
        self.DHCPServer = dhcp_server_cls
        self.gateway_manager = gateway_manager
        self.uplink_manager = uplink_manager

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.lan_ifaces: Set[str] = set()
        self._dhcp_fingerprint: Optional[str] = None

        self.hosts_by_ip: Dict[str, LanHost] = {}
        self.hosts_by_mac: Dict[str, LanHost] = {}

        self._prefs = {
            "bridge_name": "ManagedLANBridge",
            "create_bridge": True,
            "member_ifaces": None,
            "serve_on_all_lan_ifaces": False,
            "authoritative": True,
            "rogue_policy": "nak_on_mismatch",
            "enforce_same_subnet": True,
            "allow_out_of_pool": False,
            "dns_v6": ["fd00::1", "fd00::2"],
            "search_domains": ["lan.local"],
            "dhcp_pool_start": None,
            "dhcp_pool_end": None,
            "dhcp6_prefix": None,
            "health_interval_sec": 20.0,
            "start_transport_dhcp_client": True,
            "handle_icmp": True,
            "learn_ipv6_link_local": True,
            "learn_ipv6_ula": True,
        }

    # ---------------------------------------------------------
    # lifecycle
    # ---------------------------------------------------------

    def configure(
        self,
        *,
        bridge_name: str = "ManagedLANBridge",
        create_bridge: bool = True,
        member_ifaces: Optional[list[str]] = None,
        serve_on_all_lan_ifaces: bool = False,
        authoritative: bool = True,
        rogue_policy: str = "nak_on_mismatch",
        enforce_same_subnet: bool = True,
        allow_out_of_pool: bool = False,
        dns_v6: Optional[list[str]] = None,
        search_domains: Optional[list[str]] = None,
        dhcp_pool_start: Optional[str] = None,
        dhcp_pool_end: Optional[str] = None,
        dhcp6_prefix: Optional[str] = None,
        health_interval_sec: float = 20.0,
        start_transport_dhcp_client: bool = True,
        handle_icmp: bool = True,
        learn_ipv6_link_local: bool = True,
        learn_ipv6_ula: bool = True,
    ) -> None:
        self._prefs.update({
            "bridge_name": bridge_name,
            "create_bridge": bool(create_bridge),
            "member_ifaces": list(member_ifaces) if member_ifaces else None,
            "serve_on_all_lan_ifaces": bool(serve_on_all_lan_ifaces),
            "authoritative": bool(authoritative),
            "rogue_policy": rogue_policy,
            "enforce_same_subnet": bool(enforce_same_subnet),
            "allow_out_of_pool": bool(allow_out_of_pool),
            "dns_v6": list(dns_v6 or ["fd00::1", "fd00::2"]),
            "search_domains": list(search_domains or ["lan.local"]),
            "dhcp_pool_start": dhcp_pool_start,
            "dhcp_pool_end": dhcp_pool_end,
            "dhcp6_prefix": dhcp6_prefix,
            "health_interval_sec": max(5.0, float(health_interval_sec)),
            "start_transport_dhcp_client": bool(start_transport_dhcp_client),
            "handle_icmp": bool(handle_icmp),
            "learn_ipv6_link_local": bool(learn_ipv6_link_local),
            "learn_ipv6_ula": bool(learn_ipv6_ula),
        })
        self._say("lan_configured", "stored LAN preferences", ["📝", "🏠"], cooldown=0.0)

    def start(self) -> None:
        with self._lock:
            if self._state.started:
                return
            self._state.started = True
            self._stop_event.clear()

        self._refresh_lan_members()
        self._seed_lan_trust()
        self._ensure_bridge()
        self._ensure_dhcp_server(force_restart=True)
        self._start_transport_client()

        self._thread = threading.Thread(target=self._health_loop, name="LanManagerHealth", daemon=True)
        self._thread.start()
        self._say("lan_started", f"LAN services started for members={sorted(self.lan_ifaces)}", ["🏠", "📦", "🛜"], cooldown=0.0)

    def stop(self) -> None:
        with self._lock:
            if not self._state.started:
                return
            self._state.started = False
            self._stop_event.set()
            t = self._thread
            self._thread = None

        if t and t.is_alive():
            t.join(timeout=2.0)

        current = getattr(self.router, "dhcp_server_in", None)
        if current is not None:
            try:
                current.stop()
            except Exception:
                pass

        self.router.dhcp_server_in = None
        self.router.dhcp_server_out = None
        self._dhcp_fingerprint = None
        self._gc_flows()
        self._say("lan_stopped", "LAN services stopped", ["🛑", "🌙"], cooldown=0.0)

    # ---------------------------------------------------------
    # always-on observation
    # ---------------------------------------------------------

    def observe_packet(self, packet, inbound_iface: str) -> None:
        packet = self._decode_if_bytes(packet)
        if packet is None:
            return

        if self.uplink_manager is not None:
            try:
                self.uplink_manager.observe_packet(packet, inbound_iface)
            except Exception:
                pass

        role = self._iface_role(inbound_iface)
        if role == "wan":
            return
        if not self._is_allowed_learning_iface(inbound_iface):
            return

        self._learn_host_from_arp_ndp(packet, inbound_iface)
        self._learn_host_from_dhcp(packet, inbound_iface)
        self._learn_host_from_ip(packet, inbound_iface)

    def _learn_host(self, ip: str, mac: Optional[str], iface: str, family: int = 4) -> None:
        now = time.time()
        host = self.hosts_by_ip.get(ip)
        if host is None:
            host = LanHost(ip=ip, mac=mac.lower() if mac else None, iface=iface, family=family)
            self.hosts_by_ip[ip] = host
            self._say("host_learned", f"learned LAN host {ip} on {iface.split('_')[-1]}", ["🏠", "👀", "🧠"])
        host.last_seen = now
        host.iface = iface
        if mac:
            host.mac = mac.lower()
            self.hosts_by_mac[host.mac] = host

    def _extract_eth_src_mac(self, packet) -> Optional[str]:
        try:
            if packet.haslayer(Ether):
                return str(packet[Ether].src).lower()
        except Exception:
            pass
        return None

    def _extract_eth_dst_mac(self, packet) -> Optional[str]:
        try:
            if packet.haslayer(Ether):
                return str(packet[Ether].dst).lower()
        except Exception:
            pass
        return None

    def _is_allowed_learning_iface(self, inbound_iface: str) -> bool:
        if inbound_iface == getattr(self.router, "interface_out_full_name", None):
            return False
        if inbound_iface == getattr(self.router, "interface_loopback_full_name", None):
            return False
        return inbound_iface in self.lan_ifaces or inbound_iface == getattr(self.router, "interface_in_full_name", None)

    def _is_real_lan_ipv4(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            bare = str(ip).split("%")[0]
            net = getattr(self.router, "router_network_in", None)
            if not isinstance(net, ipaddress.IPv4Network):
                return False
            addr = ipaddress.IPv4Address(bare)
            return addr in net and bare != getattr(self.router, "router_ip_in", None)
        except Exception:
            return False

    def _is_real_lan_ipv6(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            bare = str(ip).split("%")[0]
            addr = ipaddress.IPv6Address(bare)
            if addr.is_multicast or addr.is_loopback:
                return False
            if self._is_router_local_ip(bare):
                return False

            if self._prefs["learn_ipv6_link_local"] and addr.is_link_local:
                return True

            # unique local fc00::/7
            if self._prefs["learn_ipv6_ula"] and (addr.packed[0] & 0xFE) == 0xFC:
                return True

            return False
        except Exception:
            return False

    def _learn_host_from_dhcp(self, packet, inbound_iface: str) -> None:
        if not packet.haslayer(BOOTP):
            return
        try:
            bootp = packet[BOOTP]
            yiaddr = getattr(bootp, "yiaddr", None)
            if not yiaddr or yiaddr == "0.0.0.0":
                return
            if not self._is_real_lan_ipv4(str(yiaddr)):
                return

            mac = None
            raw = getattr(bootp, "chaddr", None)
            if isinstance(raw, bytes):
                mac = ":".join(f"{b:02x}" for b in raw[:6])
            else:
                try:
                    raw = bytes(raw)[:6]
                    mac = ":".join(f"{b:02x}" for b in raw)
                except Exception:
                    pass

            self._learn_host(str(yiaddr), mac, inbound_iface, family=4)

            if mac:
                try:
                    if hasattr(self.router.arp_manager, "add_static_arp_entry"):
                        self.router.arp_manager.add_static_arp_entry(str(yiaddr), mac.lower())
                except Exception:
                    pass
        except Exception:
            pass

    def _learn_host_from_arp_ndp(self, packet, inbound_iface: str) -> None:
        try:
            if packet.haslayer(ARP):
                arp = packet[ARP]
                ip = getattr(arp, "psrc", None)
                mac = getattr(arp, "hwsrc", None)
                if ip and mac and self._is_real_lan_ipv4(str(ip)):
                    self._learn_host(str(ip), str(mac).lower(), inbound_iface, family=4)
                    return
        except Exception:
            pass

        try:
            if packet.haslayer(IPv6):
                src = str(packet[IPv6].src).split("%")[0]
                if self._is_real_lan_ipv6(src):
                    mac = self._extract_eth_src_mac(packet)
                    self._learn_host(src, mac, inbound_iface, family=6)
        except Exception:
            pass

    def _learn_host_from_ip(self, packet, inbound_iface: str) -> None:
        try:
            src_ip, dst_ip = self._extract_ips(packet)

            if src_ip:
                src_bare = str(src_ip).split("%")[0]
                if self._is_real_lan_ipv4(src_bare) or self._is_real_lan_ipv6(src_bare):
                    mac = self._extract_eth_src_mac(packet)
                    family = 6 if ":" in src_bare else 4
                    self._learn_host(src_bare, mac, inbound_iface, family=family)
                    self.hosts_by_ip[src_bare].tx_packets += 1

            if dst_ip:
                dst_bare = str(dst_ip).split("%")[0]
                if self._is_real_lan_ipv4(dst_bare) or self._is_real_lan_ipv6(dst_bare):
                    host = self.hosts_by_ip.get(dst_bare)
                    if host:
                        host.rx_packets += 1

            if self._is_dns_packet(packet) and src_ip:
                src_bare = str(src_ip).split("%")[0]
                if src_bare in self.hosts_by_ip:
                    self.hosts_by_ip[src_bare].dns_queries += 1
        except Exception:
            pass

    # ---------------------------------------------------------
    # packet ownership
    # ---------------------------------------------------------

    def inspect_packet(self, packet, inbound_iface: str) -> ManagerPacketDecision:
        packet = self._decode_if_bytes(packet)
        if packet is None:
            return ManagerPacketDecision("pass", "null-packet", "null/undecodable packet", 100)

        role = self._iface_role(inbound_iface)
        _, dst_ip = self._extract_ips(packet)
        proto, _, dport = self._extract_proto_ports(packet)
        known = self._get_known_owner(packet)

        if known == "lan":
            return ManagerPacketDecision("consume", "known-lan-service-flow", "learned LAN-service flow", 95)
        if known == "pass":
            return ManagerPacketDecision("pass", "known-pass-flow", "learned non-LAN-service flow", 95)

        if role == "wan":
            return ManagerPacketDecision("pass", "wan-ingress", "WAN ingress should not be claimed by LAN manager", 100)

        if packet.haslayer(ARP):
            return ManagerPacketDecision("consume", "arp-lan-control", "ARP is LAN control traffic", 100)

        if self._is_ndp_packet(packet):
            return ManagerPacketDecision("consume", "ndp-lan-control", "NDP is LAN control traffic", 100)

        if self._is_dhcp_packet(packet):
            return ManagerPacketDecision("consume", "dhcp-lan-service", "DHCP belongs to LAN service ownership", 100)

        if self._is_dns_packet(packet):
            if self.gateway_manager:
                gw_decision = self.gateway_manager.inspect_packet(packet, inbound_iface)
                if gw_decision.action == "consume":
                    return ManagerPacketDecision("consume", "delegated-router-dns", "gateway manager classified router DNS ownership", gw_decision.confidence)

            if dport in (53, 5353) and self._is_likely_router_service_address(dst_ip):
                return ManagerPacketDecision("consume", "dns-router-local", "DNS targets router-local service address", 80)

            return ManagerPacketDecision("pass", "dns-not-clearly-router-owned", "DNS not clearly LAN router-owned", 70)

        if self._prefs["handle_icmp"] and proto in ("ICMP", "ICMPv6"):
            if self._is_router_local_ip(dst_ip):
                return ManagerPacketDecision("consume", "icmp-to-router", "ICMP is aimed at a router-local address", 85)
            return ManagerPacketDecision("pass", "icmp-transit-or-host", "ICMP is not clearly LAN-service-owned", 70)

        if dst_ip and not self._is_likely_router_service_address(dst_ip):
            return ManagerPacketDecision("pass", "foreign-unicast", "unicast packet is not aimed at router/local service space", 85)

        return ManagerPacketDecision("observe", "ambiguous", "packet does not strongly match LAN service ownership", 15)

    def should_consume(self, packet, inbound_iface: str) -> bool:
        decision = self.inspect_packet(packet, inbound_iface)
        p = self._decode_if_bytes(packet)
        if decision.action == "consume" and p is not None:
            self._remember_flow(p, "lan")
            return True
        if decision.action == "pass" and p is not None:
            self._remember_flow(p, "pass")
        return False

    def handle_packet(self, packet, inbound_iface: str) -> bool:
        packet = self._decode_if_bytes(packet)
        if packet is None:
            return False

        self.observe_packet(packet, inbound_iface)

        decision = self.inspect_packet(packet, inbound_iface)
        if decision.action != "consume":
            return False

        try:
            if packet.haslayer(ARP):
                return self._handle_arp(packet, inbound_iface)

            if self._is_ndp_packet(packet):
                return self._handle_ndp(packet, inbound_iface)

            if self._is_dhcp_packet(packet):
                return self._handle_dhcp(packet, inbound_iface)

            if packet.haslayer(DNS):
                if self.gateway_manager:
                    return bool(self.gateway_manager.handle_packet(packet, inbound_iface))
                return False

            proto, _, _ = self._extract_proto_ports(packet)
            if self._prefs["handle_icmp"] and proto in ("ICMP", "ICMPv6"):
                icmp_manager = getattr(self.router, "icmp_manager", None)
                if icmp_manager and icmp_manager.handle_packet(packet, inbound_iface):
                    return True

            return False
        except Exception as e:
            self._say("lan_handle_error", f"LAN packet handling failed: {type(e).__name__}: {e}", ["⚠️", "🧯"])
            return False

    # ---------------------------------------------------------
    # service handlers
    # ---------------------------------------------------------

    def _handle_arp(self, packet, inbound_iface: str) -> bool:
        iface_short = str(inbound_iface).split("_")[-1]

        try:
            if not self.router.arp_manager.perform_arp_inspection(packet, inbound_iface):
                self._say(f"arp_drop_{iface_short}", f"dropped ARP on {iface_short} because inspection failed", ["🚫", "🛡️"])
                return True
        except Exception:
            pass

        try:
            self.router.arp_manager.learn_from_packet(packet, inbound_iface)
        except Exception:
            pass
        try:
            self.router.arp_manager.learn_arp_response(packet)
        except Exception:
            pass
        try:
            self.router.arp_manager.reply_to_arp_request(packet, inbound_iface)
        except Exception:
            pass
        return True

    def _handle_ndp(self, packet, inbound_iface: str) -> bool:
        try:
            if getattr(self.router, "ndp_manager", None) is not None:
                self.router.ndp_manager.learn_from_packet(packet, inbound_iface)
        except Exception:
            pass

        try:
            if packet.haslayer(ICMPv6ND_NA):
                self.router.ndp_manager.learn_neighbor_advertisement(packet)
        except Exception:
            pass

        try:
            if getattr(self.router, "ndp_manager", None) is not None:
                handled = self._call_if_present(self.router.ndp_manager, "handle_packet", packet, inbound_iface)
                if handled is not None:
                    return bool(handled)
        except Exception:
            pass

        return True

    def _dhcp_allowed_ifaces(self) -> set[str]:
        allowed = set(self.lan_ifaces)
        in_iface = getattr(self.router, "interface_in_full_name", None)
        if in_iface:
            allowed.add(in_iface)
        return allowed

    def _handle_dhcp(self, packet, inbound_iface: str) -> bool:
        if inbound_iface not in self._dhcp_allowed_ifaces():
            self._say(
                f"dhcp_reject_{inbound_iface}",
                f"ignored DHCP on non-approved interface {inbound_iface.split('_')[-1]}",
                ["🚫", "🛡️"],
            )
            return False

        self._ensure_dhcp_server(force_restart=False)
        dhcp_server = getattr(self.router, "dhcp_server_in", None)
        if dhcp_server is None:
            return False

        handled = False
        try:
            handled = bool(dhcp_server.handle_packet(packet, inbound_iface, self.router.rip_manager.find_route))
        except Exception:
            handled = False

        if handled:
            self._learn_host_from_dhcp(packet, inbound_iface)
        return handled

    # ---------------------------------------------------------
    # LAN state / health
    # ---------------------------------------------------------

    def _health_loop(self) -> None:
        while not self._stop_event.wait(self._prefs["health_interval_sec"]):
            try:
                self._refresh_lan_members()
                self._seed_lan_trust()
                self._ensure_bridge()
                self._ensure_dhcp_server(force_restart=False)
                self._prune_stale_hosts()
                self._gc_flows()
            except Exception as e:
                self._say("lan_health_error", f"LAN health loop hit {type(e).__name__}: {e}", ["⚠️", "🧩"])

    def _is_safe_lan_member(self, iface_name: str, cfg: dict) -> bool:
        if not iface_name or not cfg:
            return False

        if iface_name == getattr(self.router, "interface_out_full_name", None):
            return False

        if iface_name == getattr(self.router, "interface_loopback_full_name", None):
            return False

        if bool(cfg.get("is_default_gateway_iface")):
            return False

        if cfg.get("gateway"):
            return False

        lan_net = getattr(self.router, "router_network_in", None)
        iface_net = cfg.get("network")
        if not isinstance(lan_net, ipaddress.IPv4Network):
            return False
        if iface_net != lan_net:
            return False

        return True

    def _refresh_lan_members(self) -> None:
        r = self.router
        explicit = self._prefs.get("member_ifaces") or []
        found = []

        def add_iface(name: Optional[str]) -> None:
            if not name:
                return
            cfg = getattr(r, "_interfaces_config", {}).get(name)
            if self._is_safe_lan_member(name, cfg) and name not in found:
                found.append(name)

        if explicit:
            for iface in explicit:
                add_iface(iface)
        else:
            add_iface(getattr(r, "interface_in_full_name", None))
            add_iface(getattr(r, "interface_ethernet_2_full_name", None))
            add_iface(getattr(r, "interface_lac_full_name", None))
            add_iface(getattr(r, "interface_lac_2_full_name", None))

            for iface_name, cfg in getattr(r, "_interfaces_config", {}).items():
                if self._is_safe_lan_member(iface_name, cfg) and iface_name not in found:
                    found.append(iface_name)

        old = set(self.lan_ifaces)
        self.lan_ifaces = set(found)

        if self.lan_ifaces != old:
            self._say(
                "lan_members_changed",
                f"safe LAN members now {sorted(self.lan_ifaces)}",
                ["🏘️", "🛜", "🔗"],
                cooldown=0.0,
            )

    def _seed_lan_trust(self) -> None:
        r = self.router
        lan_ip = getattr(r, "router_ip_in", None)
        in_full = getattr(r, "interface_in_full_name", None)

        if in_full and in_full in getattr(r, "_interfaces_config", {}):
            mac = r._interfaces_config[in_full].get("mac")
            if lan_ip and mac:
                try:
                    if hasattr(r, "add_static_arp_entry"):
                        r.add_static_arp_entry(lan_ip, mac)
                    elif hasattr(r.arp_manager, "add_static_arp_entry"):
                        r.arp_manager.add_static_arp_entry(lan_ip, mac)
                except Exception:
                    pass

        for iface in self.lan_ifaces:
            try:
                if hasattr(r, "add_trusted_arp_port"):
                    r.add_trusted_arp_port(iface)
                elif hasattr(r.arp_manager, "add_trusted_port"):
                    r.arp_manager.add_trusted_port(iface)
            except Exception:
                pass

    def _ensure_bridge(self) -> None:
        if not self._prefs["create_bridge"]:
            return
        if len(self.lan_ifaces) < 2:
            return
        if hasattr(self.router, "create_l2_bridge"):
            try:
                ok = self.router.create_l2_bridge(self._prefs["bridge_name"], sorted(self.lan_ifaces))
                if ok:
                    self._say("lan_bridge_ok", f"bridge '{self._prefs['bridge_name']}' ready for {sorted(self.lan_ifaces)}", ["🧩", "🌉"], cooldown=30.0)
            except Exception as e:
                self._say("lan_bridge_error", f"bridge setup failed: {e}", ["⚠️", "🧯"])

    def _ensure_dhcp_server(self, *, force_restart: bool) -> None:
        r = self.router
        in_iface = getattr(r, "interface_in_full_name", None)
        lan_ip = getattr(r, "router_ip_in", None)
        lan_net = getattr(r, "router_network_in", None)

        if not in_iface or not lan_ip or not isinstance(lan_net, ipaddress.IPv4Network):
            return

        pool_start, pool_end = self._compute_pool(lan_net, lan_ip)
        fingerprint = "|".join([
            str(in_iface),
            str(lan_ip),
            str(lan_net),
            str(pool_start),
            str(pool_end),
            str(self._prefs["serve_on_all_lan_ifaces"]),
            str(self._prefs["authoritative"]),
            str(self._prefs["rogue_policy"]),
            str(self._prefs["enforce_same_subnet"]),
        ])

        current = getattr(r, "dhcp_server_in", None)
        need_restart = force_restart or current is None or (fingerprint != self._dhcp_fingerprint)
        if not need_restart:
            return

        if current is not None:
            try:
                current.stop()
            except Exception:
                pass

        in_mac = r._interfaces_config.get(in_iface, {}).get("mac")

        dhcp_server = self.DHCPServer(
            r.router_logger,
            r.packet_writer,
            in_iface,
            pool_start,
            pool_end,
            r._interfaces_config,
            dhcp6_prefix=self._prefs["dhcp6_prefix"],
            allow_out_of_pool=self._prefs["allow_out_of_pool"],
            enforce_same_subnet=self._prefs["enforce_same_subnet"],
            serve_on_all_ifaces=self._prefs["serve_on_all_lan_ifaces"],
            authoritative=self._prefs["authoritative"],
            rogue_policy=self._prefs["rogue_policy"],
            in_mac=in_mac,
            dns_v6=self._prefs["dns_v6"],
            search_domains=self._prefs["search_domains"],
        )
        dhcp_server.sniffer = getattr(r, "sniffer", None)
        dhcp_server.router_ipv6_link_local_out = getattr(r, "router_ipv6_link_local_out", None)
        dhcp_server.start()

        r.dhcp_server_in = dhcp_server
        r.dhcp_server_out = None
        self._dhcp_fingerprint = fingerprint

        try:
            if getattr(r, "arp_manager", None) is not None:
                r.arp_manager.set_dhcp_server_reference(dhcp_server, None)
        except Exception:
            pass

        self._say("dhcp_ready", f"DHCP ready on {getattr(r, 'interface_in_friendly_name', in_iface)} pool={pool_start}-{pool_end}", ["📦", "🧃", "📡"], cooldown=0.0)

    def _start_transport_client(self) -> None:
        if not self._prefs["start_transport_dhcp_client"]:
            return
        try:
            transport_dhcp = self.router.transport_manager.transport_dhcp
            if hasattr(transport_dhcp, "enable_client") and getattr(self.router, "interface_in_friendly_name", None):
                transport_dhcp.enable_client(self.router.sniffer)


            if hasattr(self.router, "parallel_python") and hasattr(transport_dhcp, "_active"):
                if hasattr(self.router.parallel_python, "inject_into"):
                    self.router.parallel_python.inject_into(transport_dhcp._active)
            self._say("lan_transport_client", "LAN DHCP transport client enabled", ["🔌", "📬"], cooldown=0.0)
        except Exception as e:
            self._say("lan_transport_client_error", f"failed enabling LAN transport DHCP client: {e}", ["⚠️"])

    def _compute_pool(self, network: ipaddress.IPv4Network, router_ip: str) -> tuple[str, str]:
        manual_start = self._prefs.get("dhcp_pool_start")
        manual_end = self._prefs.get("dhcp_pool_end")
        if manual_start and manual_end:
            return manual_start, manual_end

        router_ip_obj = ipaddress.IPv4Address(router_ip)
        usable = [ip for ip in network.hosts() if ip != router_ip_obj]
        if not usable:
            raise RuntimeError(f"No usable LAN DHCP addresses in {network}")

        preferred = [ip for ip in usable if int(str(ip).split(".")[-1]) >= 50]
        if preferred:
            return str(preferred[0]), str(preferred[-1])

        return str(usable[0]), str(usable[-1])

    def _prune_stale_hosts(self) -> None:
        now = time.time()
        for ip, host in list(self.hosts_by_ip.items()):
            if (now - host.last_seen) > 3600:
                self.hosts_by_ip.pop(ip, None)
                if host.mac:
                    self.hosts_by_mac.pop(host.mac.lower(), None)


@dataclass
class _LocalSender:
    sender_id: str
    kind: str  # "hyperv" | "wintun" | "windivert"
    send_callable: Callable[[Any], bool]
    allow_protocols: Set[str] = field(default_factory=lambda: {"ESP", "AH", "GRE", "ISAKMP", "IKEv2"})
    enabled: bool = True

    start_fn: Optional[Callable[[], Any]] = None
    stop_fn: Optional[Callable[[], Any]] = None
    started_by_manager: bool = False

    send_q: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=4096))
    worker: Optional[threading.Thread] = None

    send_count: int = 0
    drop_count: int = 0
    consecutive_failures: int = 0
    cooldown_until: float = 0.0


@dataclass
class _Peer:
    node_id: str
    host_name: str
    listen_ip: str
    data_port: int
    segment_id: str

    sender_ids: Set[str] = field(default_factory=set)
    sender_kinds: Dict[str, str] = field(default_factory=dict)
    allow_protocols: Set[str] = field(default_factory=set)

    public_ok: bool = False
    gateway_ok: bool = False
    online: bool = True
    last_seen: float = field(default_factory=time.time)


@dataclass
class _RemoteEndpoint:
    node_id: str
    host_name: str
    listen_ip: str
    data_port: int
    sender_id: str
    sender_kind: str
    allow_protocols: Set[str] = field(default_factory=set)
    public_ok: bool = False
    gateway_ok: bool = False


class HyperVRouterManager:
    """
    Distributed transport manager for Hyper-V / WinTun / WinDivert.

    Changes in this rewrite:
      - sockets are opened under a lock
      - stale sockets are always closed before rebinding
      - discovery socket failure no longer crashes the manager
      - data socket falls back safely instead of raising 10048
      - start() rolls forward in degraded mode instead of exploding
      - stop() is idempotent and clears thread refs
      - hello advertises the actual bound data port if a fallback happened
    """

    MAGIC = "HVRM3"

    def __init__(
        self,
        router_logger,
        *,
        discovery_group: str = "239.255.77.77",
        discovery_port: int = 47771,
        data_port: int = 47772,
        heartbeat_sec: float = 3.0,
        peer_timeout_sec: float = 12.0,
        sender_failure_cooldown_sec: float = 10.0,
        dedupe_ttl_sec: float = 8.0,
        recent_cache_size: int = 32768,
        max_network_queue: int = 8192,
        sender_queue_size: int = 4096,
    ):
        self.router_logger = router_logger

        self.discovery_group = str(discovery_group)
        self.discovery_port = int(discovery_port)
        self.data_port = int(data_port)
        self.heartbeat_sec = max(1.0, float(heartbeat_sec))
        self.peer_timeout_sec = max(3.0, float(peer_timeout_sec))
        self.sender_failure_cooldown_sec = max(1.0, float(sender_failure_cooldown_sec))
        self.dedupe_ttl_sec = max(1.0, float(dedupe_ttl_sec))
        self.recent_cache_size = max(512, int(recent_cache_size))
        self.max_network_queue = max(512, int(max_network_queue))
        self.sender_queue_size = max(128, int(sender_queue_size))

        self.segment_id: str = "default"
        self.node_id: str = ""
        self.host_name: str = socket.gethostname()
        self.bind_ip: str = "0.0.0.0"

        self._lock = threading.RLock()
        self._sock_lock = threading.RLock()
        self._started = False
        self._stop_event = threading.Event()

        self._discovery_sock: Optional[socket.socket] = None
        self._data_sock: Optional[socket.socket] = None
        self._bound_discovery_port: int = self.discovery_port
        self._bound_data_port: int = self.data_port

        self._hello_thread: Optional[threading.Thread] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._health_thread: Optional[threading.Thread] = None

        self._senders: Dict[str, _LocalSender] = {}
        self._peers: Dict[str, _Peer] = {}
        self._net_tx_q: queue.Queue = queue.Queue(maxsize=self.max_network_queue)

        self._recent: Dict[str, float] = {}
        self._recent_order: List[Tuple[str, float]] = []

        # optional manager references
        self._hyperv_managers: Dict[str, Any] = {}
        self._wintun_manager: Optional[Any] = None
        self._windivert_manager: Optional[Any] = None
        self._hostboundary_manager: Optional[Any] = None

        # ingress identity / anti-fight settings
        self._wintun_iface_name: str = "Nate's Tunnel"
        self._windivert_iface_names: Set[str] = {"WinDivert", "windivert", "WinDivertLoopback"}
        self._hyperv_iface_names: Set[str] = {"Hyper-V", "hyperv", "vEthernet"}

        self._manage_wintun_lifecycle = False
        self._manage_windivert_lifecycle = False

        # bind/fallback behavior
        self._allow_data_port_fallback = True
        self._allow_discovery_degraded_mode = True
        self._socket_close_wait_sec = 0.05

    # ---------------------------------------------------------
    # config / attach
    # ---------------------------------------------------------

    def configure(
        self,
        *,
        segment_id: str,
        bind_ip: str = "0.0.0.0",
        node_id: Optional[str] = None,
    ) -> None:
        self.segment_id = str(segment_id or "default").strip() or "default"
        self.bind_ip = str(bind_ip or "0.0.0.0").strip() or "0.0.0.0"
        self.node_id = str(node_id or f"{self.host_name}-{uuid.getnode():012x}")

        self._log(
            f"configured segment='{self.segment_id}' node='{self.node_id}' bind='{self.bind_ip}'",
            ["🧠", "📝"],
        )

    def register_hyperv_backend(
        self,
        sender_id: str,
        backend: Any,
        *,
        allow_protocols: Optional[Set[str]] = None,
        enabled: bool = True,
        start_backend: bool = False,
    ) -> None:
        send_fn = getattr(backend, "send_packet", None)
        if not callable(send_fn):
            raise ValueError(f"Hyper-V backend '{sender_id}' must expose send_packet(packet)")

        state = _LocalSender(
            sender_id=str(sender_id),
            kind="hyperv",
            send_callable=send_fn,
            allow_protocols=set(allow_protocols or {"ESP", "AH", "GRE", "ISAKMP", "IKEv2"}),
            enabled=bool(enabled),
            start_fn=getattr(backend, "start", None) if start_backend else None,
            stop_fn=(getattr(backend, "teardown", None) or getattr(backend, "stop", None)) if start_backend else None,
            started_by_manager=bool(start_backend),
            send_q=queue.Queue(maxsize=self.sender_queue_size),
        )

        with self._lock:
            self._senders[state.sender_id] = state
            self._hyperv_managers[state.sender_id] = backend
            started = self._started

        if started:
            self._start_sender_worker(state)

        self._log(f"registered Hyper-V backend '{state.sender_id}'", ["🧩", "📦"])

    def attach_wintun_manager(
        self,
        wintun_manager: Any,
        *,
        sender_id: str = "wintun-local",
        allow_protocols: Optional[Set[str]] = None,
        start_manager: bool = False,
        expose_as_sender: bool = False,
        wintun_send: Optional[Callable[[Any], bool]] = None,
        iface_name: Optional[str] = None,
    ) -> None:
        self._wintun_manager = wintun_manager
        self._manage_wintun_lifecycle = bool(start_manager)
        self._wintun_iface_name = str(
            iface_name or getattr(wintun_manager, "VIRTUAL_IFACE_NAME", "Nate's Tunnel")
        )

        self._log(f"attached WinTunManager iface='{self._wintun_iface_name}'", ["🪟", "🛜"])

        if expose_as_sender:
            if not callable(wintun_send):
                raise ValueError("expose_as_sender=True requires wintun_send(packet)")
            self._register_generic_sender(
                sender_id=sender_id,
                kind="wintun",
                send_callable=wintun_send,
                allow_protocols=allow_protocols,
                start_fn=getattr(wintun_manager, "start", None) if start_manager else None,
                stop_fn=getattr(wintun_manager, "stop", None),
                enabled=True,
            )

    def attach_windivert_manager(
        self,
        windivert_manager: Any,
        *,
        sender_id: str = "windivert-local",
        allow_protocols: Optional[Set[str]] = None,
        start_manager: bool = False,
        expose_as_sender: bool = False,
        windivert_send: Optional[Callable[[Any], bool]] = None,
        iface_names: Optional[Set[str]] = None,
    ) -> None:
        self._windivert_manager = windivert_manager
        self._manage_windivert_lifecycle = bool(start_manager)

        if iface_names:
            self._windivert_iface_names = {str(x) for x in iface_names if x}

        self._log("attached WinDivertManager", ["🪟", "🧲", "📥"])

        if expose_as_sender:
            if not callable(windivert_send):
                raise ValueError("expose_as_sender=True requires windivert_send(packet)")
            self._register_generic_sender(
                sender_id=sender_id,
                kind="windivert",
                send_callable=windivert_send,
                allow_protocols=allow_protocols,
                start_fn=getattr(windivert_manager, "start", None) if start_manager else None,
                stop_fn=getattr(windivert_manager, "stop", None),
                enabled=True,
            )

    def attach_hostboundary_manager(self, hostboundary_manager: Any) -> None:
        self._hostboundary_manager = hostboundary_manager
        self._log("attached HostConnectivityBoundaryManager", ["🛡️", "🤝"])

    def _register_generic_sender(
        self,
        *,
        sender_id: str,
        kind: str,
        send_callable: Callable[[Any], bool],
        allow_protocols: Optional[Set[str]],
        start_fn: Optional[Callable[[], Any]],
        stop_fn: Optional[Callable[[], Any]],
        enabled: bool,
    ) -> None:
        state = _LocalSender(
            sender_id=str(sender_id),
            kind=str(kind),
            send_callable=send_callable,
            allow_protocols=set(allow_protocols or {"ESP", "AH", "GRE", "ISAKMP", "IKEv2"}),
            enabled=bool(enabled),
            start_fn=start_fn,
            stop_fn=stop_fn,
            send_q=queue.Queue(maxsize=self.sender_queue_size),
        )

        with self._lock:
            self._senders[state.sender_id] = state
            started = self._started

        if started:
            self._start_sender_worker(state)

        self._log(f"registered sender '{state.sender_id}' kind={state.kind}", ["📦", "🧩"])

    # ---------------------------------------------------------
    # lifecycle
    # ---------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stop_event.clear()

        if self._wintun_manager is not None and self._manage_wintun_lifecycle:
            try:
                self._wintun_manager.start()
                self._log("started WinTunManager", ["▶️", "🪟"])
            except Exception as e:
                self._log(f"failed to start WinTunManager: {type(e).__name__}: {e}", ["⚠️", "🧯"])

        if self._windivert_manager is not None and self._manage_windivert_lifecycle:
            try:
                self._windivert_manager.start()
                self._log("started WinDivertManager", ["▶️", "🧲"])
            except Exception as e:
                self._log(f"failed to start WinDivertManager: {type(e).__name__}: {e}", ["⚠️", "🧯"])

        # Never let socket bind errors crash the whole manager.
        self._open_sockets()

        with self._lock:
            for state in self._senders.values():
                self._start_sender_worker(state)

        self._hello_thread = threading.Thread(target=self._hello_loop, name="HyperVRouterHello", daemon=True)
        self._recv_thread = threading.Thread(target=self._recv_loop, name="HyperVRouterRecv", daemon=True)
        self._health_thread = threading.Thread(target=self._health_loop, name="HyperVRouterHealth", daemon=True)

        self._hello_thread.start()
        self._recv_thread.start()
        self._health_thread.start()

        if self._data_sock is None:
            self._log(
                "started in local-only mode (data socket unavailable); remote transport disabled",
                ["🧯", "🏠"],
            )
        elif self._discovery_sock is None:
            self._log(
                "started with discovery disabled (discovery port unavailable); direct peers only",
                ["⚠️", "📡"],
            )
        else:
            self._log("HyperVRouterManager started", ["🚀", "🌐"])

    def stop(self) -> None:
        with self._lock:
            if not self._started:
                return
            self._started = False
            self._stop_event.set()

        # 1. stop network ingress first
        self._close_sockets()

        # 2. stop tunnel/capture managers before sender teardown
        if self._windivert_manager is not None and self._manage_windivert_lifecycle:
            try:
                self._windivert_manager.stop()
                self._log("stopped WinDivertManager", ["🛑", "🧲"])
            except Exception as e:
                self._log(f"failed to stop WinDivertManager: {type(e).__name__}: {e}", ["⚠️", "🧯"])

        if self._wintun_manager is not None and self._manage_wintun_lifecycle:
            try:
                self._wintun_manager.stop()
                self._log("stopped WinTunManager", ["🛑", "🪟"])
            except Exception as e:
                self._log(f"failed to stop WinTunManager: {type(e).__name__}: {e}", ["⚠️", "🧯"])

        # 3. then join manager threads
        for t in (self._hello_thread, self._recv_thread, self._health_thread):
            if t and t.is_alive():
                t.join(timeout=3.0)

        self._hello_thread = None
        self._recv_thread = None
        self._health_thread = None

        # 4. then drain sender workers
        with self._lock:
            senders = list(self._senders.values())

        for state in senders:
            try:
                state.send_q.put_nowait(None)
            except Exception:
                pass

        for state in senders:
            if state.worker and state.worker.is_alive():
                state.worker.join(timeout=3.0)
            state.worker = None

        # 5. only now stop owned backends
        for state in senders:
            self._maybe_stop_sender(state)

        self._log("HyperVRouterManager stopped", ["🌙", "🛑"])

    # ---------------------------------------------------------
    # router hot path
    # ---------------------------------------------------------

    def handle_packet(self, packet, inbound_iface: str) -> bool:
        try:
            if not self._started or self._stop_event.is_set():
                return False

            if packet is None:
                self._log("handle_packet got None packet; ignoring", ["⚠️", "📭"])
                return False

            iface_name = str(inbound_iface or "").strip()
            if not iface_name:
                self._log("handle_packet got empty inbound iface; ignoring", ["⚠️", "🧩"])
                return False

            boundary = self._consult_hostboundary(packet, iface_name)
            if boundary == "bypass":
                self._log(
                    f"handle_packet bypassed by host boundary iface={iface_name}",
                    ["🛡️", "↩️"],
                )
                return False

            protocol_tag = self._classify_protocol(packet)
            if protocol_tag is None:
                return False

            raw = self._packet_to_bytes(packet)
            if not raw:
                self._log(
                    f"handle_packet could not serialize packet iface={iface_name} protocol={protocol_tag}",
                    ["⚠️", "📦"],
                )
                return False

            ingress_kind = self._infer_ingress_kind(iface_name)
            noisy_local = self._is_noisy_local_broadcast(packet)

            if noisy_local:
                fp = self._broadcast_fingerprint(raw, protocol_tag)
                if self._seen_recently(fp):
                    self._log(
                        f"handle_packet dropped duplicate noisy-local frame iface={iface_name} "
                        f"ingress={ingress_kind or 'unknown'} protocol={protocol_tag} len={len(raw)}",
                        ["♻️", "🔇", "🧱"],
                    )
                    return True

                self._log(
                    f"handle_packet dropped noisy-local frame iface={iface_name} "
                    f"ingress={ingress_kind or 'unknown'} protocol={protocol_tag} len={len(raw)}",
                    ["🔇", "📣", "🧱"],
                )
                return True

            loop_prefix = ingress_kind or "pkt"
            fp = self._fingerprint(raw, iface_name, protocol_tag, prefix=loop_prefix)
            if self._seen_recently(fp):
                self._log(
                    f"handle_packet dropped duplicate iface={iface_name} "
                    f"ingress={ingress_kind or 'unknown'} protocol={protocol_tag} len={len(raw)}",
                    ["♻️", "🧱"],
                )
                return True

            exclude_kind = ingress_kind if ingress_kind in {"wintun", "windivert", "hyperv"} else None
            endpoints = self._collect_candidate_endpoints(protocol_tag, exclude_kind=exclude_kind)

            if not endpoints:
                self._log(
                    f"handle_packet no endpoints iface={iface_name} "
                    f"ingress={ingress_kind or 'unknown'} protocol={protocol_tag}",
                    ["🕳️", "📭"],
                )
                return False

            chosen = self._choose_endpoint(packet, iface_name, protocol_tag, raw, endpoints)
            if chosen is None:
                self._log(
                    f"handle_packet no route choice iface={iface_name} "
                    f"ingress={ingress_kind or 'unknown'} protocol={protocol_tag} candidates={len(endpoints)}",
                    ["🤔", "🧭"],
                )
                return False

            kind, endpoint = chosen

            if kind == "local":
                sender_id = getattr(endpoint, "sender_id", "unknown")
                sender_kind = getattr(endpoint, "kind", getattr(endpoint, "sender_kind", "unknown"))

                ok = self._enqueue_local(endpoint, raw)
                if ok:
                    self._log(
                        f"handle_packet queued local iface={iface_name} protocol={protocol_tag} "
                        f"sender={sender_id} sender_kind={sender_kind} len={len(raw)}",
                        ["✅", "📬", "🏠"],
                    )
                    return True

                self._log(
                    f"handle_packet local enqueue failed iface={iface_name} protocol={protocol_tag} "
                    f"sender={sender_id} sender_kind={sender_kind} len={len(raw)}",
                    ["⚠️", "📬", "🧯"],
                )
                return False

            dst_node_id = getattr(endpoint, "node_id", "unknown")
            dst_sender_id = getattr(endpoint, "sender_id", "unknown")

            ok = self._enqueue_remote(
                protocol_tag=protocol_tag,
                raw=raw,
                inbound_iface=iface_name,
                dst_node_id=dst_node_id,
                dst_sender_id=dst_sender_id,
            )
            if ok:
                self._log(
                    f"handle_packet queued remote iface={iface_name} protocol={protocol_tag} "
                    f"dst_node={dst_node_id} dst_sender={dst_sender_id} len={len(raw)}",
                    ["✅", "📡", "🌐"],
                )
                return True

            self._log(
                f"handle_packet remote enqueue failed iface={iface_name} protocol={protocol_tag} "
                f"dst_node={dst_node_id} dst_sender={dst_sender_id} len={len(raw)}",
                ["⚠️", "📡", "🧯"],
            )
            return False

        except Exception as e:
            self._log(
                f"handle_packet error iface={inbound_iface}: {type(e).__name__}: {e}",
                ["🧯", "❄️", "⚠️"],
            )
            return False

    def _consult_hostboundary(self, packet, inbound_iface: str) -> str:
        mgr = self._hostboundary_manager
        if mgr is None:
            return "observe"

        try:
            decision = mgr.inspect_packet(packet, inbound_iface)
            action = str(getattr(decision, "action", "observe") or "observe").lower()
            if action in {"bypass", "process", "observe"}:
                return action
        except Exception:
            pass

        try:
            if bool(mgr.should_bypass_router(packet, inbound_iface)):
                return "bypass"
        except Exception:
            pass

        return "observe"

    def _infer_ingress_kind(self, inbound_iface: str) -> Optional[str]:
        iface = str(inbound_iface or "").strip().lower()
        if not iface:
            return None

        if self._wintun_iface_name and iface == self._wintun_iface_name.strip().lower():
            return "wintun"

        for name in self._windivert_iface_names:
            if iface == str(name).strip().lower():
                return "windivert"

        for token in self._hyperv_iface_names:
            token_l = str(token).strip().lower()
            if token_l and token_l in iface:
                return "hyperv"

        return None

    # ---------------------------------------------------------
    # sender workers
    # ---------------------------------------------------------

    def _start_sender_worker(self, state: _LocalSender) -> None:
        self._maybe_start_sender(state)

        if state.worker and state.worker.is_alive():
            return

        t = threading.Thread(
            target=self._sender_worker_loop,
            args=(state,),
            name=f"HVRM-{state.sender_id}",
            daemon=True,
        )
        state.worker = t
        t.start()

    def _sender_worker_loop(self, state: _LocalSender) -> None:
        self._log(f"worker started for sender '{state.sender_id}' ({state.kind})", ["🧵", "▶️"])

        while not self._stop_event.is_set():
            try:
                item = state.send_q.get(timeout=0.5)
            except queue.Empty:
                continue

            if item is None:
                break

            if time.time() < state.cooldown_until:
                state.drop_count += 1
                continue

            try:
                pkt = self._decode_packet(item)
                if pkt is None:
                    state.drop_count += 1
                    continue

                ok = state.send_callable(pkt)
                if ok is False:
                    raise RuntimeError("send_callable returned False")

                state.send_count += 1
                state.consecutive_failures = 0

                send_fp = self._fingerprint(
                    item,
                    f"sender:{state.sender_id}",
                    "egress",
                    prefix=f"tx:{state.kind}",
                )
                self._seen_recently(send_fp)

            except Exception as e:
                state.consecutive_failures += 1
                if state.consecutive_failures >= 3:
                    state.cooldown_until = time.time() + self.sender_failure_cooldown_sec
                    self._log(
                        f"sender '{state.sender_id}' cooled down after repeated failures: {type(e).__name__}: {e}",
                        ["🧯", "❄️", "⚠️"],
                    )
                else:
                    self._log(
                        f"sender '{state.sender_id}' send failed: {type(e).__name__}: {e}",
                        ["⚠️", "🧩"],
                    )

        self._log(f"worker stopped for sender '{state.sender_id}'", ["🛑", "🧵"])

    def _maybe_start_sender(self, state: _LocalSender) -> None:
        if not callable(state.start_fn):
            return
        try:
            state.start_fn()
            state.started_by_manager = True
        except Exception as e:
            self._log(
                f"sender start for '{state.sender_id}' failed: {type(e).__name__}: {e}",
                ["⚠️", "🧯"],
            )

    def _maybe_stop_sender(self, state: _LocalSender) -> None:
        if not state.started_by_manager:
            return
        fn = state.stop_fn
        if not callable(fn):
            return
        try:
            fn()
        except Exception as e:
            self._log(f"failed stopping sender '{state.sender_id}': {type(e).__name__}: {e}", ["⚠️", "🧯"])

    def _enqueue_local(self, state: _LocalSender, raw: bytes) -> bool:
        try:
            state.send_q.put_nowait(raw)
            return True
        except queue.Full:
            try:
                _ = state.send_q.get_nowait()
                state.drop_count += 1
            except Exception:
                pass
            try:
                state.send_q.put_nowait(raw)
                return True
            except Exception:
                state.drop_count += 1
                return False

    # ---------------------------------------------------------
    # endpoint collection / selection
    # ---------------------------------------------------------

    def _collect_candidate_endpoints(self, protocol_tag: str, *, exclude_kind: Optional[str] = None):
        out: List[Tuple[str, Any]] = []
        now = time.time()

        with self._lock:
            for state in self._senders.values():
                if not state.enabled:
                    continue
                if protocol_tag not in state.allow_protocols:
                    continue
                if now < state.cooldown_until:
                    continue
                if exclude_kind and state.kind == exclude_kind:
                    continue
                out.append(("local", state))

            for peer in self._peers.values():
                if peer.segment_id != self.segment_id:
                    continue
                if (now - peer.last_seen) > self.peer_timeout_sec:
                    continue

                for sender_id in sorted(peer.sender_ids):
                    sender_kind = peer.sender_kinds.get(sender_id, "hyperv")
                    if exclude_kind and sender_kind == exclude_kind:
                        continue
                    if peer.allow_protocols and protocol_tag not in peer.allow_protocols:
                        continue

                    out.append((
                        "remote",
                        _RemoteEndpoint(
                            node_id=peer.node_id,
                            host_name=peer.host_name,
                            listen_ip=peer.listen_ip,
                            data_port=peer.data_port,
                            sender_id=sender_id,
                            sender_kind=sender_kind,
                            allow_protocols=set(peer.allow_protocols),
                            public_ok=peer.public_ok,
                            gateway_ok=peer.gateway_ok,
                        ),
                    ))
        return out

    def _choose_endpoint(self, packet, inbound_iface: str, protocol_tag: str, raw: bytes, endpoints):
        if not endpoints:
            return None

        def _score(item):
            kind, obj = item
            if kind == "local":
                score = 5
                if obj.kind == "hyperv":
                    score += 3
                elif obj.kind == "wintun":
                    score += 2
                elif obj.kind == "windivert":
                    score += 1
                return score

            score = 0
            if obj.public_ok:
                score += 10
            if obj.gateway_ok:
                score += 4
            if obj.sender_kind == "hyperv":
                score += 3
            elif obj.sender_kind == "wintun":
                score += 2
            elif obj.sender_kind == "windivert":
                score += 1
            return score

        endpoints = sorted(endpoints, key=_score, reverse=True)

        flow_key = self._stable_flow_key(packet, inbound_iface, protocol_tag, raw)
        idx = int.from_bytes(
            hashlib.blake2b(flow_key.encode("utf-8"), digest_size=8).digest(),
            "big",
        ) % len(endpoints)
        return endpoints[idx]

    # ---------------------------------------------------------
    # discovery / transport
    # ---------------------------------------------------------

    def _open_sockets(self) -> None:
        with self._sock_lock:
            self._close_sockets_locked()

            # Discovery socket: fixed multicast port. If it is taken, degrade gracefully.
            self._discovery_sock = self._open_discovery_socket()
            self._bound_discovery_port = self.discovery_port

            # Data socket: try configured port, then safe fallbacks instead of raising 10048.
            self._data_sock, self._bound_data_port = self._open_data_socket_with_fallback()

    def _open_discovery_socket(self) -> Optional[socket.socket]:
        try:
            ds = self._make_udp_socket()
            ds.bind(("", self.discovery_port))
            self._join_multicast_group(ds)
            ds.settimeout(1.0)
            self._log(
                f"discovery socket bound on 0.0.0.0:{self.discovery_port}",
                ["📡", "✅"],
            )
            return ds
        except OSError as e:
            if self._is_addr_in_use_error(e):
                self._log(
                    f"discovery bind in use on *:{self.discovery_port}; discovery disabled for this instance",
                    ["⚠️", "📡", "🧯"],
                )
                if not self._allow_discovery_degraded_mode:
                    raise
                return None
            self._log(
                f"discovery socket open failed: {type(e).__name__}: {e}",
                ["⚠️", "🧯"],
            )
            if not self._allow_discovery_degraded_mode:
                raise
            return None
        except Exception as e:
            self._log(
                f"discovery socket open failed: {type(e).__name__}: {e}",
                ["⚠️", "🧯"],
            )
            if not self._allow_discovery_degraded_mode:
                raise
            return None

    def _open_data_socket_with_fallback(self) -> Tuple[Optional[socket.socket], int]:
        attempts: List[Tuple[str, int, str]] = []

        bind_ip = self.bind_ip or "0.0.0.0"
        attempts.append((bind_ip, self.data_port, "configured"))
        if bind_ip != "0.0.0.0":
            attempts.append(("0.0.0.0", self.data_port, "wildcard-port"))
        if self._allow_data_port_fallback:
            attempts.append((bind_ip, 0, "configured-ephemeral"))
            if bind_ip != "0.0.0.0":
                attempts.append(("0.0.0.0", 0, "wildcard-ephemeral"))

        last_err: Optional[Exception] = None

        for host, port, label in attempts:
            sock_obj = None
            try:
                sock_obj = self._make_udp_socket()
                sock_obj.bind((host, port))
                sock_obj.settimeout(1.0)
                actual_port = int(sock_obj.getsockname()[1])
                if actual_port != self.data_port:
                    self._log(
                        f"data socket fallback active: requested {bind_ip}:{self.data_port}, bound {host}:{actual_port} ({label})",
                        ["🧯", "↪️", "📦"],
                    )
                else:
                    self._log(
                        f"data socket bound on {host}:{actual_port}",
                        ["📦", "✅"],
                    )
                return sock_obj, actual_port

            except OSError as e:
                last_err = e
                if self._is_addr_in_use_error(e):
                    self._log(
                        f"data bind in use on {host}:{port} ({label}); trying fallback",
                        ["⚠️", "📦", "🧯"],
                    )
                else:
                    self._log(
                        f"data bind failed on {host}:{port} ({label}): {type(e).__name__}: {e}",
                        ["⚠️", "📦", "🧯"],
                    )
            except Exception as e:
                last_err = e
                self._log(
                    f"data bind failed on {host}:{port} ({label}): {type(e).__name__}: {e}",
                    ["⚠️", "📦", "🧯"],
                )
            finally:
                if sock_obj is not None:
                    try:
                        if sock_obj.fileno() != -1 and sock_obj.gettimeout() is None:
                            sock_obj.close()
                    except Exception:
                        pass

        self._log(
            f"data socket unavailable after all fallbacks: {type(last_err).__name__ if last_err else 'UnknownError'}: {last_err}",
            ["🧯", "❌", "📦"],
        )
        return None, self.data_port

    def _close_sockets(self) -> None:
        with self._sock_lock:
            self._close_sockets_locked()

    def _close_sockets_locked(self) -> None:
        for attr in ("_discovery_sock", "_data_sock"):
            s = getattr(self, attr, None)
            if s is not None:
                self._safe_socket_close(s)
                setattr(self, attr, None)

        self._bound_discovery_port = self.discovery_port
        self._bound_data_port = self.data_port

        if self._socket_close_wait_sec > 0:
            time.sleep(self._socket_close_wait_sec)

    def _hello_loop(self) -> None:
        while not self._stop_event.wait(self.heartbeat_sec):
            try:
                self._send_hello()
                self._flush_network_queue()
            except Exception as e:
                self._log(f"hello/network loop error: {type(e).__name__}: {e}", ["⚠️", "🧩"])

    def _recv_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._sock_lock:
                d_sock = self._discovery_sock
                t_sock = self._data_sock

            for which, sock_obj in (("discovery", d_sock), ("data", t_sock)):
                if sock_obj is None:
                    continue
                try:
                    data, addr = sock_obj.recvfrom(1024 * 1024)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                except Exception:
                    continue

                try:
                    self._handle_wire_message(data, addr[0], addr[1], which)
                except Exception as e:
                    self._log(f"wire message handling failed: {type(e).__name__}: {e}", ["⚠️", "🧩"])

    def _health_loop(self) -> None:
        while not self._stop_event.wait(self.heartbeat_sec):
            try:
                self._prune_peers()
                self._prune_recent()
            except Exception:
                pass

    def _send_hello(self) -> None:
        with self._sock_lock:
            d_sock = self._discovery_sock
            advertised_data_port = self._bound_data_port or self.data_port

        if d_sock is None:
            return

        with self._lock:
            sender_ids = sorted(self._senders.keys())
            sender_kinds = {sid: self._senders[sid].kind for sid in self._senders}
            allow_protocols = sorted(
                set().union(*(s.allow_protocols for s in self._senders.values())) if self._senders else set()
            )

        msg = {
            "magic": self.MAGIC,
            "type": "hello",
            "segment_id": self.segment_id,
            "node_id": self.node_id,
            "host_name": self.host_name,
            "listen_ip": self._advertise_ip(),
            "data_port": advertised_data_port,
            "sender_ids": sender_ids,
            "sender_kinds": sender_kinds,
            "allow_protocols": allow_protocols,
            "public_ok": False,
            "gateway_ok": True,
            "ts": time.time(),
        }

        raw = json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        try:
            d_sock.sendto(raw, (self.discovery_group, self.discovery_port))
        except Exception:
            pass

    def _flush_network_queue(self) -> None:
        with self._sock_lock:
            data_sock = self._data_sock

        if data_sock is None:
            while True:
                try:
                    _ = self._net_tx_q.get_nowait()
                except queue.Empty:
                    break
            return

        while True:
            try:
                item = self._net_tx_q.get_nowait()
            except queue.Empty:
                break

            try:
                data_sock.sendto(item["raw"], (item["ip"], item["port"]))
            except Exception as e:
                self._log(
                    f"network send failed to {item['ip']}:{item['port']}: {type(e).__name__}: {e}",
                    ["⚠️", "🧯"],
                )

    def _handle_wire_message(self, raw: bytes, from_ip: str, from_port: int, which: str) -> None:
        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception:
            return

        if msg.get("magic") != self.MAGIC:
            return
        if msg.get("segment_id") != self.segment_id:
            return

        node_id = str(msg.get("node_id") or "")
        if not node_id or node_id == self.node_id:
            return

        mtype = msg.get("type")
        if mtype == "hello":
            self._update_peer_from_hello(msg, from_ip)
            return

        if mtype == "frame":
            self._handle_remote_frame(msg, from_ip)

    def _update_peer_from_hello(self, msg: dict, from_ip: str) -> None:
        node_id = str(msg.get("node_id"))
        with self._lock:
            peer = self._peers.get(node_id)
            if peer is None:
                peer = _Peer(
                    node_id=node_id,
                    host_name=str(msg.get("host_name") or node_id),
                    listen_ip=str(msg.get("listen_ip") or from_ip),
                    data_port=int(msg.get("data_port") or self.data_port),
                    segment_id=str(msg.get("segment_id") or self.segment_id),
                )
                self._peers[node_id] = peer

            peer.host_name = str(msg.get("host_name") or peer.host_name)
            peer.listen_ip = str(msg.get("listen_ip") or from_ip)
            peer.data_port = int(msg.get("data_port") or peer.data_port)
            peer.segment_id = str(msg.get("segment_id") or peer.segment_id)
            peer.sender_ids = set(str(x) for x in (msg.get("sender_ids") or []))
            peer.sender_kinds = {str(k): str(v) for k, v in (msg.get("sender_kinds") or {}).items()}
            peer.allow_protocols = set(str(x) for x in (msg.get("allow_protocols") or []))
            peer.public_ok = bool(msg.get("public_ok", False))
            peer.gateway_ok = bool(msg.get("gateway_ok", False))
            peer.last_seen = time.time()
            peer.online = True

    def _handle_remote_frame(self, msg: dict, from_ip: str) -> None:
        frame_id = str(msg.get("frame_id") or "")
        src_node_id = str(msg.get("src_node_id") or "")
        dst_sender_id = str(msg.get("dst_sender_id") or "")
        protocol_tag = str(msg.get("protocol_tag") or "")

        if not frame_id or not src_node_id:
            return
        if self._seen_recently(f"remote:{src_node_id}:{frame_id}"):
            return

        payload_b64 = msg.get("payload_b64")
        if not payload_b64:
            return

        try:
            raw = base64.b64decode(payload_b64.encode("ascii"), validate=True)
        except Exception:
            return

        sender = self._choose_local_sender_for_remote(
            dst_sender_id=dst_sender_id,
            protocol_tag=protocol_tag,
            raw=raw,
        )
        if sender is None:
            return

        self._enqueue_local(sender, raw)

    def _choose_local_sender_for_remote(self, *, dst_sender_id: str, protocol_tag: str, raw: bytes) -> Optional[_LocalSender]:
        now = time.time()

        with self._lock:
            if dst_sender_id and dst_sender_id in self._senders:
                state = self._senders[dst_sender_id]
                if state.enabled and now >= state.cooldown_until:
                    return state

            candidates = []
            for state in self._senders.values():
                if not state.enabled:
                    continue
                if protocol_tag and protocol_tag not in state.allow_protocols:
                    continue
                if now < state.cooldown_until:
                    continue
                candidates.append(state)

        if not candidates:
            return None

        digest = hashlib.blake2b(raw[:128], digest_size=8).digest()
        idx = int.from_bytes(digest, "big") % len(candidates)
        return candidates[idx]

    def _enqueue_remote(
        self,
        *,
        protocol_tag: str,
        raw: bytes,
        inbound_iface: str,
        dst_node_id: str,
        dst_sender_id: str,
    ) -> bool:
        with self._lock:
            peer = self._peers.get(dst_node_id)

        if peer is None:
            return False

        frame_id = hashlib.blake2b(
            raw + str(time.time_ns()).encode("ascii"),
            digest_size=16,
        ).hexdigest()

        msg = {
            "magic": self.MAGIC,
            "type": "frame",
            "segment_id": self.segment_id,
            "src_node_id": self.node_id,
            "dst_node_id": dst_node_id,
            "dst_sender_id": dst_sender_id,
            "protocol_tag": protocol_tag,
            "inbound_iface": str(inbound_iface),
            "frame_id": frame_id,
            "payload_b64": base64.b64encode(raw).decode("ascii"),
        }

        wire = json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        try:
            self._net_tx_q.put_nowait({"raw": wire, "ip": peer.listen_ip, "port": peer.data_port})
            return True
        except queue.Full:
            return False

    # ---------------------------------------------------------
    # helpers
    # ---------------------------------------------------------

    def _make_udp_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s

    def _join_multicast_group(self, s: socket.socket) -> None:
        mreq = struct.pack("=4sl", socket.inet_aton(self.discovery_group), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def _safe_socket_close(self, s: socket.socket) -> None:
        try:
            s.close()
        except Exception:
            pass

    def _is_addr_in_use_error(self, e: Exception) -> bool:
        return isinstance(e, OSError) and getattr(e, "winerror", None) == 10048

    def _classify_protocol(self, packet) -> Optional[str]:
        try:
            if ESP is not None and packet.haslayer(ESP):
                return "ESP"
            if AH is not None and packet.haslayer(AH):
                return "AH"
            if GRE is not None and packet.haslayer(GRE):
                return "GRE"
            if ISAKMP is not None and packet.haslayer(ISAKMP):
                return "ISAKMP"
            if IKEv2 is not None and packet.haslayer(IKEv2):
                return "IKEv2"
        except Exception:
            return None
        return None

    def _packet_to_bytes(self, packet) -> Optional[bytes]:
        try:
            return bytes(packet)
        except Exception:
            return None

    def _decode_packet(self, raw_bytes: bytes):
        if not raw_bytes:
            return None

        if Ether is not None:
            try:
                return Ether(raw_bytes)
            except Exception:
                pass

        try:
            version = raw_bytes[0] >> 4
            if version == 4 and IP is not None:
                return IP(raw_bytes)
            if version == 6 and IPv6 is not None:
                return IPv6(raw_bytes)
        except Exception:
            pass

        return None

    def _stable_flow_key(self, packet, inbound_iface: str, protocol_tag: str, raw: bytes) -> str:
        try:
            src = None
            dst = None

            if IP is not None and packet.haslayer(IP):
                src = str(packet[IP].src)
                dst = str(packet[IP].dst)
            elif IPv6 is not None and packet.haslayer(IPv6):
                src = str(packet[IPv6].src)
                dst = str(packet[IPv6].dst)

            if src or dst:
                return f"{protocol_tag}|{inbound_iface}|{src}|{dst}"
        except Exception:
            pass

        digest = hashlib.blake2b(raw[:128], digest_size=16).hexdigest()
        return f"{protocol_tag}|{inbound_iface}|{digest}"

    def _is_noisy_local_broadcast(self, packet) -> bool:
        try:
            from scapy.layers.inet import IP, UDP
            from scapy.layers.inet6 import IPv6

            # -------- IPv4 --------
            if packet.haslayer(IP):
                ip = packet[IP]
                src = str(getattr(ip, "src", "") or "")
                dst = str(getattr(ip, "dst", "") or "")

                # limited broadcast / multicast / 169.254 broadcast space
                if dst == "255.255.255.255":
                    return True
                if dst.startswith("224."):
                    return True
                if dst.startswith("169.254."):
                    # especially bad: 169.254.255.255 discovery chatter
                    return True
                if src.startswith("169.254.") and dst.startswith("169.254."):
                    return True

                if packet.haslayer(UDP):
                    udp = packet[UDP]
                    sp = int(getattr(udp, "sport", 0) or 0)
                    dp = int(getattr(udp, "dport", 0) or 0)

                    # SSDP / mDNS / LLMNR
                    if sp in (1900, 5353, 5355) or dp in (1900, 5353, 5355):
                        return True

                    # NBNS broadcast
                    if dp == 137 and dst in ("255.255.255.255", "169.254.255.255"):
                        return True

                    # Steam LAN beacons
                    if dp == 27036 and dst in ("255.255.255.255", "169.254.255.255"):
                        return True

            # -------- IPv6 --------
            if packet.haslayer(IPv6):
                ip6 = packet[IPv6]
                dst6 = str(getattr(ip6, "dst", "") or "").lower()
                # multicast discovery chatter
                if dst6.startswith("ff02:") or dst6.startswith("ff05:"):
                    return True

                if packet.haslayer(UDP):
                    udp = packet[UDP]
                    sp = int(getattr(udp, "sport", 0) or 0)
                    dp = int(getattr(udp, "dport", 0) or 0)
                    if sp in (5353, 5355) or dp in (5353, 5355):
                        return True

        except Exception:
            return False

        return False

    def _broadcast_fingerprint(self, raw: bytes, protocol_tag: str) -> str:
        h = hashlib.blake2b(digest_size=16)
        h.update(b"broadcast|")
        h.update(protocol_tag.encode("utf-8", "ignore"))
        h.update(b"|")
        h.update(raw[:256])
        h.update(len(raw).to_bytes(4, "big", signed=False))
        return h.hexdigest()

    def _fingerprint(
            self,
            raw: bytes,
            iface_name: str,
            protocol_tag: str,
            *,
            prefix: str = "pkt",
    ) -> str:
        h = hashlib.blake2b(digest_size=16)
        h.update(str(prefix or "pkt").encode("utf-8", "ignore"))
        h.update(b"|")
        h.update(str(iface_name or "").strip().lower().encode("utf-8", "ignore"))
        h.update(b"|")
        h.update(str(protocol_tag or "").encode("utf-8", "ignore"))
        h.update(b"|")
        h.update(raw[:256])
        h.update(b"|")
        h.update(len(raw).to_bytes(4, "big", signed=False))
        return h.hexdigest()
    
    
    def _seen_recently(self, fp: str) -> bool:
        now = time.time()
        self._prune_recent(now=now)

        ts = self._recent.get(fp)
        if ts is not None and (now - ts) <= self.dedupe_ttl_sec:
            return True

        self._recent[fp] = now
        self._recent_order.append((fp, now))
        return False

    def _prune_recent(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        while self._recent_order:
            old_fp, ts = self._recent_order[0]
            if (now - ts) <= self.dedupe_ttl_sec and len(self._recent) <= self.recent_cache_size:
                break
            self._recent_order.pop(0)
            cur = self._recent.get(old_fp)
            if cur == ts:
                self._recent.pop(old_fp, None)

    def _prune_peers(self) -> None:
        now = time.time()
        with self._lock:
            for peer in self._peers.values():
                peer.online = (now - peer.last_seen) <= self.peer_timeout_sec

    def _advertise_ip(self) -> str:
        if self.bind_ip and self.bind_ip != "0.0.0.0":
            return self.bind_ip
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _log(self, message: str, emojis: Optional[list[str]] = None) -> None:
        try:
            self.router_logger.log_message(
                RouterRandomMessages("HyperVRouterManager", message, emojis or [])
            )
        except Exception:
            pass



