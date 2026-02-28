import binascii
import hashlib
import hmac
import queue
import random
import re
import ssl
import subprocess
import uuid
import zlib
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field
from enum import auto, Enum
from functools import reduce
from typing import Optional, List, Any, Dict, Tuple, Literal, Callable, Set, Iterable
import ipaddress
import time

import psutil
import requests
import zmq
from scapy.arch import get_windows_if_list
from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3mq
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6, DHCP6_RelayForward, DHCP6_Advertise, DHCP6_Reply, DHCP6_Solicit, DHCP6OptIA_NA, \
    DUID_LLT, DHCP6OptServerId, DHCP6_InfoRequest, DHCP6_Request, DHCP6OptClientId, DHCP6OptDNSServers, \
    DHCP6OptDNSDomains, DHCP6OptInfoRefreshTime, DHCP6OptIAAddress, DHCP6_Renew, DHCP6_Confirm, DHCP6_Release, \
    DHCP6_Decline, DHCP6_RelayReply, DHCP6OptStatusCode
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import ICMP, IPOption_Router_Alert
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, ICMPv6ND_RA, ICMPv6MLReport, ICMPv6MLReport2, ICMPv6MLDone, \
    IPv6ExtHdrHopByHop, RouterAlert, ICMPv6NDOptDstLLAddr, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NS
from scapy.layers.l2 import ARP, getmacbyip
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

from p2pool_tools import RandomXLoader, RandomXFlags
from scapy.layers.inet6 import ICMPv6NDOptPrefixInfo

from p2pool_sniffer import DNSRR_AAAA, ICMPv6

bind_layers(ICMPv6ND_RA, ICMPv6NDOptPrefixInfo)

# -------------------------------------------------------------------
# MLDv1 (Query/Report/Done) — light shims if your Scapy lacks them
# -------------------------------------------------------------------



class ConnectionState(Enum):
    """Represents the explicit state of the direct pool connection."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    STOPPING = auto()

class ZMQReader:
    """
    A dedicated thread for subscribing to monerod's ZeroMQ feed.
    Forwards received messages to a callback function.
    """
    def __init__(self,
                 zmq_address: str,
                 message_handler: Callable[[bytes], None],
                 logger: Any):
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
        socket.setsockopt(zmq.SUBSCRIBE, b"json-minimal-txpool_add")
        socket.setsockopt(zmq.SUBSCRIBE, b"json-full-txpool_add")
        socket.setsockopt(zmq.SUBSCRIBE, b"json-minimal-block")
        socket.setsockopt(zmq.SUBSCRIBE, b"json-full-block")
        socket.setsockopt(zmq.SUBSCRIBE, b"json-minimal-miner_data")
        socket.setsockopt(zmq.SUBSCRIBE, b"json-full-miner_data")
        socket.RCVTIMEO = 500  # ms (so we can check stop flag regularly)

        try:
            socket.connect(self.zmq_address)
            while not self._stop_event.is_set():
                try:
                    # Try multipart first (topic, payload)
                    frames = socket.recv_multipart(flags=0)  # blocks up to RCVTIMEO
                    if not frames:
                        continue

                    if len(frames) >= 2:
                        # Normalize to "topic payload" so existing handler keeps working
                        topic = frames[0]
                        payload = b" ".join(frames[1:])  # in case of >2 frames
                        self.message_handler(topic + b" " + payload)
                    else:
                        # Single-frame: could be "topic:payload" or just "topic"
                        self.message_handler(frames[0])

                except zmq.Again:
                    continue
                except Exception as e:
                    self.logger.log_message(f"[ZMQ] ❌ Error receiving message: {e}")
        except zmq.ZMQError as e:
            self.logger.log_message(f"[ZMQ] ❌ Failed to connect to ZMQ socket: {e}")
        finally:
            socket.close(0)
            context.term()


class MoneroDaemonManager:
    """
    Talks to monerod: listens for ZMQ notifications, fetches new block templates via RPC,
    distributes jobs to Stratum, and submits blocks found by workers.
    """

    NONCE_BYTE_OFFSET = 39
    DEFAULT_RESERVE_SIZE = 60
    _DAEMON_SESSION_ID = "daemon_local"

    def __init__(
        self,
        code_output_manager,
        daemon_url: str,
        zmq_address: str,
        stratum_conn_manager: "StratumConnectionManager",
        logger: Any,
        reserve_size: int = DEFAULT_RESERVE_SIZE,
    ):
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
        self._last_distributed_fingerprint = None
        # IMPORTANT: attach submitter for the daemon session specifically
        self.stratum_conn_manager.stratum_manager.attach_submitter(
            self._DAEMON_SESSION_ID, self.submit_block_to_daemon
        )
        self.code_output_manager = code_output_manager
    # ----- Lifecycle -----

    def start(self) -> None:
        if self._running:
            self.logger.log_message("[Daemon] Manager is already running.")
            return
        self._running = True
        self._stop_event.clear()

        # Start ZMQ and do an initial template fetch
        self.zmq_reader.start()
        threading.Thread(target=self._initial_job_fetch, daemon=True).start()
        self.logger.log_message("[Daemon] Listening for ZMQ messages...")

    def stop(self) -> None:
        if not self._running:
            return
        self.logger.log_message("[Daemon] Stopping manager...")
        self._running = False
        self._stop_event.set()
        self.zmq_reader.stop()

        # Stop the daemon-local share worker in StratumManager
        try:
            self.stratum_conn_manager.stratum_manager.deregister_session(self._DAEMON_SESSION_ID)
        except Exception as e:
            self.logger.log_message(f"[Daemon] ⚠️ Failed to stop Stratum worker: {e}")

        self.logger.log_message("[Daemon] Manager stopped.")

    def _initial_job_fetch(self):
        self.logger.log_message("[Daemon] Performing initial job fetch via RPC...")
        try:
            self._fetch_and_distribute_job()
        except Exception as e:
            self.logger.log_message(f"[Daemon] ❌ Initial job fetch failed: {e}")

    # ----- ZMQ -----

    def _handle_zmq_message(self, raw_message: bytes):
        """
        Handles monerod ZMQ publications for:
          - block/json-full-chain_main/json-minimal-block
          - txpool_add/json-*-txpool_add
          - miner_data/json-*-miner_data
        Accepts both multipart (normalized by ZMQReader) and single-frame "topic:payload".
        """
        try:
            topic, payload = self._split_topic_payload(raw_message)
            nt = self._norm_topic(topic)

            # Topic families (normalized with underscores)
            block_topics = {
                b"block",
                b"json_full_chain_main",
                b"json_minimal_chain_main",
                b"json_full_block",
                b"json_minimal_block",
            }
            tx_topics = {b"txpool_add", b"json_full_txpool_add", b"json_minimal_txpool_add"}
            miner_topics = {b"miner_data", b"json_full_miner_data", b"json_minimal_miner_data"}

            def _debounced_refresh(label: str, min_interval: float = 0.5):
                now = time.time()
                last = getattr(self, "_last_template_refresh", 0.0)
                if now - last >= min_interval:
                    setattr(self, "_last_template_refresh", now)
                    self.logger.log_message(f"[Daemon] ZMQ {label} → fetching template...")
                    threading.Thread(target=self._fetch_and_distribute_job, daemon=True).start()

            # ---------- Decode JSON if present ----------
            j = None
            if payload and payload.lstrip()[:1] in (b"{", b"["):
                try:
                    j = json.loads(payload.decode("utf-8", "ignore"))
                except Exception:
                    j = None

            # ---------- Miner data ----------
            if nt in miner_topics:
                # Example keys: height, seed_hash, difficulty (hex), median_weight, tx_backlog[...]
                height = None
                seed_hash = None
                diff_int = None
                backlog_n = None
                try:
                    if isinstance(j, dict):
                        height = j.get("height")
                        seed_hash = j.get("seed_hash")
                        diff_raw = j.get("difficulty")
                        if isinstance(diff_raw, str):
                            diff_int = int(diff_raw, 16) if diff_raw.startswith(("0x", "0X")) else int(diff_raw)
                        backlog = j.get("tx_backlog")
                        backlog_n = len(backlog) if isinstance(backlog, list) else None
                except Exception:
                    pass

                # Optional: refresh template—miner_data changes (seed/diff) imply new job economics
                _debounced_refresh("miner_data", min_interval=1.0)

                # Surface for UI/metrics
                try:
                    self.code_output_manager.submit_packet(
                        {
                            "topic": topic.decode("utf-8", "ignore"),
                            "height": height,
                            "seed_hash": seed_hash,
                            "difficulty": diff_int,
                            "tx_backlog_len": backlog_n,
                        },
                        inbound_iface="daemon",
                        phase="handled",
                        component="daemon-miner-data",
                    )
                except Exception:
                    pass

                self.logger.log_message(
                    f"[Daemon] ZMQ miner_data h={height} diff={diff_int} backlog={backlog_n}"
                )
                return

            # ---------- Block / chain_main ----------
            if nt in block_topics:
                _debounced_refresh("new block")

                height = None
                block_hash = None
                reward = None
                ts = int(time.time())
                tx_count = None

                if isinstance(j, dict):
                    height = self._peek(j, "height", ("block_header", "height"))
                    block_hash = self._peek(j, "hash", ("block_header", "hash"))
                    reward = self._peek(j, "reward", ("block_header", "reward"), "block_reward")
                    ts = self._peek(j, "timestamp", ("block_header", "timestamp"), default=ts)
                    txs_hashes = self._peek(j, "tx_hashes")
                    txs_full = self._peek(j, "txs")
                    if isinstance(txs_hashes, list):
                        tx_count = len(txs_hashes)
                    elif isinstance(txs_full, list):
                        tx_count = len(txs_full)

                elif isinstance(j, list) and j:
                    # json-full-chain_main sometimes emits a one-element array
                    elem = j[0] if isinstance(j[0], dict) else None
                    if elem:
                        height = self._peek(elem, "height", ("block_header", "height"))
                        block_hash = self._peek(elem, "hash", ("block_header", "hash"))
                        reward = self._peek(elem, "reward", ("block_header", "reward"), "block_reward")
                        ts = self._peek(elem, "timestamp", ("block_header", "timestamp"), default=ts)
                        txs_hashes = self._peek(elem, "tx_hashes")
                        txs_full = self._peek(elem, "txs")
                        if isinstance(txs_hashes, list):
                            tx_count = len(txs_hashes)
                        elif isinstance(txs_full, list):
                            tx_count = len(txs_full)

                # Update local chain snapshot for stale analytics
                try:
                    if height is not None:
                        self._last_block_height = int(height)
                    self._last_block_ts = float(ts) if ts is not None else time.time()
                except Exception:
                    pass

                # Optional UI packet
                try:
                    self.code_output_manager.submit_packet(
                        {
                            "topic": topic.decode("utf-8", "ignore"),
                            "height": height,
                            "hash": block_hash,
                            "reward": reward,
                            "tx_count": tx_count,
                            "timestamp": ts,
                        },
                        inbound_iface="daemon",
                        phase="handled",
                        component="daemon-block",
                    )
                except Exception:
                    pass

                h_disp = f"h={height}" if height is not None else "h=?"
                tx_disp = f", txs={tx_count}" if tx_count is not None else ""
                rw_disp = f", reward={reward}" if reward is not None else ""
                self.logger.log_message(f"[Daemon] ZMQ block {h_disp}{tx_disp}{rw_disp}")
                return

            # ---------- Tx pool add ----------
            if nt in tx_topics:
                _debounced_refresh("txpool_add")
                tx_hash = fee = size = receive_time = None

                if isinstance(j, dict):
                    tx_hash = self._peek(j, "tx_hash", "hash")
                    fee = self._peek(j, "fee", ("tx", "rct_signatures", "fee"))
                    size = self._peek(j, "size", ("tx", "size"))
                    receive_time = self._peek(j, "receive_time", "timestamp")
                else:
                    # Fallback for bare "txpool_add" (non-JSON): payload is often raw 32-byte txid
                    try:
                        # our ZMQReader joined extra frames already; if you change it to keep frames,
                        # handle the second frame explicitly here
                        if payload and len(payload) in (32, 64):  # 32 bytes or 64 hex chars
                            tx_hash = payload.hex() if len(payload) == 32 else payload.decode("ascii", "ignore")
                        elif payload and all(c in b"0123456789abcdef" for c in payload.strip().lower()) and len(
                                payload.strip()) in (64, 66):
                            tx_hash = payload.strip().decode("ascii", "ignore").lstrip("0x")
                    except Exception:
                        pass

                h = (tx_hash[:10] + "…") if isinstance(tx_hash, str) and len(tx_hash) > 10 else (tx_hash or "?")
                self.logger.log_message(f"[Daemon] ZMQ txpool_add tx={h} fee={fee} size={size}")
                return

            # ---------- Unknown topic ----------
            if payload:
                if payload.lstrip()[:1] in (b"{", b"["):
                    try:
                        jj = json.loads(payload.decode("utf-8", "ignore"))
                        k = list(jj) if isinstance(jj, dict) else (["list"] if isinstance(jj, list) else [])
                        self.logger.log_message(f"[Daemon] ZMQ {topic!r} (json keys={k[:4]})")
                    except Exception:
                        self.logger.log_message(f"[Daemon] ZMQ {topic!r} ({len(payload)}B json-like payload)")
                else:
                    self.logger.log_message(f"[Daemon] ZMQ {topic!r} ({len(payload)}B non-json payload)")
            else:
                self.logger.log_message(f"[Daemon] ZMQ {topic!r} (no payload)")

        except Exception as e:
            self.logger.log_message(f"[Daemon] ⚠️ Malformed ZMQ message received: {e}")

    @staticmethod
    def _norm_topic(t: bytes) -> bytes:
        # Lowercase and unify separators so json-full-chain_main == json-full-chain-main
        return t.strip().lower().replace(b"-", b"_")

    @staticmethod
    def _split_topic_payload(raw: bytes) -> tuple[bytes, bytes]:
        """
        Accepts:
          • "topic payload"
          • "topic:payload"
          • "topic" (no payload)
        Returns (topic, payload)
        """
        raw = (raw or b"").strip()
        if not raw:
            return b"", b""

        # Prefer space once (older code path)
        if b" " in raw:
            t, p = raw.split(b" ", 1)
            return t.strip(), p

        # Fallback: colon form (as seen in your logs)
        i = raw.find(b":")
        if i != -1:
            t, p = raw[:i], raw[i + 1:]
            return t.strip(), p

        # Topic only
        return raw, b""
    @staticmethod
    def _peek(d: dict, *keys, default=None):
        """Try multiple paths; returns first found non-None value."""
        for k in keys:
            try:
                # support nested "a.b.c" or tuple path
                if isinstance(k, (tuple, list)):
                    cur = d
                    ok = True
                    for part in k:
                        if not isinstance(cur, dict) or part not in cur:
                            ok = False
                            break
                        cur = cur[part]
                    if ok and cur is not None:
                        return cur
                elif isinstance(k, str) and "." in k:
                    cur = d
                    ok = True
                    for part in k.split("."):
                        if not isinstance(cur, dict) or part not in cur:
                            ok = False
                            break
                        cur = cur[part]
                    if ok and cur is not None:
                        return cur
                else:
                    if isinstance(d, dict) and k in d and d[k] is not None:
                        return d[k]
            except Exception:
                pass
        return default
    # ----- RPC -----

    def _rpc_call(self, method: str, params: Optional[Any] = None) -> Dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        payload = {"jsonrpc": "2.0", "id": "0", "method": method, "params": params or {}}
        r = requests.post(f"{self.daemon_url}/json_rpc", data=json.dumps(payload), headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
        if "error" in data and data["error"]:
            err = data["error"]
            code = err.get("code")
            msg = err.get("message") or str(err)
            raise RuntimeError(f"RPC {method} error {code}: {msg}")
        return data

    # ----- Template fetch / distribution -----
    def _tpl_fingerprint(self, *, height: int, prev_hash: str, seed_hash: str | None,
                         target_hex: str, blob_hex: str) -> tuple:
        # short, stable de-dup key
        try:
            import hashlib
            h8 = hashlib.blake2b(bytes.fromhex(blob_hex), digest_size=8).hexdigest()
        except Exception:
            h8 = hex(len(blob_hex) // 2)[2:]
        return (int(height), (prev_hash or "")[:16], (seed_hash or "")[:16], target_hex[:16], h8)

    # --- replace _fetch_and_distribute_job with this version (or merge diffs) ---
    def _fetch_and_distribute_job(self) -> None:
        wa = (self.stratum_conn_manager.wallet_address or "").strip()
        if not wa:
            self.logger.log_message("[Daemon] ❌ No wallet_address configured; cannot request block template.")
            return

        reserve = int(self.reserve_size)
        if reserve < 0 or reserve > 127:
            self.logger.log_message(f"[Daemon] ⚠️ reserve_size {reserve} out of range; clamping to 60.")
            reserve = 60

        params = {"wallet_address": wa, "reserve_size": reserve}

        try:
            resp = self._rpc_call("get_block_template", params)
            res = resp.get("result") or {}
            needed = ("blocktemplate_blob", "height")
            if not all(k in res for k in needed):
                self.logger.log_message("[Daemon] ⚠️ Template missing required fields (daemon syncing or wrong net?).")
                return

            tpl = RandomXLoader.norm_hex(res["blocktemplate_blob"])
            if not tpl or (len(tpl) % 2 != 0):
                self.logger.log_message("[Daemon] ⚠️ Invalid blocktemplate_blob from daemon.")
                return

            # Difficulty (prefer wide_difficulty, accept hex or decimal)
            D = None
            wide = res.get("wide_difficulty")
            if isinstance(wide, (str, int)) and str(wide).strip():
                ws = str(wide).strip()
                try:
                    D = int(ws, 16) if ws.lower().startswith("0x") else int(ws)
                except Exception:
                    D = None
            if D is None:
                low = int(res.get("difficulty", 0))
                high = int(res.get("difficulty_top64", 0))
                D = (high << 64) | low
            if not isinstance(D, int) or D <= 0:
                self.logger.log_message("[Daemon] ⚠️ Difficulty missing/invalid.")
                return

            height = int(res["height"])
            seed_hash = RandomXLoader.norm_hex(res.get("seed_hash"))
            seed_height = res.get("seed_height")
            prev_hash = RandomXLoader.norm_hex(res.get("prev_hash")) or ""
            reserved_offset = int(res.get("reserved_offset", 0))

            # Compute target from difficulty (LE hex, 32 bytes)
            target_hex = RandomXLoader.target_hex_from_difficulty(D)
            if not isinstance(target_hex, str) or len(target_hex) not in (16, 64):
                self.logger.log_message("[Daemon] ⚠️ Computed target has unexpected length.")
                return

            # Sanity: Nonce position and reserve bounds
            blob_len_bytes = len(tpl) // 2
            nonce_off = self.NONCE_BYTE_OFFSET
            if blob_len_bytes < (nonce_off + 4):
                self.logger.log_message("[Daemon] ⚠️ Blob too short to contain nonce at expected offset.")
                return

            # Validate reserve window
            reserve_size = int(self.reserve_size)
            if reserve_size < 0: reserve_size = 0
            if reserved_offset <= 0:
                # Older/alt nodes may omit; fall back to end of blob
                reserved_offset = blob_len_bytes  # no reserved region in coinbase extra
            if reserved_offset + reserve_size > blob_len_bytes:
                new_size = max(0, blob_len_bytes - reserved_offset)
                self.logger.log_message(
                    f"[Daemon] ⚠️ reserve window {reserved_offset}+{reserve_size} > {blob_len_bytes}; clamping to {new_size}."
                )
                reserve_size = new_size

            # De-dup identical templates (height/prev/seed/target/blob hash)
            fp = self._tpl_fingerprint(height=height, prev_hash=prev_hash, seed_hash=seed_hash,
                                       target_hex=target_hex, blob_hex=tpl)
            if fp == getattr(self, "_last_distributed_fingerprint", None):
                self.logger.log_message("[Daemon] ⏸️ Template unchanged; not redistributing job.")
                return
            self._last_distributed_fingerprint = fp

            # Synthesize job_id
            job_id = f"daemon-{height}-{prev_hash[:16]}-{int(time.time() * 1000) % 1_000_000:06d}"

            # Stratum job payload (carry useful extras)
            stratum_job = {
                "id": job_id,
                "blob": tpl,
                "target": target_hex,
                "height": height,
                "difficulty": D,
                "seed_hash": seed_hash,
                "seed_height": seed_height,
                "prev_hash": prev_hash,
                "reserved_offset": reserved_offset,
                "reserve_size": reserve_size,
                # Optional: some pools like to see where the nonce is (debug/metrics)
                "nonce_byte_offset": self.NONCE_BYTE_OFFSET,
            }

            # Cache + distribute
            self._templates_by_job_id[job_id] = tpl
            self._difficulty_by_job_id[job_id] = D
            self._cleanup_templates()

            self.stratum_conn_manager.distribute_job_from_daemon(stratum_job)
            self.code_output_manager.submit_packet(
                {
                    "job_id": job_id,
                    "height": height,
                    "difficulty": D,
                    "target": target_hex,
                    "seed_hash": seed_hash,
                    "prev_hash": prev_hash,
                    "reserved_offset": reserved_offset,
                    "reserve_size": reserve_size,
                },
                inbound_iface="daemon",
                phase="handled",
                component="daemon-job",
            )
            self.logger.log_message(
                f"[Daemon] ✅ Distributed new job {job_id} (h={height}, diff={D}, seed={str(seed_hash)[:12]}…)."
            )

        except requests.exceptions.RequestException as e:
            self.logger.log_message(f"[Daemon] ❌ Network error fetching template: {e}")
        except Exception as e:
            self.logger.log_message(f"[Daemon] ❌ Error preparing job: {type(e).__name__}: {e}")
    # ----- Submission -----

    def submit_block_to_daemon(self, job_id: str, nonce: str, result_hash: str) -> None:
        try:

            tpl = self._templates_by_job_id.get(job_id)
            if not tpl:
                self.logger.log_message(f"[Daemon] ⚠️ Missing template for job {job_id}; unable to submit.")
                return

            nonce = RandomXLoader.norm_hex(nonce)
            if not nonce or len(nonce) != 8:
                raise ValueError(f"Invalid nonce hex (need 8 chars LE): {nonce!r}")

            off = self.NONCE_BYTE_OFFSET * 2  # hex chars index
            if len(tpl) < off + 8:
                raise ValueError("Template blob too short to write nonce.")

            full_blob_hex = tpl[:off] + nonce + tpl[off + 8:]

            # Optional: client-side difficulty check before RPC submit
            difficulty = self._difficulty_by_job_id.get(job_id)
            if difficulty:
                t_int = RandomXLoader.target_from_difficulty_int(difficulty)
                hb = bytes.fromhex(result_hash)
                if int.from_bytes(hb, "little") > t_int:
                    self.logger.log_message(f"[Daemon] ⚠️ Share for job {job_id} doesn’t meet difficulty. Not submitting.")
                    return
                self.logger.log_message(f"[Daemon] Verifying share for job {job_id} meets difficulty {difficulty}.")

            resp = self._rpc_call("submit_block", [full_blob_hex])
            status = (resp.get("result") or {}).get("status", "")
            if status.upper() == "OK":
                self.logger.log_message(f"[Daemon] ✅ Block accepted by daemon for job {job_id}.")
                self._templates_by_job_id.pop(job_id, None)
                self._difficulty_by_job_id.pop(job_id, None)
            else:
                err = resp.get("error") or {}
                self.logger.log_message(f"[Daemon] ❗ Block submission not OK for job {job_id}: {status or err}")
            self.code_output_manager.submit_packet(
                {
                    "job_id": job_id,
                    "nonce": nonce,
                    "result_hash": result_hash,
                    "status": status,
                },
                inbound_iface="daemon",
                phase="handled",
                component="daemon-submit"
            )
        except requests.exceptions.RequestException as e:
            self.logger.log_message(f"[Daemon] ❌ Network error submitting block: {e}")
        except Exception as e:
            self.logger.log_message(f"[Daemon] ❌ Error submitting block: {type(e).__name__}: {e}")

    # ----- Cache -----

    def _cleanup_templates(self):
        # keep cache bounded
        if len(self._templates_by_job_id) > 100:
            oldest = next(iter(self._templates_by_job_id))
            self._templates_by_job_id.pop(oldest, None)
            self._difficulty_by_job_id.pop(oldest, None)
            self.logger.log_message("[Daemon] Cleaning up old block template cache.")



class StratumConnectionManager:
    """
    Dual-mode Stratum proxy + direct-pool connector.
    Forwards parsed messages to StratumManager; accepts local jobs from MoneroDaemonManager.
    """
    MONERO_ALLOWED_METHODS = {"login", "submit", "job", "keepalived", "getjob"}
    LIKELY_TLS_PORTS = {443, 3333, 5555, 7443, 8443}

    def __init__(self, code_output_manager, router_logger: Any, stratum_manager: "StratumManager", packet_processor_callback: Callable):
        import threading as _th
        self.logger = router_logger
        self.stratum_manager = stratum_manager
        self.packet_processor = packet_processor_callback
        self.code_output_manager = code_output_manager
        # Proxy listener
        self.proxy_host = "127.0.0.1"
        self.proxy_port = 3333

        # Pool config
        self.pool_ip: Optional[str] = None
        self.pool_port: Optional[int] = None
        self.pool_host: Optional[str] = None  # For TLS SNI
        self.use_tls: str | bool = "auto"
        self.wallet_address: Optional[str] = None
        self.worker_name = "default"
        self.user_agent = "pystratum/0.5-synergy"

        # State
        self._threads: list[_th.Thread] = []
        self._active_sockets: list[socket.socket] = []
        self._stop_event = _th.Event()
        self._lock = _th.Lock()
        self._pending_by_id: Dict[int, str] = {}

        # Direct connection
        self._direct_conn_state = ConnectionState.DISCONNECTED
        self.direct_session_id: Optional[str] = None
        self._pool_socket: Optional[socket.socket] = None
        self.KEEPALIVE_INTERVAL_S = 30
        self._next_keepalive_ts = 0.0

        # NEW: track upstream pool session ids for proxy sessions
        self._proxy_session_ids: Dict[str, str] = {}

        self.logger.log_message("[StratumConn] ⛏️ Synergized Dual-Mode Manager initialized.")

    # ----- Config / lifecycle -----

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
        self.pool_port = pool_port
        self.wallet_address = wallet
        self.worker_name = worker
        self.proxy_port = listen_port
        self.use_tls = use_tls
        self.pool_host = pool_host or pool_ip
        if user_agent:
            self.user_agent = user_agent

        self.logger.log_message(
            f"[StratumConn] 🎯 Configured for pool {self.pool_ip}:{self.pool_port} "
            f"(TLS={self.use_tls}, SNI={self.pool_host}). "
            f"Proxy listening on {self.proxy_host}:{self.proxy_port}"
        )

        # Ensure RandomX is ready before work arrives
        self.stratum_manager.rx_start()

    def start(self) -> None:
        if not all([self.pool_ip, self.wallet_address, self.pool_port]):
            self.logger.log_message("[StratumConn] ❌ Cannot start: Configuration is incomplete.")
            return
        if self._threads:
            self.logger.log_message("[StratumConn] Manager is already running.")
            return

        self._stop_event.clear()
        t1 = threading.Thread(target=self._direct_connection_loop, daemon=True, name="StratumDirectConnector")
        t2 = threading.Thread(target=self._listen_for_miners, daemon=True, name="StratumProxyListener")
        self._threads.extend([t1, t2])
        t1.start()
        t2.start()

    def stop(self) -> None:
        if not self._threads:
            return
        self.logger.log_message("[StratumConn] 🛑 Stopping all operations...")
        self._stop_event.set()
        self.stratum_manager.stop()

        for s in list(self._active_sockets):
            self._close_socket(s)

        for t in self._threads:
            if t.is_alive():
                t.join(timeout=2)
        self._threads.clear()
        self.logger.log_message("[StratumConn] ✅ All operations stopped.")


    def handle_packet(self, packet: "Any", inbound_iface: str = "stratum") -> bool:
        """
        Lightweight ingress for Stratum-like traffic coming from the router pipeline/sniffer.
        Forwards JSON-RPC bytes to StratumManager.handle_packet with a stable session_id.

        Returns True if this looked like Stratum and was forwarded/consumed; False otherwise.
        """
        try:
            # Fast-path: direct byte/str/dict events from other components
            if isinstance(packet, (bytes, bytearray)):
                self.stratum_manager.handle_packet(bytes(packet), session_id="stratum/default")
                return True
            if isinstance(packet, str):
                self.stratum_manager.handle_packet(packet.encode("utf-8", "ignore"), session_id="stratum/default")
                return True
            if isinstance(packet, dict):
                # Common envelope fields (payload/data/message/raw/body)
                for k in ("payload", "data", "message", "raw", "body"):
                    if k in packet:
                        v = packet[k]
                        if isinstance(v, (bytes, bytearray)):
                            self.stratum_manager.handle_packet(bytes(v), session_id="stratum/default")
                            return True
                        if isinstance(v, str):
                            self.stratum_manager.handle_packet(v.encode("utf-8", "ignore"),
                                                               session_id="stratum/default")
                            return True
                # Already-parsed JSON-RPC dict/list? Forward as-is.
                self.stratum_manager.handle_packet(packet, session_id="stratum/default")
                return True

            # Scapy path (TCP only)
            if not hasattr(packet, "haslayer"):
                return False

            # Import lazily to avoid top-level dependency
            try:
                from scapy.layers.inet import IP, TCP
                from scapy.layers.inet6 import IPv6
                from scapy.packet import Raw
            except Exception:
                return False

            if not packet.haslayer(TCP):
                return False

            tcp = packet[TCP]
            sport = int(tcp.sport)
            dport = int(tcp.dport)

            # Only consider flows that touch our known Stratum endpoints
            relevant_ports = {self.proxy_port}
            if self.pool_port:
                relevant_ports.add(int(self.pool_port))
            if sport not in relevant_ports and dport not in relevant_ports:
                return False

            # Need payload
            if not packet.haslayer(Raw):
                self._rl_log("no_raw",
                             f"[StratumConn] ⚠️ handle_packet: TCP flow {sport}->{dport} has no Raw payload; skipping.")
                return False

            raw = packet[Raw].load
            if not raw:
                self._rl_log("empty_raw",
                             f"[StratumConn] ⚠️ handle_packet: Empty TCP payload on {sport}->{dport}; skipping.")
                return False

            # Quick sniff: if it obviously isn't JSON at start, it's likely TLS or binary → ignore.
            # (We still let direct socket loops handle the true upstream pool traffic.)
            first = raw[:1]
            if first not in (b"{", b"["):
                # Occasionally pools send \n-delimited JSON preceded by whitespace
                peek = raw.lstrip()[:1]
                if peek not in (b"{", b"["):
                    # Not JSON-looking; treat as non-Stratum content on these ports.
                    self._rl_log("non_json",
                                 f"[StratumConn] ℹ️ Non-JSON TCP bytes on {sport}->{dport}; probable TLS/binary. Suppressing.")
                    return False

            # Build a stable session id from the 5-tuple so multiple miners are isolated
            sip, dip = None, None
            if packet.haslayer(IP):
                ip = packet[IP]
                sip, dip = ip.src, ip.dst
            elif packet.haslayer(IPv6):
                ip6 = packet[IPv6]
                sip, dip = ip6.src, ip6.dst
            sess = self._flow_session_id(sip, sport, dip, dport)

            # Forward just the bytes to StratumManager (it will buffer & parse)
            self.stratum_manager.handle_packet(bytes(raw), session_id=sess)
            # Optional: mirror to code_output_manager for visibility
            try:
                self.code_output_manager.submit_packet(
                    bytes(raw),
                    inbound_iface=inbound_iface,
                    phase="ingress",
                    component="stratum-conn"
                )
            except Exception:
                pass
            return True

        except Exception as e:
            self.logger.log_message(f"[StratumConn] ❗ handle_packet error: {type(e).__name__}: {e}")
            return False

    def _flow_session_id(self, sip: "Optional[str]", sport: int, dip: "Optional[str]", dport: int) -> str:
        """
        Deterministic session id for proxy/upstream flows so per-miner buffers don't collide.
        """
        # Tag direction to keep client/server halves distinct if needed
        if sip and dip:
            return f"flow/{sip}:{sport}->{dip}:{dport}"
        return "stratum/default"

    def _rl_log(self, key: str, msg: str, interval: float = 5.0) -> None:
        """
        Simple per-key rate-limited logger to avoid spam in noisy environments.
        """
        import time as _t
        if not hasattr(self, "_rl_state"):
            self._rl_state = {}
        now = _t.monotonic()
        last, count = self._rl_state.get(key, (0.0, 0))
        count += 1
        if (now - last) >= interval:
            self._rl_state[key] = (now, 0)
            suppressed = max(0, count - 1)
            if suppressed:
                self.logger.log_message(f"{msg} (suppressed {suppressed} similar)")
            else:
                self.logger.log_message(msg)
        else:
            self._rl_state[key] = (last, count)
    # ----- Synergy: accept local daemon jobs -----

    def distribute_job_from_daemon(self, job: Dict[str, Any]) -> None:
        session_id = MoneroDaemonManager._DAEMON_SESSION_ID
        # normalize expected hex fields via RandomXLoader helpers
        for k in ("blob", "seed_hash", "target"):
            if k in job and isinstance(job[k], str):
                job[k] = RandomXLoader.norm_hex(job[k])

        # Make sure worker exists then forward like an inbound pool message
        self.stratum_manager.register_session(session_id)
        self.stratum_manager.process_messages(session_id, [{"method": "job", "params": job}])
        self.code_output_manager.submit_packet(
            job,
            inbound_iface="stratum",
            phase="handled",
            component="daemon-job-distribute"
        )

    # ----- Socket helpers -----

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

    # ----- Network connection helpers -----

    def _open_pool_socket(self) -> socket.socket:
        assert self.pool_ip and self.pool_port, "Pool IP and port must be configured."

        def connect_plain() -> socket.socket:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(10.0)
            s.connect((self.pool_ip, self.pool_port))
            s.settimeout(1.0)
            self.logger.log_message("[StratumConn] 🔓 Using cleartext TCP to pool.")
            return s

        want_tls = (self.use_tls is True) or (self.use_tls == "auto" and self.pool_port in self.LIKELY_TLS_PORTS)
        if not want_tls:
            return connect_plain()

        ctx = ssl.create_default_context()
        if not self.pool_host or self.pool_host == self.pool_ip:
            self.logger.log_message("[StratumConn] ⚠️ No pool hostname; disabling TLS cert verification.")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        plain_socket.settimeout(10.0)

        try:
            plain_socket.connect((self.pool_ip, self.pool_port))
            tls_sock = ctx.wrap_socket(plain_socket, server_hostname=self.pool_host)
            tls_sock.settimeout(1.0)
            self.logger.log_message(f"[StratumConn] 🔐 Using TLS to pool (SNI: {self.pool_host}).")
            return tls_sock
        except (ssl.SSLCertVerificationError, ssl.SSLError, socket.timeout, ConnectionRefusedError) as e:
            self._close_socket(plain_socket)
            if self.use_tls is True:
                self.logger.log_message(f"[StratumConn] ❌ TLS required but failed: {e}")
                raise
            self.logger.log_message(f"[StratumConn] ⚠️ TLS failed ({type(e).__name__}); falling back to TCP.")
            return connect_plain()

    # ----- Direct connection -----

    def _direct_connection_loop(self) -> None:
        DIRECT_SESSION_ID = "direct_pool_connection"
        reconnect_delay = 5.0
        self.stratum_manager.rx_start()

        while not self._stop_event.is_set():
            pool_socket = None
            try:
                with self._lock:
                    self._direct_conn_state = ConnectionState.CONNECTING
                self.logger.log_message(f"[StratumConn] 🔌 (Direct) Connecting to {self.pool_ip}:{self.pool_port}...")
                pool_socket = self._open_pool_socket()
                self._add_socket(pool_socket)
                self._pool_socket = pool_socket

                # Attach submitter for the direct session
                self.stratum_manager.attach_submitter(DIRECT_SESSION_ID, self.submit_share)
                self.stratum_manager.register_session(DIRECT_SESSION_ID)

                with self._lock:
                    self._direct_conn_state = ConnectionState.CONNECTED
                self.logger.log_message("[StratumConn] ✅ (Direct) Connected and session registered.")

                reconnect_delay = 5.0
                self._send_authorize_request(pool_socket)
                receive_buffer = b""

                while not self._stop_event.is_set():
                    if self.direct_session_id and time.time() >= self._next_keepalive_ts:
                        self._send_keepalive(pool_socket)

                    try:
                        data = pool_socket.recv(8192)
                        if not data:
                            self.logger.log_message("[StratumConn] 💔 (Direct) Connection closed by peer.")
                            break
                        receive_buffer += data
                        receive_buffer = self._process_received_data(receive_buffer, DIRECT_SESSION_ID)
                    except socket.timeout:
                        continue
                    except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                        self.logger.log_message(f"[StratumConn] 💔 (Direct) Connection error: {e}")
                        break

            except Exception as e:
                self.logger.log_message(f"[StratumConn] ❌ (Direct) Connection loop failed: {e}")
            finally:
                self.stratum_manager.deregister_session(DIRECT_SESSION_ID)
                with self._lock:
                    self._direct_conn_state = ConnectionState.DISCONNECTED
                self._close_socket(pool_socket)
                self._pool_socket = None
                self.direct_session_id = None

            if not self._stop_event.is_set():
                self.logger.log_message(f"💤 Reconnecting in {reconnect_delay:.1f} seconds...")
                self._stop_event.wait(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 1.5, 60.0)

    # ----- Proxy mode -----

    def _listen_for_miners(self) -> None:
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.proxy_host, self.proxy_port))
            server_socket.listen(64)
            server_socket.settimeout(1.0)
            # DO NOT add the listener to _active_sockets (avoids WinError 10038 on stop)
            self.logger.log_message(f"[StratumConn] 👂 (Proxy) Listening on {self.proxy_host}:{self.proxy_port}")
        except OSError as e:
            self.logger.log_message(f"[StratumConn] ❌ (Proxy) Failed to start listener: {e}")
            return

        try:
            while not self._stop_event.is_set():
                try:
                    miner_conn, miner_addr = server_socket.accept()
                    miner_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    miner_conn.settimeout(60.0)
                    self.logger.log_message(f"[StratumConn] 🤝 (Proxy) Miner connected: {miner_addr}")

                    h = threading.Thread(target=self._handle_miner_session, args=(miner_conn,), daemon=True)
                    h.start()
                except socket.timeout:
                    continue
        finally:
            self._close_socket(server_socket)

    def _handle_miner_session(self, miner_socket: socket.socket) -> None:
        pool_socket: Optional[socket.socket] = None
        miner_addr = miner_socket.getpeername()
        session_id = f"proxy_{miner_addr[0]}:{miner_addr[1]}"
        send_q: queue.PriorityQueue[tuple[int, bytes]] = queue.PriorityQueue()

        try:
            self._add_socket(miner_socket)
            self.stratum_manager.register_session(session_id)
            self.logger.log_message(f"[StratumConn] (Proxy) Session {session_id} registered.")


            self.logger.log_message(f"[StratumConn] 🔌 (Proxy) Connecting upstream for {session_id}...")
            pool_socket = self._open_pool_socket()
            self._add_socket(pool_socket)

            # Per-session submitter for this proxy session
            def _submit_via_proxy(*, job_id: str, nonce: str, result_hash: str) -> None:
                # Include upstream session id if we have it (p2pool compatibility)
                upstream_id = self._proxy_session_ids.get(session_id)
                params = {
                    "id": upstream_id,  # CRITICAL: This must be the ID P2Pool provided
                    "job_id": job_id,
                    "nonce": nonce,
                    "result": result_hash
                }
                if upstream_id:
                    params["id"] = upstream_id
                msg = {
                    "jsonrpc": "2.0",
                    "id": 1,  # Some P2Pool versions prefer static IDs for submits
                    "method": "submit",
                    "params": params
                }
                try:
                    send_q.put_nowait((1, (json.dumps(msg) + "\n").encode("utf-8")))
                    self.logger.log_message(
                        f"[StratumConn] ⛏️ (Proxy) Submitted share for {session_id}, job {job_id}"
                    )
                except Exception as e:
                    self.logger.log_message(
                        f"[StratumConn] ❌ (Proxy) Failed to enqueue submit for {session_id}: {e}"
                    )

            self.stratum_manager.attach_submitter(session_id, _submit_via_proxy)

            threading.Thread(target=self._sender_worker, args=(send_q, pool_socket), daemon=True).start()
            threading.Thread(
                target=self._relay_data, args=(miner_socket, send_q, "Miner -> Pool", session_id), daemon=True
            ).start()
            threading.Thread(
                target=self._relay_data, args=(pool_socket, miner_socket, "Pool -> Miner", session_id), daemon=True
            ).start()

        except Exception as e:
            self.logger.log_message(f"[StratumConn] ❌ (Proxy) Session {session_id} failed: {e}")
        finally:
            self.stratum_manager.deregister_session(session_id)
            self._proxy_session_ids.pop(session_id, None)
            self.logger.log_message(f"[StratumConn] 💔 (Proxy) Session {session_id} ended.")
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
                self.logger.log_message("[StratumConn] Sender worker socket error.")
                break

    def _relay_data(self, src_socket: socket.socket, dest: socket.socket | queue.PriorityQueue, direction: str, session_id: str = "") -> None:
        while not self._stop_event.is_set():
            try:
                data = src_socket.recv(8192)
                if not data:
                    self.logger.log_message(f"[StratumConn] Relay {direction}: Connection closed.")
                    break

                if direction == "Pool -> Miner" and session_id:
                    lines = data.replace(b"\r\n", b"\n").split(b"\n")
                    for line in filter(None, lines):
                        msgs = self._parse_monero_json(line)
                        if msgs:
                            # Capture upstream session id from login result, for this proxy session
                            for m in msgs:
                                try:
                                    res = (m.get("result") or {})
                                    sid = res.get("id")
                                    if isinstance(sid, str) and sid:
                                        self._proxy_session_ids[session_id] = sid
                                except Exception:
                                    pass
                            self.stratum_manager.process_messages(session_id, msgs)

                if isinstance(dest, queue.PriorityQueue):
                    lines = data.replace(b"\r\n", b"\n").split(b"\n")
                    for line in filter(None, lines):
                        pr = self._get_message_priority(line)
                        dest.put_nowait((pr, line + b"\n"))
                else:
                    dest.sendall(data)

            except (socket.timeout, ConnectionAbortedError, ConnectionResetError, OSError):
                break
            except Exception as e:
                self.logger.log_message(f"[StratumConn] Relay error in {direction} for {session_id}: {e}")
                break

    # ----- Protocol helpers -----

    def _parse_monero_json(self, line: bytes) -> Optional[list[dict]]:
        line = line.strip()
        if not line.startswith((b"{", b"[")):
            return None
        try:
            decoded = json.loads(line)
            messages = decoded if isinstance(decoded, list) else [decoded]
            valid: list[dict] = []
            for msg in messages:
                if not isinstance(msg, dict):
                    self.logger.log_message(f"[StratumConn] ℹ️ Skipping non-dict message: {msg}")
                    continue
                valid.append(msg)  # keep unknown methods (p2pool extras)
            return valid
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.logger.log_message(f"[StratumConn] ❌ JSON decode error: {e} for line: {line[:100]!r}")
            return None

    def _get_message_priority(self, msg_bytes: bytes) -> int:
        try:
            decoded = json.loads(msg_bytes)
            m = decoded.get("method")
            if m == "submit":
                return 1
            if m == "job":
                return 2
        except Exception:
            pass
        return 3

    def _note_outgoing(self, msg: dict) -> None:
        mid = msg.get("id")
        mth = msg.get("method")
        if isinstance(mid, int) and isinstance(mth, str):
            self._pending_by_id[mid] = mth

    def _send_json_rpc_request(self, sock: socket.socket, message: dict) -> None:
        try:
            request = json.dumps(message) + "\n"
            sock.sendall(request.encode("utf-8"))
            self._note_outgoing(message)
            method = message.get("method", "response")
            self.logger.log_message(f"[StratumConn] ➡️ Sent {method} request.")
        except OSError as e:
            self.logger.log_message(f"[StratumConn] ❌ Failed to send request: {e}")
            raise

    def _send_authorize_request(self, sock: socket.socket) -> None:
        params = {"login": self.wallet_address, "pass": "x", "agent": self.user_agent, "rigid": self.worker_name}
        self._send_json_rpc_request(sock, {"jsonrpc": "2.0", "id": 1, "method": "login", "params": params})
        self._schedule_keepalive()

    def _send_keepalive(self, sock: socket.socket) -> None:
        if self.direct_session_id:
            self._send_json_rpc_request(sock, {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "keepalived",
                "params": {"id": self.direct_session_id}  # <— add this
            })
            self._schedule_keepalive()
        else:
            self.logger.log_message("[StratumConn] ⚠️ Skipping keepalive: No active session ID.")

    def submit_share(self, job_id: str, nonce: str, result_hash: str) -> None:
        # Direct connection submit
        with self._lock:
            if self._direct_conn_state != ConnectionState.CONNECTED or not self._pool_socket:
                self.logger.log_message("[StratumConn] ⚠️ Cannot submit share: Direct connection not active.")
                return
            sock_to_use = self._pool_socket

        if not all([job_id, nonce, result_hash]):
            self.logger.log_message("[StratumConn] ❌ Cannot submit share: Missing required data.")
            return

        submit_msg = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "submit",
            "params": {
                "id": self.direct_session_id,  # <— add this
                "job_id": job_id,
                "nonce": nonce,
                "result": result_hash,
            },
        }
        self.code_output_manager.submit_packet(
            {
                "job_id": job_id,
                "nonce": nonce,
                "result": result_hash,
            },
            inbound_iface="stratum",
            phase="handled",
            component="stratum-submit"
        )
        if sock_to_use.fileno() != -1:
            self.logger.log_message(f"[StratumConn] ⛏️ Submitting share for job {job_id}...")
            self._send_json_rpc_request(sock_to_use, submit_msg)
        else:
            self.logger.log_message("[StratumConn] ⚠️ Cannot submit share: Pool socket is closed.")

    def _process_received_data(self, buffer: bytes, session_id: str) -> bytes:
        buffer = buffer.replace(b"\r\n", b"\n")
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue

            messages = self._parse_monero_json(line)
            if not messages:
                self.logger.log_message(f"[StratumConn] ⚠️ Discarding malformed data: {line[:100]}")
                continue

            for msg in messages:
                try:
                    if "result" in msg or "error" in msg:
                        mid = msg.get("id")
                        last_method = self._pending_by_id.pop(mid, None) if isinstance(mid, int) else None
                        err = msg.get("error")
                        if err:
                            self.logger.log_message(
                                f"[StratumConn] ❗ RPC error for {last_method or 'unknown'}: "
                                f"{err.get('code')} {err.get('message')}"
                            )
                            self.stratum_manager.process_messages(session_id, [msg])
                            continue

                        res = msg.get("result") or {}
                        if isinstance(res, dict):
                            if "job" in res and isinstance(res["job"], dict):
                                j = res["job"]
                                for k in ("blob", "seed_hash", "next_seed_hash", "target"):
                                    if k in j and isinstance(j[k], str):
                                        j[k] = RandomXLoader.norm_hex(j[k])
                                self.stratum_manager.process_messages(session_id, [{"method": "job", "params": j}])

                            if last_method == "login":
                                sid = res.get("id")
                                if isinstance(sid, str):
                                    self.direct_session_id = sid
                                    self.logger.log_message(
                                        f"🔑 (Direct) Login successful. Session ID: {self.direct_session_id}"
                                    )
                                    self._schedule_keepalive()

                            if last_method == "submit":
                                status = (res.get("status") or res.get("state") or "").upper()
                                accepted = bool(res.get("accepted") or (status == "OK"))
                                self.logger.log_message(
                                    f"[StratumConn] 📨 Submit result: {'ACCEPTED' if accepted else status or 'UNKNOWN'}"
                                )
                                self.stratum_manager.process_messages(session_id, [msg])

                            if last_method in ("keepalived", "getjob"):
                                self.stratum_manager.process_messages(session_id, [msg])
                        continue

                    method = (msg.get("method") or "").lower()
                    params = msg.get("params") or {}

                    if method == "job" and isinstance(params, dict):
                        for k in ("blob", "seed_hash", "next_seed_hash", "target"):
                            if k in params and isinstance(params[k], str):
                                params[k] = RandomXLoader.norm_hex(params[k])
                        if "height" in params:
                            try:
                                self.logger.log_message(f"[StratumConn] 📦 New job height={int(params['height'])}")
                            except Exception:
                                pass
                        self.stratum_manager.process_messages(session_id, [{"method": "job", "params": params}])
                        continue

                    if method in ("block_notify", "new_block", "p2pool.block", "p2pool.tip", "pool.stats",
                                  "set_target", "set_difficulty", "set_extranonce"):
                        for k in ("target", "seed_hash", "next_seed_hash", "block_hash"):
                            if k in params and isinstance(params[k], str):
                                params[k] = RandomXLoader.norm_hex(params[k])
                        if "height" in params:
                            try:
                                self.logger.log_message(f"[StratumConn] ⛓️ {method} height={int(params['height'])}")
                            except Exception:
                                self.logger.log_message(f"[StratumConn] ⛓️ {method}")
                        self.stratum_manager.process_messages(session_id, [msg])
                        continue

                    # Forward unknown-but-valid pool messages for visibility
                    self.stratum_manager.process_messages(session_id, [msg])

                except Exception as e:
                    self.logger.log_message(f"[StratumConn] ❌ Message handling error: {type(e).__name__}: {e}")

        return buffer


class StratumManager:
    """
    Tracks sessions, feeds jobs to persistent workers, performs RandomX hashing,
    and calls back to a submitter (daemon/pool) when a solution is found.
    """
    NONCE_BYTE_OFFSET = 39

    def __init__(self, code_output_manager, router_logger: Any):
        self.logger = router_logger
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        self.rx: Optional[RandomXLoader] = None
        self._rx_seed: Optional[bytes] = None
        self._rx_started: bool = False
        self._rx_ready_event = threading.Event()

        self._workers: Dict[str, threading.Thread] = {}
        self._job_queues: Dict[str, queue.Queue] = {}
        # Per-session submitters
        self._submitters: Dict[str, Callable[..., None]] = {}

        self.session_buffers: Dict[str, bytes] = {}
        self.STRATUM_PORTS = {3333, 4444, 5555, 7777, 18081}
        self.code_output_manager = code_output_manager
        self._stop_events: Dict[str, threading.Event] = {}
        self.logger.log_message("[Stratum] Streamlined Manager initialized.")

    # ----- lifecycle -----

    def stop(self):
        self.logger.log_message("[Stratum] 🛑 Stopping all workers and cleaning up...")
        # Stop workers first
        for sid in list(self.sessions.keys()):
            self.deregister_session(sid)
        # Extra wait to ensure hashing loops are gone
        for _ in range(10):  # up to ~5s total
            alive = any(t.is_alive() for t in list(self._workers.values()))
            if not alive:
                break
            time.sleep(0.5)

        # Now it is safe to destroy RandomX
        try:
            if self.rx and hasattr(self.rx, "destroy"):
                self.rx.destroy()

            with self._lock:
                self.sessions.clear()
                self._workers.clear()
                self._job_queues.clear()
            self.logger.log_message("[Stratum] ✅ Manager stopped and cleaned up.")
        finally:
            self.rx = None   # avoid stale handle on restart
            self._rx_started = False
            self._rx_seed = None
            self._rx_ready_event.set()


    def rx_start(self):
        # Choose flags appropriate for your environment
        fast_flags = (RandomXFlags.HARD_AES | RandomXFlags.JIT | RandomXFlags.LARGE_PAGES)
        self.rx = RandomXLoader("tools/randomx.dll", flags=fast_flags, logger=self.logger)

    # ----- pipeline -----
    def _extract_payload_from_scapy(self, pkt) -> tuple[bytes | None, Optional[str]]:
        """
        Best-effort extraction of app bytes from a Scapy packet that may be Ether/IP/IPv6.
        Returns (payload_bytes_or_None, derived_session_id_or_None).
        - Prefers TCP; extracts bytes from Raw OR from TCP.payload when Raw missing.
        - Filters to STRATUM_PORTS to avoid noise (edit STRATUM_PORTS above).
        - Derives a stable session id from 4/5-tuple.
        """
        try:
            from scapy.packet import Raw, NoPayload
            from scapy.layers.inet import IP, TCP
            try:
                from scapy.layers.inet6 import IPv6
            except Exception:
                IPv6 = None

            # Find L3
            ip = None
            if IP in pkt:
                ip = pkt[IP]
                family = "ipv4"
            elif IPv6 and IPv6 in pkt:
                ip = pkt[IPv6]
                family = "ipv6"
            else:
                return None, None

            # Require TCP
            if TCP not in pkt:
                return None, None
            tcp = pkt[TCP]

            # Ports filter (edit set if needed)
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)
            if sport not in self.STRATUM_PORTS and dport not in self.STRATUM_PORTS:
                return None, None

            # Session id from 5-tuple
            src = getattr(ip, "src", None) or getattr(ip, "psrc", None) or "?"
            dst = getattr(ip, "dst", None) or getattr(ip, "pdst", None) or "?"
            sid = f"{family}:{src}:{sport}->{dst}:{dport}"

            # Extract bytes:
            # 1) If Raw exists, use it.
            if Raw in pkt:
                rawload = pkt[Raw].load
                if rawload:
                    return (bytes(rawload), sid)

            # 2) Sometimes Scapy doesn’t build Raw; try TCP.payload directly.
            pay = tcp.payload
            if pay and not isinstance(pay, NoPayload):
                try:
                    b = bytes(pay)
                    if b:
                        return (b, sid)
                except Exception:
                    pass

            # 3) No payload for this segment (e.g., pure ACK/handshake)
            return None, sid

        except Exception:
            return None, None

    def handle_packet(self, packet: "Any", *, session_id: Optional[str] = None) -> None:
        """
        General entry point for Stratum traffic arriving from the router's process_packet pipeline.

        Accepts:
          - bytes/str containing JSON-RPC (newline-delimited or stream-framed)
          - dict 'event' with payload under common fields (payload/data/message/raw)
          - already-parsed JSON-RPC dict or list[dict]
          - Scapy packets: only TCP payloads on STRATUM_PORTS are considered
        Derives a stable session_id when not provided (from event/flow keys), buffers partial
        frames per session, decodes objects, and routes them to process_messages().
        """

        # --- 1) Derive/initialize session buffer --------------------------------------
        sid = self._derive_session_id(session_id, packet) or "stratum/default"
        # make sure the buffer exists and is bytes (never None)
        buf0 = self.session_buffers.get(sid)
        if not isinstance(buf0, (bytes, bytearray)):
            self.session_buffers[sid] = b""
        # keep a local reference (as bytes)
        cur_buf = bytes(self.session_buffers[sid])

        # --- 2) Fast path: already-parsed JSON-RPC objects -----------------------------
        def _is_jsonrpc_obj(o: Any) -> bool:
            return isinstance(o, dict) and any(k in o for k in ("method", "result", "params", "id"))

        if isinstance(packet, list) and packet and all(_is_jsonrpc_obj(x) for x in packet):
            self.process_messages(sid, packet)
            return
        if _is_jsonrpc_obj(packet):
            self.process_messages(sid, [packet])
            return

        # --- 3) Extract raw payload bytes from common shapes ---------------------------
        payload_bytes: Optional[bytes] = None

        if isinstance(packet, (bytes, bytearray)):
            payload_bytes = bytes(packet)
        elif isinstance(packet, str):
            payload_bytes = packet.encode("utf-8", "ignore")
        elif isinstance(packet, dict):
            # direct keys
            for key in ("payload", "data", "message", "raw", "buf", "body"):
                if key in packet:
                    v = packet[key]
                    if isinstance(v, (bytes, bytearray)):
                        payload_bytes = bytes(v)
                        break
                    if isinstance(v, str):
                        payload_bytes = v.encode("utf-8", "ignore")
                        break
            else:
                # nested one level under "payload"
                p = packet.get("payload", {}) if isinstance(packet.get("payload"), dict) else {}
                for key in ("data", "message", "raw", "body"):
                    v = p.get(key)
                    if isinstance(v, (bytes, bytearray)):
                        payload_bytes = bytes(v)
                        break
                    if isinstance(v, str):
                        payload_bytes = v.encode("utf-8", "ignore")
                        break

        # --- 4) Scapy fallback (only if it looks like Stratum TCP) ---------------------
        if payload_bytes is None and hasattr(packet, "haslayer"):
            try:
                # Only treat as Stratum if it's TCP and matches the known ports
                from scapy.layers.inet import TCP
                from scapy.packet import Raw  # scapy Raw layer (payload)
                is_tcp = packet.haslayer(TCP)
                if is_tcp:
                    sport = int(packet[TCP].sport)
                    dport = int(packet[TCP].dport)
                    if (sport in getattr(self, "STRATUM_PORTS", set())) or (
                            dport in getattr(self, "STRATUM_PORTS", set())):
                        if packet.haslayer(Raw):
                            lb = packet[Raw].load
                            if isinstance(lb, (bytes, bytearray)):
                                payload_bytes = bytes(lb)
                            elif isinstance(lb, str):
                                payload_bytes = lb.encode("utf-8", "ignore")
            except Exception:
                # ignore scapy extraction failures
                payload_bytes = None

        # --- 5) If no bytes, rate-limit a log and exit safely --------------------------
        if payload_bytes is None:
            self._log_no_payload_rate_limited(sid, type(packet).__name__)
            return

        # --- 6) Buffer & drain JSON frames (supports stream framing/newlines) ----------
        try:
            buf = cur_buf + payload_bytes  # safe: both are bytes
        except Exception:
            # absolute fallback: treat as fresh payload
            buf = bytes(payload_bytes)

        objects, remainder = self._drain_json_frames(buf)
        self.session_buffers[sid] = remainder  # always store remainder, even if empty

        if not objects:
            # partial frame; keep buffering silently
            return

        # --- 7) Normalize to list[dict] and dispatch ----------------------------------
        msgs: list[dict] = []
        for obj in objects:
            if isinstance(obj, list):
                msgs.extend([x for x in obj if isinstance(x, dict)])
            elif isinstance(obj, dict):
                msgs.append(obj)

        if not msgs:
            # Non-dict JSON (e.g., "ok", true) — keep buffers but don't error
            preview = payload_bytes[:120]
            try:
                pv = preview.decode("utf-8", "ignore")
            except Exception:
                pv = repr(preview)
            self.logger.log_message(f"[Stratum] ℹ️ handle_packet({sid}): non-object JSON ignored: {pv}")
            return

        self.process_messages(sid, msgs)

    # -------------------- helpers (keep inside the class) --------------------------
    def _log_no_payload_rate_limited(self, sid: str, pkt_type: str):
        """
        Collapse noisy 'no payload' messages to at most once every few seconds per class.
        """
        import time as _t
        key = "_nopayload_rl"
        now = _t.monotonic()
        rl = getattr(self, key, None)
        if rl is None:
            rl = {"last": 0.0, "count": 0}
            setattr(self, key, rl)
        rl["count"] += 1
        if now - rl["last"] >= 5.0:  # log at most every 5s
            rl["last"] = now
            c = rl["count"]
            rl["count"] = 0
            self.logger.log_message(f"[Stratum] ⚠️ handle_packet({sid}): no JSON payload ({pkt_type}); "
                                    f"suppressed={max(0, c - 1)} in last window.")
    def _derive_session_id(self, explicit_sid: Optional[str], packet: "Any") -> Optional[str]:
        """
        Best-effort session id derivation:
          • respects explicit sid
          • uses common event keys (session_id/conn_id/flow_id/sid)
          • falls back to 5-tuple-ish strings if present in dict
        """
        if explicit_sid:
            return str(explicit_sid)

        if isinstance(packet, dict):
            for k in ("session_id", "conn_id", "connection_id", "flow_id", "sid"):
                if k in packet and packet[k]:
                    return str(packet[k])

            # Try to build a stable flow key from common fields
            src = packet.get("src") or packet.get("saddr") or packet.get("source_ip")
            dst = packet.get("dst") or packet.get("daddr") or packet.get("dest_ip")
            sp = packet.get("sport") or packet.get("src_port")
            dp = packet.get("dport") or packet.get("dst_port")
            if src and dst and sp and dp:
                return f"{src}:{sp}->{dst}:{dp}"

            # Nested
            net = packet.get("network") or packet.get("flow") or {}
            if isinstance(net, dict):
                src = net.get("src") or net.get("saddr")
                dst = net.get("dst") or net.get("daddr")
                sp = net.get("sport") or net.get("src_port")
                dp = net.get("dport") or net.get("dst_port")
                if src and dst and sp and dp:
                    return f"{src}:{sp}->{dst}:{dp}"

        # As a last resort, return None; caller will use default.
        return None

    def _drain_json_frames(self, buf: bytes) -> tuple[list[Any], bytes]:
        """
        Extract as many JSON values as possible from a byte buffer, tolerating:
          • leading/trailing whitespace
          • newline-delimited JSON
          • back-to-back objects/arrays in a stream
        Returns (objects, remainder_bytes).
        """
        import json

        if not buf:
            return [], b""

        # Fast path: if there's at least one newline, try line-delimited first.
        out: list[Any] = []
        s = buf.decode("utf-8", "ignore")
        if "\n" in s:
            lines = s.splitlines(keepends=True)
            tail = ""
            for ln in lines:
                try:
                    obj = json.loads(ln)
                    out.append(obj)
                except json.JSONDecodeError:
                    # Keep partial/incomplete in tail (accumulate)
                    tail += ln
            return out, tail.encode("utf-8")

        # Stream-framed path: use JSONDecoder.raw_decode repeatedly.
        dec = json.JSONDecoder()
        i, n = 0, len(s)
        while i < n:
            # Skip whitespace and any non-JSON noise until a plausible starter
            while i < n and s[i] not in "{[\"tfn-0123456789":  # objects, arrays, strings, true/false/null/number
                i += 1
            if i >= n:
                break
            try:
                obj, j = dec.raw_decode(s, i)
                out.append(obj)
                i = j  # continue after parsed value
            except json.JSONDecodeError:
                # Need more bytes for a complete value
                break
        remainder = s[i:].encode("utf-8") if i < n else b""
        return out, remainder
    def attach_submitter(self, session_id: str, submit_func: Callable[..., None]):
        self._submitters[session_id] = submit_func
        self.logger.log_message(f"[Stratum] Submitter attached for session: {session_id}")

    def register_session(self, session_id: str) -> None:
        with self._lock:
            t = self._workers.get(session_id)
            if session_id in self.sessions and t is not None and t.is_alive():
                return

            self.sessions[session_id] = {"job_ver": 0}
            self._stop_events[session_id] = threading.Event()

            jq = queue.Queue(maxsize=1)
            self._job_queues[session_id] = jq

            t = threading.Thread(target=self._share_worker,
                                 args=(session_id, jq),
                                 daemon=True, name=f"rx-{session_id}")
            self._workers[session_id] = t
            t.start()
        self.logger.log_message(f"[Stratum] ✅ Session registered and worker started for: {session_id}")

    def deregister_session(self, session_id: str) -> None:
        self.logger.log_message(f"[Stratum] 🛑 Deregistering session: {session_id}")

        stop_evt = None
        q = None
        t = None
        with self._lock:
            # signal stop + force version bump so inner loop breaks ASAP
            s = self.sessions.get(session_id)
            if isinstance(s, dict):
                s["job_ver"] = int(s.get("job_ver", 0)) + 1  # 🔸 preempt current job

            stop_evt = self._stop_events.get(session_id)
            if stop_evt:
                stop_evt.set()

            q = self._job_queues.get(session_id)
            t = self._workers.get(session_id)

        if q:
            try:
                q.put_nowait(None)  # unblock outer job_q.get()
            except Exception:
                pass

        if t and t.is_alive():
            t.join(timeout=2.0)

        with self._lock:
            self.sessions.pop(session_id, None)
            self._workers.pop(session_id, None)
            self._job_queues.pop(session_id, None)
            self._submitters.pop(session_id, None)
            self._stop_events.pop(session_id, None)

    def process_messages(self, session_id: str, messages: list[dict]) -> None:
        if session_id not in self.sessions:
            self.register_session(session_id)
        for msg in messages:
            if isinstance(msg, dict):
                self._process_single_message(session_id, msg)

    def _process_single_message(self, session_id: str, data: Dict[str, Any]):
        method = data.get("method")
        params = data.get("params") or {}
        result = data.get("result") or {}

        job_data = result.get("job") if isinstance(result, dict) and "job" in result else (
            params if method == "job" else None
        )
        if job_data:
            self._handle_job(session_id, job_data)
        elif method == "submit":
            self._track_submit(session_id, params)

    # ----- job handling -----

    def _ensure_rx(self):
        if self.rx is None:
            self.rx_start()

    def _maybe_reinit_randomx(self, seed_hash_hex: Optional[str]):
        if not seed_hash_hex:
            return
        try:
            seed = bytes.fromhex(seed_hash_hex)
        except ValueError:
            self.logger.log_message(f"[Stratum] ⚠️ Invalid seed_hash: {seed_hash_hex}")
            return
        self._ensure_rx()
        if (not self._rx_started) or (self._rx_seed != seed):
            self._rx_ready_event.clear()
            try:
                self.rx.ensure_started(seed, use_dataset=False)
                self._rx_seed = seed
                self._rx_started = True
                self.logger.log_message(f"[Stratum] ✅ RandomX VM ready, seed: {seed_hash_hex[:12]}...")
            except Exception as e:
                self._rx_started = False
                self.logger.log_message(f"[Stratum] ❌ RandomX init failed: {e}")
            finally:
                self._rx_ready_event.set()

    def _handle_job(self, session_id: str, job: Dict[str, Any]):
        self._maybe_reinit_randomx(job.get("seed_hash"))
        # bump per-session job version so workers can preempt immediately
        with self._lock:
            s = self.sessions.setdefault(session_id, {})
            s["job_ver"] = int(s.get("job_ver", 0)) + 1
            cur_ver = s["job_ver"]
        if session_id in self._job_queues:
            jq = self._job_queues[session_id]
            try:
                jq.get_nowait()  # drop stale
            except queue.Empty:
                pass
            jq.put(job)
            # (optional) visibility
            try:
                self.code_output_manager.submit_packet(
                    {**job, "_job_ver": cur_ver},
                    inbound_iface="stratum",
                    phase="handled",
                    component="stratum-job"
                )
            except Exception:
                pass

    def _track_submit(self, session_id: str, params: dict):
        with self._lock:
            s = self.sessions.setdefault(session_id, {})
            s["shares"] = s.get("shares", 0) + 1
        self.logger.log_message(f"[Stratum] ⛏️ {session_id} submitted share for job: {params.get('job_id', '?')}")

    # ----- hashing helpers -----

    @staticmethod
    def _prepare_blob_template(blob_hex: str) -> tuple[bytearray, int]:
        if len(blob_hex) < (StratumManager.NONCE_BYTE_OFFSET + 4) * 2:
            raise ValueError("Blob is too short to contain a nonce")
        return bytearray.fromhex(blob_hex), StratumManager.NONCE_BYTE_OFFSET

    @staticmethod
    def _write_nonce_le_inplace(buf: bytearray, offset: int, nonce: int):
        buf[offset:offset + 4] = nonce.to_bytes(4, "little")

    # ----- worker -----

    def _share_worker(self, session_id: str, job_q: queue.Queue):
        from time import perf_counter
        import time
        import random

        logger = self.logger
        submitter = self._submitters.get(session_id)

        BATCH = 4
        LOG_INTERVAL = 2.0
        max_backoff = 0.5

        stride_seed = abs(hash(session_id)) or 1
        stride = ((stride_seed & 0xFFFF) | 1)

        def _u256_le(x) -> int:
            if isinstance(x, int): return x
            if isinstance(x, (bytes, bytearray)):
                if len(x) != 32: raise ValueError(f"digest length != 32 (got {len(x)})")
                return int.from_bytes(x, "little")
            raise TypeError(f"Unsupported digest type: {type(x)}")

        def _target_u256_from_hex_le(hex_str: str | None) -> int | None:
            if not hex_str: return None
            return int.from_bytes(bytes.fromhex(hex_str), "little")

        def _target_len_bytes(hex_str: str | None) -> int:
            return len(hex_str) // 2 if hex_str else 0

        def _meets_target(d_u256: int, T: int, T_len_bytes: int) -> bool:
            if T_len_bytes == 8:
                return (d_u256 & ((1 << 64) - 1)) <= T
            return d_u256 <= T
        stop_evt = self._stop_events.get(session_id)
        while True:
            job = job_q.get()
            if job is None:
                logger.log_message(f"[Stratum] 🛑 Worker received stop signal for session={session_id}")
                break
            if stop_evt.is_set():
                self.logger.log_message(f"[Stratum] 🛑 Worker received stop signal for session={session_id}")
                break
            # Snapshot the job version *after* this job was enqueued
            with self._lock:
                my_ver = int(self.sessions.get(session_id, {}).get("job_ver", 0))

            job_id = job.get("id") or job.get("job_id")
            blob_hex = job.get("blob")
            share_hex = job.get("target")
            block_hex = job.get("block_target")
            diff_val = job.get("network_difficulty") or job.get("block_difficulty") or job.get("difficulty")

            if not all([job_id, blob_hex, share_hex]):
                logger.log_message(f"[Stratum] ⚠️ Skipping invalid job on {session_id}: missing fields.")
                continue

            self._rx_ready_event.wait()
            if not self._rx_started or not self.rx:
                logger.log_message(f"[Stratum] ⚠️ Worker for {session_id} waiting for RandomX...")
                continue
            rx = self.rx

            try:
                share_T = _target_u256_from_hex_le(share_hex)
                share_T_len = _target_len_bytes(share_hex)
                if block_hex:
                    block_T = _target_u256_from_hex_le(block_hex)
                    block_T_len = _target_len_bytes(block_hex)
                else:
                    block_T = None
                    block_T_len = 0
                    if diff_val:
                        block_T = RandomXLoader.target_from_difficulty_int(int(diff_val))
                        block_T_len = 32
                buf, off = self._prepare_blob_template(blob_hex)
            except Exception as e:
                logger.log_message(f"[Stratum] ❌ Job setup failed for {job_id}: {e}")
                continue

            has_pipe = all(
                hasattr(rx, m) for m in ("calculate_hash_first", "calculate_hash_next", "calculate_hash_last"))
            calc_hash = getattr(rx, "calculate_hash", None)
            if not callable(calc_hash):
                logger.log_message("[Stratum] ❌ Hashing backend (rx) is not ready.")
                continue

            nonce = random.getrandbits(32)
            tries, ema_rate, last_log, error_streak = 0, None, perf_counter(), 0
            submitted_nonces: set[str] = set()
            min_h64 = (1 << 64) - 1
            min_h256 = (1 << 256) - 1

            logger.log_message(f"[Stratum] ▶️ Working job {job_id} (stride={stride}, batch={BATCH if has_pipe else 1})")

            while True:
                if stop_evt and stop_evt.is_set():
                    logger.log_message(f"[Stratum] ⛔ Stop requested; leaving job {job_id} on {session_id}.")
                    break

                with self._lock:
                    sess = self.sessions.get(session_id)
                    if sess is None:
                        logger.log_message(f"[Stratum] ⛔ Session removed; leaving job {job_id} on {session_id}.")
                        break
                    cur_ver = int(sess.get("job_ver", my_ver))

                # ---- instant preemption: switch as soon as a newer job arrives ----
                with self._lock:
                    cur_ver = int(self.sessions.get(session_id, {}).get("job_ver", my_ver))
                if cur_ver != my_ver:
                    logger.log_message(
                        f"[Stratum] 🔄 New job detected for {session_id} (ver {cur_ver} > {my_ver}); switching.")
                    break

                try:
                    if has_pipe and BATCH >= 2:
                        nonces, digests_u256 = [], []
                        self._write_nonce_le_inplace(buf, off, nonce)
                        nonces.append(nonce)
                        rx.calculate_hash_first(bytes(buf))

                        cur = nonce
                        for _ in range(1, BATCH):
                            cur = (cur + stride) & 0xFFFFFFFF
                            self._write_nonce_le_inplace(buf, off, cur)
                            d_prev = rx.calculate_hash_next(bytes(buf))
                            d_prev_u256 = _u256_le(d_prev)
                            digests_u256.append(d_prev_u256)
                            nonces.append(cur)

                        d_last = rx.calculate_hash_last()
                        digests_u256.append(_u256_le(d_last))

                        for n_val, d_u256 in zip(nonces, digests_u256):
                            h64 = d_u256 & ((1 << 64) - 1)
                            if h64 < min_h64: min_h64 = h64
                            if d_u256 < min_h256: min_h256 = d_u256

                            if share_T is not None and _meets_target(d_u256, share_T, share_T_len):
                                n_hex = n_val.to_bytes(4, "little").hex()
                                if n_hex not in submitted_nonces:
                                    submitted_nonces.add(n_hex)
                                    if submitter:
                                        try:
                                            result_hex = d_u256.to_bytes(32, "little").hex()
                                            submitter(job_id=job_id, nonce=n_hex, result_hash=result_hex)
                                        except Exception as e:
                                            logger.log_message(f"[Stratum] ❌ Submit failed: {e}")
                                    logger.log_message(f"[Stratum] 🎯 SHARE: job={job_id} nonce={n_hex}")
                                    if block_T and _meets_target(d_u256, block_T, block_T_len):
                                        logger.log_message(f"[Stratum] 🎉 BLOCK FOUND by {session_id} (nonce={n_hex})")

                        tries += BATCH
                        nonce = (nonces[-1] + stride) & 0xFFFFFFFF

                    else:
                        self._write_nonce_le_inplace(buf, off, nonce)
                        d_single = _u256_le(calc_hash(bytes(buf)))
                        h64 = d_single & ((1 << 64) - 1)
                        if h64 < min_h64: min_h64 = h64
                        if d_single < min_h256: min_h256 = d_single

                        if share_T is not None and _meets_target(d_single, share_T, share_T_len):
                            n_hex = nonce.to_bytes(4, "little").hex()
                            if n_hex not in submitted_nonces:
                                submitted_nonces.add(n_hex)
                                if submitter:
                                    try:
                                        result_hex = d_single.to_bytes(32, "little").hex()
                                        submitter(job_id=job_id, nonce=n_hex, result_hash=result_hex)
                                    except Exception as e:
                                        logger.log_message(f"[Stratum] ❌ Submit failed: {e}")
                                logger.log_message(f"[Stratum] 🎯 SHARE: job={job_id} nonce={n_hex}")
                                if block_T and _meets_target(d_single, block_T, block_T_len):
                                    logger.log_message(f"[Stratum] 🎉 BLOCK FOUND by {session_id} (nonce={n_hex})")

                        tries += 1
                        nonce = (nonce + stride) & 0xFFFFFFFF

                    now = perf_counter()
                    if (now - last_log) >= LOG_INTERVAL:
                        rate = tries / (now - last_log) if now > last_log else 0.0
                        ema_rate = (0.2 * rate + 0.8 * (ema_rate or rate))
                        try:
                            self.code_output_manager.submit_packet(
                                {"job_id": job_id, "hashrate": ema_rate},
                                inbound_iface="stratum",
                                phase="handled",
                                component="work"
                            )
                        except Exception:
                            pass
                        msg = f"[Stratum] ⏱️ {session_id} job {job_id}: {ema_rate:.0f} H/s"
                        try:
                            sh_bytes = bytes.fromhex(share_hex)
                            if len(sh_bytes) == 8:
                                T64 = int.from_bytes(sh_bytes, "little")
                                msg += f" | min_h64=0x{min_h64:016x} vs T64=0x{T64:016x}"
                            elif len(sh_bytes) == 32:
                                T256 = int.from_bytes(sh_bytes, "little")
                                msg += f" | min_h256=0x{min_h256:064x} vs T256=0x{T256:064x}"
                        except Exception:
                            pass
                        logger.log_message(msg)
                        tries, last_log = 0, now
                    error_streak = 0

                except Exception as e:
                    error_streak = min(error_streak + 1, 10)
                    backoff = min(max_backoff, 0.01 * (2 ** min(error_streak, 6)))
                    logger.log_message(
                        f"[Stratum] ❌ Worker error on {session_id}/{job_id}: {type(e).__name__}: {e} "
                        f"(backoff {backoff:.3f}s)"
                    )
                    time.sleep(backoff)

        logger.log_message(f"[Stratum] ✅ Worker shutdown complete for session={session_id}")

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
        self.RIP_UPDATE_INTERVAL = 10  # seconds
        self.ROUTE_TIMEOUT = 600  # seconds until a route is considered invalid (for RIP routes)
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
        self.authentication_key = None  # For RIP authentication
        self.interface_loopback_full_name = None
        self.function_call_tracker = function_call_tracker
    def set_authentication_key(self, key: str):
        """Sets a shared secret for RIP authentication (plaintext for simplicity)."""
        self.authentication_key = key
        self.router_logger.log_message("[RIP] Authentication key set.")

    def initialize_routes(self, interfaces_config: dict, default_gateway_ip: str, default_gateway_iface: str,
                          router_gateway_out_ip: str, interface_out_full_name: str, interface_in_full_name: str):
        """
        Seeds the table with directly connected nets, a default route, and all pre-configured static routes.
        Must be called before starting the manager.
        """
        self._interfaces_config = interfaces_config
        with self._rt_lock:
            self._routing_table.clear()

            # Add directly connected networks
            for ifname, cfg in self._interfaces_config.items():
                net = cfg["network"]
                self._routing_table[net] = {
                    "next_hop": "0.0.0.0",
                    "cost": 1,
                    "interface": ifname,
                    "advertised_by": "self",
                    "last_update": time.time(),
                    "type": "direct"
                }

            # Add default route if available
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

        # --- ADDING ALL PRE-CONFIGURED STATIC ROUTES ---
        # All static routes are now added here in a single, consolidated block.
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
        # AdGuard DNS (Ad-blocking and security)
        self.router_logger.log_message("[Router] Adding AdGuard DNS static routes.")
        self.add_static_route(network_str="94.140.14.14/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="94.140.15.15/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        # Comodo Secure DNS (Security-focused)
        self.add_static_route(network_str="8.26.56.26/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="8.20.247.20/32", next_hop=router_gateway_out_ip,
                              interface=interface_out_full_name, cost=1)
        self.add_static_route(network_str="::/0",next_hop="::1",
                              interface=interface_out_full_name, cost=1)
        # Neustar UltraDNS
        self.add_static_route("156.154.70.1/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("156.154.71.1/32", router_gateway_out_ip, interface_out_full_name, 1)

        # CleanBrowsing
        self.add_static_route("185.228.168.9/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("185.228.169.9/32", router_gateway_out_ip, interface_out_full_name, 1)

        # Yandex DNS
        self.add_static_route("77.88.8.8/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("77.88.8.1/32", router_gateway_out_ip, interface_out_full_name, 1)

        # NextDNS
        self.add_static_route("45.90.28.0/32", router_gateway_out_ip, interface_out_full_name, 1)
        self.add_static_route("45.90.30.0/32", router_gateway_out_ip, interface_out_full_name, 1)
        # Loopback
        self.router_logger.log_message(f"[Router] Adding/Updating static route for ::1/128.")
        self.add_static_route(network_str="::1/128", next_hop="::1", interface=interface_in_full_name, cost=2)

        self.router_logger.log_message(f"[RIP] Routing table initialized with {len(self._routing_table)} entries.")

    def add_static_route(self, network_str: str, next_hop: str, interface: str, cost: int = 1):
        """
        Adds a static route to the routing table.
        Args:
            network_str (str): CIDR notation for the destination network (e.g., "192.168.1.0/24").
            next_hop (str): The IP address of the next hop router, or "0.0.0.0" for direct delivery.
            interface (str): The full Scapy name of the outbound interface for this route.
            cost (int): The metric/cost of this route (1-15 valid, 16 = infinity).
        Returns True if added/updated, False otherwise.
        """
        try:
            net = ipaddress.ip_network(network_str)
            if cost < 1 or cost > 15:
                self.router_logger.log_message(
                    f"[RIP] ⚠️ Static route cost {cost} is out of valid range (1-15). Setting to 1.")
                cost = 1

            if interface not in self._interfaces_config:
                self.router_logger.log_message(
                    f"[RIP] ❌ Cannot add static route: Interface '{interface}' is not configured.")
                return False

            with self._rt_lock:
                current_route = self._routing_table.get(net)

                # Logic for static routes: prefer static over dynamic if cost is equal or better.
                # Static routes are generally authoritative.
                if current_route is None or \
                        current_route["type"] != "static" or \
                        (current_route["type"] == "static" and cost < current_route["cost"]):
                    # Add if new, or if current is not static, or if current static has higher cost
                    self._routing_table[net] = {
                        "next_hop": next_hop,
                        "cost": cost,
                        "interface": interface,
                        "advertised_by": "self (static)",
                        "last_update": time.time(),  # Static routes don't age out by time but need this field
                        "type": "static"
                    }
                    self.router_logger.log_message(
                        f"[RIP] ✅ Added static route: {net} via {next_hop} on {interface.split('_')[-1]} (cost={cost})")
                    return True
                else:
                    self.router_logger.log_message(
                        f"[RIP] ℹ️ Static route {net} not added/updated: Existing static route is equal or better cost.")
                    return False
        except ValueError as e:
            self.router_logger.log_message(f"[RIP] ❌ Invalid network format for static route '{network_str}': {e}")
            return False

    def remove_static_route(self, network_str: str) -> bool:
        """
        Removes a static route from the routing table.
        Returns True if removed, False otherwise (e.g., if not found or not a static route).
        """
        try:
            net = ipaddress.ip_network(network_str)
            with self._rt_lock:
                current_route = self._routing_table.get(net)
                if current_route and current_route["type"] == "static":
                    del self._routing_table[net]
                    self.router_logger.log_message(f"[RIP] 🗑️ Removed static route: {net}")
                    return True
                else:
                    self.router_logger.log_message(f"[RIP] ⚠️ Cannot remove {net}: Not found or not a static route.")
                    return False
        except ValueError as e:
            self.router_logger.log_message(
                f"[RIP] ❌ Invalid network format for static route removal '{network_str}': {e}")
            return False

    def get_routing_table_view(self) -> List[Dict[str, Any]]:
        """Returns a copy of the current routing table for inspection, as a list of dictionaries."""
        with self._rt_lock:
            # Convert ipaddress.IPv4Network objects to strings for easier viewing/JSON serialization
            view = []
            for net, details in self._routing_table.items():
                entry = details.copy()
                entry["network"] = str(net)
                entry["subnet_mask"] = str(net.netmask)  # Add subnet mask for clarity
                entry["interface_friendly"] = entry["interface"].split('_')[-1]  # Add friendly name
                view.append(entry)
            return view

    def find_route(self, dest_ip_str: str) -> Dict[str, Any] | None:
        """Finds the best route for a destination IP using longest prefix match."""
        try:
            dest_ip_obj = ipaddress.ip_address(dest_ip_str)
            best_match = None
            best_prefix = -1

            with self._rt_lock:
                for net, rt_details in self._routing_table.items():
                    # For loopback IPs, if we have a loopback direct route, it's usually preferred.
                    # This implicitly handles the 127.0.0.0/8 network for local traffic.
                    if dest_ip_obj.is_loopback and rt_details["type"] == "direct" and \
                            rt_details["interface"] == self.interface_loopback_full_name:
                        # If a packet's destination is loopback and we have a direct loopback route
                        # This means it's for the local host's services.
                        return rt_details  # Directly return the loopback interface route

                    if dest_ip_obj in net:
                        # Prioritize based on:
                        # 1. Longest prefix match
                        # 2. Lower cost
                        # 3. Static routes over RIP/Direct (if costs are equal and prefix matches)

                        current_match_is_better = False
                        if best_match is None:
                            current_match_is_better = True
                        elif net.prefixlen > best_prefix:
                            current_match_is_better = True
                        elif net.prefixlen == best_prefix:
                            if rt_details["cost"] < best_match["cost"]:
                                current_match_is_better = True
                            elif rt_details["cost"] == best_match["cost"]:
                                # Tie-breaker: prefer static over RIP/direct (policy based)
                                if rt_details["type"] == "static" and best_match["type"] != "static":
                                    current_match_is_better = True
                                # No preference if both are static/rip/direct and equal cost/prefix

                        if current_match_is_better and rt_details["cost"] < 16:  # Ensure route is not infinity
                            best_prefix = net.prefixlen
                            best_match = rt_details
            return best_match
        except ValueError:
            return None

    def get_forwarding_route(self, dest_ip: str) -> Optional[Dict[str, Any]]:
        """
        Returns a dict {"next_hop": str, "interface": str} for the best route, or None.
        'next_hop' may be '0.0.0.0' to indicate direct delivery.
        """
        route = self.find_route(dest_ip)
        if not route:
            return None
        return {"next_hop": route["next_hop"], "interface": route["interface"]}

    def _validate_rip_packet(self, pkt: Packet) -> bool:
        """Validates RIP packet for authentication if key is set."""
        if self.authentication_key:
            # For simplicity, assume authentication is done via a custom field or payload
            # In a real RIPv2 MD5 authentication, it's more complex (RFC 2082)
            # Here, we'll just check if the last 16 bytes of the UDP payload match the key.
            # This is a very basic placeholder for demonstration.
            if pkt.haslayer(UDP) and pkt[UDP].payload:
                payload_bytes = bytes(pkt[UDP].payload)
                if len(payload_bytes) >= len(self.authentication_key.encode()):
                    received_auth = payload_bytes[-len(self.authentication_key.encode()):].decode()
                    if received_auth == self.authentication_key:
                        return True
                    else:
                        self.router_logger.log_message(f"[RIP] 🚫 Authentication failed for packet from {pkt[IP].src}")
                        return False
                else:
                    self.router_logger.log_message(
                        f"[RIP] 🚫 Authentication required, but payload too short from {pkt[IP].src}")
                    return False
            else:
                self.router_logger.log_message(
                    f"[RIP] 🚫 Authentication required, but no UDP payload from {pkt[IP].src}")
                return False
        return True  # No authentication configured

    def handle_packet(self, pkt: Packet, inbound_ifname: str):
        """Processes an incoming RIP packet with detailed logging."""
        self.function_call_tracker.track(
            identifier='RipPacket',
            threshold=5,
            final_message=f"[RIP] 📘 Received packet on {inbound_ifname.split('_')[-1]}: {pkt.summary()}. Count: {{}}.",
            count_message=None,
        )
        try:
            rip = pkt[RIP]
            if not rip:
                self.router_logger.log_message("[RIP] Ignored packet with no RIP layer.")
                return

            if not self._validate_rip_packet(pkt):
                return  # Drop if authentication fails

            if rip.command == 1:  # RIP request
                self.router_logger.log_message(f"[RIP] Ignoring RIP request from {pkt[IP].src}")
                return
            if rip.command != 2:  # Not a response
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
                for i, entry in enumerate(rip.entries):
                    entry_net = f"{entry.address}/{entry.subnet_mask}"
                    net = ipaddress.ip_network(entry_net, strict=False)

                    cost = min(entry.metric + 1, 16)
                    current_route = self._routing_table.get(net)

                    # Route Update Logic (prioritizes static routes)
                    if current_route:
                        # If existing route is static, do not override unless the RIP cost is *significantly* better
                        # (and even then, in real routers, static routes are very sticky).
                        # For simplicity, a static route is not updated by RIP unless it's gone or invalid.
                        if current_route["type"] == "static":
                            if cost < current_route["cost"] and cost < 16:  # RIP route is better than static
                                self.router_logger.log_message(
                                    f"[RIP] ⚠️ Static route {net} may be overridden by RIP from {src_router} (cost {cost} < {current_route['cost']}). This is unusual for static routes. Ignoring for now.")
                                continue  # Static routes are generally not overridden by dynamic protocols.
                            else:
                                self.router_logger.log_message(f"[RIP] ℹ️ Skipping RIP update for static route {net}.")
                                continue  # Don't update static routes via RIP

                        # Update if from same source (RIP neighbor) or if RIP provides a better path
                        if current_route["advertised_by"] == src_router:
                            # Update existing RIP route from this neighbor
                            if current_route["cost"] != cost:
                                self.router_logger.log_message(
                                    f"[RIP] 🔄 Route update: {net} via {src_router} (cost changed {current_route['cost']}→{cost})")
                            current_route["cost"] = cost
                            current_route["last_update"] = time.time()
                            current_route[
                                "interface"] = inbound_ifname  # Update interface if RIP update came via different path
                            changed = True
                        elif cost < current_route["cost"]:  # RIP provides a better path from a different source
                            self.router_logger.log_message(
                                f"[RIP] ✨ Better route found: {net} via {src_router} (cost improved {current_route['cost']}→{cost})")
                            self._routing_table[net] = {
                                "next_hop": src_router,
                                "cost": cost,
                                "interface": inbound_ifname,
                                "advertised_by": src_router,
                                "last_update": time.time(),
                                "type": "rip"  # NEW: Route type
                            }
                            changed = True
                        # If cost is higher or equal, and not from the same source, do nothing (keep current route).
                    elif cost < 16:  # New route and not infinity
                        self._routing_table[net] = {
                            "next_hop": src_router,
                            "cost": cost,
                            "interface": inbound_ifname,
                            "advertised_by": src_router,
                            "last_update": time.time(),
                            "type": "rip"  # NEW: Route type
                        }
                        self.router_logger.log_message(
                            f"[RIP] ✅ New RIP route discovered: {net} via {src_router} (cost={cost})")
                        changed = True

            if changed:
                self.router_logger.log_message(f"[RIP] Routing table updated by neighbor {src_router}.")
        except Exception as e:
            # This catch block handles the case where haslayer() was true but dissection fails.
            self.router_logger.log_message(f"[RIP] Ignored packet: RIP or IP layer not found on full dissection. {e}")
            return

    def rip_from_suspicious_source(self, src_ip: str, pkt: Packet | None = None):
        """
        Handles RIP packets not destined for us. Tracks the sender, logs metadata,
        and optionally inspects route entries to passively map their advertised networks.
        """
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
                # Defensive: make sure .entries exists and is iterable
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
                    decoded_entries = self.parse_raw_rip_entries(pkt, raw_payload)

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

        # Optional: escalate on frequent hits
        if entry["count"] >= 10 and (entry["count"] % 10 == 0):
            self.router_logger.log_message(
                f"[RIP] 🚨 {src_ip} has sent {entry['count']} unsolicited RIP packets. Potential misconfigured or rogue router."
            )

    def parse_raw_rip_entries(self, packet, raw_data: bytes) -> list:
        """
        Parses raw RIP entries from a byte string, validates them, and logs malformed ones.
        """
        entries = []
        entry_size = 20
        for i in range(0, len(raw_data), entry_size):
            try:
                chunk = raw_data[i:i + entry_size]
                if len(chunk) < entry_size:
                    break  # Incomplete entry

                # Unpack the RIP entry data
                afi, tag, ip_raw, mask_raw, nh_raw, metric = struct.unpack("!HH4s4s4sI", chunk)

                # Convert raw bytes to dotted-decimal strings
                ip_str = ".".join(map(str, ip_raw))
                mask_str = ".".join(map(str, mask_raw))
                nh_str = ".".join(map(str, nh_raw))

                is_valid = True
                log_reason = ""

                # --- Validation Checks ---
                # 1. Check for a common malformed entry
                if ip_str == "0.2.0.0" and mask_str == "0.0.0.0" and nh_str == "0.0.0.0" and metric == 0:
                    self.sniffer.banned_packets.append(packet)
                    break
                # 2. Check if the AFI is for IPv4 (2)
                elif afi != 2 and afi != 0:  # AFI 0 is often used for authentication entries
                    self.sniffer.banned_packets.append(packet)
                    break

                # 3. Validate the IP address and mask
                try:
                    ipaddress.ip_address(ip_str)
                    # It's also good practice to check if the mask is a valid netmask,
                    # but this is a more advanced check.
                except ValueError:
                    self.sniffer.banned_packets.append(packet)
                    break

                # 4. Check for invalid metric (16 is infinity in RIPv2)
                if metric >= 16:
                    self.sniffer.banned_packets.append(packet)
                    break

                # --- End of Validation Checks ---

                if is_valid:
                    # If all checks pass, append the entry to the list
                    entries.append({
                        "afi": afi,
                        "route_tag": tag,
                        "ip": ip_str,
                        "mask": mask_str,
                        "next_hop": nh_str,
                        "metric": metric,
                    })
                else:
                    # Log the malformed entry and the reason, but do not append it.
                    self.router_logger.log_message(
                        f"[RIP] ⚠️ Parsed malformed entry: {ip_str}/{mask_str} via {nh_str} metric={metric}"
                    )

            except Exception as e:
                # If an exception occurs, the packet is likely corrupted beyond a single entry.
                self.router_logger.log_message(f"[RIP] ❌ Error unpacking RIP entry: {e}")
                break

        return entries

    def _find_common_supernet(self, networks: List[ipaddress.IPv4Network]) -> ipaddress.IPv4Network:
        """
        Correctly finds the smallest common supernet for a list of networks.
        """
        if not networks:
            raise ValueError("Network list cannot be empty.")

        # Sort the networks by address to find the first and last contiguous networks
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
        """
        Performs a more robust route summarization.
        It identifies groups of routes that can be summarized into a single,
        less-specific supernet to reduce the number of advertised entries.
        """
        if not routes:
            return []

        summarized_networks = set()
        final_advertisements = []

        # Group IPv4 routes by their /16 parent network for summarization
        prefix_groups = defaultdict(list)
        for route_details in routes:
            net = route_details["network"]

            # --- FIX: Check for IPv4Network before attempting to summarize ---
            if not isinstance(net, ipaddress.IPv4Network):
                final_advertisements.append(route_details)
                summarized_networks.add(net)
                continue
            # --- END FIX ---

            # Use the /16 parent as a general grouping mechanism
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
                            next(r for r in child_routes if r["network"] == current_summary_group_nets[0]))

                    current_summary_group_nets = [current_net]

            if len(current_summary_group_nets) > 1:
                group_details = [r for r in child_routes if r["network"] in current_summary_group_nets]
                self._process_and_add_summary(final_advertisements, summarized_networks, group_details)
            elif len(current_summary_group_nets) == 1 and current_summary_group_nets[0] not in summarized_networks:
                route_details = next(r for r in child_routes if r["network"] == current_summary_group_nets[0])
                final_advertisements.append(route_details)

        # Add any remaining routes that were not processed by the summarization logic
        for route in routes:
            if route["network"] not in summarized_networks:
                final_advertisements.append(route)

        return final_advertisements
    def _process_and_add_summary(self, final_advertisements: list, summarized_networks: set, group_details: list):
        """Helper to create and add a summary route to the final list."""
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
        """Periodically sends RIP advertisements and purges timed-out routes."""
        while not self._stop_event.is_set():
            self._send_advertisements()
            self._purge_routes()
            self._stop_event.wait(self.RIP_UPDATE_INTERVAL)
        self.router_logger.log_message("[RIP] Advertisement thread has exited.")

    def _send_advertisements(self):
        """Sends RIP updates on all configured interfaces."""
        with self._rt_lock:
            # Create a list of dictionaries from the routing table for summarization
            table_snapshot_for_summarization = []
            for net_obj, details in self._routing_table.items():
                temp_entry = details.copy()
                temp_entry["network"] = net_obj  # Keep as object for internal logic
                table_snapshot_for_summarization.append(temp_entry)

        # Apply summarization before advertising
        summarized_table_entries = self._summarize_routes(table_snapshot_for_summarization)

        for ifname, cfg in self._interfaces_config.items():
            if cfg.get("ip_addr") is None:
                continue

            # Skip loopback interface for RIP advertisements as it's not typically routed
            if "loopback" in ifname.lower() or "lo" == ifname.lower():
                continue

            entries = []
            for entry_details in summarized_table_entries:
                net = entry_details["network"]  # This is already an IPv4Network object
                # Only advertise 'direct' and 'rip' type routes
                if entry_details["type"] in ["direct", "rip"]:
                    # Split-horizon with poison reverse: if we learned a route via this interface,
                    # advertise it with metric 16 (infinity) on that interface.
                    metric_to_advertise = entry_details["cost"]
                    if entry_details["type"] == "rip" and entry_details["interface"] == ifname:
                        metric_to_advertise = 16  # Poison reverse

                    entries.append(RIPEntry(
                        addr=str(net.network_address),  # Corrected from 'address'
                        mask=str(net.netmask),  # Corrected from 'subnet_mask'
                        metric=metric_to_advertise
                    ))

            if not entries:
                continue

            base = Ether(src=cfg["mac"], dst="01:00:5e:00:00:09") / \
                   IP(src=cfg["ip_addr"], dst="224.0.0.9") / \
                   UDP(sport=520, dport=520) / \
                   RIP(cmd=2, version=2)

            # entries is a list of RIPEntry(...)
            rip_packet = reduce(lambda pkt, entry: pkt / entry, entries, base)
            # Add authentication data if configured (simple append to UDP payload)
            if self.authentication_key:
                auth_payload = self.authentication_key.encode()
                # Scapy's UDP layer doesn't directly support appending to payload easily.
                # Reconstruct UDP with raw payload. This is a hack for plaintext auth.
                # A proper RIPv2 MD5 auth would involve a specific RIPAuthEntry.
                rip_packet[UDP].payload = bytes(rip_packet[UDP].payload) + auth_payload
                del rip_packet[UDP].len  # Scapy will recalculate
                del rip_packet[UDP].chksum  # Scapy will recalculate

            try:
                self.router_logger.log_message(
                    f"[RIP] 📺 Sending advertisement on {ifname.split('_')[-1]} ({len(entries)} entries)")
                self.sniffer.sendp(rip_packet, iface=ifname, verbose=0)
            except Exception as e:
                self.router_logger.log_message(f"[RIP] ❌ Advertisement send failed on {ifname.split('_')[-1]}: {e}")

    def _purge_routes(self):
        """Removes RIP-learned routes that have not been updated recently."""
        with self._rt_lock:
            now = time.time()
            timed_out_routes = []
            for net, details in self._routing_table.items():
                # Only purge RIP-learned routes, not direct or static
                if details["type"] == "rip" and (now - details["last_update"]) > self.ROUTE_TIMEOUT:
                    timed_out_routes.append(net)
            for net in timed_out_routes:
                del self._routing_table[net]
                self.router_logger.log_message(f"[RIP] 🗑️ Timed out and removed RIP route: {net}")

    def start(self):
        """Starts the RIP advertisement thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._advertisement_loop, daemon=True, name="RIPManagerThread")
        self._thread.start()
        self.router_logger.log_message("[RIP] Manager thread started.")

    def stop(self):
        """Stops the RIP advertisement thread."""
        if self._thread and self._thread.is_alive():
            self.router_logger.log_message("[RIP] Stopping manager thread...")
            self._stop_event.set()
            self._thread.join(timeout=2)
            self.router_logger.log_message("[RIP] Manager thread stopped.")

    def redistribute_route(self, network: ipaddress.IPv4Network, next_hop: str, interface: str, cost: int,
                           source_protocol: str):
        """
        Placeholder for route redistribution logic.
        In a real scenario, this would inject routes learned from other protocols (e.g., OSPF)
        into the RIP routing table, respecting administrative distance and metrics.
        """
        self.router_logger.log_message(
            f"[RIP] Redistributing route: {network} via {next_hop} on {interface.split('_')[-1]} (cost={cost}) from {source_protocol}. (Placeholder - actual injection logic needed)")
        # Example: if you had an OSPF manager, it would call this to inject OSPF routes into RIP.
        # This would then trigger RIP updates.
        # For now, it's just logs. Actual implementation would involve adding to _routing_table with type "redistributed_rip" or similar.

    def _canon_iface_name(self, name: str) -> str:
        """Normalize iface names so comparisons are apples-to-apples."""
        if not name:
            return ""
        # Strip Windows device wrapper and keep the GUID-ish bit
        # e.g. "\Device\NPF_{GUID}" -> "{GUID}"
        out = name.strip()
        if "\\Device\\NPF_" in out:
            out = out.split("\\Device\\NPF_")[-1]
        # Common pattern in your code: take suffix after underscore
        # but only if it gives us a GUID-like token
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
            max_cost: int = 15,  # RIP infinity - 1
            allow_default_as_alt: bool = False  # keep False if your caller already tries default
    ) -> Dict[str, Any] | None:
        """
        Finds the best alternate route for a destination IP, avoiding the specified interface.
        - Skips special/broadcast/multicast addresses
        - Normalizes iface names before comparing
        - Optional: consider default route as an alternate (if not on excluded iface)
        """
        try:
            dest_ip = ipaddress.ip_address(dest_ip_str)
        except ValueError:
            return None

        # 0) Special addresses: don't even try
        if dest_ip.is_multicast or dest_ip.is_unspecified or dest_ip.is_reserved:
            return None
        # Limited broadcast (v4)
        if isinstance(dest_ip, ipaddress.IPv4Address) and dest_ip == ipaddress.IPv4Address("255.255.255.255"):
            return None

        best_match = None
        best_prefix = -1

        # Normalize excluded iface to match your table
        excluded = self._canon_iface_name(exclude_iface)

        default_v4 = ipaddress.ip_network("0.0.0.0/0")
        default_v6 = ipaddress.ip_network("::/0")
        default_candidate = None

        with self._rt_lock:
            for net, rt in self._routing_table.items():
                iface = self._canon_iface_name(rt.get("interface", ""))

                # Respect exclusion (avoid the bouncing interface)
                if iface == excluded:
                    continue

                # Cache default for later if allowed
                if allow_default_as_alt and (net == default_v4 or net == default_v6):
                    # only accept if cost OK
                    if rt.get("cost", 16) <= max_cost:
                        default_candidate = rt

                # Match only proper prefixes
                try:
                    if dest_ip not in net:
                        continue
                except Exception:
                    continue

                cost = int(rt.get("cost", 16))
                if cost > max_cost:
                    continue

                # Prefer loopback direct only if target is loopback and iface is loopback
                if dest_ip.is_loopback and rt.get("type") == "direct" and iface == self._canon_iface_name(
                        self.interface_loopback_full_name):
                    return rt

                # LPM, then lower cost, then static over dynamic
                better = False
                if best_match is None:
                    better = True
                elif net.prefixlen > best_prefix:
                    better = True
                elif net.prefixlen == best_prefix:
                    if cost < best_match.get("cost", 16):
                        better = True
                    elif cost == best_match.get("cost", 16):
                        if rt.get("type") == "static" and best_match.get("type") != "static":
                            better = True

                if better:
                    best_prefix = net.prefixlen
                    best_match = rt

        # If no prefix match, optionally return default (not on excluded iface)
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
        25565: ("Minecraft", "🧱"),
    }

    # ---- Core tunables ----
    NAT_PORT_MIN = 49152
    NAT_PORT_MAX = 65535
    NAT_TIMEOUT_SECONDS = 300
    STATEFUL_NAT_TIMEOUT_SECONDS = 300

    KEEP_ALIVE_PORT = 19999
    KEEP_ALIVE_PAYLOAD_FORMAT = "!H32s"  # 2 bytes port + 32-byte HMAC

    BAN_THRESHOLD = 3
    BAN_DURATION_SEC = 120

    # MTU / MSS clamp
    WAN_MTU_DEFAULT = 1480
    CLAMP_MSS = True

    # ---- Advanced Temp-Lease Policy ----
    DEFAULT_LEASE_SECS = 60
    DEFAULT_COOLDOWN_SECS = 10
    MAX_TEMP_LEASES_PER_IP = 2
    MAX_TEMP_LEASES_PER_PREFIX = 8  # /24 for IPv4, /64 for IPv6
    RATE_WINDOW_SEC = 60
    RATE_MAX_ATTEMPTS_PER_IP = 20
    RATE_MAX_ATTEMPTS_PER_PREFIX = 60

    # Graylist pipeline → possible auto-promotion
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

    # Uplink policy (deny temp-leases on certain uplinks)
    TEMP_LEASES_POLICY = {
        "deny_gateways": {"192.168.1.254"},
        "deny_cidrs": ["192.168.1.0/24"],
        "deny_ifaces": {"wan_att", "eth_att"},
    }

    # ---- NEW knobs ------------------------------------
    # Traffic we will NEVER NAT (bypass end-to-end)
    BYPASS_DST_CIDRS = [
        "224.0.0.0/4",  # IPv4 multicast
        "255.255.255.255/32",  # broadcast
        "169.254.0.0/16",  # link-local v4
    ]
    BYPASS_SRC_CIDRS = [
        "169.254.0.0/16",
    ]
    # NAT exemptions (no SNAT for these dsts; still allow DNAT inbound)
    NAT_EXEMPT_DST_CIDRS = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918
        "100.64.0.0/10",  # CGNAT
        "198.18.0.0/15",  # benchmarking nets
    ]

    # Treat these as “our” public VIPs (in addition to self.public_ip)
    PUBLIC_VIPS: set[str] = set()

    # Small fragment cache: (src,dst,proto,ident)->decision
    _FRAG_CACHE_TTL = 20.0

    def __init__(self, router_logger, sendback_manager, router_public_ip: str, packet_writer,
                 interfaces_config: Dict, rip_manager_find_route, arp_manager_resolve, function_call_tracker,
                 *, token_secret: Optional[bytes] = None):

        # External collaborators
        self.router_logger = router_logger
        self.sendback_manager = sendback_manager
        self.public_ip = router_public_ip  # primary public IP
        self.packet_writer = packet_writer
        self._interfaces_config = interfaces_config
        self._rip_manager_find_route = rip_manager_find_route
        self._arp_manager_resolve = arp_manager_resolve
        self.function_call_tracker = function_call_tracker

        # NAT port pools (per external IP)
        self._next_port_per_ip: Dict[str, int] = defaultdict(lambda: self.NAT_PORT_MIN)

        # === Tables (Multi-IP aware) ===
        # (src_ip, sport) -> (ext_ip, ext_port, ts)
        self._nat_table: Dict[Tuple[str, int], Tuple[str, int, float]] = {}
        # (ext_ip, ext_port) -> (src_ip, sport)
        self._nat_reverse_table: Dict[Tuple[str, int], Tuple[str, int]] = {}
        # (ext_ip, ext_port) -> (int_ip, int_port)
        self._static_mappings: Dict[Tuple[str, int], Tuple[str, int]] = {}
        # (canon_session) -> (ext_ip, ext_port, ts)
        self._stateful_nat_outbound: Dict[Tuple[Tuple[str, int], Tuple[str, int]], Tuple[str, int, float]] = {}
        # (ext_ip, ext_port) -> canon_session
        self._stateful_nat_inbound: Dict[Tuple[str, int], Tuple[Tuple[str, int], Tuple[str, int]]] = {}

        # Security / probes / bans
        self._port_probe_counts: Dict[str, int] = defaultdict(int)
        self._ban_list: Dict[str, float] = {}

        # Temp leases: src_ip -> (ext_ip, ext_port) -> info
        self._temp_nat_leases: Dict[str, Dict[Tuple[str, int], Dict[str, float | str | int]]] = defaultdict(
            lambda: defaultdict(dict))

        # Graylist score: (src_ip, ext_ip, ext_port) -> score
        self._gray_score: Dict[Tuple[str, str, int], int] = defaultdict(int)

        # Sliding windows (RL)
        self._ip_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=512))
        self._prefix_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1024))

        # Concurrency
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None

        # Router settings
        self.router_internal_ip_for_self_mapping: str = "0.0.0.0"
        self.WAN_MTU = self.WAN_MTU_DEFAULT
        self.MSS_CLAMP_V4 = max(536, self.WAN_MTU - 40)
        self.MSS_CLAMP_V6 = max(536, self.WAN_MTU - 60)

        # Uplink cache
        self._uplink_cache_ttl = 10.0
        self._uplink_last_refresh = 0.0
        self._uplink_gateway_ip: Optional[str] = None
        self._uplink_iface: Optional[str] = None

        # Token/HMAC for keepalive auth
        self._token_secret = token_secret or hashlib.sha256(f"{time.time()}:{random.random()}".encode()).digest()

        # NEW: Control for verbose logging
        self.debug_logging = False

        # Example static mappings (primary IP unless explicit external_ip passed)
        self.add_static_mapping(65406, "192.168.1.50", 88)
        self.add_static_mapping(80, "192.168.1.100", 80)
        self.add_static_mapping(443, "192.168.1.100", 443)
        self.add_static_mapping(2222, "192.168.1.10", 22)
        self.add_static_mapping(3389, "192.168.1.25", 3389)
        self.add_static_mapping(25565, "192.168.1.75", 25565)
        self._config_sanity()
        self._log("[NAT] 🚀 Manager initialized with Multi-IP and advanced temporary leases.")

    # ========================= VIP management =========================

    def set_public_ips(self, primary: str, vips: Iterable[str] | None = None):
        with self._lock:
            self.public_ip = primary
            self.PUBLIC_VIPS = set(vips or set())
        self._config_sanity()
        self._log(f"[NAT] 🌐 Public IP set to {primary}; VIPs={sorted(self.PUBLIC_VIPS)}")

    def add_public_vip(self, vip: str):
        with self._lock:
            self.PUBLIC_VIPS.add(vip)
        self._log(f"[NAT] ➕ Added VIP {vip}")

    def remove_public_vip(self, vip: str):
        with self._lock:
            self.PUBLIC_VIPS.discard(vip)
        self._log(f"[NAT] ➖ Removed VIP {vip}")

    # ========================= Lifecycle =========================

    def set_router_internal_ip(self, ip: str):
        self.router_internal_ip_for_self_mapping = ip
        self._log(f"[NAT] 🏠 Router internal IP set to {ip}")

    def start(self):
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="NATCleanup")
        self._cleanup_thread.start()
        self._log("[NAT] ✅ Cleanup thread started.")

    def stop(self):
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self._log("[NAT] 🛑 Manager stopped.")

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
        ent = getattr(self, "_frag_cache", {}).get(key)
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
        if not hasattr(self, "_frag_cache"):
            self._frag_cache = {}
        self._frag_cache[key] = (decision, time.time())

    def _has_dnat_mapping(self, external_ip: str, external_port: int, src_ip: str) -> bool:
        ext_key = (external_ip, int(external_port))
        with self._lock:
            if ext_key in self._static_mappings:
                return True
            if ext_key in self._stateful_nat_inbound:
                # If pinned to a specific remote and it matches, count as “has mapping”
                canon = self._stateful_nat_inbound[ext_key]
                _a, b = canon  # ((int_ip,int_port), (src_ip,dst_port))
                return src_ip == b[0]
            if ext_key in self._nat_reverse_table:
                return True
        return False

    def _classify_direction(self, inbound_iface: str, src_ip: str, dst_ip: str,
                            router_ips: set[str], wan_ifaces: set[str], lan_ifaces: set[str] | None) -> str:
        """
        Returns 'inbound', 'outbound', 'hairpin', or 'none'.
        Robust to tunnels/bridges: any pkt targeting our public/VIP is inbound-ish.
        """
        is_wan = inbound_iface in wan_ifaces
        is_dst_ours = (dst_ip == self.public_ip) or (dst_ip in self.PUBLIC_VIPS) or (dst_ip in router_ips)
        src_is_private = not self._is_global(src_ip)

        # If the packet is heading to our public/VIP, it’s either inbound or hairpin
        if is_dst_ours:
            # Hairpin when source is from a private space (typical LAN) and iface is not a clear WAN
            if src_is_private and not is_wan:
                return "hairpin"
            return "inbound"

        # Classic outbound: LAN→global
        if (lan_ifaces and inbound_iface in lan_ifaces) or (not is_wan):
            if self._is_global(dst_ip):
                return "outbound"

        return "none"

    def _handle_icmp_error_translation(self, packet) -> bool:
        """
        Translate ICMP error payloads so internal hosts get meaningful errors.
        Returns True if translated (packet mutated), False otherwise.
        """
        try:
            if ICMP in packet and IP in packet:
                ic = packet[ICMP]
                if ic.type in (3, 11, 12):  # dest unreachable, time exceeded, param problem
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

                    if dport and (inner_dst == self.public_ip or inner_dst in self.PUBLIC_VIPS):
                        mapping = self.get_internal_from_external(inner_dst, dport, inner_src)
                        if mapping:
                            # Re-route the outer ICMP back toward the original sender
                            packet[IP].dst = inner_src
                            self._log(f"[NAT] ℹ️ ICMP error translated for {inner_dst}:{dport}")
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
            # Behind AT&T-style private WAN, we SHOULD still NAT to RFC1918 dst
            # or the upstream gateway won't know how to return packets.
            self.NAT_EXEMPT_DST_CIDRS = [
                "100.64.0.0/10",   # CGNAT
                "198.18.0.0/15",   # benchmarking nets
            ]
            warn.append("[NAT] Adjusted NAT_EXEMPT_DST_CIDRS for private WAN (AT&T-style double NAT)")

        for vip in self.PUBLIC_VIPS:
            if self._is_private_or_cgn(vip):
                warn.append(f"VIP {vip} looks private/CGN/loopback")
        if warn:
            self._log("[NAT][SANITY] ⚠️ " + " | ".join(warn) +
                      " — SNAT may be a no-op; inbound leases will never be hit unless you truly receive traffic to these addresses.")
    # ========================= Entry =========================

    def handle_packet(
            self,
            packet,
            inbound_iface: str,
            *,
            router_ips: set[str],  # Includes self.public_ip AND self.PUBLIC_VIPS
            wan_ifaces: set[str],
            lan_ifaces: set[str] | None = None,
    ) -> bool | None:
        """
        Main entry point for processing a packet.
        This method is responsible for "learning" the packet's IP addresses
        and directing it through the appropriate NAT translation path.
        """
        try:
            if not self._is_ip(packet):
                return None

            has_tcp = TCP in packet
            has_udp = UDP in packet
            has_icmp = (ICMP in packet) or (ICMPv6 in packet)

            # --- Learning the IP address of the packet itself ---
            # Extract source and destination IP addresses from the packet's IP layer.
            # This is where the NATManager "learns" the packet's IPs.
            ipL = packet[IP] if IP in packet else packet[IPv6]
            src_ip = ipL.src
            dst_ip = ipL.dst

            if not (ipaddress.ip_address(src_ip) and ipaddress.ip_address(dst_ip)):
                self._log_debug(f"⚠️ Dropping packet with invalid/resolved IP strings: {src_ip} → {dst_ip}")
                return None

            self._log_debug(f"PKT_IN {src_ip} → {dst_ip} on {inbound_iface}")

            all_our_public_ips = self.PUBLIC_VIPS.union({self.public_ip}).union(router_ips)

            # Global bans
            with self._lock:
                ban_exp = self._ban_list.get(src_ip)
                if ban_exp and time.time() < ban_exp:
                    self._log(f"[NAT] 🛡️ Drop banned IP {src_ip}")
                    return False

            # Early bypass for specific types of traffic (multicast, broadcast, link-local)
            if self._is_multicast_or_broadcast(dst_ip) or \
                    self._ip_in_any(dst_ip, self.BYPASS_DST_CIDRS) or \
                    self._ip_in_any(src_ip, self.BYPASS_SRC_CIDRS):
                #self._log(f"[NAT] ⏭️ Bypass packet {src_ip} → {dst_ip}")
                return None

            # ICMP error translation (best-effort)
            if has_icmp and IP in packet:
                try:
                    if self._handle_icmp_error_translation(packet):
                        # Log is inside the helper
                        return None
                except Exception:
                    pass

            # UDP keep-alive control plane (to whichever external IP it targeted)
            if has_udp and UDP in packet and Raw in packet:
                try:
                    if int(packet[UDP].dport) == self.KEEP_ALIVE_PORT and (dst_ip in all_our_public_ips):
                        self.handle_keep_alive(packet, dst_ip)
                        return False  # Packet consumed by keep-alive
                except Exception:
                    pass

            # Fragment awareness (IPv4)
            if IP in packet and self._is_nonfirst_ipv4_fragment(packet):
                key = self._frag_key(packet)
                if key:
                    prior = self._frag_cache_get(key)
                    if prior is not None:
                        return prior
                return None  # Defer decision until first fragment

            # Direction classification based on source, destination, and interface
            direction = self._classify_direction(inbound_iface, src_ip, dst_ip, all_our_public_ips, wan_ifaces,
                                                 lan_ifaces)
            self._log_debug(f"DIR: {direction} for {src_ip} → {dst_ip}")

            # ---- Hairpin handling (L4-aware) ----
            # Hairpin traffic is when an internal host tries to reach another internal host
            # using the router's public IP.
            if direction == "hairpin":
                if not (has_tcp or has_udp):
                    return None
                trans = packet[TCP] if has_tcp else packet[UDP]
                ext_ip, ext_port = dst_ip, int(trans.dport)
                # Attempt to find an existing mapping for the external IP/port
                mapping = self.get_internal_from_external(ext_ip, ext_port, src_ip)
                if mapping:
                    internal_ip, internal_port = mapping
                    ipL.dst = internal_ip  # Rewrite destination to internal IP
                    trans.dport = int(internal_port)  # Rewrite destination port
                    # If router internal IP is configured, SNAT the source to the router's internal IP
                    if self.router_internal_ip_for_self_mapping and self.router_internal_ip_for_self_mapping != "0.0.0.0" and IP in packet:
                        old = ipL.src
                        ipL.src = self.router_internal_ip_for_self_mapping
                        self._recalc_checksums(packet)
                        self._log(f"[NAT][HAIRPIN] 🔁 {old} → {internal_ip}:{internal_port} (via {ext_ip}:{ext_port})")
                    if self._is_first_ipv4_fragment(packet):
                        key = self._frag_key(packet)
                        if key: self._frag_cache_set(key, True)
                    return True
                else:
                    # No mapping yet → let temp-lease path handle it explicitly
                    direction = "hairprobe"
                    self._log_debug(f"DIR: 🔁 hairprobe {src_ip} → {dst_ip}:{ext_port}")

            # ---- Inbound (WAN→us) upgrade to grayprobe when no mapping yet ----
            # If inbound to a public IP/VIP but no static/stateful mapping exists,
            # it becomes a "grayprobe" to potentially trigger a temporary lease.
            if direction == "inbound" and (has_tcp or has_udp):
                trans = packet[TCP] if has_tcp else packet[UDP]
                ext_port = int(trans.dport)
                if not self._has_dnat_mapping(dst_ip, ext_port, src_ip):
                    direction = "grayprobe"
                    self._log_debug(f"DIR: 🕵️ grayprobe {src_ip} → {dst_ip}:{ext_port}")

            # Gray probe: inbound to a VIP with no mapping yet.
            # `translate_inbound()` will either find a late mapping or grant a temp lease.
            if direction == "grayprobe":
                ok = self.translate_inbound(packet, dst_ip)
                if IP in packet and self._is_first_ipv4_fragment(packet):
                    key = self._frag_key(packet)
                    if key: self._frag_cache_set(key, bool(ok))
                return True if ok else False

            # Hair probe: hairpin to a VIP with no mapping yet (treat like inbound, but keep hairpin src NAT).
            if direction == "hairprobe":
                ok = self.translate_inbound(packet, dst_ip)
                if ok and self.router_internal_ip_for_self_mapping and self.router_internal_ip_for_self_mapping != "0.0.0.0" and IP in packet:
                    old = ipL.src
                    ipL.src = self.router_internal_ip_for_self_mapping
                    self._recalc_checksums(packet)
                    self._log(f"[NAT][HAIRPROBE] 🔁 {old} → {ipL.dst} (dst was {dst_ip})")
                if IP in packet and self._is_first_ipv4_fragment(packet):
                    key = self._frag_key(packet)
                    if key: self._frag_cache_set(key, bool(ok))
                return True if ok else False

            # Outbound SNAT (with exemptions)
            # This path handles traffic originating from the internal network
            # destined for external (global) IPs.
            if direction == "outbound":
                if self._ip_in_any(dst_ip, self.NAT_EXEMPT_DST_CIDRS):
                    self._log(f"[NAT] ⏭️ Outbound exempt: {src_ip} → {dst_ip}")
                    return None

                # TCP SYN pre-pin stateful mapping for new connections
                if has_tcp and (packet[TCP].flags & 0x02) and not (packet[TCP].flags & 0x10):  # SYN, not ACK
                    try:
                        sport = int(packet[TCP].sport)
                        dport = int(packet[TCP].dport)
                        internal_key = (src_ip, sport)
                        canon = _get_canonical_session_key(src_ip, sport, dst_ip, dport)
                        with self._lock:
                            if internal_key not in self._nat_table:
                                # Select an external IP (VIP) for this flow
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

                # Perform the actual outbound translation (SNAT)
                self.translate_outbound(packet)
                if IP in packet and self._is_first_ipv4_fragment(packet):
                    key = self._frag_key(packet)
                    if key: self._frag_cache_set(key, True)
                return True

            # None: intra-LAN / non-NAT traffic
            #self._log(f"[NAT] ℹ️ No NAT action for {src_ip} → {dst_ip} (direction: {direction})")
            return None

        except Exception as e:
            self._log_error(f"handle_packet error on {inbound_iface}: {e}")
            return None

    # ========================= Outbound (SNAT) =========================

    def _select_external_ip(self, dst_ip: str, *, internal_ip: str | None = None,
                            internal_port: int | None = None) -> str:
        """
        Choose an egress IP among primary + VIPs using sticky hashing.
        This keeps flows consistently on the same external IP without a policy table.
        """
        with self._lock:
            if not self.PUBLIC_VIPS:
                return self.public_ip
            pool = [self.public_ip, *sorted(self.PUBLIC_VIPS)]
        seed = f"{internal_ip}:{internal_port}:{dst_ip}".encode()
        idx = zlib.crc32(seed) % len(pool)
        return pool[idx]

    def translate_outbound(self, packet: Packet):
        """
        Translates the source IP and port of an outbound packet (SNAT).
        This is applied to packets originating from the internal network
        and destined for external IPs.
        """
        if not self._is_ip(packet):
            self._log_debug(f"Outbound non-IP: {self._safe_summary(packet)}")
            return
        ip = packet[IP] if IP in packet else packet[IPv6]

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
                # Reuse an existing stateful mapping
                ext_ip, new_port, _ = stateful
                self._stateful_nat_outbound[canon] = (ext_ip, new_port, now)
                self._log(f"[NAT] ➡️ SNAT stateful {ip.src}:{t.sport} → {ext_ip}:{new_port}")

            elif internal_key not in self._nat_table:
                # Create a new dynamic NAT mapping
                ext_ip = self._select_external_ip(ip.dst, internal_ip=ip.src, internal_port=int(t.sport))
                new_port = self._alloc_port(ext_ip)
                if new_port == -1:
                    # _alloc_port logs the error
                    return
                self._nat_table[internal_key] = (ext_ip, new_port, now)
                self._nat_reverse_table[(ext_ip, new_port)] = internal_key
                self._log(f"[NAT] ➡️ SNAT new {ip.src}:{t.sport} → {ext_ip}:{new_port}")

            else:
                # Renew an existing dynamic NAT mapping
                ext_ip, new_port, _ = self._nat_table[internal_key]
                self._nat_table[internal_key] = (ext_ip, new_port, now)
                self._log_debug(f"SNAT renew {ip.src}:{t.sport} → {ext_ip}:{new_port}")

        if not (ext_ip and new_port is not None):
            self._log_error(f"Failed to find/alloc mapping for {ip.src}:{t.sport}")
            return

        # Rewrite the packet's source IP and port
        ip.src = ext_ip
        t.sport = int(new_port)
        if self.CLAMP_MSS:
            self._maybe_clamp_mss(packet)
        self._recalc_checksums(packet)
        # Redundant log removed:
        # self._log(f"[NAT] Outbound translated: {ip.src}:{t.sport} -> {ip.dst}:{t.dport}")

    # ========================= Inbound (DNAT) =========================

    def translate_inbound(self, packet: Packet, external_ip: str) -> bool:
        """
        Translates the destination IP and port of an inbound packet (DNAT).
        This is applied to packets arriving from the external network
        and destined for one of the router's public IPs/VIPs.
        """
        if not self._is_ip(packet):
            self._log_debug(f"Inbound non-IP: {self._safe_summary(packet)}")
            return False

        ip_layer = packet[IP] if IP in packet else packet[IPv6]
        src_ip = ip_layer.src  # The original source IP from the external network

        with self._lock:
            ban_exp = self._ban_list.get(src_ip)
            if ban_exp and time.time() < ban_exp:
                self._log(f"[NAT] 🛡️ Drop banned IP {src_ip}")
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
        ext_port = int(trans.dport)  # The original destination port on the external IP

        # Get the internal mapping for the external IP and port.
        # This function handles static mappings, stateful mappings, dynamic reverse mappings,
        # and crucially, the temporary lease mechanism.
        mapping = self.get_internal_from_external(external_ip, ext_port, src_ip)
        if mapping:
            internal_ip, internal_port = mapping
            # Rewrite the packet's destination IP and port to the internal host
            ip_layer.dst = internal_ip
            trans.dport = int(internal_port)
            self._apply_alg(packet, "inbound")
            self._bump_gray_score(src_ip, external_ip, ext_port, reason="hit")
            self._recalc_checksums(packet)
            # Redundant log removed:
            # self._log(f"[NAT] Inbound translated: {external_ip}:{ext_port} -> {internal_ip}:{internal_port} (from {src_ip})")
            return True

        # Log for failure is inside get_internal_from_external OR this:
        self._log(f"[NAT] 🚫 No DNAT for {src_ip} → {external_ip}:{ext_port} (ICMP sent)")
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
            self._static_mappings[ext_key] = (internal_ip, int(internal_port))
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
        """
        Secure lease refresh:
          payload = struct("!H32s"): (target_port, HMAC_SHA256(token_secret, f"{src_ip}|{ext_ip}|{target_port}|epoch_10s"))
        """
        if not (UDP in packet and Raw in packet and IP in packet):
            return
        try:
            payload = bytes(packet[Raw].load or b"")
            want = struct.calcsize(self.KEEP_ALIVE_PAYLOAD_FORMAT)
            if len(payload) != want:
                self._log(f"[NAT][KA] ⚠️ Bad payload size from {packet[IP].src}")
                return
            target_port, mac = struct.unpack(self.KEEP_ALIVE_PAYLOAD_FORMAT, payload)
        except Exception:
            self._log("[NAT][KA] ⚠️ Parse error")
            return

        src_ip = packet[IP].src

        if not self._verify_token(src_ip, external_ip, int(target_port), mac):
            self._log(f"[NAT][KA] ⛔ HMAC invalid from {src_ip} for {external_ip}:{target_port}")
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
                self._log(f"[NAT][KA] ❓ No active lease for {src_ip}@{external_ip}:{target_port}")

    def get_internal_from_external(self, external_ip: str, external_port: int, src_ip: str) -> Optional[
        Tuple[str, int]]:
        """
        Determines the internal IP and port for an inbound connection
        targeting a specific external IP and port. This is the core
        logic for DNAT, including temporary leases.
        """
        ext_key = (external_ip, int(external_port))

        with self._lock:
            # Sliding-window Rate Limiting
            now = time.time()
            pref = self._prefix_of(src_ip)
            self._prune_window(self._ip_attempts[src_ip], now)
            self._prune_window(self._prefix_attempts[pref], now)
            self._ip_attempts[src_ip].append(now)
            self._prefix_attempts[pref].append(now)

            if len(self._ip_attempts[src_ip]) > self.RATE_MAX_ATTEMPTS_PER_IP or \
                    len(self._prefix_attempts[pref]) > self.RATE_MAX_ATTEMPTS_PER_PREFIX:
                self._log(f"[NAT][RL] ⛔ Rate-limit {src_ip} or {pref}")
                return None

            # 1) Stateful return path (for existing connections)
            if ext_key in self._stateful_nat_inbound:
                canon = self._stateful_nat_inbound[ext_key]
                a, b = canon
                if src_ip == b[0]:  # Ensure the source IP matches the pinned remote
                    self._stateful_nat_outbound[canon] = (external_ip, int(external_port), now)
                    self._log(f"[NAT] ⬅️ DNAT stateful {external_ip}:{external_port} → {a[0]}:{a[1]} (from {src_ip})")
                    return a[0], int(a[1])

            # 2) Static DNAT (highest priority)
            static = self._static_mappings.get(ext_key)
            if static:
                self._bump_gray_score(src_ip, external_ip, int(external_port), reason="static")
                self._log(
                    f"[NAT] ⬅️ DNAT static {external_ip}:{external_port} → {static[0]}:{static[1]} (from {src_ip})")
                return static

            # 3) Dynamic reverse mapping (for previously established outbound connections)
            dyn = self._nat_reverse_table.get(ext_key)
            if dyn:
                if dyn in self._nat_table:
                    ext_ip_dyn, port_now, _ = self._nat_table[dyn]
                    self._nat_table[dyn] = (ext_ip_dyn, port_now, now)  # Refresh timestamp
                self._bump_gray_score(src_ip, external_ip, int(external_port), reason="dynamic")
                self._log(f"[NAT] ⬅️ DNAT dynamic {external_ip}:{external_port} → {dyn[0]}:{dyn[1]} (from {src_ip})")
                return dyn

            # 4) Probe path → advanced temporary lease policy
            # If no static or existing dynamic/stateful mapping, consider a temporary lease.
            self._port_probe_counts[src_ip] += 1
            count = self._port_probe_counts[src_ip]
            if count >= self.BAN_THRESHOLD:
                self._ban_list[src_ip] = now + self.BAN_DURATION_SEC
                self._log(f"[NAT] 🔒 Banned {src_ip} for {self.BAN_DURATION_SEC}s (probes={count})")
                return None

            # --- Applies temp leases between two different IPs ---
            # This function attempts to grant a temporary lease, effectively creating
            # a short-lived DNAT mapping from (external_ip, external_port) to a
            # dynamically chosen internal IP and the same port.
            lease = self._maybe_grant_temp_lease(src_ip, external_ip, int(external_port))
            if lease:
                # Logging is inside _maybe_grant_temp_lease
                pass
            return lease

    def get_internal_ip_from_external(self, external_ip: str) -> Optional[str]:
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
                self._static_mappings[ext_key] = (internal_ip, int(internal_port))
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
            }
        try:
            return json.dumps(data, indent=2, sort_keys=True)
        except Exception:
            return str(data)

    # ========================= Internals: Temp Leases =========================

    def _temp_ip_for(self, external_ip: str, external_port: int) -> str:
        """
        Pick a diagnostic-friendly internal IP for temp leases, sharded by VIP.
        Keeps your original 192.168.X.Y layout but salts by VIP last octet.
        This ensures that a temporary lease for a given (external_ip, external_port)
        always maps to a consistent internal IP, facilitating debugging and
        avoiding conflicts.
        """
        try:
            vip_tail = int(external_ip.split(".")[-1]) % 50  # 0..49 -> 192.168.(200..249).*
        except Exception:
            vip_tail = 0
        host = 100 + (external_port % 100)  # 100..199
        return f"192.168.{200 + vip_tail}.{host}"

    def _maybe_grant_temp_lease(self, src_ip: str, external_ip: str, external_port: int) -> Optional[Tuple[str, int]]:
        """
        Attempts to grant a temporary NAT lease for an inbound connection.
        This creates a dynamic DNAT mapping from (external_ip, external_port)
        to a temporary internal IP and the same port.
        """
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
                self._log(
                    f"[NAT][LEASE] ⏱️ Active {src_ip}@{external_ip}:{external_port} → {li['internal_ip']}:{li['internal_port']}")
                self._bump_gray_score(src_ip, external_ip, external_port, reason="active")
                return str(li["internal_ip"]), int(li["internal_port"])
            if now < float(li["cooldown_end"]):
                backoff = self._calc_backoff(li.get("failures", 0))
                li["cooldown_end"] = now + backoff
                self._log(
                    f"[NAT][LEASE] 🧯 Cooldown extended ({int(backoff)}s) for {src_ip}@{external_ip}:{external_port} (state={state})")
                return None

        if mode == "throttle" and random.random() > 0.5:
            self._log(f"[NAT][LEASE] ⛔ Throttled {src_ip}@{external_ip}:{external_port}")
            return None

        lease_secs = float(pol.get("lease_secs", self.DEFAULT_LEASE_SECS))
        cooldown_secs = float(pol.get("cooldown_secs", self.DEFAULT_COOLDOWN_SECS))
        temp_ip = self._temp_ip_for(external_ip, external_port)  # Dynamically chosen internal IP
        temp_port = int(external_port)  # The external port is mapped to the same internal port
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
            f"[NAT][LEASE] 🆕 {src_ip}@{external_ip}:{external_port} → {temp_ip}:{temp_port} for {int(lease_secs)}s (+{int(cooldown_secs)}s)")
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
            self._log(
                f"[NAT][LEASE] 🔶 {src_ip}@{external_ip}:{external_port} reached WARMUP (score={score}, reason={reason})")

        elif li["state"] == "warmup" and score >= self.TRUST_REQUIRED_HITS:
            li["state"] = "trusted"
            self._log(f"[NAT][LEASE] 🟢 {src_ip}@{external_ip}:{external_port} is TRUSTED (score={score})")

            if self.AUTO_PROMOTE_TO_DYNAMIC and ext_key not in self._nat_reverse_table:
                self._log(f"[NAT][LEASE] ℹ️ Auto-promote to dynamic enabled for {ext_key} (no-op placeholder)")

            if self.AUTO_PROMOTE_TO_STATIC and ext_key not in self._static_mappings:
                self._static_mappings[ext_key] = (li["internal_ip"], li["internal_port"])
                self._log(
                    f"[NAT][LEASE] ⬆️ Promoted to STATIC: {external_ip}:{external_port}→{li['internal_ip']}:{li['internal_port']}")

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
            with self._lock:
                # Dynamic NAT expiry
                for key in [k for k, (_, _, ts) in self._nat_table.items() if now - ts > self.NAT_TIMEOUT_SECONDS]:
                    ext_ip, ext_port, _ = self._nat_table.pop(key, (None, None, None))
                    ext_key = (ext_ip, ext_port)
                    if ext_ip and ext_port is not None and self._nat_reverse_table.get(ext_key) == key:
                        del self._nat_reverse_table[ext_key]
                    self._log(f"[NAT] 🗑️ Dynamic expired: {key} ({ext_ip}:{ext_port})")

                # Stateful expiry
                for canon in [k for k, (_, _, ts) in self._stateful_nat_outbound.items()
                              if now - ts > self.STATEFUL_NAT_TIMEOUT_SECONDS]:
                    ext_ip, ext_port, _ = self._stateful_nat_outbound.pop(canon, (None, None, None))
                    ext_key = (ext_ip, ext_port)
                    if ext_ip and ext_port is not None and ext_key in self._stateful_nat_inbound:
                        del self._stateful_nat_inbound[ext_key]
                    self._log(f"[NAT][STATEFUL] 🗑️ Expired {canon}")

                # Ban expiry
                for ip in [i for i, exp in self._ban_list.items() if now >= exp]:
                    del self._ban_list[ip]
                    self._port_probe_counts.pop(ip, None)
                    self._log(f"[NAT] ✅ Ban expired for {ip}")

                # Temp leases expiry + cooldown normalization
                for sip in list(self._temp_nat_leases.keys()):
                    for ext_key in list(self._temp_nat_leases[sip].keys()):
                        li = self._temp_nat_leases[sip][ext_key]
                        if now >= float(li["cooldown_end"]):
                            del self._temp_nat_leases[sip][ext_key]
                            gray_key = (sip, ext_key[0], ext_key[1])
                            self._gray_score.pop(gray_key, None)
                            self._log(f"[NAT][LEASE] ⏳ Cleared lease+cooldown {sip}@{ext_key[0]}:{ext_key[1]}")
                    if not self._temp_nat_leases[sip]:
                        del self._temp_nat_leases[sip]

            # Clean up fragment cache
            if hasattr(self, "_frag_cache"):
                with self._lock:
                    cutoff = now - self._FRAG_CACHE_TTL
                    for key in [k for k, (_, ts) in self._frag_cache.items() if ts < cutoff]:
                        try:
                            del self._frag_cache[key]
                        except Exception:
                            pass

            self._stop_event.wait(interval)

    # ========================= Uplink Policy =========================

    def _refresh_uplink_identity(self) -> None:
        now = time.time()
        if (now - self._uplink_last_refresh) < self._uplink_cache_ttl:
            return
        self._uplink_last_refresh = now

        r = self._rip_manager_find_route("8.8.8.8")
        if not r:
            self._uplink_gateway_ip = None
            self._uplink_iface = None
            return
        nh = r.get("next_hop")
        self._uplink_gateway_ip = None if (not nh or nh == "0.0.0.0") else str(nh)
        self._uplink_iface = r.get("interface")

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
            icmp_src_ip = external_ip
            icmp_dst_ip = original_ip_layer.src

            r = self._rip_manager_find_route(icmp_dst_ip)
            if not r:
                self._log_debug(f"⚠️ No route to {icmp_dst_ip} for ICMP; using fallback")
                self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3, src_ip=icmp_src_ip)
                return

            out_iface = r.get("interface")
            iface_cfg = self._interfaces_config.get(out_iface) or {}
            router_mac = iface_cfg.get("mac")
            next_hop_ip = r.get("next_hop")
            next_hop_ip = icmp_dst_ip if (not next_hop_ip or next_hop_ip == "0.0.0.0") else next_hop_ip
            next_hop_mac = self._arp_manager_resolve(next_hop_ip, out_iface)

            if not (router_mac and next_hop_mac):
                self._log_debug("⚠️ ARP failed for ICMP; fallback")
                self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3, src_ip=icmp_src_ip)
                return

            icmp = Ether(src=router_mac, dst=next_hop_mac) / IP(src=icmp_src_ip, dst=icmp_dst_ip) / ICMP(type=3,
                                                                                                         code=3) / original_ip_layer
            if IP in icmp and hasattr(icmp[IP], "chksum"): del icmp[IP].chksum
            if ICMP in icmp and hasattr(icmp[ICMP], "chksum"): del icmp[ICMP].chksum
            self.packet_writer._send_raw_packet(icmp, out_iface)
            self._log(f"[NAT] 🔕 ICMP Port Unreachable ({icmp_src_ip} → {icmp_dst_ip}) via {out_iface}")
        except Exception:
            self._log_debug("⚠️ ICMP send failed; fallback")
            try:
                self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3, src_ip=external_ip)
            except Exception:
                pass

    def _maybe_clamp_mss(self, packet: Packet):
        if TCP not in packet:
            return
        tcp = packet[TCP]
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):  # SYN && !ACK
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
            self._log(f"[NAT] ✂️ MSS clamp → {want}")

    def _alloc_port(self, external_ip: str) -> int:
        """Allocate a port for a specific external IP (per-IP pool)."""
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
        return (IP in pkt) or (IPv6 in pkt)

    def _recalc_checksums(self, pkt: Packet):
        try:
            if IP in pkt and hasattr(pkt[IP], "chksum"): del pkt[IP].chksum
        except Exception:
            pass
        try:
            if TCP in pkt and hasattr(pkt[TCP], "chksum"): del pkt[TCP].chksum
        except Exception:
            pass
        try:
            if UDP in pkt and hasattr(pkt[UDP], "chksum"): del pkt[UDP].chksum
        except Exception:
            pass

    # ========================= Logging Helpers (NEW) =========================

    def _log(self, msg: str):
        """Logs a standard (Info) message."""
        try:
            self.router_logger.log_message(msg)
        except Exception:
            pass

    def _log_debug(self, msg: str):
        """Logs a verbose debug message, only if debug_logging is True."""
        if not self.debug_logging:
            return
        try:
            self.router_logger.log_message(f"[NAT][DBG] {msg}")
        except Exception:
            pass

    def _log_error(self, msg: str):
        """Logs a critical error message."""
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
    """

    # --- Tunables (kept compatible with yours; added a few) ---
    DNS_CACHE_TTL                  = 300     # default TTL if we can't read any from response
    DNS_CACHE_TTL_CAP              = 3600    # cap overly-large TTLs to 1 hour
    DNS_CACHE_TTL_NEG              = 60      # TTL for negative answers if cached
    DNS_CACHE_MAX_ENTRIES          = 2000

    UPSTREAM_HEALTH_PROBE_INTERVAL = 180     # Seconds between health checks
    UPSTREAM_TIMEOUT_SEC           = 2.0     # Per-upstream wait budget (external loop)

    # New (optional) behaviors – leave disabled to keep your original dynamics
    ENABLE_CLIENT_RATELIMIT        = False
    RL_CLIENT_RPS                  = 30.0
    RL_CLIENT_BURST                = 60.0
    ENABLE_HEDGE                   = False   # if True, send to two upstreams (best+backup)

    def __init__(self, router_logger, packet_writer, router_ipv6_ll):
        # ---- Your existing state ----
        self.logger = router_logger
        self.pw = packet_writer
        self._lock = threading.RLock()
        self.router_ipv6_ll = router_ipv6_ll

        # Cache: LRU qkey -> (packet, expiry_ts, is_negative)
        self._dns_cache: "OrderedDict[str, Tuple[Packet, float, bool]]" = OrderedDict()

        # Pending forward maps
        self._pending_requests: Dict[Tuple, Dict] = {}  # primary key: ("4|6", router_src_ip, sport, txid)
        self._pending_by_txid: Dict[Tuple, Tuple] = {}  # secondary:   ("4|6", upstream_ip,  txid) -> primary

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

        # Optional hooks: blacklist/forwarding (user fills; helpers included)
        self.blacklist_rules: List[Dict[str, Any]] = []   # {"match": "...", "type": "suffix|exact|prefix|regex"}
        self.forward_rules: List[Dict[str, Any]] = []     # {"match": "...", "type": "...", "to": ["ip",...]}

        # In-flight de-dup: qkey -> {"waiters":[(client_pkt, iface), ...], "outstanding":[primary_keys...]}
        self._inflight: Dict[str, Dict[str, Any]] = {}

        # Client rate-limit buckets
        self._rl_clients: Dict[str, Dict[str, float]] = {}

        self._log("[DNS] 🧠 Manager initialized with stability features.")
        self.configure_upstreams()  # default cloud resolvers

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

        with self._lock:
            self.upstreams = [
                {"ip": ip, "latency_ms": 9999.0, "healthy": False, "last_probe": 0.0}
                for ip in servers
            ]
            self._dns64_enabled = bool(enable_dns64)
            self._dns64_prefix = str(dns64_prefix)

        self._log(f"[DNS] 🌐 Upstreams set: {servers}. {'DNS64 ON' if enable_dns64 else 'DNS64 OFF'} (prefix {dns64_prefix}).")

    def set_blacklist(self, rules: List[Dict[str, Any]]):
        """Install/replace blacklist rules list (exact/suffix/prefix/regex)."""
        with self._lock:
            self.blacklist_rules = list(rules or [])
        self._log(f"[DNS] ⛔ Blacklist updated: {len(self.blacklist_rules)} rule(s).")

    def set_forward_rules(self, rules: List[Dict[str, Any]]):
        """Install/replace conditional forwarding rules."""
        with self._lock:
            self.forward_rules = list(rules or [])
    def start(self):
        """Starts the background health probe thread."""
        if self._probe_thread and self._probe_thread.is_alive(): return
        self._stop_event.clear()
        self._probe_thread = threading.Thread(
            target=self._health_probe_loop,
            daemon=True,
            name="DNSHealthProber"
        )
        self._probe_thread.start()

    def stop(self):
        """Stops the background thread."""
        if not self._probe_thread or not self._probe_thread.is_alive(): return
        self._stop_event.set()
        self._probe_thread.join(timeout=2)

    # ===================== Health Probes =====================

    def _health_probe_loop(self):
        while not self._stop_event.is_set():
            self._run_health_probes()
            self._stop_event.wait(self.UPSTREAM_HEALTH_PROBE_INTERVAL)
        self._log("[DNS] 🩺 Health probe thread stopped.")

    def _run_health_probes(self):
        """Simulated probes; keep your structure intact but sortable on latency."""
        for u in self.upstreams:
            u["healthy"] = True
            u["latency_ms"] = random.uniform(10, 50)
            u["last_probe"] = time.time()

        with self._lock:
            self.upstreams.sort(key=lambda x: x["latency_ms"])

        if self.upstreams:
            best = self.upstreams[0]
            self._log(f"[DNS] 🩺 Best upstream: {best['ip']} ({best['latency_ms']:.2f} ms)")

    # ===================== Query Handling =====================

    def handle_query(self, packet: Packet, inbound_iface: str) -> bool:
        """Handles a client's DNS query."""
        if DNS is None or not (packet.haslayer(DNS) and packet[DNS].qr == 0):
            return False

        # Optional: per-client rate limiting
        if self.ENABLE_CLIENT_RATELIMIT:
            cip = self._client_ip(packet)
            if cip and not self._rl_take(cip):
                self._send_servfail(packet)  # soft failure under load
                self._log(f"[DNS] 🚦 RL applied to {cip}; SERVFAIL sent.")
                return True

        # Parse key
        qname, qtype, qkey = self._qname_qtype_key(packet)

        # Blacklist?
        if self._is_blacklisted(qname):
            self._log(f"[DNS] ⛔ Blocked {qname}")
            self._send_nxdomain(packet)
            return True

        # In-flight de-dup
        with self._lock:
            infl = self._inflight.get(qkey)
            if infl:
                infl["waiters"].append((packet, inbound_iface))
                self._log(f"[DNS] 🔁 Coalesced waiter for {qkey} (now {len(infl['waiters'])})")
                return True

        # Cache
        cached = self._cache_get(qkey)
        if cached:
            resp, negative = cached
            self._send_response_to_client(resp, packet)
            self._log(f"[DNS] 📦 {'NEG-' if negative else ''}CACHE HIT {qkey}")
            return True

        # Upstream set
        upstream_list = self._upstream_candidates(qname)
        if not upstream_list:
            self._log("[DNS] ❌ No healthy upstream servers available. Dropping query.")
            self._send_servfail(packet)
            return True

        # Register in-flight source set
        with self._lock:
            self._inflight[qkey] = {"waiters": [(packet, inbound_iface)], "outstanding": []}

        # Choose how many to send (hedge optional)
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
        with self._lock:
            info = self._pending_requests.pop(pk_primary, None)
            if info is None and pk_secondary:
                fwd_key = self._pending_by_txid.pop(pk_secondary, None)
                if fwd_key is not None:
                    info = self._pending_requests.pop(fwd_key, None)
                    matched_via = "secondary"

        if not info:
            # not ours
            return False

        # Normalize checksums
        self._normalize_checksums(packet)

        # If hedged, cancel siblings
        qkey = info.get("qkey")
        self._cancel_hedge_siblings(qkey, pk_primary, packet)

        # Apply DNS64 (if eligible)
        final_resp = self._apply_dns64_if_needed(packet)

        # Cache (with negative-awareness)
        try:
            is_negative = final_resp[DNS].rcode in (2, 3)  # SERVFAIL/NXDOMAIN
            self._cache_put_from_response(final_resp, negative=is_negative)
        except Exception:
            pass

        # Fanout to all waiters for this qkey
        waiters = self._pop_waiters(qkey)
        for client_pkt, in_iface in waiters:
            self._send_response_to_client(final_resp, client_pkt)

        # Log
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

            # Synthesize AAAA
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
        if use_ipv4:
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
        elif self._is_v6_ll(target_ip):
            v6_dst = target_ip.split("%", 1)[0]
            fwd[IPv6].dst = v6_dst
            fwd[UDP].dport = 53
            if self.router_ipv6_link_local_out:
                fwd[IPv6].src = self.router_ipv6_link_local_out.split("%", 1)[0]
            sport = self._alloc_udp_ephemeral_port()
            fwd[UDP].sport = sport
            self._normalize_checksums(fwd)
            fwd_key = ("6", fwd[IPv6].src, int(sport), int(fwd[DNS].id))
            sec_key = ("6", v6_dst, int(fwd[DNS].id))
            mode = "IPv6-LL"
        else:
            self._log(f"[DNS] ⚠️ Skip v6 upstream {target_ip}; no global/ULA WAN. Use IPv4.")
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

        if IP in original_request:
            # IPv4 client
            resp[IP].dst = original_request[IP].src
            resp[UDP].dport = int(original_request[UDP].sport)
            resp[DNS].id = original_request[DNS].id
            if self.router_ip_out:
                resp[IP].src = self.router_ip_out
            resp[UDP].sport = 53
            self._normalize_checksums(resp)
        elif IPv6 in original_request:
            # IPv6 LL client
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

    # ---- Logging / misc ----
    def _log(self, msg: str):
        try:
            self.logger.log_message(msg)
        except Exception:
            pass

    def _normalize_checksums(self, pkt: Packet):
        try:
            if IP in pkt and hasattr(pkt[IP], "chksum"): del pkt[IP].chksum
        except Exception:
            pass
        try:
            if UDP in pkt and hasattr(pkt[UDP], "chksum"): del pkt[UDP].chksum
        except Exception:
            pass

    # ---- Parsing helpers ----
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
        if IP in pkt: return pkt[IP].src
        if IPv6 in pkt: return str(pkt[IPv6].src)
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
        """Walk an/ns/ar to find any A record rdata."""
        try:
            for sect in ("an", "ns", "ar"):
                rr = getattr(dns, sect)
                while rr is not None:
                    if getattr(rr, "type", None) == 1:  # A
                        v4 = getattr(rr, "rdata", None)
                        if v4: return v4
                    rr = getattr(rr, "payload", None)
        except Exception:
            pass
        return None

    # ---- TTL & cache helpers ----
    def _ttl_from_response(self, dns, *, fallback: Optional[int] = None) -> int:
        """Return minimal TTL across records or a sane fallback."""
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
            # LRU move to MRU
            self._dns_cache.pop(qkey, None)
            self._dns_cache[qkey] = (pkt, expiry, negative)
            return pkt, negative

    # ---- In-flight de-dup helpers ----
    def _pop_waiters(self, qkey: Optional[str]) -> List[Tuple[Packet, str]]:
        if not qkey:
            return []
        with self._lock:
            infl = self._inflight.pop(qkey, None)
            return list(infl.get("waiters", [])) if infl else []

    def _cancel_hedge_siblings(self, qkey: Optional[str], winner_primary: Tuple, resp_pkt: Packet):
        """Remove sibling pending entries for a hedged set; keep winner mapped."""
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
                    # best-effort cleanup of sibling pending entries
                    self._pending_requests.pop(pk, None)
            infl["outstanding"] = keep

    # ---- Upstream choice & policy helpers ----
    def _upstream_candidates(self, qname: str) -> List[str]:
        """Resolve conditional forwarding first; else return healthy upstreams by latency."""
        # Conditional forwarding
        dst = self._match_forward(qname)
        if dst:
            return dst
        # Healthy by latency
        with self._lock:
            healthy = [u["ip"] for u in self.upstreams if u.get("healthy")]
        return healthy

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

    # ---- Small server-generated replies ----
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

    # ---- Utility ----
    def _alloc_udp_ephemeral_port(self) -> int:
        # 49152–65535 per IANA; keep it simple & safe
        return random.randint(49152, 65535)

    def _is_v6_ll(self, addr: str) -> bool:
        try:
            return ipaddress.IPv6Address(addr).is_link_local
        except Exception:
            return addr.lower().startswith("fe80:")

    def _is_ipv4(self, addr: str) -> bool:
        try:
            ipaddress.IPv4Address(addr)
            return True
        except Exception:
            return False

    # ---- Simple per-client token bucket (optional) ----
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

    def add_static_ndp_entry(self, ipv6_address: str, mac_address: str):
        """Adds a static entry to the neighbor cache."""
        self._static_ndp_entries[ipv6_address] = mac_address.lower()
        self.router_logger.log_message(f"[NDP] Added static entry: {ipv6_address} -> {mac_address}")

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

        now = time.time()
        ip_str = str(ip_obj)

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
                if now - ts < self.CACHE_TIMEOUT:
                    self.router_logger.log_message(f"[NDP] ⚡ Cache hit: {ip_str} -> {mac}")
                    return mac
                else:
                    self.router_logger.log_message(f"[NDP] 🕓 Cache stale for {ip_str}, refreshing.")
        os_mac = self._get_mac_from_os_cache(ip_str)
        if os_mac:
            with self._ndp_cache_lock:
                self._ndp_cache[ip_str] = (os_mac, now)
            return os_mac
    def _get_mac_from_os_cache(self, ipv6_address: str) -> Optional[str]:
        """
        Parses the Windows 'netsh' command to find a MAC in the OS neighbor cache.
        """
        try:
            # The regex looks for a MAC address on the same line as the IP
            mac_regex = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}")
            cmd = ["netsh", "interface", "ipv6", "show", "neighbors"]

            # Run the command and capture output
            result = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

            for line in result.splitlines():
                if ipv6_address in line:
                    match = mac_regex.search(line)
                    if match:
                        mac = match.group(0).lower().replace("-", ":")
                        self.router_logger.log_message(f"[NDP] 🧭 Found in OS cache: {ipv6_address} -> {mac}")
                        return mac
            return None
        except Exception:
            return None

    # --- Handling Incoming NDP Packets ---

    def learn_neighbor_advertisement(self, pkt: Packet):
        """Learn MAC from an IPv6 Neighbor Advertisement and update cache."""
        if not pkt.haslayer(ICMPv6ND_NA):
            return

        na = pkt[ICMPv6ND_NA]
        ip = pkt[IPv6].src
        mac = None

        # Preferred: use the NA option carrying a link-layer address.
        try:
            opt = pkt.getlayer(ICMPv6NDOptDstLLAddr) or pkt.getlayer(ICMPv6NDOptSrcLLAddr)
            if opt and hasattr(opt, "lladdr") and opt.lladdr:
                mac = opt.lladdr
        except Exception:
            mac = None  # keep going; we'll try a fallback

        # Fallback: if there’s no LL option, trust the L2 source (common on-link case)
        if mac is None and pkt.haslayer(Ether):
            mac = pkt[Ether].src

        # Optional sanity: only learn if the NA is “solicited” or override flag is set
        try:
            S = int(getattr(na, "S", 0))  # Solicited
            O = int(getattr(na, "O", 0))  # Override
            if not (S or O):
                # Unsolicited + no override → often a periodic announcement; you may skip
                pass
        except Exception:
            pass

        if ip and mac:
            with self._ndp_cache_lock:
                self._ndp_cache[ip] = (mac, time.time())
            self.router_logger.log_message(f"[NDP] 🧠 Learned: {ip} is-at {mac}")

    def learn_from_packet(self, pkt: Packet, iface: str):
        """
        Passively learns IP-to-MAC mappings from observed traffic.
        This is called by the main router for every packet.
        """
        # We can only learn if the packet has both L2 and L3 IPv6 headers
        if not pkt.haslayer(Ether) or not pkt.haslayer(IPv6):
            return

        src_mac = pkt[Ether].src
        src_ip = pkt[IPv6].src

        # Basic validation: ensure we have valid addresses to learn from
        try:
            ip_obj = ipaddress.IPv6Address(src_ip)
            if not src_mac or ip_obj.is_unspecified or ip_obj.is_multicast:
                return
        except ValueError:
            return

        now = time.time()
        with self._ndp_cache_lock:
            existing_entry = self._ndp_cache.get(src_ip)
            # Add or update the cache entry
            if not existing_entry or existing_entry[0] != src_mac:
                self.router_logger.log_message(f"[NDP] 🧠 Passively learned: {src_ip} is-at {src_mac} on {iface.split('_')[-1]}")
                self._ndp_cache[src_ip] = (src_mac, now)




class ARPManager:
    """
    Manages ARP resolution, caching, and related ARP operations for the router.
    Enhanced with Gratuitous ARP and a placeholder for ARP Snooping/Inspection.
    """
    @dataclass
    class GwOnlinkVerdict:
        ok: bool
        reason: str  # e.g. "not_on_link", "bad_cidr", "is_network", ...
        gw: str  # normalized gw string
        iface_cidr: str | None  # normalized CIDR or None
        net: str | None  # e.g. "192.168.1.0/24"
        details: dict  # extra flags for callers

    def _validate_gateway_onlink(self, gw_ip: str, iface_cidr: str | None,
                                 iface_ip: str | None = None) -> GwOnlinkVerdict:
        """
        Normalize & validate whether gw_ip is on-link for iface_cidr.
        Returns a structured verdict with reasons you can branch on.
        """
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
            gw = ipaddress.ip_address(gw_ip)
        except Exception as e:
            return self.GwOnlinkVerdict(False, f"bad_gw_ip({e})", gw_ip, iface_cidr, None, d)

        if not iface_cidr:
            d["cidr_missing"] = True
            return self.GwOnlinkVerdict(False, "cidr_missing", str(gw), None, None, d)

        try:
            net = ipaddress.ip_network(iface_cidr, strict=False)
        except Exception as e:
            return self.GwOnlinkVerdict(False, f"bad_cidr({e})", str(gw), iface_cidr, None, d)

        if gw.version != net.version:
            d["version_mismatch"] = True
            return self.GwOnlinkVerdict(False, "version_mismatch", str(gw), str(net), str(net), d)

        if gw not in net:
            return self.GwOnlinkVerdict(False, "not_on_link", str(gw), str(net), str(net), d)

        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen <= 30:
                if gw == net.network_address:
                    d["is_network"] = True
                    return self.GwOnlinkVerdict(False, "is_network", str(gw), str(net), str(net), d)
                if gw == net.broadcast_address:
                    d["is_broadcast"] = True
                    return self.GwOnlinkVerdict(False, "is_broadcast", str(gw), str(net), str(net), d)
            if ipaddress.IPv4Address(gw) in ipaddress.IPv4Network("169.254.0.0/16"):
                d["is_link_local"] = True
                return self.GwOnlinkVerdict(True, "link_local", str(gw), str(net), str(net), d)
        else:
            if ipaddress.IPv6Address(gw).is_link_local:
                d["is_link_local"] = True
                return self.GwOnlinkVerdict(True, "link_local", str(gw), str(net), str(net), d)

        if iface_ip:
            try:
                if ipaddress.ip_address(iface_ip) == gw:
                    d["is_self_ip"] = True
                    return self.GwOnlinkVerdict(False, "is_self_ip", str(gw), str(net), str(net), d)
            except Exception:
                pass

        return self.GwOnlinkVerdict(True, "ok", str(gw), str(net), str(net), d)

    def _is_usable_gw_ipv4(self, gw: ipaddress.IPv4Address, net: ipaddress.IPv4Network) -> tuple[bool, str]:
        if isinstance(net, ipaddress.IPv4Network) and net.network_address.is_link_local:
            return False, "link_local_unroutable"

        if gw.is_multicast:   return False, "multicast"
        if gw.is_unspecified: return False, "unspecified"
        if gw.is_loopback:    return False, "loopback"
        if gw.is_link_local:  return False, "gw_is_link_local"
        if net.prefixlen < 31:
            if gw == net.network_address:   return False, "is_network"
            if gw == net.broadcast_address: return False, "is_broadcast"
        if gw not in net:     return False, "not_on_link"

        return True, "ok"

    def __init__(self, router_logger, outbound_load_balancer, cache_timeout_seconds=300):
        """
        Initializes the ARP Manager.
        Args:
            router_logger: The logger instance for logging messages.
            cache_timeout_seconds (int): How long a cache entry is valid.
        """

        self.dhcp_server_out = None
        self.dhcp_server_in = None
        self.notification_manager = None
        self.sniffer = None
        self._active_ips = set()
        self.router_logger = router_logger
        self._arp_cache = {}  # Maps IP -> (MAC, timestamp)
        self._arp_cache_lock = threading.Lock()
        self.CACHE_TIMEOUT = cache_timeout_seconds
        self.dhcp_manager = None
        self._temp_arp_leases: dict[str, dict[str, float]] = {}
        self.enable_auto_temp_leases = True
        self.MAX_REPLIES_PER_LEASE  = 3
        self._trusted_ports = set()
        self.outbound_load_balancer = outbound_load_balancer
        self._static_arp_entries = {}  # {IP: MAC}
        self.interfaces_config = None
        self.router_ip_out = None
        self.default_gateway_ip = None
        self.arp_probe_offlink = True
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
        self.dai_enforce_on_untrusted_only = True  # only enforce on ports not in self._trusted_ports
        self.dai_block_gratuitous_from_untrusted = True
        self.dai_block_gateway_claims = True
        self.dai_block_ip_spoof = True
        self.dai_conflict_window = 90.0  # seconds to remember conflicting claims
        self.dai_conflict_threshold = 1  # 1 conflicting claim is enough to block
        self._dai_recent_claims = {}  # { "ip": { "mac": last_seen_ts, ... } }
        self._known_gateway_macs = {}  # { "gw_ip": "aa:bb:..." }  (learned)
        self.eset_compat_mode = True  # enable the guardrails
        self.quiet_start_s = 5.0  # first minute = quiet
        self._boot_ts = time.time()
        self.arp_probe_offlink = False
        self._offlink_nogw_suppress: dict[str, float] = {}
        self.garp_enabled = True  # hard off at boot (flip True if you really need it)
        self.garp_only_for_owned = True  # even when enabled, only for our own IPs

        self.ARP_PASSIVE_TTL = 20 * 60  # expire entries after 20 minutes (tune)
        self.ARP_MAX_ENTRIES = 10  # soft cap; oldest entries are trimmed
        self._last_passive_gc = 0.0  # last cleanup timestamp


    def _in_quiet_start(self) -> bool:
        try:
            return self.eset_compat_mode and (time.time() - self._boot_ts) < float(self.quiet_start_s)
        except Exception:
            return False
    def perform_arp_dai(self, pkt: Packet, inbound_iface: str) -> bool:
        """
        Return True = permit, False = block. Blocks ARP that would poison caches:
        - Gateway IP claimed by unexpected MAC on untrusted ports
        - Our own IPs claimed by foreign MACs
        - Gratuitous/self-claim requests from untrusted ports (unless expected)
        - Fast flip-flops (same IP, different MACs within a window)
        """
        if not self.dai_enable or not pkt.haslayer(ARP):
            return True

        if self._in_quiet_start():
            return True
        iface_name = inbound_iface.split("_")[-1]
        if self.dai_enforce_on_untrusted_only and inbound_iface in self._trusted_ports:
            return True

        arp = pkt[ARP]
        op = int(arp.op)  # 1=request, 2=reply
        spa = (arp.psrc or "").strip()
        sha = (arp.hwsrc or "").lower().strip()
        tpa = (arp.pdst or "").strip()
        tha = (arp.hwdst or "").lower().strip()

        # Basic sanity
        def _is_zero_mac(m):
            return m in ("", "00:00:00:00:00:00")

        def _log(block: bool, reason: str):
            level = "🚫 BLOCK" if block else "ℹ️  ALLOW"
            self.router_logger.log_message(
                f"[ARP][DAI] {level} {reason} on {iface_name}: op={op} {spa}({sha}) → {tpa}({tha})")

        # 0) If no sender IP (malformed) -> block
        try:
            ip_s = ipaddress.IPv4Address(spa)
        except Exception:
            _log(True, "bad_sender_ip")
            return False

        # 1) Gateway protection: anyone claiming to be the gateway must match known MAC
        if self.dai_block_gateway_claims and self._is_gateway_ip(spa):
            gw_mac_known = (self._known_gateway_macs.get(spa) or self._static_arp_entries.get(spa))
            if gw_mac_known and gw_mac_known.lower() != sha:
                _log(True, f"gateway_claim_mismatch expected={gw_mac_known.lower()}")
                # Optional active defense if it's a claim for *our* default-gw mapping seen on our L2:
                try:
                    if getattr(self, "arp_defend_on_claim", True) and self._can_defend_now(spa):
                        self._send_arp_announcement(inbound_iface, spa)
                except Exception:
                    pass
                return False

        # 2) Our IP protection: foreign MAC advertising any of our interface IPs
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

        # 3) DHCP/Static consistency (classic DAI): if we have leases/bindings, enforce them
        dhcp = self.dhcp_server_out or self.dhcp_server_in
        if dhcp:
            try:
                bindings = dhcp.get_ip_to_mac_bindings() or {}
                bmac = (bindings.get(spa) or "").lower()
                smac = (self._static_arp_entries.get(spa) or "").lower()
                expected = smac or bmac
                if expected and expected != sha:
                    _log(True, f"lease_mismatch expected={expected}")
                    return False
            except Exception:
                # If DHCP query fails, continue with heuristics
                pass

        # 4) Gratuitous/self-claim requests (who-has me tell me) from untrusted ports
        if op == 1 and self.dai_block_gratuitous_from_untrusted:
            # Spec: for requests, THA should be zeros; Ether dst is broadcast
            suspicious_tha = not _is_zero_mac(tha)
            is_self_claim = (spa == tpa)
            if is_self_claim or suspicious_tha:
                # Allow only if it matches our static/DHCP expectation (if present)
                expected = (self._static_arp_entries.get(spa) or "").lower()
                if not expected and dhcp:
                    try:
                        expected = (dhcp.get_ip_to_mac_bindings() or {}).get(spa, "").lower()
                    except Exception:
                        expected = ""
                if expected and expected != sha:
                    _log(True, f"gratuitous_mismatch expected={expected}")
                    return False
                # If no expectation, block self-claim on untrusted — this is what ESET flags most
                if not expected:
                    _log(True, "gratuitous_untrusted")
                    return False

        # 5) Fast flip-flop detection: same SPA advertised by different MACs within a window
        now = time.time()
        claims = self._dai_recent_claims.get(spa) or {}
        # prune old
        for m, ts in list(claims.items()):
            if now - ts > self.dai_conflict_window:
                claims.pop(m, None)
        # Count conflicts (any MAC ≠ current)
        conflict_cnt = sum(1 for m in claims.keys() if m != sha)
        claims[sha] = now
        self._dai_recent_claims[spa] = claims
        if conflict_cnt >= self.dai_conflict_threshold:
            _log(True, f"flip_flop ip={spa} conflicts={conflict_cnt}")
            return False

        _log(False, "passed")
        return True
    def _all_gateway_ips(self) -> set[str]:
        ips = set()
        try:
            if self.default_gateway_ip:
                ips.add(str(self.default_gateway_ip))
        except Exception:
            pass
        try:
            for cfg in (self.interfaces_config or {}).values():
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
    # ------------------------------------------------------------------------------

    def set_default_gateway(self, interfaces_config, gateway_ip: str):
        """Receives the default gateway IP from the main router manager."""
        self.router_logger.log_message(f"[ARP] Default gateway IP set to: {gateway_ip}")
        self.interfaces_config = interfaces_config
        self.default_gateway_ip = gateway_ip

    def set_dhcp_server_reference(self, dhcp_server_in, dhcp_server_out):
        """Sets a reference to the DHCPServer instance. This enables Dynamic ARP Inspection."""
        self.dhcp_server_in = dhcp_server_in
        self.dhcp_server_out = dhcp_server_out
        self.router_logger.log_message("[ARP] DHCP server reference set. Dynamic ARP Inspection is now active.")

    def add_trusted_port(self, iface_full_name: str):
        self._trusted_ports.add(iface_full_name)
        self.router_logger.log_message(f"[ARP] Added trusted port: {iface_full_name.split('_')[-1]}")

    def remove_trusted_port(self, iface_full_name: str):
        if iface_full_name in self._trusted_ports:
            self._trusted_ports.remove(iface_full_name)
            self.router_logger.log_message(f"[ARP] Removed trusted port: {iface_full_name.split('_')[-1]}")

    def add_static_arp_entry(self, ip_address: str, mac_address: str):
        self._static_arp_entries[ip_address] = mac_address
        self.router_logger.log_message(f"[ARP] Added static ARP entry: {ip_address} -> {mac_address}")

    def remove_static_arp_entry(self, ip_address: str):
        if ip_address in self._static_arp_entries:
            del self._static_arp_entries[ip_address]
            self.router_logger.log_message(f"[ARP] Removed static ARP entry for: {ip_address}")

    def perform_arp_inspection(self, pkt: Packet, inbound_iface: str) -> bool:
        """Dynamic ARP Inspection."""
        if not pkt.haslayer(ARP):
            return True
        arp_layer = pkt[ARP]
        sender_ip = arp_layer.psrc
        sender_mac = arp_layer.hwsrc

        static_mac = self._static_arp_entries.get(sender_ip)
        if static_mac and static_mac.lower() != sender_mac.lower():
            self.router_logger.log_message(
                f"[ARP][INSPECT] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on {inbound_iface.split('_')[-1]}: Static entry conflict ({static_mac})."
            )
            return False

        if inbound_iface in self._trusted_ports:
            return True

        dhcp_server_for_dai = self.dhcp_server_out or self.dhcp_server_in
        if dhcp_server_for_dai:
            dhcp_bindings = dhcp_server_for_dai.get_ip_to_mac_bindings()
            if sender_ip in dhcp_bindings:
                trusted_mac = dhcp_bindings[sender_ip]
                if sender_mac.lower() != trusted_mac.lower():
                    self.router_logger.log_message(
                        f"[ARP][DAI] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on untrusted port {inbound_iface.split('_')[-1]}: lease MAC {trusted_mac} mismatch."
                    )
                    return False
                return True
            else:
                self.router_logger.log_message(
                    f"[ARP][DAI] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on untrusted port {inbound_iface.split('_')[-1]}: IP not in DHCP leases."
                )
                return False

        self.router_logger.log_message(
            f"[ARP][INSPECT] ⚠️ No DHCP server reference. Permitting ARP from {sender_ip} on untrusted port {inbound_iface.split('_')[-1]}."
        )
        return True

    def _arp_resolve_ipv4(self, iface: str, target_ip: str) -> str | None:
        """Send an ARP who-has and return MAC, or None."""
        if not self.sniffer.iface_is_l2_capable(iface):
            self.router_logger.log_message(f"[ARP] ⚠️ {iface.split('_')[-1]} is L3-only; cannot ARP.")
            return None
        src_mac = self.get_interface_mac(iface)
        src_ip = self.get_interface_ipv4(iface) or "0.0.0.0"
        if not src_mac:
            return None
        req = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=src_ip, pdst=str(target_ip))
        ans = None
        for _ in range(self.arp_probe_retries):
            try:
                ans = srp1(req, timeout=self.arp_probe_timeout, verbose=0)
            except Exception:
                ans = None
            if ans and ans.haslayer(ARP):
                return ans[ARP].hwsrc
        return None

    def resolve(self, ip_address: str, iface: str | None) -> str | None:
        """
        Resolve an IPv4 address to a MAC (static -> cache -> DHCP -> temp lease -> OS cache -> probe -> scapy).
        """
        if self.sniffer is None:
            return None

        try:
            ip_str = str(ipaddress.ip_address(str(ip_address).strip()))
            if not isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv4Address):
                self.router_logger.log_message(f"[ARP] ⚠️ resolve: {ip_address} is not IPv4.")
                return None
        except Exception:
            self.router_logger.log_message(f"[ARP] ⚠️ resolve: invalid IP '{ip_address}'.")
            return None

        if ipaddress.ip_address(ip_str).is_loopback:
            self.router_logger.log_message(f"[ARP] ♻️ resolve: {ip_str} is loopback; no ARP.")
            return None

        now = time.time()

        mac = self._static_arp_entries.get(ip_str)
        if mac:
            with self._arp_cache_lock:
                self._arp_cache[ip_str] = (mac, now)
            self.router_logger.log_message(f"[ARP] 🧷 resolve: static {ip_str} → {mac}")
            return mac

        with self._arp_cache_lock:
            entry = self._arp_cache.get(ip_str)
        if entry:
            mac_cached, ts = entry[:2]
            if now - ts < self.CACHE_TIMEOUT:
                self.router_logger.log_message(f"[ARP] ⚡ resolve: cache {ip_str} → {mac_cached}")
                return mac_cached
            else:
                self.router_logger.log_message(f"[ARP] 🕓 resolve: cache stale for {ip_str} ({int(now-ts)}s), refreshing.")

        try:
            for dhcp_srv in (self.dhcp_server_in, self.dhcp_server_out):
                if not dhcp_srv:
                    continue
                bind = dhcp_srv.get_ip_to_mac_bindings() or {}
                mac = bind.get(ip_str)
                if mac:
                    with self._arp_cache_lock:
                        self._arp_cache[ip_str] = (mac, now)
                    self.router_logger.log_message(f"[ARP] 🔗 resolve: DHCP {ip_str} → {mac}")
                    return mac
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ⚠️ resolve: DHCP lookup failed: {e}")

        use_iface = iface
        if not use_iface:
            route = self.rip_manager.find_route(ip_str) if hasattr(self, "rip_manager") else None
            use_iface = (route.get("interface") if route else
                         (self.outbound_load_balancer.get_best_interface() if self.outbound_load_balancer else None))
            if use_iface:
                self.router_logger.log_message(f"[ARP] 🔎 resolve: chose iface {use_iface.split('_')[-1]} for {ip_str}")
            else:
                self.router_logger.log_message(f"[ARP] ❌ resolve: no interface available for {ip_str}")

        li = self._temp_arp_leases.get(ip_str)
        if li and now < li.get("lease_end", 0):
            if use_iface:
                our_mac = self.get_interface_mac(use_iface)
            else:
                our_mac = None
                try:
                    for ifk, cfg in (self.interfaces_config or {}).items():
                        if (cfg or {}).get("mac"):
                            our_mac = (cfg or {}).get("mac")
                            use_iface = ifk
                            break
                except Exception:
                    pass
            if our_mac:
                with self._arp_cache_lock:
                    self._arp_cache[ip_str] = (our_mac, now)
                self.router_logger.log_message(
                    f"[ARP] 🧪 resolve: temp-lease active for {ip_str}, returning our MAC {our_mac} on {use_iface.split('_')[-1] if use_iface else '?'}"
                )
                return our_mac
            else:
                self.router_logger.log_message(f"[ARP] ❌ resolve: temp-lease active for {ip_str} but no iface MAC available.")

        mac = self.fallback_mac_from_os_cache(ip_str)
        if mac:
            with self._arp_cache_lock:
                self._arp_cache[ip_str] = (mac, now)
            self.router_logger.log_message(f"[ARP] 🧭 resolve: OS cache {ip_str} → {mac}")
            return mac

        if use_iface:
            mac = self.send_custom_arp_request(ip_str, iface=use_iface, timeout=2)
            if mac:
                with self._arp_cache_lock:
                    self._arp_cache[ip_str] = (mac, now)
                self.router_logger.log_message(f"[ARP] 📡 resolve: active probe {ip_str} → {mac} on {use_iface.split('_')[-1]}")
                return mac
            else:
                self.router_logger.log_message(f"[ARP] 🚫 resolve: probe failed for {ip_str} on {use_iface.split('_')[-1]}")
        else:
            self.router_logger.log_message(f"[ARP] 🚫 resolve: no iface to probe {ip_str}")

        try:
            mac = getmacbyip(ip_str)
        except Exception:
            mac = None
        if mac:
            with self._arp_cache_lock:
                self._arp_cache[ip_str] = (mac, now)
            self.router_logger.log_message(f"[ARP] 🪂 resolve: getmacbyip {ip_str} → {mac}")
            return mac

        self.router_logger.log_message(f"[ARP] ⛔ resolve: failed for {ip_str}")
        return None

    def get_mac(self, target_ip: str, iface: str | None = None, timeout: int = 2,
                prefer_cache: bool = True, allow_active_probe: bool = True) -> str | None:
        """
        Best-effort MAC resolver for an IPv4 address.
        """
        try:
            ip = str(ipaddress.ip_address(str(target_ip).strip()))
            if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                self.router_logger.log_message(f"[ARP] ⚠️ get_mac: {ip} is not IPv4.")
                return None

            now = time.time()

            if ip in self._static_arp_entries:
                mac = self._static_arp_entries[ip]
                with self._arp_cache_lock:
                    self._arp_cache[ip] = (mac, now)
                self.router_logger.log_message(f"[ARP] 🧷 get_mac: static {ip} → {mac}")
                return mac

            if prefer_cache:
                with self._arp_cache_lock:
                    entry = self._arp_cache.get(ip)
                if entry:
                    mac, ts = entry[:2]
                    age = now - ts
                    if age < self.CACHE_TIMEOUT:
                        hits = self._cache_hit_table[ip]
                        hits.append(now)
                        while hits and now - hits[0] > 30:
                            hits.popleft()
                        if len(hits) <= 5:
                            self.router_logger.log_message(f"[ARP] ⚡ get_mac: cache hit {ip} → {mac}")
                        return mac
                    else:
                        self.router_logger.log_message(f"[ARP] 🕓 get_mac: cache entry for {ip} expired ({int(age)}s old), refreshing.")

            try:
                for dhcp_srv in (self.dhcp_server_in, self.dhcp_server_out):
                    if dhcp_srv:
                        bindings = dhcp_srv.get_ip_to_mac_bindings()
                        mac = bindings.get(ip)
                        if mac:
                            with self._arp_cache_lock:
                                self._arp_cache[ip] = (mac, now)
                            self.router_logger.log_message(f"[ARP] 🔗 get_mac: DHCP binding {ip} → {mac}")
                            return mac
            except Exception as e:
                self.router_logger.log_message(f"[ARP] ⚠️ get_mac: DHCP binding lookup failed: {e}")

            lease = self._temp_arp_leases.get(ip)
            if lease and now < lease.get("lease_end", 0):
                use_iface = iface or (self.outbound_load_balancer.get_best_interface() if self.outbound_load_balancer else None)
                try:
                    our_mac = get_if_hwaddr(use_iface) if use_iface else None
                except Exception:
                    our_mac = None
                if our_mac:
                    with self._arp_cache_lock:
                        self._arp_cache[ip] = (our_mac, now)
                    self.router_logger.log_message(f"[ARP] 🧪 get_mac: temp lease active for {ip}, returning {our_mac}")
                    return our_mac

            mac = self.fallback_mac_from_os_cache(ip)
            if mac:
                with self._arp_cache_lock:
                    self._arp_cache[ip] = (mac, now)
                self.router_logger.log_message(f"[ARP] 🧭 get_mac: OS cache {ip} → {mac}")
                return mac

            if allow_active_probe:
                use_iface = iface or (self.outbound_load_balancer.get_best_interface() if self.outbound_load_balancer else None)
                mac = self.send_custom_arp_request(ip, iface=use_iface, timeout=timeout)
                if mac:
                    with self._arp_cache_lock:
                        self._arp_cache[ip] = (mac, now)
                    self.router_logger.log_message(f"[ARP] 📡 get_mac: active probe {ip} → {mac}")
                    return mac

            try:
                mac = getmacbyip(ip)
            except Exception:
                mac = None
            if mac:
                with self._arp_cache_lock:
                    self._arp_cache[ip] = (mac, now)
                self.router_logger.log_message(f"[ARP] 🪂 get_mac: getmacbyip fallback {ip} → {mac}")
                return mac

            self.router_logger.log_message(f"[ARP] ⛔ get_mac: failed to resolve {ip}")
            return None

        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ get_mac({target_ip}) error: {e}")
            return None

    def send_gratuitous_arp(self, ip_address: str, mac_address: str, iface: str):
        """Sends a gratuitous ARP (announcement)."""
        if not getattr(self, "garp_enabled", True):
            self.router_logger.log_message(
                f"[ARP][ESET] 🔇 GARP disabled; skipping {ip_address} on {iface.split('_')[-1]}")
            return False

        if self._in_quiet_start():
            return True
        if getattr(self, "garp_only_for_owned", True) and not self._owns_ip(ip_address):
            self.router_logger.log_message(
                f"[ARP][ESET] 🚫 not-owned: suppressing GARP for {ip_address} on {iface.split('_')[-1]}")
            return False

        self.router_logger.log_message(f"[ARP] Sending Gratuitous ARP for {ip_address} ({mac_address}) on {iface.split('_')[-1]}")
        grat_arp = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", psrc=ip_address, pdst=ip_address, hwsrc=mac_address)
        try:
            self.sniffer.sendp(grat_arp, iface=iface, verbose=0)
            self.router_logger.log_message(f"[ARP] Successfully sent Gratuitous ARP on {iface.split('_')[-1]}.")
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Failed to send Gratuitous ARP on {iface.split('_')[-1]}: {e}")

    def send_custom_arp_request(self, target_ip: str, iface: str = None, timeout: int = 2) -> str | None:
        """Resolve a MAC for target_ip; ARP direct if on-link else ARP the gateway."""
        try:
            if self._in_quiet_start():
                return None
            ip_obj = ipaddress.ip_address(str(target_ip).strip())
            if not isinstance(ip_obj, ipaddress.IPv4Address) or self.is_special_ip(str(ip_obj)):
                self.router_logger.log_message(f"[ARP] ⚠️ Skipping ARP for special/non-IPv4 IP: {target_ip}")
                return None

            if iface:
                use_iface = iface
            else:
                route = self.rip_manager.find_route(str(ip_obj)) if hasattr(self, "rip_manager") else None
                use_iface = (route.get("interface") if route else
                             (self.outbound_load_balancer.get_best_interface() if self.outbound_load_balancer else None))
            if not use_iface:
                self.router_logger.log_message(f"[ARP] ❌ Cannot resolve {ip_obj}: No outbound interface determined.")
                return None

            iface_cfg = getattr(self, "_interfaces_config", {}).get(use_iface, {}) or {}

            net_obj = None
            net_val = iface_cfg.get("network")
            if isinstance(net_val, ipaddress.IPv4Network):
                net_obj = net_val
            elif iface_cfg.get("cidr"):
                try:
                    net_obj = ipaddress.ip_network(str(iface_cfg["cidr"]), strict=False)
                except Exception:
                    net_obj = None

            gw_obj = None
            gw_val = iface_cfg.get("gateway", None)
            if gw_val is None:
                gw_val = getattr(self, "default_gateway_ip", None)
            if gw_val is not None:
                try:
                    gw_obj = ipaddress.ip_address(str(gw_val))
                except Exception:
                    gw_obj = None

            def _is_on_link(ipv4: ipaddress.IPv4Address, net: ipaddress.IPv4Network) -> bool:
                return (ipv4 in net) and ipv4 not in (net.network_address, net.broadcast_address)

            if ip_obj.is_link_local:
                if net_obj and isinstance(net_obj, ipaddress.IPv4Network) and net_obj.network_address.is_link_local:
                    self.router_logger.log_message(f"[ARP][LL] 📡 {ip_obj} is link-local; sending direct ARP on {use_iface.split('_')[-1]}")
                    return self._arp_resolve_ipv4(use_iface, str(ip_obj))
                else:
                    self.router_logger.log_message(f"[ARP][LL] ⛔ {ip_obj} is link-local; iface not 169.254/16. Not ARPing.")
                    return None

            if isinstance(net_obj, ipaddress.IPv4Network) and isinstance(gw_obj, ipaddress.IPv4Address):
                if _is_on_link(gw_obj, net_obj):
                    self.router_logger.log_message(
                        f"[ARP] 🌐 {ip_obj} is off-link; resolving GW {gw_obj} on {use_iface.split('_')[-1]}")
                    return self._arp_resolve_ipv4(use_iface, str(gw_obj))
                else:
                    # gateway defined but not on this L2 → cannot ARP at all
                    if self._suppress_offlink_nogw(str(ip_obj)):
                        self.router_logger.log_message(
                            f"[ARP] 🔕 {ip_obj} off-link; GW {gw_obj} not on-link for {net_obj} (suppressed)")
                        return None
                    self.router_logger.log_message(
                        f"[ARP] ⛔ {ip_obj} off-link; GW {gw_obj} not on-link for {net_obj}; not ARPing")
                    return None

            if self.arp_probe_offlink and self.sniffer.iface_is_l2_capable(use_iface):
                self.router_logger.log_message(f"[ARP] 🧪 {ip_obj} appears off-link by route, probing L2 anyway on {use_iface.split('_')[-1]}.")
                mac = self._arp_resolve_ipv4(use_iface, str(ip_obj))
                if mac:
                    self.router_logger.log_message(f"[ARP] ✅ Probe succeeded; treating {ip_obj} as on-link.")
                    return mac

            self.router_logger.log_message(f"[ARP] ⛔ {ip_obj} is off-link and no valid on-link gateway; not ARPing")
            return None

        except ipaddress.AddressValueError:
            self.router_logger.log_message(f"[ARP] ⚠️ Invalid IP address format: {target_ip}")
            return None
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Unhandled exception in send_custom_arp_request for {target_ip}: {e}")
            return None

    def _suppress_offlink_nogw(self, ip: str, ttl: float = 120.0) -> bool:
        now = time.time()
        until = self._offlink_nogw_suppress.get(ip, 0.0)
        if now < until:
            return True
        self._offlink_nogw_suppress[ip] = now + ttl
        return False
    def _owns_ip(self, ip: str) -> bool:
        return ip in {cfg.get("ip_addr") for cfg in getattr(self, "_interfaces_config", {}).values() if cfg}

    def _lease_active(self, ip: str) -> bool:
        li = self._temp_arp_leases.get(ip)
        return bool(li and time.time() < li.get("lease_end", 0))

    def _lease_cooldown(self, ip: str) -> bool:
        li = self._temp_arp_leases.get(ip)
        return bool(li and time.time() < li.get("cooldown_end", 0))

    def is_special_ip(self, ip_str: str, iface_network: str | None = None) -> bool:
        """True if broadcast/network/loopback/multicast/link-local/unspecified/reserved (or invalid)."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return True
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return True
        if ip.is_link_local or ip == ipaddress.IPv4Address("255.255.255.255"):
            return True
        if iface_network:
            net = ipaddress.IPv4Network(iface_network, strict=False)
            if ip == net.network_address or ip == net.broadcast_address:
                return True
        return False

    def is_on_link(self, ip_str: str, iface_cidr: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(ip_str)
            net = ipaddress.IPv4Network(iface_cidr, strict=False)
            return ip in net and ip not in (net.network_address, net.broadcast_address)
        except ValueError:
            return False

    def learn_arp_response(self, pkt: Packet):
        """
        Learns and caches ARP is-at responses (ARP replies). Will NOT auto-lease gateways.
        """
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return

        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        iface = pkt.sniffed_on if hasattr(pkt, "sniffed_on") else "Unknown"
        now = time.time()

        static_mac = self._static_arp_entries.get(ip)
        if static_mac and static_mac.lower() != mac.lower():
            self.router_logger.log_message(
                f"[ARP] 🚫 Ignoring ARP response for {ip}: MAC {mac} conflicts with static entry {static_mac}."
            )
            return

        lease_info = self._temp_arp_leases.get(ip)
        if lease_info and now > lease_info["lease_end"]:
            cooldown_end = lease_info.get("cooldown_end", 0)
            if now < cooldown_end:
                self.router_logger.log_message(
                    f"[ARP][LEASE] ⏳ Lease for {ip} expired; cooldown still active ({cooldown_end - now:.1f}s left). Ignoring ARP from {mac}."
                )
                return
            new_lease_end = self.lease_cooldown
            new_cooldown_end = self.lease_duration
            self._temp_arp_leases[ip] = {
                "mac": mac,
                "lease_end": new_lease_end,
                "cooldown_end": new_cooldown_end,
                "replies_sent": 0,
            }
            self.router_logger.log_message(
                f"[ARP][LEASE] 🔄 New lease for {ip} → {mac} (dur=30s, cooldown=60s)."
            )
            return

        with self._arp_cache_lock:
            existing_entry = self._arp_cache.get(ip)
            if existing_entry:
                old_mac, _ = existing_entry[:2]
                if old_mac.lower() != mac.lower():
                    self.router_logger.log_message(
                        f"[ARP] ⚠️ MAC change detected for {ip}: {old_mac} → {mac} on {iface.split('_')[-1]}"
                    )
            else:
                self.router_logger.log_message(
                    f"[ARP] 🧠 Learned new ARP: {ip} → {mac} on {iface.split('_')[-1]}"
                )
                # SAFE: do NOT lease gateways or our own IPs
                ip_obj = ipaddress.ip_address(str(ip).strip())
                if (not ip_obj.is_link_local) and (not self._is_gateway_ip(ip)) and (not self._owns_ip(ip)) and not self.router_ip_out:
                    self.allow_temp_arp_lease(ip, self.lease_duration, self.lease_cooldown)

            self._arp_cache[ip] = (mac, now)

            if lease_info:
                self.router_logger.log_message(
                    f"[ARP][LEASE] ✅ ARP response accepted for {ip} under active temporary lease."
                )

    def _can_defend_now(self, ip: str) -> bool:
        t = time.time()
        last = self._arp_defense_last.get(ip, 0.0)
        if t - last >= self.arp_defense_cooldown:
            self._arp_defense_last[ip] = t
            return True
        return False

    def _send_arp_announcement(self, iface: str, ip: str, *, bursts: int = 2, gap: float = 0.2):
        """Gratuitous ARP announcement (RFC 5227)."""
        mac = self.get_interface_mac(iface)
        if not mac:
            return
        from scapy.layers.l2 import Ether, ARP
        for i in range(max(1, int(bursts))):
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(
                op=1, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst=ip
            )
            try:
                self.sniffer.sendp(pkt, iface=iface, verbose=False)
            except Exception:
                pass
            if gap > 0 and i + 1 < bursts:
                time.sleep(gap)
        self.router_logger.log_message(f"[ARP] 📣 Announced {ip} is-at {mac} on {iface.split('_')[-1]}")

    def reply_to_arp_request(self, request_pkt: Packet, iface: str):
        """
        Reply to ARP who-has iff policy allows. Never auto-lease gateways.
        """
        try:

            if not request_pkt.haslayer(ARP):
                return
            arp = request_pkt[ARP]
            if arp.op != 1:
                return

            target_ip = arp.pdst
            requester_ip = arp.psrc
            requester_mac = arp.hwsrc
            iface_cfg = (getattr(self, "_interfaces_config", {}) or {}).get(iface, {}) or {}
            iface_name = iface.split('_')[-1]
            iface_net = iface_cfg.get("network")

            def _own_mac_or_none():
                return (iface_cfg.get("mac") or getattr(self, "get_interface_mac", lambda _i: None)(iface))

            def _send_reply(psrc_ip: str, their_ip: str, their_mac: str, our_mac: str):
                reply = Ether(dst=their_mac, src=our_mac) / ARP(op=2, hwsrc=our_mac, psrc=psrc_ip, hwdst=their_mac, pdst=their_ip)
                self.sniffer.sendp(reply, iface=iface, verbose=False)
                self.router_logger.log_message(f"[ARP] 📢 Replied: {psrc_ip} is-at {our_mac} → {their_mac} on {iface_name}")

            def _learn_requester():
                try: self.learn_arp_response(request_pkt)
                except Exception: pass

            if self._in_quiet_start():
                if self._owns_ip(target_ip):
                    our_mac = _own_mac_or_none()
                    if our_mac:
                        reply = Ether(dst=requester_mac, src=our_mac) / ARP(op=2, hwsrc=our_mac, psrc=target_ip,
                                                                            hwdst=requester_mac, pdst=requester_ip)
                        self.sniffer.sendp(reply, iface=iface, verbose=False)
                        self.router_logger.log_message(
                            f"[ARP][ESET] 📢 (quiet) Replied for own {target_ip} on {iface_name}")
                else:
                    self.router_logger.log_message(
                        f"[ARP][ESET] 🤫 quiet-start: not replying for non-owned {target_ip} on {iface_name}")
                _learn_requester()
                return
            if self.is_special_ip(target_ip, iface_network=str(iface_net) if iface_net else None):
                if requester_ip == "0.0.0.0":
                    if self._owns_ip(target_ip) and getattr(self, "arp_defend_on_probe", True) and self._can_defend_now(target_ip):
                        self.router_logger.log_message(f"[ARP][PROBE] Probe for our {target_ip} from {requester_mac}; announcing on {iface_name}")
                        self._send_arp_announcement(iface, target_ip)
                    else:
                        self.router_logger.log_message(f"[ARP][PROBE] Probe for {target_ip} from {requester_mac} (ignored) on {iface_name}")
                    _learn_requester()
                    return

                if requester_ip == target_ip:
                    if self._owns_ip(target_ip):
                        our_mac = (_own_mac_or_none() or "").lower()
                        if our_mac and requester_mac.lower() != our_mac and getattr(self, "arp_defend_on_claim", True) and self._can_defend_now(target_ip):
                            self.router_logger.log_message(f"[ARP][DEFEND] Foreign claim for {target_ip} by {requester_mac}; announcing {target_ip} is-at {our_mac} on {iface_name}")
                            self._send_arp_announcement(iface, target_ip)
                        else:
                            self.router_logger.log_message(f"[ARP][DEFEND] Claim for {target_ip} from {requester_mac} (own_mac={'n/a' if not our_mac else our_mac}) on {iface_name}")
                    else:
                        self.router_logger.log_message(f"[ARP] 📨 Gratuitous ARP for {target_ip} from {requester_mac} on {iface_name} (learned)")
                        # SAFE: do not lease gateways
                        if not self._is_gateway_ip(target_ip):
                            self.allow_temp_arp_lease(target_ip, self.lease_cooldown, self.lease_duration)
                    _learn_requester()
                    return

                self.router_logger.log_message(f"[ARP] 🚫 Suppressed ARP for special IP {target_ip} on {iface_name} (learned {requester_mac})")
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
                    self.router_logger.log_message(f"[ARP][LEASE] ❌ No iface MAC for {iface_name}; cannot reply for {target_ip}")
                    _learn_requester()
                    return
                li["last_seen"] = time.time()
                if li["replies_sent"] < getattr(self, "MAX_REPLIES_PER_LEASE", 8):
                    li["replies_sent"] += 1
                    self.router_logger.log_message(
                        f"[ARP][LEASE] 🔓 Replying for leased {target_ip} with {our_mac} ({li['replies_sent']}/{getattr(self, 'MAX_REPLIES_PER_LEASE', 8)}) on {iface_name}"
                    )
                    _send_reply(target_ip, requester_ip, requester_mac, our_mac)
                else:
                    self.router_logger.log_message(f"[ARP][LEASE] ⛔ Budget exhausted for {target_ip} on {iface_name}; learning only")
                _learn_requester()
                return

            if getattr(self, "enable_auto_temp_leases", False) and not self._lease_cooldown(target_ip):
                iface_cidr = iface_cfg.get("cidr")
                if iface_cidr and self.is_on_link(target_ip, iface_cidr):
                    if target_ip not in getattr(self, "_static_arp_entries", {}):
                        dhcp_conflict = False
                        for dhcp_srv in (getattr(self, "dhcp_server_in", None), getattr(self, "dhcp_server_out", None)):
                            try:
                                if dhcp_srv and target_ip in dhcp_srv.get_ip_to_mac_bindings():
                                    dhcp_conflict = True
                                    break
                            except Exception:
                                pass
                        # SAFE: never auto-lease a gateway IP
                        if (not dhcp_conflict) and (not self._is_gateway_ip(target_ip)) and self.allow_temp_arp_lease(target_ip, lease_duration=120, cooldown=60):
                            our_mac = _own_mac_or_none()
                            if our_mac:
                                self.router_logger.log_message(f"[ARP][LEASE] ⚡ Auto-leased {target_ip}; replying with {our_mac} on {iface_name}")
                                _send_reply(target_ip, requester_ip, requester_mac, our_mac)
                                _learn_requester()
                                return

            _learn_requester()

        except Exception as e:
            self.router_logger.log_message(f"[ARP] 🚫 Exception {e}")

    def allow_temp_arp_lease(self, ip_address: str, lease_duration: int = 30, cooldown: int = 60):
        """
        Grants a temporary ARP lease for an IP (so we may respond to ARP for it).
        SAFE: will NOT lease a gateway IP.
        """
        if self._in_quiet_start():
            self.router_logger.log_message(
                f"[ARP][LEASE][ESET] 🤫 quiet-start: refusing temporary lease for {ip_address}")
            return False
        ip_address = str(ip_address).strip()

        # --- SAFETY: never lease gateways ---
        if self._is_gateway_ip(ip_address) or ip_address == self.router_ip_out:
            self.router_logger.log_message(f"[ARP][LEASE] 🚫 Refusing temporary lease for gateway IP {ip_address}.")
            return False

        now = time.time()
        current = self._temp_arp_leases.get(ip_address)

        if current and now < current.get("cooldown_end", 0):
            self.router_logger.log_message(
                f"[ARP][LEASE] ⏳ Cannot grant lease for {ip_address} — cooldown active until {time.ctime(current['cooldown_end'])}."
            )
            return False

        self._temp_arp_leases[ip_address] = {
            "lease_end": now + lease_duration,
            "cooldown_end": now + lease_duration + cooldown,
            "replies_sent": 0
        }

        self.router_logger.log_message(
            f"[ARP][LEASE] ✅ Temporary ARP lease granted for {ip_address} for {lease_duration}s (cooldown: {cooldown}s)."
        )
        return True

    def learn_from_packet(self, pkt: "Packet", inbound_iface: str):
        """
        Passively learn IPv4 IP→MAC mappings from observed traffic.
        - Learns from ARP (requests, replies, gratuitous)
        - Opportunistically learns from any IPv4 L3 packet’s source (L2 src → L3 src)
        """
        if not pkt.haslayer(Ether):
            return


        now = time.time()
        eth = pkt[Ether]
        src_mac = (eth.src or "").lower()



        if not self._is_unicast_mac(src_mac):
            return
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            try:
                op = int(a.op)  # 1=request, 2=reply
            except Exception:
                op = 0

            psrc = (a.psrc or "").strip()
            hwsrc = (a.hwsrc or "").lower().strip()

            if psrc and hwsrc and self._ipv4_ok_to_learn(psrc):
                self._update_arp_cache(psrc, hwsrc, now, "IPv4-arp", inbound_iface)

        if pkt.haslayer(IP):
            ip4 = pkt[IP]
            sip = getattr(ip4, "src", None)
            if sip and self._ipv4_ok_to_learn(sip):
                self._update_arp_cache(sip, src_mac, now, "IPv4-passive", inbound_iface)

        if (self._last_passive_gc or 0.0) + 30.0 <= now:
            cutoff = now - float(self.ARP_PASSIVE_TTL)

            with self._arp_cache_lock:
                # TTL prune: ONLY learned entries (len(tuple) >= 3)
                to_delete = []
                for ip, val in self._arp_cache.items():
                    if isinstance(val, tuple) and len(val) >= 3:
                        ts = val[1] if len(val) >= 2 else 0
                        if ts < cutoff:
                            to_delete.append(ip)
                for ip in to_delete:
                    self._arp_cache.pop(ip, None)

                # Size cap: trim ONLY learned entries, oldest first
                if self.ARP_MAX_ENTRIES and len(self._arp_cache) > int(self.ARP_MAX_ENTRIES):
                    learned = [
                        (ip, val[1])
                        for ip, val in self._arp_cache.items()
                        if isinstance(val, tuple) and len(val) >= 3
                    ]
                    self.router_logger.log_message(f"[ARP] 🧠 Learned {len(learned)}")
                    overflow = len(self._arp_cache) - int(self.ARP_MAX_ENTRIES)
                    removed = 0
                    if learned and overflow > 0:
                        learned.sort(key=lambda kv: kv[1])  # oldest ts first
                        for ip, mac in learned:
                            if removed >= overflow:
                                break
                            if ip in self._arp_cache:
                                self._arp_cache.pop(ip, None)
                                removed += 1
                    if removed:
                        self.router_logger.log_message(
                            f"[ARP] 🧹 ARP cache cleaned: removed {removed} learned entrie(s)."
                        )

            self._last_passive_gc = now
    def _update_arp_cache(self, ip: str, mac: str, now: float, reason: str, iface: str):
        with self._arp_cache_lock:
            cur = self._arp_cache.get(ip)
            if not cur or cur[0].lower() != mac.lower():
                self._arp_cache[ip] = (mac, now, "Learned")
                #self.router_logger.log_message(f"[ARP] 🧠 {reason}: {ip} is-at {mac} on {iface.split('_')[-1]}")


    def _is_unicast_mac(self, mac: str) -> bool:
        try:
            m = mac.replace("-", ":").lower()
            if m == "00:00:00:00:00:00":
                return False
            first_octet = int(m.split(":")[0], 16)
            return (first_octet & 1) == 0  # LSB=0 => unicast
        except Exception:
            return False

    def _ipv4_ok_to_learn(self, ip: str) -> bool:
        """
        Decide if we should attempt to learn/update an IPv4→MAC mapping for `ip`.

        Rules:
          • Reject special/bad IPv4 (unspecified, broadcast, loopback, multicast).
          • Do NOT learn for our own IPs or gateway IPs.
          • If cache has a protected entry (1- or 2-tuple), do NOT learn over it.
          • If cache has a 'Learned' entry (3-tuple), allow updates/refresh.

        Note: We don't have the candidate MAC here, so this only gates learning.
              The actual overwrite/flip policies should still be enforced in
              the caller (e.g., _maybe_commit_learn / _update_arp_cache).
        """
        try:
            ip4 = ipaddress.IPv4Address(ip)
        except Exception:
            return False
        if ip4.is_unspecified or ip4 == ipaddress.IPv4Address("255.255.255.255"):
            return False
        if ip4.is_multicast or ip4.is_loopback:
            return False

        with self._arp_cache_lock:
            entry = self._arp_cache.get(str(ip4))

        if entry is None:
            return True

        is_learned = isinstance(entry, tuple) and len(entry) >= 3
        if is_learned:
            return True
        return False

    def resolve_gateway_mac(self, gw_ip: str, iface: str, iface_cidr: str,
                            timeout: float = 2.0, retries: int = 2) -> str | None:
        """Resolve L2 MAC for a default gateway safely."""
        iface_ip = None
        try:
            iface_ip = (self.interfaces_config.get(iface, {}) or {}).get("ip_addr")
        except Exception:
            pass

        v = self._validate_gateway_onlink(gw_ip, iface_cidr, iface_ip)

        mac = self.fallback_mac_from_os_cache(v.gw)
        if mac:
            self.router_logger.log_message(f"[ARP][GW] ✅ Cache: {v.gw} → {mac}")
            return mac

        if not getattr(self, "sniffer", None):
            self.router_logger.log_message("[ARP][GW] ⚠️ No sniffer bound; cannot active-ARP")
            return None

        for attempt in range(1, retries + 1):
            self.router_logger.log_message(f"[ARP][GW] 📡 who-has {v.gw} on {iface} (try {attempt}/{retries})")
            try:
                req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=v.gw)
                ans = self.sniffer.sr2(req, iface=iface, timeout=timeout, verbose=0)
            except Exception as e:
                ans = None
                self.router_logger.log_message(f"[ARP][GW] ⚠️ ARP send error: {e}")

            if ans and ans.haslayer(ARP) and ans[ARP].op == 2 and ans[ARP].psrc == v.gw:
                mac = ans[ARP].hwsrc
                with self._arp_cache_lock:
                    self._arp_cache[v.gw] = (mac, time.time())
                self.router_logger.log_message(f"[ARP][GW] 🎯 Resolved {v.gw} → {mac}")
                return mac

        try:
            subprocess.run(["ping", "-n", "1", "-4", v.gw], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        mac = self.fallback_mac_from_os_cache(v.gw)
        if mac:
            self.router_logger.log_message(f"[ARP][GW] 🧭 Cache after ping: {v.gw} → {mac}")
            return mac
        if not mac:
            mac = getmacbyip(v.gw)
            return mac
        self.router_logger.log_message(f"[ARP][GW] ⛔ Could not resolve MAC for gateway {v.gw} on {iface}")
        return None

    def fallback_mac_from_os_cache(self, ip: str) -> str | None:
        """Return a sanitized MAC from the OS ARP cache for the given IPv4 address."""
        _MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}")
        try:
            cmds = [(["arp", "-a"], False), (["arp", "-an"], False)]
            for cmd, _ in cmds:
                try:
                    output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
                except Exception:
                    continue
                for line in output.splitlines():
                    if ip not in line:
                        continue
                    m = _MAC_RE.search(line)
                    if m:
                        mac = m.group(0).lower().replace("-", ":")
                        self.router_logger.log_message(f"[ARP] 🧭 OS cache: {ip} → {mac}")
                        return mac
            return None
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ⚠️ ARP cache parse failed: {e}")
            return None

    def _ifcache_get(self, key):
        c = getattr(self, "_if_cache", None)
        if not c:
            self._if_cache = {}
            return None
        ent = self._if_cache.get(key)
        if not ent:
            return None
        if (time.time() - ent["ts"]) > self._IFACE_CACHE_TTL:
            self._if_cache.pop(key, None)
            return None
        return ent["val"]

    def _ifcache_set(self, key, val):
        if not hasattr(self, "_if_cache"):
            self._if_cache = {}
        self._if_cache[key] = {"val": val, "ts": time.time()}

    def _resolve_os_iface_name(self, iface: str) -> str:
        """Map internal iface name to OS/Scapy name."""
        if iface.startswith("{") and iface.endswith("}"):
            return iface
        return iface.split("_")[-1]

    def get_interface_mac(self, iface: str) -> str | None:
        """Return lowercase MAC or None."""
        cache_key = ("mac", iface)
        cached = self._ifcache_get(cache_key)
        if cached is not None:
            return cached
        name = self._resolve_os_iface_name(iface)
        try:
            from scapy.all import get_if_hwaddr
            mac = get_if_hwaddr(name)
            if mac and mac != "00:00:00:00:00:00":
                mac = mac.lower()
                self._ifcache_set(cache_key, mac)
                return mac
        except Exception:
            pass
        try:
            from scapy.arch.windows import get_windows_if_list
            for a in get_windows_if_list():
                if name in (a.get("name"), a.get("win_name"), a.get("friendlyname"),
                            a.get("description"), a.get("guid")):
                    mac = (a.get("mac") or "").lower()
                    if mac:
                        self._ifcache_set(cache_key, mac)
                        return mac
        except Exception:
            pass
        try:
            import netifaces as ni
            if name in ni.interfaces():
                info = ni.ifaddresses(name).get(ni.AF_LINK, [{}])
                if info and "addr" in info[0]:
                    mac = info[0]["addr"].lower()
                    self._ifcache_set(cache_key, mac)
                    return mac
        except Exception:
            pass
        self._ifcache_set(cache_key, None)
        return None

    def get_interface_ipv4(self, iface: str) -> str | None:
        """Return primary IPv4 for iface or None."""
        cache_key = ("ipv4", iface)
        cached = self._ifcache_get(cache_key)
        if cached is not None:
            return cached
        name = self._resolve_os_iface_name(iface)
        try:
            from scapy.all import get_if_addr
            ip = get_if_addr(name)
            if ip and ip != "0.0.0.0":
                self._ifcache_set(cache_key, ip)
                return ip
        except Exception:
            pass
        try:
            from scapy.arch.windows import get_windows_if_list
            for a in get_windows_if_list():
                if name in (a.get("name"), a.get("win_name"), a.get("friendlyname"),
                            a.get("description"), a.get("guid")):
                    ips = a.get("ips") or []
                    for addr in ips:
                        if isinstance(addr, str) and addr.count(".") == 3:
                            self._ifcache_set(cache_key, addr)
                            return addr
        except Exception:
            pass
        try:
            import netifaces as ni
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


    def get_cache_view(self) -> dict:
        """Copy of current ARP cache."""
        with self._arp_cache_lock:
            return self._arp_cache.copy()

    def clear_cache(self):
        """Clear all ARP cache entries."""
        with self._arp_cache_lock:
            self._arp_cache.clear()
        self.router_logger.log_message("[ARP] 🧹 ARP cache cleared.")

class DHCPServer:
    """
    Acts as a DHCP server for devices.
    Assigns IP addresses from a defined pool to requesting clients.
    Enhanced with lease persistence, DHCP relay agent, multi-interface serving,
    and rogue-DHCP observation + policy (NAK-on-mismatch).

    NOTE:
      - Set serve_on_all_ifaces=False to restrict to LAN-only serving.
      - Rogue policy:
          * "log"              → only log other servers' Offers/Acks
          * "nak_on_mismatch"  → when a client REQUEST names a different server_id (opt54),
                                  send NAK (authoritative) to steer it back to us.
    """
    def make_duid(self, mac): return DUID_LLT(hwtype=1, timeval=int(time.time()), lladdr=mac)
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
        in_mac: None,
        dns_v6: str,
        search_domains: str
    ):
        import ipaddress, threading, time
        from typing import Dict, Tuple, Set
        self.ipaddress = ipaddress
        self.threading = threading
        self.time = time

        self.logger = router_logger
        self.packet_writer = packet_writer
        self.in_iface = router_in_interface_name
        self._interfaces_config = interfaces_config

        self.serve_on_all_ifaces = bool(serve_on_all_ifaces)
        self.authoritative = bool(authoritative)
        self.rogue_policy = rogue_policy
        self.dns_v6 = dns_v6
        self.search_domains = search_domains
        # --- DHCPv4 ---
        self.lease_pool_start = ipaddress.IPv4Address(dhcp_pool_start)
        self.lease_pool_end = ipaddress.IPv4Address(dhcp_pool_end)
        self._leases: Dict[str, Tuple[ipaddress.IPv4Address, float]] = {}  # mac -> (ip, expiry)
        self.dynamic_ip_pool = list(self._generate_ip_pool(self.lease_pool_start, self.lease_pool_end))
        self.available_ips = set(self.dynamic_ip_pool)
        self._static_leases: Dict[str, ipaddress.IPv4Address] = {}  # mac -> ip
        self._lease_lock = threading.Lock()
        self.LEASE_DURATION_SECONDS = 600
        self.dhcp_relay_target_ip = dhcp_relay_target_ip

        self.allow_out_of_pool = bool(allow_out_of_pool)
        self.enforce_same_subnet = bool(enforce_same_subnet)
        self._non_pool_leases: Set[ipaddress.IPv4Address] = set()
        self._reserved_ipv4: Set[ipaddress.IPv4Address] = set()

        # Track seen Offers/Acks from any server: mac -> dict(...)
        self._seen_server_offers: Dict[str, dict] = {}
        self._seen_v6_replies = {}
        # --- DHCPv6 ---
        self.dhcp6_prefix = ipaddress.IPv6Network(dhcp6_prefix) if dhcp6_prefix else None
        self.dhcp6_relay_target_ip = dhcp6_relay_target_ip
        self.router_ipv6_link_local_out = None
        self._stop_event = threading.Event()
        self._cleanup_thread = None
        self.sniffer = None
        self._dhcp6_srv_id = DHCP6OptServerId(duid=self.make_duid(in_mac))
        # =========================
        # 1) __init__(): add these DHCPv6 lease trackers (right after self._dhcp6_srv_id = ...)
        # =========================
        self.V6_LEASE_SECONDS = 3600
        self._v6_leases = {}  # client_duid_hex -> (ipaddress.IPv6Address, expiry_ts)
        self._v6_used = set()  # set[ipaddress.IPv6Address]
        self._v6_declined = set()  # set[ipaddress.IPv6Address]
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
        norm_mac = mac.lower()
        ip_addr = ipaddress.IPv4Address(ip)
        with self._lease_lock:
            in_cfg = self._interfaces_config.get(self.in_iface, {})
            net = in_cfg.get("network")
            router_ip = in_cfg.get("ip_addr")
            if router_ip and not self._reserved_ipv4:
                r = ipaddress.IPv4Address(router_ip)
                self._reserved_ipv4.add(r)
                if net:
                    self._reserved_ipv4.add(net.network_address)
                    self._reserved_ipv4.add(net.broadcast_address)
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
                mac = mac.lower()
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
                self._leases.pop(target_mac)
                self._static_leases.pop(target_mac, None)
            else:
                return False
            if ip_addr in self.dynamic_ip_pool and ip_addr not in self._reserved_ipv4:
                self.available_ips.add(ip_addr)
            self._non_pool_leases.discard(ip_addr)
            self.logger.log_message(f"[DHCP] 🔓 Released lease for {ip_addr}.")
            return True

    # ---------------- internals ----------------

    def _generate_ip_pool(self, start, end):
        current = int(start)
        end_int = int(end)
        while current <= end_int:
            yield self.ipaddress.IPv4Address(current)
            current += 1

    def get_ip_to_mac_bindings(self) -> dict:
        t = self.time.time()
        with self._lease_lock:
            return {str(ip): mac for mac, (ip, expiry) in self._leases.items() if t < expiry}

    def start(self):
        threading, time = self.threading, self.time
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_leases_loop, daemon=True, name="DHCPLeaseCleanup")
        self._cleanup_thread.start()
        self.logger.log_message("[DHCP] Cleanup thread started.")

    def stop(self):
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.logger.log_message("[DHCP] Server stopped.")

    def _cleanup_leases_loop(self):
        time = self.time
        while not self._stop_event.is_set():
            now = time.time()
            with self._lease_lock:
                expired_macs = [mac for mac, (ip, expiry) in self._leases.items() if expiry <= now]
                for mac in expired_macs:
                    ip, _ = self._leases.pop(mac)
                    if (ip in self.dynamic_ip_pool) and (ip not in set(self._static_leases.values())):
                        self.available_ips.add(ip)
                    self._non_pool_leases.discard(ip)
                    self.logger.log_message(f"[DHCP] 🗑️ IPv4 lease for {ip} (MAC: {mac}) expired.")
            self._stop_event.wait(60)

    def _assign_ip(self, client_mac: str, preferred_ip=None):
        ipaddress, time = self.ipaddress, self.time
        norm_mac = client_mac.lower()
        self.logger.log_message(f"[DHCP] Assigning IP for {norm_mac}")
        with self._lease_lock:
            in_cfg = self._interfaces_config.get(self.in_iface, {})
            net = in_cfg.get("network")
            router_in_ip = in_cfg.get("ip_addr")
            if router_in_ip and not self._reserved_ipv4:
                r = ipaddress.IPv4Address(router_in_ip)
                self._reserved_ipv4.add(r)
                if net:
                    self._reserved_ipv4.add(net.network_address)
                    self._reserved_ipv4.add(net.broadcast_address)
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
                                self.logger.log_message(f"[DHCP] ⚠️ Requested {preferred_ip} is out of pool and policy forbids it.")
                                preferred_ip = None
                        if preferred_ip is not None:
                            self._leases[norm_mac] = (preferred_ip, time.time() + self.LEASE_DURATION_SECONDS)
                            self.logger.log_message(f"[DHCP] 🎯 Honored requested IP {preferred_ip} for {norm_mac}")
                            return preferred_ip
            try:
                ip_from_pool = self.available_ips.pop()
                self._leases[norm_mac] = (ip_from_pool, time.time() + self.LEASE_DURATION_SECONDS)
                self.logger.log_message(f"[DHCP] 💻 Assigned new dynamic IP {ip_from_pool} to {norm_mac}.")
                return ip_from_pool
            except KeyError:
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
        msg_map = {"discover": 1, "offer": 2, "request": 3, "decline": 4, "ack": 5, "nak": 6, "release": 7, "inform": 8}
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
                if dport == 547 and sport == 546:
                    return "v6", "client"
                if sport == 547 and dport == 546:
                    return "v6", "server"
            if pkt.haslayer(DHCP6_InfoRequest):
                if dport == 547 and sport == 546:
                    return "v6", "client"
                if sport == 547 and dport == 546:
                    return "v6", "server"
            if pkt.haslayer(DHCP6_Reply):
                if dport == 547 and sport == 546:
                    return "v6", "client"
                if sport == 547 and dport == 546:
                    return "v6", "server"
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
        cfg = self._interfaces_config.get(inbound_iface)
        if cfg:
            return cfg
        return self._interfaces_config.get(self.in_iface, {})

    # ---------------- main packet handler ----------------

    def handle_packet(self, pkt, inbound_iface: str, find_route_function) -> bool:


        # Scope policy
        if not self.serve_on_all_ifaces and inbound_iface != self.in_iface:
            self.logger.log_message(f"[DHCP] Ignoring on non-LAN iface {inbound_iface} (serve_on_all_ifaces=False).")
            return True

        in_cfg = self._iface_cfg_for(inbound_iface)
        if not in_cfg:
            self.logger.log_message(f"[DHCP] Error: iface '{inbound_iface}' not found in configuration.")
            return True

        router_in_ip = in_cfg.get("ip_addr")
        router_in_mac = in_cfg.get("mac")

        version, direction = self._classify_dhcp(pkt)
        if version is None:
            return False  # not DHCP

        is_loopback_request = not pkt.haslayer(Ether)

        # ================= DHCPv4 =================
        if version == "v4":
            if not router_in_ip or not router_in_mac:
                self.logger.log_message(f"[DHCP] Error: '{inbound_iface}' missing IPv4 or MAC.")
                return True

            if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
                self.logger.log_message("[DHCP] Malformed v4 (missing BOOTP/DHCP); ignoring.")
                return True

            bootp_layer = pkt[BOOTP]
            dhcp_layer = pkt[DHCP]
            msg_type_norm = self._get_msg_type(dhcp_layer)

            # Derive client MAC from chaddr (first 6 bytes)
            try:
                raw_mac = bytes(bootp_layer.chaddr)[:6]
                client_mac = ":".join(f"{b:02x}" for b in raw_mac)
            except Exception:
                client_mac = "??:??:??:??:??:??"

            # ---- NEW: handle server→client frames instead of skipping
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

                tag = "our" if (sid == router_in_ip or src_mac.lower() == router_in_mac.lower()) else "other"
                self.logger.log_message(
                    f"[DHCP] v4 {kind} observed from {src_mac} (sid={sid or src_ip}) → {client_mac} yiaddr={yiaddr} on {inbound_iface} [{tag}]"
                )
                # We only observe; we don't respond to Offers/Acks from others here.
                # Actual enforcement happens when we receive the client's REQUEST (below).
                return True

            # ---- Client→Server handling (we serve/decide policy here)
            self.logger.log_message(
                f"[DHCP] 📨 v4 type {msg_type_norm} from {client_mac} on {inbound_iface} (xid {bootp_layer.xid})"
            )

            # Relay upstream (if configured)
            if self.dhcp_relay_target_ip:
                self.logger.log_message(f"[DHCP] Relaying v4 to {self.dhcp_relay_target_ip} (iface={inbound_iface}).")
                relay_packet = (
                    IP(src=router_in_ip, dst=self.dhcp_relay_target_ip) /
                    UDP(sport=67, dport=67) /
                    BOOTP(**{k: getattr(bootp_layer, k) for k in
                             ("op", "htype", "hlen", "hops", "xid", "secs", "flags",
                              "ciaddr", "yiaddr", "siaddr", "giaddr", "chaddr", "sname", "file")}) /
                    DHCP(options=dhcp_layer.options)
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

            # ---- DISCOVER
            if msg_type_norm == 1:
                assigned_ip = self._assign_ip(client_mac, preferred_ip=requested_ip if self.allow_out_of_pool else None)
                if not assigned_ip:
                    self.logger.log_message(f"[DHCP] No IP for DISCOVER from {client_mac}.")
                    return True
                opts = [("message-type", "offer"),
                        ("subnet_mask", str(in_cfg['network'].netmask)),
                        ("router", router_in_ip),
                        ("name_server", router_in_ip),
                        ("lease_time", self.LEASE_DURATION_SECONDS),
                        ("server_id", router_in_ip),
                        "end"]
                offer_l3 = (IP(src=router_in_ip, dst="255.255.255.255") /
                            UDP(sport=67, dport=68) /
                            BOOTP(op=2, xid=bootp_layer.xid, yiaddr=str(assigned_ip),
                                  siaddr=router_in_ip, chaddr=bootp_layer.chaddr) /
                            DHCP(options=opts))
                reply = (Ether(src=router_in_mac, dst="ff:ff:ff:ff:ff:ff") / offer_l3) if not is_loopback_request else offer_l3
                self.sniffer.send(reply, inbound_iface)
                self.logger.log_message(f"[DHCP] 📝 Offer {assigned_ip} → {client_mac} (iface={inbound_iface})")
                return True

            # ---- REQUEST (includes SELECTING/INIT-REBOOT/RENEW/REBIND)
            if msg_type_norm == 3:
                opt54 = self._get_server_id_opt54(dhcp_layer)  # server the client has chosen (if present)
                # Inside DHCPServer.handle_packet, under DHCP Request handling
                if opt54 and opt54 != router_in_ip:
                    if self.rogue_policy == "nak_on_mismatch":
                        # SAFETY CHECK: Only NAK if the IP they are requesting is actually
                        # inside MY managed pool. If they are requesting an IP from the
                        # other server's split pool, let it go.
                        req_ip = self._get_requested_ip_opt50(dhcp_layer)
                        if req_ip and req_ip in self.dynamic_ip_pool:
                            # Force NAK only if they are trying to take OUR ip with WRONG server ID
                            pass
                        else:
                            self.logger.log_message(
                                f"[DHCP] Ignoring request for {req_ip} managed by other server {opt54}")
                            return True
                # If client explicitly selected a different server, optionally NAK (authoritative policy)
                if opt54 and opt54 != router_in_ip and self.authoritative and self.rogue_policy == "nak_on_mismatch":
                    nak_l3 = (IP(src=router_in_ip, dst="255.255.255.255") /
                              UDP(sport=67, dport=68) /
                              BOOTP(op=2, xid=bootp_layer.xid, chaddr=bootp_layer.chaddr) /
                              DHCP(options=[("message-type", "nak"),
                                            ("server_id", router_in_ip),
                                            # RFC allows 'message' option for diagnostics; many stacks ignore
                                            ("message", "Use this DHCP server"),
                                            "end"]))
                    reply = (Ether(src=router_in_mac, dst="ff:ff:ff:ff:ff:ff") / nak_l3) if not is_loopback_request else nak_l3
                    self.sniffer.send(reply, inbound_iface)
                    self.logger.log_message(
                        f"[DHCP] 🚫 Authoritative NAK to {client_mac}: client named server_id={opt54}, ours={router_in_ip}."
                    )
                    return True

                preferred = requested_ip or ciaddr_ip
                assigned_ip = self._assign_ip(client_mac, preferred_ip=preferred if self.allow_out_of_pool else None)
                if not assigned_ip:
                    nak_l3 = (IP(src=router_in_ip, dst="255.255.255.255") /
                              UDP(sport=67, dport=68) /
                              BOOTP(op=2, xid=bootp_layer.xid, chaddr=bootp_layer.chaddr) /
                              DHCP(options=[("message-type", "nak"), ("server_id", router_in_ip), "end"]))
                    reply = (Ether(src=router_in_mac, dst="ff:ff:ff:ff:ff:ff") / nak_l3) if not is_loopback_request else nak_l3
                    self.sniffer.send(reply, inbound_iface)
                    self.logger.log_message(f"[DHCP] 🚫 NAK to {client_mac} (no IP) (iface={inbound_iface}).")
                    return True

                opts = [("message-type", "ack"),
                        ("subnet_mask", str(in_cfg['network'].netmask)),
                        ("router", router_in_ip),
                        ("name_server", router_in_ip),
                        ("lease_time", self.LEASE_DURATION_SECONDS),
                        ("server_id", router_in_ip),
                        "end"]
                ack_l3 = (IP(src=router_in_ip, dst=str(assigned_ip)) /
                          UDP(sport=67, dport=68) /
                          BOOTP(op=2, xid=bootp_layer.xid, yiaddr=str(assigned_ip),
                                siaddr=router_in_ip, chaddr=bootp_layer.chaddr) /
                          DHCP(options=opts))
                reply = (Ether(src=router_in_mac, dst=pkt[Ether].src) / ack_l3) if not is_loopback_request else ack_l3
                self.sniffer.send(reply, inbound_iface)
                self.logger.log_message(f"[DHCP] 🛰️ ACK {assigned_ip} → {client_mac} (iface={inbound_iface})")
                return True

            # ---- INFORM (no address)
            if msg_type_norm == 8:
                opts = [("message-type", "ack"),
                        ("router", router_in_ip),
                        ("name_server", router_in_ip),
                        ("server_id", router_in_ip),
                        "end"]
                ack_l3 = (IP(src=router_in_ip, dst="255.255.255.255") /
                          UDP(sport=67, dport=68) /
                          BOOTP(op=2, xid=bootp_layer.xid, yiaddr="0.0.0.0",
                                siaddr=router_in_ip, chaddr=bootp_layer.chaddr) /
                          DHCP(options=opts))
                reply = (Ether(src=router_in_mac, dst="ff:ff:ff:ff:ff:ff") / ack_l3) if not is_loopback_request else ack_l3
                self.sniffer.send(reply, inbound_iface)
                self.logger.log_message(f"[DHCP] ℹ️ INFORM ACK → {client_mac} (iface={inbound_iface})")
                return True

            # ---- RELEASE / DECLINE
            if msg_type_norm in (7, 4):
                freed = self.release_ipv4(client_mac, None)
                self.logger.log_message(
                    f"[DHCP] 🔓 {'RELEASE' if msg_type_norm == 7 else 'DECLINE'} from {client_mac} (freed={freed}) (iface={inbound_iface})"
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
                # Deterministic-ish + cached lease. Requires self.dhcp6_prefix set.
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

                # Hash -> host offset
                h = hashlib.sha256(key.encode("utf-8", "ignore")).digest()
                off = int.from_bytes(h[:8], "big") & ((1 << min(host_bits, 64)) - 1)

                # Avoid trivial offsets
                if off < 2:
                    off += 2

                cand = ipaddress.IPv6Address(base + off)

                # Avoid declined/used collisions: bump a little if needed
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
                # returns first IA_NA option (or None)
                try:
                    ia = pkt_.getlayer(DHCP6OptIA_NA)
                    return ia
                except Exception:
                    return None

            def _send_v6_reply(dst_ip6: str, dst_mac: str | None, dhcp6_payload):
                # Always UDP 547->546 for server replies
                router_ll_nz = _rm_zone(router_ll)
                dst_ip6_nz = _rm_zone(dst_ip6)
                if not router_ll_nz or not dst_ip6_nz:
                    return

                ip6 = IPv6(src=router_ll_nz, dst=dst_ip6_nz, hlim=1)
                udp = UDP(sport=547, dport=546)
                if (not is_loopback) and dst_mac:
                    out = Ether(src=router_in_mac, dst=dst_mac) / ip6 / udp / dhcp6_payload
                elif not is_loopback:
                    out = Ether(src=router_in_mac, dst="33:33:00:01:00:02") / IPv6(src=router_ll_nz, dst="ff02::1:2",
                                                                                   hlim=1) / udp / dhcp6_payload
                else:
                    out = ip6 / udp / dhcp6_payload
                self.sniffer.send(out, inbound_iface)

            def _add_dns_opts(reply_pkt):
                # DNSServers + DNSDomains (stateless options)
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
                # DHCP6OptStatusCode exists in scapy.contrib.dhcp6
                try:
                    return DHCP6OptStatusCode(statuscode=int(code), statusmsg=str(msg or ""))
                except Exception:
                    return None

            # One link-local for everything
            router_ll = self.router_ipv6_link_local_out
            if not router_ll:
                self.logger.log_message("[DHCP] v6: missing router IPv6 (no link-local/global); cannot serve.")
                return True

            # --- Frame/env details ---
            is_loopback = not pkt.haslayer(Ether)
            client_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
            v6src = pkt[IPv6].src  # client's source (usually link-local)

            # --- Pick the exact DHCPv6 subtype first, then fall back to base DHCP6 ---
            dhcp6 = None
            msgtype = 0

            if pkt.haslayer(DHCP6_Solicit):
                dhcp6 = pkt[DHCP6_Solicit]
                msgtype = 1
            elif pkt.haslayer(DHCP6_InfoRequest):
                dhcp6 = pkt[DHCP6_InfoRequest]
                msgtype = 11
            elif pkt.haslayer(DHCP6_Request):
                dhcp6 = pkt[DHCP6_Request]
                msgtype = 3
            elif pkt.haslayer(DHCP6_Renew):
                dhcp6 = pkt[DHCP6_Renew]
                msgtype = 5
            elif pkt.haslayer(DHCP6_Confirm):
                dhcp6 = pkt[DHCP6_Confirm]
                msgtype = 4
            elif pkt.haslayer(DHCP6_Release):
                dhcp6 = pkt[DHCP6_Release]
                msgtype = 8
            elif pkt.haslayer(DHCP6_Decline):
                dhcp6 = pkt[DHCP6_Decline]
                msgtype = 9
            elif pkt.haslayer(DHCP6_Advertise):
                dhcp6 = pkt[DHCP6_Advertise]
                msgtype = 2
            elif pkt.haslayer(DHCP6_Reply):
                dhcp6 = pkt[DHCP6_Reply]
                msgtype = 7  # FIXED (was DHCP6_Request)
            elif pkt.haslayer(DHCP6_RelayForward):
                dhcp6 = pkt[DHCP6_RelayForward]
                msgtype = 12
            elif pkt.haslayer(DHCP6_RelayReply):
                dhcp6 = pkt[DHCP6_RelayReply]
                msgtype = 13

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

                name = {2: "ADVERTISE", 7: "REPLY", 10: "RECONFIGURE", 13: "RELAY-REPLY"}.get(msgtype,
                                                                                              f"type={msgtype}")
                self.logger.log_message(
                    f"[DHCP] v6 {name} observed from {src_mac} → {dst_ll} [{tag}] DNS={dns_list or '[]'} DOM={dom_list or '[]'}"
                )
                return True

            # Observe server->client only
            if direction != "client":
                src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "(no-ether)"
                self.logger.log_message(f"[DHCP] v6 server→client observed from {src_mac}; skipping.")
                return True

            # -------- Relay (to upstream server) ----------
            if self.dhcp6_relay_target_ip:
                target = self.dhcp6_relay_target_ip  # can be LL or global of the upstream
                self.logger.log_message(f"[DHCP] Relaying v6 to {target}.")
                relay = (IPv6(src=router_ll, dst=target, hlim=255) /
                         UDP(sport=547, dport=547) /
                         DHCP6_RelayForward(linkaddr=router_ll, peeraddr=v6src, msg=pkt[DHCP6]))
                out = (Ether(src=router_in_mac, dst=client_mac) / relay) if (client_mac and not is_loopback) else relay
                self.sniffer.send(out, inbound_iface)
                return True
            # ---- DECLINE (9): mark declined, drop lease, Reply ----
            if msgtype == 9:
                du = _clid_hex(pkt)
                if du and du in self._v6_leases:
                    addr, _ = self._v6_leases.pop(du)
                    self._v6_used.discard(addr)
                    self._v6_declined.add(addr)

                clid = _mk_clid_opt(pkt)
                if clid:
                    reply = DHCP6_Reply(trid=dhcp6.trid) / self._dhcp6_srv_id / clid
                    st = _status(0, "Declined")
                    if st: reply /= st
                    reply = _add_dns_opts(reply)
                    _send_v6_reply(v6src, client_mac, reply)
                self.logger.log_message(f"[DHCP] v6 DECLINE handled for {v6src} (iface={inbound_iface})")
                return True
            # -------- Server replies (ADVERTISE / REPLY) ----------
            if msgtype == 1:  # SOLICIT
                _ZONE_RE = re.compile(r'%(?:\d+|[A-Za-z0-9_.-]+)$')

                def _rm_zone(addr: str | None) -> str | None:
                    """Remove Windows/Linux zone id ('%12' or '%Ethernet') from IPv6 string."""
                    if not addr or '%' not in addr:
                        return addr
                    # Only drop a trailing zone id, keep anything before it intact
                    return _ZONE_RE.sub('', addr)

                # ... inside handle_packet() before building the reply:
                is_loopback = not pkt.haslayer(Ether)
                client_mac = pkt[Ether].src if pkt.haslayer(Ether) else None

                v6src_raw = pkt[IPv6].src  # client's (likely fe80::…%X)
                router_ll_nz = _rm_zone(router_ll)  # your link-local (strip %X)
                v6src_nz = _rm_zone(v6src_raw)

                # Guard: if stripping fails for any reason, just bail gracefully
                if not router_ll_nz or not v6src_nz:
                    self.logger.log_message("[DHCP] v6: invalid link-local addressing; skipping reply")
                    return False

                dhcp6 = pkt.getlayer(DHCP6_Solicit) or pkt.getlayer(DHCP6_InfoRequest)

                # Example for SOLICIT → ADVERTISE
                advertise = (
                        IPv6(src=router_ll_nz, dst=v6src_nz, hlim=255)
                        / UDP(sport=547, dport=546)
                        / DHCP6_Advertise(trid=dhcp6.trid)
                        / self._dhcp6_srv_id
                    # / ia_block  # include if you actually offer an IA_NA/IA_PD
                )

                out = (Ether(src=router_in_mac, dst=client_mac) / advertise) if (
                            client_mac and not is_loopback) else advertise
                self.sniffer.send(out, inbound_iface)  # keep using your known egress iface
                self.logger.log_message(f"[DHCP] v6 ADVERTISE → {v6src_nz} (iface={inbound_iface})")
                return True

            if msgtype == 11:  # DHCPv6 Information-Request -> Reply (RDNSS, domains, IRT)
                # Echo Client-ID if present
                clid_layer = pkt.getlayer(DHCP6OptClientId)
                clid = DHCP6OptClientId(duid=clid_layer.duid) if clid_layer is not None else None

                # Build DHCPv6 reply with options
                reply = DHCP6_Reply(trid=dhcp6.trid)  # or pkt[DHCP6_InfoRequest].trid (same here)

                # Always include our Server-ID
                reply /= self._dhcp6_srv_id
                if clid:
                    reply /= clid

                # Coerce dns_v6 and search_domains into the right types
                def _to_list_ipv6(v):
                    if v is None:
                        return []
                    if isinstance(v, (list, tuple)):
                        return [str(x) for x in v]
                    return [str(v)]

                def _to_list_str(v):
                    if v is None:
                        return []
                    if isinstance(v, (list, tuple)):
                        return [str(x) for x in v]
                    # Accept comma-separated "example.com, local"
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

                # --- Always build full IPv6/UDP for DHCPv6 ---
                # RFC 8415: server→client reply is UDP 547 -> 546; hop limit 1 on-link
                ip6 = IPv6(src=router_ll, dst=v6src, hlim=1)
                udp = UDP(sport=547, dport=546)

                # Prefer unicast back to client MAC; fallback to ff02::1:2 multicast
                if (not is_loopback) and client_mac:
                    # Unicast to client MAC seen on the request
                    l2 = Ether(src=router_in_mac, dst=client_mac)
                    out = l2 / ip6 / udp / reply
                elif not is_loopback:
                    # L2 present but we didn't get client MAC → multicast
                    l2 = Ether(src=router_in_mac, dst="33:33:00:01:00:02")
                    out = l2 / IPv6(src=router_ll, dst="ff02::1:2", hlim=1) / udp / reply
                else:
                    # Pure L3 (loopback/virtual)
                    out = ip6 / udp / reply

                # send L2 or L3; your sniffer handles both
                self.sniffer.send(out, inbound_iface)
                self.logger.log_message(f"[DHCP] v6 INFO-REPLY → {v6src} (iface={inbound_iface})")
                return True

            # ---- CONFIRM (4) -> REPLY with StatusCode (success / not-on-link) ----
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
                            ia_reply /= DHCP6OptIAAddress(addr=str(addr), preflft=self.V6_LEASE_SECONDS,
                                                          validlft=self.V6_LEASE_SECONDS)
                            reply /= ia_reply
                        except Exception:
                            st = _status(1, "UnspecFail")
                            if st: reply /= st
                else:
                    # No prefix -> stateless-only reply
                    st = _status(0, "Stateless")
                    if st: reply /= st

                reply = _add_dns_opts(reply)
                _send_v6_reply(v6src, client_mac, reply)

                name = {3: "REQUEST", 5: "RENEW", 6: "REBIND"}.get(msgtype, str(msgtype))
                self.logger.log_message(f"[DHCP] v6 {name}-REPLY → {v6src} (iface={inbound_iface})")
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
    Sends via Scapy/Sniffer (L2 Injection).
    Listens via standard OS UDP sockets (Background thread).
    """
    MAGIC_HEADER = "PYROUTER_P2P_V4"

    def __init__(self, router_logger, router_ip: str, sniffer, out_iface: str, broadcast_ip: str = "255.255.255.255",
                 port: int = 49999):
        self.router_logger = router_logger
        self.router_ip = router_ip
        self.broadcast_ip = broadcast_ip
        self.port = port
        self.node_id = str(uuid.uuid4())

        # Initialize our custom sender socket
        self.sender_sock = PcapUDPSocket(sniffer, out_iface, router_ip, port)

        self.arp_manager = None
        self.rip_manager = None

        self.running = False
        self._listen_thread: Optional[threading.Thread] = None
        self._broadcast_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        self.peers: Dict[str, Dict[str, Any]] = {}
        self.peer_timeout = 35.0
        self.broadcast_interval = 10.0

    def set_managers(self, arp_manager, rip_manager):
        self.arp_manager = arp_manager
        self.rip_manager = rip_manager

    def start(self):
        if self.running:
            return

        self.running = True

        # Spawn both background threads
        self._listen_thread = threading.Thread(target=self._listener_loop, daemon=True, name="P2P-Listener")
        self._broadcast_thread = threading.Thread(target=self._broadcaster_loop, daemon=True, name="P2P-Broadcaster")

        self._listen_thread.start()
        self._broadcast_thread.start()

        self.router_logger.log_message(
            f"[P2P] 🟢 Started Node {self.node_id[:8]} on port {self.port}"
        )

    def stop(self):
        if not self.running:
            return

        self.running = False
        self.router_logger.log_message("[P2P] 🛑 Stopping Peer Manager...")

        if self._listen_thread:
            self._listen_thread.join(timeout=2.0)
        if self._broadcast_thread:
            self._broadcast_thread.join(timeout=2.0)

        with self._lock:
            self.peers.clear()

    def get_known_peers(self) -> Dict[str, Dict[str, Any]]:
        self._prune_dead_peers()
        with self._lock:
            return self.peers.copy()

    def _prune_dead_peers(self):
        now = time.time()
        with self._lock:
            dead_peers = [ip for ip, data in self.peers.items() if (now - data["last_seen"]) > self.peer_timeout]
            for ip in dead_peers:
                del self.peers[ip]
                self.router_logger.log_message(f"[P2P] 👻 Peer {ip} timed out and was removed.")

    def _listener_loop(self):
        """Standard Python socket listening for incoming broadcasts."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            # Bind to all interfaces to catch the broadcasts
            sock.bind(("0.0.0.0", self.port))
        except Exception as e:
            self.router_logger.log_message(f"[P2P] ❌ Failed to bind listener socket: {e}")
            self.running = False
            return

        sock.settimeout(1.0)

        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
                sender_ip = addr[0]

                payload = json.loads(data.decode('utf-8'))

                if payload.get("magic") != self.MAGIC_HEADER:
                    continue

                # Ignore packets sent by ourselves (using UUID)
                if payload.get("node_id") == self.node_id:
                    continue

                # It's a valid peer, update state
                with self._lock:
                    is_new = sender_ip not in self.peers
                    self.peers[sender_ip] = {
                        "node_id": payload.get("node_id"),
                        "last_seen": time.time(),
                        "arp_table": payload.get("arp_table", {}),
                        "routes": payload.get("routes", [])
                    }

                if is_new:
                    self.router_logger.log_message(
                        f"[P2P] 🤝 Discovered new router peer: {sender_ip} (Node: {payload.get('node_id')[:8]})"
                    )

            except socket.timeout:
                self._prune_dead_peers()
                continue
            except json.JSONDecodeError:
                pass
            except Exception as e:
                if self.running:
                    self.router_logger.log_message(f"[P2P] ⚠️ Listener error: {e}")

        sock.close()

    def _broadcaster_loop(self):
        """Gathers router state and broadcasts it using the PcapUDPSocket."""
        while self.running:
            try:
                # Gather state
                arp_data = {}
                if self.arp_manager:
                    raw_arp = self.arp_manager.get_cache_view()
                    for ip, val in raw_arp.items():
                        arp_data[ip] = list(val) if isinstance(val, tuple) else val

                route_data = []
                if self.rip_manager and hasattr(self.rip_manager, 'get_routing_table_view'):
                    route_data = self.rip_manager.get_routing_table_view()

                payload = {
                    "magic": self.MAGIC_HEADER,
                    "node_id": self.node_id,
                    "router_ip": self.router_ip,
                    "arp_table": arp_data,
                    "routes": route_data
                }

                packet_bytes = json.dumps(payload).encode('utf-8')

                # Use our custom PcapUDPSocket to send the data
                self.sender_sock.sendto(packet_bytes, (self.broadcast_ip, self.port))

            except Exception as e:
                if self.running:
                    self.router_logger.log_message(f"[P2P] ⚠️ Broadcast send error: {e}")

            for _ in range(int(self.broadcast_interval * 10)):
                if not self.running:
                    break
                time.sleep(0.1)


class PcapUDPSocket:
    """
    A pseudo-socket that uses SnifferSoftware to inject packets directly at Layer 2.
    This guarantees the broadcast goes out the correct interface, ignoring Windows routing.
    """

    def __init__(self, sniffer, iface_name: str, src_ip: str, src_port: int):
        self.sniffer = sniffer
        self.iface_name = iface_name
        self.src_ip = src_ip
        self.src_port = src_port

        try:
            # Assumes iface_name is the Scapy/OS name (e.g. \Device\NPF_...)
            self.src_mac = get_if_hwaddr(iface_name.split('_')[-1])
        except Exception:
            self.src_mac = "02:00:00:00:00:01"

    def sendto(self, data: bytes, address: tuple):
        dst_ip, dst_port = address

        if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
            dst_mac = "ff:ff:ff:ff:ff:ff"
        else:
            dst_mac = "ff:ff:ff:ff:ff:ff"

        pkt = (
                Ether(src=self.src_mac, dst=dst_mac) /
                IP(src=self.src_ip, dst=dst_ip) /
                UDP(sport=self.src_port, dport=dst_port) /
                Raw(load=data)
        )

        self.sniffer.sendp(pkt, iface=self.iface_name, verbose=0)