import hashlib
import queue
import random
import re
import ssl
import subprocess
from collections import defaultdict, deque
from enum import auto, Enum
from functools import reduce
from typing import Optional, List, Any, Dict, Tuple, Literal, Callable, Set, Iterable
import ipaddress
import time

import requests
import zmq
from scapy.arch import get_if_hwaddr, get_windows_if_list
from scapy.config import conf
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6, DHCP6_RelayForward, DHCP6OptIAPrefix, DHCP6OptDNSServers, DHCP6_Advertise, DHCP6_Reply
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, ICMPv6ND_RA
from scapy.layers.l2 import ARP, getmacbyip
from scapy.layers.rip import RIPEntry, RIP
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSFinished
from scapy.layers.tls.record import TLS
from scapy.packet import Packet, Raw
from scapy.fields import ByteField, ShortField,IP6Field
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import struct
import socket
import threading
import json
from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP

from server.p2pool_tools import RandomXLoader, RandomXFlags


class MLDQuery(Packet):
    name = "ICMPv6 MLD Query"
    fields_desc = [
        ShortField("mrd", 0),
        ShortField("res", 0),
        IP6Field("mcaddr", "::")
    ]

class MLDReport(Packet):
    name = "ICMPv6 MLD Report"
    fields_desc = [
        ShortField("mrd", 0),
        ShortField("ngrp", 0),
        # Real MLDv2 can have a list of group records, but this is a simple start
        IP6Field("mcaddr", "::")
    ]

class MLDDone(Packet):
    name = "ICMPv6 MLD Done"
    fields_desc = [
        ShortField("mrd", 0),
        ShortField("res", 0),
        IP6Field("mcaddr", "::")
    ]
# --- ICMPv6 Base and Common Types ---
class ICMPv6(Packet):
    name = "ICMPv6"
    fields_desc = [
        ByteField("type", 128),  # Echo Request
        ByteField("code", 0),
        ShortField("cksum", None),
    ]

    def post_build(self, p, pay):
        # ICMPv6 checksum calculation requires a pseudo-header
        if self.cksum is None and self.underlayer and isinstance(self.underlayer, IPv6):
            ip = self.underlayer
            # Pseudo-header: src, dst, upper-layer packet length, 3 bytes zero, next header
            psd_hdr = ip.src.encode() + ip.dst.encode() + len(p).to_bytes(4, 'big') + b'\x00\x00\x00' + ip.nh.to_bytes(1,
                                                                                                                    'big')
            # Scapy's in4_chksum can be used for the calculation logic
            from scapy.layers.inet import in4_chksum
            cksum = in4_chksum(psd_hdr + p + pay)
            p = p[:2] + cksum.to_bytes(2, 'big') + p[4:]
        return p + pay

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
        socket.setsockopt_string(zmq.SUBSCRIBE, "")  # Subscribe to all messages

        try:
            socket.connect(self.zmq_address)
            while not self._stop_event.is_set():
                try:
                    # Non-blocking receive with a timeout
                    raw_message = socket.recv(flags=zmq.NOBLOCK)
                    self.message_handler(raw_message)
                except zmq.Again:
                    # No message received, check stop event
                    self._stop_event.wait(0.5)
                except Exception as e:
                    self.logger.log_message(f"[ZMQ] ❌ Error receiving message: {e}")
                    self._stop_event.wait(1)

        except zmq.ZMQError as e:
            self.logger.log_message(f"[ZMQ] ❌ Failed to connect to ZMQ socket: {e}")
        finally:
            socket.close()
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
        try:
            topic = raw_message.split(b" ", 1)[0]
            if topic in (b"block", b"json-full-chain-main"):
                self.logger.log_message("[Daemon] ZMQ new block → fetching template...")
                threading.Thread(target=self._fetch_and_distribute_job, daemon=True).start()
            elif topic == b"txpool_add":
                # Optional: refresh template to include new txs
                pass
        except Exception:
            self.logger.log_message("[Daemon] ⚠️ Malformed ZMQ message received.")

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

    def _fetch_and_distribute_job(self) -> None:
        wa = (self.stratum_conn_manager.wallet_address or "").strip()
        if not wa:
            self.logger.log_message("[Daemon] ❌ No wallet_address configured; cannot request block template.")
            return

        reserve = int(self.reserve_size)
        if reserve < 0 or reserve > 127:  # keep safe
            self.logger.log_message(f"[Daemon] ⚠️ reserve_size {reserve} out of range; clamping to 60.")
            reserve = 60

        params = {"wallet_address": wa, "reserve_size": reserve}

        try:
            resp = self._rpc_call("get_block_template", params)
            res = resp.get("result")

            needed = ("blocktemplate_blob", "height")
            if not res or not all(k in res for k in needed):
                self.logger.log_message("[Daemon] ⚠️ Template missing required fields (daemon syncing or wrong net?).")
                return

            tpl = RandomXLoader.norm_hex(res["blocktemplate_blob"])
            if not tpl or (len(tpl) % 2 != 0):
                self.logger.log_message("[Daemon] ⚠️ Invalid blocktemplate_blob from daemon.")
                return

            # Difficulty (prefer 128-bit wide_difficulty)
            wide = res.get("wide_difficulty")
            if isinstance(wide, str) and wide.strip():
                D = int(wide, 16)
            else:
                low = int(res.get("difficulty", 0))
                high = int(res.get("difficulty_top64", 0))
                D = (high << 64) | low
                if D <= 0:
                    self.logger.log_message("[Daemon] ⚠️ Difficulty missing/invalid.")
                    return

            height = int(res["height"])
            seed_hash = RandomXLoader.norm_hex(res.get("seed_hash"))
            prev_hash = RandomXLoader.norm_hex(res.get("prev_hash")) or ""
            target_hex = RandomXLoader.target_hex_from_difficulty(D)

            # Synthesize a stable local job_id
            job_id = f"daemon-{height}-{prev_hash[:16]}-{int(time.time()*1000)%1_000_000:06d}"

            stratum_job = {
                "id": job_id,
                "blob": tpl,
                "target": target_hex,
                "height": height,
                "difficulty": D,
            }
            if seed_hash:
                stratum_job["seed_hash"] = seed_hash

            self._templates_by_job_id[job_id] = tpl
            self._difficulty_by_job_id[job_id] = D
            self._cleanup_templates()

            # Distribute to the daemon session
            self.stratum_conn_manager.distribute_job_from_daemon(stratum_job)
            self.code_output_manager.submit_packet(
                {
                    "job_id": job_id,
                    "height": height,
                    "difficulty": D,
                    "target": target_hex,
                },
                inbound_iface="daemon",
                phase="handled",
                component="daemon-job"
            )
            self.logger.log_message(f"[Daemon] ✅ Distributed new job {job_id} (h={height}, diff={D}).")

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

        try:
            self._add_socket(miner_socket)
            self.stratum_manager.register_session(session_id)
            self.logger.log_message(f"[StratumConn] (Proxy) Session {session_id} registered.")

            send_q: queue.PriorityQueue[tuple[int, bytes]] = queue.PriorityQueue()

            self.logger.log_message(f"[StratumConn] 🔌 (Proxy) Connecting upstream for {session_id}...")
            pool_socket = self._open_pool_socket()
            self._add_socket(pool_socket)

            # Per-session submitter for this proxy session
            def _submit_via_proxy(*, job_id: str, nonce: str, result_hash: str) -> None:
                params = {"job_id": job_id, "nonce": nonce, "result": result_hash}
                # Include upstream session id if we have it (p2pool compatibility)
                upstream_id = self._proxy_session_ids.get(session_id)
                if upstream_id:
                    params["id"] = upstream_id
                msg = {"jsonrpc": "2.0", "id": 4, "method": "submit", "params": params}
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

        self.code_output_manager = code_output_manager
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

    def attach_submitter(self, session_id: str, submit_func: Callable[..., None]):
        self._submitters[session_id] = submit_func
        self.logger.log_message(f"[Stratum] Submitter attached for session: {session_id}")

    def register_session(self, session_id: str) -> None:
        with self._lock:
            if session_id in self.sessions:
                return
            self.sessions[session_id] = {}

            jq = queue.Queue(maxsize=1)
            self._job_queues[session_id] = jq

            t = threading.Thread(target=self._share_worker, args=(session_id, jq), daemon=True, name=f"rx-{session_id}")
            self._workers[session_id] = t
            t.start()
        self.logger.log_message(f"[Stratum] ✅ Session registered and worker started for: {session_id}")

    def deregister_session(self, session_id: str) -> None:
        self.logger.log_message(f"[Stratum] 🛑 Deregistering session: {session_id}")
        with self._lock:
            if session_id in self._job_queues:
                self._job_queues[session_id].put(None)
            w = self._workers.get(session_id)
            if w and w.is_alive():
                w.join(timeout=2.0)
            self.sessions.pop(session_id, None)
            self._workers.pop(session_id, None)
            self._job_queues.pop(session_id, None)
            self._submitters.pop(session_id, None)

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
        if session_id in self._job_queues:
            jq = self._job_queues[session_id]
            try:
                jq.get_nowait()  # drop stale
            except queue.Empty:
                pass
            jq.put(job)
            self.code_output_manager.submit_packet(
                job,
                inbound_iface="stratum",
                phase="handled",
                component="stratum-job"
            )

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
        """
        Throughput-focused worker with optional 3-stage pipeline.
        Emits SHARE and BLOCK candidates via attached submitter.
        """
        from time import perf_counter
        import time
        import random

        logger = self.logger
        submitter = self._submitters.get(session_id)

        # Tuning
        BATCH = 4
        PREEMPT_EVERY = 0x3FFF  # check occasionally; won't starve hashing
        LOG_INTERVAL = 2.0
        max_backoff = 0.5

        # Odd stride per-session so threads don't collide
        stride_seed = abs(hash(session_id)) or 1
        stride = ((stride_seed & 0xFFFF) | 1)

        # --- helpers -------------------------------------------------------------
        def _u256_le(x) -> int:
            """Normalize a 32-byte digest (bytes or int) to a Python int as little-endian 256."""
            if isinstance(x, int):
                return x
            if isinstance(x, (bytes, bytearray)):
                if len(x) != 32:
                    # Some backends return bytearray of 32. Enforce exact size.
                    raise ValueError(f"digest length != 32 (got {len(x)})")
                return int.from_bytes(x, "little")
            raise TypeError(f"Unsupported digest type: {type(x)}")

        def _target_u256_from_hex_le(hex_str: str | None) -> int | None:
            if not hex_str:
                return None
            b = bytes.fromhex(hex_str)
            # P2Pool/Monero targets are provided as LE. 32 bytes is full 256-bit target.
            if len(b) == 32:
                return int.from_bytes(b, "little")
            elif len(b) == 8:
                # 64-bit target: compare against low 64 bits of hash (LE).
                # We lift to 256 space by zero-extending—equivalent to checking h_low64 <= T64.
                return int.from_bytes(b, "little")
            else:
                # Be permissive: interpret as LE integer anyway.
                return int.from_bytes(b, "little")

        def _meets_target(d_u256: int, T: int, T_len_bytes: int) -> bool:
            """Compare respecting width: if target was 8 bytes, compare low 64 bits only."""
            if T_len_bytes == 8:
                return (d_u256 & ((1 << 64) - 1)) <= T
            # 32 bytes or other: full 256-bit compare
            return d_u256 <= T

        def _target_len_bytes(hex_str: str | None) -> int:
            if not hex_str:
                return 0
            return len(hex_str) // 2

        # ------------------------------------------------------------------------

        while True:
            job = job_q.get()
            if job is None:
                logger.log_message(f"[Stratum] 🛑 Worker received stop signal for session={session_id}")
                break

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
                # Targets as LE integers + remember original width for correct compare
                share_T = _target_u256_from_hex_le(share_hex)
                share_T_len = _target_len_bytes(share_hex)

                if block_hex:
                    block_T = _target_u256_from_hex_le(block_hex)
                    block_T_len = _target_len_bytes(block_hex)
                else:
                    block_T = None
                    block_T_len = 0
                    if diff_val:
                        # Use your existing difficulty->target converter (LE, 256-bit int)
                        block_T = RandomXLoader.target_from_difficulty_int(int(diff_val))
                        block_T_len = 32

                buf, off = self._prepare_blob_template(blob_hex)
            except Exception as e:
                logger.log_message(f"[Stratum] ❌ Job setup failed for {job_id}: {e}")
                continue

            # Backend capabilities
            has_pipe = all(
                hasattr(rx, m) for m in ("calculate_hash_first", "calculate_hash_next", "calculate_hash_last"))
            calc_hash = getattr(rx, "calculate_hash", None)
            if not callable(calc_hash):
                logger.log_message("[Stratum] ❌ Hashing backend (rx) is not ready.")
                continue

            nonce = random.getrandbits(32)
            tries, ema_rate, last_log, error_streak = 0, None, perf_counter(), 0
            submitted_nonces: set[str] = set()

            # Diagnostics: track best observed hashes to sanity-check targets
            min_h64 = (1 << 64) - 1
            min_h256 = (1 << 256) - 1

            logger.log_message(f"[Stratum] ▶️ Working job {job_id} (stride={stride}, batch={BATCH if has_pipe else 1})")

            while True:
                # preemption: check occasionally for a newer job
                if (tries & PREEMPT_EVERY) == 0 and tries != 0:
                    try:
                        newj = job_q.get_nowait()
                        job_q.put(newj)
                        if (newj.get("id") or newj.get("job_id")) != job_id:
                            logger.log_message(f"[Stratum] 🔄 New job arrived, switching from {job_id}.")
                            break
                    except queue.Empty:
                        pass

                try:
                    if has_pipe and BATCH >= 2:
                        nonces, digests_u256 = [], []

                        # first
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

                        # Optional occasional pipeline self-check (cheap & rare)
                        if (tries & 0xFFFF) == 0:
                            tn = nonces[-1]
                            self._write_nonce_le_inplace(buf, off, tn)
                            d_single = _u256_le(calc_hash(bytes(buf)))
                            if d_single != digests_u256[-1]:
                                logger.log_message("[Stratum] ❌ Pipeline mismatch vs single-hash path")
                                # fallback to single path if you prefer:
                                # has_pipe = False

                        # decisions
                        for n_val, d_u256 in zip(nonces, digests_u256):
                            # diagnostics
                            h64 = d_u256 & ((1 << 64) - 1)
                            if h64 < min_h64: min_h64 = h64
                            if d_u256 < min_h256: min_h256 = d_u256

                            if _meets_target(d_u256, share_T, share_T_len):
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
                        # Single-shot path (no pipeline)
                        self._write_nonce_le_inplace(buf, off, nonce)
                        d_single = _u256_le(calc_hash(bytes(buf)))

                        # diagnostics
                        h64 = d_single & ((1 << 64) - 1)
                        if h64 < min_h64: min_h64 = h64
                        if d_single < min_h256: min_h256 = d_single

                        if _meets_target(d_single, share_T, share_T_len):
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
                        # Show min-hash vs target to catch width/endianness mistakes immediately
                        msg = f"[Stratum] ⏱️ {session_id} job {job_id}: {ema_rate:.0f} H/s"
                        self.code_output_manager.submit_packet(
                            {
                                "job_id": job_id,
                                "hashrate": ema_rate
                            },
                            inbound_iface="stratum",
                            phase="handled",
                            component="work"
                        )
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
    _GUID_RE = re.compile(r"\{([0-9A-Fa-f\-]{36})\}")
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

        self.packet_writer.queue_packet(response_packet, inbound_iface)
        self.logger.log_message(f"[mDNS] ✅ Sent mDNS response for '{qname}' (Type: {qtype}) on {inbound_iface.split('_')[-1]}")

    def _forward_mdns_query(self, original_packet: Packet):
        """Forwards an mDNS query to all other interfaces."""
        inbound_iface = original_packet.sniffed_on
        try:
            qname = original_packet[DNS].qd.qname.decode()
        except (IndexError, AttributeError):
            self.logger.log_message("[mDNS] ⚠️ Cannot forward: Malformed query packet.")
            return

        is_ipv6 = original_packet.haslayer(IPv6)
        dst_mac = "33:33:00:00:00:fb" if is_ipv6 else "01:00:5e:00:00:fb"
        dst_ip = self.MDNS_IPV6_ADDR if is_ipv6 else self.MDNS_IPV4_ADDR

        for iface_name, config in self.interfaces_config.items():
            if iface_name == inbound_iface:
                continue

            src_ip_out = config.get("ipv6_addr") if is_ipv6 else config.get("ip_addr")
            src_mac_out = config.get("mac")

            if not src_ip_out or not src_mac_out:
                continue

            l3 = IPv6(src=src_ip_out, dst=dst_ip) if is_ipv6 else IP(src=src_ip_out, dst=dst_ip)
            forwarded_packet = Ether(src=src_mac_out, dst=dst_mac) / \
                               l3 / \
                               UDP(sport=self.MDNS_PORT, dport=self.MDNS_PORT) / \
                               original_packet[DNS]

            self.packet_writer.queue_packet(forwarded_packet, iface_name)
            self.logger.log_message(f"[mDNS] 🔁 Forwarded mDNS query for '{qname}' to {iface_name.split('_')[-1]}")

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
    # FIX: Sort the tuples to ensure the key is always the same
    return tuple(sorted([(ip1, port1), (ip2, port2)]))



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
        if len(buf) < 5: return False
        ct, vmaj, vmin = buf[0], buf[1], buf[2]
        return ct in (20, 21, 22, 23) and vmaj == 3

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
    Tracks TCP 3-way handshakes and teardowns AND streams TLS bytes into TLSRecordManager.
    Requires a TLSRecordManager instance (or builds one) and wires its callbacks to:
      - log ClientHello/ServerHello (SNI, ALPN, JA3/JA3S, version/cipher)
      - log TLS Alerts
      - forward TLS Application Data (optional; uses last seen TCP seq/ack)
      - honor policy decisions (block/quarantine suppresses AppData forwarding)

    NOTE: This class does not depend on Scapy’s TLS layers; TLS parsing is done in TLSRecordManager.
    """
    COMMON_TLS_PORTS = {443, 444, 8443, 9443, 10443, 4443}
    def __init__(self, router_logger,
                 arp_manager,
                 nat_manager,
                 rip_manager,
                 packet_writer,
                 tls_record_manager=None,              # NEW: inject or auto-create
                 timeout_half_open: int = 60,
                 timeout_established: int = 300):
        self.logger = router_logger
        self.arp_manager = arp_manager
        self.nat_manager = nat_manager
        self.rip_manager = rip_manager
        self.packet_writer = packet_writer

        # TCP session state: key -> (state:str, ts:float, src_ip, src_port, dst_ip, dst_port)
        self._sessions: Dict[Tuple[Tuple[str, int], Tuple[str, int]],
                             Tuple[str, float, str, int, str, int]] = {}

        self._lock = threading.Lock()
        self.timeout_half_open = timeout_half_open
        self.timeout_established = timeout_established
        self._stop_event = threading.Event()

        # TLS plumbing
        self._tls_mgr = tls_record_manager or TLSRecordManager(self.logger)
        self._tls_records: Dict[Tuple, List[TLSRecord]] = defaultdict(list)  # per-flow record store
        self._tls_streams: Dict[Tuple, List[bytes]] = defaultdict(list)      # per-flow AppData buckets
        # last observed TCP packet per (flow, direction) to borrow seq/ack when forwarding
        self._last_tcp_pkt: Dict[Tuple[Tuple, str], Packet] = {}

        # decisions/meta passthrough
        self._tls_mgr.on_record = self._on_tls_record
        self._tls_mgr.on_handshake = self._on_tls_handshake
        self._tls_mgr.on_alert = self._on_tls_alert
        self._tls_mgr.on_application_data = self._on_tls_application_data
        self._tls_mgr.on_event = self._on_tls_event
        self._tls_mgr.on_decision = self._on_tls_decision

        # abuse control
        self.ban_duration = 300
        self.rate_limit_threshold = 20
        self.rate_limit_period = 60
        self._ban_list: Dict[str, float] = {}            # ip -> expiry
        self._connection_rate_tracker: Dict[str, List[float]] = defaultdict(list)

        # maintenance thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop,
                                                daemon=True, name="HandshakeCleanup")
        self._cleanup_thread.start()

        self.logger.log_message("[Handshake] Manager initialized (TLS wired to TLSRecordManager).")

    def _canon_key(self, ip1: str, pt1: int, ip2: str, pt2: int):
        return tuple(sorted([(ip1, pt1), (ip2, pt2)]))
    # ---- lifecycle ------------------------------------------------------------

    def start(self):
        if not (self._cleanup_thread and self._cleanup_thread.is_alive()):
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop,
                                                    daemon=True, name="HandshakeCleanup")
            self._cleanup_thread.start()
            self.logger.log_message("[Handshake] Cleanup thread started.")
        else:
            self.logger.log_message("[Handshake] Manager already running.")

    def stop(self):
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.logger.log_message("[Handshake] Manager stopped.")

    # ---- cleanup / timeouts / bans -------------------------------------------

    def _cleanup_loop(self):
        while not self._stop_event.is_set():
            now = time.time()
            with self._lock:
                stale_keys = []
                for key, (state, ts, _, _, _, _) in self._sessions.items():
                    current_timeout = self.timeout_half_open if state in ["SYN_SENT", "SYN_ACK_RECEIVED"] else self.timeout_established
                    if now - ts > current_timeout:
                        stale_keys.append(key)

                for key in stale_keys:
                    state_at_timeout, _, src_ip, src_port, dst_ip, dst_port = self._sessions[key]
                    self.logger.log_message(
                        f"[Handshake] ❌ Session ({src_ip}:{src_port} ↔ {dst_ip}:{dst_port}) timed out "
                        f"in state {state_at_timeout}"
                    )
                    del self._sessions[key]

                expired_bans = [ip for ip, expiry_time in self._ban_list.items() if now >= expiry_time]
                for ip in expired_bans:
                    del self._ban_list[ip]
                    if hasattr(self, '_probe_counts'):
                        self._probe_counts.pop(ip, None)
                    self.logger.log_message(f"[Handshake][BAN] ✅ Ban expired for {ip}. IP is no longer blocked.")
            # modest cadence
            self._stop_event.wait(1.0)

    def _check_and_apply_rate_limit(self, ip: str, now: float):
        timestamps = self._connection_rate_tracker[ip]
        timestamps.append(now)
        self._connection_rate_tracker[ip] = [ts for ts in timestamps if now - ts <= self.rate_limit_period]
        if len(self._connection_rate_tracker[ip]) > self.rate_limit_threshold:
            self.logger.log_message(
                f"[Handshake][BAN] 🚫 IP {ip} banned for {self.ban_duration}s. "
                f"Reason: Exceeded connection rate limit (possible scan)."
            )
            self._ban_list[ip] = now + self.ban_duration
            del self._connection_rate_tracker[ip]

    # ---- Packet handling ------------------------------------------------------

    def handle_packet(self, pkt: Packet, inbound_iface: str) -> bool:
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return False
        if not pkt.haslayer(TCP):
            return False

        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        tcp_layer = pkt[TCP]
        flags = tcp_layer.flags
        now = time.time()

        original_src_ip = ip_layer.src
        original_src_port = tcp_layer.sport
        original_dst_ip = ip_layer.dst
        original_dst_port = tcp_layer.dport

        with self._lock:
            if self._ban_list.get(original_src_ip, 0) > now:
                return False

        # NAT reverse: map public dst to internal if it matches our public IP
        if original_dst_ip == getattr(self.nat_manager, "public_ip", None):
            nat_reversed_dst_tuple = self.nat_manager.get_internal_from_external(original_dst_port, original_src_ip)
            if nat_reversed_dst_tuple:
                original_dst_ip, original_dst_port = nat_reversed_dst_tuple
                self.logger.log_message(
                    f"[Handshake] NAT reverse (DST): {ip_layer.dst}:{tcp_layer.dport} -> {original_dst_ip}:{original_dst_port}"
                )

        canonical_key = _get_canonical_session_key(original_src_ip, original_src_port,
                                                   original_dst_ip, original_dst_port)

        with self._lock:
            current_session_data = self._sessions.get(canonical_key)
            session_state = current_session_data[0] if current_session_data else None

            if session_state is None:
                stored_original_src_ip = original_src_ip
                stored_original_src_port = original_src_port
                stored_original_dst_ip = original_dst_ip
                stored_original_dst_port = original_dst_port
            else:
                _, _, stored_original_src_ip, stored_original_src_port, \
                    stored_original_dst_ip, stored_original_dst_port = current_session_data

            # --- TCP Handshake/Teardown state machine --------------------------
            if flags == 0x02:  # SYN
                if session_state is None:
                    self._sessions[canonical_key] = ("SYN_SENT", now,
                                                     original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔓 SYN {original_src_ip}:{original_src_port} -> "
                        f"{original_dst_ip}:{original_dst_port} on {inbound_iface}"
                    )
                elif session_state == "SYN_SENT":
                    self._sessions[canonical_key] = (session_state, now,
                                                     stored_original_src_ip, stored_original_src_port,
                                                     stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔁 SYN retransmit from {original_src_ip}:{original_src_port} on {inbound_iface}"
                    )
                return False

            elif flags == 0x12:  # SYN+ACK
                if session_state == "SYN_SENT":
                    self._sessions[canonical_key] = ("SYN_ACK_RECEIVED", now,
                                                     stored_original_src_ip, stored_original_src_port,
                                                     stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔐 SYN-ACK {original_src_ip}:{original_src_port} -> {original_dst_ip}:{original_dst_port} "
                        f"for {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                    )
                elif session_state == "SYN_ACK_RECEIVED":
                    self._sessions[canonical_key] = (session_state, now,
                                                     stored_original_src_ip, stored_original_src_port,
                                                     stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(f"[Handshake] 🔁 SYN-ACK retransmit on {inbound_iface}")
                else:
                    # fast-path: infer established
                    self._sessions[canonical_key] = ("ESTABLISHED", now,
                                                     original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ✅ Inferred ESTABLISHED: {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                    )
                    # Add/stateful NAT mapping if you want
                    try:
                        self.nat_manager.add_stateful_mapping(
                            src_ip=stored_original_src_ip, src_port=stored_original_src_port,
                            dst_ip=stored_original_dst_ip, dst_port=stored_original_dst_port
                        )
                    except Exception:
                        pass
                return False

            elif flags == 0x10:  # ACK
                if session_state == "SYN_ACK_RECEIVED":
                    self._sessions[canonical_key] = ("ESTABLISHED", now,
                                                     stored_original_src_ip, stored_original_src_port,
                                                     stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ✅ ESTABLISHED: {stored_original_src_ip}:{stored_original_src_port} ↔ "
                        f"{stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                    )
                    try:
                        self.nat_manager.add_stateful_mapping(
                            src_ip=stored_original_src_ip, src_port=stored_original_src_port,
                            dst_ip=stored_original_dst_ip, dst_port=stored_original_dst_port
                        )
                    except Exception:
                        pass

                elif session_state == "ESTABLISHED":
                    # refresh timestamp
                    self._sessions[canonical_key] = ("ESTABLISHED", now,
                                                     stored_original_src_ip, stored_original_src_port,
                                                     stored_original_dst_ip, stored_original_dst_port)
                elif session_state == "CLOSING":
                    self._sessions[canonical_key] = ("CLOSED", now,
                                                     stored_original_src_ip, stored_original_src_port,
                                                     stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ❎ CLOSED (ACK after FIN): "
                        f"{stored_original_src_ip}:{stored_original_src_port} ↔ "
                        f"{stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                    )
                    del self._sessions[canonical_key]
                else:
                    # generic keepalive/ack progression
                    self._sessions[canonical_key] = ("ESTABLISHED", now,
                                                     original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)

            elif flags & 0x01:  # FIN
                if session_state == "ESTABLISHED":
                    self._sessions[canonical_key] = ("CLOSING", now,
                                                     stored_original_src_ip, stored_original_src_port,
                                                     stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔻 CLOSING by {original_src_ip}:{original_src_port} "
                        f"for {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port}"
                    )
                    self._check_and_apply_rate_limit(original_src_ip, now)
                elif session_state == "CLOSING":
                    self._sessions[canonical_key] = ("CLOSED", now,
                                                     stored_original_src_ip, stored_original_src_port,
                                                     stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ❎ CLOSED (Second FIN): {stored_original_src_ip}:{stored_original_src_port} ↔ "
                        f"{stored_original_dst_ip}:{stored_original_dst_port}"
                    )
                    del self._sessions[canonical_key]
                else:
                    self.logger.log_message(
                        f"[Handshake] ⚠️ Unexpected FIN {original_src_ip}:{original_src_port} -> "
                        f"{original_dst_ip}:{original_dst_port} in state {session_state} on {inbound_iface}"
                    )
                return False

            elif flags & 0x04:  # RST
                if current_session_data:
                    self.logger.log_message(
                        f"[Handshake] ❌ RST on {stored_original_src_ip}:{stored_original_src_port} ↔ "
                        f"{stored_original_dst_ip}:{stored_original_dst_port} (closing)."
                    )
                    del self._sessions[canonical_key]
                return False

        # ---- TLS wiring: feed bytes to TLSRecordManager when we have payload ---
        if self._sessions.get(canonical_key, (None,))[0] == "ESTABLISHED":
            # Extract TCP payload (could be empty)
            tcp_payload_bytes = bytes(tcp_layer.payload) if tcp_layer.payload else b""

            # Robust TLS/SSL record sniff (TLS 1.x or SSLv2 hello)
            looks_tls = (
                    len(tcp_payload_bytes) >= 5
                    and TLSRecordManager._looks_like_tls_header(tcp_payload_bytes)  # ct in {20..23}, vmaj==3
            )
            sslv2_possible = bool(tcp_payload_bytes) and (tcp_payload_bytes[0] & 0x80) and len(tcp_payload_bytes) >= 3
            tlsish = looks_tls or sslv2_possible

            with self._lock:
                current = self._sessions.get(canonical_key)
                current_state = current[0] if current else None

            # If we see TLS bytes but didn't observe the 3-way handshake (common on mirrors/offload),
            # mark the flow ESTABLISHED for TLS parsing.
            if tlsish and current_state not in ("ESTABLISHED", "SYN_ACK_RECEIVED"):
                with self._lock:
                    if not current:
                        self._sessions[canonical_key] = ("ESTABLISHED", now,
                                                         original_src_ip, original_src_port,
                                                         original_dst_ip, original_dst_port)
                    else:
                        st, _ts, ssrc_ip, ssrc_pt, sdst_ip, sdst_pt = current
                        self._sessions[canonical_key] = ("ESTABLISHED", now, ssrc_ip, ssrc_pt, sdst_ip, sdst_pt)
                    current = self._sessions[canonical_key]
                    current_state = "ESTABLISHED"
                    self.logger.log_message(
                        f"[Handshake] ✅ Implicit ESTABLISHED by TLS payload: "
                        f"{original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                    )

            # Feed if (a) we have bytes AND (b) either the flow is established OR payload looks TLS-ish
            if tcp_payload_bytes and (current_state == "ESTABLISHED" or tlsish):
                with self._lock:
                    _, _, s_src_ip, s_src_port, s_dst_ip, s_dst_port = self._sessions[canonical_key]
                    is_c2s = self._infer_is_c2s(
                        original_src_ip, original_src_port, original_dst_ip, original_dst_port, current
                    )

                # Remember last pkt for optional AppData forwarding
                dir_key = (canonical_key, "c2s" if is_c2s else "s2c")
                self._last_tcp_pkt[dir_key] = pkt

                # Feed to TLS manager
                self._tls_mgr.feed_tcp_segment(
                    canonical_key=canonical_key,
                    is_c2s=is_c2s,
                    payload=tcp_payload_bytes,
                    src_ip=original_src_ip, src_port=original_src_port,
                    dst_ip=original_dst_ip, dst_port=original_dst_port,
                    ts=time.time()
                )

            return False

        return False

    def _infer_is_c2s(self, src_ip, src_port, dst_ip, dst_port, stored):
        # Prefer stored session roles when we have them
        if stored:
            _, _, s_src_ip, s_src_port, s_dst_ip, s_dst_port = stored
            return (src_ip == s_src_ip and src_port == s_src_port)
        # Heuristic by port
        if dst_port in self.COMMON_TLS_PORTS and src_port not in self.COMMON_TLS_PORTS:
            return True  # client -> server: dport looks like TLS
        if src_port in self.COMMON_TLS_PORTS and dst_port not in self.COMMON_TLS_PORTS:
            return False  # server -> client
        # Fallback: treat src as client
        return True
    # ---- TLSRecordManager callbacks ------------------------------------------

    def _on_tls_record(self, rec: "TLSRecord"):
        key = _get_canonical_session_key(rec.src, rec.src_port, rec.dst, rec.dst_port)
        self._tls_records[key].append(rec)
        # brief log on first few records
        if len(self._tls_records[key]) <= 3:
            self.logger.log_message(
                f"[TLS] 📄 Record ct={rec.content_type} ver={rec.version} len={rec.length} "
                f"{rec.direction} {rec.src}:{rec.src_port} -> {rec.dst}:{rec.dst_port}"
            )

    def _on_tls_handshake(self, rec: "TLSRecord", info: Dict):
        key = _get_canonical_session_key(rec.src, rec.src_port, rec.dst, rec.dst_port)
        # Summarize interesting fields (SNI, ALPN, JA3/JA3S, version/cipher)
        for msg in info.get("messages", []):
            t = msg.get("type")
            if t == "client_hello":
                sni = (msg.get("sni") or
                       (info.get("client_hello") or {}).get("sni"))
                ja3 = (info.get("client_hello") or {}).get("ja3_md5")
                ver = (info.get("client_hello") or {}).get("version")
                alpn = (info.get("client_hello") or {}).get("alpn") or []
                self.logger.log_message(
                    f"[TLS][ClientHello] SNI={sni or 'N/A'} JA3={ja3 or 'N/A'} ver={ver or 'N/A'} ALPN={','.join(alpn) or 'N/A'} "
                    f"flow={key}"
                )
            elif t == "server_hello":
                ver = (info.get("server_hello") or {}).get("version")
                cipher = (info.get("server_hello") or {}).get("cipher_suite")
                ja3s = (info.get("server_hello") or {}).get("ja3s_md5")
                self.logger.log_message(
                    f"[TLS][ServerHello] ver={ver or 'N/A'} cipher={cipher or 'N/A'} JA3S={ja3s or 'N/A'} flow={key}"
                )

    def _on_tls_alert(self, rec: "TLSRecord", alert: Dict):
        level = alert.get("level")
        desc = alert.get("description")
        self.logger.log_message(
            f"[TLS][Alert] level={level} desc={desc} {rec.direction} "
            f"{rec.src}:{rec.src_port}->{rec.dst}:{rec.dst_port}"
        )

    def _on_tls_application_data(self, rec: "TLSRecord"):
        """
        Optional: forward TLS Application Data using the last seen TCP seq/ack for that direction.
        If the TLS policy blocked/quarantined this flow, TLSRecordManager already suppresses this callback.
        """
        # Use the same canonicalizer you use elsewhere
        key = self._canon_key(rec.src, rec.src_port, rec.dst, rec.dst_port)

        # Cache the payload if you want to reassemble later
        self._tls_streams.setdefault(key, []).append(rec.payload)

        dir_key = (key, rec.direction)
        last_pkt = self._last_tcp_pkt.get(dir_key)
        if not last_pkt:
            self.logger.log_message(
                f"[TLS] 🔒 AppData {len(rec.payload)}B (no TCP context for forwarding) "
                f"{rec.src}:{rec.src_port}->{rec.dst}:{rec.dst_port}"
            )
            return

        try:
            # L2: reuse Ether if we saw it
            ether = last_pkt[Ether] if last_pkt.haslayer(Ether) else None
            base_eth = Ether(dst=ether.dst, src=ether.src) if ether else Ether()

            # L3: decide v4 vs v6 WITHOUT indexing IPv6
            is_v6 = last_pkt.haslayer(IPv6)
            ip_layer = (IPv6(src=rec.src, dst=rec.dst) if is_v6
                        else IP(src=rec.src, dst=rec.dst))

            # L4: borrow seq/ack/window from the last observed TCP in this direction
            if not last_pkt.haslayer(TCP):
                raise RuntimeError("No TCP layer on last_pkt for forwarding context")
            tcp_prev = last_pkt[TCP]
            tcp_seg = TCP(
                sport=rec.src_port,
                dport=rec.dst_port,
                flags="PA",
                seq=tcp_prev.seq,
                ack=tcp_prev.ack,
                window=tcp_prev.window
            )

            # Build full packet (note: conditional now only affects L2, not the whole chain)
            out = base_eth / ip_layer / tcp_seg / Raw(load=rec.payload)

            # Send via your writer (add iface if your writer requires it)
            self.packet_writer.queue_packet(out)
            self.logger.log_message(
                f"[TLS] 🔁 Forwarded AppData {len(rec.payload)}B {rec.src}:{rec.src_port}->{rec.dst}:{rec.dst_port}"
            )
        except Exception as e:
            self.logger.log_message(f"[TLS] ❌ Forwarding error: {e}")

    def _on_tls_event(self, evt: Dict):
        # Optional: compact log of notable events from TLSRecordManager
        kind = evt.get("kind")
        data = evt.get("data", {})
        if kind in ("block", "quarantine", "policy_alert"):
            self.logger.log_message(f"[TLS][Policy] {kind.upper()} {data}")

    def _on_tls_decision(self, flow_key, rec: "TLSRecord", decision):
        # Surface decisions (allow/alert/block/quarantine)
        if decision.action != "allow":
            self.logger.log_message(
                f"[TLS][Decision] {decision.action.upper()} flow={flow_key} reason={decision.reason} tags={decision.tags}"
            )

    # ---- misc helpers ---------------------------------------------------------

    def normalize_mac(self, mac: str) -> str:
        return mac.replace('-', ':').lower()

class IGMPManager:
    """
    Manages IPv4/IPv6 multicast memberships:
      • IGMPv1/v2: Reports(0x12/0x16), Leave(0x17), Query(0x11)
      • IGMPv3: Membership Report (0x22) with per-record INCLUDE/EXCLUDE/ALLOW/BLOCK
      • MLDv1: Report(131), Done(132), Query(130)
      • MLDv2: Report(143) with per-record INCLUDE/EXCLUDE/ALLOW/BLOCK

    Keeps a per-(group,iface) membership table with source filters for SSM.
    Periodically sends General Queries (v2 style) and purges stale entries.
    """

    # IGMPv3 record types (RFC 3376)
    IGMPV3_REC_TYPES = {
        1: "MODE_IS_INCLUDE",
        2: "MODE_IS_EXCLUDE",
        3: "CHANGE_TO_INCLUDE_MODE",
        4: "CHANGE_TO_EXCLUDE_MODE",
        5: "ALLOW_NEW_SOURCES",
        6: "BLOCK_OLD_SOURCES",
    }

    # MLDv2 record types (RFC 3810) — same numeric values as IGMPv3
    MLDV2_REC_TYPES = IGMPV3_REC_TYPES

    def __init__(self, router_logger, packet_writer):
        self.router_logger = router_logger
        self.packet_writer = packet_writer
        self.IGMP_ALL_HOSTS_GROUP = "224.0.0.1"   # all-systems
        self.RIP_ALL_ROUTERS     = "224.0.0.9"    # RIP2
        self.MDNS_ALL_NODES      = "224.0.0.251"  # mDNS (optional fast-path)

        # Query cadence / timeout knobs
        self.IGMP_QUERY_INTERVAL = 60
        self.IGMP_MEMBERSHIP_TIMEOUT = 260   # ~ default IGMP (Qi*2 + QRV*QI)
        self.LAST_MEMBER_QUERY_INTERVAL = 2  # optional (not fully modeled)

        # Membership DB:
        #   (group, ifname) -> {
        #       "last_report": ts,
        #       "mode": "include" | "exclude",
        #       "sources": set[str],    # for IGMPv3/MLDv2 SSM
        #   }
        self._multicast_groups: dict[tuple[str, str], dict] = {}

        self._group_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._interfaces_config = {}

        self.router_logger.log_message("[IGMP] Initialized (v1/v2/v3 + MLDv1/v2).")

    def set_interfaces_config(self, interfaces_config: dict):
        self._interfaces_config = interfaces_config

    # --------------------------- Packet handling ---------------------------

    def handle_packet(self, pkt: "Packet", inbound_ifname: str):
        """
        Handle IGMP (IPv4) and MLD (IPv6) packets. Updates membership table.
        Safe with or without Scapy's v3/v2 layers present.
        """
        # -------- IGMP over IPv4 --------
        if pkt.haslayer(IGMP):
            ig = pkt[IGMP]
            ip = pkt[IP]
            src_ip = ip.src
            gaddr = str(getattr(ig, "gaddr", "0.0.0.0"))
            ig_type = int(getattr(ig, "type", 0))

            # v2 Query (0x11) / v1 Report (0x12) / v2 Report (0x16) / v2 Leave (0x17)
            self.router_logger.log_message(
                f"[IGMP] v{self._infer_igmp_version(ig_type)} type=0x{ig_type:02x} "
                f"from {src_ip} on {inbound_ifname.split('_')[-1]} gaddr={gaddr}"
            )

            if ig_type == 0x11:  # Query (general or group-specific)
                # We *could* trigger last-member logic; for now just log.
                return

            if ig_type in (0x12, 0x16):  # Report (v1 or v2)
                group = gaddr if gaddr != "0.0.0.0" else str(getattr(ig, "addr", "0.0.0.0"))
                self._join_group(group, inbound_ifname, mode="include", sources=None, who=src_ip, proto="IGMP")
                return

            if ig_type == 0x17:  # Leave Group
                self._leave_group(gaddr, inbound_ifname, who=src_ip, proto="IGMP")
                return

            # IGMPv3 membership report (0x22) — may be parsed by IGMPv3 layer in Scapy
            if ig_type == 0x22 or pkt.haslayer("IGMPv3"):
                self._handle_igmpv3_report(pkt, inbound_ifname, src_ip)
                return

        # -------- MLD over IPv6 --------
        # ICMPv6 types: 130 Query, 131 Report (v1), 132 Done (v1), 143 Report (v2)
        if pkt.haslayer(IPv6):
            v6 = pkt[IPv6]
            src_ip6 = v6.src

            # MLDv1 Query / Report / Done
            if pkt.haslayer(MLDReport) or pkt.haslayer(MLDDone) or pkt.haslayer(ICMPv6MLQuery):
                group_ip = self._get_mld_group(pkt)
                kind = "Report" if pkt.haslayer(MLDReport) else "Done" if pkt.haslayer(MLDDone) else "Query"
                self.router_logger.log_message(
                    f"[MLD] {kind} from {src_ip6} on {inbound_ifname.split('_')[-1]} gaddr={group_ip}"
                )
                if pkt.haslayer(MLDReport):  # join
                    self._join_group(group_ip, inbound_ifname, mode="include", sources=None, who=src_ip6, proto="MLD")
                elif pkt.haslayer(MLDDone):  # leave
                    self._leave_group(group_ip, inbound_ifname, who=src_ip6, proto="MLD")
                return

            # MLDv2 report (ICMPv6 type 143). Layer names vary; try robustly.
            if self._looks_like_mldv2_report(pkt):
                self._handle_mldv2_report(pkt, inbound_ifname, src_ip6)
                return

    # --------------------------- Membership logic ---------------------------

    def should_forward_multicast(self, multicast_ip: str, outbound_ifname: str) -> bool:
        """
        Decide whether to forward a multicast frame to outbound_ifname.
        Fast-paths for well-known groups; otherwise consult membership + timeout.
        """
        if multicast_ip in (self.IGMP_ALL_HOSTS_GROUP, self.RIP_ALL_ROUTERS, self.MDNS_ALL_NODES):
            return True

        key = (multicast_ip, outbound_ifname)
        with self._group_lock:
            ent = self._multicast_groups.get(key)
            if not ent:
                return False
            if (time.time() - ent["last_report"]) < self.IGMP_MEMBERSHIP_TIMEOUT:
                return True
            # timeout
            self.router_logger.log_message(
                f"[IGMP] Membership for {multicast_ip} on {outbound_ifname.split('_')[-1]} timed out; purging."
            )
            del self._multicast_groups[key]
        return False

    def get_group_memberships(self) -> dict:
        with self._group_lock:
            # shallow copy; sets converted to sorted lists for readability
            out = {}
            for (g, iface), ent in self._multicast_groups.items():
                out[(g, iface)] = {
                    "last_report": ent["last_report"],
                    "mode": ent["mode"],
                    "sources": sorted(ent["sources"]) if ent["sources"] else [],
                }
            return out

    # --------------------------- Periodic thread ---------------------------

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._periodic_query_loop, daemon=True, name="IGMPManagerThread")
        self._thread.start()
        self.router_logger.log_message("[IGMP] Manager thread started.")

    def stop(self):
        if self._thread and self._thread.is_alive():
            self.router_logger.log_message("[IGMP] Stopping manager thread...")
            self._stop_event.set()
            self._thread.join(timeout=2)
            self.router_logger.log_message("[IGMP] Manager thread stopped.")

    # --------------------------- Internals ---------------------------

    def _periodic_query_loop(self):
        self.router_logger.log_message("[IGMP] Query thread started.")
        while not self._stop_event.is_set():
            self._send_general_queries()
            self._purge_memberships()
            self._stop_event.wait(self.IGMP_QUERY_INTERVAL)
        self.router_logger.log_message("[IGMP] Query thread has exited.")

    def _send_general_queries(self):
        """Send IGMPv2 General Query on each configured IPv4 interface (skip loopback)."""
        for ifname, cfg in self._interfaces_config.items():
            ip_src = cfg.get("ip_addr")
            mac_src = cfg.get("mac")
            if not ip_src or not mac_src:
                continue
            lname = ifname.lower()
            if "loopback" in lname or lname == "lo":
                continue

            pkt = (
                Ether(src=mac_src, dst="01:00:5e:00:00:01")
                / IP(src=ip_src, dst=self.IGMP_ALL_HOSTS_GROUP, ttl=1)
                / IGMP(type=0x11, mrcode=100, gaddr="0.0.0.0")
            )
            self.router_logger.log_message(f"[IGMP] Sending General Query on {ifname.split('_')[-1]}")
            self.packet_writer.queue_packet(pkt, ifname)

    def _purge_memberships(self):
        now = time.time()
        with self._group_lock:
            to_del = [
                key for key, ent in self._multicast_groups.items()
                if (now - ent["last_report"]) > self.IGMP_MEMBERSHIP_TIMEOUT
            ]
            for key in to_del:
                g, ifn = key
                del self._multicast_groups[key]
                self.router_logger.log_message(f"[IGMP] 🗑️ Timed out membership for {g} on {ifn.split('_')[-1]}.")

    # ---------- v3 / v2 helpers ----------

    def _join_group(self, group_ip: str, ifname: str, *, mode: str, sources: set | None, who: str, proto: str):
        with self._group_lock:
            key = (group_ip, ifname)
            ent = self._multicast_groups.get(key, {"mode": "include", "sources": set(), "last_report": 0})
            if sources:
                ent["sources"].update(sources)
            ent["mode"] = mode  # for v2 keep "include"
            ent["last_report"] = time.time()
            self._multicast_groups[key] = ent
        src_txt = f" sources={sorted(sources)}" if sources else ""
        self.router_logger.log_message(f"[{proto}] ✅ {who} joined {group_ip} on {ifname.split('_')[-1]} ({mode}{src_txt})")

    def _leave_group(self, group_ip: str, ifname: str, *, who: str, proto: str):
        with self._group_lock:
            key = (group_ip, ifname)
            if key in self._multicast_groups:
                del self._multicast_groups[key]
                self.router_logger.log_message(f"[{proto}] 🗑️ {who} left {group_ip} on {ifname.split('_')[-1]}.")
            else:
                self.router_logger.log_message(f"[{proto}] {who} sent Leave for {group_ip}, but not in table.")

    def _handle_igmpv3_report(self, pkt: "Packet", ifname: str, src_ip: str):
        """
        Parse IGMPv3 membership report if Scapy provides IGMPv3/IGMPv3gr layers.
        Fallback: try to pull fields generically if layers not available.
        """
        try:
            # Scapy: IGMPv3mr (report) contains multiple IGMPv3gr (group records)
            mr = pkt.getlayer("IGMPv3") or pkt.getlayer("IGMPv3mr") or pkt.getlayer(IGMP)
            records = getattr(mr, "records", None) or getattr(mr, "grps", None)
            if not records:
                self.router_logger.log_message("[IGMP] v3 report without records (parser mismatch).")
                return

            for rec in records:
                rtype = int(getattr(rec, "rtype", getattr(rec, "type", 0)))
                group = str(getattr(rec, "maddr", getattr(rec, "gaddr", "0.0.0.0")))
                srcs = [str(s) for s in (getattr(rec, "srcaddrs", []) or getattr(rec, "sources", []))]
                rname = self.IGMPV3_REC_TYPES.get(rtype, f"UNKNOWN({rtype})")

                # update membership by record semantic
                if rtype in (1, 3):  # MODE_IS_INCLUDE / CHANGE_TO_INCLUDE_MODE
                    self._join_group(group, ifname, mode="include", sources=set(srcs) if srcs else set(), who=src_ip, proto="IGMPv3")
                elif rtype in (2, 4):  # MODE_IS_EXCLUDE / CHANGE_TO_EXCLUDE_MODE
                    self._join_group(group, ifname, mode="exclude", sources=set(srcs) if srcs else set(), who=src_ip, proto="IGMPv3")
                elif rtype == 5:  # ALLOW_NEW_SOURCES
                    self._join_group(group, ifname, mode="include", sources=set(srcs), who=src_ip, proto="IGMPv3")
                elif rtype == 6:  # BLOCK_OLD_SOURCES
                    # For BLOCK, we mark last_report and keep the group; optional: prune sources.
                    with self._group_lock:
                        key = (group, ifname)
                        ent = self._multicast_groups.get(key)
                        if ent:
                            ent["last_report"] = time.time()
                    self.router_logger.log_message(
                        f"[IGMPv3] BLOCK_OLD_SOURCES group={group} srcs={srcs} on {ifname.split('_')[-1]}"
                    )
                else:
                    self.router_logger.log_message(f"[IGMPv3] {rname} group={group} srcs={srcs} on {ifname.split('_')[-1]} (noop)")
        except Exception as e:
            self.router_logger.log_message(f"[IGMP] v3 parse error: {e}")

    def _looks_like_mldv2_report(self, pkt: "Packet") -> bool:
        # Scapy names vary: "MLDv2report"/"MLDv2Report"/ICMPv6MLReport2
        for name in ("MLDv2report", "MLDv2Report", "ICMPv6MLReport2"):
            if pkt.haslayer(name):
                return True
        # ICMPv6 type 143
        icmp6 = pkt.getlayer(ICMPv6ND_RA) or pkt.getlayer("ICMPv6Unknown")
        if hasattr(pkt, "haslayer") and pkt.haslayer("ICMPv6"):
            ic = pkt["ICMPv6"]
            if int(getattr(ic, "type", 0)) == 143:
                return True
        return False

    def _handle_mldv2_report(self, pkt: "Packet", ifname: str, src_ip6: str):
        try:
            rep = pkt.getlayer("MLDv2report") or pkt.getlayer("MLDv2Report") or pkt.getlayer("ICMPv6MLReport2")
            records = getattr(rep, "records", None) or getattr(rep, "grps", None)
            if not records:
                self.router_logger.log_message("[MLD] v2 report without records (parser mismatch).")
                return

            for rec in records:
                rtype = int(getattr(rec, "rtype", getattr(rec, "type", 0)))
                group = str(getattr(rec, "mcaddr", getattr(rec, "maddr", "::")))
                srcs  = [str(s) for s in (getattr(rec, "srcaddrs", []) or getattr(rec, "sources", []))]
                rname = self.MLDV2_REC_TYPES.get(rtype, f"UNKNOWN({rtype})")

                if rtype in (1, 3):
                    self._join_group(group, ifname, mode="include", sources=set(srcs) if srcs else set(), who=src_ip6, proto="MLDv2")
                elif rtype in (2, 4):
                    self._join_group(group, ifname, mode="exclude", sources=set(srcs) if srcs else set(), who=src_ip6, proto="MLDv2")
                elif rtype == 5:
                    self._join_group(group, ifname, mode="include", sources=set(srcs), who=src_ip6, proto="MLDv2")
                elif rtype == 6:
                    with self._group_lock:
                        key = (group, ifname)
                        ent = self._multicast_groups.get(key)
                        if ent:
                            ent["last_report"] = time.time()
                    self.router_logger.log_message(
                        f"[MLDv2] BLOCK_OLD_SOURCES group={group} srcs={srcs} on {ifname.split('_')[-1]}"
                    )
                else:
                    self.router_logger.log_message(f"[MLDv2] {rname} group={group} srcs={srcs} on {ifname.split('_')[-1]} (noop)")
        except Exception as e:
            self.router_logger.log_message(f"[MLD] v2 parse error: {e}")

    def _get_mld_group(self, pkt: "Packet") -> str:
        # Best-effort: various scapy layers spell the field differently
        if pkt.haslayer(MLDReport):
            return str(pkt[MLDReport].mcaddr)
        if pkt.haslayer(MLDDone):
            return str(pkt[MLDDone].mcaddr)
        if pkt.haslayer(ICMPv6MLQuery):
            layer = pkt[ICMPv6MLQuery]
            return str(getattr(layer, "addr", getattr(layer, "mcaddr", "::")))
        return "::"

    @staticmethod
    def _infer_igmp_version(igmp_type: int) -> int:
        if igmp_type == 0x22:
            return 3
        if igmp_type in (0x12, 0x16, 0x17, 0x11):
            return 2  # treat v1 report as v2-era for logging
        return 2

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
        entry["last_seen"] = time.time()

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

    def find_alternate_route(self, dest_ip_str: str, exclude_iface: str) -> Dict[str, Any] | None:
        """
        Finds the best alternate route for a destination IP, avoiding the specified interface.
        Used for rerouting in routing loop scenarios.
        """
        try:
            dest_ip_obj = ipaddress.ip_address(dest_ip_str)
            best_match = None
            best_prefix = -1

            with self._rt_lock:
                for net, rt_details in self._routing_table.items():
                    iface = rt_details.get("interface")
                    if iface == exclude_iface:
                        continue  # Skip the looping interface

                    # Prioritize direct loopback if applicable
                    if dest_ip_obj.is_loopback and rt_details["type"] == "direct" and \
                            iface == self.interface_loopback_full_name:
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
                                if rt_details["type"] == "static" and best_match["type"] != "static":
                                    current_match_is_better = True

                        if current_match_is_better and rt_details["cost"] < 16:
                            best_prefix = net.prefixlen
                            best_match = rt_details

            return best_match
        except ValueError:
            return None

class NATManager:
    """
    Manages Network Address Translation (NAT) with both:
      - dynamic NAT for outbound connections, and
      - static port‐forwarding mappings for inbound services.
    Enhanced with NAT timeouts, keep-alive handling, and a basic ALG placeholder.
    Includes port scan detection, IP banning, and temporary NAT leases.
    """

    # Dictionary to map common ports to services and emojis
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
        25565: ("Minecraft", "🧱")
    }

    def __init__(self, router_logger, sendback_manager, router_public_ip: str, packet_writer,
                 interfaces_config: Dict, rip_manager_find_route, arp_manager_resolve, function_call_tracker):
        self.router_logger = router_logger
        self.public_ip = router_public_ip
        self.packet_writer = packet_writer
        self._interfaces_config = interfaces_config
        self._rip_manager_find_route = rip_manager_find_route
        self._arp_manager_resolve = arp_manager_resolve
        self.sendback_manager = sendback_manager
        self.function_call_tracker = function_call_tracker

        # --- Dynamic NAT Configuration ---
        self.NAT_PORT_MIN = 49152
        self.NAT_PORT_MAX = 65535
        self.NAT_TIMEOUT_SECONDS = 300
        self._next_port = self.NAT_PORT_MIN

        # --- Keep-Alive Configuration ---
        self.KEEP_ALIVE_PORT = 19999  # Dedicated UDP port for keep-alive signals
        self.KEEP_ALIVE_PAYLOAD_FORMAT = "!H"  # Network byte order, unsigned short (for the target port)

        # --- NAT Tables ---
        self._nat_table: Dict[
            Tuple[str, int], Tuple[int, float]] = {}  # (internal_ip, internal_port) -> (external_port, timestamp)
        self._nat_reverse_table: Dict[int, Tuple[str, int]] = {}  # external_port -> (internal_ip, internal_port)
        self._static_mappings = {}  # external_port -> (internal_ip, internal_port)

        # --- NAT Security & Temporary Leases ---
        self._port_probe_counts: Dict[str, int] = defaultdict(int)
        self._ban_list: Dict[str, float] = {}  # ip -> ban_expiry_timestamp
        self._ban_threshold = 3  # Number of unmapped port hits to trigger ban
        self._ban_duration = 120  # Ban duration in seconds

        self._max_temp_leases_per_ip = 2  # NEW: Flat limit on active temporary leases per IP
        self._temp_nat_leases: Dict[str, Dict[int, Dict[str, float | str | int]]] = defaultdict(
            dict)  # ip -> {port -> lease_info}
        self._temp_nat_lease_duration = 60  # seconds
        self._temp_nat_cooldown_duration = 10  # seconds

        # --- Threading & Router State ---
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._cleanup_thread = None
        self.router_internal_ip_for_self_mapping: str = "0.0.0.0"

        self._stateful_nat_outbound = {}  # Maps canonical_key -> (translated_port, last_seen_timestamp)
        self._stateful_nat_inbound = {}  # Maps translated_port -> canonical_key
        self.STATEFUL_NAT_TIMEOUT_SECONDS = 300  # A longer timeout for established connections

        # Initialize with predefined static mappings
        self.add_static_mapping(external_port=65406, internal_ip="192.168.1.50", internal_port=88)
        self.add_static_mapping(external_port=80, internal_ip="192.168.1.100", internal_port=80)
        self.add_static_mapping(external_port=443, internal_ip="192.168.1.100", internal_port=443)
        self.add_static_mapping(external_port=2222, internal_ip="192.168.1.10", internal_port=22)
        self.add_static_mapping(external_port=3389, internal_ip="192.168.1.25", internal_port=3389)
        self.add_static_mapping(external_port=25565, internal_ip="192.168.1.75", internal_port=25565)
        self.add_static_mapping(external_port=520, internal_ip="192.168.1.50", internal_port=520)

        self.router_logger.log_message("[NAT] 🚀 Manager initialized with port scan detection and temporary leases.")

    def add_stateful_mapping(self, src_ip, src_port, dst_ip, dst_port):
        """Creates a stateful NAT mapping for an established connection."""
        canonical_key = _get_canonical_session_key(src_ip, src_port, dst_ip, dst_port)
        with self._lock:
            # Check if a dynamic mapping already exists for this flow
            existing_mapping = self._nat_table.get((src_ip, src_port))
            if existing_mapping:
                translated_port, _ = existing_mapping
                self._stateful_nat_outbound[canonical_key] = (translated_port, time.time())
                self._stateful_nat_inbound[translated_port] = canonical_key
                self.router_logger.log_message(
                    f"[NAT][STATEFUL] ✅ Created stateful mapping for {src_ip}:{src_port} -> {self.public_ip}:{translated_port}"
                )

    def set_router_internal_ip(self, ip: str):
        self.router_internal_ip_for_self_mapping = ip
        self.router_logger.log_message(f"[NAT] 🏠 Router's internal IP for self-mapping set to: {ip}")

    def start(self):
        """Starts the NAT cleanup thread."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="NATCleanup")
        self._cleanup_thread.start()
        self.router_logger.log_message("[NAT] ✅ Cleanup thread started.")

    def stop(self):
        """Stops the NAT cleanup thread gracefully."""
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.router_logger.log_message("[NAT] 🛑 Manager stopped.")

    def _cleanup_loop(self):
        """
        Periodically removes stale dynamic NAT entries, expired bans,
        and temporary leases.
        """
        while not self._stop_event.is_set():
            now = time.time()
            with self._lock:
                # 1. Prune stale dynamic NAT entries
                stale_internal_keys = [
                    k for k, (_, ts) in self._nat_table.items() if now - ts > self.NAT_TIMEOUT_SECONDS
                ]
                for internal_key in stale_internal_keys:
                    external_port, _ = self._nat_table.pop(internal_key, (None, None))
                    if external_port and self._nat_reverse_table.get(external_port) == internal_key:
                        del self._nat_reverse_table[external_port]
                    self.router_logger.log_message(
                        f"[NAT] 🗑️ Timed out dynamic port mapping: {internal_key[0]}:{internal_key[1]} → {self.public_ip}:{external_port}"
                    )

                # 2. Prune expired bans
                expired_bans = [ip for ip, expiry in self._ban_list.items() if now >= expiry]
                for ip in expired_bans:
                    del self._ban_list[ip]
                    self._port_probe_counts.pop(ip, None)  # Also clear any lingering counts
                    self.router_logger.log_message(f"[NAT] ✅ Ban expired for {ip}.")

                # 3. Prune expired temporary leases and cooldowns
                for src_ip in list(self._temp_nat_leases.keys()):
                    for port in list(self._temp_nat_leases[src_ip].keys()):
                        lease_info = self._temp_nat_leases[src_ip][port]
                        # Remove the entry if both the lease and cooldown have expired
                        if now >= lease_info["cooldown_end"]:
                            del self._temp_nat_leases[src_ip][port]
                            self.router_logger.log_message(
                                f"[NAT][LEASE] ⏳ Temp lease and cooldown expired for {src_ip} on port {port}.")
                    # Clean up the outer dictionary if it's empty
                    if not self._temp_nat_leases[src_ip]:
                        del self._temp_nat_leases[src_ip]
                now = time.time()
                stale_stateful_keys = [
                    k for k, (_, ts) in self._stateful_nat_outbound.items()
                    if now - ts > self.STATEFUL_NAT_TIMEOUT_SECONDS
                ]
                for key in stale_stateful_keys:
                    translated_port, _ = self._stateful_nat_outbound.pop(key, (None, None))
                    if translated_port in self._stateful_nat_inbound:
                        del self._stateful_nat_inbound[translated_port]
                    self.router_logger.log_message(f"[NAT][STATEFUL] 🗑️ Timed out stateful mapping for {key}.")

            self._stop_event.wait(self.NAT_TIMEOUT_SECONDS / 2)

    def add_static_mapping(self, external_port: int, internal_ip: str, internal_port: int):
        """Add a permanent port‐forwarding rule."""
        with self._lock:
            if external_port in self._static_mappings:
                self.router_logger.log_message(
                    f"[NAT][STATIC] ⚠️ Static mapping for {self.public_ip}:{external_port} already exists. Overwriting."
                )
            self._static_mappings[external_port] = (internal_ip, internal_port)

        service_name, service_emoji = self.PORT_SERVICES.get(external_port, ("Custom Service", "✳️"))
        self.router_logger.log_message(
            f"[NAT][STATIC] {service_emoji} Added static mapping for {service_name}: {self.public_ip}:{external_port} "
            f"→ {internal_ip}:{internal_port}"
        )

    def remove_static_mapping(self, external_port: int):
        """Remove an existing static port-forwarding rule."""
        with self._lock:
            removed = self._static_mappings.pop(external_port, None)
        if removed:
            self.router_logger.log_message(
                f"[NAT][STATIC] 🗑️ Removed static mapping for {self.public_ip}:{external_port}"
            )
        else:
            self.router_logger.log_message(
                f"[NAT][STATIC] ❓ No static mapping found for {self.public_ip}:{external_port} to remove"
            )

    def _get_next_port(self) -> int:
        with self._lock:
            initial_next_port = self._next_port
            while True:
                port = self._next_port
                self._next_port += 1
                if self._next_port > self.NAT_PORT_MAX:
                    self._next_port = self.NAT_PORT_MIN

                if port not in self._nat_reverse_table and port not in self._static_mappings:
                    return port

                if self._next_port == initial_next_port:
                    self.router_logger.log_message("[NAT] ❌ No available dynamic NAT ports in pool.")
                    return -1

    def _apply_alg(self, packet: Packet, direction: str):
        # Placeholder for ALG logic
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
            self.router_logger.log_message(
                f"[NAT][ALG] 📁 FTP ALG triggered ({direction}). (Placeholder: Actual payload inspection/rewriting needed)")
        if packet.haslayer(UDP) and packet.haslayer(DNS) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
            self.router_logger.log_message(
                f"[NAT][ALG] ❓ DNS traffic observed ({direction}). (No DNS payload rewriting by NAT.)")

    def handle_keep_alive(self, packet: Packet):
        """
        Handles an incoming keep-alive request to refresh a dynamic NAT mapping.

        Expects a UDP packet on KEEP_ALIVE_PORT with the target external port
        in the payload. This method should be called by the main router logic
        when a UDP packet destined for self.KEEP_ALIVE_PORT is received.
        """
        if not packet.haslayer(UDP) or not packet.haslayer(Raw):
            return

        payload = packet[Raw].load
        payload_size = struct.calcsize(self.KEEP_ALIVE_PAYLOAD_FORMAT)

        if len(payload) != payload_size:
            self.router_logger.log_message(
                f"[NAT][KEEP-ALIVE] ⚠️ Received keep-alive with invalid payload size from {packet[IP].src}. "
                f"Expected {payload_size}, got {len(payload)}."
            )
            return

        try:
            target_port, = struct.unpack(self.KEEP_ALIVE_PAYLOAD_FORMAT, payload)
        except struct.error:
            self.router_logger.log_message(
                f"[NAT][KEEP-ALIVE] ⚠️ Failed to unpack keep-alive payload from {packet[IP].src}."
            )
            return

        with self._lock:
            internal_key = self._nat_reverse_table.get(target_port)
            if internal_key and internal_key in self._nat_table:
                # Mapping exists, refresh its timestamp
                self._nat_table[internal_key] = (target_port, time.time())
                self.router_logger.log_message(
                    f"[NAT][KEEP-ALIVE] 💓 Refreshed mapping for port {target_port} "
                    f"({internal_key[0]}:{internal_key[1]}) from {packet[IP].src}."
                )
            else:
                self.router_logger.log_message(
                    f"[NAT][KEEP-ALIVE] ❓ Received keep-alive for unknown/stale port {target_port} "
                    f"from {packet[IP].src}."
                )

    def translate_outbound(self, packet: Packet):
        """
        Translates outbound packets using dynamic NAT.

        If a connection is being established and a stateful mapping exists, it will
        reuse that mapping. Otherwise, it creates or renews a dynamic mapping.
        """
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            self.router_logger.log_message(
                f"[NAT] ⏭️ Skipping outbound translation for non-IP packet: {packet.summary()}")
            return
        ip = packet[IP] if packet.haslayer(IP) else packet[IPv6]

        # Check for ICMP, DHCP, IGMP, which do not need port translation
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            if packet.haslayer(ICMP):
                self.router_logger.log_message(
                    f"[NAT] 핑 Passing outbound ICMP for {ip.src} to {ip.dst} without port NAT.")
            elif packet.haslayer(DHCP):
                self.router_logger.log_message(f"[NAT] ⏭️ Skipping outbound NAT for DHCP packet from {ip.src}.")
            elif packet.haslayer(IGMP):
                self.router_logger.log_message(f"[NAT] ⏭️ Skipping outbound NAT for IGMP packet from {ip.src}.")
            else:
                self.router_logger.log_message(
                    f"[NAT] 🧐 Skipping outbound translation for unhandled non-TCP/UDP/ICMP packet: {packet.summary()}")
            return

        t = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        internal_key = (ip.src, t.sport)

        with self._lock:
            # Check for an existing stateful mapping first, as it's more persistent
            canonical_key = _get_canonical_session_key(ip.src, t.sport, ip.dst, t.dport)
            stateful_mapping = self._stateful_nat_outbound.get(canonical_key)

            if stateful_mapping:
                # Reuse the existing translated port from the stateful table
                new_port, _ = stateful_mapping
                self.router_logger.log_message(
                    f"[NAT] ➡️ Reusing stateful mapping: "
                    f"{ip.src}:{t.sport} -> {self.public_ip}:{new_port}"
                )
                # Update timestamp to keep the session alive
                self._stateful_nat_outbound[canonical_key] = (new_port, time.time())
            elif internal_key not in self._nat_table:
                # No existing mapping, create a new dynamic one
                new_port = self._get_next_port()
                if new_port == -1:
                    self.router_logger.log_message("[NAT] ❌ Outbound port allocation failed.")
                    return

                self._nat_table[internal_key] = (new_port, time.time())
                self._nat_reverse_table[new_port] = internal_key
                self.router_logger.log_message(
                    f"[NAT] ➡️ Created dynamic mapping: "
                    f"{ip.src}:{t.sport} -> {self.public_ip}:{new_port}"
                )
            else:
                # An old dynamic mapping exists, renew its timestamp
                new_port, _ = self._nat_table[internal_key]
                self._nat_table[internal_key] = (new_port, time.time())
                self.router_logger.log_message(
                    f"[NAT] 🔄 Reusing dynamic mapping: "
                    f"{ip.src}:{t.sport} -> {self.public_ip}:{new_port}"
                )

        # Apply the translation to the packet layers
        ip.src = self.public_ip
        t.sport = new_port

        # Recalculate checksums
        del ip.chksum
        if packet.haslayer(TCP):
            del packet[TCP].chksum
        elif packet.haslayer(UDP):
            del packet[UDP].chksum

    def translate_inbound(self, packet: Packet) -> bool:
        """Translates inbound packets using static, dynamic, or temporary NAT mappings."""
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            self.router_logger.log_message(
                f"[NAT] ⏭️ Skipping inbound translation for non-IP packet: {packet.summary()}")
            return False

        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        src_ip = ip_layer.src

        with self._lock:
            if src_ip in self._ban_list and time.time() < self._ban_list[src_ip]:
                self.router_logger.log_message(f"[NAT] 🛡️ Dropping packet from banned IP: {src_ip}")
                return False

        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            if packet.haslayer(ICMP):
                self.router_logger.log_message(f"[NAT] 핑 Passing ICMP packet without NAT.")
            elif packet.haslayer(DHCP) or packet.haslayer(IGMP):
                self.router_logger.log_message(f"[NAT] ⏭️ Skipping NAT for {packet.name} packet.")
            else:
                self.router_logger.log_message(f"[NAT] 🧐 Unhandled non-TCP/UDP inbound packet: {packet.summary()}")
            return False

        transport = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        ext_port = transport.dport

        internal_mapping = self.get_internal_from_external(ext_port, src_ip)
        if internal_mapping:
            internal_ip, internal_port = internal_mapping
            ip_layer.dst = internal_ip
            transport.dport = internal_port
            self._apply_alg(packet, "inbound")
            return True

        self.router_logger.log_message(
            f"[NAT] 🚫 No mapping for {self.public_ip}:{ext_port} — sending ICMP Port Unreachable."
        )
        self._send_icmp_destination_unreachable(packet, ip_layer, transport)
        return False

    def _send_icmp_destination_unreachable(self, original_packet: Packet, original_ip_layer: IP | IPv6,
                                           original_transport_layer: TCP | UDP):
        """Constructs and sends an ICMP Destination Unreachable message."""
        icmp_src_ip = self.public_ip
        icmp_dst_ip = original_ip_layer.src

        route_to_sender = self._rip_manager_find_route(icmp_dst_ip)
        if not route_to_sender:
            self.router_logger.log_message(
                f"[NAT] ⚠️ Could not find route to original sender {icmp_dst_ip} for ICMP response. Dropping.")
            self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3)
            return

        outbound_iface_for_icmp = route_to_sender["interface"]
        outbound_iface_config = self._interfaces_config.get(outbound_iface_for_icmp)
        if not outbound_iface_config or 'mac' not in outbound_iface_config:
            return
        router_mac_out = outbound_iface_config['mac']
        next_hop_ip_for_icmp = route_to_sender["next_hop"] if route_to_sender["next_hop"] != "0.0.0.0" else icmp_dst_ip
        next_hop_mac_for_icmp = self._arp_manager_resolve(next_hop_ip_for_icmp, outbound_iface_for_icmp)

        if not next_hop_mac_for_icmp:
            self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3)
            return

        icmp_response = Ether(src=router_mac_out, dst=next_hop_mac_for_icmp) / \
                        IP(src=icmp_src_ip, dst=icmp_dst_ip) / \
                        ICMP(type=3, code=3) / \
                        original_ip_layer

        del icmp_response[IP].chksum
        del icmp_response[ICMP].chksum
        self.router_logger.log_message(
            f"[NAT] 🔕 Sent ICMP Dest Unreachable (Port) to {icmp_dst_ip} via {outbound_iface_for_icmp.split('_')[-1]}.")

    def get_internal_from_external(self, external_port: int, src_ip: str) -> Optional[Tuple[str, int]]:
        """
        Returns (internal_ip, internal_port) for a NAT’d external port, with dynamic port scan detection and banning.
        """
        with self._lock:
            # Step 1: Check if IP is currently banned
            ban_expiry = self._ban_list.get(src_ip)
            if ban_expiry and time.time() < ban_expiry:
                self.function_call_tracker.track(
                    identifier='NatInternalFromExternalBannedIP', threshold=20,
                    final_message=f"[NAT] ⛔ get_internal_from_external: Banned IP {src_ip} attempted to access port {external_port}. Count: {{}}.",
                    count_message=None
                )
                return None

            if external_port in self._stateful_nat_inbound:
                canonical_key = self._stateful_nat_inbound[external_port]
                # Verify the return traffic's source IP matches the original flow's destination
                original_src_ip = canonical_key[0][0]
                original_dst_ip = canonical_key[1][0]
                if src_ip == original_dst_ip:
                    # Refresh the stateful timestamp
                    self._stateful_nat_outbound[canonical_key] = (external_port, time.time())
                    # Return the original source IP and port
                    return canonical_key[0][0], canonical_key[0][1]
            # Step 2: Check for a permanent static mapping
            static_mapping = self._static_mappings.get(external_port)
            if static_mapping:
                self.router_logger.log_message(
                    f"[NAT] 🎯 get_internal_from_external: Static hit for external port {external_port}.")
                return static_mapping

            # Step 3: Check for an existing dynamic mapping
            dynamic_mapping = self._nat_reverse_table.get(external_port)
            if dynamic_mapping:
                self.router_logger.log_message(
                    f"[NAT] 🔄 get_internal_from_external: Dynamic hit for external port {external_port}.")
                # Refresh the timestamp for the dynamic mapping to prevent timeout
                internal_key_for_nat_table = dynamic_mapping
                if internal_key_for_nat_table in self._nat_table:
                    current_ext_port, _ = self._nat_table[internal_key_for_nat_table]
                    self._nat_table[internal_key_for_nat_table] = (current_ext_port, time.time())
                return dynamic_mapping

            # Step 4: No permanent mapping found. Handle as a probe.
            self._port_probe_counts[src_ip] += 1
            count = self._port_probe_counts[src_ip]

            if count >= self._ban_threshold:
                expiry_time = time.time() + self._ban_duration
                self._ban_list[src_ip] = expiry_time
                self.router_logger.log_message(
                    f"[NAT] 🔒 IP {src_ip} banned for {self._ban_duration} seconds after {count} probes."
                )
                return None

            # Step 5: Grant a temporary lease to handle the probe, respecting the per-IP limit
            temp_mapping = self._grant_temp_nat_lease(src_ip, external_port)
            if temp_mapping:
                return temp_mapping

            # If no lease is granted (e.g., due to cooldown or lease limit), no mapping is returned.
            return None

    def _grant_temp_nat_lease(self, src_ip: str, external_port: int) -> Optional[Tuple[str, int]]:
        """
        Grants a temporary internal mapping to an external port for a probing IP.
        Returns the internal mapping (ip, port), or None if cooldown or flat IP limit prevents it.
        """
        now = time.time()

        # Check the flat limit of active leases for this IP
        active_leases_for_ip = len([v for v in self._temp_nat_leases.get(src_ip, {}).values() if now < v["lease_end"]])
        if active_leases_for_ip >= self._max_temp_leases_per_ip:
            self.router_logger.log_message(
                f"[NAT][LEASE] ❌ {src_ip} has reached the max lease limit of {self._max_temp_leases_per_ip}. Denying new lease for port {external_port}."
            )
            return None

        lease_info = self._temp_nat_leases[src_ip].get(external_port)

        if lease_info:
            if now < lease_info["lease_end"]:
                self.function_call_tracker.track(
                    identifier='NatInternalTempLeaseActive', threshold=15,
                    final_message=f"[NAT][LEASE] ⏱️ Active temp NAT lease for {src_ip}:{external_port} → {lease_info['internal_ip']}:{lease_info['internal_port']}. Count: {{}}.",
                    count_message=None
                )
                return lease_info["internal_ip"], lease_info["internal_port"]
            elif now < lease_info["cooldown_end"]:
                self.function_call_tracker.track(
                    identifier='NatInternalTempLeaseCooldown', threshold=10,
                    final_message=f"[NAT][LEASE] ❌ {src_ip} is in cooldown for port {external_port} until {time.ctime(lease_info['cooldown_end'])}. Count: {{}}.",
                    count_message=None
                )
                return None

        # No lease or expired + cooldown ended → issue new lease
        temp_internal_ip = f"192.168.99.{(external_port % 100) + 100}"
        temp_internal_port = external_port

        self._temp_nat_leases[src_ip][external_port] = {
            "internal_ip": temp_internal_ip,
            "internal_port": temp_internal_port,
            "lease_end": now + self._temp_nat_lease_duration,
            "cooldown_end": now + self._temp_nat_lease_duration + self._temp_nat_cooldown_duration
        }

        self.router_logger.log_message(
            f"[NAT][LEASE] 🆕 Granted temp NAT lease for {src_ip}:{external_port} → {temp_internal_ip}:{temp_internal_port} "
            f"for {self._temp_nat_lease_duration}s (cooldown {self._temp_nat_cooldown_duration}s)."
        )
        return temp_internal_ip, temp_internal_port

    def get_internal_ip_from_external(self, external_ip: str) -> Optional[str]:
        """
        Returns the internal IP corresponding to a NAT'd external IP.
        (Primarily for 1:1 NAT or specific ALG needs. For port NAT, it's more complex.)
        """
        if external_ip == self.public_ip:
            self.router_logger.log_message(
                f"[NAT] 🧐 Query for internal IP from external {external_ip}. Requires deeper NAT state knowledge.")
            return None
        return None

class DNSManager:
    """
    Manages DNS query proxying. Intercepts local DNS requests and forwards
    them to a public DNS server.
    Enhanced with DNS caching, conditional forwarding, and basic filtering.
    """

    def __init__(self, router_logger, packet_writer):
        self.packet_writer = packet_writer
        self.router_logger = router_logger
        self.PRIMARY_DNS_SERVER = "8.8.8.8"
        self.PRIMARY_DNS_PORT = 53  # NEW
        self._pending_requests = {}
        self._lock = threading.Lock()
        self._dns_cache = {}
        self.DNS_CACHE_TTL_MIN = 60
        self.DNS_CACHE_MAX_ENTRIES = 1000
        self._conditional_forwarders = {}  # allow "ip" or "ip:port"
        self._dns_blacklist = set()
        self.router_logger.log_message("[DNS] Manager initialized.")

    # --- NEW: easy way to pick a local stub like 127.0.0.1:8888
    def set_primary_upstream(self, ip: str, port: int = 53):
        self.PRIMARY_DNS_SERVER = ip
        self.PRIMARY_DNS_PORT = int(port)
        self.router_logger.log_message(f"[DNS] Primary upstream set to {ip}:{port}")

    # --- helper: resolve forward target (supports "ip:port" values in conditional forwarders)
    def _get_forward_target(self, qname: str) -> tuple[str, int]:
        q = qname.lower().strip('.')
        for suffix, target in self._conditional_forwarders.items():
            if q.endswith(suffix) or q == suffix:
                if ":" in target and target.count(":") == 1:  # minimal, IPv4 "ip:port"
                    ip, port = target.split(":", 1)
                    return ip, int(port)
                return target, self.PRIMARY_DNS_PORT
        return self.PRIMARY_DNS_SERVER, self.PRIMARY_DNS_PORT

    def add_conditional_forwarder(self, domain_suffix: str, dns_server_ip: str):
        """Adds a conditional DNS forwarder."""
        self._conditional_forwarders[domain_suffix.lower()] = dns_server_ip
        self.router_logger.log_message(f"[DNS] Added conditional forwarder: {domain_suffix} -> {dns_server_ip}")

    def remove_conditional_forwarder(self, domain_suffix: str):
        """Removes a conditional DNS forwarder."""
        if domain_suffix.lower() in self._conditional_forwarders:
            del self._conditional_forwarders[domain_suffix.lower()]
            self.router_logger.log_message(f"[DNS] Removed conditional forwarder: {domain_suffix}")

    def add_dns_blacklist_entry(self, domain_suffix: str):
        """Adds a domain suffix to the DNS blacklist."""
        self._dns_blacklist.add(domain_suffix.lower())
        self.router_logger.log_message(f"[DNS] Added to blacklist: {domain_suffix}")

    def remove_dns_blacklist_entry(self, domain_suffix: str):
        """Removes a domain suffix from the DNS blacklist."""
        if domain_suffix.lower() in self._dns_blacklist:
            self._dns_blacklist.remove(domain_suffix.lower())
            self.router_logger.log_message(f"[DNS] Removed from blacklist: {domain_suffix}")

    def _is_blacklisted(self, qname: str) -> bool:
        """Checks if a domain name is blacklisted."""
        qname_lower = qname.lower().strip('.')  # Remove trailing dot
        for bl_entry in self._dns_blacklist:
            if qname_lower.endswith(bl_entry) or qname_lower == bl_entry:
                return True
        return False

    def _get_forward_dns_server(self, qname: str) -> str:
        """Determines the DNS server to forward the query to based on conditional forwarders."""
        qname_lower = qname.lower().strip('.')
        for suffix, dns_ip in self._conditional_forwarders.items():
            if qname_lower.endswith(suffix) or qname_lower == suffix:
                self.router_logger.log_message(f"[DNS] Using conditional forwarder for {qname}: {dns_ip}")
                return dns_ip
        return self.PRIMARY_DNS_SERVER

    def _add_to_cache(self, qname: str, response_packet: Packet):
        """Adds a DNS response to the cache."""
        with self._lock:
            if len(self._dns_cache) >= self.DNS_CACHE_MAX_ENTRIES:
                oldest_key = next(iter(self._dns_cache))
                del self._dns_cache[oldest_key]

            min_ttl = self.DNS_CACHE_TTL_MIN
            if response_packet.haslayer(DNSRR) and response_packet[DNSRR].ttl:
                ttl = response_packet[DNSRR].ttl
                cache_duration = max(ttl, min_ttl)
            else:
                cache_duration = min_ttl

            expiry_time = time.time() + cache_duration
            self._dns_cache[qname] = (bytes(response_packet), expiry_time)  # Store raw bytes
            self.router_logger.log_message(f"[DNS] Added {qname} to cache, expires in {cache_duration}s.")

    def _get_from_cache(self, qname: str) -> Packet | None:
        """Retrieves a DNS response from the cache if valid."""
        with self._lock:
            cached_entry = self._dns_cache.get(qname)
            if cached_entry:
                response_bytes, expiry_time = cached_entry
                if time.time() < expiry_time:
                    self.router_logger.log_message(f"[DNS] Cache hit for {qname}.")
                    return Ether(response_bytes)
                else:
                    del self._dns_cache[qname]
        return None

    def handle_query(self, packet, inbound_iface: str, router_interfaces: dict,
                     get_mac_function, find_route_function):
        if not (packet.haslayer(DNS) and packet[DNS].qr == 0):
            return False

        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            self.router_logger.log_message("[DNS] ❌ No IP layer in DNS query.")
            return False

        udp_layer = packet.getlayer(UDP)
        dns_layer = packet.getlayer(DNS)
        if not udp_layer or not dns_layer:
            return False

        qname = dns_layer.qd.qname.decode() if dns_layer.qd else "unknown"

        # blacklist / cache paths unchanged...
        cached = self._get_from_cache(qname)
        if cached:
            resp = cached.copy()
            # rewrite back to client
            if IP in resp:
                resp[IP].dst = ip_layer.src
                del resp[IP].chksum
            elif IPv6 in resp:
                pass
            resp[UDP].dport = udp_layer.sport
            resp[DNS].id = dns_layer.id
            if resp.haslayer(Ether) and packet.haslayer(Ether):
                resp[Ether].dst = packet[Ether].src
            if UDP in resp: del resp[UDP].chksum
            self.packet_writer.queue_packet(resp, inbound_iface)
            return True

        # --- NEW: choose (ip, port) and detect loopback
        target_ip, target_port = self._get_forward_target(qname)
        is_loopback_target = False
        try:
            is_loopback_target = ipaddress.ip_address(target_ip).is_loopback
        except ValueError:
            pass

        # pick outbound iface
        if is_loopback_target:
            # find the loopback interface we added to _interfaces_config (ip 127.0.0.1 / ::1)
            outbound_iface_name = None
            for name, cfg in router_interfaces.items():
                if cfg.get("ip_addr") in ("127.0.0.1", "::1"):
                    outbound_iface_name = name
                    break
            if not outbound_iface_name:
                self.router_logger.log_message("[DNS] ❌ No loopback interface configured.")
                return False
        else:
            route = find_route_function(target_ip)
            if not route or not route.get("interface"):
                return False
            outbound_iface_name = route["interface"]

        outbound_iface_config = router_interfaces.get(outbound_iface_name)
        if not outbound_iface_config:
            return False

        # --- NEW: correct pending key: (router_src_ip_used_upstream, client_sport, dns_id)
        router_src_ip_used_upstream = "127.0.0.1" if is_loopback_target else outbound_iface_config["ip_addr"]
        key = (router_src_ip_used_upstream, udp_layer.sport, dns_layer.id)
        with self._lock:
            self._pending_requests[key] = {
                "original_mac_src": packet[Ether].src if packet.haslayer(Ether) else None,
                "inbound_iface": inbound_iface
            }

        # build upstream packet
        fwd = packet.copy()
        if IP in fwd:
            fwd[IP].src = router_src_ip_used_upstream
            fwd[IP].dst = target_ip
            del fwd[IP].chksum
        elif IPv6 in fwd:
            if ":" not in target_ip:
                target_ip = "2001:4860:4860::8888"
            fwd[IPv6].src = outbound_iface_config["ip_addr"]
            fwd[IPv6].dst = target_ip
        fwd[UDP].dport = target_port  # NEW: allow non-53 upstream
        del fwd[UDP].chksum

        if fwd.haslayer(Ether):
            fwd[Ether].src = outbound_iface_config["mac"]
            if is_loopback_target:
                fwd[Ether].dst = "00:00:00:00:00:00"  # no ARP on loopback
            else:
                gw_ip = route.get("next_hop") or target_ip
                mac = get_mac_function(gw_ip, outbound_iface_name)
                if not mac:
                    with self._lock: self._pending_requests.pop(key, None)
                    return True
                fwd[Ether].dst = mac

        self.router_logger.log_message(
            f"[DNS] ➡️ {ip_layer.src}:{udp_layer.sport} {qname} -> {target_ip}:{target_port} via {outbound_iface_name.split('_')[-1]}"
        )
        self.packet_writer.queue_packet(fwd, outbound_iface_name)
        return True

    def handle_response(self, packet, router_interfaces: dict):
        if not (packet.haslayer(DNS) and packet[DNS].qr == 1):
            return False

        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet[DNS]
        if not (ip_layer and udp_layer and dns_layer):
            return False

        qname = dns_layer.qd.qname.decode() if dns_layer.qd else "unknown"

        # --- NEW: look up by (dst_is_router_src_used_upstream, dport_is_client_sport, id)
        lookup_key = (ip_layer.dst, udp_layer.dport, dns_layer.id)
        with self._lock:
            original = self._pending_requests.pop(lookup_key, None)

        if not original:
            return False

        self._add_to_cache(qname, packet)
        resp_iface = original["inbound_iface"]
        resp_cfg = router_interfaces.get(resp_iface)
        if not resp_cfg:
            return False

        out = packet.copy()
        # rewrite back to LAN client
        if IP in out:
            out[IP].src = resp_cfg["ip_addr"]
            out[IP].dst = lookup_key[0]  # client IP stored in key
            del out[IP].chksum
        elif IPv6 in out:
            out[IPv6].src = resp_cfg["ip_addr"]
            out[IPv6].dst = lookup_key[0]

        if Ether in out and original["original_mac_src"]:
            out[Ether].src = resp_cfg["mac"]
            out[Ether].dst = original["original_mac_src"]

        if UDP in out: del out[UDP].chksum

        self.router_logger.log_message(f"[DNS] ⬅️ {qname} -> {lookup_key[0]} via {resp_iface.split('_')[-1]}")
        self.packet_writer.queue_packet(out, resp_iface)  # specify egress iface
        return True

class ARPManager:
    """
    Manages ARP resolution, caching, and related ARP operations for the router.
    Enhanced with Gratuitous ARP and a placeholder for ARP Snooping/Inspection.
    """

    def __init__(self, router_logger,outbound_load_balancer, cache_timeout_seconds=300):
        """
        Initializes the ARP Manager.
        Args:
            router_logger: The logger instance for logging messages.
            cache_timeout_seconds (int): How long a cache entry is valid.
        """
        self.dhcp_server_out = None
        self.dhcp_server_in = None
        self.notification_manager = None # Added for the new logic
        self.sniffer = None
        self._active_ips = set()
        self.router_logger = router_logger
        # self.packet_writer = packet_writer  # Removed as it's no longer needed
        self._arp_cache = {}  # Maps IP -> (MAC, timestamp)
        self._arp_cache_lock = threading.Lock()
        self.CACHE_TIMEOUT = cache_timeout_seconds
        self.dhcp_manager = None # Not used directly in the provided snippets, but kept for context
        self._temp_arp_leases: dict[str, dict[str, float]] = {}
        # ARP Snooping/Inspection (Placeholder)
        self.MAX_REPLIES_PER_LEASE  = 3
        self._trusted_ports = set()  # Example: {'Ethernet_IN_Full_Name'}
        self.outbound_load_balancer = outbound_load_balancer
        self._static_arp_entries = {}  # {IP: MAC} for trusted static entries

        self._cache_hit_table = defaultdict(lambda: deque(maxlen=10))

    def set_dhcp_server_reference(self, dhcp_server_in, dhcp_server_out):
        """
        Sets a reference to the DHCPServer instance. This enables Dynamic ARP Inspection.
        """
        self.dhcp_server_in = dhcp_server_in
        self.dhcp_server_out = dhcp_server_out
        self.router_logger.log_message("[ARP] DHCP server reference set. Dynamic ARP Inspection is now active.")

    def add_trusted_port(self, iface_full_name: str):
        """Marks an interface as a 'trusted port' for ARP snooping."""
        self._trusted_ports.add(iface_full_name)
        self.router_logger.log_message(f"[ARP] Added trusted port: {iface_full_name.split('_')[-1]}")

    def remove_trusted_port(self, iface_full_name: str):
        """Removes an interface from 'trusted ports' for ARP snooping."""
        if iface_full_name in self._trusted_ports:
            self._trusted_ports.remove(iface_full_name)
            self.router_logger.log_message(f"[ARP] Removed trusted port: {iface_full_name.split('_')[-1]}")

    def add_static_arp_entry(self, ip_address: str, mac_address: str):
        """Adds a static ARP entry."""
        self._static_arp_entries[ip_address] = mac_address
        self.router_logger.log_message(f"[ARP] Added static ARP entry: {ip_address} -> {mac_address}")

    def remove_static_arp_entry(self, ip_address: str):
        """Removes a static ARP entry."""
        if ip_address in self._static_arp_entries:
            del self._static_arp_entries[ip_address]
            self.router_logger.log_message(f"[ARP] Removed static ARP entry for: {ip_address}")

    def perform_arp_inspection(self, pkt: Packet, inbound_iface: str) -> bool:
        """
        Performs Dynamic ARP Inspection (DAI).
        Returns True if the packet is valid, False if it should be dropped.
        """
        if not pkt.haslayer(ARP):
            return True

        arp_layer = pkt[ARP]
        sender_ip = arp_layer.psrc
        sender_mac = arp_layer.hwsrc

        # 1. Check static ARP entries first (highest priority)
        static_mac = self._static_arp_entries.get(sender_ip)
        if static_mac and static_mac.lower() != sender_mac.lower():
            self.router_logger.log_message(
                f"[ARP][INSPECT] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on {inbound_iface.split('_')[-1]}: Static entry conflict ({static_mac})."
            )
            return False

        # 2. If on a trusted port, bypass further inspection
        if inbound_iface in self._trusted_ports:
            return True

        # 3. For untrusted ports, perform DAI using DHCP lease data
        # Note: self.dhcp_server was present in original, replaced with self.dhcp_server_in/out
        # assuming one of them would contain the relevant bindings.
        dhcp_server_for_dai = self.dhcp_server_out or self.dhcp_server_in # Use either if available

        if dhcp_server_for_dai:
            dhcp_bindings = dhcp_server_for_dai.get_ip_to_mac_bindings()

            if sender_ip in dhcp_bindings:
                trusted_mac = dhcp_bindings[sender_ip]
                if sender_mac.lower() != trusted_mac.lower():
                    self.router_logger.log_message(
                        f"[ARP][DAI] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on untrusted port {inbound_iface.split('_')[-1]}. "
                        f"Reason: MAC does not match DHCP lease ({trusted_mac}). Potential ARP spoofing."
                    )
                    return False  # Drop packet
                # Packet is valid if it matches a DHCP lease
                return True
            else:
                # The sender's IP is not in the DHCP lease table (e.g., a static IP).
                # A strict security policy blocks this on untrusted ports.
                self.router_logger.log_message(
                    f"[ARP][DAI] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on untrusted port {inbound_iface.split('_')[-1]}. "
                    f"Reason: IP address not found in DHCP lease table."
                )
                return False  # Drop packet

        # Fallback if DAI cannot be performed (no DHCP server reference)
        self.router_logger.log_message(
            f"[ARP][INSPECT] ⚠️ No DHCP server reference. Permitting ARP from {sender_ip} on untrusted port {inbound_iface.split('_')[-1]}.")
        return True

    def resolve(self, ip_address: str, iface: str) -> str | None:
        """
        Resolves an IP address to a MAC address using static entries, cache, a temporary lease,
        or a custom ARP request. Caches the result if successful.
        """
        if self.sniffer is not None:
            ip_address = ip_address.strip()
            now = time.time()

            if ipaddress.ip_address(ip_address).is_loopback:
                self.router_logger.log_message(f"[ARP] Local delivery: Loopback IP {ip_address}. No ARP needed.")
                return None

            # --- Static ARP entries ---
            if ip_address in self._static_arp_entries:
                mac = self._static_arp_entries[ip_address]
                with self._arp_cache_lock:
                    cached_entry = self._arp_cache.get(ip_address)
                    if not cached_entry or cached_entry[0].lower() != mac.lower():
                        self._arp_cache[ip_address] = (mac, now)
                        self.router_logger.log_message(f"[ARP] 🧷 Cached static ARP entry: {ip_address} → {mac}")
                return mac

            # --- Dynamic ARP cache ---
            with self._arp_cache_lock:
                cached_entry = self._arp_cache.get(ip_address)
                if cached_entry:
                    mac, timestamp = cached_entry
                    if now - timestamp < self.CACHE_TIMEOUT:
                        self.router_logger.log_message(f"[ARP] ⚡ Cache hit for {ip_address} → {mac}")
                        return mac
                    self.router_logger.log_message(f"[ARP] 🕓 Stale cache entry for {ip_address}. Re-resolving...")
                else:
                    self.router_logger.log_message(f"[ARP] 🛰️ Cache miss for {ip_address}. Resolving...")

            # --- NEW: Check for an active temporary lease ---

            lease_info = self._temp_arp_leases.get(ip_address)
            if lease_info and now < lease_info["lease_end"]:
                our_mac = get_if_hwaddr(iface)
                if our_mac:
                    self.router_logger.log_message(
                        f"[ARP] 🧪 Active temporary ARP lease for {ip_address}, using router's MAC: {our_mac}."
                    )
                    return our_mac
                else:
                    self.router_logger.log_message(
                        f"[ARP] ❌ Failed to get router MAC for temporary lease on {iface}."
                    )

            # --- Custom ARP request as a final fallback ---
            resolved_mac = self.send_custom_arp_request(ip_address)

            if resolved_mac:
                with self._arp_cache_lock:
                    self._arp_cache[ip_address] = (resolved_mac, now)
                self.router_logger.log_message(f"[ARP] ✅ Resolved {ip_address} → {resolved_mac}")
                return resolved_mac
            else:
                self.router_logger.log_message(f"[ARP] ❌ Resolve failed {ip_address}")
                return None
        return None

    def get_mac(self,
                target_ip: str,
                iface: str | None = None,
                timeout: int = 2,
                prefer_cache: bool = True,
                allow_active_probe: bool = True) -> str | None:
        """
        Best-effort MAC resolver for an IPv4 address.

        Resolution order:
          1) Static ARP entries
          2) Fresh ARP cache (if prefer_cache=True)
          3) DHCP server bindings (IN/OUT)
          4) Temporary ARP lease (returns our interface MAC)
          5) OS ARP cache (platform arp -a parsing)
          6) Active ARP who-has probe (if allow_active_probe=True)
          7) Scapy getmacbyip() fallback

        On success, caches MAC with timestamp. Returns None if unresolved.
        """
        try:
            ip = str(ipaddress.ip_address(str(target_ip).strip()))
            if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                self.router_logger.log_message(f"[ARP] ⚠️ get_mac: {ip} is not IPv4.")
                return None



            now = time.time()

            # 1) static ARP
            if ip in self._static_arp_entries:
                mac = self._static_arp_entries[ip]
                with self._arp_cache_lock:
                    self._arp_cache[ip] = (mac, now)
                self.router_logger.log_message(f"[ARP] 🧷 get_mac: static {ip} → {mac}")
                return mac

            # 2) warm cache
            if prefer_cache:
                with self._arp_cache_lock:
                    entry = self._arp_cache.get(ip)

                if entry:
                    mac, ts = entry
                    age = now - ts

                    if age < self.CACHE_TIMEOUT:
                        # --- rate limit cache hits to 5 per 30s per IP ---
                        hits = self._cache_hit_table[ip]
                        hits.append(now)
                        # purge old timestamps
                        while hits and now - hits[0] > 30:
                            hits.popleft()

                        if len(hits) <= 5:
                            self.router_logger.log_message(f"[ARP] ⚡ get_mac: cache hit {ip} → {mac}")
                        return mac
                    else:
                        self.router_logger.log_message(
                            f"[ARP] 🕓 get_mac: cache entry for {ip} expired ({int(age)}s old), refreshing."
                        )

            # 3) DHCP bindings (either server)
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

            # 4) temporary ARP lease (returns our iface MAC so we can respond)
            lease = self._temp_arp_leases.get(ip)
            if lease and now < lease.get("lease_end", 0):
                use_iface = iface or (
                    self.outbound_load_balancer.get_best_interface() if self.outbound_load_balancer else None)
                try:
                    our_mac = get_if_hwaddr(use_iface) if use_iface else None
                except Exception:
                    our_mac = None
                if our_mac:
                    with self._arp_cache_lock:
                        self._arp_cache[ip] = (our_mac, now)
                    self.router_logger.log_message(f"[ARP] 🧪 get_mac: temp lease active for {ip}, returning {our_mac}")
                    return our_mac

            # 5) OS ARP cache
            mac = self.fallback_mac_from_os_cache(ip)
            if mac:
                with self._arp_cache_lock:
                    self._arp_cache[ip] = (mac, now)
                self.router_logger.log_message(f"[ARP] 🧭 get_mac: OS cache {ip} → {mac}")
                return mac

            # 6) active probe (ARP who-has)
            if allow_active_probe:
                use_iface = iface or (
                    self.outbound_load_balancer.get_best_interface() if self.outbound_load_balancer else None)
                mac = self.send_custom_arp_request(ip, iface=use_iface, timeout=timeout)
                if mac:
                    with self._arp_cache_lock:
                        self._arp_cache[ip] = (mac, now)
                    self.router_logger.log_message(f"[ARP] 📡 get_mac: active probe {ip} → {mac}")
                    return mac

            # 7) scapy fallback
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
        """
        Sends a gratuitous ARP for the given IP and MAC on the specified interface.
        This announces the router's presence or IP change to the network.
        """
        self.router_logger.log_message(
            f"[ARP] Sending Gratuitous ARP for {ip_address} ({mac_address}) on {iface.split('_')[-1]}")
        grat_arp = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
                   ARP(op="who-has", psrc=ip_address, pdst=ip_address, hwsrc=mac_address)
        try:
            # Using sendp to send the packet directly on the specified interface
            self.sniffer.sendp(grat_arp, iface=iface, verbose=0)
            self.router_logger.log_message(f"[ARP] Successfully sent Gratuitous ARP on {iface.split('_')[-1]}.")
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Failed to send Gratuitous ARP on {iface.split('_')[-1]}: {e}")

    def send_custom_arp_request(self,target_ip: str, iface: str = None, timeout: int = 2) -> str | None:
        """
        Sends a custom ARP request to the target IP and waits for a reply.
        Only sends ARP if the target is a valid unicast IPv4 address.

        Args:
            target_ip (str): The IP address to resolve.
            iface (str): The full interface name to send the ARP request on.
            timeout (int): How long to wait for a reply (default 2 seconds).

        Returns:
            str | None: The resolved MAC address, or None if no reply or invalid target.
        """
        try:
            ip = ipaddress.ip_address(target_ip)
            if not isinstance(ip, ipaddress.IPv4Address):
                self.router_logger.log_message(f"[ARP] ⚠️ Skipping non-IPv4 address: {target_ip}")
                return None

            if (
                    ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_reserved
                    or ip.is_link_local or ip == ipaddress.IPv4Address("255.255.255.255")
            ):
                self.router_logger.log_message(f"[ARP] ⚠️ Skipping non-unicast IP: {target_ip}")
                return None


            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
            if iface is None:
                iface = self.outbound_load_balancer.get_best_interface()
            self.router_logger.log_message(
                f"[ARP] 📡 Sending direct ARP request for {target_ip} on {iface}"
            )
            packet = self.sniffer.sr2(arp_request, iface=iface, timeout=timeout, verbose=False)

            if packet:
                resolved_mac = packet.hwsrc
                self.router_logger.log_message(f"[ARP] 🎯 Directly resolved {target_ip} → {resolved_mac}")
                return resolved_mac
            else:
                self.router_logger.log_message(f"[ARP] ⛔ No response to ARP for {target_ip} on {iface.split('_')[-1]} getting mac address with function.")
                resolved_mac = getmacbyip(target_ip)
                return resolved_mac

        except ValueError:
            self.router_logger.log_message(f"[ARP] ⚠️ Invalid IP address format: {target_ip}")
            return None
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Error sending custom ARP for {target_ip}: {e}")
            return None

    def learn_arp_response(self, pkt: Packet):
        """
        Learns and caches ARP is-at responses (i.e., ARP replies).
        Only updates the cache if the new MAC is different or missing.
        Supports learning from active temporary ARP leases.
        """
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return  # Not an ARP reply (is-at)

        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        iface = pkt.sniffed_on if hasattr(pkt, "sniffed_on") else "Unknown"
        now = time.time()

        # --- Check for static ARP override ---
        static_mac = self._static_arp_entries.get(ip)
        if static_mac and static_mac.lower() != mac.lower():
            self.router_logger.log_message(
                f"[ARP] 🚫 Ignoring ARP response for {ip}: MAC {mac} conflicts with static entry {static_mac}."
            )
            return

        # --- Check if a temporary lease exists and is active ---
        lease_info = self._temp_arp_leases.get(ip)
        if lease_info and now > lease_info["lease_end"]:
            self.router_logger.log_message(
                f"[ARP][LEASE] ⏳ Lease for {ip} expired. Not accepting ARP response from {mac}."
            )
            return

        with self._arp_cache_lock:
            existing_entry = self._arp_cache.get(ip)
            if existing_entry:
                old_mac, _ = existing_entry
                if old_mac.lower() != mac.lower():
                    self.router_logger.log_message(
                        f"[ARP] ⚠️ MAC change detected for {ip}: {old_mac} → {mac} on {iface.split('_')[-1]}"
                    )
            else:
                self.router_logger.log_message(
                    f"[ARP] 🧠 Learned new ARP: {ip} → {mac} on {iface.split('_')[-1]}"
                )

            self._arp_cache[ip] = (mac, now)

            if lease_info:
                self.router_logger.log_message(
                    f"[ARP][LEASE] ✅ ARP response accepted for {ip} under active temporary lease."
                )

    def reply_to_arp_request(self, request_pkt: Packet, iface: str):
        """
        Replies to an ARP who-has request if the router owns the target IP (via static or temporary ARP lease).
        Automatically assigns a temporary lease to unknown IPs if no static entry exists.

        Args:
            request_pkt (Packet): The received ARP request packet.
            iface (str): The interface on which the request was received.
        """
        try:
            if not request_pkt.haslayer(ARP) or request_pkt[ARP].op != 1:
                return  # Not an ARP request

            target_ip = request_pkt[ARP].pdst
            requester_mac = request_pkt[ARP].hwsrc
            requester_ip = request_pkt[ARP].psrc
            now = time.time()

            # --- Case 1: Static entry
            if target_ip in self._static_arp_entries:
                our_mac = self._static_arp_entries[target_ip]

            # --- Case 2: Temporary lease exists and is valid
            elif target_ip in self._temp_arp_leases:
                lease_info = self._temp_arp_leases[target_ip]
                if lease_info["replies_sent"] >= self.MAX_REPLIES_PER_LEASE and now < lease_info["lease_end"]:
                    self.router_logger.log_message(
                        f"[ARP][LEASE] ❌ Too many replies for {target_ip}")
                    return
                if now < lease_info["lease_end"]:
                    our_mac = get_if_hwaddr(iface)
                    if not our_mac:
                        self.router_logger.log_message(
                            f"[ARP][LEASE] ❌ Failed to get interface MAC for temp lease to {target_ip}")
                        return
                    self.router_logger.log_message(
                        f"[ARP][LEASE] 🔓 Active lease: replying to ARP for {target_ip} with {our_mac}."
                    )
                    lease_info["replies_sent"] += 1
                elif now >= lease_info["cooldown_end"]:
                    del self._temp_arp_leases[target_ip]
                    self.router_logger.log_message(
                        f"[ARP][LEASE] 🔒 Lease and cooldown expired for {target_ip}. Strict mode restored.")
                    return
                else:
                    self.router_logger.log_message(
                        f"[ARP][LEASE] 🛑 Cooldown active for {target_ip}. Not replying to ARP.")
                    return

            # --- Case 3: No entry at all — assign temporary lease automatically
            else:
                cooldown_end = self._temp_arp_leases.get(target_ip, {}).get("cooldown_end", 0)
                if now < cooldown_end:
                    self.router_logger.log_message(
                        f"[ARP][LEASE]⛔ Cannot auto-grant lease for {target_ip}: cooldown active.")
                    return

                lease_granted = self.allow_temp_arp_lease(target_ip, lease_duration=120, cooldown=30)
                if not lease_granted:
                    return  # Cooldown active or error

                our_mac = get_if_hwaddr(iface)
                if not our_mac:
                    self.router_logger.log_message(
                        f"[ARP][LEASE] ❌ Failed to get interface MAC for new temp lease to {target_ip}")
                    return

                self.router_logger.log_message(
                    f"[ARP][LEASE] ⚡ Auto-assigned temporary lease and replying to ARP for {target_ip} with {our_mac}."
                )

            # --- Send the reply
            arp_reply = Ether(dst=requester_mac, src=our_mac) / ARP(
                op=2,
                hwsrc=our_mac,
                psrc=target_ip,
                hwdst=requester_mac,
                pdst=requester_ip,
            )

            self.sniffer.sendp(arp_reply, iface=iface, verbose=False)
            self.router_logger.log_message(
                f"[ARP] 📢 Replied to ARP: {target_ip} is-at {our_mac} → sent to {requester_mac} on {iface.split('_')[-1]}")
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Failed to reply to ARP on {iface.split('_')[-1]}: {e}")

    def allow_temp_arp_lease(self, ip_address: str, lease_duration: int = 30, cooldown: int = 60):
        """
        Temporarily allows ARP replies for a specific IP even if it's not in the static table.
        After lease ends, a cooldown is enforced where it cannot be re-leased.

        Args:
            ip_address (str): The IP to allow temporarily.
            lease_duration (int): How long to allow ARP replies (seconds).
            cooldown (int): Cooldown after lease expires (seconds).
        """
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

    def fallback_mac_from_os_cache(self, ip: str) -> str | None:
        try:
            output = subprocess.check_output(["arp", "-a"], text=True)
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]  # MAC address
            self.router_logger.log_message(f"[ARP] ✅ MAC for {ip} found in OS ARP cache: {parts[1]}")
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ⚠️ ARP fallback cache check failed: {e}")
        return None
    def get_cache_view(self) -> dict:
        """Returns a copy of the current ARP cache for inspection."""
        with self._arp_cache_lock:
            return self._arp_cache.copy()

    def clear_cache(self):
        """Clears all entries from the ARP cache."""
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

        # --- DHCPv6 ---
        self.dhcp6_prefix = ipaddress.IPv6Network(dhcp6_prefix) if dhcp6_prefix else None
        self.dhcp6_relay_target_ip = dhcp6_relay_target_ip

        self._stop_event = threading.Event()
        self._cleanup_thread = None

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
            if pkt.haslayer(DHCP6):
                if dport == 547 and sport == 546:
                    return "v6", "client"
                if sport == 547 and dport == 546:
                    return "v6", "server"
                return "v6", "other"
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
        router_in_ipv6 = in_cfg.get("ipv6_addr")
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
                self.packet_writer.queue_packet(relay_packet, inbound_iface)
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
                self.packet_writer.queue_packet(reply, inbound_iface)
                self.logger.log_message(f"[DHCP] 📝 Offer {assigned_ip} → {client_mac} (iface={inbound_iface})")
                return True

            # ---- REQUEST (includes SELECTING/INIT-REBOOT/RENEW/REBIND)
            if msg_type_norm == 3:
                opt54 = self._get_server_id_opt54(dhcp_layer)  # server the client has chosen (if present)

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
                    self.packet_writer.queue_packet(reply, inbound_iface)
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
                    self.packet_writer.queue_packet(reply, inbound_iface)
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
                self.packet_writer.queue_packet(reply, inbound_iface)
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
                self.packet_writer.queue_packet(reply, inbound_iface)
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
            if not self.dhcp6_prefix and not self.dhcp6_relay_target_ip:
                self.logger.log_message("[DHCP] DHCPv6 disabled; ignoring.")
                return True

            if direction != "client":
                # observe but do not act for v6 server→client
                src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "(no-ether)"
                self.logger.log_message(f"[DHCP] v6 server→client observed from {src_mac}; skipping.")
                return True

            dhcp6 = pkt[DHCP6]
            msgtype = int(getattr(dhcp6, "msgtype", getattr(dhcp6, "msgtype", 0)))

            # extract DUID if present
            client_duid = None
            for opt in getattr(dhcp6, "options", []):
                if isinstance(opt, tuple) and opt[0] == 1:
                    client_duid = opt[1]
                    break
                if hasattr(opt, "otype") and opt.otype == 1:
                    client_duid = opt.duid
                    break
            if not client_duid:
                self.logger.log_message("[DHCP] v6 missing client DUID; ignoring.")
                return True

            if self.dhcp6_relay_target_ip:
                if not router_in_ipv6:
                    self.logger.log_message("[DHCP] v6 relay enabled but missing router IPv6; skipping relay.")
                    return True
                self.logger.log_message(f"[DHCP] Relaying v6 to {self.dhcp6_relay_target_ip} (iface={inbound_iface}).")
                relay = DHCP6_RelayForward(linkaddr=router_in_ipv6,
                                           peeraddr=pkt[IP].src if pkt.haslayer(IP) else None,
                                           msg=pkt[DHCP6])
                self.packet_writer.queue_packet(relay, inbound_iface)
                return True

            if not router_in_ipv6:
                self.logger.log_message("[DHCP] v6 missing router IPv6; cannot serve.")
                return True

            if msgtype == 1:  # SOLICIT
                opts = [
                    # Stateless example: advertise prefix and DNS
                    ("iana", b""),  # placeholder if your stack expects an IA option
                    # If using scapy classes:
                    # DHCP6OptIAPrefix(prefix=str(self.dhcp6_prefix), plen=self.dhcp6_prefix.prefixlen, preferred_lifetime=3600),
                    # DHCP6OptDNSServers(dnsservers=[str(router_in_ipv6)]),
                    "end"
                ]
                advertise = (IP(src=str(router_in_ipv6), dst="ff02::1:2") /
                             UDP(sport=547, dport=546) /
                             DHCP6_Advertise(trid=dhcp6.trid, options=opts))
                self.packet_writer.queue_packet(advertise, inbound_iface)
                self.logger.log_message(f"[DHCP] v6 ADVERTISE → DUID {getattr(client_duid, 'hex', lambda: b'')()} (iface={inbound_iface})")
                return True

            if msgtype == 3:  # REQUEST
                opts = [
                    ("iana", b""),
                    "end"
                ]
                reply = (IP(src=str(router_in_ipv6), dst="ff02::1:2") /
                         UDP(sport=547, dport=546) /
                         DHCP6_Reply(trid=dhcp6.trid, options=opts))
                self.packet_writer.queue_packet(reply, inbound_iface)
                self.logger.log_message(f"[DHCP] v6 REPLY → DUID {getattr(client_duid, 'hex', lambda: b'')()} (iface={inbound_iface})")
                return True

            self.logger.log_message(f"[DHCP] v6 msgtype {msgtype} not handled; ignoring.")
            return True

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
                    self.logger.log_message(
                        f"[OutboundLB] Selected interface {candidate_iface.split('_')[-1]} for flow {ip_layer.src} -> {ip_layer.dst}.")
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
