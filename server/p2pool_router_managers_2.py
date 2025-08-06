import json
import socket
import struct
import subprocess
from collections import defaultdict
from functools import reduce
from typing import Optional, List, Any
import ipaddress
import threading
import time

import psutil
from scapy.arch import get_if_hwaddr
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6, DHCP6_RelayForward, DHCP6OptIAPrefix, DHCP6OptDNSServers, DHCP6_Advertise, DHCP6_Reply
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import TCP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether, getmacbyip
from scapy.layers.rip import RIPEntry, RIP
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSFinished
from scapy.layers.tls.record import TLS
from scapy.packet import Packet, Raw
from scapy.fields import ByteField, ShortField, IntField, IPField, PacketListField, IP6Field
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict, Literal



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


class StratumManager:
    """
    Monitors Stratum mining traffic (JSON-RPC over TCP).
    Extracts and tracks miner sessions, job info, and share submissions.
    """

    def __init__(self, router_logger):
        self.logger = router_logger
        self.sessions: Dict[str, Dict[str, Any]] = {}  # key = src_ip:src_port
        self._lock = threading.Lock()
        self.logger.log_message("[Stratum] Initialized.")

    def handle_packet(self, packet, iface: str) -> bool:
        """Handle a TCP packet and try to extract Stratum messages."""
        if not packet.haslayer(TCP):
            return False

        tcp = packet[TCP]
        ip = packet.payload

        # Stratum usually runs on TCP port 3333 or 4444
        if tcp.sport not in (3333, 4444) and tcp.dport not in (3333, 4444):
            return False

        try:
            if hasattr(tcp, "payload") and bytes(tcp.payload):
                raw_data = bytes(tcp.payload)
                session_id = f"{ip.src}:{tcp.sport}" if tcp.sport in (3333, 4444) else f"{ip.dst}:{tcp.dport}"
                self._process_stratum_payload(session_id, raw_data, iface)
                return True
        except Exception as e:
            self.logger.log_message(f"[Stratum] ⚠️ Error processing Stratum packet: {e}")
            return False

    def _process_stratum_payload(self, session_id: str, raw_data: bytes, iface: str):
        """Parses and logs JSON-RPC messages from the raw TCP payload."""
        try:
            text = raw_data.decode("utf-8", errors="ignore")
            messages = text.split("\n")

            for msg in messages:
                msg = msg.strip()
                if not msg:
                    continue

                data = json.loads(msg)
                method = data.get("method")
                params = data.get("params", [])

                if method == "mining.subscribe":
                    self._track_subscribe(session_id, params)
                elif method == "mining.authorize":
                    self._track_authorize(session_id, params)
                elif method == "mining.set_difficulty":
                    self._track_difficulty(session_id, params)
                elif method == "mining.notify":
                    self._track_job_notify(session_id, params)
                elif method == "mining.submit":
                    self._track_submit(session_id, params)
                else:
                    self.logger.log_message(f"[Stratum] 📦 {session_id} sent method: {method}")
        except json.JSONDecodeError:
            self.logger.log_message("[Stratum] ❌ Failed to decode JSON from payload.")
        except Exception as e:
            self.logger.log_message(f"[Stratum] ❌ Unexpected error: {e}")

    def _track_subscribe(self, session_id: str, params):
        self.logger.log_message(f"[Stratum] 🤝 {session_id} sent subscribe: {params}")
        with self._lock:
            self.sessions.setdefault(session_id, {})['subscribed'] = time.time()

    def _track_authorize(self, session_id: str, params):
        username = params[0] if params else "unknown"
        self.logger.log_message(f"[Stratum] 🧑‍💻 {session_id} authorized as {username}")
        with self._lock:
            self.sessions.setdefault(session_id, {})['username'] = username

    def _track_difficulty(self, session_id: str, params):
        difficulty = params[0] if params else "?"
        self.logger.log_message(f"[Stratum] 🧱 {session_id} set difficulty: {difficulty}")
        with self._lock:
            self.sessions.setdefault(session_id, {})['difficulty'] = difficulty

    def _track_job_notify(self, session_id: str, params):
        job_id = params[0] if params else "?"
        self.logger.log_message(f"[Stratum] 🚧 {session_id} received job ID: {job_id}")
        with self._lock:
            self.sessions.setdefault(session_id, {})['last_job'] = job_id

    def _track_submit(self, session_id: str, params):
        worker = params[0] if params else "unknown"
        self.logger.log_message(f"[Stratum] ⛏️ {session_id} submitted share from worker: {worker}")
        with self._lock:
            self.sessions.setdefault(session_id, {})['last_submit'] = time.time()

    def get_active_sessions(self) -> Dict[str, Any]:
        """Returns a snapshot of tracked miner sessions."""
        with self._lock:
            return dict(self.sessions)
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
    QUERY_COOLDOWN_SECONDS = 10  # Don't forward the same query from the same IP more than once every 10s

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
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished"
}
def _get_canonical_session_key(ip1: str, port1: int, ip2: str, port2: int) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """Returns a canonical session key that is order-independent."""
    # FIX: Sort the tuples to ensure the key is always the same
    return tuple(sorted([(ip1, port1), (ip2, port2)]))

class HandshakeManager:
    """
    Tracks TCP 3-way handshakes and connection teardowns based on observed packets.
    It can be initialized with references to network managers (ARP, NAT, RIP)
    to provide broader network context, though its core function remains passive
    TCP state tracking.
    """

    def __init__(self, router_logger,
                 arp_manager,
                 nat_manager,
                 rip_manager,
                 packet_writer,
                 timeout_half_open: int = 60, timeout_established: int = 300):
        self.logger = router_logger
        self._sessions: Dict[
            Tuple[Tuple[str, int], Tuple[str, int]], Tuple[HandshakeState, float, str, int, str, int]] = {}
        self._lock = threading.Lock()
        self.timeout_half_open = timeout_half_open
        self.timeout_established = timeout_established
        self._stop_event = threading.Event()
        self._tls_streams = {}
        self.arp_manager = arp_manager
        self.nat_manager = nat_manager
        self.rip_manager = rip_manager
        self.packet_writer = packet_writer
        self.ban_duration = 300
        self.rate_limit_threshold = 20
        self.rate_limit_period = 60
        self._ban_list: Dict[str, float] = {}  # Maps IP -> ban_expiry_timestamp
        self._connection_rate_tracker: Dict[str, List[float]] = defaultdict(list)
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="HandshakeCleanup")
        self._cleanup_thread.start()
        self.logger.log_message("[Handshake] Manager initialized (passive mode, with network context).")

    def start(self):
        if not (self._cleanup_thread and self._cleanup_thread.is_alive()):
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="HandshakeCleanup")
            self._cleanup_thread.start()
            self.logger.log_message("[Handshake] Cleanup thread started.")
        else:
            self.logger.log_message("[Handshake] Manager already running.")

    def stop(self):
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.logger.log_message("[Handshake] Manager stopped.")

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
                    # Remove the IP from the ban list, effectively unbanning it.
                    del self._ban_list[ip]

                    # If a probe counter exists, reset it for the newly unbanned IP.
                    if hasattr(self, '_probe_counts'):
                        self._probe_counts.pop(ip, None)

                    self.logger.log_message(f"[Handshake][BAN] ✅ Ban expired for {ip}. IP is no longer blocked.")

    def _check_and_apply_rate_limit(self, ip: str, now: float):
        """Checks the connection rate for an IP and bans it if the limit is exceeded."""
        timestamps = self._connection_rate_tracker[ip]
        timestamps.append(now)

        # Keep only timestamps within the defined period
        relevant_timestamps = [ts for ts in timestamps if now - ts <= self.rate_limit_period]
        self._connection_rate_tracker[ip] = relevant_timestamps

        if len(relevant_timestamps) > self.rate_limit_threshold:
            self.logger.log_message(
                f"[Handshake][BAN] 🚫 IP {ip} banned for {self.ban_duration}s. Reason: Exceeded connection rate limit (possible scan)."
            )
            self._ban_list[ip] = now + self.ban_duration
            # Clear the tracker for this IP once banned
            del self._connection_rate_tracker[ip]
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

        if original_dst_ip == self.nat_manager.public_ip:
            nat_reversed_dst_tuple = self.nat_manager.get_internal_from_external(original_dst_port, original_src_ip )
            if nat_reversed_dst_tuple:
                original_dst_ip, original_dst_port = nat_reversed_dst_tuple
                self.logger.log_message(
                    f"[Handshake] NAT reverse applied (DST): {ip_layer.dst}:{tcp_layer.dport} -> {original_dst_ip}:{original_dst_port}"
                )

        canonical_key = _get_canonical_session_key(original_src_ip, original_src_port, original_dst_ip, original_dst_port)

        with self._lock:
            current_session_data = self._sessions.get(canonical_key)
            session_state = current_session_data[0] if current_session_data else None

            if session_state is None:
                stored_original_src_ip = original_src_ip
                stored_original_src_port = original_src_port
                stored_original_dst_ip = original_dst_ip
                stored_original_dst_port = original_dst_port
            else:
                _, _, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port = current_session_data

            # --- TCP Handshake Logic ---
            if flags == 0x02: # SYN
                if session_state is None:
                    self._sessions[canonical_key] = ("SYN_SENT", now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔓 SYN from {original_src_ip}:{original_src_port} to {original_dst_ip}:{original_dst_port} on {inbound_iface}"
                    )
                elif session_state == "SYN_SENT":
                    self._sessions[canonical_key] = (session_state, now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔁 SYN retransmission from {original_src_ip}:{original_src_port} on {inbound_iface}"
                    )
                return False

            elif flags == 0x12: # SYN+ACK
                if session_state == "SYN_SENT":
                    self._sessions[canonical_key] = ("SYN_ACK_RECEIVED", now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔐 SYN-ACK from {original_src_ip}:{original_src_port} to {original_dst_ip}:{original_dst_port} "
                        f"for session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                    )
                elif session_state == "SYN_ACK_RECEIVED":
                    self._sessions[canonical_key] = (session_state, now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔁 SYN-ACK retransmission from {original_src_ip}:{original_src_port} on {inbound_iface}"
                    )
                else:
                    self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ✅ Inferred ESTABLISHED session from ACK ACK: {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}")
                return False

            elif flags == 0x10: # ACK
                if session_state == "SYN_ACK_RECEIVED":
                    self._sessions[canonical_key] = ("ESTABLISHED", now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ✅ Connection ESTABLISHED: {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                    )
                elif session_state == "ESTABLISHED":
                    self._sessions[canonical_key] = ("ESTABLISHED", now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                    # --- TLS Handling (Corrected as discussed) ---
                    if pkt.haslayer(Raw):
                        raw_bytes = bytes(pkt[Raw])
                        if len(raw_bytes) >= 3:
                            content_type = raw_bytes[0]
                            version_major = raw_bytes[1]
                            version_minor = raw_bytes[2]

                            # TLS/SSL record types and versions
                            if content_type in {20, 21, 22, 23} and version_major == 3:
                                tls_version_map = {
                                    0: "SSL 3.0",
                                    1: "TLS 1.0",
                                    2: "TLS 1.1",
                                    3: "TLS 1.2",
                                    4: "TLS 1.3",
                                }
                                tls_version = tls_version_map.get(version_minor, f"TLS {version_major}.{version_minor}")

                                # Try to estimate the TLS record length (3 or 5 bytes header)
                                try:
                                    if len(raw_bytes) >= 5:
                                        record_len = struct.unpack("!H", raw_bytes[3:5])[0]
                                    else:
                                        record_len = "unknown"
                                except Exception:
                                    record_len = "unknown"

                                msg_type_str = {
                                    20: "ChangeCipherSpec",
                                    21: "Alert",
                                    22: "Handshake",
                                    23: "Application Data"
                                }.get(content_type, f"Unknown({content_type})")

                                self.logger.log_message(
                                    f"[SSL] 🔍 TLS record: type={content_type} ({msg_type_str}), version={tls_version}, length={record_len} "
                                    f"in session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                )

                                # For Application Data, we know it's encrypted — confirm session is truly live
                                if content_type == 23:
                                    session_data = self._sessions.get(canonical_key)

                                    # 2. The session_info dictionary is built by unpacking that stored data
                                    session_info = {
                                        "src_ip": session_data[2],
                                        "src_port": session_data[3],
                                        "dst_ip": session_data[4],
                                        "dst_port": session_data[5],
                                        "iface": inbound_iface
                                    }
                                    self._forward_tls_application_data(raw_bytes, pkt, session_info, canonical_key)

                                elif content_type == 22:
                                    try:
                                        tls_pkt = TLS(raw_bytes)
                                        tls_handshake = tls_pkt.payload
                                        if hasattr(tls_handshake, 'msgtype'):
                                            handshake_type_id = tls_handshake.msgtype
                                            handshake_name = TLS_HANDSHAKE_TYPES.get(handshake_type_id, f"Unknown({handshake_type_id})")
                                            if isinstance(tls_handshake, TLSClientHello):
                                                sni = None
                                                if hasattr(tls_handshake, "ext") and tls_handshake.ext:
                                                    for ext in tls_handshake.ext:
                                                        if hasattr(ext, "servernames") and ext.servernames:
                                                            sni = ext.servernames[0].servername
                                                self.logger.log_message(
                                                    f"[TLS] 🛡 ClientHello (v{tls_handshake.version}, SNI={sni or 'N/A'}, "
                                                    f"ciphers={tls_handshake.ciphers}) "
                                                    f"in session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                                )
                                            elif isinstance(tls_handshake, TLSServerHello):
                                                self.logger.log_message(
                                                    f"[TLS] 🛡 ServerHello (v{tls_handshake.version}, cipher={tls_handshake.cipher}) "
                                                    f"in session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                                )
                                            elif isinstance(tls_handshake, TLSFinished):
                                                self.logger.log_message(
                                                    f"[TLS] 🛡 Finished handshake message in session "
                                                    f"{stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                                )
                                            else:
                                                self.logger.log_message(
                                                    f"[TLS] 🛡 {handshake_name} (type={handshake_type_id}) "
                                                    f"in session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                                )
                                        else:
                                            self.logger.log_message(
                                                f"[TLS] ⚠️ Handshake record present but no msgtype field found (possible fragmentation)."
                                            )
                                    except Exception as e:
                                        self.logger.log_message(f"[TLS] ⚠️ Failed to dissect handshake: {e}")
                                elif content_type == 21:
                                    alert_level = raw_bytes[5] if len(raw_bytes) > 5 else "?"
                                    alert_description = raw_bytes[6] if len(raw_bytes) > 6 else "?"
                                    self.logger.log_message(
                                        f"[SSL] ⚠️ Alert record (level={alert_level}, description={alert_description}) detected."
                                    )
                            elif content_type & 0x80 and version_major in {2, 3}:  # SSLv2 format check
                                self.logger.log_message(
                                    f"[SSL] ⚠️ SSLv2 ClientHello or legacy record format detected from {stored_original_src_ip}:{stored_original_src_port} on {inbound_iface}"
                                )

                            elif version_major == 3 and version_minor == 0:
                                self.logger.log_message(
                                    f"[SSL] ⚠️ SSLv3 record detected from {stored_original_src_ip}:{stored_original_src_port} on {inbound_iface}"
                                )
                    if pkt.haslayer(TLS):
                        tls_record = pkt[TLS]
                        # Check if it's a Handshake content type (22)
                        # Scapy automatically dissects TLSHandshake as the payload of TLS record if type is 22
                        if tls_record.type == 22: # TLS Handshake content type
                            # The payload of a TLS record with type 22 (Handshake) IS the TLSHandshake message.
                            # So, you can directly access the payload, which should be a TLSHandshake object
                            # or one of its subclasses (ClientHello, ServerHello, etc.)
                            handshake_msg = tls_record.payload
                            if hasattr(handshake_msg, 'msgtype'): # Ensure it's a handshake message with msgtype
                                handshake_type_id = handshake_msg.msgtype # Get the numeric type ID
                                tls_msg_name = TLS_HANDSHAKE_TYPES.get(handshake_type_id, f"Unknown({handshake_type_id})")

                                if isinstance(handshake_msg, TLSClientHello):
                                    self.logger.log_message(
                                        f"[TLS] 🛡 ClientHello (v{handshake_msg.version}) seen in session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                    )
                                elif isinstance(handshake_msg, TLSServerHello):
                                     self.logger.log_message(
                                        f"[TLS] 🛡 ServerHello (v{handshake_msg.version}, cipher={handshake_msg.cipher}) seen in session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                    )
                                elif isinstance(handshake_msg, TLSFinished):
                                    self.logger.log_message(
                                        f"[TLS] 🛡 Finished handshake message seen in session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                    )
                                else:
                                    self.logger.log_message(
                                        f"[TLS] 🛡 {tls_msg_name} (type={handshake_type_id}) seen in session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                                    )
                            else: # This should ideally not happen if type is 22 and Scapy dissected correctly
                                self.logger.log_message(
                                    f"[TLS] ⚠️ TLS Record (Type: {tls_record.type}) - Payload not recognized as a Handshake message (missing msgtype). on {inbound_iface}"
                                )
                        else: # Not a TLS handshake record (e.g., TLS data, Alert, ChangeCipherSpec)
                            self.logger.log_message(
                                f"[TLS] ℹ️ TLS Record (Type: {tls_record.type}) - Not a Handshake message. on {inbound_iface}"
                            )
                    # --- END TLS Handling ---

                elif session_state == "CLOSING":
                    self._sessions[canonical_key] = ("CLOSED", now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ❎ Connection CLOSED (ACK after FIN): {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                    )
                    del self._sessions[canonical_key]
                else:
                    self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ✅ Inferred ESTABLISHED session from ACK: {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}")
                return False

            elif flags & 0x01: # FIN
                if session_state == "ESTABLISHED":
                    self._sessions[canonical_key] = ("CLOSING", now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔻 CLOSING initiated by {original_src_ip}:{original_src_port} on {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                    )
                    self._check_and_apply_rate_limit(original_src_ip, now)

                elif session_state == "CLOSING":
                    self._sessions[canonical_key] = ("CLOSED", now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ❎ Connection CLOSED (Second FIN): {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port} on {inbound_iface}"
                    )
                    del self._sessions[canonical_key]
                else:
                    self.logger.log_message(
                        f"[Handshake] ⚠️ Unexpected FIN from {original_src_ip}:{original_src_port} to {original_dst_ip}:{original_dst_port} "
                        f"in state {session_state} on {inbound_iface}"
                    )
                return False

            elif flags & 0x04: # RST
                if current_session_data:
                    self.logger.log_message(
                        f"[Handshake] ❌ RST received on session {stored_original_src_ip}:{stored_original_src_port} ↔ {stored_original_dst_ip}:{stored_original_dst_port}. Forcibly closing on {inbound_iface}."
                    )
                    del self._sessions[canonical_key]
                return False

            if current_session_data and session_state == "ESTABLISHED":
                self._sessions[canonical_key] = ("ESTABLISHED", now, stored_original_src_ip, stored_original_src_port, stored_original_dst_ip, stored_original_dst_port)
                return False

        return False

    def normalize_mac(self, mac: str) -> str:
        return mac.replace('-', ':').lower()
    def _forward_tls_application_data(self, data: bytes, original_pkt: Packet, session_info: Dict,
                                      canonical_key: Tuple):
        """
        Reconstructs and queues a TLS Application Data packet for forwarding.
        """
        self.logger.log_message(
            f"[SSL] 🔒 Encrypted Application Data ({len(data)} bytes) detected in session."
        )
        self._tls_streams[canonical_key].append(data)

        try:

            # Build the forwarding packet from scratch to ensure correctness
            forward_pkt = (
                    Ether(
                        dst=self.normalize_mac(original_pkt[Ether].dst),
                        src=self.normalize_mac(original_pkt[Ether].src)
                    ) /
                    IP(src=session_info["src_ip"], dst=session_info["dst_ip"]) /
                    TCP(
                        sport=session_info["src_port"],
                        dport=session_info["dst_port"],
                        flags="PA",  # Push+Ack is typical for application data
                        seq=original_pkt[TCP].seq,
                        ack=original_pkt[TCP].ack,
                        window=original_pkt[TCP].window
                    ) /
                    Raw(load=data)
            )

            self.packet_writer.queue_packet(forward_pkt)
            self.logger.log_message(
                f"[TLS] 🔁 Queued TLS Application Data for forwarding to {session_info['dst']}"
            )

        except Exception as e:
            self.logger.log_message(f"[TLS] ❌ Exception while building forwarding packet: {e}")
class IGMPManager:
    """
    Manages IP multicast group memberships using IGMPv2.
    Monitors IGMP reports and queries, maintains a membership table,
    and sends periodic IGMP queries.
    """

    def __init__(self, router_logger, packet_writer):
        self.router_logger = router_logger
        self.packet_writer = packet_writer  # Will use PacketWriter for sending
        self.IGMP_ALL_HOSTS_GROUP = "224.0.0.1"  # Standard multicast address for all hosts
        self.IGMP_QUERY_INTERVAL = 60  # Send general queries every 60 seconds
        self.IGMP_MEMBERSHIP_TIMEOUT = 260  # Group membership timeout (e.g., Query Interval * 2 + Query Response Interval)

        # _multicast_groups: { (multicast_ip_str, interface_full_name): last_report_timestamp }
        self._multicast_groups = {}
        self._group_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._interfaces_config = {}  # Will be set by PythonRouterManager

        self.router_logger.log_message("[IGMP] Initialized.")

    def set_interfaces_config(self, interfaces_config: dict):
        """Sets the router's interface configuration for use by IGMPManager."""
        self._interfaces_config = interfaces_config

    def handle_packet(self, pkt: Packet, inbound_ifname: str):
        """
        Processes an incoming IGMP or MLD packet.
        Updates the multicast group membership table.
        """
        # Check for IGMP (IPv4)
        if pkt.haslayer(IGMP):
            igmp_layer = pkt[IGMP]
            src_ip = pkt[IP].src
            group_ip = str(igmp_layer.gaddr)

            self.router_logger.log_message(
                f"[IGMP] Received IGMPv2 Type {igmp_layer.type} on {inbound_ifname.split('_')[-1]} from {src_ip} for group {group_ip}")

            with self._group_lock:
                if igmp_layer.type == 0x16:  # IGMPv2 Membership Report
                    key = (group_ip, inbound_ifname)
                    self._multicast_groups[key] = time.time()
                    self.router_logger.log_message(
                        f"[IGMP] ✅ Host {src_ip} joined {group_ip} on {inbound_ifname.split('_')[-1]}.")
                elif igmp_layer.type == 0x17:  # IGMPv2 Leave Group
                    key = (group_ip, inbound_ifname)
                    if key in self._multicast_groups:
                        del self._multicast_groups[key]
                        self.router_logger.log_message(
                            f"[IGMP] 🗑️ Host {src_ip} left {group_ip} on {inbound_ifname.split('_')[-1]}.")
                    else:
                        self.router_logger.log_message(
                            f"[IGMP] Host {src_ip} sent Leave for {group_ip}, but not in table.")

        # NEW: Check for MLD (IPv6)
        elif pkt.haslayer(MLDReport) or pkt.haslayer(MLDDone):
            src_ip = pkt[IPv6].src
            mld_layer = pkt.getlayer(MLDReport) or pkt.getlayer(MLDDone)
            group_ip = str(mld_layer.mcaddr)

            self.router_logger.log_message(
                f"[MLD] Received MLD packet on {inbound_ifname.split('_')[-1]} from {src_ip} for group {group_ip}")

            with self._group_lock:
                if pkt.haslayer(MLDReport):  # Equivalent to Join/Report
                    key = (group_ip, inbound_ifname)
                    self._multicast_groups[key] = time.time()
                    self.router_logger.log_message(
                        f"[MLD] ✅ Host {src_ip} joined {group_ip} on {inbound_ifname.split('_')[-1]}.")
                elif pkt.haslayer(MLDDone):  # Equivalent to Leave
                    key = (group_ip, inbound_ifname)
                    if key in self._multicast_groups:
                        del self._multicast_groups[key]
                        self.router_logger.log_message(
                            f"[MLD] 🗑️ Host {src_ip} left {group_ip} on {inbound_ifname.split('_')[-1]}.")
                    else:
                        self.router_logger.log_message(
                            f"[MLD] Host {src_ip} sent Done for {group_ip}, but not in table.")

    def should_forward_multicast(self, multicast_ip: str, outbound_ifname: str) -> bool:
        """
        Determines if a multicast packet for multicast_ip should be forwarded
        to outbound_ifname.
        """

        if multicast_ip in [self.IGMP_ALL_HOSTS_GROUP, "224.0.0.9"]:  # Always forward all-hosts and RIP multicast
            return True

        with self._group_lock:
            key = (multicast_ip, outbound_ifname)
            if key in self._multicast_groups:
                # Check if the membership has timed out
                if (time.time() - self._multicast_groups[key]) < self.IGMP_MEMBERSHIP_TIMEOUT:
                    return True
                else:
                    self.router_logger.log_message(
                        f"[IGMP] Membership for {multicast_ip} on {outbound_ifname.split('_')[-1]} timed out. Will purge.")
                    del self._multicast_groups[key]  # Purge immediately if accessed
        return False

    def _periodic_query_loop(self):
        """Periodically sends IGMP General Queries and purges stale memberships."""
        self.router_logger.log_message("[IGMP] Query thread started.")
        while not self._stop_event.is_set():
            self._send_general_queries()
            self._purge_memberships()
            self._stop_event.wait(self.IGMP_QUERY_INTERVAL)
        self.router_logger.log_message("[IGMP] Query thread has exited.")

    def _send_general_queries(self):
        """Sends an IGMP General Query on each configured interface."""
        for ifname, cfg in self._interfaces_config.items():
            if cfg.get("ip_addr") is None:  # Skip interfaces without an IP
                continue

            # Skip loopback interface for multicast queries
            if "loopback" in ifname.lower() or "lo" == ifname.lower():
                continue

            igmp_packet = Ether(src=cfg["mac"], dst="01:00:5e:00:00:01") / \
                          IP(src=cfg["ip_addr"], dst=self.IGMP_ALL_HOSTS_GROUP, ttl=1) / \
                          IGMP(type=0x11, mrcode=100, gaddr="0.0.0.0")  # gaddr=0.0.0.0 for General Query

            self.router_logger.log_message(f"[IGMP] Sending General Query on {ifname.split('_')[-1]}")
            self.packet_writer.queue_packet(igmp_packet, ifname)

    def _purge_memberships(self):
        """Removes multicast group memberships that have timed out."""
        with self._group_lock:
            now = time.time()
            timed_out_keys = [
                key for key, timestamp in self._multicast_groups.items()
                if (now - timestamp) > self.IGMP_MEMBERSHIP_TIMEOUT
            ]
            for key in timed_out_keys:
                multicast_ip, ifname = key
                del self._multicast_groups[key]
                self.router_logger.log_message(
                    f"[IGMP] 🗑️ Timed out and removed membership for {multicast_ip} on {ifname.split('_')[-1]}.")

    def start(self):
        """Starts the periodic IGMP query thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._periodic_query_loop, daemon=True, name="IGMPManagerThread")
        self._thread.start()
        self.router_logger.log_message("[IGMP] Manager thread started.")

    def stop(self):
        """Stops the periodic IGMP query thread."""
        if self._thread and self._thread.is_alive():
            self.router_logger.log_message("[IGMP] Stopping manager thread...")
            self._stop_event.set()
            self._thread.join(timeout=2)
            self.router_logger.log_message("[IGMP] Manager thread stopped.")

    def get_group_memberships(self) -> dict:
        """Returns a copy of the current multicast group membership table for debugging."""
        with self._group_lock:
            return self._multicast_groups.copy()

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

    def get_forwarding_route(self, dest_ip: str) -> Tuple[str, str] | None:
        """
        Returns (next_hop, interface) for the best match route, or None.
        next_hop may be '0.0.0.0' to indicate direct delivery.
        """
        route = self.find_route(dest_ip)
        if route:
            return (route["next_hop"], route["interface"])
        return None

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
    Enhanced with NAT timeouts and a basic ALG placeholder.
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

        # --- NAT Tables ---
        self._nat_table: Dict[
            Tuple[str, int], Tuple[int, float]] = {}  # (internal_ip, internal_port) -> (external_port, timestamp)
        self._nat_reverse_table: Dict[int, Tuple[str, int]] = {}  # external_port -> (internal_ip, internal_port)
        self._static_mappings = {}  # external_port -> (internal_ip, internal_port)

        # --- NAT Security & Temporary Leases ---
        self._port_probe_counts: Dict[str, int] = defaultdict(int)
        self._ban_list: Dict[str, float] = {}  # ip -> ban_expiry_timestamp
        self._ban_threshold = 30  # Number of unmapped port hits to trigger ban
        self._ban_duration = 120  # Ban duration in seconds

        self._max_temp_leases_per_ip = 5  # NEW: Flat limit on active temporary leases per IP
        self._temp_nat_leases: Dict[str, Dict[int, Dict[str, float | str | int]]] = defaultdict(
            dict)  # ip -> {port -> lease_info}
        self._temp_nat_lease_duration = 60  # seconds
        self._temp_nat_cooldown_duration = 10  # seconds

        # --- Threading & Router State ---
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._cleanup_thread = None
        self.router_internal_ip_for_self_mapping: str = "0.0.0.0"

        # Initialize with predefined static mappings
        self.add_static_mapping(external_port=65406, internal_ip="192.168.1.50", internal_port=88)
        self.add_static_mapping(external_port=80, internal_ip="192.168.1.100", internal_port=80)
        self.add_static_mapping(external_port=443, internal_ip="192.168.1.100", internal_port=443)
        self.add_static_mapping(external_port=2222, internal_ip="192.168.1.10", internal_port=22)
        self.add_static_mapping(external_port=3389, internal_ip="192.168.1.25", internal_port=3389)
        self.add_static_mapping(external_port=25565, internal_ip="192.168.1.75", internal_port=25565)
        self.add_static_mapping(external_port=520, internal_ip="192.168.1.50", internal_port=520)

        self.router_logger.log_message("[NAT] 🚀 Manager initialized with port scan detection and temporary leases.")

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

    def translate_outbound(self, packet: Packet):
        """Translates outbound packets using dynamic NAT."""
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            self.router_logger.log_message(
                f"[NAT] ⏭️ Skipping outbound translation for non-IP packet: {packet.summary()}")
            return
        ip = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            if packet.haslayer(ICMP):
                self.router_logger.log_message(
                    f"[NAT] 핑 Passing outbound ICMP for {ip.src} to {ip.dst} without port NAT.")
                return
            if packet.haslayer(DHCP):
                self.router_logger.log_message(f"[NAT] ⏭️ Skipping outbound NAT for DHCP packet from {ip.src}.")
                return
            if packet.haslayer(IGMP):
                self.router_logger.log_message(f"[NAT] ⏭️ Skipping outbound NAT for IGMP packet from {ip.src}.")
                return
            self.router_logger.log_message(
                f"[NAT] 🧐 Skipping outbound translation for unhandled non-TCP/UDP/ICMP packet: {packet.summary()}")
            return

        t = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        internal_key = (ip.src, t.sport)

        with self._lock:
            if internal_key not in self._nat_table:
                new_port = self._get_next_port()
                if new_port == -1:
                    return

                self._nat_table[internal_key] = (new_port, time.time())
                self._nat_reverse_table[new_port] = internal_key
                self.router_logger.log_message(
                    f"[NAT] ➡️ Created dynamic mapping: "
                    f"{ip.src}:{t.sport} → {self.public_ip}:{new_port}"
                )
            else:
                new_port, _ = self._nat_table[internal_key]
                self._nat_table[internal_key] = (new_port, time.time())
                self.router_logger.log_message(
                    f"[NAT] 🔄 Reusing dynamic mapping: "
                    f"{ip.src}:{t.sport} → {self.public_ip}:{new_port}"
                )
        ip.src = self.public_ip
        t.sport = new_port

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
        self.PRIMARY_DNS_SERVER = "8.8.8.8"  # Google's public DNS
        self._pending_requests = {}
        self._lock = threading.Lock()
        self._dns_cache = {}
        self.DNS_CACHE_TTL_MIN = 60
        self.DNS_CACHE_MAX_ENTRIES = 1000
        self._conditional_forwarders = {}
        self._dns_blacklist = set()
        self.router_logger.log_message("[DNS] Manager initialized.  ")


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

    def handle_query(self, packet, inbound_iface: str, router_interfaces: dict, get_mac_function, find_route_function,
                     packet_writer, router_lan_network: ipaddress._BaseNetwork):
        if not (packet.haslayer(DNS) and packet[DNS].qr == 0):
            return False

        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            self.router_logger.log_message("[DNS] ❌ No IP layer found in DNS packet.")
            return False

        layer_name = "IP" if packet.haslayer(IP) else "IPv6"
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet.getlayer(DNS)
        qname = dns_layer.qd.qname.decode() if dns_layer.qd else "unknown"

        if self._is_blacklisted(qname):
            response = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                       packet.getlayer(type(ip_layer)).__class__(src=ip_layer.dst, dst=ip_layer.src) / \
                       UDP(sport=udp_layer.dport, dport=udp_layer.sport) / \
                       DNS(id=dns_layer.id, qr=1, ra=1, rcode=3, qd=dns_layer.qd)
            self.packet_writer.queue_packet(response, inbound_iface)
            return True

        ip_cls = ip_layer.__class__

        cached_response = self._get_from_cache(qname)
        if cached_response:
            response_pkt = cached_response.copy()

            # Set destination IP in correct layer (IP or IPv6)
            response_pkt[ip_cls].dst = ip_layer.src

            # Set UDP destination port and DNS ID to match query
            response_pkt[UDP].dport = udp_layer.sport
            response_pkt[DNS].id = dns_layer.id

            # Handle Ethernet layer (if it exists)
            if response_pkt.haslayer(Ether) and packet.haslayer(Ether):
                response_pkt[Ether].dst = packet[Ether].src

            # Remove checksums to force recalculation
            if ip_cls is IP:
                del response_pkt[IP].chksum
            elif ip_cls is IPv6:
                # IPv6 doesn't have a checksum; just reset UDP
                pass

            if UDP in response_pkt:
                del response_pkt[UDP].chksum

            self.packet_writer.queue_packet(response_pkt, inbound_iface)
            return True

        target_dns_server = self._get_forward_dns_server(qname)
        default_route = find_route_function(target_dns_server)
        if not default_route:
            return False

        outbound_iface_name = default_route.get("interface")
        if not outbound_iface_name:
            return False

        is_from_lan = ipaddress.ip_address(ip_layer.src) in router_lan_network
        if inbound_iface == outbound_iface_name and not is_from_lan:
            self.router_logger.log_message(
                f"[DNS] ⚠️ Refusing external DNS query from {ip_layer.src} to prevent loop. Sending REFUSED response.")

            # Construct a DNS response with RCODE 5 (Refused)
            refused_response = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                               ip_layer.__class__(src=ip_layer.dst, dst=ip_layer.src) / \
                               UDP(sport=udp_layer.dport, dport=udp_layer.sport) / \
                               DNS(id=dns_layer.id, qr=1, ra=1, rcode=5, qd=dns_layer.qd)

            # Remove checksums to force recalculation by the packet writer
            if refused_response.haslayer(IP):
                del refused_response[IP].chksum
            if refused_response.haslayer(UDP):
                del refused_response[UDP].chksum

            self.packet_writer.queue_packet(refused_response, inbound_iface)
            return True  # T

        outbound_iface_config = router_interfaces.get(outbound_iface_name)
        if not outbound_iface_config:
            return False
        udp_layer = packet.getlayer(UDP)
        if not udp_layer:
            self.router_logger.log_message("[DNS] ❌ No UDP layer in DNS query packet; skipping.")
            return False  # Or raise or handle however you prefer
        key = (ip_layer.src, udp_layer.sport, dns_layer.id)
        with self._lock:
            self._pending_requests[key] = {
                "original_mac_src": packet[Ether].src if packet.haslayer(Ether) else None,
                "inbound_iface": inbound_iface
            }

        self.router_logger.log_message(
            f"[DNS] ➡️ Proxying query for {qname} from {ip_layer.src} to {target_dns_server}")
        if qname.endswith(".local."):
            self.router_logger.log_message(f"[DNS] 🌐 Forwarding mDNS query for {qname} via multicast")

            if packet.haslayer(IP):
                multicast_ip = "224.0.0.251"
                ether_dst = "ff:ff:ff:ff:ff:ff"
                ip_layer = IP(dst=multicast_ip)
            elif packet.haslayer(IPv6):
                multicast_ip = "ff02::fb"
                ether_dst = "33:33:00:00:00:fb"
                ip_layer = IPv6(dst=multicast_ip)
            else:
                self.router_logger.log_message("[DNS] ❌ No IP layer found for mDNS forwarding.")
                return False

            multicast_packet = Ether(dst=ether_dst, src=outbound_iface_config['mac']) / \
                               ip_layer / \
                               UDP(sport=udp_layer.sport, dport=5353) / \
                               DNS(id=dns_layer.id, qr=0, qd=dns_layer.qd)

            del multicast_packet[UDP].chksum
            if hasattr(multicast_packet[ip_layer.name], "chksum"):
                del multicast_packet[ip_layer.name].chksum

            self.packet_writer.queue_packet(multicast_packet, outbound_iface_name)
            return True
        modified_packet = packet.copy()
        modified_packet[layer_name].src = outbound_iface_config['ip_addr']
        if layer_name == "IPv6" and ":" not in target_dns_server:
            self.router_logger.log_message("[DNS] ⚠️ IPv6 DNS query routed to IPv4 DNS server — switching to IPv6 DNS")
            target_dns_server = "2001:4860:4860::8888"  # or your own IPv6 resolver

        modified_packet[layer_name].dst = target_dns_server
        if modified_packet.haslayer(Ether):
            modified_packet[Ether].src = outbound_iface_config['mac']
            gateway_ip = default_route.get("next_hop") or target_dns_server
            target_mac = get_mac_function(gateway_ip, outbound_iface_name)
            if not target_mac:
                with self._lock: self._pending_requests.pop(key, None)
                return True
            modified_packet[Ether].dst = target_mac

        # Remove checksum to allow Scapy to recalculate
        if hasattr(modified_packet[layer_name], "chksum"):
            del modified_packet[layer_name].chksum
        if hasattr(modified_packet[UDP], "chksum"):
            del modified_packet[UDP].chksum
        self.packet_writer.queue_packet(modified_packet, outbound_iface_name)
        return True

    def handle_response(self, packet, router_interfaces: dict, packet_writer):
        if not (packet.haslayer(DNS) and packet[DNS].qr == 1):
            return False

        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet[DNS]
        qname = dns_layer.qd.qname.decode() if dns_layer.qd else "unknown"

        key = (ip_layer.dst, udp_layer.dport, dns_layer.id)
        modified_packet = packet.copy()
        with self._lock:
            original_request = self._pending_requests.pop(key, None)

        if original_request:
            self.router_logger.log_message(f"[DNS] ⬅️  Routing response for {qname} to {key[0]}")
            self._add_to_cache(qname, packet)

            response_iface_name = original_request["inbound_iface"]
            response_iface_config = router_interfaces.get(response_iface_name)




            if IP in modified_packet:
                modified_packet[IP].src = response_iface_config['ip_addr']
                modified_packet[IP].dst = key[0]
            elif IPv6 in modified_packet:
                modified_packet[IPv6].src = response_iface_config['ip_addr']
                modified_packet[IPv6].dst = key[0]


            if Ether in modified_packet and original_request["original_mac_src"]:
                modified_packet[Ether].src = response_iface_config['mac']
                modified_packet[Ether].dst = original_request["original_mac_src"]

            if IP in modified_packet:
                del modified_packet[IP].chksum
            elif IPv6 in modified_packet:
                del modified_packet[UDP].chksum

        self.packet_writer.queue_packet(modified_packet)
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
        self._trusted_ports = set()  # Example: {'Ethernet_IN_Full_Name'}
        self.outbound_load_balancer = outbound_load_balancer
        self._static_arp_entries = {}  # {IP: MAC} for trusted static entries

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
                if now < lease_info["lease_end"]:
                    our_mac = get_if_hwaddr(iface)
                    if not our_mac:
                        self.router_logger.log_message(
                            f"[ARP][LEASE] ❌ Failed to get interface MAC for temp lease to {target_ip}")
                        return
                    self.router_logger.log_message(
                        f"[ARP][LEASE] 🔓 Active lease: replying to ARP for {target_ip} with {our_mac}."
                    )
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
            "cooldown_end": now + lease_duration + cooldown
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
    Acts as a DHCP server for devices on the IN (LAN) interface.
    Assigns IP addresses from a defined pool to requesting clients.
    Enhanced with lease persistence and DHCP relay agent capabilities for both IPv4 and IPv6.
    """

    def __init__(self, router_logger, packet_writer, router_in_interface_name: str, dhcp_pool_start: str,
                 dhcp_pool_end: str, interfaces_config: dict, dhcp_relay_target_ip: str = None,
                 dhcp6_prefix: str = None, dhcp6_relay_target_ip: str = None):
        self.logger = router_logger
        self.packet_writer = packet_writer
        self.in_iface = router_in_interface_name
        self._interfaces_config = interfaces_config

        # --- DHCPv4 Configuration ---
        self.lease_pool_start = ipaddress.IPv4Address(dhcp_pool_start)
        self.lease_pool_end = ipaddress.IPv4Address(dhcp_pool_end)
        self._leases: Dict[str, Tuple[ipaddress.IPv4Address, float]] = {}
        self.dynamic_ip_pool = list(self._generate_ip_pool(self.lease_pool_start, self.lease_pool_end))
        self._static_leases: Dict[str, ipaddress.IPv4Address] = {}
        self._lease_lock = threading.Lock()
        self.LEASE_DURATION_SECONDS = 3600
        self.dhcp_relay_target_ip = dhcp_relay_target_ip

        # --- DHCPv6 Configuration ---
        self.dhcp6_prefix = ipaddress.IPv6Network(dhcp6_prefix) if dhcp6_prefix else None
        self.dhcp6_relay_target_ip = dhcp6_relay_target_ip
        # Note: For simplicity, this implementation uses stateless DHCPv6.
        # It does not maintain a lease table for IPv6 addresses.
        # It only replies with configuration options.

        self._stop_event = threading.Event()
        self._cleanup_thread = None

        self.logger.log_message(
            f"[DHCP] Server initialized. DHCPv4 Relay target: {self.dhcp_relay_target_ip if self.dhcp_relay_target_ip else 'None'}. "
            f"DHCPv6 Prefix: {self.dhcp6_prefix if self.dhcp6_prefix else 'None'}. DHCPv6 Relay target: {self.dhcp6_relay_target_ip if self.dhcp6_relay_target_ip else 'None'}")

    def _generate_ip_pool(self, start: ipaddress.IPv4Address, end: ipaddress.IPv4Address):
        """Generate all usable IPs in the DHCP range."""
        current = int(start)
        end_int = int(end)
        while current <= end_int:
            yield ipaddress.IPv4Address(current)
            current += 1
    def get_ip_to_mac_bindings(self) -> Dict[str, str]:
        """
        Returns a thread-safe copy of the current IP-to-MAC lease bindings.
        This is used by the ARPManager for Dynamic ARP Inspection.
        The key is the IP address (str) and the value is the MAC address (str).
        """
        with self._lease_lock:
            # Invert the lease table for IP -> MAC lookup and filter for active leases
            bindings = {str(ip): mac for mac, (ip, expiry) in self._leases.items() if time.time() < expiry}
        return bindings


    def start(self):
        """Starts the DHCP server's cleanup thread."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_leases_loop, daemon=True,
                                                name="DHCPLeaseCleanup")
        self._cleanup_thread.start()
        self.logger.log_message("[DHCP] Cleanup thread started.")

    def stop(self):
        """Stops the DHCP server's cleanup thread gracefully."""
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.logger.log_message("[DHCP] Server stopped.")

    def _cleanup_leases_loop(self):
        """Periodically removes expired DHCP leases (IPv4 only)."""
        while not self._stop_event.is_set():
            now = time.time()
            with self._lease_lock:
                expired_macs = [mac for mac, (ip, expiry) in self._leases.items() if expiry <= now]
                for mac in expired_macs:
                    ip, _ = self._leases.pop(mac)
                    self.logger.log_message(f"[DHCP] 🗑️ IPv4 lease for {ip} (MAC: {mac}) expired and removed.")
            self._stop_event.wait(60)


    def _assign_ip(self, client_mac: str) -> ipaddress.IPv4Address | None:
        """Assigns an IP address, prioritizing static leases over the dynamic pool."""
        norm_mac = client_mac.lower()
        self.logger.log_message(f"[DHCP] Assigning IP for {norm_mac}")

        with self._lease_lock:
            # 1. Check for a static lease assignment first.
            if norm_mac in self._static_leases:
                static_ip = self._static_leases[norm_mac]
                for mac, (ip, expiry) in self._leases.items():
                    if ip == static_ip and mac != norm_mac and time.time() < expiry:
                        self.logger.log_message(f"[DHCP] ❌ Static IP conflict! {static_ip} is currently leased to {mac}.")
                        return None
                self._leases[norm_mac] = (static_ip, time.time() + self.LEASE_DURATION_SECONDS)
                self.logger.log_message(f"[DHCP] 📌 Assigned static IP {static_ip} to {norm_mac}.")
                return static_ip

            # 2. Check for an existing dynamic lease to renew.
            if norm_mac in self._leases:
                assigned_ip, expiry = self._leases[norm_mac]
                if time.time() < expiry:
                    self._leases[norm_mac] = (assigned_ip, time.time() + self.LEASE_DURATION_SECONDS)
                    self.logger.log_message(f"[DHCP] 🏠 Renewed dynamic lease for {assigned_ip} to {norm_mac}")
                    return assigned_ip

            # 3. Find an available IP in the dynamic pool.
            leased_ips = {ip for ip, _ in self._leases.values()}
            statically_reserved_ips = set(self._static_leases.values())
            for potential_ip in self.dynamic_ip_pool:
                if potential_ip not in leased_ips and potential_ip not in statically_reserved_ips:
                    self._leases[norm_mac] = (potential_ip, time.time() + self.LEASE_DURATION_SECONDS)
                    self.logger.log_message(f"[DHCP] 💻 Assigned new dynamic IP {potential_ip} to {norm_mac}.")
                    return potential_ip

        self.logger.log_message(f"[DHCP] ❌ No available dynamic IP addresses in pool for {norm_mac}.")
        return None

    def handle_packet(self, pkt: Packet, inbound_iface: str, find_route_function) -> bool:
        """
        Handles incoming DHCP packets (DISCOVER, REQUEST, SOLICIT, etc.).
        Returns True if the packet was a DHCP packet handled by the server.
        """
        in_iface_config = self._interfaces_config.get(self.in_iface)
        if not in_iface_config:
            self.logger.log_message(f"[DHCP] Error: IN interface '{self.in_iface}' not found in configuration.")
            return False

        router_in_ip = in_iface_config.get("ip_addr")
        router_in_ipv6 = in_iface_config.get("ipv6_addr")
        router_in_mac = in_iface_config.get("mac")
        if not router_in_ip or not router_in_mac:
            # IPv6 address is optional for DHCPv4 only environments
            if pkt.haslayer(DHCP6) and not router_in_ipv6:
                self.logger.log_message(f"[DHCP] Error: IN interface '{self.in_iface}' missing IPv6 address.")
                return False
            if pkt.haslayer(DHCP) and (not router_in_ip or not router_in_mac):
                self.logger.log_message(f"[DHCP] Error: IN interface '{self.in_iface}' missing IP or MAC in configuration.")
                return False

        # --- Check for DHCPv4 or DHCPv6 packets ---
        is_dhcpv4 = pkt.haslayer(DHCP) and pkt.haslayer(UDP) and pkt[UDP].dport == 67
        is_dhcpv6 = pkt.haslayer(DHCP6) and pkt.haslayer(UDP) and pkt[UDP].dport == 547

        if not is_dhcpv4 and not is_dhcpv6:
            return False

        # Determine if the request is from loopback by checking for an Ethernet layer
        is_loopback_request = not pkt.haslayer(Ether)

        # --- DHCPv4 Handling ---
        if is_dhcpv4:
            bootp_layer = pkt[BOOTP]
            dhcp_layer = pkt[DHCP]
            try:
                raw_mac = bootp_layer.chaddr[:6]
                client_mac = ":".join(f"{b:02x}" for b in raw_mac)
            except (TypeError, IndexError):
                self.logger.log_message("[DHCP] Received malformed DHCP packet with invalid chaddr. Ignoring.")
                return True

            dhcp_message_type = next(
                (opt[1] for opt in dhcp_layer.options if isinstance(opt, tuple) and opt[0] == 'message-type'), None)
            if not dhcp_message_type:
                self.logger.log_message(
                    f"[DHCP] Received DHCP packet from {client_mac} but no message-type option. Ignoring.")
                return True

            self.logger.log_message(
                f"[DHCP] 📨 Received DHCP type {dhcp_message_type} from {client_mac} (xid: {bootp_layer.xid})")

            # DHCPv4 Relay Agent logic
            if self.dhcp_relay_target_ip:
                self.logger.log_message(f"[DHCP] Relaying packet from {client_mac} to {self.dhcp_relay_target_ip}.")
                # Forward the packet to the relay target
                relay_packet = IP(src=router_in_ip, dst=self.dhcp_relay_target_ip) / \
                               UDP(sport=67, dport=67) / pkt[BOOTP] / pkt[DHCP]
                # The DHCP relay packet has a 'giaddr' field to indicate the gateway's IP
                relay_packet[BOOTP].giaddr = router_in_ip
                self.packet_writer.queue_packet(relay_packet, self.in_iface)
                return True

            # DHCPv4 Server Logic
            if dhcp_message_type == 1:  # DHCP Discover
                assigned_ip = self._assign_ip(client_mac)
                if assigned_ip:
                    dhcp_options = [
                        ("message-type", "offer"),
                        ("subnet_mask", str(in_iface_config['network'].netmask)),
                        ("router", router_in_ip),
                        ("name_server", router_in_ip),
                        ("lease_time", self.LEASE_DURATION_SECONDS),
                        ("server_id", router_in_ip),
                        "end"
                    ]
                    offer_l3 = IP(src=router_in_ip, dst='255.255.255.255') / \
                               UDP(sport=67, dport=68) / \
                               BOOTP(op=2, xid=bootp_layer.xid, yiaddr=str(assigned_ip),
                                     siaddr=router_in_ip, chaddr=bootp_layer.chaddr) / \
                               DHCP(options=dhcp_options)
                    reply_packet = Ether(src=router_in_mac,
                                         dst="ff:ff:ff:ff:ff:ff") / offer_l3 if not is_loopback_request else offer_l3
                    self.packet_writer.queue_packet(reply_packet, self.in_iface)
                    self.logger.log_message(f"[DHCP] 📝 Sent DHCP Offer for {assigned_ip} to {client_mac}")
                else:
                    self.logger.log_message(f"[DHCP] 🚫 No IP available for {client_mac}, dropping Discover.")
                return True
            elif dhcp_message_type == 3:  # DHCP Request
                assigned_ip = self._assign_ip(client_mac)
                if assigned_ip:
                    dhcp_options = [
                        ("message-type", "ack"),
                        ("subnet_mask", str(in_iface_config['network'].netmask)),
                        ("router", router_in_ip),
                        ("name_server", router_in_ip),
                        ("lease_time", self.LEASE_DURATION_SECONDS),
                        ("server_id", router_in_ip),
                        "end"
                    ]
                    ack_l3 = IP(src=router_in_ip, dst=str(assigned_ip)) / \
                             UDP(sport=67, dport=68) / \
                             BOOTP(op=2, xid=bootp_layer.xid, yiaddr=str(assigned_ip),
                                   siaddr=router_in_ip, chaddr=bootp_layer.chaddr) / \
                             DHCP(options=dhcp_options)
                    reply_packet = Ether(src=router_in_mac,
                                         dst=pkt[Ether].src) / ack_l3 if not is_loopback_request else ack_l3
                    self.packet_writer.queue_packet(reply_packet, self.in_iface)
                    self.logger.log_message(f"[DHCP] 🛰️ Sent DHCP ACK for {assigned_ip} to {client_mac}")
                else:
                    nak_l3 = IP(src=router_in_ip, dst='255.255.255.255') / \
                             UDP(sport=67, dport=68) / \
                             BOOTP(op=2, xid=bootp_layer.xid, chaddr=bootp_layer.chaddr) / \
                             DHCP(options=[("message-type", "nak"), "end"])
                    reply_packet = Ether(src=router_in_mac,
                                         dst="ff:ff:ff:ff:ff:ff") / nak_l3 if not is_loopback_request else nak_l3
                    self.packet_writer.queue_packet(reply_packet, self.in_iface)
                    self.logger.log_message(f"[DHCP] 🚫 Sent DHCP NAK to {client_mac} (no IP available or valid).")
                return True

        # --- DHCPv6 Handling ---
        elif is_dhcpv6:
            if not self.dhcp6_prefix:
                self.logger.log_message("[DHCP] DHCPv6 is disabled. Ignoring packet.")
                return False

            dhcp6_layer = pkt[DHCP6]
            dhcp6_msg_type = dhcp6_layer.msgtype
            client_duid = None

            # Look for the client DUID in the options
            for opt in dhcp6_layer.options:
                if isinstance(opt, tuple) and opt[0] == 1:  # Assuming Scapy format (type, value)
                    client_duid = opt[1]
                    break
                elif hasattr(opt, 'otype') and opt.otype == 1:
                    client_duid = opt.duid
                    break

            if not client_duid:
                self.logger.log_message("[DHCP] Received DHCPv6 packet without a client DUID. Ignoring.")
                return True

            self.logger.log_message(f"[DHCP] 📨 Received DHCPv6 type {dhcp6_msg_type} from DUID: {client_duid.hex()}")

            # DHCPv6 Relay Agent logic
            if self.dhcp6_relay_target_ip:
                self.logger.log_message(f"[DHCP] Relaying packet from DUID {client_duid.hex()} to {self.dhcp6_relay_target_ip}.")
                # Construct and forward a DHCP6_RelayForward packet.
                # This requires more complex parsing of the original packet.
                relay_forward_packet = DHCP6_RelayForward(
                    linkaddr=router_in_ipv6,
                    peeraddr=pkt[IPv6].src,
                    msg=pkt[DHCP6],
                )
                self.packet_writer.queue_packet(relay_forward_packet, self.in_iface)
                return True

            # DHCPv6 Server Logic (Stateless)
            if dhcp6_msg_type == 1: # SOLICIT
                # Respond with a DHCP6 ADVERTISE message
                # A stateless server provides configuration but does not assign addresses.
                dhcp6_options = [
                    # Include the prefix for the client to use for SLAAC
                    DHCP6OptIAPrefix(prefix=str(self.dhcp6_prefix), plen=self.dhcp6_prefix.prefixlen, preferred_lifetime=3600),
                    # Provide DNS server information
                    DHCP6OptDNSServers(dnsservers=[str(router_in_ipv6)]),
                    # End of options
                    "end"
                ]

                advertise_packet = IPv6(src=router_in_ipv6, dst="ff02::1:2") / \
                                   UDP(sport=547, dport=546) / \
                                   DHCP6_Advertise(trid=dhcp6_layer.trid, options=dhcp6_options)

                self.packet_writer.queue_packet(advertise_packet, self.in_iface)
                self.logger.log_message(f"[DHCP] 📝 Sent DHCPv6 Advertise with prefix {self.dhcp6_prefix} to DUID {client_duid.hex()}")
                return True

            elif dhcp6_msg_type == 3: # REQUEST
                # Respond with a DHCP6 REPLY message, confirming the configuration
                dhcp6_options = [
                    DHCP6OptIAPrefix(prefix=str(self.dhcp6_prefix), plen=self.dhcp6_prefix.prefixlen, preferred_lifetime=3600),
                    DHCP6OptDNSServers(dnsservers=[str(router_in_ipv6)]),
                    "end"
                ]

                reply_packet = IPv6(src=router_in_ipv6, dst="ff02::1:2") / \
                               UDP(sport=547, dport=546) / \
                               DHCP6_Reply(trid=dhcp6_layer.trid, options=dhcp6_options)

                self.packet_writer.queue_packet(reply_packet, self.in_iface)
                self.logger.log_message(f"[DHCP] 🛰️ Sent DHCPv6 Reply with prefix {self.dhcp6_prefix} to DUID {client_duid.hex()}")
                return True

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
        if rule['protocol'] not in ['tcp', 'udp', 'icmp', 'igmp', 'any']:
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
