import json
from collections import defaultdict
from typing import Optional, List, Any
import ipaddress
import threading
import time
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6, DHCP6_RelayForward, DHCP6OptIAPrefix, DHCP6OptDNSServers, DHCP6_Advertise, DHCP6_Reply
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import TCP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether, getmacbyip
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSFinished
from scapy.layers.tls.record import TLS
from scapy.packet import Packet
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
class RIPEntry(Packet):
    """
    A RIPv2 routing table entry.
    """
    name = "RIP Route Entry"
    fields_desc = [
        ShortField("af", 2),  # Address Family Identifier (2 for IP)
        ShortField("route_tag", 0),
        IPField("address", "0.0.0.0"),
        IPField("subnet_mask", "0.0.0.0"),
        IPField("next_hop", "0.0.0.0"),
        IntField("metric", 1)
    ]


class RIP(Packet):
    """
    A RIPv2 packet.
    """
    name = "RIP"
    fields_desc = [
        ByteField("command", 1),
        ByteField("version", 2),
        ShortField("reserved", 0),
        PacketListField("entries", [], RIPEntry, count_from=lambda pkt: len(pkt.entries)),
    ]
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
    Listens for announcements and stores services in a cache.
    """

    # mDNS uses a specific multicast address and port
    MDNS_IPV4_ADDR = "224.0.0.251"
    MDNS_IPV6_ADDR = "ff02::fb"
    MDNS_PORT = 5353
    MDNS_CACHE_TTL = 3600  # Default cache time in seconds

    # [FIXED] The constructor now accepts dependencies needed for sending packets
    def __init__(self, router_logger, packet_writer, interfaces_config):
        self.logger = router_logger
        self.packet_writer = packet_writer
        self.interfaces_config = interfaces_config
        self._cache: Dict[Tuple[str, int], Tuple[Any, float]] = {}
        self._cache_lock = threading.Lock()
        self.logger.log_message("[mDNS] Manager initialized. Ready for service discovery.")

    def handle_packet(self, packet: Packet) -> bool:
        """
        Processes an incoming packet to see if it's an mDNS announcement or query.
        Returns True if the packet was handled by this manager.
        """
        # First, check if it's an mDNS packet
        if not (packet.haslayer(UDP) and packet[UDP].dport == self.MDNS_PORT):
            return False

        if packet.haslayer(DNS):
            dns_layer = packet[DNS]

            # --- Case 1: Handle mDNS Queries from a local device ---
            if dns_layer.qr == 0 and dns_layer.qd:
                qname = dns_layer.qd.qname.decode()
                qtype = dns_layer.qd.qtype
                self.logger.log_message(f"[mDNS] ❓ Received query for '{qname}' ({qtype}) from {packet[IP].src}")

                # Check cache for an answer
                cached_answer = self.get_cached_answer(qname, qtype)
                if cached_answer:
                    self.logger.log_message(f"[mDNS] ✅ Answering query for '{qname}' from cache.")
                    # [FIXED] Call the new method to send the response
                    self._send_mdns_response(packet, qname, qtype, cached_answer)
                else:
                    self._forward_mdns_query(packet)
                return True

            # --- Case 2: Handle mDNS Announcements (Answers) from a local device ---
            if dns_layer.qr == 1 and dns_layer.an:
                for answer in dns_layer.an:
                    try:
                        record_name = answer.rrname.decode()
                        record_type = answer.type
                        record_data = answer.rdata

                        # Cache the discovered service
                        self.cache_service(record_name, record_type, record_data, answer.ttl)
                        self.logger.log_message(
                            f"[mDNS] 📡 Discovered service '{record_name}' with IP '{record_data}' (TTL: {answer.ttl}s)"
                        )
                    except Exception as e:
                        self.logger.log_message(f"[mDNS] ⚠️ Failed to parse DNS answer: {e}")
                return True

        return False

    def cache_service(self, name: str, record_type: int, data: Any, ttl: int):
        """Adds a service discovery record to the cache with an expiry time."""
        expiry = time.time() + ttl
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

    # [NEW] Method to craft and send an mDNS response
    def _send_mdns_response(self, original_packet: Packet, qname: str, qtype: int, answer_data: str):
        """
        Builds and queues an mDNS response packet based on a cached answer.
        """
        inbound_iface = original_packet.sniffed_on
        iface_config = self.interfaces_config.get(inbound_iface)

        if not iface_config:
            self.logger.log_message(f"[mDNS] ❌ Cannot send response: Interface '{inbound_iface}' not configured.")
            return

        router_ip = iface_config.get("ip_addr")
        router_mac = iface_config.get("mac")
        is_ipv6 = original_packet.haslayer(IPv6)

        # Craft the DNS response record
        if qtype == 1:  # A Record
            dns_rr = DNSRR(rrname=qname, type="A", rdata=answer_data, ttl=self.MDNS_CACHE_TTL)
        elif qtype == 28:  # AAAA Record
            dns_rr = DNSRR(rrname=qname, type="AAAA", rdata=answer_data, ttl=self.MDNS_CACHE_TTL)
        else:
            self.logger.log_message(f"[mDNS] ⚠️ Cannot craft response: Unsupported record type {qtype}")
            return

        # Build the full response packet
        if is_ipv6:
            src_ip = iface_config.get("ipv6_addr")  # Assumes ipv6_addr is configured
            dst_ip = self.MDNS_IPV6_ADDR
            eth_dst = "33:33:00:00:00:fb"
            l3_packet = IPv6(src=src_ip, dst=dst_ip)
        else:
            src_ip = router_ip
            dst_ip = self.MDNS_IPV4_ADDR
            eth_dst = "01:00:5e:00:00:fb"
            l3_packet = IP(src=src_ip, dst=dst_ip)

        response_packet = Ether(src=router_mac, dst=eth_dst) / \
                          l3_packet / \
                          UDP(sport=self.MDNS_PORT, dport=self.MDNS_PORT) / \
                          DNS(id=0, qr=1, ra=1, aa=1,
                              qd=original_packet[DNS].qd,
                              an=dns_rr)

        self.packet_writer.queue_packet(response_packet, inbound_iface)
        self.logger.log_message(
            f"[mDNS] ✅ Sent mDNS response for '{qname}' ({qtype}) on {inbound_iface.split('_')[-1]}")

    def _forward_mdns_query(self, original_packet: Packet):
        """
        Forwards an mDNS query to all other interfaces except the one it came from.
        This allows service discovery across interface boundaries.
        """
        inbound_iface = original_packet.sniffed_on

        # Validate the packet has required layers
        if not original_packet.haslayer(DNS) or not original_packet.haslayer(UDP):
            self.logger.log_message("[mDNS] ⚠️ Cannot forward: Packet missing DNS or UDP layer.")
            return

        is_ipv6 = original_packet.haslayer(IPv6)
        dst_mac = "33:33:00:00:00:fb" if is_ipv6 else "01:00:5e:00:00:fb"
        dst_ip = self.MDNS_IPV6_ADDR if is_ipv6 else self.MDNS_IPV4_ADDR

        for iface_name, config in self.interfaces_config.items():
            if iface_name == inbound_iface:
                continue  # Skip original interface

            src_ip = config.get("ipv6_addr") if is_ipv6 else config.get("ip_addr")
            src_mac = config.get("mac")

            if not src_ip or not src_mac:
                self.logger.log_message(f"[mDNS] ⚠️ Skipping {iface_name}: Missing IP or MAC.")
                continue

            # Build appropriate IP layer
            l3 = IPv6(src=src_ip, dst=dst_ip) if is_ipv6 else IP(src=src_ip, dst=dst_ip)

            # Craft forwarded packet
            forwarded_packet = Ether(src=src_mac, dst=dst_mac) / \
                               l3 / \
                               UDP(sport=self.MDNS_PORT, dport=self.MDNS_PORT) / \
                               original_packet[DNS]

            self.packet_writer.queue_packet(forwarded_packet, iface_name)
            self.logger.log_message(
                f"[mDNS] 🔁 Forwarded mDNS query '{original_packet[DNS].qd.qname.decode()}' to {iface_name.split('_')[-1]}")

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
                 timeout_half_open: int = 60, timeout_established: int = 300):
        self.logger = router_logger
        self._sessions: Dict[
            Tuple[Tuple[str, int], Tuple[str, int]], Tuple[HandshakeState, float, str, int, str, int]] = {}
        self._lock = threading.Lock()
        self.timeout_half_open = timeout_half_open
        self.timeout_established = timeout_established
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="HandshakeCleanup")
        self._cleanup_thread.start()
        self.arp_manager = arp_manager
        self.nat_manager = nat_manager
        self.rip_manager = rip_manager
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

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.RIP_PORT = 520
        self.RIP_MCAST_ADDR = "224.0.0.9"
        self.RIP_UPDATE_INTERVAL = 10  # seconds
        self.ROUTE_TIMEOUT = 600  # seconds until a route is considered invalid (for RIP routes)
        self.sniffer = None
        # _routing_table: { ipaddress.IPv4Network : { "next_hop": str, "cost": int, "interface": str, "advertised_by": str, "last_update": float, "type": "direct" | "rip" | "static" } }
        self._routing_table = {}
        self._rt_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._interfaces_config = {}
        self.authentication_key = None  # For RIP authentication
        self.interface_loopback_full_name = None

    def set_authentication_key(self, key: str):
        """Sets a shared secret for RIP authentication (plaintext for simplicity)."""
        self.authentication_key = key
        self.router_logger.log_message("[RIP] Authentication key set.")

    def initialize_routes(self, interfaces_config: dict, default_gateway_ip: str, default_gateway_iface: str):
        """
        Seeds the table with directly connected nets and a default route.
        Must be called before starting the manager.
        """
        self._interfaces_config = interfaces_config
        with self._rt_lock:
            self._routing_table.clear()
            # Add directly connected networks
            for ifname, cfg in self._interfaces_config.items():
                net = cfg["network"]  # Should be an ipaddress.IPv4Network object
                self._routing_table[net] = {
                    "next_hop": "0.0.0.0",  # Indicates direct connection
                    "cost": 1,
                    "interface": ifname,
                    "advertised_by": "self",
                    "last_update": time.time(),
                    "type": "direct"  # NEW: Route type
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
                    "type": "direct"  # Default route often treated as direct or static
                }
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
        self.router_logger.log_message(f"[RIP] Received packet on {inbound_ifname.split('_')[-1]}: {pkt.summary()}")

        rip = pkt.getlayer(RIP)
        if not rip:
            self.router_logger.log_message("[RIP] Ignored packet with no RIP layer.")
            return

        if not self._validate_rip_packet(pkt):
            return  # Drop if authentication fails

        if rip.command == 1:  # RIP request
            self.router_logger.log_message(f"[RIP] Ignoring RIP request from {pkt[IP].src}")
            return
        if rip.command != 2:  # Not a response
            self.router_logger.log_message(
                f"[RIP] Ignored non-response/request RIP packet (command={rip.command}) from {pkt[IP].src}")
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

    def _summarize_routes(self, routes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Attempts to summarize routes to reduce the number of advertised entries.
        This is a basic implementation; more advanced summarization would consider
        supernetting across different prefixes.
        For simplicity, it will try to summarize /24s into a /16 if all /24s within it are present.
        """
        if not routes:
            return []

        summarized_routes = []
        # The 'network' key in the route dictionaries already holds ipaddress.IPv4Network objects.
        networks_to_summarize = [r["network"] for r in routes]

        # Group networks by their /16 parent
        prefix_groups = defaultdict(list)
        for net in networks_to_summarize:
            if net.prefixlen == 24:
                # Get the /16 parent network
                parent_net_str = f"{str(net.network_address).rsplit('.', 2)[0]}.0.0/16"
                parent_net = ipaddress.ip_network(parent_net_str, strict=False)
                prefix_groups[parent_net].append(net)
            else:
                # Keep non-/24 routes as is for now
                # Ensure we find the original route dictionary, not just the network object
                summarized_routes.append(next(r for r in routes if r["network"] == net))

        for parent_net, child_nets in prefix_groups.items():
            # Check if all 256 /24 subnets within the /16 are present
            # This is a highly simplified check. Real summarization is more complex.
            if len(child_nets) == 256:  # If all /24s are covered, summarize to /16
                # Find the minimum cost among the summarized routes
                min_cost = 16
                best_interface = ""
                best_next_hop = ""
                for net in child_nets:
                    original_route = next(r for r in routes if r["network"] == net)
                    if original_route["cost"] < min_cost:
                        min_cost = original_route["cost"]
                        best_interface = original_route["interface"]
                        best_next_hop = original_route["next_hop"]

                if min_cost < 16:  # Only summarize if the summarized route is reachable
                    summarized_routes.append({
                        "network": parent_net,  # Store as IPv4Network object
                        "subnet_mask": str(parent_net.netmask),
                        "next_hop": best_next_hop,
                        "cost": min_cost,
                        "interface": best_interface,  # Interface from one of the child routes
                        "advertised_by": "self (summarized)",
                        "last_update": time.time(),
                        "type": "rip"
                    })
                    self.router_logger.log_message(f"[RIP] Summarized {len(child_nets)} /24s into {parent_net}")
            else:
                # If not all /24s are present, keep the individual /24s
                for net in child_nets:
                    summarized_routes.append(next(r for r in routes if r["network"] == net))

        return summarized_routes

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
                        address=str(net.network_address),
                        subnet_mask=str(net.netmask),
                        metric=metric_to_advertise
                    ))

            if not entries:
                continue

            rip_packet = Ether(src=cfg["mac"], dst="01:00:5e:00:00:09") / \
                         IP(src=cfg["ip_addr"], dst=self.RIP_MCAST_ADDR) / \
                         UDP(sport=self.RIP_PORT, dport=self.RIP_PORT) / \
                         RIP(command=2, version=2, entries=entries)

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

        self.NAT_PORT_MIN = 49152
        self.NAT_PORT_MAX = 65535
        self.NAT_TIMEOUT_SECONDS = 300

        self._nat_table: Dict[Tuple[str, int], Tuple[int, float]] = {}
        self._nat_reverse_table: Dict[int, Tuple[str, int]] = {}
        self._static_mappings = {}

        self._lock = threading.Lock()
        self._next_port = self.NAT_PORT_MIN

        self._stop_event = threading.Event()
        self._cleanup_thread = None
        self.router_internal_ip_for_self_mapping: str = "0.0.0.0"

        # NEW: Port scanning detection and banning state
        self._port_probe_counts: Dict[str, int] = defaultdict(int)
        self._ban_list: Dict[str, float] = {}
        self._ban_threshold = 20  # Number of unmapped port hits to trigger ban
        self._ban_duration = 600  # Ban duration in seconds

        # Initialize with predefined static mappings
        self.add_static_mapping(external_port=65406, internal_ip="192.168.1.50", internal_port=88)
        self.add_static_mapping(external_port=80, internal_ip="192.168.1.100", internal_port=80)
        self.add_static_mapping(external_port=443, internal_ip="192.168.1.100", internal_port=443)
        self.add_static_mapping(external_port=2222, internal_ip="192.168.1.10", internal_port=22)
        self.add_static_mapping(external_port=3389, internal_ip="192.168.1.25", internal_port=3389)
        self.add_static_mapping(external_port=25565, internal_ip="192.168.1.75", internal_port=25565)
        self.add_static_mapping(external_port=520, internal_ip="192.168.1.50", internal_port=520)

        self.router_logger.log_message("[NAT] 🚀 Manager initialized with port scan detection.")

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
        """Periodically removes stale dynamic NAT entries and expired bans."""
        while not self._stop_event.is_set():
            now = time.time()
            with self._lock:
                # Prune stale dynamic NAT entries
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

                # NEW: Prune expired bans
                expired_bans = [ip for ip, expiry in self._ban_list.items() if now >= expiry]
                for ip in expired_bans:
                    del self._ban_list[ip]
                    self._port_probe_counts.pop(ip, None)  # Also clear any lingering counts
                    self.router_logger.log_message(f"[NAT] ✅ Ban expired for {ip}.")

            self._stop_event.wait(self.NAT_TIMEOUT_SECONDS / 2)

    def add_static_mapping(self, external_port: int, internal_ip: str, internal_port: int):
        """
        Add a permanent port‐forwarding rule:
          public_ip:external_port → internal_ip:internal_port
        """
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
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
            self.router_logger.log_message(
                f"[NAT][ALG] 📁 FTP ALG triggered ({direction}). (Placeholder: Actual payload inspection/rewriting needed)")
        if packet.haslayer(UDP) and packet.haslayer(DNS) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
            self.router_logger.log_message(
                f"[NAT][ALG] ❓ DNS traffic observed ({direction}). (No DNS payload rewriting by NAT.)")

    def translate_outbound(self, packet: Packet):
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            self.router_logger.log_message(f"[NAT] ⏭️ Skipping outbound translation for non-IP packet: {packet.summary()}")
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
        """
        Handle inbound TCP/UDP:
          1. Check static mappings
          2. Else check dynamic reverse mappings
          3. If no mapping, send ICMP Destination Unreachable (Port Unreachable) back.
        Returns True if packet was translated, False if dropped/none.
        """

        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            self.router_logger.log_message(f"[NAT] ⏭️ Skipping inbound translation for non-IP packet: {packet.summary()}")
            return False
        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        src_ip = ip_layer.src
        with self._lock:
            ban_expiry = self._ban_list.get(src_ip)
            if ban_expiry and time.time() < ban_expiry:
                self.router_logger.log_message(f"[NAT] 🛡️ Dropping packet from banned IP: {src_ip}")
                return False  # Silently drop the packet

        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            if packet.haslayer(ICMP):
                 self.router_logger.log_message(f"[NAT] 핑 Skipping NAT for inbound ICMP packet.")
            elif packet.haslayer(DHCP) or packet.haslayer(IGMP):
                self.router_logger.log_message(f"[NAT] ⏭️ Skipping NAT for {packet.name} packet.")
            else:
                self.router_logger.log_message(
                    f"[NAT] 🧐 Skipping inbound translation for unhandled non-TCP/UDP packet: {packet.summary()}")
            return False

        transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        ext_dst_port = transport_layer.dport

        with self._lock:
            static_mapping = self._static_mappings.get(ext_dst_port)
        if static_mapping:
            internal_ip, internal_port = static_mapping
            service_name, service_emoji = self.PORT_SERVICES.get(ext_dst_port, ("Custom Service", "🎯"))

            self.router_logger.log_message(
                f"[NAT][STATIC] {service_emoji} Static mapping hit for {service_name}: "
                f"{self.public_ip}:{ext_dst_port} → {internal_ip}:{internal_port}"
            )
            ip_layer.dst = internal_ip
            transport_layer.dport = internal_port
            self._apply_alg(packet, "inbound")
            return True

        with self._lock:
            dynamic_mapping_key = self._nat_reverse_table.get(ext_dst_port)

        if dynamic_mapping_key:
            internal_ip, internal_port = dynamic_mapping_key
            internal_key_for_nat_table = (internal_ip, internal_port)
            with self._lock:
                if internal_key_for_nat_table in self._nat_table:
                    current_ext_port, _ = self._nat_table[internal_key_for_nat_table]
                    self._nat_table[internal_key_for_nat_table] = (current_ext_port, time.time())

            self.router_logger.log_message(
                f"[NAT] ✅ Dynamic mapping found: "
                f"{self.public_ip}:{ext_dst_port} → {internal_ip}:{internal_port}"
            )
            ip_layer.dst = internal_ip
            transport_layer.dport = internal_port
            self._apply_alg(packet, "inbound")
            return True
        else:
            self._port_probe_counts[src_ip] += 1
            probe_count = self._port_probe_counts[src_ip]

            if probe_count >= self._ban_threshold:
                self._ban_list[src_ip] = time.time() + self._ban_duration
                self.router_logger.log_message(
                    f"[NAT] 🚷 IP {src_ip} banned for {self._ban_duration} sec after {probe_count} unmapped port probes."
                )
                return False  # Drop immediately

            elif probe_count % 5 == 0:  # Log every 5 hits for visibility
                self.router_logger.log_message(
                    f"[NAT] ⚠️ IP {src_ip} has {probe_count} unmapped port probes."
                )

            self.router_logger.log_message(
                f"[NAT] 🚫 Unmapped inbound traffic to {self.public_ip}:{ext_dst_port}. Sending ICMP Port Unreachable."
            )
            self._send_icmp_destination_unreachable(packet, ip_layer, transport_layer)
            return False

    def _send_icmp_destination_unreachable(self, original_packet: Packet, original_ip_layer: IP | IPv6,
                                           original_transport_layer: TCP | UDP):
        """
        Constructs and sends an ICMP Destination Unreachable (Port Unreachable) message
        back to the source of the original unmapped packet.
        """
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
            self.router_logger.log_message(
                f"[NAT] ⚠️ Missing MAC for router's outbound interface {outbound_iface_for_icmp.split('_')[-1]} for ICMP. Dropping.")
            return
        router_mac_out = outbound_iface_config['mac']

        next_hop_ip_for_icmp = route_to_sender["next_hop"] if route_to_sender["next_hop"] != "0.0.0.0" else icmp_dst_ip

        next_hop_mac_for_icmp = self._arp_manager_resolve(next_hop_ip_for_icmp, outbound_iface_for_icmp)
        if not next_hop_mac_for_icmp:
            self.router_logger.log_message(
                f"[NAT] 🕵️ ARP resolution failed for next hop {next_hop_ip_for_icmp} on {outbound_iface_for_icmp.split('_')[-1]} for ICMP. Sending back ICMP.")
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
        """Returns (internal_ip, internal_port) for a NAT’d external port, with dynamic port scan detection and banning."""
        with self._lock:
            # 1. Check if IP is already banned
            ban_expiry = self._ban_list.get(src_ip)
            if ban_expiry and time.time() < ban_expiry:
                self.function_call_tracker.track(
                    identifier='NatInternalFromExternalBannedIP',
                    threshold=20,
                    final_message=f"[NAT] ⛔ get_internal_from_external: Banned IP {src_ip} attempted to access port {external_port}. Count: {{}}.",
                    count_message=None,
                )
                return None

            # 2. Check static mappings
            static_mapping = self._static_mappings.get(external_port)
            if static_mapping:
                self.router_logger.log_message(
                    f"[NAT] 🎯 get_internal_from_external: Static hit for external port {external_port}."
                )
                return static_mapping

            # 3. Check dynamic mappings
            dynamic_mapping = self._nat_reverse_table.get(external_port)
            if dynamic_mapping:
                self.router_logger.log_message(
                    f"[NAT] 🔄 get_internal_from_external: Dynamic hit for external port {external_port}."
                )
                return dynamic_mapping

            # 4. Track failed probe for port scanning behavior
            self._port_probe_counts[src_ip] += 1
            count = self._port_probe_counts[src_ip]

            # 5. Trigger ban if threshold exceeded
            if count >= self._ban_threshold:
                expiry_time = time.time() + self._ban_duration
                self._ban_list[src_ip] = expiry_time
                self.router_logger.log_message(
                    f"[NAT] 🔒 IP {src_ip} banned for {self._ban_duration} seconds after {count} probes."
                )
        self.function_call_tracker.track(
            identifier='NatInternalFromExternalNoMapping',
            threshold=20,
            final_message=f"[NAT] ❓ get_internal_from_external: No mapping found for external port {external_port}. Count: {{}}.",
            count_message=None,
        )
        return None

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

        with self._lock:
            original_request = self._pending_requests.pop(key, None)

        if original_request:
            self.router_logger.log_message(f"[DNS] ⬅️  Routing response for {qname} to {key[0]}")
            self._add_to_cache(qname, packet)

            response_iface_name = original_request["inbound_iface"]
            response_iface_config = router_interfaces.get(response_iface_name)

            modified_packet = packet.copy()


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

            return True

        return False

class ARPManager:
    """
    Manages ARP resolution, caching, and related ARP operations for the router.
    Enhanced with Gratuitous ARP and a placeholder for ARP Snooping/Inspection.
    """

    def __init__(self, router_logger,cache_timeout_seconds=300):
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

        # ARP Snooping/Inspection (Placeholder)
        self._trusted_ports = set()  # Example: {'Ethernet_IN_Full_Name'}
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
        Resolves an IP address to a MAC address using static entries, cache, or ARP requests via getmacbyip.
        Caches the result if successful.
        """
        ip_address = ip_address.strip()  # Normalize input

        if ipaddress.ip_address(ip_address).is_loopback:
            self.router_logger.log_message(f"[ARP] Local delivery: Loopback IP {ip_address}. No ARP needed.")
            return None

        # --- Static ARP entries ---
        if ip_address in self._static_arp_entries:
            mac = self._static_arp_entries[ip_address]

            with self._arp_cache_lock:
                cached_entry = self._arp_cache.get(ip_address)
                if not cached_entry or cached_entry[0].lower() != mac.lower():
                    self._arp_cache[ip_address] = (mac, time.time())
                    self.router_logger.log_message(f"[ARP] 🧷 Cached static ARP entry: {ip_address} → {mac}")
            return mac

        # --- Dynamic ARP cache ---
        with self._arp_cache_lock:
            cached_entry = self._arp_cache.get(ip_address)
            if cached_entry:
                mac, timestamp = cached_entry
                if time.time() - timestamp < self.CACHE_TIMEOUT:
                    self.router_logger.log_message(f"[ARP] ⚡ Cache hit for {ip_address} → {mac}")
                    return mac
                else:
                    self.router_logger.log_message(f"[ARP] 🕓 Stale cache entry for {ip_address}. Re-resolving...")
            else:
                self.router_logger.log_message(f"[ARP] 🛰️ Cache miss for {ip_address}. Resolving...")

        # --- Use Scapy's getmacbyip as fallback ---
        try:
            resolved_mac = getmacbyip(ip_address)
            if resolved_mac:
                with self._arp_cache_lock:
                    self._arp_cache[ip_address] = (resolved_mac, time.time())
                self.router_logger.log_message(f"[ARP] ✅ Resolved {ip_address} → {resolved_mac}")
                return resolved_mac
            else:
                self.router_logger.log_message(f"[ARP] ❌ Resolve failed {ip_address}")
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❗ Exception during getmacbyip: {e}")

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


    def send_custom_arp_request(self, target_ip: str, iface: str, timeout: int = 2) -> str | None:
        """
        Sends a custom ARP request to the target IP and waits for a reply.
        This bypasses the cache and returns the resolved MAC address, or None if unreachable.

        Args:
            target_ip (str): The IP address to resolve.
            iface (str): The full interface name to send the ARP request on.
            timeout (int): How long to wait for a reply (default 2 seconds).

        Returns:
            str | None: The resolved MAC address, or None if no reply.
        """
        try:
            self.router_logger.log_message(
                f"[ARP] 📡 Sending direct ARP request for {target_ip} on {iface.split('_')[-1]}")
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
            answered, _ = self.sniffer.srp(arp_request, iface=iface, timeout=timeout, verbose=False)

            if answered:
                resolved_mac = answered[0][1].hwsrc
                self.router_logger.log_message(f"[ARP] 🎯 Directly resolved {target_ip} → {resolved_mac}")
                return resolved_mac
            else:
                self.router_logger.log_message(f"[ARP] ⛔ No response to ARP for {target_ip} on {iface.split('_')[-1]}")
                return None
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Error sending custom ARP for {target_ip}: {e}")
            return None

    def learn_arp_response(self, pkt: Packet):
        """
        Learns and caches ARP is-at responses (i.e., ARP replies).
        Only updates the cache if the new MAC is different or missing.

        Args:
            pkt (Packet): The ARP packet received (must have ARP layer).
        """
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return  # Not an ARP reply (is-at)

        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        iface = pkt.sniffed_on if hasattr(pkt, "sniffed_on") else "Unknown"

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

            self._arp_cache[ip] = (mac, time.time())
    def reply_to_arp_request(self, request_pkt: Packet, iface: str):
        """
        Replies to an ARP who-has request if the router owns the target IP (via static ARP).

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

            if target_ip not in self._static_arp_entries:
                self.router_logger.log_message(
                    f"[ARP] 🤷 Cannot reply to ARP for {target_ip} — no static entry.")
                return

            our_mac = self._static_arp_entries[target_ip]
            arp_reply = Ether(dst=requester_mac, src=our_mac) / ARP(
                op=2,  # is-at
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
        """
        Assigns an available IPv4 address from the pool by checking the internal lease table.
        """
        self.logger.log_message(f"[DHCPv4] Assigning IP for {client_mac}")
        with self._lease_lock:
            # 1. Check if the client already has an active lease to renew.
            if client_mac in self._leases:
                assigned_ip, expiry = self._leases[client_mac]
                if time.time() < expiry:
                    self._leases[client_mac] = (assigned_ip, time.time() + self.LEASE_DURATION_SECONDS)
                    self.logger.log_message(f"[DHCPv4] 🏠 Renewed lease for {assigned_ip} to {client_mac}")
                    return assigned_ip

            # 2. Find the next available IP address in the pool.
            leased_ips = {ip for ip, _ in self._leases.values()}
            for i in range(int(self.lease_pool_end) - int(self.lease_pool_start) + 1):
                potential_ip = self.lease_pool_start + i
                if potential_ip not in leased_ips:
                    # IP is not in our lease table, so we can assign it.
                    self._leases[client_mac] = (potential_ip, time.time() + self.LEASE_DURATION_SECONDS)
                    self.logger.log_message(f"[DHCPv4] 💻 Assigned new IP {potential_ip} to {client_mac}.")
                    return potential_ip

        # 3. If no IP was found after checking the entire pool.
        self.logger.log_message(f"[DHCPv4] ❌ No available IP addresses in pool for {client_mac}.")
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
                self.logger.log_message(f"[DHCPv6] Error: IN interface '{self.in_iface}' missing IPv6 address.")
                return False
            if pkt.haslayer(DHCP) and (not router_in_ip or not router_in_mac):
                self.logger.log_message(f"[DHCPv4] Error: IN interface '{self.in_iface}' missing IP or MAC in configuration.")
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
                self.logger.log_message("[DHCPv4] Received malformed DHCP packet with invalid chaddr. Ignoring.")
                return True

            dhcp_message_type = next(
                (opt[1] for opt in dhcp_layer.options if isinstance(opt, tuple) and opt[0] == 'message-type'), None)
            if not dhcp_message_type:
                self.logger.log_message(
                    f"[DHCPv4] Received DHCP packet from {client_mac} but no message-type option. Ignoring.")
                return True

            self.logger.log_message(
                f"[DHCPv4] 📨 Received DHCP type {dhcp_message_type} from {client_mac} (xid: {bootp_layer.xid})")

            # DHCPv4 Relay Agent logic
            if self.dhcp_relay_target_ip:
                self.logger.log_message(f"[DHCPv4] Relaying packet from {client_mac} to {self.dhcp_relay_target_ip}.")
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
                    self.logger.log_message(f"[DHCPv4] 📝 Sent DHCP Offer for {assigned_ip} to {client_mac}")
                else:
                    self.logger.log_message(f"[DHCPv4] 🚫 No IP available for {client_mac}, dropping Discover.")
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
                    self.logger.log_message(f"[DHCPv4] 🛰️ Sent DHCP ACK for {assigned_ip} to {client_mac}")
                else:
                    nak_l3 = IP(src=router_in_ip, dst='255.255.255.255') / \
                             UDP(sport=67, dport=68) / \
                             BOOTP(op=2, xid=bootp_layer.xid, chaddr=bootp_layer.chaddr) / \
                             DHCP(options=[("message-type", "nak"), "end"])
                    reply_packet = Ether(src=router_in_mac,
                                         dst="ff:ff:ff:ff:ff:ff") / nak_l3 if not is_loopback_request else nak_l3
                    self.packet_writer.queue_packet(reply_packet, self.in_iface)
                    self.logger.log_message(f"[DHCPv4] 🚫 Sent DHCP NAK to {client_mac} (no IP available or valid).")
                return True

        # --- DHCPv6 Handling ---
        elif is_dhcpv6:
            if not self.dhcp6_prefix:
                self.logger.log_message("[DHCPv6] DHCPv6 is disabled. Ignoring packet.")
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
                self.logger.log_message("[DHCPv6] Received DHCPv6 packet without a client DUID. Ignoring.")
                return True

            self.logger.log_message(f"[DHCPv6] 📨 Received DHCPv6 type {dhcp6_msg_type} from DUID: {client_duid.hex()}")

            # DHCPv6 Relay Agent logic
            if self.dhcp6_relay_target_ip:
                self.logger.log_message(f"[DHCPv6] Relaying packet from DUID {client_duid.hex()} to {self.dhcp6_relay_target_ip}.")
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
                self.logger.log_message(f"[DHCPv6] 📝 Sent DHCPv6 Advertise with prefix {self.dhcp6_prefix} to DUID {client_duid.hex()}")
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
                self.logger.log_message(f"[DHCPv6] 🛰️ Sent DHCPv6 Reply with prefix {self.dhcp6_prefix} to DUID {client_duid.hex()}")
                return True

        return True

class OutboundLoadBalancer:
    """
    Distributes outbound traffic across multiple configured WAN interfaces using a hash-based method.
    Ensures flow consistency (packets from the same source to same destination go via the same interface).
    """

    def __init__(self, router_logger):
        self.logger = router_logger
        self._outbound_interfaces: List[str] = []
        self._interface_lock = threading.Lock()
        self.logger.log_message("[OutboundLB] Initialized.")

    def add_outbound_interface(self, iface_full_name: str):
        """Adds a full interface name to the load balancing pool."""
        with self._interface_lock:
            if iface_full_name not in self._outbound_interfaces:
                self._outbound_interfaces.append(iface_full_name)
                self.logger.log_message(f"[OutboundLB] Added interface {iface_full_name.split('_')[-1]} to pool.")
            else:
                self.logger.log_message(f"[OutboundLB] Interface {iface_full_name.split('_')[-1]} already in pool.")

    def remove_outbound_interface(self, iface_full_name: str):
        """Removes an interface from the load balancing pool."""
        with self._interface_lock:
            if iface_full_name in self._outbound_interfaces:
                self._outbound_interfaces.remove(iface_full_name)
                self.logger.log_message(f"[OutboundLB] Removed interface {iface_full_name.split('_')[-1]} from pool.")
            else:
                self.logger.log_message(f"[OutboundLB] Interface {iface_full_name.split('_')[-1]} not found in pool.")

    def get_next_interface(self, packet: Packet) -> str | None:
        """
        Selects an outbound interface based on a hash of source/destination IPs and ports.
        This ensures packets belonging to the same flow use the same outbound interface.
        """
        with self._interface_lock:
            if not self._outbound_interfaces:
                self.logger.log_message("[OutboundLB] No active outbound interfaces for load balancing.")
                return None

            if len(self._outbound_interfaces) == 1:
                return self._outbound_interfaces[0]

            # Hash based on source IP, destination IP, and optionally ports for TCP/UDP
            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            hash_components = [ip_layer.src, ip_layer.dst]
            if packet.haslayer(TCP):
                hash_components.extend([packet[TCP].sport, packet[TCP].dport])
            elif packet.haslayer(UDP):
                hash_components.extend([packet[UDP].sport, packet[UDP].dport])

            # Use a simple hash function to pick an interface
            hash_val = hash(tuple(hash_components))
            selected_index = hash_val % len(self._outbound_interfaces)
            selected_iface = self._outbound_interfaces[selected_index]

            self.logger.log_message(
                f"[OutboundLB] Selected interface {selected_iface.split('_')[-1]} for flow {ip_layer.src} -> {ip_layer.dst}.")
            return selected_iface

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

    def is_lag_interface(self, iface_name: str) -> bool:
        """Checks if a given interface name is a logical LAG interface."""
        with self._lag_lock:
            return iface_name in self._lags

    def get_member_interface(self, lag_name: str, packet: Packet) -> str | None:
        """
        Selects a physical member interface from a LAG for a given packet.
        Uses a hash-based algorithm (src IP, dst IP, src port, dst port) for flow consistency.
        """
        with self._lag_lock:
            member_interfaces = self._lags.get(lag_name)
            if not member_interfaces:
                self.logger.log_message(f"[LAG] ❌ LAG '{lag_name}' not found or has no active members.")
                return None

            # Filter out any non-functional interfaces if a monitoring mechanism were in place
            active_members = [iface for iface in member_interfaces if True]  # Placeholder for actual health check

            if not active_members:
                self.logger.log_message(f"[LAG] 🚫 LAG '{lag_name}' has no active physical members. Cannot send packet.")
                return None

            if len(active_members) == 1:
                return active_members[0]

            # Hash based on source IP, destination IP, and optionally ports for TCP/UDP
            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            hash_components = [ip_layer.src, ip_layer.dst]
            if packet.haslayer(TCP):
                hash_components.extend([packet[TCP].sport, packet[TCP].dport])
            elif packet.haslayer(UDP):
                hash_components.extend([packet[UDP].sport, packet[UDP].dport])

            hash_val = hash(tuple(hash_components))
            selected_index = hash_val % len(active_members)
            selected_member = active_members[selected_index]

            self.logger.log_message(
                f"[LAG] Selected member {selected_member.split('_')[-1]} for LAG '{lag_name}' flow {ip_layer.src} -> {ip_layer.dst}.")
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
