import os
import queue
import random
import socket
import ssl
from collections import defaultdict
from pathlib import Path
from socket import AF_INET
from typing import Optional, List, Tuple, Any

import geoip2.database
import geoip2.errors
import ipaddress
import re
import shutil
import subprocess
import sys
import threading
import json
import time

import psutil
import select
from scapy.all import send, sr1, conf, get_if_list
from scapy.arch import get_if_hwaddr
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sendp, sniff
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import ByteField, ShortField, IntField, IPField, PacketListField
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict, Literal



class RIPEntry(Packet):
    name = "RIPEntry"
    fields_desc = [
        ShortField("addr_family", 2),  # IPv4
        ShortField("route_tag", 0),
        IPField("address", "0.0.0.0"),  # Network address
        IPField("subnet_mask", "0.0.0.0"),
        IPField("next_hop", "0.0.0.0"),
        IntField("metric", 1)  # 1–15 valid, 16 = infinity
    ]


class SimpleRIP(Packet):
    name = "SimpleRIP"
    fields_desc = [
        ByteField("command", 2),  # 1 = request, 2 = response
        ByteField("version", 2),  # RIPv2
        ShortField("unused", 0),
        PacketListField("entries", [], RIPEntry)
    ]


# Bind to UDP/520 so Scapy can dissect/construct automatically
bind_layers(UDP, SimpleRIP, dport=520)
bind_layers(UDP, SimpleRIP, sport=520)

# Custom Scapy Layer for IGMPv2 (if not already defined by Scapy's core)
# Scapy usually has IGMP, but defining explicitly for clarity/customization if needed
try:
    from scapy.layers.inet import IGMP
except ImportError:
    class IGMP(Packet):
        name = "IGMP"
        fields_desc = [
            ByteField("type", 0x11),  # 0x11 = Membership Query, 0x16 = V2 Membership Report, 0x17 = Leave Group
            ByteField("mrcode", 0),  # Max Response Code (for queries)
            ShortField("chksum", None),
            IPField("gaddr", "0.0.0.0")  # Group Address
        ]


    bind_layers(IP, IGMP, proto=2)  # IP protocol 2 is IGMP


class PacketWriter:
    """
    A self-contained class that sends Layer 2 network packets on a dedicated
    thread using a queue. This prevents the calling thread from blocking on I/O.
    """

    def __init__(self, logger):
        """
        Initializes the PacketWriter.
        Args:
            logger: A logger instance for logging messages.
        """
        self.logger = logger
        self.packet_queue = queue.Queue()
        self.worker_thread = None
        self._stop_event = threading.Event()
        self.logger.log_message("[PacketWriter] Initialized.")

    def _worker_loop(self):
        """The main loop for the worker thread that sends packets."""
        self.logger.log_message("[PacketWriter] Worker thread started.")
        while not self._stop_event.is_set():
            try:
                # Block until a packet is available or the thread is stopped
                item = self.packet_queue.get(timeout=1)
                if item is None:  # Sentinel value to stop the thread
                    continue

                packet, interface_name = item
                self._send_raw_packet(packet, interface_name)

            except queue.Empty:
                continue  # Loop back and wait for another item

        self.logger.log_message("[PacketWriter] Worker thread has stopped.")

    def _send_raw_packet(self, packet, interface: str):
        """
        Uses Scapy's sendp to send a Layer 2 packet on a specified interface
        and logs a detailed summary of the sent packet.
        """
        if not interface:
            self.logger.log_message("[PacketWriter] ⚠️ Error: Cannot send packet, interface name is not specified.")
            return
        try:
            # Special handling for loopback: Scapy might not need Ether layer or dst MAC
            is_loopback_iface = "loopback" in interface.lower() or "lo" == interface.lower()  # More precise check for 'lo'

            if packet.haslayer(IP):
                dst_ip_obj = ipaddress.ip_address(packet[IP].dst)

                if not (
                        dst_ip_obj.is_global or dst_ip_obj.is_private or dst_ip_obj.is_multicast or dst_ip_obj.is_loopback):
                    self.logger.log_message(
                        f"[PacketWriter] 🚫 Dropped non-unicast/non-multicast/non-loopback/non-private packet to {dst_ip_obj}. Summary: {packet.summary()}"
                    )
                    return
                else:
                    packet_summary = packet.summary()
                    sendp(packet, iface=interface, verbose=0)
                    self.logger.log_message(
                        f"[PacketWriter] ✅ Sent (Len:{len(packet)}) on {interface.split('_')[-1]} -> {packet_summary}"
                    )
            else:
                # For non-IP packets like ARP, etc.
                packet_summary = packet.summary()
                sendp(packet, iface=interface, verbose=0)
                self.logger.log_message(
                    f"[PacketWriter] ✅ Sent (Len:{len(packet)}) on {interface.split('_')[-1]} -> {packet_summary}"
                )

        except Exception as e:
            self.logger.log_message(f"[PacketWriter] ❌ Failed to send packet on interface '{interface}': {e}")

    def start(self):
        """Starts the packet-sending worker thread."""
        if self.worker_thread and self.worker_thread.is_alive():
            self.logger.log_message("[PacketWriter] Already running.")
            return

        self._stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="PacketWriterThread")
        self.worker_thread.start()

    def stop(self):
        """Stops the packet-sending worker thread gracefully."""
        if not self.worker_thread or not self.worker_thread.is_alive():
            return

        self.logger.log_message("[PacketWriter] Stopping...")
        self._stop_event.set()
        # Add a sentinel value to the queue to unblock the worker's get() call
        self.packet_queue.put(None)
        self.worker_thread.join(timeout=2)

    def queue_packet(self, packet, interface: str):
        """
        Public method to add a packet to the sending queue. This is non-blocking.

        Args:
            packet: The Scapy packet to be sent (must be a Layer 2 packet like Ether).
            interface (str): The name of the interface to send the packet on.
        """
        if self._stop_event.is_set():
            self.logger.log_message("[PacketWriter] ⚠️ Warning: Attempted to queue packet while writer is stopping.")
            return

        self.packet_queue.put((packet, interface))


class ICMPManager:
    """
    Responds to ICMP Echo-Requests (ping) and logs both
    reception and replies, using PacketWriter to send.
    Enhanced with rate limiting and handling of other ICMP types.
    """

    def __init__(self, router_logger, packet_writer, interfaces_config: dict, rate_limit_pps: int = 5):
        self.log = router_logger
        self.pw = packet_writer
        self.ifaces = interfaces_config  # to know MAC & IP

        # Rate Limiting for Echo Replies
        self.rate_limit_pps = rate_limit_pps
        self._last_reply_time = defaultdict(float)  # Key: (src_ip, dst_ip) -> last_reply_timestamp
        self._rate_limit_lock = threading.Lock()

        self.log.log_message("[ICMP] Manager initialized.")

    def _is_rate_limited(self, src_ip: str, dst_ip: str) -> bool:
        """Checks if an ICMP Echo-Reply should be rate-limited."""
        with self._rate_limit_lock:
            now = time.time()
            key = (src_ip, dst_ip)
            if now - self._last_reply_time[key] < (1.0 / self.rate_limit_pps):
                self.log.log_message(f"[ICMP] 🚫 Rate-limiting Echo-Reply to {src_ip}.")
                return True
            self._last_reply_time[key] = now
            return False

    def handle_packet(self, pkt: Packet, inbound_iface: str) -> bool:
        """
        Handles incoming ICMP packets.
        Returns True if the packet was an ICMP packet handled by the manager.
        """
        if not pkt.haslayer(ICMP) or not pkt.haslayer(IP):
            return False

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code if pkt[ICMP].hasfield("code") else 0  # Some ICMP types don't have codes

        # Ensure the packet's destination IP is one of our router's IPs
        is_for_router = False
        router_mac_for_reply = None
        router_ip_for_reply = None
        for iface_full_name, cfg in self.ifaces.items():
            if cfg.get("ip_addr") == dst_ip:
                is_for_router = True
                router_mac_for_reply = cfg.get("mac")
                router_ip_for_reply = cfg.get("ip_addr")
                break

        # If it's not for the router, let the router manager handle forwarding
        if not is_for_router:
            self.log.log_message(
                f"[ICMP] Received {icmp_type} for {dst_ip} (not router's IP). Not handled by ICMP Manager directly.")
            return False

        # --- Handle specific ICMP types ---
        if icmp_type == 8:  # ICMP Echo-Request
            self.log.log_message(
                f"[ICMP] 📨 Echo-Request from {src_ip} to {dst_ip} on {inbound_iface.split('_')[-1]}"
            )

            if self._is_rate_limited(src_ip, dst_ip):
                return True  # Packet handled (rate-limited)

            # Build Echo-Reply
            reply_src_mac = router_mac_for_reply if router_mac_for_reply else "00:00:00:00:00:00"  # Fallback
            reply_dst_mac = pkt[Ether].src if pkt.haslayer(Ether) else "00:00:00:00:00:00"  # Use sender's MAC for reply

            # Handle potential loopback reply: no Ether layer needed for loopback if it didn't come with one
            if "loopback" in inbound_iface.lower() or "lo" == inbound_iface.lower() or not pkt.haslayer(Ether):
                reply = IP(src=dst_ip, dst=src_ip) / \
                        ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / \
                        pkt[ICMP].payload
            else:
                reply = Ether(src=reply_src_mac, dst=reply_dst_mac) / \
                        IP(src=dst_ip, dst=src_ip) / \
                        ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / \
                        pkt[ICMP].payload

            self.pw.queue_packet(reply, inbound_iface)
            self.log.log_message(
                f"[ICMP] ✅ Echo-Reply queued on {inbound_iface.split('_')[-1]} for {src_ip}"
            )
            return True

        elif icmp_type == 3:  # Destination Unreachable
            self.log.log_message(
                f"[ICMP] 🚫 Destination Unreachable (Type 3, Code {icmp_code}) from {src_ip} on {inbound_iface.split('_')[-1]}"
            )
            # Log and potentially trigger further action (e.g., update routing table if host unreachable)
            # For now, just logging.
            return True

        elif icmp_type == 11:  # Time Exceeded
            self.log.log_message(
                f"[ICMP] ⏳ Time Exceeded (Type 11, Code {icmp_code}) from {src_ip} on {inbound_iface.split('_')[-1]}"
            )
            # Log and potentially trigger further action (e.g., for traceroute)
            # For now, just logging.
            return True

        else:
            self.log.log_message(
                f"[ICMP] Received unhandled ICMP type {icmp_type} from {src_ip} on {inbound_iface.split('_')[-1]}. Summary: {pkt.summary()}"
            )
            return False  # Not specifically handled, but it was an ICMP packet


HandshakeState = Literal["SYN_SENT", "SYN_ACK_RECEIVED", "ESTABLISHED", "CLOSING", "CLOSED"]


def _get_canonical_session_key(ip1: str, port1: int, ip2: str, port2: int) -> Tuple[str, int, str, int]:
    """Returns a canonical key for a connection regardless of which end is src/dst."""
    return tuple(sorted([(ip1, port1), (ip2, port2)]))  # type: ignore


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

        # Key: canonical_key -> (state, last_seen_ts, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
        self._sessions: Dict[Tuple[str, int, str, int], Tuple[HandshakeState, float, str, int, str, int]] = {}
        self._lock = threading.Lock()
        self.timeout_half_open = timeout_half_open
        self.timeout_established = timeout_established

        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="HandshakeCleanup")
        # Start cleanup thread immediately as it's purely passive
        self._cleanup_thread.start()

        # Stored for contextual awareness, but not directly used in passive state tracking logic
        self.arp_manager = arp_manager
        self.nat_manager = nat_manager
        self.rip_manager = rip_manager

        self.logger.log_message("[Handshake] Manager initialized (passive mode, with network context).")

    def start(self):
        """Ensures the cleanup thread is running. No active scan thread in passive mode."""
        if not (self._cleanup_thread and self._cleanup_thread.is_alive()):
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="HandshakeCleanup")
            self._cleanup_thread.start()
            self.logger.log_message("[Handshake] Cleanup thread started.")
        else:
            self.logger.log_message("[Handshake] Manager already running.")

    def stop(self):
        """Stops the HandshakeManager's cleanup thread gracefully."""
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.logger.log_message("[Handshake] Manager stopped.")

    def _cleanup_loop(self):
        """
        Periodically removes stale TCP sessions based on their state and last seen timestamp.
        """
        while not self._stop_event.is_set():
            now = time.time()
            with self._lock:
                stale_keys = []
                for key, (state, ts, _, _, _, _) in self._sessions.items():
                    current_timeout = self.timeout_half_open if state in ["SYN_SENT",
                                                                          "SYN_ACK_RECEIVED"] else self.timeout_established
                    if now - ts > current_timeout:
                        stale_keys.append(key)

                for key in stale_keys:
                    state_at_timeout, _, src_ip, src_port, dst_ip, dst_port = self._sessions[key]
                    self.logger.log_message(
                        f"[Handshake] ❌ Session ({src_ip}, {src_port}, {dst_ip}, {dst_port}) timed out "
                        f"in state {state_at_timeout}"
                    )
                    del self._sessions[key]
            # Sleep for the minimum of half-open timeout or 1/10th of established timeout
            time.sleep(min(self.timeout_half_open / 2, self.timeout_established / 10))

    def handle_packet(self, pkt: Packet, inbound_iface: str) -> bool:
        """
        Processes an incoming packet to update TCP session states.
        Returns True if the packet was a TCP packet and potentially updated a session.
        """
        # Ensure it's a TCP packet with an IP layer
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return False

        ip = pkt[IP]
        tcp = pkt[TCP]
        flags = tcp.flags

        # Use canonical key for lookup
        canonical_key = _get_canonical_session_key(ip.src, tcp.sport, ip.dst, tcp.dport)

        with self._lock:
            current_session = self._sessions.get(canonical_key)
            session_state = current_session[0] if current_session else None
            # Extract original roles for logging consistency or new session creation
            # If current_session is None, these default to packet's src/dst
            original_src_ip = current_session[2] if current_session else ip.src
            original_src_port = current_session[3] if current_session else tcp.sport
            original_dst_ip = current_session[4] if current_session else ip.dst
            original_dst_port = current_session[5] if current_session else tcp.dport

            # Get current timestamp for updating last_seen_ts
            now = time.time()

            # --- TCP State Machine Logic ---

            # SYN (New connection initiation or retransmission)
            if flags == 0x02:  # SYN (just SYN flag)
                if session_state is None:
                    # New session: store original src/dst based on this SYN packet
                    self._sessions[canonical_key] = ("SYN_SENT", now, ip.src, tcp.sport, ip.dst, tcp.dport)
                    self.logger.log_message(f"[Handshake] SYN from {ip.src}:{tcp.sport} to {ip.dst}:{tcp.dport}")
                elif session_state == "SYN_SENT":  # SYN retransmission
                    # Update timestamp to keep half-open session alive
                    self._sessions[canonical_key] = (session_state, now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] SYN retransmission from {ip.src}:{tcp.sport}")  # Optional: detailed logging
                # No other state should receive a plain SYN that advances state
                return True

            # SYN+ACK (Server response to SYN)
            elif flags == 0x12:  # SYN+ACK (SYN and ACK flags set)
                if session_state == "SYN_SENT":
                    self._sessions[canonical_key] = ("SYN_ACK_RECEIVED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(f"[Handshake] SYN-ACK from {ip.src}:{tcp.sport} to {ip.dst}:{tcp.dport}")
                elif session_state == "SYN_ACK_RECEIVED":  # SYN+ACK retransmission
                    # Update timestamp to keep half-open session alive
                    self._sessions[canonical_key] = (session_state, now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] SYN-ACK retransmission from {ip.src}:{tcp.sport}")  # Optional: detailed logging
                return True

            # ACK (Client completing handshake, data ACK, or final ACK for FIN)
            elif flags == 0x10:  # Pure ACK (only ACK flag)
                if session_state == "SYN_ACK_RECEIVED":
                    self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ✅ Connection ESTABLISHED: {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                    )
                elif session_state == "ESTABLISHED":
                    # Crucially, update timestamp for ESTABLISHED data flow
                    self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    # self.logger.log_message(f"[Handshake] Data packet seen on ESTABLISHED session {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}") # Optional: verbose data logging
                elif session_state == "CLOSING":
                    # This ACK completes a graceful close after a FIN
                    self._sessions[canonical_key] = ("CLOSED", now, original_src_ip, original_src_port, original_dst_ip,
                                                     original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ❎ Connection CLOSED (ACK after FIN): {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}")
                    del self._sessions[canonical_key]  # Remove fully closed session
                return True

            # FIN (Initiating graceful close)
            # Check for FIN flag being set (0x01) along with other flags (e.g., ACK)
            elif flags & 0x01:  # FIN flag is set (can be FIN, FIN+ACK, PSH+FIN+ACK, etc.)
                if session_state == "ESTABLISHED":
                    self._sessions[canonical_key] = ("CLOSING", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔻 CLOSING initiated by {ip.src}:{tcp.sport} on {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}")
                elif session_state == "CLOSING":  # Second FIN in the exchange
                    self._sessions[canonical_key] = ("CLOSED", now, original_src_ip, original_src_port, original_dst_ip,
                                                     original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ❎ Connection CLOSED (Second FIN): {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}")
                    del self._sessions[canonical_key]  # Remove fully closed session
                return True

            # RST (Abrupt close)
            # Check for RST flag being set (0x04)
            elif flags & 0x04:  # RST flag is set (can be RST, RST+ACK, etc.)
                if current_session:  # If we are tracking it, remove it
                    self.logger.log_message(
                        f"[Handshake] ❌ RST received on session {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}. Forcibly closing.")
                    del self._sessions[canonical_key]  # Remove abruptly closed session
                return True

            # For any other TCP packet on an ESTABLISHED connection (e.g., PSH|ACK for data)
            # Ensure the timestamp is updated even if no state change occurs.
            if current_session and current_session[0] == "ESTABLISHED":
                self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port,
                                                 original_dst_ip, original_dst_port)
                # self.logger.log_message(f"[Handshake] Data packet seen on ESTABLISHED session {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}") # Optional: verbose data logging
                return True  # Packet processed as part of an existing session

        return False  # Packet was TCP/IP but not part of a tracked state change or existing session.


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
        Processes an incoming IGMP packet.
        Updates the multicast group membership table.
        """
        if not pkt.haslayer(IGMP):
            return

        igmp_layer = pkt[IGMP]
        src_ip = pkt[IP].src
        group_ip = str(igmp_layer.gaddr)  # Group address associated with the message

        self.router_logger.log_message(
            f"[IGMP] Received {igmp_layer.type} packet on {inbound_ifname.split('_')[-1]} from {src_ip} for group {group_ip}")

        with self._group_lock:
            if igmp_layer.type == 0x11:  # IGMP Membership Query
                self.router_logger.log_message(
                    f"[IGMP] Received Query (Type 0x11) for {group_ip} from {src_ip}. (No state change from query itself).")

            elif igmp_layer.type == 0x16:  # IGMPv2 Membership Report
                key = (group_ip, inbound_ifname)
                self._multicast_groups[key] = time.time()
                self.router_logger.log_message(
                    f"[IGMP] ✅ Host {src_ip} reported membership in {group_ip} on {inbound_ifname.split('_')[-1]}. Table updated.")

            elif igmp_layer.type == 0x17:  # IGMPv2 Leave Group
                key = (group_ip, inbound_ifname)
                if key in self._multicast_groups:
                    del self._multicast_groups[key]
                    self.router_logger.log_message(
                        f"[IGMP] 🗑️ Host {src_ip} left group {group_ip} on {inbound_ifname.split('_')[-1]}. Table updated.")
                else:
                    self.router_logger.log_message(
                        f"[IGMP] Host {src_ip} sent Leave for {group_ip} on {inbound_ifname.split('_')[-1]}, but not in table.")
            else:
                self.router_logger.log_message(f"[IGMP] Ignored unsupported IGMP type: {igmp_layer.type}")

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


class TLSProxyManager:
    """
    Handles the application-layer TLS proxying of connections handed off by the router.
    Accepts (client_socket, target_host, target_port) tuples from the router.
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.connection_queue = queue.Queue()
        self._stop_event = threading.Event()
        self.worker_thread = None

    def start(self):
        """Starts the TLS proxy worker thread."""
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        self.router_logger.log_message("[TLSProxy] Worker thread started.")

    def stop(self):
        """Stops the TLS proxy worker thread."""
        self._stop_event.set()
        self.connection_queue.put(None)  # Unblock the queue if it's waiting
        self.worker_thread.join(timeout=2)
        self.router_logger.log_message("[TLSProxy] Worker thread stopped.")

    def _worker_loop(self):
        """Main loop for proxying queued connections."""
        while not self._stop_event.is_set():
            try:
                conn_details = self.connection_queue.get(timeout=1)
                if conn_details is None:
                    continue
                client_socket, target_host, target_port = conn_details
                self.router_logger.log_message(
                    f"[TLSProxy] Handling connection to {target_host}:{target_port}"
                )
                self._handle_tls_proxy(client_socket, target_host, target_port)
            except queue.Empty:
                continue
            except Exception as e:
                self.router_logger.log_message(f"[TLSProxy] Unexpected error: {e}")

    def _handle_tls_proxy(self, client_socket: socket.socket, target_host: str, target_port: int):
        """Establishes TLS connection to target and relays data between sockets."""
        server_socket = None
        try:
            # Set both sockets to non-blocking
            client_socket.setblocking(False)

            # Connect to the remote TLS server
            context = ssl.create_default_context()
            raw_server_socket = socket.create_connection((target_host, target_port), timeout=10)
            server_socket = context.wrap_socket(raw_server_socket, server_hostname=target_host)
            server_socket.setblocking(False)

            self.router_logger.log_message(f"[TLSProxy] TLS handshake with {target_host} complete.")

            # Main relay loop
            sockets = [client_socket, server_socket]
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 1)
                if exceptional:
                    break

                for sock in readable:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            raise ConnectionResetError("Connection closed")

                        # Relay to the opposite socket
                        if sock is client_socket:
                            server_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                        continue
                    except Exception as e:
                        self.router_logger.log_message(f"[TLSProxy] Socket relay error: {e}")
                        return

        except Exception as e:
            self.router_logger.log_message(f"[TLSProxy] TLS proxy failed: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                if server_socket:
                    server_socket.close()
            except:
                pass
            self.router_logger.log_message(f"[TLSProxy] Connection closed.")

    def queue_connection(self, client_socket: socket.socket, target_host: str, target_port: int):
        """Enqueue a new connection for TLS proxying."""
        self.connection_queue.put((client_socket, target_host, target_port))


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
        self.ROUTE_TIMEOUT = 180  # seconds until a route is considered invalid (for RIP routes)

        # _routing_table: { ipaddress.IPv4Network : { "next_hop": str, "cost": int, "interface": str, "advertised_by": str, "last_update": float, "type": "direct" | "rip" | "static" } }
        self._routing_table = {}
        self._rt_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._interfaces_config = {}
        self.authentication_key = None  # For RIP authentication

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

    def get_routing_table_view(self) -> list[dict]:
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

    def find_route(self, dest_ip_str: str):
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
                            rt_details["interface"] == self._interfaces_config.get(
                        self.router_logger.interface_loopback_full_name, {}).get('full_name'):
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

    def get_forwarding_route(self, dest_ip: str) -> tuple[str, str] | None:
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

        rip = pkt.getlayer(SimpleRIP)
        if not rip:
            self.router_logger.log_message("[RIP] Ignored packet with no SimpleRIP layer.")
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
            for entry in rip.entries:
                net = ipaddress.ip_network(f"{entry.address}/{entry.subnet_mask}", strict=False)
                cost = min(entry.metric + 1, 16)  # Cost for us is sender's metric + 1
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

    def _summarize_routes(self, routes: list[dict]) -> list[dict]:
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
                         SimpleRIP(command=2, version=2, entries=entries)

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
                    f"[RIP] Sending advertisement on {ifname.split('_')[-1]} ({len(entries)} entries)")
                sendp(rip_packet, iface=ifname, verbose=0)
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


class NATManager:
    """
    Manages Network Address Translation (NAT) with both:
      - dynamic NAT for outbound connections, and
      - static port‐forwarding mappings for inbound services.
    Enhanced with NAT timeouts and a basic ALG placeholder.
    """

    def __init__(self, router_logger, router_public_ip: str):
        self.router_logger = router_logger
        self.public_ip = router_public_ip

        # Dynamic NAT port pool (IANA recommended private range)
        self.NAT_PORT_MIN = 49152
        self.NAT_PORT_MAX = 65535
        self.NAT_TIMEOUT_SECONDS = 300  # Timeout for dynamic NAT entries (5 minutes)

        # _nat_table: { (internal_ip, internal_port, external_port) : last_seen_timestamp }
        # The key is (internal_ip, internal_port) -> (external_port, last_seen_timestamp)
        self._nat_table: Dict[Tuple[str, int], Tuple[int, float]] = {}
        # _nat_reverse_table: { external_port -> (internal_ip, internal_port) }
        self._nat_reverse_table: Dict[int, Tuple[str, int]] = {}

        # Static port‐forwarding: external_port -> (internal_ip, internal_port)
        self._static_mappings = {}

        self._lock = threading.Lock()
        self._next_port = self.NAT_PORT_MIN

        self._stop_event = threading.Event()
        self._cleanup_thread = None

        self.add_static_mapping(
            external_port=65406,
            internal_ip="192.168.1.50",
            internal_port=88
        )
        self.router_logger.log_message("[NAT] Manager initialized.")

    def start(self):
        """Starts the NAT cleanup thread."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="NATCleanup")
        self._cleanup_thread.start()
        self.router_logger.log_message("[NAT] Cleanup thread started.")

    def stop(self):
        """Stops the NAT cleanup thread gracefully."""
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        self.router_logger.log_message("[NAT] Manager stopped.")

    def _cleanup_loop(self):
        """Periodically removes stale dynamic NAT entries."""
        while not self._stop_event.is_set():
            now = time.time()
            with self._lock:
                stale_keys = []
                for internal_key, (external_port, timestamp) in self._nat_table.items():
                    if now - timestamp > self.NAT_TIMEOUT_SECONDS:
                        stale_keys.append(internal_key)

                for internal_key in stale_keys:
                    external_port, _ = self._nat_table.pop(internal_key)
                    del self._nat_reverse_table[external_port]
                    self.router_logger.log_message(
                        f"[NAT] 🗑️ Timed out dynamic mapping: {internal_key[0]}:{internal_key[1]} -> {self.public_ip}:{external_port}"
                    )
            time.sleep(self.NAT_TIMEOUT_SECONDS / 2)  # Check every half timeout duration

    def add_static_mapping(self, external_port: int, internal_ip: str, internal_port: int):
        """
        Add a permanent port‐forwarding rule:
          public_ip:external_port → internal_ip:internal_port
        """
        with self._lock:
            self._static_mappings[external_port] = (internal_ip, internal_port)
        self.router_logger.log_message(
            f"[NAT][STATIC] ✳️  Added static mapping: {self.public_ip}:{external_port} "
            f"→ {internal_ip}:{internal_port}"
        )

    def remove_static_mapping(self, external_port: int):
        """Remove an existing static port-forwarding rule."""
        with self._lock:
            removed = self._static_mappings.pop(external_port, None)
        if removed:
            self.router_logger.log_message(
                f"[NAT][STATIC] 🗑️  Removed static mapping for "
                f"{self.public_ip}:{external_port}"
            )
        else:
            self.router_logger.log_message(
                f"[NAT][STATIC] ⚠️  No static mapping found for "
                f"{self.public_ip}:{external_port} to remove"
            )

    def _get_next_port(self) -> int:
        with self._lock:
            # Simple linear scan for next available port. For high scale, use a bitmap or more complex pool.
            for _ in range(self.NAT_PORT_MIN, self.NAT_PORT_MAX + 1):
                port = self._next_port
                self._next_port += 1
                if self._next_port > self.NAT_PORT_MAX:
                    self._next_port = self.NAT_PORT_MIN  # Wrap around

                # Check if this port is already in use (dynamic or static)
                if port not in self._nat_reverse_table and port not in self._static_mappings:
                    return port
            self.router_logger.log_message("[NAT] ❌ No available dynamic NAT ports in pool.")
            return -1  # Indicate no port found

    def _apply_alg(self, packet: Packet, direction: str):
        """
        Application Layer Gateway (ALG) placeholder.
        This would inspect and modify application-layer payloads (e.g., FTP PORT/PASV commands)
        to rewrite IP addresses and port numbers for NAT traversal.
        """
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):  # FTP
            self.router_logger.log_message(
                f"[NAT][ALG] FTP ALG triggered ({direction}). (Placeholder: Actual payload inspection/rewriting needed)")
            # Example: For FTP, you would need to parse the FTP command/response,
            # find IP/port values, and rewrite them, then update TCP/IP checksums.
            # This is highly complex and protocol-specific.
            pass  # No actual modification for now

    def translate_outbound(self, packet: Packet):
        """Perform dynamic NAT for outbound TCP/UDP, logging creation/reuse."""
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            self.router_logger.log_message(
                f"[NAT] Skipping outbound translation for non-TCP/UDP packet: {packet.summary()}"
            )
            return

        ip = packet[IP]
        t = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        key = (ip.src, t.sport)

        with self._lock:
            if key not in self._nat_table:
                new_port = self._get_next_port()
                if new_port == -1:  # No available port
                    self.router_logger.log_message(
                        f"[NAT] 🚫 Dropping outbound packet from {ip.src}:{t.sport} due to no available NAT ports.")
                    return  # Drop packet if no port can be assigned

                self._nat_table[key] = (new_port, time.time())  # Store port and timestamp
                self._nat_reverse_table[new_port] = key
                self.router_logger.log_message(
                    f"[NAT] ➡️ Created dynamic mapping: "
                    f"{ip.src}:{t.sport} → {self.public_ip}:{new_port}"
                )
            else:
                new_port, _ = self._nat_table[key]
                self._nat_table[key] = (new_port, time.time())  # Update timestamp on reuse
                self.logger.log_message(
                    f"[NAT] 🔄 Reusing dynamic mapping: "
                    f"{ip.src}:{t.sport} → {self.public_ip}:{new_port}"
                )

        # Rewrite packet
        ip.src = self.public_ip
        t.sport = new_port

        self._apply_alg(packet, "outbound")  # Apply ALG if applicable

    def translate_inbound(self, packet: Packet):
        """
        Handle inbound TCP/UDP:
          1. Check static mappings
          2. Else check dynamic reverse mappings
          3. Rewrite or drop
        Returns True if packet was translated, False if dropped/none.
        """
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            self.router_logger.log_message(
                f"[NAT] Skipping inbound translation for non-TCP/UDP packet: {packet.summary()}"
            )
            return False

        ip = packet[IP]
        t = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        ext_port = t.dport

        # 1) Static port‐forwarding
        with self._lock:
            static = self._static_mappings.get(ext_port)
        if static:
            internal_ip, internal_port = static
            self.router_logger.log_message(
                f"[NAT][STATIC] ⬅️  Static mapping hit: "
                f"{self.public_ip}:{ext_port} → {internal_ip}:{internal_port}"
            )
            ip.dst = internal_ip
            t.dport = internal_port
            self._apply_alg(packet, "inbound")  # Apply ALG if applicable
            return True

        # 2) Dynamic reverse mapping
        self.router_logger.log_message(
            f"[NAT] ⬅️  Lookup dynamic mapping for external port {ext_port} "
            f"(from {ip.src}:{t.sport})"
        )
        with self._lock:
            orig = self._nat_reverse_table.get(ext_port)

        if orig:
            internal_ip, internal_port = orig
            # Update timestamp for dynamic entry on inbound traffic
            # Need to find the original key (internal_ip, internal_port) to update its timestamp
            internal_key = (internal_ip, internal_port)
            if internal_key in self._nat_table:
                self._nat_table[internal_key] = (ext_port, time.time())  # Update timestamp

            self.router_logger.log_message(
                f"[NAT] ✅  Dynamic mapping found: "
                f"{self.public_ip}:{ext_port} → {internal_ip}:{internal_port}"
            )
            ip.dst = internal_ip
            t.dport = internal_port
            self._apply_alg(packet, "inbound")  # Apply ALG if applicable
            return True
        else:
            self.router_logger.log_message(
                f"[NAT] ❌  No mapping for inbound port {ext_port}. "
                f"Packet will be dropped or passed unmodified."
            )
            return False


class DNSManager:
    """
    Manages DNS query proxying. Intercepts local DNS requests and forwards
    them to a public DNS server.
    Enhanced with DNS caching, conditional forwarding, and basic filtering.
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.PRIMARY_DNS_SERVER = "8.8.8.8"  # Google's public DNS
        self._pending_requests = {}  # Tracks ongoing DNS queries: key (src_ip, sport, dns_id) -> original_mac_src, inbound_iface
        self._lock = threading.Lock()

        # DNS Caching
        self._dns_cache = {}  # Key: qname (str) -> (response_packet_bytes, expiry_time)
        self.DNS_CACHE_TTL_MIN = 60  # Minimum TTL for cached entries
        self.DNS_CACHE_MAX_ENTRIES = 1000  # Max entries in cache

        # Conditional Forwarding: { domain_suffix : dns_server_ip }
        self._conditional_forwarders = {
            # "example.com": "1.1.1.1",
            # "internal.net": "192.168.0.1"
        }

        # DNS Filtering: set of blacklisted domain suffixes
        self._dns_blacklist = {
            # "badsite.com",
            # "malware.net"
        }

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
                # Simple LRU: remove oldest entry if cache is full (not truly LRU, but simple)
                # In a real impl, use OrderedDict or more complex LRU cache.
                oldest_key = next(iter(self._dns_cache))
                del self._dns_cache[oldest_key]
                self.router_logger.log_message(f"[DNS] Cache full, removed {oldest_key}")

            # Determine TTL from response, use min_ttl if response TTL is too small
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
                    return Ether(response_bytes)  # Reconstruct packet from bytes
                else:
                    del self._dns_cache[qname]
                    self.logger.log_message(f"[DNS] Cache expired for {qname}.")
        return None

    def handle_query(self, packet, inbound_iface: str, router_interfaces: dict, get_mac_function, find_route_function,
                     packet_writer):
        """
        Processes a DNS query packet, forwarding it to a public DNS server.
        Returns True if the packet was handled, False otherwise.
        """
        if not (packet.haslayer(DNS) and packet[DNS].qr == 0):  # 0 = query
            return False

        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet.getlayer(DNS)
        qname = dns_layer.qd.qname.decode() if dns_layer.qd and dns_layer.qd.qname else "unknown"

        # 1. DNS Filtering
        if self._is_blacklisted(qname):
            self.router_logger.log_message(f"[DNS] 🚫 Blocked blacklisted query for {qname} from {ip_layer.src}.")
            # Send a DNS response indicating NXDOMAIN (Non-Existent Domain)
            # This is a basic form of blocking.
            blocked_response = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                               IP(src=ip_layer.dst, dst=ip_layer.src) / \
                               UDP(sport=udp_layer.dport, dport=udp_layer.sport) / \
                               DNS(id=dns_layer.id, qr=1, ra=1, rcode=3, qd=dns_layer.qd)  # rcode=3 is NXDOMAIN
            packet_writer.queue_packet(blocked_response, inbound_iface)
            return True

        # 2. DNS Caching
        cached_response = self._get_from_cache(qname)
        if cached_response:
            # Reconstruct the response with the original query's ID and client's IP/port
            original_ether_src = packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
            router_in_mac = router_interfaces.get(inbound_iface, {}).get("mac")
            router_in_ip = router_interfaces.get(inbound_iface, {}).get("ip_addr")

            if not router_in_mac or not router_in_ip:
                self.router_logger.log_message(
                    f"[DNS] Cannot send cached response: Router IN interface config missing for {inbound_iface.split('_')[-1]}.")
                return True  # Handled, but couldn't send

            # Modify cached response to match current request's source/destination
            response_pkt = cached_response.copy()
            response_pkt[IP].src = router_in_ip
            response_pkt[IP].dst = ip_layer.src
            response_pkt[UDP].sport = udp_layer.dport
            response_pkt[UDP].dport = udp_layer.sport
            response_pkt[DNS].id = dns_layer.id

            if response_pkt.haslayer(Ether):
                response_pkt[Ether].src = router_in_mac
                response_pkt[Ether].dst = original_ether_src
            else:  # If original packet had no Ether (e.g., loopback), ensure response also has no Ether
                response_pkt = response_pkt[IP] / response_pkt[UDP] / response_pkt[DNS]

            del response_pkt[IP].chksum
            del response_pkt[UDP].chksum

            packet_writer.queue_packet(response_pkt, inbound_iface)
            self.router_logger.log_message(f"[DNS] ✅ Sent cached DNS response for {qname} to {ip_layer.src}.")
            return True

        # 3. Conditional Forwarding & Normal Forwarding
        target_dns_server = self._get_forward_dns_server(qname)

        # Use the find_route_function to get the default route and its interface
        default_route = find_route_function(target_dns_server)
        if not default_route:
            self.router_logger.log_message(f"[DNS] Cannot proxy query: No route found to {target_dns_server}.")
            return False

        outbound_iface_name = default_route.get("interface")
        if not outbound_iface_name:
            self.router_logger.log_message("[DNS] Cannot proxy query: No outbound interface specified in route.")
            return False

        # If the query came from the "external" interface and is going to the primary DNS, we don't proxy it.
        # This prevents loops and assumes the primary DNS server is on the WAN side.
        if inbound_iface == outbound_iface_name and target_dns_server == self.PRIMARY_DNS_SERVER:
            self.router_logger.log_message(
                f"[DNS] Not proxying DNS query from {inbound_iface.split('_')[-1]} (likely external traffic to primary DNS).")
            return False

        outbound_iface_config = router_interfaces.get(outbound_iface_name)
        if not outbound_iface_config:
            self.router_logger.log_message(
                f"[DNS] Cannot proxy query: Outbound interface {outbound_iface_name.split('_')[-1]} config missing.")
            return False

        key = (ip_layer.src, udp_layer.sport, dns_layer.id)
        with self._lock:
            self._pending_requests[key] = {
                "original_mac_src": packet[Ether].src if packet.haslayer(Ether) else None,
                "inbound_iface": inbound_iface
            }

        self.router_logger.log_message(
            f"[DNS] ➡️  Proxying query for {qname} from {ip_layer.src} on {inbound_iface.split('_')[-1]} to {target_dns_server}"
        )

        modified_packet = packet.copy()
        modified_packet[IP].src = outbound_iface_config['ip_addr']
        modified_packet[IP].dst = target_dns_server

        # Handle Layer 2 for physical vs. loopback interfaces
        if packet.haslayer(Ether) and not (
                "loopback" in outbound_iface_name.lower() or "lo" == outbound_iface_name.lower()):
            modified_packet[Ether].src = outbound_iface_config['mac']
            gateway_ip = default_route.get("next_hop")
            target_mac = get_mac_function(gateway_ip, outbound_iface_name) if gateway_ip else None

            if not target_mac:
                self.router_logger.log_message(f"[DNS] Could not resolve gateway MAC for {gateway_ip}. Dropping query.")
                with self._lock:
                    self._pending_requests.pop(key, None)
                return True
            modified_packet[Ether].dst = target_mac
        elif packet.haslayer(Ether) and (
                "loopback" in outbound_iface_name.lower() or "lo" == outbound_iface_name.lower()):
            # For loopback, remove Ether layer if present and let Scapy handle it
            modified_packet = modified_packet[IP] / modified_packet[UDP] / modified_packet[DNS]
        else:
            # If original packet had no Ether, keep it that way (e.g., if it originated on loopback)
            pass

        del modified_packet[IP].chksum
        del modified_packet[UDP].chksum

        try:
            packet_writer.queue_packet(modified_packet, outbound_iface_name)
        except Exception as e:
            self.router_logger.log_message(f"[DNS] Failed to send proxied query: {e}")
            with self._lock:
                self._pending_requests.pop(key, None)
        return True

    def handle_response(self, packet, router_interfaces: dict, packet_writer):
        """
        Processes a DNS response, rewriting and forwarding it to the original client.
        Returns True if the packet was handled, False otherwise.
        """
        if not (packet.haslayer(DNS) and packet[DNS].qr == 1):
            return False

        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet[DNS]
        key = (ip_layer.dst, udp_layer.dport, dns_layer.id)  # Key is based on the original query's src/sport
        qname = dns_layer.qd.qname.decode() if dns_layer.qd and dns_layer.qd.qname else "unknown"

        with self._lock:
            original_request = self._pending_requests.pop(key, None)

        if original_request:
            self.router_logger.log_message(
                f"[DNS] ⬅️  Routing response for {qname} to {key[0]} on {original_request['inbound_iface'].split('_')[-1]}"
            )

            # Add to cache before modifying the packet for forwarding
            self._add_to_cache(qname, packet)

            response_iface_name = original_request["inbound_iface"]
            response_iface_config = router_interfaces.get(response_iface_name)
            if not response_iface_config:
                self.router_logger.log_message(
                    f"[DNS] Response interface {response_iface_name.split('_')[-1]} config missing.")
                return True  # Indicate handled, but couldn't send

            modified_packet = packet.copy()
            modified_packet[IP].src = response_iface_config['ip_addr']  # Router's IN IP
            modified_packet[IP].dst = key[0]  # Original client IP

            # Handle Layer 2 for physical vs. loopback interfaces
            if original_request["original_mac_src"] and not (
                    "loopback" in response_iface_name.lower() or "lo" == response_iface_name.lower()):
                modified_packet[Ether].src = response_iface_config['mac']
                modified_packet[Ether].dst = original_request["original_mac_src"]
            elif original_request["original_mac_src"] is None and (
                    "loopback" in response_iface_name.lower() or "lo" == response_iface_name.lower()):
                # Packet originated from loopback, no Ether needed for response
                modified_packet = modified_packet[IP] / modified_packet[UDP] / modified_packet[DNS]
            else:
                # If original packet had Ether, but we don't have original_mac_src (e.g., error),
                # or if it's a physical interface but no original MAC. This case needs careful handling.
                # For simplicity, if we don't have a valid dst MAC, drop it, or log a warning.
                self.router_logger.log_message(
                    f"[DNS] WARNING: Cannot send DNS response to {key[0]} on {response_iface_name.split('_')[-1]}: Missing original MAC or incompatible L2.")
                return True

            del modified_packet[IP].chksum
            del modified_packet[UDP].chksum

            try:
                packet_writer.queue_packet(modified_packet, response_iface_name)
            except Exception as e:
                self.router_logger.log_message(f"[DNS] Failed to send proxied response: {e}")
            return True
        return False


class ARPManager:
    """
    Manages ARP resolution, caching, and related ARP operations for the router.
    Enhanced with Gratuitous ARP and a placeholder for ARP Snooping/Inspection.
    """

    def __init__(self, router_logger, packet_writer, cache_timeout_seconds=300):
        """
        Initializes the ARP Manager.
        Args:
            router_logger: The logger instance for logging messages.
            packet_writer: The PacketWriter instance for sending packets.
            cache_timeout_seconds (int): How long a cache entry is valid.
        """
        self.router_logger = router_logger
        self.packet_writer = packet_writer  # Used for sending Gratuitous ARP
        self._arp_cache = {}  # Maps IP -> (MAC, timestamp)
        self._arp_cache_lock = threading.Lock()
        self.CACHE_TIMEOUT = cache_timeout_seconds

        # ARP Snooping/Inspection (Placeholder)
        self._trusted_ports = set()  # Example: {'Ethernet_IN_Full_Name'}
        self._static_arp_entries = {}  # {IP: MAC} for trusted static entries

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

    def _perform_arp_inspection(self, pkt: Packet, inbound_iface: str) -> bool:
        """
        Placeholder for ARP Snooping/Inspection.
        Returns True if packet is valid, False if it should be dropped.
        """
        if not pkt.haslayer(ARP):
            return True  # Not an ARP packet, pass

        arp_layer = pkt[ARP]
        sender_ip = arp_layer.psrc
        sender_mac = arp_layer.hwsrc

        # Check static ARP entries first (highest priority)
        if sender_ip in self._static_arp_entries and self._static_arp_entries[sender_ip].lower() != sender_mac.lower():
            self.router_logger.log_message(
                f"[ARP][INSPECT] 🚫 Blocked ARP from {sender_mac} for {sender_ip} on {inbound_iface.split('_')[-1]}: Static entry conflict ({self._static_arp_entries[sender_ip]}).")
            return False

        # If the port is not trusted, we might apply stricter checks
        if inbound_iface not in self._trusted_ports:
            # Example: Prevent ARP replies from untrusted ports if we don't know the mapping
            # or if it's an unsolicited ARP reply for a critical IP (e.g., gateway).
            # This is complex and requires knowledge of valid IP-MAC bindings.
            if arp_layer.op == 2:  # ARP Reply
                # Basic check: if sender_ip is one of our router's IPs, ensure sender_mac matches our MAC
                # (This check is implicitly done in the main router logic, but good to have here too)
                # More advanced: check against DHCP snooping table if available
                pass  # For now, allow replies on untrusted ports, but log

            # Prevent gratuitous ARP from untrusted ports for IPs we didn't assign or don't expect.
            # This requires more context (e.g., knowing assigned DHCP IPs).
            if arp_layer.op == 1 and arp_layer.psrc == arp_layer.pdst:  # Gratuitous ARP
                self.router_logger.log_message(
                    f"[ARP][INSPECT] ⚠️ Received Gratuitous ARP from {sender_mac} for {sender_ip} on untrusted port {inbound_iface.split('_')[-1]}.")
                # In a real system, you might block this if the IP is not expected on this port.

        return True  # Packet passed inspection (for now)

    def resolve(self, ip_address: str, iface: str) -> str | None:
        """
        Resolves an IP address to a MAC address using the ARP protocol.
        Checks the cache first. If the entry is not found or is stale, it sends a new ARP request.
        """
        ip_address = ip_address.strip()  # Normalize input

        # If destination is loopback, no ARP is needed. Return a dummy MAC or None.
        if ipaddress.ip_address(ip_address).is_loopback:
            self.router_logger.log_message(f"[ARP] Skipping ARP for loopback IP {ip_address}.")
            return "00:00:00:00:00:00"  # A placeholder, as L2 isn't strictly needed for loopback

        # --- Check static ARP entries first ---
        if ip_address in self._static_arp_entries:
            self.router_logger.log_message(
                f"[ARP] Static ARP hit for {ip_address} -> {self._static_arp_entries[ip_address]}")
            return self._static_arp_entries[ip_address]

        # --- Check dynamic cache ---
        with self._arp_cache_lock:
            cached_entry = self._arp_cache.get(ip_address)
            if cached_entry:
                mac, timestamp = cached_entry
                if time.time() - timestamp < self.CACHE_TIMEOUT:
                    self.router_logger.log_message(f"[ARP] Cache hit for {ip_address} -> {mac}")
                    return mac
                else:
                    self.router_logger.log_message(f"[ARP] Stale cache entry for {ip_address}. Re-resolving...")
            else:
                self.router_logger.log_message(f"[ARP] Cache miss for {ip_address}. Sending ARP request...")

        # --- Send ARP request ---
        try:
            # Need to get router's own IP and MAC for the interface to send ARP from
            # This requires the ARPManager to have access to the interfaces_config or a way to query it.
            # For now, relying on srp which should handle source MAC/IP automatically.
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                iface=iface,
                verbose=0
            )

            if ans:
                resolved_mac = ans[0][1].hwsrc
                with self._arp_cache_lock:
                    self._arp_cache[ip_address] = (resolved_mac, time.time())
                self.router_logger.log_message(f"[ARP] ✅ Resolved {ip_address} to {resolved_mac}")
                return resolved_mac
            else:
                self.router_logger.log_message(f"[ARP] ⚠️ No ARP reply for {ip_address} on {iface.split('_')[-1]}")
                return None
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Exception while resolving {ip_address}: {e}")
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
        self.packet_writer.queue_packet(grat_arp, iface)

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
    Enhanced with lease persistence and DHCP relay agent capabilities.
    """

    # Removed LEASE_FILE as leases will now be in-memory only

    def __init__(self, router_logger, packet_writer, router_in_interface_name: str, dhcp_pool_start: str,
                 dhcp_pool_end: str, interfaces_config: dict, dhcp_relay_target_ip: str = None):
        self.logger = router_logger
        self.packet_writer = packet_writer
        self.in_iface = router_in_interface_name  # This is the full Scapy interface name (e.g., '\Device\NPF_{...}')
        self._interfaces_config = interfaces_config  # Reference to the router's central interface config

        self.lease_pool_start = ipaddress.IPv4Address(dhcp_pool_start)
        self.lease_pool_end = ipaddress.IPv4Address(dhcp_pool_end)
        self._leases: Dict[
            str, Tuple[ipaddress.IPv4Address, float]] = {}  # Key: client_mac (str) -> (assigned_ip, expiry_time)
        self._lease_lock = threading.Lock()
        self.LEASE_DURATION_SECONDS = 3600  # 1 hour default lease
        self._stop_event = threading.Event()
        self._cleanup_thread = None

        self.dhcp_relay_target_ip = dhcp_relay_target_ip  # If set, act as relay agent
        self.logger.log_message(
            f"[DHCP] Server initialized. Relay target: {self.dhcp_relay_target_ip if self.dhcp_relay_target_ip else 'None'}")
        # Removed _load_leases() call as leases are now in-memory only

    # Removed _load_leases method

    # Removed _save_leases method

    def start(self):
        """Starts the DHCP server's cleanup thread."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_leases_loop, daemon=True, name="DHCPLeaseCleanup")
        self._cleanup_thread.start()
        self.logger.log_message("[DHCP] Cleanup thread started.")

    def stop(self):
        """Stops the DHCP server's cleanup thread gracefully."""
        self._stop_event.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        # Removed _save_leases() call as leases are now in-memory only
        self.logger.log_message("[DHCP] Server stopped.")

    def _cleanup_leases_loop(self):
        """Periodically removes expired DHCP leases."""
        while not self._stop_event.is_set():
            now = time.time()
            # leases_changed = False # No longer needed as we don't save to file
            with self._lease_lock:
                expired_macs = [mac for mac, (ip, expiry) in self._leases.items() if expiry <= now]
                for mac in expired_macs:
                    ip, _ = self._leases.pop(mac)
                    self.logger.log_message(f"[DHCP] 🗑️ Lease for {ip} (MAC: {mac}) expired and removed.")
                    # leases_changed = True # No longer needed
            # if leases_changed: # No longer needed
            #     self._save_leases() # No longer needed
            self._stop_event.wait(60)  # Check every minute

    def _assign_ip(self, client_mac: str) -> ipaddress.IPv4Address | None:
        """Assigns an available IP address from the pool, or reuses an existing one."""
        with self._lease_lock:
            # Check if client already has a lease
            if client_mac in self._leases:
                assigned_ip, _ = self._leases[client_mac]
                # Update expiry for existing lease if requested (e.g., in a RENEW or REBIND)
                self._leases[client_mac] = (assigned_ip, time.time() + self.LEASE_DURATION_SECONDS)
                self.logger.log_message(f"[DHCP] Re-assigned {assigned_ip} to {client_mac}")
                return assigned_ip

            # Find next available IP
            for i in range(0, int(self.lease_pool_end) - int(self.lease_pool_start) + 1):
                potential_ip = self.lease_pool_start + i
                # Check if potential_ip is already leased to *another* MAC
                is_taken = False
                for mac, (ip, _) in self._leases.items():
                    if ip == potential_ip:
                        is_taken = True
                        break
                if not is_taken:
                    self._leases[client_mac] = (potential_ip, time.time() + self.LEASE_DURATION_SECONDS)
                    self.logger.log_message(f"[DHCP] Assigned new IP {potential_ip} to {client_mac}")
                    # Removed _save_leases() call as leases are now in-memory only
                    return potential_ip
        self.logger.log_message("[DHCP] ❌ No available IP addresses in pool.")
        return None

    def handle_packet(self, pkt: Packet, inbound_iface: str, find_route_function) -> bool:
        """
        Handles incoming DHCP packets (DISCOVER, REQUEST).
        Returns True if the packet was a DHCP packet handled by the server.
        """
        # Ensure we are processing on the designated IN interface
        if inbound_iface != self.in_iface:
            return False

        # Get router's own IP and MAC for the IN interface from the config
        in_iface_config = self._interfaces_config.get(self.in_iface)
        if not in_iface_config:
            self.logger.log_message(f"[DHCP] Error: IN interface '{self.in_iface}' not found in configuration.")
            return False

        router_in_ip = in_iface_config.get("ip_addr")
        router_in_mac = in_iface_config.get("mac")

        if not router_in_ip or not router_in_mac:
            self.logger.log_message(f"[DHCP] Error: IN interface '{self.in_iface}' missing IP or MAC in configuration.")
            return False

        if not pkt.haslayer(DHCP) or not pkt.haslayer(UDP) or pkt[UDP].dport != 67:
            return False

        bootp_layer = pkt[BOOTP]
        dhcp_layer = pkt[DHCP]
        # Scapy's chaddr can be bytes or string; decode if bytes and strip nulls
        client_mac = bootp_layer.chaddr.decode('ascii').strip('\x00') if isinstance(bootp_layer.chaddr,
                                                                                    bytes) else bootp_layer.chaddr.strip(
            '\x00')
        dhcp_message_type = None
        for opt in dhcp_layer.options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                dhcp_message_type = opt[1]
                break

        if not dhcp_message_type:
            self.logger.log_message(
                f"[DHCP] Received DHCP packet from {client_mac} but no message-type option. Ignoring.")
            return True  # Still handled it by logging and ignoring.

        self.logger.log_message(
            f"[DHCP] 📨 Received DHCP {dhcp_message_type} from {client_mac} (xid: {bootp_layer.xid})")

        # --- DHCP Relay Agent Logic ---
        if self.dhcp_relay_target_ip:
            # If a DHCP relay target is configured, forward the request
            self.logger.log_message(
                f"[DHCP] Acting as DHCP Relay Agent. Forwarding {dhcp_message_type} to {self.dhcp_relay_target_ip}")

            # Construct DHCP Relay packet
            relay_pkt = pkt.copy()
            relay_pkt[IP].src = router_in_ip  # Router's IP on the incoming interface
            relay_pkt[IP].dst = self.dhcp_relay_target_ip
            relay_pkt[UDP].sport = 67
            relay_pkt[UDP].dport = 67
            relay_pkt[BOOTP].giaddr = router_in_ip  # Gateway IP address

            # Ensure Ether layer is correct for outbound interface
            # Need to find route to DHCP server to get outbound interface and next hop MAC
            route_to_dhcp_server = find_route_function(self.dhcp_relay_target_ip)
            if not route_to_dhcp_server:
                self.logger.log_message(
                    f"[DHCP] ❌ No route to DHCP relay target {self.dhcp_relay_target_ip}. Dropping relayed packet.")
                return True

            outbound_iface_for_relay = route_to_dhcp_server["interface"]
            outbound_iface_config = self._interfaces_config.get(outbound_iface_for_relay)
            if not outbound_iface_config:
                self.logger.log_message(
                    f"[DHCP] ❌ Outbound interface config missing for DHCP relay: {outbound_iface_for_relay.split('_')[-1]}. Dropping.")
                return True

            relay_pkt[Ether].src = outbound_iface_config["mac"]
            # For simplicity, assuming direct connection or next hop handled by general forwarding
            # In a real scenario, you'd need ARP resolution for the next hop.
            # For now, we'll let the main router's _forward_general_ip_packet handle L2
            # by setting dst to broadcast for DHCP or specific MAC if known.
            relay_pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"  # DHCP requests are often broadcast at L2

            # Queue the relayed packet
            self.packet_writer.queue_packet(relay_pkt, outbound_iface_for_relay)
            self.logger.log_message(f"[DHCP] ✅ Relayed DHCP {dhcp_message_type} to {self.dhcp_relay_target_ip}.")
            return True  # Handled by relay agent

        # --- DHCP Server Logic (if not acting as relay) ---
        if dhcp_message_type == 1:  # DHCP Discover
            assigned_ip = self._assign_ip(client_mac)
            if assigned_ip:
                # Common DHCP Options:
                # 1 (subnet_mask)
                # 3 (router/gateway)
                # 6 (DNS servers)
                # 15 (domain_name)
                # 42 (NTP servers)
                # 51 (lease_time)
                # 54 (server_identifier)
                dhcp_options = [
                    ("message-type", "offer"),
                    ("subnet_mask", "255.255.255.0"),  # Assuming /24 for simplicity
                    ("router", router_in_ip),  # Default Gateway
                    ("name_server", router_in_ip),  # Point to router for DNS proxy
                    ("lease_time", self.LEASE_DURATION_SECONDS),
                    ("server_identifier", router_in_ip),  # Our IP as DHCP server
                    ("ntp_server", router_in_ip),  # Our IP as NTP server (if implemented)
                    "end"
                ]
                offer = Ether(src=router_in_mac, dst=pkt[Ether].src) / \
                        IP(src=router_in_ip, dst='255.255.255.255') / \
                        UDP(sport=67, dport=68) / \
                        BOOTP(op='BOOTP_REPLY',
                              xid=bootp_layer.xid,
                              yiaddr=assigned_ip,  # 'Your' IP address
                              siaddr=router_in_ip,  # Server IP
                              chaddr=bootp_layer.chaddr) / \
                        DHCP(options=dhcp_options)
                self.packet_writer.queue_packet(offer, self.in_iface)
                self.logger.log_message(f"[DHCP] ✅ Sent DHCP Offer for {assigned_ip} to {client_mac}")
            else:
                self.logger.log_message(f"[DHCP] 🚫 No IP available for {client_mac}, dropping Discover.")
            return True

        elif dhcp_message_type == 3:  # DHCP Request
            requested_ip = None
            for opt in dhcp_layer.options:
                if isinstance(opt, tuple) and opt[0] == 'requested_addr':
                    requested_ip = ipaddress.IPv4Address(opt[1])
                    break

            # Validate requested_ip if it exists, otherwise assign
            current_assigned_ip = self._leases.get(client_mac, (None, None))[0]

            if not requested_ip or requested_ip == current_assigned_ip:
                # Client is requesting its current IP or no specific IP
                assigned_ip = self._assign_ip(client_mac)  # This also updates lease time
            else:
                # Client is requesting a new IP or one it had before (could be from another server)
                # For simplicity, we'll try to assign it; in a real DHCP server, more complex logic (conflict detection)
                assigned_ip = self._assign_ip(client_mac)
                if assigned_ip and requested_ip != assigned_ip:
                    self.logger.log_message(
                        f"[DHCP] ⚠️ Client {client_mac} requested {requested_ip} but assigned {assigned_ip}.")

            if assigned_ip:
                dhcp_options = [
                    ("message-type", "ack"),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", router_in_ip),
                    ("name_server", router_in_ip),
                    ("lease_time", self.LEASE_DURATION_SECONDS),
                    ("server_identifier", router_in_ip),
                    ("ntp_server", router_in_ip),
                    "end"
                ]
                ack = Ether(src=router_in_mac, dst=pkt[Ether].src) / \
                      IP(src=router_in_ip, dst='255.255.255.255') / \
                      UDP(sport=67, dport=68) / \
                      BOOTP(op='BOOTP_REPLY',
                            xid=bootp_layer.xid,
                            yiaddr=assigned_ip,
                            siaddr=router_in_ip,
                            chaddr=bootp_layer.chaddr) / \
                      DHCP(options=dhcp_options)
                self.packet_writer.queue_packet(ack, self.in_iface)
                self.logger.log_message(f"[DHCP] ✅ Sent DHCP ACK for {assigned_ip} to {client_mac}")
            else:
                # No IP available, send NAK (or simply drop)
                nak = Ether(src=router_in_mac, dst=pkt[Ether].src) / \
                      IP(src=router_in_ip, dst='255.255.255.255') / \
                      UDP(sport=67, dport=68) / \
                      BOOTP(op='BOOTP_REPLY',
                            xid=bootp_layer.xid,
                            chaddr=bootp_layer.chaddr) / \
                      DHCP(options=[("message-type", "nak"), "end"])
                self.packet_writer.queue_packet(nak, self.in_iface)
                self.logger.log_message(f"[DHCP] 🚫 Sent DHCP NAK to {client_mac} (no IP available or valid).")
            return True
        # Add handling for other DHCP message types (DECLINE, RELEASE, INFORM) if desired.
        return True  # Processed as DHCP, even if not fully handled.


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
            hash_components = [packet[IP].src, packet[IP].dst]
            if packet.haslayer(TCP):
                hash_components.extend([packet[TCP].sport, packet[TCP].dport])
            elif packet.haslayer(UDP):
                hash_components.extend([packet[UDP].sport, packet[UDP].dport])

            # Use a simple hash function to pick an interface
            hash_val = hash(tuple(hash_components))
            selected_index = hash_val % len(self._outbound_interfaces)
            selected_iface = self._outbound_interfaces[selected_index]

            self.logger.log_message(
                f"[OutboundLB] Selected interface {selected_iface.split('_')[-1]} for flow {packet[IP].src} -> {packet[IP].dst}.")
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
            hash_components = [packet[IP].src, packet[IP].dst]
            if packet.haslayer(TCP):
                hash_components.extend([packet[TCP].sport, packet[TCP].dport])
            elif packet.haslayer(UDP):
                hash_components.extend([packet[UDP].sport, packet[UDP].dport])

            hash_val = hash(tuple(hash_components))
            selected_index = hash_val % len(active_members)
            selected_member = active_members[selected_index]

            self.logger.log_message(
                f"[LAG] Selected member {selected_member.split('_')[-1]} for LAG '{lag_name}' flow {packet[IP].src} -> {packet[IP].dst}.")
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
        self._rules: List[Dict[str, Any]] = [
        {'action': 'permit', 'protocol': 'any', 'src_ip': '192.168.0.0/16', 'dst_ip': '192.168.0.0/16',
         'src_port': 'any', 'dst_port': 'any'},
        {'action': 'permit', 'protocol': 'tcp', 'src_ip': '192.168.0.0/16', 'dst_ip': 'any',
         'src_port': 'any', 'dst_port': '80'},
        {'action': 'permit', 'protocol': 'tcp', 'src_ip': '192.168.0.0/16', 'dst_ip': 'any',
         'src_port': 'any', 'dst_port': '443'},
        {'action': 'permit', 'protocol': 'udp', 'src_ip': '192.168.0.0/16', 'dst_ip': 'any',
         'src_port': 'any', 'dst_port': '53'},
        {'action': 'permit', 'protocol': 'icmp', 'src_ip': '192.168.0.0/16', 'dst_ip': 'any',
         'src_port': 'any', 'dst_port': 'any'},
        {'action': 'permit', 'protocol': 'tcp', 'src_ip': 'any', 'dst_ip': '192.168.0.0/16',
         'src_port': 'any', 'dst_port': '1024-65535'},
        {'action': 'deny', 'protocol': 'any', 'src_ip': 'any', 'dst_ip': '192.168.0.0/16',
         'src_port': 'any', 'dst_port': 'any'},]

        self._rule_lock = threading.Lock()
        self.logger.log_message("[Firewall] Manager initialized.")

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
            self.logger.log_message(f"[Firewall] ❌ Invalid action '{action}'. Must be 'permit' or 'deny'.")
            return False
        if rule['protocol'] not in ['tcp', 'udp', 'icmp', 'any']:
            self.logger.log_message(
                f"[Firewall] ❌ Invalid protocol '{protocol}'. Must be 'tcp', 'udp', 'icmp', or 'any'.")
            return False

        # IP address validation (basic)
        for ip_field in ['src_ip', 'dst_ip']:
            if rule[ip_field] != 'any':
                try:
                    ipaddress.ip_network(rule[ip_field], strict=False)  # Allows both host and network
                except ValueError:
                    self.logger.log_message(
                        f"[Firewall] ❌ Invalid IP address/network format for {ip_field}: {rule[ip_field]}.")
                    return False

        # Port validation (basic)
        for port_field in ['src_port', 'dst_port']:
            if rule[port_field] != 'any':
                if isinstance(rule[port_field], int):
                    if not (0 <= rule[port_field] <= 65535):
                        self.logger.log_message(
                            f"[Firewall] ❌ Invalid port number for {port_field}: {rule[port_field]}. Must be 0-65535.")
                        return False
                elif isinstance(rule[port_field], str) and '-' in rule[port_field]:
                    try:
                        start, end = map(int, rule[port_field].split('-'))
                        if not (0 <= start <= end <= 65535):
                            self.logger.log_message(
                                f"[Firewall] ❌ Invalid port range for {port_field}: {rule[port_field]}. Must be 0-65535 and start <= end.")
                            return False
                    except ValueError:
                        self.logger.log_message(
                            f"[Firewall] ❌ Invalid port range format for {port_field}: {rule[port_field]}. Use 'start-end'.")
                        return False
                else:
                    self.logger.log_message(
                        f"[Firewall] ❌ Invalid port format for {port_field}: {rule[port_field]}. Use integer, 'start-end', or 'any'.")
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
        if not packet.haslayer(IP):
            return True  # Non-IP packets are not filtered by this firewall (e.g., ARP)

        ip_layer = packet[IP]
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
                        self.logger.log_message(f"[Firewall] ✅ Packet permitted by rule {i}: {rule}")
                        return True
                    else:  # deny
                        self.logger.log_message(f"[Firewall] 🚫 Packet DENIED by rule {i}: {rule}")
                        return False

            return True

class PythonRouterManager:
    """
    Manages sniffing packets on multiple interfaces and routing them
    based on a simplified routing table. Self-contained for interface discovery and IP assignment.
    """

    # --- Configuration Defaults (used if dynamic assignment fails or as starting points) ---
    DEFAULT_IN_IFACE_FRIENDLY_NAME = "Ethernet"
    DEFAULT_OUT_IFACE_FRIENDLY_NAME = "Wi-Fi"
    # Friendly name pattern for loopback, can be 'Loopback' or empty depending on OS/driver
    DEFAULT_LOOPBACK_IFACE_FRIENDLY_NAME = "Loopback"

    # Default private IP ranges to try for the IN interface if auto-picking
    PRIVATE_SUBNETS_TO_TRY = [
        "192.168.100.0/24", "192.168.101.0/24", "192.168.102.0/24", "192.168.103.0/24",
        "10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24",
        "172.16.10.0/24", "172.16.11.0/24", "172.16.12.0/24"
    ]

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self._interfaces_config = {}  # Stores config for all physical interfaces
        self.interface_in_full_name = None
        self.interface_in_friendly_name = None
        self.interface_out_full_name = None  # Primary OUT interface
        self.interface_out_friendly_name = None
        self.interface_loopback_full_name = None
        self.router_ip_in = None
        self.router_ip_out = None
        self.router_gateway_out_ip = None

        self._sniff_threads = {}
        self._stop_sniffing_event = threading.Event()
        self._tshark_path = None
        self._discovered_tshark_interfaces = []

        # Instantiate all specialized managers
        self.packet_writer = PacketWriter(router_logger)
        self.dns_manager = DNSManager(router_logger)
        self.rip_manager = RIPManager(router_logger)
        self.nat_manager = None  # Initialized after public IP is known
        self.tls_proxy_manager = TLSProxyManager(router_logger)
        self.arp_manager = ARPManager(router_logger, self.packet_writer)
        self.handshake_manager = None
        self.igmp_manager = IGMPManager(router_logger, self.packet_writer)
        self.icmp_manager = ICMPManager(router_logger, self.packet_writer, self._interfaces_config)
        self.dhcp_server = None
        self.outbound_load_balancer = OutboundLoadBalancer(router_logger)  # New: Outbound Load Balancer
        self.lag_manager = LinkAggregationManager(router_logger)  # New: Link Aggregation Manager
        self.firewall_manager = FirewallManager(router_logger)  # New: Firewall Manager


        self.router_logger.log_message("[RouterManager] Orchestrator Initialized.")

    def _get_tshark_path(self) -> str | None:
        """Discover the path to tshark.exe (copied from your WiresharkManager)."""
        if getattr(sys, "frozen", False):
            tshark_exe = os.path.join(sys._MEIPASS, "tools", "Wireshark", "tshark.exe")
            if os.path.exists(tshark_exe):
                return tshark_exe

        server_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(server_dir)
        tools_dir = os.path.join(project_root, "client", "tools", "Wireshark")
        candidate = os.path.join(tools_dir, "tshark.exe")
        if os.path.exists(candidate):
            return candidate

        system_tshark = shutil.which("tshark")
        if system_tshark:
            return system_tshark

        self.router_logger.log_message(
            "[RouterManager] Error: tshark.exe not found. Cannot discover interfaces via tshark -D.")
        return None

    def _initialize_interface_discovery(self):
        """Discover network interfaces using tshark -D and store them internally."""
        self._tshark_path = self._get_tshark_path()
        if not self._tshark_path:
            self.router_logger.log_message("[RouterManager] Cannot perform interface discovery: tshark not found.")
            return

        self.router_logger.log_message("[RouterManager] Discovering network interfaces via tshark -D...")
        try:
            proc = subprocess.run(
                [self._tshark_path, '-D'], capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            pattern = re.compile(r"(\d+)\.\s+([^(]+)(?:\((.*)\))?")
            interface_output_lines = proc.stdout.strip().split('\n')

            for line in interface_output_lines:
                match = pattern.match(line)
                if match:
                    full_name = match.group(2).strip()
                    friendly_name = match.group(3) if match.group(3) else ""

                    self._discovered_tshark_interfaces.append({
                        'id': match.group(1),
                        'full_name': full_name,
                        'friendly_name': friendly_name
                    })
            self.router_logger.log_message(
                f"[RouterManager] Discovered {len(self._discovered_tshark_interfaces)} interfaces via tshark.")
        except Exception as e:
            self.router_logger.log_message(f"[RouterManager] Error during tshark interface discovery: {e}")

    def _configure_firewall_rules(self):
        """
        Adds firewall rules to allow traffic on the OUT interface.
        Note: Loopback doesn't typically need explicit firewall rules
        for routing traffic, as it's local to the host.
        """
        try:
            if not self.interface_out_friendly_name:
                self.router_logger.log_message(
                    "[Firewall] Skipping firewall rule configuration: OUT interface not found.")
                return

            for direction_str in ["Outbound", "Inbound"]:
                rule_name = f"PythonRouter-Allow-{direction_str}-{self.interface_out_friendly_name}"
                direction_flag = "Out" if direction_str == "Outbound" else "In"

                # Check if rule already exists to prevent duplicates on successive runs
                # Use a specific PowerShell command that returns null/empty if rule doesn't exist
                check_rule_cmd = ["powershell.exe", "-Command",
                                  f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"]
                check_result = subprocess.run(check_rule_cmd, capture_output=True, text=True,
                                              creationflags=subprocess.CREATE_NO_WINDOW)

                if check_result.stdout.strip() == rule_name:
                    self.router_logger.log_message(f"[Firewall] Rule already exists: {rule_name}. Skipping.")
                    continue

                ps_command = [
                    "powershell.exe",
                    "-Command",
                    f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction {direction_flag} "
                    f"-InterfaceAlias '{self.interface_out_friendly_name}' -Action Allow -Profile Any -Protocol Any"
                ]

                result = subprocess.run(ps_command, capture_output=True, text=True,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    self.router_logger.log_message(f"[Firewall] ✅ Rule added: {rule_name}")
                else:
                    self.router_logger.log_message(
                        f"[Firewall] ⚠️ Failed to add rule: {rule_name}. STDERR: {result.stderr.strip()}")
        except Exception as e:
            self.router_logger.log_message(f"[Firewall] ❌ Unexpected error adding rules: {e}")

    def _remove_firewall_rules(self):
        """Removes any firewall rules added by this router."""
        try:
            # Using a wildcard pattern to ensure all rules created by this router are removed
            rule_name_pattern = "PythonRouter-Allow-*"
            ps_command = ["powershell.exe", "-Command",
                          f"Remove-NetFirewallRule -DisplayName '{rule_name_pattern}' -ErrorAction SilentlyContinue"]
            result = subprocess.run(ps_command, capture_output=True, text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode == 0:
                # Check stdout for specific text indicating rules were found and removed
                if "No matching firewall rules found" not in result.stdout:
                    self.router_logger.log_message(f"[Firewall] 🧹 Removed rules matching: {rule_name_pattern}")
                else:
                    self.router_logger.log_message(f"[Firewall] No rules found to remove matching: {rule_name_pattern}")
            else:
                self.router_logger.log_message(
                    f"[Firewall] ⚠️ Failed to remove rules matching: {rule_name_pattern}. STDERR: {result.stderr.strip()}")
        except Exception as e:
            self.router_logger.log_message(f"[Firewall] ❌ Unexpected error removing rules: {e}")

    def _execute_netsh(self, full_netsh_command_args: list[str]) -> bool:
        """
        Helper to run netsh commands.
        Takes the full list of arguments *after* 'netsh interface ipv4'.
        """
        full_command = ["netsh", "interface", "ipv4"] + full_netsh_command_args
        try:
            self.router_logger.log_message(f"[Netsh] Executing: {' '.join(full_command)}")
            result = subprocess.run(
                full_command, capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.stdout: self.router_logger.log_message(f"[Netsh] STDOUT: {result.stdout.strip()}")
            return True
        except subprocess.CalledProcessError as e:
            self.router_logger.log_message(f"[Netsh] ERROR executing netsh (Return Code: {e.returncode}):")
            if e.stdout: self.router_logger.log_message(f"[Netsh] STDOUT: {e.stdout.strip()}")
            if e.stderr: self.router_logger.log_message(f"[Netsh] STDERR: {e.stderr.strip()}")
            self.router_logger.log_message(f"[Netsh] Command was: {' '.join(full_command)}")
            return False
        except FileNotFoundError:
            self.router_logger.log_message("[Netsh] ERROR: 'netsh' command not found. Is Windows installed correctly?")
            return False
        except Exception as e:
            self.router_logger.log_message(f"[Netsh] UNEXPECTED ERROR during netsh execution: {e}")
            return False

    def _assign_ip_to_interface(self, iface_friendly_name: str, ip_address: str, netmask: str,
                                gateway: str = "") -> bool:
        """Assigns a static IP and netmask (and optional gateway) to a specific interface using netsh."""
        self.router_logger.log_message(
            f"[RouterManager] Assigning IP {ip_address}/{netmask} to '{iface_friendly_name}'...")

        # Build the netsh command arguments in the correct order for 'set address'
        netsh_args = [
            "set", "address",
            f'name={iface_friendly_name}',
            "source=static",
            f"address={ip_address}",
            f"mask={netmask}"
        ]

        if gateway:
            netsh_args.append(f"gateway={gateway}")
            netsh_args.append("gwmetric=1")
        else:
            netsh_args.append("gateway=none")

        if not self._execute_netsh(netsh_args):
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Failed to assign IP {ip_address} to '{iface_friendly_name}'.")
            return False
        self.router_logger.log_message(
            f"[RouterManager] Successfully assigned IP {ip_address} to '{iface_friendly_name}'.")
        return True

    def _get_system_networks(self) -> list[ipaddress.IPv4Network]:
        """Gets all currently active IPv4 networks on the system using psutil."""
        active_networks = []
        try:
            for iface_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address and addr.netmask:  # Use socket.AF_INET
                        try:
                            network_obj = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                            active_networks.append(network_obj)
                        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                            self.router_logger.log_message(
                                f"[RouterManager] Warning: Could not parse network {addr.address}/{addr.netmask}: {e}")
        except Exception as e:
            self.router_logger.log_message(f"[RouterManager] Error getting system networks via psutil: {e}")
        return active_networks

    def _find_unused_private_subnet(self, existing_networks: list[ipaddress.IPv4Network],
                                    subnet_size: int = 24) -> str | None:
        """
        Finds the first available /24 private subnet from a predefined list that
        does not conflict with existing_networks.
        Returns IP address (e.g., '192.168.X.1') from the first available subnet.
        """
        self.router_logger.log_message("[RouterManager] Searching for an unused private subnet for IN interface...")
        for potential_network_str in self.PRIVATE_SUBNETS_TO_TRY:
            try:
                potential_network = ipaddress.ip_network(potential_network_str, strict=False)

                conflicts = False
                for existing_net in existing_networks:
                    if potential_network.overlaps(existing_net):
                        self.router_logger.log_message(
                            f"[RouterManager] Subnet {potential_network} conflicts with {existing_net}. Skipping.")
                        conflicts = True
                        break

                if not conflicts:
                    router_ip = str(potential_network.network_address + 1)
                    self.router_logger.log_message(
                        f"[RouterManager] Found unused subnet: {potential_network}. Router IN IP: {router_ip}")
                    return router_ip
            except ValueError as e:
                self.router_logger.log_message(
                    f"[RouterManager] Invalid potential subnet '{potential_network_str}': {e}")

        self.router_logger.log_message("[RouterManager] ERROR: No unused private subnet found from predefined list.")
        return None

    def _get_default_gateway_for_interface(self, iface_friendly_name: str) -> str | None:
        """
        Attempts to get the default gateway IP for a specific interface using PowerShell.
        (Windows specific: uses Get-NetRoute and Get-NetAdapter)
        """
        self.router_logger.log_message(f"[RouterManager] Discovering default gateway for '{iface_friendly_name}'...")
        try:
            ps_command = f"""
            $iface = Get-NetAdapter -Name "{iface_friendly_name}" -ErrorAction SilentlyContinue
            if ($iface) {{
                (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceIndex -eq $iface.IfIndex }}).NextHop | Select-Object -First 1
            }}
            """

            result = subprocess.run(
                ["powershell.exe", "-Command", ps_command],
                capture_output=True, text=True, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip():
                gateway_ip = result.stdout.strip()
                self.router_logger.log_message(
                    f"[RouterManager] Discovered gateway for '{iface_friendly_name}': {gateway_ip}")
                return gateway_ip
            else:
                self.router_logger.log_message(
                    f"[RouterManager] Could not discover gateway for '{iface_friendly_name}'. STDOUT: {result.stdout.strip()}, STDERR: {result.stderr.strip()}")
                return None
        except Exception as e:
            self.router_logger.log_message(
                f"[RouterManager] Error discovering gateway for '{iface_friendly_name}': {e}")
            return None

    def _auto_configure_interfaces(self):
        """
        Automatically finds and configures IN, OUT, and Loopback interfaces.
        Sets their IP addresses dynamically (for IN/OUT) and determines default gateway.
        """
        in_iface_info = None
        out_iface_info = None
        loopback_iface_info = None  # NEW: For loopback interface

        self.router_logger.log_message(
            "[RouterManager] Attempting to auto-configure IN, OUT, and Loopback interfaces...")

        for iface_info in self._discovered_tshark_interfaces:
            # Check for IN interface
            if self.DEFAULT_IN_IFACE_FRIENDLY_NAME.lower() in iface_info[
                'friendly_name'].lower() and in_iface_info is None:
                in_iface_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found IN interface: {self.DEFAULT_IN_IFACE_FRIENDLY_NAME} as {in_iface_info['full_name']}")

            # Check for OUT interface
            if self.DEFAULT_OUT_IFACE_FRIENDLY_NAME.lower() in iface_info[
                'friendly_name'].lower() and out_iface_info is None:
                out_iface_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found OUT interface: {self.DEFAULT_OUT_IFACE_FRIENDLY_NAME} as {out_iface_info['full_name']}")

            # NEW: Check for Loopback interface
            # Common names for loopback include 'Loopback', 'lo', or an empty friendly name with 'loopback' in full name
            if ("loopback" in iface_info['full_name'].lower() or \
                self.DEFAULT_LOOPBACK_IFACE_FRIENDLY_NAME.lower() in iface_info['friendly_name'].lower() or \
                iface_info['friendly_name'].lower() == "lo") and loopback_iface_info is None:
                loopback_iface_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found Loopback interface: {loopback_iface_info['full_name']} (Friendly: {loopback_iface_info['friendly_name']})")

            if in_iface_info is not None and out_iface_info is not None and loopback_iface_info is not None:
                break  # All found, exit loop

        # Handle cases where IN or OUT are not found
        if in_iface_info is None or out_iface_info is None:
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Could not auto-configure required interfaces ('{self.DEFAULT_IN_IFACE_FRIENDLY_NAME}' and '{self.DEFAULT_OUT_IFACE_FRIENDLY_NAME}').")
            self.router_logger.log_message(
                f"[RouterManager] Please check interface names and ensure they are active. Available: {[i['friendly_name'] for i in self._discovered_tshark_interfaces]}")

            self.interface_in_full_name = None
            self.interface_out_full_name = None
            self.interface_in_friendly_name = None
            self.interface_out_friendly_name = None
            self.mac_in = None
            self.mac_out = None
            self.interface_loopback_full_name = None  # Ensure loopback is also cleared on critical failure
            return False

        # Assign full and friendly names to instance attributes
        self.interface_in_full_name = in_iface_info['full_name']
        self.interface_in_friendly_name = in_iface_info['friendly_name']
        self.interface_out_full_name = out_iface_info['full_name']
        self.interface_out_friendly_name = out_iface_info['friendly_name']
        if loopback_iface_info:  # Assign if found
            self.interface_loopback_full_name = loopback_iface_info['full_name']

        # Step 2: Determine IP configurations for IN and OUT interfaces
        system_active_networks = self._get_system_networks()

        # For OUT interface: use its current IP config as router_ip_out
        current_out_ip = None
        current_out_netmask = None

        for addr in psutil.net_if_addrs().get(self.interface_out_friendly_name, []):
            if addr.family == socket.AF_INET:
                current_out_ip = addr.address
                current_out_netmask = addr.netmask
                break

        self._configure_firewall_rules()  # Configure firewall rules based on discovered OUT interface

        if current_out_ip and current_out_netmask:
            self.router_ip_out = current_out_ip
            self.router_netmask_out = current_out_netmask
            self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}",
                                                           strict=False)
            self.router_logger.log_message(
                f"[RouterManager] Using current IP for OUT interface '{self.interface_out_friendly_name}': {self.router_ip_out}/{self.router_netmask_out}")
        else:
            self.router_logger.log_message(
                f"[RouterManager] WARNING: Could not determine current IP for OUT interface '{self.interface_out_friendly_name}'. Attempting DHCP/dynamic configuration fallback.")
            # Fallback logic if current IP is not found - assign a new private IP or rely on DHCP
            # This is a bit unusual for a production WAN interface but ensures the router has an IP.
            # In a real scenario, you'd likely use DHCP client here or fail.
            unused_out_ip = self._find_unused_private_subnet(system_active_networks)
            if unused_out_ip:
                self.router_ip_out = unused_out_ip
                self.router_netmask_out = "255.255.255.0"
                self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}",
                                                               strict=False)
                self.router_logger.log_message(
                    f"[RouterManager] Dynamically assigned fallback IP for OUT interface '{self.interface_out_friendly_name}': {self.router_ip_out}/{self.router_netmask_out}")
            else:
                self.router_logger.log_message(
                    "[RouterManager] CRITICAL ERROR: Failed to assign any IP to OUT interface. Routing may not work.")
                return False  # Cannot proceed without OUT IP

        # Discover default gateway for the OUT interface (using friendly name)
        self.router_gateway_out_ip = self._get_default_gateway_for_interface(self.interface_out_friendly_name)

        # For IN interface: dynamically find an unused private subnet
        unused_in_ip = self._find_unused_private_subnet(system_active_networks)
        if unused_in_ip:
            self.router_ip_in = unused_in_ip
            self.router_netmask_in = "255.255.255.0"
            self.router_network_in = ipaddress.ip_network(f"{self.router_ip_in}/{self.router_netmask_in}", strict=False)
            self.router_logger.log_message(
                f"[RouterManager] Dynamically assigned IP for IN interface '{self.interface_in_friendly_name}': {self.router_ip_in}/{self.router_netmask_in}")
        else:
            self.router_logger.log_message(
                "[RouterManager] CRITICAL ERROR: Failed to assign IP to IN interface. Routing may not work.")
            return False  # Cannot proceed without IN IP

        # Step 3: Assign IPs to interfaces using OS commands (netsh for Windows)
        self.router_logger.log_message(
            "[RouterManager] Assigning IPs to interfaces via OS commands (Requires Admin). This may cause temporary network disruption.")

        # Assign IN interface IP (using its friendly name for netsh)
        if not self._assign_ip_to_interface(self.interface_in_friendly_name, self.router_ip_in, self.router_netmask_in):
            self.router_logger.log_message(
                f"[RouterManager] CRITICAL ERROR: Failed to assign IP to IN interface. Routing may not work.")
            return False

        # Assign OUT interface IP with its (discovered/fallback) gateway (using its friendly name for netsh)
        if not self._assign_ip_to_interface(self.interface_out_friendly_name, self.router_ip_out,
                                            self.router_netmask_out,
                                            self.router_gateway_out_ip):
            self.router_logger.log_message(
                f"[RouterManager] CRITICAL ERROR: Failed to assign IP to OUT interface. Routing may not work.")
            return False

        # Step 4: Update internal _interfaces_config with assigned IPs and MACs
        # Store configurations by full Scapy name
        self._interfaces_config[self.interface_in_full_name] = {
            'ip_addr': self.router_ip_in,
            'network': self.router_network_in,
            'mac': get_if_hwaddr(self.interface_in_full_name)
        }
        self._interfaces_config[self.interface_out_full_name] = {
            'ip_addr': self.router_ip_out,
            'network': self.router_network_out,
            'mac': get_if_hwaddr(self.interface_out_full_name),
            'is_default_gateway_iface': True
        }
        self.default_gateway_ip = self.router_gateway_out_ip

        # NEW: Add Loopback interface to config if found
        if self.interface_loopback_full_name:
            # Loopback usually has 127.0.0.1/8. MAC is typically '00:00:00:00:00:00' or similar virtual.
            loopback_ip = "127.0.0.1"
            loopback_netmask = "255.0.0.0"
            loopback_network = ipaddress.ip_network(f"{loopback_ip}/{loopback_netmask}", strict=False)

            # Attempt to get actual loopback MAC, but fall back to dummy if not available
            # Some platforms or virtual envs might not give a real MAC for loopback.
            try:
                loopback_mac = get_if_hwaddr(self.interface_loopback_full_name)
            except Exception:
                loopback_mac = "00:00:00:00:00:00"  # Dummy MAC for loopback

            self._interfaces_config[self.interface_loopback_full_name] = {
                'ip_addr': loopback_ip,
                'network': loopback_network,
                'mac': loopback_mac
            }
            self.router_logger.log_message(
                f"  Loopback Interface: '{self.interface_loopback_full_name}' (IP: {loopback_ip}/{loopback_netmask}, MAC: {loopback_mac})")

        # Get our own MAC addresses (re-get after IP assignment for certainty)
        self.mac_in = get_if_hwaddr(self.interface_in_full_name)
        self.mac_out = get_if_hwaddr(self.interface_out_full_name)

        # Add primary OUT interface to outbound load balancer
        self.outbound_load_balancer.add_outbound_interface(self.interface_out_full_name)

        self.router_logger.log_message(f"\n--- Python Router Configuration Summary (Dynamically Assigned) ---")
        self.router_logger.log_message(
            f"  IN Interface: '{self.interface_in_friendly_name}' (Full: {self.interface_in_full_name}, MAC: {self.mac_in}, IP: {self.router_ip_in}/{self.router_netmask_in})")
        self.router_logger.log_message(
            f"  OUT Interface: '{self.interface_out_friendly_name}' (Full: {self.interface_out_full_name}, MAC: {self.mac_out}, IP: {self.router_ip_out}/{self.router_netmask_out})")
        self.router_logger.log_message(
            f"  IN Network: {self.router_network_in}, OUT Network: {self.router_network_out}")
        self.router_logger.log_message(
            f"  External Gateway: {self.router_gateway_out_ip} via '{self.interface_out_friendly_name}'")
        self.router_logger.log_message(f"----------------------------------------------------------------")
        return True  # Configuration successful

    def add_interface(self, iface_name: str, ip_address: str, netmask: str) -> bool:
        """
        Adds a network interface to the router's configuration.
        This interface must have the given static IP and netmask.
        Returns True on success, False on failure.
        """
        try:
            current_mac = get_if_hwaddr(iface_name)  # Use full Scapy name for Scapy functions
            if not current_mac:
                self.router_logger.log_message(
                    f"[RouterManager] ERROR: Could not get MAC for {iface_name}. Interface may not exist or be active.")
                return False

            ip_obj = ipaddress.ip_address(ip_address)
            network_obj = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)

            self._interfaces_config[iface_name] = {  # Store config by full Scapy name
                'ip_addr': str(ip_obj),
                'network': network_obj,
                'mac': current_mac
            }
            self.router_logger.log_message(
                f"[RouterManager] Added interface to config: {iface_name} (IP: {ip_address}, Net: {network_obj})")
            return True
        except Exception as e:
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Failed to add interface {iface_name} to config: {e}")
            return False

    def set_default_gateway(self, gateway_ip: str, outbound_iface_name: str) -> bool:
        """
        Sets the default gateway IP and the interface through which to reach it.
        outbound_iface_name here is the full Scapy interface name.
        """
        if outbound_iface_name not in self._interfaces_config:
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Outbound interface '{outbound_iface_name}' not configured for default gateway.")
            return False

        self.default_gateway_ip = gateway_ip
        self._interfaces_config[outbound_iface_name]['is_default_gateway_iface'] = True
        self.router_logger.log_message(
            f"[RouterManager] Set default gateway: {gateway_ip} via {outbound_iface_name.split('_')[-1]}")
        return True

    def _start_single_sniffer(self, iface_name: str):
        """Starts a single sniffer thread for a given interface."""

        def sniffer_loop(name=iface_name):
            self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[-1]} starting...")

            try:
                sniff(
                    iface=name,
                    prn=lambda pkt: self._process_packet(pkt, name),
                    store=0,
                    promisc=True,
                    stop_filter=lambda p: self._stop_sniffing_event.is_set()
                )
            except Exception as e:
                # If a thread crashes, this will log it!
                self.router_logger.log_message(f"‼️ CRITICAL ERROR in sniffer thread for {name.split('_')[-1]}: {e}")
            finally:
                self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[-1]} has exited.")

        thread = threading.Thread(target=sniffer_loop, name=f"Sniffer-{iface_name.split('_')[-1]}", daemon=True)
        self._sniff_threads[iface_name] = thread
        thread.start()
        self.router_logger.log_message(f"[Router] Sniffing started on {iface_name.split('_')[-1]}.")

    def _process_packet(self, packet, inbound_iface: str):
        """Main packet processing pipeline."""
        try:  # Added try-except block for general packet processing errors
            # 0. Initial check for IP layer and ARP
            if not packet.haslayer(IP) and not packet.haslayer(ARP):
                return  # Not an IP or ARP packet, ignore

            # 1. ARP Snooping/Inspection (early drop if malicious)
            if packet.haslayer(ARP):
                if not self.arp_manager._perform_arp_inspection(packet, inbound_iface):
                    self.router_logger.log_message(
                        f"[Router] Dropped ARP packet due to inspection failure on {inbound_iface.split('_')[-1]}.")
                    return
                # ARP packets are typically handled by ARP manager itself, not forwarded
                # If it's an ARP reply for us, ARP manager will cache it. If it's a request, it might reply.
                # No further processing needed for ARP packets in the main IP pipeline.
                return

            # From here on, we expect an IP packet
            if not packet.haslayer(IP):
                return  # Should not happen if previous check passed, but defensive

            self.router_logger.log_message(f"CAPTURED on {inbound_iface.split('_')[-1]}: {packet.summary()}")

            # 3. Firewall (ACLs) - First line of defense for IP packets
            if not self.firewall_manager.process_packet(packet):
                self.router_logger.log_message(f"[Router] Packet DENIED by firewall on {inbound_iface.split('_')[-1]}.")
                return  # Packet dropped by firewall

            # 4. Handshake Manager (TCP state tracking)
            self.handshake_manager.handle_packet(packet, inbound_iface)

            # 5. ICMP Manager (Echo-Request, Destination Unreachable, Time Exceeded)
            if self.icmp_manager.handle_packet(packet, inbound_iface):
                return  # ICMP manager fully handled the packet

            # 6. DHCP Server/Relay
            if packet.haslayer(UDP) and (packet[UDP].dport == 67 or packet[UDP].sport == 67 or
                                         packet[UDP].dport == 68 or packet[UDP].sport == 68):
                if self.dhcp_server and self.dhcp_server.handle_packet(packet, inbound_iface,
                                                                       self.rip_manager.find_route):
                    return  # Packet handled by DHCP server/relay

            # 7. DNS Manager (Query/Response, Caching, Filtering, Conditional Forwarding)
            if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
                if self.dns_manager.handle_query(packet, inbound_iface, self._interfaces_config,
                                                 self.arp_manager.resolve,
                                                 self.rip_manager.find_route, self.packet_writer):
                    return
                if self.dns_manager.handle_response(packet, self._interfaces_config, self.packet_writer):
                    return

            # 8. IGMP Manager (Multicast Group Management)
            if packet.haslayer(IGMP):
                dst_ip = packet[IP].dst
                inbound_if_ip = self._interfaces_config.get(inbound_iface, {}).get("ip_addr")
                if (dst_ip == inbound_if_ip) or (ipaddress.ip_address(dst_ip).is_multicast):
                    self.igmp_manager.handle_packet(packet, inbound_iface)
                    return  # IGMP packets are usually processed locally, not forwarded

            # If not for the router, it's transit traffic to be forwarded
            dst_ip = packet[IP].dst
            router_ips = [cfg["ip_addr"] for cfg in self._interfaces_config.values() if "ip_addr" in cfg]
            is_for_router = any(dst_ip == ip for ip in router_ips)

            if is_for_router:
                # 9. RIP Manager (if for router's RIP process)
                if packet.haslayer(SimpleRIP):
                    self.rip_manager.handle_packet(packet, inbound_iface)
                    return

                # 10. NAT Manager (Inbound Translation for router's public IP)
                if self.nat_manager and self.nat_manager.translate_inbound(packet):
                    self.router_logger.log_message(
                        f"[NAT] ✅ Inbound translation applied for packet now destined to "
                        f"{packet[IP].dst}:{(packet[TCP] if packet.haslayer(TCP) else packet[UDP]).dport}; forwarding."
                    )
                    self._forward_general_ip_packet(packet, inbound_iface)
                return

            # If not for the router, it's transit traffic to be forwarded
            self._forward_general_ip_packet(packet, inbound_iface)
        except Exception as e:
            self.router_logger.log_message(
                f"‼️ ERROR processing packet on {inbound_iface.split('_')[-1]}: {e}. Packet summary: {packet.summary()}")

    def _forward_general_ip_packet(self, packet, inbound_iface: str):
        """Forwards a transit packet, applying NAT and other rules."""
        ip_layer = packet.getlayer(IP)
        dst_ip = ip_layer.dst

        if ip_layer.ttl <= 1:
            self.router_logger.log_message(f"-> TTL expired for {dst_ip}. Dropping.")
            # Optionally send ICMP Time Exceeded back to source
            # self._send_icmp_time_exceeded(packet, inbound_iface)
            return

        route = self.rip_manager.find_route(dst_ip)
        if not route:
            self.router_logger.log_message(f"-> No route to {dst_ip}. Dropping.")
            # Optionally send ICMP Destination Unreachable back to source
            # self._send_icmp_dest_unreachable(packet, inbound_iface, 0) # 0 = Network Unreachable
            return

        # Determine the initial outbound interface based on routing table
        initial_outbound_iface = route["interface"]
        next_hop_ip = route["next_hop"] if route["next_hop"] != "0.0.0.0" else dst_ip

        # Let's get the network object for the inbound interface
        inbound_net_config = self._interfaces_config.get(inbound_iface)
        inbound_network = inbound_net_config["network"] if inbound_net_config else None

        # Check if the packet is destined for a host on the same segment it came from
        is_intra_lan_traffic = (
                inbound_network and
                ipaddress.ip_address(dst_ip) in inbound_network and
                dst_ip != inbound_net_config["ip_addr"]  # Not for the router itself
        )

        if inbound_iface == initial_outbound_iface and not is_intra_lan_traffic:
            # This is a critical routing error: external traffic routed back to inbound interface.
            self.router_logger.log_message(
                f"-> ⚠️ POTENTIAL ROUTING LOOP: External traffic for {dst_ip} is routed back to {initial_outbound_iface.split('_')[-1]}."
            )
            return
        elif inbound_iface == initial_outbound_iface and is_intra_lan_traffic:
            # This is legitimate intra-LAN traffic, allow it.
            self.router_logger.log_message(
                f"✅ FORWARDING (Intra-LAN): {packet.summary()} | In:{inbound_iface.split('_')[-1]} -> Out:{initial_outbound_iface.split('_')[-1]}"
            )

        is_lan_to_wan = (inbound_iface == self.interface_in_full_name and
                         initial_outbound_iface == self.interface_out_full_name)  # Check against primary OUT

        # --- Apply Outbound Load Balancing if applicable ---
        # If this is LAN to WAN traffic and the outbound load balancer has multiple interfaces
        actual_outbound_iface = initial_outbound_iface
        if is_lan_to_wan and len(self.outbound_load_balancer.get_configured_interfaces()) > 1:
            selected_lb_iface = self.outbound_load_balancer.get_next_interface(packet)
            if selected_lb_iface:
                actual_outbound_iface = selected_lb_iface
                self.router_logger.log_message(
                    f"[Router] Outbound traffic for {dst_ip} load balanced to {actual_outbound_iface.split('_')[-1]}.")
            else:
                self.router_logger.log_message(f"[Router] No active interfaces for outbound load balancing. Dropping.")
                return  # Drop if LB fails to find an interface

        # Check for multicast forwarding based on IGMP membership
        if ipaddress.ip_address(dst_ip).is_multicast:
            if not self.igmp_manager.should_forward_multicast(dst_ip, actual_outbound_iface):
                self.router_logger.log_message(
                    f"-> Dropping multicast {dst_ip} on {actual_outbound_iface.split('_')[-1]}: No active members.")
                return  # Do not forward if no members

        self.router_logger.log_message(
            f"✅ FORWARDING: {packet.summary()} | In:{inbound_iface.split('_')[-1]} -> Out:{actual_outbound_iface.split('_')[-1]}"
        )

        # Apply NAT for LAN to WAN traffic (using the *actual* outbound interface)
        if is_lan_to_wan and self.nat_manager:
            self.nat_manager.translate_outbound(packet)
            # If NAT translation resulted in packet drop (e.g., no available ports), then return
            if packet[IP].src != self.nat_manager.public_ip:  # Simple check if NAT was applied
                self.router_logger.log_message(f"-> Packet dropped by NAT outbound translation.")
                return

        # --- Determine final physical interface (considering LAGs) ---
        final_physical_iface = actual_outbound_iface
        if self.lag_manager.is_lag_interface(actual_outbound_iface):
            selected_lag_member = self.lag_manager.get_member_interface(actual_outbound_iface, packet)
            if selected_lag_member:
                final_physical_iface = selected_lag_member
                self.router_logger.log_message(
                    f"[Router] Packet for {dst_ip} sent via LAG member {final_physical_iface.split('_')[-1]} of {actual_outbound_iface}.")
            else:
                self.router_logger.log_message(
                    f"[Router] LAG '{actual_outbound_iface}' has no active members. Dropping packet.")
                return  # Drop if LAG has no active members

        # --- Handle Layer 2 details based on final physical outbound interface type ---
        outbound_iface_config = self._interfaces_config.get(final_physical_iface)
        if not outbound_iface_config:
            self.router_logger.log_message(
                f"-> Final physical outbound interface {final_physical_iface.split('_')[-1]} configuration missing. Dropping.")
            return

        outbound_network = outbound_iface_config["network"]

        # Determine if the final physical outbound interface is loopback
        is_outbound_loopback = ("loopback" in final_physical_iface.lower() or "lo" == final_physical_iface.lower())

        target_mac = None
        # Do not perform ARP for loopback destinations or if the outbound interface is loopback
        if ipaddress.ip_address(dst_ip).is_loopback or is_outbound_loopback:
            self.router_logger.log_message(
                f"-> Destination {dst_ip} is loopback or final physical outbound interface {final_physical_iface.split('_')[-1]} is loopback. Skipping ARP.")
            target_mac = "00:00:00:00:00:00"  # Dummy MAC, as L2 is often not used for loopback
        elif ipaddress.ip_address(dst_ip) == outbound_network.broadcast_address:
            target_mac = "ff:ff:ff:ff:ff:ff"
            self.router_logger.log_message(f"-> Destination is broadcast ({dst_ip}). Setting MAC to {target_mac}")
        else:
            target_mac = self.arp_manager.resolve(next_hop_ip, final_physical_iface)

        if not target_mac:
            self.router_logger.log_message(
                f"-> ARP failed for next hop {next_hop_ip} on {final_physical_iface.split('_')[-1]}. Dropping.")
            return

        packet.ttl -= 1

        # Only set Ether layer if not loopback, or if it was already present and we're just updating
        # If the packet came with an Ether layer but is going to loopback, remove it.
        # If the packet has no Ether layer and is going to a physical interface, this is problematic.
        if is_outbound_loopback:
            if packet.haslayer(Ether):
                # Remove Ether layer for loopback destination to avoid issues
                packet = packet[IP] / packet.payload  # This removes Ether layer
        elif packet.haslayer(Ether):
            packet[Ether].src = outbound_iface_config["mac"]
            packet[Ether].dst = target_mac
        else:
            # This case means an IP packet without an Ether layer is trying to go out a physical interface.
            # In a real setup, this means it was either injected as raw IP or originated from a
            # virtual interface that doesn't use L2. This router expects L2 for physical interfaces.
            self.router_logger.log_message(
                f"-> WARNING: Packet has no Ether layer but destined for physical interface {final_physical_iface.split('_')[-1]}. Cannot send without L2 header.")
            return  # Cannot send without proper L2 on physical interface

        # Recalculate checksums after modifications
        del ip_layer.chksum
        if packet.haslayer(TCP): del packet[TCP].chksum
        if packet.haslayer(UDP): del packet[UDP].chksum

        self.packet_writer.queue_packet(packet, final_physical_iface)

    def start_routing(self):
        """Configures interfaces and starts all manager threads."""
        self._initialize_interface_discovery()
        if not self._auto_configure_interfaces():
            self.router_logger.log_message("[Router] Auto-configuration failed. Aborting start.")
            return

        self.nat_manager = NATManager(self.router_logger, self.router_ip_out)
        self.nat_manager.start()  # Start NAT cleanup thread

        # Initialize DHCP server (can be configured as relay agent or standalone server)
        if self.router_network_in:
            dhcp_start_ip = str(self.router_network_in.network_address + 100)
            dhcp_end_ip = str(self.router_network_in.network_address + 200)
            # Example: To enable DHCP relay, pass self.router_gateway_out_ip as dhcp_relay_target_ip
            # self.dhcp_server = DHCPServer(
            #     self.router_logger, self.packet_writer, self.interface_in_full_name,
            #     dhcp_start_ip, dhcp_end_ip, self._interfaces_config, dhcp_relay_target_ip="10.0.0.1" # Example relay target
            # )
            self.dhcp_server = DHCPServer(
                self.router_logger,
                self.packet_writer,
                self.interface_in_full_name,  # The full Scapy name for the IN interface
                dhcp_start_ip,
                dhcp_end_ip,
                self._interfaces_config  # Pass the full interfaces configuration
            )
        else:
            self.router_logger.log_message("[DHCP] DHCP Server not initialized: Router IN network not configured.")
        if self.dhcp_server:  # Start DHCP server if it was initialized
            self.dhcp_server.start()

        # Initialize RIP routes with all known interfaces, including loopback for direct connection
        self.rip_manager.initialize_routes(self._interfaces_config, self.router_gateway_out_ip,
                                           self.interface_out_full_name)
        # Example: Set RIP authentication key
        # self.rip_manager.set_authentication_key("mysecretkey")

        # NEW: Add a default static route to 8.8.8.8 via the WAN interface, if not already present
        # This gives direct control over a specific route without RIP
        google_dns_route_network = ipaddress.ip_network("8.8.8.8/32")
        # Check if the route exists AND if its type is static. If not, add/update it as static.
        current_route_details = self.rip_manager.find_route("8.8.8.8")
        if not current_route_details or current_route_details.get("type") != "static":
            self.router_logger.log_message("[Router] Adding/Updating static route for 8.8.8.8/32.")
            self.rip_manager.add_static_route(
                network_str=str(google_dns_route_network),
                next_hop=self.router_gateway_out_ip,
                interface=self.interface_out_full_name,
                cost=1
            )
        else:
            self.router_logger.log_message("[Router] Static route for 8.8.8.8/32 already exists.")

        self.handshake_manager = HandshakeManager(self.router_logger, self.arp_manager, self.nat_manager,
                                                  self.rip_manager)

        self.rip_manager.start()
        self.tls_proxy_manager.start()
        self.packet_writer.start()
        self.handshake_manager.start()
        self.igmp_manager.set_interfaces_config(self._interfaces_config)
        self.igmp_manager.start()


        # Send Gratuitous ARP for router's own IPs on startup
        if self.interface_in_full_name and self.router_ip_in and self.mac_in:
            self.arp_manager.send_gratuitous_arp(self.router_ip_in, self.mac_in, self.interface_in_full_name)
        if self.interface_out_full_name and self.router_ip_out and self.mac_out:
            self.arp_manager.send_gratuitous_arp(self.router_ip_out, self.mac_out, self.interface_out_full_name)

        self.router_logger.log_message("\n--- Python Router Starting Services ---")
        self._stop_sniffing_event.clear()

        # Start sniffing on ALL configured interfaces, including loopback
        for iface_name in self._interfaces_config.keys():
            self._start_single_sniffer(iface_name)

    def stop_routing(self):
        """Stops all manager threads and cleans up network interfaces."""
        self.router_logger.log_message("\n--- Python Router Stopping Services ---")
        self._stop_sniffing_event.set()
        if self.dhcp_server:  # Stop DHCP server if it was initialized
            self.dhcp_server.stop()
        # Stop all manager threads
        self.rip_manager.stop()
        self.tls_proxy_manager.stop()
        self.packet_writer.stop()
        if self.nat_manager:
            self.nat_manager.stop()
        for thread in self._sniff_threads.values():
            if thread.is_alive():
                thread.join(timeout=2)
        self._sniff_threads.clear()
        self.igmp_manager.stop()
        self.handshake_manager.stop()
        self.cleanup_all_network_changes()
        self.router_logger.log_message("[Router] All services stopped.")

    def cleanup_all_network_changes(self):
        """
        Cleans up all network changes made by the router, reverting IPs and DNS
        to DHCP for the interfaces it managed.
        Note: Loopback interface configuration is typically OS-managed and
        does not need DHCP reset.
        """
        self.router_logger.log_message("\n--- Cleaning up all network changes made by Python Router ---")
        self._remove_firewall_rules()
        if self.interface_in_friendly_name and self.router_ip_in:
            self.router_logger.log_message(
                f"[RouterManager Cleanup] Cleaning up IN interface '{self.interface_in_friendly_name}'...")
            self._cleanup_interface_ip(self.interface_in_friendly_name)
        else:
            self.router_logger.log_message(
                "[RouterManager Cleanup] No IN interface IP to clean up (not assigned or auto-config failed).")

        if self.interface_out_friendly_name and self.router_ip_out:
            self.router_logger.log_message(
                f"[RouterManager Cleanup] Cleaning up OUT interface '{self.interface_out_friendly_name}'...")
            self._cleanup_interface_ip(self.interface_out_friendly_name)
        else:
            self.router_logger.log_message(
                "[RouterManager Cleanup] No OUT interface IP to clean up (not assigned or auto-config failed).")

        # No cleanup for loopback needed as it's typically managed by OS and static.
        self.router_logger.log_message("--- Network cleanup complete. ---")

    def _cleanup_interface_ip(self, iface_friendly_name: str):
        """
        Resets the IP configuration of an interface to DHCP.
        """
        self.router_logger.log_message(
            f"[RouterManager] Cleaning up IP for '{iface_friendly_name}' (setting to DHCP)...")

        netsh_args = ["set", "address", f'name={iface_friendly_name}', "source=dhcp"]

        if self._execute_netsh(netsh_args):
            self.router_logger.log_message(f"[RouterManager] Successfully set '{iface_friendly_name}' to DHCP.")
            return True
        else:
            self.router_logger.log_message(
                f"[RouterManager] WARNING: Failed to set '{iface_friendly_name}' to DHCP. Manual reset may be required.")
            return False

    # --- New Methods for Static Route Management ---
    def add_static_route(self, network_str: str, next_hop: str, interface_full_name: str, cost: int = 1) -> bool:
        """
        Adds a static route to the router's routing table.
        Args:
            network_str (str): CIDR notation for the destination network (e.g., "192.168.1.0/24").
            next_hop (str): The IP address of the next hop router, or "0.0.0.0" for direct delivery.
            interface_full_name (str): The full Scapy name of the outbound interface for this route.
            cost (int): The metric/cost of this route (1-15 valid, 16 = infinity).
        Returns True if added/updated, False otherwise.
        """
        return self.rip_manager.add_static_route(network_str, next_hop, interface_full_name, cost)

    def remove_static_route(self, network_str: str) -> bool:
        """
        Removes a static route from the router's routing table.
        Returns True if removed, False otherwise.
        """
        return self.rip_manager.remove_static_route(network_str)

    def get_routing_table(self) -> list[dict]:
        """
        Returns a human-readable list of all entries in the router's routing table.
        """
        return self.rip_manager.get_routing_table_view()

    # --- New Methods for ARP Management ---
    def add_trusted_arp_port(self, iface_full_name: str):
        """Adds an interface to the list of trusted ports for ARP inspection."""
        self.arp_manager.add_trusted_port(iface_full_name)

    def remove_trusted_arp_port(self, iface_full_name: str):
        """Removes an interface from the list of trusted ports for ARP inspection."""
        self.arp_manager.remove_trusted_port(iface_full_name)

    def add_static_arp_entry(self, ip_address: str, mac_address: str):
        """Adds a static ARP entry to the ARP manager."""
        self.arp_manager.add_static_arp_entry(ip_address, mac_address)

    def remove_static_arp_entry(self, ip_address: str):
        """Removes a static ARP entry from the ARP manager."""
        self.arp_manager.remove_static_arp_entry(ip_address)

    # --- New Methods for DNS Management ---
    def add_dns_conditional_forwarder(self, domain_suffix: str, dns_server_ip: str):
        """Adds a conditional DNS forwarder."""
        self.dns_manager.add_conditional_forwarder(domain_suffix, dns_server_ip)

    def remove_dns_conditional_forwarder(self, domain_suffix: str):
        """Removes a conditional DNS forwarder."""
        self.dns_manager.remove_conditional_forwarder(domain_suffix)

    def add_dns_blacklist_entry(self, domain_suffix: str):
        """Adds a domain suffix to the DNS blacklist."""
        self.dns_manager.add_dns_blacklist_entry(domain_suffix)

    def remove_dns_blacklist_entry(self, domain_suffix: str):
        """Removes a domain suffix from the DNS blacklist."""
        self.dns_manager.remove_dns_blacklist_entry(domain_suffix)

    # --- New Methods for DHCP Management ---
    def set_dhcp_relay_target(self, target_ip: str):
        """Configures the DHCP server to act as a relay agent to the specified IP."""
        if self.dhcp_server:
            self.dhcp_server.dhcp_relay_target_ip = target_ip
            self.router_logger.log_message(f"[RouterManager] DHCP server configured as relay to: {target_ip}")
        else:
            self.router_logger.log_message("[RouterManager] DHCP server not initialized. Cannot set relay target.")

    def clear_dhcp_relay_target(self):
        """Disables DHCP relay functionality."""
        if self.dhcp_server:
            self.dhcp_server.dhcp_relay_target_ip = None
            self.router_logger.log_message("[RouterManager] DHCP relay functionality disabled.")
        else:
            self.router_logger.log_message("[RouterManager] DHCP server not initialized.")

    # --- New Methods for RIP Management ---
    def set_rip_authentication_key(self, key: str):
        """Sets the shared secret for RIP authentication."""
        self.rip_manager.set_authentication_key(key)

    def clear_rip_authentication_key(self):
        """Clears the RIP authentication key."""
        self.rip_manager.set_authentication_key(None)

    # --- New Methods for Outbound Load Balancing ---
    def add_outbound_load_balancing_interface(self, iface_full_name: str):
        """Adds an interface to the pool used for outbound load balancing."""
        self.outbound_load_balancer.add_outbound_interface(iface_full_name)

    def remove_outbound_load_balancing_interface(self, iface_full_name: str):
        """Removes an interface from the pool used for outbound load balancing."""
        self.outbound_load_balancer.remove_outbound_interface(iface_full_name)

    # --- New Methods for Link Aggregation (LAG) ---
    def create_link_aggregation_group(self, lag_name: str, member_interfaces: List[str]) -> bool:
        """
        Creates a new Link Aggregation Group (LAG).
        Args:
            lag_name (str): The logical name for the LAG (e.g., "PortChannel1").
            member_interfaces (List[str]): A list of full Scapy interface names that are part of this LAG.
                                            These interfaces should be configured via add_interface first.
        Returns True if LAG created/updated, False otherwise.
        """
        # Ensure all member interfaces are known physical interfaces
        for member_iface in member_interfaces:
            if member_iface not in self._interfaces_config:
                self.router_logger.log_message(
                    f"[RouterManager] ❌ Cannot create LAG '{lag_name}': Member interface '{member_iface.split('_')[-1]}' is not a known physical interface.")
                return False
        return self.lag_manager.create_lag(lag_name, member_interfaces)

    def remove_link_aggregation_group(self, lag_name: str) -> bool:
        """Removes a Link Aggregation Group."""
        return self.lag_manager.remove_lag(lag_name)

    # --- New Methods for Firewall Management ---
    def add_firewall_rule(self, action: str, protocol: str = 'any', src_ip: str = 'any', dst_ip: str = 'any',
                          src_port: Any = 'any', dst_port: Any = 'any', position: int = None) -> bool:
        """Adds a new firewall rule to the FirewallManager."""
        return self.firewall_manager.add_rule(action, protocol, src_ip, dst_ip, src_port, dst_port, position)

    def remove_firewall_rule(self, index: int) -> bool:
        """Removes a firewall rule from the FirewallManager by its index."""
        return self.firewall_manager.remove_rule(index)

    def get_firewall_rules(self) -> List[Dict[str, Any]]:
        """Returns the current list of firewall rules."""
        return self.firewall_manager.get_rules()

class PacketManager:
    """
    A stateless utility class for discovering network interfaces and sending various
    types of packets. Each sending function is self-contained and requires
    the interface to be specified on each call.
    """

    def __init__(self, packet_logger):
        """
        Initializes the PacketManager.
        Args:
            packet_logger: A logger instance for logging messages.
        """
        self.packet_logger = packet_logger
        self._tshark_interfaces = []
        self._tshark_path = None
        self._initialize_interface_discovery()
        print("[PacketManager] Initialized and ready.")

    def get_interfaces(self) -> List[dict]:
        """Returns the list of discovered network interfaces."""
        return self._tshark_interfaces

    def _get_tshark_path(self) -> Optional[str]:
        """Discovers the path to tshark.exe."""
        if getattr(sys, "frozen", False):
            # Path for bundled executable
            tshark_exe = Path(sys._MEIPASS) / "tools" / "Wireshark" / "tshark.exe"
            if tshark_exe.exists():
                return str(tshark_exe)

        # Path for development environment
        server_dir = Path(__file__).resolve().parent
        project_root = server_dir.parent
        tools_dir = project_root / "client" / "tools" / "Wireshark"
        candidate = tools_dir / "tshark.exe"
        if candidate.exists():
            return str(candidate)

        # Fallback to system PATH
        system_tshark = shutil.which("tshark")
        if system_tshark:
            return system_tshark

        self.packet_logger.log_message("[PacketManager] Error: tshark.exe not found.")
        return None

    def _initialize_interface_discovery(self):
        """Discovers network interfaces using tshark -D and stores them."""
        self._tshark_path = self._get_tshark_path()
        if not self._tshark_path:
            return
        self.packet_logger.log_message("[PacketManager] Discovering network interfaces via tshark -D...")
        try:
            proc = subprocess.run(
                [self._tshark_path, '-D'], capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            pattern = re.compile(r"(\d+)\.\s+([^(]+)(?:\((.*)\))?")
            for line in proc.stdout.strip().split('\n'):
                match = pattern.match(line)
                if match:
                    self._tshark_interfaces.append({
                        'id': match.group(1),
                        'full_name': match.group(2).strip(),
                        'friendly_name': match.group(3).strip() if match.group(3) else match.group(2).strip()
                    })
            self.packet_logger.log_message(f"[PacketManager] Discovered {len(self._tshark_interfaces)} interfaces.")
        except Exception as e:
            self.packet_logger.log_message(f"[PacketManager] Error during interface discovery: {e}")

    def send_ping(self, target_ip: str, iface: str, src_ip: Optional[str] = None, timeout: int = 2) -> Tuple[
        str, Optional[Packet]]:
        """Sends an ICMP Echo Request from a specific interface."""
        self.packet_logger.log_message(f"[PacketManager] Sending Ping to {target_ip} via {iface}...")
        try:
            packet = IP(dst=target_ip)
            if src_ip: packet.src = src_ip
            packet /= ICMP()

            response = sr1(packet, timeout=timeout, verbose=0, iface=iface)

            if response is None: return 'TIMEOUT', None
            if response.haslayer(ICMP) and response.getlayer(ICMP).type == 0: return 'REPLY', response
            return 'UNEXPECTED_RESPONSE', response
        except Exception as e:
            self.packet_logger.log_message(f"[Ping] Error sending on {iface}: {e}")
            return 'ERROR', None

    def send_tcp_syn(self, target_ip: str, target_port: int, iface: str, src_ip: Optional[str] = None,
                     timeout: int = 2) -> Tuple[str, Optional[Packet]]:
        """Performs a TCP SYN scan for a single port from a specific interface."""
        self.packet_logger.log_message(f"[PacketManager] Sending TCP SYN to {target_ip}:{target_port} via {iface}...")
        try:
            packet = IP(dst=target_ip)
            if src_ip: packet.src = src_ip
            packet /= TCP(dport=target_port, sport=54321, flags='S')

            response = sr1(packet, timeout=timeout, verbose=0, iface=iface)

            if response is None: return 'FILTERED', None

            if response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN/ACK
                    rst_src_ip = response[IP].dst
                    rst_packet = IP(dst=target_ip, src=rst_src_ip) / TCP(
                        dport=target_port, sport=packet[TCP].sport, flags='R', seq=tcp_layer.ack
                    )
                    send(rst_packet, verbose=0, iface=iface)
                    return 'OPEN', response
                elif tcp_layer.flags & 0x04:  # RST
                    return 'CLOSED', response

            return 'UNEXPECTED_RESPONSE', response
        except Exception as e:
            self.packet_logger.log_message(f"[TCP-SYN] Error sending on {iface}: {e}")
            return 'ERROR', None

    def send_udp_packet(self, target_ip: str, target_port: int, payload: bytes, iface: str,
                        src_ip: Optional[str] = None, timeout: int = 2) -> Tuple[str, Optional[Packet]]:
        """Sends a UDP packet from a specific interface."""
        self.packet_logger.log_message(f"[PacketManager] Sending UDP to {target_ip}:{target_port} via {iface}...")
        try:
            packet = IP(dst=target_ip)
            if src_ip: packet.src = src_ip
            packet /= UDP(dport=target_port, sport=54322) / payload

            response = sr1(packet, timeout=timeout, verbose=0, iface=iface)

            if response is None: return 'NO_RESPONSE', None
            if response.haslayer(ICMP): return 'ICMP_RESPONSE', response
            return 'REPLY', response
        except Exception as e:
            self.packet_logger.log_message(f"[UDP] Error sending on {iface}: {e}")
            return 'ERROR', None

    def send_dns_query(self, target_dns_server: str, domain: str, record_type: str, iface: str,
                       src_ip: Optional[str] = None, timeout: int = 2) -> Tuple[str, Optional[Packet]]:
        """Sends a DNS query from a specific interface."""
        self.packet_logger.log_message(
            f"[PacketManager] Sending DNS Query for {domain} to {target_dns_server} via {iface}...")
        try:
            packet = IP(dst=target_dns_server)
            if src_ip: packet.src = src_ip
            packet /= UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=record_type))

            response = sr1(packet, timeout=timeout, verbose=0, iface=iface)

            if response is None: return 'TIMEOUT', None
            if response.haslayer(DNS): return 'REPLY', response
            return 'UNEXPECTED_RESPONSE', response
        except Exception as e:
            self.packet_logger.log_message(f"[DNS] Error sending on {iface}: {e}")
            return 'ERROR', None

class WiresharkManager:


    def __init__(self, p2pool_data, logger):
        self.p2pool_data = p2pool_data
        self.logger = logger
        self.tshark_procs = {}
        self.redirect_threads = {}
        self.stop_event = threading.Event()
        self.geoip_reader = None
        self._decompressed_db_path = None  # To store the path to the decompressed database

        # Attributes for stateful correlation engine
        self.correlation_lock = threading.Lock()

        self.stream_map = {}  # Stores the final loopback <-> VPN mappings
        self.loopback_interface_id = None
        self.vpn_interface_id = None
        self.min_packet_len = 60


    def _initialize_geoip(self):
        """Finds and loads the GeoLite2-City database."""
        try:
            # Determine base path for GeoIP files based on execution mode
            if getattr(sys, "frozen", False):
                # Running in bundled mode (PyInstaller)
                # sys._MEIPASS is the path to the temporary directory where PyInstaller extracts files
                base_path = Path(sys._MEIPASS)
                self._decompressed_db_path = base_path / "tools" / "GeoLite2-City.mmdb"
            else:
                # Running in development mode
                # Path(__file__).resolve().parent is 'server' directory, .parent gets 'project_root'
                base_path = Path(__file__).resolve().parent.parent
                self._decompressed_db_path = base_path / "server" / "tools" / "GeoLite2-City.mmdb"

            # Define path for the uncompressed database file


            # Ensure the target directory exists
            self._decompressed_db_path.parent.mkdir(parents=True, exist_ok=True)

            # Try to load the .mmdb file directly
            if not self._decompressed_db_path.exists() or self._decompressed_db_path.stat().st_size == 0:
                self.logger.log_message(
                    f"[GeoIP] Warning: GeoIP database not found or is empty at {self._decompressed_db_path}. GeoIP lookups disabled.")
                self.geoip_reader = None
                self._decompressed_db_path = None
                return  # Exit if the file doesn't exist or is empty

            self.logger.log_message(f"[GeoIP] Attempting to load GeoIP database from {self._decompressed_db_path}...")

            # Attempt to load the GeoIP database with retries
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    self.geoip_reader = geoip2.database.Reader(str(self._decompressed_db_path))
                    self.logger.log_message("[GeoIP] Successfully loaded GeoIP database.")
                    break  # Exit loop if successful
                except geoip2.errors.AddressNotFoundError as e:
                    # This error can sometimes indicate a malformed/incomplete file
                    self.logger.log_message(
                        f"[GeoIP] Attempt {attempt + 1}/{max_retries}: GeoIP database format error: {e}. Retrying in 0.5 seconds...")
                    self.geoip_reader = None
                    time.sleep(0.5)
                except Exception as e:
                    self.logger.log_message(
                        f"[GeoIP] Attempt {attempt + 1}/{max_retries}: Error loading database: {e}. Retrying in 0.5 seconds...")
                    self.geoip_reader = None  # Ensure reader is None on failure
                    time.sleep(0.5)
            else:
                self.logger.log_message(
                    f"[GeoIP] Failed to load GeoIP database after {max_retries} attempts. GeoIP lookups disabled.")
                self._decompressed_db_path = None  # Clear the path reference if loading failed


        except Exception as e:
            self.logger.log_message(
                f"[GeoIP] An unexpected error occurred during GeoIP initialization: {e}. GeoIP lookups disabled.")
            self.geoip_reader = None
            # Clear the path reference if loading failed
            self._decompressed_db_path = None

    def _get_geoip_location(self, ip_address: str) -> str:
        """Looks up an IP address and returns a formatted location string."""
        if not self.geoip_reader or not ip_address:
            return ""

        try:
            # First, check if it's a private IP using ipaddress module
            # This is robust for standard private IP ranges (RFC1918)
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private:
                    self.logger.log_message(f"[GeoIP Debug] IP: {ip_address} identified as Private IP (RFC1918).")
                    return "Private IP"
            except ValueError:
                # If ip_address is not a valid IP string, log and return
                self.logger.log_message(f"[GeoIP Debug] IP: {ip_address} identified as Invalid IP Format.")
                return "Invalid IP Format"

            # Attempt to look up the IP in the GeoIP database.
            # The geoip2.database.Reader.city() method will raise AddressNotFoundError
            # for IPs not found in the database, including non-public IPs not covered
            # by ipaddress.is_private.
            response = self.geoip_reader.city(ip_address)
            city = response.city.name or "Unknown City"
            country = response.country.iso_code or "N/A"
            return f"{city}, {country}"

        except geoip2.errors.AddressNotFoundError:
            self.logger.log_message(
                f"[GeoIP] AddressNotFoundError for IP: {ip_address} - IP not found in database (might be non-public or unlisted).")
            return "Unknown"
        except Exception as e:
            self.logger.log_message(f"[GeoIP] Lookup Error for IP: {ip_address} - Details: {e}")
            return "Lookup Error"

    def _get_tshark_path(self) -> str | None:
        if getattr(sys, "frozen", False):
            self.logger.log_message("[Wireshark] Running in bundled mode.")
            exe = Path(self.p2pool_data.P2POOL_DIR) / "Wireshark" / "tshark.exe"
            return str(exe) if exe.exists() else None
        self.logger.log_message("[Wireshark] Running in development mode. Using relative path.")
        server_dir = Path(__file__).resolve().parent
        project_root = server_dir.parent
        tools_dir = project_root / "client" / "tools" / "Wireshark"
        candidate = tools_dir / "tshark.exe"
        if candidate.exists():
            self.logger.log_message(f"[Wireshark] Found tshark at: {candidate}")
            return str(candidate)
        system_tshark = shutil.which("tshark")
        if system_tshark:
            self.logger.log_message(f"[Wireshark] Falling back to system tshark at: {system_tshark}")
            return system_tshark
        self.logger.log_message(
            f"[Wireshark] Error: tshark.exe not found. Looked in {candidate} and on PATH."
        )
        return None

    def _list_interfaces(self, tshark_path: str) -> list[dict]:
        self.logger.log_message("[Wireshark] Discovering network interfaces...")
        interfaces = []
        try:
            proc = subprocess.run(
                [tshark_path, '-D'], capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            pattern = re.compile(r"(\d+)\.\s+(.*)")
            interface_output_lines = proc.stdout.strip().split('\n')

            self.logger.log_message("[Wireshark] Available Network Interfaces:")
            for line in interface_output_lines:
                match = pattern.match(line)
                if match:
                    iface_id = match.group(1)
                    iface_name = match.group(2).strip()
                    interfaces.append({'id': iface_id, 'name': iface_name})
                    self.logger.log_message(f"  ID: {iface_id}, Name: {iface_name}")

            self.logger.log_message(f"[Wireshark] Found {len(interfaces)} interfaces.")
        except Exception as e:
            self.logger.log_message(f"[Wireshark] An error occurred while listing interfaces: {e}")
        return interfaces

    def start_capture(self, main_interface_name: str = 'Wi-Fi', promiscuous=True):
        self._initialize_geoip()
        tshark_path = self._get_tshark_path()
        if not tshark_path: return False
        if self.tshark_procs:
            self.logger.log_message("[Wireshark] Capture is already running.")
            return False

        # Ensure GeoIP reader is initialized before starting capture
        if self.geoip_reader is None:
            self.logger.log_message("[GeoIP] GeoIP reader is not initialized. Attempting to initialize it now.")
            self._initialize_geoip()
            if self.geoip_reader is None:  # If initialization still failed
                self.logger.log_message("[GeoIP] Failed to initialize GeoIP reader. Proceeding without GeoIP lookups.")
                # You might want to return False here if GeoIP is critical for your application
                # For now, we'll allow capture to proceed without GeoIP if it fails.

        available_interfaces = self._list_interfaces(tshark_path)
        if not available_interfaces: return False

        # --- NEW LOGIC: Resolve main_interface_name to its ID ---
        main_interface_id = None
        for iface in available_interfaces:
            # We need to be careful with string matching for interface names
            # Use 'in' for partial matches, or '==' for exact matches
            # For "Wi-Fi", a simple "Wi-Fi" in iface['name'] should work.
            if main_interface_name.lower() in iface['name'].lower():
                main_interface_id = iface['id']
                self.logger.log_message(
                    f"[Wireshark] Resolved '{main_interface_name}' to ID: {main_interface_id}")
                break

        if not main_interface_id:
            self.logger.log_message(
                f"[Wireshark] Error: Main interface '{main_interface_name}' not found. Available interfaces: "
                f"{[iface['name'] for iface in available_interfaces]}")
            return False
        # --- END NEW LOGIC ---

        interfaces_to_capture = {main_interface_id}  # Start with the resolved main interface

        # Add VPN and Loopback interfaces dynamically
        for iface in available_interfaces:
            if "WireGuard Tunnel" in iface['name'] or "ProtonVPN" in iface['name']:
                self.logger.log_message(
                    f"[Wireshark] Detected active VPN interface: {iface['name']} (ID: {iface['id']}). Adding to capture.")
                interfaces_to_capture.add(iface['id'])
                # Set VPN interface ID for correlation engine if not already set
                if self.vpn_interface_id is None:
                    self.vpn_interface_id = iface['id']
            elif "Loopback" in iface['name']:
                self.logger.log_message(
                    f"[Wireshark] Detected Loopback interface: {iface['name']} (ID: {iface['id']}). Adding to capture.")
                interfaces_to_capture.add(iface['id'])
                # Set Loopback interface ID for correlation engine if not already set
                if self.loopback_interface_id is None:
                    self.loopback_interface_id = iface['id']

        self.logger.log_message(f"[Wireshark] Final capture list (IDs): {list(interfaces_to_capture)}")
        self.logger.log_message(
            f"[CorrelationEngine] Watching for 'cause' on Loopback ID: {self.loopback_interface_id}")
        self.logger.log_message(f"[CorrelationEngine] Watching for 'effect' on VPN ID: {self.vpn_interface_id}")

        self.stop_event.clear()

        base_command = [
            tshark_path, '-l',
            '-T', 'json',
            '-V',
            '-o', 'tcp.desegment_tcp_streams:TRUE'
        ]
        if not promiscuous:
            base_command.append('-p')
        started_count = 0
        for iface_id in interfaces_to_capture:
            self.logger.log_message(f"[Wireshark] Starting capture on interface {iface_id}...")
            command = base_command + ['-i', str(iface_id)]
            try:
                proc = subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, creationflags=subprocess.CREATE_NO_WINDOW
                )
                self.tshark_procs[iface_id] = proc
                thread = threading.Thread(target=self._redirect_output, args=(proc, iface_id), daemon=True)
                self.redirect_threads[iface_id] = thread
                thread.start()
                self.logger.log_message(f"[Wireshark] Capture started on interface {iface_id} with PID: {proc.pid}")
                started_count += 1
            except Exception as e:
                self.logger.log_message(f"[Wireshark] Failed to start capture on interface {iface_id}: {e}")
        return started_count > 0

    def stop_capture(self):
        if not self.tshark_procs:
            self.logger.log_message("[Wireshark] Capture is not running.")
            return

        self.logger.log_message("[Wireshark] Stopping all captures...")
        self.stop_event.set()
        for iface_id, proc in self.tshark_procs.items():
            if proc.poll() is None:
                proc.terminate()
        for iface_id, proc in self.tshark_procs.items():
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.logger.log_message(f"[Wireshark] Process for interface {iface_id} did not terminate, killing.")
                proc.kill()

        if self.geoip_reader:
            self.geoip_reader.close()
            self.logger.log_message("[GeoIP] Database closed.")

        # The decompressed file is now persistent, no need to delete it on stop.
        self._decompressed_db_path = None  # Clear the path reference

        self.logger.log_message("[Wireshark] All capture processes stopped.")
        self.tshark_procs.clear()
        self.redirect_threads.clear()

    def _process_packet(self, packet_data: dict | str, interface_id: str) -> None:
        """Parse a JSON packet dict, enrich it, and push to logger / callback."""
        if not isinstance(packet_data, dict):
            return  # ignore non‑JSON / malformed

        try:
            layers = packet_data.get("_source", {}).get("layers", {})
            if not layers:
                return

            # ----------------------------------------------------------
            #          Basic frame / IP / transport extraction
            # ----------------------------------------------------------
            frame = layers.get("frame", {})
            timestamp = frame.get("frame.time", "N/A")
            packet_num = frame.get("frame.number", "N/A")
            packet_len = frame.get("frame.len", "N/A")

            # Filter by minimum packet length
            try:
                if int(packet_len) < self.min_packet_len:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering small packet (Len: {packet_len}) on interface {interface_id}.")
                    return
            except ValueError:
                pass  # packet_len might be "N/A"

            ip_layer = layers.get("ip") or layers.get("ipv6")
            src_ip = ip_layer.get("ip.src", ip_layer.get("ipv6.src", "N/A")) if ip_layer else "N/A"
            dst_ip = ip_layer.get("ip.dst", ip_layer.get("ipv6.dst", "N/A")) if ip_layer else "N/A"

            # ----------------------------------------------------------
            #                  Filtering for idle/senseless traffic
            # ----------------------------------------------------------
            # This filtering logic is now always active within _process_packet.

            # Check for IPv4 multicast/broadcast or IPv6 multicast
            try:
                dst_ip_obj = ipaddress.ip_address(dst_ip)

                # Check for IPv4 broadcast address (255.255.255.255)
                if isinstance(dst_ip_obj, ipaddress.IPv4Address) and dst_ip_obj == ipaddress.IPv4Address(
                        '255.255.255.255'):
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering IPv4 Broadcast packet to {dst_ip} on interface {interface_id}.")
                    return  # Filter this packet

                # Filter common multicast addresses and general link-local multicast/broadcast.
                if dst_ip_obj.is_multicast:
                    # Specific common multicast ranges/addresses for discovery protocols (MDNS, SSDP, etc.)
                    if (isinstance(dst_ip_obj, ipaddress.IPv4Address) and (
                            dst_ip_obj in ipaddress.IPv4Network('224.0.0.0/24') or  # Link-local multicast, MDNS
                            dst_ip_obj in ipaddress.IPv4Network('239.255.255.0/24')  # Some SSDP/UPnP
                    )) or \
                            (isinstance(dst_ip_obj, ipaddress.IPv6Address) and (
                                    dst_ip_obj in ipaddress.IPv6Network('ff02::/16')  # Link-local multicast IPv6
                            )) or \
                            dst_ip == "239.255.255.250":  # SSDP specific IPv4 multicast
                        self.logger.log_message(
                            f"[Wireshark Filter] Filtering Multicast/Discovery packet to {dst_ip} on interface {interface_id}.")
                        return  # Filter this packet
            except ValueError:
                pass  # Not a valid IP, so can't check for multicast/broadcast

            # Check for common discovery/idle protocol ports (UDP/TCP)
            # Expanded list of common noisy ports
            common_noisy_ports = [
                "5353",  # MDNS
                "1900",  # SSDP
                "137",  # NetBIOS Name Service (UDP)
                "138",  # NetBIOS Datagram Service (UDP)
                "139",  # NetBIOS Session Service (TCP)
                "445",  # SMB over TCP (can be noisy on local networks)
                "520",  # RIP (Routing Information Protocol)
                "161",  # SNMP (Simple Network Management Protocol)
                "162",  # SNMP Trap
                "67",  # DHCP Server (BOOTP Server)
                "68",  # DHCP Client (BOOTP Client)
                "546",  # DHCPv6 Client
                "547",  # DHCPv6 Server
                "5678",  # UPnP (some implementations)
                "5679",  # UPnP (some implementations)
                "3702",  # WS-Discovery (Web Services Dynamic Discovery)
                "5355"  # LLMNR (Link-Local Multicast Name Resolution)
            ]

            # Convert ports to integers for direct comparison if needed, but tshark output is string
            # So keep as strings for comparison with dictionary values.

            if "udp" in layers:
                udp_layer = layers["udp"]
                dst_port = udp_layer.get("udp.dstport", "N/A")
                src_port = udp_layer.get("udp.srcport", "N/A")
                if dst_port in common_noisy_ports or src_port in common_noisy_ports:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering Discovery/Idle UDP packet on port {dst_port} from {src_ip} to {dst_ip} on interface {interface_id}.")
                    return  # Filter this packet

            if "tcp" in layers:
                tcp_layer = layers["tcp"]
                dst_port = tcp_layer.get("tcp.dstport", "N/A")
                src_port = tcp_layer.get("tcp.srcport", "N/A")
                if dst_port in common_noisy_ports or src_port in common_noisy_ports:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering Discovery/Idle TCP packet on port {dst_port} from {src_ip} to {dst_ip} on interface {interface_id}.")
                    return  # Filter this packet

            # ----------------------------------------------------------
            #                  Contextual / VPN tagging
            # ----------------------------------------------------------
            def _is_private(addr: str) -> bool:
                try:
                    return ipaddress.ip_address(addr.split("%")[0]).is_private  # strip zone index
                except ValueError:
                    return True  # treat invalid as private to avoid FP egress tags

            context_tags: list[str] = []

            # 1) Loopback packet that will be encrypted by VPN soon
            if (
                    interface_id == self.loopback_interface_id and
                    self.vpn_interface_id is not None and
                    not _is_private(dst_ip)
            ):
                context_tags.append("via‑VPN‑out")

            # 2) Traffic already on VPN adapter
            if interface_id == self.vpn_interface_id:
                if _is_private(src_ip) and not _is_private(dst_ip):
                    context_tags.append("VPN→WAN")  # egress after encryption
                elif not _is_private(src_ip) and _is_private(dst_ip):
                    context_tags.append("WAN→VPN")  # ingress before decryption
                else:
                    context_tags.append("VPN‑internal")

            # ----------------------------------------------------------
            #               Transport & service lookup
            # ----------------------------------------------------------
            src_port = dst_port = "N/A"
            tcp_layer = layers.get("tcp")
            if tcp_layer:
                src_port = tcp_layer.get("tcp.srcport", "N/A")
                dst_port = tcp_layer.get("tcp.dstport", "N/A")
            elif "udp" in layers:
                udp_layer = layers["udp"]
                src_port = udp_layer.get("udp.srcport", "N/A")
                dst_port = udp_layer.get("udp.dstport", "N/A")

            highest_proto = frame.get("frame.protocols", "N/A").split(":")[-1].upper()

            # ----------------------------------------------------------
            #                     GeoIP (optional)
            # ----------------------------------------------------------
            dst_location = ""
            if hasattr(self, "_get_geoip_location"):
                dst_location = self._get_geoip_location(dst_ip)
            loc_str = f"({dst_location})" if dst_location else ""

            # ----------------------------------------------------------
            #                       Structured log
            # ----------------------------------------------------------
            tag_str = f" [{' | '.join(context_tags)}]" if context_tags else ""
            self.logger.log_message(
                f"[NetTrace-{interface_id}] Pkt:{packet_num:<6} | {timestamp} | Len:{packet_len:<5} | "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} {loc_str} | Proto:{highest_proto}{tag_str}"
            )

            # ----------------------------------------------------------
            #              Application‑layer quick peeks
            # ----------------------------------------------------------
            if "http" in layers:
                http = layers["http"]
                if "http.request.method" in http:
                    host = http.get("http.host", "")
                    uri = http.get("http.request.full_uri", "")
                    self.logger.log_message(
                        f"[HTTP-{interface_id}] {src_ip} → {host}{uri} ({http['http.request.method']}){tag_str}")
                elif "http.response.code" in http:
                    code = http["http.response.code"]
                    self.logger.log_message(
                        f"[HTTP-{interface_id}] {dst_ip} ← {code}{tag_str}")

            elif "ssl" in layers or "tls" in layers:
                tls = layers.get("ssl", layers.get("tls", {}))
                if "tls.handshake.extensions_server_name" in tls:
                    sni = tls["tls.handshake.extensions_server_name"]
                    self.logger.log_message(
                        f"[TLS-{interface_id}] SNI={sni} {src_ip}:{src_port} → {dst_ip}:{dst_port}{tag_str}")

            if "dns" in layers and layers["dns"].get("dns.qry.name"):
                dns = layers["dns"]
                qname = dns["dns.qry.name"]
                qtype = dns["dns.qry.type"]
                answer = dns.get("dns.a", dns.get("dns.aaaa", ""))
                self.logger.log_message(
                    f"[DNS-{interface_id}] {qname} ({qtype}) → {answer or 'NO-ANSWER'}{tag_str}")

            # ----------------------------------------------------------
            #           Optional reassembled payload preview (TCP)
            # ----------------------------------------------------------
            reassembled = None
            if tcp_layer and tcp_layer.get("tcp.payload"):
                reassembled = bytes.fromhex(tcp_layer["tcp.payload"].replace(":", "")).decode(
                    "utf-8", errors="ignore")
            elif "data-text-lines" in layers:
                reassembled = layers["data-text-lines"]

            if reassembled:
                # Check if the reassembled data is mostly printable ASCII
                printable_chars = sum(1 for char in reassembled if 32 <= ord(char) <= 126 or ord(char) in [9, 10,
                                                                                                           13])  # ASCII printable + tab, newline, carriage return
                total_chars = len(reassembled)

                if total_chars > 0 and (printable_chars / total_chars) > 0.7:  # Heuristic: >70% printable
                    self.logger.log_message(f"[StreamData-{interface_id}]{tag_str} Text Payload: {reassembled.strip()}")
                else:
                    # If not mostly printable, it's likely binary. Log hex for debugging.
                    # Limit hex output to avoid excessively long logs
                    raw_payload_hex = tcp_layer.get("tcp.payload", "").replace(":", "")
                    truncated_hex = raw_payload_hex[:128] + ("..." if len(raw_payload_hex) > 128 else "")
                    self.logger.log_message(
                        f"[StreamData-{interface_id}]{tag_str} Binary Payload (Hex): {truncated_hex}")
            else:
                self.logger.log_message(
                    f"[StreamData-{interface_id}]{tag_str} No reassembled text/binary payload found.")

        except Exception as e:
            self.logger.log_message(
                f"[Wireshark-Process] Error processing packet on interface {interface_id}: {e}")
    def _redirect_output(self, process: subprocess.Popen, interface_id: str):
        if not process.stdout: return
        json_buffer = ""
        decoder = json.JSONDecoder()
        for line in iter(process.stdout.readline, ''):
            if self.stop_event.is_set(): break
            json_buffer += line
            while True:
                start_index = json_buffer.find('{')
                if start_index == -1:
                    json_buffer = ""
                    break
                json_buffer = json_buffer[start_index:]
                try:
                    packet_data, index = decoder.raw_decode(json_buffer)
                    self._process_packet(packet_data, interface_id)
                    json_buffer = json_buffer[index:]
                except json.JSONDecodeError:
                    break
        self.logger.log_message(f"[Wireshark] Output stream ended for interface {interface_id}.")