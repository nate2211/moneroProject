import queue
import random
import socket
import ssl
from pathlib import Path
from socket import AF_INET
from typing import Optional, List, Tuple

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
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sendp, sniff
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ShortField, IntField, IPField, PacketListField
from scapy.layers.inet import IP, UDP        # (already imported elsewhere, keep only one copy)
from typing import Tuple, Dict, Literal


class RIPEntry(Packet):
    name = "RIPEntry"
    fields_desc = [
        ShortField("addr_family", 2),          # IPv4
        ShortField("route_tag",   0),
        IPField  ("address",     "0.0.0.0"),   # Network address
        IPField  ("subnet_mask", "0.0.0.0"),
        IPField  ("next_hop",    "0.0.0.0"),
        IntField ("metric",      1)            # 1–15 valid, 16 = infinity
    ]

class SimpleRIP(Packet):
    name = "SimpleRIP"
    fields_desc = [
        ByteField ("command", 2),              # 1 = request, 2 = response
        ByteField ("version", 2),              # RIPv2
        ShortField("unused",  0),
        PacketListField("entries", [], RIPEntry)
    ]

# Bind to UDP/520 so Scapy can dissect/construct automatically
bind_layers(UDP, SimpleRIP, dport=520)
bind_layers(UDP, SimpleRIP, sport=520)

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
            if packet.haslayer(IP):
                dst_ip = ipaddress.ip_address(packet[IP].dst)

                if not (dst_ip.is_global or dst_ip.is_private):
                    ## ENHANCED LOGGING ##
                    self.logger.log_message(
                        f"[PacketWriter] 🚫 Dropped non-unicast packet to {dst_ip}. Summary: {packet.summary()}"
                    )
                    return
                else:
                    packet_summary = packet.summary()
                    sendp(packet, iface=interface, verbose=0)
                    ## ENHANCED LOGGING ##
                    self.logger.log_message(
                        f"[PacketWriter] ✅ Sent (Len:{len(packet)}) on {interface} -> {packet_summary}"
                    )
            else:
                # For non-IP packets like ARP, etc.
                packet_summary = packet.summary()
                sendp(packet, iface=interface, verbose=0)
                ## ENHANCED LOGGING ##
                self.logger.log_message(
                    f"[PacketWriter] ✅ Sent (Len:{len(packet)}) on {interface} -> {packet_summary}"
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
    """
    def __init__(self, router_logger, packet_writer, interfaces_config: dict):
        self.log = router_logger
        self.pw = packet_writer
        self.ifaces = interfaces_config  # to know MAC & IP
        self.log.log_message("[ICMP] Manager initialized.")

    def handle_packet(self, pkt: Packet, inbound_iface: str) -> bool:
        # Only handle ICMP Echo-Requests (type 8)
        if not pkt.haslayer(ICMP) or pkt[ICMP].type != 8:
            return False

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        self.log.log_message(
            f"[ICMP] 📨 Echo-Request from {src_ip} to {dst_ip} on {inbound_iface}"
        )

        # Build Echo-Reply
        reply = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / \
                IP(src=dst_ip, dst=src_ip) / \
                ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / \
                pkt[ICMP].payload

        # Choose the correct outbound interface (same as inbound for router)
        # and queue the reply
        self.pw.queue_packet(reply, inbound_iface)
        self.log.log_message(
            f"[ICMP] ✅ Echo-Reply queued on {inbound_iface} for {src_ip}"
        )
        return True

HandshakeState = Literal["SYN_SENT", "SYN_ACK_RECEIVED", "ESTABLISHED", "CLOSING", "CLOSED"]

def _get_canonical_session_key(ip1: str, port1: int, ip2: str, port2: int) -> Tuple[str, int, str, int]:
    """Returns a canonical key for a connection regardless of which end is src/dst."""
    return tuple(sorted([(ip1, port1), (ip2, port2)])) # type: ignore


class HandshakeManager:
    """
    Tracks TCP 3-way handshakes and connection teardowns based on observed packets.
    It can be initialized with references to network managers (ARP, NAT, RIP)
    to provide broader network context, though its core function remains passive
    TCP state tracking.
    """
    def __init__(self, router_logger,
                 arp_manager,      # Kept: Provides ARP context
                 nat_manager,      # Kept: Provides NAT context
                 rip_manager,      # Kept: Provides routing table context
                 timeout_half_open: int = 60, timeout_established: int = 300):
        self.logger = router_logger

        # Key: canonical_key -> (state, last_seen_ts, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
        self._sessions: Dict[Tuple[str,int,str,int], Tuple[HandshakeState, float, str, int, str, int]] = {}
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
                    current_timeout = self.timeout_half_open if state in ["SYN_SENT", "SYN_ACK_RECEIVED"] else self.timeout_established
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
            if flags == 0x02: # SYN (just SYN flag)
                if session_state is None:
                    # New session: store original src/dst based on this SYN packet
                    self._sessions[canonical_key] = ("SYN_SENT", now, ip.src, tcp.sport, ip.dst, tcp.dport)
                    self.logger.log_message(f"[Handshake] SYN from {ip.src}:{tcp.sport} to {ip.dst}:{tcp.dport}")
                elif session_state == "SYN_SENT": # SYN retransmission
                    # Update timestamp to keep half-open session alive
                    self._sessions[canonical_key] = (session_state, now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    self.logger.log_message(f"[Handshake] SYN retransmission from {ip.src}:{tcp.sport}") # Optional: detailed logging
                # No other state should receive a plain SYN that advances state
                return True

            # SYN+ACK (Server response to SYN)
            elif flags == 0x12: # SYN+ACK (SYN and ACK flags set)
                if session_state == "SYN_SENT":
                    self._sessions[canonical_key] = ("SYN_ACK_RECEIVED", now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    self.logger.log_message(f"[Handshake] SYN-ACK from {ip.src}:{tcp.sport} to {ip.dst}:{tcp.dport}")
                elif session_state == "SYN_ACK_RECEIVED": # SYN+ACK retransmission
                    # Update timestamp to keep half-open session alive
                    self._sessions[canonical_key] = (session_state, now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    self.logger.log_message(f"[Handshake] SYN-ACK retransmission from {ip.src}:{tcp.sport}") # Optional: detailed logging
                return True

            # ACK (Client completing handshake, data ACK, or final ACK for FIN)
            elif flags == 0x10: # Pure ACK (only ACK flag)
                if session_state == "SYN_ACK_RECEIVED":
                    self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ✅ Connection ESTABLISHED: {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                    )
                elif session_state == "ESTABLISHED":
                    # Crucially, update timestamp for ESTABLISHED data flow
                    self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    # self.logger.log_message(f"[Handshake] Data packet seen on ESTABLISHED session {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}") # Optional: verbose data logging
                elif session_state == "CLOSING":
                    # This ACK completes a graceful close after a FIN
                    self._sessions[canonical_key] = ("CLOSED", now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    self.logger.log_message(f"[Handshake] ❎ Connection CLOSED (ACK after FIN): {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}")
                    del self._sessions[canonical_key] # Remove fully closed session
                return True

            # FIN (Initiating graceful close)
            # Check for FIN flag being set (0x01) along with other flags (e.g., ACK)
            elif flags & 0x01: # FIN flag is set (can be FIN, FIN+ACK, PSH+FIN+ACK, etc.)
                if session_state == "ESTABLISHED":
                    self._sessions[canonical_key] = ("CLOSING", now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    self.logger.log_message(f"[Handshake] 🔻 CLOSING initiated by {ip.src}:{tcp.sport} on {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}")
                elif session_state == "CLOSING": # Second FIN in the exchange
                    self._sessions[canonical_key] = ("CLOSED", now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                    self.logger.log_message(f"[Handshake] ❎ Connection CLOSED (Second FIN): {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}")
                    del self._sessions[canonical_key] # Remove fully closed session
                return True

            # RST (Abrupt close)
            # Check for RST flag being set (0x04)
            elif flags & 0x04: # RST flag is set (can be RST, RST+ACK, etc.)
                if current_session: # If we are tracking it, remove it
                    self.logger.log_message(f"[Handshake] ❌ RST received on session {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}. Forcibly closing.")
                    del self._sessions[canonical_key] # Remove abruptly closed session
                return True

            # For any other TCP packet on an ESTABLISHED connection (e.g., PSH|ACK for data)
            # Ensure the timestamp is updated even if no state change occurs.
            if current_session and current_session[0] == "ESTABLISHED":
                self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port, original_dst_ip, original_dst_port)
                # self.logger.log_message(f"[Handshake] Data packet seen on ESTABLISHED session {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}") # Optional: verbose data logging
                return True # Packet processed as part of an existing session

        return False # Packet was TCP/IP but not part of a tracked state change or existing session.


class IGMPManager:
    """
    Manages IP multicast group memberships using IGMPv2.
    Monitors IGMP reports and queries, maintains a membership table,
    and sends periodic IGMP queries.
    """

    def __init__(self, router_logger, packet_writer):
        self.router_logger = router_logger
        self.packet_writer = packet_writer # Will use PacketWriter for sending
        self.IGMP_ALL_HOSTS_GROUP = "224.0.0.1" # Standard multicast address for all hosts
        self.IGMP_QUERY_INTERVAL = 60      # Send general queries every 60 seconds
        self.IGMP_MEMBERSHIP_TIMEOUT = 260 # Group membership timeout (e.g., Query Interval * 2 + Query Response Interval)

        # _multicast_groups: { (multicast_ip_str, interface_full_name): last_report_timestamp }
        self._multicast_groups = {}
        self._group_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._interfaces_config = {} # Will be set by PythonRouterManager

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
        group_ip = str(igmp_layer.gaddr) # Group address associated with the message

        self.router_logger.log_message(f"[IGMP] Received {igmp_layer.type} packet on {inbound_ifname} from {src_ip} for group {group_ip}")

        with self._group_lock:
            if igmp_layer.type == 0x11:
                self.router_logger.log_message(f"[IGMP] Received Query (Type 0x11) for {group_ip} from {src_ip}. (No state change from query itself).")

            elif igmp_layer.type == 0x16:
                key = (group_ip, inbound_ifname)
                self._multicast_groups[key] = time.time()
                self.router_logger.log_message(
                    f"[IGMP] ✅ Host {src_ip} reported membership in {group_ip} on {inbound_ifname}. Table updated.")

            elif igmp_layer.type == 0x17:
                key = (group_ip, inbound_ifname)
                if key in self._multicast_groups:
                    del self._multicast_groups[key]
                    self.router_logger.log_message(
                        f"[IGMP] 🗑️ Host {src_ip} left group {group_ip} on {inbound_ifname}. Table updated.")
                else:
                    self.router_logger.log_message(
                        f"[IGMP] Host {src_ip} sent Leave for {group_ip} on {inbound_ifname}, but not in table.")
            else:
                self.router_logger.log_message(f"[IGMP] Ignored unsupported IGMP type: {igmp_layer.type}")

    def should_forward_multicast(self, multicast_ip: str, outbound_ifname: str) -> bool:
        """
        Determines if a multicast packet for `multicast_ip` should be forwarded
        to `outbound_ifname`.
        """

        if multicast_ip in [self.IGMP_ALL_HOSTS_GROUP, "224.0.0.9"]:
            return True


        with self._group_lock:
            key = (multicast_ip, outbound_ifname)
            if key in self._multicast_groups:
                # Check if the membership has timed out
                if (time.time() - self._multicast_groups[key]) < self.IGMP_MEMBERSHIP_TIMEOUT:
                    return True
                else:
                    self.router_logger.log_message(
                        f"[IGMP] Membership for {multicast_ip} on {outbound_ifname} timed out. Will purge.")
                    del self._multicast_groups[key] # Purge immediately if accessed
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
            if cfg.get("ip_addr") is None: # Skip interfaces without an IP
                continue

            igmp_packet = Ether(src=cfg["mac"], dst="01:00:5e:00:00:01") / \
                          IP(src=cfg["ip_addr"], dst=self.IGMP_ALL_HOSTS_GROUP, ttl=1) / \
                          IGMP(type=0x11, mrcode=100, gaddr="0.0.0.0") # gaddr=0.0.0.0 for General Query

            self.router_logger.log_message(f"[IGMP] Sending General Query on {ifname}")
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
                self.router_logger.log_message(f"[IGMP] 🗑️ Timed out and removed membership for {multicast_ip} on {ifname}.")

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
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.RIP_PORT = 520
        self.RIP_MCAST_ADDR = "224.0.0.9"
        self.RIP_UPDATE_INTERVAL = 10  # seconds
        self.ROUTE_TIMEOUT = 180  # seconds until a route is considered invalid

        self._routing_table = {}
        self._rt_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._interfaces_config = {}

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
                }
        self.router_logger.log_message(f"[RIP] Routing table initialized with {len(self._routing_table)} entries.")

    def find_route(self, dest_ip_str: str):
        """Finds the best route for a destination IP using longest prefix match."""
        try:
            dest_ip_obj = ipaddress.ip_address(dest_ip_str)
            best_match = None
            best_prefix = -1

            with self._rt_lock:
                for net, rt_details in self._routing_table.items():
                    if dest_ip_obj in net:
                        if net.prefixlen > best_prefix and rt_details["cost"] < 16:
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

    def handle_packet(self, pkt: Packet, inbound_ifname: str):
        """Processes an incoming RIP packet with detailed logging."""
        self.router_logger.log_message(f"[RIP] Received packet on {inbound_ifname}: {pkt.summary()}")

        rip = pkt.getlayer(SimpleRIP)
        if not rip:
            self.router_logger.log_message("[RIP] Ignored packet with no SimpleRIP layer.")
            return

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
                cost = min(entry.metric + 1, 16)
                current_route = self._routing_table.get(net)

                if current_route is None and cost < 16:
                    self._routing_table[net] = {
                        "next_hop": src_router,
                        "cost": cost,
                        "interface": inbound_ifname,
                        "advertised_by": src_router,
                        "last_update": time.time(),
                    }
                    self.router_logger.log_message(
                        f"[RIP] ✅ New route discovered: {net} via {src_router} (cost={cost})")
                    changed = True
                elif current_route and current_route["advertised_by"] == src_router:
                    if current_route["cost"] != cost:
                        self.router_logger.log_message(
                            f"[RIP] 🔄 Route update: {net} via {src_router} (cost changed {current_route['cost']}→{cost})")
                    current_route["cost"] = cost
                    current_route["last_update"] = time.time()
                    changed = True
                elif current_route and cost < current_route["cost"]:
                    self.router_logger.log_message(
                        f"[RIP] ✨ Better route found: {net} via {src_router} (cost improved {current_route['cost']}→{cost})")
                    self._routing_table[net] = {
                        "next_hop": src_router,
                        "cost": cost,
                        "interface": inbound_ifname,
                        "advertised_by": src_router,
                        "last_update": time.time(),
                    }
                    changed = True

        if changed:
            self.router_logger.log_message(f"[RIP] Routing table updated by neighbor {src_router}.")

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
            table_snapshot = list(self._routing_table.items())

        for ifname, cfg in self._interfaces_config.items():
            if cfg.get("ip_addr") is None:
                continue
            entries = [
                RIPEntry(
                    address=str(net.network_address),
                    subnet_mask=str(net.netmask),
                    metric=16 if details["interface"] == ifname and details["advertised_by"] != "self"
                    else details["cost"]
                ) for net, details in table_snapshot
            ]
            if not entries:
                continue

            rip_packet = Ether(src=cfg["mac"], dst="01:00:5e:00:00:09") / \
                         IP(src=cfg["ip_addr"], dst=self.RIP_MCAST_ADDR) / \
                         UDP(sport=self.RIP_PORT, dport=self.RIP_PORT) / \
                         SimpleRIP(command=2, version=2, entries=entries)
            try:
                self.router_logger.log_message(f"[RIP] Sending advertisement on {ifname} ({len(entries)} entries)")
                sendp(rip_packet, iface=ifname, verbose=0)
            except Exception as e:
                self.router_logger.log_message(f"[RIP] ❌ Advertisement send failed on {ifname}: {e}")

    def _purge_routes(self):
        """Removes routes that have not been updated recently."""
        with self._rt_lock:
            now = time.time()
            timed_out_routes = [
                net for net, details in self._routing_table.items()
                if details["advertised_by"] != "self" and (now - details["last_update"]) > self.ROUTE_TIMEOUT
            ]
            for net in timed_out_routes:
                del self._routing_table[net]
                self.router_logger.log_message(f"[RIP] 🗑️ Timed out and removed route: {net}")

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




class NATManager:
    """
    Manages Network Address Translation (NAT) with both:
      - dynamic NAT for outbound connections, and
      - static port‐forwarding mappings for inbound services.
    """

    def __init__(self, router_logger, router_public_ip: str):
        self.router_logger = router_logger
        self.public_ip = router_public_ip

        # Dynamic NAT port pool (IANA recommended private range)
        self.NAT_PORT_MIN = 49152
        self.NAT_PORT_MAX = 65535

        # key: (internal_ip, internal_port) -> external_port
        self._nat_table = {}
        # key: external_port -> (internal_ip, internal_port)
        self._nat_reverse_table = {}

        # Static port‐forwarding: external_port -> (internal_ip, internal_port)
        self._static_mappings = {}

        self._lock = threading.Lock()
        self._next_port = self.NAT_PORT_MIN
        self.add_static_mapping(
            external_port=65406,
            internal_ip="192.168.1.50",
            internal_port=88
        )

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
            port = self._next_port
            self._next_port += 1
            if self._next_port > self.NAT_PORT_MAX:
                self._next_port = self.NAT_PORT_MIN
            return port

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
                self._nat_table[key] = new_port
                self._nat_reverse_table[new_port] = key
                self.router_logger.log_message(
                    f"[NAT] ➡️ Created dynamic mapping: "
                    f"{ip.src}:{t.sport} → {self.public_ip}:{new_port}"
                )
            else:
                new_port = self._nat_table[key]
                self.router_logger.log_message(
                    f"[NAT] 🔄 Reusing dynamic mapping: "
                    f"{ip.src}:{t.sport} → {self.public_ip}:{new_port}"
                )

        # Rewrite packet
        ip.src = self.public_ip
        t.sport = new_port

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
            self.router_logger.log_message(
                f"[NAT] ✅  Dynamic mapping found: "
                f"{self.public_ip}:{ext_port} → {internal_ip}:{internal_port}"
            )
            ip.dst = internal_ip
            t.dport = internal_port
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
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.PRIMARY_DNS_SERVER = "8.8.8.8"  # Google's public DNS
        self._pending_requests = {}  # Tracks ongoing DNS queries
        self._lock = threading.Lock()

    def handle_query(self, packet, inbound_iface: str, router_interfaces: dict, get_mac_function, find_route_function):
        """
        Processes a DNS query packet, forwarding it to a public DNS server.
        Returns True if the packet was handled, False otherwise.
        """
        if not (packet.haslayer(DNS) and packet[DNS].qr == 0):  # 0 = query
            return False

        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet.getlayer(DNS)

        # Use the find_route_function to get the default route and its interface
        default_route = find_route_function("8.8.8.8")
        if not default_route:
            self.router_logger.log_message("[DNS] Cannot proxy query: No default route found.")
            return False

        outbound_iface_name = default_route.get("interface")
        if not outbound_iface_name or inbound_iface == outbound_iface_name:
            return False

        outbound_iface_config = router_interfaces.get(outbound_iface_name)
        if not outbound_iface_config:
            return False

        key = (ip_layer.src, udp_layer.sport, dns_layer.id)
        with self._lock:
            self._pending_requests[key] = {
                "original_mac_src": packet[Ether].src,
                "inbound_iface": inbound_iface
            }

        self.router_logger.log_message(
            f"[DNS] ➡️  Proxying query for {dns_layer.qd.qname.decode()} from {ip_layer.src}"
        )

        modified_packet = packet.copy()
        modified_packet[IP].src = outbound_iface_config['ip_addr']
        modified_packet[IP].dst = self.PRIMARY_DNS_SERVER
        modified_packet[Ether].src = outbound_iface_config['mac']

        gateway_ip = default_route.get("next_hop")
        target_mac = get_mac_function(gateway_ip, outbound_iface_name) if gateway_ip else None

        if not target_mac:
            self.router_logger.log_message(f"[DNS] Could not resolve gateway MAC for {gateway_ip}. Dropping query.")
            with self._lock:
                self._pending_requests.pop(key, None)
            return True

        modified_packet[Ether].dst = target_mac
        del modified_packet[IP].chksum
        del modified_packet[UDP].chksum

        try:
            sendp(modified_packet, iface=outbound_iface_name, verbose=0)
        except Exception as e:
            self.router_logger.log_message(f"[DNS] Failed to send proxied query: {e}")
            with self._lock:
                self._pending_requests.pop(key, None)
        return True

    def handle_response(self, packet, router_interfaces: dict):
        """
        Processes a DNS response, rewriting and forwarding it to the original client.
        Returns True if the packet was handled, False otherwise.
        """
        if not (packet.haslayer(DNS) and packet[DNS].qr == 1):
            return False

        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet.getlayer(DNS)
        key = (ip_layer.dst, udp_layer.dport, dns_layer.id)

        with self._lock:
            original_request = self._pending_requests.pop(key, None)

        if original_request:
            self.router_logger.log_message(
                f"[DNS] ⬅️  Routing response for {dns_layer.qd.qname.decode()} to {key[0]}"
            )

            response_iface_name = original_request["inbound_iface"]
            response_iface_config = router_interfaces.get(response_iface_name)
            if not response_iface_config:
                return True

            modified_packet = packet.copy()
            modified_packet[IP].src = self.PRIMARY_DNS_SERVER
            modified_packet[IP].dst = key[0]
            modified_packet[Ether].src = response_iface_config['mac']
            modified_packet[Ether].dst = original_request["original_mac_src"]

            del modified_packet[IP].chksum
            del modified_packet[UDP].chksum

            try:
                sendp(modified_packet, iface=response_iface_name, verbose=0)
            except Exception as e:
                self.router_logger.log_message(f"[DNS] Failed to send proxied response: {e}")
            return True
        return False

class ARPManager:
    """
    Manages ARP resolution, caching, and related ARP operations for the router.
    """

    def __init__(self, router_logger, cache_timeout_seconds=300):
        """
        Initializes the ARP Manager.
        Args:
            router_logger: The logger instance for logging messages.
            cache_timeout_seconds (int): How long a cache entry is valid.
        """
        self.router_logger = router_logger
        self._arp_cache = {}  # Maps IP -> (MAC, timestamp)
        self._arp_cache_lock = threading.Lock()
        self.CACHE_TIMEOUT = cache_timeout_seconds

    def resolve(self, ip_address: str, iface: str) -> str | None:
        """
        Resolves an IP address to a MAC address using the ARP protocol.
        Checks the cache first. If the entry is not found or is stale, it sends a new ARP request.
        """
        ip_address = ip_address.strip()  # Normalize input

        # --- Check cache first ---
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
                self.router_logger.log_message(f"[ARP] ⚠️ No ARP reply for {ip_address} on {iface}")
                return None
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Exception while resolving {ip_address}: {e}")
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

class PythonRouterManager:
    """
    Manages sniffing packets on multiple interfaces and routing them
    based on a simplified routing table. Self-contained for interface discovery and IP assignment.
    """

    # --- Configuration Defaults (used if dynamic assignment fails or as starting points) ---
    DEFAULT_IN_IFACE_FRIENDLY_NAME = "Ethernet"
    DEFAULT_OUT_IFACE_FRIENDLY_NAME = "Wi-Fi"

    # Default private IP ranges to try for the IN interface if auto-picking
    PRIVATE_SUBNETS_TO_TRY = [
        "192.168.100.0/24", "192.168.101.0/24", "192.168.102.0/24", "192.168.103.0/24",
        "10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24",
        "172.16.10.0/24", "172.16.11.0/24", "172.16.12.0/24"
    ]

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self._interfaces_config = {}
        self.interface_in_full_name = None
        self.interface_in_friendly_name = None
        self.interface_out_full_name = None
        self.interface_out_friendly_name = None
        self.router_ip_in = None
        self.router_ip_out = None
        self.router_gateway_out_ip = None

        self._sniff_threads = {}
        self._stop_sniffing_event = threading.Event()
        self._tshark_path = None
        self._discovered_tshark_interfaces = []

        # Instantiate all specialized managers
        self.dns_manager = DNSManager(router_logger)
        self.rip_manager = RIPManager(router_logger)
        self.nat_manager = None  # Initialized after public IP is known
        self.tls_proxy_manager = TLSProxyManager(router_logger)
        self.arp_manager = ARPManager(router_logger)

        self.packet_writer = PacketWriter(router_logger)
        self.handshake_manager = None
        self.igmp_manager = IGMPManager(router_logger, self.packet_writer) # NEW: IGMP Manager
        self.icmp_manager = ICMPManager(router_logger, self.packet_writer, self._interfaces_config)
        self.router_logger.log_message("[RouterManager] Orchestrator Initialized.")

    def _get_tshark_path(self) -> str | None:
        """Discover the path to tshark.exe (copied from your WiresharkManager)."""
        if getattr(sys, "frozen", False):
            tshark_exe = Path(sys._MEIPASS) / "tools" / "Wireshark" / "tshark.exe"
            if tshark_exe.exists():
                return str(tshark_exe)

        server_dir = Path(__file__).resolve().parent
        project_root = server_dir.parent
        tools_dir = project_root / "client" / "tools" / "Wireshark"
        candidate = tools_dir / "tshark.exe"
        if candidate.exists():
            return str(candidate)

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
        Adds firewall rules to allow traffic between IN and OUT interfaces.
        """
        try:
            for direction, iface in [("Outbound", self.interface_out_friendly_name),
                                     ("Inbound", self.interface_out_friendly_name)]:
                rule_name = f"PythonRouter-Allow-{direction}"
                direction_flag = "Out" if direction == "Outbound" else "In"

                ps_command = [
                    "powershell.exe",
                    "-Command",
                    f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction {direction_flag} "
                    f"-InterfaceAlias '{iface}' -Action Allow -Profile Any -Protocol Any"
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
            for rule_name in ["PythonRouter-Allow-Outbound", "PythonRouter-Allow-Inbound"]:
                ps_command = ["powershell.exe", "-Command", f"Remove-NetFirewallRule -DisplayName '{rule_name}'"]
                result = subprocess.run(ps_command, capture_output=True, text=True,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    self.router_logger.log_message(f"[Firewall] 🧹 Removed rule: {rule_name}")
                else:
                    self.router_logger.log_message(
                        f"[Firewall] ⚠️ Failed to remove rule: {rule_name}. STDERR: {result.stderr.strip()}")
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
        # Crucial: Add 'source=static', 'address=', and 'mask=' tags
        netsh_args = [
            "set", "address",
            f'name={iface_friendly_name}',
            "source=static",
            f"address={ip_address}",  # ADDED 'address=' tag
            f"mask={netmask}"  # ADDED 'mask=' tag
        ]

        if gateway:
            netsh_args.append(f"gateway={gateway}")
            netsh_args.append("gwmetric=1")  # Metric
        else:
            netsh_args.append("gateway=none")

        # Call _execute_netsh with the fully constructed arguments
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
                    if addr.family == AF_INET and addr.address and addr.netmask:
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
        Automatically finds and configures IN and OUT interfaces.
        Sets their IP addresses dynamically and determines default gateway.
        """
        in_iface_info = None  # Initialize
        out_iface_info = None  # Initialize

        self.router_logger.log_message("[RouterManager] Attempting to auto-configure IN and OUT interfaces...")

        for iface_info in self._discovered_tshark_interfaces:
            # Check for IN interface
            # Corrected: Use `is None` for explicit check against previous assignment
            if self.DEFAULT_IN_IFACE_FRIENDLY_NAME.lower() in iface_info[
                'friendly_name'].lower() and in_iface_info is None:
                in_iface_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found IN interface: {self.DEFAULT_IN_IFACE_FRIENDLY_NAME} as {in_iface_info['full_name']}")

            # Check for OUT interface
            # Corrected: Use `is None` for explicit check against previous assignment
            if self.DEFAULT_OUT_IFACE_FRIENDLY_NAME.lower() in iface_info[
                'friendly_name'].lower() and out_iface_info is None:
                out_iface_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found OUT interface: {self.DEFAULT_OUT_IFACE_FRIENDLY_NAME} as {out_iface_info['full_name']}")

            if in_iface_info is not None and out_iface_info is not None:
                break  # Both found, exit loop

        # IMPORTANT: If either interface was not found, exit *before* trying to use them.
        if in_iface_info is None or out_iface_info is None:
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Could not auto-configure required interfaces ('{self.DEFAULT_IN_IFACE_FRIENDLY_NAME}' and '{self.DEFAULT_OUT_IFACE_FRIENDLY_NAME}').")
            self.router_logger.log_message(
                f"[RouterManager] Please check interface names and ensure they are active. Available: {[i['friendly_name'] for i in self._discovered_tshark_interfaces]}")

            # Set internal attributes to None to reflect failure
            self.interface_in_full_name = None
            self.interface_out_full_name = None
            self.interface_in_friendly_name = None
            self.interface_out_friendly_name = None
            self.mac_in = None
            self.mac_out = None
            return False  # Exit early

        # Assign full and friendly names to instance attributes (only if both were found)
        self.interface_in_full_name = in_iface_info['full_name']
        self.interface_in_friendly_name = in_iface_info['friendly_name']
        self.interface_out_full_name = out_iface_info['full_name']
        self.interface_out_friendly_name = out_iface_info['friendly_name']

        # Step 2: Determine IP configurations for IN and OUT interfaces
        system_active_networks = self._get_system_networks()

        # For OUT interface: use its current IP config as router_ip_out
        current_out_ip = None
        current_out_netmask = None

        # Use the already resolved friendly name: self.interface_out_friendly_name
        for addr in psutil.net_if_addrs().get(self.interface_out_friendly_name, []):
            if addr.family == AF_INET:
                current_out_ip = addr.address
                current_out_netmask = addr.netmask
                break
        self._configure_firewall_rules()
        if current_out_ip and current_out_netmask:
            self.router_ip_out = current_out_ip
            self.router_netmask_out = current_out_netmask
            self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}",
                                                           strict=False)
            self.router_logger.log_message(
                f"[RouterManager] Using current IP for OUT interface '{self.interface_out_friendly_name}': {self.router_ip_out}/{self.router_netmask_out}")



        # Discover default gateway for the OUT interface (using friendly name)
        self.router_gateway_out_ip = self._get_default_gateway_for_interface(self.interface_out_friendly_name)


        # For IN interface: dynamically find an unused private subnet
        unused_in_ip = self._find_unused_private_subnet(system_active_networks)
        self.router_ip_in = unused_in_ip
        self.router_netmask_in = "255.255.255.0"
        self.router_network_in = ipaddress.ip_network(f"{self.router_ip_in}/{self.router_netmask_in}", strict=False)
        self.router_logger.log_message(
            f"[RouterManager] Dynamically assigned IP for IN interface '{self.interface_in_friendly_name}': {self.router_ip_in}/{self.router_netmask_in}")

        # Step 3: Assign IPs to interfaces using OS commands (netsh for Windows)
        self.router_logger.log_message(
            "[RouterManager] Assigning IPs to interfaces via OS commands (Requires Admin). This may cause temporary network disruption.")

        # Assign IN interface IP (using its friendly name for netsh)
        if not self._assign_ip_to_interface(self.interface_in_friendly_name, self.router_ip_in, self.router_netmask_in):
            self.router_logger.log_message(
                "[RouterManager] CRITICAL ERROR: Failed to assign IP to IN interface. Routing may not work.")
            return False

        # Assign OUT interface IP with its (discovered/fallback) gateway (using its friendly name for netsh)
        if not self._assign_ip_to_interface(self.interface_out_friendly_name, self.router_ip_out,
                                            self.router_netmask_out,
                                            self.router_gateway_out_ip):
            self.router_logger.log_message(
                "[RouterManager] CRITICAL ERROR: Failed to assign IP to OUT interface. Routing may not work.")
            return False

        # Step 4: Update internal _interfaces_config with assigned IPs and MACs
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

        # Get our own MAC addresses (re-get after IP assignment for certainty)
        self.mac_in = get_if_hwaddr(self.interface_in_full_name)
        self.mac_out = get_if_hwaddr(self.interface_out_full_name)

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
        self.router_logger.log_message(f"[RouterManager] Set default gateway: {gateway_ip} via {outbound_iface_name}")
        return True

    def _start_single_sniffer(self, iface_name: str):
        """Starts a single sniffer thread for a given interface."""
        def sniffer_loop(name=iface_name):
            self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[1]} starting...")
            capture_filter = "icmp or arp or udp or tcp"

            try:
                sniff(
                    iface=name,
                    filter=capture_filter,
                    prn=lambda pkt: self._process_packet(pkt, name),
                    store=0,
                    promisc=True,
                    stop_filter=lambda p: self._stop_sniffing_event.is_set()
                )
            except Exception as e:
                # If a thread crashes, this will log it!
                self.router_logger.log_message(f"‼️ CRITICAL ERROR in sniffer thread for {name.split('_')[1]}: {e}")
            finally:
                self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[1]} has exited.")

        thread = threading.Thread(target=sniffer_loop, name=f"Sniffer-{iface_name.split('_')[1]}", daemon=True)
        self._sniff_threads[iface_name] = thread
        thread.start()
        self.router_logger.log_message(f"[Router] Sniffing started on {iface_name.split('_')[1]}.")

    def _process_packet(self, packet, inbound_iface: str):
        """Main packet processing pipeline."""
        if not packet.haslayer(IP):
            return
        self.router_logger.log_message(f"CAPTURED on {inbound_iface.split('_')[1]}: {packet.summary()}")
        self.handshake_manager.handle_packet(packet, inbound_iface)

        # 1) ICMP ping
        if self.icmp_manager.handle_packet(packet, inbound_iface):
            return

        # --- High-priority packet handling ---
        # **FIX 3**: Call DNS handler with the correct, existing functions for ARP and routing.
        if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
            if self.dns_manager.handle_query(packet, inbound_iface, self._interfaces_config, self.arp_manager.resolve,
                                             self.rip_manager.find_route):
                return
            if self.dns_manager.handle_response(packet, self._interfaces_config):
                return
        # NEW: Handle IGMP packets if they are for the router (which they usually are)
        if packet.haslayer(IGMP):
            # Check if the destination IP is the router's IP on the inbound interface,
            # or a multicast group the router should listen to (e.g., 224.0.0.1 for general queries)
            dst_ip = packet[IP].dst
            inbound_if_ip = self._interfaces_config.get(inbound_iface, {}).get("ip_addr")
            if (dst_ip == inbound_if_ip) or (ipaddress.ip_address(dst_ip).is_multicast):
                self.igmp_manager.handle_packet(packet, inbound_iface)
                return # IGMP packets are usually processed locally, not forwarded
        dst_ip = packet[IP].dst
        router_ips = [cfg["ip_addr"] for cfg in self._interfaces_config.values() if "ip_addr" in cfg]
        is_for_router = any(dst_ip == ip for ip in router_ips)

        if is_for_router:
            if packet.haslayer(SimpleRIP):
                self.rip_manager.handle_packet(packet, inbound_iface)
                return

            # **FIX 2**: Correctly handle inbound NAT packets. Use the `inbound_iface` variable
            # instead of a hardcoded value.
            if self.nat_manager and self.nat_manager.translate_inbound(packet):
                self.router_logger.log_message(
                    f"[NAT] ✅ Inbound translation applied for packet now destined to "
                    f"{packet[IP].dst}:{(packet[TCP] if packet.haslayer(TCP) else packet[UDP]).dport}; forwarding."
                )
                self._forward_general_ip_packet(packet, inbound_iface)
            return

        # If not for the router, it's transit traffic to be forwarded
        self._forward_general_ip_packet(packet, inbound_iface)

    def _forward_general_ip_packet(self, packet, inbound_iface: str):
        """Forwards a transit packet, applying NAT and other rules."""
        ip_layer = packet.getlayer(IP)
        dst_ip = ip_layer.dst

        if ip_layer.ttl <= 1:
            self.router_logger.log_message(f"-> TTL expired for {dst_ip}. Dropping.")
            return

        route = self.rip_manager.find_route(dst_ip)
        if not route:
            self.router_logger.log_message(f"-> No route to {dst_ip}. Dropping.")
            return

        outbound_iface = route["interface"]
        next_hop_ip = route["next_hop"] if route["next_hop"] != "0.0.0.0" else dst_ip

        # Let's get the network object for the inbound interface
        inbound_net_config = self._interfaces_config.get(inbound_iface)
        inbound_network = inbound_net_config["network"] if inbound_net_config else None

        # Check if the packet is destined for a host on the same segment it came from
        is_intra_lan_traffic = (
            inbound_network and
            ipaddress.ip_address(dst_ip) in inbound_network and
            dst_ip != inbound_net_config["ip_addr"] # Not for the router itself
        )

        if inbound_iface == outbound_iface and not is_intra_lan_traffic:
            # This is a critical routing error: external traffic routed back to inbound interface.
            self.router_logger.log_message(
                f"-> ⚠️ POTENTIAL ROUTING LOOP: External traffic for {dst_ip} is routed back to {inbound_iface}."
            )
            # You might want to log the full routing table here for deeper debugging
            # self.router_logger.log_message(f"Current Routing Table: {self.rip_manager.get_routing_table_for_debug()}")

            return
        elif inbound_iface == outbound_iface and is_intra_lan_traffic:
            # This is legitimate intra-LAN traffic, allow it.
            # Your new broadcast logic for NBNS is handling this.
            self.router_logger.log_message(
                f"✅ FORWARDING (Intra-LAN): {packet.summary()} | In:{inbound_iface.split('_')[1]} -> Out:{outbound_iface.split('_')[1]}"
            )

        is_lan_to_wan = (inbound_iface == self.interface_in_full_name and
                         outbound_iface == self.interface_out_full_name)

        self.router_logger.log_message(
            f"✅ FORWARDING: {packet.summary()} | In:{inbound_iface.split('_')[1]} -> Out:{outbound_iface.split('_')[1]}"
        )

        if is_lan_to_wan and self.nat_manager:
            self.nat_manager.translate_outbound(packet)
        outbound_network = self._interfaces_config[outbound_iface]["network"]
        if ipaddress.ip_address(dst_ip) == outbound_network.broadcast_address:
            target_mac = "ff:ff:ff:ff:ff:ff"
            self.router_logger.log_message(f"-> Destination is broadcast ({dst_ip}). Setting MAC to {target_mac}")
        else:
            target_mac = self.arp_manager.resolve(next_hop_ip, outbound_iface)

        if not target_mac:
            self.router_logger.log_message(f"-> ARP failed for next hop {next_hop_ip}. Dropping.")
            return
        if not target_mac:
            self.router_logger.log_message(f"-> ARP failed for next hop {next_hop_ip}. Dropping.")
            return

        packet.ttl -= 1
        packet[Ether].src = self._interfaces_config[outbound_iface]["mac"]
        packet[Ether].dst = target_mac

        del ip_layer.chksum
        if packet.haslayer(TCP): del packet[TCP].chksum
        if packet.haslayer(UDP): del packet[UDP].chksum

        self.packet_writer.queue_packet(packet, outbound_iface)

    def start_routing(self):
        """Configures interfaces and starts all manager threads."""
        self._initialize_interface_discovery()
        if not self._auto_configure_interfaces():
            self.router_logger.log_message("[Router] Auto-configuration failed. Aborting start.")
            return

        self.nat_manager = NATManager(self.router_logger, self.router_ip_out)
        self.rip_manager.initialize_routes(self._interfaces_config, self.router_gateway_out_ip,
                                           self.interface_out_full_name)
        self.handshake_manager = HandshakeManager(self.router_logger, self.arp_manager, self.nat_manager, self.rip_manager)
        self.rip_manager.start()
        self.tls_proxy_manager.start()
        self.packet_writer.start()
        self.handshake_manager.start()
        self.igmp_manager.set_interfaces_config(self._interfaces_config)
        self.igmp_manager.start()
        self.router_logger.log_message("\n--- Python Router Starting Services ---")
        self._stop_sniffing_event.clear()
        for iface_name in self._interfaces_config.keys():
            self._start_single_sniffer(iface_name)

    def stop_routing(self):
        """Stops all manager threads and cleans up network interfaces."""
        self.router_logger.log_message("\n--- Python Router Stopping Services ---")
        self._stop_sniffing_event.set()

        # Stop all manager threads
        self.rip_manager.stop()
        self.tls_proxy_manager.stop()
        self.packet_writer.stop()
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