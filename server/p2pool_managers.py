import asyncio
import ctypes
import datetime
import os
import queue
import random
import socket
import ssl
import string
import traceback
import uuid
from collections import defaultdict, deque
from collections.abc import Set
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
import requests
import select
from PyQt5.QtCore import QObject, pyqtSignal
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from scapy.all import send, sr1, conf, get_if_list
from scapy.arch import get_if_hwaddr
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import TCP, IP, ICMP, UDP, IPerror
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sendp, sniff
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import ByteField, ShortField, IntField, IPField, PacketListField, Field, BitField, XByteField, \
    FieldLenField, StrFixedLenField, FlagsField
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict, Literal
import xml.etree.ElementTree as ET

class IP6Field(Field):
    """Custom Scapy field for handling IPv6 addresses."""

    def __init__(self, name, default):
        Field.__init__(self, name, default, "16s")

    def i2m(self, pkt, x):
        if x is None:
            return b"\0" * 16
        return socket.inet_pton(socket.AF_INET6, x)

    def m2i(self, pkt, x):
        return socket.inet_ntop(socket.AF_INET6, x)


class IPv6(Packet):
    name = "IPv6"
    fields_desc = [
        BitField("version", 6, 4),
        BitField("tc", 0, 8),  # Traffic Class
        BitField("fl", 0, 20),  # Flow Label
        ShortField("plen", None),  # Payload Length
        XByteField("nh", 0),  # Next Header
        ByteField("hlim", 64),  # Hop Limit
        IP6Field("src", "::1"),
        IP6Field("dst", "::1"),
    ]

    def post_build(self, p, pay):
        # Calculate payload length if not specified
        if self.plen is None:
            self.plen = len(pay)
        return p + pay


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


class ICMPv6EchoRequest(Packet):
    name = "ICMPv6 Echo Request"
    fields_desc = [
        ShortField("id", 0),
        ShortField("seq", 0),
        Raw("data", b"")
    ]


class ICMPv6EchoReply(ICMPv6EchoRequest):
    name = "ICMPv6 Echo Reply"


# --- ICMPv6 Neighbor Discovery Protocol (NDP) ---
class ICMPv6ND_Option(Packet):
    name = "ICMPv6 ND Option"
    fields_desc = [
        ByteField("type", 1),  # 1: Source Link-Layer, 2: Target Link-Layer
        FieldLenField("len", None, length_of="lladdr", fmt="B"),
        StrFixedLenField("lladdr", "", length=6)  # Link-Layer Address (MAC)
    ]


class ICMPv6ND_NS(Packet):
    name = "ICMPv6 Neighbor Solicitation"
    fields_desc = [
        IntField("res", 0),  # Reserved
        IP6Field("tgt", "::"),  # Target Address
        PacketListField("options", [], ICMPv6ND_Option, length_from=lambda pkt: pkt.underlayer.plen - 24)
    ]


class ICMPv6ND_NA(Packet):
    name = "ICMPv6 Neighbor Advertisement"
    fields_desc = [
        FlagsField("flags", 0, 32, "RSO"),  # R:Router, S:Solicited, O:Override
        IP6Field("tgt", "::"),  # Target Address
        PacketListField("options", [], ICMPv6ND_Option, length_from=lambda pkt: pkt.underlayer.plen - 24)
    ]


class ICMPv6ND_RA_Option(Packet):
    name = "ICMPv6 ND RA Option"
    fields_desc = [
        ByteField("type", 3),  # 3: Prefix Information
        FieldLenField("len", None, length_of="prefix", fmt="B"),
        ByteField("prefixlen", 64),
        FlagsField("flags", 0, 8, "LA"),  # L:On-Link, A:Autonomous
        IntField("validlifetime", 2592000),  # 30 days
        IntField("preflifetime", 604800),  # 7 days
        IntField("res2", 0),
        IP6Field("prefix", "::")
    ]


class ICMPv6ND_RA(Packet):
    name = "ICMPv6 Router Advertisement"
    fields_desc = [
        ByteField("chlim", 64),  # Current Hop Limit
        FlagsField("flags", 0, 8, "MOP"),  # M:Managed, O:Other, P:Proxy
        ShortField("routerlifetime", 1800),  # seconds
        IntField("reachtime", 0),
        IntField("retranstimer", 0),
        PacketListField("options", [], ICMPv6ND_RA_Option, length_from=lambda pkt: pkt.underlayer.plen - 16)
    ]


# --- RIPng (for IPv6) ---
class RIPngEntry(Packet):
    name = "RIPng Entry"
    fields_desc = [
        IP6Field("prefix", "::"),
        ShortField("route_tag", 0),
        ByteField("prefix_len", 0),
        ByteField("metric", 1)
    ]


class RIPng(Packet):
    name = "RIPng"
    fields_desc = [
        ByteField("command", 2),  # 1=request, 2=response
        ByteField("version", 1),
        ShortField("unused", 0),
        PacketListField("entries", [], RIPngEntry)
    ]

# --- Layer Bindings ---
bind_layers(Ether, IPv6, type=0x86DD)
bind_layers(IPv6, ICMPv6, nh=58)
bind_layers(IPv6, TCP, nh=6)
bind_layers(IPv6, UDP, nh=17)
bind_layers(ICMPv6, ICMPv6EchoRequest, type=128)
bind_layers(ICMPv6, ICMPv6EchoReply, type=129)
bind_layers(ICMPv6, ICMPv6ND_NS, type=135)
bind_layers(ICMPv6, ICMPv6ND_NA, type=136)
bind_layers(ICMPv6, ICMPv6ND_RA, type=134)
bind_layers(UDP, RIPng, dport=521)
bind_layers(UDP, RIPng, sport=521)

# endregion


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

class NotificationManager:
    """Sends simple UDP notifications for network events."""

    def __init__(self, router_logger, target_ip: str, target_port: int, iface: str):
        self.logger = router_logger
        self.target_ip = target_ip
        self.target_port = target_port
        self.outbound_iface = iface  # The interface to send notifications from
        self.logger.log_message(f"[Notifier] Initialized. Will send alerts to {target_ip}:{target_port}")

    def send_notification(self, event_data: dict):
        """Sends a JSON-formatted UDP packet."""
        try:
            message = json.dumps(event_data)
            self.logger.log_message(f"[Notifier] 📡 Sending notification: {message}")

            # Use Scapy to send a simple UDP packet
            # This doesn't require the PacketWriter as it's a simple, infrequent send
            packet = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=message)
            send(packet, iface=self.outbound_iface, verbose=0)

        except Exception as e:
            self.logger.log_message(f"[Notifier] ❌ Failed to send notification: {e}")


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

            if packet.haslayer(IP) or packet.haslayer(IPv6):
                if packet.haslayer(IP):
                    dst_ip_obj = ipaddress.ip_address(packet[IP].dst)
                else:
                    dst_ip_obj = ipaddress.ip_address(packet[IPv6].dst)

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
                        f"[PacketWriter] 📝 Sent (Len:{len(packet)}) on {interface.split('_')[-1]} -> {packet_summary}"
                    )
            else:
                # For non-IP packets like ARP, etc.
                packet_summary = packet.summary()
                sendp(packet, iface=interface, verbose=0)
                self.logger.log_message(
                    f"[PacketWriter] 📝 Sent (Len:{len(packet)}) on {interface.split('_')[-1]} -> {packet_summary}"
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

class ForwardingManager:
    """
    Tracks recently forwarded (src, dst, port, proto) flows to prevent looping or repeated forwards.
    """
    def __init__(self, router_logger=None, timeout: int = 60, max_entries: int = 10000):
        self.logger = router_logger or (lambda x: None)
        self.timeout = timeout  # seconds
        self._forwarded_cache = deque(maxlen=max_entries)
        self._forwarded_set: Set[Tuple] = set()
        self._lock = threading.Lock()

    def _prune_expired(self):
        now = time.time()
        while self._forwarded_cache and (now - self._forwarded_cache[0][1]) > self.timeout:
            key, _ = self._forwarded_cache.popleft()
            self.logger.log_message(f"[Forwarding] 🔁 Duplicate flow expired: {key}")
            self._forwarded_set.discard(key)

    def is_duplicate(self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: str) -> bool:
        """
        Returns True if the flow has been seen recently and should be considered a duplicate.
        """
        key = (src_ip, dst_ip, sport, dport, proto)
        now = time.time()
        with self._lock:
            self._prune_expired()
            if key in self._forwarded_set:
                if self.logger:
                    pass
                return True
            self._forwarded_cache.append((key, now))
            self._forwarded_set.add(key)
            return False

class EthernetBridgeManager:
    """
    Manages Layer 2 bridging (switching) between a group of interfaces.
    This allows multiple physical ports to act as a single broadcast domain.
    """

    def __init__(self, router_logger, packet_writer):
        self.logger = router_logger
        self.packet_writer = packet_writer
        self.MAC_TABLE_TIMEOUT = 300  # 5 minutes for MAC table entries

        # _bridges: { bridge_name: set(member_iface_full_name) }
        self._bridges: Dict[str, Set[str]] = {}
        self._bridge_lock = threading.Lock()

        # MAC address table: { mac_address: (interface_full_name, expiry_timestamp) }
        self._mac_table: Dict[str, Tuple[str, float]] = {}
        self._mac_table_lock = threading.Lock()

        self._stop_event = threading.Event()
        self._cleanup_thread = None
        self.logger.log_message("[Bridge] Manager initialized.")

    def create_bridge(self, bridge_name: str, member_interfaces: List[str]) -> bool:
        """Creates a new bridge group or updates an existing one."""
        if not member_interfaces:
            self.logger.log_message(f"[Bridge] ❌ Cannot create bridge '{bridge_name}': No member interfaces provided.")
            return False

        with self._bridge_lock:
            # Check if any of the proposed members are already in another bridge
            for iface in member_interfaces:
                for name, members in self._bridges.items():
                    if name != bridge_name and iface in members:
                        self.logger.log_message(
                            f"[Bridge] ❌ Interface {iface.split('_')[-1]} is already a member of bridge '{name}'.")
                        return False

            self._bridges[bridge_name] = set(member_interfaces)
            self.logger.log_message(
                f"[Bridge] ✅ Created/Updated bridge '{bridge_name}' with members: {[m.split('_')[-1] for m in member_interfaces]}")
        return True

    def remove_bridge(self, bridge_name: str) -> bool:
        """Removes a bridge group."""
        with self._bridge_lock:
            if bridge_name in self._bridges:
                del self._bridges[bridge_name]
                self.logger.log_message(f"[Bridge] 🗑️ Removed bridge '{bridge_name}'.")
                # Optionally, clear MAC table entries associated with this bridge's interfaces
                return True
            else:
                self.logger.log_message(f"[Bridge] ⚠️ Bridge '{bridge_name}' not found.")
                return False

    def is_bridge_member(self, iface_name: str) -> bool:
        """Checks if a given interface is part of any bridge."""
        with self._bridge_lock:
            for members in self._bridges.values():
                if iface_name in members:
                    return True
        return False

    def get_bridge_for_interface(self, iface_name: str) -> str | None:
        """Returns the name of the bridge an interface belongs to."""
        with self._bridge_lock:
            for name, members in self._bridges.items():
                if iface_name in members:
                    return name
        return None

    def learn_mac(self, mac_address: str, iface_name: str):
        """Adds or updates a MAC address in the forwarding table."""
        with self._mac_table_lock:
            # Do not learn broadcast or multicast MACs as source addresses
            if mac_address.lower() == "ff:ff:ff:ff:ff:ff" or mac_address.startswith(
                    "01:00:5e") or mac_address.startswith("33:33"):
                return

            if self._mac_table.get(mac_address, (None, 0))[0] != iface_name:
                self.logger.log_message(f"[Bridge] 🌉 Learned {mac_address} is on port {iface_name.split('_')[-1]}")
            self._mac_table[mac_address] = (iface_name, time.time() + self.MAC_TABLE_TIMEOUT)

    def handle_frame(self, frame: Packet, inbound_iface: str):
        """
        Processes a Layer 2 frame, either forwarding it to a specific port or flooding it.
        This method should only be called for interfaces that are part of a bridge.
        """
        if not frame.haslayer(Ether):
            self.logger.log_message(
                f"[Bridge] ⚠️ Non-Ethernet frame received on {inbound_iface.split('_')[-1]}. Dropping.")
            return

        src_mac = frame[Ether].src
        dst_mac = frame[Ether].dst
        ether_type = frame[Ether].type  # Get the EtherType field

        # --- NEW: Filter L2 traffic here ---
        # 1. Filter out known "noisy" or uninteresting EtherTypes for logging/deep processing
        #    Common EtherTypes:
        #    0x0800: IPv4
        #    0x0806: ARP
        #    0x86DD: IPv6
        #    0x88CC: LLDP (Link Layer Discovery Protocol) - often noisy
        #    0x88CC is LLDP, 0x8137 is IPX, etc.
        #    You might want to filter out specific vendor/management protocols.

        # Example: Log only IP, ARP frames, and broadcasts/multicasts for silent handling
        # You can adjust this list based on what you *do* want to log/process.
        # Everything else will be silently processed by the bridge.
        log_this_frame = False
        if ether_type in [0x0800, 0x0806, 0x86DD]:  # IPv4, ARP, IPv6
            log_this_frame = True
        elif dst_mac.lower() == "ff:ff:ff:ff:ff:ff" or dst_mac.startswith("01:00:5e") or dst_mac.startswith("33:33"):
            # Always log broadcasts/multicasts at a high level, as flooding is a core bridge function
            # but avoid logging *every detail* of every such frame if it's very frequent
            if ether_type not in [0x0800, 0x0806, 0x86DD]:  # Only log non-IP/ARP broadcasts
                self.logger.log_message(
                    f"[Bridge] 📡 L2 Flooding (Broadcast/Multicast Type {hex(ether_type)}) from {inbound_iface.split('_')[-1]}")
                # You might return here if you don't want to process these further, just flood.
        # --- END NEW FILTER ---

        # 1. Learn the source MAC address from the inbound frame.
        self.learn_mac(src_mac, inbound_iface)

        # 2. Determine the bridge this frame belongs to.
        bridge_name = self.get_bridge_for_interface(inbound_iface)
        if not bridge_name:
            self.logger.log_message(
                f"[Bridge] ⚠️ {inbound_iface.split('_')[-1]} is not in any bridge. Cannot handle frame.")
            return

        # 3. Look up the destination MAC in the table to find the target interface.
        with self._mac_table_lock:
            target_iface = self._mac_table.get(dst_mac, (None, 0))[0]

        # 4. Decide whether to forward to a specific port or flood.
        is_broadcast = dst_mac.lower() == "ff:ff:ff:ff:ff:ff"
        is_multicast = dst_mac.startswith("01:00:5e") or dst_mac.startswith("33:33:")

        # For logging: Only log detailed forwarding decisions for interesting frames
        if log_this_frame:
            if target_iface and not is_broadcast and not is_multicast:
                if target_iface == inbound_iface:
                    self.logger.log_message(f"[Bridge] ↩️ Dropping L2 Frame {src_mac}->{dst_mac} (same port).")
                else:
                    self.logger.log_message(
                        f"[Bridge] ➡️ Forwarding L2 Frame {src_mac} -> {dst_mac} on {target_iface.split('_')[-1]}")
            else:  # Flooding decision
                self.logger.log_message(
                    f"[Bridge] ❓ Flooding L2 Frame {src_mac} -> {dst_mac} (Unknown Unicast/Broadcast/Multicast) from {inbound_iface.split('_')[-1]}")

    def _cleanup_mac_table_loop(self):
        """Periodically removes stale entries from the MAC address table."""
        while not self._stop_event.is_set():
            now = time.time()
            with self._mac_table_lock:
                stale_macs = [mac for mac, (_, expiry) in self._mac_table.items() if expiry <= now]
                for mac in stale_macs:
                    del self._mac_table[mac]
                    self.logger.log_message(f"[Bridge] 🗑️ MAC table entry for {mac} expired.")
            self._stop_event.wait(60)

    def start(self):
        """Starts the MAC table cleanup thread."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_mac_table_loop, daemon=True,
                                                name="BridgeMacCleanup")
        self._cleanup_thread.start()
        self.logger.log_message("[Bridge] Cleanup thread started.")

    def stop(self):
        """Stops the MAC table cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self.logger.log_message("[Bridge] Stopping cleanup thread...")
            self._stop_event.set()
            self._cleanup_thread.join(timeout=2)
            self.logger.log_message("[Bridge] Cleanup thread stopped.")

class SYNScanner:
    """
    Manages periodic SYN scans for specified IP:port targets.
    Logs scan results and operates on a dedicated thread.
    """

    def __init__(self, router_logger, packet_writer, interfaces_config: Dict[str, Any],
                 scan_targets: Optional[List[Tuple[str, List[int]]]] = None, scan_interval: int = 60):
        """
        Initializes the SYNScanner.

        Args:
            router_logger: A logger instance for logging messages.
            packet_writer: A PacketWriter instance for sending packets (though sr1/send are used directly for scan results).
            interfaces_config: Dictionary of network interfaces configuration {full_name: config_dict}.
            scan_targets: A list of tuples, where each tuple contains (target_ip: str, list_of_ports: List[int]).
                          If None, a default set of targets will be used.
            scan_interval: The interval in seconds between full scan cycles.
        """
        self.router_logger = router_logger
        self.packet_writer = packet_writer  # Kept for consistency, but sr1/send are blocking calls.
        self.interfaces_config = interfaces_config
        self.scan_targets = scan_targets if scan_targets is not None else [
            ("8.8.8.8", [53, 80]),
            ("1.1.1.1", [443, 80]),
        ]
        self.scan_interval = scan_interval

        self._scannable_interfaces = []
        self._populate_scannable_interfaces()

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.router_logger.log_message("[SYNScanner] Initialized.")
        if not self._scannable_interfaces:
            self.router_logger.log_message(
                "[SYNScanner] Warning: No suitable non-loopback interfaces with an IP found for scanning.")

    def _populate_scannable_interfaces(self):
        """Identifies and stores network interfaces suitable for SYN scanning."""
        self._scannable_interfaces.clear()
        for iface_full_name, cfg in self.interfaces_config.items():
            # Only consider interfaces with an IP address and not loopback
            if cfg.get("ip_addr") and not ("loopback" in iface_full_name.lower() or "lo" == iface_full_name.lower()):
                self._scannable_interfaces.append(iface_full_name)
        self.router_logger.log_message(f"[SYNScanner] Found {len(self._scannable_interfaces)} scannable interfaces.")

    def start(self):
        """Starts the periodic SYN scanning thread."""
        if self._thread and self._thread.is_alive():
            self.router_logger.log_message("[SYNScanner] Already running.")
            return

        # Re-populate scannable interfaces in case config changed since init
        self._populate_scannable_interfaces()
        if not self._scannable_interfaces:
            self.router_logger.log_message("[SYNScanner] Cannot start: No scannable interfaces available.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_scan_loop, daemon=True, name="SYNScannerThread")
        self._thread.start()
        self.router_logger.log_message("[SYNScanner] Thread started.")

    def stop(self):
        """Stops the periodic SYN scanning thread gracefully."""
        if not self._thread or not self._thread.is_alive():
            return

        self.router_logger.log_message("[SYNScanner] Stopping thread...")
        self._stop_event.set()
        self._thread.join(timeout=5)
        self.router_logger.log_message("[SYNScanner] Thread stopped.")

    def _run_scan_loop(self):
        """The main loop for the SYN scanning thread."""
        self.router_logger.log_message("[SYNScanner] Scan loop started.")
        while not self._stop_event.is_set():
            if not self._scannable_interfaces:
                self.router_logger.log_message("[SYNScanner] No active scannable interfaces. Waiting...")
                self._stop_event.wait(self.scan_interval)
                self._populate_scannable_interfaces()  # Try to re-populate ifaces if they become available
                continue

            # Randomly select an interface for the current scan cycle
            selected_iface = random.choice(self._scannable_interfaces)
            self.router_logger.log_message(f"[SYNScanner] Commencing scan cycle using {selected_iface.split('_')[-1]}")

            for target_ip, ports in self.scan_targets:
                for port in ports:
                    if self._stop_event.is_set():
                        break  # Stop if event is set during inner loop

                    self.router_logger.log_message(
                        f"[SYNScanner] Scanning {target_ip}:{port} via {selected_iface.split('_')[-1]}..."
                    )
                    status, response_pkt = self._perform_syn_scan(target_ip, port, selected_iface)
                    self.router_logger.log_message(
                        f"[SYNScanner] Result for {target_ip}:{port} on {selected_iface.split('_')[-1]} -> {status}"
                    )
                    # Optional: Log full response packet for 'OPEN' or 'UNEXPECTED_RESPONSE'
                    if status in ['OPEN', 'UNEXPECTED_RESPONSE'] and response_pkt:
                        self.router_logger.log_message(f"[SYNScanner] Response summary: {response_pkt.summary()}")
                if self._stop_event.is_set():
                    break  # Stop if event is set during outer loop

            self.router_logger.log_message(f"[SYNScanner] Scan cycle completed. Waiting for {self.scan_interval}s.")
            self._stop_event.wait(self.scan_interval)
        self.router_logger.log_message("[SYNScanner] Scan loop has exited.")

    def _perform_syn_scan(self, target_ip: str, target_port: int, iface: str, timeout: float = 2.0) -> Tuple[
        str, Optional[Any]]:
        """
        Sends a single SYN packet and interprets the response.
        Returns a tuple: (status_string, response_packet_or_None).
        Status can be "OPEN", "CLOSED", "FILTERED", "TIMEOUT", "ERROR".
        """
        try:
            # Construct the SYN packet
            # Scapy will automatically select a source IP from the interface if not specified.
            # However, for consistency and control, explicitly setting source IP from config is better.
            src_ip = self.interfaces_config.get(iface, {}).get("ip_addr", None)
            if not src_ip:
                self.router_logger.log_message(
                    f"[SYNScanner] Warning: No source IP found for interface {iface}. Using default Scapy IP.")
                pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
            else:
                pkt = IP(src=src_ip, dst=target_ip) / TCP(dport=target_port, flags="S")

            # Send the SYN packet and wait for a response
            # sr1 is blocking, so it's fine within a dedicated thread.
            response = sr1(pkt, timeout=timeout, iface=iface, verbose=0)

            if response is None:
                return 'FILTERED (no response)', None
            elif response.haslayer(TCP):
                tcp_flags = response[TCP].flags
                if tcp_flags & 0x12:  # SYN-ACK (SYN=0x02, ACK=0x10 -> 0x12)
                    # Port is Open. Send an RST to gracefully tear down the connection.
                    rst_pkt = IP(dst=target_ip, src=response[IP].dst) / \
                              TCP(dport=target_port, sport=response[TCP].dport, flags="R", seq=response[TCP].ack)
                    send(rst_pkt, verbose=0, iface=iface)
                    return 'OPEN', response
                elif tcp_flags & 0x04:  # RST (RST=0x04)
                    return 'CLOSED', response
                else:
                    return f'UNEXPECTED_TCP_FLAGS ({hex(tcp_flags)})', response
            elif response.haslayer(ICMP):
                icmp_type = response[ICMP].type
                icmp_code = response[ICMP].code
                # ICMP type 3 (Destination Unreachable) with various codes
                if icmp_type == 3:
                    if icmp_code == 1:  # Host unreachable
                        return 'FILTERED (ICMP Host Unreachable)', response
                    elif icmp_code == 2:  # Protocol unreachable
                        return 'FILTERED (ICMP Protocol Unreachable)', response
                    elif icmp_code == 3:  # Port unreachable
                        return 'CLOSED (ICMP Port Unreachable)', response
                    elif icmp_code == 9 or icmp_code == 10:  # Admin prohibited
                        return 'FILTERED (ICMP Admin Prohibited)', response
                    else:
                        return f'FILTERED (ICMP Type 3, Code {icmp_code})', response
                else:
                    return f'UNEXPECTED_ICMP_RESPONSE (Type {icmp_type})', response
            else:
                return 'UNEXPECTED_NON_TCP_RESPONSE', response

        except Exception as e:
            self.router_logger.log_message(
                f"[SYNScanner] Error during scan of {target_ip}:{target_port} on {iface.split('_')[-1]}: {e}")
            return 'ERROR', None

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
        if not pkt.haslayer(TCP) or not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return False

        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        tcp = pkt[TCP]
        flags = tcp.flags
        if ip.src == self.nat_manager.public_ip:
            # Try reverse NAT map for source port
            orig = self.nat_manager.get_internal_from_external(tcp.sport)
            if orig:
                ip.src, tcp.sport = orig

        elif ip.dst == self.nat_manager.public_ip:
            # Try reverse NAT map for destination port
            orig = self.nat_manager.get_internal_from_external(tcp.dport)
            if orig:
                ip.dst, tcp.dport = orig
        canonical_key = _get_canonical_session_key(ip.src, tcp.sport, ip.dst, tcp.dport)

        with self._lock:
            current_session = self._sessions.get(canonical_key)
            session_state = current_session[0] if current_session else None
            original_src_ip = current_session[2] if current_session else ip.src
            original_src_port = current_session[3] if current_session else tcp.sport
            original_dst_ip = current_session[4] if current_session else ip.dst
            original_dst_port = current_session[5] if current_session else tcp.dport
            now = time.time()

            if flags == 0x02:  # SYN
                if session_state is None:
                    self._sessions[canonical_key] = ("SYN_SENT", now, ip.src, tcp.sport, ip.dst, tcp.dport)
                    self.logger.log_message(
                        f"[Handshake] 🔓 SYN from {ip.src}:{tcp.sport} to {ip.dst}:{tcp.dport}"
                    )
                elif session_state == "SYN_SENT":
                    self._sessions[canonical_key] = (session_state, now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔁 SYN retransmission from {ip.src}:{tcp.sport}"
                    )
                return True

            elif flags == 0x12:  # SYN+ACK
                if session_state == "SYN_SENT":
                    self._sessions[canonical_key] = ("SYN_ACK_RECEIVED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔐 SYN-ACK from {ip.src}:{tcp.sport} to {ip.dst}:{tcp.dport}"
                    )
                elif session_state == "SYN_ACK_RECEIVED":
                    self._sessions[canonical_key] = (session_state, now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔁 SYN-ACK retransmission from {ip.src}:{tcp.sport}"
                    )
                return True

            elif flags == 0x10:  # ACK
                if session_state == "SYN_ACK_RECEIVED":
                    self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ✅ Connection ESTABLISHED: {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                    )
                elif session_state == "ESTABLISHED":
                    self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    payload = bytes(tcp.payload)
                    if len(payload) >= 6 and payload[0] == 0x16:  # TLS
                        tls_version = payload[1:3]
                        tls_len = int.from_bytes(payload[3:5], "big")
                        handshake_type = payload[5]
                        tls_msg = TLS_HANDSHAKE_TYPES.get(handshake_type, f"Unknown({handshake_type})")
                        self.logger.log_message(
                            f"[TLS] 🛡 {tls_msg} (type={handshake_type}) seen in session {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                        )
                elif session_state == "CLOSING":
                    self._sessions[canonical_key] = ("CLOSED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ❎ Connection CLOSED (ACK after FIN): {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                    )
                    del self._sessions[canonical_key]
                return True

            elif flags & 0x01:  # FIN
                if session_state == "ESTABLISHED":
                    self._sessions[canonical_key] = ("CLOSING", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] 🔻 CLOSING initiated by {ip.src}:{tcp.sport} on {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                    )
                elif session_state == "CLOSING":
                    self._sessions[canonical_key] = ("CLOSED", now, original_src_ip, original_src_port,
                                                     original_dst_ip, original_dst_port)
                    self.logger.log_message(
                        f"[Handshake] ❎ Connection CLOSED (Second FIN): {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}"
                    )
                    del self._sessions[canonical_key]
                return True

            elif flags & 0x04:  # RST
                if current_session:
                    self.logger.log_message(
                        f"[Handshake] ❌ RST received on session {original_src_ip}:{original_src_port} ↔ {original_dst_ip}:{original_dst_port}. Forcibly closing."
                    )
                    del self._sessions[canonical_key]
                return True

            # Passive timestamp refresh for long-lived sessions
            if current_session and session_state == "ESTABLISHED":
                self._sessions[canonical_key] = ("ESTABLISHED", now, original_src_ip, original_src_port,
                                                 original_dst_ip, original_dst_port)
                return True

        return False  # Not a TCP handshake-related packet

    def get_internal_from_external(self, external_port: int) -> Optional[Tuple[str, int]]:
        """Returns (internal_ip, internal_port) for a NAT’d external port."""
        with self._lock:
            return self._nat_reverse_table.get(external_port)
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
                    f"[RIP] 📺 Sending advertisement on {ifname.split('_')[-1]} ({len(entries)} entries)")
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
        # _nat_ip_reverse_table: { external_ip -> internal_ip } for ICMP error messages
        self._nat_ip_reverse_table: Dict[str, str] = {}

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
                stale_port_keys = []
                for internal_key, (external_port, timestamp) in self._nat_table.items():
                    if now - timestamp > self.NAT_TIMEOUT_SECONDS:
                        stale_port_keys.append(internal_key)

                for internal_key in stale_port_keys:
                    external_port, _ = self._nat_table.pop(internal_key)
                    if external_port in self._nat_reverse_table:
                        del self._nat_reverse_table[external_port]
                    self.router_logger.log_message(
                        f"[NAT] 🗑️ Timed out dynamic port mapping: {internal_key[0]}:{internal_key[1]} -> {self.public_ip}:{external_port}"
                    )

                # Clean up IP reverse table (if direct IP NAT was implemented, which it isn't fully here)
                # For this basic NAT, IP mappings are implicitly tied to port mappings.
                # If a direct IP NAT (e.g., 1:1 NAT) were implemented, this would need more sophisticated cleanup.
                # For now, it's just linked to the public IP.

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
        # FTP ALG
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):  # FTP
            self.router_logger.log_message(
                f"[NAT][ALG] FTP ALG triggered ({direction}). (Placeholder: Actual payload inspection/rewriting needed)")
            # Example: For FTP, you would need to parse the FTP command/response,
            # find IP/port values, and rewrite them, then update TCP/IP checksums.
            # This is highly complex and protocol-specific.
            pass

        # DNS ALG (Minimal - typically DNS simply relies on port NAT)
        # A true DNS ALG might rewrite IPs within DNS A/AAAA records for specific scenarios (e.g., DNS doctoring)
        # But for typical NAT, it's not strictly necessary as clients resolve names, not IPs.
        if packet.haslayer(UDP) and packet.haslayer(DNS) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
            self.router_logger.log_message(
                f"[NAT][ALG] DNS traffic observed ({direction}). (No DNS payload rewriting by NAT.)")
            pass

    def translate_outbound(self, packet: Packet):
        """Perform dynamic NAT for outbound TCP/UDP, logging creation/reuse."""
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            # Handle ICMP special case: Outbound echo requests don't need port NAT, but their return errors might.
            # Also, ICMP Time Exceeded/Dest Unreachable messages from internal hosts typically don't need NAT.
            # Only if an internal IP is specifically mapped 1:1, or if ICMP is part of a tracked connection,
            # would it require stateful NAT awareness for its embedded headers.
            if packet.haslayer(ICMP) and packet.haslayer(IP):
                self.router_logger.log_message(
                    f"[NAT] Passing outbound ICMP for {packet[IP].src} to {packet[IP].dst} without port NAT.")
                # No port translation for ICMP, but the source IP will be overwritten by the router manager if it's external-bound
                # This function does not perform the source IP overwrite itself, that's done in _forward_general_ip_packet
                return  # Do not drop, let it continue.

            self.router_logger.log_message(
                f"[NAT] Skipping outbound translation for non-TCP/UDP/ICMP packet: {packet.summary()}"
            )
            return

        ip = packet[IP]

        # DHCP packets usually originate with 0.0.0.0 src IP and are broadcast/unicast to specific ports.
        # They are not typically NAT'd. If DHCP relay is in use, the relay agent (your DHCPServer class)
        # would modify the packet, not the NAT.
        if packet.haslayer(UDP) and (packet[UDP].sport == 68 or packet[UDP].dport == 67):  # DHCP client/server ports
            self.router_logger.log_message(
                f"[NAT] Skipping outbound NAT for DHCP packet from {ip.src}:{packet[UDP].sport}.")
            return  # DHCP is handled by DHCPServer, not NAT's port translation

        # IGMP packets are Layer 3 (IP protocol 2) and do not have ports. They are not subject to port NAT.
        if packet.haslayer(IGMP):
            self.router_logger.log_message(f"[NAT] Skipping outbound NAT for IGMP packet from {ip.src}.")
            return  # IGMP is handled by IGMPManager, not NAT's port translation

        # Proceed with TCP/UDP NAT
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
                # self._nat_ip_reverse_table[self.public_ip] = ip.src # This is for 1:1 NAT, not port NAT
                self.router_logger.log_message(
                    f"[NAT] ➡️ Created dynamic mapping: "
                    f"{ip.src}:{t.sport} → {self.public_ip}:{new_port}"
                )
            else:
                new_port, _ = self._nat_table[key]
                self._nat_table[key] = (new_port, time.time())  # Update timestamp on reuse
                self.router_logger.log_message(
                    f"[NAT] 🔄 Reusing dynamic mapping: "
                    f"{ip.src}:{t.sport} → {self.public_ip}:{new_port}"
                )

        # Rewrite packet (source IP will be rewritten by the router's main forwarding logic)
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
        ip = packet[IP]

        # ICMP error messages (e.g., Destination Unreachable, Time Exceeded) need special handling
        # if they contain the original packet's header which might refer to an internal NAT'd IP.
        if packet.haslayer(ICMP) and (packet[ICMP].type == 3 or packet[ICMP].type == 11):
            if packet.haslayer(IPerror):  # Check if it's an encapsulated IP header
                original_ip_in_error = packet[IPerror].dst
                # Check if this original_ip_in_error corresponds to one of our NAT'd sessions
                # This is complex as it requires matching the original flow's external_port.
                # For this simple NAT, we will primarily rely on the TCP/UDP reverse table.
                # A more robust stateful NAT would have a connection tracking table.
                self.router_logger.log_message(
                    f"[NAT] Inbound ICMP error for {original_ip_in_error}. Needs stateful check (not fully implemented).")
                # For basic functionality, if the destination of the ICMP error is our public IP,
                # we need to rewrite the IPerror.dst and potentially port in the encapsulated payload.
                # However, our current _nat_reverse_table maps external_port to (internal_ip, internal_port)
                # not external_ip to internal_ip for just an IP.
                # If the external IP is our public IP, it means the error is for our NAT'd connection.
                if ip.dst == self.public_ip:
                    # Attempt to find the original internal IP and port based on the encapsulated packet.
                    # This usually means inspecting the IPerror.payload, but that's beyond the scope of this basic NAT.
                    self.router_logger.log_message(
                        f"[NAT] ICMP error for router's public IP. Passing to router's ICMP manager.")
                    return False  # Let the router's ICMP manager handle it or drop it.
                return False  # ICMP error not directly handled by port NAT, let other logic apply.

        # DHCP packets (inbound to server port) are typically not NAT'd
        if packet.haslayer(UDP) and (packet[UDP].sport == 67 or packet[UDP].dport == 68):
            self.router_logger.log_message(
                f"[NAT] Skipping inbound NAT for DHCP packet to {ip.dst}:{packet[UDP].dport}.")
            return False  # DHCP is handled by DHCPServer, not NAT's port translation

        # IGMP packets are Layer 3 and do not have ports. They are not subject to port NAT.
        if packet.haslayer(IGMP):
            self.router_logger.log_message(f"[NAT] Skipping inbound NAT for IGMP packet to {ip.dst}.")
            return False  # IGMP is handled by IGMPManager, not NAT's port translation

        # Proceed with TCP/UDP NAT
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            self.router_logger.log_message(
                f"[NAT] Skipping inbound translation for non-TCP/UDP packet: {packet.summary()}"
            )
            return False

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

    def get_internal_from_external(self, external_port: int) -> Optional[Tuple[str, int]]:
        """Returns (internal_ip, internal_port) for a NAT’d external port."""
        with self._lock:
            return self._nat_reverse_table.get(external_port)

    def get_internal_ip_from_external(self, external_ip: str) -> Optional[str]:
        """
        Returns the internal IP corresponding to a NAT'd external IP.
        (Primarily for 1:1 NAT or specific ALG needs. For port NAT, it's more complex.)
        """
        # In the context of Port Address Translation (PAT/NAPT) as implemented here,
        # the 'external_ip' is always the router's public IP. So this helper might be less useful
        # unless you have explicit 1:1 NAT rules.
        # This implementation only stores mapping for IP+Port.
        # If external_ip matches the router's public_ip, it's our router.
        if external_ip == self.public_ip:
            # We would need to look up if this public IP maps to an internal IP in a 1:1 fashion.
            # Your current NAT table does not explicitly store this.
            # It's more about the external_port.
            self.router_logger.log_message(
                f"[NAT] Query for internal IP from external {external_ip}. Requires deeper NAT state knowledge.")
            return None  # Or return the IP of the LAN interface if it implies 1:1.
        return None

class DNSManager:
    """
    Manages DNS query proxying. Intercepts local DNS requests and forwards
    them to a public DNS server.
    Enhanced with DNS caching, conditional forwarding, and basic filtering.
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.PRIMARY_DNS_SERVER = "8.8.8.8"  # Google's public DNS
        self._pending_requests = {}
        self._lock = threading.Lock()
        self._dns_cache = {}
        self.DNS_CACHE_TTL_MIN = 60
        self.DNS_CACHE_MAX_ENTRIES = 1000
        self._conditional_forwarders = {}
        self._dns_blacklist = {}

    # ... (all other methods like add_blacklist, _get_from_cache, etc., are correct and remain the same) ...
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

    # --- FIX 1: Update the function signature ---
    def handle_query(self, packet, inbound_iface: str, router_interfaces: dict, get_mac_function, find_route_function,
                     packet_writer, router_lan_network: ipaddress.IPv4Network):
        if not (packet.haslayer(DNS) and packet[DNS].qr == 0):
            return False

        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet.getlayer(DNS)
        qname = dns_layer.qd.qname.decode() if dns_layer.qd else "unknown"

        if self._is_blacklisted(qname):
            blocked_response = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=ip_layer.dst, dst=ip_layer.src) / UDP(sport=udp_layer.dport, dport=udp_layer.sport) / DNS(id=dns_layer.id, qr=1, ra=1, rcode=3, qd=dns_layer.qd)
            packet_writer.queue_packet(blocked_response, inbound_iface)
            return True

        cached_response = self._get_from_cache(qname)
        if cached_response:
            response_pkt = cached_response.copy()
            response_pkt[IP].dst = ip_layer.src
            response_pkt[UDP].dport = udp_layer.sport
            response_pkt[DNS].id = dns_layer.id
            if response_pkt.haslayer(Ether):
                response_pkt[Ether].dst = packet[Ether].src
            del response_pkt[IP].chksum; del response_pkt[UDP].chksum
            packet_writer.queue_packet(response_pkt, inbound_iface)
            return True

        target_dns_server = self._get_forward_dns_server(qname)
        default_route = find_route_function(target_dns_server)
        if not default_route:
            return False

        outbound_iface_name = default_route.get("interface")
        if not outbound_iface_name:
            return False

        # --- FIX 2: Implement more intelligent loop prevention ---
        is_from_lan = ipaddress.ip_address(ip_layer.src) in router_lan_network

        if inbound_iface == outbound_iface_name and not is_from_lan:
            self.router_logger.log_message(f"[DNS] Not proxying DNS query from external source {ip_layer.src} to prevent loop.")
            return False

        outbound_iface_config = router_interfaces.get(outbound_iface_name)
        if not outbound_iface_config:
            return False

        key = (ip_layer.src, udp_layer.sport, dns_layer.id)
        with self._lock:
            self._pending_requests[key] = {
                "original_mac_src": packet[Ether].src if packet.haslayer(Ether) else None,
                "inbound_iface": inbound_iface
            }

        self.router_logger.log_message(f"[DNS] ➡️  Proxying query for {qname} from {ip_layer.src} to {target_dns_server}")

        modified_packet = packet.copy()
        modified_packet[IP].src = outbound_iface_config['ip_addr']
        modified_packet[IP].dst = target_dns_server

        if packet.haslayer(Ether):
            modified_packet[Ether].src = outbound_iface_config['mac']
            gateway_ip = default_route.get("next_hop") or target_dns_server
            target_mac = get_mac_function(gateway_ip, outbound_iface_name)
            if not target_mac:
                with self._lock: self._pending_requests.pop(key, None)
                return True
            modified_packet[Ether].dst = target_mac

        del modified_packet[IP].chksum
        del modified_packet[UDP].chksum
        packet_writer.queue_packet(modified_packet, outbound_iface_name)
        return True

    def handle_response(self, packet, router_interfaces: dict, packet_writer):
        # This method is correct and remains unchanged
        if not (packet.haslayer(DNS) and packet[DNS].qr == 1):
            return False

        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet[DNS]
        key = (ip_layer.dst, udp_layer.dport, dns_layer.id)
        qname = dns_layer.qd.qname.decode() if dns_layer.qd else "unknown"

        with self._lock:
            original_request = self._pending_requests.pop(key, None)

        if original_request:
            self.router_logger.log_message(f"[DNS] ⬅️  Routing response for {qname} to {key[0]}")
            self._add_to_cache(qname, packet)
            response_iface_name = original_request["inbound_iface"]
            response_iface_config = router_interfaces.get(response_iface_name)

            modified_packet = packet.copy()
            modified_packet[IP].src = response_iface_config['ip_addr']
            modified_packet[IP].dst = key[0]

            if original_request["original_mac_src"]:
                modified_packet[Ether].src = response_iface_config['mac']
                modified_packet[Ether].dst = original_request["original_mac_src"]
            else:
                 modified_packet = modified_packet[IP]

            del modified_packet[IP].chksum
            del modified_packet[UDP].chksum
            packet_writer.queue_packet(modified_packet, response_iface_name)
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
        self.notification_manager = None
        self._active_ips = set()
        self.router_logger = router_logger
        self.packet_writer = packet_writer  # Used for sending Gratuitous ARP
        self._arp_cache = {}  # Maps IP -> (MAC, timestamp)
        self._arp_cache_lock = threading.Lock()
        self.CACHE_TIMEOUT = cache_timeout_seconds
        self.dhcp_manager = None
        # ARP Snooping/Inspection (Placeholder)
        self._trusted_ports = set()  # Example: {'Ethernet_IN_Full_Name'}
        self._static_arp_entries = {}  # {IP: MAC} for trusted static entries

    def set_dhcp_server_reference(self, dhcp_server):
        """
        Sets a reference to the DHCPServer instance. This enables Dynamic ARP Inspection.
        """
        self.dhcp_server = dhcp_server
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

    def _perform_arp_inspection(self, pkt: Packet, inbound_iface: str) -> bool:
        """
        Performs Dynamic ARP Inspection (DAI).
        Returns True if the packet is valid, False if it should be dropped.
        """
        if not pkt.haslayer(ARP):
            return True

        arp_layer = pkt[ARP]
        sender_ip = arp_layer.psrc
        sender_mac = arp_layer.hwsrc
        # --- NEW: First-Use Detection Logic ---
        if sender_ip not in self._active_ips:
            # Check if this IP has a valid DHCP lease before activating
            if self.dhcp_server and sender_ip in self.dhcp_server.get_ip_to_mac_bindings():
                self._active_ips.add(sender_ip)
                self.router_logger.log_message(f"[ARP] ✅ First use of leased IP {sender_ip} by {sender_mac} detected.")

                # Send notification
                self.notification_manager.send_notification({
                    "event": "ip_in_use",
                    "ip": sender_ip,
                    "mac": sender_mac,
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                })
        # --- END NEW LOGIC ---

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
        if self.dhcp_server:
            dhcp_bindings = self.dhcp_server.get_ip_to_mac_bindings()

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
    def __init__(self, router_logger, packet_writer, router_in_interface_name: str, dhcp_pool_start: str,
                 dhcp_pool_end: str, interfaces_config: dict, dhcp_relay_target_ip: str = None):
        self.logger = router_logger
        self.packet_writer = packet_writer
        self.in_iface = router_in_interface_name
        self._interfaces_config = interfaces_config

        self.lease_pool_start = ipaddress.IPv4Address(dhcp_pool_start)
        self.lease_pool_end = ipaddress.IPv4Address(dhcp_pool_end)
        self._leases: Dict[str, Tuple[ipaddress.IPv4Address, float]] = {}
        self._lease_lock = threading.Lock()
        self.LEASE_DURATION_SECONDS = 3600
        self._stop_event = threading.Event()
        self._cleanup_thread = None

        self.dhcp_relay_target_ip = dhcp_relay_target_ip
        self.logger.log_message(
            f"[DHCP] Server initialized. Relay target: {self.dhcp_relay_target_ip if self.dhcp_relay_target_ip else 'None'}")


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
        """Periodically removes expired DHCP leases."""
        while not self._stop_event.is_set():
            now = time.time()
            with self._lease_lock:
                expired_macs = [mac for mac, (ip, expiry) in self._leases.items() if expiry <= now]
                for mac in expired_macs:
                    ip, _ = self._leases.pop(mac)
                    self.logger.log_message(f"[DHCP] 🗑️ Lease for {ip} (MAC: {mac}) expired and removed.")
            self._stop_event.wait(60)

    def _assign_ip(self, client_mac: str) -> ipaddress.IPv4Address | None:
        """
        Assigns an available IP address from the pool by checking the internal lease table.
        """
        with self._lease_lock:
            # 1. Check if the client already has an active lease to renew.
            if client_mac in self._leases:
                assigned_ip, expiry = self._leases[client_mac]
                if time.time() < expiry:
                    self._leases[client_mac] = (assigned_ip, time.time() + self.LEASE_DURATION_SECONDS)
                    self.logger.log_message(f"[DHCP] 🏠 Renewed lease for {assigned_ip} to {client_mac}")
                    return assigned_ip

            # 2. Find the next available IP address in the pool.
            leased_ips = {ip for ip, _ in self._leases.values()}
            for i in range(int(self.lease_pool_end) - int(self.lease_pool_start) + 1):
                potential_ip = self.lease_pool_start + i
                if potential_ip not in leased_ips:
                    # IP is not in our lease table, so we can assign it.
                    self._leases[client_mac] = (potential_ip, time.time() + self.LEASE_DURATION_SECONDS)
                    self.logger.log_message(f"[DHCP] 💻 Assigned new IP {potential_ip} to {client_mac}.")
                    return potential_ip

        # 3. If no IP was found after checking the entire pool.
        self.logger.log_message(f"[DHCP] ❌ No available IP addresses in pool for {client_mac}.")
        return None

    def handle_packet(self, pkt: Packet, inbound_iface: str, find_route_function) -> bool:
        """
        Handles incoming DHCP packets (DISCOVER, REQUEST).
        Returns True if the packet was a DHCP packet handled by the server.
        """
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

        # --- FIX: Determine if the request is from loopback by checking for an Ethernet layer ---
        is_loopback_request = not pkt.haslayer(Ether)

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

        if self.dhcp_relay_target_ip:
            return True

        # --- DHCP Server Logic ---
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

                # --- FIX: Construct L3 packet first, then conditionally add L2 header ---
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

                # --- FIX: Construct L3 packet first, then conditionally add L2 header ---
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
        if rule['protocol'] not in ['tcp', 'udp', 'icmp', 'any']:
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
                        self.logger.log_message(f"[Firewall] ✅ Packet permitted by rule {i}: {rule}")
                        return True
                    else:  # deny
                        self.logger.log_message(f"[Firewall] 🔥 Packet DENIED by rule {i}: {rule}")
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
    NOTIFICATION_TARGET_IP = "127.0.0.1"  # IP of the machine to receive alerts
    NOTIFICATION_TARGET_PORT = 12345       # UDP Port to listen on

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
        self.notification_manager = None
        self.arp_manager = ARPManager(router_logger, self.packet_writer)
        self.handshake_manager = None
        self.igmp_manager = IGMPManager(router_logger, self.packet_writer)
        self.icmp_manager = ICMPManager(router_logger, self.packet_writer, self._interfaces_config)
        self.dhcp_server = None
        self.outbound_load_balancer = OutboundLoadBalancer(router_logger)  # New: Outbound Load Balancer
        self.lag_manager = LinkAggregationManager(router_logger)  # New: Link Aggregation Manager
        self.firewall_manager = FirewallManager(router_logger)  # New: Firewall Manager
        self.syn_scanner = None
        self.ethernet_manager = EthernetBridgeManager(router_logger, self.packet_writer)
        self.forwarding_manager = ForwardingManager(router_logger=self.router_logger)
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

    def _setup_dynamic_firewall_manager_rules(self):
        """
        Adds firewall rules based on the dynamically configured LAN network.
        """
        if not self.router_network_in:
            self.router_logger.log_message("[Firewall] Skipping dynamic rule setup: LAN network not configured.")
            return

        lan_network_cidr = str(self.router_network_in)
        self.router_logger.log_message(f"[Firewall] Adding dynamic rules for LAN: {lan_network_cidr}")

        # Rule 1: Allow all traffic within the LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='any', src_ip=lan_network_cidr, dst_ip=lan_network_cidr,
            src_port='any', dst_port='any'
        )
        # Rule 2: Allow outbound HTTP/HTTPS from LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port=80
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port=443
        )
        # Rule 3: Allow outbound DNS from LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port=53
        )
        # Rule 4: Allow outbound ICMP (ping) from LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='icmp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port='any'
        )
        # Rule 5: Allow inbound traffic for established connections to the LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip='any', dst_ip=lan_network_cidr,
            src_port='any', dst_port='1024-65535'
        )
        self.firewall_manager.add_rule(
            action='deny', protocol='tcp', src_ip='any', dst_ip=lan_network_cidr, dst_port=22,
        )
        self.firewall_manager.add_rule(
            action='deny', protocol='tcp', src_ip='any', dst_ip=lan_network_cidr, dst_port=3389,
        )
        self.firewall_manager.add_rule(
            action='deny', protocol='tcp', src_ip='any', dst_ip=lan_network_cidr, dst_port=445,
        )
        self.firewall_manager.add_rule(action='permit', protocol='udp', src_ip='0.0.0.0', dst_ip='255.255.255.255', src_port=68,
         dst_port=67)
        self.firewall_manager.add_rule(action='permit', protocol='udp', src_ip='any', dst_ip='255.255.255.255', src_port=67,
         dst_port=68)

        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip=lan_network_cidr, dst_ip='224.0.0.9',
            src_port='any', dst_port=520
        )


        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip='any', dst_ip=lan_network_cidr,
            src_port=520, dst_port='any'
        )

        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip='any', dst_ip='any',
            src_port='any', dst_port=53
        )


        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip='any', dst_ip='any',
            src_port='any', dst_port=53
        )
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
        ethernet_2_info = None
        self.router_logger.log_message(
            "[RouterManager] Attempting to auto-configure IN, OUT, and Loopback interfaces...")

        for iface_info in self._discovered_tshark_interfaces:
            # Check for IN interface
            if self.DEFAULT_IN_IFACE_FRIENDLY_NAME.lower() == iface_info['friendly_name'].lower() and in_iface_info is None:
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
            if ("ethernet 2" in iface_info['friendly_name'].lower()):
                ethernet_2_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found Ethernet 2 interface")

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
        bridge_members = [self.interface_in_full_name]
        if ethernet_2_info:
            try:
                eth2_mac = get_if_hwaddr(ethernet_2_info["full_name"])
                eth2_ip = None
                eth2_netmask = None
                for addr in psutil.net_if_addrs().get(ethernet_2_info["friendly_name"], []):
                    if addr.family == socket.AF_INET:
                        eth2_ip = addr.address
                        eth2_netmask = addr.netmask
                        break
                if eth2_ip and eth2_netmask:
                    eth2_network = ipaddress.ip_network(f"{eth2_ip}/{eth2_netmask}", strict=False)
                    self._interfaces_config[ethernet_2_info["full_name"]] = {
                        "ip_addr": eth2_ip,
                        "network": eth2_network,
                        "mac": eth2_mac
                    }
                else:
                    self._interfaces_config[ethernet_2_info["full_name"]] = {
                        "ip_addr": "0.0.0.0",
                        "network": None,
                        "mac": eth2_mac
                    }
                self.router_logger.log_message(
                    f"[RouterManager] Added Ethernet 2 to config: {ethernet_2_info['full_name']}, MAC: {eth2_mac}")
                bridge_members.append(ethernet_2_info["full_name"])
            except Exception as e:
                self.router_logger.log_message(f"[RouterManager] ⚠️ Failed to add Ethernet 2 to bridge: {e}")

        # ✅ Create LAN bridge with discovered members
        self.create_l2_bridge("MyLANBridge", bridge_members)
        self.create_link_aggregation_group("MyLanAggregation", bridge_members)
        self.add_outbound_load_balancing_interface(self.interface_in_full_name)
        self.router_logger.log_message("[RouterManager][ARP] 🔒 Configuring trusted ARP interfaces and static entries...")

        # Trust the IN interface
        self.add_trusted_arp_port(self.interface_in_full_name)

        # Optionally trust Ethernet 2 (if used in bridging)
        if ethernet_2_info:
            self.add_trusted_arp_port(ethernet_2_info["full_name"])

        # Example: Add static ARP entry for gateway (if known)
        if self.router_gateway_out_ip:
            try:
                gateway_mac = self.arp_manager.resolve(self.router_gateway_out_ip)
                if gateway_mac:
                    self.add_static_arp_entry(self.router_gateway_out_ip, gateway_mac)
                    self.router_logger.log_message(
                        f"[RouterManager][ARP] 📌 Added static ARP entry for gateway {self.router_gateway_out_ip} → {gateway_mac}")
            except Exception as e:
                self.router_logger.log_message(f"[RouterManager][ARP] ⚠️ Failed to resolve gateway MAC: {e}")

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
        return True

    def _enable_nat_forwarding(self):
        """
        Enables NAT forwarding by first removing any old NAT instances and then creating a new one.
        This makes the operation idempotent and resilient to crashes.
        """
        if not self.router_network_in:
            self.router_logger.log_message("[NAT Setup] ⚠️ Cannot enable NAT: IN network is not configured.")
            return

        # --- Step 1: Unconditionally clean up any previous NAT rules ---
        # This prevents errors caused by stale configurations from a previous run.
        self._disable_nat_forwarding()

        # --- Step 2: Create the new NAT rule ---
        lan_network_cidr = str(self.router_network_in)
        self.router_logger.log_message(f"[NAT Setup] 🚀 Enabling NAT for network {lan_network_cidr}...")

        ps_command = [
            "powershell.exe",
            "-Command",
            f'New-NetNat -Name "PythonRouterNAT" -InternalIPInterfaceAddressPrefix "{lan_network_cidr}"'
        ]

        try:
            # Run the command. It requires administrator privileges.
            result = subprocess.run(ps_command, capture_output=True, text=True, check=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.router_logger.log_message("[NAT Setup] ✅ NAT forwarding enabled successfully.")
            if result.stdout:
                self.router_logger.log_message(f"[NAT Setup] PowerShell output: {result.stdout.strip()}")

        except subprocess.CalledProcessError as e:
            # After the cleanup step, an error here indicates a more serious problem.
            self.router_logger.log_message(f"[NAT Setup] ❌ Failed to enable NAT. Error: {e.stderr.strip()}")
            self.router_logger.log_message(
                "[NAT Setup] ℹ️ Please ensure this script is run with Administrator privileges.")
        except FileNotFoundError:
            self.router_logger.log_message("[NAT Setup] ❌ PowerShell not found. Cannot enable NAT.")
        except Exception as e:
            self.router_logger.log_message(f"[NAT Setup] ❌ An unexpected error occurred while enabling NAT: {e}")

    def _disable_nat_forwarding(self):
        """
        Removes the NAT forwarding rule created by the router.
        """
        self.router_logger.log_message("[NAT Setup] 🧹 Disabling NAT forwarding...")

        # The PowerShell command to remove the NAT rule by the name we gave it.
        # -Confirm:$false prevents it from asking "Are you sure?"
        ps_command = [
            "powershell.exe",
            "-Command",
            'Remove-NetNat -Name "PythonRouterNAT" -Confirm:$false'
        ]

        try:
            subprocess.run(ps_command, capture_output=True, text=True, check=False,
                           # check=False to ignore errors if rule doesn't exist
                           creationflags=subprocess.CREATE_NO_WINDOW)
            self.router_logger.log_message("[NAT Setup] ✅ NAT forwarding rule removed (if it existed).")
        except Exception as e:
            self.router_logger.log_message(f"[NAT Setup] ⚠️ An error occurred while disabling NAT: {e}")

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
        """Main packet processing pipeline with verbose logging."""
        try:
            iface_short = inbound_iface.split('_')[-1]

            # 0. Initial validation
            if not (packet.haslayer(IP) or packet.haslayer(IPv6) or packet.haslayer(ARP)):

                return

            # 1. Duplicate Flow Check
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
                sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else 0
                dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 0

                if self.forwarding_manager.is_duplicate(ip_layer.src, ip_layer.dst, sport, dport, proto):

                    return
            # 2. DHCP Early Handling
            if packet.haslayer(UDP) and {packet[UDP].sport, packet[UDP].dport} & {67, 68}:
                self.router_logger.log_message(f"[DHCP] 📦 DHCP packet detected on {iface_short}")
                if self.dhcp_server and self.dhcp_server.handle_packet(
                        packet, inbound_iface, self.rip_manager.find_route):
                    self.router_logger.log_message(f"[DHCP] ✅ Handled DHCP packet on {iface_short}")
                    return

            # 3. ARP Inspection
            if packet.haslayer(ARP):
                self.router_logger.log_message(f"[ARP] 🧠 Inspecting ARP packet on {iface_short}")
                if not self.arp_manager._perform_arp_inspection(packet, inbound_iface):
                    self.router_logger.log_message(f"[ARP] 🚫 Dropped ARP packet after inspection on {iface_short}")
                    return
                self.router_logger.log_message(f"[ARP] ✅ Passed inspection on {iface_short}")
                return

            # 4. DNS Handling
            if packet.haslayer(UDP) and {packet[UDP].sport, packet[UDP].dport} & {53}:
                self.router_logger.log_message(f"[DNS] 🗺️ Intercepting DNS packet on {iface_short}")

                # --- FIX 3: Add self.router_network_in to the call ---
                if self.dns_manager.handle_query(packet, inbound_iface, self._interfaces_config,
                                                 self.arp_manager.resolve,
                                                 self.rip_manager.find_route, self.packet_writer,
                                                 self.router_network_in):
                    self.router_logger.log_message(f"[DNS] 🌐 Handled DNS query on {iface_short}")
                    return
                if self.dns_manager.handle_response(packet, self._interfaces_config, self.packet_writer):
                    self.router_logger.log_message(f"[DNS] 🌐 Handled DNS response on {iface_short}")
                    return


            # 5. Firewall Check
            self.router_logger.log_message(f"[Firewall] 🔍 Inspecting packet on {iface_short}")
            if not self.firewall_manager.process_packet(packet):
                self.router_logger.log_message(f"[Firewall] 🔥 Blocked packet on {iface_short}")
                return

            # 6. ICMP Handling
            if self.icmp_manager.handle_packet(packet, inbound_iface):
                self.router_logger.log_message(f"[ICMP] 📬 Handled ICMP packet on {iface_short}")
                return


            # 7. IGMP Handling
            if packet.haslayer(IGMP):
                dst_ip = packet[IP].dst
                inbound_if_ip = self._interfaces_config.get(inbound_iface, {}).get("ip_addr")
                if (dst_ip == inbound_if_ip) or (ipaddress.ip_address(dst_ip).is_multicast):
                    self.router_logger.log_message(f"[IGMP] 📶 Processing IGMP on {iface_short}")
                    self.igmp_manager.handle_packet(packet, inbound_iface)
                    return

            # 8. NAT or RIP (if addressed to router)
            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            dst_ip = ip_layer.dst
            router_ips = [cfg["ip_addr"] for cfg in self._interfaces_config.values() if "ip_addr" in cfg]
            is_for_router = dst_ip in router_ips

            if is_for_router:
                if packet.haslayer(SimpleRIP):
                    self.router_logger.log_message(f"[RIP] 📘 RIP packet for router detected on {iface_short}")
                    self.rip_manager.handle_packet(packet, inbound_iface)
                    return

                if self.nat_manager and self.nat_manager.translate_inbound(packet):
                    self.router_logger.log_message(f"[NAT] 🔄 NAT translated inbound packet on {iface_short}")
                    self._forward_general_ip_packet(packet, inbound_iface)
                return

            # 9. TCP State Tracking
            self.router_logger.log_message(f"[TCP] 🧾 Tracking TCP/UDP state on {iface_short}")
            self.handshake_manager.handle_packet(packet, inbound_iface)

            # 10. Ethernet L2 Bridging
            if self.ethernet_manager.is_bridge_member(inbound_iface):
                if packet.haslayer(Ether):
                    self.router_logger.log_message(f"[Bridge] 🔗 Processing Layer 2 frame on {iface_short}")
                    self.ethernet_manager.handle_frame(packet, inbound_iface)
                    return
                else:
                    self.router_logger.log_message(
                        f"[Bridge] ⚠️ Non-Ethernet frame dropped on bridge port {iface_short}")
                    return

            # 11. General Forwarding (Transit)
            self.router_logger.log_message(f"[Forwarding] 🚚 Forwarding packet on {iface_short}")
            self._forward_general_ip_packet(packet, inbound_iface)

        except Exception as e:
            self.router_logger.log_message(
                f"[Router] ❗ ERROR while processing on {inbound_iface.split('_')[-1]}: {e}. Packet: {packet.summary()}")

    def _forward_general_ip_packet(self, packet, inbound_iface: str):
        """Forwards a transit packet, applying NAT, LAG, ARP resolution, and Layer 2 handling."""

        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        dst_ip = ip_layer.dst

        # --- [0] TTL Check ---
        if ip_layer.ttl <= 1:
            self.router_logger.log_message(f"[Router] ⌛ TTL expired for {dst_ip}. Dropping.")
            return

        # --- [1] Routing Lookup ---
        route = self.rip_manager.find_route(dst_ip)
        if not route:
            self.router_logger.log_message(f"[Router] 🛑 No route to {dst_ip}. Dropping.")
            return

        initial_outbound_iface = route["interface"]
        next_hop_ip = route["next_hop"] if route["next_hop"] != "0.0.0.0" else dst_ip

        # --- [2] Intra-LAN Loop Prevention ---
        inbound_config = self._interfaces_config.get(inbound_iface)
        inbound_network = inbound_config.get("network") if inbound_config else None
        is_intra_lan = (
                inbound_network and
                ipaddress.ip_address(dst_ip) in inbound_network and
                dst_ip != inbound_config.get("ip_addr")
        )

        if inbound_iface == initial_outbound_iface:
            if not is_intra_lan:
                self.router_logger.log_message(
                    f"[Router] 🔁 Routing loop detected! Traffic for {dst_ip} bounced back on {iface_short}. Dropping."
                )
                return
            else:
                self.router_logger.log_message(
                    f"[Router] 🏠 Intra-LAN forwarding: {packet.summary()} | In:{iface_short} -> Out:{iface_short}"
                )

        # --- [3] Load Balancing ---
        is_lan_to_wan = (
                inbound_iface == self.interface_in_full_name and
                initial_outbound_iface == self.interface_out_full_name
        )
        actual_outbound_iface = initial_outbound_iface

        if is_lan_to_wan and len(self.outbound_load_balancer.get_configured_interfaces()) > 1:
            selected_iface = self.outbound_load_balancer.get_next_interface(packet)
            if selected_iface:
                actual_outbound_iface = selected_iface
                self.router_logger.log_message(
                    f"[Router] 🔀 Load-balanced {dst_ip} to {actual_outbound_iface.split('_')[-1]}"
                )
            else:
                self.router_logger.log_message(f"[Router] ❌ No load-balanced interface available. Dropping.")
                return

        # --- [4] Multicast Filtering ---
        if ipaddress.ip_address(dst_ip).is_multicast:
            if not self.igmp_manager.should_forward_multicast(dst_ip, actual_outbound_iface):
                self.router_logger.log_message(
                    f"[Router] 📡 Dropping multicast {dst_ip} on {actual_outbound_iface.split('_')[-1]}: No members."
                )
                return

        self.router_logger.log_message(
            f"[Router] 🚚 Forwarding: {packet.summary()} | In:{iface_short} -> Out:{actual_outbound_iface.split('_')[-1]}"
        )

        # --- [5] Apply NAT (if applicable) ---
        if is_lan_to_wan and self.nat_manager:
            self.nat_manager.translate_outbound(packet)
            if packet[IP].src != self.nat_manager.public_ip:
                self.router_logger.log_message(f"[NAT] ❌ Packet dropped after NAT failure.")
                return

        # --- [6] Link Aggregation Handling ---
        final_outbound_iface = actual_outbound_iface
        if self.lag_manager.is_lag_interface(actual_outbound_iface):
            selected_member = self.lag_manager.get_member_interface(actual_outbound_iface, packet)
            if selected_member:
                final_outbound_iface = selected_member
                self.router_logger.log_message(
                    f"[Router] 🧵 LAG: Packet sent via member {final_outbound_iface.split('_')[-1]} of {actual_outbound_iface}."
                )
            else:
                self.router_logger.log_message(f"[Router] ❌ LAG {actual_outbound_iface} has no active members.")
                return

        # --- [7] Prepare L2 Details ---
        outbound_config = self._interfaces_config.get(final_outbound_iface)
        if not outbound_config:
            self.router_logger.log_message(
                f"[Router] ⚠️ Interface {final_outbound_iface.split('_')[-1]} not in config. Dropping."
            )
            return

        is_loopback = (
                ipaddress.ip_address(dst_ip).is_loopback or
                "loopback" in final_outbound_iface.lower() or
                final_outbound_iface.lower() == "lo"
        )
        outbound_network = outbound_config["network"]
        target_mac = None

        # --- [8] MAC Resolution ---
        if is_loopback:
            target_mac = "00:00:00:00:00:00"
            self.router_logger.log_message(
                f"[Router] 🌀 Loopback forwarding for {dst_ip}. No ARP needed."
            )
        elif ipaddress.ip_address(dst_ip) == outbound_network.broadcast_address:
            target_mac = "ff:ff:ff:ff:ff:ff"
            self.router_logger.log_message(f"[Router] 📢 Broadcast forwarding to {target_mac}")
        else:
            target_mac = self.arp_manager.resolve(next_hop_ip, final_outbound_iface)

        if not target_mac:
            self.router_logger.log_message(
                f"[Router] 🕵️ ARP failed for {next_hop_ip} on {final_outbound_iface.split('_')[-1]}. Dropping."
            )
            return

        # --- [9] TTL Decrement ---
        packet.ttl -= 1

        # --- [10] Adjust or Apply Ether Layer ---
        if is_loopback:
            if packet.haslayer(Ether):
                packet = packet[IP] / packet.payload  # strip Ethernet layer
        elif packet.haslayer(Ether):
            packet[Ether].src = outbound_config["mac"]
            packet[Ether].dst = target_mac
        else:
            self.router_logger.log_message(
                f"[Router] ⚠️ Packet missing Ether layer for {final_outbound_iface.split('_')[-1]}. Cannot send."
            )
            return

        # --- [11] Fix Checksums ---
        del ip_layer.chksum
        if packet.haslayer(TCP): del packet[TCP].chksum
        if packet.haslayer(UDP): del packet[UDP].chksum

        # --- [12] Send Packet ---
        self.packet_writer.queue_packet(packet, final_outbound_iface)
        self.router_logger.log_message(
            f"[Router] 📤 Packet queued to {final_outbound_iface.split('_')[-1]}"
        )

    def start_routing(self):
        """Configures interfaces and starts all manager threads."""
        self._initialize_interface_discovery()
        if not self._auto_configure_interfaces():
            self.router_logger.log_message("[Router] Auto-configuration failed. Aborting start.")
            return
        self._enable_nat_forwarding()
        self.nat_manager = NATManager(self.router_logger, self.router_ip_out)
        self.nat_manager.start()  # Start NAT cleanup thread
        self.notification_manager = NotificationManager(
            self.router_logger,
            self.NOTIFICATION_TARGET_IP,
            self.NOTIFICATION_TARGET_PORT,
            self.interface_in_full_name # Send notifications from the IN interface
        )
        # Assign the fully configured notifier to the ARP manager
        self.arp_manager.notification_manager = self.notification_manager
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
            self.arp_manager.set_dhcp_server_reference(self.dhcp_server)
        else:
            self.router_logger.log_message("[DHCP] DHCP Server not initialized: Router IN network not configured.")
        if self.dhcp_server:  # Start DHCP server if it was initialized
            self.dhcp_server.start()

        # Initialize RIP routes with all known interfaces, including loopback for direct connection
        self.rip_manager.initialize_routes(self._interfaces_config, self.router_gateway_out_ip,
                                           self.interface_out_full_name)
        self.ethernet_manager.start()
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
        self._setup_dynamic_firewall_manager_rules()
        # Send Gratuitous ARP for router's own IPs on startup
        if self.interface_in_full_name and self.router_ip_in and self.mac_in:
            self.arp_manager.send_gratuitous_arp(self.router_ip_in, self.mac_in, self.interface_in_full_name)
        if self.interface_out_full_name and self.router_ip_out and self.mac_out:
            self.arp_manager.send_gratuitous_arp(self.router_ip_out, self.mac_out, self.interface_out_full_name)

        self.router_logger.log_message("\n--- Python Router Starting Services ---")
        self._stop_sniffing_event.clear()
        self.syn_scanner = SYNScanner(
            router_logger=self.router_logger,
            packet_writer=self.packet_writer, # Pass your packet_writer instance
            interfaces_config=self._interfaces_config, # Pass the populated config
            scan_targets=[
                ("8.8.8.8", [53, 80]),
                ("1.1.1.1", [443]),
            ],scan_interval=300)
        self.syn_scanner.start()
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
        self.ethernet_manager.stop()
        self.tls_proxy_manager.stop()
        self.packet_writer.stop()
        self._disable_nat_forwarding()
        if self.nat_manager:
            self.nat_manager.stop()
        for thread in self._sniff_threads.values():
            if thread.is_alive():
                thread.join(timeout=2)
        self._sniff_threads.clear()
        self.igmp_manager.stop()
        self.handshake_manager.stop()
        self.remove_l2_bridge("MyLanBridge")
        self.remove_link_aggregation_group("MyLanAggregation")
        self.remove_outbound_load_balancing_interface(self.interface_in_full_name)
        self.syn_scanner.stop()
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

    def create_l2_bridge(self, bridge_name: str, member_iface_full_names: List[str]) -> bool:
        """
        Public method to create a Layer 2 bridge.
        Args:
            bridge_name: A logical name for the bridge (e.g., "LAN_Bridge").
            member_iface_full_names: List of full Scapy interface names to include in the bridge.
        """
        # Ensure that these interfaces are already discovered and configured with MACs
        for iface_name in member_iface_full_names:
            if iface_name not in self._interfaces_config:
                self.router_logger.log_message(f"[RouterManager] ❌ Cannot add '{iface_name.split('_')[-1]}' to bridge: Interface not configured in router.")
                return False
            # IMPORTANT: Interfaces in a Layer 2 bridge usually should NOT have IP addresses assigned
            # on the OS level, as the bridge itself will have the IP. If they have IPs, it can cause issues.
            # Your current auto-config *will* assign IPs. You might need to adjust this.
            # For a pure Layer 2 bridge, the *bridge* itself would have the IP if it's also a router interface.
            # Here, we'll assume they just pass L2 frames.

        return self.ethernet_manager.create_bridge(bridge_name, member_iface_full_names)

    def remove_l2_bridge(self, bridge_name: str) -> bool:
        """Public method to remove a Layer 2 bridge."""
        return self.ethernet_manager.remove_bridge(bridge_name)

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
            raw_payload_hex_str = None
            if tcp_layer and tcp_layer.get("tcp.payload"):
                raw_payload_hex_str = tcp_layer["tcp.payload"].replace(":", "")
            elif "data-text-lines" in layers:
                # TShark sometimes puts reassembled data here, might not be hex string
                reassembled = layers["data-text-lines"]
                if isinstance(reassembled, list): # data-text-lines can be an array of lines
                    reassembled = "\n".join(reassembled)

                # Attempt to convert to bytes if it's not already binary and get hex
                try:
                    raw_payload_hex_str = reassembled.encode('utf-8', errors='ignore').hex()
                except Exception:
                    raw_payload_hex_str = None # Couldn't convert to hex from this source

            if raw_payload_hex_str:
                # Truncate raw hex for logging
                truncated_hex_display = raw_payload_hex_str[:128] + ("..." if len(raw_payload_hex_str) > 128 else "")
                self.logger.log_message(f"[Payload-Wireshark] 📦 Raw payload (hex): {truncated_hex_display}...")

                # Attempt to decode to human-readable string
                try:
                    # Convert hex string to bytes, then decode
                    payload_bytes = bytes.fromhex(raw_payload_hex_str)
                    decoded_payload = payload_bytes.decode('utf-8', errors='replace')

                    # Heuristic for human-readability (same as in TransportLayerManager)
                    replacement_char_count = decoded_payload.count('\ufffd')
                    printable_char_count = sum(1 for char in decoded_payload if char in string.printable)

                    is_human_readable = True
                    if len(decoded_payload) > 0:
                        if replacement_char_count / len(decoded_payload) > 0.10:
                            is_human_readable = False
                        elif printable_char_count / len(decoded_payload) < 0.50:
                            is_human_readable = False
                    elif len(payload_bytes) > 0: # If decoded_payload is empty but payload has content, it's not readable
                        is_human_readable = False

                    if is_human_readable and len(decoded_payload.strip()) > 0:
                        self.logger.log_message(f"[Payload-Wireshark] 📝 Decoded payload: {decoded_payload}")
                    else:
                        self.logger.log_message("[Payload-Wireshark] ⚠️ Decoded payload not considered human-readable.")

                except UnicodeDecodeError: # Less likely with errors='replace', but good to catch
                    self.logger.log_message("[Payload-Wireshark] ⚠️ Could not decode payload as UTF-8.")
                except Exception as e:
                    self.logger.log_message(f"[Payload-Wireshark] ❌ Error processing/decoding payload: {e}")
            else:
                self.logger.log_message(f"[Payload-Wireshark] 📦 No reassembled payload data found.")

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


# --- Backend WSL Nmap Manager ---
class AsyncNmapManager:
    """An asynchronous manager for running Nmap through WSL."""

    def __init__(self, logger, async_loop):
        self.i_stdout_thread = None
        self.i_stderr_thread = None
        self.logger = logger
        self.wsl_path = self._find_wsl_executable()
        self.is_ready = False
        self.setup_message = "Ready to initialize."
        self.status = "idle"
        if getattr(sys, "frozen", False):


            self.tools_dir = Path(sys._MEIPASS) / "tools" / "Linux"
        else:
            self.tools_dir = Path(__file__).resolve().parent  / "tools" / "Linux"

        self.nmap_wsl_path = None
        self._scan_task = None
        self._scan_process = None
        self.async_loop = async_loop
        # --- ADDED: Attributes for the interactive session ---
        self._interactive_session_process = None
        self._interactive_session_tasks = []

        self.stdout_capture = []
    # --- ADDED: Methods for managing the interactive session ---
    async def initialize(self, on_complete_callback):
        """
        Asynchronously ensures WSL is functional and Nmap is properly installed.
        """
        self.logger.log_message("🚀 Starting asynchronous WSL & Nmap setup...")
        self.is_ready = False
        try:
            # Step 1: Verify WSL is working
            if not self.wsl_path or not await self._check_wsl_functionality():
                self.setup_message = "⚠️ WSL not found or non-functional. Attempting install/repair..."
                self.logger.log_message(self.setup_message)
                if not await self._install_wsl():
                    self.setup_message = "❌ WSL installation failed."
                else:
                    self.setup_message = "-> WSL setup started. Please restart your PC."
                return

            # Step 2: Check if Nmap is installed inside WSL
            self.logger.log_message("✅ WSL is functional. Checking for Nmap installation...")
            if not await self._check_nmap_installed():
                self.logger.log_message("   - Nmap not found. Attempting installation via apt...")
                if not await self._install_nmap_in_wsl():
                    # Error message is set within the install method
                    return

            self.logger.log_message("   - ✅ Nmap is installed in WSL.")
            self.is_ready = True
            self.setup_message = "✅ WSL & Nmap are ready."
        finally:
            self.logger.log_message(f"[Nmap] Setup finished. Status: {self.setup_message}")
            on_complete_callback()

    async def _check_nmap_installed(self) -> bool:
        """
        Checks if Nmap is installed in the default WSL path OR in the custom tools directory.
        """
        try:
            # Check 1: Is 'nmap' in the default WSL PATH?
            self.logger.log_message("   - Checking for Nmap in default WSL PATH...")
            proc_path = await asyncio.create_subprocess_exec(
                self.wsl_path, "command", "-v", "nmap",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc_path.wait()
            if proc_path.returncode == 0:
                self.logger.log_message("   - ✅ Found Nmap in default PATH.")
                return True

            # Check 2: If not found, check the custom tools directory.
            self.logger.log_message("   - ℹ️ Nmap not found in default PATH. Checking tools directory...")
            nmap_in_tools_win_path = self.tools_dir / "usr" / "bin" / "nmap"

            # Convert the Windows path to its WSL equivalent for the check
            nmap_in_tools_wsl_path = await self._get_wsl_path_for_windows_path(nmap_in_tools_win_path)

            if not nmap_in_tools_wsl_path:
                self.logger.log_message(
                    f"   - ❌ Could not resolve tools directory path '{nmap_in_tools_win_path}' in WSL.")
                return False

            # Use 'test -f' to see if the file exists at that specific WSL path
            proc_tools = await asyncio.create_subprocess_exec(
                self.wsl_path, "test", "-f", nmap_in_tools_wsl_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc_tools.wait()

            if proc_tools.returncode == 0:
                self.logger.log_message(f"   - ✅ Found Nmap in tools directory.")
                return True

            self.logger.log_message("   - ❌ Nmap not found.")
            return False

        except Exception as e:
            self.logger.log_message(f"   - ❌ An error occurred while checking for Nmap: {e}")
            return False
    # --- ADDED: Methods for managing the interactive session ---
    async def start_interactive_session(self):
        if self._interactive_session_process:
            self.logger.log_message("[WSL-Shell] An interactive session is already running."); return
        self.logger.log_message("[WSL-Shell] Starting interactive bash session...")
        try:
            self._interactive_session_process = await asyncio.create_subprocess_exec(
                self.wsl_path, "bash", "-i", stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            self.i_stdout_thread = threading.Thread(target=self.stream_output, args=(self._interactive_session_process.stdout, "Nmap"))
            self.i_stderr_thread = threading.Thread(target=self.stream_output, args=(self._interactive_session_process.stderr, "Nmap-ERR"))
            self.i_stdout_thread.start()
            self.i_stderr_thread.start()

            self.logger.log_message("[WSL-Shell] ✅ Session started.")
        except Exception as e:
            self.logger.log_message(f"[WSL-Shell] 💥 Failed to start session: {e}"); self._interactive_session_process = None
    async def stop_interactive_session(self):
        if not self._interactive_session_process: return
        self.logger.log_message("[WSL-Shell] Stopping interactive session...")
        for task in self._interactive_session_tasks: task.cancel()
        if self._interactive_session_process:
            self._interactive_session_process.terminate()
            self.i_stdout_thread.join()
            self.i_stderr_thread.join()
            await self._interactive_session_process.wait()
        self._interactive_session_process = None
        self.logger.log_message("[WSL-Shell] ⏹️ Session stopped.")

    async def send_command_to_session(self, command: str):
        """Sends a command string to the running interactive shell's stdin."""
        if not self._interactive_session_process or not self._interactive_session_process.stdin:
            self.logger.log_message("[WSL-Shell] ❌ Cannot send command: No active session.")
            return

        stdin = self._interactive_session_process.stdin
        # Add a newline to execute the command
        stdin.write(f"{command}\n".encode())
        await stdin.drain()

    async def _install_nmap_in_wsl(self) -> bool:
        """
        Installs Nmap in WSL using Snap and copies the binary to the tools directory.
        This opens a new terminal window to allow user input for the sudo password.
        """
        self.setup_message = "Installing Nmap in WSL via external terminal..."
        self.logger.log_message(self.setup_message)

        try:
            wsl_tools_path_str = await self._get_wsl_path_for_windows_path(self.tools_dir)
            if not wsl_tools_path_str:
                self.setup_message = "❌ ERROR: Could not resolve WSL path for tools directory."
                self.logger.log_message(self.setup_message)
                return False

            nmap_dest_dir = f"{wsl_tools_path_str}/usr/bin"

            shell_command = (
                f"echo '--- Installing Nmap using Snap (requires sudo) ---' && "
                f"sudo snap install nmap && "
                f"echo '--- Copying Nmap to tools directory: {nmap_dest_dir} ---' && "
                f"mkdir -p {nmap_dest_dir} && "
                f"sudo cp /snap/bin/nmap {nmap_dest_dir}/ && "
                f"sudo chmod +x {nmap_dest_dir}/nmap && "
                f"echo; echo '✅ Nmap installation complete. You can close this window now.' && "
                f"read -p 'Press [Enter] to close...'"  # Wait for user input
            )

            # This is the corrected, more robust way to launch the process.
            # It calls wsl.exe directly and forces a new console window.
            self.logger.log_message("   - Launching in new console window...")
            subprocess.Popen(
                ["wsl.exe", "-e", "bash", "-c", shell_command],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )

            self.logger.log_message(
                "   - 🕔 Installation running in new terminal. Please complete the sudo prompt there.")
            return True

        except FileNotFoundError:
            self.setup_message = "❌ ERROR: wsl.exe not found. Please ensure WSL is installed and in your system's PATH."
            self.logger.log_message(self.setup_message)
            return False
        except Exception as e:
            self.setup_message = f"❌ ERROR: An unexpected error occurred during installation: {e}"
            self.logger.log_message(self.setup_message)
            return False

        except FileNotFoundError:
            self.setup_message = "❌ ERROR: wsl.exe not found. Please ensure WSL is installed and in your system's PATH."
            self.logger.log_message(self.setup_message)
            return False
        except Exception as e:
            self.setup_message = f"❌ ERROR: An unexpected error occurred during installation: {e}"
            self.logger.log_message(self.setup_message)
            return False

    # (The rest of the class, including _run_scan, _check_wsl_functionality, etc., is correct and remains unchanged)
    async def start_scan(self, targets, arguments, on_complete_callback):
        """
        This is now a coroutine, ensuring it runs on the event loop
        and can safely create other tasks.
        """

        if self.status == "running":
            self.logger.log_message("[Nmap] ⚠️ Scan already running.")
            return
        if not self.is_ready:
            self.logger.log_message("[Nmap] ❌ Cannot start scan: Nmap is not ready.")
            return

        async def run_and_callback():
            try:
                xml_output = await self._run_scan(targets, arguments)
                if callable(on_complete_callback):
                    on_complete_callback(xml_output)
            except Exception as e:
                self.logger.log_message(f"[Nmap] 💥 Exception during scan task: {e}")
            finally:
                self.status = "idle"
                self._scan_task = None

        self.status = "running"
        self._scan_task = asyncio.create_task(run_and_callback())
        self.logger.log_message("[Nmap] ▶️ Nmap scan task started.")
    def stop_scan(self):
        if self.status != "running": return
        self.logger.log_message("[Nmap] ⏹️ Stop request received...")
        self.status = "stopping"
        if self._scan_task: self._scan_task.cancel()
        if self._scan_process: self._scan_process.terminate()
    def stream_output(self, stream, label):
        for line in iter(stream.readline, ''):
            self.logger.log_message(f"[{label}] {line.strip()}")
            self.stdout_capture.append(line)
        stream.close()

    async def _run_scan(self, targets: List[str], arguments: List[str]) -> str:
        """
        Runs an Nmap scan asynchronously within WSL, allowing for interactive sudo password entry.

        Args:
            targets: A list of target IP addresses or hostnames.
            arguments: A list of Nmap command-line arguments.

        Returns:
            A string containing the Nmap XML output or an <error> tag on failure.
        """
        self.logger.log_message("[Nmap] 🚀 Preparing interactive scan...")
        # 1. Resolve Nmap path.
        if not self.nmap_wsl_path:
            nmap_windows_path = self.tools_dir / "usr" / "bin" / "nmap"
            self.nmap_wsl_path = await self._get_wsl_path_for_windows_path(nmap_windows_path)
            if not self.nmap_wsl_path:
                error_msg = "Could not resolve Nmap path inside WSL."
                self.logger.log_message(f"[Nmap] ❌ {error_msg}")
                return f"<error>{error_msg}</error>"

        # 2. Prepare commands for interactive session.
        # First, resolve the tools directory path for use inside WSL.
        wsl_tools_dir = await self._get_wsl_path_for_windows_path(self.tools_dir)
        if not wsl_tools_dir:
            error_msg = f"Could not resolve tools directory path '{self.tools_dir}' inside WSL."
            self.logger.log_message(f"[Nmap] ❌ {error_msg}")
            return f"<error>{error_msg}</error>"

        # Use a unique filename and construct the full WSL path for the output file.
        # Note the use of single quotes to handle potential spaces in paths.
        output_filename = f"nmap_output_{uuid.uuid4()}.xml"
        output_path = f"'{wsl_tools_dir}/{output_filename}'"
        all_targets = " ".join(targets)

        # The Nmap command saves output to the temp file.
        nmap_cmd = f"sudo {self.nmap_wsl_path} {' '.join(arguments)} -oX {output_path} {all_targets}"

        # 'script' is used to force TTY allocation, which sudo requires for password prompts.
        # The output of 'script' itself is sent to /dev/null.
        script_cmd = f"script -q -c '{nmap_cmd}; echo Press Enter to continue...; read' /dev/null"

        # The final command to be run in a new console window.
        interactive_command = [self.wsl_path, "bash", "-c", script_cmd]
        self.logger.log_message(f"[Nmap] 🚀 Launching interactive console for command: {script_cmd}")

        try:
            # 3. Launch the interactive scan in a new console window.
            # We don't pipe stdio, allowing direct user interaction.
            self._scan_process = await asyncio.create_subprocess_exec(
                *interactive_command,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            return_code = await self._scan_process.wait()

            if return_code != 0:
                error_msg = f"Scan process exited with code {return_code}. Check the console window for details."
                self.logger.log_message(f"[Nmap] ❌ {error_msg}")
                return f"<error>{error_msg}</error>"

            self.logger.log_message("[Nmap] ✅ Interactive scan completed. Fetching results...")

            # 4. Read the XML output from the temporary file in WSL.
            read_command = [self.wsl_path, "cat", output_path]
            read_proc = await asyncio.create_subprocess_exec(
                *read_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await read_proc.communicate()

            if read_proc.returncode != 0:
                error_msg = stderr.decode(errors='ignore').strip()
                self.logger.log_message(f"[Nmap] ❌ Failed to read output file: {error_msg}")
                return f"<error>Failed to read Nmap output file: {error_msg}</error>"

            xml_output = stdout.decode()
            self.logger.log_message(f"[Nmap-DBG] XML output size: {len(xml_output)} bytes.")

            # 5. Validate XML.
            try:
                ET.fromstring(xml_output)
                self.logger.log_message("[Nmap] ✅ XML output successfully validated.")
            except ET.ParseError as e:
                self.logger.log_message(f"[Nmap] ⚠️ XML parse error: {e}")
                return f"<error>Malformed XML output received from Nmap: {e}</error>"

            return xml_output

        except FileNotFoundError:
            self.logger.log_message("[Nmap] 💥 Critical Error: wsl.exe not found.")
            return "<error>wsl.exe not found. Please ensure WSL is installed and in your PATH.</error>"
        except Exception as e:
            self.logger.log_message(f"[Nmap] 💥 An unexpected exception occurred: {e}")
            return f"<error>Scan failed with an unexpected exception: {e}</error>"
        finally:
            # 6. Clean up the temporary file from WSL.
            self.logger.log_message(f"[Nmap] 🧹 Cleaning up temporary file: {output_path}")
            cleanup_command = [self.wsl_path, "rm", "-f", output_path]
            await asyncio.create_subprocess_exec(*cleanup_command)

            self._scan_process = None
            self.logger.log_message("[Nmap] ✅ Scan complete.")
    def _find_wsl_executable(self):
        path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe")
        return path if os.path.exists(path) else None

    def _is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    async def _check_wsl_functionality(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(self.wsl_path, "-l", "-v", stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False

    async def _install_wsl(self) -> bool:
        if not self._is_admin(): self.logger.log_message(
            "❌ ERROR: WSL install requires admin privileges."); return False
        try:
            subprocess.Popen('start cmd.exe /k "wsl --install"', shell=True); return True
        except Exception as e:
            self.logger.log_message(f"❌ Failed to launch installer: {e}"); return False


    async def _get_wsl_path_for_windows_path(self, windows_path: Path) -> str | None:
        """
        Converts a Windows path to its WSL equivalent. It first tries the reliable
        'wslpath' command and falls back to manual path construction and
        verification if that fails.
        """
        # --- Attempt 1: Use the standard wslpath tool ---
        try:
            proc = await asyncio.create_subprocess_exec(
                self.wsl_path, "wslpath", "-a", str(windows_path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                wsl_path = stdout.decode().strip()
                self.logger.log_message(f"   - Successfully converted path using wslpath: {wsl_path}")
                return wsl_path
            else:
                raise RuntimeError(f"wslpath failed: {stderr.decode().strip()}")
        except Exception as e:
            self.logger.log_message(f"   - wslpath command failed: {e}. Attempting manual fallback...")

        # --- Attempt 2: Manual fallback for non-standard drives ---
        try:
            win_path_str = str(windows_path.resolve())
            drive, path_no_drive = os.path.splitdrive(win_path_str)

            if not drive:
                self.logger.log_message("   - Manual fallback failed: Path has no drive letter.")
                return None

            drive_letter = drive.replace(":", "").lower()
            manual_path = f"/mnt/{drive_letter}{path_no_drive.replace(os.sep, '/')}"
            self.logger.log_message(f"   - Manually constructed path: {manual_path}. Verifying access...")

            # --- THE FIX IS HERE ---
            # Use 'test -e' to check if the path EXISTS (file or directory).
            # The old code used 'test -d' which only checks for directories.
            verify_proc = await asyncio.create_subprocess_exec(
                self.wsl_path, "test", "-e", manual_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await verify_proc.wait()
            # ---------------------

            if verify_proc.returncode == 0:
                self.logger.log_message("   - ✅ Manual path verification successful.")
                return manual_path
            else:
                self.logger.log_message("   - ❌ Manual path verification failed. WSL cannot access this path.")
                return None
        except Exception as e:
            self.logger.log_message(f"   - ❌ Manual path fallback failed with an exception: {e}")
            return None



class AsyncGobusterManager(QObject):
    """An asynchronous manager for running Gobuster through WSL."""
    # Signals for GUI updates
    gobuster_process_started_signal = pyqtSignal()
    gobuster_new_result_signal = pyqtSignal(str)  # Emits each found URL or relevant line
    gobuster_scan_finished_signal = pyqtSignal(str) # Emits final status/error message
    def __init__(self, logger, async_loop, manual_gobuster_path: str = None):
        super().__init__()
        self._current_target_url = None
        self.logger = logger
        self.async_loop = async_loop
        self.wsl_path = self._find_wsl_executable()
        self.is_ready = False
        self.setup_message = "Ready to initialize."
        self.status = "idle"  # idle, initializing, ready, running, stopping, completed, error, cancelled
        if getattr(sys, "frozen", False):
            self.tools_dir = Path(sys._MEIPASS) / "tools" / "Linux"
        else:
            self.tools_dir = Path(__file__).resolve().parent / "tools" / "Linux"
        self.gobuster_wsl_path = self.tools_dir / "gobuster" # Will be set to the validated WSL path of the manual binary
        self.default_wsl_wordlist_path = self.tools_dir / "SecLists/Discovery/Web-Content/common.txt"  # Common SecLists path
        # Determine the base path for the application (handles PyInstaller bundling)
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # Running in a PyInstaller bundle
            self.base_path = Path(sys._MEIPASS)
        else:
            # Running in a normal Python environment
            self.base_path = Path(__file__).resolve().parent
        # Construct the manual Gobuster path relative to the base_path
        if manual_gobuster_path:
            self._manual_gobuster_path_windows = (self.base_path / manual_gobuster_path).resolve()
            self.logger.log_message(f"Manual Gobuster path provided (Windows): {self._manual_gobuster_path_windows}")
        else:
            self._manual_gobuster_path_windows = None
            self.logger.log_message(
                "No manual Gobuster path provided. Manager will rely on default WSL 'gobuster' or not be ready.")
        self._manual_gobuster_path_wsl = None  # To store the converted WSL path
        self._scan_task = None
        self._scan_process = None
    async def initialize(self, on_complete_callback):
        """
        Asynchronously ensures WSL is functional and Gobuster is installed
        at the provided manual path. Also ensures wordlists are present.
        """
        self.logger.log_message("🚀 Starting asynchronous WSL & Gobuster setup (manual path only)...")
        self.is_ready = False
        self.status = "initializing"
        try:
            # Step 1: Verify WSL is working
            if not self.wsl_path or not await self._check_wsl_functionality():
                self.setup_message = "⚠️ WSL not found or non-functional. Please ensure WSL is installed and working."
                self.logger.log_message(self.setup_message)
                if not self.wsl_path and self._is_admin():
                    self.setup_message += " Attempting WSL install..."
                    self.logger.log_message(self.setup_message)
                    if await self._install_wsl():
                        self.setup_message = "-> WSL setup initiated. Please restart your PC."
                    else:
                        self.setup_message = "❌ WSL installation failed. Please install manually."
                self.status = "error"
                return
            self.logger.log_message("✅ WSL is functional.")
            # Step 2: Handle manual Gobuster path
            if self._manual_gobuster_path_windows:
                if not self._manual_gobuster_path_windows.exists():
                    self.setup_message = f"❌ ERROR: Manual Gobuster binary not found at specified path: {self._manual_gobuster_path_windows}. Please ensure the file exists."
                    self.logger.log_message(self.setup_message)
                    self.status = "error"
                    return
                self.logger.log_message(f"✅ Manual Gobuster binary detected at: {self._manual_gobuster_path_windows}")
                self._manual_gobuster_path_wsl = await self._get_wsl_path_for_windows_path(
                    self._manual_gobuster_path_windows)
                if not self._manual_gobuster_path_wsl:
                    self.setup_message = f"❌ ERROR: Failed to convert/verify manual Gobuster path in WSL: {self._manual_gobuster_path_windows}. Please check path validity or permissions."
                    self.logger.log_message(self.setup_message)
                    self.status = "error"
                    return
                self.logger.log_message(
                    f"   - Checking/setting execute permissions for {self._manual_gobuster_path_wsl} in WSL...")
                chmod_proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "chmod", "+x", self._manual_gobuster_path_wsl,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await chmod_proc.communicate()
                if chmod_proc.returncode != 0:
                    self.logger.log_message(
                        f"   - ⚠️ Failed to set execute permissions via chmod: {stderr.decode().strip()}. This might cause issues.")
                else:
                    self.logger.log_message("   - ✅ Execute permissions set (or already present) for Gobuster binary.")
                exec_check_proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "test", "-x", self._manual_gobuster_path_wsl,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await exec_check_proc.wait()
                if exec_check_proc.returncode == 0:
                    self.gobuster_wsl_path = self._manual_gobuster_path_wsl
                    self.logger.log_message(
                        f"   - ✅ Manual Gobuster binary is executable in WSL: {self.gobuster_wsl_path}")
                else:
                    self.setup_message = f"❌ ERROR: Manual Gobuster binary not executable in WSL: {self._manual_gobuster_path_wsl}. Please ensure it's a valid Linux binary."
                    self.logger.log_message(self.setup_message)
                    self.is_ready = False
                    self.status = "error"
                    return
            else:
                # If no manual path provided, fall back to checking if 'gobuster' is in WSL's PATH
                self.logger.log_message("No manual Gobuster path provided. Checking for 'gobuster' in WSL's PATH.")
                if not await self._check_gobuster_installed():  # This checks 'gobuster' in WSL PATH
                    self.setup_message = "❌ ERROR: No manual Gobuster path provided and 'gobuster' not found in WSL's PATH. Cannot proceed."
                    self.logger.log_message(self.setup_message)
                    self.is_ready = False
                    self.status = "error"
                    return
                else:
                    self.gobuster_wsl_path = "gobuster"  # Set to default 'gobuster'
                    self.logger.log_message("✅ 'gobuster' found in WSL's PATH.")
            # Step 3: Ensure Wordlists are installed in WSL
            if not await self._check_wordlist_installed(self.default_wsl_wordlist_path):
                self.logger.log_message(
                    f"   - Required wordlist '{self.default_wsl_wordlist_path}' not found. Attempting automatic installation of SecLists...")
                if not await self._install_wordlists_in_wsl():
                    self.setup_message = f"❌ ERROR: Failed to install wordlists in WSL. {self.setup_message}"
                    self.is_ready = False
                    self.status = "error"
                    return
            self.logger.log_message("   - ✅ Wordlists are installed in WSL.")
            self.is_ready = True
            self.setup_message = "✅ WSL, Gobuster, and Wordlists are ready."
            self.status = "ready"
        except Exception as e:
            self.logger.log_message(f"💥 An unexpected error occurred during setup: {e}")
            self.setup_message = f"❌ An unexpected error occurred: {e}"
            self.is_ready = False
            self.status = "error"
        finally:
            self.logger.log_message(f"[Gobuster] Setup finished. Status: {self.setup_message}")
            if on_complete_callback:
                self.async_loop.call_soon_threadsafe(on_complete_callback)
    async def _check_gobuster_installed(self) -> bool:
        """
        Checks if the 'gobuster' command is available in the WSL path (if not using a manual path)
        or if the manually provided path is executable.
        """
        if self.gobuster_wsl_path:
            # If a manual path was set, check it directly
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "test", "-x", self.gobuster_wsl_path,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()
                return proc.returncode == 0
            except Exception:
                return False
        else:
            # Otherwise, check if 'gobuster' is in WSL's PATH
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "command", "-v", "gobuster",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()
                return proc.returncode == 0
            except Exception:
                return False
    async def _check_wordlist_installed(self, wsl_wordlist_path: str) -> bool:
        """Checks if a specific wordlist file exists in WSL."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.wsl_path, "test", "-f", wsl_wordlist_path,  # -f tests if it's a regular file
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False
    def _check_wordlist_exists_in_wsl(self, wsl_file_path: str) -> bool:
        """
        Checks if a given file exists in WSL using the 'test -f' command.
        This method now expects a WSL-formatted path.
        """
        try:
            # Use 'test -f' in bash to check for file existence
            # This is more reliable than trying to parse 'ls' output
            command = f"test -f \"{wsl_file_path}\""
            result = subprocess.run(
                [self.wsl_path, 'bash', '-c', command],
                capture_output=True,
                check=False,  # Don't raise an exception for non-zero exit code (file not found)
            )
            return result.returncode == 0  # returncode 0 means success (file exists)
        except Exception as e:
            self.logger.log_message(f"ERROR checking wordlist existence in WSL for {wsl_file_path}: {e}")
            return False
    async def _install_wordlists_in_wsl(self) -> bool:
        """
        Installs SecLists wordlists in WSL by launching a single command in a new console,
        ensuring TTY allocation for sudo prompts. This method is now asynchronous.
        """
        self.setup_message = "Installing wordlists in WSL..."
        self.logger.log_message(self.setup_message)
        try:
            SECLISTS_REPO = "https://github.com/danielmiessler/SecLists.git"
            windows_seclists_target_dir = self.tools_dir / "SecLists"
            windows_parent_dir = windows_seclists_target_dir.parent
            # *** CRITICAL CHANGE: Get WSL paths in Python BEFORE constructing the bash string ***
            # This leverages your existing _get_wsl_path_for_windows_path which has fallback logic.
            actual_wsl_seclists_target_dir = await self._get_wsl_path_for_windows_path(windows_seclists_target_dir)
            actual_wsl_parent_dir = await self._get_wsl_path_for_windows_path(windows_parent_dir)
            if not actual_wsl_seclists_target_dir or not actual_wsl_parent_dir:
                self.setup_message = "❌ ERROR: Failed to translate SecLists paths for WSL. Installation aborted."
                self.logger.log_message(self.setup_message)
                return False
            windows_check_file = windows_seclists_target_dir / "Discovery" / "Web-Content" / "common.txt"
            # Use the already translated wsl_check_file_path for initial existence check
            wsl_check_file_path = await self._get_wsl_path_for_windows_path(windows_check_file)
            if wsl_check_file_path and await self._check_wordlist_installed(wsl_check_file_path):
                self.logger.log_message("   - ✅ Required wordlist already detected in WSL. Skipping installation.")
                return True
            # Construct a single, comprehensive command string for bash
            # Now, directly use the *translated WSL paths* obtained from Python
            # This bypasses the need for `wslpath -u` inside the bash script itself for these variables.
            wsl_installation_commands_bash_string = (
                # Optional debug print of the translated paths
                f"echo 'Using Translated WSL Target Dir: {actual_wsl_seclists_target_dir}' && "
                f"echo 'Using Translated WSL Parent Dir: {actual_wsl_parent_dir}' && "
                "echo '---' && "
                "sudo apt-get update && "  # Update package lists
                "sudo apt-get install -y git && "  # Install git
                f"sudo mkdir -p \"{actual_wsl_parent_dir}\" && "  # Create parent directory (if not exists)
                f"sudo git clone --depth 1 {SECLISTS_REPO} \"{actual_wsl_seclists_target_dir}\" && "  # Shallow clone SecLists
                "echo 'SecLists installation attempt finished. You can close this window now.' && "
                "read -p 'Press Enter to close this window...'"  # Always keep for debugging until stable
            )
            self.logger.log_message("   - Launching wordlist installation in a new console window...")
            self.logger.log_message("     👉 Please monitor the new window for progress and any sudo password prompts.")
            self.logger.log_message("     👉 You MUST type your WSL password if prompted in that window.")
            self.logger.log_message("     👉 Installation might take some time (cloning SecLists).")
            subprocess.Popen(
                [self.wsl_path, 'bash', '-c', '-i', wsl_installation_commands_bash_string],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            self.logger.log_message("   - ✅ Wordlist installation command launched. Waiting for completion...")
            max_wait = 1800
            interval = 10
            waited = 0
            while waited < max_wait:
                if wsl_check_file_path and await self._check_wordlist_installed(wsl_check_file_path):
                    self.logger.log_message("   - ✅ SecLists detected in WSL.")
                    return True
                await asyncio.sleep(interval)
                waited += interval
                self.logger.log_message(f"     ...still waiting ({waited}/{max_wait}s)...")
            self.logger.log_message("   - ❌ Timeout: SecLists installation not completed within expected time.")
            return False
        except Exception as e:
            self.setup_message = f"❌ ERROR: Unexpected error during wordlist installation: {e}"
            self.logger.log_message(self.setup_message)
            return False

    async def start_scan(self, target_url: str, wordlist_path: str = None, arguments: list = None,
                         on_complete_callback=None):
        try:
            if self.status == "running":
                self.logger.log_message("[Gobuster] ⚠️ Scan already running.")
                return
            if not self.is_ready:
                self.logger.log_message(f"[Gobuster] ❌ Cannot start scan: {self.setup_message}")
                return
            if not self.gobuster_wsl_path:
                self.logger.log_message("[Gobuster] ❌ Gobuster WSL path is not configured.")
                return

            final_wsl_wordlist_path = None
            if wordlist_path:
                try:
                    windows_wordlist_path = Path(wordlist_path)
                    if not windows_wordlist_path.exists():
                        self.logger.log_message(
                            f"⚠️ Provided wordlist not found on Windows: {wordlist_path}. Trying fallback."
                        )
                    else:
                        wsl_converted_path = await self._get_wsl_path_for_windows_path(windows_wordlist_path)
                        if wsl_converted_path and await self._check_wordlist_installed(wsl_converted_path):
                            final_wsl_wordlist_path = wsl_converted_path
                            self.logger.log_message(f"✅ Using converted WSL path: {final_wsl_wordlist_path}")
                        else:
                            self.logger.log_message(f"⚠️ Converted WSL wordlist invalid. Falling back.")
                except Exception as e:
                    self.logger.log_message(f"⚠️ Error converting wordlist: {e}. Will fall back to default.")

            if not final_wsl_wordlist_path:
                converted_default = await self._get_wsl_path_for_windows_path(self.default_wsl_wordlist_path)
                if converted_default and await self._check_wordlist_installed(converted_default):
                    final_wsl_wordlist_path = converted_default
                    self.logger.log_message(f"✅ Using fallback default wordlist: {final_wsl_wordlist_path}")
                else:
                    error_msg = f"❌ ERROR: Default wordlist missing or inaccessible: {converted_default}"
                    self.logger.log_message(error_msg)
                    self.status = "error"
                    if on_complete_callback:
                        self.async_loop.call_soon_threadsafe(
                            lambda: on_complete_callback(f"<error>{error_msg}</error>")
                        )
                    return

            # --- CRITICAL CHANGE HERE ---
            # Manually quote the gobuster_wsl_path and final_wsl_wordlist_path
            # This ensures Bash treats paths with spaces as single arguments.
            # Use shlex.quote for robust quoting if paths can contain complex characters
            import shlex
            quoted_gobuster_path = shlex.quote(str(self.gobuster_wsl_path))
            quoted_wordlist_path = shlex.quote(final_wsl_wordlist_path)

            # Construct the command string to be executed by bash -c
            # The gobuster arguments themselves (target_url, arguments) should NOT be quoted here,
            # as they are distinct arguments for gobuster.
            # Bash will handle splitting the string and executing it.
            gobuster_base_cmd = f"{quoted_gobuster_path} dir -u {shlex.quote(target_url)} -w {quoted_wordlist_path}"

            # Append additional arguments, ensuring they are also quoted for robustness
            if arguments:
                gobuster_base_cmd += " " + " ".join([shlex.quote(arg) for arg in arguments])

            # The full command to pass to wsl.exe bash -c
            # We are providing a single string to bash -c, so it needs to be syntactically correct Bash.
            full_wsl_command = [self.wsl_path, "bash", "-c", gobuster_base_cmd]

            full_command_str_for_logging = ' '.join(full_wsl_command)  # for logging only
            self.logger.log_message(f"[Gobuster] 🚀 Running: {full_command_str_for_logging}")

            self.status = "running"
            self._current_target_url = target_url.strip().rstrip('/')
            self._scan_task = asyncio.create_task(self._run_and_callback(full_wsl_command, on_complete_callback))
            self.logger.log_message("[Gobuster] ▶️ Gobuster scan task started.")

        except Exception:
            self.status = "error"
            error_msg = f"[Gobuster] 💥 Exception during start_scan:\n{traceback.format_exc()}"
            self.logger.log_message(error_msg)
            if on_complete_callback:
                self.async_loop.call_soon_threadsafe(
                    lambda: on_complete_callback(f"<error>{error_msg}</error>")
                )
    async def _run_and_callback(self, command, on_complete_callback):
        final_message = ""
        try:
            self._scan_process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.async_loop.call_soon_threadsafe(self.gobuster_process_started_signal.emit)
            self.logger.log_message(f"[Gobuster-DBG] Subprocess created. PID: {self._scan_process.pid}")
            self.logger.log_message(f"[Gobuster-DBG] Starting concurrent streaming...")

            await asyncio.gather(
                self._stream_gobuster_stdout_for_results(self._scan_process.stdout, "Gobuster-out"),
                self._stream_gobuster_stderr(self._scan_process.stderr, "Gobuster-err")
            )

            await self._scan_process.wait()
            return_code = self._scan_process.returncode

            if return_code == 0:
                self.status = "completed"
                final_message = "Gobuster scan completed successfully."
            else:
                self.status = "error"
                # Read any remaining stderr for error messages if process exited with non-zero
                stderr_output = (await self._scan_process.stderr.read()).decode(errors='ignore').strip()
                final_message = f"<error>Gobuster scan failed with exit code {return_code}. Stderr: {stderr_output}</error>"

        except asyncio.CancelledError:
            self.status = "cancelled"
            final_message = "<error>Gobuster scan was cancelled.</error>"
        except Exception as e:
            self.logger.log_message(f"[Gobuster] 💥 Scan exception: {e}\n{traceback.format_exc()}")
            self.status = "error"
            final_message = f"<error>Exception occurred: {e}</error>"
        finally:
            self.logger.log_message(f"[Gobuster] ✅ Scan finished with status: {self.status}.")
            self._scan_process = None
            if on_complete_callback:
                self.gobuster_scan_finished_signal.emit(final_message)
                self.async_loop.call_soon_threadsafe(lambda: on_complete_callback(final_message))


    def stop_scan(self):
        if self.status != "running" and self.status != "stopping":
            self.logger.log_message("[Gobuster] Not running or stopping.")
            return

        self.logger.log_message("[Gobuster] ⏹️ Stop request received...")
        self.status = "stopping"

        if self._scan_task:
            self.logger.log_message("[Gobuster-DBG] Cancelling scan task.")
            self._scan_task.cancel()
            # No need to await here, it will be handled in _run_and_callback's finally block
        if self._scan_process and self._scan_process.returncode is None:
            self.logger.log_message("[Gobuster-DBG] Terminating Gobuster process.")
            try:
                self._scan_process.terminate()
            except ProcessLookupError:
                self.logger.log_message("[Gobuster-DBG] Process already terminated or not found.")

    async def _stream_gobuster_stdout_for_results(self, stream, prefix):
        """
        Reads from Gobuster's stdout line-by-line, logs each line, and emits
        found URLs/relevant output via signal.
        """
        while True:
            try:
                line_bytes = await stream.readline()
                if not line_bytes:
                    break
                line_str = line_bytes.decode(errors='ignore').strip()
                self.logger.log_message(f"[{prefix}] {line_str}")

                # Simple parsing for Gobuster output (lines starting with / or other indicators)
                # This logic is adapted from _parse_and_display_results in GobusterTab
                if line_str.startswith('/'):
                    full_url = f"{self._current_target_url}{line_str}"
                    self.logger.log_message(f"[{prefix}] Found: {full_url}")
                    self.async_loop.call_soon_threadsafe(lambda s=full_url: self.gobuster_new_result_signal.emit(s))
                elif line_str.startswith("http://") or line_str.startswith("https://"):
                    self.logger.log_message(f"[{prefix}] Found: {line_str}")
                    self.async_loop.call_soon_threadsafe(lambda s=line_str: self.gobuster_new_result_signal.emit(s))
                elif "Status:" in line_str or "Found:" in line_str:
                    self.logger.log_message(f"[{prefix}] Found line: {line_str}")
                    self.async_loop.call_soon_threadsafe(lambda s=line_str: self.gobuster_new_result_signal.emit(s))
                elif "Status:" in line_str or "Found:" in line_str:
                    # Catch lines that might be results not starting with /
                    self.async_loop.call_soon_threadsafe(lambda s=line_str: self.gobuster_new_result_signal.emit(s))

            except asyncio.CancelledError:
                self.logger.log_message(f"[{prefix}] Stream cancelled.")
                break
            except Exception as e:
                self.logger.log_message(f"[{prefix}] Error reading stream: {e}")
                break
        self.logger.log_message(f"[{prefix}] Stream finished.")


    async def _stream_gobuster_stderr(self, stream, prefix):
        """
        Streams Gobuster's stderr to the logger.
        """
        while True:
            try:
                line = await stream.readline()
                if not line:
                    break
                decoded_line = line.decode(errors='ignore').strip()
                self.logger.log_message(f"[{prefix}] {decoded_line}")
            except asyncio.CancelledError:
                self.logger.log_message(f"[{prefix}] Stream cancelled.")
                break
            except Exception as e:
                self.logger.log_message(f"[{prefix}] Error reading stream: {e}")
                break
        self.logger.log_message(f"[{prefix}] Stream finished.")

    def _find_wsl_executable(self):
        path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe")
        return path if os.path.exists(path) else None
    def _is_admin(self):
        """Checks if the current Python process is running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    async def _check_wsl_functionality(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(self.wsl_path, "-l", "-v", stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            self.logger.log_message("Error checking WSL functionality. Is WSL installed?")
            return False
    async def _install_wsl(self) -> bool:
        if not self._is_admin():
            self.logger.log_message("❌ ERROR: WSL install requires administrator privileges. Please run as admin.")
            return False
        try:
            self.logger.log_message("Attempting to initiate WSL installation. A new command prompt window will open.")
            subprocess.Popen('start cmd.exe /k "wsl --install"', shell=True)
            self.logger.log_message(
                "WSL installation command launched. Please follow the instructions in the new window and restart your PC if prompted.")
            return True
        except Exception as e:
            self.logger.log_message(f"❌ Failed to launch WSL installer: {e}")
            return False
    async def _stream_output(self, stream, prefix):
        while True:
            try:
                line = await stream.readline()
                if not line: break
                decoded_line = line.decode(errors='ignore').strip()
                self.logger.log_message(f"[{prefix}] {decoded_line}")
            except asyncio.CancelledError:
                self.logger.log_message(f"[{prefix}] Stream cancelled.")
                break
            except Exception as e:
                self.logger.log_message(f"[{prefix}] Error reading stream: {e}")
                break
        self.logger.log_message(f"[{prefix}] Stream finished.")
    async def _get_wsl_path_for_windows_path(self, windows_path: Path) -> str | None:
        """
        Converts a Windows path to its WSL equivalent. It first tries the reliable
        'wslpath' command and falls back to manual path construction and
        verification if that fails.
        """
        windows_path_str = str(windows_path.resolve())  # Ensure absolute path and string for wslpath
        # Attempt wslpath -a first
        try:
            # Use -a to ensure absolute path, even if it's not strictly needed for existing files
            # It seems your issue is the input string to wslpath. Let's ensure it's quoted.
            proc = await asyncio.create_subprocess_exec(
                self.wsl_path, "wslpath", "-a", windows_path_str,
                # Removed quotes around windows_path_str, wslpath handles arguments directly
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                wsl_path = stdout.decode().strip()
                self.logger.log_message(f"   - Successfully converted path using wslpath: {wsl_path}")
                return wsl_path
            else:
                # Log the full stderr from wslpath to diagnose malformed input issue
                wslpath_stderr = stderr.decode().strip()
                self.logger.log_message(
                    f"   - wslpath command failed (return code {proc.returncode}): {wslpath_stderr}. Input was: '{windows_path_str}'")
                raise RuntimeError(f"wslpath failed: {wslpath_stderr}")
        except Exception as e:
            self.logger.log_message(f"   - wslpath command failed: {e}. Attempting manual fallback...")
        # Manual Fallback
        try:
            drive, path_no_drive = os.path.splitdrive(windows_path_str)
            if not drive:
                self.logger.log_message("   - Manual fallback failed: Path has no drive letter.")
                return None
            drive_letter = drive.replace(":", "").lower()
            # Important: Ensure path_no_drive starts with '/', otherwise it will be relative in WSL
            path_no_drive = path_no_drive.replace(os.sep, '/').lstrip('/')
            manual_path = f"/mnt/{drive_letter}/{path_no_drive}"
            self.logger.log_message(f"   - Manually constructed path: {manual_path}.")
            # --- CRITICAL CHANGE HERE ---
            # Only verify existence if the Windows path *actually exists*.
            # For target directories that will be created, we just need the translation.
            if windows_path.exists():
                self.logger.log_message(f"   - Verifying access for existing path in WSL...")
                verify_proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "test", "-e", manual_path,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await verify_proc.wait()
                if verify_proc.returncode == 0:
                    self.logger.log_message("   - ✅ Manual path verification successful.")
                    return manual_path
                else:
                    stderr_output = (await verify_proc.stderr.read()).decode().strip()
                    self.logger.log_message(
                        f"   - ❌ Manual path verification failed (return code {verify_proc.returncode}). WSL cannot access this path. Stderr: {stderr_output}")
                    return None
            else:
                # If the Windows path doesn't exist, we assume it's a target path to be created.
                # We return the translated path without verifying existence.
                self.logger.log_message(
                    "   - Windows path does not exist; returning translated path for future creation.")
                return manual_path
        except Exception as e:
            self.logger.log_message(f"   - ❌ Manual path fallback failed with an exception: {e}")
            return None


class AsyncScrapingManager(QObject):
    """
    An asynchronous manager for performing web scraping operations.
    Uses Playwright for JavaScript rendering and BeautifulSoup for parsing.
    Designed to integrate with PyQt5 signals and asyncio.
    """

    scraping_started_signal = pyqtSignal()
    scraping_finished_signal = pyqtSignal(dict)
    scraping_progress_signal = pyqtSignal(str)

    def __init__(self, logger, async_loop):
        super().__init__()
        self.logger = logger
        self.async_loop = async_loop
        self.status = "idle"
        self._scrape_task = None
        self._current_url = None

    async def initialize(self, on_complete_callback=None):
        self.logger.log_message("[Scraper] Initializing scraping manager...")
        self.status = "ready"
        self.logger.log_message("[Scraper] Manager is ready.")
        if on_complete_callback:
            self.async_loop.call_soon_threadsafe(on_complete_callback)

    async def start_scrape(self, url: str, on_complete_callback=None):
        if self.status == "running":
            self.logger.log_message("[Scraper] ⚠️ Scraping already running.")
            return

        self._current_url = url.strip()
        if not self._current_url:
            error_msg = "URL cannot be empty."
            self.logger.log_message(f"[Scraper] ❌ {error_msg}")
            self.status = "error"
            if on_complete_callback:
                self.async_loop.call_soon_threadsafe(lambda: on_complete_callback({"error": error_msg}))
            return

        self.logger.log_message(f"[Scraper] ▶️ Starting scrape for: {self._current_url}")
        self.status = "running"
        self.scraping_started_signal.emit()

        async def run_and_callback():
            scraped_data = {"error": "Unknown error during scrape."}
            try:
                scraped_data = await self._perform_scrape(self._current_url)
            except asyncio.CancelledError:
                self.logger.log_message("[Scraper] ⏹️ Scrape task cancelled.")
                scraped_data = {"error": "Scrape cancelled."}
                self.status = "cancelled"
            except Exception as e:
                self.logger.log_message(f"[Scraper] 💥 Exception during scrape task: {e}\n{traceback.format_exc()}")
                scraped_data = {"error": f"Scrape failed: {str(e)}"}
                self.status = "error"
            finally:
                self.logger.log_message(f"[Scraper] ✅ Scrape finished with status: {self.status}.")
                self._scrape_task = None
                if on_complete_callback:
                    self.async_loop.call_soon_threadsafe(lambda: on_complete_callback(scraped_data))
                self.scraping_finished_signal.emit(scraped_data)

        self._scrape_task = self.async_loop.create_task(run_and_callback())

    def stop_scrape(self):
        if self.status != "running":
            self.logger.log_message("[Scraper] Not running or stopping.")
            return

        self.logger.log_message("[Scraper] ⏹️ Stop request received...")
        self.status = "stopping"
        if self._scrape_task:
            self._scrape_task.cancel()

    async def _perform_scrape(self, url: str) -> dict:
        self.scraping_progress_signal.emit("Launching headless browser...")
        self.logger.log_message(f"[Scraper-DBG] Launching Playwright for {url}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ])
            context = await browser.new_context()
            page = await context.new_page()

            try:
                await page.goto(url, timeout=60000)
                self.scraping_progress_signal.emit("Rendering and extracting HTML...")
                content = await page.content()
                self.logger.log_message("[Scraper-DBG] Page content loaded. Parsing...")

                scraped_data = await self.async_loop.run_in_executor(
                    None,
                    lambda: self._parse_content(content, url)
                )
                scraped_data["html_content"] = content
                self.status = "completed"
                return scraped_data

            except Exception as e:
                self.logger.log_message(f"[Scraper] 🚨 Playwright scrape failed: {e}")
                raise ValueError(f"Playwright error: {e}")

            finally:
                await browser.close()

    def _parse_content(self, html_content: str, base_url: str) -> dict:
        soup = BeautifulSoup(html_content, 'html.parser')

        for script in soup(["script", "style"]):
            script.extract()

        extracted_text = soup.get_text(separator='\n', strip=True)

        extracted_links = []
        for a_tag in soup.find_all('a', href=True):
            link_text = a_tag.get_text(strip=True)
            href = a_tag['href']
            if not href.startswith('http') and not href.startswith('//'):
                try:
                    from requests.compat import urljoin
                    href = urljoin(base_url, href)
                except Exception:
                    pass
            extracted_links.append({"text": link_text, "href": href})

        return {
            "extracted_text": extracted_text,
            "extracted_links": extracted_links
        }