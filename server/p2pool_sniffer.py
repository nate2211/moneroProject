import contextlib
import hashlib
import ctypes
import ipaddress
import os
import socket
import struct
import subprocess
import time
import threading
from ctypes import c_char, c_int, c_long, POINTER, CFUNCTYPE, Structure, c_uint
import sys
from typing import Optional, List, Union
import importlib
import psutil
from scapy.arch import get_if_hwaddr, get_windows_if_list
from scapy.config import conf
from scapy.contrib.geneve import GENEVE
from scapy.contrib.igmpv3 import IGMPv3mq, IGMPv3mr
from scapy.contrib.mpls import MPLS
from scapy.fields import IntField, XShortField, LELongField, LEIntField, LESignedIntField, StrLenField, EnumField, \
    FieldLenField, IPField
from scapy.interfaces import get_if_list
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import DHCP6
from scapy.layers.dns import DNS, DNSStrField, DNSRR
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.ipsec import ESP, AH
from scapy.layers.kerberos import Kerberos
from scapy.layers.l2tp import L2TP
from scapy.layers.mobileip import MobileIP
from scapy.layers.ppp import PPP, PPPoED, PPPoE
from scapy.layers.rip import RIP
from scapy.layers.rtp import RTP
from scapy.layers.isakmp import ISAKMP
try:
    from scapy.all import ShortField, ByteField, IP6Field, Packet, load_layer, TCPSession
    from scapy.contrib.igmp import IGMP
    from scapy.layers.inet import TCP, UDP, IP, ICMP
    from scapy.layers.inet6 import (
        ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA,
        ICMPv6ND_RA, ICMPv6ND_RS, IPv6, ICMPv6Unknown, ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6ParamProblem,
        IPv6ExtHdrHopByHop, ICMPv6NDOptSrcLLAddr, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
        ICMPv6ND_Redirect
    )
    from scapy.layers.l2 import Ether, ARP, GRE, Loopback, Dot1Q, getmacbyip
    from scapy.packet import bind_layers, Raw, NoPayload
except ImportError:
    print("[Sniffer] Scapy library not found. Please install it using: pip install scapy")
    sys.exit(1)

# --- Load the libpcap library dynamically ---
try:
    if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        try:
            libpcap = ctypes.CDLL("libpcap.so.1.0")
        except OSError:
            libpcap = ctypes.CDLL("libpcap.dylib")
    elif sys.platform.startswith("win"):
        libpcap = ctypes.CDLL("wpcap.dll")
    else:
        raise OSError("Unsupported operating system.")
except OSError as e:
    print(f"[Sniffer] Could not load libpcap library: {e}")
    print("Please ensure libpcap (or WinPcap/Npcap) is installed and available in your system's PATH.")
    sys.exit(1)

# --- Define C data types and structures for libpcap functions ---

class bpf_program(Structure):
    _fields_ = [
        ("bf_len", c_uint),
        ("bf_insns", POINTER(c_char))  # Opaque pointer is fine for compile/setfilter/freecode
    ]

class timeval(Structure):
    _fields_ = [
        ("tv_sec", c_long),   # seconds
        ("tv_usec", c_long),  # microseconds
    ]

# pcap_pkthdr (with timeval)
class pcap_pkthdr(Structure):
    _fields_ = [
        ("ts", timeval),
        ("caplen", c_uint),
        ("len", c_uint),
    ]

# --- DLT constants we care about ---
# --- DLT constants we care about (tcpdump.org/linktypes) ---
DLT_NULL            = 0
DLT_EN10MB          = 1
DLT_IEEE802_3       = 2
DLT_PPP             = 9
DLT_LOOP            = 12
DLT_PPP_BSDOS       = 16
DLT_PFLOG           = 48
DLT_PPP_SERIAL      = 50
DLT_C_HDLC          = 104     # Cisco HDLC
DLT_IEEE802_11      = 105
DLT_IEEE802_11_RADIO= 127
DLT_PPP_WITH_DIR    = 204
DLT_PPI             = 192     # Per-Packet Info
DLT_LINUX_SLL       = 113
DLT_RAW             = 101
DLT_LINUX_SLL2      = 276
# Optional/less common but useful:
DLT_FRELAY          = 107     # Frame Relay (payload varies; often like CHDLC)
DLT_IPV4            = 228
DLT_IPV6            = 229
DLT_PRISM_HEADER       = 119
DLT_TZSP               = 128
DLT_IEEE802_11_RADIO_AVS = 163

# Optional capture direction (if supported by lib)
PCAP_D_IN = 1  # inbound only



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
        IP6Field("mcaddr", "::")
    ]

class MLDDone(Packet):
    name = "ICMPv6 MLD Done"
    fields_desc = [
        ShortField("mrd", 0),
        ShortField("res", 0),
        IP6Field("mcaddr", "::")
    ]



class ICMPv6(Packet):
    """
    Custom ICMPv6 base layer based on RFC 4443.
    This layer defines the common header and handles checksum calculation.
    """
    name = "ICMPv6 - Internet Control Message Protocol v6"
    fields_desc = [
        ByteField("type", 0),  # ICMPv6 Message Type
        ByteField("code", 0),  # ICMPv6 Message Code
        XShortField("cksum", None)  # Checksum. 'None' tells Scapy to compute it.
    ]

    def post_build(self, p, pay):
        """
        Calculates the checksum after the packet is built.
        This is crucial because the checksum includes a pseudo-header
        derived from the parent IPv6 layer.
        """
        # If a checksum is already provided, do nothing.
        if self.cksum is None and self.underlayer and isinstance(self.underlayer, IPv6):
            # The 'p' variable contains the built ICMPv6 header (type, code, checksum)
            # The 'pay' variable is the payload that follows
            ip = self.underlayer

            # Construct the IPv6 pseudo-header
            # Format: Src IP (16B), Dst IP (16B), Upper-Layer Pkt Len (4B), Zeroes (3B), Next Hdr (1B)
            psd_hdr = struct.pack(
                "!16s16sI3xB",
                socket.inet_pton(socket.AF_INET6, ip.src),
                socket.inet_pton(socket.AF_INET6, ip.dst),
                len(p) + len(pay),
                58  # Protocol number for ICMPv6
            )

            # The checksum is calculated over the pseudo-header + the ICMPv6 packet
            # Scapy's in6_chksum handles this correctly
            from scapy.layers.inet6 import in6_chksum
            cksum = in6_chksum(58, ip, p + pay)

            # Place the calculated checksum back into the packet bytes
            p = p[:2] + struct.pack("!H", cksum) + p[4:]

        return p + pay
class DNSRR_AAAA(DNSRR):
    name = "DNSRR_AAAA"
    fields_desc = [
        DNSStrField("rrname", None),
        EnumField("type", 28, {1: "A", 28: "AAAA"}),
        EnumField("rclass", 1, {1: "IN"}),
        IntField("ttl", 0),
        FieldLenField("rdlen", None, length_of="rdata", fmt="!H"),
        IP6Field("rdata", "::")  # The IPv6 address itself
    ]

    def __init__(self, *args, **kwargs):
        super(DNSRR_AAAA, self).__init__(*args, **kwargs)
        # Force the type field to be AAAA (28)
        self.type = 28


class SnifferSoftware:
    """
    A class to manage sniffing and sending of Layer 2 and Layer 3 packets
    using direct libpcap/wpcap calls via ctypes.
    """
    ICMPV6_TYPES = (
        ICMPv6EchoRequest, ICMPv6EchoReply,
        ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_RS,
        ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6ParamProblem,
        ICMPv6Unknown, ICMP
    )
    def __init__(self, arp_manager, rip_manager, lag_manager, outbound_manager, notification_manager=None, _interfaces_config = None, logger=None, hyperv_manager = None, use_hyperv = False):
        self.arp_manager = arp_manager
        self.rip_manager = rip_manager
        self.lag_manager = lag_manager
        self.outbound_manager = outbound_manager
        self.use_hyperv = use_hyperv
        self._interfaces_config = _interfaces_config
        self.notification_manager = notification_manager
        self.logger = logger if logger else self._default_logger()
        self.libpcap = None

        # Persistent IPv4 resolution state for logical/virtual interfaces.
        # Some router-side names (WinDivertBridge, WireShark, Nate's Tunnel)
        # are not normal Windows NICs and therefore do not appear in Scapy's
        # interface inventory.  Keep one authoritative CIDR cache so sr1/send
        # can reuse the same answer instead of repeatedly failing resolution.
        self._ipv4_cidr_cache = {}
        self._ipv4_cidr_cache_source = {}
        self._ipv4_resolution_lock = threading.RLock()
        self._ipconfig_ipv4_inventory = None
        self._ipconfig_ipv4_loaded = False
        self._synthetic_ipv4_assignments = {}


        # Built-in dual-stack route fallback.  This is intentionally independent
        # of RIP so link-local multicast and ordinary OS-routed destinations do
        # not fail merely because the dynamic routing table has no entry.
        self._builtin_route_lock = threading.RLock()
        self._builtin_route_cache = {}
        self._builtin_route_cache_ttl_sec = 5.0
        self._builtin_route_log_ts = {}


        # Canonical interface inventory and Npcap alias caches.  Scapy versions
        # disagree on whether the capture path is stored in name, pcap_name, or
        # network_name, so all send/capture code goes through these caches.
        self._iface_inventory_lock = threading.RLock()
        self._iface_inventory_cache = []
        self._iface_inventory_cache_at = 0.0
        self._iface_inventory_cache_ttl_sec = 1.0
        self._pcap_alias_lock = threading.RLock()
        self._pcap_alias_cache = ({}, {})
        self._pcap_alias_cache_at = 0.0
        self._pcap_alias_cache_ttl_sec = 0.75

        # Send health state prevents a disconnected adapter from being retried for
        # every packet in a burst.  Successful interfaces are remembered per family.
        self._send_state_lock = threading.RLock()
        self._send_bad_until = {}
        self._send_failure_count = {}
        self._send_last_error = {}
        self._send_log_ts = {}
        self._last_good_send_iface = {}

        self.supported_ethertypes = {
            0x888E,  # EAPOL (802.1X)
            0x88CC,  # LLDP
            0x8809,  # LACP / Slow Protocols
            0x88F7,  # PTP
            0x88E7,  # keep if you already want it tolerated
            0x8808,  # MAC Control
            0x8902,  # OAM / CFM / Y.1731
            0x0800,  # IPv4
            0x86DD,  # IPv6
            0x0806,  # ARP
            0x8100,  # VLAN (802.1Q)
            0x88A8,  # QinQ / 802.1ad
            0x8864,  # PPPoE Session (you unwrap PPP->IP later)
            0x8863,  # PPPoE Discovery (to avoid false "unsupported" spam)
            0x8847,  # MPLS unicast
            0x8848,}
        self.unsupported_ethertypes = {}
        self.local_ips = self._get_local_ips()
        self.banned_packets = []
        self._load_pcap_library()
        # Load extra Scapy contrib dissectors we want available
        for mod in (
            "lldp", "lacp", "slowprot", "cdp", "vtp", "dtp",
            "oam", "mac_control", "erspan", "tzsp", "avs"
        ):
            try:
                importlib.import_module(f"scapy.contrib.{mod}")
            except Exception as e:
                self.logger.log_message(f"[Scapy] contrib load failed: {mod}: {e}")
        self.setup_scapy_bindings()
        self._define_pcap_prototypes()
        self.logged_packets = []
        self.hyperv_manager = hyperv_manager
        self.banned_ips = ["89.222.103.1"]

    # Add these helpers inside SnifferSoftware

    def _looks_like_removed_iface_error(self, err: str) -> bool:
        s = (err or "").strip().lower()
        if not s:
            return False
        needles = (
            "error_device_removed",
            "status_device_removed",
            "device removed",
            "the interface disappeared",
            "interface disappeared",
            "adapter was removed",
            "network adapter has been removed",
            "the handle is invalid",  # sometimes what Windows/Npcap surfaces after a rebind
            "invalid handle",
        )
        return any(n in s for n in needles)

    def _iter_reopen_candidates(self, iface: str):
        """Yield valid capture-device names for an interface alias.

        On Windows, Npcap must receive ``\\Device\\NPF_{GUID}``, not a friendly
        adapter label such as ``Wi-Fi``.  Friendly names are therefore used only
        for lookup and are never passed to ``pcap_open_live`` when unresolved.
        """
        requested = self._iface_text(iface)
        seen = set()

        def add(value):
            if not value:
                return
            normalized = self._normalize_pcap_name(value)
            resolved = self._resolve_pcap_iface_alias(normalized) or normalized
            resolved = self._normalize_pcap_name(resolved)
            if os.name == "nt" and not self._is_probable_pcap_device(resolved):
                return
            key = resolved.casefold()
            if key in seen:
                return
            seen.add(key)
            yield resolved

        # The canonical alias lookup is authoritative and should be attempted first.
        yield from add(requested)

        requested_cf = requested.casefold()
        with contextlib.suppress(Exception):
            for row in get_windows_if_list():
                aliases = self._aliases_from_windows_row(row)
                alias_cfs = {self._normalize_pcap_name(x).casefold() for x in aliases if x}
                if requested_cf in alias_cfs:
                    yield from add(self._pcap_name_from_windows_row(row))

        # Router metadata often stores the friendly name and Npcap path separately.
        with contextlib.suppress(Exception):
            for cfg_name, meta in (getattr(self, "_interfaces_config", {}) or {}).items():
                meta = meta or {}
                aliases = {
                    self._normalize_pcap_name(cfg_name),
                    self._normalize_pcap_name(meta.get("friendly_name")),
                    self._normalize_pcap_name(meta.get("name")),
                    self._normalize_pcap_name(meta.get("win_name")),
                    self._normalize_pcap_name(meta.get("description")),
                    self._normalize_pcap_name(meta.get("pcap_name")),
                    self._normalize_pcap_name(meta.get("full_name")),
                    self._normalize_pcap_name(meta.get("guid")),
                }
                aliases.discard("")
                if requested_cf not in {x.casefold() for x in aliases}:
                    continue
                for key in ("pcap_name", "full_name", "network_name", "guid", "name"):
                    yield from add(meta.get(key))

        # Non-Windows libpcap commonly accepts the native interface name directly.
        if os.name != "nt":
            yield from add(requested)

    def _open_pcap_handle(self, iface: str, promisc: bool, timeout: int,
                          bpf_filter: str | None, *, for_send: bool = False):
        """Open one canonical libpcap/Npcap device and optionally apply a BPF.

        Returns ``(handle, error_text)``.  Friendly Windows adapter names are
        resolved before the native call so error 123 is not generated by passing
        values such as ``Wi-Fi`` directly to Npcap.
        """
        candidate = self._resolve_pcap_iface_alias(iface) or self._normalize_pcap_name(iface)
        candidate = self._normalize_pcap_name(candidate)
        if not candidate:
            return None, "empty interface name"
        if os.name == "nt" and not self._is_probable_pcap_device(candidate):
            return None, f"unresolved Windows interface alias: {iface!r}"
        if for_send and not self._iface_is_known_up(candidate):
            return None, "network media is disconnected or adapter is administratively down"
        if for_send and self._iface_on_send_cooldown(candidate):
            return None, "interface is temporarily suppressed after a recent send failure"

        errbuf = ctypes.create_string_buffer(256)
        handle = self.libpcap.pcap_open_live(
            candidate.encode("utf-8"),
            65535,
            1 if promisc else 0,
            max(1, int(timeout)),
            errbuf,
        )
        if not handle:
            return None, errbuf.value.decode(errors="ignore")

        if bpf_filter:
            bpf = bpf_program()
            if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), bpf_filter.encode(), 1, 0) == -1:
                err = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
                with contextlib.suppress(Exception):
                    self.libpcap.pcap_close(handle)
                return None, f"filter compile failed: {err}"

            if self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) == -1:
                err = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
                with contextlib.suppress(Exception):
                    self.libpcap.pcap_freecode(ctypes.byref(bpf))
                with contextlib.suppress(Exception):
                    self.libpcap.pcap_close(handle)
                return None, f"filter set failed: {err}"

            with contextlib.suppress(Exception):
                self.libpcap.pcap_freecode(ctypes.byref(bpf))

        return handle, ""

    def iface_is_l2_capable(self, iface_name: str) -> bool:
        cfgs = getattr(self, "_interfaces_config", {}) or {}
        cfg = cfgs.get(iface_name, {}) if isinstance(cfgs, dict) else {}
        kind = str((cfg or {}).get("driver", "")).lower()
        return not any(token in kind for token in ("windivert", "rawip", "winfw"))
    def is_interface_connected(self, iface: str) -> bool:
        row = self._inventory_row_for_iface(iface)
        if row is not None:
            return bool(row.get("is_up", False))

        wanted = self._normalize_pcap_name(iface).casefold()
        with contextlib.suppress(Exception):
            stats = psutil.net_if_stats()
            for nic, state in stats.items():
                if self._normalize_pcap_name(nic).casefold() == wanted:
                    return bool(state.isup)
        return False

    def _default_logger(self):
        class Logger:
            def log_message(self, msg):
                print(msg)
        return Logger()

    def _get_local_ips(self):
        local_ips = []
        for iface_addrs in psutil.net_if_addrs().values():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    local_ips.append(addr.address)
        return local_ips

    def is_loopback(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return False

    def setup_scapy_bindings(self):
        # Standard L2 -> L3 Bindings
        bind_layers(Dot1Q, IP, type=0x0800)
        bind_layers(Dot1Q, IPv6, type=0x86DD)
        bind_layers(Dot1Q, ARP, type=0x0806)
        # --- FIX: Add Bindings for IPv6 Hop-by-Hop Extension Header ---
        # The Hop-by-Hop header is indicated by a Next Header value of 0 in the main IPv6 header.
        bind_layers(IPv6, IPv6ExtHdrHopByHop, nh=0)

        # Now, tell Scapy what can come *after* the Hop-by-Hop header.
        # The `nh` field within the Hop-by-Hop header itself points to the next layer.
        bind_layers(IPv6ExtHdrHopByHop, TCP, nh=6)
        bind_layers(IPv6ExtHdrHopByHop, UDP, nh=17)
        bind_layers(IPv6ExtHdrHopByHop, ICMPv6, nh=58)
        bind_layers(IPv6ExtHdrHopByHop, NoPayload, nh=59)  # No Next Header
        # -----------------------------------------------------------

        # Standard IPv6 -> L4 Bindings
        bind_layers(IPv6, TCP, nh=6)
        bind_layers(IPv6, UDP, nh=17)
        bind_layers(IPv6, ICMPv6, nh=58)
        bind_layers(IPv6, AH, nh=51)
        bind_layers(ICMPv6, ICMPv6ND_RS, type=133)
        bind_layers(ICMPv6, ICMPv6ND_RA, type=134)
        bind_layers(ICMPv6, ICMPv6ND_NS, type=135)
        bind_layers(ICMPv6, ICMPv6ND_NA, type=136)
        bind_layers(ICMPv6, ICMPv6ND_Redirect, type=137)
        bind_layers(ICMPv6, MLDQuery, type=130)
        bind_layers(ICMPv6, MLDReport, type=131)
        bind_layers(ICMPv6, MLDDone, type=132)
        bind_layers(IP, IGMP, proto=2)
        bind_layers(IGMP, IGMPv3mq, type=0x11)
        bind_layers(IGMP, IGMPv3mr, type=0x22)
        bind_layers(Ether, ARP, type=0x0806)
        # Use the real ones:
        bind_layers(UDP, ISAKMP, dport=500)
        bind_layers(UDP, ISAKMP, sport=500)
        bind_layers(UDP, ISAKMP, dport=4500)
        bind_layers(UDP, ISAKMP, sport=4500)
        bind_layers(UDP, DNS, dport=53)
        bind_layers(UDP, DNS, sport=53)
        bind_layers(IP, ESP, proto=50)
        bind_layers(IP, AH, proto=51)
        bind_layers(IPv6, AH, nh=51)
        bind_layers(IP, GRE, proto=47)
        # DHCPv4 over IPv4/UDP
        bind_layers(UDP, BOOTP, sport=67)  # server -> client
        bind_layers(UDP, BOOTP, dport=67)  # client -> server
        bind_layers(UDP, BOOTP, sport=68)  # some NICs/drivers expose reverse ordering
        bind_layers(UDP, BOOTP, dport=68)

        # BOOTP payload carries the DHCP options layer
        bind_layers(BOOTP, DHCP)
        # Extra protocols
        bind_layers(UDP, DHCP6, sport=547)
        bind_layers(UDP, DHCP6, dport=546)
        bind_layers(UDP, RTP, dport=5004)
        bind_layers(UDP, RTP, sport=5004)
        bind_layers(UDP, GENEVE, dport=6081)
        bind_layers(UDP, GENEVE, sport=6081)
        bind_layers(UDP, L2TP, dport=1701)
        bind_layers(UDP, L2TP, sport=1701)
        bind_layers(UDP, MobileIP, dport=434)
        bind_layers(UDP, MobileIP, sport=434)
        bind_layers(EAPOL, EAP, type=0)
        bind_layers(PPP, EAP, proto=0xC227)
        bind_layers(UDP, Kerberos, sport=88)
        bind_layers(UDP, Kerberos, dport=88)
        bind_layers(TCP, Kerberos, sport=88)
        bind_layers(TCP, Kerberos, dport=88)
        bind_layers(Ether, EAPOL, type=0x888E)
        #
        #special
        bind_layers(IPv6, IPv6ExtHdrRouting, nh=43)
        bind_layers(IPv6, IPv6ExtHdrDestOpt, nh=60)
        bind_layers(IPv6, IPv6ExtHdrFragment, nh=44)
        bind_layers(PPP, IP, proto=0x0021)  # IPv4 over PPP
        bind_layers(PPP, IPv6, proto=0x0057)  # IPv6 over PPP

        bind_layers(Ether, PPPoED, type=0x8863)
        bind_layers(Ether, PPPoE, type=0x8864)
        bind_layers(PPPoE, PPP)  # then PPP will carry IPCP/IP/IPv6CP

        bind_layers(Ether, MPLS, type=0x8847)
        bind_layers(Ether, MPLS, type=0x8848)

        bind_layers(Dot1Q, Dot1Q, type=0x8100)  # nested VLANs (common)
        #
        load_layer("vxlan")
        load_layer("dhcp")
        load_layer("dhcp6")
        load_layer("tls")
        load_layer("kerberos")
        load_layer("rip")
        load_layer("dns")
        load_layer("dot11")

        # TZSP automatic dissection on default UDP port 0x9090
        try:
            from scapy.contrib.tzsp import TZSP
            bind_layers(UDP, TZSP, sport=0x9090)
            bind_layers(UDP, TZSP, dport=0x9090)
        except Exception as e:
            self.logger.log_message(f"[Scapy] TZSP bind failed: {e}")
    def _load_pcap_library(self):
        if self.libpcap:
            return
        try:
            if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
                try:
                    self.libpcap = ctypes.CDLL("libpcap.so.1.0")
                except OSError:
                    self.libpcap = ctypes.CDLL("libpcap.dylib")
            elif sys.platform.startswith("win"):
                self.libpcap = ctypes.CDLL("wpcap.dll")
            else:
                raise OSError("Unsupported operating system.")
        except OSError as e:
            self.logger.log_message(f"[Sniffer] Could not load libpcap library: {e}")
            self.logger.log_message("Please ensure libpcap (or WinPcap/Npcap) is installed.")
            sys.exit(1)

    def _define_pcap_prototypes(self):
        if not self.libpcap:
            return

        # Consistent handle type
        pcap_t_p = ctypes.c_void_p

        # open_live(dev, snaplen, promisc, to_ms, errbuf)
        self.libpcap.pcap_open_live.restype  = pcap_t_p
        self.libpcap.pcap_open_live.argtypes = [ctypes.c_char_p, c_int, c_int, c_int, ctypes.c_char_p]

        # next_ex(pcap_t*, const struct pcap_pkthdr **, const u_char **)
        self.libpcap.pcap_next_ex.restype  = c_int
        self.libpcap.pcap_next_ex.argtypes = [
            pcap_t_p,
            ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))
        ]

        # sendpacket(pcap_t *, const u_char *, int)
        self.libpcap.pcap_sendpacket.restype  = c_int
        self.libpcap.pcap_sendpacket.argtypes = [pcap_t_p, ctypes.POINTER(ctypes.c_ubyte), c_int]

        # compile/setfilter/freecode/close/geterr/datalink
        self.libpcap.pcap_compile.restype  = c_int
        self.libpcap.pcap_compile.argtypes = [pcap_t_p, ctypes.POINTER(bpf_program), ctypes.c_char_p, c_int, c_uint]

        self.libpcap.pcap_setfilter.restype  = c_int
        self.libpcap.pcap_setfilter.argtypes = [pcap_t_p, ctypes.POINTER(bpf_program)]

        self.libpcap.pcap_freecode.restype  = None
        self.libpcap.pcap_freecode.argtypes = [ctypes.POINTER(bpf_program)]

        self.libpcap.pcap_close.restype  = None
        self.libpcap.pcap_close.argtypes = [pcap_t_p]

        self.libpcap.pcap_geterr.restype  = ctypes.c_char_p
        self.libpcap.pcap_geterr.argtypes = [pcap_t_p]

        self.libpcap.pcap_datalink.restype  = c_int
        self.libpcap.pcap_datalink.argtypes = [pcap_t_p]

        # Optional (inbound-only)
        try:
            self.libpcap.pcap_setdirection.restype  = c_int
            self.libpcap.pcap_setdirection.argtypes = [pcap_t_p, c_int]
        except Exception:
            pass  # Not present on very old builds

    # --- NEW: generic tunnel/L2 unwrap helpers --------------------------------
    def _unwrap_vlan(self, p):
        # peel stacked Dot1Q to next payload (often Ether or L3)
        while isinstance(p, Dot1Q):
            p = p.payload
        return p

    def _unwrap_pppoe(self, p):
        # PPPoE -> PPP -> IP/IPv6
        if isinstance(p, PPPoE):
            p = p.payload
        if isinstance(p, PPP):
            p = p.payload
        return p

    def _unwrap_mpls(self, p):
        # MPLS may stack; walk until Bottom-of-Stack (s=1)
        cur = p
        last = None
        while isinstance(cur, MPLS):
            last = cur
            cur = cur.payload
        # Some captures leave inner Ether unparsed; Scapy usually handles it,
        # but we just return the payload after the last MPLS label.
        return cur if last else p

    def _unwrap_udp_tunnels(self, l4):
        """
        VXLAN/GENEVE/L2TP-over-UDP → return inner payload (often Ether → IP).
        """
        try:
            # VXLAN (default UDP 4789). scapy's VXLAN returns inner Ether as payload.
            if hasattr(l4, "dport") and int(l4.dport) in (4789,):  # VXLAN
                vx = getattr(l4, "payload", None)
                # VXLAN layer name can vary by scapy build; rely on presence of .payload that is Ether
                if vx and hasattr(vx, "payload"):
                    return vx.payload  # inner Ether

            # GENEVE (UDP 6081): scapy.contrib.geneve.GENEVE
            if hasattr(l4, "dport") and int(l4.dport) in (6081,):
                ge = getattr(l4, "payload", None)
                if isinstance(ge, GENEVE) and ge.payload is not None:
                    return ge.payload  # usually Ether

            # L2TP (UDP 1701) typically carries PPP (and then IP)
            if hasattr(l4, "dport") and int(l4.dport) in (1701,):
                l2tp = getattr(l4, "payload", None)
                if isinstance(l2tp, L2TP) and l2tp.payload is not None:
                    return l2tp.payload  # often PPP/HDLC/Ether
        except Exception:
            pass
        return None

    def _unwrap_gre(self, layer):
        """
        GRE payload can be Ether or IP; return the useful inner layer.
        """
        try:
            if isinstance(layer, GRE):
                inner = layer.payload
                # If inner is Ether, go one deeper to IP/IPv6 if present
                if isinstance(inner, Ether):
                    ethp = inner.payload
                    return ethp if isinstance(ethp, (IP, IPv6, MPLS, PPP, PPPoE, Dot1Q)) else inner
                return inner
        except Exception:
            pass
        return None

    def _descend_to_ip(self, p, max_depth=8):
        """
        From any layer (Ether/VLAN/PPPoE/PPP/MPLS/Ether), descend until IP/IPv6 or give up.
        """
        depth = 0
        cur = p
        while depth < max_depth and cur is not None:
            depth += 1
            # If already at L3, stop
            if isinstance(cur, (IP, IPv6)):
                return cur

            # Ether → handle VLANs and get inner
            if isinstance(cur, Ether):
                pay = cur.payload
                # unwrap nested VLANs first
                if isinstance(pay, Dot1Q):
                    pay = self._unwrap_vlan(pay)
                # PPPoE?
                if isinstance(pay, PPPoE) or isinstance(pay, PPP):
                    pay = self._unwrap_pppoe(pay)
                # MPLS?
                if isinstance(pay, MPLS):
                    pay = self._unwrap_mpls(pay)
                # If still Ether-like (some drivers), step once
                if isinstance(pay, Ether):
                    cur = pay
                    continue
                cur = pay
                continue

            # Direct VLAN
            if isinstance(cur, Dot1Q):
                cur = self._unwrap_vlan(cur)
                continue

            # PPPoE/PPP
            if isinstance(cur, (PPPoE, PPP)):
                cur = self._unwrap_pppoe(cur)
                continue

            # MPLS
            if isinstance(cur, MPLS):
                cur = self._unwrap_mpls(cur)
                continue

            # GRE anywhere in path
            if isinstance(cur, GRE):
                cur = self._unwrap_gre(cur)
                continue

            # Some tunnels deliver an inner Ether frame as 'payload'
            pay = getattr(cur, "payload", None)
            if isinstance(pay, Ether):
                cur = pay
                continue

            # Nothing we recognize further
            break
        return cur if isinstance(cur, (IP, IPv6)) else None

    # --- UPDATED: transport finder w/ tunnel awareness -------------------------
    def _find_transport_layer(self, pkt: Packet) -> Optional[Packet]:
        """
        Return the deepest useful transport/control layer object if discoverable.

        Contract:
          - Returns a Scapy layer instance (not metadata/dict)
          - Returns None when the transport/control layer is not safely knowable

        Coverage:
          - TCP / UDP / ICMP / ICMPv6*
          - IGMP / IGMPv3mq / IGMPv3mr
          - ISAKMP / L2TP / BOOTP / DHCP / DHCP6 / DNS
          - AH (visible), but ESP => None
          - Tunnel-aware via _coerce_to_l3 / _descend_to_ip / _walk_ipv4 / _walk_ipv6 / _iter_layers_deep

        Safety rules:
          - IPv4 non-first fragment (frag > 0) => None
          - IPv6 fragment offset != 0 => None
          - ESP => None
        """
        if pkt is None:
            return None

        def _is_nonfirst_ipv4_fragment(ip4_layer: Packet) -> bool:
            try:
                return isinstance(ip4_layer, IP) and int(getattr(ip4_layer, "frag", 0) or 0) > 0
            except Exception:
                return False

        def _ipv6_fragment_blocks_l4(layer_obj: Packet) -> bool:
            try:
                if isinstance(layer_obj, IPv6ExtHdrFragment):
                    off = int(getattr(layer_obj, "offset", 0) or 0)
                    return off != 0
            except Exception:
                return True
            return False

        def _is_icmpv6_like(layer_obj: Packet) -> bool:
            if layer_obj is None:
                return False
            try:
                if isinstance(layer_obj, self.ICMPV6_TYPES):
                    return True
            except Exception:
                pass
            try:
                return layer_obj.__class__.__name__.startswith("ICMPv6")
            except Exception:
                return False

        def _is_transport_candidate(layer_obj: Packet) -> bool:
            if layer_obj is None:
                return False

            if isinstance(layer_obj, (TCP, UDP, ICMP, IGMP, IGMPv3mq, IGMPv3mr)):
                return True

            if _is_icmpv6_like(layer_obj):
                return True

            if isinstance(layer_obj, (ISAKMP, L2TP, BOOTP, DHCP, DHCP6, DNS, AH)):
                return True

            return False

        def _prefer_layer(current_best: Optional[Packet], candidate: Packet) -> Packet:
            """
            Prefer the later/deeper candidate, but avoid replacing a strong, specific
            candidate with a weaker wrapper when possible.
            """
            if current_best is None:
                return candidate

            try:
                # Prefer IGMPv3 subtype over generic IGMP
                if isinstance(candidate, (IGMPv3mq, IGMPv3mr)) and isinstance(current_best, IGMP):
                    return candidate

                # Prefer specific ICMPv6 subtype over generic/custom ICMPv6 base
                if _is_icmpv6_like(candidate) and _is_icmpv6_like(current_best):
                    cur_name = current_best.__class__.__name__
                    new_name = candidate.__class__.__name__
                    if cur_name == "ICMPv6" and new_name != "ICMPv6":
                        return candidate

                # Prefer DHCP over BOOTP if both appear
                if isinstance(candidate, DHCP) and isinstance(current_best, BOOTP):
                    return candidate

                # Prefer deeper layer by default
                return candidate
            except Exception:
                return candidate

        # ------------------------------------------------------------
        # 1) Fast path: use the dedicated L3 walkers first
        # ------------------------------------------------------------
        try:
            ip, _why = self._coerce_to_l3(pkt)
            if ip is None and isinstance(pkt, Ether):
                ip = self._descend_to_ip(pkt)

            if isinstance(ip, IPv6):
                tl = self._walk_ipv6(ip)
                if tl is not None:
                    return tl

            elif isinstance(ip, IP):
                tl = self._walk_ipv4(ip)
                if tl is not None:
                    return tl

                # IPv4-local fallback for IGMP if walker is conservative
                try:
                    if ip.haslayer(IGMPv3mq):
                        return ip.getlayer(IGMPv3mq)
                    if ip.haslayer(IGMPv3mr):
                        return ip.getlayer(IGMPv3mr)
                    if ip.haslayer(IGMP):
                        return ip.getlayer(IGMP)
                except Exception:
                    pass

        except Exception:
            pass

        # ------------------------------------------------------------
        # 2) Direct packet-local scan before deep decap
        #    Cheap and often enough for already-dissected packets
        # ------------------------------------------------------------
        try:
            for cls in (
                    IGMPv3mq, IGMPv3mr, IGMP,
                    DHCP, BOOTP, DHCP6, DNS,
                    ISAKMP, L2TP,
                    TCP, UDP, ICMP,
            ):
                try:
                    layer = pkt.getlayer(cls)
                    if layer is not None:
                        ip4 = pkt.getlayer(IP)
                        if ip4 is not None and _is_nonfirst_ipv4_fragment(ip4):
                            return None

                        frag6 = pkt.getlayer(IPv6ExtHdrFragment)
                        if frag6 is not None and _ipv6_fragment_blocks_l4(frag6):
                            return None

                        if pkt.getlayer(ESP) is not None:
                            return None

                        return layer
                except Exception:
                    pass

            # ICMPv6 family needs looser matching
            try:
                for layer in pkt.layers():
                    obj = pkt.getlayer(layer)
                    if _is_icmpv6_like(obj):
                        ip4 = pkt.getlayer(IP)
                        if ip4 is not None and _is_nonfirst_ipv4_fragment(ip4):
                            return None

                        frag6 = pkt.getlayer(IPv6ExtHdrFragment)
                        if frag6 is not None and _ipv6_fragment_blocks_l4(frag6):
                            return None

                        if pkt.getlayer(ESP) is not None:
                            return None

                        return obj
            except Exception:
                pass

        except Exception:
            pass

        # ------------------------------------------------------------
        # 3) Deep path: decap across tunnels and pick the best deepest
        # ------------------------------------------------------------
        best: Optional[Packet] = None

        try:
            for layer in self._iter_layers_deep(pkt, max_nodes=192):
                if layer is None:
                    continue

                # ---- hard stop gates ----
                if isinstance(layer, IP):
                    if _is_nonfirst_ipv4_fragment(layer):
                        return None
                    continue

                if isinstance(layer, IPv6ExtHdrFragment):
                    if _ipv6_fragment_blocks_l4(layer):
                        return None
                    continue

                if isinstance(layer, ESP):
                    return None

                # AH is visible/authenticated; allow it as a candidate but keep walking
                if isinstance(layer, AH):
                    best = _prefer_layer(best, layer)
                    continue

                # ---- transport / control candidates ----
                if _is_transport_candidate(layer):
                    best = _prefer_layer(best, layer)
                    continue

                # ---- packet-specific tunnel assists ----
                # If a GRE layer exposes an inner packet that deep iterator has not yielded yet,
                # try a local descend-to-IP rescue.
                try:
                    if isinstance(layer, GRE):
                        inner = self._unwrap_gre(layer)
                        if inner is not None:
                            if isinstance(inner, IPv6):
                                tl = self._walk_ipv6(inner)
                                if tl is not None:
                                    best = _prefer_layer(best, tl)
                                    continue
                            elif isinstance(inner, IP):
                                tl = self._walk_ipv4(inner)
                                if tl is not None:
                                    best = _prefer_layer(best, tl)
                                    continue
                            else:
                                ip_inner = self._descend_to_ip(inner)
                                if isinstance(ip_inner, IPv6):
                                    tl = self._walk_ipv6(ip_inner)
                                    if tl is not None:
                                        best = _prefer_layer(best, tl)
                                        continue
                                elif isinstance(ip_inner, IP):
                                    tl = self._walk_ipv4(ip_inner)
                                    if tl is not None:
                                        best = _prefer_layer(best, tl)
                                        continue
                except Exception:
                    pass

                # UDP tunnel rescue if iterator surfaces the UDP but not yet the inner payload
                try:
                    if isinstance(layer, UDP):
                        inner = self._unwrap_udp_tunnels(layer)
                        if inner is not None:
                            if isinstance(inner, IPv6):
                                tl = self._walk_ipv6(inner)
                                if tl is not None:
                                    best = _prefer_layer(best, tl)
                                    continue
                            elif isinstance(inner, IP):
                                tl = self._walk_ipv4(inner)
                                if tl is not None:
                                    best = _prefer_layer(best, tl)
                                    continue
                            else:
                                ip_inner = self._descend_to_ip(inner)
                                if isinstance(ip_inner, IPv6):
                                    tl = self._walk_ipv6(ip_inner)
                                    if tl is not None:
                                        best = _prefer_layer(best, tl)
                                        continue
                                elif isinstance(ip_inner, IP):
                                    tl = self._walk_ipv4(ip_inner)
                                    if tl is not None:
                                        best = _prefer_layer(best, tl)
                                        continue
                except Exception:
                    pass

            return best

        except Exception:
            return best

    def _walk_ipv6(self, ip6: IPv6) -> Optional[Packet]:
        """
        Walk an IPv6 packet (including extension headers / common tunnels)
        and return the first real transport/control layer we can safely identify.

        Rules:
          - Non-first IPv6 fragment (offset != 0) -> None
          - ESP -> None (encrypted; inner L4 not knowable here)
          - AH  -> allowed; continue walking
          - Supports nested IPv6/IPv4, GRE, Ether-carried inner packets
          - Returns a Scapy layer object (TCP/UDP/ICMPv6/... ) or None
        """
        if ip6 is None:
            return None

        layer: Packet = ip6.payload
        max_hops = 24  # a little larger than IPv4 because of ext-header chains

        while layer is not None and max_hops > 0:
            max_hops -= 1

            # ---------------------------------------------------------
            # IPv6 extension headers
            # ---------------------------------------------------------
            if isinstance(layer, (IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt)):
                layer = layer.payload
                continue

            if isinstance(layer, IPv6ExtHdrFragment):
                try:
                    off = int(getattr(layer, "offset", 0) or 0)
                except Exception:
                    off = 0

                # Non-first fragment doesn't contain a full transport header
                if off != 0:
                    return None

                layer = layer.payload
                continue

            # ---------------------------------------------------------
            # IPsec
            # ---------------------------------------------------------
            if isinstance(layer, ESP):
                return None

            if isinstance(layer, AH):
                layer = layer.payload
                continue

            # ---------------------------------------------------------
            # Direct transport / control
            # ---------------------------------------------------------
            if isinstance(layer, (TCP, UDP, ICMP)):
                return layer

            # Your codebase uses multiple ICMPv6-specific classes and sometimes
            # name-based checks, so support both styles.
            try:
                if isinstance(layer, self.ICMPV6_TYPES):
                    return layer
            except Exception:
                pass

            try:
                if layer.__class__.__name__.startswith("ICMPv6"):
                    return layer
            except Exception:
                pass

            # Some control protocols you may still want surfaced directly
            if isinstance(layer, (ISAKMP, L2TP, DHCP6, DNS)):
                return layer

            # ---------------------------------------------------------
            # Nested IP
            # ---------------------------------------------------------
            if isinstance(layer, IPv6):
                layer = layer.payload
                continue

            if isinstance(layer, IP):
                return self._walk_ipv4(layer)

            # ---------------------------------------------------------
            # GRE tunnel
            # ---------------------------------------------------------
            if isinstance(layer, GRE):
                inner = self._unwrap_gre(layer)

                if isinstance(inner, IPv6):
                    return self._walk_ipv6(inner)

                if isinstance(inner, IP):
                    return self._walk_ipv4(inner)

                ip_inner = self._descend_to_ip(inner)
                if isinstance(ip_inner, IPv6):
                    return self._walk_ipv6(ip_inner)
                if isinstance(ip_inner, IP):
                    return self._walk_ipv4(ip_inner)
                return None

            # ---------------------------------------------------------
            # UDP tunnel payloads (GENEVE / L2TP / VXLAN-style inner payloads)
            # Only attempt this after confirming the current layer is UDP.
            # ---------------------------------------------------------
            if isinstance(layer, UDP):
                inner = self._unwrap_udp_tunnels(layer)
                if inner is not None:
                    if isinstance(inner, IPv6):
                        return self._walk_ipv6(inner)
                    if isinstance(inner, IP):
                        return self._walk_ipv4(inner)

                    ip_inner = self._descend_to_ip(inner)
                    if isinstance(ip_inner, IPv6):
                        return self._walk_ipv6(ip_inner)
                    if isinstance(ip_inner, IP):
                        return self._walk_ipv4(ip_inner)

                return layer

            # ---------------------------------------------------------
            # Ether-carried inner packet after some tunnel
            # ---------------------------------------------------------
            pay = getattr(layer, "payload", None)
            if isinstance(pay, Ether):
                ip_inner = self._descend_to_ip(pay)
                if isinstance(ip_inner, IPv6):
                    return self._walk_ipv6(ip_inner)
                if isinstance(ip_inner, IP):
                    return self._walk_ipv4(ip_inner)
                return None

            # ---------------------------------------------------------
            # PPP / PPPoE / MPLS / VLAN if they appear below odd tunnels
            # ---------------------------------------------------------
            if isinstance(layer, (PPPoE, PPP, MPLS, Dot1Q)):
                ip_inner = self._descend_to_ip(layer)
                if isinstance(ip_inner, IPv6):
                    return self._walk_ipv6(ip_inner)
                if isinstance(ip_inner, IP):
                    return self._walk_ipv4(ip_inner)
                return None

            # ---------------------------------------------------------
            # Unknown next layer: stop conservatively
            # ---------------------------------------------------------
            return None

        return None
    # --- UPDATED: IPv4 walker with more tunnels -------------------------------
    def _walk_ipv4(self, ip4: IP) -> Optional[Packet]:
        # Non-first fragment (frag>0) lacks L4 header
        if getattr(ip4, "frag", 0) > 0:
            return None

        layer: Packet = ip4.payload
        max_hops = 16

        while layer is not None and max_hops > 0:
            max_hops -= 1

            # IPsec
            if isinstance(layer, ESP):
                return None
            if isinstance(layer, AH):
                layer = layer.payload
                continue

            # Transport
            if isinstance(layer, (TCP, UDP, ICMP)):
                return layer

            # Tunnels
            if isinstance(layer, IP):
                # IP-in-IP
                if getattr(layer, "frag", 0) > 0:
                    return None
                layer = layer.payload
                continue
            if isinstance(layer, IPv6):
                return self._walk_ipv6(layer)

            if isinstance(layer, GRE):
                inner = self._unwrap_gre(layer)
                if isinstance(inner, IPv6):
                    return self._walk_ipv6(inner)
                if isinstance(inner, IP):
                    return self._walk_ipv4(inner)
                ip_inner = self._descend_to_ip(inner)
                if isinstance(ip_inner, IPv6):
                    return self._walk_ipv6(ip_inner)
                if isinstance(ip_inner, IP):
                    return self._walk_ipv4(ip_inner)
                return None

            # If the payload is an Ether frame (after some tunnel), descend
            pay = getattr(layer, "payload", None)
            if isinstance(pay, Ether):
                ip_inner = self._descend_to_ip(pay)
                if isinstance(ip_inner, IPv6):
                    return self._walk_ipv6(ip_inner)
                if isinstance(ip_inner, IP):
                    # Restart walk from inner IP
                    return self._walk_ipv4(ip_inner)
                return None

            return None

        return None

    def _decode_by_dlt(self, raw: bytes, dlt: int):
        """
        Best-effort decode based on pcap linktype (DLT_*).
        Returns a Scapy Packet (Ether/IP/IPv6/LLC/PPP/CHDLC/etc.) or Raw on failure.
        """
        try:
            # Ethernet
            if dlt == DLT_EN10MB:
                return Ether(raw)
            if dlt == DLT_PRISM_HEADER:
                from scapy.layers.dot11 import PrismHeader
                return PrismHeader(raw)
            # 802.11 (with or without Radiotap/PPI)
            if dlt == DLT_IEEE802_11_RADIO:
                from scapy.layers.dot11 import RadioTap
                return RadioTap(raw)
            if dlt == DLT_IEEE802_11_RADIO_AVS:
                from scapy.contrib.avs import AVSWLANHeader
                return AVSWLANHeader(raw)
            if dlt == DLT_PPI:
                # PPI often wraps 802.11; Scapy understands inner payload
                from scapy.layers.ppi import PPI
                return PPI(raw)

            if dlt == DLT_IEEE802_11:
                from scapy.layers.dot11 import Dot11
                return Dot11(raw)
            if dlt == DLT_TZSP:
                from scapy.contrib.tzsp import TZSP
                return TZSP(raw)
            # Linux "cooked" captures
            if dlt == DLT_LINUX_SLL:
                from scapy.layers.l2 import CookedLinux
                return CookedLinux(raw)

            if dlt == DLT_LINUX_SLL2:
                # Newer cooked format; Scapy parses it as CookedLinux (SLL2 aware)
                from scapy.layers.l2 import CookedLinux
                return CookedLinux(raw)

            # PF firewall logs
            if dlt == DLT_PFLOG:
                from scapy.layers.pflog import PFLog
                return PFLog(raw)

            # PPP and friends
            if dlt == DLT_PPP:
                from scapy.layers.ppp import PPP
                return PPP(raw)

            if dlt == DLT_PPP_SERIAL:
                # Serial PPP is usually just PPP with HDLC flag stripped; try PPP directly
                from scapy.layers.ppp import PPP
                return PPP(raw)

            if dlt == DLT_PPP_WITH_DIR:
                # First byte is direction (0=sent, 1=received), then PPP frame
                # Guard against short frames
                from scapy.layers.ppp import PPP
                return PPP(raw[1:]) if len(raw) > 1 else Raw(raw)

            if dlt == DLT_PPP_BSDOS:
                # BSD/OS PPP: 1-byte direction + PPP (most common); some variants 4 bytes
                from scapy.layers.ppp import PPP
                if len(raw) > 1 and raw[0] in (0, 1):
                    return PPP(raw[1:])
                # Heuristic fallback
                return PPP(raw)

            # Cisco HDLC / Frame Relay
            if dlt == DLT_C_HDLC:
                from scapy.layers.l2 import CHDLC
                return CHDLC(raw)

            if dlt == DLT_FRELAY:
                # Frame Relay: Scapy doesn't have a dedicated FR layer that always fits
                # Many captures look like CHDLC framing; try CHDLC then fall back.
                from scapy.layers.l2 import CHDLC
                try:
                    return CHDLC(raw)
                except Exception:
                    return Raw(raw)

            # IEEE 802.3 length + LLC/SNAP
            if dlt == DLT_IEEE802_3:
                from scapy.layers.l2 import LLC
                return LLC(raw)

            # RAW/LOOP/NULL/IP-only linktypes
            if dlt == DLT_RAW:
                # raw IP (opaque to whether v4 or v6)
                try:
                    return IP(raw)
                except Exception:
                    return IPv6(raw)

            if dlt == DLT_IPV4:
                return IP(raw)

            if dlt == DLT_IPV6:
                return IPv6(raw)

            if dlt in (DLT_NULL, DLT_LOOP):
                # First 4 bytes are AF_* in **host** byte order; use native '@I'
                if len(raw) >= 4:
                    af = struct.unpack("@I", raw[:4])[0]
                    payload = raw[4:]
                    if af == socket.AF_INET:
                        return IP(payload)
                    if af == socket.AF_INET6:
                        return IPv6(payload)
                    # unknown family: still return Raw payload
                    return Raw(payload)
                return Raw(raw)

            # Fallback: let Scapy try raw IP, then IPv6, then Raw
            try:
                return IP(raw)
            except Exception:
                pass
            try:
                return IPv6(raw)
            except Exception:
                pass
            return Raw(raw)

        except Exception:
            # Never let a bad decode kill the loop
            return Raw(raw)

    def _dlt_name(self, dlt: int) -> str:
        names = {
            DLT_EN10MB: "EN10MB",
            DLT_IEEE802_11_RADIO: "IEEE802_11_RADIO",
            DLT_IEEE802_11: "IEEE802_11",
            DLT_LINUX_SLL: "LINUX_SLL",
            DLT_LINUX_SLL2: "LINUX_SLL2",
            DLT_NULL: "NULL",
            DLT_LOOP: "LOOP",
            DLT_RAW: "RAW",
            DLT_PPI: "PPI",
            DLT_PFLOG: "PFLOG",
            DLT_PPP: "PPP",
            DLT_PPP_SERIAL: "PPP_SERIAL",
            DLT_PPP_WITH_DIR: "PPP_WITH_DIR",
            DLT_PPP_BSDOS: "PPP_BSDOS",
            DLT_C_HDLC: "C_HDLC",
            DLT_IEEE802_3: "IEEE802_3",
            DLT_FRELAY: "FRELAY",
            DLT_IPV4: "IPV4",
            DLT_IPV6: "IPV6",
            DLT_PRISM_HEADER: "PRISM_HEADER",
            DLT_TZSP: "TZSP",
            DLT_IEEE802_11_RADIO_AVS: "IEEE802_11_RADIO_AVS",
        }
        return names.get(dlt, f"DLT({dlt})")

    # --- NEW: Windows-aware helpers ---
    def _send_l3_loopback(self, packet, *, expect_reply: bool = False, timeout: float = 2.0,
                         iface: Optional[str] = None, logger=None):
        """Send through the operating-system loopback stack without recursive calls."""
        try:
            from scapy.sendrecv import send as scapy_send
            from scapy.sendrecv import sr1 as scapy_sr1

            pkt = packet
            if isinstance(pkt, Ether):
                pkt = pkt.payload
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                raise ValueError("packet has no IP/IPv6 layer")

            loop_iface = iface
            if not loop_iface:
                loop_iface = getattr(conf, "loopback_interface", None) or getattr(conf, "loopback_name", None)
            if not loop_iface:
                with contextlib.suppress(Exception):
                    available = set(get_if_list())
                    for candidate in ("lo", "lo0", "Npcap Loopback Adapter", r"\Device\NPF_Loopback"):
                        if candidate in available:
                            loop_iface = candidate
                            break
            if not loop_iface:
                loop_iface = conf.iface

            if isinstance(ip, IP):
                if str(getattr(ip, "src", "") or "") in {"", "0.0.0.0"}:
                    pkt[IP].src = "127.0.0.1"
                if str(getattr(ip, "dst", "") or "") in {"", "0.0.0.0"}:
                    pkt[IP].dst = "127.0.0.1"
            else:
                if str(getattr(ip, "src", "") or "") in {"", "::"}:
                    pkt[IPv6].src = "::1"
                if str(getattr(ip, "dst", "") or "") in {"", "::"}:
                    pkt[IPv6].dst = "::1"

            if expect_reply:
                return scapy_sr1(pkt, timeout=float(timeout), iface=loop_iface, verbose=0)
            scapy_send(pkt, iface=loop_iface, verbose=0)
            return None
        except Exception as e:
            self.logger.log_message(f"[Loopback] Error: {type(e).__name__}: {e}")
            return None

    def _normalize_pcap_name(self, name: str) -> str:
        """Normalize aliases without changing the meaning of an Npcap path."""
        if name is None:
            return ""
        n = str(name).strip().strip('"')
        while "\\\\" in n:
            n = n.replace("\\\\", "\\")
        if n.casefold().startswith("device\\npf_"):
            n = "\\" + n
        return n

    @staticmethod
    def _guid_text(value: str) -> str:
        value = str(value or "").strip().strip("{}")
        parts = value.split("-")
        if len(parts) == 5 and [len(x) for x in parts] == [8, 4, 4, 4, 12]:
            if all(all(c in "0123456789abcdefABCDEF" for c in part) for part in parts):
                return value.upper()
        return ""

    def _is_probable_pcap_device(self, value: str) -> bool:
        n = self._normalize_pcap_name(value).casefold()
        if os.name != "nt":
            return bool(n)
        return n.startswith("\\device\\npf_") or n == "npf_loopback"

    def _pcap_name_from_windows_row(self, row: dict) -> str:
        if not isinstance(row, dict):
            return ""
        for key in ("pcap_name", "network_name", "name"):
            value = self._normalize_pcap_name(row.get(key))
            if self._is_probable_pcap_device(value):
                return value
        for key in ("guid", "id", "interface_guid"):
            guid = self._guid_text(row.get(key))
            if guid:
                return rf"\Device\NPF_{{{guid}}}"
        # Some Scapy builds put only the GUID in the name field.
        guid = self._guid_text(row.get("name"))
        return rf"\Device\NPF_{{{guid}}}" if guid else ""

    def _aliases_from_windows_row(self, row: dict) -> set[str]:
        aliases = set()
        if not isinstance(row, dict):
            return aliases
        pcap_name = self._pcap_name_from_windows_row(row)
        if pcap_name:
            aliases.add(pcap_name)
        for key in (
            "pcap_name", "network_name", "name", "win_name", "friendlyname",
            "friendly_name", "description", "guid", "id", "interface_guid",
        ):
            value = self._normalize_pcap_name(row.get(key))
            if value:
                aliases.add(value)
                guid = self._guid_text(value)
                if guid:
                    aliases.add(guid)
                    aliases.add("{" + guid + "}")
                    aliases.add(rf"\Device\NPF_{{{guid}}}")
        return aliases

    def _invalidate_interface_caches(self) -> None:
        with contextlib.suppress(Exception):
            with self._iface_inventory_lock:
                self._iface_inventory_cache_at = 0.0
                self._iface_inventory_cache = []
        with contextlib.suppress(Exception):
            with self._pcap_alias_lock:
                self._pcap_alias_cache_at = 0.0
                self._pcap_alias_cache = ({}, {})

    def _is_media_disconnected_error(self, error_text: str) -> bool:
        text = str(error_text or "").casefold()
        return any(token in text for token in (
            "network media is disconnected",
            "wireless access point is out of range",
            "media disconnected",
            "adapter is administratively down",
            "2150891551",
        ))

    def _log_send_once(self, key: str, message: str, every: float = 5.0) -> None:
        now = time.monotonic()
        with self._send_state_lock:
            last = float(self._send_log_ts.get(key, 0.0) or 0.0)
            if now - last < max(0.25, float(every)):
                return
            self._send_log_ts[key] = now
        self.logger.log_message(message)

    def _iface_on_send_cooldown(self, iface: str) -> bool:
        key = self._normalize_pcap_name(iface).casefold()
        with self._send_state_lock:
            return time.monotonic() < float(self._send_bad_until.get(key, 0.0) or 0.0)

    def _mark_send_failure(self, iface: str, error_text: str) -> None:
        normalized = self._normalize_pcap_name(iface)
        key = normalized.casefold()
        media_down = self._is_media_disconnected_error(error_text)
        with self._send_state_lock:
            failures = int(self._send_failure_count.get(key, 0) or 0) + 1
            self._send_failure_count[key] = failures
            self._send_last_error[key] = str(error_text or "unknown send failure")
            base = 3.0 if media_down else 1.0
            cooldown = min(60.0, base * (2 ** min(failures - 1, 5)))
            self._send_bad_until[key] = time.monotonic() + cooldown
        self._invalidate_interface_caches()
        # Do not keep returning a route that is tied to the failed adapter.
        with contextlib.suppress(Exception):
            failed_cf = normalized.casefold()
            with self._builtin_route_lock:
                stale = [
                    cache_key for cache_key, route in self._builtin_route_cache.items()
                    if self._normalize_pcap_name(route.get("interface", "")).casefold() == failed_cf
                ]
                for cache_key in stale:
                    self._builtin_route_cache.pop(cache_key, None)

    def _mark_send_success(self, iface: str, family: int = 0) -> None:
        normalized = self._normalize_pcap_name(iface)
        key = normalized.casefold()
        with self._send_state_lock:
            self._send_failure_count.pop(key, None)
            self._send_bad_until.pop(key, None)
            self._send_last_error.pop(key, None)
            if family in (4, 6):
                self._last_good_send_iface[family] = normalized

    def _iface_is_known_up(self, iface: str) -> bool:
        row = self._inventory_row_for_iface(iface)
        # Unknown virtual/capture devices should still be allowed one open attempt.
        return True if row is None else bool(row.get("is_up", False))

    def _is_npf_loopback(self, iface_name: str) -> bool:
        n = self._normalize_pcap_name(iface_name).lower()
        # handles "\Device\NPF_Loopback", "NPF_Loopback", with/without trailing space
        return n.endswith("\\device\\npf_loopback") or n == "npf_loopback"
    def _iface_text(self, iface) -> str:
        """Return a stable interface name from Scapy interface objects or strings."""
        if iface is None:
            return ""
        if isinstance(iface, str):
            return self._normalize_pcap_name(iface)
        for attr in ("pcap_name", "network_name", "name", "description"):
            value = getattr(iface, attr, None)
            if value:
                return self._normalize_pcap_name(str(value))
        return self._normalize_pcap_name(str(iface))

    def _resolve_pcap_iface_alias(self, iface_name: str | None) -> str | None:
        name = self._iface_text(iface_name)
        if not name:
            return None
        if self._is_probable_pcap_device(name):
            return name

        guid = self._guid_text(name)
        if guid and os.name == "nt":
            return rf"\Device\NPF_{{{guid}}}"

        try:
            alias_to_pcap, _ = self._build_pcap_alias_map()
            resolved = alias_to_pcap.get(name) or alias_to_pcap.get(name.casefold())
            if resolved:
                return self._normalize_pcap_name(resolved)
        except Exception:
            pass

        # Check router-side metadata even when Scapy has not refreshed yet.
        with contextlib.suppress(Exception):
            for cfg_name, cfg in (getattr(self, "_interfaces_config", {}) or {}).items():
                cfg = cfg or {}
                aliases = {
                    self._normalize_pcap_name(cfg_name),
                    self._normalize_pcap_name(cfg.get("friendly_name")),
                    self._normalize_pcap_name(cfg.get("name")),
                    self._normalize_pcap_name(cfg.get("win_name")),
                    self._normalize_pcap_name(cfg.get("description")),
                    self._normalize_pcap_name(cfg.get("pcap_name")),
                    self._normalize_pcap_name(cfg.get("full_name")),
                    self._normalize_pcap_name(cfg.get("guid")),
                }
                aliases.discard("")
                if name.casefold() not in {x.casefold() for x in aliases}:
                    continue
                for key in ("pcap_name", "full_name", "network_name", "guid", "name"):
                    candidate = self._normalize_pcap_name(cfg.get(key))
                    if self._is_probable_pcap_device(candidate):
                        return candidate
                    candidate_guid = self._guid_text(candidate)
                    if candidate_guid and os.name == "nt":
                        return rf"\Device\NPF_{{{candidate_guid}}}"

        return name

    @staticmethod
    def _strip_ipv6_zone(value: str) -> str:
        return str(value or "").split("%", 1)[0].strip()

    def _ip_object(self, value):
        try:
            return ipaddress.ip_address(self._strip_ipv6_zone(str(value or "")))
        except Exception:
            return None

    def _iface_inventory(self) -> list[dict]:
        """Return a cached, merged Windows/Npcap/psutil interface inventory."""
        now = time.monotonic()
        with self._iface_inventory_lock:
            if self._iface_inventory_cache and (
                now - self._iface_inventory_cache_at <= self._iface_inventory_cache_ttl_sec
            ):
                return [dict(row, aliases=set(row.get("aliases", set()))) for row in self._iface_inventory_cache]

        rows: list[dict] = []
        ps_addrs = psutil.net_if_addrs()
        ps_stats = psutil.net_if_stats()
        ps_names_cf = {name.casefold(): name for name in ps_addrs}

        try:
            win_rows = list(get_windows_if_list())
        except Exception:
            win_rows = []

        def norm_mac(value: str) -> str:
            return str(value or "").replace("-", ":").casefold()

        ps_by_mac = {}
        for friendly, addrs in ps_addrs.items():
            for addr in addrs:
                if getattr(addr, "family", None) == psutil.AF_LINK and addr.address:
                    ps_by_mac[norm_mac(addr.address)] = friendly

        seen_pcap = set()
        for raw in win_rows:
            pcap_name = self._pcap_name_from_windows_row(raw)
            if os.name == "nt" and not self._is_probable_pcap_device(pcap_name):
                continue
            aliases = self._aliases_from_windows_row(raw)
            if pcap_name:
                aliases.add(pcap_name)

            friendly = ""
            for alias in aliases:
                match = ps_names_cf.get(self._normalize_pcap_name(alias).casefold())
                if match:
                    friendly = match
                    break
            if not friendly:
                friendly = ps_by_mac.get(norm_mac(raw.get("mac") or raw.get("mac_address")), "")
            if friendly:
                aliases.add(friendly)

            address_strings = []
            for key in ("ips", "addresses"):
                value = raw.get(key)
                if isinstance(value, (list, tuple, set)):
                    address_strings.extend(str(x) for x in value if x)
            for key in ("ip", "ipv4", "ipv6"):
                value = raw.get(key)
                if value:
                    address_strings.append(str(value))
            if friendly in ps_addrs:
                address_strings.extend(str(a.address) for a in ps_addrs[friendly] if a.address)

            ipv4, ipv6 = [], []
            for value in address_strings:
                obj = self._ip_object(value)
                if obj is None or obj.is_unspecified:
                    continue
                target = ipv4 if obj.version == 4 else ipv6
                clean = str(obj)
                if clean not in target:
                    target.append(clean)

            index = 0
            for key in ("index", "if_index", "interface_index", "ipv6_if_index"):
                with contextlib.suppress(Exception):
                    index = int(raw.get(key) or 0)
                if index > 0:
                    break
            if index <= 0 and friendly:
                with contextlib.suppress(Exception):
                    index = int(socket.if_nametoindex(friendly))

            is_up = True
            if friendly and friendly in ps_stats:
                is_up = bool(ps_stats[friendly].isup)

            key = self._normalize_pcap_name(pcap_name).casefold()
            if key and key in seen_pcap:
                continue
            if key:
                seen_pcap.add(key)
            rows.append({
                "pcap_name": pcap_name,
                "friendly": friendly,
                "aliases": aliases,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "index": index,
                "is_up": is_up,
                "description": str(raw.get("description") or ""),
                "mac": norm_mac(raw.get("mac") or raw.get("mac_address")),
            })

        # Preserve active psutil adapters omitted by Scapy if they can be resolved.
        known_friendly = {str(r.get("friendly") or "").casefold() for r in rows}
        for friendly, addrs in ps_addrs.items():
            if friendly.casefold() in known_friendly:
                continue
            pcap_name = self._resolve_pcap_iface_alias(friendly) or ""
            if os.name == "nt" and not self._is_probable_pcap_device(pcap_name):
                continue
            ipv4, ipv6 = [], []
            mac = ""
            for addr in addrs:
                if getattr(addr, "family", None) == psutil.AF_LINK:
                    mac = norm_mac(getattr(addr, "address", ""))
                    continue
                obj = self._ip_object(getattr(addr, "address", ""))
                if obj is None or obj.is_unspecified:
                    continue
                (ipv4 if obj.version == 4 else ipv6).append(str(obj))
            index = 0
            with contextlib.suppress(Exception):
                index = int(socket.if_nametoindex(friendly))
            rows.append({
                "pcap_name": pcap_name,
                "friendly": friendly,
                "aliases": {friendly, pcap_name},
                "ipv4": list(dict.fromkeys(ipv4)),
                "ipv6": list(dict.fromkeys(ipv6)),
                "index": index,
                "is_up": bool(ps_stats.get(friendly).isup) if friendly in ps_stats else True,
                "description": friendly,
                "mac": mac,
            })

        with self._iface_inventory_lock:
            self._iface_inventory_cache = [dict(row, aliases=set(row.get("aliases", set()))) for row in rows]
            self._iface_inventory_cache_at = now
        return rows

    def _inventory_row_for_iface(self, iface_name: str | None) -> dict | None:
        wanted = self._normalize_pcap_name(iface_name or "")
        if not wanted:
            return None
        resolved = self._resolve_pcap_iface_alias(wanted) or wanted
        wanted_cfs = {wanted.casefold(), self._normalize_pcap_name(resolved).casefold()}
        for row in self._iface_inventory():
            aliases = {
                self._normalize_pcap_name(x).casefold()
                for x in row.get("aliases", set()) if x
            }
            aliases.add(self._normalize_pcap_name(row.get("pcap_name", "")).casefold())
            aliases.add(self._normalize_pcap_name(row.get("friendly", "")).casefold())
            if aliases.intersection(wanted_cfs):
                return row
        return None

    def _source_ip_for_iface(self, iface_name: str, family: int, destination: str = "") -> str | None:
        row = self._inventory_row_for_iface(iface_name)
        if row is None:
            return None
        values = list(row.get("ipv4" if family == 4 else "ipv6", []))
        if not values:
            return None
        dst = self._ip_object(destination)

        def score(value: str) -> int:
            obj = self._ip_object(value)
            if obj is None:
                return -10000
            result = 0
            if obj.is_loopback:
                result -= 1000
            if obj.is_unspecified:
                result -= 1000
            if family == 6 and dst is not None and dst.is_multicast:
                # ff02::/16 must use a link-local-capable source/interface.
                scope = int(dst.packed[1] & 0x0F)
                if scope <= 2 and obj.is_link_local:
                    result += 1000
                elif scope <= 2:
                    result -= 200
            if obj.is_link_local:
                result += 120 if family == 6 else -50
            if obj.is_private:
                result += 80
            if getattr(obj, "is_global", False):
                result += 70
            return result

        return max(values, key=score)

    def _interface_score(self, row: dict, family: int, destination: str, preferred: str = "") -> int:
        pcap_name = self._normalize_pcap_name(row.get("pcap_name", ""))
        if os.name == "nt" and not self._is_probable_pcap_device(pcap_name):
            return -100000
        if not row.get("is_up", True) or self._iface_on_send_cooldown(pcap_name):
            return -100000
        addresses = row.get("ipv4" if family == 4 else "ipv6", [])
        if not addresses:
            return -100000

        friendly = str(row.get("friendly") or "")
        desc = str(row.get("description") or "")
        token = f"{pcap_name} {friendly} {desc}".casefold()
        preferred_norm = self._normalize_pcap_name(preferred).casefold()
        aliases = {
            self._normalize_pcap_name(x).casefold()
            for x in row.get("aliases", set()) if x
        }
        aliases.add(pcap_name.casefold())

        score = 0
        if preferred_norm and preferred_norm in aliases:
            score += 10000
        if any(x in token for x in ("wi-fi", "wifi", "ethernet")):
            score += 600
        if any(x in token for x in ("wireless", "802.11")):
            score += 300
        if any(x in token for x in ("loopback", "npcap loopback")):
            score -= 5000
        if any(x in token for x in (
            "windivert", "wintun", "wireguard", "openvpn", "protonvpn",
            "zerotier", "hyper-v", "vethernet", "virtualbox", "vmware",
        )):
            score -= 500
        if "local area connection*" in token or "wi-fi direct" in token:
            score -= 900

        dst = self._ip_object(destination)
        if family == 6 and dst is not None and dst.is_multicast and int(dst.packed[1] & 0x0F) <= 2:
            if any(self._ip_object(ip) and self._ip_object(ip).is_link_local for ip in addresses):
                score += 1000
            else:
                score -= 500
        if family == 4 and dst is not None and dst.is_multicast:
            if any(self._ip_object(ip) and self._ip_object(ip).is_private for ip in addresses):
                score += 120

        with contextlib.suppress(Exception):
            cfgs = getattr(self, "_interfaces_config", {}) or {}
            for cfg_name, cfg in cfgs.items():
                cfg = cfg or {}
                cfg_tokens = {
                    self._normalize_pcap_name(cfg_name).casefold(),
                    self._normalize_pcap_name(cfg.get("friendly_name")).casefold(),
                    self._normalize_pcap_name(cfg.get("name")).casefold(),
                    self._normalize_pcap_name(cfg.get("pcap_name")).casefold(),
                    self._normalize_pcap_name(cfg.get("full_name")).casefold(),
                }
                cfg_tokens.discard("")
                if not aliases.intersection(cfg_tokens):
                    continue
                role = str(cfg.get("role") or cfg.get("direction") or "").casefold()
                if role in {"out", "wan", "uplink", "lan", "inside"}:
                    score += 350
                if bool(cfg.get("default_route") or cfg.get("is_default")):
                    score += 800
        return score

    def _scapy_route_for_destination(self, destination: str, family: int) -> dict | None:
        try:
            if family == 4:
                iface_obj, source_ip, gateway = conf.route.route(destination)
            else:
                iface_obj, source_ip, gateway = conf.route6.route(destination)
            iface_name = self._resolve_pcap_iface_alias(self._iface_text(iface_obj))
            if not iface_name:
                return None
            return {
                "interface": iface_name,
                "source_ip": self._strip_ipv6_zone(str(source_ip or "")),
                "next_hop": self._strip_ipv6_zone(str(gateway or "")),
                "route_source": "scapy-os-route",
            }
        except Exception:
            return None

    def _os_udp_source_for_destination(self, destination: str, family: int, scope_id: int = 0) -> str | None:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(0.25)
            if family == 4:
                sock.connect((destination, 9))
            else:
                sock.connect((destination, 9, 0, max(0, int(scope_id or 0))))
            return self._strip_ipv6_zone(str(sock.getsockname()[0]))
        except Exception:
            return None
        finally:
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()

    def _pick_pcap_iface_for_dst(self, dst_ip: str, preferred_iface: str | None = None) -> str | None:
        """Choose an active Npcap device for the destination and address family."""
        dst = self._ip_object(dst_ip)
        preferred = self._resolve_pcap_iface_alias(preferred_iface) or ""
        if dst is None:
            if preferred and self._iface_is_known_up(preferred) and not self._iface_on_send_cooldown(preferred):
                return preferred
            return None

        family = dst.version
        inventory = self._iface_inventory()

        if preferred:
            row = self._inventory_row_for_iface(preferred)
            if row and self._interface_score(row, family, str(dst), preferred) > -100000:
                return self._normalize_pcap_name(row.get("pcap_name") or preferred)

        os_route = self._scapy_route_for_destination(str(dst), family)
        if os_route:
            routed = self._resolve_pcap_iface_alias(os_route.get("interface"))
            row = self._inventory_row_for_iface(routed)
            if row and self._interface_score(row, family, str(dst)) > -100000:
                return self._normalize_pcap_name(row.get("pcap_name") or routed)

        if not dst.is_multicast:
            local_ip = self._os_udp_source_for_destination(str(dst), family)
            if local_ip:
                for row in inventory:
                    if local_ip in row.get("ipv4" if family == 4 else "ipv6", []):
                        if self._interface_score(row, family, str(dst), preferred) > -100000:
                            return self._normalize_pcap_name(row.get("pcap_name"))

        with self._send_state_lock:
            last_good = self._last_good_send_iface.get(family, "")
        if last_good:
            row = self._inventory_row_for_iface(last_good)
            if row and self._interface_score(row, family, str(dst), preferred) > -100000:
                return self._normalize_pcap_name(row.get("pcap_name") or last_good)

        ranked = sorted(
            inventory,
            key=lambda row: self._interface_score(row, family, str(dst), preferred),
            reverse=True,
        )
        if ranked and self._interface_score(ranked[0], family, str(dst), preferred) > -100000:
            return self._normalize_pcap_name(ranked[0].get("pcap_name"))
        return None

    def _dst_is_private_or_local(self, ip: str) -> bool:
        try:
            x = ipaddress.ip_address(ip)
            return x.is_loopback or x.is_link_local or x.is_private
        except Exception:
            return False


    def _ensure_egress_iface_for_dst(self, iface_in: str | None, dst_ip: str) -> str | None:
        """
        If iface_in is NPF Loopback and dst is not local, pick the real egress
        pcap device that Windows would use for dst_ip.
        """
        iface = iface_in
        if os.name == "nt" and iface and iface.lower().startswith("\\device\\npf_"):
            # If loopback and not local/private, remap
            if self._is_npf_loopback(iface) and not self._dst_is_private_or_local(dst_ip):
                # Use UDP connect trick to learn OS-chosen local IPv4 for this dst
                local_ip = None
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect((dst_ip, 53))
                    local_ip = s.getsockname()[0]
                    s.close()
                except Exception:
                    pass
                if not local_ip or not get_windows_if_list:
                    return None
                # Map local_ip → pcap_name
                for itf in get_windows_if_list():
                    ips = (itf.get("ips") or []) + ([itf.get("ip")] if itf.get("ip") else [])
                    for ip in ips:
                        if ip and "." in ip and ip == local_ip:
                            new_iface = itf.get("pcap_name")
                            if new_iface and not self._is_npf_loopback(new_iface):
                                self.logger.log_message(
                                    f"[Sniffer] 🔁 Replacing loopback with egress NIC: {iface} → {new_iface}"
                                )
                                return new_iface
                return None
        return iface

    @staticmethod
    def _ipv4_cache_key(iface_name: str) -> str:
        return str(iface_name or "").strip().casefold()

    def _remember_ipv4_cidr(self, iface_name: str, cidr: str, *, source: str) -> str | None:
        """Validate, cache, and expose an interface CIDR through _interfaces_config."""
        try:
            iface = str(iface_name or "").strip()
            parsed = ipaddress.IPv4Interface(str(cidr))
            canonical = f"{parsed.ip}/{parsed.network.prefixlen}"
        except Exception:
            return None

        key = self._ipv4_cache_key(iface)
        with self._ipv4_resolution_lock:
            self._ipv4_cidr_cache[key] = canonical
            self._ipv4_cidr_cache_source[key] = str(source or "unknown")

            configs = getattr(self, "_interfaces_config", None)
            if isinstance(configs, dict) and iface:
                cfg = configs.setdefault(iface, {})
                if isinstance(cfg, dict):
                    cfg.setdefault("friendly_name", iface)
                    cfg["ip_addr"] = str(parsed.ip)
                    cfg["netmask"] = str(parsed.network.netmask)
                    cfg["cidr"] = canonical
                    cfg["network"] = str(parsed.network)
                    cfg["ipv4_resolution_source"] = str(source or "unknown")
                    if str(source).startswith("synthetic"):
                        cfg["synthetic_ipv4"] = True

        return canonical

    def _load_ipconfig_ipv4_inventory_once(self) -> dict:
        """
        Parse `ipconfig /all` exactly once and retain a friendly-name -> CIDR map.

        This intentionally supplements rather than replaces Scapy/psutil because
        Windows can expose an address in ipconfig before Npcap refreshes its view.
        """
        with self._ipv4_resolution_lock:
            if self._ipconfig_ipv4_loaded:
                return dict(self._ipconfig_ipv4_inventory or {})
            self._ipconfig_ipv4_loaded = True

        inventory = {}
        if os.name != "nt":
            with self._ipv4_resolution_lock:
                self._ipconfig_ipv4_inventory = inventory
            return inventory

        try:
            cp = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            text = cp.stdout or ""
        except Exception as exc:
            self.logger.log_message(f"[Sniffer] ipconfig IPv4 inventory unavailable: {exc}")
            text = ""

        current = ""
        pending_ip = None
        for raw_line in text.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue

            # Adapter headings normally look like: "Ethernet adapter Ethernet:".
            if not raw_line[:1].isspace() and stripped.endswith(":"):
                heading = stripped[:-1].strip()
                lower = heading.casefold()
                if " adapter " in lower:
                    current = heading.split(" adapter ", 1)[1].strip()
                else:
                    current = heading
                pending_ip = None
                continue

            if not current or ":" not in stripped:
                continue
            label, value = stripped.split(":", 1)
            label = label.casefold()
            value = value.strip().replace("(Preferred)", "").replace("(Tentative)", "").strip()
            if "ipv4 address" in label or "autoconfiguration ipv4 address" in label:
                candidate = value.split("%", 1)[0].strip()
                try:
                    pending_ip = str(ipaddress.IPv4Address(candidate))
                except Exception:
                    pending_ip = None
            elif "subnet mask" in label and pending_ip:
                try:
                    net = ipaddress.IPv4Network((pending_ip, value), strict=False)
                    cidr = f"{pending_ip}/{net.prefixlen}"
                    inventory[self._ipv4_cache_key(current)] = cidr
                except Exception:
                    pass
                pending_ip = None

        with self._ipv4_resolution_lock:
            self._ipconfig_ipv4_inventory = dict(inventory)
        if inventory:
            self.logger.log_message(
                f"[Sniffer] Cached one-time ipconfig IPv4 inventory for {len(inventory)} interface(s)."
            )
        return inventory

    def _ipv4_cidr_from_ipconfig_once(self, iface_name: str) -> str | None:
        inventory = self._load_ipconfig_ipv4_inventory_once()
        wanted = self._ipv4_cache_key(iface_name)
        if wanted in inventory:
            return inventory[wanted]

        # Match aliases from router interface metadata against ipconfig headings.
        try:
            cfgs = getattr(self, "_interfaces_config", {}) or {}
            cfg = cfgs.get(iface_name, {}) or {}
            aliases = {
                wanted,
                self._ipv4_cache_key(cfg.get("friendly_name")),
                self._ipv4_cache_key(cfg.get("name")),
                self._ipv4_cache_key(cfg.get("win_name")),
            }
            aliases.discard("")
            for alias in aliases:
                if alias in inventory:
                    return inventory[alias]
        except Exception:
            pass

        # Conservative partial match for exact adapter names with decorations.
        for name_key, cidr in inventory.items():
            if wanted and (wanted in name_key or name_key in wanted):
                return cidr
        return None

    @staticmethod
    def _looks_like_virtual_ipv4_iface(iface_name: str) -> bool:
        name = str(iface_name or "").casefold()
        hints = (
            "windivert", "wintun", "nate's tunnel", "nates tunnel",
            "wireshark", "wire shark", "vethernet", "virtual ethernet",
            "hyper-v", "hyperv", "tunnel", "bridge",
        )
        return any(h in name for h in hints)

    def _synthesize_ipv4_cidr_for_iface(self, iface_name: str) -> str | None:
        """
        Give logical bridge/tunnel names a stable router-side IPv4 identity.

        Preference is to inherit the configured downstream RFC1918 LAN address;
        only when no downstream address exists do we allocate a deterministic
        metadata-only RFC1918 /24.  The value is persisted in _interfaces_config
        and the runtime cache so every later caller receives the same CIDR.
        """
        if not self._looks_like_virtual_ipv4_iface(iface_name):
            return None

        cfgs = getattr(self, "_interfaces_config", {}) or {}
        candidates = []
        for full_name, cfg in cfgs.items():
            if not isinstance(cfg, dict):
                continue
            if self._ipv4_cache_key(full_name) == self._ipv4_cache_key(iface_name):
                continue
            ip_s = str(cfg.get("ip_addr") or "").strip()
            mask_s = str(cfg.get("netmask") or "").strip()
            cidr_s = str(cfg.get("cidr") or "").strip()
            try:
                if cidr_s:
                    iv = ipaddress.IPv4Interface(cidr_s)
                elif ip_s and mask_s:
                    net = ipaddress.IPv4Network((ip_s, mask_s), strict=False)
                    iv = ipaddress.IPv4Interface(f"{ip_s}/{net.prefixlen}")
                else:
                    continue
                if iv.ip.is_private and not iv.ip.is_link_local and not iv.ip.is_loopback:
                    friendly = str(cfg.get("friendly_name") or full_name).casefold()
                    score = 0
                    if "ethernet" in friendly or "lan" in friendly:
                        score += 3
                    if not cfg.get("synthetic_ipv4"):
                        score += 2
                    candidates.append((score, f"{iv.ip}/{iv.network.prefixlen}"))
            except Exception:
                continue

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]

        # Deterministic fallback in 192.168.240.0/20. It is metadata for logical
        # interfaces, not an instruction to reconfigure a Windows NIC.
        digest = hashlib.sha256(str(iface_name).encode("utf-8", "ignore")).digest()
        third = 240 + (digest[0] % 15)
        return f"192.168.{third}.1/24"

    def _ipv4_cidr_for_iface(self, iface_name: str) -> str | None:
        if not iface_name:
            return None
        try:
            normalized = self._normalize_pcap_name(iface_name)
        except Exception:
            normalized = str(iface_name)

        key = self._ipv4_cache_key(normalized)
        with self._ipv4_resolution_lock:
            cached = self._ipv4_cidr_cache.get(key)
        if cached:
            return cached

        cidr = self._discover_ipv4_cidr_for_iface_uncached(normalized)
        source = "scapy/psutil/config"
        if not cidr:
            cidr = self._ipv4_cidr_from_ipconfig_once(normalized)
            source = "ipconfig-once"
        if not cidr:
            cidr = self._synthesize_ipv4_cidr_for_iface(normalized)
            source = "synthetic-virtual"

        if cidr:
            remembered = self._remember_ipv4_cidr(normalized, cidr, source=source)
            if source == "synthetic-virtual" and remembered:
                self.logger.log_message(
                    f"[Sniffer] 🧩 Saved synthesized IPv4 CIDR {remembered} for logical iface '{normalized}'."
                )
            return remembered
        return None

    def _discover_ipv4_cidr_for_iface_uncached(self, iface_name: str) -> str | None:
        """
        Return 'A.B.C.D/pfx' for the interface.
        Supports Windows Npcap names ('\\Device\\NPF_{GUID}') and friendly names.
        Returns None only if no usable IPv4 can be derived.
        """
        if not iface_name:
            return None

        try:
            iface_name = self._normalize_pcap_name(iface_name)
        except Exception:
            iface_name = str(iface_name)

        # Synthetic loopback CIDR so callers do not explode
        try:
            if os.name == "nt" and self._is_npf_loopback(iface_name):
                return "127.0.0.1/8"
        except Exception:
            pass

        # ---------------------------------------------------------
        # 1) FIRST: trust our own cached interface config
        # ---------------------------------------------------------
        try:
            cfg = (getattr(self, "_interfaces_config", {}) or {}).get(iface_name, {}) or {}

            cidr = cfg.get("cidr")
            if cidr:
                return str(cidr)

            net = cfg.get("network")
            if net is not None:
                try:
                    return str(net)
                except Exception:
                    pass

            ip_addr = cfg.get("ip_addr")
            netmask = cfg.get("netmask")
            if ip_addr and netmask:
                try:
                    pref = ipaddress.IPv4Network((str(ip_addr), str(netmask)), strict=False).prefixlen
                    return f"{ip_addr}/{pref}"
                except Exception:
                    pass
        except Exception:
            pass

        # ---------------------------------------------------------
        # 2) Windows Npcap device lookup
        # ---------------------------------------------------------
        if os.name == "nt" and iface_name.lower().startswith("\\device\\npf_"):
            try:
                if 'get_windows_if_list' in globals() and get_windows_if_list:
                    for itf in get_windows_if_list():
                        if itf.get("pcap_name") == iface_name:
                            ips = (itf.get("ips") or [])
                            masks = (itf.get("netmasks") or [])

                            for ip, m in zip(ips, masks):
                                if ip and m and "." in str(ip):
                                    try:
                                        pref = ipaddress.IPv4Network((str(ip), str(m)), strict=False).prefixlen
                                        return f"{ip}/{pref}"
                                    except Exception:
                                        continue

                            ip = itf.get("ip")
                            m = itf.get("netmask")
                            if ip and m and "." in str(ip):
                                try:
                                    pref = ipaddress.IPv4Network((str(ip), str(m)), strict=False).prefixlen
                                    return f"{ip}/{pref}"
                                except Exception:
                                    pass
            except Exception:
                pass

            # MAC -> psutil NIC fallback
            try:
                cidr = self._ipv4_cidr_via_mac_match(iface_name)
                if cidr:
                    return cidr
            except Exception:
                pass

        # ---------------------------------------------------------
        # 3) Friendly-name / partial-name psutil fallback
        # ---------------------------------------------------------
        try:
            addr, mask = self._ipv4_addr_netmask_for_iface(iface_name)
            if addr and mask:
                pref = ipaddress.IPv4Network((str(addr), str(mask)), strict=False).prefixlen
                return f"{addr}/{pref}"
        except Exception:
            pass

        # ---------------------------------------------------------
        # 4) Final fallback: try matching friendly_name from config
        # ---------------------------------------------------------
        try:
            for full_name, cfg in (getattr(self, "_interfaces_config", {}) or {}).items():
                if full_name == iface_name:
                    continue

                friendly = str((cfg or {}).get("friendly_name") or "").strip()
                if not friendly:
                    continue

                if friendly.lower() == iface_name.lower():
                    ip_addr = (cfg or {}).get("ip_addr")
                    netmask = (cfg or {}).get("netmask")
                    if ip_addr and netmask:
                        pref = ipaddress.IPv4Network((str(ip_addr), str(netmask)), strict=False).prefixlen
                        return f"{ip_addr}/{pref}"

                    net = (cfg or {}).get("network")
                    if net is not None:
                        return str(net)
        except Exception:
            pass

        return None

    def _ipv4_cidr_for_pcap_name(self, pcap_name: str) -> str | None:
        """
        Use scapy's Windows interface inventory to resolve a Npcap device to IPv4+mask.
        """
        try:
            from scapy.arch.windows import get_windows_if_list
            for itf in get_windows_if_list():
                # scapy exposes 'pcap_name' exactly like '\\Device\\NPF_{GUID}'
                if itf.get("pcap_name") == pcap_name:
                    ips = itf.get("ips", []) or []
                    masks = itf.get("netmasks", []) or []
                    for ip, m in zip(ips, masks):
                        if ip and m and "." in ip:
                            pref = ipaddress.IPv4Network((ip, m), strict=False).prefixlen
                            return f"{ip}/{pref}"
                    # some builds expose only one IPv4/mask as 'ip'/'netmask'
                    ip = itf.get("ip")
                    m = itf.get("netmask")
                    if ip and m and "." in ip:
                        pref = ipaddress.IPv4Network((ip, m), strict=False).prefixlen
                        return f"{ip}/{pref}"
            return None
        except Exception:
            return None

    def _ipv4_cidr_via_mac_match(self, pcap_name: str) -> str | None:
        """
        Fallback: get MAC for the Npcap device, find the psutil NIC with same MAC,
        then compute IPv4/prefix from that NIC.
        """
        try:
            # scapy gets the L2 addr even for Npcap device names
            mac = get_if_hwaddr(pcap_name)
        except Exception:
            mac = None

        if not mac:
            return None

        mac_norm = mac.replace("-", ":").lower()
        for nic, addrs in psutil.net_if_addrs().items():
            nic_mac = None
            for a in addrs:
                if getattr(a, "family", None) == psutil.AF_LINK:
                    nic_mac = (a.address or "").replace("-", ":").lower()
                    break
            if nic_mac and nic_mac == mac_norm:
                # get IPv4 and netmask
                for a in addrs:
                    if a.family == socket.AF_INET and a.address and a.netmask:
                        try:
                            pref = ipaddress.IPv4Network((a.address, a.netmask), strict=False).prefixlen
                            return f"{a.address}/{pref}"
                        except Exception:
                            pass
        return None

    def _ipv4_addr_netmask_for_iface(self, iface_name: str):
        """
        Existing helper (kept) – returns (addr, netmask) for friendly name;
        tries exact match then partial.
        """
        addrs = psutil.net_if_addrs().get(iface_name)
        if addrs is None:
            for nic, lst in psutil.net_if_addrs().items():
                if iface_name.lower() in nic.lower():
                    addrs = lst
                    break
        if not addrs:
            return None, None
        for a in addrs:
            if a.family == socket.AF_INET and a.address and a.netmask:
                return a.address, a.netmask
        return None, None

    def _coerce_to_l3(self, pkt):
        """
        Best-effort: return an IP/IPv6 layer from various inputs or (None, reason).
        Accepts Ether(with VLAN/SNAP), raw bytes, or already-formed IP/IPv6.
        """

        # Already L3?
        if isinstance(pkt, (IP, IPv6)):
            return pkt, None

        # Full Ethernet frame?
        if isinstance(pkt, Ether):
            # Handle optional VLAN tag(s)
            p = pkt
            # peel Dot1Q stack if present
            while p.payload and isinstance(p.payload, Dot1Q):
                p = p.payload
            # now p.payload is after the last Dot1Q
            inner = p.payload
            if isinstance(inner, (IP, IPv6)):
                return inner, None
            return None, f"Ethernet payload is not IP/IPv6 (got {type(inner).__name__})."

        # Any Scapy packet—try to find an IP/IPv6 layer
        try:
            if hasattr(pkt, "haslayer"):
                if pkt.haslayer(IP):
                    return pkt[IP], None
                if pkt.haslayer(IPv6):
                    return pkt[IPv6], None
        except Exception:
            pass

        # Raw bytes? Try to guess by version nibble
        if isinstance(pkt, (bytes, bytearray)):
            b0 = pkt[0] if pkt else 0
            ver = (b0 >> 4) & 0xF
            try:
                if ver == 4:
                    from scapy.layers.inet import IP as _IP
                    return _IP(pkt), None
                if ver == 6:
                    from scapy.layers.inet6 import IPv6 as _IPv6
                    return _IPv6(pkt), None
            except Exception as e:
                return None, f"Failed to parse raw bytes as IPv{ver}: {e}"

            return None, "Raw bytes do not look like an IPv4/IPv6 header."

        # Unknown shape
        tname = type(pkt).__name__
        return None, f"Unsupported packet type for sr1: {tname}. Expected IP/IPv6, Ether, or raw bytes."

    def _multicast_mac_for(self, ip_str: str) -> str:
        """IPv4: 01:00:5e:0x:xx:xx (lower 23 bits). IPv6: 33:33:xx:xx:xx:xx (lower 32 bits)."""
        x = ipaddress.ip_address(ip_str)
        b = x.packed
        if x.version == 4:
            return "01:00:5e:%02x:%02x:%02x" % (b[1] & 0x7F, b[2], b[3])
        else:
            return "33:33:%02x:%02x:%02x:%02x" % (b[12], b[13], b[14], b[15])


    def _log_route_once(self, key: str, message: str, every: float = 5.0) -> None:
        now = time.monotonic()
        previous = float(self._builtin_route_log_ts.get(key, 0.0) or 0.0)
        if now - previous < max(0.1, float(every)):
            return
        self._builtin_route_log_ts[key] = now
        self.logger.log_message(message)

    def _builtin_find_route(self, packet: Packet, preferred_iface: str | None = None) -> dict | None:
        """Resolve a route without requiring RIP, including IPv4/IPv6 multicast."""
        dst = self._ip_object(getattr(packet, "dst", ""))
        if dst is None:
            return None
        family = dst.version
        destination = str(dst)
        preferred = self._resolve_pcap_iface_alias(preferred_iface) or ""
        cache_key = (family, destination, preferred.casefold())
        now = time.monotonic()

        with self._builtin_route_lock:
            cached = self._builtin_route_cache.get(cache_key)
            if cached and (now - float(cached.get("cached_at", 0.0))) <= self._builtin_route_cache_ttl_sec:
                return dict(cached)

        os_route = self._scapy_route_for_destination(destination, family)
        route_iface = preferred or (os_route or {}).get("interface") or ""
        iface_out = self._pick_pcap_iface_for_dst(destination, preferred_iface=route_iface)
        if not iface_out:
            return None

        source_ip = ""
        if os_route and self._resolve_pcap_iface_alias(os_route.get("interface")) == self._resolve_pcap_iface_alias(iface_out):
            candidate = self._ip_object(os_route.get("source_ip"))
            if candidate is not None and candidate.version == family and not candidate.is_unspecified:
                source_ip = str(candidate)
        if not source_ip:
            source_ip = self._source_ip_for_iface(iface_out, family, destination) or ""

        next_hop = destination
        if not dst.is_multicast and os_route:
            candidate = self._ip_object(os_route.get("next_hop"))
            if candidate is not None and candidate.version == family and not candidate.is_unspecified:
                next_hop = str(candidate)

        row = self._inventory_row_for_iface(iface_out) or {}
        route = {
            "interface": self._resolve_pcap_iface_alias(iface_out) or iface_out,
            "next_hop": next_hop,
            "source_ip": source_ip,
            "family": family,
            "destination": destination,
            "is_multicast": bool(dst.is_multicast),
            "is_link_local_multicast": bool(
                family == 6 and dst.is_multicast and int(dst.packed[1] & 0x0F) <= 2
            ),
            "scope_id": int(row.get("index") or 0),
            "dst_mac": self._multicast_mac_for(destination) if dst.is_multicast else "",
            "route_source": "builtin-multicast" if dst.is_multicast else "builtin-default",
            "cached_at": now,
        }
        with self._builtin_route_lock:
            self._builtin_route_cache[cache_key] = dict(route)
            if len(self._builtin_route_cache) > 256:
                oldest = min(self._builtin_route_cache, key=lambda k: self._builtin_route_cache[k].get("cached_at", 0.0))
                self._builtin_route_cache.pop(oldest, None)

        self._log_route_once(
            f"{family}:{destination}:{route['interface']}",
            f"[Sniffer] Built-in IPv{family} route: {destination} -> {route['interface']} "
            f"src={source_ip or '-'} next_hop={next_hop} multicast={int(dst.is_multicast)}",
            every=10.0,
        )
        return route

    def _normalize_route_info(self, route_info: dict, packet: Packet, preferred_iface: str | None = None) -> dict | None:
        if not isinstance(route_info, dict):
            return None
        dst = self._ip_object(getattr(packet, "dst", ""))
        if dst is None:
            return None
        route = dict(route_info)
        iface = preferred_iface or route.get("interface") or route.get("iface")
        iface = self._resolve_pcap_iface_alias(iface)
        if not iface:
            return None
        route["interface"] = iface
        route["destination"] = str(dst)
        route["family"] = dst.version
        route["is_multicast"] = bool(dst.is_multicast)
        route["is_link_local_multicast"] = bool(
            dst.version == 6 and dst.is_multicast and int(dst.packed[1] & 0x0F) <= 2
        )
        next_hop = self._ip_object(route.get("next_hop"))
        if dst.is_multicast or next_hop is None or next_hop.version != dst.version or next_hop.is_unspecified:
            route["next_hop"] = str(dst)
        else:
            route["next_hop"] = str(next_hop)
        source = self._ip_object(route.get("source_ip"))
        if source is None or source.version != dst.version or source.is_unspecified:
            route["source_ip"] = self._source_ip_for_iface(iface, dst.version, str(dst)) or ""
        else:
            route["source_ip"] = str(source)
        row = self._inventory_row_for_iface(iface) or {}
        route["scope_id"] = int(route.get("scope_id") or row.get("index") or 0)
        if dst.is_multicast:
            route["dst_mac"] = self._multicast_mac_for(str(dst))
        route.setdefault("route_source", "external")
        return route

    def _resolve_route_info(self, packet: Packet, iface: str | None = None,
                            route_info: dict | None = None) -> dict | None:
        dst = self._ip_object(getattr(packet, "dst", ""))
        if dst is None:
            return None

        # Multicast is always on-link.  Do not wait for RIP to learn it.
        if dst.is_multicast:
            route = self._builtin_find_route(packet, preferred_iface=iface)
            if route:
                return route

        if route_info:
            route = self._normalize_route_info(route_info, packet, preferred_iface=iface)
            if route:
                return route

        try:
            rip_route = self.rip_manager.find_route(str(dst)) if self.rip_manager is not None else None
        except Exception:
            rip_route = None
        if rip_route:
            route = self._normalize_route_info(rip_route, packet, preferred_iface=iface)
            if route:
                return route

        return self._builtin_find_route(packet, preferred_iface=iface)

    def _invalidate_packet_checksums(self, packet: Packet) -> None:
        for layer_cls, fields in ((IP, ("len", "chksum")), (IPv6, ("plen",)),
                                  (UDP, ("len", "chksum")), (TCP, ("chksum",)),
                                  (ICMP, ("chksum",))):
            try:
                layer = packet.getlayer(layer_cls)
                if layer is None:
                    continue
                for field_name in fields:
                    if hasattr(layer, field_name):
                        setattr(layer, field_name, None)
            except Exception:
                pass

    def _apply_route_source(self, packet: Packet, route: dict) -> None:
        source_ip = str(route.get("source_ip") or "").strip()
        if not source_ip:
            return
        try:
            if isinstance(packet, IP):
                if str(getattr(packet, "src", "") or "") in {"", "0.0.0.0"}:
                    packet.src = source_ip
                    self._invalidate_packet_checksums(packet)
            elif isinstance(packet, IPv6):
                if str(getattr(packet, "src", "") or "") in {"", "::"}:
                    packet.src = source_ip
                    self._invalidate_packet_checksums(packet)
        except Exception:
            pass

    def _ipv6_neighbor_mac_from_windows(self, next_hop: str, iface_name: str = "") -> str | None:
        if os.name != "nt":
            return None
        commands = []
        friendly = ""
        row = self._inventory_row_for_iface(iface_name) or {}
        friendly = str(row.get("friendly") or "")
        if friendly:
            commands.append(["netsh", "interface", "ipv6", "show", "neighbors", f"interface={friendly}"])
        commands.append(["netsh", "interface", "ipv6", "show", "neighbors"])
        target = self._strip_ipv6_zone(next_hop).lower()
        for command in commands:
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=2.0,
                                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                for line in (proc.stdout or "").splitlines():
                    if target not in line.lower():
                        continue
                    for token in line.replace("-", ":").split():
                        parts = token.split(":")
                        if len(parts) == 6 and all(len(x) == 2 for x in parts):
                            return token.lower()
            except Exception:
                continue
        return None

    def _resolve_ipv6_neighbor_mac(self, next_hop: str, iface_name: str) -> str | None:
        obj = self._ip_object(next_hop)
        if obj is None or obj.version != 6:
            return None
        if obj.is_multicast:
            return self._multicast_mac_for(str(obj))
        mac = self._ipv6_neighbor_mac_from_windows(str(obj), iface_name)
        if mac:
            return mac
        try:
            from scapy.layers.inet6 import getmacbyip6
            return getmacbyip6(str(obj))
        except Exception:
            return None

    def _build_l2_route_frame(self, packet: Packet, route: dict,
                              dst_mac: str | None = None, src_mac: str | None = None):
        iface_out = self._resolve_pcap_iface_alias(route.get("interface"))
        if not iface_out:
            raise RuntimeError("route has no usable interface")
        route["interface"] = iface_out
        self._apply_route_source(packet, route)

        dst = self._ip_object(getattr(packet, "dst", ""))
        if dst is None:
            raise RuntimeError("packet has no valid destination")
        next_hop = str(route.get("next_hop") or dst)

        resolved_src_mac = src_mac
        if not resolved_src_mac:
            resolved_src_mac = get_if_hwaddr(iface_out)
        if not resolved_src_mac or resolved_src_mac == "00:00:00:00:00:00":
            raise RuntimeError(f"interface has no MAC address: {iface_out}")

        resolved_dst_mac = dst_mac or str(route.get("dst_mac") or "")
        if not resolved_dst_mac and dst.is_multicast:
            resolved_dst_mac = self._multicast_mac_for(str(dst))

        iface_cidr = None
        if dst.version == 4:
            iface_cidr = self._ipv4_cidr_for_iface(iface_out)
            if not iface_cidr:
                raise RuntimeError(f"could not derive IPv4 CIDR for iface '{iface_out}'")
            if not resolved_dst_mac:
                target = self._ip_object(next_hop)
                if target is None or target.version != 4:
                    target = dst
                resolved_dst_mac = self.arp_manager.resolve_gateway_mac(
                    str(target), iface=iface_out, iface_cidr=iface_cidr
                )
                if not resolved_dst_mac:
                    resolved_dst_mac = getmacbyip(str(target))
        else:
            if not resolved_dst_mac:
                resolved_dst_mac = self._resolve_ipv6_neighbor_mac(next_hop, iface_out)

        if not resolved_dst_mac:
            raise RuntimeError(f"could not resolve destination MAC for IPv{dst.version} next-hop {next_hop}")

        frame = Ether(src=resolved_src_mac, dst=resolved_dst_mac) / packet
        return iface_out, iface_cidr, resolved_src_mac, resolved_dst_mac, frame

    def _build_reply_bpf(self, packet: Packet, route: dict) -> str:
        dst = self._ip_object(getattr(packet, "dst", ""))
        family = 6 if isinstance(packet, IPv6) else 4
        prefix = "ip6" if family == 6 else "ip"
        source = self._ip_object(getattr(packet, "src", ""))
        is_multicast = bool(dst and dst.is_multicast)

        if UDP in packet:
            sport = int(getattr(packet[UDP], "sport", 0) or 0)
            dport = int(getattr(packet[UDP], "dport", 0) or 0)
            terms = [prefix, "udp"]
            if sport:
                terms.append(f"dst port {sport}")
            if source is not None and not source.is_unspecified:
                terms.append(f"dst host {source}")
            if not is_multicast:
                if dst is not None:
                    terms.append(f"src host {dst}")
                if dport:
                    terms.append(f"src port {dport}")
            return " and ".join(terms)

        if TCP in packet:
            sport = int(getattr(packet[TCP], "sport", 0) or 0)
            dport = int(getattr(packet[TCP], "dport", 0) or 0)
            terms = [prefix, "tcp"]
            if sport:
                terms.append(f"dst port {sport}")
            if dport:
                terms.append(f"src port {dport}")
            if source is not None and not source.is_unspecified:
                terms.append(f"dst host {source}")
            if dst is not None and not is_multicast:
                terms.append(f"src host {dst}")
            return " and ".join(terms)

        proto = "icmp6" if family == 6 else "icmp"
        terms = [prefix, proto]
        if source is not None and not source.is_unspecified:
            terms.append(f"dst host {source}")
        return " and ".join(terms)

    def _is_iface_recovery_error(self, err_text: str) -> bool:
        s = str(err_text or "").strip().lower()
        if not s:
            return False

        needles = (
            "not found",
            "no such device",
            "invalid handle",
            "the handle is invalid",
            "device removed",
            "adapter was removed",
            "network adapter has been removed",
            "interface disappeared",
            "error_device_removed",
            "status_device_removed",
            "filename, directory name, or volume label syntax is incorrect",
            "could not derive ipv4 cidr",
            "no usable ipv4 cidr",
            "interface has no mac address",
            "could not get hardware address",
        )
        if any(n in s for n in needles):
            return True

        try:
            return self._looks_like_removed_iface_error(s)
        except Exception:
            return False

    def _recover_send_iface(self, failed_iface: str, packet: Packet) -> str | None:
        failed = self._normalize_pcap_name(self._resolve_pcap_iface_alias(failed_iface) or failed_iface)
        dst = str(getattr(packet, "dst", "") or "")

        for candidate in self._iter_reopen_candidates(failed_iface):
            if candidate.casefold() != failed.casefold() and self._iface_is_known_up(candidate):
                return candidate

        candidate = self._pick_pcap_iface_for_dst(dst, preferred_iface=None) if dst else None
        if candidate and candidate.casefold() != failed.casefold():
            return candidate

        with contextlib.suppress(Exception):
            candidate = self._resolve_pcap_iface_alias(self.outbound_manager.get_next_interface(packet))
            if candidate and candidate.casefold() != failed.casefold() and self._iface_is_known_up(candidate):
                return candidate
        return None

    def _recover_sr1_iface(self, failed_iface: str, packet: Packet) -> str | None:
        return self._recover_send_iface(failed_iface, packet)

    def _build_pcap_alias_map(self):
        """Build case-insensitive alias -> canonical Npcap maps."""
        now = time.monotonic()
        with self._pcap_alias_lock:
            if self._pcap_alias_cache[0] and (
                now - self._pcap_alias_cache_at <= self._pcap_alias_cache_ttl_sec
            ):
                return self._pcap_alias_cache

        alias_to_pcap = {}
        pcap_to_row = {}

        def add_row(row: dict):
            pcap_name = self._pcap_name_from_windows_row(row)
            if not pcap_name:
                return
            pcap_name = self._normalize_pcap_name(pcap_name)
            pcap_to_row[pcap_name] = row
            for alias in self._aliases_from_windows_row(row) | {pcap_name}:
                normalized = self._normalize_pcap_name(alias)
                if not normalized:
                    continue
                alias_to_pcap[normalized] = pcap_name
                alias_to_pcap[normalized.casefold()] = pcap_name

        with contextlib.suppress(Exception):
            for row in get_windows_if_list():
                add_row(row)

        # Scapy's conf.ifaces sometimes knows the Npcap path before
        # get_windows_if_list() exposes the same adapter.
        with contextlib.suppress(Exception):
            values = conf.ifaces.values() if hasattr(conf.ifaces, "values") else []
            for iface_obj in values:
                row = {
                    "pcap_name": getattr(iface_obj, "pcap_name", None),
                    "network_name": getattr(iface_obj, "network_name", None),
                    "name": getattr(iface_obj, "name", None),
                    "win_name": getattr(iface_obj, "win_name", None),
                    "description": getattr(iface_obj, "description", None),
                    "guid": getattr(iface_obj, "guid", None),
                }
                add_row(row)

        with self._pcap_alias_lock:
            self._pcap_alias_cache = (alias_to_pcap, pcap_to_row)
            self._pcap_alias_cache_at = now
        return alias_to_pcap, pcap_to_row

    def _friendly_name_for_pcap_iface(self, iface: str) -> str | None:
        row = self._inventory_row_for_iface(iface)
        if row and row.get("friendly"):
            return str(row["friendly"])

        wanted = self._normalize_pcap_name(iface).casefold()
        with contextlib.suppress(Exception):
            for cfg_name, cfg in (getattr(self, "_interfaces_config", {}) or {}).items():
                cfg = cfg or {}
                aliases = {
                    self._normalize_pcap_name(cfg_name).casefold(),
                    self._normalize_pcap_name(cfg.get("pcap_name")).casefold(),
                    self._normalize_pcap_name(cfg.get("full_name")).casefold(),
                    self._normalize_pcap_name(cfg.get("guid")).casefold(),
                }
                if wanted in aliases:
                    for key in ("friendly_name", "win_name", "name", "description"):
                        value = str(cfg.get(key) or "").strip()
                        if value:
                            return value
        return None

    def _adapter_looks_up(self, friendly_name: str) -> bool:
        """
        Best-effort check whether the Windows adapter appears present/up.
        """
        if not friendly_name:
            return False

        try:
            stats = psutil.net_if_stats()
            for nic, st in stats.items():
                if nic.strip().lower() == friendly_name.strip().lower():
                    return bool(st.isup)
        except Exception:
            pass

        return False

    def _maybe_reenable_adapter(self, friendly_name: str, read_label: str = "Sniffer") -> bool:
        """
        Best-effort attempt to re-enable a Windows adapter.
        Requires admin privileges.
        Returns True if the adapter appears up afterward.
        """
        if not friendly_name:
            return False

        subprocess_mod = __import__("subprocess")
        ps_name = friendly_name.replace("'", "''")
        netsh_name_arg = f"name={friendly_name}"

        def _run(cmd):
            try:
                return subprocess_mod.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=getattr(subprocess_mod, "CREATE_NO_WINDOW", 0),
                )
            except Exception:
                return None

        def _wait_up(seconds: float = 2.5, step: float = 0.25) -> bool:
            deadline = time.time() + seconds
            while time.time() < deadline:
                if self._adapter_looks_up(friendly_name):
                    return True
                time.sleep(step)
            return self._adapter_looks_up(friendly_name)

        # 1) Try simple enable first
        enable_cmds = [
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                f"Enable-NetAdapter -Name '{ps_name}' -Confirm:$false",
            ],
            [
                "netsh",
                "interface",
                "set",
                "interface",
                netsh_name_arg,
                "admin=ENABLED",
            ],
        ]

        for cmd in enable_cmds:
            _run(cmd)
            if _wait_up():
                self.logger.log_message(
                    f"[{read_label}] 🟢 Adapter '{friendly_name}' is enabled/up."
                )
                return True

        # 2) Last resort: bounce the adapter (disable -> enable)
        bounce_cmds = [
            (
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command",
                    f"Disable-NetAdapter -Name '{ps_name}' -Confirm:$false",
                ],
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command",
                    f"Enable-NetAdapter -Name '{ps_name}' -Confirm:$false",
                ],
            ),
            (
                [
                    "netsh",
                    "interface",
                    "set",
                    "interface",
                    netsh_name_arg,
                    "admin=DISABLED",
                ],
                [
                    "netsh",
                    "interface",
                    "set",
                    "interface",
                    netsh_name_arg,
                    "admin=ENABLED",
                ],
            ),
        ]

        for disable_cmd, enable_cmd in bounce_cmds:
            _run(disable_cmd)
            time.sleep(1.0)
            _run(enable_cmd)

            if _wait_up(seconds=4.0):
                self.logger.log_message(
                    f"[{read_label}] 🔄 Adapter '{friendly_name}' was bounced and is back up."
                )
                return True

        return self._adapter_looks_up(friendly_name)

    def _recover_read_handle(self, *, handle, active_iface: str, promisc: bool,
                             timeout: int, bpf_filter: str | None,
                             read_label: str = "Sniffer"):
        """Close a stale capture handle and reopen the same adapter by canonical name."""
        with contextlib.suppress(Exception):
            if handle:
                self.libpcap.pcap_close(handle)
        time.sleep(0.15)

        failed_iface = self._normalize_pcap_name(active_iface)
        friendly = self._friendly_name_for_pcap_iface(failed_iface)
        if friendly and not self._adapter_looks_up(friendly):
            self.logger.log_message(
                f"[{read_label}] Adapter '{friendly}' is down; attempting to re-enable it before reopening."
            )
            self._maybe_reenable_adapter(friendly, read_label=read_label)
            time.sleep(0.5)

        self._invalidate_interface_caches()
        last_err = ""
        for candidate in self._iter_reopen_candidates(failed_iface):
            new_handle, err = self._open_pcap_handle(
                iface=candidate,
                promisc=promisc,
                timeout=int(timeout),
                bpf_filter=bpf_filter,
            )
            if new_handle:
                new_dlt = None
                with contextlib.suppress(Exception):
                    new_dlt = self.libpcap.pcap_datalink(new_handle)
                self.logger.log_message(
                    f"[{read_label}] Recovered capture on '{candidate}' "
                    f"datalink={new_dlt} ({self._dlt_name(new_dlt) if new_dlt is not None else 'unknown'})"
                )
                return new_handle, candidate, new_dlt, True, ""
            last_err = err or last_err

        self.logger.log_message(
            f"[{read_label}] Reopen failed for '{failed_iface}': {last_err or 'no valid Npcap candidate'}"
        )
        return None, failed_iface, None, False, last_err

    def _capture_meta_from_pkthdr(self, pkthdr_ptr):
        """
        Build capture metadata from libpcap's packet header.
        - captured_len: bytes actually captured into memory
        - wire_len: original on-the-wire packet length
        - capture_complete: True if we captured the whole packet
        """
        try:
            hdr = pkthdr_ptr.contents
            captured_len = int(getattr(hdr, "caplen", 0) or 0)
            wire_len = int(getattr(hdr, "len", captured_len) or captured_len)
        except Exception:
            return {
                "captured_len": 0,
                "wire_len": 0,
                "capture_complete": False,
                "capture_quality": "invalid_header",
                "truncated_bytes": 0,
            }

        capture_complete = (captured_len >= wire_len and wire_len > 0)
        truncated_bytes = max(0, wire_len - captured_len)

        return {
            "captured_len": captured_len,
            "wire_len": wire_len,
            "capture_complete": capture_complete,
            "capture_quality": "full" if capture_complete else "truncated",
            "truncated_bytes": truncated_bytes,
        }

    def _attach_capture_meta(self, packet, meta: dict, *, iface: str = None, dlt: int = None):
        """
        Attach capture metadata directly to the decoded Scapy packet.
        """
        try:
            setattr(packet, "_captured_len", int(meta.get("captured_len", 0) or 0))
            setattr(packet, "_wire_len", int(meta.get("wire_len", 0) or 0))
            setattr(packet, "_capture_complete", bool(meta.get("capture_complete", False)))
            setattr(packet, "_capture_quality", str(meta.get("capture_quality", "unknown")))
            setattr(packet, "_truncated_bytes", int(meta.get("truncated_bytes", 0) or 0))
            if iface is not None:
                setattr(packet, "_capture_iface", iface)
            if dlt is not None:
                setattr(packet, "_capture_dlt", dlt)
        except Exception:
            pass
        return packet

    def _decode_captured_packet(self, pkthdr_ptr, packet_data_ptr, dlt: int, *, iface: str = None,
                                warn_on_truncation: bool = True):
        """
        Safe helper for libpcap receive sites.
        """
        if not pkthdr_ptr or not pkthdr_ptr.contents:
            self.logger.log_message("[Sniffer] ERROR: Null packet header pointer.")
            return None, None

        meta = self._capture_meta_from_pkthdr(pkthdr_ptr)
        packet_len = int(meta["captured_len"])

        if packet_len <= 0:
            self.logger.log_message("[Sniffer] WARNING: Zero-length packet.")
            return None, meta

        raw_packet = ctypes.string_at(packet_data_ptr, packet_len)
        packet = self._decode_by_dlt(raw_packet, dlt)
        self._attach_capture_meta(packet, meta, iface=iface, dlt=dlt)

        if warn_on_truncation and not meta["capture_complete"]:
            self.logger.log_message(
                f"[Sniffer] ⚠️ Truncated capture on {iface or '?'}: "
                f"captured={meta['captured_len']} wire={meta['wire_len']} "
                f"lost={meta['truncated_bytes']} dlt={dlt} ({self._dlt_name(dlt)})"
            )

        return packet, meta
    def sniff(self, iface, prn, promisc=True, stop_filter=None, filter=None, timeout=100, mac_filter_only=False,
              session=None):
        """
        Live sniff loop that keeps going forever (unless stop_filter returns True).
        """
        if not isinstance(iface, str):
            sys.stderr.write(f"[Sniffer] Error: `iface` must be a string. Got type {type(iface)}.\n")
            return
        if prn and not callable(prn):
            sys.stderr.write(f"[Sniffer] Error: `prn` must be callable. Got type {type(prn)}.\n")
            return
        if stop_filter and not callable(stop_filter):
            sys.stderr.write(f"[Sniffer] Error: `stop_filter` must be callable. Got type {type(stop_filter)}.\n")
            return

        # Forever loop
        pkthdr_ptr = ctypes.POINTER(pcap_pkthdr)()
        packet_data_ptr = ctypes.POINTER(ctypes.c_ubyte)()

        def _open_on_candidates(target_iface: str):
            last_err = ""
            for candidate in self._iter_reopen_candidates(target_iface):
                h, err = self._open_pcap_handle(
                    iface=candidate,
                    promisc=promisc,
                    timeout=int(timeout),
                    bpf_filter=filter,
                )
                if h:
                    return h, candidate, ""
                last_err = err
            return None, target_iface, last_err

        handle, active_iface, open_err = _open_on_candidates(iface)
        if not handle:
            self.logger.log_message(
                f"[Sniffer] Error opening device {iface!r}: {open_err or 'no valid Npcap device found'}"
            )
            return
        dlt = self.libpcap.pcap_datalink(handle)
        self.logger.log_message(
            f"[Sniffer] capture iface={active_iface} datalink={dlt} ({self._dlt_name(dlt)})"
        )
        try:
            while True:
                if stop_filter and stop_filter(None): # Pass None since we don't have a packet yet
                    break
                ret = self.libpcap.pcap_next_ex(handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr))

                if ret == 0:
                    # read timeout; loop again
                    continue
                elif ret == -1:
                    err = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")

                    if self._looks_like_removed_iface_error(err):
                        self.logger.log_message(
                            f"[Sniffer] Interface removed on '{active_iface}'. Closing stale handle and attempting reopen."
                        )

                        handle, active_iface, dlt, recovered, reopen_err = self._recover_read_handle(
                            handle=handle,
                            active_iface=active_iface,
                            promisc=promisc,
                            timeout=int(timeout),
                            bpf_filter=filter,
                            read_label="Sniffer",
                        )

                        if not recovered or not handle:
                            return

                        continue

                    self.logger.log_message(f"[Sniffer] Error reading packet: {err}")
                    continue
                elif ret == -2:
                    # breakloop() or EOF - for live capture, just retry after a small pause
                    time.sleep(0.05)
                    continue

                packet, meta = self._decode_captured_packet(
                    pkthdr_ptr,
                    packet_data_ptr,
                    dlt,
                    iface=active_iface,
                    warn_on_truncation=True,
                )
                if packet is None:
                    continue

                packet_len = int(getattr(packet, "_captured_len", 0) or 0)
                wire_len = int(getattr(packet, "_wire_len", packet_len) or packet_len)
                capture_tag = "FULL" if getattr(packet, "_capture_complete", False) else "TRUNC"

                try:
                    try:
                        if packet.summary() not in self.logged_packets:
                            self.logger.log_message(
                                f"[Packet] iface={active_iface} caplen={packet_len} wire={wire_len} "
                                f"capture={capture_tag} | {packet.summary()}"
                            )
                            self.logged_packets.append(packet.summary())

                            if "Loopback" in active_iface:
                                processed_packet = session().process(pkt=packet, cls=None) if session else packet
                                try:
                                    if prn and processed_packet is not None:
                                        prn(processed_packet)
                                        continue
                                except Exception:
                                    pass
                    except Exception:
                        self.logger.log_message(
                            f"[Packet] iface={active_iface} caplen={packet_len} wire={wire_len} "
                            f"capture={capture_tag} | <decode error>"
                        )

                    try:
                        if stop_filter and stop_filter(packet):
                            break
                    except Exception:
                        pass

                    packet.sniffed_on = active_iface

                    if mac_filter_only and not packet.haslayer(Ether):
                        continue

                    if packet.haslayer(Ether):
                        # ARP handling
                        if packet.haslayer(ARP):
                            if not self.arp_manager.perform_arp_inspection(packet, active_iface):
                                continue
                            arp_op = packet[ARP].op
                            if arp_op == 2:
                                self.arp_manager.learn_arp_response(packet)
                            elif arp_op == 1:
                                try:
                                    self.arp_manager.reply_to_arp_request(packet, active_iface)
                                except Exception as e:
                                    if self.notification_manager:
                                        self.notification_manager.send_notification({
                                            "event": "ARP Reply Failure",
                                            "message": f"Failed to reply to ARP from {packet[ARP].psrc} on {iface}: {e}",
                                            "iface": iface,
                                            "timestamp": time.time(),
                                            "emojis": ["🛑", "🧩", "🐍"]
                                        }, cooldown_seconds=5, cooldown_key="arp_reply_fail")
                            else:
                                if self.notification_manager:
                                    self.notification_manager.send_notification({
                                        "event": "Unknown ARP Operation",
                                        "message": f"Received ARP with unknown op {arp_op} from {packet[ARP].psrc} on {iface}",
                                        "iface": iface,
                                        "timestamp": time.time(),
                                        "emojis": ["❓", "📛", "🕵️"]
                                    }, cooldown_seconds=10, cooldown_key="arp_unknown_op")
                            continue

                        # EtherType checks ONLY when Ether is present
                        eth_type = packet[Ether].type
                        if eth_type not in self.supported_ethertypes or eth_type in self.unsupported_ethertypes:
                            if self.notification_manager:
                                self.notification_manager.send_notification({
                                    "event": "Unsupported EtherType",
                                    "message": f"Dropped packet with unsupported EtherType {hex(eth_type)} from "
                                               f"{packet[Ether].src} → {packet[Ether].dst}.",
                                    "iface": iface, "timestamp": time.time(), "emojis": ["❌", "📦", "⚠️"]
                                }, cooldown_seconds=10, cooldown_key="ethertype_blocked")
                            continue

                        if eth_type == 0x86DD and not packet.haslayer(IPv6):
                            if self.notification_manager:
                                self.notification_manager.send_notification({
                                    "event": "IPv6 Parse Error",
                                    "message": f"Expected IPv6 layer not found. Packet length: {packet_len}",
                                    "iface": iface, "timestamp": time.time(), "emojis": ["⚠️", "📡", "❌"]
                                }, cooldown_seconds=10, cooldown_key="ipv6_blocked")
                            continue

                    # For non-Ether captures, check for L3 presence
                    if not (
                        packet.haslayer(Ether) or
                        packet.haslayer(IP) or
                        packet.haslayer(IPv6) or
                        packet.haslayer(ARP)
                    ):
                        continue
                    src_ip, dst_ip = None, None
                    if packet.haslayer(IP):
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                    elif packet.haslayer(IPv6):
                        src_ip = packet[IPv6].src
                        dst_ip = packet[IPv6].dst

                    if src_ip and (src_ip in self.banned_ips or dst_ip in self.banned_ips):
                        banned_ip = src_ip if src_ip in self.banned_ips else dst_ip
                        if self.notification_manager:
                            self.notification_manager.send_notification({
                                "event": "Sniffer Banned IP Detected",
                                "message": f"Packet on sniffer from {src_ip} to {dst_ip} dropped due to banned IP: {banned_ip}",
                                "iface": iface,
                                "timestamp": time.time(),
                                "emojis": ["🚫", "🧱", "🛑"]
                            }, cooldown_seconds=10, cooldown_key=f"banned_ip_{banned_ip}")
                        continue
                    if packet.haslayer(RIP) and packet.haslayer(IP) and packet.haslayer(UDP):
                        try:
                            original_ip = packet.getlayer(IP)
                            if original_ip.dst == self.rip_manager.RIP_MCAST_ADDR or original_ip.dst in self.local_ips:
                                self.rip_manager.handle_packet(packet, active_iface)
                            else:
                                if self.notification_manager:
                                    self.notification_manager.send_notification({
                                        "event": "RIP Blocked",
                                        "message": f"Dropped RIP packet from {original_ip.src} to {original_ip.dst} (not for this router)",
                                        "iface": iface, "timestamp": time.time(), "emojis": ["🚫", "🗺️", "🛑"]
                                    }, cooldown_seconds=20, cooldown_key="rip_blocked")
                        except Exception as e:
                            original_ip = packet.getlayer(IP)
                            self.rip_manager.rip_from_suspicious_source(original_ip.src, packet)
                            if self.notification_manager:
                                self.notification_manager.send_notification({
                                    "event": "RIP Unsolicited",
                                    "message": f"[Sniffer] ⚠️ Unsolicited RIP handling: {e}",
                                    "iface": iface, "timestamp": time.time(), "emojis": ["🚫", "🗺️", "🛑"]
                                }, cooldown_seconds=20, cooldown_key="rip_unsolicited")

                    processed_packet = session().process(pkt=packet, cls=None) if session else packet
                    try:
                        if prn and processed_packet is not None:
                            prn(session().process(pkt=packet, cls=None) if session else packet)
                    except Exception:
                        pass

                except Exception:
                    # Never let a malformed frame kill the loop
                    continue
        finally:
            if handle:
                self.libpcap.pcap_close(handle)

    def sendp(self, packet: Packet, iface: str, verbose: int = 0) -> bool:
        """Transmit an Ethernet frame with alias resolution and safe failover.

        A failed/disconnected adapter is put on an exponential cooldown so packet
        bursts do not produce thousands of identical Npcap errors.  When the frame
        contains IPv4/IPv6, a fallback adapter receives a freshly rebuilt Ethernet
        header instead of reusing the original adapter's MAC addresses.
        """
        requested = self._normalize_pcap_name(iface)
        canonical_requested = self._resolve_pcap_iface_alias(requested) or requested
        l3, _why = self._coerce_to_l3(packet)
        family = 6 if isinstance(l3, IPv6) else 4 if isinstance(l3, IP) else 0

        candidates = []
        seen = set()

        def add(value):
            resolved = self._resolve_pcap_iface_alias(value)
            if not resolved:
                return
            resolved = self._normalize_pcap_name(resolved)
            if os.name == "nt" and not self._is_probable_pcap_device(resolved):
                return
            key = resolved.casefold()
            if key in seen:
                return
            seen.add(key)
            candidates.append(resolved)

        add(canonical_requested)
        if l3 is not None:
            add(self._pick_pcap_iface_for_dst(str(l3.dst), preferred_iface=canonical_requested))
            add(self._recover_send_iface(canonical_requested, l3))
        with contextlib.suppress(Exception):
            add(self.outbound_manager.get_next_interface(l3 if l3 is not None else packet))
        if family in (4, 6):
            with self._send_state_lock:
                add(self._last_good_send_iface.get(family))

        # Last-resort active interfaces, ranked for this destination.
        if l3 is not None:
            ranked = sorted(
                self._iface_inventory(),
                key=lambda row: self._interface_score(
                    row, family, str(l3.dst), canonical_requested
                ),
                reverse=True,
            )
            for row in ranked[:4]:
                if self._interface_score(row, family, str(l3.dst), canonical_requested) > -100000:
                    add(row.get("pcap_name"))

        if not candidates:
            self._log_send_once(
                f"sendp:no-candidate:{requested.casefold()}",
                f"[Sniffer] sendp could not resolve {requested!r} to a valid Npcap device.",
            )
            return False

        last_error = ""
        attempted = []
        for candidate in candidates:
            if self._iface_on_send_cooldown(candidate):
                continue
            if not self._iface_is_known_up(candidate):
                self._mark_send_failure(candidate, "network media is disconnected")
                continue

            frame = packet
            if candidate.casefold() != self._normalize_pcap_name(canonical_requested).casefold() and l3 is not None:
                try:
                    route = self._builtin_find_route(l3, preferred_iface=candidate)
                    if not route:
                        continue
                    candidate, _, _, _, frame = self._build_l2_route_frame(l3.copy(), route)
                except Exception as exc:
                    last_error = str(exc)
                    self._mark_send_failure(candidate, last_error)
                    continue

            handle, open_error = self._open_pcap_handle(
                candidate, promisc=True, timeout=100, bpf_filter=None, for_send=True
            )
            attempted.append(candidate)
            if not handle:
                last_error = open_error or "pcap_open_live failed"
                self._mark_send_failure(candidate, last_error)
                continue

            try:
                packet_bytes = bytes(frame)
                result = self.libpcap.pcap_sendpacket(
                    handle,
                    (ctypes.c_ubyte * len(packet_bytes))(*packet_bytes),
                    len(packet_bytes),
                )
                if result != 0:
                    last_error = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
                    self._mark_send_failure(candidate, last_error)
                    continue

                self._mark_send_success(candidate, family)
                if verbose >= 1:
                    self.logger.log_message(f"[Sniffer] Sent frame on {candidate}: {frame.summary()}")
                return True
            finally:
                with contextlib.suppress(Exception):
                    self.libpcap.pcap_close(handle)

        if self.use_hyperv and self.hyperv_manager is not None:
            with contextlib.suppress(Exception):
                result = self.hyperv_manager.send_packet(bytes(l3 if l3 is not None else packet))
                if result is not False:
                    self._log_send_once(
                        "sendp:hyperv-fallback",
                        "[Sniffer] Npcap egress unavailable; packet handed to Hyper-V fallback.",
                        every=2.0,
                    )
                    return True

        attempted_text = ", ".join(attempted) if attempted else "none (all candidates cooling down/down)"
        self._log_send_once(
            f"sendp:failed:{requested.casefold()}:{last_error.casefold()}",
            f"[Sniffer] sendp failed for {requested!r}; attempted={attempted_text}; "
            f"last_error={last_error or 'no active adapter'}",
            every=5.0,
        )
        return False

    def send(self, packet: Packet, iface: str = None, verbose: int = 0, route_info: dict = None,
             dst_mac: str = None, src_mac: str = None):
        """Send IPv4/IPv6 with RIP first and a built-in dual-stack route fallback."""
        if not isinstance(packet, (IP, IPv6)):
            packet, why = self._coerce_to_l3(packet)
            if packet is None:
                self.logger.log_message(f"[Sniffer] send: could not obtain a Layer 3 packet. Hint: {why}")
                return False

        route = self._resolve_route_info(packet, iface=iface, route_info=route_info)
        if not route:
            self.logger.log_message(
                f"[Sniffer] Error: no RIP, OS, or built-in route for destination {getattr(packet, 'dst', '?')}"
            )
            return False

        iface_out = route.get("interface")
        if self._is_npf_loopback(iface_out) and self._dst_is_private_or_local(str(packet.dst)):
            self._send_l3_loopback(packet, expect_reply=False, iface=iface_out)
            return True

        try:
            iface_out, _, src_mac_eff, dst_mac_eff, l2_packet = self._build_l2_route_frame(
                packet, route, dst_mac=dst_mac, src_mac=src_mac
            )
            if verbose >= 1:
                self.logger.log_message(
                    f"[Sniffer] Route {packet.dst} via {route.get('next_hop')} on {iface_out}; "
                    f"Ether {src_mac_eff} -> {dst_mac_eff}; source={route.get('route_source')}"
                )
            if self.sendp(l2_packet, iface=iface_out, verbose=verbose):
                return True
        except Exception as first_error:
            if not self._is_iface_recovery_error(str(first_error)):
                self.logger.log_message(f"[Sniffer] Error preparing/sending packet: {first_error}")
                return False

            retry_iface = self._recover_send_iface(str(iface_out or ""), packet)
            if not retry_iface:
                self.logger.log_message(f"[Sniffer] Send recovery failed: {first_error}")
                return False
            retry_route = self._builtin_find_route(packet, preferred_iface=retry_iface)
            if not retry_route:
                self.logger.log_message(f"[Sniffer] No built-in recovery route through {retry_iface}")
                return False
            try:
                retry_iface, _, _, _, retry_frame = self._build_l2_route_frame(
                    packet, retry_route, dst_mac=dst_mac, src_mac=src_mac
                )
                return self.sendp(retry_frame, iface=retry_iface, verbose=verbose)
            except Exception as retry_error:
                self.logger.log_message(f"[Sniffer] Send recovery failed on {retry_iface}: {retry_error}")
                return False

        return False

    def sr1(self, packet: Packet, iface: str = None, timeout: int = 2, verbose: int = 0,
            route_info: dict = None, dst_mac: str = None, src_mac: str = None) -> Optional[Packet]:
        """Send one IPv4/IPv6 packet and receive one matching response."""
        if isinstance(packet, Ether) and (IP in packet or IPv6 in packet):
            packet = packet[IP] if IP in packet else packet[IPv6]
        if not isinstance(packet, (IP, IPv6)):
            packet, why = self._coerce_to_l3(packet)
            if packet is None:
                self.logger.log_message(f"[Sniffer] sr1: could not obtain Layer 3 packet: {why}")
                return None

        initial_route = self._resolve_route_info(packet, iface=iface, route_info=route_info)
        if not initial_route:
            self.logger.log_message(
                f"[Sniffer] Error: no RIP, OS, or built-in route for destination {getattr(packet, 'dst', '?')}"
            )
            return None

        initial_iface = self._resolve_pcap_iface_alias(initial_route.get("interface"))
        if self._is_npf_loopback(initial_iface) and self._dst_is_private_or_local(str(packet.dst)):
            return self._send_l3_loopback(packet, expect_reply=True, timeout=timeout, iface=initial_iface)

        candidates = []
        seen = set()

        def add(value):
            resolved = self._resolve_pcap_iface_alias(value)
            if not resolved:
                return
            resolved = self._normalize_pcap_name(resolved)
            if os.name == "nt" and not self._is_probable_pcap_device(resolved):
                return
            key = resolved.casefold()
            if key in seen:
                return
            seen.add(key)
            candidates.append(resolved)

        add(initial_iface)
        add(self._pick_pcap_iface_for_dst(str(packet.dst), preferred_iface=initial_iface))
        add(self._recover_sr1_iface(initial_iface or "", packet))

        last_error = ""
        for candidate in candidates:
            if self._iface_on_send_cooldown(candidate) or not self._iface_is_known_up(candidate):
                continue
            route = initial_route if candidate.casefold() == self._normalize_pcap_name(initial_iface).casefold() else None
            if route is None:
                route = self._builtin_find_route(packet, preferred_iface=candidate)
            if not route:
                continue

            try:
                iface_out, _, src_mac_eff, dst_mac_eff, l2_packet = self._build_l2_route_frame(
                    packet.copy(), route, dst_mac=dst_mac, src_mac=src_mac
                )
            except Exception as exc:
                last_error = str(exc)
                self._mark_send_failure(candidate, last_error)
                continue

            handle, open_error = self._open_pcap_handle(
                iface_out,
                promisc=True,
                timeout=max(1, int(float(timeout) * 1000)),
                bpf_filter=None,
                for_send=True,
            )
            if not handle:
                last_error = open_error
                self._mark_send_failure(iface_out, last_error)
                continue

            try:
                with contextlib.suppress(Exception):
                    self.libpcap.pcap_setdirection(handle, PCAP_D_IN)
                dlt = self.libpcap.pcap_datalink(handle)
                inner = self._build_reply_bpf(packet, route)
                supports_vlan = dlt not in (DLT_NULL, DLT_LOOP, DLT_RAW)
                expressions = [f"({inner}) or (vlan and {inner})", inner] if supports_vlan else [inner]

                compiled = False
                filter_error = ""
                for expression in expressions:
                    bpf = bpf_program()
                    if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), expression.encode("utf-8"), 1, 0) != 0:
                        filter_error = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
                        with contextlib.suppress(Exception):
                            self.libpcap.pcap_freecode(ctypes.byref(bpf))
                        continue
                    if self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) == 0:
                        compiled = True
                        with contextlib.suppress(Exception):
                            self.libpcap.pcap_freecode(ctypes.byref(bpf))
                        break
                    filter_error = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
                    with contextlib.suppress(Exception):
                        self.libpcap.pcap_freecode(ctypes.byref(bpf))

                if not compiled:
                    last_error = f"reply filter failed: {filter_error}"
                    self._mark_send_failure(iface_out, last_error)
                    continue

                packet_bytes = bytes(l2_packet)
                result = self.libpcap.pcap_sendpacket(
                    handle,
                    (ctypes.c_ubyte * len(packet_bytes))(*packet_bytes),
                    len(packet_bytes),
                )
                if result != 0:
                    last_error = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
                    self._mark_send_failure(iface_out, last_error)
                    continue

                self._mark_send_success(iface_out, 6 if isinstance(packet, IPv6) else 4)
                if verbose >= 1:
                    self.logger.log_message(
                        f"[Sniffer] sr1 sent {packet.dst} on {iface_out}; "
                        f"Ether {src_mac_eff} -> {dst_mac_eff}; filter={inner}"
                    )

                pkthdr_ptr = ctypes.POINTER(pcap_pkthdr)()
                packet_data_ptr = ctypes.POINTER(ctypes.c_ubyte)()
                deadline = time.monotonic() + max(0.05, float(timeout))
                while time.monotonic() < deadline:
                    ret = self.libpcap.pcap_next_ex(
                        handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr)
                    )
                    if ret == 1:
                        reply_packet, _meta = self._decode_captured_packet(
                            pkthdr_ptr, packet_data_ptr, dlt,
                            iface=iface_out, warn_on_truncation=True,
                        )
                        if reply_packet is not None:
                            return reply_packet
                    elif ret == 0:
                        continue
                    elif ret == -1:
                        last_error = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
                        self._mark_send_failure(iface_out, last_error)
                        break
                    elif ret == -2:
                        break
            finally:
                with contextlib.suppress(Exception):
                    self.libpcap.pcap_close(handle)

        if verbose >= 1:
            self.logger.log_message(
                f"[Sniffer] sr1 failed/timeout for {packet.dst}: {last_error or 'no usable interface'}"
            )
        return None

    def _iter_layers(self, pkt: Packet):
        """Yield each layer from outermost to innermost."""
        l = pkt
        while isinstance(l, Packet) and not isinstance(l.payload, NoPayload):
            yield l
            l = l.payload
        if isinstance(l, Packet):
            yield l

    def _match_layer(self, l: Packet, query: str) -> bool:
        """Case-insensitive match on class name or scapy 'name'."""
        q = (query or "").lower()
        return l.__class__.__name__.lower() == q or getattr(l, "name", "").lower() == q

    def _layer_to_string(self, layer: Packet, fmt: str = "show") -> str:
        """Render a single layer to string."""
        fmt = (fmt or "show").lower()
        if fmt == "summary":
            return layer.summary()
        if fmt == "fields":
            # key=value pairs for all declared fields
            parts = []
            for f in getattr(layer, "fields_desc", []):
                fname = getattr(f, "name", None)
                if not fname:
                    continue
                try:
                    val = getattr(layer, fname, None)
                except Exception:
                    val = None
                parts.append(f"{fname}={val!r}")
            return f"{layer.__class__.__name__}(" + ", ".join(parts) + ")"
        # default: full verbose dump
        try:
            return layer.show(dump=True)
        except Exception:
            return str(layer)

    def get_layer_as_string(self,
            pkt: Packet,
            layer: str | type[Packet] | int,
            *,
            fmt: str = "show",
            default: str = ""
    ) -> str:
        """
        Return the specified layer rendered as a string.

        layer:
          • class    -> e.g., IPv6, UDP, DNS
          • name str -> e.g., "IPv6", "ICMPv6ND_NS", "DNS", "Raw"
          • index    -> 0=outermost (Ether/RadioTap), 1=next, etc.

        fmt: "show" (verbose), "summary", or "fields".
        default: string to return if not found.
        """
        if pkt is None:
            return default

        # layer by index
        if isinstance(layer, int):
            for i, l in enumerate(self._iter_layers(pkt)):
                if i == layer:
                    return self._layer_to_string(l, fmt=fmt)
            return default

        # layer by class
        if isinstance(layer, type) and issubclass(layer, Packet):
            found = pkt.getlayer(layer)
            return self._layer_to_string(found, fmt=fmt) if found else default

        # layer by name (string)
        if isinstance(layer, str):
            # try exact by walking the actual stack (most reliable)
            for l in self._iter_layers(pkt):
                if self._match_layer(l, layer):
                    return self._layer_to_string(l, fmt=fmt)
            # as a fallback, try scapy's dynamic resolver if it exists
            try:
                # sometimes scapy exposes layer classes in globals of loaded modules
                import scapy.layers.inet as _inet
                import scapy.layers.inet6 as _inet6
                import scapy.layers.l2 as _l2
                import scapy.layers.dns as _dns
                _spaces = [globals(), vars(_inet), vars(_inet6), vars(_l2), vars(_dns)]
                for space in _spaces:
                    cls = space.get(layer)
                    if isinstance(cls, type) and issubclass(cls, Packet):
                        found = pkt.getlayer(cls)
                        if found:
                            return self._layer_to_string(found, fmt=fmt)
            except Exception:
                pass

        return default

    def get_layer_deep(
            self,
            pkt: Packet,
            layer: str | type[Packet] | int,
            *,
            fmt: str = "show",
            default: str = "",
            nth: int = 0,  # NEW: choose nth match in deep walk
    ) -> str:
        if pkt is None:
            return default

        layers = list(self._iter_layers_deep(pkt))

        # by index in deep list
        if isinstance(layer, int):
            if 0 <= layer < len(layers):
                return self._layer_to_string(layers[layer], fmt=fmt)
            return default

        # by class
        if isinstance(layer, type) and issubclass(layer, Packet):
            matches = [l for l in layers if isinstance(l, layer)]
            if len(matches) > nth:
                return self._layer_to_string(matches[nth], fmt=fmt)
            return default

        # by name
        if isinstance(layer, str):
            q = layer.lower()
            matches = [l for l in layers if (l.__class__.__name__.lower() == q or getattr(l, "name", "").lower() == q)]
            if len(matches) > nth:
                return self._layer_to_string(matches[nth], fmt=fmt)
            return default

        return default

    # Optionally: make your existing get_ipv6_layer use the deep walker too
    def get_ipv6_layer(self, pkt: Packet, layer_spec: Union[type[Packet], str, int]) -> Optional[Packet]:
        if not isinstance(pkt, Packet):
            return None

        layers = list(self._iter_layers_deep(pkt))

        if isinstance(layer_spec, int):
            return layers[layer_spec] if 0 <= layer_spec < len(layers) else None

        if isinstance(layer_spec, type) and issubclass(layer_spec, Packet):
            for l in layers:
                if isinstance(l, layer_spec):
                    return l
            return None

        if isinstance(layer_spec, str):
            q = layer_spec.lower()
            for l in layers:
                if l.__class__.__name__.lower() == q or getattr(l, "name", "").lower() == q:
                    return l
            return None

        return None

    def _maybe_parse_inner(self, b: bytes):
        """Best-effort parse inner packet from raw bytes."""
        if not b:
            return None
        # Try Ethernet first (common for VXLAN/GENEVE)
        try:
            p = Ether(b)
            # sanity: Ether type looks plausible
            if hasattr(p, "type") and int(p.type) not in (0,):
                return p
        except Exception:
            pass

        # Try IP/IPv6 by version nibble
        ver = (b[0] >> 4) & 0xF
        if ver == 4:
            try:
                return IP(b)
            except Exception:
                return None
        if ver == 6:
            try:
                return IPv6(b)
            except Exception:
                return None

        return None

    def _iter_layers_deep(self, pkt: Packet, max_nodes: int = 128):
        """
        Yields layers across decapsulation boundaries (tunnels + Raw heuristics).
        Prevents loops with a visited set.
        """
        from collections import deque

        q = deque()
        q.append(pkt)
        visited = set()
        nodes = 0

        try:
            from scapy.layers.vxlan import VXLAN
        except Exception:
            VXLAN = None

        try:
            from scapy.layers.dot11 import PrismHeader
        except Exception:
            PrismHeader = None

        try:
            from scapy.contrib.avs import AVSWLANHeader
        except Exception:
            AVSWLANHeader = None

        try:
            from scapy.contrib.tzsp import TZSP
        except Exception:
            TZSP = None

        try:
            from scapy.contrib.erspan import ERSPAN, ERSPAN_II, ERSPAN_III
            ERSPAN_TYPES = tuple(x for x in (ERSPAN, ERSPAN_II, ERSPAN_III) if x is not None)
        except Exception:
            ERSPAN_TYPES = ()

        while q and nodes < max_nodes:
            cur = q.popleft()
            if cur is None:
                continue

            key = (id(cur), cur.__class__)
            if key in visited:
                continue
            visited.add(key)

            nodes += 1
            yield cur

            pay = getattr(cur, "payload", None)

            try:
                # Prism / AVS monitor wrappers
                if PrismHeader is not None and isinstance(cur, PrismHeader):
                    if isinstance(pay, Packet) and not isinstance(pay, NoPayload):
                        q.append(pay)
                    continue

                if AVSWLANHeader is not None and isinstance(cur, AVSWLANHeader):
                    if isinstance(pay, Packet) and not isinstance(pay, NoPayload):
                        q.append(pay)
                    continue

                # GRE / ERSPAN
                if isinstance(cur, GRE):
                    if ERSPAN_TYPES:
                        try:
                            erspan_pkt = None
                            if isinstance(pay, Packet) and any(isinstance(pay, t) for t in ERSPAN_TYPES):
                                erspan_pkt = pay
                            elif isinstance(pay, Raw):
                                for t in ERSPAN_TYPES:
                                    try:
                                        tmp = t(bytes(pay.load or b""))
                                        erspan_pkt = tmp
                                        break
                                    except Exception:
                                        pass
                            if erspan_pkt is not None:
                                q.append(erspan_pkt)
                                continue
                        except Exception:
                            pass

                    if isinstance(pay, Packet) and not isinstance(pay, NoPayload):
                        q.append(pay)
                    continue

                # ERSPAN payload is usually inner Ether
                if ERSPAN_TYPES and any(isinstance(cur, t) for t in ERSPAN_TYPES):
                    if isinstance(pay, Packet) and not isinstance(pay, NoPayload):
                        q.append(pay)
                    continue

                if isinstance(cur, (PPPoE, PPP, MPLS, Dot1Q)):
                    if isinstance(pay, Packet) and not isinstance(pay, NoPayload):
                        q.append(pay)
                    continue

                if isinstance(cur, UDP):
                    # TZSP
                    if int(getattr(cur, "dport", -1)) == 0x9090 or int(getattr(cur, "sport", -1)) == 0x9090:
                        tz = None
                        if TZSP is not None:
                            try:
                                if cur.haslayer(TZSP):
                                    tz = cur.getlayer(TZSP)
                                elif isinstance(pay, Raw):
                                    tz = TZSP(bytes(pay.load or b""))
                            except Exception:
                                tz = None

                        if tz is not None:
                            q.append(tz)
                            try:
                                inner = tz.get_encapsulated_payload()
                                if isinstance(inner, Packet) and not isinstance(inner, NoPayload):
                                    q.append(inner)
                            except Exception:
                                pass
                            continue

                    # VXLAN ports: 4789 + 8472
                    if int(getattr(cur, "dport", -1)) in (4789, 8472) or int(getattr(cur, "sport", -1)) in (4789, 8472):
                        if VXLAN and cur.haslayer(VXLAN):
                            vx = cur.getlayer(VXLAN)
                            if vx and hasattr(vx, "payload"):
                                q.append(vx.payload)
                                continue

                    # GENEVE
                    if int(getattr(cur, "dport", -1)) == 6081 or int(getattr(cur, "sport", -1)) == 6081:
                        ge = cur.getlayer(GENEVE) if cur.haslayer(GENEVE) else None
                        if ge and hasattr(ge, "payload"):
                            q.append(ge.payload)
                            continue

                    # L2TP
                    if int(getattr(cur, "dport", -1)) == 1701 or int(getattr(cur, "sport", -1)) == 1701:
                        l2tp = cur.getlayer(L2TP) if cur.haslayer(L2TP) else None
                        if l2tp and hasattr(l2tp, "payload"):
                            q.append(l2tp.payload)
                            continue

                # If the current layer is TZSP itself, try to unwrap it too
                if TZSP is not None and isinstance(cur, TZSP):
                    try:
                        inner = cur.get_encapsulated_payload()
                        if isinstance(inner, Packet) and not isinstance(inner, NoPayload):
                            q.append(inner)
                            continue
                    except Exception:
                        pass

            except Exception:
                pass

            if isinstance(pay, Packet) and not isinstance(pay, NoPayload):
                q.append(pay)
                continue

            if isinstance(cur, Raw):
                inner = self._maybe_parse_inner(bytes(cur.load or b""))
                if inner is not None:
                    q.append(inner)
                continue
