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
import json
import math
import re
import collections
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple, Deque, Iterable
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


class pcap_stat(Structure):
    """Portable prefix of libpcap/Npcap's packet statistics structure."""
    _fields_ = [
        ("ps_recv", c_uint),
        ("ps_drop", c_uint),
        ("ps_ifdrop", c_uint),
    ]


# pcap timestamp precision values used by pcap_set_tstamp_precision.
PCAP_TSTAMP_PRECISION_MICRO = 0
PCAP_TSTAMP_PRECISION_NANO = 1

# pcap_activate status values. Positive values are warnings and still produce
# a usable handle; negative values are hard errors.
PCAP_WARNING = 1
PCAP_WARNING_PROMISC_NOTSUP = 2
PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3
PCAP_ERROR = -1
PCAP_ERROR_BREAK = -2
PCAP_ERROR_NOT_ACTIVATED = -3
PCAP_ERROR_ACTIVATED = -4
PCAP_ERROR_NO_SUCH_DEVICE = -5
PCAP_ERROR_RFMON_NOTSUP = -6
PCAP_ERROR_NOT_RFMON = -7
PCAP_ERROR_PERM_DENIED = -8
PCAP_ERROR_IFACE_NOT_UP = -9
PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10
PCAP_ERROR_PROMISC_PERM_DENIED = -11
PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12


@dataclass
class _PendingTcpSegment:
    """One bounded out-of-order TCP segment retained for later gap closure."""
    sequence: int
    payload: bytes
    timestamp_ns: int
    flags: int = 0


@dataclass
class _TcpDirectionState:
    """Loss-aware state for one direction of a normalized TCP flow."""
    initial_sequence: Optional[int] = None
    next_sequence: Optional[int] = None
    contiguous_total: int = 0
    observed_payload_total: int = 0
    retransmission_segments: int = 0
    retransmission_bytes: int = 0
    overlap_segments: int = 0
    overlap_bytes: int = 0
    duplicate_segments: int = 0
    out_of_order_segments: int = 0
    sequence_gap_events: int = 0
    largest_gap: int = 0
    pending_bytes: int = 0
    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    last_ack: Optional[int] = None
    last_window: Optional[int] = None
    last_seen_ns: int = 0
    stream_tail: bytearray = field(default_factory=bytearray)
    pending: Dict[int, _PendingTcpSegment] = field(default_factory=dict)
    recent_segments: collections.OrderedDict = field(default_factory=collections.OrderedDict)


@dataclass
class _TcpFlowState:
    """Bidirectional flow container with independent sequence spaces."""
    flow_id: str
    endpoint_a: Tuple[str, int]
    endpoint_b: Tuple[str, int]
    created_ns: int
    last_seen_ns: int
    directions: Dict[int, _TcpDirectionState] = field(
        default_factory=lambda: {0: _TcpDirectionState(), 1: _TcpDirectionState()}
    )
    packet_count: int = 0
    payload_bytes: int = 0
    closed: bool = False


@dataclass
class _FragmentState:
    """Bounded metadata for observing IPv4/IPv6 fragmented datagrams."""
    key: Tuple[Any, ...]
    created_ns: int
    last_seen_ns: int
    fragments: int = 0
    bytes_observed: int = 0
    final_offset: Optional[int] = None
    offsets: set = field(default_factory=set)

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

        # ------------------------------------------------------------------
        # High-fidelity capture configuration and bounded analysis state.
        # These defaults deliberately favor loss resistance without asking
        # Npcap for unbounded buffers that could destabilize a busy router.
        # ------------------------------------------------------------------
        self.capture_snapshot_length = 262144
        self.capture_kernel_buffer_bytes = 64 * 1024 * 1024
        self.capture_read_timeout_ms = 100
        self.capture_immediate_mode = False
        self.capture_request_nanosecond_timestamps = True
        self.capture_stats_interval_sec = 1.0
        self.capture_raw_retention_limit = self.capture_snapshot_length
        self.capture_stream_tail_bytes = 512 * 1024
        self.capture_stream_pending_bytes = 2 * 1024 * 1024
        self.capture_max_tcp_flows = 8192
        self.capture_tcp_flow_idle_sec = 300.0
        self.capture_max_fragment_sets = 2048
        self.capture_fragment_idle_sec = 60.0
        self.capture_keep_unknown_ethertypes = True
        self.capture_analyze_protocols = True
        self.capture_preserve_original_frame = True

        # Allow router settings to override capture tuning without changing
        # any constructor or public method signature.
        capture_cfg = {}
        try:
            if isinstance(self._interfaces_config, dict):
                capture_cfg = dict(
                    self._interfaces_config.get("__capture__", {})
                    or self._interfaces_config.get("capture", {})
                    or {}
                )
        except Exception:
            capture_cfg = {}

        def _cfg_int(name, current, low, high):
            try:
                value = int(capture_cfg.get(name, current))
            except Exception:
                value = current
            return max(low, min(high, value))

        def _cfg_float(name, current, low, high):
            try:
                value = float(capture_cfg.get(name, current))
            except Exception:
                value = current
            return max(low, min(high, value))

        self.capture_snapshot_length = _cfg_int(
            "snapshot_length", self.capture_snapshot_length, 65535, 4 * 1024 * 1024
        )
        self.capture_kernel_buffer_bytes = _cfg_int(
            "kernel_buffer_bytes", self.capture_kernel_buffer_bytes,
            4 * 1024 * 1024, 256 * 1024 * 1024
        )
        self.capture_read_timeout_ms = _cfg_int(
            "read_timeout_ms", self.capture_read_timeout_ms, 1, 5000
        )
        self.capture_stream_tail_bytes = _cfg_int(
            "stream_tail_bytes", self.capture_stream_tail_bytes, 16 * 1024, 4 * 1024 * 1024
        )
        self.capture_stream_pending_bytes = _cfg_int(
            "stream_pending_bytes", self.capture_stream_pending_bytes,
            64 * 1024, 16 * 1024 * 1024
        )
        self.capture_max_tcp_flows = _cfg_int(
            "max_tcp_flows", self.capture_max_tcp_flows, 256, 65536
        )
        self.capture_tcp_flow_idle_sec = _cfg_float(
            "tcp_flow_idle_sec", self.capture_tcp_flow_idle_sec, 10.0, 3600.0
        )
        self.capture_max_fragment_sets = _cfg_int(
            "max_fragment_sets", self.capture_max_fragment_sets, 64, 16384
        )
        self.capture_fragment_idle_sec = _cfg_float(
            "fragment_idle_sec", self.capture_fragment_idle_sec, 5.0, 600.0
        )
        for key, attr in (
            ("immediate_mode", "capture_immediate_mode"),
            ("nanosecond_timestamps", "capture_request_nanosecond_timestamps"),
            ("keep_unknown_ethertypes", "capture_keep_unknown_ethertypes"),
            ("analyze_protocols", "capture_analyze_protocols"),
            ("preserve_original_frame", "capture_preserve_original_frame"),
        ):
            if key in capture_cfg:
                value = capture_cfg.get(key)
                if isinstance(value, str):
                    value = value.strip().casefold() in {"1", "true", "yes", "on", "enabled"}
                setattr(self, attr, bool(value))

        self._capture_state_lock = threading.RLock()
        self._capture_sequence = 0
        self._capture_handle_precision = {}
        self._capture_handle_iface = {}
        self._active_capture_handles = {}
        # Per-device timestamp capability cache.  Npcap commonly exposes the
        # precision API while individual adapters still support microseconds
        # only.  Cache that result so each reopen does not repeat a rejected
        # nanosecond request or emit misleading warnings.
        self._capture_timestamp_precision_support = {}
        self._capture_stats = {}
        self._capture_stats_last_sample = {}
        self._capture_total_frames = 0
        self._capture_total_bytes = 0
        self._capture_total_wire_bytes = 0
        self._capture_total_truncated = 0
        self._capture_decode_failures = 0
        self._capture_protocol_counts = collections.Counter()
        self._capture_priority_counts = collections.Counter()
        self._capture_unknown_ethertypes = collections.Counter()

        self._flow_state_lock = threading.RLock()
        self._tcp_flows = collections.OrderedDict()
        self._fragment_sets = collections.OrderedDict()
        self._last_flow_cleanup_ns = 0

        # Ports are hints only. Recognition still checks payload structure so
        # non-standard Stratum/TLS/QUIC ports are not missed.
        self._high_value_tcp_ports = {
            22, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445,
            465, 587, 636, 853, 993, 995, 1433, 1521, 2375, 2376,
            3306, 3389, 4444, 5000, 5432, 5671, 5672, 6379, 8080,
            8443, 8883, 9000, 9092, 10001, 10128, 18080, 18081,
            18089, 3333, 4444, 5555, 7777,
        }
        self._high_value_udp_ports = {
            53, 67, 68, 88, 123, 161, 162, 389, 443, 500, 514,
            520, 546, 547, 1900, 4500, 4789, 5353, 6081, 8472,
            9090,
        }
        self._stratum_method_names = {
            "mining.subscribe", "mining.authorize", "mining.configure",
            "mining.extranonce.subscribe", "mining.notify",
            "mining.set_difficulty", "mining.set_target", "mining.submit",
            "mining.get_transactions", "login", "job", "submit",
            "keepalived", "getjob", "get_jobs",
        }

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
            0x8848,  # MPLS multicast
            0x9100,  # provider/stacked VLAN used by some switches
            0x9200,  # stacked VLAN variant
            0x88B5,  # IEEE local experimental EtherType
            0x88B6,  # IEEE local experimental EtherType
            0x88B7,  # IEEE OUI Extended EtherType
            0x88E5,  # MACsec
            0x88E1,  # HomePlug AV
            0x88E3,  # Media Redundancy Protocol
            0x8915,  # RoCE
        }
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
        self.logged_packets = collections.deque(maxlen=8192)
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

        # Capture handles use pcap_create/pcap_activate when available so Npcap
        # receives the larger snapshot, kernel buffer, timestamp precision, and
        # timeout before activation. Packet-injection handles keep the simpler
        # open_live path to avoid allocating a large receive buffer per send.
        advanced_error = ""
        if not for_send:
            handle, advanced_error = self._open_pcap_handle_advanced(
                candidate=candidate,
                promisc=promisc,
                timeout=timeout,
                bpf_filter=bpf_filter,
            )
            if handle:
                return handle, ""

        errbuf = ctypes.create_string_buffer(256)
        handle = self.libpcap.pcap_open_live(
            candidate.encode("utf-8"),
            int(self.capture_snapshot_length),
            1 if promisc else 0,
            max(1, int(timeout)),
            errbuf,
        )
        if not handle:
            fallback_error = errbuf.value.decode(errors="ignore")
            if advanced_error:
                fallback_error = f"{fallback_error}; advanced_open={advanced_error}".strip("; ")
            return None, fallback_error

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

        if not for_send:
            self._register_capture_handle(
                handle,
                candidate,
                precision=PCAP_TSTAMP_PRECISION_MICRO,
                open_mode="pcap_open_live",
            )

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


        # Optional advanced activation path. Every symbol is probed separately
        # because WinPcap and older Npcap releases expose different subsets.
        def _optional(name, restype, argtypes):
            try:
                fn = getattr(self.libpcap, name)
                fn.restype = restype
                fn.argtypes = argtypes
                return True
            except Exception:
                return False

        self._pcap_has_create = _optional(
            "pcap_create", pcap_t_p, [ctypes.c_char_p, ctypes.c_char_p]
        )
        self._pcap_has_activate = _optional(
            "pcap_activate", c_int, [pcap_t_p]
        )
        self._pcap_has_set_snaplen = _optional(
            "pcap_set_snaplen", c_int, [pcap_t_p, c_int]
        )
        self._pcap_has_set_promisc = _optional(
            "pcap_set_promisc", c_int, [pcap_t_p, c_int]
        )
        self._pcap_has_set_timeout = _optional(
            "pcap_set_timeout", c_int, [pcap_t_p, c_int]
        )
        self._pcap_has_set_buffer_size = _optional(
            "pcap_set_buffer_size", c_int, [pcap_t_p, c_int]
        )
        self._pcap_has_set_immediate_mode = _optional(
            "pcap_set_immediate_mode", c_int, [pcap_t_p, c_int]
        )
        self._pcap_has_set_tstamp_precision = _optional(
            "pcap_set_tstamp_precision", c_int, [pcap_t_p, c_int]
        )
        self._pcap_has_get_tstamp_precision = _optional(
            "pcap_get_tstamp_precision", c_int, [pcap_t_p]
        )
        self._pcap_has_statustostr = _optional(
            "pcap_statustostr", ctypes.c_char_p, [c_int]
        )
        self._pcap_has_stats = _optional(
            "pcap_stats", c_int, [pcap_t_p, ctypes.POINTER(pcap_stat)]
        )
        self._pcap_has_setmintocopy = _optional(
            "pcap_setmintocopy", c_int, [pcap_t_p, c_int]
        )
        self._pcap_has_breakloop = _optional(
            "pcap_breakloop", None, [pcap_t_p]
        )


    # -------------------------------------------------------------------------
    # High-fidelity capture activation, statistics, and metadata helpers
    # -------------------------------------------------------------------------
    def _pcap_status_text(self, status: int) -> str:
        """Return a stable human-readable libpcap activation status."""
        if getattr(self, "_pcap_has_statustostr", False):
            try:
                value = self.libpcap.pcap_statustostr(int(status))
                if value:
                    return value.decode("utf-8", "replace")
            except Exception:
                pass
        fallback = {
            0: "success",
            PCAP_WARNING: "generic warning",
            PCAP_WARNING_PROMISC_NOTSUP: "promiscuous mode not supported",
            PCAP_WARNING_TSTAMP_TYPE_NOTSUP: "timestamp type not supported",
            PCAP_ERROR: "generic libpcap error",
            PCAP_ERROR_BREAK: "capture loop terminated",
            PCAP_ERROR_NOT_ACTIVATED: "capture handle not activated",
            PCAP_ERROR_ACTIVATED: "capture handle already activated",
            PCAP_ERROR_NO_SUCH_DEVICE: "no such capture device",
            PCAP_ERROR_RFMON_NOTSUP: "monitor mode not supported",
            PCAP_ERROR_NOT_RFMON: "device is not in monitor mode",
            PCAP_ERROR_PERM_DENIED: "permission denied",
            PCAP_ERROR_IFACE_NOT_UP: "interface is not up",
            PCAP_ERROR_CANTSET_TSTAMP_TYPE: "cannot set timestamp type",
            PCAP_ERROR_PROMISC_PERM_DENIED: "promiscuous permission denied",
            PCAP_ERROR_TSTAMP_PRECISION_NOTSUP: "timestamp precision unsupported",
        }
        return fallback.get(int(status), f"pcap status {status}")

    def _pcap_handle_key(self, handle) -> int:
        """Normalize ctypes/int pcap handles to a dictionary key."""
        if handle is None:
            return 0
        try:
            if isinstance(handle, int):
                return int(handle)
            value = ctypes.cast(handle, ctypes.c_void_p).value
            return int(value or 0)
        except Exception:
            try:
                return int(handle)
            except Exception:
                return 0

    def _register_capture_handle(
            self,
            handle,
            iface: str,
            *,
            precision: int = PCAP_TSTAMP_PRECISION_MICRO,
            open_mode: str = "unknown",
    ) -> None:
        key = self._pcap_handle_key(handle)
        if not key:
            return
        normalized = self._normalize_pcap_name(iface)
        with self._capture_state_lock:
            self._capture_handle_precision[key] = int(precision)
            self._capture_handle_iface[key] = normalized
            self._active_capture_handles[normalized.casefold()] = handle
            row = self._capture_stats.setdefault(normalized.casefold(), {})
            row.update({
                "interface": normalized,
                "open_mode": str(open_mode),
                "timestamp_precision": (
                    "nanosecond"
                    if int(precision) == PCAP_TSTAMP_PRECISION_NANO
                    else "microsecond"
                ),
                "snapshot_length": int(self.capture_snapshot_length),
                "kernel_buffer_bytes_requested": int(self.capture_kernel_buffer_bytes),
                "opened_at_ns": time.time_ns(),
            })

    def _unregister_capture_handle(self, handle, iface: str = "") -> None:
        key = self._pcap_handle_key(handle)
        normalized = self._normalize_pcap_name(iface)
        with self._capture_state_lock:
            known_iface = self._capture_handle_iface.pop(key, "")
            self._capture_handle_precision.pop(key, None)
            name = normalized or known_iface
            if name:
                current = self._active_capture_handles.get(name.casefold())
                if current is handle or self._pcap_handle_key(current) == key:
                    self._active_capture_handles.pop(name.casefold(), None)

    def _install_bpf_on_handle(self, handle, bpf_filter: str | None) -> tuple[bool, str]:
        """Compile/install one BPF expression without leaking native code."""
        if not bpf_filter:
            return True, ""
        bpf = bpf_program()
        expression = str(bpf_filter).encode("utf-8", "replace")
        if self.libpcap.pcap_compile(
                handle, ctypes.byref(bpf), expression, 1, 0
        ) == -1:
            err = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
            with contextlib.suppress(Exception):
                self.libpcap.pcap_freecode(ctypes.byref(bpf))
            return False, f"filter compile failed: {err}"
        try:
            if self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) == -1:
                err = (self.libpcap.pcap_geterr(handle) or b"").decode(errors="ignore")
                return False, f"filter set failed: {err}"
            return True, ""
        finally:
            with contextlib.suppress(Exception):
                self.libpcap.pcap_freecode(ctypes.byref(bpf))

    def _negotiate_capture_timestamp_precision(self, handle, candidate: str) -> tuple[int, list[str]]:
        """Select the best timestamp precision the capture device really supports.

        ``pcap_set_tstamp_precision`` is a pre-activation API.  Npcap may export
        it even when a particular adapter cannot provide nanosecond capture
        timestamps.  ``PCAP_ERROR_TSTAMP_PRECISION_NOTSUP`` is therefore a
        normal capability result, not an activation warning or a fatal error.

        The returned precision describes the units in ``pcap_pkthdr.ts.tv_usec``:
        microseconds for ``PCAP_TSTAMP_PRECISION_MICRO`` and nanoseconds for
        ``PCAP_TSTAMP_PRECISION_NANO``.
        """
        warnings: list[str] = []
        precision = PCAP_TSTAMP_PRECISION_MICRO
        device_key = self._normalize_pcap_name(candidate).casefold()

        if not self.capture_request_nanosecond_timestamps:
            return precision, warnings
        if not getattr(self, "_pcap_has_set_tstamp_precision", False):
            with self._capture_state_lock:
                self._capture_timestamp_precision_support[device_key] = False
            return precision, warnings

        with self._capture_state_lock:
            cached_support = self._capture_timestamp_precision_support.get(device_key)

        # A previous handle already proved this adapter is microsecond-only.
        # Microsecond precision is libpcap's default, so no rejected call needs
        # to be repeated for every reopen.
        if cached_support is False:
            return precision, warnings

        try:
            rc = int(self.libpcap.pcap_set_tstamp_precision(
                handle, PCAP_TSTAMP_PRECISION_NANO
            ))
        except Exception as exc:
            with self._capture_state_lock:
                self._capture_timestamp_precision_support[device_key] = False
            # An exception is unusual and worth retaining, but capture can still
            # proceed with the default microsecond precision.
            warnings.append(f"timestamp precision probe exception: {exc}")
            return precision, warnings

        if rc == 0:
            with self._capture_state_lock:
                self._capture_timestamp_precision_support[device_key] = True
            return PCAP_TSTAMP_PRECISION_NANO, warnings

        if rc == PCAP_ERROR_TSTAMP_PRECISION_NOTSUP:
            with self._capture_state_lock:
                self._capture_timestamp_precision_support[device_key] = False
            # This is an expected capability response on many Npcap adapters.
            # Do not report it as a warning and do not pretend the header has
            # nanosecond resolution.  The default remains microseconds.
            return precision, warnings

        # An unexpected status still should not prevent packet capture.  Make a
        # best-effort explicit microsecond request and report only genuinely
        # abnormal failures.
        with self._capture_state_lock:
            self._capture_timestamp_precision_support[device_key] = False
        try:
            fallback_rc = int(self.libpcap.pcap_set_tstamp_precision(
                handle, PCAP_TSTAMP_PRECISION_MICRO
            ))
        except Exception as exc:
            warnings.append(
                "timestamp precision fallback failed after "
                f"{self._pcap_status_text(rc)}: {exc}"
            )
            return precision, warnings

        if fallback_rc != 0:
            warnings.append(
                "timestamp precision fallback failed: "
                f"nano={self._pcap_status_text(rc)}, "
                f"micro={self._pcap_status_text(fallback_rc)}"
            )
        return precision, warnings

    def _capture_precision_for_iface(self, iface: str) -> int:
        """Return the registered packet-header precision for one live handle."""
        normalized = self._normalize_pcap_name(iface)
        with self._capture_state_lock:
            handle = self._active_capture_handles.get(normalized.casefold())
            return int(self._capture_handle_precision.get(
                self._pcap_handle_key(handle),
                PCAP_TSTAMP_PRECISION_MICRO,
            ))

    def _capture_precision_name_for_iface(self, iface: str) -> str:
        return (
            "nanosecond"
            if self._capture_precision_for_iface(iface) == PCAP_TSTAMP_PRECISION_NANO
            else "microsecond"
        )

    def _open_pcap_handle_advanced(
            self,
            *,
            candidate: str,
            promisc: bool,
            timeout: int,
            bpf_filter: str | None,
    ):
        """Create and activate one loss-resistant capture handle.

        All standard capture settings are applied before activation.  Timestamp
        precision is negotiated rather than assumed.  Npcap's ``mintocopy``
        control is applied only after activation because its Windows extension
        rejects inactive handles.
        """
        if not (
            getattr(self, "_pcap_has_create", False)
            and getattr(self, "_pcap_has_activate", False)
        ):
            return None, "pcap_create/pcap_activate unavailable"

        errbuf = ctypes.create_string_buffer(256)
        handle = self.libpcap.pcap_create(
            candidate.encode("utf-8", "replace"),
            errbuf,
        )
        if not handle:
            return None, errbuf.value.decode("utf-8", "replace")

        warnings: list[str] = []

        def _set_pre_activation(name: str, enabled: bool, *args) -> None:
            if not enabled:
                return
            try:
                rc = int(getattr(self.libpcap, name)(handle, *args))
            except Exception as exc:
                warnings.append(f"{name} exception: {exc}")
                return
            if rc != 0:
                warnings.append(f"{name}: {self._pcap_status_text(rc)}")

        _set_pre_activation(
            "pcap_set_snaplen",
            getattr(self, "_pcap_has_set_snaplen", False),
            int(self.capture_snapshot_length),
        )
        _set_pre_activation(
            "pcap_set_promisc",
            getattr(self, "_pcap_has_set_promisc", False),
            1 if promisc else 0,
        )
        _set_pre_activation(
            "pcap_set_timeout",
            getattr(self, "_pcap_has_set_timeout", False),
            max(1, int(timeout or self.capture_read_timeout_ms)),
        )
        _set_pre_activation(
            "pcap_set_buffer_size",
            getattr(self, "_pcap_has_set_buffer_size", False),
            int(self.capture_kernel_buffer_bytes),
        )
        _set_pre_activation(
            "pcap_set_immediate_mode",
            getattr(self, "_pcap_has_set_immediate_mode", False),
            1 if self.capture_immediate_mode else 0,
        )

        requested_precision, precision_warnings = (
            self._negotiate_capture_timestamp_precision(handle, candidate)
        )
        warnings.extend(precision_warnings)

        try:
            status = int(self.libpcap.pcap_activate(handle))
        except Exception as exc:
            with contextlib.suppress(Exception):
                self.libpcap.pcap_close(handle)
            return None, f"pcap_activate exception: {exc}"

        if status < 0:
            native_error = ""
            with contextlib.suppress(Exception):
                native_error = (
                    self.libpcap.pcap_geterr(handle) or b""
                ).decode("utf-8", "replace")
            with contextlib.suppress(Exception):
                self.libpcap.pcap_close(handle)
            detail = self._pcap_status_text(status)
            if native_error:
                detail = f"{detail}: {native_error}"
            return None, detail

        if status > 0:
            warnings.append(self._pcap_status_text(status))

        # Npcap's pcap_setmintocopy extension requires an activated pcap_t.
        # Calling it before pcap_activate generated the exact warning seen in
        # the router log: "The pcap_t has not been activated".
        if getattr(self, "_pcap_has_setmintocopy", False):
            minimum_copy = 1 if self.capture_immediate_mode else 16 * 1024
            try:
                mincopy_rc = int(self.libpcap.pcap_setmintocopy(
                    handle, minimum_copy
                ))
            except Exception as exc:
                warnings.append(f"pcap_setmintocopy exception: {exc}")
            else:
                if mincopy_rc != 0:
                    warnings.append(
                        "pcap_setmintocopy: "
                        + self._pcap_status_text(mincopy_rc)
                    )

        actual_precision = requested_precision
        if getattr(self, "_pcap_has_get_tstamp_precision", False):
            try:
                reported_precision = int(
                    self.libpcap.pcap_get_tstamp_precision(handle)
                )
                if reported_precision in (
                    PCAP_TSTAMP_PRECISION_MICRO,
                    PCAP_TSTAMP_PRECISION_NANO,
                ):
                    actual_precision = reported_precision
            except Exception:
                pass

        ok, filter_error = self._install_bpf_on_handle(handle, bpf_filter)
        if not ok:
            with contextlib.suppress(Exception):
                self.libpcap.pcap_close(handle)
            return None, filter_error

        self._register_capture_handle(
            handle,
            candidate,
            precision=actual_precision,
            open_mode="pcap_create",
        )
        if warnings:
            self._log_send_once(
                f"pcap-open-warning:{candidate.casefold()}",
                f"[Sniffer] Npcap activated {candidate} with warning(s): "
                + "; ".join(warnings),
                every=30.0,
            )
        return handle, ""

    def _next_capture_sequence(self) -> int:
        with self._capture_state_lock:
            self._capture_sequence += 1
            return self._capture_sequence

    def _timestamp_ns_from_header(self, pkthdr_ptr, iface: str = "") -> int:
        try:
            hdr = pkthdr_ptr.contents
            seconds = int(getattr(hdr.ts, "tv_sec", 0) or 0)
            fraction = int(getattr(hdr.ts, "tv_usec", 0) or 0)
        except Exception:
            return time.time_ns()

        precision = PCAP_TSTAMP_PRECISION_MICRO
        normalized = self._normalize_pcap_name(iface)
        with self._capture_state_lock:
            handle = self._active_capture_handles.get(normalized.casefold())
            precision = self._capture_handle_precision.get(
                self._pcap_handle_key(handle),
                PCAP_TSTAMP_PRECISION_MICRO,
            )
        if precision == PCAP_TSTAMP_PRECISION_NANO:
            return seconds * 1_000_000_000 + max(0, fraction)
        return seconds * 1_000_000_000 + max(0, fraction) * 1_000

    def _sample_capture_stats(
            self,
            iface: str,
            *,
            handle=None,
            force: bool = False,
    ) -> dict:
        """Sample Npcap receive/drop counters at a bounded interval."""
        normalized = self._normalize_pcap_name(iface)
        key = normalized.casefold()
        now = time.monotonic()
        with self._capture_state_lock:
            previous = float(self._capture_stats_last_sample.get(key, 0.0) or 0.0)
            if not force and now - previous < self.capture_stats_interval_sec:
                return dict(self._capture_stats.get(key, {}))
            self._capture_stats_last_sample[key] = now
            if handle is None:
                handle = self._active_capture_handles.get(key)

        if not handle or not getattr(self, "_pcap_has_stats", False):
            with self._capture_state_lock:
                return dict(self._capture_stats.get(key, {}))

        native = pcap_stat()
        try:
            rc = int(self.libpcap.pcap_stats(handle, ctypes.byref(native)))
        except Exception as exc:
            with self._capture_state_lock:
                row = self._capture_stats.setdefault(key, {"interface": normalized})
                row["stats_error"] = str(exc)
                return dict(row)

        with self._capture_state_lock:
            row = self._capture_stats.setdefault(key, {"interface": normalized})
            if rc == 0:
                old_recv = int(row.get("ps_recv", 0) or 0)
                old_drop = int(row.get("ps_drop", 0) or 0)
                old_ifdrop = int(row.get("ps_ifdrop", 0) or 0)
                recv = int(native.ps_recv)
                drop = int(native.ps_drop)
                ifdrop = int(native.ps_ifdrop)
                row.update({
                    "ps_recv": recv,
                    "ps_drop": drop,
                    "ps_ifdrop": ifdrop,
                    "delta_recv": max(0, recv - old_recv),
                    "delta_drop": max(0, drop - old_drop),
                    "delta_ifdrop": max(0, ifdrop - old_ifdrop),
                    "sampled_at_ns": time.time_ns(),
                    "stats_error": "",
                })
            else:
                row["stats_error"] = (
                    self.libpcap.pcap_geterr(handle) or b""
                ).decode("utf-8", "replace")
            return dict(row)

    def get_capture_stats(self, iface: str = None) -> dict:
        """Return a thread-safe snapshot of capture and drop counters."""
        if iface:
            return self._sample_capture_stats(iface, force=True)
        with self._capture_state_lock:
            handles = list(self._active_capture_handles.items())
        for key, handle in handles:
            with self._capture_state_lock:
                name = str(self._capture_stats.get(key, {}).get("interface") or key)
            self._sample_capture_stats(name, handle=handle, force=True)
        with self._capture_state_lock:
            return {
                "interfaces": {
                    key: dict(value)
                    for key, value in self._capture_stats.items()
                },
                "totals": {
                    "frames": int(self._capture_total_frames),
                    "captured_bytes": int(self._capture_total_bytes),
                    "wire_bytes": int(self._capture_total_wire_bytes),
                    "truncated_frames": int(self._capture_total_truncated),
                    "decode_failures": int(self._capture_decode_failures),
                },
                "protocol_counts": dict(self._capture_protocol_counts),
                "priority_counts": dict(self._capture_priority_counts),
                "unknown_ethertypes": {
                    f"0x{k:04x}": int(v)
                    for k, v in self._capture_unknown_ethertypes.items()
                },
                "active_tcp_flows": len(self._tcp_flows),
                "active_fragment_sets": len(self._fragment_sets),
            }

    def _safe_set_packet_attr(self, packet, name: str, value) -> None:
        try:
            setattr(packet, name, value)
        except Exception:
            pass

    def _payload_bytes(self, packet: Packet) -> bytes:
        """Return the deepest readily available application payload."""
        if packet is None:
            return b""
        try:
            raw_layer = packet.getlayer(Raw)
            if raw_layer is not None:
                return bytes(getattr(raw_layer, "load", b"") or b"")
        except Exception:
            pass
        transport = self._find_transport_layer(packet)
        if transport is not None:
            try:
                payload = getattr(transport, "payload", None)
                if isinstance(payload, Raw):
                    return bytes(payload.load or b"")
            except Exception:
                pass
        return b""

    def _packet_endpoint_tuple(self, packet: Packet):
        """Return family/protocol/source/destination/ports for a decoded packet."""
        ip_layer = None
        family = 0
        try:
            ip_layer = packet.getlayer(IP)
            if ip_layer is not None:
                family = 4
            else:
                ip_layer = packet.getlayer(IPv6)
                if ip_layer is not None:
                    family = 6
        except Exception:
            ip_layer = None

        if ip_layer is None:
            return None

        src = self._strip_ipv6_zone(str(getattr(ip_layer, "src", "") or ""))
        dst = self._strip_ipv6_zone(str(getattr(ip_layer, "dst", "") or ""))
        protocol = "ip"
        sport = 0
        dport = 0
        try:
            tcp = packet.getlayer(TCP)
            udp = packet.getlayer(UDP)
            if tcp is not None:
                protocol = "tcp"
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
            elif udp is not None:
                protocol = "udp"
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
            elif family == 4 and packet.getlayer(ICMP) is not None:
                protocol = "icmp"
            else:
                for layer in self._iter_layers(packet):
                    if layer.__class__.__name__.startswith("ICMPv6"):
                        protocol = "icmp6"
                        break
        except Exception:
            pass

        return family, protocol, src, sport, dst, dport

    def _normalized_flow_identity(self, packet: Packet):
        endpoints = self._packet_endpoint_tuple(packet)
        if endpoints is None:
            return None
        family, protocol, src, sport, dst, dport = endpoints
        left = (src, int(sport))
        right = (dst, int(dport))
        if left <= right:
            endpoint_a, endpoint_b = left, right
            direction = 0
        else:
            endpoint_a, endpoint_b = right, left
            direction = 1
        canonical = (
            f"ip{family}/{protocol}/"
            f"{endpoint_a[0]}:{endpoint_a[1]}<->{endpoint_b[0]}:{endpoint_b[1]}"
        )
        digest = hashlib.blake2s(
            canonical.encode("utf-8", "replace"),
            digest_size=16,
        ).hexdigest()
        return {
            "id": digest,
            "canonical": canonical,
            "family": family,
            "protocol": protocol,
            "endpoint_a": endpoint_a,
            "endpoint_b": endpoint_b,
            "direction": direction,
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
        }

    def _attach_flow_identity(self, packet: Packet) -> dict | None:
        flow = self._normalized_flow_identity(packet)
        if flow is None:
            return None
        for name, value in (
            ("_flow_id", flow["id"]),
            ("_flow_canonical", flow["canonical"]),
            ("_flow_direction", flow["direction"]),
            ("_flow_family", flow["family"]),
            ("_flow_protocol", flow["protocol"]),
            ("_flow_source", flow["src"]),
            ("_flow_destination", flow["dst"]),
            ("_flow_source_port", flow["sport"]),
            ("_flow_destination_port", flow["dport"]),
        ):
            self._safe_set_packet_attr(packet, name, value)
        return flow

    def _tcp_flags_int(self, tcp: TCP) -> int:
        try:
            return int(tcp.flags)
        except Exception:
            value = 0
            text = str(getattr(tcp, "flags", "") or "")
            for char, bit in {
                "F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
                "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80,
            }.items():
                if char in text:
                    value |= bit
            return value

    def _tcp_options_metadata(self, tcp: TCP) -> dict:
        metadata = {
            "mss": None,
            "window_scale": None,
            "sack_permitted": False,
            "sack_blocks": [],
            "timestamps": None,
            "unknown": [],
        }
        try:
            options = list(getattr(tcp, "options", []) or [])
        except Exception:
            options = []
        for item in options:
            try:
                name, value = item
            except Exception:
                continue
            key = str(name or "").casefold()
            if key == "mss":
                with contextlib.suppress(Exception):
                    metadata["mss"] = int(value)
            elif key in {"wscale", "window scale"}:
                with contextlib.suppress(Exception):
                    metadata["window_scale"] = int(value)
            elif key in {"sackok", "sack permitted"}:
                metadata["sack_permitted"] = True
            elif key == "sack":
                try:
                    values = list(value) if isinstance(value, (list, tuple)) else [value]
                    metadata["sack_blocks"] = [int(v) for v in values]
                except Exception:
                    metadata["sack_blocks"] = []
            elif key in {"timestamp", "timestamps"}:
                try:
                    metadata["timestamps"] = tuple(int(v) for v in value)
                except Exception:
                    metadata["timestamps"] = value
            elif key not in {"nop", "eol"}:
                metadata["unknown"].append((str(name), value))
        return metadata

    def _get_tcp_flow_state(self, flow: dict, timestamp_ns: int) -> _TcpFlowState:
        flow_id = flow["id"]
        with self._flow_state_lock:
            state = self._tcp_flows.get(flow_id)
            if state is None:
                state = _TcpFlowState(
                    flow_id=flow_id,
                    endpoint_a=tuple(flow["endpoint_a"]),
                    endpoint_b=tuple(flow["endpoint_b"]),
                    created_ns=int(timestamp_ns),
                    last_seen_ns=int(timestamp_ns),
                )
                self._tcp_flows[flow_id] = state
            else:
                self._tcp_flows.move_to_end(flow_id)
                state.last_seen_ns = int(timestamp_ns)
            return state

    def _append_stream_tail(self, direction: _TcpDirectionState, payload: bytes) -> None:
        if not payload:
            return
        direction.stream_tail.extend(payload)
        limit = int(self.capture_stream_tail_bytes)
        if len(direction.stream_tail) > limit:
            del direction.stream_tail[:-limit]

    def _remember_recent_tcp_segment(
            self,
            direction: _TcpDirectionState,
            *,
            sequence: int,
            payload: bytes,
    ) -> bool:
        """Return True when the exact segment was already observed."""
        fingerprint = hashlib.blake2s(
            struct.pack("!I", sequence & 0xFFFFFFFF) + payload,
            digest_size=12,
        ).digest()
        duplicate = fingerprint in direction.recent_segments
        direction.recent_segments[fingerprint] = len(payload)
        direction.recent_segments.move_to_end(fingerprint)
        while len(direction.recent_segments) > 4096:
            direction.recent_segments.popitem(last=False)
        return duplicate

    def _trim_pending_tcp_segments(self, direction: _TcpDirectionState) -> None:
        limit = int(self.capture_stream_pending_bytes)
        if direction.pending_bytes <= limit:
            return
        # Drop the farthest-ahead segments first; data nearest next_sequence is
        # most likely to become useful soon.
        ordered = sorted(direction.pending, reverse=True)
        for sequence in ordered:
            segment = direction.pending.pop(sequence, None)
            if segment is None:
                continue
            direction.pending_bytes = max(
                0, direction.pending_bytes - len(segment.payload)
            )
            if direction.pending_bytes <= limit:
                break

    def _flush_pending_tcp_segments(self, direction: _TcpDirectionState) -> int:
        flushed = 0
        while direction.next_sequence is not None:
            next_seq = int(direction.next_sequence)
            exact = direction.pending.pop(next_seq, None)
            if exact is not None:
                direction.pending_bytes = max(
                    0, direction.pending_bytes - len(exact.payload)
                )
                self._append_stream_tail(direction, exact.payload)
                direction.contiguous_total += len(exact.payload)
                direction.next_sequence = (
                    next_seq + len(exact.payload)
                ) & 0xFFFFFFFF
                flushed += len(exact.payload)
                continue

            # A pending segment may begin before next_sequence and overlap it.
            overlap_key = None
            for sequence, segment in direction.pending.items():
                end = sequence + len(segment.payload)
                if sequence < next_seq < end:
                    overlap_key = sequence
                    break
            if overlap_key is None:
                break
            segment = direction.pending.pop(overlap_key)
            direction.pending_bytes = max(
                0, direction.pending_bytes - len(segment.payload)
            )
            skip = next_seq - overlap_key
            unseen = segment.payload[skip:]
            direction.overlap_segments += 1
            direction.overlap_bytes += max(0, skip)
            if unseen:
                self._append_stream_tail(direction, unseen)
                direction.contiguous_total += len(unseen)
                direction.next_sequence = (
                    next_seq + len(unseen)
                ) & 0xFFFFFFFF
                flushed += len(unseen)
        return flushed

    def _update_tcp_reassembly(
            self,
            packet: Packet,
            flow: dict,
            timestamp_ns: int,
    ) -> dict | None:
        tcp = packet.getlayer(TCP)
        if tcp is None:
            return None

        state = self._get_tcp_flow_state(flow, timestamp_ns)
        direction_id = int(flow["direction"])
        direction = state.directions[direction_id]
        flags = self._tcp_flags_int(tcp)
        sequence = int(getattr(tcp, "seq", 0) or 0) & 0xFFFFFFFF
        acknowledgement = int(getattr(tcp, "ack", 0) or 0) & 0xFFFFFFFF
        payload = self._payload_bytes(packet)
        syn_consumed = 1 if flags & 0x02 else 0
        data_sequence = (sequence + syn_consumed) & 0xFFFFFFFF

        with self._flow_state_lock:
            state.packet_count += 1
            state.payload_bytes += len(payload)
            state.last_seen_ns = int(timestamp_ns)
            direction.last_seen_ns = int(timestamp_ns)
            direction.observed_payload_total += len(payload)
            direction.syn_seen = direction.syn_seen or bool(flags & 0x02)
            direction.fin_seen = direction.fin_seen or bool(flags & 0x01)
            direction.rst_seen = direction.rst_seen or bool(flags & 0x04)
            direction.last_ack = acknowledgement
            direction.last_window = int(getattr(tcp, "window", 0) or 0)
            if flags & (0x01 | 0x04):
                state.closed = True

            duplicate_exact = self._remember_recent_tcp_segment(
                direction, sequence=data_sequence, payload=payload
            ) if payload else False

            if direction.initial_sequence is None:
                direction.initial_sequence = data_sequence
            if direction.next_sequence is None:
                direction.next_sequence = data_sequence

            classification = "ack-only"
            accepted_bytes = 0
            flushed_bytes = 0
            gap = 0
            overlap = 0

            if payload:
                next_sequence = int(direction.next_sequence)
                if duplicate_exact:
                    direction.duplicate_segments += 1

                if data_sequence == next_sequence:
                    classification = "contiguous"
                    self._append_stream_tail(direction, payload)
                    accepted_bytes = len(payload)
                    direction.contiguous_total += len(payload)
                    direction.next_sequence = (
                        next_sequence + len(payload)
                    ) & 0xFFFFFFFF
                    flushed_bytes = self._flush_pending_tcp_segments(direction)

                elif data_sequence < next_sequence:
                    overlap = next_sequence - data_sequence
                    direction.retransmission_segments += 1
                    direction.retransmission_bytes += min(overlap, len(payload))
                    if overlap >= len(payload):
                        classification = "retransmission"
                    else:
                        classification = "overlap-new-tail"
                        direction.overlap_segments += 1
                        direction.overlap_bytes += overlap
                        unseen = payload[overlap:]
                        self._append_stream_tail(direction, unseen)
                        accepted_bytes = len(unseen)
                        direction.contiguous_total += len(unseen)
                        direction.next_sequence = (
                            next_sequence + len(unseen)
                        ) & 0xFFFFFFFF
                        flushed_bytes = self._flush_pending_tcp_segments(direction)

                else:
                    classification = "out-of-order"
                    gap = data_sequence - next_sequence
                    direction.out_of_order_segments += 1
                    direction.sequence_gap_events += 1
                    direction.largest_gap = max(direction.largest_gap, gap)
                    existing = direction.pending.get(data_sequence)
                    if existing is None or len(payload) > len(existing.payload):
                        if existing is not None:
                            direction.pending_bytes = max(
                                0,
                                direction.pending_bytes - len(existing.payload),
                            )
                        direction.pending[data_sequence] = _PendingTcpSegment(
                            sequence=data_sequence,
                            payload=bytes(payload),
                            timestamp_ns=int(timestamp_ns),
                            flags=flags,
                        )
                        direction.pending_bytes += len(payload)
                        self._trim_pending_tcp_segments(direction)

            snapshot = {
                "flow_id": state.flow_id,
                "direction": direction_id,
                "classification": classification,
                "sequence": sequence,
                "data_sequence": data_sequence,
                "acknowledgement": acknowledgement,
                "flags": flags,
                "payload_bytes": len(payload),
                "accepted_contiguous_bytes": accepted_bytes,
                "flushed_pending_bytes": flushed_bytes,
                "gap_bytes": gap,
                "overlap_bytes": overlap,
                "next_sequence": direction.next_sequence,
                "initial_sequence": direction.initial_sequence,
                "contiguous_total": direction.contiguous_total,
                "observed_payload_total": direction.observed_payload_total,
                "retransmission_segments": direction.retransmission_segments,
                "retransmission_bytes": direction.retransmission_bytes,
                "overlap_segments": direction.overlap_segments,
                "overlap_total_bytes": direction.overlap_bytes,
                "duplicate_segments": direction.duplicate_segments,
                "out_of_order_segments": direction.out_of_order_segments,
                "sequence_gap_events": direction.sequence_gap_events,
                "largest_gap": direction.largest_gap,
                "pending_segments": len(direction.pending),
                "pending_bytes": direction.pending_bytes,
                "syn_seen": direction.syn_seen,
                "fin_seen": direction.fin_seen,
                "rst_seen": direction.rst_seen,
                "flow_closed": state.closed,
                "tcp_options": self._tcp_options_metadata(tcp),
            }
            stream_tail = bytes(direction.stream_tail)

        self._safe_set_packet_attr(packet, "_tcp_stream", snapshot)
        self._safe_set_packet_attr(packet, "_tcp_stream_tail", stream_tail)
        self._safe_set_packet_attr(packet, "_tcp_stream_tail_length", len(stream_tail))
        return snapshot

    def _track_ip_fragments(self, packet: Packet, timestamp_ns: int) -> dict | None:
        key = None
        offset = 0
        more_fragments = False
        payload_len = 0
        family = 0

        ip4 = packet.getlayer(IP)
        if ip4 is not None:
            try:
                offset = int(getattr(ip4, "frag", 0) or 0) * 8
                flags = int(getattr(ip4, "flags", 0) or 0)
                more_fragments = bool(flags & 0x01)
                if not offset and not more_fragments:
                    return None
                family = 4
                key = (
                    4,
                    str(ip4.src),
                    str(ip4.dst),
                    int(getattr(ip4, "id", 0) or 0),
                    int(getattr(ip4, "proto", 0) or 0),
                )
                payload_len = max(
                    0,
                    int(getattr(ip4, "len", len(bytes(ip4))) or len(bytes(ip4)))
                    - int(getattr(ip4, "ihl", 5) or 5) * 4,
                )
            except Exception:
                return None
        else:
            frag6 = packet.getlayer(IPv6ExtHdrFragment)
            ip6 = packet.getlayer(IPv6)
            if frag6 is None or ip6 is None:
                return None
            try:
                offset = int(getattr(frag6, "offset", 0) or 0) * 8
                more_fragments = bool(int(getattr(frag6, "m", 0) or 0))
                family = 6
                key = (
                    6,
                    str(ip6.src),
                    str(ip6.dst),
                    int(getattr(frag6, "id", 0) or 0),
                    int(getattr(frag6, "nh", 0) or 0),
                )
                payload_len = len(bytes(getattr(frag6, "payload", b"")))
            except Exception:
                return None

        with self._flow_state_lock:
            state = self._fragment_sets.get(key)
            if state is None:
                state = _FragmentState(
                    key=key,
                    created_ns=int(timestamp_ns),
                    last_seen_ns=int(timestamp_ns),
                )
                self._fragment_sets[key] = state
            else:
                self._fragment_sets.move_to_end(key)
            state.last_seen_ns = int(timestamp_ns)
            state.fragments += 1
            state.bytes_observed += payload_len
            state.offsets.add(offset)
            if not more_fragments:
                state.final_offset = offset + payload_len
            metadata = {
                "family": family,
                "key": tuple(key),
                "offset": offset,
                "more_fragments": more_fragments,
                "payload_bytes": payload_len,
                "fragments_seen": state.fragments,
                "bytes_observed": state.bytes_observed,
                "offsets_seen": sorted(state.offsets)[:256],
                "expected_end": state.final_offset,
                "appears_complete": (
                    state.final_offset is not None
                    and 0 in state.offsets
                ),
            }
        self._safe_set_packet_attr(packet, "_fragment_metadata", metadata)
        return metadata

    def _cleanup_capture_state(self, timestamp_ns: int) -> None:
        if timestamp_ns - self._last_flow_cleanup_ns < 5_000_000_000:
            return
        self._last_flow_cleanup_ns = int(timestamp_ns)
        tcp_cutoff = timestamp_ns - int(self.capture_tcp_flow_idle_sec * 1e9)
        frag_cutoff = timestamp_ns - int(self.capture_fragment_idle_sec * 1e9)

        with self._flow_state_lock:
            stale_tcp = [
                key for key, state in self._tcp_flows.items()
                if state.last_seen_ns < tcp_cutoff
            ]
            for key in stale_tcp:
                self._tcp_flows.pop(key, None)
            while len(self._tcp_flows) > self.capture_max_tcp_flows:
                self._tcp_flows.popitem(last=False)

            stale_fragments = [
                key for key, state in self._fragment_sets.items()
                if state.last_seen_ns < frag_cutoff
            ]
            for key in stale_fragments:
                self._fragment_sets.pop(key, None)
            while len(self._fragment_sets) > self.capture_max_fragment_sets:
                self._fragment_sets.popitem(last=False)



    # -------------------------------------------------------------------------
    # Application-protocol recognition for high-value packet/stream metadata
    # -------------------------------------------------------------------------
    @staticmethod
    def _u16(data: bytes, offset: int) -> tuple[int, int]:
        if offset + 2 > len(data):
            raise ValueError("short u16")
        return struct.unpack_from("!H", data, offset)[0], offset + 2

    @staticmethod
    def _u24(data: bytes, offset: int) -> tuple[int, int]:
        if offset + 3 > len(data):
            raise ValueError("short u24")
        value = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
        return value, offset + 3

    @staticmethod
    def _is_grease_value(value: int) -> bool:
        return (value & 0x0F0F) == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)

    def _parse_tls_extensions(self, data: bytes) -> dict:
        offset = 0
        extension_ids = []
        server_names = []
        alpns = []
        supported_versions = []
        supported_groups = []
        ec_point_formats = []
        signature_algorithms = []
        key_share_groups = []
        raw_lengths = {}

        while offset + 4 <= len(data):
            ext_type = struct.unpack_from("!H", data, offset)[0]
            ext_len = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
            if offset + ext_len > len(data):
                break
            body = data[offset:offset + ext_len]
            offset += ext_len
            extension_ids.append(ext_type)
            raw_lengths[ext_type] = ext_len

            try:
                if ext_type == 0 and len(body) >= 2:
                    list_len = struct.unpack_from("!H", body, 0)[0]
                    pos = 2
                    limit = min(len(body), 2 + list_len)
                    while pos + 3 <= limit:
                        name_type = body[pos]
                        name_len = struct.unpack_from("!H", body, pos + 1)[0]
                        pos += 3
                        if pos + name_len > limit:
                            break
                        name = body[pos:pos + name_len].decode("idna", "replace")
                        pos += name_len
                        if name_type == 0 and name:
                            server_names.append(name)

                elif ext_type == 16 and len(body) >= 2:
                    list_len = struct.unpack_from("!H", body, 0)[0]
                    pos = 2
                    limit = min(len(body), 2 + list_len)
                    while pos < limit:
                        item_len = body[pos]
                        pos += 1
                        if pos + item_len > limit:
                            break
                        value = body[pos:pos + item_len].decode("ascii", "replace")
                        pos += item_len
                        if value:
                            alpns.append(value)

                elif ext_type == 43:
                    if len(body) == 2:
                        supported_versions.append(struct.unpack_from("!H", body, 0)[0])
                    elif body:
                        list_len = body[0]
                        pos = 1
                        limit = min(len(body), 1 + list_len)
                        while pos + 2 <= limit:
                            supported_versions.append(
                                struct.unpack_from("!H", body, pos)[0]
                            )
                            pos += 2

                elif ext_type == 10 and len(body) >= 2:
                    list_len = struct.unpack_from("!H", body, 0)[0]
                    pos = 2
                    limit = min(len(body), 2 + list_len)
                    while pos + 2 <= limit:
                        supported_groups.append(struct.unpack_from("!H", body, pos)[0])
                        pos += 2

                elif ext_type == 11 and body:
                    list_len = body[0]
                    ec_point_formats.extend(int(v) for v in body[1:1 + list_len])

                elif ext_type == 13 and len(body) >= 2:
                    list_len = struct.unpack_from("!H", body, 0)[0]
                    pos = 2
                    limit = min(len(body), 2 + list_len)
                    while pos + 2 <= limit:
                        signature_algorithms.append(
                            struct.unpack_from("!H", body, pos)[0]
                        )
                        pos += 2

                elif ext_type == 51:
                    # ClientHello has a two-byte vector length; ServerHello has
                    # one selected group followed by a key length.
                    pos = 0
                    if len(body) >= 2:
                        possible_vector = struct.unpack_from("!H", body, 0)[0]
                        if possible_vector + 2 == len(body):
                            pos = 2
                            limit = len(body)
                            while pos + 4 <= limit:
                                group = struct.unpack_from("!H", body, pos)[0]
                                key_len = struct.unpack_from("!H", body, pos + 2)[0]
                                pos += 4
                                if pos + key_len > limit:
                                    break
                                key_share_groups.append(group)
                                pos += key_len
                        else:
                            key_share_groups.append(
                                struct.unpack_from("!H", body, 0)[0]
                            )
            except Exception:
                continue

        return {
            "extension_ids": extension_ids,
            "server_names": server_names,
            "alpn": alpns,
            "supported_versions": supported_versions,
            "supported_groups": supported_groups,
            "ec_point_formats": ec_point_formats,
            "signature_algorithms": signature_algorithms,
            "key_share_groups": key_share_groups,
            "extension_lengths": raw_lengths,
        }

    def _parse_tls_client_hello(self, body: bytes) -> dict | None:
        try:
            if len(body) < 34:
                return None
            offset = 0
            legacy_version, offset = self._u16(body, offset)
            random_bytes = body[offset:offset + 32]
            offset += 32
            session_len = body[offset]
            offset += 1
            if offset + session_len > len(body):
                return None
            session_id = body[offset:offset + session_len]
            offset += session_len

            cipher_len, offset = self._u16(body, offset)
            if cipher_len % 2 or offset + cipher_len > len(body):
                return None
            ciphers = [
                struct.unpack_from("!H", body, pos)[0]
                for pos in range(offset, offset + cipher_len, 2)
            ]
            offset += cipher_len

            if offset >= len(body):
                return None
            compression_len = body[offset]
            offset += 1
            if offset + compression_len > len(body):
                return None
            compression_methods = list(body[offset:offset + compression_len])
            offset += compression_len

            extensions = {
                "extension_ids": [],
                "server_names": [],
                "alpn": [],
                "supported_versions": [],
                "supported_groups": [],
                "ec_point_formats": [],
                "signature_algorithms": [],
                "key_share_groups": [],
                "extension_lengths": {},
            }
            if offset + 2 <= len(body):
                extension_len, offset = self._u16(body, offset)
                extension_data = body[offset:min(len(body), offset + extension_len)]
                extensions = self._parse_tls_extensions(extension_data)

            clean_ciphers = [v for v in ciphers if not self._is_grease_value(v)]
            clean_extensions = [
                v for v in extensions["extension_ids"]
                if not self._is_grease_value(v)
            ]
            clean_groups = [
                v for v in extensions["supported_groups"]
                if not self._is_grease_value(v)
            ]
            ja3_string = ",".join((
                str(legacy_version),
                "-".join(str(v) for v in clean_ciphers),
                "-".join(str(v) for v in clean_extensions),
                "-".join(str(v) for v in clean_groups),
                "-".join(str(v) for v in extensions["ec_point_formats"]),
            ))

            return {
                "handshake": "client_hello",
                "legacy_version": legacy_version,
                "random_sha256": hashlib.sha256(random_bytes).hexdigest(),
                "session_id_length": len(session_id),
                "cipher_suites": ciphers,
                "compression_methods": compression_methods,
                "sni": extensions["server_names"],
                "alpn": extensions["alpn"],
                "supported_versions": extensions["supported_versions"],
                "supported_groups": extensions["supported_groups"],
                "signature_algorithms": extensions["signature_algorithms"],
                "key_share_groups": extensions["key_share_groups"],
                "extension_ids": extensions["extension_ids"],
                "ja3_string": ja3_string,
                "ja3": hashlib.md5(
                    ja3_string.encode("ascii", "ignore")
                ).hexdigest(),
            }
        except Exception:
            return None

    def _parse_tls_server_hello(self, body: bytes) -> dict | None:
        try:
            if len(body) < 38:
                return None
            offset = 0
            legacy_version, offset = self._u16(body, offset)
            random_bytes = body[offset:offset + 32]
            offset += 32
            session_len = body[offset]
            offset += 1
            if offset + session_len + 3 > len(body):
                return None
            session_id = body[offset:offset + session_len]
            offset += session_len
            cipher_suite, offset = self._u16(body, offset)
            compression_method = body[offset]
            offset += 1

            extensions = {
                "extension_ids": [],
                "server_names": [],
                "alpn": [],
                "supported_versions": [],
                "supported_groups": [],
                "ec_point_formats": [],
                "signature_algorithms": [],
                "key_share_groups": [],
                "extension_lengths": {},
            }
            if offset + 2 <= len(body):
                extension_len, offset = self._u16(body, offset)
                extension_data = body[offset:min(len(body), offset + extension_len)]
                extensions = self._parse_tls_extensions(extension_data)

            clean_extensions = [
                v for v in extensions["extension_ids"]
                if not self._is_grease_value(v)
            ]
            ja3s_string = ",".join((
                str(legacy_version),
                str(cipher_suite),
                "-".join(str(v) for v in clean_extensions),
            ))
            selected_version = (
                extensions["supported_versions"][0]
                if extensions["supported_versions"]
                else legacy_version
            )
            return {
                "handshake": "server_hello",
                "legacy_version": legacy_version,
                "selected_version": selected_version,
                "random_sha256": hashlib.sha256(random_bytes).hexdigest(),
                "session_id_length": len(session_id),
                "cipher_suite": cipher_suite,
                "compression_method": compression_method,
                "alpn": extensions["alpn"],
                "extension_ids": extensions["extension_ids"],
                "key_share_groups": extensions["key_share_groups"],
                "ja3s_string": ja3s_string,
                "ja3s": hashlib.md5(
                    ja3s_string.encode("ascii", "ignore")
                ).hexdigest(),
            }
        except Exception:
            return None

    def _parse_tls_records(self, data: bytes, max_records: int = 32) -> dict | None:
        if len(data) < 5:
            return None
        offset = 0
        records = []
        handshakes = []
        recognized = False

        while offset + 5 <= len(data) and len(records) < max_records:
            content_type = data[offset]
            version = struct.unpack_from("!H", data, offset + 1)[0]
            length = struct.unpack_from("!H", data, offset + 3)[0]
            if content_type not in {20, 21, 22, 23, 24}:
                break
            if version < 0x0300 or version > 0x0304:
                break
            recognized = True
            complete = offset + 5 + length <= len(data)
            record_payload = data[offset + 5:min(len(data), offset + 5 + length)]
            records.append({
                "content_type": content_type,
                "legacy_version": version,
                "length": length,
                "complete": complete,
            })
            if content_type == 22:
                hpos = 0
                while hpos + 4 <= len(record_payload) and len(handshakes) < 64:
                    handshake_type = record_payload[hpos]
                    handshake_len = (
                        (record_payload[hpos + 1] << 16)
                        | (record_payload[hpos + 2] << 8)
                        | record_payload[hpos + 3]
                    )
                    hpos += 4
                    available = min(
                        len(record_payload) - hpos,
                        handshake_len,
                    )
                    body = record_payload[hpos:hpos + available]
                    item = {
                        "type": handshake_type,
                        "length": handshake_len,
                        "complete": available == handshake_len,
                    }
                    if handshake_type == 1:
                        parsed = self._parse_tls_client_hello(body)
                        if parsed:
                            item.update(parsed)
                    elif handshake_type == 2:
                        parsed = self._parse_tls_server_hello(body)
                        if parsed:
                            item.update(parsed)
                    elif handshake_type == 11:
                        item["handshake"] = "certificate"
                    elif handshake_type == 8:
                        item["handshake"] = "encrypted_extensions"
                    elif handshake_type == 4:
                        item["handshake"] = "new_session_ticket"
                    elif handshake_type == 20:
                        item["handshake"] = "finished"
                    handshakes.append(item)
                    hpos += available
                    if available < handshake_len:
                        break
            offset += 5 + length
            if not complete:
                break

        if not recognized:
            return None
        client_hellos = [
            item for item in handshakes
            if item.get("handshake") == "client_hello"
        ]
        server_hellos = [
            item for item in handshakes
            if item.get("handshake") == "server_hello"
        ]
        return {
            "protocol": "tls",
            "records": records,
            "handshakes": handshakes,
            "client_hello": client_hellos[-1] if client_hellos else None,
            "server_hello": server_hellos[-1] if server_hellos else None,
            "bytes_consumed": min(offset, len(data)),
            "stream_bytes_available": len(data),
        }

    def _quic_varint(self, data: bytes, offset: int) -> tuple[int, int]:
        if offset >= len(data):
            raise ValueError("short QUIC varint")
        first = data[offset]
        width = 1 << (first >> 6)
        if offset + width > len(data):
            raise ValueError("short QUIC varint body")
        value = first & 0x3F
        for byte in data[offset + 1:offset + width]:
            value = (value << 8) | byte
        return value, offset + width

    def _parse_quic_header(self, data: bytes) -> dict | None:
        if len(data) < 5:
            return None
        first = data[0]
        if not (first & 0x40):
            return None

        # Long header: version and both connection IDs are visible without
        # decrypting Initial/Handshake payloads.
        if first & 0x80:
            try:
                version = struct.unpack_from("!I", data, 1)[0]
                offset = 5
                dcid_len = data[offset]
                offset += 1
                if dcid_len > 20 or offset + dcid_len > len(data):
                    return None
                dcid = data[offset:offset + dcid_len]
                offset += dcid_len
                if offset >= len(data):
                    return None
                scid_len = data[offset]
                offset += 1
                if scid_len > 20 or offset + scid_len > len(data):
                    return None
                scid = data[offset:offset + scid_len]
                offset += scid_len

                packet_type_code = (first >> 4) & 0x03
                packet_type = {
                    0: "initial",
                    1: "0-rtt",
                    2: "handshake",
                    3: "retry",
                }.get(packet_type_code, "unknown")
                if version == 0:
                    packet_type = "version-negotiation"

                metadata = {
                    "protocol": "quic",
                    "header_form": "long",
                    "fixed_bit": bool(first & 0x40),
                    "version": version,
                    "version_hex": f"0x{version:08x}",
                    "packet_type": packet_type,
                    "dcid": dcid.hex(),
                    "dcid_length": len(dcid),
                    "scid": scid.hex(),
                    "scid_length": len(scid),
                    "header_bytes_observed": offset,
                }

                if version != 0 and packet_type == "initial":
                    token_len, pos = self._quic_varint(data, offset)
                    if pos + token_len <= len(data):
                        metadata["token_length"] = token_len
                        metadata["token_sha256"] = (
                            hashlib.sha256(
                                data[pos:pos + token_len]
                            ).hexdigest()
                            if token_len
                            else None
                        )
                        pos += token_len
                        packet_len, pos = self._quic_varint(data, pos)
                        metadata["declared_payload_length"] = packet_len
                        metadata["packet_number_length"] = (first & 0x03) + 1
                        metadata["protected_payload_offset"] = pos
                elif version == 0:
                    versions = []
                    pos = offset
                    while pos + 4 <= len(data):
                        versions.append(struct.unpack_from("!I", data, pos)[0])
                        pos += 4
                    metadata["offered_versions"] = versions
                return metadata
            except Exception:
                return None

        # Short headers do not expose the destination connection-ID length.
        return {
            "protocol": "quic",
            "header_form": "short",
            "fixed_bit": True,
            "spin_bit": bool(first & 0x20),
            "key_phase": bool(first & 0x04),
            "packet_number_length": (first & 0x03) + 1,
        }

    def _json_objects_from_bytes(self, data: bytes, max_objects: int = 32) -> list:
        if not data:
            return []
        text = data.decode("utf-8", "replace")
        objects = []
        decoder = json.JSONDecoder()

        for line in text.replace("\x00", "\n").splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            # Strip common HTTP chunk-size lines and JSON-RPC framing noise.
            if re.fullmatch(r"[0-9a-fA-F]{1,8}", candidate):
                continue
            starts = [
                index for index, char in enumerate(candidate)
                if char in "[{"
            ]
            for start in starts[:4]:
                try:
                    value, _end = decoder.raw_decode(candidate[start:])
                except Exception:
                    continue
                if isinstance(value, (dict, list)):
                    objects.append(value)
                    break
            if len(objects) >= max_objects:
                break
        return objects

    def _redact_json_value(self, key: str, value):
        key_cf = str(key or "").casefold()
        if any(token in key_cf for token in (
            "password", "passwd", "pass", "token", "secret",
            "authorization", "cookie", "private_key",
        )):
            raw = str(value).encode("utf-8", "replace")
            return {
                "redacted": True,
                "length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        if isinstance(value, dict):
            return {
                str(k): self._redact_json_value(str(k), v)
                for k, v in list(value.items())[:64]
            }
        if isinstance(value, list):
            return [
                self._redact_json_value(key, item)
                for item in value[:64]
            ]
        if isinstance(value, str) and len(value) > 512:
            return value[:512] + "…"
        return value

    def _parse_json_rpc_and_stratum(self, data: bytes) -> dict | None:
        objects = self._json_objects_from_bytes(data)
        if not objects:
            return None
        messages = []
        stratum = False
        methods = []
        for value in objects:
            if isinstance(value, dict):
                method = str(value.get("method") or "").strip()
                command = str(value.get("command") or "").strip()
                kind = method or command
                if kind:
                    methods.append(kind)
                lower_kind = kind.casefold()
                if (
                    lower_kind in self._stratum_method_names
                    or lower_kind.startswith("mining.")
                    or {"login", "pass", "agent"}.intersection(
                        str(k).casefold() for k in value.keys()
                    )
                ):
                    stratum = True
                messages.append(
                    self._redact_json_value("", value)
                )
            else:
                messages.append(value[:64] if isinstance(value, list) else value)

        protocol = "stratum-json-rpc" if stratum else "json-rpc"
        return {
            "protocol": protocol,
            "message_count": len(messages),
            "methods": methods,
            "messages": messages,
        }

    def _parse_http_headers(self, data: bytes) -> dict | None:
        if not data:
            return None
        head_end = data.find(b"\r\n\r\n")
        separator = 4
        if head_end < 0:
            head_end = data.find(b"\n\n")
            separator = 2
        if head_end < 0:
            head_end = min(len(data), 16384)
            separator = 0
        head = data[:head_end]
        try:
            text = head.decode("iso-8859-1", "replace")
        except Exception:
            return None
        lines = text.splitlines()
        if not lines:
            return None
        first = lines[0].strip()
        request_match = re.match(
            r"^([A-Z]{3,12})\s+(\S+)\s+HTTP/(\d\.\d)$",
            first,
        )
        response_match = re.match(
            r"^HTTP/(\d\.\d)\s+(\d{3})(?:\s+(.*))?$",
            first,
        )
        if not request_match and not response_match:
            return None

        headers = {}
        current_name = None
        for line in lines[1:]:
            if line[:1] in {" ", "\t"} and current_name:
                headers[current_name] += " " + line.strip()
                continue
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            current_name = name.strip().casefold()
            clean_value = value.strip()
            if current_name in {
                "authorization", "proxy-authorization", "cookie", "set-cookie",
            }:
                raw = clean_value.encode("utf-8", "replace")
                clean_value = (
                    f"<redacted len={len(raw)} "
                    f"sha256={hashlib.sha256(raw).hexdigest()}>"
                )
            headers[current_name] = clean_value[:4096]

        result = {
            "protocol": "http",
            "headers": headers,
            "header_complete": separator > 0,
            "body_bytes_available": (
                max(0, len(data) - head_end - separator)
                if separator
                else 0
            ),
        }
        if request_match:
            result.update({
                "message_type": "request",
                "method": request_match.group(1),
                "target": request_match.group(2)[:4096],
                "version": request_match.group(3),
                "host": headers.get("host"),
                "user_agent": headers.get("user-agent"),
            })
        else:
            result.update({
                "message_type": "response",
                "version": response_match.group(1),
                "status": int(response_match.group(2)),
                "reason": (response_match.group(3) or "")[:512],
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
            })
        return result

    def _parse_dns_metadata(self, packet: Packet) -> dict | None:
        dns = packet.getlayer(DNS)
        if dns is None:
            return None

        def _name(value) -> str:
            if isinstance(value, bytes):
                return value.rstrip(b".").decode("idna", "replace")
            return str(value or "").rstrip(".")

        questions = []
        answers = []
        try:
            qd = dns.qd
            for index in range(min(int(getattr(dns, "qdcount", 0) or 0), 64)):
                item = qd[index] if hasattr(qd, "__getitem__") else qd
                if item is None:
                    break
                questions.append({
                    "name": _name(getattr(item, "qname", "")),
                    "type": int(getattr(item, "qtype", 0) or 0),
                    "class": int(getattr(item, "qclass", 0) or 0),
                })
                qd = getattr(item, "payload", None)
        except Exception:
            pass
        try:
            rr = dns.an
            for index in range(min(int(getattr(dns, "ancount", 0) or 0), 128)):
                item = rr[index] if hasattr(rr, "__getitem__") else rr
                if item is None:
                    break
                rdata = getattr(item, "rdata", None)
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", "replace")
                answers.append({
                    "name": _name(getattr(item, "rrname", "")),
                    "type": int(getattr(item, "type", 0) or 0),
                    "class": int(getattr(item, "rclass", 0) or 0),
                    "ttl": int(getattr(item, "ttl", 0) or 0),
                    "rdata": str(rdata)[:2048],
                })
                rr = getattr(item, "payload", None)
        except Exception:
            pass
        return {
            "protocol": "dns",
            "id": int(getattr(dns, "id", 0) or 0),
            "response": bool(int(getattr(dns, "qr", 0) or 0)),
            "opcode": int(getattr(dns, "opcode", 0) or 0),
            "rcode": int(getattr(dns, "rcode", 0) or 0),
            "truncated": bool(int(getattr(dns, "tc", 0) or 0)),
            "questions": questions,
            "answers": answers,
        }

    def _parse_dhcp_metadata(self, packet: Packet) -> dict | None:
        dhcp = packet.getlayer(DHCP)
        bootp = packet.getlayer(BOOTP)
        if dhcp is None and bootp is None:
            if packet.getlayer(DHCP6) is not None:
                return {
                    "protocol": "dhcpv6",
                    "message_class": packet.getlayer(DHCP6).__class__.__name__,
                }
            return None
        options = {}
        if dhcp is not None:
            for option in list(getattr(dhcp, "options", []) or []):
                if isinstance(option, tuple) and option:
                    key = str(option[0])
                    value = option[1] if len(option) == 2 else option[1:]
                    if isinstance(value, bytes):
                        value = value.hex()
                    options[key] = value
        result = {
            "protocol": "dhcpv4",
            "options": options,
        }
        if bootp is not None:
            result.update({
                "operation": int(getattr(bootp, "op", 0) or 0),
                "xid": int(getattr(bootp, "xid", 0) or 0),
                "client_ip": str(getattr(bootp, "ciaddr", "") or ""),
                "your_ip": str(getattr(bootp, "yiaddr", "") or ""),
                "server_ip": str(getattr(bootp, "siaddr", "") or ""),
                "gateway_ip": str(getattr(bootp, "giaddr", "") or ""),
                "client_mac": str(getattr(bootp, "chaddr", b"") or b"")[:64],
            })
        return result

    def _parse_ssh_banner(self, data: bytes) -> dict | None:
        if not data.startswith(b"SSH-"):
            return None
        line = data.splitlines()[0][:512].decode("ascii", "replace")
        parts = line.split("-", 2)
        return {
            "protocol": "ssh",
            "banner": line,
            "protocol_version": parts[1] if len(parts) > 1 else "",
            "software": parts[2] if len(parts) > 2 else "",
        }

    def _parse_protocol_metadata(
            self,
            packet: Packet,
            *,
            payload: bytes,
            stream_tail: bytes,
    ) -> dict:
        metadata = {}
        candidates = []
        if stream_tail:
            candidates.append(("stream", stream_tail))
        if payload and payload != stream_tail:
            candidates.append(("packet", payload))

        dns = self._parse_dns_metadata(packet)
        if dns:
            metadata["dns"] = dns
        dhcp = self._parse_dhcp_metadata(packet)
        if dhcp:
            metadata["dhcp"] = dhcp

        udp = packet.getlayer(UDP)
        tcp = packet.getlayer(TCP)
        for source_name, data in candidates:
            if not data:
                continue
            if "tls" not in metadata:
                tls = self._parse_tls_records(data)
                if tls:
                    tls["source"] = source_name
                    metadata["tls"] = tls
            if "stratum" not in metadata and "json_rpc" not in metadata:
                parsed_json = self._parse_json_rpc_and_stratum(data)
                if parsed_json:
                    parsed_json["source"] = source_name
                    if parsed_json["protocol"] == "stratum-json-rpc":
                        metadata["stratum"] = parsed_json
                    else:
                        metadata["json_rpc"] = parsed_json
            if "http" not in metadata:
                http = self._parse_http_headers(data)
                if http:
                    http["source"] = source_name
                    metadata["http"] = http
            if "ssh" not in metadata:
                ssh = self._parse_ssh_banner(data)
                if ssh:
                    ssh["source"] = source_name
                    metadata["ssh"] = ssh

        if udp is not None and payload:
            sport = int(getattr(udp, "sport", 0) or 0)
            dport = int(getattr(udp, "dport", 0) or 0)
            if sport == 443 or dport == 443 or payload[0] & 0x40:
                quic = self._parse_quic_header(payload)
                if quic:
                    metadata["quic"] = quic

        if tcp is not None:
            metadata["tcp"] = {
                "flags": self._tcp_flags_int(tcp),
                "sequence": int(getattr(tcp, "seq", 0) or 0),
                "acknowledgement": int(getattr(tcp, "ack", 0) or 0),
                "window": int(getattr(tcp, "window", 0) or 0),
                "options": self._tcp_options_metadata(tcp),
            }
        return metadata

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = collections.Counter(data)
        length = float(len(data))
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return round(entropy, 5)

    def _capture_priority(
            self,
            packet: Packet,
            metadata: dict,
            *,
            payload: bytes,
            capture_complete: bool,
    ) -> tuple[int, str, list]:
        score = 0
        reasons = []
        flow = self._packet_endpoint_tuple(packet)
        if capture_complete:
            score += 5
            reasons.append("complete-frame")
        if payload:
            score += min(20, 4 + len(payload) // 256)
            reasons.append("application-payload")
        if flow:
            _family, protocol, _src, sport, _dst, dport = flow
            if protocol == "tcp" and (
                sport in self._high_value_tcp_ports
                or dport in self._high_value_tcp_ports
            ):
                score += 15
                reasons.append("high-value-tcp-port")
            if protocol == "udp" and (
                sport in self._high_value_udp_ports
                or dport in self._high_value_udp_ports
            ):
                score += 12
                reasons.append("high-value-udp-port")

        weights = {
            "stratum": 45,
            "tls": 35,
            "quic": 30,
            "dns": 20,
            "dhcp": 20,
            "http": 20,
            "ssh": 20,
            "json_rpc": 18,
            "tcp": 4,
        }
        for name, weight in weights.items():
            if name in metadata:
                score += weight
                reasons.append(name)

        tcp = packet.getlayer(TCP)
        if tcp is not None:
            flags = self._tcp_flags_int(tcp)
            if flags & 0x02:
                score += 8
                reasons.append("tcp-syn")
            if flags & 0x04:
                score += 8
                reasons.append("tcp-rst")
            if flags & 0x01:
                score += 4
                reasons.append("tcp-fin")

        if score >= 70:
            priority = "critical"
        elif score >= 45:
            priority = "high"
        elif score >= 20:
            priority = "elevated"
        else:
            priority = "normal"
        return score, priority, list(dict.fromkeys(reasons))

    def _enrich_captured_packet(
            self,
            packet: Packet,
            *,
            raw_packet: bytes,
            meta: dict,
            iface: str,
            dlt: int,
            pkthdr_ptr=None,
    ) -> Packet:
        host_arrival_ns = time.time_ns()
        timestamp_ns = self._timestamp_ns_from_header(pkthdr_ptr, iface) if pkthdr_ptr else host_arrival_ns
        sequence = self._next_capture_sequence()
        raw_bytes = bytes(raw_packet or b"")
        retained_raw = raw_bytes[:int(self.capture_raw_retention_limit)]

        self._safe_set_packet_attr(packet, "_capture_sequence", sequence)
        self._safe_set_packet_attr(packet, "_capture_timestamp_ns", timestamp_ns)
        self._safe_set_packet_attr(packet, "_capture_timestamp", timestamp_ns / 1e9)
        self._safe_set_packet_attr(packet, "_capture_host_arrival_ns", host_arrival_ns)
        self._safe_set_packet_attr(packet, "_capture_timestamp_precision", self._capture_precision_name_for_iface(iface))
        self._safe_set_packet_attr(packet, "_capture_iface", iface)
        self._safe_set_packet_attr(packet, "_capture_dlt", dlt)
        self._safe_set_packet_attr(packet, "_capture_dlt_name", self._dlt_name(dlt))
        self._safe_set_packet_attr(packet, "_capture_raw_length", len(raw_bytes))
        if self.capture_preserve_original_frame:
            self._safe_set_packet_attr(packet, "_capture_raw", retained_raw)
            self._safe_set_packet_attr(
                packet,
                "_capture_raw_retained_complete",
                len(retained_raw) == len(raw_bytes),
            )
        self._safe_set_packet_attr(
            packet,
            "_capture_sha256",
            hashlib.sha256(raw_bytes).hexdigest(),
        )
        self._safe_set_packet_attr(
            packet,
            "_capture_blake2b",
            hashlib.blake2b(raw_bytes, digest_size=32).hexdigest(),
        )
        self._safe_set_packet_attr(
            packet,
            "_capture_entropy",
            self._shannon_entropy(raw_bytes[:65536]),
        )

        flow = self._attach_flow_identity(packet)
        stream_metadata = None
        if flow and flow["protocol"] == "tcp":
            stream_metadata = self._update_tcp_reassembly(
                packet, flow, timestamp_ns
            )
        fragment_metadata = self._track_ip_fragments(packet, timestamp_ns)
        payload = self._payload_bytes(packet)
        stream_tail = bytes(
            getattr(packet, "_tcp_stream_tail", b"") or b""
        )

        protocol_metadata = {}
        if self.capture_analyze_protocols:
            protocol_metadata = self._parse_protocol_metadata(
                packet,
                payload=payload,
                stream_tail=stream_tail,
            )
        self._safe_set_packet_attr(
            packet, "_protocol_metadata", protocol_metadata
        )
        self._safe_set_packet_attr(
            packet,
            "_recognized_protocols",
            sorted(protocol_metadata),
        )

        score, priority, reasons = self._capture_priority(
            packet,
            protocol_metadata,
            payload=payload,
            capture_complete=bool(meta.get("capture_complete", False)),
        )
        self._safe_set_packet_attr(packet, "_capture_priority_score", score)
        self._safe_set_packet_attr(packet, "_capture_priority", priority)
        self._safe_set_packet_attr(packet, "_capture_priority_reasons", reasons)
        self._safe_set_packet_attr(packet, "_capture_high_value", priority in {"high", "critical"})
        self._safe_set_packet_attr(packet, "_capture_payload_length", len(payload))
        self._safe_set_packet_attr(packet, "_capture_payload_sha256", hashlib.sha256(payload).hexdigest() if payload else None)
        self._safe_set_packet_attr(packet, "_tcp_stream_metadata", stream_metadata)
        self._safe_set_packet_attr(packet, "_fragment_metadata", fragment_metadata)

        stats = self._sample_capture_stats(iface)
        self._safe_set_packet_attr(packet, "_capture_stats", stats)

        with self._capture_state_lock:
            self._capture_total_frames += 1
            self._capture_total_bytes += int(meta.get("captured_len", len(raw_bytes)) or 0)
            self._capture_total_wire_bytes += int(meta.get("wire_len", len(raw_bytes)) or 0)
            if not meta.get("capture_complete", False):
                self._capture_total_truncated += 1
            for protocol in protocol_metadata:
                self._capture_protocol_counts[protocol] += 1
            self._capture_priority_counts[priority] += 1
            try:
                ether = packet.getlayer(Ether)
                if ether is not None:
                    ether_type = int(getattr(ether, "type", 0) or 0)
                    if ether_type not in self.supported_ethertypes:
                        self._capture_unknown_ethertypes[ether_type] += 1
            except Exception:
                pass

        self._cleanup_capture_state(timestamp_ns)
        return packet


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
                self._unregister_capture_handle(handle, active_iface)
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
        """Build complete packet-header metadata without trusting malformed lengths."""
        try:
            hdr = pkthdr_ptr.contents
            captured_len = max(0, int(getattr(hdr, "caplen", 0) or 0))
            wire_len = max(0, int(getattr(hdr, "len", captured_len) or captured_len))
            seconds = int(getattr(hdr.ts, "tv_sec", 0) or 0)
            fraction = int(getattr(hdr.ts, "tv_usec", 0) or 0)
        except Exception:
            return {
                "captured_len": 0,
                "wire_len": 0,
                "capture_complete": False,
                "capture_quality": "invalid_header",
                "truncated_bytes": 0,
                "timestamp_seconds": 0,
                "timestamp_fraction": 0,
                "snapshot_length": int(self.capture_snapshot_length),
            }

        # A corrupt header must never cause ctypes.string_at to read beyond the
        # configured snapshot. Keep the true header value for diagnostics.
        reported_captured_len = captured_len
        captured_len = min(captured_len, int(self.capture_snapshot_length))
        wire_len = max(wire_len, reported_captured_len)
        capture_complete = wire_len > 0 and reported_captured_len >= wire_len
        truncated_bytes = max(0, wire_len - reported_captured_len)

        if reported_captured_len > self.capture_snapshot_length:
            quality = "header_exceeds_snapshot"
        elif capture_complete:
            quality = "full"
        elif reported_captured_len > 0:
            quality = "truncated"
        else:
            quality = "empty"

        return {
            "captured_len": captured_len,
            "reported_captured_len": reported_captured_len,
            "wire_len": wire_len,
            "capture_complete": capture_complete,
            "capture_quality": quality,
            "truncated_bytes": truncated_bytes,
            "timestamp_seconds": seconds,
            "timestamp_fraction": fraction,
            "snapshot_length": int(self.capture_snapshot_length),
        }

    def _attach_capture_meta(self, packet, meta: dict, *, iface: str = None, dlt: int = None):
        """Attach compatibility fields plus the richer capture envelope."""
        try:
            setattr(packet, "_captured_len", int(meta.get("captured_len", 0) or 0))
            setattr(packet, "_wire_len", int(meta.get("wire_len", 0) or 0))
            setattr(packet, "_capture_complete", bool(meta.get("capture_complete", False)))
            setattr(packet, "_capture_quality", str(meta.get("capture_quality", "unknown")))
            setattr(packet, "_truncated_bytes", int(meta.get("truncated_bytes", 0) or 0))
            setattr(packet, "_capture_reported_len", int(meta.get("reported_captured_len", meta.get("captured_len", 0)) or 0))
            setattr(packet, "_capture_snapshot_length", int(meta.get("snapshot_length", self.capture_snapshot_length) or self.capture_snapshot_length))
            setattr(packet, "_capture_timestamp_seconds", int(meta.get("timestamp_seconds", 0) or 0))
            setattr(packet, "_capture_timestamp_fraction", int(meta.get("timestamp_fraction", 0) or 0))
            if iface is not None:
                setattr(packet, "_capture_iface", iface)
            if dlt is not None:
                setattr(packet, "_capture_dlt", dlt)
                setattr(packet, "_capture_dlt_name", self._dlt_name(dlt))
        except Exception:
            pass
        return packet

    def _decode_captured_packet(self, pkthdr_ptr, packet_data_ptr, dlt: int, *, iface: str = None,
                                warn_on_truncation: bool = True):
        """Copy, decode, retain, hash, classify, and enrich one libpcap packet."""
        if not pkthdr_ptr or not pkthdr_ptr.contents:
            self.logger.log_message("[Sniffer] ERROR: Null packet header pointer.")
            return None, None
        if not packet_data_ptr:
            self.logger.log_message("[Sniffer] ERROR: Null packet data pointer.")
            return None, None

        meta = self._capture_meta_from_pkthdr(pkthdr_ptr)
        packet_len = int(meta["captured_len"])

        if packet_len <= 0:
            self.logger.log_message("[Sniffer] WARNING: Zero-length packet.")
            return None, meta

        try:
            raw_packet = ctypes.string_at(packet_data_ptr, packet_len)
        except Exception as exc:
            with self._capture_state_lock:
                self._capture_decode_failures += 1
            self.logger.log_message(f"[Sniffer] ERROR: Could not copy captured frame: {exc}")
            return None, meta

        try:
            packet = self._decode_by_dlt(raw_packet, dlt)
        except Exception as exc:
            packet = Raw(raw_packet)
            with self._capture_state_lock:
                self._capture_decode_failures += 1
            self._safe_set_packet_attr(packet, "_capture_decode_error", str(exc))

        self._attach_capture_meta(packet, meta, iface=iface, dlt=dlt)
        try:
            self._enrich_captured_packet(
                packet,
                raw_packet=raw_packet,
                meta=meta,
                iface=iface or "",
                dlt=dlt,
                pkthdr_ptr=pkthdr_ptr,
            )
        except Exception as exc:
            # Enrichment is never allowed to remove the original decoded packet.
            self._safe_set_packet_attr(packet, "_capture_enrichment_error", str(exc))
            with self._capture_state_lock:
                self._capture_decode_failures += 1

        if warn_on_truncation and not meta["capture_complete"]:
            self.logger.log_message(
                f"[Sniffer] ⚠️ Truncated capture on {iface or '?'}: "
                f"captured={meta['reported_captured_len']} wire={meta['wire_len']} "
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
            f"[Sniffer] capture iface={active_iface} datalink={dlt} ({self._dlt_name(dlt)}) "
            f"timestamp={self._capture_precision_name_for_iface(active_iface)} "
            f"host_clock=nanosecond"
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

                        # EtherType policy is now explicit-deny rather than
                        # implicit-deny. Unknown frames are valuable capture
                        # evidence and remain available as decoded/Raw payloads.
                        eth_type = int(packet[Ether].type)
                        if eth_type in self.unsupported_ethertypes:
                            if self.notification_manager:
                                self.notification_manager.send_notification({
                                    "event": "Blocked EtherType",
                                    "message": f"Dropped explicitly blocked EtherType {hex(eth_type)} from "
                                               f"{packet[Ether].src} → {packet[Ether].dst}.",
                                    "iface": iface, "timestamp": time.time(), "emojis": ["❌", "📦", "⚠️"]
                                }, cooldown_seconds=10, cooldown_key=f"ethertype_blocked_{eth_type:04x}")
                            continue

                        if eth_type not in self.supported_ethertypes:
                            self._safe_set_packet_attr(packet, "_unknown_ethertype", eth_type)
                            self._safe_set_packet_attr(packet, "_unknown_ethertype_hex", f"0x{eth_type:04x}")
                            if not self.capture_keep_unknown_ethertypes:
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
                self._unregister_capture_handle(handle, active_iface)
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
