import contextlib
import ctypes
import ipaddress
import os
import socket
import struct
import time
from ctypes import c_char, c_int, c_long, POINTER, CFUNCTYPE, Structure, c_uint
import sys
from typing import Optional, List, Union

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
    def __init__(self,router, arp_manager, rip_manager, lag_manager, notification_manager=None, _interfaces_config = None, logger=None, hyperv_manager = None):
        self.arp_manager = arp_manager
        self.rip_manager = rip_manager
        self.lag_manager = lag_manager
        self.router = router
        self._interfaces_config = _interfaces_config
        self.notification_manager = notification_manager
        self.logger = logger if logger else self._default_logger()
        self.libpcap = None
        self.supported_ethertypes = {
            0x888E,  # EAPOL (802.1X)
            0x88CC,  # LLDP
            0x8809,  # LACP / Slow Protocols
            0x88F7,  # PTP
            0x88E7,  # MACsec (encrypted but detectable)
            0x0800,  # IPv4
            0x86DD,  # IPv6
            0x0806,  # ARP
            0x8100,  # VLAN (802.1Q)
            0x88A8,  # QinQ / 802.1ad
            0x8864,  # PPPoE Session (you unwrap PPP->IP later)
            0x8863,  # PPPoE Discovery (to avoid false "unsupported" spam)
            0x8847,  # MPLS unicast
            0x8848,}
        self.unsupported_ethertypes = {0x8006}
        self.local_ips = self._get_local_ips()
        self.banned_packets = []
        self._load_pcap_library()
        self.setup_scapy_bindings()
        self._define_pcap_prototypes()
        self.logged_packets = []
        self.hyperv_manager = hyperv_manager
        self.banned_ips = ["89.222.103.1"]

    def iface_is_l2_capable(self, iface_name: str) -> bool:
        kind = (self._interfaces_config.get(iface_name, {}) or {}).get("driver", "").lower()
        return not ("windivert" in kind or "rawip" in kind or "winfw" in kind)
    def is_interface_connected(self, iface: str) -> bool:
        for nic, addrs in psutil.net_if_addrs().items():
            if iface in nic:
                stats = psutil.net_if_stats().get(nic)
                if stats and stats.isup:
                    return True
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
        Return the **inner-most** transport layer (TCP/UDP/ICMP/ICMPv6) if discoverable.

        This version is aligned with your newer decapsulation helpers:
          - _coerce_to_l3 / _descend_to_ip
          - _walk_ipv4 / _walk_ipv6 (fragment-aware, GRE/IPsec-aware)
          - _iter_layers_deep (decaps across GRE/PPPoE/PPP/MPLS/Dot1Q + UDP tunnels + Raw heuristics)

        Fragment rules:
          - IPv4 non-first fragment (frag>0) -> None
          - IPv6 fragment offset!=0 -> None
        IPsec:
          - ESP -> None (encrypted)
          - AH  -> allowed (authenticated only)
        """
        if pkt is None:
            return None

        # ---- 1) Fast path: get L3 and use the dedicated walkers ----
        try:
            ip, _why = self._coerce_to_l3(pkt)
            if ip is None:
                # Might still be a full Ether frame or some tunnel stack
                if isinstance(pkt, Ether):
                    ip = self._descend_to_ip(pkt)

            if isinstance(ip, IPv6):
                tl = self._walk_ipv6(ip)
                if tl is not None:
                    return tl
            elif isinstance(ip, IP):
                tl = self._walk_ipv4(ip)
                if tl is not None:
                    return tl
        except Exception:
            pass

        # ---- 2) Deep path: decap across tunnels + Raw heuristics, pick deepest L4 ----
        best: Optional[Packet] = None
        try:
            for layer in self._iter_layers_deep(pkt, max_nodes=128):
                if layer is None:
                    continue

                # ---- Fragment / IPsec gates (if we hit these, L4 isn't safely knowable) ----
                if isinstance(layer, IP):
                    if int(getattr(layer, "frag", 0) or 0) > 0:
                        return None
                    continue

                if isinstance(layer, IPv6ExtHdrFragment):
                    try:
                        off = int(getattr(layer, "offset", 0) or 0)
                    except Exception:
                        off = 0
                    if off != 0:
                        return None
                    continue

                if isinstance(layer, ESP):
                    return None

                # AH isn't encryption; keep going
                if isinstance(layer, AH):
                    continue

                # ---- Transport candidates (keep last one seen = deepest) ----
                if isinstance(layer, (TCP, UDP, ICMP)):
                    best = layer
                    continue

                # Your ICMPv6 world includes both scapy ICMPv6* classes + your custom ICMPv6 base
                try:
                    if isinstance(layer, self.ICMPV6_TYPES) or layer.__class__.__name__.startswith("ICMPv6"):
                        best = layer
                        continue
                except Exception:
                    # if ICMPV6_TYPES isn't initialized for some reason, fall back to name check only
                    if layer.__class__.__name__.startswith("ICMPv6"):
                        best = layer
                        continue

            return best
        except Exception:
            return best

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

            # 802.11 (with or without Radiotap/PPI)
            if dlt == DLT_IEEE802_11_RADIO:
                from scapy.layers.dot11 import RadioTap
                return RadioTap(raw)

            if dlt == DLT_PPI:
                # PPI often wraps 802.11; Scapy understands inner payload
                from scapy.layers.ppi import PPI
                return PPI(raw)

            if dlt == DLT_IEEE802_11:
                from scapy.layers.dot11 import Dot11
                return Dot11(raw)

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
        }
        return names.get(dlt, f"DLT({dlt})")

    # --- NEW: Windows-aware helpers ---
    def _send_l3_loopback(self, packet, *, expect_reply: bool = False, timeout: float = 2.0,
                         iface: Optional[str] = None, logger=None):
        """
        Send an L3 (IP/IPv6) packet via the OS loopback and optionally wait for one reply.

        Args:
            packet: A Scapy Packet. If it has an Ether layer, it will be stripped.
            expect_reply: If True, waits for a single reply and returns it; otherwise returns None.
            timeout: sr1() timeout in seconds when expect_reply=True.
            iface: Loopback interface name to use. If None, auto-detects (lo/lo0/Npcap Loopback Adapter/conf.iface).
            logger: Optional object with .log_message(str). If not provided, falls back to print().

        Returns:
            The reply Packet (when expect_reply=True and a reply is received), or None.
        """


        # --- import scapy locally to keep function self-contained --

        try:
            pkt = packet

            # 1) Strip any L2 header so we always send at L3.
            if pkt.haslayer(Ether):
                pkt = pkt[Ether].payload

            # 2) Ensure we have IP or IPv6.
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                raise ValueError("packet has no IP/IPv6 layer")

            # 3) Pick a loopback interface robustly.
            loop_iface = iface
            if not loop_iface:
                loop_iface = getattr(conf, "loopback_interface", None) or getattr(conf, "loopback_name", None)

            if not loop_iface:
                candidates = ("lo", "lo0", "Npcap Loopback Adapter")
                with contextlib.suppress(Exception):
                    ifaces = set(get_if_list())
                    for cand in candidates:
                        if cand in ifaces:
                            loop_iface = cand
                            break
                # last resort: whatever Scapy is using
                if not loop_iface:
                    loop_iface = conf.iface

            # 4) Normalize src/dst to loopback addresses if missing/unspecified, and build a tight BPF.
            if ip.version == 4:
                if getattr(ip, "src", "0.0.0.0") in ("0.0.0.0", "", None):
                    pkt[IP].src = "127.0.0.1"
                if getattr(ip, "dst", "0.0.0.0") in ("0.0.0.0", "", None):
                    pkt[IP].dst = "127.0.0.1"
                loop_host = "127.0.0.1"
                bpf = f"host {loop_host} and (icmp or tcp or udp)"
                layer_name = "IP"
                src = pkt[IP].src
                dst = pkt[IP].dst
            else:
                if getattr(ip, "src", "::") in ("::", "", None):
                    pkt[IPv6].src = "::1"
                if getattr(ip, "dst", "::") in ("::", "", None):
                    pkt[IPv6].dst = "::1"
                loop_host = "::1"
                bpf = f"host {loop_host} and (icmp6 or tcp or udp)"
                layer_name = "IPv6"
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst


            # 6) Send (and maybe receive) on loopback.
            if expect_reply:
                # Use a tight BPF so we don’t pick up unrelated traffic.
                try:
                    reply = self.sr1(pkt, timeout=float(timeout), iface=loop_iface, verbose=0, filter=bpf)
                except TypeError:
                    # Some builds don’t support 'filter' kw; fall back without it.
                    reply = self.sr1(pkt, timeout=float(timeout), iface=loop_iface, verbose=0)

                if reply:
                    rep_ip = reply.getlayer(IP) or reply.getlayer(IPv6)
                    self.logger.log_message(
                        f"[Loopback] Reply | iface={loop_iface} | {getattr(rep_ip, 'src', '?')} → {getattr(rep_ip, 'dst', '?')} | {reply.summary()}")
                else:
                    self.logger.log_message(f"[Loopback] No reply (timeout={timeout}s) | iface={loop_iface}")
                return reply
            else:
                self.send(pkt, verbose=0, iface=loop_iface)
                return None

        except Exception as e:
            # Best-effort summary without assuming Ether is present.
            with contextlib.suppress(Exception):
                self.logger.log_message(f"[Loopback] ❌ Error for packet '{pkt.summary()}': {e}")
            if 'pkt' not in locals():
                self.logger.log_message(f"[Loopback] ❌ Error before build: {e}")
            return None
    def _normalize_pcap_name(self, name: str) -> str:
        # collapse backslashes and trim whitespace
        n = (name or "").strip().replace("\\\\", "\\")
        return n

    def _is_npf_loopback(self, iface_name: str) -> bool:
        n = self._normalize_pcap_name(iface_name).lower()
        # handles "\Device\NPF_Loopback", "NPF_Loopback", with/without trailing space
        return n.endswith("\\device\\npf_loopback") or n == "npf_loopback"
    def _pick_pcap_iface_for_dst(self, dst_ip: str) -> str | None:
        """
        Choose the correct Npcap device for reaching dst_ip on Windows.
        We find the local IPv4 that the OS would use for dst_ip, then map it to a pcap device.
        """
        local_ip = None
        try:
            # UDP connect trick to learn the chosen egress local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((dst_ip, 53))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass
        if not local_ip:
            return None

        # Map local_ip → pcap_name using scapy's interface list
        for itf in get_windows_if_list():
            ips = (itf.get("ips") or []) + ([itf.get("ip")] if itf.get("ip") else [])
            for ip in ips:
                if not ip or "." not in ip:
                    continue
                if ip == local_ip:
                    return itf.get("pcap_name")
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

    def _ipv4_cidr_for_iface(self, iface_name: str) -> str | None:
        """
        Return 'A.B.C.D/pfx' for the interface.
        Supports Windows Npcap names ('\\Device\\NPF_{GUID}') and friendly names.
        Returns None for Npcap loopback or if no IPv4 is configured.
        """
        if not iface_name:
            return None
        if os.name == "nt" and self._is_npf_loopback(iface_name):
            return "127.0.0.1/8"  # synthetic; ensures downstream code doesn't crash
        iface_name = self._normalize_pcap_name(iface_name)
        # Windows pcap device path?
        if os.name == "nt" and iface_name.lower().startswith("\\device\\npf_"):
            if self._is_npf_loopback(iface_name):
                return None

            # Prefer Scapy's Windows inventory
            try:
                if 'get_windows_if_list' in globals() and get_windows_if_list:
                    for itf in get_windows_if_list():
                        if itf.get("pcap_name") == iface_name:
                            # Try vector form first
                            ips = (itf.get("ips") or [])
                            masks = (itf.get("netmasks") or [])
                            for ip, m in zip(ips, masks):
                                if ip and m and "." in ip:
                                    pref = ipaddress.IPv4Network((ip, m), strict=False).prefixlen
                                    return f"{ip}/{pref}"
                            # Fallback to scalar ip/netmask keys
                            ip, m = itf.get("ip"), itf.get("netmask")
                            if ip and m and "." in ip:
                                pref = ipaddress.IPv4Network((ip, m), strict=False).prefixlen
                                return f"{ip}/{pref}"
            except Exception:
                pass

            # Last resort: match the device MAC to a psutil NIC and read its IPv4
            return self._ipv4_cidr_via_mac_match(iface_name)

        # Non-Windows or friendly (human) name: use psutil inventory
        addr, mask = self._ipv4_addr_netmask_for_iface(iface_name)
        if not addr or not mask:
            return None
        try:
            pref = ipaddress.IPv4Network((addr, mask), strict=False).prefixlen
            return f"{addr}/{pref}"
        except Exception:
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

        errbuf = ctypes.create_string_buffer(256)
        handle = self.libpcap.pcap_open_live(iface.encode('utf-8'), 65535, 1 if promisc else 0, timeout, errbuf)
        if not handle:
            self.logger.log_message(f"[Sniffer] Error opening device: {errbuf.value.decode(errors='ignore')}")
            return

        dlt = self.libpcap.pcap_datalink(handle)
        self.logger.log_message(f"[Sniffer] datalink={dlt} ({self._dlt_name(dlt)})")

        if filter:
            bpf = bpf_program()
            if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), filter.encode(), 1, 0) == -1:
                err = (self.libpcap.pcap_geterr(handle) or b"").decode(errors='ignore')
                self.logger.log_message(f"[Sniffer] Filter error: {err}")
                self.libpcap.pcap_close(handle)
                return
            self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf))
            self.libpcap.pcap_freecode(ctypes.byref(bpf))

        # Forever loop
        pkthdr_ptr = ctypes.POINTER(pcap_pkthdr)()
        packet_data_ptr = ctypes.POINTER(ctypes.c_ubyte)()

        try:
            while True:
                if stop_filter and stop_filter(None): # Pass None since we don't have a packet yet
                    break
                ret = self.libpcap.pcap_next_ex(handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr))

                if ret == 0:
                    # read timeout; loop again
                    continue
                elif ret == -1:
                    err = (self.libpcap.pcap_geterr(handle) or b"").decode(errors='ignore')
                    sys.stderr.write(f"[-] Error reading packet: {err}\n")
                    time.sleep(0.05)
                    continue
                elif ret == -2:
                    # breakloop() or EOF - for live capture, just retry after a small pause
                    time.sleep(0.05)
                    continue

                if not pkthdr_ptr or not pkthdr_ptr.contents:
                    continue

                packet_len = pkthdr_ptr.contents.caplen
                if packet_len <= 0:
                    continue

                raw_packet = ctypes.string_at(packet_data_ptr, packet_len)

                try:
                    try:
                        packet = self._decode_by_dlt(raw_packet, dlt)
                    except Exception:
                        continue  # malformed frame
                    try:
                        if packet.summary() not in self.logged_packets:
                            self.logger.log_message(f"[Packet] iface={iface} len={packet_len} | {packet.summary()}")
                            self.logged_packets.append(packet.summary())
                    except Exception:
                        self.logger.log_message(f"[Packet] iface={iface} len={packet_len} | <decode error>")

                    try:
                        if stop_filter and stop_filter(packet):
                            break
                    except Exception:
                        pass

                    packet.sniffed_on = iface

                    if mac_filter_only and not packet.haslayer(Ether):
                        continue

                    if packet.haslayer(Ether):
                        # ARP handling
                        if packet.haslayer(ARP):
                            if not self.arp_manager.perform_arp_inspection(packet, iface):
                                continue
                            arp_op = packet[ARP].op
                            if arp_op == 2:
                                self.arp_manager.learn_arp_response(packet)
                            elif arp_op == 1:
                                try:
                                    self.arp_manager.reply_to_arp_request(packet, iface)
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
                    if not (packet.haslayer(IP) or packet.haslayer(IPv6) or packet.haslayer(ARP)):
                        # Likely 802.11 mgmt/ctrl etc.
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
                                self.rip_manager.handle_packet(packet, iface)
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

    def sendp(self, packet: Packet, iface: str, verbose: int = 0):
        errbuf = ctypes.create_string_buffer(256)
        handle = self.libpcap.pcap_open_live(iface.encode(), 65535, 1, 100, errbuf)
        if not handle:
            iface_out = self.lag_manager.get_member_interface("MyLANAggregation", packet)
            handle = self.libpcap.pcap_open_live(iface_out.encode("utf-8"), 65535, 1, 100, errbuf)
            if not handle:
                self.logger.log_message(f"Sendp error on '{iface}': {errbuf.value.decode(errors='ignore')}")
                return
        try:
            packet_bytes = bytes(packet)
            self.libpcap.pcap_sendpacket(
                handle,
                (ctypes.c_ubyte * len(packet_bytes))(*packet_bytes),
                len(packet_bytes)
            )
        finally:
            self.libpcap.pcap_close(handle)

    def send(self, packet: Packet, iface: str = None, verbose: int = 0, route_info: dict = None, dst_mac: str = None,
             src_mac: str = None):
        """
        Sends a Layer 3 packet (IP/IPv6) by wrapping in Ether().
        """
        if not (isinstance(packet, IP) or isinstance(packet, IPv6)):
            packet, _why = self._coerce_to_l3(packet)
            if packet is None:
                self.logger.log_message(f"[Sniffer] sr1: could not obtain a Layer 3 packet. Hint: {_why}")
                return None

        try:
            if not route_info:
                route_info = self.rip_manager.find_route(packet.dst)
                if not route_info:
                    self.logger.log_message(f"[Sniffer] Error: No route found for destination {packet.dst}")
                    return

            iface_out = self._normalize_pcap_name(iface or route_info['interface'])
            gw_ip = route_info['next_hop'] if route_info['next_hop'] != '0.0.0.0' else packet.dst

            # If loopback and dst is local/private → use OS stack at L3, skip pcap/L2 entirely
            if self._is_npf_loopback(iface_out) and self._dst_is_private_or_local(str(packet.dst)):
                self._send_l3_loopback(packet, expect_reply=False)
                return

            # For remote dst: remap loopback to real NIC first
            iface_out = self._ensure_egress_iface_for_dst(iface_out, str(packet.dst))
            if not iface_out:
                self.logger.log_message(f"[Sniffer] Error: cannot map loopback to a real NIC for {packet.dst}")
                return None

            iface_cidr = self._ipv4_cidr_for_iface(iface_out)
            if not iface_cidr:
                verbose = 1
                iface_out = self.lag_manager.get_member_interface("MyLANAggregation", packet)
                iface_cidr = self._ipv4_cidr_for_iface(iface_out)
                if not iface_cidr:
                    self.logger.log_message(f"[Sniffer] Error: could not derive IPv4 CIDR for iface '{iface_out}'")
                    return None

            # Resolve next hop MAC (only if not loopback gw)
            if not dst_mac:
                if self.is_loopback(gw_ip):
                    dst_mac = None
                else:
                    dst_mac = self.arp_manager.resolve_gateway_mac(gw_ip, iface=iface_out, iface_cidr=iface_cidr)
                    if not dst_mac:
                        dst_mac = getmacbyip(gw_ip)
                        if not dst_mac:
                            self.logger.log_message(f"[Sniffer] Error: Could not resolve MAC for gateway {gw_ip}")
                            return None

            if not src_mac:
                src_mac = get_if_hwaddr(iface_out)

            l2_packet = Ether(src=src_mac, dst=dst_mac) / packet

            if verbose >= 1:
                self.logger.log_message(f"[Sniffer] Resolved route: {packet.dst} -> via {gw_ip} on {iface_out} [+] L2 Frame: {src_mac} -> {dst_mac}")

            self.sendp(l2_packet, iface=iface_out, verbose=verbose)

        except Exception as e:
            self.logger.log_message(f"[Sniffer] An error occurred during send: {e}")

    def sr1(self, packet: Packet, iface: str = None, timeout: int = 2, verbose: int = 0,
            route_info: dict = None, dst_mac: str = None, src_mac: str = None) -> Optional[Packet]:
        """
        Sends a Layer 3 packet and waits for a single reply (within timeout).
        """
        # If a full Ether frame was passed, unwrap it
        if isinstance(packet, Ether) and (IP in packet or IPv6 in packet):
            packet = packet[IP] if IP in packet else packet[IPv6]

        if not (isinstance(packet, IP) or isinstance(packet, IPv6)):
            packet, _why = self._coerce_to_l3(packet)
            if packet is None:
                self.logger.log_message(f"[Sniffer] sr1: could not obtain a Layer 3 packet. Hint: {_why}")
                return None

        try:
            if not route_info:
                route_info = self.rip_manager.find_route(packet.dst)
                if not route_info:
                    self.logger.log_message(f"[Sniffer] Error: No route found for destination {packet.dst}")
                    return None
            iface_out = iface or route_info['interface']
            iface_out = self._normalize_pcap_name(iface_out)  # normalize
            gw_ip = route_info['next_hop'] if route_info['next_hop'] != '0.0.0.0' else packet.dst


            iface_cidr = self._ipv4_cidr_for_iface(iface_out)  # now safe
            if not iface_cidr:
                self.logger.log_message(f"[Sniffer] SR1 Error: could not derive IPv4 CIDR for iface '{iface_out}'")
                return None
            if not dst_mac:
                if self.is_loopback(gw_ip):
                    dst_mac = None
                else:
                    dst_mac = self.arp_manager.resolve_gateway_mac(gw_ip, iface=iface_out, iface_cidr=iface_cidr)
                    if not dst_mac:
                        dst_mac = getmacbyip(gw_ip)
                        if not dst_mac:
                            self.logger.log_message(f"[Sniffer] Error: Could not resolve MAC for gateway {gw_ip}")
                            return None

            if not src_mac:
                src_mac = get_if_hwaddr(iface_out)

            l2_packet = Ether(src=src_mac, dst=dst_mac) / packet

        except Exception as e:
            self.logger.log_message(f"[Sniffer] Error preparing packet for sr1: {e}")
            return None

        errbuf = ctypes.create_string_buffer(256)
        handle = self.libpcap.pcap_open_live(iface_out.encode("utf-8"), 65535, 1, int(timeout * 1000), errbuf)
        if not handle:
            iface_out = self.lag_manager.get_member_interface("MyLANAggregation", packet)
            handle = self.libpcap.pcap_open_live(iface_out.encode("utf-8"), 65535, 1, int(timeout * 1000), errbuf)
            if not handle:
                self.logger.log_message(
                    f"[Sniffer] Error opening device {iface_out}: {errbuf.value.decode('utf-8', errors='ignore')}")
                return None
        try:
            self.libpcap.pcap_setdirection(handle, 1)  # PCAP_D_IN
        except Exception:
            pass
        try:
            # Get datalink (DLT) and use it for decoding the reply
            dlt = self.libpcap.pcap_datalink(handle)

            # Prefer inbound-only if supported (avoid seeing our own transmit)
            try:
                self.libpcap.pcap_setdirection(handle, PCAP_D_IN)
            except Exception:
                pass

            # Compile BPF filter for the reply (REVERSED flow)
            # We expect: src=remote (packet.dst), dst=local (packet.src)
            if TCP in packet:
                inner = (f"tcp and src host {packet.dst} and dst host {packet.src} and "
                         f"src port {packet.dport} and dst port {packet.sport}")
            elif UDP in packet:
                inner = (f"udp and src host {packet.dst} and dst host {packet.src} and "
                         f"src port {packet.dport} and dst port {packet.sport}")
            else:
                # ICMP/ICMPv6 or other L4-less traffic
                if IPv6 in packet:
                    inner = f"ip6 and src host {packet.dst} and dst host {packet.src} and (icmp6 or (tcp or udp))"
                else:
                    inner = f"ip and src host {packet.dst} and dst host {packet.src} and (icmp or (tcp or udp))"

            # Decide whether the linktype can use 'vlan'
            dlt = self.libpcap.pcap_datalink(handle)
            # Loopback/raw types do NOT support 'vlan'
            DLT_NULL = 0
            DLT_LOOP = 12
            DLT_RAW = 101
            supports_vlan = dlt not in (DLT_NULL, DLT_LOOP, DLT_RAW)

            # Try filters in order of preference
            candidates = [f"({inner}) or (vlan and {inner})", inner] if supports_vlan else [inner]

            bpf = bpf_program()
            compiled = False
            last_err = ""
            for expr in candidates:
                if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), expr.encode("utf-8"), 1, 0) == 0:
                    if self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) == 0:
                        compiled = True
                        break
                    else:
                        last_err = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                        # free and try next candidate
                        self.libpcap.pcap_freecode(ctypes.byref(bpf))
                        continue
                else:
                    last_err = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                    # If error mentions VLAN on a weird DLT, fall back to inner only once
                    if "vlan" in last_err.lower() and expr != inner:
                        # free current bpf before retry
                        self.libpcap.pcap_freecode(ctypes.byref(bpf))
                        # attempt compile/set with inner only
                        if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), inner.encode("utf-8"), 1, 0) == 0:
                            if self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) == 0:
                                compiled = True
                                break
                            else:
                                last_err = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                        # free and continue to next candidate (though there isn't one)
                        self.libpcap.pcap_freecode(ctypes.byref(bpf))
                    else:
                        # free and try next candidate
                        self.libpcap.pcap_freecode(ctypes.byref(bpf))

            if not compiled:
                self.logger.log_message(f"[Sniffer] Error compiling/setting BPF filter (DLT={dlt}): {last_err}")
                return None

            # Send the packet
            packet_bytes = bytes(l2_packet)
            result = self.libpcap.pcap_sendpacket(
                handle,
                (ctypes.c_ubyte * len(packet_bytes))(*packet_bytes),
                len(packet_bytes)
            )

            if result != 0:
                error_msg = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                if "device attached" in error_msg.lower() or "not functioning" in error_msg.lower():
                    self.logger.log_message(
                        f"[Sniffer] 🪈 sr1 send failed on {iface_out}: Device not functioning (likely Win32 error 31) sending down PYPIPE.")
                    self.hyperv_manager.send_packet(bytes(packet))
                else:
                    self.router.process_packet(bytes(packet))
                    self.logger.log_message(f"[Sniffer] 🪈 sr1 send failed on {iface_out} sending to Router")
                return None

            if verbose >= 1:
                self.logger.log_message(f"[+] Sent packet on {iface_out}: {l2_packet.summary()}")
                if verbose >= 2:
                    l2_packet.show()

            # Receive response (bounded by timeout)
            pkthdr_ptr = ctypes.POINTER(pcap_pkthdr)()
            packet_data_ptr = ctypes.POINTER(ctypes.c_ubyte)()

            start_time = time.time()
            while time.time() - start_time < timeout:
                ret = self.libpcap.pcap_next_ex(handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr))
                if ret == 1:
                    if not pkthdr_ptr or not pkthdr_ptr.contents:
                        self.logger.log_message("[Sniffer] ERROR: Null packet header pointer.")
                        continue
                    packet_len = getattr(pkthdr_ptr.contents, "caplen", pkthdr_ptr.contents.len)
                    if packet_len <= 0:
                        self.logger.log_message("[Sniffer] WARNING: Zero-length packet.")
                        continue
                    raw_packet = ctypes.string_at(packet_data_ptr, packet_len)
                    reply_packet = self._decode_by_dlt(raw_packet, dlt)
                    return reply_packet
                elif ret == -1:
                    error_msg = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                    self.logger.log_message(f"[Sniffer] Error reading packet: {error_msg}")
                    break
                # ret == 0 -> timeout tick -> loop

            if verbose >= 1:
                self.logger.log_message("[Sniffer] Timeout: No reply received.")
            return None

        finally:
            if handle:
                self.libpcap.pcap_close(handle)

    def sr2(self, packet: Packet, iface: str, timeout: int = 2, verbose: int = 0) -> Optional[Packet]:
        """
        Sends a Layer 2 packet and waits for a single reply (within timeout).
        Assumes the packet is already a complete Layer 2 frame (Ether()).
        """
        if not isinstance(packet, Ether):
            self.logger.log_message("[Sniffer] Error: sr2 requires a Layer 2 packet (Ether frame).")
            return None
        if not packet.dst:
            self.logger.log_message(
                "[Sniffer] Error: The provided Layer 2 packet is missing a destination MAC address.")
            return None

        iface_out = iface
        if not iface_out:
            self.logger.log_message("[Sniffer] Error: Interface not specified for sr2.")
            return None

        handle = None
        try:
            errbuf = ctypes.create_string_buffer(256)
            handle = self.libpcap.pcap_open_live(iface_out.encode("utf-8"), 65535, 1, int(timeout * 1000), errbuf)
            if not handle:
                self.logger.log_message(
                    f"[Sniffer] Error opening device {iface_out}: {errbuf.value.decode('utf-8', errors='ignore')}"
                )
                return None

            dlt = self.libpcap.pcap_datalink(handle)
            try:
                self.libpcap.pcap_setdirection(handle, 1)  # PCAP_D_IN
            except Exception:
                pass

            bpf_filter_str = f"ether src host {packet.dst}"
            bpf = bpf_program()
            if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), bpf_filter_str.encode("utf-8"), 1, 0) != 0:
                error_msg = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                self.logger.log_message(f"[Sniffer] Error compiling BPF filter: {error_msg}")
                return None
            if self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) != 0:
                error_msg = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                self.logger.log_message(f"[Sniffer] Error setting BPF filter: {error_msg}")
                self.libpcap.pcap_freecode(ctypes.byref(bpf))
                return None
            self.libpcap.pcap_freecode(ctypes.byref(bpf))

            # Send the L2 packet
            packet_bytes = bytes(packet)

            # --- CORRECTED LINE ---
            # Cast the Python bytes object to a C-style unsigned byte array
            result = self.libpcap.pcap_sendpacket(
                handle,
                (ctypes.c_ubyte * len(packet_bytes))(*packet_bytes),
                len(packet_bytes)
            )

            if result != 0:
                error_msg = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                if "device attached" in error_msg.lower() or "not functioning" in error_msg.lower():
                    self.logger.log_message(
                        f"[Sniffer] 🪈 sr2 send failed on {iface_out}: Device not functioning (likely Win32 error 31) sending down PYPIPE.")
                    self.hyperv_manager.send_packet(bytes(packet))
                else:
                    self.router.process_packet(bytes(packet))
                    self.logger.log_message(f"[Sniffer] 🪈 sr2 send failed on {iface_out} sending to Router")
                return None

            if verbose >= 1:
                self.logger.log_message(f"[+] Sent packet on {iface_out}: {packet.summary()}")

            # Receive response (bounded by timeout)
            pkthdr_ptr = ctypes.POINTER(pcap_pkthdr)()
            packet_data_ptr = ctypes.POINTER(ctypes.c_ubyte)()

            start_time = time.time()
            while time.time() - start_time < timeout:
                ret = self.libpcap.pcap_next_ex(handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr))
                if ret == 1:
                    packet_len = pkthdr_ptr.contents.caplen
                    raw_packet = ctypes.string_at(packet_data_ptr, packet_len)
                    reply_packet = self._decode_by_dlt(raw_packet, dlt)

                    if ARP in packet and reply_packet.haslayer(ARP):
                        if reply_packet[ARP].op == 2 and reply_packet[ARP].psrc == packet[ARP].pdst:
                            if verbose >= 1:
                                self.logger.log_message(
                                    f"[Sniffer] ✅ Received ARP reply on {iface_out}: {reply_packet.summary()}")
                            return reply_packet
                        else:
                            continue
                    else:
                        if verbose >= 1:
                            self.logger.log_message(
                                f"[Sniffer] ✅ Received reply on {iface_out}: {reply_packet.summary()}")
                        return reply_packet
                elif ret == -1:
                    error_msg = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                    self.logger.log_message(f"[Sniffer] Error reading packet: {error_msg}")
                    break

            if verbose >= 1:
                self.logger.log_message("[Sniffer] Timeout: No reply received.")
            return None

        finally:
            if handle:
                self.libpcap.pcap_close(handle)

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

        # Optional VXLAN class (depends on scapy build)
        try:
            from scapy.layers.vxlan import VXLAN
        except Exception:
            VXLAN = None  # type: ignore

        while q and nodes < max_nodes:
            cur = q.popleft()
            if cur is None:
                continue

            # De-dupe by object id + class
            key = (id(cur), cur.__class__)
            if key in visited:
                continue
            visited.add(key)

            nodes += 1
            yield cur

            # Normal payload path
            pay = getattr(cur, "payload", None)

            # Tunnel decap shortcuts
            try:
                if isinstance(cur, GRE):
                    q.append(cur.payload)
                    continue

                if isinstance(cur, (PPPoE, PPP, MPLS, Dot1Q)):
                    q.append(cur.payload)
                    continue

                if isinstance(cur, UDP):
                    # VXLAN ports: 4789 + 8472 (common)
                    if int(getattr(cur, "dport", -1)) in (4789, 8472) or int(getattr(cur, "sport", -1)) in (4789, 8472):
                        if VXLAN and cur.haslayer(VXLAN):
                            vx = cur.getlayer(VXLAN)
                            if vx and hasattr(vx, "payload"):
                                q.append(vx.payload)  # inner Ether normally
                                continue

                    # GENEVE (6081)
                    if int(getattr(cur, "dport", -1)) == 6081 or int(getattr(cur, "sport", -1)) == 6081:
                        ge = cur.getlayer(GENEVE) if cur.haslayer(GENEVE) else None
                        if ge and hasattr(ge, "payload"):
                            q.append(ge.payload)
                            continue

                    # L2TP (1701) often carries PPP
                    if int(getattr(cur, "dport", -1)) == 1701 or int(getattr(cur, "sport", -1)) == 1701:
                        l2tp = cur.getlayer(L2TP) if cur.haslayer(L2TP) else None
                        if l2tp and hasattr(l2tp, "payload"):
                            q.append(l2tp.payload)
                            continue

            except Exception:
                pass

            # If payload is a packet, traverse it
            if isinstance(pay, Packet) and not isinstance(pay, NoPayload):
                q.append(pay)
                continue

            # If payload is Raw bytes, try to parse an inner frame
            if isinstance(cur, Raw):
                inner = self._maybe_parse_inner(bytes(cur.load or b""))
                if inner is not None:
                    q.append(inner)
                continue