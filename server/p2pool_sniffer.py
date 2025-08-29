import ctypes
import ipaddress
import socket
import struct
import time
from ctypes import c_char, c_int, c_long, POINTER, CFUNCTYPE, Structure, c_uint
import sys
from typing import Optional

import psutil
from scapy.arch import get_if_hwaddr
from scapy.contrib.geneve import GENEVE
from scapy.fields import IntField
from scapy.layers.dhcp6 import DHCP6
from scapy.layers.dns import DNS
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.ipsec import ESP, AH
from scapy.layers.kerberos import Kerberos
from scapy.layers.l2tp import L2TP
from scapy.layers.mobileip import MobileIP
from scapy.layers.ppp import PPP
from scapy.layers.rip import RIP
from scapy.layers.rtp import RTP
from scapy.main import load_contrib

# Import all functionalities from the Scapy library to parse packets.
try:
    from scapy.all import ShortField, ByteField, IP6Field, Packet, load_layer, TCPSession
    from scapy.contrib.igmp import IGMP
    from scapy.layers.inet import TCP, UDP, IP
    from scapy.layers.inet6 import (
        ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA,
        ICMPv6ND_RA, ICMPv6ND_RS, IPv6
    )
    from scapy.layers.l2 import Ether, ARP, GRE
    from scapy.packet import bind_layers, Raw
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
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_IEEE802_11 = 105
DLT_LINUX_SLL = 113
DLT_IEEE802_11_RADIO = 127
DLT_LINUX_SLL2 = 276

# Optional capture direction (if supported by lib)
PCAP_D_IN = 1  # inbound only

# --- Scapy helper layers ---

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
    name = "ICMPv6"
    fields_desc = [
        ByteField("type", 128),
        ByteField("code", 0),
        ShortField("cksum", None),
    ]

    def post_build(self, p, pay):
        # Scapy will compute checksums normally; keeping your custom routine guarded
        try:
            if self.cksum is None and self.underlayer and isinstance(self.underlayer, IPv6):
                ip = self.underlayer
                psd_hdr = ip.src.encode() + ip.dst.encode() + len(p).to_bytes(4, 'big') + b'\x00\x00\x00' + ip.nh.to_bytes(1, 'big')
                from scapy.layers.inet import in4_chksum
                cksum = in4_chksum(psd_hdr + p + pay)
                p = p[:2] + cksum.to_bytes(2, 'big') + p[4:]
        except Exception:
            pass
        return p + pay

class ISKEMP(Packet):
    name = "ISKEMP"
    fields_desc = [
        ByteField("version", 1),
        ShortField("opcode", 0),
        IntField("session_id", 0),
    ]

class SnifferSoftware:
    """
    A class to manage sniffing and sending of Layer 2 and Layer 3 packets
    using direct libpcap/wpcap calls via ctypes.
    """

    def __init__(self, arp_manager, rip_manager, notification_manager=None, logger=None):
        self.arp_manager = arp_manager
        self.rip_manager = rip_manager
        self.notification_manager = notification_manager
        self.logger = logger if logger else self._default_logger()
        self.libpcap = None
        self.supported_ethertypes = {0x0800, 0x86DD, 0x0806, 0x8100}  # IPv4, IPv6, ARP, VLAN
        self.unsupported_ethertypes = {0x8006}
        self.local_ips = self._get_local_ips()
        self.banned_packets = []
        self._load_pcap_library()
        self.setup_scapy_bindings()
        self._define_pcap_prototypes()

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
        bind_layers(Ether, IPv6, type=0x86DD)
        bind_layers(IPv6, ICMPv6, nh=58)
        bind_layers(IPv6, TCP, nh=6)
        bind_layers(IPv6, UDP, nh=17)
        bind_layers(IPv6, Raw)
        bind_layers(ICMPv6, ICMPv6EchoRequest, type=128)
        bind_layers(ICMPv6, ICMPv6EchoReply, type=129)
        bind_layers(ICMPv6, ICMPv6ND_NS, type=135)
        bind_layers(ICMPv6, ICMPv6ND_NA, type=136)
        bind_layers(ICMPv6, ICMPv6ND_RA, type=134)
        bind_layers(ICMPv6, ICMPv6ND_RS, type=133)  # fixed
        bind_layers(ICMPv6, MLDQuery, type=130)
        bind_layers(ICMPv6, MLDReport, type=131)
        bind_layers(ICMPv6, MLDDone, type=132)
        bind_layers(IP, IGMP, proto=2)
        bind_layers(Ether, ARP, type=0x0806)
        bind_layers(UDP, ISKEMP, dport=9999)
        bind_layers(UDP, ISKEMP, sport=9999)
        bind_layers(UDP, DNS, dport=53)
        bind_layers(UDP, DNS, sport=53)
        bind_layers(IP, ESP, proto=50)
        bind_layers(IP, AH, proto=51)
        bind_layers(IPv6, AH, nh=51)
        bind_layers(IP, GRE, proto=47)
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

    def _decode_by_dlt(self, raw: bytes, dlt: int):
        """
        Return a Scapy packet that matches the capture's datalink type.
        Falls back to Raw on failure.
        """
        try:
            if dlt == DLT_EN10MB:
                return Ether(raw)
            if dlt == DLT_IEEE802_11_RADIO:
                from scapy.layers.dot11 import RadioTap
                return RadioTap(raw)
            if dlt == DLT_IEEE802_11:
                from scapy.layers.dot11 import Dot11
                return Dot11(raw)
            if dlt in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
                from scapy.layers.l2 import CookedLinux
                return CookedLinux(raw)
            if dlt == DLT_RAW:
                try:
                    return IP(raw)
                except Exception:
                    return IPv6(raw)
            if dlt == DLT_NULL:
                # 4-byte host-endian AF then payload
                af = struct.unpack("@I", raw[:4])[0]
                payload = raw[4:]
                if af == socket.AF_INET:
                    return IP(payload)
                if af == socket.AF_INET6:
                    return IPv6(payload)
                return Raw(payload)
            return Raw(raw)
        except Exception:
            return Raw(raw)

    def _dlt_name(self, dlt: int) -> str:
        if dlt == DLT_EN10MB:
            return "EN10MB"
        if dlt == DLT_IEEE802_11_RADIO:
            return "IEEE802_11_RADIO"
        if dlt == DLT_IEEE802_11:
            return "IEEE802_11"
        if dlt == DLT_LINUX_SLL:
            return "LINUX_SLL"
        if dlt == DLT_LINUX_SLL2:
            return "LINUX_SLL2"
        if dlt == DLT_NULL:
            return "NULL"
        if dlt == DLT_RAW:
            return "RAW"
        return f"DLT({dlt})"

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
                        if stop_filter and stop_filter(packet):
                            continue  # don't break the loop; just skip this packet
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

                    # RIP handling
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
            self.logger.log_message("[Sniffer] Error: Requires a Layer 3 packet (IP or IPv6).")
            return

        try:
            if not route_info:
                route_info = self.rip_manager.find_route(packet.dst)
                if not route_info:
                    self.logger.log_message(f"[Sniffer] Error: No route found for destination {packet.dst}")
                    return

            iface_out = route_info['interface']
            gw_ip = route_info['next_hop'] if route_info['next_hop'] != '0.0.0.0' else packet.dst

            if self.is_loopback(gw_ip):
                self.logger.log_message(f"[Sniffer] Skipping MAC resolution for loopback destination {gw_ip}")
                dst_mac = None
            else:
                dst_mac = self.arp_manager.resolve(gw_ip, iface=iface_out)
                if not dst_mac:
                    self.logger.log_message(f"[Sniffer] Error: Could not resolve MAC for gateway {gw_ip}")
                    return None

            if not src_mac:
                src_mac = get_if_hwaddr(iface_out)

            l2_packet = Ether(src=src_mac, dst=dst_mac) / packet

            if verbose >= 1:
                self.logger.log_message(f"[+] Resolved route: {packet.dst} -> via {gw_ip} on {iface_out}")
                self.logger.log_message(f"[+] L2 Frame: {src_mac} -> {dst_mac}")

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
            self.logger.log_message("[Sniffer] Error: sr1 requires a Layer 3 packet (IP or IPv6).")
            return None

        try:
            if not route_info:
                route_info = self.rip_manager.find_route(packet.dst)
                if not route_info:
                    self.logger.log_message(f"[Sniffer] Error: No route found for destination {packet.dst}")
                    return None

            iface_out = iface or route_info['interface']
            gw_ip = route_info['next_hop'] if route_info['next_hop'] != '0.0.0.0' else packet.dst

            if not dst_mac:
                dst_mac = self.arp_manager.resolve(gw_ip, iface=iface_out)
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
                inner = f"tcp and src host {packet.dst} and dst host {packet.src} and src port {packet.dport} and dst port {packet.sport}"
            elif UDP in packet:
                inner = f"udp and src host {packet.dst} and dst host {packet.src} and src port {packet.dport} and dst port {packet.sport}"
            else:
                # ICMP/ICMPv6 or other L4-less traffic
                if IPv6 in packet:
                    inner = f"ip6 and src host {packet.dst} and dst host {packet.src} and (icmp6 or (tcp or udp))"
                else:
                    inner = f"ip and src host {packet.dst} and dst host {packet.src} and (icmp or (tcp or udp))"

            # VLAN-safe: match inner payload whether or not a 802.1Q tag is present
            bpf_filter_str = f"({inner}) or (vlan and {inner})"
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
                        f"[Sniffer] ⛔ sr1 send failed on {iface_out}: Device not functioning (likely Win32 error 31).")
                else:
                    self.logger.log_message(f"[Sniffer] ❌ sr1 send failed on {iface_out}: {error_msg}")
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
                # --- END OF CORRECTION ---
                error_msg = (self.libpcap.pcap_geterr(handle) or b"").decode('utf-8', errors='ignore')
                if "device attached" in error_msg.lower() or "not functioning" in error_msg.lower():
                    self.logger.log_message(
                        f"[Sniffer] ⛔ sr2 send failed on {iface_out}: Device not functioning (likely Win32 error 31)."
                    )
                else:
                    self.logger.log_message(f"[Sniffer] ❌ sr2 send failed on {iface_out}: {error_msg}")
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
