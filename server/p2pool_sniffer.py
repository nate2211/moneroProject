import ctypes
import ipaddress
import socket
import struct
import time
from ctypes import c_char, c_int, c_long, POINTER, CFUNCTYPE, Structure, c_uint, cast
import sys
from typing import List, Tuple, Union, Optional

import psutil
from scapy.arch import get_if_hwaddr
from scapy.fields import IntField
from scapy.layers.dns import DNS
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.ipsec import ESP, AH
from scapy.layers.rip import RIP

# Import all functionalities from the Scapy library to parse packets.
try:
    from scapy.all import ShortField, ByteField, IP6Field, Packet, load_layer, TCPSession
    from scapy.contrib.igmp import IGMP
    from scapy.layers.inet import in4_chksum, TCP, UDP, IP, ICMP
    from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, \
        ICMPv6ND_RS, IPv6
    from scapy.layers.l2 import Ether, ARP, getmacbyip, GRE
    from scapy.packet import bind_layers, Raw
except ImportError:
    # Print error for Scapy and exit
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

# BPF program structure for filters
class bpf_program(Structure):
    _fields_ = [
        ("bf_len", c_uint),
        ("bf_insns", POINTER(c_char))  # Pointer to the instructions
    ]


# pcap_pkthdr struct (packet header)
class pcap_pkthdr(Structure):
    _fields_ = [
        ("ts", c_long),  # Time stamp
        ("caplen", c_int),  # Length of portion present
        ("len", c_int),  # Length of original packet
    ]







# --- Scapy Layer Bindings (MUST BE DEFINED GLOBALLY) ---
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
        if self.cksum is None and self.underlayer and isinstance(self.underlayer, IPv6):
            ip = self.underlayer
            psd_hdr = ip.src.encode() + ip.dst.encode() + len(p).to_bytes(4, 'big') + b'\x00\x00\x00' + ip.nh.to_bytes(
                1, 'big')
            from scapy.layers.inet import in4_chksum
            cksum = in4_chksum(psd_hdr + p + pay)
            p = p[:2] + cksum.to_bytes(2, 'big') + p[4:]
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
        """
        Initializes the PacketManager.

        Args:
            arp_manager: An instance of your ARPManager for MAC address resolution.
            rip_manager: An instance of your RIPManager for route lookups.
            notification_manager: An optional instance for sending alerts.
            logger: An optional logger object with a `log_message` method.
        """
        self.arp_manager = arp_manager
        self.rip_manager = rip_manager
        self.notification_manager = notification_manager
        self.logger = logger if logger else self._default_logger()
        self.libpcap = None
        self.supported_ethertypes = {0x0800, 0x86DD, 0x0806, 0x8100}  # IPv4, IPv6, ARP, VLAN-tagged
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
        """Provides a basic logger if none is provided."""

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
        bind_layers(ICMPv6, ICMPv6ND_RS, type=134)
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
        bind_layers(IPv6, GRE, nh=47)
        load_layer("tls")
        load_layer("kerberos")
        load_layer("rip")
        load_layer("dns")
    def _load_pcap_library(self):
        """Loads the appropriate libpcap/wpcap library based on the OS."""
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
        """Defines the ctypes function prototypes for the loaded pcap library."""
        if not self.libpcap:
            return
        PCAP_HANDLER_CALLBACK = CFUNCTYPE(
            None,
            POINTER(c_char),
            POINTER(pcap_pkthdr),
            POINTER(c_char)
        )

        # --- Define C function prototypes from libpcap ---
        self.libpcap.pcap_open_live.restype = POINTER(c_char)
        self.libpcap.pcap_open_live.argtypes = [
            POINTER(c_char), c_int, c_int, c_int, POINTER(c_char)
        ]
        self.libpcap.pcap_compile.restype = c_int
        self.libpcap.pcap_compile.argtypes = [
            POINTER(c_char), POINTER(bpf_program), POINTER(c_char), c_int, c_uint
        ]
        self.libpcap.pcap_setfilter.restype = c_int
        self.libpcap.pcap_setfilter.argtypes = [
            POINTER(c_char), POINTER(bpf_program)
        ]
        self.libpcap.pcap_next_ex.restype = c_int
        self.libpcap.pcap_next_ex.argtypes = [
            POINTER(c_char), POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_char))
        ]
        self.libpcap.pcap_sendpacket.restype = c_int
        self.libpcap.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), c_int]
        self.libpcap.pcap_freecode.restype = None
        self.libpcap.pcap_freecode.argtypes = [POINTER(bpf_program)]
        self.libpcap.pcap_close.restype = None
        self.libpcap.pcap_close.argtypes = [POINTER(c_char)]
        self.libpcap.pcap_geterr.restype = POINTER(c_char)
        self.libpcap.pcap_geterr.argtypes = [POINTER(c_char)]

    def sniff(self, iface, prn, promisc=True, stop_filter=None, filter=None, timeout=100, mac_filter_only=False,
              session=None):
        """
        A corrected and unified version of the sniff function that processes packets using ctypes with libpcap,
        preserving advanced features from the original implementation.

        Args:
            iface (str): Interface to sniff on.
            prn (callable): Callback to invoke for each packet.
            promisc (bool): Enable promiscuous mode.
            stop_filter (callable): A function that returns True to stop sniffing.
            filter_str (str): BPF filter string.
            timeout (int): Timeout in milliseconds.
            mac_filter_only (bool): Only accept packets with Ethernet headers.
            session (callable): Optional Scapy session processor.
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

        if filter:
            bpf = bpf_program()
            if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), filter.encode(), 1, 0) == -1:
                self.logger.log_message(
                    f"[Sniffer] Filter error: {ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode(errors='ignore')}")
                self.libpcap.pcap_close(handle)
                return
            self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf))
            self.libpcap.pcap_freecode(ctypes.byref(bpf))

        pkthdr_ptr = ctypes.POINTER(pcap_pkthdr)()
        packet_data_ptr = ctypes.POINTER(ctypes.c_char)()

        try:
            while not (stop_filter(1) if stop_filter else False):
                ret = self.libpcap.pcap_next_ex(handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr))

                if ret == 0:
                    if stop_filter and stop_filter(None):
                        break
                    continue
                elif ret == -1:
                    sys.stderr.write(f"[-] Error reading packet: {libpcap.pcap_geterr(handle).decode()}\n")
                    break
                elif ret == -2:
                    # End of file reached for a live capture or timeout
                    break
                packet_len = pkthdr_ptr.contents.len
                if packet_len < 14:  # Minimum Ethernet frame size
                    continue
                raw_packet = ctypes.string_at(packet_data_ptr, packet_len)
                try:
                    packet = Ether(raw_packet)
                    if packet in self.banned_packets:
                        self.notification_manager.send_notification({
                            "event": "Banned Packets",
                            "message": f"Banned packets",
                            "iface": iface,
                            "timestamp": time.time(),
                            "emojis": ["🛑", "🧩", "🐍"]
                        }, cooldown_seconds=5, cooldown_key="banned_packets")
                        continue
                    packet.sniffed_on = iface
                    if mac_filter_only and not packet.haslayer(Ether):
                        continue
                    if packet.haslayer(ARP):
                        if not self.arp_manager.perform_arp_inspection(packet, iface):
                            continue

                        arp_op = packet[ARP].op

                        # ARP Reply
                        if arp_op == 2:
                            self.arp_manager.learn_arp_response(packet)

                        # ARP Request
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

                        # Unknown or suspicious ARP operation
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
                    if packet.haslayer(IP):
                        ip = packet[IP]
                        if ip.flags == 1 or ip.frag > 0:
                            if not (ip.frag == 0 and ip.flags == 1):
                                self.notification_manager.send_notification({
                                    "event": "IP Fragment Dropped",
                                    "message": f"Fragmented IP packet dropped from {ip.src}",
                                    "iface": iface,
                                    "timestamp": time.time(),
                                    "emojis": ["✂️", "📦", "🔕"]
                                }, cooldown_seconds=2, cooldown_key="ipfrag_blocked")
                                continue

                    eth_type = packet.type
                    if eth_type not in self.supported_ethertypes or eth_type in self.unsupported_ethertypes:
                        self.notification_manager.send_notification({
                            "event": "Unsupported EtherType",
                            "message": f"Dropped packet with unsupported EtherType {hex(eth_type)} from {packet[Ether].src} → {packet[Ether].dst}.",
                            "iface": iface,
                            "timestamp": time.time(),
                            "emojis": ["❌", "📦", "⚠️"]
                        }, cooldown_seconds=10, cooldown_key="ethertype_blocked")
                        continue

                    if packet.type == 0x86DD and not packet.haslayer(IPv6):
                        self.notification_manager.send_notification({
                            "event": "IPv6 Parse Error",
                            "message": f"Expected IPv6 layer not found. Packet length: {packet_len}",
                            "iface": iface,
                            "timestamp": time.time(),
                            "emojis": ["⚠️", "📡", "❌"]
                        }, cooldown_seconds=10, cooldown_key="ipv6_blocked")
                        continue

                    if packet.haslayer(RIP) and packet.haslayer(IP) and packet.haslayer(UDP):
                        try:
                            original_ip = packet.getlayer(IP)
                            original_udp = packet.getlayer(UDP)

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

                    processed_packet = packet
                    if session:
                        processed_packet = session().process(pkt=packet, cls=None)

                    if prn and processed_packet is not None:
                        prn(processed_packet)
                except Exception:
                    continue
        finally:
            if handle:
                self.libpcap.pcap_close(handle)


    def sendp(self, packet: Packet, iface: str, verbose: int = 0):
        errbuf = ctypes.create_string_buffer(256)
        handle = self.libpcap.pcap_open_live(iface.encode(), 65535, 1, 100, errbuf)
        if not handle:
            self.logger.log_message(f"Sendp error on '{iface}': {errbuf.value.decode(errors='ignore')}", "ERROR"); return
        try:
            packet_bytes = bytes(packet)
            self.libpcap.pcap_sendpacket(handle, (ctypes.c_ubyte * len(packet_bytes))(*packet_bytes), len(packet_bytes))
        finally:
            self.libpcap.pcap_close(handle)

    def send(self, packet: Packet, iface: str = None, verbose: int = 0, route_info: dict = None, dst_mac: str = None,
             src_mac: str = None):
        """
        Sends a Layer 3 packet (IP/IPv6).
        """
        if not (isinstance(packet, IP) or isinstance(packet, IPv6)):
            self.logger.log_message("[Sniffer] Error: Erequires a Layer 3 packet (IP or IPv6).")
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

    def sr1(self, packet: Packet, iface: str = None, timeout: int = 2, verbose: int = 0, route_info: dict = None,
            dst_mac: str = None, src_mac: str = None):
        """
        Sends a Layer 3 packet and waits for a single reply.
        Automatically wraps with Ether() if needed.
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
            # Compile BPF filter
            bpf_filter_str = f"host {packet.dst} and src host {packet.src}"
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                bpf_filter_str += f" and src port {packet.dport} and dst port {packet.sport}"

            bpf = bpf_program()
            if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), bpf_filter_str.encode("utf-8"), 1, 0) != 0:
                error_msg = ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode('utf-8', errors='ignore')
                self.logger.log_message(f"[Sniffer] Error compiling BPF filter: {error_msg}")
                return None
            if self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) != 0:
                error_msg = ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode('utf-8', errors='ignore')
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
                error_msg = ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode('utf-8', errors='ignore')
                if "device attached" in error_msg.lower() or "not functioning" in error_msg.lower():
                    self.logger.log_message(
                        f"[Sniffer] ⛔ sr1 send failed on {iface_out}: Device not functioning (likely Win32 error 31). Skipping interface."
                    )
                else:
                    self.logger.log_message(
                        f"[Sniffer] ❌ sr1 send failed on {iface_out}: {error_msg}"
                    )
                return None

            if verbose >= 1:
                self.logger.log_message(f"[+] Sent packet on {iface_out}: {l2_packet.summary()}")
                if verbose >= 2:
                    l2_packet.show()

            # Receive response
            pkthdr_ptr = ctypes.POINTER(pcap_pkthdr)()
            packet_data_ptr = ctypes.POINTER(ctypes.c_char)()

            start_time = time.time()
            while time.time() - start_time < timeout:
                ret = self.libpcap.pcap_next_ex(handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr))
                if ret == 1:
                    if not pkthdr_ptr or not pkthdr_ptr.contents:
                        self.logger.log_message("[Sniffer] ERROR: Null packet header pointer.")
                        continue
                    packet_len = pkthdr_ptr.contents.len
                    if packet_len <= 0:
                        self.logger.log_message("[Sniffer] WARNING: Zero-length packet.")
                        continue
                    raw_packet = ctypes.string_at(packet_data_ptr, packet_len)
                    reply_packet = Ether(raw_packet)
                    return reply_packet
                elif ret == -1:
                    error_msg = ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode('utf-8', errors='ignore')
                    self.logger.log_message(f"[Sniffer] Error reading packet: {error_msg}")
                    break

            if verbose >= 1:
                self.logger.log_message("[Sniffer] Timeout: No reply received.")
            return None

        finally:
            if handle:
                self.libpcap.pcap_close(handle)

    def sr2(self, packet: Packet, iface: str, timeout: int = 2, verbose: int = 0) -> Optional[Packet]:
        """
        Sends a Layer 2 packet and waits for a single reply.
        Assumes the packet is already a complete Layer 2 frame (Ether()).

        Args:
            packet (Packet): The Layer 2 packet (Ether frame) to send.
            iface (str): The network interface to send the packet on.
            timeout (int): The number of seconds to wait for a reply.
            verbose (int): Verbosity level (0=quiet, 1=normal, 2=detailed).

        Returns:
            Optional[Packet]: The first reply packet received, or None on timeout/error.
        """
        # 1. Validate the input packet is a Layer 2 frame and has a valid destination MAC
        if not isinstance(packet, Ether):
            self.logger.log_message("[Sniffer] Error: sr2 requires a Layer 2 packet (Ether frame).")
            return None
        if not packet.dst:
            self.logger.log_message(
                "[Sniffer] Error: The provided Layer 2 packet is missing a destination MAC address.")
            return None

        # 2. Get the interface name and MAC addresses for the BPF filter
        iface_out = iface
        src_mac = packet.src
        dst_mac = packet.dst

        if not iface_out:
            self.logger.log_message("[Sniffer] Error: Interface not specified for sr2.")
            return None

        # 3. Open the libpcap handle for sniffing on the specified interface.
        # snaplen=65535 (capture full packets), promiscuous=1 (capture all packets on the network), timeout_ms=int(timeout * 1000)
        errbuf = ctypes.create_string_buffer(256)
        handle = self.libpcap.pcap_open_live(iface_out.encode("utf-8"), 65535, 1, int(timeout * 1000), errbuf)

        if not handle:
            self.logger.log_message(
                f"[Sniffer] Error opening device {iface_out}: {errbuf.value.decode('utf-8', errors='ignore')}"
            )
            return None

        try:
            # 4. Compile a BPF filter to capture reply packets.
            # A valid reply will have the original destination MAC as its source, and vice-versa.
            # We also filter by protocol if the original packet is an ARP request.
            bpf_filter_str = f"ether src {dst_mac} and ether dst {src_mac}"
            if ARP in packet:
                bpf_filter_str += " and arp"

            bpf = bpf_program()
            if self.libpcap.pcap_compile(handle, ctypes.byref(bpf), bpf_filter_str.encode("utf-8"), 1, 0) != 0:
                error_msg = ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode('utf-8', errors='ignore')
                self.logger.log_message(f"[Sniffer] Error compiling BPF filter: {error_msg}")
                return None

            # 5. Apply the filter to the pcap handle
            if self.libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) != 0:
                error_msg = ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode('utf-8', errors='ignore')
                self.logger.log_message(f"[Sniffer] Error setting BPF filter: {error_msg}")
                return None
            self.libpcap.pcap_freecode(ctypes.byref(bpf))

            # 6. Send the Layer 2 packet
            packet_bytes = bytes(packet)
            result = self.libpcap.pcap_sendpacket(
                handle,
                (ctypes.c_ubyte * len(packet_bytes))(*packet_bytes),
                len(packet_bytes)
            )

            if result != 0:
                error_msg = ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode('utf-8', errors='ignore')
                # Improved error handling for common device-related issues
                if "device attached" in error_msg.lower() or "not functioning" in error_msg.lower():
                    self.logger.log_message(
                        f"[Sniffer] ⛔ sr2 send failed on {iface_out}: Device not functioning (likely Win32 error 31). Skipping interface."
                    )
                else:
                    self.logger.log_message(f"[Sniffer] ❌ sr2 send failed on {iface_out}: {error_msg}")
                return None

            if verbose >= 1:
                self.logger.log_message(f"[+] Sent packet on {iface_out}: {packet.summary()}")
                if verbose >= 2:
                    packet.show()

            # 7. Sniff for a reply packet until timeout
            pkthdr_ptr = ctypes.POINTER(pcap_pkthdr)()
            packet_data_ptr = ctypes.POINTER(ctypes.c_char)()

            start_time = time.time()
            while time.time() - start_time < timeout:
                ret = self.libpcap.pcap_next_ex(handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr))
                if ret == 1:
                    # We received a packet that passed the filter.
                    if not pkthdr_ptr or not pkthdr_ptr.contents:
                        self.logger.log_message("[Sniffer] ERROR: Null packet header pointer.")
                        continue
                    packet_len = pkthdr_ptr.contents.len
                    if packet_len <= 0:
                        self.logger.log_message("[Sniffer] WARNING: Zero-length packet.")
                        continue
                    raw_packet = ctypes.string_at(packet_data_ptr, packet_len)
                    reply_packet = Ether(raw_packet)

                    # Additional check to verify the reply is a valid ARP response to our request
                    if ARP in packet and ARP in reply_packet:
                        # Check if the ARP reply is for the original ARP request
                        if reply_packet[ARP].op == 2 and reply_packet[ARP].psrc == packet[ARP].pdst:
                            if verbose >= 1:
                                self.logger.log_message(
                                    f"[Sniffer] ✅ Received ARP reply on {iface_out}: {reply_packet.summary()}")
                            return reply_packet
                        else:
                            # If the ARP reply doesn't match, we ignore it and continue sniffing
                            continue
                    else:
                        # For non-ARP packets, we assume any packet that matches the BPF filter is a valid reply
                        if verbose >= 1:
                            self.logger.log_message(
                                f"[Sniffer] ✅ Received reply on {iface_out}: {reply_packet.summary()}")
                        return reply_packet

                elif ret == -1:
                    error_msg = ctypes.string_at(self.libpcap.pcap_geterr(handle)).decode('utf-8', errors='ignore')
                    self.logger.log_message(f"[Sniffer] Error reading packet: {error_msg}")
                    break
                # ret == 0 means timeout, which is handled by the while loop's condition

            # 8. Handle timeout case
            if verbose >= 1:
                self.logger.log_message("[Sniffer] Timeout: No reply received.")
            return None

        finally:
            # 9. Clean up resources
            if handle:
                self.libpcap.pcap_close(handle)


