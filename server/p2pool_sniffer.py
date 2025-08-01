#
# A custom network sniffing function built from scratch using Python's `ctypes`
# library to interface with the `libpcap` C library.
#
# This is a single-threaded version that processes packets directly in the main loop.
# All informational print statements have been removed, but error prints remain.
#
# To run this, you must have libpcap (or WinPcap/Npcap) installed on your system.
# You also need administrator/root privileges to open network devices for sniffing.
#
# Scapy is still used here for packet parsing after ctypes captures the raw data.
# To install Scapy: pip install scapy
#

import ctypes
import struct
import time
from ctypes import c_char, c_int, c_long, c_ushort, POINTER, CFUNCTYPE, Structure, c_uint
import sys
import os

# Import all functionalities from the Scapy library to parse packets.
try:
    from scapy.all import ShortField, ByteField, IP6Field, Packet, load_layer, TCPSession
    from scapy.contrib.igmp import IGMP
    from scapy.layers.inet import in4_chksum, TCP, UDP, IP, ICMP
    from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, \
        ICMPv6ND_RS, IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.packet import bind_layers, Raw
except ImportError:
    # Print error for Scapy and exit
    print("[-] Scapy library not found. Please install it using: pip install scapy")
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
    print(f"[-] Could not load libpcap library: {e}")
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


# Define the prototype for the callback function for pcap_loop/pcap_dispatch
PCAP_HANDLER_CALLBACK = CFUNCTYPE(
    None,
    POINTER(c_char),
    POINTER(pcap_pkthdr),
    POINTER(c_char)
)

# --- Define C function prototypes from libpcap ---
libpcap.pcap_open_live.restype = POINTER(c_char)
libpcap.pcap_open_live.argtypes = [
    POINTER(c_char), c_int, c_int, c_int, POINTER(c_char)
]
libpcap.pcap_compile.restype = c_int
libpcap.pcap_compile.argtypes = [
    POINTER(c_char), POINTER(bpf_program), POINTER(c_char), c_int, c_uint
]
libpcap.pcap_setfilter.restype = c_int
libpcap.pcap_setfilter.argtypes = [
    POINTER(c_char), POINTER(bpf_program)
]
libpcap.pcap_next_ex.restype = c_int
libpcap.pcap_next_ex.argtypes = [
    POINTER(c_char), POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_char))
]
libpcap.pcap_freecode.restype = None
libpcap.pcap_freecode.argtypes = [POINTER(bpf_program)]
libpcap.pcap_close.restype = None
libpcap.pcap_close.argtypes = [POINTER(c_char)]
libpcap.pcap_geterr.restype = POINTER(c_char)
libpcap.pcap_geterr.argtypes = [POINTER(c_char)]


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


# This is a critical step: The bindings must be defined globally
def setup_scapy_bindings():
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
    load_layer("tls")
    load_layer("kerberos")
    load_layer("rip")
    load_layer("dns")


def sniff(iface, prn, promisc=True, stop_filter=None, filter=None, timeout=100, mac_filter_only=False, session=None,
          notification_manager=None):
    """
    A custom, low-level sniffing function that emulates Scapy's sniff.

    This version is single-threaded and processes packets synchronously.

    Args:
        iface (str): The name of the network interface to sniff on.
        prn (callable): A function to be called for each captured packet.
        promisc (bool): Whether to enable promiscuous mode.
        stop_filter (callable): A function that, when True, stops the sniffer.
        filter (str): A BPF filter string to apply.
        timeout (int): The read timeout in milliseconds for pcap_next_ex.
        mac_filter_only (bool): If True, only accepts packets with a MAC address.
        session (callable): A session-layer handler (e.g., Scapy's TCPSession).
        notification_manager (NotificationManager): An optional NotificationManager instance to send alerts.
    """

    if not isinstance(iface, str):
        sys.stderr.write(f"[-] Error: `iface` must be a string. Got type {type(iface)}.\n")
        return
    if prn and not callable(prn):
        sys.stderr.write(f"[-] Error: `prn` must be a callable function. Got type {type(prn)}.\n")
        return
    if stop_filter and not callable(stop_filter):
        sys.stderr.write(f"[-] Error: `stop_filter` must be a callable function. Got type {type(stop_filter)}.\n")
        return

    # Set up Scapy bindings once
    setup_scapy_bindings()

    errbuf = ctypes.create_string_buffer(256)
    handle = libpcap.pcap_open_live(
        iface.encode("utf-8"), 65535, 1 if promisc else 0, timeout, errbuf
    )
    if not handle:
        sys.stderr.write(f"[-] Error opening device: {errbuf.value.decode()}\n")
        return

    if filter:
        bpf = bpf_program()
        if libpcap.pcap_compile(handle, ctypes.byref(bpf), filter.encode("utf-8"), 1, 0) == -1:
            sys.stderr.write(f"[-] Error compiling filter: {libpcap.pcap_geterr(handle).decode()}\n")
            libpcap.pcap_close(handle)
            return
        if libpcap.pcap_setfilter(handle, ctypes.byref(bpf)) == -1:
            sys.stderr.write(f"[-] Error setting filter: {libpcap.pcap_geterr(handle).decode()}\n")
            libpcap.pcap_freecode(ctypes.byref(bpf))
            libpcap.pcap_close(handle)
            return
        libpcap.pcap_freecode(ctypes.byref(bpf))

    try:
        pkthdr_ptr = POINTER(pcap_pkthdr)()
        packet_data_ptr = POINTER(c_char)()

        # Main capture loop
        while True:
            ret = libpcap.pcap_next_ex(handle, ctypes.byref(pkthdr_ptr), ctypes.byref(packet_data_ptr))

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

            # CRITICAL FIX: Check the length of the captured packet
            # This prevents Scapy from trying to parse malformed/truncated packets
            packet_len = pkthdr_ptr.contents.len
            if packet_len < 14:  # Minimum Ethernet frame size
                continue

            raw_packet = ctypes.string_at(packet_data_ptr, packet_len)

            try:
                packet = Ether(raw_packet)

                if mac_filter_only and not packet.haslayer(Ether):
                    continue

                processed_packet = packet
                if session:
                    processed_packet = session().process(pkt=packet, cls=None)

                if prn and processed_packet is not None:
                    prn(processed_packet)

            except struct.error as e:
                # Catch the specific unpack error and send a notification
                if notification_manager:
                    event_data = {
                        "event": "Malformed Packet",
                        "message": f"Packet parsing error: {e}. Length: {packet_len}. Raw data (hex): {raw_packet[:32].hex()}",
                        "iface": iface,
                        "timestamp": time.time(),
                        "emojis": ["🚨", "📦", "💥"]
                    }
                    notification_manager.send_notification(event_data)
                continue
            except Exception as e:
                sys.stderr.write(f"[-] Packet parsing error: {e}\n")
                continue

            if stop_filter:
                try:
                    temp_packet = Ether(raw_packet)
                    if stop_filter(temp_packet):
                        break
                except Exception as e:
                    sys.stderr.write(f"[-] Error in stop_filter: {e}. Stopping sniffer.\n")
                    break

    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.stderr.write(f"[-] An unexpected error occurred: {e}\n")
    finally:
        if handle:
            libpcap.pcap_close(handle)

