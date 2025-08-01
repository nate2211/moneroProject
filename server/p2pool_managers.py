import asyncio
import ctypes
import datetime
import hashlib
import hmac
import inspect
import os
import queue
import random
import socket
import ssl
import string
import struct
import traceback
import uuid
from collections import defaultdict, deque
from collections.abc import Set
from ctypes import wintypes
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
import scapy
import select
from PyQt5.QtCore import QObject, pyqtSignal
from _ctypes import sizeof, byref
from aioquic._buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import pull_quic_header
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from scapy.all import send, sr1, conf, get_if_list
from scapy.arch import get_if_hwaddr
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6, DHCP6_RelayForward, DHCP6OptIAPrefix, DHCP6OptDNSServers, DHCP6_Advertise, \
    DHCP6_Reply
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import TCP, IP, ICMP, UDP, IPerror
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6ND_RS, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, \
    ICMPv6ND_NA, ICMPv6ND_RA
from scapy.layers.l2 import ARP, Ether, getmacbyip
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSFinished, TLSCertificate, \
    TLSClientKeyExchange, TLSServerKeyExchange, TLSServerHelloDone, TLSCertificateRequest
from scapy.layers.tls.record import TLS, TLSAlert, TLSApplicationData
from scapy.layers.tls.tools import TLSPlaintext, TLSCiphertext
from scapy.libs.rfc3961 import Key
from scapy.main import load_layer
from scapy.sendrecv import srp, sendp
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import ByteField, ShortField, IntField, IPField, PacketListField, Field, BitField, XByteField, \
    FieldLenField, StrFixedLenField, FlagsField, IP6Field, ConditionalField
from scapy.layers.tls.crypto import suites
from scapy.layers.tls.crypto.suites import _GenericCipherSuite
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict, Literal
import xml.etree.ElementTree as ET
from scapy.layers.kerberos import (
    Kerberos, KRB_AS_REQ, KRB_AS_REP, KRB_TGS_REQ, KRB_TGS_REP, KRB_ERROR,
    EncryptedData, PrincipalName, EncryptionKey, PADATA
)
from scapy.sessions import TCPSession
from win32timezone import now

from p2pool_sniffer import sniff

packet_queue = queue.Queue(maxsize=25)
def RouterRandomMessages(name: str, message: str, emoticons: list[str]) -> str:
    emoji = random.choice(emoticons) if emoticons else ''
    return f"[{name}] {emoji} {message}"


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
# --- Layer Bindings ---
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
bind_layers(ICMPv6, MLDQuery, type=130)   # MLD Query
bind_layers(ICMPv6, MLDReport, type=131)  # MLD Report
bind_layers(ICMPv6, MLDDone, type=132)    # MLD Done
bind_layers(IP, IGMP, proto=2)  # IP protocol 2 is IGMP
bind_layers(Ether, ARP, type=0x0806)
bind_layers(UDP, RIP, sport=520, dport=520)

load_layer("tls")
load_layer("kerberos")
load_layer("dns")
load_layer("rip")

class SendBackManager:
    """
    A simplified version that signs and immediately sends a packet back.
    Supports ICMP Destination Unreachable (Type 3) generation and custom handling.
    """

    def __init__(self, router_logger, packet_signer, outbound_load_balancer):
        self.logger = router_logger
        self.packet_signer = packet_signer
        self.outbound_load_balancer = outbound_load_balancer
        self.logger.log_message("[SendBack] Initialized.")

    def send_back(self, packet: Packet, interface_name: str):
        """
        Signs and sends a packet immediately on a chosen outbound interface.
        """

        try:
            if not hasattr(packet[Ether], "dst") or not packet[Ether].dst or packet[
                Ether].dst.lower() == "ff:ff:ff:ff:ff:ff":
                self.logger.log_message(
                    f"[Sendback] 💦 Dropped packet: Ethernet layer has an invalid destination MAC address or it's a broadcast address. Summary: {packet.summary()}")
                return
            self.packet_signer.sign_packet(packet)
            outbound_interface = self.outbound_load_balancer.get_next_interface(packet)
            sendp(packet, iface=outbound_interface, verbose=0)
            self.logger.log_message(
                f"[SendBack] 🧃 Packet signed and sent on {outbound_interface.split('_')[-1]}"
            )
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.logger.log_message(f"[SendBack] ❗ Failed to send back packet:\n{tb}")

    def send_icmp_packet(self, original_packet: Packet, icmp_type: int = 3, icmp_code: int = 1,
                         payload: Optional[bytes] = None):
        """
        Constructs and sends a signed ICMP or ICMPv6 packet based on the given type/code.

        Args:
            original_packet (Packet): The triggering packet.
            icmp_type (int): ICMP type (e.g., 3 for Destination Unreachable).
            icmp_code (int): ICMP code (e.g., 1 = host unreachable, 13 = admin prohibited).
            payload (Optional[bytes]): Optional payload; defaults to 64 bytes of original packet.
        """
        if not hasattr(original_packet[Ether], "dst") or not original_packet[Ether].dst or original_packet[
            Ether].dst.lower() == "ff:ff:ff:ff:ff:ff":
            self.logger.log_message(
                f"[Sendback] 💦 Dropped packet: Ethernet layer has an invalid destination MAC address or it's a broadcast address. Summary: {original_packet.summary()}")
            return
        try:
            if IP in original_packet:
                ip = original_packet[IP]
                dst = ip.src
                src = ip.dst
                if payload is None:
                    payload = bytes(original_packet)[:64]

                icmp_reply = IP(dst=dst, src=src) / ICMP(type=icmp_type, code=icmp_code) / payload
                self.packet_signer.sign_packet(icmp_reply)
                outbound_iface = self.outbound_load_balancer.get_next_interface(icmp_reply)
                sendp(icmp_reply, iface=outbound_iface, verbose=0)
                self.logger.log_message(
                    f"[SendBack] 📮 Sent ICMPv4 type={icmp_type} code={icmp_code} to {dst}"
                )

            elif IPv6 in original_packet:
                ip6 = original_packet[IPv6]
                dst = ip6.src
                src = ip6.dst
                if payload is None:
                    payload = bytes(original_packet)[:64]

                from scapy.layers.inet6 import ICMPv6Unknown
                icmpv6_reply = IPv6(dst=dst, src=src) / ICMPv6Unknown(type=icmp_type, code=icmp_code) / payload
                self.packet_signer.sign_packet(icmpv6_reply)
                outbound_iface = self.outbound_load_balancer.get_next_interface(icmpv6_reply)
                sendp(icmpv6_reply, iface=outbound_iface, verbose=0)
                self.logger.log_message(
                    f"[SendBack] 📬 Sent ICMPv6 type={icmp_type} code={icmp_code} to {dst}"
                )

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.logger.log_message(f"[SendBack] ❗ Error sending ICMP packet:\n{tb}")

class PacketCatcherManager:
    """
    A manager responsible for inspecting packets for unencrypted payloads
    and outputting their content. It uses heuristics to identify potential plaintext.
    It also maintains a count of detected unencrypted payloads per IP and triggers an
    internal alert when a threshold is reached for a specific IP, then re-sends
    the collected packets for that IP.
    """

    def __init__(self, router_logger, catching_threshold: int = 3, packet_queue_maxlen: int = 3):
        """
        Initializes the FishingManager.

        Args:
            router_logger (RouterLogger): An instance of the router's logger.
            catching_threshold (int): The number of unencrypted payloads from a single IP
                                     that triggers a release of collected packets for that IP.
            packet_queue_maxlen (int): The maximum number of packets to store per IP
                                       in the catching table before old ones are dropped.
        """
        self.logger = router_logger
        self.logger.log_message("[Fishing] 🎣 Manager initialized. Ready to cast nets for plaintext payloads.")
        self.notification_manager = None
        self.arp_manager = None
        # Common plaintext ports for heuristic checking
        self.plaintext_ports = {
            80: "HTTP",  # Hypertext Transfer Protocol
            21: "FTP (Control)",  # File Transfer Protocol
            23: "Telnet",  # Telnet
            25: "SMTP",  # Simple Mail Transfer Protocol
            110: "POP3",  # Post Office Protocol version 3
            143: "IMAP",  # Internet Message Access Protocol
            53: "DNS",  # Domain Name System (UDP/TCP)
            161: "SNMP",  # Simple Network Management Protocol (UDP)
            389: "LDAP",  # Lightweight Directory Access Protocol (plaintext)
            # Add more as needed
        }

        # Fishing table to store packets and counts per IP
        # Each entry is { 'packets': deque, 'count': int }
        self.catching_table = defaultdict(lambda: {'packets': deque(maxlen=packet_queue_maxlen), 'count': 0})
        self.catching_threshold = catching_threshold
        self.dry_table = defaultdict(lambda: {'count': 0})
        self.dry_threshold = 5  # You can adjust this threshold
        self.packet_queue_maxlen = packet_queue_maxlen  # Max length for the deque per IP

    def process_packet(self, packet: Packet):
        """
        Inspects a packet for unencrypted (plaintext) payloads.
        If a potential plaintext payload with an interesting keyword is found, its content is logged,
        the packet is stored in the catching table for its source IP,
        the per-IP catching count is incremented, and if the threshold is met,
        the collected packets for that IP are re-sent.

        Args:
            packet (Packet): The Scapy packet to inspect.
        """
        payload_detected_in_this_packet = False
        protocol_info = "Unknown"
        src_ip = None
        dst_ip = None
        decoded_payload = ""

        # Determine the source IP for per-IP tracking
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IP].dst
        else:
            self.logger.log_message("[PacketCatcher] 🐠 Not an IP packet, skipping payload inspection.")
            return  # Only process IP packets for catching

        try:
            # --- TCP Payload Check ---
            if TCP in packet and packet.haslayer('Raw'):
                tcp_layer = packet[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport

                # Check if source or destination port is a known plaintext port
                if sport in self.plaintext_ports:
                    protocol_info = self.plaintext_ports[sport]
                elif dport in self.plaintext_ports:
                    protocol_info = self.plaintext_ports[dport]

                payload = packet[Raw].load
                decoded_payload = payload.decode('utf-8', errors='ignore')

                # Check for interesting keywords
                log_payload = decoded_payload[:50] + "..." if len(decoded_payload) > 50 else decoded_payload
                log_payload = log_payload.replace('\n', '').replace('\r', '')
                self.logger.log_message(
                    f"[PacketCatcher] 🐟 Caught interesting TCP Payload ({protocol_info}). Payload snippet:{log_payload}")
                payload_detected_in_this_packet = True

            # --- UDP Payload Check ---
            elif UDP in packet and packet.haslayer('Raw'):
                udp_layer = packet[UDP]
                sport = udp_layer.sport
                dport = udp_layer.dport

                if sport in self.plaintext_ports:
                    protocol_info = self.plaintext_ports[sport]
                elif dport in self.plaintext_ports:
                    protocol_info = self.plaintext_ports[dport]

                payload = packet[Raw].load
                decoded_payload = payload.decode('utf-8', errors='ignore')
                # Check for interesting keywords
                log_payload = decoded_payload[:50] + "..." if len(decoded_payload) > 50 else decoded_payload
                log_payload = log_payload.replace('\n', '').replace('\r', '')
                self.logger.log_message(
                    f"[PacketCatcher] 🎣 Caught interesting UDP Payload ({protocol_info}). Payload snippet:{log_payload}")
                payload_detected_in_this_packet = True

            # For ICMP Echo Replies, which inherently have plaintext data
            elif (ICMP in packet and packet.haslayer('Raw') and (
                    packet[ICMP].type == 0 or (IPv6 in packet and ICMPv6EchoReply in packet))):
                payload = packet[Raw].load
                decoded_payload = payload.decode('utf-8', errors='ignore')
                # Check for interesting keywords
                log_payload = decoded_payload[:50] + "..." if len(decoded_payload) > 50 else decoded_payload
                log_payload = log_payload.replace('\n', '').replace('\r', '')
                self.logger.log_message(
                    f"[PacketCatcher] 🐟 Caught interesting ICMP Echo Reply Payload. Payload snippet:{log_payload}")
                payload_detected_in_this_packet = True

            if payload_detected_in_this_packet:
                # Store the packet and increment count for the specific source IP
                ip_entry = self.catching_table[src_ip]
                ip_entry['packets'].append(packet)
                ip_entry['count'] += 1
                self.logger.log_message(
                    f"[PacketCatcher] 🐠 Stored packet from {src_ip}. Current count for {src_ip}: {ip_entry['count']}/{self.catching_threshold} ({len(ip_entry['packets'])} in queue)."
                )

                # Check if the catching count for this IP has reached the threshold
                if ip_entry['count'] >= self.catching_threshold:
                    self.logger.log_message(
                        f"[PacketCatcher] 💰 Unencrypted payload threshold reached for {src_ip}! ({ip_entry['count']} detections)")
                    self._release_packets_for_ip(src_ip, packet.sniffed_on)  # Release packets for this specific IP
                    self.request_fish(dst_ip)
            else:
                if dst_ip:
                    self.dry_table[dst_ip]['count'] += 1

                    if self.dry_table[dst_ip]['count'] >= self.dry_threshold:
                        self.logger.log_message(f"[Fishing] 🚰 Too many dry packets to {dst_ip}. Requesting payload.")
                        self.request_fish(dst_ip)
                        self.dry_table[dst_ip]['count'] = 0  # Reset after trigger

                    if self.dry_table[dst_ip]['count'] >= self.dry_threshold / 2 and self.catching_table[src_ip][
                        'count'] < self.catching_threshold:
                        sender_mac = packet[Ether].src if Ether in packet else "00:00:00:00:00:00"
                        self.notification_manager.send_notification(
                            {
                                "event": "Dry Fishing",
                                "ip": dst_ip,
                                "mac": sender_mac,
                                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                                "emojis": ["🚣", "🚣🏻", "🚣🏽", "🚣🏿"]
                            })

        except Exception as e:
            self.logger.log_message(f"[Fishing] ❗ Error during payload inspection: {e}\n{traceback.format_exc()}")

    def request_fish(self, ip_address: str):
        """
        Sends a custom UDP packet to the specified IP to request re-transmission of unencrypted data.
        Intended for interaction with systems tracked by the FishingManager.
        """
        try:
            # Build a UDP packet to a high-numbered port with a recognizable payload
            payload = b"SEND_FISH"  # This could be anything you define as a trigger
            packet = IP(dst=ip_address) / UDP(sport=55555, dport=55555) / Raw(load=payload)

            self.logger.log_message(f"[PacketCatcher] 🕳️ Sending fish request to {ip_address}")
            send(packet, verbose=False)

        except Exception as e:
            self.logger.log_message(f"[PacketCatcher] ❌ Failed to send fish request to {ip_address}.")

    def _release_packets_for_ip(self, ip_address: str, iface: str = None):
        """
        Processes packets stored in the catching table for a specific IP by reconstructing them
        and sending them at Layer 3, then clearing the count for that IP.

        Args:
            ip_address (str): The IP address whose packets should be processed.
            iface (str): The interface from which the packets were sniffed. This is for logging purposes.
        """
        if ip_address not in self.catching_table:
            self.logger.log_message(f"[PacketCatcher] ℹ️ No packets to process for IP: {ip_address}")
            return

        ip_entry = self.catching_table[ip_address]
        num_packets_to_process = len(ip_entry['packets'])
        self.logger.log_message(
            f"[PacketCatcher] 🏴‍☠️ Reconstructing and sending {num_packets_to_process} packets for IP: {ip_address}.")

        while ip_entry['packets']:
            pkt = ip_entry['packets'].popleft()

            # Reconstruct the packet to send at Layer 3
            l3_packet = None
            if IP in pkt:
                l3_packet = pkt.getlayer(IP)
            elif IPv6 in pkt:
                l3_packet = pkt.getlayer(IPv6)

            if l3_packet:
                try:
                    # Using the send() function which operates at Layer 3
                    if not hasattr(pkt[Ether], "dst") or not pkt[Ether].dst or pkt[
                        Ether].dst.lower() == "ff:ff:ff:ff:ff:ff":
                        self.logger.log_message(
                            f"[PacketCatcher] 💦 Dropped packet: Ethernet layer has an invalid destination MAC address or it's a broadcast address. Summary: {pkt.summary()}")
                        return
                    send(l3_packet, verbose=False)
                    self.logger.log_message(
                        f"[PacketCatcher] 🦜 Reconstructed and sent L3 packet from {l3_packet.src} to {l3_packet.dst}.")
                except Exception as e:
                    self.logger.log_message(f"[PacketCatcher] ❌ Failed to send reconstructed packet: {e}")
            else:
                self.logger.log_message(f"[PacketCatcher] ⚠️ Packet for {ip_address} was not a valid L3 packet. Dropping.")

        # Reset the count for this IP after processing all packets
        ip_entry['count'] = 0

class PacketSigningManager:
    """
    Signs IPv4/IPv6 packets using HMAC and embeds a fragment of the signature
    into IP ID (IPv4) or Flow Label (IPv6). Automatically verifies the signature
    before sending to prevent tampered packets and can process incoming packets.
    """


    def __init__(self, router_logger):
        self.logger = router_logger
        self.signing_key = os.urandom(32)
        self.writing_table = defaultdict(lambda: {"count": 0, "last_seen": 0})
        self.TRUST_THRESHOLD = 4
        self.logger.log_message("[Signing] 🧿 Manager initialized.")
        self.signature_table = {}
        self.notification_manager = None

    def _get_signature_data(self, packet: Packet, ip_layer) -> bytes:
        """
        Constructs HMAC input from stable, deterministic fields, and updates
        signature table with a trackable packet fingerprint.
        """
        try:
            # Determine source IP bytes
            if hasattr(ip_layer, "src") and hasattr(ip_layer.src, "packed"):
                src = ip_layer.src.packed
            else:
                src = socket.inet_pton(socket.AF_INET6 if isinstance(ip_layer, IPv6) else socket.AF_INET, ip_layer.src)

            # Determine destination IP bytes
            if hasattr(ip_layer, "dst") and hasattr(ip_layer.dst, "packed"):
                dst = ip_layer.dst.packed
            else:
                dst = socket.inet_pton(socket.AF_INET6 if isinstance(ip_layer, IPv6) else socket.AF_INET, ip_layer.dst)
        except Exception:
            src, dst = b"", b""

        # Correct protocol/next-header byte
        try:
            if isinstance(ip_layer, IP):
                proto = bytes([ip_layer.proto])
            elif isinstance(ip_layer, IPv6):
                proto = bytes([ip_layer.nh])
            else:
                proto = b"\x00"
        except Exception:
            proto = b"\x00"

        # Port info for TCP/UDP/ICMP
        ports = b"\x00\x00\x00\x00"
        try:
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            else:
                sport = dport = 0
            ports = struct.pack("!HH", sport, dport)
        except Exception:
            ports = b"\x00\x00\x00\x00"

        # First 64 bytes of payload (sample)
        try:
            payload = bytes(ip_layer.payload)[:64] if ip_layer.payload else b""
        except Exception:
            payload = b""

        # Final HMAC input
        sig_data = src + dst + proto + ports + payload

        # Optional signature logging
        signature_hash = hashlib.sha1(sig_data).hexdigest()
        if hasattr(self, "sigintable"):
            self.signature_table[signature_hash] = {
                "src_ip": str(ip_layer.src),
                "dst_ip": str(ip_layer.dst),
                "proto": ip_layer.proto if isinstance(ip_layer, IP) else ip_layer.nh if isinstance(ip_layer,
                                                                                                   IPv6) else None,
                "ports": struct.unpack("!HH", ports) if len(ports) == 4 else None,
                "payload_sample": payload.hex(),
                "timestamp": time.time()
            }

        return sig_data

    def sign_packet(self, packet: Packet) -> bool:
        """
        Signs the packet and embeds signature into appropriate header.
        Returns True if the signature is valid after signing; otherwise drops.
        """

        if IP in packet:
            ip = packet[IP]
            sig_data = self._get_signature_data(packet, ip)
            if not sig_data:
                return False

            digest = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()
            packet[IP].id = struct.unpack("!H", digest[:2])[0]
            del packet[IP].chksum

            if self.verify_packet(packet):
                self.logger.log_message(
                    RouterRandomMessages("Signing", f"IPv4 signed + verified (ID: {packet[IP].id:#06x})", ["🖊️", "🖋️", "✒️", "📝", "🪶"]))
                return True
            else:
                self.logger.log_message("[Signing] 🧨 Dropped IPv4: Signature mismatch after signing")
                return False

        elif IPv6 in packet:
            ip = packet[IPv6]
            sig_data = self._get_signature_data(packet, ip)
            if not sig_data:
                return False

            digest = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()
            flow_label = struct.unpack("!I", b'\x00' + digest[:3])[0] & 0xFFFFF
            packet[IPv6].fl = flow_label

            if self.verify_packet(packet):
                self.logger.log_message(
                    RouterRandomMessages("Signing", f"IPv6 signed + verified (Flow Label: {packet[IPv6].fl:#06x})",["📏", "📐", "📓", "📕", "📔"]))
                return True
            else:
                self.logger.log_message("[Signing] 💥 Dropped IPv6: Signature mismatch after signing")
                return False

        else:
            self.logger.log_message("[Signing] 👻 Skipped non-IP packet")
        expired_keys = [k for k, v in self.signature_table.items() if now - v["last_seen"] > 30]
        for k in expired_keys:
            del self.signature_table[k]

            return False
        return False
    def verify_packet(self, packet: Packet) -> bool:
        """Verifies that the embedded signature matches a fresh HMAC and removes matching entry from sigintable."""
        try:
            ip = None
            if IP in packet:
                ip = packet[IP]
            elif IPv6 in packet:
                ip = packet[IPv6]
            else:
                return False

            sig_data = self._get_signature_data(packet, ip)
            digest = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()

            if IP in packet:
                expected_id = struct.unpack("!H", digest[:2])[0]
                if ip.id != expected_id:
                    return False

            elif IPv6 in packet:
                expected_fl = struct.unpack("!I", b'\x00' + digest[:3])[0] & 0xFFFFF
                if ip.fl != expected_fl:
                    return False

            # Signature verified — now remove from sigintable
            sig_hash = hashlib.sha1(sig_data).hexdigest()
            if sig_hash in self.signature_table:
                del self.signature_table[sig_hash]

            return True

        except Exception as e:
            self.logger.log_message(f"[Signing] ⚠️ Signature verify error: {e}")
            return False

    def process_packet(self, packet: Packet) -> bool:
        """
        Verifies and re-signs incoming packets. If unsigned, tracks sender.
        On exceeding threshold, sends signed rejection and resets sender counter.
        Returns True if re-signed, False otherwise.
        """
        try:
            if IP in packet:
                ip = packet[IP]
                sig_data = self._get_signature_data(packet, ip)
                if not sig_data:
                    return False

                digest = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()
                expected_id = struct.unpack("!H", digest[:2])[0]

                if ip.id == expected_id:
                    self.logger.log_message(f"[Signing] 🛡️ Verified incoming IPv4 packet (ID: {ip.id:#06x})")
                    return True
                else:
                    self._handle_unsigned_packet(packet, ip, str(ip.src))
                    return True

            elif IPv6 in packet:
                ip = packet[IPv6]
                sig_data = self._get_signature_data(packet, ip)
                if not sig_data:
                    return False

                digest = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()
                expected_fl = struct.unpack("!I", b'\x00' + digest[:3])[0] & 0xFFFFF
                if ip.fl == expected_fl:
                    self.logger.log_message(f"[Signing] 🔒 Verified incoming IPv6 packet (Flow Label: {ip.fl:#06x})")
                    return True
                else:
                    self._handle_unsigned_packet(packet, ip, str(ip.src))
                    return True

            return False

        except Exception as e:
            self.logger.log_message(f"[Signing] 💢 Error in processing packet: {e}")
            return False

    def _handle_unsigned_packet(self, packet, ip_layer, src_ip_str: str):
        """Handles unsigned packet by updating table and taking action if needed."""
        entry = self.writing_table[src_ip_str]
        entry["count"] += 1
        entry["last_seen"] = int(time.time())

        if entry["count"] >= self.TRUST_THRESHOLD:
            self.logger.log_message(f"[Signing] 🚨 Threshold exceeded for {src_ip_str}, sending response...")

            self._send_rejection(packet, ip_layer)

            # Reset after action
            entry["count"] = 0
            return False
        if entry["count"] == 2:
            self.logger.log_message(f"[Signing] 🚨 Threshold exceeded for {src_ip_str}, sending response...")

            sender_mac = packet[Ether].src if Ether in packet else "00:00:00:00:00:00"
            self.notification_manager.send_notification(
                {
                    "event": "Receiving Unsigned Packets",
                    "ip": ip_layer.dst,
                    "mac": sender_mac,
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "emojis": ["📋"]
                })
            return False
        self.logger.log_message(f"[Signing] 🧱 Unsigned packet from {src_ip_str} (count={entry['count']})")
        return False
    def _send_rejection(self, packet: Packet, ip_layer):
        """Constructs and sends a signed ICMP rejection packet."""
        try:
            dst = ip_layer.src
            if IP in packet:
                response = IP(dst=dst, src=ip_layer.dst)/ICMP(type=3, code=13)/b"Unsigned packet rejected"
                self.sign_packet(response)
                send(response, verbose=False)
                self.logger.log_message(f"[Signing] 📮 Sent signed IPv4 rejection to {dst}")
            elif IPv6 in packet:
                response = IPv6(dst=dst, src=ip_layer.dst)/ICMPv6DestUnreach(code=1)/b"Unsigned IPv6 packet rejected"
                self.sign_packet(response)
                send(response, verbose=False)
                self.logger.log_message(f"[Signing] 📬 Sent signed IPv6 rejection to {dst}")
        except Exception as e:
            pass


class TransportManager:
    """
    Manages the processing and logging of Transport Layer packets (TCP, UDP, etc.).
    This version supports a wide variety of protocols including DNS, DHCP, NTP, TFTP,
    VoIP (SIP/RTP), QUIC, ZeroTier/SSDP, and dynamic ports.
    """

    def __init__(self, router_logger, packet_signer):
        """
        Initializes the TransportManager with a logger and a packet signer.

        Args:
            router_logger: An object for logging messages.
            packet_signer: An object for signing packets (not used in this example,
                           but part of the original class context).
        """
        self.logger = router_logger
        self.packet_signer = packet_signer
        self.logger.log_message("[Transport] Manager initialized.")
        self.voip_port_range = range(10000, 20001)

    def handle_packet(self, packet: Packet, inbound_iface: str) -> bool:
        """
        Processes and logs Transport Layer packet details, with enhanced UDP protocol
        dissection for DNS, DHCP, NTP, TFTP, and VoIP.

        Args:
            packet (Packet): The Scapy packet to process.
            inbound_iface (str): The full Scapy name of the interface the packet
                                 was sniffed on.

        Returns:
            bool: True if the packet contained a recognized transport layer and was
                  processed. False otherwise.
        """
        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6] if packet.haslayer(IPv6) else None

        if not ip_layer:
            return False

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # --- TCP ---
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.sprintf("%TCP.flags%")
            payload_len = len(tcp.payload)
            flag_details = []
            if "S" in flags: flag_details.append("SYN")
            if "F" in flags: flag_details.append("FIN")
            if "A" in flags: flag_details.append("ACK")
            if "R" in flags: flag_details.append("RST")

            self.logger.log_message(
                f"[Transport] 🧵 TCP Packet on {iface_short}: {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport} | "
                f"Flags: {','.join(flag_details)} | Payload: {payload_len}"
            )
            # Example hook: Detect SYN scan
            if "SYN" in flag_details and payload_len == 0:
                self.logger.log_message(
                    f"[Transport][⚠️ SCAN] SYN scan suspected from {src_ip} → {dst_ip}:{tcp.dport}"
                )

            # Check for dynamic port 56709
            if tcp.sport == 56709 or tcp.dport == 56709:
                self.logger.log_message(
                    f"[Transport][❔ Dynamic Port] TCP Port 56709 detected from {src_ip}:{tcp.sport} to {dst_ip}:{tcp.dport}."
                )

            return True

        # --- UDP ---
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            payload_len = len(udp.payload)

            self.logger.log_message(
                f"[Transport] 🚀 UDP Packet on {iface_short}: {src_ip}:{udp.sport} → {dst_ip}:{udp.dport} | "
                f"Payload: {payload_len}"
            )

            # Check for specific known UDP protocols
            if udp.dport == 53 and packet.haslayer(DNS):
                self._handle_dns_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.sport == 67 or udp.dport == 68:
                self._handle_dhcp_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport == 443 or udp.sport == 443:
                self._handle_quic_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport == 123 and packet.haslayer(Raw):
                self._handle_ntp_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport == 69 and packet.haslayer(Raw):
                self._handle_tftp_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport == 5060 or udp.sport == 5060:
                self._handle_sip_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport in self.voip_port_range or udp.sport in self.voip_port_range:
                self._handle_rtp_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport == 9993 or udp.sport == 9993:
                self._handle_zerotier_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport == 1900 or udp.sport == 1900:
                self._handle_ssdp_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport == 3702 or udp.sport == 3702:
                self._handle_ws_discovery_packet(packet, src_ip, dst_ip, udp.sport, udp.dport)
            elif udp.dport == 51163 or udp.sport == 51163:
                self.logger.log_message(
                    f"[Transport][❔ Ephemeral Port] UDP Port 51163 detected from {src_ip}:{udp.sport} to {dst_ip}:{udp.dport}. "
                    "This is an ephemeral port, often used by client applications."
                )
            elif udp.dport == 54742 or udp.sport == 54742:
                self.logger.log_message(
                    f"[Transport][❔ Ephemeral Port] UDP Port 54742 detected from {src_ip}:{udp.sport} to {dst_ip}:{udp.dport}."
                )
            else:
                self.logger.log_message(
                    f"[Transport][❔ Undecoded] Unknown UDP protocol on ports {udp.sport} → {udp.dport}. "
                    f"Payload size: {payload_len}"
                )

            return True

        return False

    def _bytes_to_str(self, data: bytes) -> str:
        """
        Safely decodes bytes to a string, ignoring any decoding errors.
        """
        return data.decode('utf-8', errors='ignore')

    def _handle_dns_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for DNS packets."""
        dns = packet[DNS]
        query_name = "N/A"
        if dns.qr == 0 and dns.qd:  # It's a query
            query_name = self._bytes_to_str(dns.qd.qname)
            self.logger.log_message(
                f"[Transport][🔍 DNS] Query from {src_ip}:{sport} for domain '{query_name}'"
            )
        elif dns.qr == 1 and dns.an:  # It's a response
            query_name = self._bytes_to_str(dns.qd.qname) if dns.qd else "N/A"
            answers = dns.ancount
            self.logger.log_message(
                f"[Transport][🔍 DNS] Response to {dst_ip}:{dport} for '{query_name}' with {answers} answers."
            )
        else:
            self.logger.log_message(
                f"[Transport][🔍 DNS] Malformed or unrecognized DNS packet from {src_ip}:{sport}"
            )

    def _handle_dhcp_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for DHCP packets."""
        if packet.haslayer(BOOTP):
            bootp = packet[BOOTP]
            dhcp_message_type = "N/A"
            if packet.haslayer(DHCP):
                for opt in packet[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type':
                        dhcp_message_type = opt[1]
                        break

            self.logger.log_message(
                f"[Transport][⚙️ DHCP] {dhcp_message_type} packet from {src_ip}:{sport} to {dst_ip}:{dport} "
                f"Client MAC: {bootp.chaddr.hex()}"
            )
        else:
            self.logger.log_message(
                f"[Transport][⚙️ DHCP] DHCP-related UDP packet from {src_ip}:{sport}, no BOOTP layer found."
            )

    def _handle_quic_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for QUIC packets."""
        if packet.haslayer(Raw):
            raw_data = bytes(packet[Raw].load)
            if len(raw_data) >= 6:
                first_byte = raw_data[0]
                is_long_header = (first_byte & 0x80) == 0x80  # MSB is 1 for long header

                if is_long_header:
                    # Long Header Parsing
                    packet_type = (first_byte & 0x30) >> 4
                    version_bytes = raw_data[1:5]
                    version_hex = version_bytes.hex()

                    dcid_len = raw_data[5]
                    scid_len = raw_data[6 + dcid_len]

                    # Assuming a fixed offset for simplicity, actual parsing is more complex
                    try:
                        dcid = raw_data[6:6 + dcid_len].hex()
                        scid = raw_data[7 + dcid_len:7 + dcid_len + scid_len].hex()

                        packet_type_str = {
                            0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"
                        }.get(packet_type, "Unknown")

                        self.logger.log_message(
                            f"[Transport][🌐 QUIC] Long Header ({packet_type_str}) from {src_ip}:{sport} | "
                            f"Version: 0x{version_hex} | DCID: {dcid} | SCID: {scid}"
                        )
                    except IndexError:
                        self.logger.log_message(
                            f"[Transport][🌐 QUIC] Malformed Long Header from {src_ip}:{sport}"
                        )

                else:
                    # Short Header Parsing
                    dcid_len = 8  # A common guess, but not explicitly defined in the header
                    dcid = raw_data[1:1 + dcid_len].hex() if len(raw_data) > 1 else "?"
                    spin_bit = (first_byte & 0x20) >> 5
                    key_phase = (first_byte & 0x04) >> 2

                    self.logger.log_message(
                        f"[Transport][🌐 QUIC] Short Header from {src_ip}:{sport} | "
                        f"DCID: {dcid} | Spin Bit: {spin_bit} | Key Phase: {key_phase}"
                    )

                # Further dissect QUIC frames
                quic_payload_start = 7 + dcid_len + scid_len if is_long_header else 1 + dcid_len
                self._inspect_quic_frames(raw_data[quic_payload_start:], src_ip, dport)
        else:
            self.logger.log_message(
                f"[Transport][🌐 QUIC] UDP on port 443 detected, but no Raw payload."
            )

    def _inspect_quic_frames(self, data: bytes, src_ip: str, dport: int):
        """
        Parses and logs details of QUIC frames within a packet payload.

        Args:
            data (bytes): The raw QUIC payload (without the header).
            src_ip (str): The source IP of the packet.
            dport (int): The destination port of the packet.
        """
        i = 0
        while i < len(data):
            try:
                first_byte = data[i]
                frame_type = first_byte & 0x3F  # Mask for frame type

                # Stream Frame
                if 0x08 <= first_byte <= 0x0F:
                    stream_id, = struct.unpack("!Q", data[i + 1:i + 9])
                    frame_len = len(data) - i  # For simplicity, assume one stream frame per packet
                    self.logger.log_message(
                        f"[Transport][🌐 QUIC Frame] STREAM | Stream ID: {stream_id} | Length: {frame_len}"
                    )
                    i += frame_len  # Exit loop as we've processed the rest of the payload

                # ACK Frame
                elif frame_type == 0x02:
                    # Very simple ACK parsing, not a full implementation
                    ack_delay, = struct.unpack("!H", data[i + 1:i + 3])
                    self.logger.log_message(
                        f"[Transport][🌐 QUIC Frame] ACK | Delay: {ack_delay}"
                    )
                    i += 3  # Move past this simple ACK frame

                # CRYPTO Frame
                elif frame_type == 0x06:
                    offset, length = struct.unpack("!II", data[i + 1:i + 9])
                    self.logger.log_message(
                        f"[Transport][🌐 QUIC Frame] CRYPTO | Offset: {offset} | Length: {length}"
                    )
                    i += 9 + length  # Move past the frame

                # PADDING Frame
                elif frame_type == 0x00:
                    self.logger.log_message(f"[Transport][🌐 QUIC Frame] PADDING")
                    i += 1

                # PING Frame
                elif frame_type == 0x01:
                    self.logger.log_message(f"[Transport][🌐 QUIC Frame] PING")
                    i += 1

                # Connection Close
                elif frame_type == 0x1C or frame_type == 0x1D:
                    self.logger.log_message(f"[Transport][🌐 QUIC Frame] CONNECTION_CLOSE")
                    i += len(data)  # Exit after seeing a close frame

                else:
                    self.logger.log_message(
                        f"[Transport][🌐 QUIC Frame] Unknown frame type: 0x{first_byte:02x}"
                    )
                    # To avoid an infinite loop on a malformed packet, we'll exit
                    break

            except struct.error:
                self.logger.log_message(
                    f"[Transport][🌐 QUIC Frame] Malformed frame detected. Exiting frame inspection."
                )
                break
            except IndexError:
                self.logger.log_message(
                    f"[Transport][🌐 QUIC Frame] End of packet data reached while parsing frame."
                )
                break

    def _handle_ntp_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for NTP packets."""
        raw_data = bytes(packet[Raw].load)
        if len(raw_data) >= 48:  # A standard NTP packet is 48 bytes
            try:
                first_byte = raw_data[0]
                li = (first_byte >> 6) & 0x03  # Leap Indicator (2 bits)
                vn = (first_byte >> 3) & 0x07  # Version Number (3 bits)
                mode = first_byte & 0x07  # Mode (3 bits)
                stratum = raw_data[1]  # Stratum (1 byte)

                mode_str = {1: "Symmetric Active", 2: "Symmetric Passive", 3: "Client",
                            4: "Server", 5: "Broadcast"}.get(mode, "Unknown")

                self.logger.log_message(
                    f"[Transport][🕰️ NTP] NTP packet from {src_ip}:{sport} | "
                    f"Mode: {mode_str} | Version: {vn} | Stratum: {stratum}"
                )
            except IndexError:
                self.logger.log_message(
                    f"[Transport][🕰️ NTP] Malformed NTP packet from {src_ip}:{sport}"
                )


    def _handle_tftp_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for TFTP packets."""
        raw_data = bytes(packet[Raw].load)
        if len(raw_data) >= 2:
            try:
                opcode = struct.unpack("!H", raw_data[0:2])[0]
                opcode_str = {1: "RRQ (Read Request)", 2: "WRQ (Write Request)",
                              3: "DATA", 4: "ACK", 5: "ERROR"}.get(opcode, "Unknown")

                if opcode == 3 or opcode == 4:
                    if len(raw_data) >= 4:
                        block_number = struct.unpack("!H", raw_data[2:4])[0]
                        self.logger.log_message(
                            f"[Transport][📄 TFTP] {opcode_str} from {src_ip}:{sport} to {dst_ip}:{dport} | "
                            f"Block #: {block_number}"
                        )
                    else:
                        self.logger.log_message(
                            f"[Transport][📄 TFTP] Malformed {opcode_str} packet from {src_ip}:{sport}"
                        )
                else:
                    self.logger.log_message(
                        f"[Transport][📄 TFTP] {opcode_str} from {src_ip}:{sport} to {dst_ip}:{dport}"
                    )
            except (struct.error, IndexError):
                self.logger.log_message(
                    f"[Transport][📄 TFTP] Malformed TFTP packet from {src_ip}:{sport}"
                )

    def _handle_sip_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for SIP packets."""
        if packet.haslayer(Raw):
            raw_data = bytes(packet[Raw].load)
            try:
                # SIP is a text-based protocol, check for key strings in the payload
                if raw_data.startswith(b"INVITE") or raw_data.startswith(b"REGISTER") or raw_data.startswith(b"BYE"):
                    first_line = raw_data.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                    self.logger.log_message(
                        f"[Transport][📞 SIP] Request from {src_ip}:{sport} to {dst_ip}:{dport} | "
                        f"Method: {first_line.split(' ')[0]}"
                    )
                elif raw_data.startswith(b"SIP/2.0"):
                    status_line = raw_data.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                    self.logger.log_message(
                        f"[Transport][📞 SIP] Response from {src_ip}:{sport} to {dst_ip}:{dport} | "
                        f"Status: {status_line.split(' ', 1)[1]}"
                    )
            except (UnicodeDecodeError, IndexError):
                self.logger.log_message(
                    f"[Transport][📞 SIP] Malformed or undecodable SIP packet from {src_ip}:{sport}"
                )

    def _handle_rtp_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for RTP packets."""
        if packet.haslayer(Raw) and len(packet[Raw].load) >= 12:  # Min RTP header is 12 bytes
            raw_data = bytes(packet[Raw].load)
            try:
                # RTP header: first byte is version, padding, extension, CC. Second byte is marker, payload type
                version = (raw_data[0] >> 6) & 0x03
                payload_type = raw_data[1] & 0x7F

                # Check for common RTP version 2
                if version == 2:
                    # Very simple lookup for common payload types
                    payload_type_str = {
                        0: "PCMU", 8: "PCMA", 10: "L16", 96: "G.722", 97: "H.264"
                    }.get(payload_type, f"Unknown ({payload_type})")

                    self.logger.log_message(
                        f"[Transport][🔊 RTP] Media stream from {src_ip}:{sport} to {dst_ip}:{dport} | "
                        f"Version: {version} | Payload Type: {payload_type_str}"
                    )
                else:
                    self.logger.log_message(
                        f"[Transport][🔊 RTP] Non-RTP packet on VoIP port, or unknown version {version}"
                    )
            except IndexError:
                self.logger.log_message(
                    f"[Transport][🔊 RTP] Malformed RTP packet from {src_ip}:{sport}"
                )

    def _handle_zerotier_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for ZeroTier-like packets on UDP port 9993."""
        self.logger.log_message(
            f"[Transport][🛰️ ZeroTier] UDP port 9993 traffic detected from {src_ip}:{sport} to {dst_ip}:{dport}. "
            "Likely ZeroTier, Cisco ACS, or other application."
        )

    def _handle_ssdp_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for SSDP/UPnP packets on UDP port 1900."""
        self.logger.log_message(
            f"[Transport][🔌 SSDP] SSDP/UPnP packet detected from {src_ip}:{sport} to {dst_ip}:{dport}. "
            "Likely for device discovery."
        )

    def _handle_ws_discovery_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for WS-Discovery packets on UDP port 3702."""
        self.logger.log_message(
            f"[Transport][🔍 WS-Discovery] WS-Discovery packet detected from {src_ip}:{sport} to {dst_ip}:{dport}. "
            "Likely for dynamic device discovery."
        )


class HTTPSManager:
    """
    Manages passive monitoring of HTTPS/TLS and TCP traffic.
    This enhanced version provides detailed logging for TLS 1.2 and 1.3 handshakes,
    and now includes a comprehensive analysis of TCP connection establishment,
    termination, and key options.
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.cipher_map = self.build_cipher_suite_map()
        self.router_logger.log_message("[HTTPSManager] 🔒 Initialized for passive TLS/TCP monitoring.")
        self.router_logger.log_message(f"[HTTPSManager] 🗺️  Built map with {len(self.cipher_map)} cipher suites.")

        self.TLS_VERSIONS = {
            0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"
        }

        self.TLS_HANDSHAKE_TYPES = {
            0: "hello_request_RESERVED", 1: "client_hello", 2: "server_hello",
            3: "hello_verify_request_RESERVED", 4: "new_session_ticket",
            5: "end_of_early_data", 6: "hello_retry_request",
            8: "encrypted_extensions", 11: "certificate",
            12: "server_key_exchange_RESERVED", 13: "certificate_request",
            14: "server_hello_done_RESERVED", 15: "certificate_verify",
            16: "client_key_exchange_RESERVED", 20: "finished",
            21: "certificate_url_RESERVED", 22: "certificate_status_RESERVED",
            23: "supplemental_data_RESERVED", 24: "key_update",
            254: "message_hash"
        }

        self.TLS_EXTENSIONS = {
            0: "server_name", 1: "max_fragment_length", 2: "client_certificate_url",
            3: "trusted_ca_keys", 4: "truncated_hmac", 5: "status_request",
            6: "user_mapping", 7: "client_authz", 8: "server_authz", 9: "cert_type",
            10: "supported_groups", 11: "ec_point_formats", 12: "srp",
            13: "signature_algorithms", 14: "use_srtp", 15: "heartbeat",
            16: "application_layer_protocol_negotiation", 17: "status_request_v2",
            18: "signed_certificate_timestamp", 19: "client_certificate_type",
            20: "server_certificate_type", 21: "padding", 22: "encrypt_then_mac",
            23: "extended_master_secret", 24: "token_binding", 25: "cached_info",
            26: "tls_lts", 27: "compress_certificate", 28: "record_size_limit",
            29: "pwd_protect", 30: "pwd_clear", 31: "password_salt",
            32: "ticket_pinning", 33: "tls_cert_with_extern_psk", 34: "delegated_credential",
            35: "session_ticket", 36: "TLMSP", 37: "TLMSP_proxying",
            38: "TLMSP_delegate", 39: "supported_ekt_ciphers", 40: "Reserved",
            41: "pre_shared_key", 42: "early_data", 43: "supported_versions",
            44: "cookie", 45: "psk_key_exchange_modes", 46: "Reserved",
            47: "certificate_authorities", 48: "oid_filters", 49: "post_handshake_auth",
            50: "signature_algorithms_cert", 51: "key_share", 52: "transparency_info",
            53: "connection_id (deprecated)", 54: "connection_id", 55: "external_id_hash",
            56: "external_session_id", 57: "quic_transport_parameters", 58: "ticket_request",
            59: "dnssec_chain", 60: "sequence_number_encryption_algorithms", 61: "rrc",
            62: "tls_flags", 2570: "Reserved", 65037: "encrypted_client_hello",
            65281: "renegotiation_info"
        }

        self.TLS_ALERT_LEVEL = {1: "warning", 2: "fatal"}
        self.TLS_ALERT_DESCRIPTION = {
            0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
            22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
            43: "unsupported_certificate", 46: "certificate_unknown", 47: "illegal_parameter",
            48: "unknown_ca", 49: "access_denied", 50: "decode_error",
            51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
            80: "internal_error", 90: "user_canceled", 112: "unrecognized_name"
        }

        self.ALPN_PROTOCOLS = {
            b'http/0.9': 'HTTP/0.9', b'http/1.0': 'HTTP/1.0', b'http/1.1': 'HTTP/1.1',
            b'spdy/1': 'SPDY/1', b'spdy/2': 'SPDY/2', b'spdy/3': 'SPDY/3',
            b'stun.turn': 'Traversal Using Relays around NAT (TURN)',
            b'stun.nat-discovery': 'NAT discovery using STUN', b'h2': 'HTTP/2 over TLS',
            b'h2c': 'HTTP/2 over TCP', b'webrtc': 'WebRTC Media and Data',
            b'c-webrtc': 'Confidential WebRTC Media and Data', b'ftp': 'FTP',
            b'imap': 'IMAP', b'pop3': 'POP3', b'managesieve': 'ManageSieve',
            b'coap': 'CoAP (over TLS)', b'co': 'CoAP (over DTLS)',
            b'xmpp-client': 'XMPP jabber:client', b'xmpp-server': 'XMPP jabber:server',
            b'acme-tls/1': 'acme-tls/1', b'mqtt': 'MQTT', b'dot': 'DNS-over-TLS',
            b'ntske/1': 'Network Time Security Key Establishment', b'sunrpc': 'SunRPC',
            b'h3': 'HTTP/3', b'smb': 'SMB2', b'irc': 'IRC', b'nntp': 'NNTP (reading)',
            b'nnsp': 'NNTP (transit)', b'doq': 'DoQ', b'sip/2': 'SIP',
            b'tds/8.0': 'TDS/8.0', b'dicom': 'DICOM', b'postgresql': 'PostgreSQL',
            b'radius/1.0': 'RADIUS/1.0', b'radius/1.1': 'RADIUS/1.1'
        }

        self.tcp_state_map = {}  # Tracks TCP states by connection tuple
        self.TCP_FLAGS = {
            'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST', 'P': 'PSH', 'U': 'URG'
        }

    def build_cipher_suite_map(self) -> dict:
        """
        Dynamically builds a map of TLS cipher suite IDs to their string names
        for compatibility with various Scapy versions.
        """
        cipher_map = {}
        cipher_map[0x1301] = "TLS_AES_128_GCM_SHA256"
        cipher_map[0x1302] = "TLS_AES_256_GCM_SHA384"
        cipher_map[0x1303] = "TLS_CHACHA20_POLY1305_SHA256"
        cipher_map[0xC02B] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        cipher_map[0xC02F] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        return cipher_map

    def handle_packet(self, packet: Packet, inbound_iface: str) -> bool:
        """
        Processes an incoming packet, first handling the TCP layer and then
        iterating through any TLS records to detect and process all handshake messages.
        """
        processed = False
        if packet.haslayer(TCP):
            self.router_logger.log_message(self._generate_tcp_summary(packet, inbound_iface))
            self._handle_tcp_options(packet, inbound_iface)
            self._handle_tcp_state(packet, inbound_iface)
            processed = True

        # Now check for TLS records on top of TCP
        if packet.haslayer(TLS):
            tls_layer = packet.getlayer(TLS)
            while tls_layer:
                if tls_layer.haslayer(TLSPlaintext):
                    if tls_layer.type == 22 and tls_layer.payload:
                        processed = self._handle_tls_handshake_payload(tls_layer.payload, inbound_iface) or processed
                    elif tls_layer.type == 21:
                        processed = self._handle_tls_alert(tls_layer.payload, inbound_iface) or processed
                    elif tls_layer.type == 23:
                        processed = self._handle_tls_app_data(inbound_iface) or processed
                elif tls_layer.haslayer(TLSCiphertext):
                    processed = self._handle_tls_app_data(inbound_iface) or processed

                tls_layer = tls_layer.payload if hasattr(tls_layer, 'payload') else None
                if not isinstance(tls_layer, Packet):
                    tls_layer = None

        return processed

    def _generate_tcp_summary(self, packet: Packet, inbound_iface: str) -> str:
        """
        Generates a summary string for a detected TCP packet.
        """
        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        transport_layer = packet.getlayer(TCP)

        if not ip_layer or not transport_layer:
            return f"[TCP] 🔄 TCP packet detected on {iface_short}. Cannot determine source/dest."

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = transport_layer.sport
        dst_port = transport_layer.dport

        flags_str = ",".join([self.TCP_FLAGS.get(f, f) for f in str(transport_layer.flags)])

        return (f"[TCP] 🔄 TCP packet on {iface_short}: "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                f"Flags: {flags_str} | "
                f"Seq: {transport_layer.seq} | Ack: {transport_layer.ack}")

    def _handle_tcp_state(self, packet: Packet, inbound_iface: str):
        """
        Monitors and logs TCP connection state changes based on flags.
        This provides a high-level view of the three-way handshake and termination.
        """
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        tcp_layer = packet.getlayer(TCP)

        src_ip, src_port = ip_layer.src, tcp_layer.sport
        dst_ip, dst_port = ip_layer.dst, tcp_layer.dport

        # Use a consistent tuple for tracking the conversation, regardless of direction
        if src_port < dst_port:
            conn_key = (src_ip, src_port, dst_ip, dst_port)
        else:
            conn_key = (dst_ip, dst_port, src_ip, src_port)

        current_state = self.tcp_state_map.get(conn_key, "CLOSED")

        flags = tcp_layer.flags

        # Connection Establishment (Three-way handshake)
        if flags == 2:  # SYN
            if current_state == "CLOSED":
                self.router_logger.log_message(
                    f"[TCP] Handshake Initiated: Client {src_ip}:{src_port} sent SYN. ➡️ State: SYN-SENT.")
                self.tcp_state_map[conn_key] = "SYN-SENT"
        elif flags == 18:  # SYN-ACK
            if current_state == "SYN-SENT":
                self.router_logger.log_message(
                    f"[TCP] Handshake Progress: Server {src_ip}:{src_port} replied with SYN-ACK. 🔄 State: SYN-RECEIVED.")
                self.tcp_state_map[conn_key] = "SYN-RECEIVED"
        elif flags == 16:  # ACK
            if current_state == "SYN-RECEIVED":
                self.router_logger.log_message(
                    f"[TCP] Handshake Completed: Client {src_ip}:{src_port} sent ACK. ✅ Connection ESTABLISHED.")
                self.tcp_state_map[conn_key] = "ESTABLISHED"

        # Connection Termination (Four-way handshake)
        elif flags == 17:  # FIN-ACK
            if current_state == "ESTABLISHED":
                self.router_logger.log_message(
                    f"[TCP] Termination Started: {src_ip}:{src_port} sent FIN-ACK. ✂️ State: FIN-WAIT-1.")
                self.tcp_state_map[conn_key] = "FIN-WAIT-1"
            elif current_state == "CLOSE-WAIT":
                self.router_logger.log_message(
                    f"[TCP] Termination Progress: {src_ip}:{src_port} sent FIN-ACK. ⏳ State: LAST-ACK.")
                self.tcp_state_map[conn_key] = "LAST-ACK"
        elif flags == 16 and (current_state == "FIN-WAIT-1" or current_state == "LAST-ACK"):  # ACK
            # A simple ACK in this state means we are acknowledging a FIN
            if current_state == "FIN-WAIT-1":
                self.router_logger.log_message(
                    f"[TCP] Termination Progress: {src_ip}:{src_port} sent ACK. ➡️ State: FIN-WAIT-2.")
                self.tcp_state_map[conn_key] = "FIN-WAIT-2"
            elif current_state == "LAST-ACK":
                self.router_logger.log_message(
                    f"[TCP] Termination Completed: {src_ip}:{src_port} sent ACK. 🏁 Connection CLOSED.")
                self.tcp_state_map.pop(conn_key, None)
        elif flags == 20:  # PSH-ACK (often used with FIN-ACK)
            # This is a simplification; a full state machine is more complex.
            pass
        elif flags == 4:  # RST
            self.router_logger.log_message(
                f"[TCP] Connection Aborted: {src_ip}:{src_port} sent RST. ⚠️ Connection reset.")
            self.tcp_state_map.pop(conn_key, None)

    def _handle_tcp_options(self, packet: Packet, inbound_iface: str):
        """
        Parses and logs details about TCP options, such as Window Scale, Timestamps, and SACK.
        """
        tcp_layer = packet.getlayer(TCP)
        if hasattr(tcp_layer, 'options') and tcp_layer.options:
            self.router_logger.log_message(f"[TCP]   - Options ({len(tcp_layer.options)} total):")
            for opt in tcp_layer.options:
                opt_name = opt[0]
                if opt_name == 'WScale':
                    scale_val = opt[1]
                    self.router_logger.log_message(f"[TCP]     - Found Option: Window Scale (WScale={scale_val}) 📈")
                elif opt_name == 'Timestamp':
                    ts_val, ts_ecr = opt[1]
                    self.router_logger.log_message(
                        f"[TCP]     - Found Option: Timestamps (TSval={ts_val}, TSecr={ts_ecr}) ⏰")
                elif opt_name == 'SAckOK':
                    self.router_logger.log_message(
                        f"[TCP]     - Found Option: Selective Acknowledgment (SACK) Permitted ✅")
                elif opt_name == 'MSS':
                    mss_val = opt[1]
                    self.router_logger.log_message(f"[TCP]     - Found Option: Maximum Segment Size (MSS={mss_val}) 📝")
                elif opt_name == 'NOP':
                    continue  # No-op, just padding
                else:
                    self.router_logger.log_message(f"[TCP]     - Found Unknown Option: {opt_name} ❓")

    def _generate_tls_summary(self, packet: Packet, inbound_iface: str) -> str:
        """
        Generates a summary string for a detected TLS packet.
        """
        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)

        if not ip_layer or not transport_layer:
            return f"[TLS] 🔐 TLS packet detected on {iface_short}. Cannot determine source/dest."

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = transport_layer.sport
        dst_port = transport_layer.dport

        tls_layer = packet.getlayer(TLS)
        record_type = "Unknown"
        if tls_layer and hasattr(tls_layer, "type"):
            record_type = {
                20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake",
                23: "ApplicationData", 24: "Heartbeat"
            }.get(tls_layer.type, f"Unknown ({tls_layer.type})")

        return (f"[TLS] 🔐 TLS packet detected on {iface_short}: "
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                f"Record Type: {record_type}")

    def _handle_tls_handshake_payload(self, payload: Packet, iface_short: str) -> bool:
        """
        Processes TLS handshake messages from within a TLSPlaintext payload.
        """
        processed = False
        handshake_type_val = payload.type
        handshake_type_str = self.TLS_HANDSHAKE_TYPES.get(handshake_type_val, f"Unknown (0x{handshake_type_val:02x})")

        self.router_logger.log_message(
            f"[HTTPS] 🤝 TLS Handshake Message: {handshake_type_str} detected on {iface_short}.")

        if handshake_type_val == 1:  # client_hello
            self._handle_client_hello(payload, iface_short)
            processed = True
        elif handshake_type_val == 2:  # server_hello
            self._handle_server_hello(payload, iface_short)
            processed = True
        elif handshake_type_val == 4:  # new_session_ticket
            self.router_logger.log_message("[HTTPS]   - 🎟️ New session ticket issued, enabling session resumption.")
            processed = True
        elif handshake_type_val == 5:  # end_of_early_data:
            self.router_logger.log_message("[HTTPS]   - ➡️ End of early data signal. Handshake now begins.")
            processed = True
        elif handshake_type_val == 6:  # hello_retry_request
            self.router_logger.log_message(
                "[HTTPS]   - 🔄 A HelloRetryRequest was received, client will re-send ClientHello.")
            processed = True
        elif handshake_type_val == 8:  # encrypted_extensions
            self.router_logger.log_message("[HTTPS]   - 📝 Encrypted extensions received. Server's final parameters.")
            self._handle_extensions_from_payload(payload)
            processed = True
        elif handshake_type_val == 11:  # certificate
            self._handle_certificate(payload, iface_short)
            processed = True
        elif handshake_type_val == 13:  # certificate_request
            self.router_logger.log_message("[HTTPS]   - 🤝 Server requested a client certificate (Mutual TLS).")
            processed = True
        elif handshake_type_val == 15:  # certificate_verify
            self.router_logger.log_message("[HTTPS]   - ✅ Certificate verify message received.")
            processed = True
        elif handshake_type_val == 20:  # finished
            self.router_logger.log_message("[HTTPS]   - 🎉 Handshake Finished message. Connection keys established.")
            processed = True
        elif handshake_type_val == 24:  # key_update
            self.router_logger.log_message("[HTTPS]   - 🔑 Key Update message received, keys are being renegotiated.")
            processed = True

        return processed

    def _handle_client_hello(self, client_hello: Packet, iface_short: str):
        """Processes and logs details from a TLS ClientHello message."""
        version_str = self.TLS_VERSIONS.get(client_hello.version, f"Unknown (0x{client_hello.version:04x})")
        self.router_logger.log_message(f"[HTTPS]   - Version Offered: {version_str}")
        if hasattr(client_hello, 'ciphersuites'):
            self.router_logger.log_message(f"[HTTPS]   - Ciphers Offered: {len(client_hello.ciphersuites)}")

        if hasattr(client_hello, 'extensions'):
            self._handle_extensions_from_payload(client_hello)
        else:
            self.router_logger.log_message("[HTTPS]   - No extensions found.")

    def _handle_server_hello(self, server_hello: Packet, iface_short: str):
        """Processes and logs details from a TLS ServerHello message."""
        version_str = self.TLS_VERSIONS.get(server_hello.version, f"Unknown (0x{server_hello.version:04x})")
        self.router_logger.log_message(f"[HTTPS]   - Version Negotiated: {version_str}")
        cipher_suite = server_hello.cipher_suite
        cipher_name = self.cipher_map.get(cipher_suite, f"Unknown (ID: 0x{cipher_suite:04x})")
        self.router_logger.log_message(f"[HTTPS]   - Cipher Suite Chosen: {cipher_name}")

        if hasattr(server_hello, 'extensions'):
            self._handle_extensions_from_payload(server_hello)
        else:
            self.router_logger.log_message("[HTTPS]   - No extensions found.")

    def _handle_extensions_from_payload(self, payload: Packet):
        """Parses and logs details from TLS extensions in a handshake message."""
        if hasattr(payload, 'extensions') and payload.extensions:
            self.router_logger.log_message(f"[HTTPS]   - Extensions ({len(payload.extensions)} total):")
            for ext in payload.extensions:
                ext_type = getattr(ext, 'type', None)
                ext_name = self.TLS_EXTENSIONS.get(ext_type, f"Unknown (ID: {ext_type})")
                self.router_logger.log_message(f"[HTTPS]     - Found Extension: {ext_name}")

                # Special handler for Server Name Indication (SNI)
                if ext_type == 0 and hasattr(ext, 'servernames'):
                    sni_name = ext.servernames[0].servername.decode('utf-8', 'ignore')
                    self.router_logger.log_message(f"[HTTPS]       - SNI: {sni_name} 🌐")

                # Special handler for Application Layer Protocol Negotiation (ALPN)
                if ext_type == 16 and hasattr(ext, 'alpn_protocols'):
                    alpn_list = [self.ALPN_PROTOCOLS.get(p, p.decode('utf-8', 'ignore')) for p in ext.alpn_protocols]
                    self.router_logger.log_message(f"[HTTPS]       - ALPN Protocols: {', '.join(alpn_list)} 💬")

                # Special handler for Supported Versions
                if ext_type == 43 and hasattr(ext, 'versions'):
                    version_list = [self.TLS_VERSIONS.get(v, f"Unknown (0x{v:04x})") for v in ext.versions]
                    self.router_logger.log_message(f"[HTTPS]       - Supported Versions: {', '.join(version_list)} 📜")

    def _handle_certificate(self, cert_layer: Packet, iface_short: str):
        """Processes and logs details from a TLS Certificate message."""
        num_certs = len(cert_layer.certs) if hasattr(cert_layer, 'certs') else 0
        self.router_logger.log_message(f"[HTTPS] 📜 Certificate detected on {iface_short}.")
        self.router_logger.log_message(f"[HTTPS]   - Certificate Chain Length: {num_certs}")
        if num_certs > 0:
            server_cert = cert_layer.certs[0]
            if hasattr(server_cert, 'subject') and hasattr(server_cert.subject, 'rdn_seq'):
                for rdn_sequence in server_cert.subject.rdn_seq:
                    for rdn in rdn_sequence:
                        if hasattr(rdn, 'type') and rdn.type.val == '2.5.4.3':
                            cn = rdn.value.val.decode('utf-8', 'ignore')
                            self.router_logger.log_message(f"[HTTPS]   - Certificate CN: {cn} 👨‍💻")
                            break
            if hasattr(server_cert, 'not_before') and hasattr(server_cert, 'not_after'):
                valid_from = server_cert.not_before.val.decode('utf-8', 'ignore')
                valid_to = server_cert.not_after.val.decode('utf-8', 'ignore')
                self.router_logger.log_message(f"[HTTPS]   - Validity: {valid_from} to {valid_to} 📅")

    def _handle_tls_alert(self, alert_payload: Packet, iface_short: str) -> bool:
        """Processes and logs details from a TLS Alert message."""
        alert_layer = alert_payload.getlayer(TLSAlert)
        if alert_layer:
            level = self.TLS_ALERT_LEVEL.get(alert_layer.level, "Unknown")
            description = self.TLS_ALERT_DESCRIPTION.get(alert_layer.descr, "Unknown")
            self.router_logger.log_message(
                f"[HTTPS] ⚠️  Alert on {iface_short}: Level={level}, Desc='{description}'")
            return True
        return False

    def _handle_tls_app_data(self, iface_short: str) -> bool:
        """Logs the presence of encrypted application data."""
        self.router_logger.log_message(f"[HTTPS] 📦 Encrypted Application Data on {iface_short}.")
        return True
class KerberosManager:
    """
    Manages Kerberos protocol traffic within the router.
    Can be used for passive analysis, logging, or active intervention/proxying.
    """

    def __init__(self, router_logger, packet_writer):
        self.router_logger = router_logger
        self.packet_writer = packet_writer # For sending crafted responses if needed
        self.kerberos_sessions = {} # Tracks ongoing Kerberos exchanges (e.g., for correlating requests/responses)
        self._keytab_entries = {} # Stores principal keys (e.g., from a 'keytab' file or configuration)
        self._stop_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None

        self.router_logger.log_message("[KerberosManager] Initialized.")

    def start(self):
        """Starts background threads for session management, if any."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._session_cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        self.router_logger.log_message("[KerberosManager] Started session cleanup thread.")

    def stop(self):
        """Stops all background threads."""
        self._stop_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)
        self.router_logger.log_message("[KerberosManager] Stopped.")

    def add_keytab_entry(self, principal_name: str, key_type: int, key_value_hex: str):
        """
        Adds a key for a specific principal to be used for decryption/encryption.
        Args:
            principal_name (str): The Kerberos principal (e.g., "host/router.domain.com@DOMAIN.COM").
            key_type (int): The encryption type (etype) as an integer (e.g., 23 for AES256-CTS-HMAC-SHA1-96).
            key_value_hex (str): The hexadecimal string of the raw key value.
        """
        try:
            key_bytes = bytes.fromhex(key_value_hex)
            self._keytab_entries[principal_name.lower()] = Key(key_type, key=key_bytes)
            self.router_logger.log_message(f"[KerberosManager] Added key for principal: {principal_name}")
        except ValueError as e:
            self.router_logger.log_message(f"[KerberosManager] ❌ Error adding key for {principal_name}: Invalid hex string. {e}")
        except Exception as e:
            self.router_logger.log_message(f"[KerberosManager] ❌ Unexpected error adding key for {principal_name}: {e}")


    def _session_cleanup_loop(self):
        """Background thread to clean up old Kerberos sessions."""
        while not self._stop_event.is_set():
            # Implement logic to clean up old sessions based on timestamp or other criteria
            # For simplicity, we'll just log and sleep here.
            self.router_logger.log_message("[KerberosManager] Performing session cleanup...")
            # Placeholder for actual cleanup logic:
            # Iterate self.kerberos_sessions and remove entries older than a certain threshold.
            # Example: for session_id, session_data in list(self.kerberos_sessions.items()):
            #              if time.time() - session_data['timestamp'] > SOME_TIMEOUT:
            #                  del self.kerberos_sessions[session_id]

            self._stop_event.wait(60) # Check every 60 seconds

    def handle_kerberos_packet(self, packet: Packet, inbound_iface: str, interfaces_config: Dict[str, Any]):
        """
        Processes an incoming Kerberos packet.
        Args:
            packet: The Scapy packet containing the Kerberos layer.
            inbound_iface (str): The full Scapy name of the interface the packet was sniffed on.
            interfaces_config (dict): The router's internal interfaces configuration.
        Returns:
            bool: True if the packet was handled by the Kerberos manager, False otherwise.
        """
        kerb_layer = packet[Kerberos]
        iface_short = inbound_iface.split('_')[-1]
        self.router_logger.log_message(f"[KerberosManager] 🔑 Kerberos packet detected on {iface_short}.")

        try:
            # Identify the Kerberos message type
            msg_type = kerb_layer.root.msgType.val

            if msg_type == KRB_AS_REQ.msgType.val:
                self._handle_as_req(kerb_layer, packet, inbound_iface)
            elif msg_type == KRB_AS_REP.msgType.val:
                self._handle_as_rep(kerb_layer, packet, inbound_iface)
            elif msg_type == KRB_TGS_REQ.msgType.val:
                self._handle_tgs_req(kerb_layer, packet, inbound_iface)
            elif msg_type == KRB_TGS_REP.msgType.val:
                self._handle_tgs_rep(kerb_layer, packet, inbound_iface)
            elif msg_type == KRB_ERROR.msgType.val:
                self._handle_error(kerb_layer, packet, inbound_iface)
            else:
                self.router_logger.log_message(f"[KerberosManager] Unhandled Kerberos message type: {msg_type}")

            return True

        except Exception as e:
            self.router_logger.log_message(f"[KerberosManager] ❌ Error processing Kerberos packet: {e}")
            return False

    def _handle_as_req(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles an AS-REQ packet."""
        as_req = kerb_layer.root
        cname = as_req.reqBody.cname.nameString[0] if as_req.reqBody.cname and as_req.reqBody.cname.nameString else "UNKNOWN"
        crealm = as_req.reqBody.realm if as_req.reqBody.realm else "UNKNOWN"
        etype_str = ", ".join([str(e.val) for e in as_req.reqBody.etype]) if as_req.reqBody.etype else "None"

        self.router_logger.log_message(f"[KerberosManager] AS-REQ from {cname}@{crealm} (ETypes: {etype_str})")

        # Example: Try to decrypt pre-authentication data if present (e.g., PA-ENC-TIMESTAMP)
        for pa_data_item in as_req.padata:
            if pa_data_item.padataType.val == PADATA:
                enc_data = pa_data_item.padataValue
                self.router_logger.log_message(f"[KerberosManager] Attempting to decrypt PA-ENC-TIMESTAMP...")
                # To decrypt, you'd need the client's long-term key, which is usually not available on the router.
                # This is why client AS-REQs are hard to decrypt without the password/keytab.
                # If you *had* the key (e.g., from a known test client), you could do:
                # client_key = self._keytab_entries.get(f"{cname}@{crealm}".lower())
                # if client_key and isinstance(enc_data, EncryptedData):
                #     try:
                #         decrypted_timestamp = enc_data.decrypt(client_key, cls=PA_ENC_TIMESTAMP)
                #         self.router_logger.log_message(f"[KerberosManager] Decrypted PA-ENC-TIMESTAMP: {decrypted_timestamp.patimestamp.ctime}")
                #     except Exception as e:
                #         self.router_logger.log_message(f"[KerberosManager] Failed to decrypt PA-ENC-TIMESTAMP: {e}")
                break # Only try to decrypt the first one

        # Store session info if tracking needed (e.g., for replay detection)
        # self.kerberos_sessions[nonce] = {"client": f"{cname}@{crealm}", "timestamp": time.time(), ...}

    def _handle_as_rep(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles an AS-REP packet."""
        as_rep = kerb_layer.root
        crealm = as_rep.crealm if as_rep.crealm else "UNKNOWN"
        cname = as_rep.cname.nameString[0] if as_rep.cname and as_rep.cname.nameString else "UNKNOWN"
        sname = as_rep.ticket.sname.nameString[0] if as_rep.ticket.sname and as_rep.ticket.sname.nameString else "UNKNOWN"
        srealm = as_rep.ticket.realm if as_rep.ticket.realm else "UNKNOWN"

        self.router_logger.log_message(f"[KerberosManager] AS-REP for {cname}@{crealm} from {sname}@{srealm}")

        # The AS-REP `encPart` contains the EncASRepPart, encrypted with the client's long-term key.
        # This is hard to decrypt passively without the client's password.
        # However, the `ticket.encPart` is encrypted with the KDC's master key (TGT key).
        # If the router holds the TGT key (unlikely in a real scenario, but possible for a test KDC), it could decrypt.
        encrypted_ticket_part = as_rep.ticket.encPart
        if isinstance(encrypted_ticket_part, EncryptedData):
            # Example: Decrypt the TGT if the KDC's master key is known to the manager
            # KDC_TGT_PRINCIPAL = f"krbtgt/{srealm}@{srealm}".lower()
            # tgt_key = self._keytab_entries.get(KDC_TGT_PRINCIPAL)
            # if tgt_key:
            #     try:
            #         decrypted_tgt = encrypted_ticket_part.decrypt(tgt_key, cls=EncTicketPart)
            #         self.router_logger.log_message(f"[KerberosManager] Decrypted TGT for {decrypted_tgt.cname.nameString[0]}@{decrypted_tgt.crealm}")
            #         self.router_logger.log_message(f"[KerberosManager] TGT Session Key Type: {decrypted_tgt.key.keytype.val}")
            #     except Exception as e:
            #         self.router_logger.log_message(f"[KerberosManager] Failed to decrypt TGT: {e}")
            # else:
            #     self.router_logger.log_message(f"[KerberosManager] No KDC TGT key found for {KDC_TGT_PRINCIPAL}.")
            pass # Placeholder for actual decryption logic

    def _handle_tgs_req(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles a TGS-REQ packet."""
        tgs_req = kerb_layer.root
        sname = tgs_req.reqBody.sname.nameString[0] if tgs_req.reqBody.sname and tgs_req.reqBody.sname.nameString else "UNKNOWN"
        realm = tgs_req.reqBody.realm if tgs_req.reqBody.realm else "UNKNOWN"
        self.router_logger.log_message(f"[KerberosManager] TGS-REQ requesting service ticket for {sname}@{realm}")

        # The TGS-REQ contains an Authenticator encrypted with the TGT session key.
        # To decrypt this, you'd need the session key from the previously seen AS-REP's EncASRepPart.
        # This requires robust session tracking.

    def _handle_tgs_rep(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles a TGS-REP packet."""
        tgs_rep = kerb_layer.root
        crealm = tgs_rep.crealm if tgs_rep.crealm else "UNKNOWN"
        cname = tgs_rep.cname.nameString[0] if tgs_rep.cname and tgs_rep.cname.nameString else "UNKNOWN"
        sname = tgs_rep.ticket.sname.nameString[0] if tgs_rep.ticket.sname and tgs_rep.ticket.sname.nameString else "UNKNOWN"
        srealm = tgs_rep.ticket.realm if tgs_rep.ticket.realm else "UNKNOWN"

        self.router_logger.log_message(f"[KerberosManager] TGS-REP for {cname}@{crealm} from {sname}@{srealm}")

        # Similar to AS-REP, the `encPart` is encrypted with the TGT session key (for the EncTGSRepPart).
        # The `ticket.encPart` is encrypted with the service principal's long-term key.
        # If your router acts as that service or has access to the service's keytab, it could decrypt this.
        encrypted_service_ticket_part = tgs_rep.ticket.encPart
        if isinstance(encrypted_service_ticket_part, EncryptedData):
            # Example: Decrypt the service ticket if the service principal's key is known
            # SERVICE_PRINCIPAL = f"{sname}@{srealm}".lower()
            # service_key = self._keytab_entries.get(SERVICE_PRINCIPAL)
            # if service_key:
            #     try:
            #         decrypted_service_ticket = encrypted_service_ticket_part.decrypt(service_key, cls=EncTicketPart)
            #         self.router_logger.log_message(f"[KerberosManager] Decrypted Service Ticket for {decrypted_service_ticket.cname.nameString[0]}@{decrypted_service_ticket.crealm}")
            #     except Exception as e:
            #         self.router_logger.log_message(f"[KerberosManager] Failed to decrypt Service Ticket: {e}")
            pass # Placeholder

    def _handle_error(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles a KRB-ERROR packet."""
        error_msg = kerb_layer.root
        error_code = error_msg.errorCode.val
        e_text = error_msg.eText if error_msg.eText else ""
        sname = error_msg.sname.nameString[0] if error_msg.sname and error_msg.sname.nameString else "UNKNOWN"
        srealm = error_msg.realm if error_msg.realm else "UNKNOWN"

        self.router_logger.log_message(f"[KerberosManager] ⚠️ KRB-ERROR (Code: {error_code}) from {sname}@{srealm}: {e_text}")

        # You can map error codes to meanings for better logging/alerting
        # e.g., if error_code == 6 (KDC_ERR_C_PRINCIPAL_UNKNOWN) log a specific alert.
        # Check RFC 4120 for a full list of error codes.

    # Additional methods could be added here for active Kerberos proxying,
    # or for initiating Kerberos requests from the router itself.

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
            emojis = event_data.get("emojis") or ["📡"]
            self.logger.log_message(RouterRandomMessages("Notifier", f"Sending notification: {event_data['event']}", emojis))

            # Use Scapy to send a simple UDP packet
            # This doesn't require the PacketWriter as it's a simple, infrequent send
            packet = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=message)
            send(packet, verbose=0)

        except Exception as e:
            self.logger.log_message(f"[Notifier] ❌ Failed to send notification: {e}")

class PacketWriter:
    """
    A self-contained class that sends Layer 2 network packets on a dedicated
    thread using a queue. This prevents the calling thread from blocking on I/O.
    Includes per-destination throttling and packet signing support.
    """

    def __init__(self, logger, packet_signer, outbound_load_balancer):
        """
        Initializes the PacketWriter.
        Args:
            logger: Logger instance for logging.
            packet_signer: Instance of PacketSigningManager.
        """
        self.logger = logger
        self.packet_signer = packet_signer
        self.packet_queue = queue.Queue()
        self.worker_thread = None
        self._stop_event = threading.Event()
        self.logger.log_message("[PacketWriter] Initialized.")

        # Destination throttling
        self.packet_writing_table = defaultdict(lambda: {"count": 0, "last_sent": 0})
        self.THRESHOLD_PER_DST = 5
        self.RESET_INTERVAL = 1  # seconds
        self.outbound_load_balancer = outbound_load_balancer

    def _worker_loop(self):
        """The main loop for the worker thread that sends packets."""
        self.logger.log_message("[PacketWriter] Worker thread started.")
        while not self._stop_event.is_set():
            try:
                item = self.packet_queue.get(timeout=1)
                if item is None:
                    continue  # Sentinel

                packet, interface = item
                self._send_raw_packet(packet, interface)

            except queue.Empty:
                continue

        self.logger.log_message("[PacketWriter] Worker thread has stopped.")

    def _send_raw_packet(self, packet, interface: str):
        """
        Uses Scapy's sendp to send a Layer 2 packet on a specified interface.
        Also signs the packet and logs summary.
        """
        if not interface:
            self.logger.log_message("[PacketWriter] ⚠️ Error: Interface name is not specified.")
            return

        # Check for the presence of the Ethernet layer before proceeding
        if not packet.haslayer(Ether):
            self.logger.log_message(f"[PacketWriter] 🚫 Dropped packet: Missing Ethernet layer (no MAC address). Summary: {packet.summary()}")
            return

        try:
            if packet.haslayer(IP) or packet.haslayer(IPv6):
                if packet.haslayer(IP):
                    dst_ip = packet[IP].dst
                    dst_ip_obj = ipaddress.ip_address(dst_ip)
                    ip_layer = packet[IP]
                else:
                    dst_ip = packet[IPv6].dst
                    dst_ip_obj = ipaddress.ip_address(dst_ip)
                    ip_layer = packet[IPv6]

                # Throttle check
                entry = self.packet_writing_table[dst_ip]
                now = time.time()

                if entry["count"] >= self.THRESHOLD_PER_DST and (now - entry["last_sent"]) < self.RESET_INTERVAL:
                    self.logger.log_message(
                        f"[PacketWriter] ⏱️ Rate limit hit for {dst_ip}. Skipping packet."
                    )
                    return
                elif (now - entry["last_sent"]) >= self.RESET_INTERVAL:
                    entry["count"] = 0  # reset count after cooldown

                entry["count"] += 1
                entry["last_sent"] = now

                # Address validity check
                if not (
                    dst_ip_obj.is_global or dst_ip_obj.is_private or
                    dst_ip_obj.is_multicast or dst_ip_obj.is_loopback
                ):
                    self.logger.log_message(
                        f"[PacketWriter] 🚫 Dropped invalid destination {dst_ip_obj}. Summary: {packet.summary()}"
                    )
                    return
                if not hasattr(packet[Ether], "dst") or not packet[Ether].dst or packet[
                    Ether].dst.lower() == "ff:ff:ff:ff:ff:ff":
                    self.logger.log_message(
                        f"[PacketWriter] ☔ Dropped packet: Ethernet layer has an invalid destination MAC address or it's a broadcast address. Summary: {packet.summary()}")
                    return
                self.packet_signer.sign_packet(packet)
                sendp(packet, iface=interface, verbose=0)
                self.logger.log_message(
                    f"[PacketWriter] 📝 Sent (Len:{len(packet)}) on {interface.split('_')[-1]} -> {packet.summary()}"
                )
                self.logger.log_message(
                    f"[PacketWriter] 📊 Sent {entry['count']}/{self.THRESHOLD_PER_DST} to {dst_ip}"
                )

            else:
                if not hasattr(packet[Ether], "dst") or not packet[Ether].dst or packet[
                    Ether].dst.lower() == "ff:ff:ff:ff:ff:ff":
                    self.logger.log_message(
                        f"[PacketWriter] ☔ Dropped packet: Ethernet layer has an invalid destination MAC address or it's a broadcast address. Summary: {packet.summary()}")
                    return
                # Non-IP packets (ARP, etc.)
                self.packet_signer.sign_packet(packet)
                sendp(packet, verbose=0)
                self.logger.log_message(
                    f"[PacketWriter] 📝 Sent non-IP (Len:{len(packet)}) on {interface.split('_')[-1]} -> {packet.summary()}"
                )

        except Exception as e:
            self.logger.log_message(f"[PacketWriter] ❌ Failed to send packet on '{interface}': {e}")

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
        self.packet_queue.put(None)  # Sentinel to unblock queue
        self.worker_thread.join(timeout=2)

    def queue_packet(self, packet, interface: str):
        """
        Adds a packet to the queue for asynchronous sending.
        Args:
            packet: A Scapy packet to send.
            interface: Interface to send on (e.g., 'eth0').
        """
        if self._stop_event.is_set():
            self.logger.log_message("[PacketWriter] ⚠️ Warning: Cannot queue packet — writer is stopping.")
            return
        outbound_interface = self.outbound_load_balancer.get_next_interface(packet)
        self.packet_queue.put((packet, outbound_interface))

class ForwardingManager:
    """
    Tracks recently forwarded flows and considers them duplicates only after
    a certain threshold has been reached within a timeout period.
    """

    def __init__(self, router_logger=None, timeout: int = 5, max_entries: int = 10000, duplicate_threshold: int = 5):
        self.logger = router_logger or (lambda x: None)
        self.timeout = timeout
        self.duplicate_threshold = duplicate_threshold  # NEW: Configurable threshold
        self._forwarded_cache = deque(maxlen=max_entries)

        # CHANGED: from a set to a dictionary to store (count, timestamp)
        self._flow_counts: Dict[Tuple, Tuple[int, float]] = {}
        self._lock = threading.Lock()

    def _prune_expired(self):
        now = time.time()
        while self._forwarded_cache and (now - self._forwarded_cache[0][1]) > self.timeout:
            key, _ = self._forwarded_cache.popleft()
            # UPDATED: Remove from the counts dictionary as well
            if key in self._flow_counts:
                del self._flow_counts[key]
                self.logger.log_message(f"[Forwarding] 🔁 Flow expired from cache: {key}")

    def record_flow(self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: str):
        """Manually records a flow, setting its count to the threshold to block it immediately."""
        key = (src_ip, dst_ip, sport, dport, proto)
        now = time.time()
        with self._lock:
            self._prune_expired()
            if key not in self._flow_counts:
                self._forwarded_cache.append((key, now))
                # Set count to the threshold to ensure the next is_duplicate check will fail
                self._flow_counts[key] = (self.duplicate_threshold, now)
                self.logger.log_message(f"[Forwarding] 🧾 Flow pre-emptively recorded as duplicate: {key}")

    def is_duplicate(self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: str) -> bool:
        """
        Checks if a flow has been seen at least 'duplicate_threshold' times.
        Returns True if the threshold is met, otherwise increments the count and returns False.
        """
        key = (src_ip, dst_ip, sport, dport, proto)
        now = time.time()
        with self._lock:
            self._prune_expired()

            if key in self._flow_counts:
                # Flow has been seen before, increment its count
                count, _ = self._flow_counts[key]
                new_count = count + 1
                self._flow_counts[key] = (new_count, now)  # Update count and timestamp

                # Check if the new count meets or exceeds the threshold
                if new_count >= self.duplicate_threshold:
                    self.logger.log_message(
                        f"[Forwarding] 🚫 Duplicate threshold ({self.duplicate_threshold}) hit for flow {key}. Blocking.")
                    return True
                else:
                    # Log the sighting but don't block yet
                    self.logger.log_message(
                        f"[Forwarding] Sighting {new_count}/{self.duplicate_threshold} for flow {key}.")
                    return False
            else:
                # This is the first time seeing this flow
                self._forwarded_cache.append((key, now))
                self._flow_counts[key] = (1, now)  # Start with a count of 1
                return False

class EthernetBridgeManager:
    """
    Manages Layer 2 bridging (switching) between a group of interfaces.
    This allows multiple physical ports to act as a single broadcast domain.
    Enhanced with traffic rate-limiting to prevent network congestion.
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

        # --- New Traffic Management Fields ---
        # _mac_traffic_count: { mac_address: count } for rate limiting
        self._mac_traffic_count: Dict[str, int] = {}
        self._traffic_lock = threading.Lock()
        self.TRAFFIC_RATE_LIMIT = 40  # Max packets per MAC address per interval
        self.TRAFFIC_CHECK_INTERVAL = 5  # Interval in seconds
        # A queue for packets that exceed the rate limit
        self._waiting_queue = deque()

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
        if not frame.haslayer(Ether):
            self.logger.log_message(
                f"[Bridge] ⚠️ Non-Ethernet frame received on {inbound_iface.split('_')[-1]}. Dropping.")
            return

        src_mac = frame[Ether].src
        dst_mac = frame[Ether].dst
        ether_type = frame[Ether].type

        # --- New Traffic Management Logic ---
        with self._traffic_lock:
            self._mac_traffic_count[src_mac] = self._mac_traffic_count.get(src_mac, 0) + 1
            if self._mac_traffic_count[src_mac] > self.TRAFFIC_RATE_LIMIT:
                # Place packet in waiting queue instead of processing it
                self._waiting_queue.append((frame, inbound_iface))
                self.logger.log_message(
                    f"[Bridge] 🚦 Rate limit exceeded for {src_mac}. Packet moved to waiting queue.")
                return

        log_this_frame = False
        if ether_type in [0x0800, 0x0806, 0x86DD]:
            log_this_frame = True
        elif dst_mac.lower() == "ff:ff:ff:ff:ff:ff" or dst_mac.startswith("01:00:5e") or dst_mac.startswith("33:33"):
            reason = "Broadcast" if dst_mac.lower() == "ff:ff:ff:ff:ff:ff" else "Multicast"
            if ether_type not in [0x0800, 0x0806, 0x86DD]:
                self.logger.log_message(
                    f"[Bridge] 📡 L2 Flooding ({reason} Type {hex(ether_type)}) from {inbound_iface.split('_')[-1]}")

        self.learn_mac(src_mac, inbound_iface)

        bridge_name = self.get_bridge_for_interface(inbound_iface)
        if not bridge_name:
            self.logger.log_message(
                f"[Bridge] ⚠️ {inbound_iface.split('_')[-1]} is not in any bridge. Cannot handle frame.")
            return

        with self._mac_table_lock:
            target_iface = self._mac_table.get(dst_mac, (None, 0))[0]

        is_broadcast = dst_mac.lower() == "ff:ff:ff:ff:ff:ff"
        is_multicast = dst_mac.startswith("01:00:5e") or dst_mac.startswith("33:33")

        if log_this_frame:
            if target_iface and not is_broadcast and not is_multicast:
                if target_iface == inbound_iface:
                    self.logger.log_message(f"[Bridge] ↩️ Dropping L2 Frame {src_mac}->{dst_mac} (same port).")
                    return
                else:
                    self.logger.log_message(
                        f"[Bridge] ➡️ Forwarding L2 Frame {src_mac} -> {dst_mac} on {target_iface.split('_')[-1]}")
            else:
                reason = "Broadcast" if is_broadcast else "Multicast" if is_multicast else "Unknown Unicast"
                self.logger.log_message(
                    f"[Bridge] ❓ Flooding L2 Frame {src_mac} -> {dst_mac} ({reason}) from {inbound_iface.split('_')[-1]}")

                flood_targets = []
                interfaces = self._bridges.get(bridge_name, set())
                for iface in interfaces:
                    if iface != inbound_iface:
                        self.packet_writer.queue_packet(frame, iface)
                        flood_targets.append(iface.split('_')[-1])

                if flood_targets:
                    self.logger.log_message(
                        f"[Bridge] 🌊 Flooded to: {', '.join(flood_targets)}")
                else:
                    self.logger.log_message("[Bridge] 🚫 No active interfaces to flood to.")
                return

            if target_iface and target_iface != inbound_iface:
                self.packet_writer.queue_packet(frame, target_iface)
                self.logger.log_message(f"[Bridge] 📬 Forwarded unicast frame to {target_iface.split('_')[-1]}")
            else:
                self.logger.log_message(
                    f"[Bridge] ⚠️ Target interface {target_iface.split('_')[-1]} is down. Dropping frame.")


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

    def _cleanup_traffic_loop(self):
        """Periodically resets the traffic counters."""
        while not self._stop_event.is_set():
            time.sleep(self.TRAFFIC_CHECK_INTERVAL)
            with self._traffic_lock:
                # Clear the counters after each interval
                self._mac_traffic_count.clear()
            self.logger.log_message("[Bridge] ⏱️ Traffic counters have been reset.")

    def start(self):
        """Starts the MAC table and traffic cleanup threads."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_mac_table_loop, daemon=True,
                                                name="BridgeMacCleanup")
        self._cleanup_thread.start()
        self._traffic_cleanup_thread = threading.Thread(target=self._cleanup_traffic_loop, daemon=True,
                                                        name="BridgeTrafficCleanup")
        self._traffic_cleanup_thread.start()
        self.logger.log_message("[Bridge] Cleanup threads started.")

    def stop(self):
        """Stops the cleanup threads."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self.logger.log_message("[Bridge] Stopping cleanup threads...")
            self._stop_event.set()
            self._cleanup_thread.join(timeout=2)
            self._traffic_cleanup_thread.join(timeout=2)
            self.logger.log_message("[Bridge] Cleanup threads stopped.")

class EthernetL2Manager:
    """
    Handles non-IP Ethernet (Layer 2) packets such as 802.3 frames, STP, LLDP, and malformed traffic.
    Logs or filters low-level packets that do not include IP/IPv6 layers.
    """

    def __init__(self, router_logger):
        self.logger = router_logger

    def handle_packet(self, packet, iface_name: str) -> bool:
        """
        Inspect and optionally handle non-IP packets.
        Returns True if handled (packet is consumed/dropped); False otherwise (packet continues in pipeline).
        """
        if packet.haslayer(IP) or packet.haslayer(IPv6):
            return False  # This manager only handles non-IP packets

        try:
            if not packet.haslayer(Ether):
                self.logger.log_message(f"[L2] ⚠️ Non-IP packet without Ether layer on {iface_name}: {packet.summary()}")
                return True # Drop malformed/unparseable L2 frames

            if len(packet) < 14: # Standard Ethernet header is 14 bytes
                 self.logger.log_message(f"[L2] 🚫 Dropping malformed Ethernet frame (too short: {len(packet)} bytes) on {iface_name}. Summary: {packet.summary()}")
                 return True

            ether_type_val = packet[Ether].type
            ether_type_hex = hex(ether_type_val)

            # --- Specific Handling for Known Non-IP Layer 2 Protocols ---

            # 1. ARP (Address Resolution Protocol)
            if ether_type_hex == "0x0806" and packet.haslayer(ARP):
                self.logger.log_message(f"[L2] ➡️ Passing ARP packet to ARPManager on {iface_name}.")
                return False # IMPORTANT: Return False so ARPManager can process it

            # 2. STP (Spanning Tree Protocol)
            elif ether_type_hex == "0x0026": # SNAP_STP (802.1D) - though often has DSAP/SSAP headers
                self.logger.log_message(f"[L2] ❌ Dropping known Layer 2 protocol (STP type {ether_type_hex}) on {iface_name}")
                return True

            # 3. LLDP (Link Layer Discovery Protocol)
            elif ether_type_hex == "0x88cc":
                self.logger.log_message(f"[L2] ❌ Dropping known Layer 2 protocol (LLDP type {ether_type_hex}) on {iface_name}")
                return True
            self.logger.log_message(f"[L2] 📡 Dropping unhandled non-IP Ethernet packet (type {ether_type_hex}) on {iface_name}.")
            return True # Handled (by dropping)

        except Exception as e:
            # Catch exceptions during deeper dissection attempts within this manager
            self.logger.log_message(f"[L2] ‼️ ERROR dissecting problematic non-IP packet on {iface_name}: {e}. Raw packet summary: {packet.summary()}")
            # If it's unparseable at this level, it's garbage. Drop it.
            return True # Handled (by dropping due to error)

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
            response = sr1(pkt, timeout=timeout, verbose=0)

            if response is None:
                return 'FILTERED (no response)', None
            elif response.haslayer(TCP):
                tcp_flags = response[TCP].flags
                if tcp_flags & 0x12:  # SYN-ACK (SYN=0x02, ACK=0x10 -> 0x12)
                    # Port is Open. Send an RST to gracefully tear down the connection.
                    rst_pkt = IP(dst=target_ip, src=response[IP].dst) / \
                              TCP(dport=target_port, sport=response[TCP].dport, flags="R", seq=response[TCP].ack)
                    send(rst_pkt, verbose=0)
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

    def __init__(self, router_logger, packet_writer, sendback_manager, interfaces_config: dict, rate_limit_pps: int = 5):
        self.log = router_logger
        self.pw = packet_writer
        self.ifaces = interfaces_config  # to know MAC & IP

        # Rate Limiting for Echo Replies
        self.rate_limit_pps = rate_limit_pps
        self._last_reply_time = defaultdict(float)  # Key: (src_ip, dst_ip) -> last_reply_timestamp
        self._rate_limit_lock = threading.Lock()
        self.sendback_manager = sendback_manager
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
        icmp_code = pkt[ICMP].code if hasattr(pkt[ICMP], 'code') else 0

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

        if not is_for_router:
            self.log.log_message(
                f"[ICMP] 📭 Received {icmp_type} for {dst_ip} (not router's IP). Not handled by ICMP Manager directly."
            )
            return False

        # --- Handle specific ICMP types ---
        if icmp_type == 8:  # Echo Request
            self.log.log_message(
                f"[ICMP] 📨 Echo-Request from {src_ip} to {dst_ip} on {inbound_iface.split('_')[-1]}"
            )

            if self._is_rate_limited(src_ip, dst_ip):
                return True

            reply_src_mac = router_mac_for_reply if router_mac_for_reply else "00:00:00:00:00:00"
            reply_dst_mac = pkt[Ether].src if pkt.haslayer(Ether) else "00:00:00:00:00:00"

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
                f"[ICMP] 🔌 Destination Unreachable (Code {icmp_code}) from {src_ip} on {inbound_iface.split('_')[-1]}"
            )
            self.sendback_manager.send_icmp_packet(pkt, icmp_type=3, icmp_code=icmp_code)
            return True

        elif icmp_type == 11:  # Time Exceeded
            self.log.log_message(
                f"[ICMP] ⏳ Time Exceeded (Code {icmp_code}) from {src_ip} on {inbound_iface.split('_')[-1]}"
            )
            self.sendback_manager.send_icmp_packet(pkt, icmp_type=11, icmp_code=icmp_code)
            return True

        else:
            self.log.log_message(
                f"[ICMP] ❔ Unhandled ICMP type {icmp_type} from {src_ip} on {inbound_iface.split('_')[-1]}. Summary: {pkt.summary()}"
            )
            return False


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
        self._sessions: Dict[Tuple[str, int, str, int], Tuple[HandshakeState, float, str, int, str, int]] = {}
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
            nat_reversed_dst_tuple = self.nat_manager.get_internal_from_external(original_dst_port)
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

    def __init__(self, router_logger, sendback_manager, router_public_ip: str, packet_writer,
                 interfaces_config: Dict[str, Dict[str, Any]],
                 rip_manager_find_route, arp_manager_resolve):  # ADD interfaces_config, rip_manager_find_route
        self.router_logger = router_logger
        self.public_ip = router_public_ip
        self.packet_writer = packet_writer  # Store the packet writer
        self._interfaces_config = interfaces_config  # Store interfaces config
        self._rip_manager_find_route = rip_manager_find_route  # Store the find_route method
        self._arp_manager_resolve = arp_manager_resolve
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

        self.router_internal_ip_for_self_mapping: str = "0.0.0.0"  # Still present, but used differently now

        self.add_static_mapping(
            external_port=65406,
            internal_ip="192.168.1.50",
            internal_port=88
        )
        self.router_logger.log_message("[NAT] Manager initialized.")
        self.sendback_manager = sendback_manager
    def set_router_internal_ip(self, ip: str):
        self.router_internal_ip_for_self_mapping = ip
        self.router_logger.log_message(f"[NAT] Router's internal IP for self-mapping set to: {ip}")

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
                stale_internal_keys = []
                for internal_key, (external_port, timestamp) in self._nat_table.items():
                    if now - timestamp > self.NAT_TIMEOUT_SECONDS:
                        stale_internal_keys.append(internal_key)

                for internal_key in stale_internal_keys:
                    external_port, _ = self._nat_table.pop(internal_key)
                    if external_port in self._nat_reverse_table and self._nat_reverse_table[
                        external_port] == internal_key:
                        del self._nat_reverse_table[external_port]
                    self.router_logger.log_message(
                        f"[NAT] 🗑️ Timed out dynamic port mapping: {internal_key[0]}:{internal_key[1]} → {self.public_ip}:{external_port}"
                    )
            time.sleep(self.NAT_TIMEOUT_SECONDS / 2)

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
                f"[NAT][ALG] FTP ALG triggered ({direction}). (Placeholder: Actual payload inspection/rewriting needed)")
        if packet.haslayer(UDP) and packet.haslayer(DNS) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
            self.router_logger.log_message(
                f"[NAT][ALG] DNS traffic observed ({direction}). (No DNS payload rewriting by NAT.)")

    def translate_outbound(self, packet: Packet):
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            self.router_logger.log_message(f"[NAT] Skipping outbound translation for non-IP packet: {packet.summary()}")
            return
        ip = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            if packet.haslayer(ICMP):
                self.router_logger.log_message(
                    f"[NAT] Passing outbound ICMP for {ip.src} to {ip.dst} without port NAT.")
                return
            if packet.haslayer(DHCP):
                self.router_logger.log_message(f"[NAT] Skipping outbound NAT for DHCP packet from {ip.src}.")
                return
            if packet.haslayer(IGMP):
                self.router_logger.log_message(f"[NAT] Skipping outbound NAT for IGMP packet from {ip.src}.")
                return
            self.router_logger.log_message(
                f"[NAT] Skipping outbound translation for unhandled non-TCP/UDP/ICMP packet: {packet.summary()}")
            return

        t = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        internal_key = (ip.src, t.sport)

        with self._lock:
            if internal_key not in self._nat_table:
                new_port = self._get_next_port()
                if new_port == -1:
                    #self.router_logger.log_message(f"[NAT] 🚫 Dropping outbound packet from {ip.src}:{t.sport} due to no available NAT ports.")
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
        t.sport = new_port
        self._apply_alg(packet, "outbound")

    def translate_inbound(self, packet: Packet) -> bool:
        """
        Handle inbound TCP/UDP:
          1. Check static mappings
          2. Else check dynamic reverse mappings
          3. If no mapping, send ICMP Destination Unreachable (Port Unreachable) back.
        Returns True if packet was translated, False if dropped/none.
        """
        # Ensure IP and TCP/UDP layers are present
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            self.router_logger.log_message(f"[NAT] Skipping inbound translation for non-IP packet: {packet.summary()}")
            return False
        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            if packet.haslayer(ICMP) and (packet[ICMP].type == 3 or packet[ICMP].type == 11):
                self.router_logger.log_message(
                    f"[NAT] Inbound ICMP error message to {ip_layer.dst}. Not performing NAT translation.")
                return False
            if packet.haslayer(DHCP) and packet.haslayer(UDP) and (packet[UDP].sport == 67 or packet[UDP].dport == 68):
                self.router_logger.log_message(
                    f"[NAT] Skipping inbound NAT for DHCP packet to {ip_layer.dst}:{packet[UDP].dport}.")
                return False
            if packet.haslayer(IGMP):
                self.router_logger.log_message(f"[NAT] Skipping inbound NAT for IGMP packet to {ip_layer.dst}.")
                return False
            self.router_logger.log_message(
                f"[NAT] Skipping inbound translation for unhandled non-TCP/UDP packet: {packet.summary()}")
            return False

        # Get relevant layers for translation
        transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        ext_dst_port = transport_layer.dport

        # 1) Check Static port-forwarding
        with self._lock:
            static_mapping = self._static_mappings.get(ext_dst_port)
        if static_mapping:
            internal_ip, internal_port = static_mapping
            self.router_logger.log_message(
                f"[NAT][STATIC] ⬅️  Static mapping hit: "
                f"{self.public_ip}:{ext_dst_port} → {internal_ip}:{internal_port}"
            )
            ip_layer.dst = internal_ip
            transport_layer.dport = internal_port
            self._apply_alg(packet, "inbound")
            return True

        # 2) Check Dynamic reverse mapping
        #self.router_logger.log_message(
        #    f"[NAT] ⬅️  Lookup dynamic mapping for external port {ext_dst_port} "
        #    f"(from {ip_layer.src}:{transport_layer.sport})")
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
                f"[NAT] ✅  Dynamic mapping found: "
                f"{self.public_ip}:{ext_dst_port} → {internal_ip}:{internal_port}"
            )
            ip_layer.dst = internal_ip
            transport_layer.dport = internal_port
            self._apply_alg(packet, "inbound")
            return True
        else:
            # --- NEW: Send ICMP Destination Unreachable (Port Unreachable) ---
            #self.router_logger.log_message(f"[NAT] 🚫 Unmapped inbound traffic to {self.public_ip}:{ext_dst_port} from {ip_layer.src}:{transport_layer.sport}. Sending ICMP Destination Unreachable (Port Unreachable).")
            self._send_icmp_destination_unreachable(packet, ip_layer, transport_layer)
            return False  # Packet was not translated, but handled (by sending ICMP)

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
                f"[NAT] ⚠️ Could not find route to original sender {icmp_dst_ip} for ICMP response. Dropping ICMP.")
            self.sendback_manager.send_icmp_packet(original_packet, icmp_type=3, icmp_code=3)
            return

        outbound_iface_for_icmp = route_to_sender["interface"]

        outbound_iface_config = self._interfaces_config.get(outbound_iface_for_icmp)
        if not outbound_iface_config or 'mac' not in outbound_iface_config:
            self.router_logger.log_message(
                f"[NAT] ⚠️ Missing MAC for router's outbound interface {outbound_iface_for_icmp.split('_')[-1]} for ICMP. Dropping ICMP.")
            return
        router_mac_out = outbound_iface_config['mac']

        next_hop_ip_for_icmp = route_to_sender["next_hop"] if route_to_sender["next_hop"] != "0.0.0.0" else icmp_dst_ip

        # --- CRITICAL CHANGE: Resolve next-hop MAC using ARPManager ---
        next_hop_mac_for_icmp = self._arp_manager_resolve(next_hop_ip_for_icmp, outbound_iface_for_icmp)
        if not next_hop_mac_for_icmp:
            self.router_logger.log_message(
                f"[NAT] 🕵️ ARP resolution failed for next hop {next_hop_ip_for_icmp} on {outbound_iface_for_icmp.split('_')[-1]} for ICMP. Sending back ICMP.")
            self.sendback_manager.send_icmp_packet(
                original_packet,
                icmp_type=3,
                icmp_code=3,
            )
            return
        # --- END CRITICAL CHANGE ---

        # Construct the ICMP packet
        # The payload of the ICMP error is the IP header + first 8 bytes of the original packet.
        # Scapy's ICMP error messages often automatically handle this if you layer correctly.
        # We'll embed the original IP layer as the payload.

        icmp_response = Ether(src=router_mac_out, dst=next_hop_mac_for_icmp) / \
                        IP(src=icmp_src_ip, dst=icmp_dst_ip) / \
                        ICMP(type=3, code=3) / \
                        original_ip_layer  # Embedding the original IP layer for context

        # Scapy should automatically calculate checksums on send, but explicitly deleting them
        # ensures they are recalculated.
        del icmp_response[IP].chksum
        del icmp_response[ICMP].chksum


        self.router_logger.log_message(
            f"[NAT] 🔕 Sent ICMP Dest Unreachable (Port) to {icmp_dst_ip} via {outbound_iface_for_icmp.split('_')[-1]}.")

    def get_internal_from_external(self, external_port: int) -> Optional[Tuple[str, int]]:
        """Returns (internal_ip, internal_port) for a NAT’d external port."""
        with self._lock:
            # 1. Check static mappings
            static_mapping = self._static_mappings.get(external_port)
            if static_mapping:
                self.router_logger.log_message(
                    f"[NAT] get_internal_from_external: Static hit for external port {external_port}.")
                return static_mapping

            # 2. Check dynamic reverse mappings
            dynamic_mapping = self._nat_reverse_table.get(external_port)
            if dynamic_mapping:
                self.router_logger.log_message(
                    f"[NAT] get_internal_from_external: Dynamic hit for external port {external_port}.")
                return dynamic_mapping

        self.router_logger.log_message(
            f"[NAT] get_internal_from_external: No mapping found for external port {external_port}.")
        return None

    def get_internal_ip_from_external(self, external_ip: str) -> Optional[str]:
        """
        Returns the internal IP corresponding to a NAT'd external IP.
        (Primarily for 1:1 NAT or specific ALG needs. For port NAT, it's more complex.)
        """
        if external_ip == self.public_ip:
            self.router_logger.log_message(
                f"[NAT] Query for internal IP from external {external_ip}. Requires deeper NAT state knowledge.")
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
                f"[DNS] 🔁 Not proxying DNS query from external source {ip_layer.src} to prevent loop.")
            return False

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
            else:

                modified_packet = modified_packet[ip_layer.__class__]

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

    def __init__(self, router_logger, cache_timeout_seconds=300):
        """
        Initializes the ARP Manager.
        Args:
            router_logger: The logger instance for logging messages.
            cache_timeout_seconds (int): How long a cache entry is valid.
        """
        self.dhcp_server_out = None
        self.dhcp_server_in = None
        self.notification_manager = None # Added for the new logic
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
        # Ensure notification_manager is set before attempting to send notifications
        if self.notification_manager and (
            (self.dhcp_server_out and sender_ip in self.dhcp_server_out.get_ip_to_mac_bindings()) or
            (self.dhcp_server_in and sender_ip in self.dhcp_server_in.get_ip_to_mac_bindings())
        ):
            if sender_ip not in self._active_ips: # Only log/notify on first detection
                self._active_ips.add(sender_ip)
                self.router_logger.log_message(f"[ARP] ✅ First use of leased IP {sender_ip} by {sender_mac} detected.")
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
        Resolves an IP address to a MAC address using the ARP protocol.
        Checks the cache first. If the entry is not found or is stale, it sends a new ARP request.
        """
        ip_address = ip_address.strip()  # Normalize input

        if ipaddress.ip_address(ip_address).is_loopback:
            self.router_logger.log_message(f"[ARP] Local delivery: Loopback IP {ip_address}. No ARP needed.")
            return None

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
                    self.router_logger.log_message(f"[ARP] ⚡ Cache hit for {ip_address} → {mac}")
                    return mac
                else:
                    self.router_logger.log_message(f"[ARP] 🕓 Stale cache entry for {ip_address}. Re-resolving...")
            else:
                self.router_logger.log_message(f"[ARP] 🛰️ Cache miss for {ip_address}. Sending ARP request...")

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
        try:
            # Using sendp to send the packet directly on the specified interface
            sendp(grat_arp, iface=iface, verbose=0)
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
            answered, _ = srp(arp_request, iface=iface, timeout=timeout, verbose=False)

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

            return True
class PythonRouterManager:

    """
    Manages sniffing packets on multiple interfaces and routing them
    based on a simplified routing table. Self-contained for interface discovery and IP assignment.
    """

    # --- Configuration Defaults (used if dynamic assignment fails or as starting points) ---
    DEFAULT_IN_IFACE_FRIENDLY_NAME = "Ethernet"
    DEFAULT_OUT_IFACE_FRIENDLY_NAME = "Wi-Fi"
    DEFAULT_LOOPBACK_IFACE_FRIENDLY_NAME = "Loopback"
    NOTIFICATION_TARGET_IP = "127.0.0.1"  # IP of the machine to receive alerts
    NOTIFICATION_TARGET_PORT = 12345  # UDP Port to listen on

    # Default private IP ranges to try for the IN interface if auto-picking
    PRIVATE_SUBNETS_TO_TRY = [
        "192.168.100.0/24", "192.168.101.0/24", "192.168.102.0/24", "192.168.103.0/24",
        "10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24",
        "172.16.10.0/24", "172.16.11.0/24", "172.16.12.0/24"
    ]

    BPF_FILTER_BASE_DEFINITIONS = {
        "Ethernet": [],
        "Wi-Fi": [],
        "Loopback": [],
        "Ethernet 2": [],
    }
    def __init__(self, router_logger):

        self.router_logger = router_logger
        self._interfaces_config = {}  # Stores config for all physical interfaces
        self.interface_in_full_name = None
        self.interface_in_friendly_name = None
        self.interface_out_full_name = None  # Primary OUT interface
        self.interface_out_friendly_name = None
        self.interface_loopback_full_name = None
        self.interface_ethernet_2_full_name = None
        self.interface_ethernet_2_friendly_name = None
        self.interface_lac_full_name = None
        self.interface_lac_friendly_name = None
        self.interface_lac_2_full_name = None
        self.interface_lac_2_friendly_name = None
        self.router_ip_in = None
        self.router_ip_out = None
        self.router_gateway_out_ip = None

        self._sniff_threads = {}
        self._worker_threads = {}
        self._stop_sniffing_event = threading.Event()
        self._sniff_threads_lock = threading.Lock() # Lock for _sniff_threads dictionary
        self._tshark_path = None
        self._discovered_tshark_interfaces = []

        # Instantiate all specialized managers
        self.arp_manager = ARPManager(router_logger)
        self.outbound_load_balancer = OutboundLoadBalancer(router_logger)  # New: Outbound Load Balancer
        self.packet_signer = PacketSigningManager(router_logger)
        self.packet_writer = PacketWriter(router_logger, self.packet_signer, self.outbound_load_balancer)
        self.sendback_manager = SendBackManager(router_logger, self.packet_signer, self.outbound_load_balancer)
        self.dns_manager = DNSManager(router_logger, self.packet_writer)
        self.rip_manager = RIPManager(router_logger)
        self.nat_manager = None  # Initialized after public IP is known
        self.notification_manager = None
        self.packet_catcher = PacketCatcherManager(router_logger)
        self.handshake_manager = None
        self.igmp_manager = IGMPManager(router_logger, self.packet_writer)
        self.icmp_manager = ICMPManager(router_logger, self.packet_writer, self.sendback_manager, self._interfaces_config)
        self.dhcp_server_in = None
        self.dhcp_server_out = None
        self.lag_manager = LinkAggregationManager(router_logger)  # New: Link Aggregation Manager
        self.firewall_manager = FirewallManager(router_logger)  # New: Firewall Manager
        self.syn_scanner = None
        self.ethernet_manager = EthernetBridgeManager(router_logger, self.packet_writer)
        self.forwarding_manager = ForwardingManager(router_logger=self.router_logger)
        self.kerberos_manager = KerberosManager(router_logger, self.packet_writer)
        self.https_manager = HTTPSManager(router_logger)
        self.ethernet_l2_manager = EthernetL2Manager(router_logger)

        self.transport_manager = TransportManager(router_logger, self.packet_signer)
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
                self.router_logger.log_message("[Firewall] Skipping firewall rule configuration: OUT interface not found.")
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

        self.firewall_manager.add_rule(
            action='permit', protocol='igmp', src_ip='any', dst_ip='any',
            src_port='any', dst_port='any'  # Ports are 'any' as IGMP doesn't use them
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
                full_command, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            if result.returncode == 0:
                if stdout:
                    self.router_logger.log_message(f"[Netsh] STDOUT: {stdout}")
                return True


            # Otherwise treat as real error
            self.router_logger.log_message(f"[Netsh] ERROR executing netsh (Return Code: {result.returncode}):")
            if stdout:
                self.router_logger.log_message(f"[Netsh] STDOUT: {stdout}")
            if stderr:
                self.router_logger.log_message(f"[Netsh] STDERR: {stderr}")
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

    def _auto_configure_interfaces(self, use_dhcp_out, use_dhcp_in):
        """
        Automatically finds and configures IN, OUT, and Loopback interfaces.
        Sets their IP addresses dynamically (for IN/OUT) and determines default gateway.
        """
        in_iface_info = None
        out_iface_info = None
        loopback_iface_info = None  # NEW: For loopback interface
        ethernet_2_info = None
        lac_2_info = None
        lac_2_info_2 = None
        self.router_logger.log_message(
            "[RouterManager] Attempting to auto-configure IN, OUT, and Loopback interfaces...")

        for iface in self._discovered_tshark_interfaces:
            name = iface['friendly_name'].lower()
            match = re.search(r'\*[\s]?(\d+)$', name)
            if match and int(match.group(1)) == 1:
                lac_2_info = iface
                self.router_logger.log_message(
                    f"[RouterManager] Found exact match for LAC 1: {iface['friendly_name']}")
            if (match and int(match.group(1)) == 12) or (match and int(match.group(1)) == 2):
                lac_2_info_2 = iface
                self.router_logger.log_message(
                    f"[RouterManager] Found exact match for LAC 2: {iface['friendly_name']}")


        if lac_2_info:
            self.router_logger.log_message(
                f"[RouterManager] Found lowest-numbered LAC: {lac_2_info['friendly_name']}")
        if lac_2_info_2:
            self.router_logger.log_message(
                f"[RouterManager] Found second-lowest-numbered LAC: {lac_2_info_2['friendly_name']}")
        for iface_info in self._discovered_tshark_interfaces:
            # Check for IN interface
            if self.DEFAULT_IN_IFACE_FRIENDLY_NAME.lower() == iface_info[
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
            if ("ethernet 2" in iface_info['friendly_name'].lower()):
                ethernet_2_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found Ethernet 2 interface")
            if in_iface_info is not None and out_iface_info is not None and loopback_iface_info is not None and ethernet_2_info is not None:
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
        if(lac_2_info_2):
            self.interface_lac_2_full_name = lac_2_info_2["full_name"]
            self.interface_lac_2_friendly_name = lac_2_info_2["friendly_name"]
        if(lac_2_info):
            self.interface_lac_full_name = lac_2_info['full_name']
            self.interface_lac_friendly_name = lac_2_info['friendly_name']
        if(ethernet_2_info):
            self.interface_ethernet_2_full_name =  ethernet_2_info['full_name']
            self.interface_ethernet_2_friendly_name =  ethernet_2_info['friendly_name']
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

        if(not use_dhcp_in):
            if not self._assign_ip_to_interface(self.interface_in_friendly_name, self.router_ip_in, self.router_netmask_in):
                self.router_logger.log_message(
                    f"[RouterManager] CRITICAL ERROR: Failed to assign IP to IN interface. Routing may not work.")
                return False

        # Assign OUT interface IP with its (discovered/fallback) gateway (using its friendly name for netsh)
        if(not use_dhcp_out):
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
            'mac': get_if_hwaddr(self.interface_in_full_name),
            'broadcast': str(self.router_network_in.broadcast_address)
        }
        self._interfaces_config[self.interface_out_full_name] = {
            'ip_addr': self.router_ip_out,
            'network': self.router_network_out,
            'mac': get_if_hwaddr(self.interface_out_full_name),
            'broadcast': str(self.router_network_out.broadcast_address),
            'is_default_gateway_iface': True,
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
                        "mac": eth2_mac,
                        "broadcast": str(eth2_network.broadcast_address)
                    }
                else:
                    self._interfaces_config[ethernet_2_info["full_name"]] = {
                        "ip_addr": "0.0.0.0",
                        "network": None,
                        "mac": eth2_mac,
                        "broadcast": "255.255.255.255"
                    }

                self.router_logger.log_message(
                    f"[RouterManager] Added Ethernet 2 to config: {ethernet_2_info['full_name']}, MAC: {eth2_mac}")
                bridge_members.append(ethernet_2_info["full_name"])
            except Exception as e:
                self.router_logger.log_message(f"[RouterManager] ⚠️ Failed to add Ethernet 2 to bridge: {e}")
        if lac_2_info:
            try:
                lac_mac = get_if_hwaddr(self.interface_lac_full_name)
                lac_ip = None
                lac_netmask = None
                # Find the IP configuration for the LAC interface
                for addr in psutil.net_if_addrs().get(self.interface_lac_friendly_name, []):
                    if addr.family == socket.AF_INET:
                        lac_ip = addr.address
                        lac_netmask = addr.netmask
                        break

                if lac_ip and lac_netmask:
                    lac_network = ipaddress.ip_network(f"{lac_ip}/{lac_netmask}", strict=False)
                    self._interfaces_config[self.interface_lac_full_name] = {
                        "ip_addr": lac_ip,
                        "network": lac_network,
                        "mac": lac_mac,
                        "broadcast": str(lac_network.broadcast_address)
                    }
                    self.router_logger.log_message(
                        f"[RouterManager] Added LAC interface to config: {self.interface_lac_full_name}, IP: {lac_ip}, MAC: {lac_mac}")
                else:
                    # If no IP is found, add it with a placeholder IP
                    self._interfaces_config[self.interface_lac_full_name] = {
                        "ip_addr": "0.0.0.0",
                        "network": None,
                        "mac": lac_mac,
                        "broadcast": "255.255.255.255"
                    }
                    self.router_logger.log_message(
                        f"[RouterManager] Added LAC interface to config: {self.interface_lac_full_name} (No IP found), MAC: {lac_mac}")

            except Exception as e:
                self.router_logger.log_message(
                    f"[RouterManager] ⚠️ Failed to configure LAC interface {self.interface_lac_full_name}: {e}")
        if lac_2_info_2:
            try:
                # Use the full name for getting hardware address
                lac_2_mac = get_if_hwaddr(self.interface_lac_2_full_name)
                lac_2_ip = None
                lac_2_netmask = None

                # Find the IP configuration for the second LAC interface using its friendly name
                for addr in psutil.net_if_addrs().get(self.interface_lac_2_friendly_name, []):
                    if addr.family == socket.AF_INET:
                        lac_2_ip = addr.address
                        lac_2_netmask = addr.netmask
                        break  # Stop after finding the first IPv4 address

                # If an IP and netmask were successfully found, calculate network info
                if lac_2_ip and lac_2_netmask:
                    lac_2_network = ipaddress.ip_network(f"{lac_2_ip}/{lac_2_netmask}", strict=False)

                    # Add the interface configuration to your main dictionary
                    self._interfaces_config[self.interface_lac_2_full_name] = {
                        "ip_addr": lac_2_ip,
                        "network": lac_2_network,
                        "mac": lac_2_mac,
                        "broadcast": str(lac_2_network.broadcast_address)
                    }
                    self.router_logger.log_message(
                        f"[RouterManager] Added LAC 2 interface to config: {self.interface_lac_2_full_name}, IP: {lac_2_ip}, MAC: {lac_2_mac}")
                else:
                    # If no IP is found, add it with a placeholder IP
                    self._interfaces_config[self.interface_lac_2_full_name] = {
                        "ip_addr": "0.0.0.0",
                        "network": None,
                        "mac": lac_2_mac,
                        "broadcast": "255.255.255.255"
                    }
                    self.router_logger.log_message(
                        f"[RouterManager] Added LAC 2 interface to config: {self.interface_lac_2_full_name} (No IP found), MAC: {lac_2_mac}")

            except Exception as e:
                self.router_logger.log_message(
                    f"[RouterManager] ⚠️ Failed to configure LAC 2 interface {self.interface_lac_2_full_name}: {e}")
        # ✅ Create LAN bridge with discovered members
        self.router_logger.log_message(
            "[RouterManager][ARP] 🔒 Configuring trusted ARP interfaces and static entries...")

        # Trust the IN interface
        self.add_trusted_arp_port(self.interface_in_full_name)


        # Optionally trust Ethernet 2 (if used in bridging)
        if ethernet_2_info:
            self.add_trusted_arp_port(self.interface_ethernet_2_full_name)

        # Example: Add static ARP entry for gateway (if known)
        if self.router_gateway_out_ip:
            try:
                gateway_mac = self.arp_manager.resolve(self.router_gateway_out_ip, self.interface_out_full_name)
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
                'mac': loopback_mac,
                "broadcast": str(loopback_network.broadcast_address)
            }

            self.rip_manager.interface_loopback_full_name = self.interface_loopback_full_name
            self.router_logger.log_message(
                f"  Loopback Interface: '{self.interface_loopback_full_name}' (IP: {loopback_ip}/{loopback_netmask}, MAC: {loopback_mac})")

        self.create_l2_bridge("MyLANBridge", bridge_members)
        link_group = [self.interface_in_full_name]
        self.add_outbound_load_balancing_interface(self.interface_out_full_name)
        if self.interface_lac_full_name:
            self.add_outbound_load_balancing_interface(self.interface_lac_full_name)
            link_group.append(self.interface_lac_full_name)
        if self.interface_lac_2_full_name:
            self.add_outbound_load_balancing_interface(self.interface_lac_2_full_name)
            link_group.append(self.interface_lac_2_full_name)
        # Get our own MAC addresses (re-get after IP assignment for certainty)
        self.mac_in = get_if_hwaddr(self.interface_in_full_name)
        self.mac_out = get_if_hwaddr(self.interface_out_full_name)
        self.create_link_aggregation_group("MyLANAggregation", link_group)
        conf.route.add(net=str(self.router_network_in), gw=self.router_gateway_out_ip,
                       dev=self.interface_out_friendly_name)
        conf.route.add(
            host="192.168.0.10",
            gw="192.168.0.1",
            dev=self.interface_out_friendly_name  # <-- Use the dynamically found name
        )
        # Do the same for IPv6 if needed
        conf.route6.add(
            dst="2001:db8:cafe:f000::/64",
            dev=self.interface_out_friendly_name  # <-- Use the dynamically found name
        )

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
        global packet_queue
        """Starts a sniffer thread + processing worker pool for a given interface."""
        RATE_LIMIT_PACKETS_PER = .50  # Can be any float value
        TOKEN_BUCKET = {"tokens": RATE_LIMIT_PACKETS_PER, "last_refill": time.time()}
        TOKEN_BUCKET_LOCK = threading.Lock()

        def refill_tokens():
            with TOKEN_BUCKET_LOCK:
                now = time.time()
                elapsed = now - TOKEN_BUCKET["last_refill"]
                TOKEN_BUCKET["last_refill"] = now

                # Accumulate tokens with float precision
                TOKEN_BUCKET["tokens"] += elapsed * RATE_LIMIT_PACKETS_PER
                # Optional: set a max burst limit (e.g., allow up to 5 tokens max)
                TOKEN_BUCKET["tokens"] = min(TOKEN_BUCKET["tokens"], 5.0)

        def consume_token() -> bool:
            refill_tokens()
            with TOKEN_BUCKET_LOCK:
                if TOKEN_BUCKET["tokens"] >= 1.0:
                    TOKEN_BUCKET["tokens"] -= 1.0
                    return True
                return False

        friendly_name_for_filter = next((item['friendly_name'] for item in self._discovered_tshark_interfaces if item['full_name'] == iface_name),'DEFAULT')
        filter_clauses = self.BPF_FILTER_BASE_DEFINITIONS.get(friendly_name_for_filter,self.BPF_FILTER_BASE_DEFINITIONS.get("DEFAULT", []))
        filter_str = " or ".join(f"({clause})" for clause in filter_clauses) if filter_clauses else ""
        def sniffer_loop(name=iface_name):
            self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[-1]} starting...")

            try:
                sniff(
                    iface=name,
                    prn=lambda pkt: safe_enqueue(pkt),
                    promisc=True,
                    stop_filter=lambda p: self._stop_sniffing_event.is_set(),
                    filter=filter_str,
                    mac_filter_only=True,
                    session=TCPSession,
                    notification_manager = self.notification_manager
                )
            except Exception as e:
                self.router_logger.log_message(f"‼️ CRITICAL ERROR in sniffer thread for {name.split('_')[-1]}: {e}")
            finally:
                self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[-1]} has exited.")

        def packet_worker():
            while not self._stop_sniffing_event.is_set():
                try:
                    pkt = packet_queue.get(timeout=1)
                    self._process_packet(pkt, iface_name)
                except queue.Empty:
                    continue  # Normal timeout behavior
                except Exception as e:
                    import traceback
                    tb = traceback.format_exc()
                    self.router_logger.log_message(f"[Worker] ❌ Error processing packet:\n{tb}")

        def safe_enqueue(pkt):
            try:
                if not pkt.haslayer(Ether):
                    return  # Drop if no Ethernet layer

                try:
                    pkt_len = len(pkt)
                except Exception:
                    return  # Malformed packet — silently drop

                if pkt_len < 14 or pkt_len > 65535:
                    return  # Drop too short or invalid size

                if not consume_token():
                    return  # Rate limit drop

                try:
                    packet_queue.put(pkt, block=False)
                except queue.Full:
                    try:
                        oldest_packet = packet_queue.get(block=False)
                        selected_iface = self.outbound_load_balancer.get_next_interface(oldest_packet)
                        self.sendback_manager.send_back(oldest_packet, selected_iface)
                    except queue.Full:
                        pass  # Drop if still full
                    except Exception as e:
                        self.router_logger.log_message(f"[Sniffer] ⚠️ Queue recovery error: {e}")

            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                self.router_logger.log_message(f"[Sniffer] ❗ Error in safe_enqueue(): {e}\n{tb}")

        # Start sniffing thread
        # Start sniffing thread
        sniffer_thread = threading.Thread(target=sniffer_loop, name=f"Sniffer-{iface_name.split('_')[-1]}", daemon=True)
        # Add to tracking BEFORE starting
        with self._sniff_threads_lock: # Protect the dict access
            self._sniff_threads[iface_name] = sniffer_thread
        sniffer_thread.start()

        # Start worker threads
        self._worker_threads[iface_name] = [] # Ensure this list is initialized for this interface
        for i in range(4):
            worker = threading.Thread(target=packet_worker, name=f"Worker-{iface_name}-{i}", daemon=True)
            worker.start()
            self._worker_threads[iface_name].append(worker)

        self.router_logger.log_message(f"[Router] Sniffing + workers started on {iface_name.split('_')[-1]}.")

    def _start_dhcp_servers(self):
        if self.router_network_in:
            dhcp_start_in_ip = str(self.router_network_in.network_address + 100)
            dhcp_end_in_ip = str(self.router_network_in.network_address + 200)
            dhcp_start_out_ip = str(self.router_network_out.network_address + 100)
            dhcp_end_out_ip = str(self.router_network_out.network_address + 200)

            self.dhcp_server_in = DHCPServer(
                self.router_logger,
                self.packet_writer,
                self.interface_in_full_name,
                dhcp_start_in_ip,
                dhcp_end_in_ip,
                self._interfaces_config
            )
            self.dhcp_server_out = DHCPServer(
                self.router_logger,
                self.packet_writer,
                self.interface_out_full_name,
                dhcp_start_out_ip,
                dhcp_end_out_ip,
                self._interfaces_config
            )
            self.arp_manager.set_dhcp_server_reference(self.dhcp_server_in, self.dhcp_server_out)
        else:
            self.router_logger.log_message("[DHCP] DHCP Server not initialized: Router IN network not configured.")
        if self.dhcp_server_in:
            self.dhcp_server_in.start()
        if self.dhcp_server_out:
            self.dhcp_server_out.start()

    def _process_packet(self, packet, inbound_iface: str):
        """Main packet processing pipeline with verbose logging."""
        try:
            iface_short = inbound_iface.split('_')[-1]
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if not ip_layer:
                return
            if self.ethernet_l2_manager.handle_packet(packet, inbound_iface):
                return
            self.transport_manager.handle_packet(packet, inbound_iface)
                # 4. DNS Handling
            if packet.haslayer(DNS):
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

            if packet.haslayer(TLS):
                self.router_logger.log_message(f"[TLS] 🔐 TLS packet detected on {iface_short}")
                if self.https_manager and self.https_manager.handle_packet(packet, inbound_iface):
                    self.router_logger.log_message(f"[TLS] 🛡️ TLS packet successfully handled on {iface_short}")
                    return

            if packet.haslayer(Kerberos):
                self.router_logger.log_message(f"[Kerberos] 🎟️ Kerberos packet detected on {iface_short}")
                if self.kerberos_manager and self.kerberos_manager.handle_kerberos_packet(packet):
                    self.router_logger.log_message(f"[Kerberos] 🧾 Kerberos packet authenticated on {iface_short}")
                    return

            # 2. DHCP Early Handling
            if packet.haslayer(DHCP) or packet.haslayer(DHCP6):
                self.router_logger.log_message(f"[DHCP] 📦 DHCP packet detected on {iface_short}")
                handled = False
                if self.dhcp_server_in and self.dhcp_server_in.handle_packet(packet, inbound_iface,self.rip_manager.find_route):
                    self.router_logger.log_message(
                        f"[DHCP] 📗 DHCP packet handled successfully by IN server on {iface_short}")
                    handled = True
                if self.dhcp_server_out and self.dhcp_server_out.handle_packet(packet, inbound_iface,self.rip_manager.find_route):
                    self.router_logger.log_message(
                        f"[DHCP] 📘 DHCP packet handled successfully by OUT server on {iface_short}")
                    handled = True
                if handled:
                    return
            # 3. ARP Inspection



            dst_ip = ip_layer.dst
            router_ips = [cfg["ip_addr"] for cfg in self._interfaces_config.values() if "ip_addr" in cfg]
            is_for_router = dst_ip in router_ips
            if packet.haslayer(RIP) or packet.haslayer(RIPEntry):
                self.router_logger.log_message(f"[RIP] 📘 RIP packet for router detected on {iface_short}")
                self.rip_manager.handle_packet(packet, inbound_iface)
                return
            if self.nat_manager.translate_inbound(packet):
                self.router_logger.log_message(f"[NAT] 🔄 NAT translated inbound packet on {iface_short}")
                self._forward_general_ip_packet(packet, inbound_iface)
                return

            # 5. Firewall Check

            if not self.firewall_manager.process_packet(packet):
                self.router_logger.log_message(f"[Firewall] 🔥 Blocked packet on {iface_short}")
                return

            # 6. ICMP Handling
            if packet.haslayer(scapy.layers.inet.ICMP):
                self.router_logger.log_message(f"[ICMP] 📶 Processing ICMP packet {iface_short}")
                if self.icmp_manager.handle_packet(packet, inbound_iface):
                    self.router_logger.log_message(f"[ICMP] 📬 Handled ICMP packet on {iface_short}")
                    return


            # 7. IGMP Handling
            if packet.haslayer(IGMP) or packet.haslayer(MLDReport) or packet.haslayer(MLDDone):
                dst_ip =packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst
                inbound_if_ip = self._interfaces_config.get(inbound_iface, {}).get("ip_addr")
                # Check if multicast or addressed to the router's interface IP
                if (inbound_if_ip and dst_ip == inbound_if_ip) or ipaddress.ip_address(dst_ip).is_multicast:
                    self.router_logger.log_message(f"[IGMP/MLD] 📶 Processing multicast membership on {iface_short}")
                    self.igmp_manager.handle_packet(packet, inbound_iface)
                    return



            # 9. Handshake
            if packet.haslayer(TCP):
                self.handshake_manager.handle_packet(packet, inbound_iface)

            result = self.packet_signer.process_packet(packet)

            if isinstance(result, Packet):
                pass
            elif result is False:
                self.router_logger.log_message("[Router] 🔏 Packet failed signature verification")
                return
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

            if not hasattr(packet[Ether], "dst") or not packet[Ether].dst or packet[
                Ether].dst.lower() == "ff:ff:ff:ff:ff:ff":
                self.router_logger.log_message(
                    f"[Router] 💧 Dropped packet: Ethernet layer has an invalid destination MAC address or it's a broadcast address. Summary: {packet.summary()}")
                return
            self.arp_manager._perform_arp_inspection(packet, inbound_iface)

            # 1. Duplicate Flow Check
            if packet.haslayer(IP):
                proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
                sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else 0
                dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 0
                if self.forwarding_manager.is_duplicate(ip_layer.src, ip_layer.dst, sport, dport, proto):
                    return

            # 11. General Forwarding (Transit)
            self.router_logger.log_message(
                RouterRandomMessages(
                    name="Router",
                    message=f"Forwarding: {packet.summary()} | In:{iface_short}",
                    emoticons=["🚚", "🚛", "🛻", "🚒", "🚐", "🚙", "🚎", "🚕"]
                )
            )
            self._forward_general_ip_packet(packet, inbound_iface)

        except Exception as e:
            self.router_logger.log_message(
                f"[Router] ❗ ERROR while processing on {inbound_iface.split('_')[-1]}: {e}. Packet: {packet.summary()}")

    def _forward_general_ip_packet(self, packet, inbound_iface: str):
        """Forwards a transit packet, applying NAT, LAG, ARP resolution, and Layer 2 handling."""

        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        dst_ip = ip_layer.dst

        ip_layer = None
        if packet.haslayer(IP):
            ip_layer = packet[IP]
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]

        if not ip_layer:
            self.router_logger.log_message(f"[Router] ❗ No IP layer found in packet. Dropping.")
            return
        if isinstance(ip_layer, IPv6) and ipaddress.ip_address(dst_ip).is_multicast:
            self.router_logger.log_message(f"[Router] 🚧 Flooding IPv6 multicast packet for {dst_ip} via bridge.")
            # Use the EthernetBridgeManager to handle L2 flooding
            self.ethernet_manager.handle_frame(packet, inbound_iface)
            return # IMPORTANT: Stop further processing to prevent routing attempt

        src_ip = ip_layer.src
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
        sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(
            UDP) else 0
        dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(
            UDP) else 0

        if self.forwarding_manager.is_duplicate(src_ip, dst_ip, sport, dport, proto):
            return

        # --- [1] Routing Lookup ---
        route = self.rip_manager.find_route(dst_ip)
        if not route:
            self.router_logger.log_message(f"[Router] 🛑 No route to {dst_ip}. Dropping.")
            return

        # --- [3] Load Balancing ---


        if ipaddress.ip_address(dst_ip).is_global:
            selected_iface = self.outbound_load_balancer.get_next_interface(packet)
            if selected_iface:
                actual_outbound_iface = selected_iface
                self.router_logger.log_message(
                    RouterRandomMessages(
                        name="Router",
                        message=f"Internet-bound packet Load-balanced {dst_ip} to {actual_outbound_iface.split('_')[-1]}",
                        emoticons=["👽", "🌍", "🌎", "🌏", "🌠", "🌌", "🪐", "🌗"]
                    )
                )
            else:
                self.router_logger.log_message(f"[Router] ❌ No load-balanced interface available. Dropping.")
                return


        initial_outbound_iface = route["interface"]
        next_hop_ip = route["next_hop"] if route["next_hop"] != "0.0.0.0" else dst_ip
        # --- [2] Link Aggregation Handling ---
        actual_outbound_iface = self.lag_manager.get_member_interface("MyLANAggregation", packet)



        # --- [4] Intra-LAN Loop Prevention ---
        inbound_config = self._interfaces_config.get(inbound_iface)
        inbound_network = inbound_config.get("network") if inbound_config else None
        is_intra_lan = (
                inbound_network and
                ipaddress.ip_address(dst_ip) in inbound_network and
                dst_ip != inbound_config.get("ip_addr")
        )



        if inbound_iface == initial_outbound_iface:
            if not is_intra_lan:
                alternate_route = self.rip_manager.find_alternate_route(dst_ip, exclude_iface=inbound_iface)
                if alternate_route:
                    actual_outbound_iface = alternate_route["interface"]
                    self.router_logger.log_message(
                        f"[Router] 🛣️ Routing loop on {inbound_iface} for {dst_ip} — rerouting via {actual_outbound_iface.split('_')[-1]}"
                    )
                    self.forwarding_manager.record_flow(src_ip, dst_ip, sport, dport, proto)

                    initial_outbound_iface = actual_outbound_iface
                else:
                    # Try default route (0.0.0.0/0)
                    default_route = self.rip_manager.find_route("0.0.0.0")
                    if default_route:
                        actual_outbound_iface = default_route["interface"]
                        self.router_logger.log_message(
                            f"[Router] 🚵 No alternate route to {dst_ip}. Using default route via {actual_outbound_iface.split('_')[-1]}"
                        )
                        self.forwarding_manager.record_flow(src_ip, dst_ip, sport, dport, proto)
                        initial_outbound_iface = actual_outbound_iface
                    else:
                        self.router_logger.log_message(
                            f"[Router] ❌ Routing loop on {inbound_iface} and no alternate or default route for {dst_ip}. Dropping.")
                        return
            else:
                self.router_logger.log_message(
                    f"[Router] 🏠 Intra-LAN forwarding: {packet.summary()} | In:{iface_short} -> Out:{iface_short}"
                )



        # --- [5] Multicast Filtering ---
        if ipaddress.ip_address(dst_ip).is_multicast:
            if not self.igmp_manager.should_forward_multicast(dst_ip, actual_outbound_iface):
                self.router_logger.log_message(
                    f"[Router] 📡 Dropping multicast {dst_ip} on {actual_outbound_iface.split('_')[-1]}: No members."
                )
                return

        is_lan_to_wan = (
                inbound_iface == self.interface_in_full_name and
                initial_outbound_iface == self.interface_out_full_name
        )

        # --- [6] Apply NAT (if applicable) ---
        if is_lan_to_wan and self.nat_manager:
            self.nat_manager.translate_outbound(packet)
            # Use the pre-defined ip_layer variable which handles both IP and IPv6
            if ip_layer.src != self.nat_manager.public_ip:
                self.router_logger.log_message(f"[NAT] ❌ Packet dropped after NAT failure.")
                return


        # --- [7] Prepare L2 Details ---
        outbound_config = self._interfaces_config.get(actual_outbound_iface)
        if not outbound_config:
            self.router_logger.log_message(
                f"[Router] ⚠️ Interface {actual_outbound_iface.split('_')[-1]} not in config. Dropping."
            )
            return

        is_loopback = (
                ipaddress.ip_address(dst_ip).is_loopback or
                "loopback" in actual_outbound_iface.lower() or
                actual_outbound_iface.lower() == "lo"
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
            target_mac = self.arp_manager.resolve(next_hop_ip, actual_outbound_iface)

        if not target_mac:
            self.router_logger.log_message(
                f"[Router] 🕵️ ARP failed for {next_hop_ip} on {actual_outbound_iface.split('_')[-1]}. Dropping."
            )
            return

        # --- [9] TTL Decrement ---
        # --- [0] Loopback Check (Crucial for your error) ---
        is_loopback_dest = ipaddress.ip_address(dst_ip).is_loopback

        # Only decrement TTL/HLIM if it's NOT a loopback destination
        # and if the packet is actually meant to be forwarded.
        if not is_loopback_dest:
            ttl_or_hlim = getattr(ip_layer, "ttl", None)
            if ttl_or_hlim is None:
                ttl_or_hlim = getattr(ip_layer, "hlim", None)

            if ttl_or_hlim is None:
                self.router_logger.log_message(f"[Router] ❗ Cannot find TTL/Hop Limit field for {dst_ip}. Dropping.")
                return

            if ttl_or_hlim <= 1:
                self.router_logger.log_message(f"[Router] ⌛ TTL/Hop Limit expired for {dst_ip}. Dropping.")
                return
            if hasattr(ip_layer, "ttl"):
                packet[IP].ttl -= 1
            elif hasattr(ip_layer, "hlim"):
                packet[IPv6].hlim -= 1
        # --- [10] Adjust or Apply Ether Layer ---
        if is_loopback:
            if packet.haslayer(Ether):
                packet =  packet.payload  # strip Ethernet layer
        elif packet.haslayer(Ether):
            packet[Ether].src = outbound_config["mac"]
            packet[Ether].dst = target_mac
        else:
            self.router_logger.log_message(
                f"[Router] ⚠️ Packet missing Ether layer for {actual_outbound_iface.split('_')[-1]}. Cannot send."
            )
            return

        # --- [11] Fix Checksums ---
        del ip_layer.chksum
        if packet.haslayer(TCP): del packet[TCP].chksum
        if packet.haslayer(UDP): del packet[UDP].chksum

        # --- [12] Send Packet ---
        self.packet_writer.queue_packet(packet, actual_outbound_iface)
        self.packet_catcher.process_packet(packet)
        self.router_logger.log_message(
            f"[Router] 📤 Packet queued to {actual_outbound_iface.split('_')[-1]}"
        )


    def start_routing(self, use_dhcp_out, use_dhcp_in):
        """Configures interfaces and starts all manager threads."""
        try:
            self._initialize_interface_discovery()
            if not self._auto_configure_interfaces(use_dhcp_out, use_dhcp_in):
                self.router_logger.log_message("[RouterManager] ❌ Failed to auto-configure interfaces.")
        except Exception as e:
            self.router_logger.log_message(f"[RouterManager] ❌ Crash in start_routing: {e}")

        self._enable_nat_forwarding()
        self.nat_manager = NATManager(self.router_logger, self.sendback_manager, self.router_ip_out, self.packet_writer, self._interfaces_config, self.rip_manager.find_route, self.arp_manager.resolve)
        self.nat_manager.start()

        self.notification_manager = NotificationManager(
            self.router_logger,
            self.NOTIFICATION_TARGET_IP,
            self.NOTIFICATION_TARGET_PORT,
            self.interface_in_full_name
        )
        self.packet_catcher.notification_manager = self.notification_manager
        self.arp_manager.notification_manager = self.notification_manager
        self.packet_signer.notification_manager = self.notification_manager

        self._start_dhcp_servers()

        self.rip_manager.initialize_routes(self._interfaces_config, self.router_gateway_out_ip,
                                           self.interface_out_full_name)
        self.ethernet_manager.start()

        google_dns_route_network = ipaddress.ip_network("8.8.8.8/32")

        current_route_details = self.rip_manager.find_route("8.8.8.8")
        if not current_route_details or current_route_details.get("type") != "static":
            self.router_logger.log_message("[Router] Adding/Updating static route for 8.8.8.8/32.")

            self.rip_manager.add_static_route(
                network_str=str(google_dns_route_network),
                next_hop=self.router_gateway_out_ip,
                interface=self.interface_out_full_name,
                cost=1
            )
            loopback_network = ipaddress.IPv6Network("::1/128")

            self.rip_manager.add_static_route(
                network_str=str(loopback_network),
                next_hop="::1",
                interface=self.interface_in_full_name,  # fallback to your IN interface
                cost=2
            )
        else:
            self.router_logger.log_message("[Router] Static route for 8.8.8.8/32 already exists.")

        self.handshake_manager = HandshakeManager(self.router_logger, self.arp_manager, self.nat_manager,
                                                  self.rip_manager)

        self.rip_manager.start()
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
            packet_writer=self.packet_writer,
            interfaces_config=self._interfaces_config,
            scan_targets=[
                ("8.8.8.8", [53, 80]),
                ("1.1.1.1", [443]),
            ],scan_interval=300)
        self.syn_scanner.start()

        for iface_name in self._interfaces_config.keys():
            self._start_single_sniffer(iface_name)

    def stop_routing(self):
        """Stops all manager threads and cleans up network interfaces."""
        self.router_logger.log_message("\n--- Python Router Stopping Services ---")
        self._stop_sniffing_event.set()
        if self.dhcp_server_in:
            self.dhcp_server_in.stop()
        if self.dhcp_server_out:
            self.dhcp_server_out.stop()
        self.rip_manager.stop()
        self.ethernet_manager.stop()
        self.packet_writer.stop()
        self._disable_nat_forwarding()
        if self.nat_manager:
            self.nat_manager.stop()
        self.router_logger.log_message("[Router] Waiting for worker threads to finish...")
        for iface_workers_list in getattr(self, "_worker_threads", {}).values():
            for worker in iface_workers_list:
                if worker.is_alive():
                    worker.join(timeout=2) # Give a short timeout
        self._worker_threads.clear()
        self.router_logger.log_message("[Router] Worker threads stopped.")

        # 5. Join sniffer threads (these should have died or be dying from _stop_sniffing_event)
        self.router_logger.log_message("[Router] Waiting for sniffer threads to finish...")
        # Access _sniff_threads with lock, as monitor might be trying to remove/add.
        with self._sniff_threads_lock:
            # Take a snapshot of current threads to avoid RuntimeError from dict changes during iteration
            # while a thread is joining.
            active_sniffers_snapshot = list(self._sniff_threads.values())
            for thread in active_sniffers_snapshot:
                if thread.is_alive():
                    thread.join(timeout=2)
            self._sniff_threads.clear() # Clear out any remaining references after joining
        self.router_logger.log_message("[Router] Sniffer threads stopped.")
        self._worker_threads.clear()
        self._sniff_threads.clear()
        self.igmp_manager.stop()
        self.handshake_manager.stop()
        self.remove_l2_bridge("MyLANBridge")
        self.remove_link_aggregation_group("MyLANAggregation")
        self.remove_outbound_load_balancing_interface(self.interface_ethernet_2_full_name)
        self.remove_outbound_load_balancing_interface(self.interface_out_full_name)
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

            response = sr1(packet, timeout=timeout, verbose=0)

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

            response = sr1(packet, timeout=timeout, verbose=0)

            if response is None: return 'FILTERED', None

            if response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN/ACK
                    rst_src_ip = response[IP].dst
                    rst_packet = IP(dst=target_ip, src=rst_src_ip) / TCP(
                        dport=target_port, sport=packet[TCP].sport, flags='R', seq=tcp_layer.ack
                    )
                    send(rst_packet, verbose=0)
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

            response = sr1(packet, timeout=timeout, verbose=0)

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

            response = sr1(packet, timeout=timeout, verbose=0)

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