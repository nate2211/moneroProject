import datetime
import hashlib
import hmac
import os
import queue
import random
import socket
import string
import struct
import subprocess
import traceback
from collections import defaultdict, deque
from collections.abc import Set
from typing import Optional, List, Any, Callable
import ipaddress
import threading
import json
import time
import numpy as np
from scapy.arch import get_if_hwaddr
from scapy.contrib.ikev2 import IKEv2
from scapy.fields import StrLenField
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import  DNS
from scapy.layers.inet import TCP, ICMP, defrag
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoReply
from scapy.layers.l2 import ARP, Ether, Dot1Q, getmacbyip
from scapy.layers.mobileip import MobileIP
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSFinished, TLSCertificate, \
    TLSClientKeyExchange, TLSServerKeyExchange, TLSServerHelloDone, TLSCertificateRequest, TLSNewSessionTicket, \
    TLSEncryptedExtensions
from scapy.layers.tls.keyexchange import ServerECDHNamedCurveParams, ServerDHParams, ClientECDiffieHellmanPublic, \
    ClientDiffieHellmanPublic, EncryptedPreMasterSecret
from scapy.layers.tls.record import TLS, TLSAlert, TLSChangeCipherSpec
from scapy.libs.rfc3961 import Key
from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict
from scapy.layers.kerberos import (
    Kerberos, KRB_AS_REQ, KRB_AS_REP, KRB_TGS_REQ, KRB_TGS_REP, KRB_ERROR,
    EncryptedData, PADATA
)

from server.p2pool_router_managers_2 import TLSRecordManager, TLSRecord


class FunctionCallTracker:
    """
    A class that tracks the invocation count for multiple functions or events.

    It automatically registers a function on its first call and logs a message once
    its call count reaches a specified threshold.
    """

    def __init__(self, logger):
        """
        Initializes the tracker with a logger and an empty dictionary for tracking state.
        """
        if not callable(getattr(logger, "log_message", None)):
            raise TypeError("The provided logger object must have a 'log_message' method.")

        self.logger = logger
        self._call_state = {}
        self.logger.log_message("[FunctionCallTracker] Initialized.")

    def track(self, identifier: str, threshold: int, final_message: Optional[str] = None,
              count_message: Optional[str] = None):
        """
        Tracks the invocation count for an event, but does NOT call a function.

        It registers the event on the first call using the provided parameters.

        Args:
            identifier (str): A unique name for the event being tracked.
            threshold (int): The number of times the event must occur to trigger the log.
            final_message (str): A format string for the message to log once the threshold is met.
            count_message (Optional[str]): An optional format string for a progress message.
                                           If not provided (None), no progress messages are logged.
        """
        if identifier not in self._call_state:
            self._call_state[identifier] = {
                'count': 0,
                'threshold': threshold,
                'final_message': final_message,
                'logged': False
            }
            self.logger.log_message(f"[FunctionCallTracker] Registered '{identifier}' on first call.")

        state = self._call_state[identifier]

        if not state['logged']:
            state['count'] += 1

            if count_message:
                self.logger.log_message(count_message.format(state['count']))

            if state['count'] >= state['threshold']:
                if final_message:
                    self.logger.log_message(state['final_message'].format(state['count']))
                state['logged'] = True

    def track_and_call(self, func, identifier: str, threshold: int, final_message: Optional[str] = None,
                       count_message: Optional[str] = None, *args, **kwargs):
        """
        Calls a function while tracking its invocation count. It registers the function
        on the first call using the provided parameters.

        Args:
            func: The function to be called.
            identifier (str): A unique name for the function or event being tracked.
            threshold (int): The number of times the function must be called to trigger the log.
            final_message (str): A format string for the message to log once the threshold is met.
            count_message (Optional[str]): An optional format string for a progress message.
                                           If not provided (None), no progress messages are logged.
            *args, **kwargs: Arguments to pass to the function.

        Returns:
            The result of the wrapped function call.
        """
        if identifier not in self._call_state:
            self._call_state[identifier] = {
                'count': 0,
                'threshold': threshold,
                'final_message': final_message,
                'logged': False
            }
            self.logger.log_message(f"[FunctionCallTracker] Registered '{identifier}' on first call.")

        state = self._call_state[identifier]

        if not state['logged']:
            state['count'] += 1

            if count_message:
                self.logger.log_message(count_message.format(state['count']))

            if state['count'] >= state['threshold']:
                if final_message:
                    self.logger.log_message(state['final_message'].format(state['count']))
                state['logged'] = True

        return func(*args, **kwargs)

    def track_and_final_call(self, func, identifier: str, threshold: int, final_message: Optional[str] = None,
                             count_message: Optional[str] = None, *args, **kwargs):
        """
        Tracks a function call but only executes the function once the call count
        reaches the threshold. Logs messages similarly to `track_and_call`.

        Args:
            func: The function to be called once the threshold is met.
            identifier (str): A unique name for tracking.
            threshold (int): Number of calls required before executing the function.
            final_message (str): Message to log when the function is executed.
            count_message (Optional[str]): Message to log on each call before the threshold.
            *args, **kwargs: Arguments to pass to the function.

        Returns:
            The result of the function if executed, otherwise None.
        """
        if identifier not in self._call_state:
            self._call_state[identifier] = {
                'count': 0,
                'threshold': threshold,
                'final_message': final_message,
                'logged': False
            }
            self.logger.log_message(f"[FunctionCallTracker] Registered '{identifier}' on first call.")

        state = self._call_state[identifier]

        if not state['logged']:
            state['count'] += 1

            if count_message:
                self.logger.log_message(count_message.format(state['count']))

            if state['count'] >= state['threshold']:
                if final_message:
                    self.logger.log_message(state['final_message'].format(state['count']))
                state['logged'] = True
                return func(*args, **kwargs)

        return None

def RouterRandomMessages(name: str, message: str, emoticons: list[str]) -> str:
    emoji = random.choice(emoticons) if emoticons else ''
    return f"[{name}] {emoji} {message}"

def _canon_key(ip1: str, pt1: int, ip2: str, pt2: int):
    return tuple(sorted([(ip1, pt1), (ip2, pt2)]))

class ISAKMPManager:
    """
    Manages ISAKMP packets. This version is hardened with per-source IP
    rate-limiting to protect against scans and floods.
    """

    def __init__(self, router_logger, packet_writer, notification_manager, interfaces_config: dict):
        self.log = router_logger
        self.pw = packet_writer
        self.ifaces = interfaces_config
        self.notification_manager = notification_manager
        self.fragment_cache = {}

        # --- NEW: Rate-limiting configuration ---
        self.RATE_LIMIT_HZ = 1  # Max 10 packets per second per source IP
        self.BURST_LIMIT = 2  # How many packets to track for rate calculation
        self.source_tracker = defaultdict(lambda: {
            "timestamps": deque(maxlen=self.BURST_LIMIT),
            "is_throttling": False
        })
        # --- END NEW ---

        self.log.log_message("[ISAKMP] Manager initialized with rate-limiting.")

    def _check_for_malformed_isakmp(self, packet, inbound_iface: str):
        # This method remains unchanged
        if not packet.haslayer(IP) or not packet.haslayer(UDP):
            return
        ip_layer = packet.getlayer(IP)
        if packet.haslayer(IKEv2) and packet.getlayer(IKEv2).payload.name == 'Raw':
            event_data = {
                "event": "Malformed ISAKMP Packet Detected",
                "message": f"Malformed ISAKMP packet from {ip_layer.src}. Extra unparsed bytes found.",
                "iface": inbound_iface, "timestamp": time.time(), "emojis": ["🚨", "🗃️", "💥"]
            }
            self.notification_manager.send_notification(event_data, cooldown_seconds=10,
                                                        cooldown_key="isakmpmalformed")

    def handle_packet(self, pkt: Packet, inbound_iface: str) -> bool:
        """
        Handles incoming packets. Now includes rate-limiting to prevent spam.
        """
        if not pkt.haslayer(UDP) or not (pkt[UDP].dport == 500 or pkt[UDP].sport == 500):
            return False

        # --- NEW: Rate-limiting logic at the very beginning ---
        src_ip = pkt[IP].src
        entry = self.source_tracker[src_ip]
        now = time.time()
        entry["timestamps"].append(now)

        # Only check the rate if we have enough samples to make a decision
        if len(entry["timestamps"]) == self.BURST_LIMIT:
            duration = now - entry["timestamps"][0]
            rate = self.BURST_LIMIT / duration if duration > 0 else float('inf')

            if rate > self.RATE_LIMIT_HZ:
                # If we aren't already throttling this IP, send one notification
                if not entry["is_throttling"]:
                    self.notification_manager.send_notification({
                        "event": "ISAKMP Flood Detected",
                        "message": f"High rate of ISAKMP packets from {src_ip}. Throttling source.",
                        "iface": inbound_iface, "timestamp": now, "emojis": ["🌊", "🛡️", "🛑"]
                    }, cooldown_seconds=30, cooldown_key=f"isakmpflood_{src_ip}")
                    entry["is_throttling"] = True

                # Silently drop the packet
                return True  # Indicate packet was "handled" by dropping it

            elif entry["is_throttling"]:
                # If the rate has dropped back to normal, stop throttling
                entry["is_throttling"] = False
        # --- END NEW ---

        # If the packet was not dropped by the rate-limiter, proceed as normal
        self.log.log_message(f"[ISAKMP] 📨 Packet from {src_ip} on {inbound_iface}")

        final_packet = pkt
        if pkt.haslayer(IP) and (pkt[IP].flags == 'MF' or pkt[IP].frag != 0):
            frag_key = (pkt[IP].src, pkt[IP].dst, pkt[IP].id)
            self.fragment_cache.setdefault(frag_key, []).append(pkt[IP])

            reassembled_layers = defrag(self.fragment_cache[frag_key])
            if reassembled_layers and isinstance(reassembled_layers[0], IP):
                final_packet = Ether() / reassembled_layers[0]
                del self.fragment_cache[frag_key]
            else:
                return True  # Consume fragment, wait for more

        self._check_for_malformed_isakmp(final_packet, inbound_iface)
        return True

class SendBackManager:
    """
    An enhanced version that uses a sendback table and numpy to intelligently decide
    whether to send a response packet.
    """

    # Constants for the decision-making logic
    RATE_LIMIT_SECONDS = 1.0  # Time window for rate limiting per source IP
    MAX_RESPONSES_PER_WINDOW = 3  # Max number of responses to send back per source IP per window
    MIN_HISTORY_SIZE = 5  # Minimum number of packets to analyze before using numpy

    # Store a history of packet sizes and timestamps per source IP
    # Key: str(source_ip) -> {'timestamps': deque, 'sizes': deque}
    _sendback_table = defaultdict(lambda: {
        'timestamps': deque(maxlen=20),
        'sizes': deque(maxlen=20),
    })

    _table_lock = threading.Lock()  # Ensure thread safety

    def __init__(self, router_logger, packet_signer, outbound_load_balancer):
        self.logger = router_logger
        self.packet_signer = packet_signer
        self.outbound_load_balancer = outbound_load_balancer
        self.sniffer = None
        self.logger.log_message("[SendBack] Initialized.")

    def _should_sendback(self, packet: Packet) -> bool:
        """
        Decides whether to send a packet back based on rate-limiting and statistical analysis.
        """
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if not ip_layer:
            return False

        src_ip = ip_layer.src
        now = time.time()

        with self._table_lock:
            entry = self._sendback_table[src_ip]

            # 1. Check Rate-Limiting
            # Filter out timestamps older than our rate-limiting window
            recent_timestamps = [t for t in entry['timestamps'] if now - t <= self.RATE_LIMIT_SECONDS]
            if len(recent_timestamps) >= self.MAX_RESPONSES_PER_WINDOW:
                self.logger.log_message(f"[SendBack] ⏱️ Rate-limited response to {src_ip}.")
                return False

            # 2. Check for suspicious packet size patterns (using numpy)
            packet_len = len(packet)
            entry['sizes'].append(packet_len)
            entry['timestamps'].append(now)

            if len(entry['sizes']) >= self.MIN_HISTORY_SIZE:
                # Use numpy to calculate the standard deviation of recent packet sizes
                size_array = np.array(entry['sizes'])
                std_dev = np.std(size_array)

                # If the standard deviation is very low, it could be a simple flood
                # with packets of the same size.
                if std_dev < 10:  # A heuristic threshold; can be tuned
                    self.logger.log_message(
                        f"[SendBack] 🕵️ Packet sizes from {src_ip} are suspicious (low std dev: {std_dev:.2f}). Dropping response."
                    )
                    return False

        return True

    def send_back(self, packet: Packet):
        """
        Signs and sends a packet immediately on a chosen outbound interface.
        Only proceeds if the sendback is permitted by the decision logic.
        """
        if not self._should_sendback(packet):
            return

        try:
            if not packet.haslayer(Ether) or not packet[Ether].dst or packet[Ether].dst.lower() == "ff:ff:ff:ff:ff:ff":
                self.logger.log_message(
                    f"[Sendback] 💦 Dropped packet: Ethernet layer has an invalid destination MAC address or it's a broadcast address. Summary: {packet.summary()}")
                return

            if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                self.logger.log_message(
                    f"[Sendback] ❌ Dropped packet: No IP or IPv6 layer present. Summary: {packet.summary()}")
                return
            self.packet_signer.sign_packet(packet)
            outbound_interface = self.outbound_load_balancer.get_next_interface(packet)

            self.sniffer.sendp(packet, iface=outbound_interface, verbose=0)
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
        Only proceeds if the sendback is permitted by the decision logic.
        """
        if not self._should_sendback(original_packet):
            return

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
                self.sniffer.sendp(icmp_reply, iface=outbound_iface, verbose=0)
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
                self.sniffer.sendp(icmpv6_reply, iface=outbound_iface, verbose=0)
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

    def __init__(self, router_logger, interfaces_config: dict, catching_threshold: int = 3,
                 packet_queue_maxlen: int = 3):
        """
        Initializes the PacketCatcherManager with the router's interface configuration.

        Args:
            router_logger (RouterLogger): An instance of the router's logger.
            interfaces_config (dict): A reference to the router's interface configuration.
            catching_threshold (int): The number of unencrypted payloads from a single IP
                                     that triggers a release of collected packets for that IP.
            packet_queue_maxlen (int): The maximum number of packets to store per IP
                                       in the catching table before old ones are dropped.
        """
        self.logger = router_logger
        self.sniffer = None
        self._interfaces_config = interfaces_config
        self.notification_manager = None
        self.arp_manager = None
        self.plaintext_ports = {
            80: "HTTP", 21: "FTP (Control)", 23: "Telnet", 25: "SMTP", 110: "POP3",
            143: "IMAP", 53: "DNS", 161: "SNMP", 389: "LDAP",
        }
        self.readable_content_types = {
            'text/html', 'application/json', 'text/plain', 'text/xml', 'application/xhtml+xml'
        }
        self.catching_table = defaultdict(lambda: {'packets': deque(maxlen=packet_queue_maxlen), 'count': 0})
        self.catching_threshold = catching_threshold
        self.dry_table = defaultdict(lambda: {'count': 0, 'history': deque(maxlen=10)})
        self.dry_threshold = 5000
        self.packet_queue_maxlen = packet_queue_maxlen

        # Use a deque to store a fixed number of recent payload hashes to manage memory.
        self._caught_payloads_hash_set = deque(maxlen=1000)

        # Cooldown table to prevent repeated fishing requests to the same IP.
        self._fishing_cooldown_table = defaultdict(int)
        self._fishing_cooldown_threshold = 5
        self._cooldown_duration = 300

        self.logger.log_message(
            f"[PacketCatcher] 🎣 Manager initialized.")

    def _parse_http_response(self, payload: bytes) -> Tuple[Optional[int], Optional[str]]:
        """
        Attempts to parse a raw HTTP response payload to extract the status code and content type.
        Returns a tuple of (status_code, content_type) or (None, None) if parsing fails.
        """
        try:
            status_line_end = payload.find(b'\r\n')
            if status_line_end == -1:
                return None, None
            status_line = payload[:status_line_end].decode('utf-8', errors='ignore')

            parts = status_line.split(' ')
            if len(parts) < 2 or not parts[1].isdigit():
                return None, None
            status_code = int(parts[1])

            headers_end = payload.find(b'\r\n\r\n')
            if headers_end == -1:
                return status_code, None

            headers_raw = payload[status_line_end + 2:headers_end]
            headers_str = headers_raw.decode('utf-8', errors='ignore')

            for line in headers_str.split('\r\n'):
                if line.lower().startswith('content-type:'):
                    content_type_full = line.split(':', 1)[1].strip()
                    content_type = content_type_full.split(';')[0].strip().lower()
                    return status_code, content_type

            return status_code, None
        except Exception as e:
            self.logger.log_message(f"[PacketCatcher-HTTP] ⚠️ Error parsing HTTP payload: {e}")
            return None, None

    def _should_catch(self, status_code, content_type, payload: bytes) -> bool:
        """
        Determines whether a payload should be flagged based on heuristics.
        """
        # --- Heuristic 1: Status code in error range ---
        if status_code is not None and 400 <= status_code < 600:
            self.logger.log_message(f"[PacketCatcher-Heuristic] 🔍 Status code {status_code} indicates error.")
            return True

        # --- Heuristic 2: Readable content type ---
        if content_type in self.readable_content_types:
            self.logger.log_message(f"[PacketCatcher-Heuristic] 📄 Content-Type '{content_type}' is readable.")
            return True

        # --- Heuristic 3: Printable character ratio ---
        try:
            payload_array = np.frombuffer(payload, dtype=np.uint8)
            printable_bytes = set(bytes(string.printable, 'utf-8'))
            printable_ratio = np.mean([b in printable_bytes for b in payload_array])

            if printable_ratio > 0.9:
                self.logger.log_message(
                    f"[PacketCatcher-Heuristic] ✨ Printable ratio {printable_ratio:.2f} suggests plaintext.")
                return True
        except ValueError:
            # Handle cases where payload cannot be converted to a numpy array
            pass

        # --- Heuristic 4: Entropy check ---
        try:
            unique, counts = np.unique(payload_array, return_counts=True)
            probs = counts / counts.sum()
            entropy = -np.sum(probs * np.log2(probs))

            if entropy < 4.0:
                self.logger.log_message(
                    f"[PacketCatcher-Heuristic] 📉 Low entropy {entropy:.2f} suggests unencrypted data.")
                return True
        except (ValueError, np.AxisError):
            # Handle cases where entropy cannot be calculated
            pass

        return False

    def process_packet(self, packet: Packet):
        """
        Inspects a packet for unencrypted (plaintext) payloads, using a heuristic
        for HTTP traffic.
        """
        payload_detected_in_this_packet = False
        protocol_info = "Unknown"
        src_ip = None
        dst_ip = None
        decoded_payload = None

        # Robust payload extraction logic
        raw_payload = None
        if Raw in packet and packet[Raw].load:
            raw_payload = packet[Raw].load
        elif packet.payload:
            # Fallback to the next layer's payload. This is a common pattern for mDNS, etc.
            raw_payload = bytes(packet.payload)

        if not raw_payload:
            return

        try:
            # Calculate a unique hash for the payload to prevent duplicates
            payload_hash = hashlib.sha256(raw_payload).hexdigest()
            if payload_hash in self._caught_payloads_hash_set:
                return
        except TypeError:
            # Catch the error if raw_payload is not a bytes-like object
            self.logger.log_message(
                f"[PacketCatcher] ❗ Error: Payload is not a bytes-like object. Skipping hash check.")
            return

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            self.logger.log_message("[PacketCatcher] 🐠 Not an IP packet, skipping payload inspection.")
            return

        try:
            # --- TCP Payload Check ---
            if TCP in packet and raw_payload:
                tcp_layer = packet[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport

                # HEURISTIC 1: Check for HTTP traffic with a readable error payload.
                if dport in self.plaintext_ports or sport in self.plaintext_ports:
                    status_code, content_type = self._parse_http_response(raw_payload)
                    if self._should_catch(status_code, content_type, raw_payload):
                        protocol_info = f"HTTP Error ({status_code})"
                        log_payload = raw_payload.decode('utf-8', errors='ignore')[:50].replace('\n', '').replace('\r',
                                                                                                                  '')
                        self.logger.log_message(
                            f"[PacketCatcher] 🐟 Caught HTTP Error Payload. Heuristic Matched. Payload snippet:{log_payload}")
                        payload_detected_in_this_packet = True
                    else:
                        return

                # If not an interesting HTTP payload, fall back to generic plaintext check.
                if not payload_detected_in_this_packet:
                    # HEURISTIC 2: Generic plaintext check on known ports.
                    if sport in self.plaintext_ports:
                        protocol_info = self.plaintext_ports[sport]
                    elif dport in self.plaintext_ports:
                        protocol_info = self.plaintext_ports[dport]

                    if protocol_info != "Unknown":
                        decoded_payload = raw_payload.decode('utf-8', errors='ignore')
                        if decoded_payload.strip() in ["SEND_FISH", "DESKTOP-RM18V5L"]:
                            self.logger.log_message(
                                f"[PacketCatcher] 🦈 Ignored packet with restricted payload from {src_ip}")
                            return
                        log_payload = decoded_payload[:50] + "..." if len(decoded_payload) > 50 else decoded_payload
                        log_payload = log_payload.replace('\n', '').replace('\r', '')
                        self.logger.log_message(
                            f"[PacketCatcher] 🐟 Caught interesting TCP Payload ({protocol_info}). Payload snippet:{log_payload}")
                        payload_detected_in_this_packet = True

            # --- UDP Payload Check (unchanged) ---
            elif UDP in packet and raw_payload:
                udp_layer = packet[UDP]
                sport = udp_layer.sport
                dport = udp_layer.dport

                if sport in self.plaintext_ports:
                    protocol_info = self.plaintext_ports[sport]
                elif dport in self.plaintext_ports:
                    protocol_info = self.plaintext_ports[dport]

                decoded_payload = raw_payload.decode('utf-8', errors='ignore')
                if decoded_payload.strip() in ["SEND_FISH", "DESKTOP-RM18V5L"]:
                    self.logger.log_message(
                        f"[PacketCatcher] 🦈 Ignored packet with restricted payload from {src_ip}")
                    return
                log_payload = decoded_payload[:50] + "..." if len(decoded_payload) > 50 else decoded_payload
                log_payload = log_payload.replace('\n', '').replace('\r', '')
                self.logger.log_message(
                    f"[PacketCatcher] 🐡 Caught interesting UDP Payload ({protocol_info}). Payload snippet:{log_payload}")
                payload_detected_in_this_packet = True

            # For ICMP Echo Replies
            elif ICMP in packet and raw_payload and (
                    packet[ICMP].type == 0 or (IPv6 in packet and ICMPv6EchoReply in packet)):
                decoded_payload = raw_payload.decode('utf-8', errors='ignore')
                if decoded_payload.strip() in ["SEND_FISH", "DESKTOP-RM18V5L"]:
                    self.logger.log_message(
                        f"[PacketCatcher] 🦈 Ignored packet with restricted payload from {src_ip}")
                    return
                log_payload = decoded_payload[:50] + "..." if len(decoded_payload) > 50 else decoded_payload
                log_payload = log_payload.replace('\n', '').replace('\r', '')
                self.logger.log_message(
                    f"[PacketCatcher] 🍣 Caught interesting ICMP Echo Reply Payload. Payload snippet:{log_payload}")
                payload_detected_in_this_packet = True

            if payload_detected_in_this_packet:
                self._caught_payloads_hash_set.append(payload_hash)
                ip_entry = self.catching_table[src_ip]
                ip_entry['packets'].append(packet)
                ip_entry['count'] += 1
                self.logger.log_message(
                    f"[PacketCatcher] 🐠 Stored packet from {src_ip}. Current count for {src_ip}: {ip_entry['count']}/{self.catching_threshold} ({len(ip_entry['packets'])} in queue)."
                )

                if ip_entry['count'] >= self.catching_threshold:
                    self.logger.log_message(
                        f"[PacketCatcher] 💰 Unencrypted payload threshold reached for {src_ip}! ({ip_entry['count']} detections)")
                    self._release_packets_for_ip(src_ip, packet.sniffed_on)
                    self.request_fish(dst_ip)
            else:
                if dst_ip:
                    dry_entry = self.dry_table[dst_ip]
                    dry_entry['count'] += 1
                    dry_entry['history'].append(dry_entry['count'])

                    history_array = np.array(dry_entry['history'])
                    trend = np.gradient(history_array)[-1] if len(history_array) > 1 else 0
                    if trend > 0.95 or dry_entry['count'] > self.dry_threshold:
                        self.request_fish(dst_ip)
        except Exception as e:
            self.logger.log_message(f"[PacketCatcher] ❗ Error during payload inspection: {e}\n{traceback.format_exc()}")

    def request_fish(self, ip_address: str):
        """
        Sends a custom UDP packet to the specified IP to request re-transmission of unencrypted data.
        """
        try:
            if self._fishing_cooldown_table[ip_address] >= self._fishing_cooldown_threshold:
                self.logger.log_message(f"[PacketCatcher] ⏱️ Fish request for {ip_address} is on cooldown.")
                return

            payload = b"SEND_FISH"
            packet = IP(dst=ip_address) / UDP(sport=55555, dport=55555) / Raw(load=payload)

            self.logger.log_message(f"[PacketCatcher] 🕳️ Sending fish request to {ip_address}")
            self.sniffer.send(packet, verbose=False)

            self._fishing_cooldown_table[ip_address] += 1

        except Exception as e:
            self.logger.log_message(f"[PacketCatcher] ❌ Failed to send fish request to {ip_address}.")

    def _release_packets_for_ip(self, ip_address: str, iface: str = None):
        """
        Processes packets stored in the catching table for a specific IP by reconstructing them
        and sending them at Layer 3, then clearing the count for that IP.
        """
        if ip_address not in self.catching_table:
            self.logger.log_message(f"[PacketCatcher] ℹ️ No packets to process for IP: {ip_address}")
            return

        ip_entry = self.catching_table[ip_address]
        num_packets_to_process = len(ip_entry['packets'])
        self.logger.log_message(
            f"[PacketCatcher] 🏴‍☠️ Reconstructing and sending {num_packets_to_process} packets for IP: {ip_address}.")

        router_ips = [cfg["ip_addr"] for cfg in self._interfaces_config.values() if "ip_addr" in cfg]

        while ip_entry['packets']:
            pkt = ip_entry['packets'].popleft()

            l3_packet = pkt.getlayer(IP) or pkt.getlayer(IPv6)

            if l3_packet:
                if str(l3_packet.dst) in router_ips:
                    self.logger.log_message(
                        f"[PacketCatcher] 🦜 Redirecting packet originally meant for our IP ({l3_packet.dst})..."
                    )
                    # Replace with a safe external address (modify as needed)
                    if IP in l3_packet:
                        l3_packet.dst = "8.8.8.8"
                    elif IPv6 in l3_packet:
                        l3_packet.dst = "2001:4860:4860::8888"

                try:
                    # Check for Ether layer before accessing its attributes
                    if Ether in pkt and (not pkt[Ether].dst or pkt[Ether].dst.lower() == "ff:ff:ff:ff:ff:ff"):
                        self.logger.log_message(
                            f"[PacketCatcher] 💦 Dropped packet: Ethernet layer has an invalid destination MAC address or it's a broadcast address. Summary: {pkt.summary()}")
                        continue

                    self.sniffer.send(l3_packet, verbose=False)
                    self.logger.log_message(
                        f"[PacketCatcher] 🦜 Reconstructed and sent L3 packet from {l3_packet.src} to {l3_packet.dst}.")
                except Exception as e:
                    self.logger.log_message(f"[PacketCatcher] ❌ Failed to send reconstructed packet: {e}")
            else:
                self.logger.log_message(
                    f"[PacketCatcher] ⚠️ Packet for {ip_address} was not a valid L3 packet. Dropping.")

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
        self.sniffer = None
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
        # ... (This part of the method is mostly the same)
        try:
            if hasattr(ip_layer, "src") and hasattr(ip_layer.src, "packed"):
                src = ip_layer.src.packed
            else:
                src = socket.inet_pton(socket.AF_INET6 if isinstance(ip_layer, IPv6) else socket.AF_INET, ip_layer.src)
            if hasattr(ip_layer, "dst") and hasattr(ip_layer.dst, "packed"):
                dst = ip_layer.dst.packed
            else:
                dst = socket.inet_pton(socket.AF_INET6 if isinstance(ip_layer, IPv6) else socket.AF_INET, ip_layer.dst)
        except Exception:
            src, dst = b"", b""
        try:
            if isinstance(ip_layer, IP):
                proto = bytes([ip_layer.proto])
            elif isinstance(ip_layer, IPv6):
                proto = bytes([ip_layer.nh])
            else:
                proto = b"\x00"
        except Exception:
            proto = b"\x00"
        ports = b"\x00\x00\x00\x00"
        try:
            if TCP in packet:
                sport, dport = packet[TCP].sport, packet[TCP].dport
            elif UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
            else:
                sport = dport = 0
            ports = struct.pack("!HH", sport, dport)
        except Exception:
            ports = b"\x00\x00\x00\x00"
        try:
            payload = bytes(ip_layer.payload)[:64] if ip_layer.payload else b""
        except Exception:
            payload = b""

        sig_data = src + dst + proto + ports + payload
        signature_hash = hashlib.sha1(sig_data).hexdigest()

        # --- BUG FIX: Corrected typo 'sigintable' to 'signature_table' ---
        # --- BUG FIX: Used 'last_seen' key to match cleanup logic ---
        if hasattr(self, "signature_table"):
            self.signature_table[signature_hash] = {
                "src_ip": str(ip_layer.src),
                "dst_ip": str(ip_layer.dst),
                "proto": ip_layer.proto if isinstance(ip_layer, IP) else ip_layer.nh if isinstance(ip_layer,
                                                                                                   IPv6) else None,
                "ports": struct.unpack("!HH", ports) if len(ports) == 4 else None,
                "payload_sample": payload.hex(),
                "last_seen": time.time() # Corrected key from 'timestamp'
            }

        return sig_data

    def sign_packet(self, packet: Packet) -> bool:
        """
        Signs the packet and embeds signature into appropriate header.
        Returns True if the signature is valid after signing; otherwise drops.
        """
        # --- REFACTORED: The misplaced cleanup logic has been removed from this function. ---

        if IP in packet:
            ip = packet[IP]
            sig_data = self._get_signature_data(packet, ip)
            if not sig_data:
                return False

            digest = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()
            packet[IP].id = struct.unpack("!H", digest[:2])[0]
            del packet[IP].chksum # Recalculate checksum

            if self.verify_packet(packet):
                self.logger.log_message(f"[Signing] 🖊️ IPv4 signed + verified (ID: {packet[IP].id:#06x})")
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
                self.logger.log_message(f"[Signing] 📏 IPv6 signed + verified (Flow Label: {packet[IPv6].fl:#06x})")
                # This return True is critical and correctly makes the function succeed.
                return True
            else:
                self.logger.log_message("[Signing] 💥 Dropped IPv6: Signature mismatch after signing")
                return False

        # --- BUG FIX: Explicitly handle non-IP packets and return False. ---
        else:
            self.logger.log_message("[Signing] 👻 Skipped non-IP packet")
            return False

    def _cleanup_signature_table(self):
        """
        NEW METHOD: Dedicated function to remove expired entries from the signature table.
        This should be called periodically by the router's main loop.
        """
        now = time.time()
        # The original code had a bug where it would return after one deletion.
        # This implementation correctly removes all expired keys.
        expired_keys = [k for k, v in self.signature_table.items() if now - v.get("last_seen", 0) > 30]
        if expired_keys:
            self.logger.log_message(f"[Signing] 🧹 Cleaning up {len(expired_keys)} expired signature entries.")
            for k in expired_keys:
                del self.signature_table[k]

    def verify_packet(self, packet: Packet) -> bool:
        """Verifies that the embedded signature matches a fresh HMAC."""
        # This method's logic was correct and remains unchanged.
        try:
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if not ip:
                return False

            sig_data = self._get_signature_data(packet, ip)
            digest = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()

            if isinstance(ip, IP):
                expected_id = struct.unpack("!H", digest[:2])[0]
                return ip.id == expected_id
            elif isinstance(ip, IPv6):
                expected_fl = struct.unpack("!I", b'\x00' + digest[:3])[0] & 0xFFFFF
                return ip.fl == expected_fl

            return False
        except Exception as e:
            self.logger.log_message(f"[Signing] ⚠️ Signature verify error: {e}")
            return False

    # ... The rest of the class (process_packet, _handle_unsigned_packet, etc.) remains unchanged ...
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
                    self.logger.log_message(f"[Signing] 🔒 Verified incoming IPv6 packet (Flow Label: {ip.fl:#0x})")
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
            # self.notification_manager.send_notification(
            #     {
            #         "event": "Receiving Unsigned Packets",
            #         "ip": ip_layer.dst,
            #         "mac": sender_mac,
            #         "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            #         "emojis": ["📋"]
            #     })
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
                # self.sniffer.send(response, verbose=False)
                self.logger.log_message(f"[Signing] 📮 Sent signed IPv4 rejection to {dst}")
            elif IPv6 in packet:
                response = IPv6(dst=dst, src=ip_layer.dst)/ICMPv6DestUnreach(code=1)/b"Unsigned IPv6 packet rejected"
                self.sign_packet(response)
                # self.sniffer.send(response, verbose=False)
                self.logger.log_message(f"[Signing] 📬 Sent signed IPv6 rejection to {dst}")
        except Exception as e:
            pass

class ESPManager:
    """
    Transparent ESP/NAT-T forwarder and flow tracker.

    Key features:
      - Pass-through routing for native ESP (IP proto 50) and NAT-T (UDP/4500).
      - Tracks outbound flows so inbound replies are delivered to the right LAN iface/MAC.
      - Parses ESP SPI from header (first 4 bytes) and associates it with a (peer, direction).
      - Detects and drops NAT-T keepalives (single 0xFF byte) and can log them.
      - Handles NAT-T Non-ESP Marker (first 4 bytes == 0x00000000) before ESP header.
      - Optional peer allow-list for ingress protection.
      - Minimal anti-replay window bookkeeping (sequence numbers per (peer, spi, dir)).
      - Zero cryptography: this is a transparent forwarder, not an IPsec endpoint.

    Integration points expected from your router:
      - router_logger: has .log_message(str)
      - packet_writer: has .queue_packet(pkt, egress_iface_name)
      - get_mac_function(ip, iface_name) -> dst_mac or None
      - find_route_function(ip) -> {"interface": name, "next_hop": ip or None} or None
      - router_interfaces: {iface_name: {"ip_addr": "...", "mac": "..."}}
    """

    NAT_T_PORT = 4500

    def __init__(self, router_logger, packet_writer):
        self.log = router_logger
        self.pw = packet_writer

        # Map for native ESP (no ports), so we rely on SPI + peer direction.
        # Key: ("ESP", dst_ip, spi) for outbound (LAN->WAN) learned mapping
        # Val: {"lan_iface": str, "lan_mac": str, "lan_ip": str, "ts": float}
        self._esp_out_map = {}

        # NAT-T map (has ports). We track 5-tuple to route replies.
        # Key: ("NATT", remote_ip, remote_port, local_ip, local_port)
        # Val: {"lan_iface": str, "lan_mac": str, "lan_ip": str, "ts": float}
        self._natt_out_map = {}

        # Anti-replay lite: per (peer_ip, spi, dir) we remember a small sliding window.
        # dir ∈ {"out", "in"} relative to LAN side perspective.
        # Val: {"last": int, "seen": set[int] or deque, "win": int}
        self._replay = defaultdict(lambda: {"last": 0, "seen": set(), "win": 64})

        # Optional peer allow-list (string IPs or CIDRs). Empty = allow all.
        self._peer_allowlist = set()

        # Timeouts
        self.MAP_TTL = 300  # seconds to keep mappings
        self.CLEANUP_INTERVAL = 60
        self._last_cleanup = 0.0

        # Concurrency
        self._lock = threading.RLock()

        self.log.log_message("[ESP] Manager initialized.")

    # -------------------------
    # Public config methods
    # -------------------------
    def allow_peer(self, ip_or_cidr: str):
        """Allow inbound ESP/NAT-T from a specific peer IP or CIDR."""
        with self._lock:
            self._peer_allowlist.add(ip_or_cidr)
        self.log.log_message(f"[ESP] Allow-listed peer/net: {ip_or_cidr}")

    def deny_peer(self, ip_or_cidr: str):
        """Remove from allow-list (if present). If list becomes empty, all peers allowed."""
        with self._lock:
            self._peer_allowlist.discard(ip_or_cidr)
        self.log.log_message(f"[ESP] Removed from allow-list: {ip_or_cidr}")

    # -------------------------
    # Main entry
    # -------------------------
    def handle_packet(self, pkt, inbound_iface: str, router_interfaces: dict,
                      get_mac_function, find_route_function) -> bool:
        """
        Intercept and forward ESP/NAT-T. Return True if handled (consumed or forwarded).
        """
        try:
            handled = False
            ip, ipv6 = pkt.getlayer(IP), pkt.getlayer(IPv6)
            if not (ip or ipv6):
                return False

            if self._is_natt(pkt):
                handled = self._handle_natt(pkt, inbound_iface, router_interfaces, get_mac_function, find_route_function)
            elif self._is_esp(pkt):
                handled = self._handle_native_esp(pkt, inbound_iface, router_interfaces, get_mac_function, find_route_function)

            # Periodic GC
            now = time.time()
            if now - self._last_cleanup > self.CLEANUP_INTERVAL:
                self._cleanup(now)

            return handled
        except Exception as e:
            self.log.log_message(f"[ESP] ❌ Exception in handle_packet: {e}")
            return False

    # -------------------------
    # Detection helpers
    # -------------------------
    @staticmethod
    def _is_esp(pkt) -> bool:
        ip = pkt.getlayer(IP)
        if ip and getattr(ip, "proto", None) == 50:
            return True
        v6 = pkt.getlayer(IPv6)
        if v6 and getattr(v6, "nh", None) == 50:
            return True
        return False

    def _is_natt(self, pkt) -> bool:
        udp = pkt.getlayer(UDP)
        if not udp:
            return False
        if udp.sport == self.NAT_T_PORT or udp.dport == self.NAT_T_PORT:
            # NAT-T keepalive is 1 byte 0xFF; Non-ESP Marker is 4 zero bytes.
            raw = pkt.getlayer(Raw)
            if raw:
                payload = bytes(raw.load)
                if payload == b"\xff":  # keepalive
                    return True
                if len(payload) >= 8:
                    # Non-ESP marker (4 zero bytes) followed by ESP header
                    if payload[:4] == b"\x00\x00\x00\x00":
                        return True
            else:
                # No Raw layer: still treat as NAT-T (some stacks may send empty keepalive frames)
                return True
        return False

    # -------------------------
    # NAT-T handling
    # -------------------------
    def _handle_natt(self, pkt, inbound_iface: str, router_ifaces: dict,
                     get_mac_function, find_route_function) -> bool:
        udp = pkt[UDP]
        raw = pkt.getlayer(Raw)
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)

        # Keepalive handling
        if raw and bytes(raw.load) == b"\xff":
            self.log.log_message(f"[ESP] 🔸 NAT-T keepalive from {self._src(ip)}:{udp.sport} -> {self._dst(ip)}:{udp.dport} on {inbound_iface.split('_')[-1]}")
            # Drop (do not forward) or forward based on preference; here we forward to keep NAT bindings alive.
            # fallthrough to forward

        # Parse SPI (if Non-ESP Marker present)
        spi = None
        if raw and len(raw.load) >= 12:
            data = bytes(raw.load)
            if data[:4] == b"\x00\x00\x00\x00":  # Non-ESP marker
                spi = int.from_bytes(data[4:8], "big", signed=False)
                seq = int.from_bytes(data[8:12], "big", signed=False)
                self._note_seq(self._peer(ip, outbound=(self._is_lan_src(pkt, inbound_iface, router_ifaces))), spi, seq,
                               dir_out=self._is_lan_src(pkt, inbound_iface, router_ifaces))

        # Choose routing direction
        is_from_lan = self._is_lan_src(pkt, inbound_iface, router_ifaces)
        if is_from_lan:
            # Outbound (LAN -> remote)
            key = ("NATT", self._dst(ip), udp.dport, self._src(ip), udp.sport)
            with self._lock:
                self._natt_out_map[key] = {
                    "lan_iface": inbound_iface,
                    "lan_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
                    "lan_ip": self._src(ip),
                    "ts": time.time()
                }
            # Forward out according to route to remote IP
            return self._forward(pkt, outbound_to=self._dst(ip), router_ifaces=router_ifaces,
                                 get_mac_function=get_mac_function, find_route_function=find_route_function,
                                 inbound_iface=inbound_iface, note="[ESP] ➡️ NAT-T")
        else:
            # Inbound (remote -> LAN). Find matching mapping by reversing tuple.
            key = ("NATT", self._src(ip), udp.sport, self._dst(ip), udp.dport)
            with self._lock:
                entry = self._natt_out_map.get(key)

            if not entry:
                # Unknown flow; if allow-list enabled, drop unless peer allowed.
                if not self._peer_is_allowed(self._src(ip)):
                    self.log.log_message(f"[ESP] 🚫 NAT-T inbound from disallowed peer {self._src(ip)}")
                    return False
                # Otherwise just route via normal path (let IP routing decide)
                return self._forward(pkt, outbound_to=self._src(ip), router_ifaces=router_ifaces,
                                     get_mac_function=get_mac_function, find_route_function=find_route_function,
                                     inbound_iface=inbound_iface, note="[ESP] ↔ NAT-T (stateless)")
            # Deliver back to the learned LAN iface/MAC
            return self._deliver_to_lan(pkt, entry, router_ifaces, note="[ESP] ⬅️ NAT-T")

    # -------------------------
    # Native ESP handling
    # -------------------------
    def _handle_native_esp(self, pkt, inbound_iface: str, router_ifaces: dict,
                           get_mac_function, find_route_function) -> bool:
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        # Extract SPI: first 4 bytes of ESP header are right after IP header.
        spi = self._extract_spi_native_esp(pkt)
        if spi is None:
            self.log.log_message(f"[ESP] ❓ Could not parse SPI for {self._src(ip)} -> {self._dst(ip)} on {inbound_iface.split('_')[-1]}")
            # Still forward statelessly
            return self._forward(pkt, outbound_to=self._dst(ip), router_ifaces=router_ifaces,
                                 get_mac_function=get_mac_function, find_route_function=find_route_function,
                                 inbound_iface=inbound_iface, note="[ESP] ↔ ESP (no SPI)")

        is_from_lan = self._is_lan_src(pkt, inbound_iface, router_ifaces)
        if is_from_lan:
            # Learn mapping so replies (same SPI, reversed direction) make it back.
            key = ("ESP", self._dst(ip), spi)
            with self._lock:
                self._esp_out_map[key] = {
                    "lan_iface": inbound_iface,
                    "lan_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
                    "lan_ip": self._src(ip),
                    "ts": time.time()
                }
            return self._forward(pkt, outbound_to=self._dst(ip), router_ifaces=router_ifaces,
                                 get_mac_function=get_mac_function, find_route_function=find_route_function,
                                 inbound_iface=inbound_iface, note=f"[ESP] ➡️ ESP spi=0x{spi:08x}")
        else:
            # Remote -> LAN. Look up mapping by (remote_ip_as_dst_in_outbound, spi)
            key = ("ESP", self._src(ip), spi)
            with self._lock:
                entry = self._esp_out_map.get(key)

            if not entry:
                if not self._peer_is_allowed(self._src(ip)):
                    self.log.log_message(f"[ESP] 🚫 ESP inbound from disallowed peer {self._src(ip)} spi=0x{spi:08x}")
                    return False
                # Stateless forward (normal routing) if no mapping
                return self._forward(pkt, outbound_to=self._src(ip), router_ifaces=router_ifaces,
                                     get_mac_function=get_mac_function, find_route_function=find_route_function,
                                     inbound_iface=inbound_iface, note=f"[ESP] ↔ ESP spi=0x{spi:08x} (stateless)")
            # Deliver back to learned LAN iface/MAC
            return self._deliver_to_lan(pkt, entry, router_ifaces, note=f"[ESP] ⬅️ ESP spi=0x{spi:08x}")

    # -------------------------
    # Forwarding helpers
    # -------------------------
    def _forward(self, pkt, outbound_to: str, router_ifaces: dict,
                 get_mac_function, find_route_function, inbound_iface: str, note: str) -> bool:
        """
        Route-based forwarding: set Ether src to egress iface MAC and dst via ARP/ND.
        IP headers remain unchanged (we are routing, not proxying).
        """
        route = find_route_function(outbound_to)
        if not route or not route.get("interface"):
            self.log.log_message(f"{note} ❌ No route to {outbound_to}")
            return False

        egress = route["interface"]
        cfg = router_ifaces.get(egress)
        if not cfg:
            self.log.log_message(f"{note} ❌ Missing iface config for {egress}")
            return False

        fwd = pkt.copy()
        # L2 rewrite
        if fwd.haslayer(Ether):
            fwd[Ether].src = cfg["mac"]
            nh = route.get("next_hop") or outbound_to
            mac = get_mac_function(nh, egress)
            if not mac:
                self.log.log_message(f"{note} ❌ Unknown MAC for next-hop {nh} (iface {egress.split('_')[-1]})")
                return True  # ARP resolution will be triggered elsewhere; we consumed the packet.
            fwd[Ether].dst = mac

        # (We do NOT change IP src/dst; checksums not touched)
        self.log.log_message(f"{note} {self._five_tuple_str(fwd)} via {egress.split('_')[-1]}")
        self.pw.queue_packet(fwd, egress)
        return True

    def _deliver_to_lan(self, pkt, entry: dict, router_ifaces: dict, note: str) -> bool:
        lan_if = entry.get("lan_iface")
        lan_mac = entry.get("lan_mac")
        cfg = router_ifaces.get(lan_if)
        if not cfg:
            self.log.log_message(f"{note} ❌ Original LAN iface missing")
            return False

        out = pkt.copy()
        if out.haslayer(Ether):
            out[Ether].src = cfg["mac"]
            if lan_mac:
                out[Ether].dst = lan_mac
        # (Keep IP headers unchanged)
        self.log.log_message(f"{note} {self._five_tuple_str(out)} via {lan_if.split('_')[-1]}")
        self.pw.queue_packet(out, lan_if)
        return True

    # -------------------------
    # Utilities
    # -------------------------
    @staticmethod
    def _src(ip_layer) -> str:
        return getattr(ip_layer, "src", "")

    @staticmethod
    def _dst(ip_layer) -> str:
        return getattr(ip_layer, "dst", "")

    @staticmethod
    def _is_v6(ip_layer) -> bool:
        from scapy.layers.inet6 import IPv6 as _IPv6  # local import to avoid top-level hard dep
        return isinstance(ip_layer, _IPv6)

    @staticmethod
    def _is_lan_src(pkt, inbound_iface: str, router_ifaces: dict) -> bool:
        """
        Heuristic: packets arriving on a non-WAN iface are considered LAN-origin.
        If you already tag ifaces (e.g., router_ifaces[name]['role'] == 'lan'), use that.
        """
        cfg = router_ifaces.get(inbound_iface, {})
        role = cfg.get("role")
        if role == "lan":
            return True
        if role == "wan":
            return False
        # Fallback: treat non-WAN as LAN.
        return True

    @staticmethod
    def _peer(ip_layer, outbound: bool) -> str:
        """Return the 'remote' peer IP for replay keying."""
        return getattr(ip_layer, "dst" if outbound else "src", "")

    @staticmethod
    def _extract_spi_native_esp(pkt) -> int | None:
        """
        Extracts SPI from native ESP packet (no UDP).
        SPI is the first 32-bit word after the IP header.
        """
        # Use raw bytes to avoid needing scapy's ESP layer.
        try:
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            raw = bytes(bytes(pkt[IP]) if ip and isinstance(ip, IP) else bytes(pkt[IPv6]))  # serialize the IP packet
            # Compute IP header length
            if isinstance(ip, IP):
                ihl = (ip.ihl or 5) * 4
                if len(raw) < ihl + 4:
                    return None
                return int.from_bytes(raw[ihl:ihl + 4], "big", signed=False)
            else:
                # IPv6 header is fixed 40 bytes; next header should be ESP (already verified)
                offset = 40
                if len(raw) < offset + 4:
                    return None
                return int.from_bytes(raw[offset:offset + 4], "big", signed=False)
        except Exception:
            return None

    def _five_tuple_str(self, pkt) -> str:
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if pkt.haslayer(UDP):
            u = pkt[UDP]
            return f"{self._src(ip)}:{u.sport} -> {self._dst(ip)}:{u.dport}"
        return f"{self._src(ip)} -> {self._dst(ip)} proto={'50/ESP' if self._is_esp(pkt) else 'udp/4500' if self._is_natt(pkt) else 'ip'}"

    def _peer_is_allowed(self, peer_ip: str) -> bool:
        with self._lock:
            if not self._peer_allowlist:
                return True
            try:
                pip = ipaddress.ip_address(peer_ip)
            except Exception:
                return False
            for item in self._peer_allowlist:
                try:
                    if "/" in item:
                        if pip in ipaddress.ip_network(item, strict=False):
                            return True
                    else:
                        if pip == ipaddress.ip_address(item):
                            return True
                except Exception:
                    continue
            return False

    def _note_seq(self, peer: str, spi: int, seq: int, dir_out: bool):
        """
        Minimal anti-replay note (does NOT enforce drops—add policy if desired).
        """
        k = (peer, spi, "out" if dir_out else "in")
        with self._lock:
            rec = self._replay[k]
            win = rec["win"]
            # keep only a small window of seen seqs
            if len(rec["seen"]) > 2 * win:
                # prune oldest-ish: for set, rebuild a tighter set around last
                if isinstance(rec["seen"], set):
                    last = rec["last"]
                    rec["seen"] = {s for s in rec["seen"] if last - win <= s <= last}
            rec["seen"].add(int(seq))
            if seq > rec["last"]:
                rec["last"] = int(seq)

    def _cleanup(self, now: float):
        with self._lock:
            # Expire old mappings
            for table_name, table in (("ESP", self._esp_out_map), ("NAT-T", self._natt_out_map)):
                expired = []
                for k, v in table.items():
                    if now - v.get("ts", 0) > self.MAP_TTL:
                        expired.append(k)
                for k in expired:
                    table.pop(k, None)
                if expired:
                    self.log.log_message(f"[ESP] 🧹 Cleanup: removed {len(expired)} {table_name} mappings")
            self._last_cleanup = now

class TransportManager:
    """
    Manages the processing and logging of Transport Layer packets (TCP, UDP, etc.).
    This version supports a wide variety of protocols including DNS, DHCP, NTP, TFTP,
    VoIP (SIP/RTP), QUIC, ZeroTier/SSDP, and dynamic ports.

    TLS dissection is performed passively by TLSRecordManager using TCP Raw bytes.
    """

    def __init__(self, router_logger, packet_signer):
        """
        Initializes the TransportManager with a logger and a packet signer.
        """
        self.logger = router_logger
        self.packet_signer = packet_signer
        self.logger.log_message("[Transport] Manager initialized.")
        self.voip_port_range = range(10000, 20001)
        self.logged_quic_streams = {}
        self.QUIC_STREAM_TIMEOUT = 300
        self.last_quic_cleanup_time = time.time()

        # TLS record manager + callbacks
        self.tls_manager = TLSRecordManager(self.logger)
        self._wire_tls_callbacks()

        # Minimal initiator tracker to set c2s/s2c directions reliably
        # key -> (client_ip, client_port)
        self._initiators: Dict[Tuple[Tuple[str,int],Tuple[str,int]], Tuple[str,int]] = {}

        # Alert/Description maps for prettier logs (optional)
        self.TLS_ALERT_LEVEL = {1: "warning", 2: "fatal"}
        self.TLS_ALERT_DESCRIPTION = {
            0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
            22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
            43: "unsupported_certificate", 46: "certificate_unknown", 47: "illegal_parameter",
            48: "unknown_ca", 49: "access_denied", 50: "decode_error",
            51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
            80: "internal_error", 90: "user_canceled", 112: "unrecognized_name"
        }
    def _on_tls_policy_decision(self, key, rec, decision):
        """
        Called on EVERY TLS record after the policy engine evaluates it.
        key: canonical 4-tuple ((src_ip,src_port),(dst_ip,dst_port))
        rec: TLSRecord (content_type/version/length/src/dst/ports/direction)
        decision: TLSPolicyDecision(action, reason, tags)
        """
        flow = f"{rec.src}:{rec.src_port} -> {rec.dst}:{rec.dst_port} [{rec.direction}]"
        if decision.action == "allow":
            self.logger.log_message(
                f"[Transport][🔐 TLS][policy] ✅ allow | {flow}"
            )
            return

        tag_str = ",".join(decision.tags) if decision.tags else "-"
        if decision.action == "alert":
            self.logger.log_message(
                f"[Transport][🔐 TLS][policy] ⚠️ alert | {flow} | reason={decision.reason} | tags={tag_str}"
            )
            return

        # block / quarantine -> log + enforce hook
        self.logger.log_message(
            f"[Transport][🔐 TLS][policy] ⛔ {decision.action} | {flow} | reason={decision.reason} | tags={tag_str}"
        )
        try:
            self._enforce_tls_decision(key, rec, decision)
        except Exception as e:
            self.logger.log_message(f"[Transport][🔐 TLS][policy] enforcement error: {e}")

    def _on_tls_event(self, evt: dict):
        """
        High-level event feed from TLSRecordManager (client_hello/server_hello/alert/block/quarantine/policy_alert).
        Use this to emit metrics or forward to your UI.
        """
        kind = evt.get("kind")
        data = evt.get("data", {})
        flow = evt.get("flow")
        # Keep it concise; expand if you want richer telemetry
        if kind in ("client_hello", "server_hello"):
            brief = []
            if "sni" in data and data["sni"]:
                brief.append(f"SNI={data['sni']}")
            if "ja3" in data and data["ja3"]:
                brief.append("ja3")
            if "ja3s" in data and data["ja3s"]:
                brief.append("ja3s")
            self.logger.log_message(f"[Transport][🔐 TLS][event] {kind} | {flow} | {' '.join(brief) or '-'}")
        elif kind in ("alert", "policy_alert", "block", "quarantine"):
            self.logger.log_message(f"[Transport][🔐 TLS][event] {kind} | {flow} | {data}")
        else:
            # Uncomment if you want every event
            # self.logger.log_message(f"[Transport][🔐 TLS][event] {kind} | {flow} | {data}")
            pass

    def _enforce_tls_decision(self, key, rec, decision):
        """
        Central place to ACT on a block/quarantine decision.
        Replace the placeholders with your real enforcement (firewall, ACL, RST, etc.)
        """
        # Example: mark in your signer/tagger, raise a notification, or update a banlist.
        # self.packet_signer.tag_flow(key, decision.tags)
        # self.notification_manager.warn(...)

        # If you want to immediately terminate TCP:
        #   - you can queue forged TCP RSTs to both directions (requires your packet writer)
        #   - or set a table your firewall consults to drop subsequent segments

        action = decision.action
        reason = decision.reason

        # Example pseudo-enforcement toggles:
        DROP_FUTURE_APPDATA = True
        SEND_TCP_RST        = False

        if DROP_FUTURE_APPDATA:
            # TLSRecordManager already suppresses on_application_data callbacks
            # once a session is marked blocked/quarantined. Nothing else needed here.
            pass

        if SEND_TCP_RST:
            try:
                sip, sport = rec.src, rec.src_port
                dip, dport = rec.dst, rec.dst_port
                # enqueue two RSTs (c2s and s2c) via your packet writer here...
                # self.packet_writer.send_tcp_rst(sip, sport, dip, dport)
                # self.packet_writer.send_tcp_rst(dip, dport, sip, sport)
                self.logger.log_message(
                    f"[Transport][🔐 TLS][policy] injected TCP RSTs for {sip}:{sport} <-> {dip}:{dport}"
                )
            except Exception as e:
                self.logger.log_message(f"[Transport][🔐 TLS][policy] RST injection failed: {e}")
    # --------------------- TLS callback wiring ------------------------
    def _wire_tls_callbacks(self):
        def fmt_flow(rec: TLSRecord):
            return f"{rec.src}:{rec.src_port} -> {rec.dst}:{rec.dst_port} [{rec.direction}]"

        # Every TLS record parsed
        self.tls_manager.on_record = lambda rec: self.logger.log_message(
            f"[Transport][🔐 TLS] Record ct={rec.content_type} v={rec.version[0]}.{rec.version[1]} "
            f"len={rec.length} on {fmt_flow(rec)}"
        )

        # Handshake messages summary (ClientHello/ServerHello best-effort)
        def on_hs(rec: TLSRecord, info: Dict):
            for m in info.get("messages", []):
                t = m.get("type") or f"type={m.get('type_id')}"
                if m.get("hello") == "client":
                    v = m.get("version")
                    sni = m.get("sni") or "N/A"
                    suites = m.get("cipher_suites_count")
                    self.logger.log_message(
                        f"[Transport][🔐 TLS] ClientHello v={v} SNI={sni} suites≈{suites} on {fmt_flow(rec)}"
                    )
                elif m.get("hello") == "server":
                    v = m.get("version")
                    cs = m.get("cipher_suite")
                    self.logger.log_message(
                        f"[Transport][🔐 TLS] ServerHello v={v} cipher={cs} on {fmt_flow(rec)}"
                    )
                else:
                    self.logger.log_message(f"[Transport][🔐 TLS] Handshake {t} on {fmt_flow(rec)}")

        self.tls_manager.on_handshake = on_hs

        # Application Data (encrypted)
        self.tls_manager.on_application_data = lambda rec: self.logger.log_message(
            f"[Transport][🔐 TLS] Application Data {rec.length}B on {fmt_flow(rec)}"
        )

        # Alerts
        def on_alert(rec: TLSRecord, alert: Dict):
            lvl = self.TLS_ALERT_LEVEL.get(alert.get("level"), str(alert.get("level")))
            desc = self.TLS_ALERT_DESCRIPTION.get(alert.get("description"), str(alert.get("description")))
            self.logger.log_message(
                f"[Transport][🔐 TLS] Alert on {fmt_flow(rec)}: level={lvl} desc={desc}"
            )

        self.tls_manager.on_alert = on_alert

        # ChangeCipherSpec
        self.tls_manager.on_change_cipher_spec = lambda rec: self.logger.log_message(
            f"[Transport][🔐 TLS] ChangeCipherSpec on {fmt_flow(rec)}"
        )

        # Legacy SSL-ish
        self.tls_manager.on_legacy_ssl = lambda rec: self.logger.log_message(
            f"[Transport][🔐 TLS] Legacy/SSLv2-like record len={rec.length} on {fmt_flow(rec)}"
        )

        # 🔧 NEW: policy decisions + event feed
        self.tls_manager.on_decision = self._on_tls_policy_decision
        self.tls_manager.on_event = self._on_tls_event

    # --------------------- Main packet handler ------------------------
    def handle_packet(self, packet: Packet, inbound_iface: str) -> bool:
        """
        Processes and logs Transport Layer packet details, with enhanced UDP protocol
        dissection for DNS, DHCP, NTP, TFTP, VoIP, QUIC, ZeroTier/SSDP, and dynamic ports.
        Also feeds TCP payloads into TLSRecordManager for passive TLS parsing.
        """
        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6] if packet.haslayer(IPv6) else None

        if not ip_layer:
            return False

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        processed = False

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
                f"[Transport][🧵 TCP] Packet on {iface_short}: {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport} | "
                f"Flags: {','.join(flag_details)} | Payload: {payload_len}"
            )

            # Track initiator when we see initial SYN (no ACK)
            if "S" in flags and "A" not in flags:
                key = _canon_key(src_ip, tcp.sport, dst_ip, tcp.dport)
                self._initiators[key] = (src_ip, tcp.sport)

            # Feed TLS bytes (if present) to TLSRecordManager
            if packet.haslayer(Raw) and len(packet[Raw].load) > 0:
                raw_bytes = bytes(packet[Raw].load)
                key = _canon_key(src_ip, tcp.sport, dst_ip, tcp.dport)
                client_tuple = self._initiators.get(key)

                # Decide direction: c2s if (src_ip,src_port) == client_tuple
                if client_tuple:
                    is_c2s = (src_ip, tcp.sport) == client_tuple
                else:
                    # Fallback heuristic if we never saw the SYN
                    is_c2s = (tcp.sport <= tcp.dport)

                self.tls_manager.feed_tcp_segment(
                    canonical_key=key,
                    is_c2s=is_c2s,
                    payload=raw_bytes,
                    src_ip=src_ip, src_port=tcp.sport,
                    dst_ip=dst_ip, dst_port=tcp.dport,
                    ts=time.time()
                )

            # Example hook: Detect SYN scan
            if "SYN" in flag_details and payload_len == 0:
                self.logger.log_message(
                    f"[Transport][🧵 TCP][⚠️ SCAN] SYN scan suspected from {src_ip} → {dst_ip}:{tcp.dport}"
                )

            # Check for dynamic port 56709
            if tcp.sport == 56709 or tcp.dport == 56709:
                self.logger.log_message(
                    f"[Transport][🧵 TCP][❔ Dynamic Port] TCP Port 56709 detected from {src_ip}:{tcp.sport} to {dst_ip}:{tcp.dport}."
                )

            processed = True

        # --- UDP ---
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            payload_len = len(udp.payload)

            self.logger.log_message(
                f"[Transport][🚀 UDP] Packet on {iface_short}: {src_ip}:{udp.sport} → {dst_ip}:{udp.dport} | "
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
                    f"[Transport][🚀 UDP][❔ Ephemeral Port] UDP Port 51163 detected from {src_ip}:{udp.sport} to {dst_ip}:{udp.dport}. "
                    "This is an ephemeral port, often used by client applications."
                )
            elif udp.dport == 54742 or udp.sport == 54742:
                self.logger.log_message(
                    f"[Transport][🚀 UDP][❔ Ephemeral Port] UDP Port 54742 detected from {src_ip}:{udp.sport} to {dst_ip}:{udp.dport}."
                )
            else:
                self.logger.log_message(
                    f"[Transport][🚀 UDP][❔ Undecoded] Unknown UDP protocol on ports {udp.sport} → {udp.dport}. "
                    f"Payload size: {payload_len}"
                )

            processed = True

        return processed

    # ---------------------- UDP protocol handlers ---------------------
    def _bytes_to_str(self, data: bytes) -> str:
        """Safely decodes bytes to a string, ignoring any decoding errors."""
        return data.decode('utf-8', errors='ignore')

    def _handle_dns_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for DNS packets."""
        dns = packet[DNS]
        query_name = "N/A"
        if dns.qr == 0 and dns.qd:
            query_name = self._bytes_to_str(dns.qd.qname)
            self.logger.log_message(
                f"[Transport][🚀 UDP][🔍 DNS] Query from {src_ip}:{sport} for domain '{query_name}'"
            )
        elif dns.qr == 1 and dns.an:
            query_name = self._bytes_to_str(dns.qd.qname) if dns.qd else "N/A"
            answers = dns.ancount
            self.logger.log_message(
                f"[Transport][🚀 UDP][🔍 DNS] Response to {dst_ip}:{dport} for '{query_name}' with {answers} answers."
            )
        else:
            self.logger.log_message(
                f"[Transport][🚀 UDP][🔍 DNS] Malformed or unrecognized DNS packet from {src_ip}:{sport}"
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
                f"[Transport][🚀 UDP][⚙️ DHCP] {dhcp_message_type} packet from {src_ip}:{sport} to {dst_ip}:{dport} "
                f"Client MAC: {bootp.chaddr.hex()}"
            )
        else:
            self.logger.log_message(
                f"[Transport][🚀 UDP][⚙️ DHCP] DHCP-related UDP packet from {src_ip}:{sport}, no BOOTP layer found."
            )

    def _handle_quic_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for QUIC packets."""
        if packet.haslayer(Raw):
            raw_data = bytes(packet[Raw].load)
            dcid_len = 0
            scid_len = 0
            is_long_header = False

            if len(raw_data) >= 1:
                first_byte = raw_data[0]
                is_long_header = (first_byte & 0x80) == 0x80

                if is_long_header and len(raw_data) >= 6:
                    packet_type = (first_byte & 0x30) >> 4
                    version_bytes = raw_data[1:5]
                    version_hex = version_bytes.hex()
                    dcid_len = raw_data[5]
                    if len(raw_data) > 6 + dcid_len:
                        scid_len = raw_data[6 + dcid_len]
                    try:
                        dcid = raw_data[6:6 + dcid_len].hex()
                        scid = raw_data[7 + dcid_len:7 + dcid_len + scid_len].hex()
                        packet_type_str = {
                            0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"
                        }.get(packet_type, "Unknown")
                        self.logger.log_message(
                            f"[Transport][🚀 UDP][🌐 QUIC] Long Header ({packet_type_str}) from {src_ip}:{sport} | "
                            f"Version: 0x{version_hex} | DCID: {dcid} | SCID: {scid}"
                        )
                    except IndexError:
                        self.logger.log_message(
                            f"[Transport][🚀 UDP][🌐 QUIC] Malformed Long Header from {src_ip}:{sport}"
                        )
                elif not is_long_header:
                    dcid_len = 8
                    dcid = raw_data[1:1 + dcid_len].hex() if len(raw_data) > 1 + dcid_len else "?"
                    spin_bit = (first_byte & 0x20) >> 5
                    key_phase_bit = (first_byte & 0x04) >> 2
                    key_phase_str = "Updated Keys" if key_phase_bit else "Initial Keys"
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][🌐 QUIC] Short Header from {src_ip}:{sport} | "
                        f"DCID: {dcid} | Spin Bit: {spin_bit} | Key Phase: {key_phase_str}"
                    )
                if is_long_header:
                    header_len = 7 + dcid_len + scid_len
                else:
                    header_len = 1 + dcid_len
                if len(raw_data) > header_len:
                    self._inspect_quic_frames(raw_data[header_len:], src_ip, dst_ip, dport)
        else:
            self.logger.log_message(
                f"[Transport][🚀 UDP][🌐 QUIC] UDP on port 443 detected, but no Raw payload."
            )

    def _inspect_quic_frames(self, data: bytes, src_ip: str, dst_ip: str, dport: int):
        """
        Parses and logs details of QUIC frames within a packet payload. This version
        prevents spam by only logging new STREAM frames and using a time-based
        cache to expire old stream entries.
        """
        i = 0
        while i < len(data):
            try:
                first_byte = data[i]
                if 0x08 <= first_byte <= 0x0f:
                    has_len_bit = (first_byte & 0x02)
                    has_off_bit = (first_byte & 0x04)
                    offset = 1
                    stream_id, bytes_read = self._parse_quic_varint(data[i + offset:])
                    if bytes_read == 0: break
                    stream_key = (src_ip, dst_ip, stream_id)
                    current_time = time.time()
                    if stream_key not in self.logged_quic_streams:
                        log_msg = f"[Transport][🌐 QUIC][Frame] STREAM | New Stream ID: {stream_id}"
                        self.logger.log_message(log_msg)
                        if current_time - self.last_quic_cleanup_time > 60:
                            expired_keys = [
                                key for key, timestamp in self.logged_quic_streams.items()
                                if current_time - timestamp > self.QUIC_STREAM_TIMEOUT
                            ]
                            if expired_keys:
                                self.logger.log_message(
                                    f"[Transport] Pruning {len(expired_keys)} expired QUIC stream entries from cache."
                                )
                                for key in expired_keys:
                                    self.logged_quic_streams.pop(key, None)
                            self.last_quic_cleanup_time = current_time
                    self.logged_quic_streams[stream_key] = current_time
                    offset += bytes_read
                    data_len = 0
                    if has_off_bit:
                        _, bytes_read = self._parse_quic_varint(data[i + offset:])
                        offset += bytes_read
                    if has_len_bit:
                        data_len, bytes_read = self._parse_quic_varint(data[i + offset:])
                        offset += bytes_read
                    else:
                        data_len = len(data) - (i + offset)
                    i += offset + data_len
                    continue
                frame_type = first_byte
                if frame_type == 0x24:
                    self.logger.log_message(f"[Transport][🌐 QUIC][Frame] RESET_STREAM_AT")
                    i = len(data)
                elif frame_type == 0x14:
                    self.logger.log_message(f"[Transport][🌐 QUIC][Frame] STREAMS_BLOCKED")
                    i = len(data)
                elif frame_type == 0xa4:
                    self.logger.log_message(f"[Transport][🌐 QUIC][Frame] ACK_FREQUENCY")
                    i = len(data)
                elif frame_type == 0x02 or frame_type == 0x03:
                    self.logger.log_message(f"[Transport][🌐 QUIC][Frame] ACK")
                    i = len(data)
                elif frame_type == 0x06:
                    offset, length = struct.unpack("!II", data[i + 1:i + 9])
                    self.logger.log_message(f"[Transport][🌐 QUIC][Frame] CRYPTO | Offset: {offset} | Length: {length}")
                    i += 9 + length
                elif frame_type == 0x00:
                    i += 1
                elif frame_type == 0x01:
                    self.logger.log_message(f"[Transport][🌐 QUIC][Frame] PING")
                    i += 1
                elif frame_type == 0x1C or frame_type == 0x1D:
                    self.logger.log_message(f"[Transport][🌐 QUIC][Frame] CONNECTION_CLOSE")
                    i = len(data)
                else:
                    self.logger.log_message(f"[Transport][🌐 QUIC][Frame] Unknown frame type: 0x{first_byte:02x}")
                    break
            except (struct.error, IndexError):
                self.logger.log_message("[Transport][🌐 QUIC][Frame] Malformed frame or end of packet reached.")
                break

    def _parse_quic_varint(self, data: bytes) -> tuple[int, int]:
        """
        Parses a QUIC variable-length integer from the beginning of a byte string.
        Returns (value, bytes_consumed), or (0,0) on failure.
        """
        if not data:
            return 0, 0
        first_byte = data[0]
        length_bits = first_byte >> 6
        try:
            if length_bits == 0b00:
                return first_byte & 0x3F, 1
            elif length_bits == 0b01:
                if len(data) < 2: return 0, 0
                val = struct.unpack("!H", data[:2])[0]
                return val & 0x3FFF, 2
            elif length_bits == 0b10:
                if len(data) < 4: return 0, 0
                val = struct.unpack("!I", data[:4])[0]
                return val & 0x3FFFFFFF, 4
            elif length_bits == 0b11:
                if len(data) < 8: return 0, 0
                val = struct.unpack("!Q", data[:8])[0]
                return val & 0x3FFFFFFFFFFFFFFF, 8
        except (struct.error, IndexError):
            return 0, 0
        return 0, 0

    def _handle_ntp_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for NTP packets."""
        raw_data = bytes(packet[Raw].load)
        if len(raw_data) >= 48:
            try:
                first_byte = raw_data[0]
                li = (first_byte >> 6) & 0x03
                vn = (first_byte >> 3) & 0x07
                mode = first_byte & 0x07
                stratum = raw_data[1]
                mode_str = {1: "Symmetric Active", 2: "Symmetric Passive", 3: "Client",
                            4: "Server", 5: "Broadcast"}.get(mode, "Unknown")
                self.logger.log_message(
                    f"[Transport][🚀 UDP][🕰️ NTP] NTP packet from {src_ip}:{sport} | "
                    f"Mode: {mode_str} | Version: {vn} | Stratum: {stratum}"
                )
            except IndexError:
                self.logger.log_message(
                    f"[Transport][🚀 UDP][🕰️ NTP] Malformed NTP packet from {src_ip}:{sport}"
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
                            f"[Transport][🚀 UDP][📄 TFTP] {opcode_str} from {src_ip}:{sport} to {dst_ip}:{dport} | "
                            f"Block #: {block_number}"
                        )
                    else:
                        self.logger.log_message(
                            f"[Transport][🚀 UDP][📄 TFTP] Malformed {opcode_str} packet from {src_ip}:{sport}"
                        )
                else:
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][📄 TFTP] {opcode_str} from {src_ip}:{sport} to {dst_ip}:{dport}"
                    )
            except (struct.error, IndexError):
                self.logger.log_message(
                    f"[Transport][🚀 UDP][📄 TFTP] Malformed TFTP packet from {src_ip}:{sport}"
                )

    def _handle_sip_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for SIP packets."""
        if packet.haslayer(Raw):
            raw_data = bytes(packet[Raw].load)
            try:
                if raw_data.startswith(b"INVITE") or raw_data.startswith(b"REGISTER") or raw_data.startswith(b"BYE"):
                    first_line = raw_data.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][📞 SIP] Request from {src_ip}:{sport} to {dst_ip}:{dport} | "
                        f"Method: {first_line.split(' ')[0]}"
                    )
                elif raw_data.startswith(b"SIP/2.0"):
                    status_line = raw_data.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][📞 SIP] Response from {src_ip}:{sport} to {dst_ip}:{dport} | "
                        f"Status: {status_line.split(' ', 1)[1]}"
                    )
            except (UnicodeDecodeError, IndexError):
                self.logger.log_message(
                    f"[Transport][🚀 UDP][📞 SIP] Malformed or undecodable SIP packet from {src_ip}:{sport}"
                )

    def _handle_rtp_packet(self, packet, src_ip, dst_ip, sport, dport):
        """
        Handles and logs details for RTP packets with full header parsing.
        This enhanced version decodes the SSRC, sequence number, and marker bit.
        """
        if packet.haslayer(Raw) and len(packet[Raw].load) >= 12:
            raw_data = bytes(packet[Raw].load)
            RTP_PAYLOAD_TYPES = {
                0: "PCMU", 3: "GSM", 4: "G723", 8: "PCMA", 9: "G722",
                10: "L16/2ch", 11: "L16/1ch", 15: "G728", 18: "G729",
                26: "JPEG", 31: "H261", 32: "MPV", 33: "MP2T", 34: "H263",
                96: "H264", 97: "H264", 98: "H265/HEVC", 100: "VP8", 101: "VP9", 103: "Opus"
            }
            try:
                byte1, byte2, seq_num, timestamp, ssrc = struct.unpack('!BBHII', raw_data[:12])
                version = (byte1 >> 6) & 0x03
                marker = (byte2 >> 7) & 0x01
                payload_type = byte2 & 0x7F
                if version == 2:
                    payload_type_str = RTP_PAYLOAD_TYPES.get(payload_type, f"Dynamic({payload_type})")
                    log_details = (
                        f"Ver: {version}, PT: {payload_type_str}, "
                        f"Seq: {seq_num}, SSRC: 0x{ssrc:08x}"
                    )
                    if marker:
                        log_details += " [Marker]"
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][🔊 RTP] Media Stream from {src_ip}:{sport} to {dst_ip}:{dport} | {log_details}"
                    )
                else:
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][🔊 RTP] Non-RTP packet on VoIP port, or unknown version {version}"
                    )
            except (struct.error, IndexError):
                self.logger.log_message(
                    f"[Transport][🚀 UDP][🔊 RTP] Malformed RTP packet from {src_ip}:{sport}"
                )

    def _handle_zerotier_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for ZeroTier-like packets on UDP port 9993."""
        self.logger.log_message(
            f"[Transport][🚀 UDP][🛰️ ZeroTier] UDP port 9993 traffic detected from {src_ip}:{sport} to {dst_ip}:{dport}. "
            "Likely ZeroTier, Cisco ACS, or other application."
        )

    def _handle_ssdp_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for SSDP/UPnP packets on UDP port 1900."""
        self.logger.log_message(
            f"[Transport][🚀 UDP][🔌 SSDP] SSDP/UPnP packet detected from {src_ip}:{sport} to {dst_ip}:{dport}. "
            "Likely for device discovery."
        )

    def _handle_ws_discovery_packet(self, packet, src_ip, dst_ip, sport, dport):
        """Handles and logs details for WS-Discovery packets on UDP port 3702."""
        self.logger.log_message(
            f"[Transport][🚀 UDP][🔍 WS-Discovery] WS-Discovery packet detected from {src_ip}:{sport} to {dst_ip}:{dport}. "
            "Likely for dynamic device discovery."
        )

class HTTPSManager:
    """
    Passive HTTPS/TLS + TCP monitor that **does not** rely on Scapy's TLS layers.
    Instead, it feeds TCP payload bytes into TLSRecordManager, which performs
    stream-aware reassembly and best-effort TLS record/handshake parsing (e.g., SNI).
    """

    # Pretty names for TLS content types
    _CT_NAMES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}

    # Common TLS server ports (used as a light prefilter; parsing still works on any port)
    _TLS_LIKE_PORTS = {443, 8443, 9443, 10443, 444, 8444}

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.cipher_map = self._build_cipher_suite_map()
        self.router_logger.log_message("[HTTPS] 🔒 Initialized for passive TLS/TCP monitoring.")
        self.router_logger.log_message(f"[HTTPS] 🗺️  Cipher map has {len(self.cipher_map)} entries.")

        # For nicer alert logs
        self.TLS_ALERT_LEVEL = {1: "warning", 2: "fatal"}
        self.TLS_ALERT_DESCRIPTION = {
            0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
            22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
            43: "unsupported_certificate", 46: "certificate_unknown", 47: "illegal_parameter",
            48: "unknown_ca", 49: "access_denied", 50: "decode_error",
            51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
            80: "internal_error", 90: "user_canceled", 112: "unrecognized_name"
        }

        # TCP state tracking (simple)
        self.tcp_state_map: Dict[Tuple[str, int, str, int], str] = {}
        self.TCP_FLAGS = {'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST', 'P': 'PSH', 'U': 'URG'}

        # Track TCP initiators so we can label TLS direction (c2s vs s2c)
        # key = canonical 4-tuple (two endpoint pairs in sorted order) -> (client_ip, client_port)
        self._initiators: Dict[Tuple[Tuple[str, int], Tuple[str, int]], Tuple[str, int]] = {}

        # TLS record parser/manager
        self.tls_manager = TLSRecordManager(self.router_logger)
        self._wire_tls_callbacks()

    # ------------ Public ------------

    def handle_packet(self, packet: Packet, inbound_iface: str) -> bool:
        """
        Handle one packet: log TCP, parse TCP options/state, and feed any TCP payload
        bytes into TLSRecordManager (direction-aware) for passive TLS parsing.
        """
        processed = False

        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return processed

        ip = packet.getlayer(IP) or packet.getlayer(IPv6)

        # ---------- TCP ----------
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            self.router_logger.log_message(self._generate_tcp_summary(packet, inbound_iface))
            self._handle_tcp_options(packet)
            self._handle_tcp_state(packet)

            # Record the initiator on a bare SYN (no ACK)
            flags_txt = tcp.sprintf("%TCP.flags%")
            if "S" in flags_txt and "A" not in flags_txt:
                key = self._canon_key(ip.src, tcp.sport, ip.dst, tcp.dport)
                self._initiators[key] = (ip.src, tcp.sport)

            # Feed possible TLS bytes (Raw) into TLSRecordManager
            if packet.haslayer(Raw) and len(packet[Raw].load) > 0:
                raw = bytes(packet[Raw].load)
                if self._looks_tlsish(raw, tcp.sport, tcp.dport):
                    key = self._canon_key(ip.src, tcp.sport, ip.dst, tcp.dport)
                    client_tuple = self._initiators.get(key)
                    is_c2s = (client_tuple is not None and (ip.src, tcp.sport) == client_tuple)
                    # Fallback heuristic if initiator unknown
                    if client_tuple is None:
                        is_c2s = (tcp.sport <= tcp.dport)

                    self.tls_manager.feed_tcp_segment(
                        canonical_key=key,
                        is_c2s=is_c2s,
                        payload=raw,
                        src_ip=ip.src, src_port=tcp.sport,
                        dst_ip=ip.dst, dst_port=tcp.dport,
                        ts=time.time()
                    )
            processed = True

        return processed

    # ------------ TLS wiring & callbacks ------------

    def _wire_tls_callbacks(self):
        def fmt_flow(rec):
            return f"{rec.src}:{rec.src_port} → {rec.dst}:{rec.dst_port} [{rec.direction}]"

        # Generic TLS record callback
        def on_record(rec):
            ct_name = self._CT_NAMES.get(rec.content_type, f"ct={rec.content_type}")
            self.router_logger.log_message(
                f"[HTTPS][TLS] 📦 {ct_name} v={rec.version[0]}.{rec.version[1]} len={rec.length} on {fmt_flow(rec)}"
            )

        # Handshake messages (best-effort summaries from TLSRecordManager)
        def on_handshake(rec, info):
            for m in info.get("messages", []):
                if m.get("hello") == "client":
                    v = m.get("version") or "?"
                    sni = m.get("sni") or "N/A"
                    suites = m.get("cipher_suites_count")
                    self.router_logger.log_message(
                        f"[HTTPS][TLS] 🤝 ClientHello v={v} SNI={sni} suites≈{suites} on {fmt_flow(rec)}"
                    )
                elif m.get("hello") == "server":
                    v = m.get("version") or "?"
                    cs_id_hex = (m.get("cipher_suite") or "").lower()  # "0xNNNN"
                    cs_name = None
                    try:
                        if cs_id_hex.startswith("0x"):
                            cs_val = int(cs_id_hex, 16)
                            cs_name = self.cipher_map.get(cs_val)
                    except Exception:
                        pass
                    cs_display = f"{cs_name} ({cs_id_hex})" if cs_name else (cs_id_hex or "?")
                    self.router_logger.log_message(
                        f"[HTTPS][TLS] 🤝 ServerHello v={v} cipher={cs_display} on {fmt_flow(rec)}"
                    )
                else:
                    t = m.get("type") or f"type={m.get('type_id')}"
                    self.router_logger.log_message(
                        f"[HTTPS][TLS] 🤝 Handshake: {t} on {fmt_flow(rec)}"
                    )

        def on_app(rec):
            self.router_logger.log_message(
                f"[HTTPS][TLS] 🔒 Application Data {rec.length}B on {fmt_flow(rec)}"
            )

        def on_alert(rec, alert):
            lvl = self.TLS_ALERT_LEVEL.get(alert.get("level"), str(alert.get("level")))
            desc = self.TLS_ALERT_DESCRIPTION.get(alert.get("description"), str(alert.get("description")))
            self.router_logger.log_message(
                f"[HTTPS][TLS] ⚠️ Alert on {fmt_flow(rec)}: level={lvl}, desc={desc}"
            )

        def on_ccs(rec):
            self.router_logger.log_message(
                f"[HTTPS][TLS] 🔁 ChangeCipherSpec on {fmt_flow(rec)}"
            )

        def on_legacy(rec):
            self.router_logger.log_message(
                f"[HTTPS][TLS] 🧓 Legacy/SSLv2-like record len={rec.length} on {fmt_flow(rec)}"
            )

        self.tls_manager.on_record = on_record
        self.tls_manager.on_handshake = on_handshake
        self.tls_manager.on_application_data = on_app
        self.tls_manager.on_alert = on_alert
        self.tls_manager.on_change_cipher_spec = on_ccs
        self.tls_manager.on_legacy_ssl = on_legacy

    # ------------ TCP helpers/logging ------------

    def _generate_tcp_summary(self, packet: Packet, inbound_iface: str) -> str:
        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        tcp = packet.getlayer(TCP)

        if not ip_layer or not tcp:
            return f"[TCP] 🔄 TCP packet on {iface_short} (no IP/TCP layer?)"

        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        flags_str = ",".join([self.TCP_FLAGS.get(f, f) for f in str(tcp.flags)])
        return (f"[TCP] 🔄 {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport} on {iface_short} | "
                f"Flags: {flags_str} | Seq: {tcp.seq} | Ack: {tcp.ack}")

    def _handle_tcp_options(self, packet: Packet):
        tcp = packet.getlayer(TCP)
        if hasattr(tcp, 'options') and tcp.options:
            self.router_logger.log_message(f"[TCP]   - Options ({len(tcp.options)} total):")
            for opt in tcp.options:
                name = opt[0]
                if name == 'WScale':
                    self.router_logger.log_message(f"[TCP]     - Window Scale: {opt[1]} 📈")
                elif name == 'Timestamp':
                    ts_val, ts_ecr = opt[1]
                    self.router_logger.log_message(f"[TCP]     - Timestamps: TSval={ts_val}, TSecr={ts_ecr} ⏰")
                elif name == 'SAckOK':
                    self.router_logger.log_message(f"[TCP]     - SACK Permitted ✅")
                elif name == 'MSS':
                    self.router_logger.log_message(f"[TCP]     - MSS: {opt[1]} 📝")
                elif name == 'NOP':
                    continue
                else:
                    self.router_logger.log_message(f"[TCP]     - Option: {name} ❓")

    def _handle_tcp_state(self, packet: Packet):
        ip = packet.getlayer(IP) or packet.getlayer(IPv6)
        tcp = packet.getlayer(TCP)
        if not ip or not tcp:
            return

        src_ip, src_port = ip.src, tcp.sport
        dst_ip, dst_port = ip.dst, tcp.dport

        # Direction-agnostic key
        conn_key = (src_ip, src_port, dst_ip, dst_port) if src_port < dst_port else (dst_ip, dst_port, src_ip, src_port)
        cur = self.tcp_state_map.get(conn_key, "CLOSED")
        flags = tcp.flags

        if flags == 0x02:  # SYN
            if cur == "CLOSED":
                self.router_logger.log_message(
                    f"[TCP] Handshake Initiated: {src_ip}:{src_port} sent SYN. ➡️ State: SYN-SENT."
                )
                self.tcp_state_map[conn_key] = "SYN-SENT"
        elif flags == 0x12:  # SYN-ACK
            if cur == "SYN-SENT":
                self.router_logger.log_message(
                    f"[TCP] Handshake Progress: {src_ip}:{src_port} replied with SYN-ACK. 🔄 State: SYN-RECEIVED."
                )
                self.tcp_state_map[conn_key] = "SYN-RECEIVED"
        elif flags == 0x10 and cur == "SYN-RECEIVED":  # ACK
            self.router_logger.log_message(
                f"[TCP] Handshake Completed: {src_ip}:{src_port} sent ACK. ✅ ESTABLISHED."
            )
            self.tcp_state_map[conn_key] = "ESTABLISHED"
        elif 'F' in str(flags):
            if cur == "ESTABLISHED":
                self.router_logger.log_message(
                    f"[TCP] Termination Started: {src_ip}:{src_port} sent FIN. ✂️ FIN-WAIT-1."
                )
                self.tcp_state_map[conn_key] = "FIN-WAIT-1"
        elif 'R' in str(flags):
            self.router_logger.log_message(
                f"[TCP] Connection Aborted: {src_ip}:{src_port} sent RST. ⚠️ Reset."
            )
            self.tcp_state_map.pop(conn_key, None)

        def on_decision(key, rec, decision):
            flow = f"{rec.src}:{rec.src_port} → {rec.dst}:{rec.dst_port} [{rec.direction}]"
            if decision.action == "allow":
                return
            self.router_logger.log_message(
                f"[HTTPS][Policy] {decision.action.upper()} on {flow} "
                f"reason={decision.reason} tags={decision.tags}"
            )

        def on_event(evt):
            flow = evt.get("flow")
            kind = evt.get("kind")
            data = evt.get("data", {})
            self.router_logger.log_message(
                f"[HTTPS][Event] kind={kind} flow={flow} data={data}"
            )

        self.tls_manager.on_decision = on_decision
        self.tls_manager.on_event = on_event
    # ------------ Utils ------------

    @staticmethod
    def _canon_key(ip1: str, pt1: int, ip2: str, pt2: int) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        """Order-independent session key: ((a,pa),(b,pb)) sorted by tuple."""
        a, b = (ip1, pt1), (ip2, pt2)
        return (a, b) if a <= b else (b, a)

    def _looks_tlsish(self, buf: bytes, sport: int, dport: int) -> bool:
        """
        Cheap prefilter to avoid feeding obviously non-TLS payloads.
        Still safe to return True liberally—TLSRecordManager will resync/drop non-TLS.
        """
        if len(buf) >= 5 and buf[1] == 3 and buf[0] in (20, 21, 22, 23):
            return True  # TLS1.x record header
        if len(buf) >= 2 and (buf[0] & 0x80):  # SSLv2 length MSB set
            return True
        if sport in self._TLS_LIKE_PORTS or dport in self._TLS_LIKE_PORTS:
            return True
        return False

    def _build_cipher_suite_map(self) -> dict:
        """
        Build a minimal cipher map; extend from scapy's tls_ciphersuites if present.
        """
        cipher_map = {
            # TLS 1.3
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384",
            0x1303: "TLS_CHACHA20_POLY1305_SHA256",
            # Common TLS 1.2 ECDHE
            0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        }
        if 'tls_ciphersuites' in globals():
            try:
                cipher_map.update(globals()['tls_ciphersuites'])
            except Exception:
                pass
        return cipher_map

class _MsgTypeShim:
    def __init__(self, val: int): self.val = val

class _RootShim:
    def __init__(self, msgtype_val: int): self.msgType = _MsgTypeShim(msgtype_val)

class KerberosManager:
    """
    Manages Kerberos protocol traffic within the router.
    Can be used for passive analysis, logging, or active intervention/proxying.
    """

    class KerberosOpaque(Packet):
        name = "KerberosOpaque"
        fields_desc = [StrLenField("blob", b"", length_from=lambda pkt: len(pkt.blob))]

        # Kerberos APPLICATION tag number -> msgType value (same number for these)
        _APPNUM_TO_MSGTYPE = {
            10: 10, 11: 11, 12: 12, 13: 13, 14: 14, 15: 15,  # AS/TGS/AP
            20: 20, 21: 21, 22: 22,  # KRB-SAFE/PRIV/CRED
            30: 30,  # KRB-ERROR
        }
        _MSGTYPE_NAME = {
            10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP",
            14: "AP-REQ", 15: "AP-REP", 20: "KRB-SAFE", 21: "KRB-PRIV",
            22: "KRB-CRED", 30: "KRB-ERROR"
        }

        @staticmethod
        def _ber_read_len(buf: bytes, i: int):
            if i >= len(buf): return None, None
            first = buf[i];
            i += 1
            if first < 0x80: return first, i
            n = first & 0x7F
            if n == 0 or i + n > len(buf): return None, None
            return int.from_bytes(buf[i:i + n], "big"), i + n

        @classmethod
        def _peel_octet_string(cls, buf: bytes):
            if not buf or buf[0] != 0x04: return None
            ln, j = cls._ber_read_len(buf, 1)
            if ln is None or j is None or j + ln > len(buf): return None
            return buf[j:j + ln]

        @classmethod
        def _extract_gssapi_inner(cls, buf: bytes):
            # Kerberos V5 OID: 1.2.840.113554.1.2.2
            KRB5_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
            idx = buf.find(KRB5_OID)
            if idx < 0: return None
            oct_idx = buf.find(b"\x04", idx + len(KRB5_OID))
            if oct_idx < 0: return None
            return cls._peel_octet_string(buf[oct_idx:])

        @classmethod
        def _extract_spnego_inner(cls, buf: bytes):
            """
            Find SPNEGO (1.3.6.1.5.5.2) and peel the first OCTET STRING likely to be
            mechToken/responseToken containing AP-REQ/REP.
            """
            SPNEGO_OID = b"\x06\x06\x2b\x06\x01\x05\x05\x02"  # DER OID for 1.3.6.1.5.5.2
            idx = buf.find(SPNEGO_OID)
            if idx < 0:
                return None
            # Search a window after the OID for a plausible OCTET STRING and peel it
            win = buf[idx + len(SPNEGO_OID): idx + len(SPNEGO_OID) + 2048]
            pos = 0
            while True:
                j = win.find(b"\x04", pos)  # OCTET STRING tag
                if j < 0:
                    return None
                ln, k = cls._ber_read_len(win, j + 1)
                if ln is None:
                    return None
                if k + ln <= len(win):
                    return win[k:k + ln]  # inner bytes (often AP-REQ/REP)
                pos = j + 1

        @classmethod
        def _scan_for_kerb_app(cls, buf: bytes):
            """
            Scan the blob for the first byte that looks like an APPLICATION|CONSTRUCTED tag
            used by Kerberos (10,11,12,13,14,15,20,21,22,30). Return the slice starting there.
            """
            VALID = {10, 11, 12, 13, 14, 15, 20, 21, 22, 30}
            for i in range(len(buf)):
                b0 = buf[i]
                if (b0 & 0xE0) == 0x60:  # APPLICATION + constructed
                    appnum = b0 & 0x1F
                    if appnum in VALID:
                        return buf[i:]
            return None

        @classmethod
        def _candidates(cls, blob: bytes):
            """
            Build increasingly aggressive candidates:
            - raw
            - single OCTET STRING peel
            - GSS-API (Kerberos OID) inner token
            - SPNEGO (NegToken) inner token
            - second peel of any found inner
            - deep scan for a Kerberos APPLICATION tag anywhere
            """
            cands = []
            if blob:
                cands.append(blob)

                peeled = cls._peel_octet_string(blob)
                if peeled:
                    cands.append(peeled)

                # existing Kerberos V5 OID extraction (GSS-API InitialContextToken)
                inner_gss = cls._extract_gssapi_inner(blob)
                if inner_gss:
                    cands.append(inner_gss)
                    inner2 = cls._peel_octet_string(inner_gss)
                    if inner2:
                        cands.append(inner2)

                # NEW: SPNEGO unwrap
                inner_spnego = cls._extract_spnego_inner(blob)
                if inner_spnego:
                    cands.append(inner_spnego)
                    inner2b = cls._peel_octet_string(inner_spnego)
                    if inner2b:
                        cands.append(inner2b)

                # NEW: deep scan anywhere in the blob
                scanned = cls._scan_for_kerb_app(blob)
                if scanned:
                    cands.append(scanned)

            return cands

        @staticmethod
        def _is_app_tag(b: int) -> bool:
            # Application + Constructed
            return (b & 0xE0) == 0x60

        def _classify_appnum(self) -> int | None:
            for cand in self._candidates(self.blob or b""):
                if cand and self._is_app_tag(cand[0]):
                    return cand[0] & 0x1F  # application tag number
            return None

        def _classify_msgtype(self) -> int | None:
            appnum = self._classify_appnum()
            if appnum is None:
                return None
            # If we know the mapping, use it; else return the raw app tag as msgType
            return self._APPNUM_TO_MSGTYPE.get(appnum, appnum)

        @property
        def root(self):
            mt = self._classify_msgtype()
            return _RootShim(mt if mt is not None else -1)

        def msgtype_name(self) -> str:
            mt = self._classify_msgtype()
            if mt in self._MSGTYPE_NAME:
                return self._MSGTYPE_NAME[mt]
            appnum = self._classify_appnum()
            return f"APP-{appnum}" if appnum is not None else "UNKNOWN"

    # ===== OPAQUE ASN.1 HELPERS =====

    def _ber_len(self, buf: bytes, i: int):
        if i >= len(buf): return None, None
        first = buf[i];
        i += 1
        if first < 0x80: return first, i
        n = first & 0x7F
        if n == 0 or i + n > len(buf): return None, None
        return int.from_bytes(buf[i:i + n], "big"), i + n

    def _find_first_universal_string(self, buf: bytes):
        # Try UTF8String (0x0C), GeneralString (0x1B), IA5String (0x16)
        i = 0
        while i < len(buf):
            tag = buf[i]
            ln, j = self._ber_len(buf, i + 1)
            if ln is None or j is None: break
            if tag in (0x0C, 0x1B, 0x16) and j + ln <= len(buf):
                raw = buf[j:j + ln]
                try:
                    return raw.decode("utf-8" if tag == 0x0C else "latin-1", "ignore")
                except Exception:
                    pass
            i = j + ln
        return None

    def _find_ctx_slice(self, buf: bytes, ctx_tag_num: int):
        """
        Find a context-specific [N] (constructed) tag and return its value slice.
        Tag byte = 0xA0 | (ctx_tag_num & 0x1F).
        """
        want = bytes([0xA0 | (ctx_tag_num & 0x1F)])
        i = 0
        while True:
            idx = buf.find(want, i)
            if idx < 0: return None
            ln, j = self._ber_len(buf, idx + 1)
            if ln is None or j is None: return None
            if j + ln <= len(buf):
                return buf[j:j + ln]
            i = idx + 1

    def _scan_app_slice(self, buf: bytes, appnum: int):
        """Return the slice of an APPLICATION|CONSTRUCTED tag (e.g., Ticket app=1 => 0x61)."""
        want = bytes([(0x60 | (appnum & 0x1F))])
        i = 0
        while True:
            idx = buf.find(want, i)
            if idx < 0: return None
            ln, j = self._ber_len(buf, idx + 1)
            if ln is None or j is None: return None
            if j + ln <= len(buf):
                return buf[j:j + ln]
            i = idx + 1

    # ---- specific opaque extractors ----

    def _opaque_guess_realm_from_kdc_req(self, blob: bytes):
        # KDC-REQ-BODY is [4]; inside, realm is [2]
        body = self._find_ctx_slice(blob, 4)
        if not body: return None
        realm_ctx = self._find_ctx_slice(body, 2)
        return self._find_first_universal_string(realm_ctx or b"")

    def _opaque_guess_sname_from_kdc_req(self, blob: bytes):
        # KDC-REQ-BODY [4] -> sname [3] -> PrincipalName -> name-string [1] -> first string
        body = self._find_ctx_slice(blob, 4)
        if not body: return None
        sname_ctx = self._find_ctx_slice(body, 3)
        if not sname_ctx: return None
        names_ctx = self._find_ctx_slice(sname_ctx, 1)  # name-string [1]
        return self._find_first_universal_string(names_ctx or b"")

    def _opaque_guess_cname_from_kdc_rep(self, blob: bytes):
        # KDC-REP: crealm [3], cname [4]
        cname_ctx = self._find_ctx_slice(blob, 4)
        if not cname_ctx: return None
        names_ctx = self._find_ctx_slice(cname_ctx, 1)  # PrincipalName.name-string [1]
        return self._find_first_universal_string(names_ctx or b"")

    def _opaque_guess_crealm_from_kdc_rep(self, blob: bytes):
        # KDC-REP: crealm [3]
        realm_ctx = self._find_ctx_slice(blob, 3)
        return self._find_first_universal_string(realm_ctx or b"")

    def _opaque_guess_ticket_realm_from_ap_req(self, blob: bytes):
        # AP-REQ: ticket [3] -> Ticket (APPLICATION 1) -> realm [1]
        ticket_ctx = self._find_ctx_slice(blob, 3)
        if not ticket_ctx:
            # Sometimes we can just scan for Ticket APPLICATION(1) = 0x61
            ticket_ctx = self._scan_app_slice(blob, 1)
        if not ticket_ctx: return None
        realm_ctx = self._find_ctx_slice(ticket_ctx, 1)  # realm [1]
        return self._find_first_universal_string(realm_ctx or b"")

    def _opaque_guess_ticket_sname_from_ap_req(self, blob: bytes):
        # AP-REQ: ticket [3] -> Ticket (app=1) -> sname [2] -> name-string [1]
        ticket_ctx = self._find_ctx_slice(blob, 3) or self._scan_app_slice(blob, 1)
        if not ticket_ctx: return None
        sname_ctx = self._find_ctx_slice(ticket_ctx, 2)  # sname [2]
        if not sname_ctx: return None
        names_ctx = self._find_ctx_slice(sname_ctx, 1)  # name-string [1]
        return self._find_first_universal_string(names_ctx or b"")

    def _opaque_guess_error_code(self, blob: bytes):
        # KRB-ERROR: error-code [6] => 0xA6 -> INTEGER (0x02)
        ctx = self._find_ctx_slice(blob, 6)
        if not ctx: return None
        i = 0
        while i < len(ctx):
            if i < len(ctx) and ctx[i] == 0x02:  # INTEGER
                ln, j = self._ber_len(ctx, i + 1)
                if ln is not None and j is not None and j + ln <= len(ctx):
                    try:
                        return int.from_bytes(ctx[j:j + ln], "big", signed=True)
                    except Exception:
                        pass
            ln, j = self._ber_len(ctx, i + 1)
            if ln is None or j is None: break
            i = j + ln
        return None

    def _opaque_5tuple(self, original_packet):
        try:
            from scapy.layers.inet import IP, TCP, UDP
            ip = original_packet.getlayer(IP)
            l4 = original_packet.getlayer(TCP) or original_packet.getlayer(UDP)
            if ip and l4:
                return f"{ip.src}:{int(l4.sport)} > {ip.dst}:{int(l4.dport)}"
        except Exception:
            pass
        return "n/a"

    def __init__(self, router_logger, packet_writer):
        self.router_logger = router_logger
        self.packet_writer = packet_writer # For sending crafted responses if needed
        self.kerberos_sessions = {} # Tracks ongoing Kerberos exchanges (e.g., for correlating requests/responses)
        self._keytab_entries = {} # Stores principal keys (e.g., from a 'keytab' file or configuration)
        self._stop_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None
        self._dynamic_handlers: dict[int, Callable[[Packet, Packet, str], None]] = {}
        self.error_counts = {}  # Key: src_ip, Value: [count, timestamp]
        self.ERROR_THRESHOLD = 10  # Alert if 10 errors...
        self.ERROR_TIMEFRAME = 60  # ...within 60 seconds.
        self.message_type_counts = {}
        self.router_logger.log_message("[Kerberos] Initialized.")

    def start(self):
        """Starts background threads for session management, if any."""
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(target=self._session_cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        self.router_logger.log_message("[Kerberos] Started session cleanup thread.")

    def stop(self):
        """Stops all background threads."""
        self._stop_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)
        self.router_logger.log_message("[Kerberos] Stopped.")

    def register_msgtype_handler(self, msgtype: int, handler: Callable[[Packet, Packet, str], None]):
        """Register/override a handler for a Kerberos msgType (works for decoded and opaque)."""
        self._dynamic_handlers[msgtype] = handler
        self.router_logger.log_message(f"[Kerberos] Registered handler for msgType {msgtype}")

    def unregister_msgtype_handler(self, msgtype: int):
        self._dynamic_handlers.pop(msgtype, None)
        self.router_logger.log_message(f"[Kerberos] Unregistered handler for msgType {msgtype}")

    def _handle_unknown(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        iface_short = inbound_iface.split('_')[-1]
        mt = getattr(getattr(kerb_layer, "root", None), "msgType", None)
        mt_val = getattr(mt, "val", None)
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob_len = len(getattr(kerb_layer, "blob", b""))
            self.router_logger.log_message(
                f"[Kerberos] 🤷 Unknown/unsupported msgType {mt_val} on {iface_short} (opaque, {blob_len} bytes)."
            )
        else:
            self.router_logger.log_message(
                f"[Kerberos] 🤷 Unknown/unsupported msgType {mt_val} on {iface_short} (decoded Kerberos)."
            )

    def _resolve_handler(self, msgtype_val: int):
        """Resolves a handler for any Kerberos message type."""
        builtin = {
            10: self._handle_as_req,
            11: self._handle_as_rep,
            12: self._handle_tgs_req,
            13: self._handle_tgs_rep,
            14: self._handle_ap_req,  # <-- ADDED
            15: self._handle_ap_rep,  # <-- ADDED
            20: self._handle_krb_safe,
            21: self._handle_krb_priv,
            22: self._handle_krb_cred,
            30: self._handle_error,
        }
        # Dynamic overrides take precedence; then built-ins; else unknown
        return self._dynamic_handlers.get(msgtype_val) or builtin.get(msgtype_val) or self._handle_unknown
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
            self.router_logger.log_message(f"[Kerberos] Added key for principal: {principal_name}")
        except ValueError as e:
            self.router_logger.log_message(f"[Kerberos] ❌ Error adding key for {principal_name}: Invalid hex string. {e}")
        except Exception as e:
            self.router_logger.log_message(f"[Kerberos] ❌ Unexpected error adding key for {principal_name}: {e}")


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

    def handle_kerberos_packet(self, packet: Packet, inbound_iface: str, interfaces_config: Dict[str, Any]) -> bool:
        """
        Hardened: always yields a Kerberos-like layer and dispatches it
        to the correct, type-aware handler.
        """
        iface_short = inbound_iface.split('_')[-1]

        try:
            # 1) Gate: Ensure it's a potential Kerberos packet (unchanged)
            if UDP in packet:
                l4 = packet[UDP]
            elif TCP in packet:
                l4 = packet[TCP]
            else:
                return False

            if 88 not in (l4.sport, l4.dport) and 464 not in (l4.sport, l4.dport) and Kerberos not in packet:
                return False

            # 2) Ensure Kerberos-like layer (unchanged)
            if Kerberos in packet:
                kerb_layer = packet[Kerberos]
                self.router_logger.log_message(f"[Kerberos] 🔑 Decoded Kerberos packet on {iface_short}.")
            else:
                raw_payload = bytes(getattr(packet.getlayer(Raw) or Raw(), "load", b""))
                if not raw_payload: return False
                try:
                    # Still try to decode first, it's better if it works
                    kerb_layer = Kerberos(raw_payload)
                    self.router_logger.log_message(f"[Kerberos] 🔑 Decoded raw payload on {iface_short}.")
                except Exception:
                    kerb_layer = self.KerberosOpaque(blob=raw_payload)
                    # The classification log will be handled below

            # 3) UNIFIED DISPATCH LOGIC
            root = getattr(kerb_layer, "root", None)
            if not root or not hasattr(root, "msgType"):
                self.router_logger.log_message(f"[Kerberos] ⚠️ Could not determine msgType.")
                return True  # Handled, but can't dispatch

            msgtype_val = getattr(root.msgType, "val", -1)

            # --- ADD THIS BLOCK FOR PROFILING ---
            self.message_type_counts[msgtype_val] = self.message_type_counts.get(msgtype_val, 0) + 1
            # ------------------------------------

            is_opaque = isinstance(kerb_layer, self.KerberosOpaque) or hasattr(kerb_layer, "blob")

            if is_opaque:
                mt_val = getattr(getattr(getattr(kerb_layer, "root", None), "msgType", None), "val", -1)
                mt_name = kerb_layer.msgtype_name() if hasattr(kerb_layer, "msgtype_name") else "UNKNOWN"
                self.router_logger.log_message(
                    f"[Kerberos] 📦 Opaque on {iface_short} classified as {mt_name} ({mt_val})"
                )
                self._handle_opaque(mt_val, kerb_layer, packet, inbound_iface)
                return True  # ← DO NOT FALL THROUGH

            # Resolve and call the appropriate handler
            handler = self._resolve_handler(msgtype_val)
            handler(kerb_layer, packet, inbound_iface)

            return True

        except Exception as e:
            self.router_logger.log_message(f"[Kerberos] ❌ Error processing Kerberos packet: {repr(e)}")
            return False

        except Exception as e:
            self.router_logger.log_message(f"[Kerberos] ❌ Error: {e}\n{traceback.format_exc()}")
            return False

        except Exception as e:
            self.router_logger.log_message(f"[Kerberos] ❌ Error: {e}\n{traceback.format_exc()}")
            return False

        except Exception as e:
            # Make sure the router gets a useful error string
            self.router_logger.log_message(f"[Kerberos] ❌ Error processing Kerberos packet: {repr(e)}")
            return False
    def _handle_opaque(self, mt_val: int, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        iface_short = inbound_iface.split('_')[-1]
        blob_len = len(getattr(kerb_layer, "blob", b""))
        self.router_logger.log_message(
            f"[Kerberos] (opaque) msgType {mt_val} on {iface_short}; {blob_len} bytes; skipping structured parse."
        )
    def _handle_as_req(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles an AS-REQ packet."""
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            cname = self._opaque_guess_sname_from_kdc_req(
                blob)  # cname/sname share structure; we prefer sname() for strings
            realm = self._opaque_guess_realm_from_kdc_req(blob)
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(
                f"[Kerberos] (opaque) AS-REQ {five} "
                f"{'(cname=' + cname + ') ' if cname else ''}{'(realm=' + realm + ') ' if realm else ''}"
                f"len={len(blob)}"
            )
            return

        as_req = kerb_layer.root
        cname = as_req.reqBody.cname.nameString[0] if as_req.reqBody.cname else "UNKNOWN"
        crealm = as_req.reqBody.realm if as_req.reqBody.realm else "UNKNOWN"
        nonce = as_req.reqBody.nonce.val  # Extract the nonce

        # Store session info in the dictionary we defined in __init__
        self.kerberos_sessions[nonce] = {
            "client": f"{cname}@{crealm}",
            "timestamp": time.time(),
            "type": "AS-REQ"
        }
        self.router_logger.log_message(f"[Kerberos] AS-REQ from {cname}@{crealm} (Nonce: {nonce})")

    def _handle_ap_req(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles an AP-REQ (msgType 14) packet."""
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            realm = self._opaque_guess_ticket_realm_from_ap_req(blob)
            sname = self._opaque_guess_ticket_sname_from_ap_req(blob)
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(
                f"[Kerberos] (opaque) AP-REQ {five} "
                f"{'(ticket_realm=' + realm + ') ' if realm else ''}"
                f"{'(sname=' + sname + ') ' if sname else ''}"
                f"len={len(blob)}"
            )
            return
        # Logic for fully parsed AP-REQ packets
        ap_req = kerb_layer.root
        # You could potentially inspect ap_req.authenticator if you have the right session key
        self.router_logger.log_message("[Kerberos] Parsed AP-REQ message.")

    def _handle_ap_rep(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles an AP-REP (msgType 15) packet."""
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(f"[Kerberos] (opaque) AP-REP {five} len={len(blob)}")
            return

        as_rep = kerb_layer.root
        nonce = as_rep.encPart.nonce.val  # Extract the nonce from the encrypted part

        # Check if this is a reply to a known request
        if nonce in self.kerberos_sessions:
            session_info = self.kerberos_sessions[nonce]
            client = session_info.get("client", "UNKNOWN")
            request_time = session_info.get("timestamp", 0)
            response_time = time.time() - request_time

            self.router_logger.log_message(
                f"[Kerberos] ✅ Correlated AS-REP for {client} (Nonce: {nonce}, Response time: {response_time:.2f}s)"
            )
            # Clean up the completed session
            del self.kerberos_sessions[nonce]
        else:
            self.router_logger.log_message(
                f"[Kerberos] ⚠️ Uncorrelated AS-REP received (Nonce: {nonce})"
            )


    def _handle_krb_safe(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles a KRB-SAFE (msgType 20) packet."""
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(f"[Kerberos] (opaque) KRB-SAFE {five} len={len(blob)}")
            return
        # Add logic here for fully parsed KRB-SAFE packets if needed
        self.router_logger.log_message("[Kerberos] Parsed KRB-SAFE message.")

    def _handle_krb_priv(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles a KRB-PRIV (msgType 21) packet."""
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(f"[Kerberos] (opaque) KRB-PRIV {five} len={len(blob)}")
            return
        self.router_logger.log_message("[Kerberos] Parsed KRB-PRIV message.")

    def _handle_krb_cred(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles a KRB-CRED (msgType 22) packet."""
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(f"[Kerberos] (opaque) KRB-CRED {five} len={len(blob)}")
            return
        self.router_logger.log_message("[Kerberos] Parsed KRB-CRED message.")

    def _handle_as_rep(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles an AS-REP packet."""
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            crealm = self._opaque_guess_crealm_from_kdc_rep(blob)
            cname = self._opaque_guess_cname_from_kdc_rep(blob)
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(
                f"[Kerberos] (opaque) AS-REP {five} "
                f"{'(cname=' + cname + ') ' if cname else ''}{'(crealm=' + crealm + ') ' if crealm else ''}"
                f"len={len(blob)}"
            )
            return
        as_rep = kerb_layer.root
        crealm = as_rep.crealm if as_rep.crealm else "UNKNOWN"
        cname = as_rep.cname.nameString[0] if as_rep.cname and as_rep.cname.nameString else "UNKNOWN"
        sname = as_rep.ticket.sname.nameString[0] if as_rep.ticket.sname and as_rep.ticket.sname.nameString else "UNKNOWN"
        srealm = as_rep.ticket.realm if as_rep.ticket.realm else "UNKNOWN"

        self.router_logger.log_message(f"[Kerberos] AS-REP for {cname}@{crealm} from {sname}@{srealm}")

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
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            sname = self._opaque_guess_sname_from_kdc_req(blob)
            realm = self._opaque_guess_realm_from_kdc_req(blob)
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(
                f"[Kerberos] (opaque) TGS-REQ {five} "
                f"{'(sname=' + sname + ') ' if sname else ''}{'(realm=' + realm + ') ' if realm else ''}"
                f"len={len(blob)}"
            )
        tgs_req = kerb_layer.root
        sname = (tgs_req.reqBody.sname.nameString[0]
                 if tgs_req.reqBody.sname and tgs_req.reqBody.sname.nameString else "UNKNOWN")
        realm = tgs_req.reqBody.realm if tgs_req.reqBody.realm else "UNKNOWN"
        self.router_logger.log_message(f"[Kerberos] TGS-REQ requesting service ticket for {sname}@{realm}")

    def _handle_tgs_rep(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles a TGS-REP packet, whether parsed or opaque."""
        # This is the crucial check
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(f"[Kerberos] (opaque) TGS-REP {five} len={len(blob)}")
            return
        # This code only runs if the packet was fully parsed
        tgs_rep = kerb_layer.root
        crealm = tgs_rep.crealm if tgs_rep.crealm else "UNKNOWN"
        cname = tgs_rep.cname.nameString[0] if tgs_rep.cname and tgs_rep.cname.nameString else "UNKNOWN"

        self.router_logger.log_message(f"[Kerberos] TGS-REP for {cname}@{crealm}")

    def _handle_error(self, kerb_layer: Packet, original_packet: Packet, inbound_iface: str):
        """Handles a KRB-ERROR packet and tracks error rates."""
        # This logic applies even if the packet is opaque, since we have the IP header.
        if isinstance(kerb_layer, self.KerberosOpaque):
            blob = getattr(kerb_layer, "blob", b"")
            code = self._opaque_guess_error_code(blob)
            five = self._opaque_5tuple(original_packet)
            self.router_logger.log_message(
                f"[Kerberos] (opaque) KRB-ERROR {five} "
                f"{'(code=' + str(code) + ') ' if code is not None else ''}"
                f"len={len(blob)}"
            )
            return
        if IP in original_packet:
            src_ip = original_packet[IP].src
            current_time = time.time()

            # Get or initialize the count for this IP
            count, first_seen = self.error_counts.get(src_ip, [0, 0])

            # If outside the time window, reset the count
            if current_time - first_seen > self.ERROR_TIMEFRAME:
                count = 0
                first_seen = current_time

            count += 1
            self.error_counts[src_ip] = [count, first_seen]

            # Check if the threshold has been breached
            if count >= self.ERROR_THRESHOLD:
                self.router_logger.log_message(
                    f"[Kerberos] 🚨 SECURITY ALERT: High rate of KRB-ERRORs ({count}) from {src_ip}!"
                )
                # You could add logic here to temporarily block the IP
                # Reset count after alerting to avoid log spam
                self.error_counts[src_ip] = [0, current_time]

        if isinstance(kerb_layer, self.KerberosOpaque):
            self.router_logger.log_message("[Kerberos] (opaque) KRB-ERROR: Cannot inspect error details.")
            return

    # Additional methods could be added here for active Kerberos proxying,
    # or for initiating Kerberos requests from the router itself.

class NotificationManager:
    """
    Sends simple UDP notifications for network events, with a cooldown table
    to prevent spamming.
    """
    # A table to store the last time a specific event was sent
    # Key: Tuple[event_name, iface] -> float (timestamp)
    _cooldown_table: Dict[str, float] = {}
    _cooldown_lock = threading.Lock()

    # The minimum time in seconds that must pass before sending the same notification again
    DEFAULT_COOLDOWN_SECONDS = 300  # 5 minutes

    def __init__(self, router_logger, target_ip: str, target_port: int, iface: str):
        self.logger = router_logger
        self.target_ip = target_ip
        self.target_port = target_port
        self.outbound_iface = iface  # The interface to send notifications from
        self.sniffer = None
        self.logger.log_message(f"[Notifier] Initialized. Will send alerts to {target_ip}:{target_port}")

    def send_notification(self, event_data: dict, cooldown_seconds: Optional[int] = None,
                          cooldown_key: Optional[str] = None):
        event_name = event_data.get("event")
        if not event_name:
            self.logger.log_message("[Notifier] ❌ Notification missing 'event' field.")
            return

        if cooldown_seconds is not None and cooldown_key:
            with self._cooldown_lock:
                last_sent = self._cooldown_table.get(cooldown_key, 0)
                now = time.time()

                if (now - last_sent) < cooldown_seconds:
                    return
                self._cooldown_table[cooldown_key] = now

        try:
            message = json.dumps(event_data)
            emojis = event_data.get("emojis", ["📡"])
            self.logger.log_message(RouterRandomMessages("Notifier", f"Sending notification: {event_name}", emojis))

            packet = IP(dst=self.target_ip) / UDP(dport=self.target_port) / Raw(load=message)
            self.sniffer.send(packet, verbose=0)
        except Exception as e:
            self.logger.log_message(f"[Notifier] ❌ Failed to send notification: {e}")

class PacketWriter:
    """
    A self-contained class that sends Layer 2 network packets on a dedicated
    thread using a queue.
    """

    # --- MAC normalization helpers ---
    _HEX = "0123456789abcdef"

    @staticmethod
    def _normalize_mac(mac) -> Optional[str]:
        """
        Accepts many forms:
          - 'aa:bb:cc:dd:ee:ff'
          - 'aa-bb-cc-dd-ee-ff'
          - 'aabbccddeeff'
        Rejects placeholders like 'dynamic', 'unknown', '', None.
        Returns lowercased colon-form or None if invalid.
        """
        if mac is None:
            return None
        if isinstance(mac, bytes):
            try:
                mac = mac.decode("ascii", "ignore")
            except Exception:
                return None
        mac = str(mac).strip().lower()
        if mac in ("", "dynamic", "unknown", "ff:ff:ff:ff:ff:ff (broadcast)"):
            return None
        mac = mac.replace("-", ":")
        # bare 12 hex digits -> colonize
        raw = mac.replace(":", "")
        if len(raw) == 12 and all(c in PacketWriter._HEX for c in raw):
            mac = ":".join(raw[i:i+2] for i in range(0, 12, 2))
        # validate aa:bb:cc:dd:ee:ff
        parts = mac.split(":")
        if len(parts) != 6 or any(len(p) != 2 or any(ch not in PacketWriter._HEX for ch in p) for p in parts):
            return None
        return mac

    @staticmethod
    def _is_broadcast(mac: str) -> bool:
        return mac and mac.lower().replace("-", ":") == "ff:ff:ff:ff:ff:ff"

    def _same_subnet(self, ip: str, iface_ip: str, netmask: str | int) -> bool:
        try:
            if isinstance(netmask, int):
                cidr = f"{iface_ip}/{netmask}"
            else:
                # netmask like "255.255.255.0"
                cidr = f"{iface_ip}/{netmask}"
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False

    def _ipv4_mcast_mac(self, ip: str) -> str:
        # RFC 1112: 01:00:5e:0x:xx:xx (low 23 bits of IPv4 mcast)
        n = int(ipaddress.IPv4Address(ip))
        low23 = n & 0x7FFFFF
        return "01:00:5e:%02x:%02x:%02x" % ((low23 >> 16) & 0x7f, (low23 >> 8) & 0xff, low23 & 0xff)

    def _ipv6_mcast_mac(self, ip6: str) -> str:
        # RFC 2464: 33:33:xx:xx:xx:xx (low 32 bits of IPv6 dest)
        n = int(ipaddress.IPv6Address(ip6))
        return "33:33:%02x:%02x:%02x:%02x" % ((n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)

    def _infer_next_hop(self, final_iface: str, pkt) -> tuple[Optional[str], Optional[str]]:
        """
        Decide the L3 next-hop IP and address-family for ARP/ND resolution.
        Returns (next_hop_ip, af) where af is 'ipv4'| 'ipv6' | None.
        """
        cfg = self._interfaces_config.get(final_iface, {})
        if IP in pkt:
            dst = pkt[IP].dst
            if dst == "255.255.255.255":
                return (dst, "ipv4")
            ip_if = cfg.get("ip_addr")
            netmask = cfg.get("netmask") or cfg.get("cidr")
            if ip_if and netmask and self._same_subnet(dst, ip_if, netmask):
                return (dst, "ipv4")
            gw = cfg.get("gateway_ip")
            return (gw if gw else None, "ipv4")
        elif IPv6 in pkt:
            dst6 = pkt[IPv6].dst
            # For IPv6, if on-link (assume /64 unless provided)
            ip_if6 = cfg.get("ip6_addr")
            prefix = cfg.get("prefixlen6") or 64
            try:
                if ip_if6 and ipaddress.IPv6Address(dst6).exploded.split(":")[:4] == ipaddress.IPv6Address(
                        ip_if6).exploded.split(":")[:4]:
                    return (dst6, "ipv6")
            except Exception:
                pass
            gw6 = cfg.get("gateway_ip6")
            return (gw6 if gw6 else None, "ipv6")
        return (None, None)

    def _heal_dst_mac_before_queue(self, packet, final_iface: str) -> bool:
        """
        If Ether.dst is invalid (e.g., 'dynamic', 'static', 'unknown'), attempt to repair it.
        Uses ARPManager.resolve() first, then multicast/broadcast, then getmacbyip().
        """
        if not packet.haslayer(Ether):
            return False

        eth = packet[Ether]
        raw_dst = str(eth.dst).lower().strip()

        # Normalize first
        dst_fixed = self._normalize_mac(eth.dst)
        if dst_fixed:
            eth.dst = dst_fixed
            return True

        # Handle placeholders like 'static', 'dynamic', 'unknown'
        if raw_dst in ("static", "dynamic", "unknown"):
            # Try to resolve via ARPManager
            try:
                nh_ip, af = self._infer_next_hop(final_iface, packet)
                if nh_ip and af == "ipv4" and self.arp_manager:
                    mac = self.arp_manager.resolve(nh_ip, final_iface)
                    mac_norm = self._normalize_mac(mac)
                    if mac_norm:
                        eth.dst = mac_norm
                        self.logger.log_message(
                            f"[PacketWriter] 🔍 Resolved placeholder Ether.dst '{raw_dst}' to {mac_norm} via ARPManager"
                        )
                        return True
            except Exception as e:
                self.logger.log_message(f"[PacketWriter] ⚠️ ARPManager.resolve failed: {e}")

            # Allow broadcast if caller says so
            if getattr(packet, "_pw_allow_broadcast", False):
                eth.dst = "ff:ff:ff:ff:ff:ff"
                return True

            # Derive from L3 multicast/broadcast
            try:
                if IP in packet:
                    dip = packet[IP].dst
                    if dip == "255.255.255.255":
                        eth.dst = "ff:ff:ff:ff:ff:ff"
                        return True
                    if ipaddress.IPv4Address(dip).is_multicast:
                        eth.dst = self._ipv4_mcast_mac(dip)
                        return True
                elif IPv6 in packet:
                    dip6 = packet[IPv6].dst
                    if ipaddress.IPv6Address(dip6).is_multicast:
                        eth.dst = self._ipv6_mcast_mac(dip6)
                        return True
            except Exception:
                pass

            # Last chance: raw getmacbyip
            nh_ip, af = self._infer_next_hop(final_iface, packet)
            if nh_ip and af == "ipv4":
                mac = self._normalize_mac(getmacbyip(nh_ip))
                if mac:
                    eth.dst = mac
                    self.logger.log_message(
                        f"[PacketWriter] ⚠️ Healed placeholder Ether.dst '{raw_dst}' with getmacbyip → {mac}"
                    )
                    return True

            # Final fallback: broadcast
            eth.dst = "ff:ff:ff:ff:ff:ff"
            self.logger.log_message(f"[PacketWriter] ⚠️ Healed placeholder Ether.dst '{raw_dst}' as broadcast")
            return True

        # If dst was something else invalid, fail
        return False
    def __init__(self, logger, interfaces_config, packet_signer, outbound_load_balancer):
        """
        Initializes the PacketWriter.
        The interface map is now populated by calling the update_interfaces method.
        """
        self.logger = logger
        self.packet_signer = packet_signer
        self.sniffer = None
        self.packet_queue = queue.Queue()
        self.worker_thread = None
        self._stop_event = threading.Event()
        self.outbound_load_balancer = outbound_load_balancer
        self._interfaces_config = interfaces_config

        # This map will be populated by the new update_interfaces method
        self.iface_map = {}

        # Destination throttling
        self.packet_writing_table = defaultdict(lambda: {
            "timestamps": deque(maxlen=10),
            "last_sent": 0,
            "count": 0
        })
        self.SEND_RATE_LIMIT_HZ = 10
        self.logger.log_message("[PacketWriter] Initialized.")

    # --- NEW METHOD TO UPDATE INTERFACES ---
    def update_interfaces(self, new_interfaces_config: dict):
        """
        Updates the internal interface configuration and rebuilds the
        friendly name to system name map. This should be called after the
        router manager has finished configuring interfaces.
        """
        self.logger.log_message("[PacketWriter] 🔄 Updating interface configuration...")
        self._interfaces_config = new_interfaces_config

        # Clear the old map
        self.iface_map.clear()

        # Rebuild the map from the new configuration
        for system_name, config_dict in self._interfaces_config.items():
            friendly_name = config_dict.get('friendly_name')
            if friendly_name:
                self.iface_map[friendly_name] = system_name

        self.logger.log_message(f"[PacketWriter] ✅ Interface map updated. {len(self.iface_map)} interfaces mapped.")

    # --- END NEW METHOD ---

    def _worker_loop(self):
        """The main loop for the worker thread that sends packets."""
        self.logger.log_message("[PacketWriter] Worker thread started.")
        while not self._stop_event.is_set():
            try:
                item = self.packet_queue.get(timeout=1)
                if item is None:
                    continue
                packet, interface = item
                packet._pw_allow_local_dest = True
                self._send_raw_packet(packet, interface)
            except queue.Empty:
                continue
        self.logger.log_message("[PacketWriter] Worker thread has stopped.")

    def _send_raw_packet(self, packet, interface: str):
        """
        Uses the sniffer's sendp to send a Layer 2 packet. The 'interface' string
        is now the correct system name, thanks to translation in queue_packet.
        """
        if not interface:
            self.logger.log_message("[PacketWriter] ⚠️ Error: Interface name is not specified.")
            return
        if not packet.haslayer(Ether):
            self.logger.log_message(
                f"[PacketWriter] 🚫 Dropped packet: Missing Ethernet layer. Summary: {packet.summary()}")
            return

        # Final guard: fix/validate Ether src/dst before send
        try:
            eth = packet[Ether]
            norm_src = self._normalize_mac(eth.src)
            norm_dst = self._normalize_mac(eth.dst)

            if not norm_src:
                # Try to use interface MAC if src is bogus
                try:
                    eth.src = get_if_hwaddr(interface)
                    norm_src = self._normalize_mac(eth.src)
                except Exception:
                    pass
            if not norm_src:
                raise ValueError(f"Invalid Ether src '{eth.src}'")

            if not norm_dst:
                # If caller allowed broadcast, salvage as broadcast
                if bool(getattr(packet, "_pw_allow_broadcast", False)):
                    eth.dst = "ff:ff:ff:ff:ff:ff"
                else:
                    raise ValueError(f"Invalid Ether dst '{eth.dst}'")
            else:
                eth.dst = norm_dst
                eth.src = norm_src
        except Exception as ve:
            self.logger.log_message(f"[PacketWriter] ❌ Packet validation failed: {ve}")
            return

        router_ips = [cfg.get("ip_addr") for cfg in self._interfaces_config.values() if "ip_addr" in cfg]
        dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else None

        allow_local_dest = bool(getattr(packet, "_pw_allow_local_dest", False))
        if dst_ip in router_ips and not allow_local_dest:
            self.logger.log_message(
                f"[PacketWriter] 🚫 Dropped packet: Destination IP ({dst_ip}) is our own. Summary: {packet.summary()}")
            return

        try:
            self.packet_signer.sign_packet(packet)
            self.sniffer.sendp(packet, iface=interface, verbose=0)
        except Exception as e:
            self.logger.log_message(f"[PacketWriter] ❌ Failed to send packet on '{interface}': {e}")

    def forward_l2(self, pkt, *, inbound_iface: str = None, egress_iface: str = None, next_hop_ip: str = None,
                   preserve_vlan: bool = True, allow_local_dest: bool = False, allow_broadcast: bool = False):
        if not egress_iface:
            egress_iface = self.outbound_load_balancer.get_next_interface(pkt)
        if not egress_iface:
            self.logger.log_message("[PacketWriter] forward_l2: No egress iface")
            return

        if inbound_iface and egress_iface == inbound_iface:
            self.logger.log_message(f"[PacketWriter] forward_l2: Skip hairpin on {egress_iface}")
            return

        dst_ip = pkt[IP].dst if IP in pkt else pkt[IPv6].dst if IPv6 in pkt else None
        nh_ip = next_hop_ip or dst_ip

        try:
            src_mac = get_if_hwaddr(egress_iface)
        except Exception as e:
            self.logger.log_message(f"[PacketWriter] forward_l2: get_if_hwaddr({egress_iface}) failed: {e}")
            return

        # Resolve destination MAC robustly
        dst_mac: Optional[str] = None
        try:
            if allow_broadcast and pkt.haslayer(Ether) and self._is_broadcast(getattr(pkt, "dst", "")):
                dst_mac = "ff:ff:ff:ff:ff:ff"
            elif nh_ip:
                dst_mac = self._normalize_mac(getmacbyip(nh_ip))
            elif pkt.haslayer(Ether) and getattr(pkt, "dst", None):
                dst_mac = self._normalize_mac(pkt.dst)  # may be 'dynamic' → becomes None
        except Exception:
            dst_mac = None

        if not dst_mac:
            if allow_broadcast:
                dst_mac = "ff:ff:ff:ff:ff:ff"
            else:
                # Don't attempt to send with 'dynamic'/unknown MAC
                msg_dst = getattr(pkt, "dst", None)
                self.logger.log_message(
                    f"[PacketWriter] forward_l2: No valid dst MAC "
                    f"(nh={nh_ip}, pkt.dst={msg_dst!r}). ARP unresolved; dropping."
                )
                return

        payload = pkt.payload if pkt.haslayer(Ether) else pkt
        out_frame = Ether(src=self._normalize_mac(src_mac) or src_mac, dst=dst_mac) / (
            Dot1Q(vlan=pkt[Dot1Q].vlan) / payload if preserve_vlan and pkt.haslayer(Dot1Q) else payload)

        is_ike_packet = UDP in pkt and (pkt[UDP].sport in [500, 4500] or pkt[UDP].dport in [500, 4500])
        if is_ike_packet:
            self.logger.log_message(f"[PacketWriter] 🛡️ IKE packet detected, applying forwarding overrides.")

        final_allow_local = allow_local_dest or is_ike_packet
        final_allow_broadcast = allow_broadcast or is_ike_packet

        setattr(out_frame, "_pw_tx", True)
        if final_allow_local:
            setattr(out_frame, "_pw_allow_local_dest", True)
        if final_allow_broadcast:
            setattr(out_frame, "_pw_allow_broadcast", True)

        self.queue_packet(out_frame, interface=egress_iface)

    def start(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self.logger.log_message("[PacketWriter] Already running.")
            return
        self._stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="PacketWriterThread")
        self.worker_thread.start()

    def stop(self):
        if not self.worker_thread or not self.worker_thread.is_alive():
            return
        self.logger.log_message("[PacketWriter] Stopping...")
        self._stop_event.set()
        self.packet_queue.put(None)
        self.worker_thread.join(timeout=2)

    def queue_packet(self, packet, interface: str = None):
        """
        Adds a packet to the queue for sending.
        Translates friendly interface name to system name before queuing.
        Attempts to repair invalid Ether.dst values (e.g., 'dynamic') automatically.
        """
        if self._stop_event.is_set():
            self.logger.log_message("[PacketWriter] ⚠️ Warning: Cannot queue packet — writer is stopping.")
            return

        target_iface_name = interface or self.outbound_load_balancer.get_next_interface(packet)
        if not target_iface_name:
            self.logger.log_message("[PacketWriter] ⚠️ Dropped packet: No outbound interface determined.")
            return

        # Translate friendly -> system name
        final_iface = self.iface_map.get(target_iface_name, target_iface_name)
        if final_iface == target_iface_name and not target_iface_name.startswith("\\Device\\NPF_"):
            self.logger.log_message(
                f"[PacketWriter] ⚠️ No system name mapped for '{target_iface_name}'. Sending may fail.")

        # Heal dst MAC if invalid
        if packet.haslayer(Ether):
            if not self._heal_dst_mac_before_queue(packet, final_iface):
                self.logger.log_message(
                    f"[PacketWriter] 🚫 Dropped packet before queue: invalid Ether.dst '{packet[Ether].dst}'")
                # Helpful once: where did this come from?
                return

        self.packet_queue.put((packet, final_iface))

class ForwardingManager:
    """
    Tracks recently forwarded flows and considers them duplicates only after
    a certain threshold has been reached within a timeout period.
    """

    def __init__(self, function_call_tracker, router_logger=None,timeout: int = 5, max_entries: int = 10000, duplicate_threshold: int = 5):
        self.logger = router_logger or (lambda x: None)
        self.timeout = timeout
        self.duplicate_threshold = duplicate_threshold  # NEW: Configurable threshold
        self._forwarded_cache = deque(maxlen=max_entries)
        self.function_call_tracker = function_call_tracker
        # CHANGED: from a set to a dictionary to store (count, timestamp)
        self._flow_counts: Dict[Tuple, Tuple[int, float]] = {}
        self.ban_duration = 60  # seconds
        self.max_consecutive_rate = 20  # e.g., more than 10 packets/sec = ban
        self._banned_flows: Dict[Tuple, float] = {}  # flow → ban_expiry_time
        self._lock = threading.Lock()

    def _prune_expired(self):
        now = time.time()
        while self._forwarded_cache and (now - self._forwarded_cache[0][1]) > self.timeout:
            key, _ = self._forwarded_cache.popleft()
            # UPDATED: Remove from the counts dictionary as well
            if key in self._flow_counts:
                del self._flow_counts[key]
                self.function_call_tracker.track(
                    identifier='FlowExpired',
                    threshold=20,
                    final_message=f"[Forwarding] 🔁 Flow expired from cache: {key}. Count: {{}}.",
                    count_message=None,
                )

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
        key = (src_ip, dst_ip, sport, dport, proto)
        now = time.time()

        with self._lock:
            self._prune_expired()

            # ⛔ Check if this flow is currently banned
            if key in self._banned_flows:
                if now < self._banned_flows[key]:
                    self.function_call_tracker.track(
                        identifier='ForwardingBanFlow',
                        threshold=100,
                        final_message=f"[Forwarding] ⛔ Banned flow detected: {key}.",
                        count_message=None,
                    )
                    return True
                else:
                    del self._banned_flows[key]
                    self.logger.log_message(f"[Forwarding] ✅ Ban expired for flow: {key}")

            # Record or update count
            if key in self._flow_counts:
                count, last_time = self._flow_counts[key]
                delta = now - last_time

                new_count = count + 1
                self._flow_counts[key] = (new_count, now)

                # 🚫 Ban logic: too many hits per second
                if delta < 1 and new_count >= self.max_consecutive_rate:
                    self._banned_flows[key] = now + self.ban_duration
                    self.function_call_tracker.track(
                        identifier='ForwardingBan',
                        threshold=20,
                        final_message=f"[Forwarding] 🚷 Flow {key} temporarily banned for flood rate. Count: {{}}.",
                        count_message=None,
                    )
                    return True

                # Duplicate logic
                if new_count >= self.duplicate_threshold:
                    self.function_call_tracker.track(
                        identifier='Duplicate threshold',
                        threshold=20,
                        final_message=f"[Forwarding] 🚫 Duplicate threshold hit for flow {key}. Count: {{}}.",
                        count_message=None,
                    )
                    return True
                else:
                    return False

            else:
                # First time seeing this flow
                self._forwarded_cache.append((key, now))
                self._flow_counts[key] = (1, now)
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
            if mac_address.lower() == "ff:ff:ff:ff:ff:ff" or mac_address.startswith(("01:00:5e", "33:33")):
                return

            if self._mac_table.get(mac_address, (None, 0))[0] != iface_name:
                self.logger.log_message(f"[Bridge] 🌉 Learned {mac_address} is on port {iface_name.split('_')[-1]}")
            self._mac_table[mac_address] = (iface_name, time.time() + self.MAC_TABLE_TIMEOUT)

    def handle_frame(self, frame: Packet, inbound_iface: str):
        """
        Processes a Layer 2 frame by learning its source MAC and then
        either forwarding it to a known port or flooding it to all other ports.
        """
        if not frame.haslayer(Ether):
            return

        src_mac = frame[Ether].src
        dst_mac = frame[Ether].dst

        # Learn the source MAC address and associate it with the inbound interface.
        self.learn_mac(src_mac, inbound_iface)

        bridge_name = self.get_bridge_for_interface(inbound_iface)
        if not bridge_name:
            # This should not happen if called from the main router dispatcher correctly
            return

        # Look up the destination MAC in our learned table.
        with self._mac_table_lock:
            target_info = self._mac_table.get(dst_mac)

        target_iface = target_info[0] if target_info else None

        # Decide whether to forward to a specific port or flood to all ports.
        is_broadcast = dst_mac.lower() == "ff:ff:ff:ff:ff:ff"
        is_multicast = dst_mac.startswith(("01:00:5e", "33:33"))

        # Case 1: Destination is known and is not a broadcast/multicast (Unicast Forwarding)
        if target_iface and not is_broadcast and not is_multicast:
            # If the target port is the same as the source port, drop the frame to prevent loops.
            if target_iface == inbound_iface:
                self.logger.log_message(f"[Bridge] ↩️ Dropping L2 Frame {src_mac}->{dst_mac} (same source/dest port).")
                return

            # Forward the frame to the specific target interface.
            self.logger.log_message(
                f"[Bridge] ➡️ Forwarding L2 Frame {src_mac} -> {dst_mac} to port {target_iface.split('_')[-1]}")
            self.packet_writer.queue_packet(frame, target_iface)

        # Case 2: Destination is unknown, a broadcast, or a multicast (Flooding)
        else:
            reason = "Broadcast" if is_broadcast else "Multicast" if is_multicast else "Unknown Unicast"
            self.logger.log_message(
                f"[Bridge] 🌊 Flooding L2 Frame {src_mac} -> {dst_mac} ({reason}) from port {inbound_iface.split('_')[-1]}")

            flood_targets = []
            interfaces_in_bridge = self._bridges.get(bridge_name, set())

            for iface in interfaces_in_bridge:
                # Don't send the frame back out the port it came in on.
                if iface != inbound_iface:
                    self.packet_writer.queue_packet(frame.copy(), iface)
                    flood_targets.append(iface.split('_')[-1])

            if not flood_targets:
                self.logger.log_message("[Bridge] 🚫 No other active interfaces in bridge to flood to.")

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
        """Stops the cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self.logger.log_message("[Bridge] Stopping cleanup thread...")
            self._stop_event.set()
            self._cleanup_thread.join(timeout=2)
            self.logger.log_message("[Bridge] Cleanup thread stopped.")

class EthernetL2Manager:
    """
    Handles non-IP Ethernet (Layer 2) packets such as 802.3 frames, STP, LLDP, and malformed traffic.
    Logs or filters low-level packets that do not include IP/IPv6 layers.
    """

    def __init__(self, function_call_tracker, router_logger):
        self.logger = router_logger
        self.function_call_tracker = function_call_tracker

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
            self.function_call_tracker.track(
                identifier='DroppedL2Multicast',
                threshold=20,
                final_message=f"[L2] 📡 Dropping unhandled non-IP Ethernet packet (type {ether_type_hex}) on {iface_name}. Count: {{}}.",
                count_message=None)
            return True # Handled (by dropping)

        except Exception as e:
            self.function_call_tracker.track(
                identifier='DroppedL2Multicast',
                threshold=20,
                final_message=f"[L2] ‼️ ERROR dissecting problematic non-IP packet on {iface_name}: {e}. Raw packet summary: {packet.summary()}. Count: {{}}.",
                count_message=None)
            return True # Handled (by dropping due to error)

class SYNScanner:
    """
    Manages periodic SYN scans, performs banner grabbing on open ports,
    and sends stateful notifications about port status changes.
    """

    def __init__(self, router_logger, packet_writer, arp_manager, interfaces_config: Dict[str, Any],
                 notification_manager: Optional[Any],  # MODIFIED: Added NotificationManager
                 scan_targets: Optional[List[Tuple[str, List[int]]]] = None, scan_interval: int = 60):
        """
        Initializes the SYNScanner.
        # ... (docstring is the same, but with notification_manager added)
        """
        self.sniffer = None
        self.router_logger = router_logger
        self.packet_writer = packet_writer
        self.interfaces_config = interfaces_config
        self.notification_manager = notification_manager  # NEW: Store notification manager
        self.scan_targets = scan_targets if scan_targets is not None else [
            ("8.8.8.8", [53, 80]),
            ("1.1.1.1", [443, 80]),
        ]
        self.scan_interval = scan_interval
        self.arp_manager = arp_manager
        self._scannable_interfaces = []
        self._populate_scannable_interfaces()

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # NEW: State tracking for open ports
        self.open_ports_state = set()

        self.router_logger.log_message("[SYNScanner] Initialized.")
        if not self._scannable_interfaces:
            self.router_logger.log_message(
                "[SYNScanner] Warning: No suitable non-loopback interfaces with an IP found for scanning.")

    def _populate_scannable_interfaces(self):
        # ... (This method remains unchanged)
        self._scannable_interfaces.clear()
        for iface_full_name, cfg in self.interfaces_config.items():
            if cfg.get("ip_addr") and not ("loopback" in iface_full_name.lower() or "lo" == iface_full_name.lower()):
                self._scannable_interfaces.append(iface_full_name)
        self.router_logger.log_message(f"[SYNScanner] Found {len(self._scannable_interfaces)} scannable interfaces.")

    def start(self):
        # ... (This method remains unchanged)
        if self._thread and self._thread.is_alive():
            self.router_logger.log_message("[SYNScanner] Already running.")
            return
        self._populate_scannable_interfaces()
        if not self._scannable_interfaces:
            self.router_logger.log_message("[SYNScanner] Cannot start: No scannable interfaces available.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_scan_loop, daemon=True, name="SYNScannerThread")
        self._thread.start()
        self.router_logger.log_message("[SYNScanner] Thread started.")

    def stop(self):
        # ... (This method remains unchanged)
        if not self._thread or not self._thread.is_alive():
            return
        self.router_logger.log_message("[SYNScanner] Stopping thread...")
        self._stop_event.set()
        self._thread.join(timeout=5)
        self.router_logger.log_message("[SYNScanner] Thread stopped.")

    def _run_scan_loop(self):
        """The main loop for the SYN scanning thread, now with stateful logic."""
        self.router_logger.log_message("[SYNScanner] Scan loop started.")
        while not self._stop_event.is_set():
            if not self._scannable_interfaces:
                self.router_logger.log_message("[SYNScanner] No active scannable interfaces. Waiting...")
                self._stop_event.wait(self.scan_interval)
                self._populate_scannable_interfaces()
                continue

            selected_iface = random.choice(self._scannable_interfaces)
            self.router_logger.log_message(f"[SYNScanner] Commencing scan cycle using {selected_iface.split('_')[-1]}")

            for target_ip, ports in self.scan_targets:
                for port in ports:
                    if self._stop_event.is_set(): break

                    port_identifier = (target_ip, port)

                    # MODIFIED: Perform scan and get banner
                    status, response_pkt, banner = self._perform_syn_scan(target_ip, port, selected_iface)
                    self.router_logger.log_message(
                        f"[SYNScanner] Result for {target_ip}:{port} on {selected_iface.split('_')[-1]} -> {status}"
                    )

                    is_open = status == 'OPEN'
                    was_open = port_identifier in self.open_ports_state

                    # State Change Logic
                    if is_open and not was_open:
                        # NEW DISCOVERY
                        self.open_ports_state.add(port_identifier)
                        self.router_logger.log_message(f"[SYNScanner] ✅ NEW OPEN PORT: {target_ip}:{port}")
                        if banner:
                            self.router_logger.log_message(f"[SYNScanner]    Banner: {banner}")
                        if self.notification_manager:
                            self.notification_manager.send_notification({
                                "event": "Port Opened", "ip": target_ip, "port": port, "banner": banner or "N/A"
                            })
                    elif not is_open and was_open:
                        # PORT HAS CLOSED
                        self.open_ports_state.remove(port_identifier)
                        self.router_logger.log_message(f"[SYNScanner] ❌ PORT CLOSED: {target_ip}:{port}")
                        if self.notification_manager:
                            self.notification_manager.send_notification({
                                "event": "Port Closed", "ip": target_ip, "port": port
                            })

                if self._stop_event.is_set(): break

            self.router_logger.log_message(f"[SYNScanner] Scan cycle completed. Waiting for {self.scan_interval}s.")
            self._stop_event.wait(self.scan_interval)
        self.router_logger.log_message("[SYNScanner] Scan loop has exited.")

    # NEW METHOD for banner grabbing
    def _get_service_banner(self, target_ip: str, target_port: int, timeout: float = 3.0) -> Optional[str]:
        """Tries to connect to an open port and grab a service banner."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target_ip, target_port))
                banner_bytes = s.recv(1024)
                return banner_bytes.decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            self.router_logger.log_message(f"[SYNScanner] Banner grab for {target_ip}:{target_port} timed out.")
            return None
        except Exception as e:
            self.router_logger.log_message(f"[SYNScanner] Banner grab for {target_ip}:{target_port} failed: {e}")
            return None

    def _perform_syn_scan(self, target_ip: str, target_port: int, iface: str, timeout: float = 2.0) -> Tuple[
        str, Optional[Any], Optional[str]]:  # MODIFIED: Returns banner now
        """
        Sends a single SYN packet and interprets the response.
        If port is open, also attempts to grab a service banner.
        Returns a tuple: (status_string, response_packet_or_None, banner_or_None).
        """
        banner = None  # Initialize banner as None
        try:
            src_ip = self.interfaces_config.get(iface, {}).get("ip_addr", None)
            src_mac = self.interfaces_config.get(iface, {}).get("mac_addr", get_if_hwaddr(iface))
            dst_mac = self.arp_manager.resolve(target_ip,
                                               iface=iface) or "ff:ff:ff:ff:ff:ff"  # fallback for unreachable

            # Construct Layer 2-4 SYN packet
            ip_layer = IP(src=src_ip, dst=target_ip) if src_ip else IP(dst=target_ip)
            tcp_layer = TCP(dport=target_port, flags="S")
            pkt = Ether(src=src_mac, dst=dst_mac) / ip_layer / tcp_layer

            response = self.sniffer.sr1(pkt, timeout=timeout, verbose=0)  # MODIFIED: specify interface for reliability

            if response is None:
                return 'FILTERED (no response)', None, None
            elif response.haslayer(TCP):
                tcp_flags = response[TCP].flags
                if tcp_flags & 0x12:  # SYN-ACK
                    # Send RST to tear down the half-open connection
                    rst_pkt = IP(dst=target_ip, src=response[IP].dst) / \
                              TCP(dport=target_port, sport=response[TCP].dport, flags="R", seq=response[TCP].ack)
                    self.sniffer.sendp(rst_pkt, verbose=0, iface=iface)

                    # MODIFIED: Now that the scan part is done, try to grab the banner
                    banner = self._get_service_banner(target_ip, target_port)

                    return 'OPEN', response, banner
                elif tcp_flags & 0x04:  # RST
                    return 'CLOSED', response, None
                else:
                    return f'UNEXPECTED_TCP_FLAGS ({hex(tcp_flags)})', response, None
            # ... (ICMP handling remains the same, just returning None for banner)
            elif response.haslayer(ICMP):
                # ...
                return f'FILTERED (ICMP ...)', response, None
            else:
                return 'UNEXPECTED_NON_TCP_RESPONSE', response, None

        except Exception as e:
            self.router_logger.log_message(f"[SYNScanner] Error during scan of {target_ip}:{target_port}: {e}")
            return 'ERROR', None, None

class ICMPManager:
    """
    Responds to ICMP Echo-Requests (ping) and logs both
    reception and replies, using PacketWriter to send.
    Enhanced with rate limiting, IPv4 reassembly for router-destined
    datagrams, and safe fragmentation of Echo-Replies to MTU.
    """

    # Reassembly tuning
    REASM_TIMEOUT_SEC = 5.0  # RFC says 30s typical; we keep it short in user-space
    _EIGHT = 8

    def __init__(self, router_logger, packet_writer, sendback_manager, interfaces_config: dict, rate_limit_pps: int = 5):
        self.log = router_logger
        self.pw = packet_writer
        self.ifaces = interfaces_config  # expects per-iface dicts; if present, may include 'mtu'
        self.rate_limit_pps = rate_limit_pps
        self._last_reply_time = defaultdict(float)  # (src_ip, dst_ip) -> ts
        self._rate_limit_lock = threading.Lock()
        self.sendback_manager = sendback_manager

        # IPv4 reassembly buffers keyed by (src,dst,proto,id)
        # Each value: {"first_hdr": IP, "parts": {offset_bytes: bytes}, "total": Optional[int], "t0": float, "iface": str}
        self._reasm: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
        self._reasm_lock = threading.Lock()

        self.log.log_message("[ICMP] Manager initialized (frag reasm + reply fragmenter enabled).")

    # ---------- Public entry ----------

    def handle_packet(self, pkt, inbound_iface: str) -> bool:
        """
        Handles incoming ICMP packets (including fragmented ones).
        Returns True if the packet was handled (consumed) by the manager.
        """

        # Only IPv4 here (IPv6 has different frag mechanics/ICMPv6)
        if not pkt.haslayer(IP):
            return False

        ip = pkt[IP]
        dst_ip = ip.dst

        # Is this datagram addressed to the router?
        is_for_router, router_mac_for_reply, router_ip_for_reply = self._match_router_ip(dst_ip)

        # If this is a fragmented IPv4 datagram destined to us, reassemble first.
        if self._is_ipv4_fragment(ip) and is_for_router:
            assembled = self._reassemble_ipv4(pkt, inbound_iface)
            # If not complete yet, we "handled" it by buffering.
            if assembled is None:
                return True
            # Continue with the reassembled full packet
            pkt = assembled
            ip = pkt[IP]

        # From here, only ICMP packets interest us.
        if not pkt.haslayer(ICMP):
            # Not ICMP (or later fragments that we didn’t buffer) -> not our job
            return False

        icmp = pkt[ICMP]
        src_ip = ip.src
        icmp_type = icmp.type
        icmp_code = getattr(icmp, "code", 0)

        if not is_for_router:
            self.log.log_message(f"[ICMP] 📭 ICMP type {icmp_type} to {dst_ip} (not router IP) on {inbound_iface.split('_')[-1]}; skipping.")
            return False

        # ---------- ICMP type handling ----------

        # Echo Request (type 8) -> send Echo Reply (type 0); fragment reply if needed
        if icmp_type == 8:
            self.log.log_message(f"[ICMP] 📨 Echo-Request from {src_ip} → {dst_ip} on {inbound_iface.split('_')[-1]} (len={len(bytes(pkt))})")

            if self._is_rate_limited(src_ip, dst_ip):
                return True

            # Build the reply (mirror payload, keep id/seq)
            if pkt.haslayer(Ether) and not self._is_loopback_name(inbound_iface):
                l2dst = pkt[Ether].src
                l2src = router_mac_for_reply or "00:00:00:00:00:00"
                reply = (
                    Ether(src=l2src, dst=l2dst) /
                    IP(src=dst_ip, dst=src_ip) /
                    ICMP(type=0, id=icmp.id, seq=icmp.seq) /
                    icmp.payload
                )
            else:
                reply = IP(src=dst_ip, dst=src_ip) / ICMP(type=0, id=icmp.id, seq=icmp.seq) / icmp.payload

            # Ensure reply fits MTU (fragment if necessary)
            self._maybe_fragment_and_queue(reply, inbound_iface)
            self.log.log_message(f"[ICMP] ✅ Echo-Reply queued on {inbound_iface.split('_')[-1]} for {src_ip}")
            return True

        # Destination Unreachable
        if icmp_type == 3:
            if icmp_code == 4:
                # Fragmentation needed (DF set); RFC 1191/4821 PMTUD signal
                # MTU may be carried in 'unused'/nexthopmtu field depending on Scapy version
                hinted_mtu = getattr(icmp, "unused", None) or getattr(icmp, "nexthopmtu", None)
                self.log.log_message(f"[ICMP] 📦 Frag-needed (DF) from {src_ip} on {inbound_iface.split('_')[-1]} (mtu={hinted_mtu})")
            else:
                self.log.log_message(f"[ICMP] 🔌 Dest Unreachable (code {icmp_code}) from {src_ip} on {inbound_iface.split('_')[-1]}")
            # Optionally forward upstream:
            if hasattr(self.sendback_manager, "send_icmp_packet"):
                self.sendback_manager.send_icmp_packet(pkt, icmp_type=3, icmp_code=icmp_code)
            return True

        # Time Exceeded
        if icmp_type == 11:
            self.log.log_message(f"[ICMP] ⏳ Time Exceeded (code {icmp_code}) from {src_ip} on {inbound_iface.split('_')[-1]}")
            if hasattr(self.sendback_manager, "send_icmp_packet"):
                self.sendback_manager.send_icmp_packet(pkt, icmp_type=11, icmp_code=icmp_code)
            return True
        elif icmp_type == 3:  # Destination Unreachable
            if icmp_code == 13:
                self._log_admin_block(pkt, inbound_iface)
                # Optionally fail fast to the client (see below)
                return True
        # Others: log & ignore
        self.log.log_message(f"[ICMP] ❔ Unhandled ICMP type {icmp_type} from {src_ip} on {inbound_iface.split('_')[-1]}. Summary: {pkt.summary()}")
        return False

    # ---------- Rate limiting ----------

    def _is_rate_limited(self, src_ip: str, dst_ip: str) -> bool:
        with self._rate_limit_lock:
            now = time.time()
            key = (src_ip, dst_ip)
            if now - self._last_reply_time[key] < (1.0 / self.rate_limit_pps):
                self.log.log_message(f"[ICMP] 🚫 Rate-limiting Echo-Reply to {src_ip}.")
                return True
            self._last_reply_time[key] = now
            return False

    # ---------- Fragmentation helpers ----------

    def _is_ipv4_fragment(self, ip) -> bool:
        # MF flag or non-zero fragment offset means "fragment"
        try:
            mf = bool(int(ip.flags) & 0x1)  # MF
        except Exception:
            # scapy flags can be flag objects; fall back
            mf = getattr(ip.flags, "MF", False)
        return mf or (int(ip.frag) > 0)

    def _reassemble_ipv4(self, pkt, inbound_iface: str):
        """
        Buffer IPv4 fragments for datagrams destined to the router.
        Returns a fully reassembled packet when complete, else None.
        """
        ip = pkt[IP]
        key = (ip.src, ip.dst, int(ip.proto), int(ip.id))
        now = time.time()

        # Housekeeping: drop stale buffers
        self._cleanup_reasm(now)

        # Extract fragment info
        try:
            mf = bool(int(ip.flags) & 0x1)
        except Exception:
            mf = getattr(ip.flags, "MF", False)
        off_bytes = int(ip.frag) * self._EIGHT
        frag_payload = bytes(ip.payload)

        with self._reasm_lock:
            st = self._reasm.get(key)
            if not st:
                st = self._reasm[key] = {
                    "first_hdr": ip.copy(),   # keep a copy of the first-seen header (may be non-zero offset; we’ll normalize)
                    "parts": {},
                    "total": None,            # known once we see MF==0 (last fragment)
                    "t0": now,
                    "iface": inbound_iface,
                }

            st["parts"][off_bytes] = frag_payload
            st["t0"] = now  # touch

            if not mf:
                # last fragment => total length is end of this fragment
                st["total"] = off_bytes + len(frag_payload)

            # If we don't have total length yet, we can't know completion
            total = st["total"]
            if total is None:
                return None

            # Check if we have a full contiguous coverage [0, total)
            covered = 0
            while covered in st["parts"]:
                covered += len(st["parts"][covered])

            if covered < total:
                return None

            # Reassemble payload bytes
            assembled_payload = bytearray(total)
            for off, data in st["parts"].items():
                assembled_payload[off:off+len(data)] = data

            # Build a normalized IP datagram with frag/flags cleared
            base = st["first_hdr"].copy()
            base.flags = 0
            base.frag = 0
            # Rebuild as IP()/Raw(...) so Scapy can decode inner (ICMP) again
            full = IP(bytes(base)) / Raw(bytes(assembled_payload))
            try:
                full = IP(bytes(full))  # force full decode
            except Exception:
                pass

            # Done with this buffer
            del self._reasm[key]

            self.log.log_message(f"[ICMP] 🔧 Reassembled IPv4 fragments from {ip.src} → {ip.dst} (len={len(bytes(full))}) on {inbound_iface.split('_')[-1]}")
            return full

    def _cleanup_reasm(self, now: float) -> None:
        with self._reasm_lock:
            dead = []
            for key, st in self._reasm.items():
                if now - st.get("t0", now) > self.REASM_TIMEOUT_SEC:
                    dead.append(key)
            for key in dead:
                st = self._reasm.pop(key, None)
                if st:
                    src, dst, proto, _ = key
                    self.log.log_message(f"[ICMP] ⏳ Reassembly timeout for {src}→{dst} proto={proto} on {st.get('iface')}. Dropping partial datagram.")

    def _log_admin_block(self, pkt, inbound_iface: str):
        icmp = pkt[ICMP]
        inner = icmp.payload
        if IP in inner:
            ip2 = inner[IP]
            l4 = ip2.payload
            sport = getattr(l4, "sport", None)
            dport = getattr(l4, "dport", None)
            proto = "TCP" if TCP in inner else ("UDP" if UDP in inner else str(ip2.proto))
            self.log.log_message(
                f"[ICMP] 🔒 Admin-prohibited on {inbound_iface.split('_')[-1]}: "
                f"{ip2.src}:{sport} → {ip2.dst}:{dport} proto={proto}"
            )
        else:
            self.log.log_message(f"[ICMP] 🔒 Admin-prohibited (no inner IP decode) on {inbound_iface.split('_')[-1]}")
    def _maybe_fragment_and_queue(self, reply_pkt, outbound_iface: str) -> None:
        """
        Ensure reply fits iface MTU. If too large and IPv4, fragment manually.
        """
        # Get iface MTU (fallback 1500)
        try:
            mtu = int(self.ifaces.get(outbound_iface, {}).get("mtu", 1500))
        except Exception:
            mtu = 1500

        raw_len = len(bytes(reply_pkt))
        if raw_len <= mtu:
            self.pw.queue_packet(reply_pkt, outbound_iface)
            return

        # Effective IP MTU subtracting L2 header if present
        l2_overhead = 14 if reply_pkt.haslayer(Ether) else 0
        ip_mtu = max(576, mtu - l2_overhead)  # safe lower bound per IPv4 reassembly

        if not reply_pkt.haslayer(IP):
            # Not IPv4; just send (or drop) — we log and send to keep behavior simple
            self.log.log_message(
                f"[ICMP] ⚠ Oversize non-IPv4 reply ({raw_len}B) > MTU {mtu} on {outbound_iface}; sending as-is.")
            self.pw.queue_packet(reply_pkt, outbound_iface)
            return

        ip_part = reply_pkt[IP].copy()
        # Clear DF if set; for router-originated replies it shouldn't be set anyway
        try:
            if int(ip_part.flags) & 0x2:
                ip_part.flags = int(ip_part.flags) & ~0x2
        except Exception:
            # Scapy flags obj: just force-clear DF by reassigning numeric 0
            ip_part.flags = 0

        try:
            ip_frags = self._ipv4_fragment_datagram(ip_part, ip_mtu)
        except Exception as e:
            self.log.log_message(f"[ICMP] ❌ Fragmentation failed ({e}); sending unfragmented.")
            self.pw.queue_packet(reply_pkt, outbound_iface)
            return

        if reply_pkt.haslayer(Ether):
            eth = reply_pkt[Ether]
            for ipf in ip_frags:
                self.pw.queue_packet(Ether(src=eth.src, dst=eth.dst) / ipf, outbound_iface)
        else:
            for ipf in ip_frags:
                self.pw.queue_packet(ipf, outbound_iface)

        self.log.log_message(
            f"[ICMP] ✂ Fragmented Echo-Reply into {len(ip_frags)} frags for {outbound_iface} (MTU={mtu}, IP-MTU={ip_mtu}).")

    def _ipv4_fragment_datagram(self, ip_pkt: IP, ip_mtu: int):
        """
        Fragment an IPv4 datagram into a list of IP fragments that each fit <= ip_mtu.
        - Honors 8-byte alignment for offsets
        - Clears DF on fragments; sets MF on all but the last
        - Preserves IP id/tos/ttl/proto/options
        - Does NOT touch L4 checksums (correct for fragmentation)
        """
        # Header length (handles options)
        ihl_bytes = int(getattr(ip_pkt, "ihl", 5)) * 4
        if ihl_bytes <= 0:
            ihl_bytes = 20

        # Max payload per fragment must be 8-byte aligned
        max_payload = (max(ip_mtu - ihl_bytes, 0) // 8) * 8
        if max_payload <= 0:
            raise ValueError(f"ip_mtu too small ({ip_mtu}) for header size {ihl_bytes}")

        full_payload = bytes(ip_pkt.payload)  # everything after IP header
        total = len(full_payload)
        frags = []
        offset = 0

        while offset < total:
            chunk = full_payload[offset: offset + max_payload]
            more = (offset + len(chunk)) < total

            frag = IP(
                version=ip_pkt.version,
                ihl=ip_pkt.ihl,
                tos=ip_pkt.tos,
                id=ip_pkt.id,
                flags=0,  # DF cleared on fragments
                frag=offset // 8,  # 8-byte units
                ttl=ip_pkt.ttl,
                proto=ip_pkt.proto,
                src=ip_pkt.src,
                dst=ip_pkt.dst,
                options=getattr(ip_pkt, "options", b"") or b"",
            ) / Raw(chunk)

            if more:
                # set MF
                try:
                    frag.flags = int(frag.flags) | 0x1
                except Exception:
                    frag.flags = 0x1

            # let Scapy recompute len/chksum
            try:
                del frag.len, frag.chksum
            except Exception:
                pass

            frags.append(frag)
            offset += len(chunk)

        return frags
    # ---------- small helpers ----------

    def _match_router_ip(self, dst_ip: str) -> Tuple[bool, Optional[str], Optional[str]]:
        for iface_full_name, cfg in (self.ifaces or {}).items():
            if cfg.get("ip_addr") == dst_ip:
                return True, cfg.get("mac"), cfg.get("ip_addr")
        return False, None, None

    def _is_loopback_name(self, name: str) -> bool:
        n = (name or "").lower()
        return "loopback" in n or n == "lo"