import hashlib
import hmac
import math
import os
import queue
import random
import re
import socket
import string
import struct
import traceback
from collections import defaultdict, deque
from collections.abc import Set
from typing import Optional, List, Any, Callable, Union
import ipaddress
import threading
import json
import time
import numpy as np
from scapy.arch import get_if_hwaddr
from scapy.contrib.ikev2 import IKEv2
from scapy.fields import StrLenField
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import TCP, ICMP, defrag
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6TimeExceeded, \
    ICMPv6ParamProblem, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6Unknown, ICMPv6PacketTooBig, IPv6ExtHdrHopByHop, ICMPv6ND_RA, \
    ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, ICMPv6ND_RS, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment
from scapy.layers.l2 import ARP, Ether, Dot1Q, getmacbyip
from scapy.libs.rfc3961 import Key
from scapy.packet import Packet, Raw, NoPayload
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict
from scapy.layers.kerberos import (
    Kerberos,
    EncryptedData
)

from p2pool_router_managers_2 import TLSRecordManager, TLSRecord
from p2pool_sniffer import MLDQuery, MLDReport, MLDDone, ICMPv6
from tools.pythontools import yield_no_gil
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

FlowEnd = tuple[str, int]
FlowKey = tuple[FlowEnd, FlowEnd]


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
            self.logger.log_message(f"[SendBack] ❗ Failed to send back packet:\n{tb}/ERROR:{e}")

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
            self.logger.log_message(f"[SendBack] ❗ Error sending ICMP packet:\n{tb}/ERROR{e}")

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
            self.logger.log_message(f"[PacketCatcher] ⚠️ Error parsing HTTP payload: {e}")
            return None, None

    def _should_catch(self, status_code, content_type, payload: bytes) -> bool:
        """
        Determines whether a payload should be flagged based on heuristics.
        """
        # --- Heuristic 1: Status code in error range ---
        if status_code is not None and 400 <= status_code < 600:
            self.logger.log_message(f"[PacketCatcher] 🔍 Status code {status_code} indicates error.")
            return True

        # --- Heuristic 2: Readable content type ---
        if content_type in self.readable_content_types:
            self.logger.log_message(f"[PacketCatcher] 📄 Content-Type '{content_type}' is readable.")
            return True
        payload_array = None
        # --- Heuristic 3: Printable character ratio ---
        try:
            payload_array = np.frombuffer(payload, dtype=np.uint8)
            printable_bytes = set(bytes(string.printable, 'utf-8'))
            printable_ratio = np.mean([b in printable_bytes for b in payload_array])

            if printable_ratio > 0.9:
                self.logger.log_message(
                    f"[PacketCatcher] ✨ Printable ratio {printable_ratio:.2f} suggests plaintext.")
                return True
        except ValueError:
            # Handle cases where payload cannot be converted to a numpy array
            pass

        # --- Heuristic 4: Entropy check ---
        unique, counts = np.unique(payload_array, return_counts=True)
        probs = counts / counts.sum()
        entropy = -np.sum(probs * np.log2(probs))
        try:


            if entropy < 4.0:
                self.logger.log_message(
                    f"[PacketCatcher] 📉 Low entropy {entropy:.2f} suggests unencrypted data.")
                return True
        except Exception as e:
            self.logger.log_message(
                f"[PacketCatcher] 📉 Error {e}")
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

class TransportHTTPManager:
    def __init__(self, logger): self.logger = logger
    def handle(self, pkt, src, dst, sport, dport):
        self.logger.log_message(f"[Transport][🧵 TCP][🌐 HTTP] Port 80 traffic detected from {src}:{sport} to {dst}:{dport}.")

class TransportSSHManager:
    def __init__(self, logger): self.logger = logger
    def handle(self, pkt, src, dst, sport, dport):
        self.logger.log_message(f"[Transport][🧵 TCP][💻 SSH] Port 22 traffic detected from {src}:{sport} to {dst}:{dport}.")

class TransportFTPManager:
    def __init__(self, logger): self.logger = logger
    def handle(self, pkt, src, dst, sport, dport):
        self.logger.log_message(f"[Transport][🧵 TCP][📁 FTP] Port 21 (Control) traffic detected from {src}:{sport} to {dst}:{dport}.")

class TransportRDPManager:
    def __init__(self, logger): self.logger = logger
    def handle(self, pkt, src, dst, sport, dport):
        self.logger.log_message(f"[Transport][🧵 TCP][🖥️ RDP] Port 3389 traffic detected from {src}:{sport} to {dst}:{dport}.")


class TransportHTTPSManager:
    """
    HTTPS/TLS transport handler (callback-safe, single-threaded).

    Public API:
      - handle(packet, inbound_iface) -> bool
      - snapshot_metrics() -> dict
    """

    def __init__(
        self,
        logger,
        *,
        detect_non443_tls: bool = False,   # OFF by default to avoid scanning every TCP flow
        max_bytes_to_peek: int = 512,      # cap for memoryview peeks (no large copies)
        logging_enabled: bool = True,      # kill switch for inline logging
        report_tcp_meta: bool = True,      # log TCP flags/options/window/MSS/SACK
        report_tls_record: bool = True,    # log TLS record header (ct, version, len)
        report_tls_meta: bool = True,      # log ClientHello SNI/ALPN/counters
        compute_ja3: bool = False,         # optional JA3 for ClientHello
        # New: cache SNI so it's logged on EVERY packet after first parse
        flow_cache_ttl: int = 15 * 60,     # seconds to keep flow cache entries
        flow_cache_max: int = 50000,       # soft cap to avoid unbounded growth
    ):
        self.logger = logger
        self.detect_non443_tls = bool(detect_non443_tls)
        self._peek_cap = int(max_bytes_to_peek)
        self.logging_enabled = bool(logging_enabled)
        self.report_tcp_meta = bool(report_tcp_meta)
        self.report_tls_record = bool(report_tls_record)
        self.report_tls_meta = bool(report_tls_meta)
        self.compute_ja3 = bool(compute_ja3)

        self.flow_cache_ttl = int(flow_cache_ttl)
        self.flow_cache_max = int(flow_cache_max)

        # Flow cache keyed by canonical 4-tuple ((ip,port),(ip,port)) sorted
        # value: {"sni": str|None, "alpn": list|None, "ja3": str|None, "first": ts, "last": ts}
        self._tls_flows = {}

        # Single-threaded counters
        self._metrics = {
            "https_seen": 0,
            "tls_non443_seen": 0,
            "client_hello_seen": 0,
            "errors": 0,
            "sni_parsed": 0,
            "sni_cache_hits": 0,
            "flow_cache_evictions": 0,
        }

        self._safe_log("[Transport][🔒 HTTPS] Manager ready")

    # ---------------------------
    # Public entrypoint
    # ---------------------------
    def handle(self, packet, inbound_iface: str) -> bool:
        """
        Fast, non-blocking hot path. Returns True if the packet looks like HTTPS/TLS
        (port 443 by default, optional off-443 via cheap TLS signature).
        Logs exactly ONCE per packet with all available metadata, and ALWAYS prints SNI
        if we have it cached (or we can parse it from this packet).
        """
        try:
            if not self._pre_checks(packet):
                return False

            src_ip, dst_ip = self._resolve_ips(packet)
            sport, dport = self._resolve_ports(packet)

            on_443 = (sport == 443) or (dport == 443)
            if not on_443:
                if not self.detect_non443_tls:
                    return False
                if not self._cheap_tls_signature(packet):
                    return False

            # Canonical, direction-agnostic flow key
            fkey = self._flow_key(src_ip, sport, dst_ip, dport)
            now = time.time()
            state = self._tls_flows.get(fkey)
            if state is None:
                state = {"sni": None, "alpn": None, "ja3": None, "first": now, "last": now}
                self._tls_flows[fkey] = state
            else:
                state["last"] = now

            # ---- Try to parse ClientHello ONLY if we don't have SNI yet (cheap) ----
            ch = None
            if (state.get("sni") is None) and getattr(self, "report_tls_meta", False):
                ch = self._peek_client_hello_rich(packet)
                if ch and ch.get("client_hello"):
                    self._metrics["client_hello_seen"] += 1
                    if ch.get("sni"):
                        state["sni"] = ch.get("sni")
                        self._metrics["sni_parsed"] += 1
                    if ch.get("alpn"):
                        state["alpn"] = ch.get("alpn")
                    if ch.get("ja3"):
                        state["ja3"] = ch.get("ja3")

            sni_for_log = state.get("sni") or "-"
            if sni_for_log != "-":
                self._metrics["sni_cache_hits"] += 1

            # ---- Gather details, but DO NOT log yet ----
            parts = []

            # Baseline with SNI ALWAYS included
            parts.append(
                f"{'443' if on_443 else 'non-443 TLS'} "
                f"{src_ip}:{sport} → {dst_ip}:{dport} on {self._iface_suffix(inbound_iface)} "
                f"SNI={sni_for_log}"
            )

            # TCP meta (header-only)
            if getattr(self, "report_tcp_meta", False):
                tmeta = self._peek_tcp_meta(packet)
                if tmeta:
                    parts.append(
                        "tcp{"
                        f"flags={tmeta.get('flags', '-')},"
                        f"win={tmeta.get('win', '-')},"
                        f"ws={tmeta.get('wscale', '-')},"
                        f"mss={tmeta.get('mss', '-')},"
                        f"sack={tmeta.get('sack_perm', '-')}"
                        "}"
                    )

            # TLS record header (first 5 bytes)
            if getattr(self, "report_tls_record", False):
                rhead = self._peek_tls_record_header(packet)
                if rhead:
                    parts.append(
                        f"tlsrec{{ct={rhead['ct']},v={rhead['version']},len={rhead['length']}}}"
                    )

            # ClientHello meta (OPTIONAL extra detail — SNI is already in baseline)
            if getattr(self, "report_tls_meta", False) and ch and ch.get("client_hello"):
                vname = ch.get("version") or "-"
                suites = ch.get("cipher_suites_count", 0)
                exts = ch.get("extensions_count", 0)
                groups = ch.get("groups_count", 0)
                alpn_compact = self._compact_list(ch.get("alpn") or [], max_items=4)
                ja3 = ch.get("ja3")
                ch_part = (
                    f"ch{{v={vname},ALPN={alpn_compact},suites≈{suites},exts≈{exts},groups≈{groups}"
                )
                if ja3:
                    ch_part += f",ja3={ja3}"
                ch_part += "}"
                parts.append(ch_part)

            # ---- Log exactly once ----
            self._safe_log("[Transport][🧵 TCP][🔒 HTTPS] " + " | ".join(parts))

            # metrics last
            if on_443:
                self._metrics["https_seen"] += 1
            else:
                self._metrics["tls_non443_seen"] += 1

            # Opportunistic cleanup (cheap)
            if (len(self._tls_flows) > self.flow_cache_max) or (self._metrics["https_seen"] % 4096 == 0):
                self._cleanup_flow_cache(now)

            return True

        except Exception:
            self._metrics["errors"] += 1
            return False

    # ---------------------------
    # Metrics
    # ---------------------------
    def snapshot_metrics(self) -> dict:
        return dict(self._metrics)

    # ---------------------------
    # Flow cache
    # ---------------------------
    def _flow_key(self, src_ip: str, sport: int, dst_ip: str, dport: int) -> tuple[str, ...]:
        a = (str(src_ip), str(int(sport)))
        b = (str(dst_ip), str(int(dport)))
        first, second = (a, b) if a <= b else (b, a)
        return first + second  # ('ip1','port1','ip2','port2')

    def _cleanup_flow_cache(self, now_ts: float):
        ttl = self.flow_cache_ttl
        if ttl <= 0 or not self._tls_flows:
            return
        before = len(self._tls_flows)
        # Drop stale entries
        stale = [k for k, v in self._tls_flows.items() if now_ts - v.get("last", now_ts) > ttl]
        for k in stale:
            self._tls_flows.pop(k, None)
        # Soft cap: if still too big, drop oldest extras
        if len(self._tls_flows) > self.flow_cache_max:
            excess = len(self._tls_flows) - self.flow_cache_max
            # sort by last seen ascending
            victims = sorted(self._tls_flows.items(), key=lambda kv: kv[1].get("last", 0.0))[:excess]
            for k, _ in victims:
                self._tls_flows.pop(k, None)
        evicted = before - len(self._tls_flows)
        if evicted > 0:
            self._metrics["flow_cache_evictions"] += evicted

    # ---------------------------
    # Helpers (hot-path safe)
    # ---------------------------
    def _compact_list(self, items, max_items=4):
        try:
            if not items:
                return "-"
            items = [str(x) for x in items if x is not None]
            if len(items) <= max_items:
                return ",".join(items) if items else "-"
            extra = len(items) - max_items
            return ",".join(items[:max_items]) + f",+{extra}"
        except Exception:
            return "-"

    def _pre_checks(self, pkt) -> bool:
        if TCP is None:
            return False
        if not pkt or not pkt.haslayer(TCP):
            return False
        return pkt.haslayer(IP) or pkt.haslayer(IPv6)

    def _resolve_ips(self, pkt):
        if IP is not None and pkt.haslayer(IP):
            ip = pkt[IP]
            return getattr(ip, "src", "0.0.0.0"), getattr(ip, "dst", "0.0.0.0")
        if IPv6 is not None and pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            return getattr(ip6, "src", "::"), getattr(ip6, "dst", "::")
        return "0.0.0.0", "0.0.0.0"

    def _resolve_ports(self, pkt):
        t = pkt[TCP]
        try:
            sport = int(getattr(t, "sport", 0) or 0)
        except Exception:
            sport = 0
        try:
            dport = int(getattr(t, "dport", 0) or 0)
        except Exception:
            dport = 0
        return sport, dport

    def _cheap_tls_signature(self, pkt) -> bool:
        if Raw is None or not pkt.haslayer(Raw):
            return False
        try:
            raw = pkt[Raw].load
            if not raw or len(raw) < 6:
                return False
            mv = memoryview(raw)
            ct = mv[0]
            ver = (mv[1] << 8) | mv[2]
            if ver not in (0x0301, 0x0302, 0x0303, 0x0304):
                return False
            if ct not in (0x16, 0x17, 0x14):
                return False
            return (ct != 0x16) or (mv[5] == 0x01)
        except Exception:
            return False

    def _peek_tcp_meta(self, pkt):
        try:
            t = pkt[TCP]
            flags = t.sprintf("%TCP.flags%")
            win = getattr(t, "window", None)
            opts = getattr(t, "options", []) or []
            wscale = mss = None
            sack_perm = False
            for name, val in opts:
                n = (name or "").lower()
                if n == "wscale":
                    try: wscale = int(val)
                    except Exception: wscale = None
                elif n == "mss":
                    try: mss = int(val)
                    except Exception: mss = None
                elif n == "sackok":
                    sack_perm = True
            return {"flags": flags, "win": win, "wscale": wscale, "mss": mss, "sack_perm": sack_perm}
        except Exception:
            return None

    def _peek_tls_record_header(self, pkt):
        if Raw is None or not pkt.haslayer(Raw):
            return None
        try:
            raw = pkt[Raw].load
            if not raw or len(raw) < 5:
                return None
            mv = memoryview(raw)
            ct = mv[0]
            ver = (mv[1] << 8) | mv[2]
            if ver not in (0x0301, 0x0302, 0x0303, 0x0304):
                return None
            if ct not in (0x16, 0x17, 0x14, 0x15):
                return None
            rlen = (mv[3] << 8) | mv[4]
            if not (0 < rlen <= 18432):
                return None
            return {"ct": self._tls_ct_name(ct), "version": self._tls_version_name(ver), "length": int(rlen)}
        except Exception:
            return None

    def _peek_client_hello_rich(self, pkt) -> Optional[dict]:
        if Raw is None or not pkt.haslayer(Raw):
            return None
        try:
            raw = pkt[Raw].load
            if not raw or len(raw) < 6:
                return None
            mv = memoryview(raw)
            if mv[0] != 0x16:
                return None

            cap = min(self._peek_cap, len(mv))
            rec_len = (mv[3] << 8) | mv[4]
            if rec_len + 5 > cap:
                return {"client_hello": True} if mv[5] == 0x01 else None

            p = 5
            if p + 4 > cap or mv[p] != 0x01:
                return None
            p += 1
            hs_len = ((mv[p] << 16) | (mv[p+1] << 8) | mv[p+2]); p += 3

            # client_version
            if p + 2 > cap: return {"client_hello": True}
            ver_major, ver_minor = mv[p], mv[p+1]; p += 2
            version_name = self._tls_version_tuple_name((ver_major, ver_minor))

            # random(32)
            p += 32
            if p >= cap: return {"client_hello": True, "version": version_name}

            # session id
            sid_len = mv[p]; p += 1 + sid_len
            if p + 2 > cap: return {"client_hello": True, "version": version_name}

            # cipher suites
            cs_len = (mv[p] << 8) | mv[p+1]; p += 2
            cs_count = cs_len // 2
            cs_start = p
            p += cs_len
            if p >= cap: return {"client_hello": True, "version": version_name, "cipher_suites_count": cs_count}

            # compression
            comp_len = mv[p]; p += 1 + comp_len
            if p + 2 > cap: return {"client_hello": True, "version": version_name, "cipher_suites_count": cs_count}

            # extensions
            ext_total = (mv[p] << 8) | mv[p+1]; p += 2
            end_ext = min(p + ext_total, cap)

            sni = None
            alpn = []
            exts_count = 0
            groups_count = 0

            ja3_exts = []
            ja3_groups = []
            ja3_ecpf = []

            while p + 4 <= end_ext:
                etype = (mv[p] << 8) | mv[p+1]
                elen  = (mv[p+2] << 8) | mv[p+3]
                p += 4
                if p + elen > end_ext:
                    break
                edata = mv[p:p+elen]
                exts_count += 1
                ja3_exts.append(str(etype))

                if etype == 0x0000 and elen >= 5:  # SNI
                    if len(edata) >= 2:
                        snl = (edata[0] << 8) | edata[1]
                        q = 2; limit = min(2 + snl, len(edata))
                        while q + 3 <= limit:
                            name_type = edata[q]
                            name_len  = (edata[q+1] << 8) | edata[q+2]
                            q += 3
                            if q + name_len > limit:
                                break
                            if name_type == 0:
                                try:
                                    sni = bytes(edata[q:q+name_len]).decode("idna", errors="ignore")
                                except Exception:
                                    sni = None
                                break
                            q += name_len

                elif etype == 0x0010 and elen >= 2:  # ALPN
                    if len(edata) >= 2:
                        list_len = (edata[0] << 8) | edata[1]
                        q = 2; limit = min(2 + list_len, len(edata))
                        while q < limit:
                            if q >= limit: break
                            nlen = edata[q]; q += 1
                            if q + nlen > limit: break
                            try:
                                alpn.append(bytes(edata[q:q+nlen]).decode("ascii", errors="ignore"))
                            except Exception:
                                pass
                            q += nlen

                elif etype == 0x000a and elen >= 2:  # supported_groups
                    if len(edata) >= 2:
                        glen = (edata[0] << 8) | edata[1]
                        q = 2; limit = min(2 + glen, len(edata))
                        while q + 1 < limit:
                            g = (edata[q] << 8) | edata[q+1]
                            ja3_groups.append(str(g))
                            groups_count += 1
                            q += 2

                elif etype == 0x000b and elen >= 1:  # ec_point_formats
                    q = 1
                    limit = len(edata)
                    while q < limit:
                        ja3_ecpf.append(str(edata[q]))
                        q += 1

                p += elen

            ja3_hash = None
            if self.compute_ja3:
                try:
                    ciphers = []
                    end_cs = min(cs_start + cs_len, cap)
                    q = cs_start
                    while q + 1 < end_cs:
                        cid = (mv[q] << 8) | mv[q+1]
                        ciphers.append(str(cid))
                        q += 2
                    vnum = (ver_major << 8) | ver_minor
                    ja3_str = f"{vnum},{'-'.join(ciphers)},{'-'.join(ja3_exts)},{'-'.join(ja3_groups)},{'-'.join(ja3_ecpf)}"
                    ja3_hash = hashlib.md5(ja3_str.encode("ascii", errors="ignore")).hexdigest()
                except Exception:
                    ja3_hash = None

            out = {
                "client_hello": True,
                "version": version_name,
                "cipher_suites_count": cs_count,
                "extensions_count": exts_count,
                "alpn": alpn or None,
                "groups_count": groups_count,
            }
            if sni: out["sni"] = sni
            if ja3_hash: out["ja3"] = ja3_hash
            return out

        except Exception:
            return None

    # ---------------------------
    # Tiny utilities
    # ---------------------------
    def _iface_suffix(self, inbound_iface: str) -> str:
        try:
            return inbound_iface.split("_")[-1]
        except Exception:
            return inbound_iface or ""

    def _safe_log(self, msg: str):
        if not self.logging_enabled:
            return
        try:
            self.logger.log_message(msg)
        except Exception:
            pass

    def _tls_ct_name(self, ct: int) -> str:
        return {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "ApplicationData"}.get(ct, hex(ct))

    def _tls_version_name(self, ver: int) -> str:
        if (ver >> 8) != 0x03:
            return f"0x{ver:04x}"
        return {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}.get(ver, f"0x{ver:04x}")

    def _tls_version_tuple_name(self, tup) -> str:
        try:
            mj, mn = tup
            if mj != 3:
                return f"{mj}.{mn}"
            return {1: "TLS1.0", 2: "TLS1.1", 3: "TLS1.2", 4: "TLS1.3"}.get(mn, f"TLS(3,{mn})")
        except Exception:
            return "-"



class TransportMoneroManager:
    """
    Unified Monero transport observer + policy engine.

    Observes Monero traffic and returns a policy decision:
      • P2P (Levin over TCP): default ports 18080/28080/38080
      • RPC (HTTP JSON-RPC over TCP): default ports 18081/28081/38081

    Design goals:
      - Single public handle(pkt, src, dst, sport, dport, inbound_iface) -> 'allow'|'deny'
      - Preserve your RPC detection/telemetry structure and logs
      - Robust Levin P2P framing with human-friendly logs
      - Passive by default; parser failures are swallowed
      - Optional auto-reply to Levin PING keep-alives (built-in tx)
      - Rate-limited logging; idle flow cleanup
    """

    DEFAULT_P2P_PORTS = {18080, 28080, 38080}
    DEFAULT_RPC_PORTS = {18081, 28081, 38081}

    # ---- Levin constants ----
    _LEVIN_SIG   = 0x0101010101010101
    _LEVIN_BEGIN = 0x01
    _LEVIN_END   = 0x02
    _LEVIN_REQ   = 0x04
    _LEVIN_RSP   = 0x08
    _LEVIN_OK    = 1
    _CMD_PING    = 1000

    class _LevinMessage:
        __slots__ = ("cmd", "flags", "ret", "pv", "cb", "payload",
                     "begin", "end", "req", "rsp")

        def __init__(self, cmd: int, flags: int, ret: int, pv: int, cb: int, payload: bytes):
            self.cmd, self.flags, self.ret, self.pv, self.cb, self.payload = cmd, flags, ret, pv, cb, payload
            self.begin = bool(flags & TransportMoneroManager._LEVIN_BEGIN)
            self.end   = bool(flags & TransportMoneroManager._LEVIN_END)
            self.req   = bool(flags & TransportMoneroManager._LEVIN_REQ)
            self.rsp   = bool(flags & TransportMoneroManager._LEVIN_RSP)

        def kind(self) -> str:
            return "REQ" if self.req else ("RSP" if self.rsp else "DATA")

    class _LevinParser:
        """Minimal Levin bucket_head2 parser (little-endian, 33-byte header)."""
        SIG  = 0x0101010101010101
        HLEN = 33
        HFMT = "<QQBIiII"          # (Q sig, Q cb, B not_used, I cmd, i ret, I flags, I pv)
        CB_MAX = 16 * 1024 * 1024  # 16 MiB

        CMD_NAMES = {
            1000: "COMMAND_PING",
            1001: "COMMAND_HANDSHAKE",
            1002: "COMMAND_TIMED_SYNC",
            2001: "NOTIFY_NEW_BLOCK",
            2002: "NOTIFY_NEW_TRANSACTIONS",
            2003: "NOTIFY_REQUEST_GET_OBJECTS",
            2004: "NOTIFY_RESPONSE_GET_OBJECTS",
            2006: "NOTIFY_REQUEST_CHAIN",
            2007: "NOTIFY_RESPONSE_CHAIN_ENTRY",
        }

        def __init__(self):
            self._buf = bytearray()

        @classmethod
        def cmd_name(cls, cmd: int) -> str:
            return cls.CMD_NAMES.get(cmd, f"CMD({cmd})")

        def feed(self, data: bytes) -> List["TransportMoneroManager._LevinMessage"]:
            if not data:
                return []
            self._buf += data
            out: List[TransportMoneroManager._LevinMessage] = []
            mv = memoryview(self._buf)
            off = 0
            while True:
                if len(mv) - off < self.HLEN:
                    break
                try:
                    sig, cb, _retbyte, cmd, ret, flags, pv = struct.unpack_from(self.HFMT, mv, off)
                except struct.error:
                    break
                if sig != self.SIG:
                    off += 1; continue
                if cb < 0 or cb > self.CB_MAX:
                    off += 1; continue
                need = self.HLEN + cb
                if len(mv) - off < need:
                    break
                payload = bytes(mv[off + self.HLEN: off + need])
                out.append(TransportMoneroManager._LevinMessage(cmd, flags, ret, pv, cb, payload))
                off += need
            if off:
                self._buf = bytearray(mv[off:].tobytes())
            return out

    def __init__(
        self,
        logger,
        *,
        extra_p2p_ports: Optional[List[int]] = None,
        extra_rpc_ports: Optional[List[int]] = None,
        max_payload_sample: int = 128,
        flow_idle_timeout: int = 15 * 60,
        msg_rate_window: float = 3.0,
        # Built-in auto-reply to Levin keep-alives (PING)
        p2p_auto_reply_ping: bool = True,
        # Optional: allow overriding the tx function; if None, use built-in
        tx_cb: Optional[Callable[[dict, bytes, str], bool]] = None,
    ):
        self.logger = logger
        self.max_payload_sample = int(max_payload_sample)
        self.flow_idle_timeout = int(flow_idle_timeout)

        self._p2p_ports = set(self.DEFAULT_P2P_PORTS)
        self._rpc_ports = set(self.DEFAULT_RPC_PORTS)
        if extra_p2p_ports:
            self._p2p_ports.update(int(p) for p in extra_p2p_ports if self._is_valid_port(p))
        if extra_rpc_ports:
            self._rpc_ports.update(int(p) for p in extra_rpc_ports if self._is_valid_port(p))

        self._flows: dict = {}  # key -> flow dict
        self._recent_msgs = defaultdict(float)
        self._recent_msg_window = float(msg_rate_window)

        self.p2p_auto_reply_ping = bool(p2p_auto_reply_ping)
        self._tx_cb = tx_cb  # may be None; we fall back to _default_tx_bytes

        self.logger.log_message("[Transport][⛏️ Monero] Manager ready.")

    # ========== Public entrypoint ==========
    def handle(self, pkt, src, dst, sport, dport, inbound_iface) -> str:
        if not self._is_tcp(pkt):
            return 'allow'

        sport = int(sport); dport = int(dport)
        now = time.time()
        key = self._flow_key(src, sport, dst, dport)

        flow = self._flows.get(key)
        if not flow:
            # classify by static ports, then by payload if needed
            flow_type = self._classify_flow_type(sport, dport)
            if not flow_type:
                payload = self._get_payload_bytes(pkt)
                flow_type = self._dynamic_classify_from_payload(payload)
            if not flow_type:
                return 'allow'

            flow = self._new_flow(src, sport, dst, dport, inbound_iface, now, flow_type)
            self._flows[key] = flow

        self._update_flow_state(flow, pkt, now, inbound_iface)
        decision, reason = self._apply_policy(flow, pkt)
        self._perform_detailed_logging(flow, pkt, inbound_iface)

        if decision == 'deny':
            self._rate_limited_log(
                f"[Transport][🪙 Monero] ⛔ DENY {flow['type'].upper()} "
                f"{src}:{sport} -> {dst}:{dport} | {reason}"
            )

        self._cleanup_idle(now)
        return decision

    # ========== Policy ==========
    def _apply_policy(self, flow: dict, pkt) -> Tuple[str, str]:
        payload_len = len(self._get_payload_bytes(pkt))

        if flow['type'] == 'p2p':
            if flow.get('state') == 'ESTABLISHED' and not flow.get('synack_seen') and payload_len > 0:
                return 'deny', "P2P data before handshake completion"

        if flow['type'] == 'rpc':
            self._rpc_parse_and_log(flow, pkt, "policy_check")
            if flow.get('rpc_last_method') == 'get_block_template':
                self.logger.log_message("[Transport][🪙 Monero][POLICY] ℹ️ Mining activity detected on flow.")

        return 'allow', "default allow"

    # ========== Flow state ==========
    def _update_flow_state(self, flow: dict, pkt, now: float, iface: str):
        flags = self._tcp_flags(pkt)
        payload_len = len(self._get_payload_bytes(pkt))

        flow["last_seen"]  = now
        flow["last_iface"] = iface
        flow["pkts"]       = flow.get("pkts", 0) + 1
        flow["bytes"]      = flow.get("bytes", 0) + payload_len
        flow["last_flags"] = flags
        flags = self._tcp_flags(pkt)
        payload_len = len(self._get_payload_bytes(pkt))

        # ✅ SAFE: Extract data immediately and store the copies
        flow["last_flags"] = flags
        tcp_opts = self._parse_tcp_opts(pkt.getlayer(TCP))  # Get data now
        flow["last_tcp_opts"] = tcp_opts  # Store the resulting dictionary

        d = self._pkt_dir(flow, pkt)
        if d: flow["last_dir"] = d

        st = flow.get("state", "INIT")
        if 'S' in flags and 'A' not in flags:
            flow['state'] = 'SYN_SENT'; flow['syn_seen'] = True
        elif 'S' in flags and 'A' in flags:
            if st == 'SYN_SENT':
                flow['state'] = 'ESTABLISHED'
            flow['synack_seen'] = True
        elif st == 'SYN_SENT' and 'A' in flags and payload_len == 0:
            flow['state'] = 'ESTABLISHED'
        elif 'F' in flags or 'R' in flags:
            flow['state'] = 'CLOSED'; flow['fin_or_rst'] = True

    @staticmethod
    def _new_flow(src, sport, dst, dport, iface, now_ts, flow_type: str):
        return {
            "type": flow_type,                     # "p2p" or "rpc"
            "state": "INIT",
            "endpoints": ((src, int(sport)), (dst, int(dport))),
            "created": now_ts,
            "last_seen": now_ts,
            "last_iface": iface,
            "syn_seen": False,
            "synack_seen": False,
            "fin_or_rst": False,
            "pkts": 0,
            "bytes": 0,
            "first_sample": None,
            "entropy": None,
            "last_flags": "",
            "last_pkt": None,
            "last_dir": None,          # "a2b" or "b2a"
            # RPC rolling state
            "rpc_buf_c2s": bytearray(),
            "rpc_buf_s2c": bytearray(),
            "rpc_seen_req": 0,
            "rpc_seen_rsp": 0,
            "rpc_last_status": None,
            "rpc_last_method": None,   # JSON "method" preferred; else HTTP verb fallback
            "rpc_last_path": None,
            "rpc_last_host": None,
            # P2P rolling state
            "p2p_parser": None,
            "p2p_frames_logged": 0,
            # Built-in TX sockets (optional)
            "client_sock": None,       # send to A (direction "b2a")
            "server_sock": None,       # send to B (direction "a2b")
        }

    def _cleanup_idle(self, now_ts):
        if not self._flows:
            return
        dead = [k for k, f in self._flows.items()
                if now_ts - f.get("last_seen", now_ts) > self.flow_idle_timeout]
        for k in dead:
            self._flows.pop(k, None)

    # ========== Logging + parsing ==========
    def _perform_detailed_logging(self, f: dict, pkt, iface: str):
        flags = f.get("last_flags", "")
        payload = self._get_payload_bytes(pkt)
        plen = len(payload)

        if "S" in flags and "A" not in flags and f.get('state') == 'SYN_SENT' and f.get('pkts', 0) == 1:
            self._on_syn(f, flags, iface)
        elif "S" in flags and "A" in flags:
            self._on_syn_ack(f, flags, iface)
        elif "F" in flags or "R" in flags:
            self._on_fin_rst(f, flags, iface)

        if plen > 0:
            if f["first_sample"] is None:
                sample = payload[:self.max_payload_sample]
                f["first_sample"] = sample
                f["entropy"] = self._byte_entropy(sample)
                self._log_first_data(f, sample, iface)
            else:
                rh = f.get("rolling_sha")
                if rh:
                    rh.update(payload[: min(len(payload), self.max_payload_sample)])
                self._maybe_progress_log(f)

            if f["type"] == "rpc":
                self._rpc_parse_and_log(f, pkt, iface)

            if f["type"] == "p2p":
                direction = self._pkt_dir(f, pkt) or f.get("last_dir")
                if direction: f["last_dir"] = direction
                self._p2p_feed_and_log(f, payload, iface, direction)

    # ---- TCP lifecycle logs ----
    def _on_syn(self, f, flags, iface):
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        tcp = None
        try:
            tcp = getattr(f.get("last_pkt"), "getlayer", lambda _: None)(TCP) if f.get("last_pkt") else None
        except Exception:
            tcp = None
        syn_opts = self._parse_tcp_opts(tcp) if tcp else {}
        win = getattr(tcp, "window", None) if tcp else None
        f["syn_opts"] = syn_opts
        f["win_init"] = int(win) if isinstance(win, int) else None
        f["syn_ts"] = time.time()

        mss = syn_opts.get("mss"); ws = syn_opts.get("ws"); sack = syn_opts.get("sack"); ts = syn_opts.get("ts")
        ts_str = f" ts={ts[0]}/{ts[1]}" if ts else ""
        win_str = f" win={f['win_init']}" if f.get("win_init") else ""
        ws_str = f" ws={ws}" if ws is not None else ""
        mss_str = f" mss={mss}" if mss is not None else ""
        sack_str = " sackOK" if sack else ""

        self._rate_limited_log(
            f"[Transport][🧵 TCP][🪙 Monero][{t}] SYN {a[0]}:{a[1]} → {b[0]}:{b[1]} on {iface} "
            f"(flags={flags}{win_str}{ws_str}{mss_str}{sack_str}{ts_str})"
        )

    def _on_syn_ack(self, f, flags, iface):
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        tcp = None
        try:
            tcp = getattr(f.get("last_pkt"), "getlayer", lambda _: None)(TCP) if f.get("last_pkt") else None
        except Exception:
            tcp = None
        synack_opts = self._parse_tcp_opts(tcp) if tcp else {}
        f["synack_opts"] = synack_opts; f["synack_ts"] = time.time()

        rtt_ms = None
        try:
            rtt_ms = (f["synack_ts"] - f.get("syn_ts", f["synack_ts"])) * 1000.0
        except Exception:
            rtt_ms = None

        ws = synack_opts.get("ws"); mss = synack_opts.get("mss"); sack = synack_opts.get("sack"); ts = synack_opts.get("ts")
        bits = []
        if f.get("win_init") is not None: bits.append(f"win={f['win_init']}")
        if ws is not None: bits.append(f"ws={ws}"); f["win_scale"] = ws
        if mss is not None: bits.append(f"mss={mss}")
        if sack: bits.append("sackOK")
        if ts: bits.append(f"ts={ts[0]}/{ts[1]}")
        if rtt_ms is not None: bits.append(f"rtt~{self._fmt_ms(rtt_ms)}")
        extra = (" " + " ".join(bits)) if bits else ""

        self._rate_limited_log(
            f"[Transport][🧵 TCP][🪙 Monero][{t}] SYN/ACK {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface} (flags={flags}{extra})"
        )

    def _on_fin_rst(self, f, flags, iface):
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        dur = time.time() - f.get("created", time.time())
        reason = "RST" if ("R" in flags and "F" not in flags) else "FIN"
        who = f.get("last_dir", "peer?")
        self._rate_limited_log(
            f"[Transport][🧵 TCP][🪙 Monero][{t}] {reason} ✂ {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface} "
            f"(flags={flags}, by={who}, dur={dur:.1f}s, bytes={f.get('bytes', 0)}, pkts={f.get('pkts', 0)})"
        )

    def _log_first_data(self, f, sample: bytes, iface: str):
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        ent = f.get("entropy", 0.0); hint = self._summarize_payload(sample)

        f["rolling_sha"] = hashlib.sha256()
        f["rolling_sha"].update(sample)
        f["last_bytes_ts"] = time.time()

        preview = sample[:32]
        try:
            pv = preview.decode("utf-8", "ignore")
            pv = "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in pv)
        except Exception:
            pv = ""
        pv = f" preview='{pv}'" if pv else ""

        self._rate_limited_log(
            f"[Transport][🧵 TCP][🪙 Monero][{t}] DATA ▶ {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface} "
            f"first={len(sample)}B ent={ent:.2f} {hint}{pv}"
        )

    def _maybe_progress_log(self, f):
        now = time.time()
        f["last_bytes_ts"] = now
        roll = f.get("rolling_sha")
        roll_hex8 = roll.hexdigest()[:8] if roll else "na"
        should_emit = (f.get("pkts", 0) % 50 == 0) or (f.get("bytes", 0) in (1024, 4096, 16384, 65536, 262144))
        if not should_emit:
            return
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        rate = f.get("bytes", 0) / max(1e-3, (now - f.get("created", now)))
        rate_str = f"{rate / 1024:.1f}KB/s" if rate >= 1024 else f"{rate:.0f}B/s"
        self._rate_limited_log(
            f"[Transport][🧵 TCP][🪙 Monero][{t}] DATA ⏩ {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} "
            f"bytes={f.get('bytes', 0)} pkts={f.get('pkts', 0)} rate~{rate_str} roll8={roll_hex8}"
        )

    # ---- RPC: split + hints ----
    def _rpc_parse_and_log(self, f, pkt, iface_or_tag: str):
        (a_ip, a_port), (b_ip, b_port) = f["endpoints"]
        payload = self._get_payload_bytes(pkt)
        c2s = "a2b" if b_port in self._rpc_ports else ("b2a" if a_port in self._rpc_ports else None)
        if c2s == "a2b":
            f["rpc_buf_c2s"] += payload; self._rpc_drain_c2s(f, iface_or_tag)
        elif c2s == "b2a":
            f["rpc_buf_s2c"] += payload; self._rpc_drain_s2c(f, iface_or_tag)

    def _rpc_drain_c2s(self, f, iface_or_tag: str):
        msgs, remaining = self._split_http_messages(f["rpc_buf_c2s"])
        f["rpc_buf_c2s"] = remaining
        for hdrs, body, raw_hdr in msgs:
            f["rpc_seen_req"] += 1
            start = hdrs.get(":start", "")
            host = hdrs.get("host")
            path = self._extract_path_from_start(start)
            http_method = start.split(" ", 1)[0] if start else "?"
            json_method = self._json_method_name(body) if self._looks_like_json(body) else None
            f["rpc_last_method"] = json_method or http_method
            f["rpc_last_path"] = path
            f["rpc_last_host"] = host
            self._rate_limited_log(
                f"[Transport][🧵 TCP][🪙 Monero][RPC] ▶REQ {http_method} {path or ''} host={host or '-'} "
                f"json_method={json_method or '-'} body={len(body)}B"
            )

    def _rpc_drain_s2c(self, f, iface_or_tag: str):
        msgs, remaining = self._split_http_messages(f["rpc_buf_s2c"])
        f["rpc_buf_s2c"] = remaining
        for hdrs, body, raw_hdr in msgs:
            f["rpc_seen_rsp"] += 1
            start = hdrs.get(":start", "")
            status = self._extract_status_from_start(start)
            f["rpc_last_status"] = status
            jhint = "json" if self._looks_like_json(body) else "-"
            self._rate_limited_log(
                f"[Transport][🧵 TCP][🪙 Monero][RPC] ◀RSP status={status or '?'} body={len(body)}B type={jhint}"
            )

    @staticmethod
    def _split_http_messages(buffer: bytearray):
        msgs = []
        view = memoryview(buffer)
        start = 0
        while True:
            hdr_end = TransportMoneroManager._find_double_crlf(view, start)
            if hdr_end < 0:
                break
            raw_hdr = bytes(view[start:hdr_end])
            headers = TransportMoneroManager._parse_headers(raw_hdr)
            content_length = int(headers.get("content-length", "0") or "0")
            body_start = hdr_end + 4
            body_end = body_start + content_length
            if body_end > len(view):
                break
            body = bytes(view[body_start:body_end])
            msgs.append((headers, body, raw_hdr))
            start = body_end
        remaining = bytearray(view[start:].tobytes())
        return msgs, remaining

    @staticmethod
    def _fmt_ms(v) -> str:
        """
        Best-effort formatting of a millisecond float -> '123ms'.
        Returns '-' if v is None / NaN / not a number.
        """
        try:
            if v is None:
                return "-"
            v = float(v)
            if v != v:  # NaN
                return "-"
            return f"{int(round(v))}ms"
        except Exception:
            return "-"

    @staticmethod
    def _summarize_payload(sample: bytes) -> str:
        """
        Classify a TCP payload sample and return a short summary string.
          • Detects HTTP vs TLS record vs ASCII/mixed/binary
          • Adds sha8 fingerprint (first 8 hex chars of SHA256)
        """
        if not sample:
            return "empty"

        def sha8(b: bytes) -> str:
            return hashlib.sha256(b).hexdigest()[:8]

        def ascii_ratio(b: bytes) -> float:
            if not b:
                return 0.0
            printable = sum(1 for x in b if 32 <= x <= 126 or x in (9, 10, 13))
            return printable / len(b)

        def is_http_head(b: bytes) -> bool:
            head = b[:8].upper()
            return (
                    head.startswith(b"GET ")
                    or head.startswith(b"POST ")
                    or head.startswith(b"PUT ")
                    or head.startswith(b"HEAD ")
                    or head.startswith(b"HTTP/")
                    or head.startswith(b"OPTI")  # OPTIONS
                    or head.startswith(b"DELET")  # DELETE
                    or head.startswith(b"PATCH ")
            )

        def is_tls_record(b: bytes) -> bool:
            # TLS ContentType (0x14..0x17), Version = 0x03 0x0x
            return (
                    len(b) >= 3
                    and b[0] in (0x14, 0x15, 0x16, 0x17)
                    and b[1] == 0x03
                    and 0x00 <= b[2] <= 0x05
            )

        hints = []
        if is_http_head(sample):
            hints.append("HTTP")
        elif is_tls_record(sample):
            hints.append("TLS")
        else:
            ar = ascii_ratio(sample)
            if ar >= 0.85:
                hints.append("ASCII")
            elif ar >= 0.4:
                hints.append("mixed")
            else:
                hints.append("binary")

        hints.append(f"sha8={sha8(sample)}")
        return ",".join(hints)

    @staticmethod
    def _parse_tcp_opts(tcp_layer) -> dict:
        """
        Parse a Scapy TCP layer's options into a compact dict:
          {"mss": int|None, "ws": int|None, "sack": bool, "ts": (tsval, tsecr)|None}
        Safe on missing/odd option formats.
        """
        out: Dict[str, Union[bool, int, None]] = {}
        try:
            opts = getattr(tcp_layer, "options", None) or []
            for name, val in opts:
                n = (name or "").strip().lower()
                # MSS
                if n in ("mss",):
                    try:

                        out["mss"] = int(val)
                    except Exception:
                        pass
                # Window scale
                elif n in ("wscale", "ws", "window_scale"):
                    try:
                        out["ws"] = int(val)
                    except Exception:
                        pass
                # SACK permitted
                elif n in ("sackok", "sack_perm", "sack_ok"):
                    out["sack"] = True
                # Timestamps
                elif n in ("timestamp", "ts"):
                    try:
                        # Scapy usually gives (tsval, tsecr)
                        tsval = int(val[0]) if len(val) > 0 else None
                        tsecr = int(val[1]) if len(val) > 1 else None
                        if tsval is not None and tsecr is not None:
                            out["tsval"] = tsval
                            out["tsecr"] = tsecr
                    except Exception:
                        pass
        except Exception:
            pass
        return out

    @staticmethod
    def _find_double_crlf(view: memoryview, start: int) -> int:
        data = view[start:].tobytes()
        idx = data.find(b"\r\n\r\n")
        return -1 if idx < 0 else start + idx

    @staticmethod
    def _parse_headers(raw_hdr: bytes) -> dict:
        text = raw_hdr.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")
        hdrs = {}
        if lines:
            hdrs[":start"] = lines[0]
        for line in lines[1:]:
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        return hdrs

    @staticmethod
    def _looks_like_json(b: bytes) -> bool:
        bb = b.strip()
        return (bb.startswith(b"{") and bb.endswith(b"}")) or (bb.startswith(b"[") and bb.endswith(b"]"))

    @staticmethod
    def _json_method_name(b: bytes):
        try:
            data = json.loads(b.decode("utf-8", errors="replace"))
            if isinstance(data, dict) and isinstance(data.get("method"), str):
                return data["method"]
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_path_from_start(start_line: str) -> Optional[str]:
        try:
            parts = start_line.split()
            return parts[1] if len(parts) >= 2 else None
        except Exception:
            return None

    @staticmethod
    def _extract_status_from_start(start_line: str) -> Optional[str]:
        try:
            parts = start_line.split()
            if len(parts) >= 2 and parts[0].startswith("HTTP/"):
                return parts[1]
            return None
        except Exception:
            return None

    # ---- P2P (Levin) ----
    def _p2p_feed_and_log(self, f: dict, payload: bytes, iface: str, direction: Optional[str]) -> None:
        try:
            if direction:
                f["last_dir"] = direction
            if f.get("p2p_parser") is None:
                f["p2p_parser"] = TransportMoneroManager._LevinParser()
            frames = f["p2p_parser"].feed(payload)
            if frames:
                self._log_levin_frames(f, frames, iface)
        except Exception:
            pass

    def _log_levin_frames(self, f: dict, frames: List["_LevinMessage"], iface: str) -> None:
        a, b = f["endpoints"]
        for m in frames:
            name = TransportMoneroManager._LevinParser.cmd_name(m.cmd)
            bits = []
            if m.begin: bits.append("BEGIN")
            if m.end:   bits.append("END")
            if m.req:   bits.append("REQ")
            if m.rsp:   bits.append("RSP")
            flags_txt = ",".join(bits) if bits else "-"
            preview = (m.payload[:24].hex() + ("…" if m.cb > 24 else "")) if m.cb else "-"
            self._rate_limited_log(
                f"[Transport][🧵 TCP][🪙 Monero][P2P] {m.kind()} {name} "
                f"flags={flags_txt} ret={m.ret} pv={m.pv} len={m.cb} "
                f"preview={preview} {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface}"
            )
            f["p2p_frames_logged"] = f.get("p2p_frames_logged", 0) + 1
            self._maybe_reply_ping(f, m, iface)

    def _maybe_reply_ping(self, f: dict, m: "_LevinMessage", iface: str):
        if not self.p2p_auto_reply_ping:
            return
        if not (m.cmd == self._CMD_PING and m.req and not m.rsp):
            return
        req_dir = f.get("last_dir") or "a2b"
        rsp_dir = "b2a" if req_dir == "a2b" else "a2b"
        pkt_bytes = self._levin_ping_rsp(m.pv)
        if self._send_bytes(f, pkt_bytes, rsp_dir):
            self._rate_limited_log(f"[Transport][🧵 TCP][🪙 Monero][P2P] ◀ sent PING RSP (OK) pv={m.pv} on {iface}")
        else:
            self._rate_limited_log(f"[Transport][🧵 TCP][🪙 Monero][P2P] (no-tx) would reply PING pv={m.pv} on {iface}")

    def _levin_build(self, cmd: int, *, flags: int, pv: int, payload: bytes = b"", ret: int = 0) -> bytes:
        cb = len(payload)
        return struct.pack("<QQBIiII", self._LEVIN_SIG, cb, 0, cmd, int(ret), int(flags), int(pv)) + payload

    def _levin_ping_rsp(self, pv: int) -> bytes:
        return self._levin_build(
            self._CMD_PING,
            flags=(self._LEVIN_RSP | self._LEVIN_BEGIN | self._LEVIN_END),
            pv=int(pv),
            payload=b"",
            ret=self._LEVIN_OK,
        )

    # ========== Built-in TX ==========
    def _send_bytes(self, f: dict, data: bytes, direction: str) -> bool:
        """
        Try user-supplied tx_cb first; otherwise use built-in socket sender.
        direction: "a2b" to B (server_sock), "b2a" to A (client_sock)
        """
        # User override?
        if callable(self._tx_cb):
            try:
                return bool(self._tx_cb(f, data, direction))
            except Exception:
                pass

        # Built-in
        try:
            if direction == "a2b":
                sock = f.get("server_sock")
            else:
                sock = f.get("client_sock")
            if not sock:
                return False
            sock.sendall(data)
            return True
        except Exception:
            return False

    # Public helpers to attach/detach sockets for a flow (self-contained TX)
    def attach_sockets(self, src: str, sport: int, dst: str, dport: int, *,
                       client_sock=None, server_sock=None) -> bool:
        """
        Attach sockets to a flow so the manager can transmit keep-alive replies itself.
        - client_sock: socket writing toward A (used for direction 'b2a')
        - server_sock: socket writing toward B (used for direction 'a2b')
        Returns True if a flow exists/was created and sockets were recorded.
        """
        key = self._flow_key(src, int(sport), dst, int(dport))
        f = self._flows.get(key)
        if not f:
            # create a minimal p2p flow container if not seen yet
            now = time.time()
            f = self._new_flow(src, sport, dst, dport, "sock_attach", now, "p2p")
            self._flows[key] = f
        if client_sock: f["client_sock"] = client_sock
        if server_sock: f["server_sock"] = server_sock
        self._rate_limited_log(
            f"[Transport][🧵 TCP][🪙 Monero][P2P] sockets attached for {src}:{sport} ⇄ {dst}:{dport} "
            f"(client={'yes' if client_sock else 'no'}, server={'yes' if server_sock else 'no'})"
        )
        return True

    def detach_sockets(self, src: str, sport: int, dst: str, dport: int) -> None:
        key = self._flow_key(src, int(sport), dst, int(dport))
        f = self._flows.get(key)
        if f:
            f["client_sock"] = None
            f["server_sock"] = None
            self._rate_limited_log(
                f"[Transport][🧵 TCP][🪙 Monero][P2P] sockets detached for {src}:{sport} ⇄ {dst}:{dport}"
            )

    # ========== Port classification ==========
    def _classify_flow_type(self, sport: int, dport: int) -> Optional[str]:
        if (sport in self._rpc_ports) or (dport in self._rpc_ports):
            return "rpc"
        if (sport in self._p2p_ports) or (dport in self._p2p_ports):
            return "p2p"
        return None

    def _dynamic_classify_from_payload(self, payload: bytes) -> Optional[str]:
        if not payload:
            return None
        if payload.startswith(b'\x01\x01\x01\x01\x01\x01\x01\x01'):
            return "p2p"
        if self._is_http_head(payload):
            return "rpc"
        return None
    def _is_http_head(self, payload: bytes) -> bool:
        """
        Lightweight check: True iff payload looks like an HTTP/1.x HEAD request line.
        Safe for arbitrary TCP payload; no exceptions.
        """
        _HTTP_START_RE = re.compile(
            rb"^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PATCH)\s+([^\s]+)\s+HTTP/\d\.\d\r?\n", re.I)
        if not payload:
            return False
        m = _HTTP_START_RE.match(payload)
        if not m:
            return False
        method = m.group(1).upper()
        return method == b"HEAD"
    # ========== TCP / payload helpers ==========
    @staticmethod
    def _is_tcp(pkt) -> bool:
        return hasattr(pkt, "haslayer") and TCP is not None and pkt.haslayer(TCP)

    @staticmethod
    def _tcp_flags(pkt) -> str:
        try:
            return pkt[TCP].flags.flagrepr()
        except Exception:
            return ""

    @staticmethod
    def _get_payload_bytes(pkt) -> bytes:
        try:
            if hasattr(pkt, "haslayer") and Raw is not None and pkt.haslayer(Raw) and pkt[Raw].load:
                return bytes(pkt[Raw].load)
            pb = bytes(getattr(pkt[TCP], "payload", b"") or b"")
            if pb:
                return pb
        except Exception:
            pass
        return b""

    @staticmethod
    def _flow_key(src, sport, dst, dport):
        a, b = (src, int(sport)), (dst, int(dport))
        return (a, b) if a <= b else (b, a)

    @staticmethod
    def _pkt_dir(f: dict, pkt) -> Optional[str]:
        try:
            sport = int(pkt[TCP].sport); dport = int(pkt[TCP].dport)
            a_port = f["endpoints"][0][1]; b_port = f["endpoints"][1][1]
            if sport == a_port and dport == b_port:
                return "a2b"
            if sport == b_port and dport == a_port:
                return "b2a"
        except Exception:
            pass
        return None

    # ========== Logging control ==========
    def _rate_limited_log(self, msg: str):
        key = hash(msg)
        t = time.time()
        if t - self._recent_msgs[key] >= self._recent_msg_window:
            self._recent_msgs[key] = t
            try:
                self.logger.log_message(msg)
            except Exception:
                pass

    @staticmethod
    def _short_hex(b: bytes, max_len: int) -> str:
        if not b:
            return ""
        out = b[:max_len].hex()
        if len(b) > max_len:
            out += "…"
        return out

    @staticmethod
    def _byte_entropy(b: bytes) -> float:
        if not b:
            return 0.0
        counts = [0] * 256
        for x in b:
            counts[x] += 1
        n = len(b)
        ent = 0.0
        for c in counts:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return ent

    # ========== Management APIs ==========
    def get_active_flows(self):
        return {k: dict(v) for k, v in self._flows.items()}

    def add_candidate_p2p_port(self, port: int):
        if self._is_valid_port(port):
            self._p2p_ports.add(int(port))
            self.logger.log_message(f"[Transport][🪙 Monero] Added P2P port {int(port)}")

    def remove_candidate_p2p_port(self, port: int):
        try:
            self._p2p_ports.discard(int(port))
            self.logger.log_message(f"[Transport][🪙 Monero] Removed P2P port {int(port)}")
        except Exception:
            pass

    def add_candidate_rpc_port(self, port: int):
        if self._is_valid_port(port):
            self._rpc_ports.add(int(port))
            self.logger.log_message(f"[Transport][🪙 Monero] Added RPC port {int(port)}")

    def remove_candidate_rpc_port(self, port: int):
        try:
            self._rpc_ports.discard(int(port))
            self.logger.log_message(f"[Transport][🪙 Monero] Removed RPC port {int(port)}")
        except Exception:
            pass

    @staticmethod
    def _is_valid_port(p) -> bool:
        try:
            p = int(p)
            return 1 <= p <= 65535
        except Exception:
            return False

class TransportSteamManager:
    """
    Observes Valve/Steam traffic and Source-engine queries.

    • Typical TCP (Steam CM/content/friends): 27014–27050
    • Typical UDP (games & SDR): 27000–27100, 4380
    • A2S_* server queries (UDP): usually 27015±n
    • LAN discovery: 27036, 27037 (UDP)

    Public API:
        handle(pkt, src, dst, sport, dport, inbound_iface) -> None
    """

    # --- Port sets (tunable) ---
    TCP_STEAM_RANGE = range(27014, 27051)    # inclusive upper is 27050
    UDP_STEAM_RANGE = range(27000, 27101)
    UDP_EXTRA = {4380}                       # Steam client UDP
    UDP_DISCOVERY = {27036, 27037}           # Steam Link/Big Picture discovery
    UDP_A2S_DEFAULTS = {27015, 27016, 27017, 27018, 27019, 27020}

    # --- A2S markers (Source/GoldSrc) ---
    _FF_FF_FF_FF = b"\xff\xff\xff\xff"      # query preamble
    _A2S_INFO_REQ  = _FF_FF_FF_FF + b"\x54" + b"Source Engine Query\x00"   # \x54 = 'T'
    _A2S_RULES_REQ = _FF_FF_FF_FF + b"\x56"                                  # 'V'
    _A2S_PLAYERS_REQ = _FF_FF_FF_FF + b"\x55"                                # 'U'
    _A2S_CHALLENGE_REQ = _FF_FF_FF_FF + b"\x57"                              # 'W'
    # Responses
    _A2S_INFO_RSP_HDR = b"\x49"    # I
    _A2S_RULES_CHALLENGE = b"\x45" # E
    _A2S_PLAYERS_CHALLENGE = b"\x41" # A
    _A2S_RULES_RSP_HDR = b"\x45"   # E (Rules/Challenge depending on framing)
    _A2S_PLAYERS_RSP_HDR = b"\x44" # D

    def __init__(self, logger, *,
                 extra_tcp_ports=None,
                 extra_udp_ports=None,
                 extra_query_ports=None,
                 max_payload_sample: int = 128,
                 flow_idle_timeout: int = 15 * 60,
                 msg_rate_window: float = 3.0):
        self.log = logger
        self.max_payload_sample = int(max_payload_sample)
        self.flow_idle_timeout = int(flow_idle_timeout)

        # dynamic port sets
        self._tcp_ports = set(self.TCP_STEAM_RANGE)
        if extra_tcp_ports:
            self._tcp_ports.update(int(p) for p in extra_tcp_ports if self._is_valid_port(p))

        self._udp_ports = set(self.UDP_STEAM_RANGE) | set(self.UDP_EXTRA) | set(self.UDP_DISCOVERY)
        if extra_udp_ports:
            self._udp_ports.update(int(p) for p in extra_udp_ports if self._is_valid_port(p))

        self._query_ports = set(self.UDP_A2S_DEFAULTS)
        if extra_query_ports:
            self._query_ports.update(int(p) for p in extra_query_ports if self._is_valid_port(p))

        # flows cache (TCP and UDP conversations)
        self._flows = {}
        self._recent_msgs = defaultdict(float)
        self._recent_window = float(msg_rate_window)

        self.log.log_message("[Transport][🎮 Steam] Manager ready.")

    # -------------------- Public entry --------------------
    def handle(self, pkt, src, dst, sport, dport, inbound_iface):
        if IP is None or TCP is None or UDP is None:
            return

        is_tcp = self._is_tcp(pkt)
        is_udp = self._is_udp(pkt)
        if not (is_tcp or is_udp):
            return

        kind = self._classify_kind(sport, dport, is_tcp=is_tcp, is_udp=is_udp)
        if not kind:
            return  # not recognized as Steam-ish

        key = self._flow_key(src, sport, dst, dport, "TCP" if is_tcp else "UDP")
        now = time.time()
        f = self._flows.get(key)
        if f is None:
            f = self._flows[key] = self._new_flow(src, sport, dst, dport, inbound_iface, now, kind)

        f["last_seen"] = now
        f["last_iface"] = inbound_iface

        if is_tcp:
            self._handle_tcp(f, pkt, inbound_iface)
        else:
            self._handle_udp(f, pkt, inbound_iface)

        self._cleanup_idle(now)

    # -------------------- TCP path --------------------
    def _handle_tcp(self, f: dict, pkt, iface: str):
        flags = self._tcp_flags(pkt)
        payload = self._payload(pkt)

        # handshake/teardown
        if 'S' in flags and 'A' not in flags:
            self._on_syn(f, flags, iface)
        elif 'S' in flags and 'A' in flags:
            self._on_syn_ack(f, flags, iface)
        elif 'F' in flags or 'R' in flags:
            self._on_fin_rst(f, flags, iface)

        # data logging
        if payload:
            f["pkts"] += 1
            f["bytes"] += len(payload)
            if f["first_sample"] is None:
                sample = payload[:self.max_payload_sample]
                f["first_sample"] = sample
                f["entropy"] = self._entropy(sample)
                self._log_first_data(f, sample, iface, l4="TCP")
            else:
                self._maybe_progress(f, l4="TCP")

    # -------------------- UDP path --------------------
    def _handle_udp(self, f: dict, pkt, iface: str):
        payload = self._payload(pkt)
        sport = f["endpoints"][0][1]
        dport = f["endpoints"][1][1]

        # First log (sample/entropy)
        if payload:
            f["pkts"] += 1
            f["bytes"] += len(payload)
            if f["first_sample"] is None:
                sample = payload[:self.max_payload_sample]
                f["first_sample"] = sample
                f["entropy"] = self._entropy(sample)
                self._log_first_data(f, sample, iface, l4="UDP")
            else:
                self._maybe_progress(f, l4="UDP")

        # Attempt decode for A2S queries/responses
        if payload:
            tag = self._try_a2s_decode(payload)
            if tag:
                self._rate_log(f"[Transport][🎮 Steam][A2S] {tag} {f['endpoints'][0][0]}:{sport} ⇄ {f['endpoints'][1][0]}:{dport} on {iface}")
                return

            # Heuristic SDR/Steam Datagram tagging
            if self._looks_like_sdr(payload, sport, dport):
                self._rate_log(f"[Transport][🎮 Steam][SDR?] Heuristic match {f['endpoints'][0][0]}:{sport} ⇄ {f['endpoints'][1][0]}:{dport} on {iface} "
                               f"len={len(payload)} ent={f.get('entropy', 0):.2f}")

            # LAN discovery hint
            if sport in self.UDP_DISCOVERY or dport in self.UDP_DISCOVERY:
                self._rate_log(f"[Transport][🎮 Steam][Discovery] UDP discovery {f['endpoints'][0][0]}:{sport} ⇄ {f['endpoints'][1][0]}:{dport} on {iface}")

    # -------------------- Kind classification --------------------
    def _classify_kind(self, sport: int, dport: int, *, is_tcp: bool, is_udp: bool) -> Optional[str]:
        if is_tcp:
            if sport in self._tcp_ports or dport in self._tcp_ports:
                return "steam-tcp"
        if is_udp:
            if (sport in self._udp_ports or dport in self._udp_ports):
                # distinguish A2S as a subtype if it is on typical query ports
                if sport in self._query_ports or dport in self._query_ports:
                    return "steam-udp"
                return "steam-udp"
        return None

    # -------------------- A2S decoding (best-effort) --------------------
    def _try_a2s_decode(self, payload: bytes) -> Optional[str]:
        # Must start with 0xFFFFFFFF for queries/responses (most Source/GoldSrc server query frames)
        if len(payload) < 5:
            return None
        # Requests:
        if payload.startswith(self._A2S_INFO_REQ):
            return "REQ A2S_INFO"
        if payload.startswith(self._A2S_RULES_REQ):
            # could be a RULES request or challenge containing extra bytes
            return "REQ A2S_RULES"
        if payload.startswith(self._A2S_PLAYERS_REQ):
            return "REQ A2S_PLAYER"
        if payload.startswith(self._A2S_CHALLENGE_REQ):
            return "REQ A2S_SERVERQUERY_GETCHALLENGE"

        # Responses: often "\xff\xff\xff\xff" + TYPE
        if payload.startswith(self._FF_FF_FF_FF) and len(payload) >= 5:
            t = payload[4:5]
            if t == self._A2S_INFO_RSP_HDR:
                return "RSP A2S_INFO"
            if t == self._A2S_RULES_RSP_HDR:
                return "RSP A2S_RULES/CHALLENGE"
            if t == self._A2S_PLAYERS_RSP_HDR:
                return "RSP A2S_PLAYER"
        return None

    # -------------------- SDR heuristic --------------------
    def _looks_like_sdr(self, payload: bytes, sport: int, dport: int) -> bool:
        """
        Very light heuristic for Steam Datagram Relay or game UDP:
          • payload length often in small/medium frames (20–1400)
          • entropy fairly high (encryption/compression)
          • ports in Steam UDP ranges (already true)
          • avoid A2S signature
        """
        if len(payload) < 20 or len(payload) > 1500:
            return False
        # exclude A2S (already handled)
        if payload.startswith(self._FF_FF_FF_FF):
            return False
        # entropy check
        ent = self._entropy(payload[:min(96, len(payload))])
        return ent > 4.0  # encrypted/compressed-looking

    # -------------------- Flow bookkeeping --------------------
    @staticmethod
    def _new_flow(src, sport, dst, dport, iface, now_ts, kind: str):
        return {
            "kind": kind,                       # "steam-tcp" | "steam-udp"
            "endpoints": ((src, int(sport)), (dst, int(dport))),
            "created": now_ts,
            "last_seen": now_ts,
            "last_iface": iface,
            "pkts": 0,
            "bytes": 0,
            "first_sample": None,
            "entropy": None,
            "last_flags": "",
        }

    def _cleanup_idle(self, now_ts: float):
        if not self._flows:
            return
        stale = [k for k, f in self._flows.items() if now_ts - f.get("last_seen", now_ts) > self.flow_idle_timeout]
        for k in stale:
            del self._flows[k]

    # -------------------- TCP lifecycle logs --------------------
    def _on_syn(self, f, flags, iface):
        a, b = f["endpoints"]
        self._rate_log(f"[Transport][🧵 TCP][🎮 Steam] SYN {a[0]}:{a[1]} → {b[0]}:{b[1]} on {iface} (flags={flags})")

    def _on_syn_ack(self, f, flags, iface):
        a, b = f["endpoints"]
        self._rate_log(f"[Transport][🧵 TCP][🎮 Steam] SYN/ACK {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface} (flags={flags})")

    def _on_fin_rst(self, f, flags, iface):
        a, b = f["endpoints"]
        dur = time.time() - f.get("created", time.time())
        self._rate_log(f"[Transport][🧵 TCP][🎮 Steam] FIN/RST ✂ {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} "
                       f"(flags={flags}, dur={dur:.1f}s, bytes={f['bytes']}, pkts={f['pkts']})")

    def _log_first_data(self, f, sample: bytes, iface: str, *, l4: str):
        a, b = f["endpoints"]
        ent = f["entropy"] if f["entropy"] is not None else 0.0
        self._rate_log(f"[Transport][{ '🧵 TCP' if l4=='TCP' else '🚀 UDP' }][🎮 Steam] DATA ▶ "
                       f"{a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface} first={len(sample)}B ent={ent:.2f} "
                       f"hex={self._short_hex(sample, 32)}")

    def _maybe_progress(self, f, *, l4: str):
        a, b = f["endpoints"]
        if f["pkts"] % 50 == 0 or f["bytes"] in (1024, 4096, 16384, 65536, 262144):
            self._rate_log(f"[Transport][{ '🧵 TCP' if l4=='TCP' else '🚀 UDP' }][🎮 Steam] DATA ⏩ "
                           f"{a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} bytes={f['bytes']} pkts={f['pkts']}")

    # -------------------- Utils --------------------
    @staticmethod
    def _is_tcp(pkt) -> bool:
        return hasattr(pkt, "haslayer") and TCP is not None and pkt.haslayer(TCP)

    @staticmethod
    def _is_udp(pkt) -> bool:
        return hasattr(pkt, "haslayer") and UDP is not None and pkt.haslayer(UDP)

    @staticmethod
    def _tcp_flags(pkt) -> str:
        try:
            return pkt[TCP].flags.flagrepr()
        except Exception:
            return ""

    @staticmethod
    def _payload(pkt) -> bytes:
        try:
            if Raw is not None and hasattr(pkt, "haslayer") and pkt.haslayer(Raw) and pkt[Raw].load:
                return bytes(pkt[Raw].load)
            # For TCP, Scapy sometimes stores data in TCP.payload
            if hasattr(pkt, "haslayer") and pkt.haslayer(TCP):
                pl = bytes(pkt[TCP].payload)
                if pl:
                    return pl
            if hasattr(pkt, "haslayer") and pkt.haslayer(UDP):
                pl = bytes(pkt[UDP].payload)
                if pl:
                    return pl
        except Exception:
            pass
        return b""

    @staticmethod
    def _flow_key(src, sport, dst, dport, l4: str):
        a, b = (src, int(sport)), (dst, int(dport))
        key = (a, b) if a <= b else (b, a)
        return (l4,) + key

    def _rate_log(self, msg: str):
        h = hash(msg)
        t = time.time()
        if t - self._recent_msgs[h] >= self._recent_window:
            self._recent_msgs[h] = t
            self.log.log_message(msg)

    @staticmethod
    def _short_hex(b: bytes, max_len: int) -> str:
        if not b:
            return ""
        s = b[:max_len].hex()
        return s + ("…" if len(b) > max_len else "")

    @staticmethod
    def _entropy(b: bytes) -> float:
        if not b:
            return 0.0
        counts = [0]*256
        for x in b:
            counts[x] += 1
        n = len(b)
        ent = 0.0
        for c in counts:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return ent

    @staticmethod
    def _is_valid_port(p) -> bool:
        try:
            p = int(p)
            return 1 <= p <= 65535
        except Exception:
            return False

class TransportQUICManager:
    """
    QUIC (UDP/443) parser & logger.

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool

    Features:
      • Detects Long vs Short header, logs Version/DCID/SCID/spin/key-phase
      • Best-effort frame peek (STREAM/CRYPTO/ACK/PING/CC/etc.)
      • De-dupes STREAM logs via a time-based cache (configurable timeout)
      • Emoji-rich logs consistent with TransportManager style
    """

    def __init__(self, router_logger, stream_timeout: int = 300):
        self.logger = router_logger
        self.logged_quic_streams: Dict[Tuple[str, str, int], float] = {}
        self.QUIC_STREAM_TIMEOUT = stream_timeout
        self._last_gc = time.time()
        self.logger.log_message("[Transport][🌐 QUIC] Manager ready.")

    # -------------------- Public entry point --------------------
    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool:
        handled = False
        try:
            if UDP is None or not packet or not packet.haslayer(UDP):
                return False

            on_443 = (sport == 443) or (dport == 443)
            if not on_443 and not getattr(self, "detect_non443_quic", False):
                return False

            raw_data = b""
            if Raw is not None and packet.haslayer(Raw):
                try:
                    raw_data = bytes(packet[Raw].load) or b""
                except Exception:
                    raw_data = b""

            if not raw_data:
                if on_443:
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][🌐 QUIC] hdr-only {src_ip}:{sport} → {dst_ip}:{dport} on {inbound_iface}"
                    )
                    handled = True
                return handled  # no payload

            mv = memoryview(raw_data)
            first = mv[0]
            is_long = (first & 0x80) == 0x80
            parts = [f"[Transport][🚀 UDP][🌐 QUIC] {src_ip}:{sport} → {dst_ip}:{dport} on {inbound_iface}"]

            if is_long:
                # ... your long-header parsing ...
                self.logger.log_message("".join(parts))
                handled = True
                return handled
            else:
                # ... your short-header parsing ...
                self.logger.log_message("".join(parts))
                handled = True
                return handled

        except Exception:
            try:
                self.logger.log_message(
                    f"[Transport][🚀 UDP][🌐 QUIC] parse-error {src_ip}:{sport} → {dst_ip}:{dport} on {inbound_iface}"
                )
            except Exception:
                pass
            return False
        finally:
            try:
                if hasattr(self, "_maybe_gc"):
                    self._maybe_gc()
            except Exception:
                pass

    def _short_hex(self, data: bytes | bytearray | memoryview | None, max_len: int = 8) -> str:
        """
        Return the first max_len bytes of data as hex, appending '…' if truncated.
        Safe for None/empty/non-bytes-like input.
        """
        if not data:
            return ""
        try:
            mv = memoryview(data)
            n = min(len(mv), max_len)
            out = bytes(mv[:n]).hex()
            if len(mv) > n:
                out += "…"
            return out
        except Exception:
            # Last-resort fallback; don't break logging
            try:
                b = bytes(data)
                out = b[:max_len].hex()
                if len(b) > max_len:
                    out += "…"
                return out
            except Exception:
                return ""
    # --------- tiny helpers you can keep with the class ---------

    def _quic_lh_type_name(self, n: int) -> str:
        return {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}.get(n, f"lh{n}")

    def _quic_version_name(self, ver: int) -> str:
        if ver == 0:
            return "VN"  # Version Negotiation
        # Common versions you’ll see in the wild
        return {
            0x00000001: "v1",
            0x00000002: "v2",
            0x709A50C4: "draft-29",
        }.get(ver, f"0x{ver:08x}")

    def _quic_read_varint(self, mv: memoryview, p: int) -> tuple[int | None, int]:
        """
        RFC 9000 QUIC varint:
          00: 1 byte,  01: 2 bytes,  10: 4 bytes,  11: 8 bytes
        Returns (value, new_index) or (None, p) if truncated.
        """
        if p >= len(mv):
            return None, p
        fb = mv[p]
        prefix = fb >> 6
        sizes = (1, 2, 4, 8)
        size = sizes[prefix]
        if p + size > len(mv):
            return None, p
        val = int.from_bytes(mv[p:p + size], "big") & {1: 0x3F, 2: 0x3FFF, 4: 0x3FFFFFFF, 8: 0x3FFFFFFFFFFFFFFF}[size]
        return val, p + size
    # -------------------- Header helpers (return formatted text + header length) --------------------

    def _format_long_header(self, raw: bytes, first_byte: int, src_ip: str, sport: int) -> Tuple[str, int]:
        if len(raw) < 6:
            raise IndexError
        packet_type = (first_byte & 0x30) >> 4
        version_hex = raw[1:5].hex()
        dcid_len = raw[5]
        scid_len = raw[6 + dcid_len] if len(raw) > 6 + dcid_len else 0
        dcid = raw[6:6 + dcid_len].hex() if len(raw) >= 6 + dcid_len else "?"
        scid = raw[7 + dcid_len:7 + dcid_len + scid_len].hex() if len(raw) >= 7 + dcid_len + scid_len else "?"
        packet_type_str = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}.get(packet_type, "Unknown")
        msg = (f" Long Header ({packet_type_str}) from {src_ip}:{sport}"
               f" | Version: 0x{version_hex} | DCID: {dcid} | SCID: {scid}")
        header_len = 7 + dcid_len + scid_len
        return msg, header_len

    def _format_short_header(self, raw: bytes, first_byte: int, src_ip: str, sport: int) -> Tuple[str, int]:
        # Short header: DCID length heuristic (8 is common)
        dcid_len = 8
        dcid = raw[1:1 + dcid_len].hex() if len(raw) > 1 + dcid_len else "?"
        spin_bit = (first_byte & 0x20) >> 5
        key_phase_bit = (first_byte & 0x04) >> 2
        key_phase_str = "Updated Keys" if key_phase_bit else "Initial Keys"
        msg = (f" Short Header from {src_ip}:{sport}"
               f" | DCID: {dcid} | Spin Bit: {spin_bit} | Key Phase: {key_phase_str}")
        header_len = 1 + dcid_len
        return msg, header_len

    # -------------------- Frame collector (no direct logging) --------------------

    def _maybe_gc(self) -> None:
        now = time.time()
        if now - self._last_gc < 60:
            return
        expired = [
            k for k, ts in self.logged_quic_streams.items()
            if now - ts > self.QUIC_STREAM_TIMEOUT
        ]
        for k in expired:
            self.logged_quic_streams.pop(k, None)
        if expired:
            self.logger.log_message(f"[Transport][🌐 QUIC] 🧹 GC pruned {len(expired)} stream entries")
        self._last_gc = now
    # -------------------- Varint --------------------

    def _parse_quic_varint(self, data: bytes) -> Tuple[int, int]:
        """
        Returns (value, bytes_consumed) or (0,0) on failure.
        """
        if not data:
            return 0, 0
        b0 = data[0]
        lbits = b0 >> 6
        try:
            if lbits == 0b00:
                return b0 & 0x3F, 1
            elif lbits == 0b01:
                if len(data) < 2:
                    return 0, 0
                val = struct.unpack("!H", data[:2])[0]
                return val & 0x3FFF, 2
            elif lbits == 0b10:
                if len(data) < 4:
                    return 0, 0
                val = struct.unpack("!I", data[:4])[0]
                return val & 0x3FFFFFFF, 4
            else:
                if len(data) < 8:
                    return 0, 0
                val = struct.unpack("!Q", data[:8])[0]
                return val & 0x3FFFFFFFFFFFFFFF, 8
        except (struct.error, IndexError):
            return 0, 0

    def _collect_quic_frames(self, data: bytes, src_ip: str, dst_ip: str) -> list:
        """
        Returns a list of concise frame descriptors for a single-line summary.
        Updates stream de-dupe cache but does not log by itself.
        """
        out = []
        i = 0
        while i < len(data):
            try:
                first = data[i]

                # STREAM 0x08..0x0F
                if 0x08 <= first <= 0x0F:
                    has_len = (first & 0x02)
                    has_off = (first & 0x04)
                    offset = 1

                    stream_id, n = self._parse_quic_varint(data[i + offset:])
                    if n == 0:
                        break
                    offset += n

                    # Update (src,dst,stream) de-dupe timestamp; tag "new" once
                    key = (src_ip, dst_ip, stream_id)
                    now = time.time()
                    label = f"STREAM[{stream_id}]"
                    if key not in self.logged_quic_streams:
                        label += "*"
                    self.logged_quic_streams[key] = now

                    if has_off:
                        _, n = self._parse_quic_varint(data[i + offset:])
                        offset += n
                    if has_len:
                        data_len, n = self._parse_quic_varint(data[i + offset:])
                        offset += n
                        label += f" len={data_len}"
                        out.append(label)
                        payload_len = (len(data) - (i + offset)) if not has_len else data_len
                        i += offset + max(0, payload_len)
                        continue

                # Selected common types
                if first in (0x02, 0x03):          # ACK
                    out.append("ACK")
                    i = len(data)
                elif first == 0x00:                 # PADDING
                    out.append("PADDING")
                    i += 1
                elif first == 0x01:                 # PING
                    out.append("PING")
                    i += 1
                elif first == 0x06:                 # CRYPTO (drafty)
                    if len(data) >= i + 9:
                        _, length = struct.unpack("!II", data[i + 1:i + 9])
                        out.append(f"CRYPTO len={length}")
                        i += 9 + length
                    else:
                        out.append("CRYPTO(malformed)")
                        break
                elif first in (0x1C, 0x1D):         # CONNECTION_CLOSE
                    out.append("CONNECTION_CLOSE")
                    i = len(data)
                elif first == 0x24:
                    out.append("RESET_STREAM_AT")
                    i = len(data)
                elif first == 0x14:
                    out.append("STREAMS_BLOCKED")
                    i = len(data)
                elif first == 0xA4:
                    out.append("ACK_FREQUENCY")
                    i = len(data)
                else:
                    out.append(f"0x{first:02x}")
                    break

            except (struct.error, IndexError):
                out.append("FRAME(malformed)")
                break

        return out

class TransportSSDPManager:
    """
    SSDP/UPnP logger & helper.

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
          Returns True if this was SSDP and got handled/logged.

    Features:
      • Parses NOTIFY, M-SEARCH, and 200 OK responses over UDP/1900
      • Pretty, emoji-rich logs (🔌📣🔎📬)
      • Extracts key headers: ST/NT/NTS/USN/LOCATION/SERVER/HOST/MAN/MX
      • Tracks recent announcements by USN with TTL from Cache-Control: max-age
      • Lightweight GC for stale announcements (dedup noise)
    """

    # Multicast hints
    _SSDP_MCAST_V4 = "239.255.255.250"
    _SSDP_MCAST_PORT = 1900
    _SSDP_MCAST_V6 = ("ff02::c", "ff05::c", "ff08::c")  # link/site/org-local

    # Default retention for NOTIFY/response entries if no max-age present
    _DEFAULT_MAX_AGE = 1800  # 30 min
    _GC_INTERVAL = 60  # seconds

    def __init__(self, router_logger):
        self.log = router_logger
        # usn -> info
        # info = { 'seen': ts, 'expires': ts, 'nt': str, 'st': str, 'location': str, 'server': str, 'src': str }
        self._announced: Dict[str, Dict[str, Any]] = {}
        self._last_gc = time.time()
        self.log.log_message("[Transport][🔌 SSDP] Manager ready.")

    # -------------------- Public entry point --------------------

    def handle(
        self,
        packet: Packet,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        inbound_iface: str,
    ) -> bool:
        if UDP is None or Raw is None:
            return False
        if not packet.haslayer(UDP) or dport != self._SSDP_MCAST_PORT:
            # Some devices unicast replies from random ports →1900 or 1900→random,
            # but we call this only for :1900 in your TransportManager.
            pass
        if not packet.haslayer(Raw):
            # No payload → nothing to parse
            return False

        raw = bytes(packet[Raw].load)
        if not raw:
            return False

        text = self._safe_decode(raw)
        first_line, headers = self._parse_httpu(text)

        if not first_line:
            return False

        # Determine type
        if first_line.startswith("NOTIFY "):
            self._log_notify(first_line, headers, src_ip, dst_ip, sport, dport, inbound_iface)
        elif first_line.startswith("M-SEARCH "):
            self._log_search(first_line, headers, src_ip, dst_ip, sport, dport, inbound_iface)
        elif first_line.startswith("HTTP/1.1 200"):
            self._log_response(first_line, headers, src_ip, dst_ip, sport, dport, inbound_iface)
        else:
            self.log.log_message(
                f"[Transport][🔌 SSDP][❔ Unknown] if={self._iface_short(inbound_iface)} "
                f"{src_ip}:{sport} → {dst_ip}:{dport} | line='{first_line[:80]}'"
            )

        self._maybe_gc()
        return True

    # -------------------- Loggers --------------------

    def _log_notify(
        self,
        line: str,
        h: Dict[str, str],
        sip: str, dip: str, sport: int, dport: int,
        inbound_iface: str,
    ):
        iface = self._iface_short(inbound_iface)
        nt = h.get("nt", "-")
        nts = h.get("nts", "-")
        usn = h.get("usn", "-")
        loc = h.get("location", "-")
        srv = h.get("server", "-")
        cc = h.get("cache-control", "")
        max_age = self._parse_max_age(cc) or self._DEFAULT_MAX_AGE

        # Track announcement by USN (if present) to reduce log noise
        if usn != "-":
            self._announced[usn] = {
                "seen": time.time(),
                "expires": time.time() + max_age,
                "nt": nt, "st": h.get("st", ""),
                "location": loc, "server": srv, "src": sip,
            }

        mcast = self._mcast_tag(dip)
        self.log.log_message(
            f"[Transport][🔌 SSDP][📣 NOTIFY]{mcast} if={iface} {sip}:{sport} → {dip}:{dport} "
            f"NT={nt} NTS={nts} USN={usn} LOCATION={loc} SERVER='{srv}' max-age={max_age}s"
        )

    def _log_search(
        self,
        line: str,
        h: Dict[str, str],
        sip: str, dip: str, sport: int, dport: int,
        inbound_iface: str,
    ):
        iface = self._iface_short(inbound_iface)
        st = h.get("st", "-")
        man = h.get("man", "-")
        mx = h.get("mx", "-")
        host = h.get("host", "-")
        mcast = self._mcast_tag(dip)
        self.log.log_message(
            f"[Transport][🔌 SSDP][🔎 M-SEARCH]{mcast} if={iface} {sip}:{sport} → {dip}:{dport} "
            f"ST={st} MAN={man} MX={mx} HOST={host}"
        )

    def _log_response(
            self,
            line: str,
            h: Dict[str, str],
            sip: str, dip: str, sport: int, dport: int,
            inbound_iface: str,
    ):
        iface = self._iface_short(inbound_iface)

        # --- normalize & sanitize ---
        # (headers already lowercased by _parse_httpu, but trim values)
        st = (h.get("st") or "-").strip()
        usn = (h.get("usn") or "-").strip()
        loc = (h.get("location") or "-").strip()
        srv = (h.get("server") or "-").strip()
        cc = (h.get("cache-control") or "").strip()

        max_age = self._parse_max_age(cc)
        if max_age is None:
            max_age = self._DEFAULT_MAX_AGE
        # clamp ridiculous values
        max_age = max(60, min(max_age, 24 * 3600))  # [1 min, 24h]

        # --- coalesce announcement ---
        # Build a canonical key to avoid spam (USN preferred; fallback on LOCATION)
        key = usn if usn != "-" else f"loc:{loc}"
        prev = self._announced.get(key)

        entry = {
            "seen": time.time(),
            "expires": time.time() + max_age,
            "nt": h.get("nt", ""),  # some responses include it
            "st": st,
            "location": loc,
            "server": srv,
            "src": sip,
            # placeholders for enrichment
            "friendly_name": None,
            "model_name": None,
            "igd": None,  # {'controlURL': str, 'serviceType': str, 'scpdURL': str, 'baseURL': str}
        }
        # Only log loudly if this is new or materially changed
        is_new = True
        if prev:
            is_new = any(entry.get(k) != prev.get(k) for k in ("st", "location", "server", "src"))
            # keep prior enrichment if present
            entry["friendly_name"] = prev.get("friendly_name")
            entry["model_name"] = prev.get("model_name")
            entry["igd"] = prev.get("igd")

        self._announced[key] = entry

        # multicast tag
        mcast = self._mcast_tag(dip)

        # concise, stable log line
        self.log.log_message(
            f"[Transport][🔌 SSDP][📬 Response]{mcast} if={iface} "
            f"{sip}:{sport} → {dip}:{dport} | "
            f"ST='{st}' USN='{usn}' LOCATION='{loc}' SERVER='{srv}' max-age={max_age}s"
        )

        # Kick off async enrichment (no blocking on the packet hot path)
        # Only (re)fetch if new or we have no enrichment yet.
        if is_new or not entry.get("friendly_name"):
            self._schedule_fetch_description(key, loc)

    # -------------------- Helpers --------------------
    def _schedule_fetch_description(self, key: str, location_url: str) -> None:
        """
        Spawns a short-lived thread to fetch and parse the UPnP device description
        from LOCATION. Safe no-op if URL is missing/invalid.
        """
        import threading
        if not location_url or location_url == "-":
            return
        try:
            t = threading.Thread(
                target=self._fetch_and_enrich_description,
                args=(key, location_url),
                daemon=True,
                name=f"ssdp-desc-{key[:16]}"
            )
            t.start()
        except Exception:
            # never let enrichment disturb packet path
            pass

    def _fetch_and_enrich_description(self, key: str, location_url: str) -> None:
        """
        Fetches LOCATION XML, extracts friendly/model and IGD endpoints,
        and updates self._announced[key].
        """
        try:
            import urllib.request
            import urllib.parse
            import xml.etree.ElementTree as ET

            # Basic safety: 2s timeout, avoid redirects to non-http(s)
            req = urllib.request.Request(location_url, headers={"User-Agent": "SSDP-Helper/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status != 200:
                    return
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "xml" not in ctype and "text/" not in ctype:
                    # still try parse, but it's a hint
                    pass
                data = resp.read(200_000)  # cap ~200KB
            # Parse XML
            root = ET.fromstring(data)

            # Namespaces commonly used in UPnP descriptions
            ns = {
                "upnp": "urn:schemas-upnp-org:device-1-0",
                "s": "urn:schemas-upnp-org:service-1-0"
            }

            # Try to detect baseURL to resolve relative control/scpd URLs
            base_url = self._xml_text(root, "URLBase") or self._url_base(location_url)

            # Extract friendly/model names
            friendly = self._xml_text(root, ".//{urn:schemas-upnp-org:device-1-0}friendlyName") \
                       or self._xml_text(root, ".//friendlyName")
            model = self._xml_text(root, ".//{urn:schemas-upnp-org:device-1-0}modelName") \
                    or self._xml_text(root, ".//modelName")

            igd = self._find_igd_service(root, base_url)

            # Update entry if still present
            ent = self._announced.get(key)
            if ent:
                ent["friendly_name"] = friendly
                ent["model_name"] = model
                ent["igd"] = igd

                # Nice one-line enrichment log
                extra = []
                if friendly: extra.append(f"friendly='{friendly}'")
                if model:    extra.append(f"model='{model}'")
                if igd:      extra.append(f"igd={igd.get('serviceType')} ctrl={igd.get('controlURL')}")
                if extra:
                    self.log.log_message(f"[Transport][🔌 SSDP] ℹ️ Enriched USN key='{key}': " + " ".join(extra))

        except Exception as e:
            # keep quiet; SSDP devices can be messy
            # uncomment for debugging:
            # self.log.log_message(f"[Transport][🔌 SSDP] ⚠️ Enrichment failed for {location_url}: {e}")
            pass

    def _xml_text(self, node, xpath: str) -> str | None:
        try:
            # Supports both namespaced and bare tags depending on caller
            if xpath.startswith(".//") or "}" in xpath or ":" in xpath:
                found = node.find(xpath)
            else:
                found = node.find(f".//{xpath}")
            if found is not None and found.text:
                return found.text.strip()
        except Exception:
            pass
        return None

    def _url_base(self, url: str) -> str:
        try:
            from urllib.parse import urlparse
            u = urlparse(url)
            # scheme://host[:port]
            hostport = u.netloc
            if not hostport:
                return ""
            return f"{u.scheme}://{hostport}"
        except Exception:
            return ""

    def _resolve_url(self, base: str, path: str) -> str:
        try:
            from urllib.parse import urljoin
            return urljoin(base or "", path or "")
        except Exception:
            return path or ""

    def _find_igd_service(self, root, base_url: str) -> dict | None:
        """
        Finds WANIPConnection or WANPPPConnection service in the device description
        and returns normalized endpoints (absolute controlURL/SCPDURL).
        """
        # Common service types to look for (v1/v2)
        svc_types = [
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:2",
        ]
        # Walk all serviceList entries
        try:
            for svc in root.findall(".//{urn:schemas-upnp-org:device-1-0}serviceList/"
                                    "{urn:schemas-upnp-org:device-1-0}service"):
                st = self._xml_text(svc, "{urn:schemas-upnp-org:device-1-0}serviceType") or \
                     self._xml_text(svc, "serviceType")
                if not st or st not in svc_types:
                    continue
                ctrl = self._xml_text(svc, "{urn:schemas-upnp-org:device-1-0}controlURL") or \
                       self._xml_text(svc, "controlURL")
                scpd = self._xml_text(svc, "{urn:schemas-upnp-org:device-1-0}SCPDURL") or \
                       self._xml_text(svc, "SCPDURL")
                evt = self._xml_text(svc, "{urn:schemas-upnp-org:device-1-0}eventSubURL") or \
                      self._xml_text(svc, "eventSubURL")
                return {
                    "serviceType": st,
                    "controlURL": self._resolve_url(base_url, ctrl),
                    "scpdURL": self._resolve_url(base_url, scpd),
                    "eventSubURL": self._resolve_url(base_url, evt),
                    "baseURL": base_url,
                }
        except Exception:
            pass
        return None
    def _safe_decode(self, b: bytes) -> str:
        # SSDP is HTTP-like; headers are ASCII/Latin-1
        try:
            return b.decode("utf-8", errors="ignore")
        except Exception:
            return repr(b)

    def _parse_httpu(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Parse HTTPU-style start-line + headers into a dict with lowercased keys.
        """
        # Split at first blank line
        parts = text.split("\r\n\r\n", 1)
        header_blob = parts[0]
        lines = header_blob.split("\r\n")
        if not lines:
            return "", {}
        first = lines[0].strip()
        headers: Dict[str, str] = {}
        # Join folded headers (rare in SSDP but be safe)
        cur_key = None
        for raw in lines[1:]:
            if not raw:
                continue
            if raw.startswith((" ", "\t")) and cur_key:
                headers[cur_key] += " " + raw.strip()
                continue
            if ":" in raw:
                k, v = raw.split(":", 1)
                key = k.strip().lower()
                val = v.strip()
                cur_key = key
                # Allow repeated headers (rare) by concatenation
                if key in headers:
                    headers[key] += f", {val}"
                else:
                    headers[key] = val
        return first, headers

    def _parse_max_age(self, cache_control: str) -> Optional[int]:
        """
        Extracts max-age=N from Cache-Control (any order/case).
        """
        if not cache_control:
            return None
        m = re.search(r"max-age\s*=\s*(\d+)", cache_control, flags=re.IGNORECASE)
        if not m:
            return None
        try:
            return int(m.group(1))
        except Exception:
            return None

    def _mcast_tag(self, dip: str) -> str:
        if self._is_ipv4_mcast(dip) or self._is_ipv6_mcast(dip):
            return " [mcast]"
        return ""

    def _is_ipv4_mcast(self, ip: str) -> bool:
        return ip == self._SSDP_MCAST_V4

    def _is_ipv6_mcast(self, ip: str) -> bool:
        ip_l = (ip or "").lower()
        return any(ip_l.startswith(prefix) for prefix in self._SSDP_MCAST_V6)

    def _iface_short(self, name: str) -> str:
        return name.split("_")[-1] if name else "?"

    # -------------------- GC --------------------

    def _maybe_gc(self):
        now = time.time()
        if now - self._last_gc < self._GC_INTERVAL:
            return
        expired = [usn for usn, info in self._announced.items() if now >= info.get("expires", 0)]
        for usn in expired:
            self._announced.pop(usn, None)
        if expired:
            self.log.log_message(f"[Transport][🔌 SSDP] 🧹 GC expired {len(expired)} announcement(s)")
        self._last_gc = now

class TransportDNSManager:
    """
    DNS-focused helper that parses, summarizes, and tracks DNS queries/responses
    over UDP and TCP.

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
            Returns True if the packet carried DNS and was handled/logged.

    Features:
      • Query/Response summaries with emojis 🧭📦
      • RCODE/flags (RD, RA, AA, TC), EDNS(0) OPT summary (DO bit, UDP size)
      • Answer preview (A/AAAA/CNAME/TXT/MX/SRV/NS/PTR/SOA…)
      • Basic latency tracking by (client_ip, client_port, txid, proto)
      • Lightweight GC for old pending queries
    """

    # rcode → (name, emoji)
    _RCODES = {
        0:  ("NOERROR",  "✅"),
        1:  ("FORMERR",  "🧩"),
        2:  ("SERVFAIL", "🔥"),
        3:  ("NXDOMAIN", "❌"),
        4:  ("NOTIMP",   "🚫"),
        5:  ("REFUSED",  "⛔"),
        9:  ("NOTAUTH",  "🔒"),
        10: ("NOTZONE",  "📍"),
    }

    # qtype to string (common only; scapy prints numeric otherwise)
    _QT = {
        1:  "A",
        2:  "NS",
        5:  "CNAME",
        6:  "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        41: "OPT",
        43: "DS",
        46: "RRSIG",
        47: "NSEC",
        48: "DNSKEY",
        65: "HTTPS",   # SVCB=64 / HTTPS=65 (newer)
        64: "SVCB",
    }

    def __init__(
        self,
        router_logger,
        *,
        pending_ttl_sec: int = 30,
        gc_interval_sec: int = 10,
        max_preview_answers: int = 4,
    ):
        self.log = router_logger
        self._pending_ttl = pending_ttl_sec
        self._gc_interval = gc_interval_sec
        self._max_ans = max_preview_answers

        # key = (client_ip, client_port, txid, proto) → {ts, names:[...], server:ip}
        self._pending: Dict[Tuple[str, int, int, str], Dict[str, Any]] = {}

        self._last_gc = time.time()
        self.log.log_message("[Transport][🔎 DNS] Manager ready.")

    # ---------- Public entry point ----------

    def handle(
        self,
        packet: Packet,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        inbound_iface: str,
    ) -> bool:
        """
        Parse and log DNS carried by this packet (UDP/TCP). Returns True if handled.
        """
        if DNS is None:
            return False
        if not packet.haslayer(DNS):
            return False

        dns = packet[DNS]
        proto = "udp" if UDP is not None and packet.haslayer(UDP) else "tcp" if TCP is not None and packet.haslayer(TCP) else "ip"
        iface = inbound_iface.split("_")[-1]
        txid = int(getattr(dns, "id", 0))
        qr = int(getattr(dns, "qr", 0))  # 0=query, 1=response

        try:
            if qr == 0:
                # ---- QUERY ----
                qnames, qtypes = self._extract_questions(dns)
                self._log_query(iface, src_ip, sport, dst_ip, dport, txid, proto, dns, qnames, qtypes)
                # Track for latency on reply
                if qnames:
                    key = (src_ip, sport, txid, proto)
                    self._pending[key] = {
                        "ts": time.time(),
                        "names": qnames,
                        "types": qtypes,
                        "server": dst_ip,
                    }
            else:
                # ---- RESPONSE ----
                latency_ms = None
                key = (dst_ip, dport, txid, proto)  # reverse: dst/dport now match original client src/sport
                pend = self._pending.pop(key, None)
                if pend:
                    latency_ms = int((time.time() - pend["ts"]) * 1000)
                self._log_response(iface, src_ip, sport, dst_ip, dport, txid, proto, dns, latency_ms)
        finally:
            self._maybe_gc()
            return True

    # ---------- Query logging ----------

    def _log_query(
        self,
        iface: str,
        sip: str, sport: int,
        dip: str, dport: int,
        txid: int, proto: str,
        dns: Any,
        qnames: List[str],
        qtypes: List[str],
    ) -> None:
        # flags
        rd = bool(getattr(dns, "rd", 0))
        ad = bool(getattr(dns, "ad", 0))
        cd = bool(getattr(dns, "cd", 0))
        tc = bool(getattr(dns, "tc", 0))

        edns = self._extract_edns(dns)
        edns_str = f" EDNS(udp={edns['size']}{' DO' if edns['do'] else ''})" if edns else ""

        # Query preview (first name/type)
        head = qnames[0] if qnames else "?"
        qtype0 = qtypes[0] if qtypes else "?"
        more = f" +{len(qnames)-1} more" if len(qnames) > 1 else ""

        self.log.log_message(
            f"[Transport][🔎 DNS][🧭 Query] if={iface} {sip}:{sport} → {dip}:{dport} "
            f"txid=0x{txid:04x} proto={proto.upper()} name={head} type={qtype0}{more} "
            f"flags={'RD' if rd else '-'}{'|AD' if ad else ''}{'|CD' if cd else ''}{'|TC' if tc else ''}{edns_str}"
        )

    # ---------- Response logging ----------

    def _log_response(
        self,
        iface: str,
        sip: str, sport: int,  # server:port
        dip: str, dport: int,  # client:port
        txid: int, proto: str,
        dns: Any,
        latency_ms: Optional[int],
    ) -> None:
        rcode = int(getattr(dns, "rcode", 0))
        name, r_emoji = self._RCODES.get(rcode, (f"RCODE{rcode}", "❔"))

        aa = bool(getattr(dns, "aa", 0))
        ra = bool(getattr(dns, "ra", 0))
        tc = bool(getattr(dns, "tc", 0))
        ad = bool(getattr(dns, "ad", 0))

        qn_preview = self._preview_qname(dns)
        edns = self._extract_edns(dns)
        edns_str = f" EDNS(udp={edns['size']}{' DO' if edns['do'] else ''})" if edns else ""

        # Counts
        an, ns, ar = int(getattr(dns, "ancount", 0)), int(getattr(dns, "nscount", 0)), int(getattr(dns, "arcount", 0))
        lat = f" {latency_ms}ms" if latency_ms is not None else ""
        trunc = " TC" if tc else ""

        # Header line
        self.log.log_message(
            f"[Transport][🔎 DNS][📦 Response] if={iface} {sip}:{sport} → {dip}:{dport} "
            f"txid=0x{txid:04x} proto={proto.upper()} q={qn_preview} "
            f"rcode={name}{trunc} {r_emoji} an={an} ns={ns} ar={ar}{lat}{edns_str} "
            f"flags={'AA' if aa else '-'}{'|RA' if ra else ''}{'|AD' if ad else ''}"
        )

        # Answers preview
        if an:
            answers = self._iter_rr(dns.an, an)
            lines = []
            for i, rr in enumerate(answers):
                if i >= self._max_ans:
                    lines.append(f"… +{an - self._max_ans} more")
                    break
                lines.append(self._fmt_rr(rr))
            for ln in lines:
                self.log.log_message(f"[Transport][🔎 DNS][📜 Answer] {ln}")

        # Authority (NS/SOA) preview
        if ns:
            auths = self._iter_rr(dns.ns, ns)
            for i, rr in enumerate(auths):
                if i >= 2:
                    self.log.log_message(f"[Transport][🔎 DNS][📜 Authority] … +{ns - 2} more")
                    break
                self.log.log_message(f"[Transport][🔎 DNS][📜 Authority] {self._fmt_rr(rr)}")

        # Additional preview
        if ar:
            adds = self._iter_rr(dns.ar, ar)
            shown = 0
            for rr in adds:
                # Skip OPT detailed spam, we already summarized EDNS
                if getattr(rr, "type", 0) == 41:
                    continue
                if shown >= 3:
                    self.log.log_message(f"[Transport][🔎 DNS][📜 Additional] … +{ar - shown} more")
                    break
                self.log.log_message(f"[Transport][🔎 DNS][📜 Additional] {self._fmt_rr(rr)}")
                shown += 1

    # ---------- Utilities ----------

    def _extract_questions(self, dns: Any) -> Tuple[List[str], List[str]]:
        names: List[str] = []
        types: List[str] = []
        try:
            qdcount = int(getattr(dns, "qdcount", 0))
            qd = getattr(dns, "qd", None)
            # scapy represents multiple questions as a chained/stacked DNSQR list
            for i, qr in enumerate(self._iter_qr(qd, qdcount)):
                name = self._safe_name(getattr(qr, "qname", b""))
                qtype = int(getattr(qr, "qtype", 0))
                names.append(name)
                types.append(self._QT.get(qtype, str(qtype)))
        except Exception:
            pass
        return names, types

    def _preview_qname(self, dns: Any) -> str:
        try:
            if int(getattr(dns, "qdcount", 0)) and getattr(dns, "qd", None):
                q = dns.qd
                nm = self._safe_name(getattr(q, "qname", b""))
                qt = self._QT.get(int(getattr(q, "qtype", 0)), str(int(getattr(q, "qtype", 0))))
                return f"{nm} {qt}"
        except Exception:
            pass
        return "-"

    def _extract_edns(self, dns: Any) -> Optional[Dict[str, Any]]:
        """
        Look for OPT (type 41) in additional; return {'size': int, 'do': bool} if present.
        """
        try:
            arcount = int(getattr(dns, "arcount", 0))
            rr = getattr(dns, "ar", None)
            for r in self._iter_rr(rr, arcount):
                if int(getattr(r, "type", 0)) == 41:
                    # In OPT, 'rclass' is UDP payload size; DO bit is in the Z field (scapy uses 'ttl')
                    size = int(getattr(r, "rclass", 0))
                    z = int(getattr(r, "ttl", 0))
                    do = bool(z & 0x8000)
                    return {"size": size, "do": do}
        except Exception:
            pass
        return None

    def _iter_qr(self, qd: Any, count: int):
        """Iterate DNSQR chain safely."""
        cur = qd
        n = 0
        while cur is not None and n < count:
            yield cur
            cur = getattr(cur, "payload", None)
            if cur is qd:  # safety
                break
            if not isinstance(cur, DNSQR):
                break
            n += 1

    def _iter_rr(self, rr: Any, count: int):
        """Iterate DNSRR chain safely."""
        cur = rr
        n = 0
        while cur is not None and n < count:
            yield cur
            cur = getattr(cur, "payload", None)
            if cur is rr:  # safety
                break
            if not isinstance(cur, DNSRR):
                break
            n += 1

    def _fmt_rr(self, rr: Any) -> str:
        """Compact one-line RR rendering with emojis by type."""
        try:
            name = self._safe_name(getattr(rr, "rrname", b""))
            rtype = int(getattr(rr, "type", 0))
            rttl = int(getattr(rr, "ttl", 0))
            cls = int(getattr(rr, "rclass", 1))
            tstr = self._QT.get(rtype, str(rtype))

            # Value by type
            val = "?"
            if tstr in ("A", "AAAA", "NS", "CNAME", "PTR"):
                val = self._safe_name(getattr(rr, "rdata", b"")) if tstr != "A" and tstr != "AAAA" else getattr(rr, "rdata", "?")
            elif tstr == "MX":
                pref = getattr(rr, "preference", None)
                exch = self._safe_name(getattr(rr, "exchange", b""))
                val = f"{pref} {exch}" if pref is not None else exch
            elif tstr == "TXT":
                val = self._fmt_txt(getattr(rr, "rdata", b""))
            elif tstr == "SRV":
                tgt = self._safe_name(getattr(rr, "target", b""))
                port = getattr(rr, "port", "?")
                prio = getattr(rr, "priority", None)
                weight = getattr(rr, "weight", None)
                val = f"{tgt}:{port}"
                if prio is not None and weight is not None:
                    val += f" prio={prio} w={weight}"
            elif tstr == "SOA":
                mname = self._safe_name(getattr(rr, "mname", b""))
                rname = self._safe_name(getattr(rr, "rname", b""))
                serial = getattr(rr, "serial", "?")
                val = f"{mname} {rname} serial={serial}"
            elif rtype == 41:
                # OPT already summarized separately
                val = "OPT"
            else:
                # Fallback
                v = getattr(rr, "rdata", None)
                if isinstance(v, bytes):
                    val = self._safe(v)
                else:
                    val = str(v)

            # Emoji by common types
            emo = {
                "A": "🧭",
                "AAAA": "🧭",
                "CNAME": "🔁",
                "NS": "📌",
                "MX": "✉️",
                "TXT": "📝",
                "SRV": "🎯",
                "PTR": "↩️",
                "SOA": "📜",
                "OPT": "⚙️",
            }.get(tstr, "📦")

            return f"{emo} {name} {tstr} {val} (ttl={rttl})"
        except Exception:
            return "📦 (unprintable RR)"

    def _fmt_txt(self, rdata: Any) -> str:
        # TXT can be bytes or list of bytes; render compact
        try:
            if isinstance(rdata, (bytes, bytearray)):
                s = self._safe(rdata)
                return f"\"{s}\""
            if isinstance(rdata, list):
                parts = [self._safe(x) for x in rdata[:3]]
                more = f" +{len(rdata)-3}" if len(rdata) > 3 else ""
                return "[" + ", ".join(f"\"{p}\"" for p in parts) + "]" + more
        except Exception:
            pass
        return "\"?\""

    def _safe_name(self, val: Any) -> str:
        if isinstance(val, (bytes, bytearray)):
            s = val.decode("utf-8", errors="ignore").rstrip(".")
            return s or "."
        if isinstance(val, str):
            return val.rstrip(".")
        return str(val)

    def _safe(self, b: Any) -> str:
        try:
            if isinstance(b, (bytes, bytearray)):
                s = b.decode("utf-8", errors="ignore")
                # compact long strings
                return s if len(s) <= 80 else s[:77] + "…"
            return str(b)
        except Exception:
            return "?"

    # ---------- GC ----------

    def _maybe_gc(self) -> None:
        now = time.time()
        if now - self._last_gc < self._gc_interval:
            return
        dead = []
        for k, v in self._pending.items():
            if now - v.get("ts", 0) > self._pending_ttl:
                dead.append(k)
        for k in dead:
            _ = self._pending.pop(k, None)
        if dead:
            self.log.log_message(f"[Transport][🔎 DNS] 🧹 GC expired {len(dead)} pending query slots")
        self._last_gc = now

class TransportDHCPActiveAgent:
    """
    Small DHCP active helper:
      - Client mode: discover/request
      - Server mode: respond with offer/ack from a pool
    Uses sniffer.sendp/sr2 to emit frames.
    """

    def _mac_bytes(self,mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.split(":"))

    def _chaddr(self,mac: str) -> bytes:
        # BOOTP chaddr field is 16 bytes; pad MAC to 16
        b = self._mac_bytes(mac)
        return b + b"\x00" * (16 - len(b))

    def _iface_ipv4(self,iface: str) -> Optional[str]:
        # Light, portable IPv4-on-interface helper
        try:
            import psutil
            for nic, addrs in psutil.net_if_addrs().items():
                if iface in nic:
                    for a in addrs:
                        if getattr(a, "family", None) == 2 and a.address != "127.0.0.1":
                            return a.address
        except Exception:
            pass
        return None
    def __init__(self, *, sniffer, logger, pool_cidr: Optional[str] = None, server_ip: Optional[str] = None):
        self.sniffer = sniffer
        self.log = logger
        # Client-side outstanding transactions by xid
        self._pending_client: Dict[int, Dict[str, Any]] = {}
        # Server-side leases: mac -> {ip, expires, xid}
        self._leases: Dict[str, Dict[str, Any]] = {}
        self._pool = None
        self._server_ip_static = server_ip
        if pool_cidr:
            self._pool = [str(ip) for ip in ipaddress.ip_network(pool_cidr, strict=False).hosts()]

    # ---------------- Client mode ----------------

    def client_discover(self, iface: str, *, prl: Optional[List[int]] = None) -> int:
        """
        Send DHCPDISCOVER on 'iface'. Returns xid used.
        """
        mac = get_if_hwaddr(iface)
        xid = random.getrandbits(32)
        if prl is None:
            prl = [1, 3, 6, 15, 51, 54, 58, 59, 119, 121, 249, 252, 44]  # mask, router, dns, domain, lease, server id, T1,T2,...

        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, chaddr=self._chaddr(mac), xid=xid, flags=0x8000, htype=1, hlen=6) /
            DHCP(options=[
                ("message-type", "discover"),
                ("client_id", b"\x01" + self._mac_bytes(mac)),
                ("param_req_list", prl),
                "end"
            ])
        )

        self.sniffer.sendp(pkt, iface=iface)
        self._pending_client[xid] = {"iface": iface, "state": "DISCOVER", "ts": time.time(), "mac": mac}
        self.log.log_message(f"[DHCP][client] 📡 DISCOVER sent on {iface} | xid=0x{xid:08x} | mac={mac}")
        return xid

    def _client_send_request(self, *, iface: str, xid: int, server_ip: str, offered_ip: str, mac: str):
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, chaddr=self._chaddr(mac), xid=xid, flags=0x8000, htype=1, hlen=6) /
            DHCP(options=[
                ("message-type", "request"),
                ("client_id", b"\x01" + self._mac_bytes(mac)),
                ("server_id", server_ip),
                ("requested_addr", offered_ip),
                "end"
            ])
        )
        self.sniffer.sendp(pkt, iface=iface)
        self.log.log_message(f"[DHCP][client] 🙋 REQUEST sent on {iface} | xid=0x{xid:08x} | req={offered_ip} | server={server_ip}")

    def on_offer(self, *, iface: str, xid: int, server_ip: Optional[str], yiaddr: Optional[str], mac: str):
        # React to OFFER with REQUEST (client mode)
        pend = self._pending_client.get(xid)
        if not pend:
            # Not our transaction; ignore
            return
        srv = server_ip
        ip = yiaddr
        if not srv or not ip:
            self.log.log_message(f"[DHCP][client] ⚠️ OFFER missing server_id/yiaddr (xid=0x{xid:08x}); ignoring")
            return
        self._client_send_request(iface=iface, xid=xid, server_ip=srv, offered_ip=ip, mac=mac)
        pend.update({"state": "REQUEST", "server_id": srv, "requested_ip": ip})

    def on_ack(self, *, xid: int, yiaddr: str, lease_time: Optional[int]):
        pend = self._pending_client.get(xid)
        if not pend:
            return
        iface = pend["iface"]
        self.log.log_message(
            f"[DHCP][client] ✅ ACK on {iface} | xid=0x{xid:08x} | ip={yiaddr} | lease={lease_time or '-'}s"
        )
        # You could configure the OS IP here (platform-specific). For now we just mark complete.
        pend["state"] = "BOUND"
        pend["bound_ip"] = yiaddr
        pend["lease_time"] = lease_time

    # ---------------- Server mode ----------------

    def _server_ip(self, iface: str) -> Optional[str]:
        return self._server_ip_static or self._iface_ipv4(iface)

    def _pool_take(self) -> Optional[str]:
        if not self._pool:
            return None
        for ip in self._pool:
            # naive: not tracking in-use at this moment (we track on ACK)
            return ip
        return None

    def _server_reply_common(self, *, dst_mac: str, client_mac: str, xid: int, yiaddr: str,
                             server_ip: str, msg_type: str, lease_time: int,
                             subnet_mask: Optional[str], router: Optional[str], dns: Optional[List[str]],
                             broadcast: bool) -> Ether:
        # If client set broadcast flag, we broadcast. Otherwise unicast to client MAC.
        ether_dst = "ff:ff:ff:ff:ff:ff" if broadcast else dst_mac
        ip_dst = "255.255.255.255" if broadcast else "0.0.0.0"
        opts = [
            ("message-type", msg_type),
            ("server_id", server_ip),
            ("lease_time", lease_time),
        ]
        if subnet_mask:
            opts.append(("subnet_mask", subnet_mask))
        if router:
            opts.append(("router", router))
        if dns:
            opts.append(("name_server", dns[0]))
        opts.append(("end", 0))

        src_mac = get_if_hwaddr(self._find_iface_by_mac(dst_mac) or "")
        if not src_mac:
            # Best-effort; many drivers accept any src MAC set by the NIC; fallback to interface that will be used in sendp call
            src_mac = get_if_hwaddr(self._last_iface_for_send or "")

        pkt = (
            Ether(dst=ether_dst, src=src_mac) /
            IP(src=server_ip, dst=ip_dst) /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=yiaddr, siaddr=server_ip, chaddr=self._chaddr(client_mac), xid=xid, htype=1, hlen=6) /
            DHCP(options=opts)
        )
        return pkt

    def _find_iface_by_mac(self, mac: str) -> Optional[str]:
        try:
            import psutil
            for nic, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if getattr(a, "address", "").lower() == mac.lower():
                        return nic
        except Exception:
            pass
        return None

    def server_offer(self, *, iface: str, xid: int, client_mac: str, broadcast: bool,
                     yiaddr: Optional[str] = None, lease_time: int = 3600,
                     subnet_mask: Optional[str] = None, router: Optional[str] = None, dns: Optional[List[str]] = None):
        if yiaddr is None:
            yiaddr = self._pool_take()
        server_ip = self._server_ip(iface)
        if not server_ip or not yiaddr:
            self.log.log_message("[DHCP][server] ❌ cannot send OFFER: missing server_ip or pool address")
            return
        pkt = self._server_reply_common(
            dst_mac=client_mac, client_mac=client_mac, xid=xid, yiaddr=yiaddr, server_ip=server_ip,
            msg_type="offer", lease_time=lease_time, subnet_mask=subnet_mask, router=router, dns=dns,
            broadcast=broadcast
        )
        self._last_iface_for_send = iface
        self.sniffer.sendp(pkt, iface=iface)
        self.log.log_message(
            f"[DHCP][server] 🎁 OFFER on {iface} | xid=0x{xid:08x} | yiaddr={yiaddr} | to={client_mac}"
        )
        # Track what we offered (simplified)
        self._leases.setdefault(client_mac, {})["pending_offer"] = {"xid": xid, "yiaddr": yiaddr, "ts": time.time()}

    def server_ack(self, *, iface: str, xid: int, client_mac: str, yiaddr: str, broadcast: bool,
                   lease_time: int = 3600, subnet_mask: Optional[str] = None, router: Optional[str] = None,
                   dns: Optional[List[str]] = None):
        server_ip = self._server_ip(iface)
        if not server_ip:
            self.log.log_message("[DHCP][server] ❌ cannot send ACK: missing server_ip")
            return
        pkt = self._server_reply_common(
            dst_mac=client_mac, client_mac=client_mac, xid=xid, yiaddr=yiaddr, server_ip=server_ip,
            msg_type="ack", lease_time=lease_time, subnet_mask=subnet_mask, router=router, dns=dns,
            broadcast=broadcast
        )
        self._last_iface_for_send = iface
        self.sniffer.sendp(pkt, iface=iface)
        # Record lease
        self._leases[client_mac] = {"ip": yiaddr, "granted": time.time(), "expires": time.time()+lease_time, "xid": xid}
        self.log.log_message(
            f"[DHCP][server] ✅ ACK on {iface} | xid=0x{xid:08x} | yiaddr={yiaddr} | to={client_mac}"
        )

    def server_nak(self, *, iface: str, xid: int, client_mac: str, broadcast: bool, msg: str = "NAK"):
        server_ip = self._server_ip(iface)
        if not server_ip:
            self.log.log_message("[DHCP][server] ❌ cannot send NAK: missing server_ip")
            return
        ether_dst = "ff:ff:ff:ff:ff:ff" if broadcast else client_mac
        pkt = (
            Ether(dst=ether_dst, src=get_if_hwaddr(iface)) /
            IP(src=server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, siaddr=server_ip, chaddr=self._chaddr(client_mac), xid=xid, htype=1, hlen=6) /
            DHCP(options=[("message-type", "nak"), ("message", msg), ("server_id", server_ip), "end"])
        )
        self._last_iface_for_send = iface
        self.sniffer.sendp(pkt, iface=iface)
        self.log.log_message(f"[DHCP][server] ⛔ NAK on {iface} | xid=0x{xid:08x} | to={client_mac} | msg={msg}")
class TransportDHCPManager:
    """
    (Your existing class) + active send support via self.sniffer.
    Enable client mode:  self.enable_client(sniffer)
    Enable server mode:  self.enable_server(sniffer, pool_cidr="192.168.50.0/24", server_ip="192.168.50.1")
    """

    # Message map kept the same...
    _MTYPES = {
        1: ("DISCOVER", "🛰️"),
        2: ("OFFER",    "🎁"),
        3: ("REQUEST",  "🙋"),
        4: ("DECLINE",  "🙅"),
        5: ("ACK",      "✅"),
        6: ("NAK",      "⛔"),
        7: ("RELEASE",  "🧹"),
        8: ("INFORM",   "📝"),
    }

    def __init__(self, router_logger, *, txn_ttl_sec: int = 180, lease_ttl_sec: int = 24*3600):
        self.logger = router_logger
        self.txn_ttl = txn_ttl_sec
        self.lease_ttl = lease_ttl_sec
        self._txns: Dict[int, Dict[str, Any]] = {}
        self._leases: Dict[str, Dict[str, Any]] = {}
        self._last_gc = time.time()
        self._gc_interval = 30
        self.logger.log_message("[Transport][⚙️ DHCP] Manager ready.")
        # NEW:
        self._active: Optional[TransportDHCPActiveAgent] = None
        self._client_mode = False
        self._server_mode = False

    # -------- enable active modes --------
    def enable_client(self, sniffer) -> None:
        self._active = TransportDHCPActiveAgent(sniffer=sniffer, logger=self.logger)
        self._client_mode = True
        self.logger.log_message("[Transport][⚙️ DHCP] Client mode enabled.")

    def enable_server(self, sniffer, *, pool_cidr: str, server_ip: Optional[str] = None) -> None:
        self._active = TransportDHCPActiveAgent(sniffer=sniffer, logger=self.logger, pool_cidr=pool_cidr, server_ip=server_ip)
        self._server_mode = True
        self.logger.log_message(f"[Transport][⚙️ DHCP] Server mode enabled (pool={pool_cidr}, server_ip={server_ip or 'auto'})")

    # Simple helper for client: kick off a discover now
    def client_start(self, iface: str) -> Optional[int]:
        if not (self._active and self._client_mode):
            self.logger.log_message("[Transport][⚙️ DHCP] client_start ignored (client mode not enabled)")
            return None
        return self._active.client_discover(iface)

    # ---------- Public entry point (unchanged signature) ----------
    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool:
        from scapy.layers.dhcp import DHCP as _DHCP

        if _DHCP is None or BOOTP is None:
            return False
        if not packet.haslayer(BOOTP) or not packet.haslayer(_DHCP):
            return False
        if not (67 in (sport, dport) or 68 in (sport, dport)):
            return False

        bp = packet[BOOTP]
        dh = packet[_DHCP]
        xid = int(getattr(bp, "xid", 0))
        mac = self._mac_from_bootp(bp)
        msg_id, msg_name, emoji = self._message_type(dh)

        yiaddr = getattr(bp, "yiaddr", "0.0.0.0")
        siaddr = getattr(bp, "siaddr", "0.0.0.0")
        req_ip = self._opt_value(dh.options, "requested_addr")
        server_id = self._opt_value(dh.options, "server_id")
        lease_time = self._opt_value(dh.options, "lease_time")
        prl = self._opt_value(dh.options, "param_req_list") or []
        host = self._opt_value(dh.options, "hostname")
        agent = self._opt_value(dh.options, "agent_info")

        role = self._guess_role(sport, dport)
        iface = inbound_iface.split("_")[-1]
        self._log_summary(
            emoji=emoji, msg=msg_name, iface=iface,
            src=f"{src_ip}:{sport}", dst=f"{dst_ip}:{dport}",
            mac=mac, xid=xid, yiaddr=yiaddr, req_ip=req_ip,
            srv=server_id or siaddr, host=host, lease=lease_time, prl=prl, vend=self._opt_value(dh.options, "vendor_class_id"),
            agent=agent, role=role
        )

        # --- ACTIVE REACTIONS ---
        if self._active:
            # Client reactions
            if self._client_mode:
                if msg_name == "OFFER":
                    self._active.on_offer(
                        iface=iface, xid=xid, server_ip=server_id or siaddr,
                        yiaddr=yiaddr if yiaddr != "0.0.0.0" else req_ip, mac=get_if_hwaddr(iface)
                    )
                elif msg_name == "ACK":
                    self._active.on_ack(xid=xid, yiaddr=yiaddr, lease_time=lease_time)

            # Server reactions
            if self._server_mode:
                # broadcast flag in BOOTP (bit 15)
                broadcast = bool(getattr(bp, "flags", 0) & 0x8000)
                if msg_name == "DISCOVER":
                    self._active.server_offer(
                        iface=iface, xid=xid, client_mac=mac, broadcast=broadcast
                    )
                elif msg_name == "REQUEST":
                    # If client requested a specific IP and the server_id matches us (or is absent), ACK it if available
                    our_ip = self._active._server_ip(iface)
                    if (not server_id) or (our_ip and server_id == our_ip):
                        yi = req_ip or yiaddr
                        if yi:
                            self._active.server_ack(
                                iface=iface, xid=xid, client_mac=mac, yiaddr=yi, broadcast=broadcast
                            )
                        else:
                            self._active.server_nak(iface=iface, xid=xid, client_mac=mac, broadcast=broadcast, msg="No requested address")
                # You can add DECLINE/RELEASE handling if desired

        # Passive state/lease tracking (unchanged)
        self._update_transaction(xid=xid, msg=msg_name, mac=mac, req_ip=req_ip, yiaddr=yiaddr,
                                 server=server_id or siaddr, host=host, lease_time=lease_time)
        self._maybe_update_lease(msg_name, mac, yiaddr, lease_time, server_id or siaddr)
        self._maybe_gc()
        return True

    # ---------- Existing helpers from your class (unchanged) ----------
    def _fmt_prl(self, prl: list) -> str:
        try: return ",".join(str(x) for x in prl)
        except Exception: return "-"

    def _mac_from_bootp(self, bp: Any) -> str:
        try:
            raw: bytes = bytes(bp.chaddr)
            hlen = int(getattr(bp, "hlen", 6)) or 6
            return ":".join(f"{b:02x}" for b in raw[:hlen])
        except Exception:
            return "00:00:00:00:00:00"

    def _message_type(self, dh_opts: Any) -> Tuple[int, str, str]:
        mval = self._opt_value(dh_opts.options if hasattr(dh_opts, "options") else dh_opts, "message-type")
        if isinstance(mval, (bytes, bytearray)):
            try: mval = int(mval[0])
            except Exception: mval = None
        if isinstance(mval, str):
            name = mval.upper(); inv = {v[0]: k for k, v in self._MTYPES.items()}
            mid = inv.get(name)
            if mid is not None: return mid, name, self._MTYPES[mid][1]
        if isinstance(mval, int) and mval in self._MTYPES:
            name, emoji = self._MTYPES[mval]; return mval, name, emoji
        return 0, "UNKNOWN", "❔"

    def _opt_value(self, options: list, key: str):
        if not options: return None
        for opt in options:
            if isinstance(opt, tuple) and opt and opt[0] == key:
                return opt[1]
        return None

    def _guess_role(self, sport: int, dport: int) -> str:
        if sport == 68 and dport == 67: return "client→server"
        if sport == 67 and dport == 68: return "server→client"
        return "peer"

    def _log_summary(self, *, emoji: str, msg: str, iface: str, src: str, dst: str, mac: str, xid: int,
                     yiaddr: str, req_ip: Optional[str], srv: Optional[str], host: Optional[str],
                     lease: Optional[int], prl: list, vend: Optional[str], agent: Any, role: str) -> None:
        parts = [
            f"{emoji} {msg}", f"if={iface}", f"{src} → {dst}", f"MAC={mac}", f"xid=0x{xid:08x}",
        ]
        if req_ip: parts.append(f"req={req_ip}")
        if yiaddr and yiaddr != "0.0.0.0": parts.append(f"yiaddr={yiaddr}")
        if srv and srv != "0.0.0.0": parts.append(f"server={srv}")
        if host: parts.append(f"host={host}")
        if lease: parts.append(f"lease={lease}s")
        if vend: parts.append(f"vcid={vend}")
        if prl:  parts.append(f"prl={self._fmt_prl(prl)}")
        if agent: parts.append("opt82")
        parts.append(f"role={role}")
        self.logger.log_message("[Transport][🚀 UDP][⚙️ DHCP] " + " | ".join(parts))

    # ---------- Helpers: state & leases ----------

    def _update_transaction(
        self, *, xid: int, msg: str, mac: str, req_ip: Optional[str], yiaddr: str,
        server: Optional[str], host: Optional[str], lease_time: Optional[int],
    ) -> None:
        now = time.time()
        t = self._txns.get(xid) or {
            "created": now,
            "mac": mac,
            "history": [],
        }
        t["last"] = now
        t["server"] = server or t.get("server")
        t["host"] = host or t.get("host")
        t["req_ip"] = req_ip or t.get("req_ip")
        if yiaddr and yiaddr != "0.0.0.0":
            t["yiaddr"] = yiaddr
        if lease_time:
            t["lease_time"] = lease_time
        t["history"].append(msg)
        self._txns[xid] = t

    def _maybe_update_lease(self, msg: str, mac: str, yiaddr: str, lease_time: Optional[int], server: Optional[str]) -> None:
        # On ACK, record/refresh lease
        if msg == "ACK" and yiaddr and yiaddr != "0.0.0.0":
            now = time.time()
            ttl = int(lease_time or self.lease_ttl)
            self._leases[mac] = {
                "ip": yiaddr,
                "server": server,
                "granted": now,
                "expires": now + ttl,
            }
            self.logger.log_message(
                f"[Transport][🚀 UDP][⚙️ DHCP] 🗂️ lease | MAC={mac} → IP={yiaddr} | server={server or '-'} | ttl={ttl}s"
            )
        elif msg == "NAK":
            # On NAK, clear any pending lease idea (soft)
            if mac in self._leases:
                self.logger.log_message(
                    f"[Transport][🚀 UDP][⚙️ DHCP] 🗑️ lease | NAK for MAC={mac} cleared cached lease {self._leases[mac].get('ip','-')}"
                )
                self._leases.pop(mac, None)

    def _maybe_gc(self) -> None:
        now = time.time()
        if now - self._last_gc < self._gc_interval:
            return
        # GC transactions
        expired_xids = [x for x, t in self._txns.items() if now - t.get("last", t.get("created", 0)) > self.txn_ttl]
        for x in expired_xids:
            self._txns.pop(x, None)
        # GC leases (soft expiry notice)
        expired_macs = [m for m, l in self._leases.items() if now >= l.get("expires", 0)]
        for m in expired_macs:
            ip = self._leases[m].get("ip", "-")
            self.logger.log_message(f"[Transport][🚀 UDP][⚙️ DHCP] ⏳ lease-expired | MAC={m} IP={ip}")
            self._leases.pop(m, None)
        self._last_gc = now

class TransportRTPManager:
    """
    Standalone RTP (VoIP) parser & logger.

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool

    What it does:
      • Best-effort RTP v2 header parsing (version/PT/marker/seq/ts/ssrc)
      • CSRC & Extension header skipping (keeps offset correct)
      • Optional DTMF (RFC 4733 / 'telephone-event') peek when PT==101
      • Per-SSRC stream cache to de-dupe "new stream" logs + light stats
      • Periodic GC of stale stream entries (configurable timeout)

    Log style matches TransportManager:
      [Transport][🚀 UDP][🔊 RTP] ...
    """

    # Common/static PTs + friendly names (dynamic 96–127 shown as "Dynamic(n)")
    RTP_PT_NAMES = {
        0: "PCMU",   3: "GSM",   4: "G723",  8: "PCMA",   9: "G722",
        10: "L16/2ch", 11: "L16/1ch", 15: "G728", 18: "G729",
        26: "JPEG", 31: "H261", 32: "MPV", 33: "MP2T", 34: "H263",
        96: "H264", 97: "H264", 98: "H265/HEVC", 100: "VP8", 101: "Telephone-Event", 103: "Opus",
    }

    def __init__(self, router_logger, stream_timeout: int = 300):
        self.logger = router_logger
        self._stream_timeout = stream_timeout
        # Keyed by SSRC (int) → dict(state)
        self._streams: Dict[int, Dict[str, int]] = {}
        self._last_gc = time.time()
        self.logger.log_message("[Transport][🔊 RTP] Manager ready.")

    # -------------------- Public entry point --------------------

    def handle(
        self,
        packet: Packet,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        inbound_iface: Optional[str] = None,
    ) -> bool:
        """Returns True if the packet looked like RTP and was handled (logged)."""
        if Raw is None or not packet.haslayer(Raw):
            # Nothing to parse; not necessarily an error (could be too short)
            return False

        payload = bytes(packet[Raw].load)
        if len(payload) < 12:
            # Too short for a valid RTP v2 header
            self.logger.log_message(
                f"[Transport][🚀 UDP][🔊 RTP] Short/Non-RTP packet from {src_ip}:{sport} (len={len(payload)})"
            )
            return True

        try:
            b1, b2, seq, ts, ssrc = struct.unpack("!BBHII", payload[:12])
        except struct.error:
            self.logger.log_message(
                f"[Transport][🚀 UDP][🔊 RTP] Malformed header from {src_ip}:{sport}"
            )
            return True

        version = (b1 >> 6) & 0x03
        padding = (b1 >> 5) & 0x01
        extension = (b1 >> 4) & 0x01
        csrc_count = b1 & 0x0F
        marker = (b2 >> 7) & 0x01
        pt = b2 & 0x7F

        if version != 2:
            self.logger.log_message(
                f"[Transport][🚀 UDP][🔊 RTP] Non-RTPv2/unknown version={version} from {src_ip}:{sport}"
            )
            return True

        # Calculate header offset (12 + 4*CSRC + ext header if present)
        offset = 12 + (csrc_count * 4)
        if extension:
            # Extension header: 16-bit profile, 16-bit length (in 32-bit words), then data
            if len(payload) >= offset + 4:
                _, ext_len_words = struct.unpack("!HH", payload[offset:offset + 4])
                offset += 4 + (ext_len_words * 4)
            else:
                # Malformed but still log the core header fields
                pass

        # Name the payload type
        pt_name = self.RTP_PT_NAMES.get(pt, f"Dynamic({pt})" if 96 <= pt <= 127 else f"PT({pt})")

        # Initialize/update per-SSRC stream state
        new_stream = False
        st = self._streams.get(ssrc)
        if st is None:
            new_stream = True
            st = {"last_seq": seq, "last_ts": ts}
            self._streams[ssrc] = st
        else:
            st["last_seq"] = seq
            st["last_ts"] = ts

        # Build log details
        details = [f"Ver:{version}", f"PT:{pt_name}", f"Seq:{seq}", f"TS:{ts}", f"SSRC:0x{ssrc:08x}"]
        if csrc_count:
            details.append(f"CSRCs:{csrc_count}")
        if extension:
            details.append("Ext")
        if padding:
            details.append("Pad")
        if marker:
            details.append("[Marker]")

        prefix = "[Transport][🚀 UDP][🔊 RTP]"
        if new_stream:
            self.logger.log_message(
                f"{prefix} New stream {src_ip}:{sport} → {dst_ip}:{dport} | " + ", ".join(details)
            )
        else:
            self.logger.log_message(
                f"{prefix} {src_ip}:{sport} → {dst_ip}:{dport} | " + ", ".join(details)
            )

        # Optional: Peek DTMF when PT==101 (telephone-event, unencrypted)
        if pt == 101 and len(payload) >= offset + 4:
            event_id = payload[offset]
            end_bit = (payload[offset + 1] >> 7) & 0x01
            volume = payload[offset + 1] & 0x3F
            duration = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            evt_name = self._dtmf_name(event_id)
            self.logger.log_message(
                f"{prefix} DTMF event={evt_name} ({event_id}) vol={volume} dur={duration} end={end_bit}"
            )

        self._maybe_gc()
        return True

    # -------------------- Helpers --------------------

    def _dtmf_name(self, event_id: int) -> str:
        mapping = {
            0: "0", 1: "1", 2: "2", 3: "3", 4: "4", 5: "5", 6: "6", 7: "7",
            8: "8", 9: "9", 10: "*", 11: "#", 12: "A", 13: "B", 14: "C", 15: "D"
        }
        return mapping.get(event_id, f"ev{event_id}")

    def _maybe_gc(self) -> None:
        now = time.time()
        if now - self._last_gc < 60:
            return
        # Here we don't track last-seen timestamps per SSRC; add if desired.
        # For a simple GC, just clear entries older than _stream_timeout since last GC.
        # (Lightweight: avoids unbounded growth without per-packet timestamps.)
        if self._streams and (now - self._last_gc) > self._stream_timeout:
            count = len(self._streams)
            self._streams.clear()
            self.logger.log_message(f"[Transport][🔊 RTP] 🧹 GC pruned {count} stream entries")
        self._last_gc = now

class TransportKerberosManager:
    """
    UDP Kerberos (port 88) parser & logger.

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool

    What it does:
      • Detects top-level Kerberos APPLICATION tag (DER) and classifies message:
            AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP, KRB-ERROR, etc.
      • Emits concise logs with direction, guessed realm and SPN (best-effort)
      • Tracks request→response latency by (client_ip, sport, server_ip)
      • Rate-limits duplicate lines and performs periodic GC of pending entries
    """

    # Application tag byte → name (constructed bit set; values shown here include class/constructed)
    # In DER: class=APPLICATION(0b01), constructed=1, tag number (e.g. 10..30)
    # First byte for [APPLICATION n | constructed] when n<31 is: 0x60 + n (0x60..0x7F).
    _APP_TAG_TO_NAME = {
        0x6A: "AS-REQ",
        0x6B: "AS-REP",
        0x6C: "TGS-REQ",
        0x6D: "TGS-REP",
        0x6E: "AP-REQ",
        0x6F: "AP-REP",
        0x70: "KRB-SAFE",
        0x71: "KRB-PRIV",
        0x72: "KRB-CRED",
        0x7E: "KRB-ERROR",
        # Not exhaustive; add more if you care (ENC types, etc.)
    }

    # Simple patterns to fish out a realm/SPN without full ASN.1:
    _REALM_RE = re.compile(rb"\b[A-Z0-9][A-Z0-9.-]+[A-Z0-9]\b")
    _SPN_HINTS = (b"krbtgt/", b"HTTP/", b"cifs/", b"ldap/", b"MSSQLSvc/", b"host/")

    def __init__(self, router_logger, *, pending_ttl_sec: int = 20, gc_interval_sec: int = 10):
        self.log = router_logger
        self._pending_ttl = int(pending_ttl_sec)
        self._gc_interval = int(gc_interval_sec)
        # key = (client_ip, client_port, server_ip) → {"ts": float, "kind": str}
        self._pending: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
        self._recent_msgs: Dict[int, float] = defaultdict(float)
        self._recent_window = 2.0
        self._last_gc = time.time()
        self.log.log_message("[Transport][🔑 Kerberos] Manager ready.")

    # -------------------- Public entry --------------------

    def handle(
        self,
        packet: Packet,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        inbound_iface: str,
    ) -> bool:
        """Returns True if treated as Kerberos (UDP/88) and logged, else False."""
        if UDP is None or Raw is None:
            return False
        if not packet.haslayer(UDP):
            return False
        if not (sport == 88 or dport == 88):
            return False
        if not packet.haslayer(Raw):
            # Nothing to parse but we claim it to avoid 'Undecoded'
            self._rate_log(f"[Transport][🚀 UDP][🔑 Kerberos] if={inbound_iface.split('_')[-1]} "
                           f"{src_ip}:{sport} → {dst_ip}:{dport} (no payload)")
            return True

        payload = bytes(packet[Raw].load or b"")
        iface = inbound_iface.split("_")[-1]
        direction = "REQ" if dport == 88 else "RSP"

        kind = self._classify_top_level(payload) or "-"
        realm = self._guess_realm(payload) or "-"
        spn = self._guess_spn(payload) or "-"

        # Pending tracking for latency (only for requests heading to :88)
        latency = None
        key = (src_ip, sport, dst_ip)
        if direction == "REQ":
            self._pending[key] = {"ts": time.time(), "kind": kind}
        else:
            # response path: swap to find original requester
            rev_key = (dst_ip, dport, src_ip)
            pend = self._pending.pop(rev_key, None)
            if pend:
                latency = int((time.time() - pend["ts"]) * 1000)

        lat_str = f" {latency}ms" if latency is not None else ""
        self._rate_log(
            f"[Transport][🚀 UDP][🔑 Kerberos] {direction} if={iface} "
            f"{src_ip}:{sport} → {dst_ip}:{dport} | {kind} size={len(payload)}B realm={realm} spn={spn}{lat_str}"
        )

        # Extra hint for KRB-ERROR: try to surface an ASCII message (best-effort)
        if kind == "KRB-ERROR":
            emsg = self._extract_readable_tail(payload)
            if emsg:
                self._rate_log(f"[Transport][🔑 Kerberos][⚠️ KRB-ERROR] {emsg}")

        self._maybe_gc()
        return True

    # -------------------- Classifiers / heuristics --------------------

    def _classify_top_level(self, data: bytes) -> Optional[str]:
        """
        Minimal DER sniff: read first tag byte and map if it's APPLICATION n (constructed).
        Kerberos outermost is usually [APPLICATION x] SEQUENCE → first byte 0x6A..0x7E.
        """
        if not data:
            return None
        tag = data[0]
        # Quick sanity: APPLICATION (01), constructed (1), tag < 31 → 0x60..0x7F
        if 0x60 <= tag <= 0x7F:
            return self._APP_TAG_TO_NAME.get(tag, f"APP({tag - 0x60})")
        return None

    def _guess_realm(self, data: bytes) -> Optional[str]:
        """
        Grab a plausible Kerberos REALM (ALLCAPS.DOTS) from ASCII zones.
        """
        # Limit scanning to first ~512 bytes for speed
        sample = data[:512]
        # Prefer ALL CAPS with dot(s)
        for m in self._REALM_RE.finditer(sample):
            token = m.group(0)
            if b"." in token and token.isupper():
                try:
                    return token.decode("ascii", "ignore")
                except Exception:
                    pass
        # Fallback: return first upper-ish token with dot
        for m in self._REALM_RE.finditer(sample):
            token = m.group(0)
            if b"." in token:
                try:
                    return token.decode("ascii", "ignore")
                except Exception:
                    pass
        return None

    def _guess_spn(self, data: bytes) -> Optional[str]:
        """
        Fish out common SPN patterns like 'krbtgt/REALM@REALM', 'HTTP/host@REALM', etc.
        """
        sample = data[:800]
        best = None
        for hint in self._SPN_HINTS:
            idx = sample.lower().find(hint.lower())
            if idx >= 0:
                # read until delimiter (NUL, quote, newline, or non-printable)
                end = idx
                while end < len(sample) and 32 <= sample[end] <= 126:
                    end += 1
                cand = sample[idx:end]
                # minor cleanup: stop before spaces or trailing commas
                cand = cand.rstrip(b",; ")
                if cand:
                    best = cand
                    break
        if best:
            try:
                return best.decode("utf-8", "ignore")
            except Exception:
                pass
        return None

    def _extract_readable_tail(self, data: bytes) -> Optional[str]:
        """
        KRB-ERROR often includes an e-text; surface a readable tail line if present.
        """
        tail = data[-200:]
        try:
            txt = tail.decode("utf-8", "ignore")
        except Exception:
            txt = ""
        # pick a printable line with at least a few letters
        lines = [L.strip() for L in txt.splitlines() if len(L.strip()) >= 6]
        return lines[-1][:160] if lines else None

    # -------------------- Utils --------------------

    def _rate_log(self, msg: str) -> None:
        h = hash(msg)
        t = time.time()
        if t - self._recent_msgs[h] >= self._recent_window:
            self._recent_msgs[h] = t
            self.log.log_message(msg)

    def _maybe_gc(self) -> None:
        now = time.time()
        if now - self._last_gc < self._gc_interval:
            return
        dead = [k for k, v in self._pending.items() if now - v.get("ts", 0) > self._pending_ttl]
        for k in dead:
            self._pending.pop(k, None)
        if dead:
            self.log.log_message(f"[Transport][🔑 Kerberos] 🧹 GC expired {len(dead)} pending entries")
        self._last_gc = now

class TransportIPv6Manager:
    """
    Robust IPv6 transport/exthdr summarizer with a single public handle().
    Emits one concise log line per packet, matching the house style.
    """

    def __init__(self, router_logger, early_claim_hop_by_hop: bool = True, ext_depth_limit: int = 16):
        self.log = router_logger
        self.early_claim_hbh = bool(early_claim_hop_by_hop)
        self.ext_depth_limit = max(4, int(ext_depth_limit))
        self._rl_last: dict[str, float] = {}
        self.log.log_message("[Transport][🌍 IPv6] Manager ready.")

    # -------------------- Public entrypoint --------------------
    def handle(self, packet: Packet, inbound_iface: Optional[str] = None) -> bool:
        try:
            if IPv6 is None or not hasattr(packet, "haslayer") or not packet.haslayer(IPv6):
                return False

            ip6 = packet[IPv6]
            src_ip = getattr(ip6, "src", "?")
            dst_ip = getattr(ip6, "dst", "?")
            iface_short = (inbound_iface or "").split("_")[-1] if inbound_iface else "?"

            # Walk extension headers without forcing Scapy to rebuild bytes
            chain, l4 = self._walk_ipv6_chain(ip6)

            # Plain IPv6 (no EH/L4 we care about) — emit a short, safe summary
            if not chain and l4 is None:
                nh = getattr(ip6, "nh", None)
                nh_name = self._nh_name(nh)
                hlim = getattr(ip6, "hlim", None)
                flow = getattr(ip6, "fl", None)

                tail = self._get_tail_bytes(ip6)
                tail_len = len(tail)
                tail_kind = "none" if nh == 59 or tail_len == 0 else "raw"

                extra: List[str] = []
                if nh in (50, 51):  # ESP / AH hints
                    extra.append("ipsec")
                elif nh == 41 and tail_len >= 1 and (tail[0] & 0xF0) == 0x60:
                    extra.append("v6-in-v6")
                elif nh == 4 and tail_len >= 1 and (tail[0] >> 4) == 4:
                    extra.append("v4-in-v6")
                elif nh == 47 and tail_len >= 4:
                    try:
                        flags = int.from_bytes(tail[0:2], "big")
                        extra.append(f"gre-flags=0x{flags:04x}")
                    except Exception:
                        pass

                if tail_len:
                    try:
                        hex_preview = tail[:8].hex()
                        extra.append(f"hex={hex_preview}{'…' if tail_len > 8 else ''}")
                    except Exception:
                        pass

                msg = (f"[Transport][🌍 IPv6] {src_ip} → {dst_ip} on {iface_short} | "
                       f"NH={nh_name} hlim={hlim} fl={self._fmt_flow(flow)} | "
                       f"tail={tail_kind}={tail_len}B" + (f" ({', '.join(extra)})" if extra else ""))
                return self._rl_log(msg, interval=3.0, ret=True)

            # Compose concise line
            parts: List[str] = [f"[Transport][🌍 IPv6] {src_ip} → {dst_ip} on {iface_short}"]

            # EH summary
            if chain:
                parts.append(" | EH: " + ", ".join(self._summarize_eh(h) for h in chain))

            # L4 summary
            if l4 is not None:
                parts.append(" | L4: " + self._summarize_l4(l4))

            # Emit once
            self.log.log_message("".join(parts))

            # Early-claim when HBH is present (to mimic your previous behavior)
            if self.early_claim_hbh and any(self._isinstance_safe(h, IPv6ExtHdrHopByHop) for h in chain):
                return True

            return True
        except Exception as e:
            # Absolutely never let this bubble (avoid destabilizing capture threads)
            try:
                self.log.log_message(f"[Transport][🌍 IPv6] error: {e}")
            except Exception:
                pass
            return False

    # -------------------- Rate-limited logger --------------------
    def _rl_log(self, msg: str, *, key: Optional[str] = None, interval: float = 3.0, ret=False):
        k = key or msg
        now = time.time()
        last = self._rl_last.get(k, 0.0)
        if (now - last) >= interval:
            self._rl_last[k] = now
            try:
                self.log.log_message(msg)
            except Exception:
                pass
        return ret

    # -------------------- Helpers: chain walking --------------------
    def _walk_ipv6_chain(self, ip6: Packet) -> Tuple[List[Packet], Optional[Packet]]:
        """
        Returns (ext_chain, l4_or_None). Safe: no bytes() on layers.
        """
        chain: List[Packet] = []
        layer = getattr(ip6, "payload", None)
        hops = self.ext_depth_limit

        while hops > 0 and layer is not None and hasattr(layer, "payload"):
            hops -= 1

            if self._isinstance_safe(layer, (IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment)):
                chain.append(layer)
                layer = getattr(layer, "payload", None)
                continue

            # Terminal L4 we care about
            if (TCP and self._isinstance_safe(layer, TCP)) or \
               (UDP and self._isinstance_safe(layer, UDP)) or \
               (ICMPv6 and self._isinstance_safe(layer, ICMPv6)):
                return chain, layer

            break

        return chain, None

    # -------------------- Helpers: summaries --------------------
    def _summarize_eh(self, h: Packet) -> str:
        try:
            if self._isinstance_safe(h, IPv6ExtHdrHopByHop):
                return self._summarize_hbh(h)
            if self._isinstance_safe(h, IPv6ExtHdrRouting):
                segs_left = getattr(h, "segleft", None)
                rtype = getattr(h, "type", None)
                return f"Routing(type={rtype},segs_left={segs_left})"
            if self._isinstance_safe(h, IPv6ExtHdrDestOpt):
                opts = getattr(h, "options", None)
                cnt = 0
                if opts:
                    try:
                        cnt = len(list(opts))
                    except Exception:
                        cnt = 1
                return f"DestOpt(opts={cnt})"
            if self._isinstance_safe(h, IPv6ExtHdrFragment):
                off = getattr(h, "offset", None)
                mflag = getattr(h, "m", None)
                ident = getattr(h, "id", None)
                if off == 0 and not mflag:
                    return f"Frag(id={ident},atomic)"
                return f"Frag(id={ident},off={off},more={'1' if mflag else '0'})"
            return h.__class__.__name__
        except Exception:
            return "EH"

    def _summarize_hbh(self, hbh: Packet) -> str:
        items = ["HBH"]
        try:
            opts = getattr(hbh, "options", None)
            if opts:
                names = []
                for o in opts:
                    name = getattr(o, "name", None) or o.__class__.__name__
                    if "RouterAlert" in name or "Router Alert" in name:
                        val = getattr(o, "value", None)
                        names.append(f"RouterAlert{'' if val is None else f'={val}'}")
                    elif "Jumbo" in name:
                        jl = getattr(o, "jumbo_len", None) or getattr(o, "length", None)
                        names.append(f"Jumbo{'' if jl is None else f'={jl}'}")
                    elif "Pad" in name:
                        plen = getattr(o, "optlen", None) or getattr(o, "len", None)
                        names.append(f"Pad{'' if plen is None else f'={plen}'}")
                    else:
                        names.append(name)
                if names:
                    items.append("[" + ",".join(names[:4]) + ("…]" if len(names) > 4 else "]"))
        except Exception:
            pass
        return " ".join(items)

    def _summarize_l4(self, l4: Packet) -> str:
        try:
            if TCP and self._isinstance_safe(l4, TCP):
                flags = getattr(l4, "flags", 0)
                sport = getattr(l4, "sport", "?")
                dport = getattr(l4, "dport", "?")
                return f"TCP {sport}→{dport} flags={flags}"
            if UDP and self._isinstance_safe(l4, UDP):
                sport = getattr(l4, "sport", "?")
                dport = getattr(l4, "dport", "?")
                return f"UDP {sport}→{dport}"
            if ICMPv6 and self._isinstance_safe(l4, ICMPv6):
                t = getattr(l4, "type", "?")
                c = getattr(l4, "code", "?")
                return f"ICMPv6 type={t} code={c}"
            return l4.__class__.__name__
        except Exception:
            return "L4"

    # -------------------- Misc helpers --------------------
    def _isinstance_safe(self, obj: object, cls) -> bool:
        try:
            return cls is not None and isinstance(obj, cls)  # type: ignore[arg-type]
        except Exception:
            return False

    def _nh_name(self, nh: Optional[int]) -> str:
        names = {
            0: "HBH", 4: "IPv4", 41: "IPv6", 43: "Routing", 44: "Fragment",
            50: "ESP", 51: "AH", 58: "ICMPv6", 59: "NoNext", 60: "DestOpt", 47: "GRE",
        }
        try:
            return names.get(int(nh), f"{nh}")
        except Exception:
            return f"{nh}"

    def _fmt_flow(self, fl) -> str:
        try:
            v = int(fl)
            return f"0x{v:05x}"
        except Exception:
            return "0x-----"

    def _get_tail_bytes(self, ip6: Packet) -> bytes:
        """
        Extract trailing bytes *without* forcing a full build.
        Preference order: .payload.original -> .payload.load -> b"".
        """
        try:
            tail = getattr(ip6, "payload", None)
            if tail is None or isinstance(tail, NoPayload):
                return b""
            # Avoid bytes(tail) which can trigger building
            orig = getattr(tail, "original", None)
            if isinstance(orig, (bytes, bytearray, memoryview)):
                return bytes(orig)
            if hasattr(tail, "load"):
                ld = getattr(tail, "load", None)
                if isinstance(ld, (bytes, bytearray, memoryview)):
                    return bytes(ld)
        except Exception:
            pass
        return b""

class TransportOverlayManager:
    """
    Overlay / virtual-network control traffic (e.g., mesh/overlay controllers).

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool

    Behavior:
      • Targets UDP/9993 by default but is protocol-agnostic (can be reused for other overlay ports)
      • Emits a single concise log line per packet (distinct emoji identity 🛰️)
      • Fingerprints payloads and heuristically classifies control vs data vs keepalive
      • Tracks peers (src,dst) with a small time-based cache + GC
    """

    def __init__(self, router_logger, peer_timeout: int = 600):
        self.logger = router_logger
        self.PEER_TIMEOUT = peer_timeout
        self._last_gc = time.time()
        # peer_seen[(a_ip,b_ip)] = last_ts (direction-agnostic order)
        self._peer_seen: Dict[Tuple[str, str], float] = {}
        # tiny cache of small “hello-ish” payload hashes to reduce log spam
        self._hello_fp: Dict[str, float] = {}
        self._zt_peers_lock = threading.RLock()
        self._zt_peers: dict = {}  # peer_id -> {"ips": set[str], "meta": {...}, "last_seen": float}
        self._zt_ip_index: set[str] = set()  # flat set of all peer IPs for O(1) membership checks
        self._zt_ttl: float = 60.0  # default seconds
        self.logger.log_message("[Transport][🛰️ Overlay] Manager ready.")

    # -------------------- Public entry point --------------------
    def handle(
        self,
        packet: Packet,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        inbound_iface: Optional[str] = None,
    ) -> bool:
        """
        Returns True if we consider this overlay traffic (and logged it), else False.
        """
        if not self._is_overlay_port(sport, dport):
            return False

        if Raw is None or not packet.haslayer(Raw):
            self.logger.log_message(
                "[Transport][🚀 UDP][🛰️ Overlay] UDP on port 9993 detected, but no Raw payload."
            )
            return True

        raw_data = bytes(packet[Raw].load) or b""
        if not raw_data:
            return True

        # Summarize in one line
        parts = [f"[Transport][🚀 UDP][🛰️ Overlay] {src_ip}:{sport} → {dst_ip}:{dport}"]

        # Classify payload
        kind = self._classify_payload(raw_data)
        if kind:
            parts.append(f"| Kind: {kind}")

        # Track peer
        s = str(src_ip)
        d = str(dst_ip)

        # order deterministically without producing a variadic tuple
        if s <= d:
            peer_key: tuple[str, str] = (s, d)
        else:
            peer_key = (d, s)

        self._peer_seen[peer_key] = time.time()

        self.logger.log_message(" ".join(parts))
        self._maybe_gc()
        return True

    @property
    def zt_ttl(self) -> float:
        return self._zt_ttl

    def set_zt_ttl(self, seconds: int | float) -> None:
        self._zt_ttl = max(1.0, float(seconds))
        self.logger.log_message(f"[Overlay] TTL set to {self._zt_ttl:.0f}s")
    # -------------------- Helpers --------------------
    def _is_overlay_port(self, sport: int, dport: int) -> bool:
        return sport == 9993 or dport == 9993

    def _classify_payload(self, raw: bytes) -> str:
        if len(raw) < 8:
            return "Keepalive"
        h = hashlib.sha1(raw[:32]).hexdigest()[:8]
        if h not in self._hello_fp:
            self._hello_fp[h] = time.time()
            return f"Control/Hello fp={h}"
        return "Control"

    def _maybe_gc(self) -> None:
        now = time.time()
        if now - self._last_gc < 60:
            return
        expired = [k for k, ts in self._peer_seen.items() if now - ts > self.PEER_TIMEOUT]
        for k in expired:
            self._peer_seen.pop(k, None)
        if expired:
            self.logger.log_message(f"[Transport][🛰️ Overlay] 🧹 GC pruned {len(expired)} peer entries")
        self._last_gc = now
    def _zt_note_peer(self, ip, port):
        e = self._zt_peers.setdefault(ip, {"ports": set(), "ts": 0})
        e["ports"].add(int(port))
        e: dict[str, Union[int, set, float]] = {}
        e["ts"] = time.time()  # OK now

    def _zt_is_peer(self, ip):
        # GC stale
        now = time.time()
        for k,v in list(self._zt_peers.items()):
            if now - v["ts"] > self._zt_ttl:
                self._zt_peers.pop(k, None)
        return ip in self._zt_peers

    # --- When you already detect ZeroTier on 9993 (your existing handler) ---
    def _handle_overlay_packet(self, pkt, src, dst, sport, dport, iface):
        # existing Hello/Control parsing...
        # after you accept it's ZeroTier:
        self._zt_note_peer(src, sport)
        self._zt_note_peer(dst, dport)
        self.logger.log_message(f"[Transport][🚀 UDP][🛰️ Overlay] {src}:{sport} → {dst}:{dport} | Control/Hello")

    def _zt__ensure_state(self):
        """Create overlay containers if missing (defensive for hot-reloads/old pickles)."""
        if not hasattr(self, "_zt_peers_lock"):
            self._zt_peers_lock = threading.RLock()
        if not hasattr(self, "_zt_peers"):
            self._zt_peers = {}
        if not hasattr(self, "_zt_ip_index"):
            self._zt_ip_index = set()

    def _zt_set_peers(self, peers: dict[str, dict] | None):
        """
        Replace the overlay peer table.
        Expected shape: {peer_id: {"ips": iterable[str], ...}, ...}
        """
        self._zt__ensure_state()
        with self._zt_peers_lock:
            self._zt_peers = {}
            self._zt_ip_index = set()
            if not peers:
                return
            for pid, rec in peers.items():
                ips = set()
                if isinstance(rec, dict):
                    val = rec.get("ips")
                    if isinstance(val, (list, set, tuple)):
                        for ip in val:
                            try:
                                ips.add(str(ipaddress.ip_address(str(ip).strip())))
                            except Exception:
                                continue
                self._zt_peers[pid] = {"ips": ips, "meta": rec, "last_seen": time.time()}
                self._zt_ip_index.update(ips)

    def _zt_add_peer(self, peer_id: str, ips: list[str] | set[str] | tuple[str, ...]):
        self._zt__ensure_state()
        with self._zt_peers_lock:
            rec = self._zt_peers.get(peer_id) or {"ips": set(), "meta": {}, "last_seen": 0.0}
            for ip in ips or []:
                try:
                    ipn = str(ipaddress.ip_address(str(ip).strip()))
                    rec["ips"].add(ipn)
                    self._zt_ip_index.add(ipn)
                except Exception:
                    pass
            rec["last_seen"] = time.time()
            self._zt_peers[peer_id] = rec

    def _zt_remove_peer(self, peer_id: str):
        self._zt__ensure_state()
        with self._zt_peers_lock:
            rec = self._zt_peers.pop(peer_id, None)
            if rec and isinstance(rec, dict):
                ips = rec.get("ips") or set()
                # rebuild index minus removed ips
                for ip in ips:
                    # only drop if no other peer still advertises it
                    still = any(ip in (r.get("ips") or set()) for r in self._zt_peers.values())
                    if not still and ip in self._zt_ip_index:
                        self._zt_ip_index.remove(ip)
class TransportEphemeralTCPManager:
    """
    Non-blocking high-port↔high-port TCP observer.

    • Learns FTP PASV data ports from control channel (21/990)
    • Notes SMB/RPC aux flows following TCP/445
    • Notes Steam control/aux (common Steam ports)
    • Notes Mongo aux (27017-27019)
    • Detects "Alt-TLS" via TLS record bytes on arbitrary ports
    • Emits ONE concise classification line per flow (rate-safe)
    • Never mutates packets; never short-circuits other handlers unless it actually emitted

    Return contract:
      - return False for SYN/ACK/ACKs (no payload), or whenever we didn't emit yet
      - return True only after payload was seen AND we emitted a classification line
    """

    # --- TTLs / limits ---
    CACHE_TTL_SEC = 120          # generic hint lifetime
    SMB_TTL_SEC   = 120
    STEAM_TTL_SEC = 120
    MONGO_TTL_SEC = 120
    MAX_BUF_BYTES = 512          # tiny rolling buffer per direction
    FALLBACK_EMIT_AFTER = 0.5    # seconds after first payload if still unclassified

    # --- Well-known controller/aux port sets (best-effort, not exhaustive) ---
    FTP_CTRL_PORTS   = {21, 990}
    SMB_PORTS        = {445}
    # Steam (not exhaustive; a mix of commonly seen TCP control/CM ports)
    STEAM_TCP_CTRL   = {27015, 27016, 27017, 27018, 27036, 27037, 27038}
    # Mongo controller
    MONGO_CTRL       = {27017, 27018, 27019}



    def __init__(self, router_logger):
        self.log = router_logger

        # FTP: server_ip -> {port:int -> ts}
        self._ftp_pasv_ports: Dict[str, Dict[int, float]] = {}

        # SMB recent pairs (sorted tuple of (ip1, ip2)) -> ts
        self._smb_pairs: Dict[Tuple[str, str], float] = {}

        # Steam recent controllers (ip -> last_ts)
        self._steam_ctrl: Dict[str, float] = {}

        # Mongo recent controllers (ip -> last_ts)
        self._mongo_ctrl: Dict[str, float] = {}

        # Per-flow state: canon_key -> dict
        self._flows: Dict[Tuple[Tuple[str, int], Tuple[str, int]], dict] = {}
        self._initiators: Dict[FlowKey, Tuple[str, int]] = {}
        self.log.log_message("[Transport][📦 TCP Ephemeral] Manager ready.")

    # ------------------- Public Entry -------------------
    @staticmethod
    def _canon_key(a_ip, a_port, b_ip, b_port):
        """Canonical 4-tuple key ((low),(high)) so lookups are direction-agnostic."""
        t1 = (a_ip, a_port)
        t2 = (b_ip, b_port)
        return (t1, t2) if t1 <= t2 else (t2, t1)

    def handle(
            self,
            packet,
            src_ip: str,
            dst_ip: str,
            sport: int,
            dport: int,
            inbound_iface: Optional[str] = None,
    ) -> bool:
        if not hasattr(packet, "haslayer") or not packet.haslayer("TCP"):
            return False

        tcp = packet["TCP"]

        self._learn_from_controls(packet, src_ip, dst_ip, sport, dport)

        is_high_pair = self._is_high(sport) and self._is_high(dport)
        if not (is_high_pair or self._recent_controller_link(src_ip, dst_ip)):
            return False

        key: FlowKey = self._canon_key(src_ip, sport, dst_ip, dport)
        self._initiators[key] = (src_ip, int(sport))

        # --- FIX: define f properly ---
        f = self._flows.get(key)
        if f is None:
            f = self._flows[key] = {
                "a": (src_ip, int(sport)),
                "b": (dst_ip, int(dport)),
                "created": time.time(),
                "last_seen": time.time(),
                "buf_c2s": bytearray(),
                "buf_s2c": bytearray(),
                "first_payload_ts": None,
                "classified": False,
                "label": None,
                "extra": None,
            }

        # update last_seen
        f["last_seen"] = time.time()

        payload = self._payload_bytes(packet)
        if payload:
            if self._is_c2s(f, src_ip, sport, dst_ip, dport):
                self._append_buf(f["buf_c2s"], payload)
            else:
                self._append_buf(f["buf_s2c"], payload)

            if f["first_payload_ts"] is None:
                f["first_payload_ts"] = f["last_seen"]

        emitted_now = False
        if payload:
            if not f["classified"]:
                tls_hint = self._peek_tls(f["buf_c2s"]) or self._peek_tls(f["buf_s2c"])
                label, extra = self._classify(src_ip, dst_ip, sport, dport, tls_hint, f)
                if label is not None:
                    self._emit(label, src_ip, sport, dst_ip, dport, extra)
                    f["classified"] = True
                    f["label"], f["extra"] = label, extra
                    emitted_now = True

            if (not f["classified"]) and f["first_payload_ts"] is not None:
                if (f["last_seen"] - f["first_payload_ts"]) >= self.FALLBACK_EMIT_AFTER:
                    self._emit("App-Data", src_ip, sport, dst_ip, dport, "fallback (low signal)")
                    f["classified"] = True
                    f["label"], f["extra"] = "App-Data", "fallback (low signal)"
                    emitted_now = True

        self._gc()
        return emitted_now

    # ------------------- Control Learning -------------------
    def _ip_key(self, a: str, b: str) -> Tuple[str, str]:
        a = str(a); b = str(b)
        return (a, b) if a <= b else (b, a)

    def _learn_from_controls(self, pkt, sip, dip, sport, dport):
        """Inspect low-port TCP flows for PASV/SMB/Steam/Mongo hints."""
        # SMB control (445)




        if sport in self.SMB_PORTS or dport in self.SMB_PORTS:
            key = self._ip_key(sip, dip)
            self._smb_pairs[key] = time.time()

        # Steam controllers (best effort)
        if sport in self.STEAM_TCP_CTRL or dport in self.STEAM_TCP_CTRL:
            now = time.time()
            self._steam_ctrl[sip] = now
            self._steam_ctrl[dip] = now

        # Mongo controllers
        if sport in self.MONGO_CTRL or dport in self.MONGO_CTRL:
            now = time.time()
            self._mongo_ctrl[sip] = now
            self._mongo_ctrl[dip] = now

        # FTP PASV (needs payload)
        if not pkt.haslayer("Raw"):
            return
        data = bytes(pkt["Raw"].load or b"")
        if not data:
            return

        if sport in self.FTP_CTRL_PORTS or dport in self.FTP_CTRL_PORTS:
            try:
                text = data.decode("utf-8", errors="ignore")
                if "227 Entering Passive Mode" in text:
                    # Extract p1,p2 from "...(h1,h2,h3,h4,p1,p2)"
                    nums = []
                    tmp = []
                    for ch in text:
                        if ch.isdigit():
                            tmp.append(ch)
                        else:
                            if tmp:
                                nums.append(int("".join(tmp)))
                                tmp = []
                    if tmp:
                        nums.append(int("".join(tmp)))
                    if len(nums) >= 6:
                        p1, p2 = nums[-2], nums[-1]
                        port = (p1 * 256) + p2
                        # use the server as key (assume ctrl flows to server)
                        server_ip = dip if dport in self.FTP_CTRL_PORTS else sip
                        self._ftp_pasv_ports.setdefault(server_ip, {})[port] = time.time()
                        self.log.log_message(
                            f"[Transport][🧵 TCP][📦 Ephemeral] Learned FTP PASV port {port} for {server_ip}"
                        )
            except Exception:
                pass

    # ------------------- Classification -------------------

    def _classify(self, src_ip, dst_ip, sport, dport, tls_hint: bool, flow: dict):
        now = time.time()

        # FTP PASV match
        for server_ip, ports in list(self._ftp_pasv_ports.items()):
            if server_ip in (src_ip, dst_ip) and ((sport in ports) or (dport in ports)):
                return "FTP-DATA?", f"matches PASV {server_ip}:{sport if sport in ports else dport}"
        # SMB aux within TTL of seeing 445
        key: Tuple[str, str] = self._ip_key(src_ip, dst_ip)
        ts: Optional[float] = self._smb_pairs.get(key)
        if ts is not None and (now - ts) <= self.SMB_TTL_SEC:
            return "RPC/SMB-AUX?", "follows recent 445 control"

        # Steam aux if near a known Steam controller
        if (now - self._steam_ctrl.get(src_ip, 0) <= self.STEAM_TTL_SEC) or \
           (now - self._steam_ctrl.get(dst_ip, 0) <= self.STEAM_TTL_SEC):
            return "Steam-AUX?", "follows recent Steam control"

        # Mongo aux if near a known Mongo controller
        if (now - self._mongo_ctrl.get(src_ip, 0) <= self.MONGO_TTL_SEC) or \
           (now - self._mongo_ctrl.get(dst_ip, 0) <= self.MONGO_TTL_SEC):
            return "Mongo-AUX?", "follows recent 27017-27019 control"

        # Alt TLS on arbitrary ports
        if tls_hint:
            return "Alt-TLS?", "TLS record bytes observed"

        # No confident classification yet
        return None, None

    # ------------------- Helpers -------------------


    @staticmethod
    def _is_high(port: int) -> bool:
        try:
            p = int(port)
            return 49152 <= p <= 65535
        except Exception:
            return False

    @staticmethod
    def _payload_bytes(pkt) -> bytes:
        try:
            if hasattr(pkt["TCP"], "payload") and bytes(pkt["TCP"].payload):
                return bytes(pkt["TCP"].payload)
            if pkt.haslayer("Raw"):
                return bytes(pkt["Raw"].load or b"")
        except Exception:
            pass
        return b""

    @staticmethod
    def _is_c2s(flow: dict, sip: str, sport: int, dip: str, dport: int) -> bool:
        # Treat 'a' endpoint as canonical client if its tuple matches (sip,sport)
        return flow["a"] == (sip, int(sport))

    @staticmethod
    def _append_buf(buf: bytearray, data: bytes):
        if not data:
            return
        # keep only the last MAX_BUF_BYTES
        if len(buf) + len(data) > TransportEphemeralTCPManager.MAX_BUF_BYTES:
            trim = max(0, len(buf) + len(data) - TransportEphemeralTCPManager.MAX_BUF_BYTES)
            del buf[:trim]
        buf += data

    @staticmethod
    def _peek_tls(data_or_buf) -> bool:
        """Accepts bytes or bytearray: look for TLS record content-type + version."""
        if not data_or_buf:
            return False
        b = bytes(data_or_buf)
        if len(b) < 3:
            return False
        ct = b[0]
        # content types 0x14..0x17 and version 0x03 0x00..0x05
        return (ct in (0x14, 0x15, 0x16, 0x17)) and (b[1] == 0x03) and (0x00 <= b[2] <= 0x05)

    def _recent_controller_link(self, a: str, b: str) -> bool:
        """True if either endpoint recently acted as a known controller (SMB/Steam/Mongo/FTP-PASV)."""
        now = time.time()
        # SMB pairs store both endpoints
        if any((a in k or b in k) and (now - ts <= self.SMB_TTL_SEC) for k, ts in self._smb_pairs.items()):
            return True
        if (now - self._steam_ctrl.get(a, 0) <= self.STEAM_TTL_SEC) or (now - self._steam_ctrl.get(b, 0) <= self.STEAM_TTL_SEC):
            return True
        if (now - self._mongo_ctrl.get(a, 0) <= self.MONGO_TTL_SEC) or (now - self._mongo_ctrl.get(b, 0) <= self.MONGO_TTL_SEC):
            return True
        # FTP PASV (per-server map)
        if a in self._ftp_pasv_ports or b in self._ftp_pasv_ports:
            return True
        return False

    def _emit(self, label: str, sip: str, sport: int, dip: str, dport: int, extra: Optional[str]):
        msg = f"[Transport][🧵 TCP][📦 Ephemeral] {label} {sip}:{sport} ↔ {dip}:{dport}"
        if extra:
            msg += f" | {extra}"
        self.log.log_message(msg)

    def _gc(self):
        """Expire old hints and idle flows."""
        now = time.time()
        # FTP PASV ports
        for ip, ports in list(self._ftp_pasv_ports.items()):
            for p, ts in list(ports.items()):
                if now - ts > self.CACHE_TTL_SEC:
                    ports.pop(p, None)
            if not ports:
                self._ftp_pasv_ports.pop(ip, None)

        # SMB pairs
        for k, ts in list(self._smb_pairs.items()):
            if now - ts > self.SMB_TTL_SEC:
                self._smb_pairs.pop(k, None)

        # Steam / Mongo controllers
        for d, ttl in ((self._steam_ctrl, self.STEAM_TTL_SEC), (self._mongo_ctrl, self.MONGO_TTL_SEC)):
            for ip, ts in list(d.items()):
                if now - ts > ttl:
                    d.pop(ip, None)

        # Idle flows (no side-effects)
        for k, f in list(self._flows.items()):
            if now - f.get("last_seen", now) > self.CACHE_TTL_SEC:
                self._flows.pop(k, None)
class TransportEphemeralUDPManager:
    """
    Classifies high↔high (and VoIP-range) UDP flows:
      • RTP / RTCP (v2)
      • STUN/TURN (WebRTC)
      • QUIC (HTTP/3) long/short header
      • DTLS (for SRTP/WebRTC)
      • μTP (BitTorrent)
    Returns True if it handled/logged the packet; False to let caller fall back.
    """

    def __init__(self, router_logger, *, voip_range: Tuple[int, int] = (10000, 20000), log_window=2.0):
        self.log = router_logger
        self.voip_lo, self.voip_hi = voip_range
        self._last_log: Dict[str, float] = defaultdict(float)
        self._log_window = float(log_window)
        # Optional correlation caches
        self._rtp_ssrc_last: Dict[int, float] = {}         # SSRC -> last_seen
        self._flow_last_class: Dict[Tuple[str,int,str,int], Tuple[str, float]] = {}  # flow -> (label, ts)
        self.log.log_message("[Transport][📦 UDP Ephemeral] Manager ready.")

    # ------------------- Public entry -------------------

    def handle(self, packet: Packet, src_ip: str, dst_ip: str, sport: int, dport: int, inbound_iface=None) -> bool:
        """Run UDP heuristics; log a concise line if recognized."""
        if not packet.haslayer(UDP):
            return False

        # Fast path: check if this flow looks “ephemeral” or media-ish
        high_high = self._is_high(sport) and self._is_high(dport)
        in_voip = self.voip_lo <= sport <= self.voip_hi or self.voip_lo <= dport <= self.voip_hi
        if not (high_high or in_voip):
            # Still allow classification if payload clearly matches a known signature
            pass

        payload = self._get_raw(packet)
        if not payload:
            return False

        label, extra = self._classify(payload, sport, dport)
        if not label:
            return False

        flow = (src_ip, sport, dst_ip, dport)
        self._flow_last_class[flow] = (label, time.time())

        if self._should_log(flow, label):
            self.log.log_message(
                f"[Transport][🚀 UDP][📦 Ephemeral] {label} {src_ip}:{sport} ↔ {dst_ip}:{dport}"
                + (f" | {extra}" if extra else "")
            )
        return True

    # ------------------- Core classifier -------------------

    def _classify(self, p: bytes, sport: int, dport: int) -> Tuple[Optional[str], Optional[str]]:
        # RTCP first (more specific than RTP)
        if self._looks_like_rtcp(p):
            pt = p[1]
            rc = p[0] & 0x1F
            length_words = int.from_bytes(p[2:4], "big")
            return "RTCP", f"type={pt} rc={rc} len={length_words*4+4}B"

        # RTP
        rtp_ok, rtp_info = self._looks_like_rtp(p)
        if rtp_ok:
            v, pt, seq, ts, ssrc, cc, xflag, mflag = rtp_info
            self._rtp_ssrc_last[ssrc] = time.time()
            return "RTP", f"pt={pt} seq={seq} ts={ts} ssrc=0x{ssrc:08x} cc={cc} x={int(xflag)} m={int(mflag)}"

        # STUN/TURN
        if self._looks_like_stun(p):
            mtyp = int.from_bytes(p[0:2], "big") & 0x3EEF  # mask out method/class bits for compactness
            length = int.from_bytes(p[2:4], "big")
            return "STUN/TURN", f"len={length}"

        # DTLS (often WebRTC)
        if self._looks_like_dtls(p):
            ct = p[0]
            vers = p[1:3].hex()
            return "DTLS", f"ct={ct} v={vers}"

        # QUIC
        if self._looks_like_quic_long(p):
            version = int.from_bytes(p[1:5], "big")
            return "QUIC", f"long v=0x{version:08x}"
        if self._looks_like_quic_short(p):
            return "QUIC", "short"

        # μTP (BitTorrent)
        if self._looks_like_utp(p):
            typ = p[0] & 0x0F
            return "μTP", f"type={typ}"

        # Nothing definitive
        return None, None

    # ------------------- Helpers: payload & logging -------------------

    @staticmethod
    def _get_raw(pkt: Packet) -> bytes:
        return bytes(pkt[Raw].load) if pkt.haslayer(Raw) and pkt[Raw].load else b""

    def _is_high(self, port: int) -> bool:
        return 49152 <= int(port) <= 65535

    def _should_log(self, flow: Tuple[str,int,str,int], label: str) -> bool:
        key = f"{flow[0]}:{flow[1]}-{flow[2]}:{flow[3]}-{label}"
        now = time.time()
        if now - self._last_log[key] >= self._log_window:
            self._last_log[key] = now
            return True
        return False

    # ------------------- Heuristics: RTP/RTCP -------------------


    def _looks_like_rtp(self, p: bytes) -> Tuple[bool, Tuple[int, int, int, int, int, int, bool, bool]]:
        _RTP_DUMMY: Tuple[int, int, int, int, int, int, bool, bool] = (0, 0, 0, 0, 0, 0, False, False)
        if len(p) < 12:
            return (False, _RTP_DUMMY)
        v = (p[0] & 0xC0) >> 6
        if v != 2:
            return (False, _RTP_DUMMY)
        cc = p[0] & 0x0F
        xflag = bool(p[0] & 0x10)
        mflag = bool(p[1] & 0x80)
        pt = p[1] & 0x7F
        if 200 <= p[1] <= 204:
            return (False, _RTP_DUMMY)
        header_len = 12 + 4 * cc
        if len(p) < header_len:
            return (False, _RTP_DUMMY)
        seq = int.from_bytes(p[2:4], "big")
        ts = int.from_bytes(p[4:8], "big")
        ssrc = int.from_bytes(p[8:12], "big")
        return (True, (v, pt, seq, ts, ssrc, cc, xflag, mflag))
    def _looks_like_rtcp(self, p: bytes) -> bool:
        if len(p) < 8:
            return False
        v = (p[0] & 0xC0) >> 6
        pt = p[1]
        if v != 2:
            return False
        # RTCP types: 200 SR, 201 RR, 202 SDES, 203 BYE, 204 APP (and others 205/206 RTPFB/PSFB)
        return 200 <= pt <= 206

    # ------------------- Heuristics: STUN / QUIC / DTLS / μTP -------------------

    def _looks_like_stun(self, p: bytes) -> bool:
        if len(p) < 20:
            return False
        # RFC5389: fixed cookie 0x2112A442 at bytes 4..7
        return p[4:8] == b"\x21\x12\xa4\x42"

    def _looks_like_dtls(self, p: bytes) -> bool:
        if len(p) < 13:
            return False
        # TLS content types 20..23; DTLS version 0xFEFF (1.0) or 0xFEFD (1.2)
        ct = p[0]
        return (20 <= ct <= 23) and p[1] == 0xFE and p[2] in (0xFF, 0xFD)

    def _looks_like_quic_long(self, p: bytes) -> bool:
        if len(p) < 7:
            return False
        # QUIC invariant: Header Form bit (0x80) set => long header; then 4-byte Version
        return (p[0] & 0x80) == 0x80

    def _looks_like_quic_short(self, p: bytes) -> bool:
        if len(p) < 5:
            return False
        # Short header has Header Form bit 0, reserved bits vary; we just detect "not long",
        # and require a few more bytes to reduce false positives.
        return (p[0] & 0x80) == 0x00

    def _looks_like_utp(self, p: bytes) -> bool:
        if len(p) < 20:
            return False
        # μTP header: first byte high nibble = 1 (version), low nibble = 0..4 (type)
        ver = (p[0] >> 4) & 0x0F
        typ = p[0] & 0x0F
        return ver == 1 and 0 <= typ <= 4
class TransportHighServerTCPManager:
    """
    Observes client→server flows where the server uses a nonstandard high port (>=1024)
    and the client uses an ephemeral port. Purely observational; never blocks/changes packets.
    """
    MIN_SERVER = 1024
    MIN_EPHEMERAL = 49152
    FALLBACK_EMIT_AFTER = 0.4  # s

    def __init__(self, router_logger):
        self.log = router_logger
        self._flows = {}  # key -> {created,last_seen,label,extra,buf_c2s,buf_s2c,first_ts,emitted}
        self.log.log_message("[Transport][🧵 TCP][📦 HighServer] Manager ready.")

    def handle(self, pkt, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool:
        if not getattr(pkt, "haslayer", lambda *_: False)("TCP"):
            return False
        # server: high non-ephemeral port; client: ephemeral
        server_port, client_port = (sport, dport) if sport >= dport else (dport, sport)
        if server_port < self.MIN_SERVER:
            return False
        if client_port < self.MIN_EPHEMERAL:
            return False

        key = self._key(src_ip, sport, dst_ip, dport)
        f = self._flows.get(key)
        now = time.time()
        if f is None:
            f = self._flows[key] = {
                "created": now, "last_seen": now, "label": None, "extra": None,
                "buf_c2s": bytearray(), "buf_s2c": bytearray(), "first_ts": None, "emitted": False,
                "a": (src_ip, int(sport)), "b": (dst_ip, int(dport))
            }
        f["last_seen"] = now

        data = self._payload(pkt)
        if data:
            if self._is_c2s(f, src_ip, sport): self._append(f["buf_c2s"], data)
            else:                               self._append(f["buf_s2c"], data)
            if f["first_ts"] is None: f["first_ts"] = now

            if not f["emitted"]:
                label, extra = self._classify(f, server_port)
                if label:
                    self._emit(src_ip, sport, dst_ip, dport, label, extra)
                    f["label"], f["extra"], f["emitted"] = label, extra, True
                elif (now - f["first_ts"]) >= self.FALLBACK_EMIT_AFTER:
                    self._emit(src_ip, sport, dst_ip, dport, "App-Data", "nonstandard server port")
                    f["label"], f["extra"], f["emitted"] = "App-Data", "nonstandard server port", True

        self._gc()
        return bool(f and f["emitted"])

    # ---------- helpers ----------
    @staticmethod
    def _key(a_ip, a_p, b_ip, b_p):
        A, B = (a_ip, int(a_p)), (b_ip, int(b_p))
        return (A, B) if A <= B else (B, A)

    @staticmethod
    def _payload(pkt):
        try:
            tcp = pkt["TCP"]
            if bytes(tcp.payload): return bytes(tcp.payload)
            if pkt.haslayer("Raw"): return bytes(pkt["Raw"].load or b"")
        except Exception:
            pass
        return b""

    @staticmethod
    def _is_c2s(f, sip, sport):
        return f["a"] == (sip, int(sport))

    @staticmethod
    def _append(buf: bytearray, b: bytes, maxlen: int = 512):
        if len(buf) + len(b) > maxlen:
            del buf[: (len(buf) + len(b) - maxlen)]
        buf += b

    def _classify(self, f, server_port: int):
        b = bytes(f["buf_c2s"] or f["buf_s2c"])
        if len(b) >= 3 and b[0] in (0x14,0x15,0x16,0x17) and b[1] == 0x03 and 0x00 <= b[2] <= 0x05:
            return "Alt-TLS?", "TLS record bytes"
        # HTTP/1.x
        for m in (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"HTTP/1.", b"OPTIONS ", b"DELETE ", b"PATCH "):
            if b.startswith(m) or b.find(b"\r\nHost:") != -1:
                return "HTTP?", "HTTP-like start/Host hdr"
        # SSH
        if b.startswith(b"SSH-"): return "SSH?", "SSH banner"
        # RFB/VNC
        if b.startswith(b"RFB "): return "RFB/VNC?", "RFB banner"
        # Redis (RESP)
        if b and b[:1] in b"+-:$*": return "Redis/RESP?", "RESP framing"
        # MySQL greeting (length+seq + 0x0a version)
        if len(b) >= 5 and b[4] == 0x0a: return "MySQL?", "greeting 0x0a"
        # MQTT
        if len(b) >= 2 and b[0] == 0x10: return "MQTT?", "CONNECT packet"
        # Generic binary handshake (length prefix)
        if len(b) >= 4 and (b[0] == 0x00 or b[0] == 0x01):
            return "Binary-Proto?", "length-prefixed"
        # Port-specific hint (your 18480 case)
        if server_port == 18480:
            return "Custom-Service?", "server port 18480"
        return None, None

    def _emit(self, sip, sport, dip, dport, label, extra):
        msg = f"[Transport][🧵 TCP][📦 HighServer] {label} {sip}:{sport} ↔ {dip}:{dport}"
        if extra: msg += f" | {extra}"
        self.log.log_message(msg)

    def _gc(self, ttl=120):
        now = time.time()
        for k, f in list(self._flows.items()):
            if now - f.get("last_seen", now) > ttl:
                self._flows.pop(k, None)
class TransportManager:
    """
    Manages the processing and logging of Transport Layer packets (TCP, UDP, etc.).
    This version supports a wide variety of protocols including DNS, DHCP, NTP, TFTP,
    VoIP (SIP/RTP), QUIC, ZeroTier/SSDP, and dynamic ports.

    TLS dissection is performed passively by TLSRecordManager using TCP Raw bytes.
    """

    def __init__(self, router_logger, packet_signer, code_output_manager):
        """
        Initializes the TransportManager with a logger and a packet signer.
        """


        self.logger = router_logger
        self.code_output_manager = code_output_manager
        self.sniffer = None
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
        self.transport_dhcp = TransportDHCPManager(self.logger)
        self.transport_dns = TransportDNSManager(self.logger)
        self.transport_ssdp = TransportSSDPManager(self.logger)
        self.transport_quic = TransportQUICManager(self.logger)
        self.transport_http = TransportHTTPManager(self.logger)
        self.transport_ssh = TransportSSHManager(self.logger)
        self.transport_ftp = TransportFTPManager(self.logger)
        self.transport_rdp = TransportRDPManager(self.logger)
        self.transport_rtp = TransportRTPManager(self.logger)
        self.transport_kerberos = TransportKerberosManager(self.logger)
        self.transport_ipv6 = TransportIPv6Manager(self.logger)
        self.transport_overlay = TransportOverlayManager(self.logger)
        self.transport_tcp_ephemeral = TransportEphemeralTCPManager(self.logger)
        self.transport_udp_ephemeral = TransportEphemeralUDPManager(self.logger)
        self.transport_steam = TransportSteamManager(self.logger)
        self.transport_tcp_high_Level = TransportHighServerTCPManager
        self.transport_https = TransportHTTPSManager(self.logger)

        self._MONERO_P2P_PORTS = [
            # Standard P2P
            18080,
            # Common alternate/anonymity network P2P ports
            18083, 18084, 18085, 18086, 18087, 18089,
            # Other known P2P ports
            18180, 18380, 18580, 21213, 37888, 37889
        ]

        self._MONERO_RPC_PORTS = [
            # Standard RPC
            18081,
            # Common restricted/wallet RPC
            18082,
            # ZMQ RPC
            18088
        ]

        # ✅ Correctly initialized manager
        self.transport_monero = TransportMoneroManager(
            self.logger,
            extra_p2p_ports=self._MONERO_P2P_PORTS,
            extra_rpc_ports=self._MONERO_RPC_PORTS
        )
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

    def _canonical_flow_key(self, a_ip, a_port, b_ip, b_port):
        """Canonical 4-tuple key ((low),(high)) so lookups are direction-agnostic."""
        t1 = (a_ip, a_port)
        t2 = (b_ip, b_port)
        return (t1, t2) if t1 <= t2 else (t2, t1)

    def _handle_tcp_packet(self, packet, src_ip, dst_ip, sport, dport, iface_short):
        """Dispatches TCP packets to the correct handler based on port."""
        tcp = packet[TCP]
        flags = tcp.sprintf("%TCP.flags%")

        if "S" in flags and "A" not in flags:
            key: FlowKey = self._canonical_flow_key(src_ip, sport, dst_ip, dport)  # use self._canon_key
            self._initiators[key] = (src_ip, int(sport))

        # --- NEW: unified rules (single ports + ranges) ---
        rules = [
            # (ports, handler)
            ([80], self._handle_http_packet),
            ([443, 8443, 9443, 2087, 2096, 2083], self._handle_https_packet),
            ([22], self._handle_ssh_packet),
            ([21], self._handle_ftp_packet),
            ([88], self._handle_kerberos_packet),
            ([3389], self._handle_rdp_packet),
            ([*self._MONERO_P2P_PORTS, *self._MONERO_RPC_PORTS], self._handle_monero_packet),
            ([(27014, 27050)], self._handle_tcp_steam_packet),
            ([(33981, 59713), (60000, 61000)], self._handle_tcp_ephemeral_packet),  # range example
            ([(1024, 65535)], self._handle_high_server_packet),  # high server port observer
        ]

        handler = None
        for ports, h in rules:
            for p in ports:
                if isinstance(p, tuple):  # range
                    lo, hi = p
                    if lo <= sport <= hi or lo <= dport <= hi:
                        handler = h
                        break
                else:  # single port
                    if p in (sport, dport):
                        handler = h
                        break
            if handler:
                break

        if handler:
            handler(packet, src_ip, dst_ip, sport, dport, iface_short)
        else:
            self.code_output_manager.submit_packet(
                packet, inbound_iface=iface_short, phase="tls-feed", component="tcp"
            )
            if not self._feed_to_tls_manager(packet, src_ip, dst_ip, sport, dport):
                self.logger.log_message(
                    f"[Transport][🧵 TCP][❔ Undecoded] Unknown TCP protocol on ports {sport} → {dport}."
                )

    def _handle_monero_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles Monero P2P traffic on port 18080."""
        self.transport_monero.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="tcp-monero"
        )

    def _handle_high_server_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_tcp_high_Level.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
    def _handle_tcp_steam_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Steam TCP (CM/content/friends; 27014–27050). Observation only."""
        self.transport_steam.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="steam-tcp"
        )
    def _handle_http_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_http.handle(packet, src_ip, dst_ip, sport, dport)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="tcp-http"
        )
    def _handle_https_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_https.handle(packet, inbound_iface)
        self._feed_to_tls_manager(packet, src_ip, dst_ip, sport, dport)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="tcp-https"
        )
    def _handle_ssh_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_ssh.handle(packet, src_ip, dst_ip, sport, dport)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="tcp-ssh"
        )
    def _handle_ftp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_ftp.handle(packet, src_ip, dst_ip, sport, dport)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="tcp-ftp"
        )
    def _handle_rdp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_rdp.handle(packet, src_ip, dst_ip, sport, dport)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="tcp-rdp"
        )
    def _handle_tcp_ephemeral_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_tcp_ephemeral.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="tcp-ephemeral"
        )
    # --------------------- Main packet handler ------------------------
    def handle_packet(self, packet: Packet, inbound_iface: str) -> bool:
        """
        Processes Transport Layer packets by robustly finding the L4 protocol,
        even when IPv6 extension headers are present.
        """

        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if not ip_layer:
            return False

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Use the robust helper to find the transport layer
        transport_layer = self.sniffer._find_transport_layer(packet)

        if isinstance(transport_layer, TCP):
            self._handle_tcp_packet(packet, src_ip, dst_ip, transport_layer.sport, transport_layer.dport, iface_short)
            return True
        elif isinstance(transport_layer, UDP):
            self._handle_udp_packet(packet, src_ip, dst_ip, transport_layer.sport, transport_layer.dport, iface_short)
            return True

        # Handle packets with extension headers that were permitted by the firewall
        handled = self.transport_ipv6.handle(packet, inbound_iface)
        if handled:
            self.code_output_manager.submit_packet(
                packet, inbound_iface=inbound_iface, phase="handled", component="transport-ipv6"
            )
            return True
        yield_no_gil(0.02)
        return False

    def _handle_udp_packet(self, packet, src_ip, dst_ip, sport, dport, iface_short):
        """Dispatches UDP packets to the correct handler based on port (supports singles + ranges)."""

        # Rules: list of (ports_or_ranges, handler)
        # A "range" is a (lo, hi) tuple, inclusive.
        rules = [
            ([53], self._handle_dns_packet),
            ([67, 68], self._handle_dhcp_packet),
            ([443], self._handle_quic_packet),
            ([123], self._handle_ntp_packet),
            ([69], self._handle_tftp_packet),
            ([88], self._handle_kerberos_packet),
            ([5060], self._handle_sip_packet),
            ([9993, 19300], self._handle_overlay_packet),
            ([1900], self._handle_ssdp_packet),
            ([3702], self._handle_ws_discovery_packet),
            ([19337], self._handle_rtp_packet),
            ([(27000, 27100), 4380, 27036, 27037], self._handle_udp_steam_packet),
            ([(49152, 65535), 3478, 5349], self._handle_udp_ephemeral_packet),
        ]

        def _match(ports_or_ranges, s, d):
            for p in ports_or_ranges:
                if isinstance(p, tuple):  # range (lo, hi)
                    lo, hi = p
                    if lo <= s <= hi or lo <= d <= hi:
                        return True
                else:  # single port
                    if p == s or p == d:
                        return True
            return False

        handler = None
        for ports, h in rules:
            if _match(ports, sport, dport):
                handler = h
                break

        if handler:
            handler(packet, src_ip, dst_ip, sport, dport, iface_short)
            return

        # RTP/VoIP dynamic range as a fallback
        try:
            if sport in self.voip_port_range or dport in self.voip_port_range:
                self._handle_rtp_packet(packet, src_ip, dst_ip, sport, dport, iface_short)
                return
        except Exception:
            # If voip_port_range isn’t iterable (e.g., misconfigured), just skip
            pass
        self.code_output_manager.submit_packet(
            packet, inbound_iface=iface_short, phase="unhandled", component="udp"
        )
        if self.transport_overlay._zt_is_peer(src_ip) or self.transport_overlay._zt_is_peer(dst_ip):
            self.logger.log_message(
                f"[Transport][🚀 UDP][🛰️ Overlay] P2P data {src_ip}:{sport} → {dst_ip}:{dport}"
            )
            self.code_output_manager.submit_packet(packet, inbound_iface=iface_short,
                                                   phase="handled", component="overlay-data")
            return
        self.logger.log_message(
            f"[Transport][🚀 UDP][❔ Undecoded] Unknown UDP protocol on ports {sport} → {dport}."
        )

    # ---------------------- UDP protocol handlers ---------------------
    def _bytes_to_str(self, data: bytes) -> str:
        """Safely decodes bytes to a string, ignoring any decoding errors."""
        return data.decode('utf-8', errors='ignore')

    def _handle_udp_steam_packet(self, packet, src_ip, dst_ip, sport, dport, iface_short):
        """
        Steam/Source UDP: A2S queries (usually 27015±n), SDR (27000–27100), client (4380), discovery (27036/27037).
        Observation only.
        """
        self.transport_steam.handle(packet, src_ip, dst_ip, sport, dport, iface_short)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=iface_short, phase="handled", component="steam-udp"
        )
    def _handle_udp_ephemeral_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_udp_ephemeral.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-ephermeral"
        )
    def _handle_dns_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for DNS packets."""
        self.transport_dns.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-dns"
        )
    def _handle_dhcp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for DHCP packets."""
        self.transport_dhcp.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-dhcp"
        )
    def _handle_quic_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for QUIC packets."""
        self.transport_quic.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-quic"
        )
    def _handle_ntp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
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

    def _handle_tftp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
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

    def _handle_sip_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
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

    def _handle_rtp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_rtp.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-rtp"
        )
    def _handle_overlay_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for ZeroTier-like packets on UDP port 9993."""
        self.transport_overlay.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-overlay"
        )
    def _handle_ssdp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for SSDP/UPnP packets on UDP port 1900."""
        self.transport_ssdp.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-ssdp"
        )
    def _handle_ws_discovery_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for WS-Discovery packets on UDP port 3702."""
        self.logger.log_message(
            f"[Transport][🚀 UDP][🔍 WS-Discovery] WS-Discovery packet detected from {src_ip}:{sport} to {dst_ip}:{dport}. "
            "Likely for dynamic device discovery."
        )
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-ephermeral"
        )
    def _handle_kerberos_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for WS-Discovery packets on UDP port 3702."""
        self.transport_kerberos.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
        self.code_output_manager.submit_packet(
            packet, inbound_iface=inbound_iface, phase="handled", component="udp-kerberos"
        )

    def _feed_to_tls_manager(self, packet, src_ip, dst_ip, sport, dport, *, reason: str = "auto", log: bool = True):
        from scapy.packet import Raw
        if not packet.haslayer(Raw):
            return
        raw_bytes = bytes(packet[Raw].load or b"")
        if not raw_bytes:
            return
        TLS_SERVICE_PORTS = {443, 8443, 9443, 2087, 2096, 2083, 8883, 10443, 853, 993, 995, 465}
        key = self._canonical_flow_key(src_ip, sport, dst_ip, dport)

        # 1) Use SYN initiator if known
        client_tuple = self._initiators.get(key)
        if client_tuple:
            is_c2s = (src_ip, sport) == client_tuple
        else:
            # 2) Service-port heuristic (works for 8883)
            if (sport in TLS_SERVICE_PORTS) ^ (dport in TLS_SERVICE_PORTS):
                # c->s if going *to* the service port; otherwise s->c
                is_c2s = dport in TLS_SERVICE_PORTS
            else:
                # 3) fallback heuristic
                is_c2s = sport <= dport

        # --- resync/preface handling (see next section) ---
        raw_bytes, skipped, tag = self._tls_preface_and_resync(raw_bytes)
        if skipped and log:
            self.logger.log_message(
                f"[Transport][🔐 TLS] resync({tag}) +{skipped}B {src_ip}:{sport} → {dst_ip}:{dport}"
            )
        if not raw_bytes:
            return  # nothing left to parse this segment

        self.tls_manager.feed_tcp_segment(
            canonical_key=key,
            is_c2s=is_c2s,
            payload=raw_bytes,
            src_ip=src_ip, src_port=sport,
            dst_ip=dst_ip, dst_port=dport,
            ts=time.time()
        )
        if log:
            dir_str = "c2s" if is_c2s else "s2c"
            self.logger.log_message(
                f"[Transport][🔐 TLS] fed {len(raw_bytes)}B ({reason}) {src_ip}:{sport} → {dst_ip}:{dport} [{dir_str}]"
            )

    def _tls_preface_and_resync(self, payload: bytes, *, scan_window: int = 512):
        """
        Returns (new_payload, skipped_len, tag)

        Behavior:
          • If payload already starts with a TLS record, return as-is ("tls").
          • Strip HAProxy PROXY v1/v2 prefaces ("proxyv1"/"proxyv2").
          • Strip a single HTTP/CONNECT preface line if present ("http-preface").
          • Search within 'scan_window' for the next TLS record and resync ("resync").
          • Recognize SSLv2 ClientHello and pass it through ("sslv2").
          • If nothing TLS-like is found, return (b"", len(payload), "notls").
        """
        if not payload:
            return b"", 0, "empty"

        mv = memoryview(payload)
        plen = len(mv)

        # 1) Already TLS?
        if self._looks_like_tls_record(mv):
            return payload, 0, "tls"

        # 2) HAProxy PROXY v1 (ASCII line) e.g. "PROXY TCP4 1.2.3.4 5.6.7.8 12345 443\r\n"
        if mv[:6].tobytes() == b"PROXY ":
            eol = self._find_crlf(mv, 0, min(plen, 256))
            if eol != -1:
                cut = eol + 2  # skip the CRLF
                rest = mv[cut:].tobytes()
                if self._looks_like_tls_record(memoryview(rest)):
                    return rest, cut, "proxyv1"
                # fall through to resync in the remaining bytes
                mv = memoryview(rest)
                plen = len(mv)

        # 3) HAProxy PROXY v2 (binary) - signature then 2-byte len
        if plen >= 16 and mv[:12].tobytes() == b"\r\n\r\n\0\r\nQUIT\n":
            hdrlen = 16
            try:
                ext_len = struct.unpack("!H", mv[14:16])[0]
            except Exception:
                ext_len = 0
            total = hdrlen + ext_len
            if total <= plen:
                rest = mv[total:].tobytes()
                if self._looks_like_tls_record(memoryview(rest)):
                    return rest, total, "proxyv2"
                mv = memoryview(rest)
                plen = len(mv)

        # 4) Plain HTTP/CONNECT preface? (common before TLS tunnels)
        # Very cheap check: starts with a known HTTP method or "CONNECT"
        if self._looks_like_http_preface(mv):
            eol = self._find_crlf(mv, 0, min(plen, 512))
            if eol != -1:
                cut = eol + 2
                rest = mv[cut:].tobytes()
                if self._looks_like_tls_record(memoryview(rest)):
                    return rest, cut, "http-preface"
                mv = memoryview(rest)
                plen = len(mv)

        # 5) SSLv2 ClientHello (legacy): high bit set on first len byte, and type==0x01 at offset 2
        if plen >= 3:
            b0 = mv[0]
            if (b0 & 0x80) and mv[2] == 0x01:
                return mv.tobytes(), 0, "sslv2"

        # 6) Resync: scan early bytes for a TLS record header
        win = min(scan_window, max(0, plen - 5))
        for i in range(win):
            if self._looks_like_tls_record(mv[i:]):
                return mv[i:].tobytes(), i, "resync"

        # 7) Give up: nothing TLS-like in this segment
        return b"", plen, "notls"

    def _looks_like_tls_record(self, mv: memoryview) -> bool:
        """
        Very cheap TLS record header check on a memoryview.
        Accept: content_type in {0x16(handshake),0x17(app),0x14(change)} and
                version in {0x0301..0x0304}, and have at least 5 bytes.
        """
        try:
            if len(mv) < 5:
                return False
            ct = mv[0]
            if ct not in (0x16, 0x17, 0x14):
                return False
            ver = (mv[1] << 8) | mv[2]
            if ver not in (0x0301, 0x0302, 0x0303, 0x0304):
                return False
            # Optional: ensure declared length doesn't exceed a sane bound (avoid bogus sync)
            rec_len = (mv[3] << 8) | mv[4]
            # TLS record length must be <= 2^14+2048 (allowing some extension wiggle)
            return 0 < rec_len <= (16384 + 2048)
        except Exception:
            return False

    # --- tiny local helpers (put either inside the class as @staticmethods,
    #     or outside; below are module-local for brevity) ---

    def _find_crlf(self, mv: memoryview, start: int, end: int) -> int:
        """Return index of '\r\n' between start..end (exclusive end), or -1."""
        try:
            buf = mv[start:end].tobytes()
            pos = buf.find(b"\r\n")
            return -1 if pos < 0 else start + pos
        except Exception:
            return -1

    def _looks_like_http_preface(self, mv: memoryview) -> bool:
        """Detect a single HTTP/CONNECT request line cheaply."""
        if len(mv) < 7:
            return False
        try:
            head = mv[:8].tobytes().upper()
            # Methods and CONNECT
            return (
                    head.startswith(b"CONNECT ") or
                    head.startswith(b"GET ") or
                    head.startswith(b"POST ") or
                    head.startswith(b"PUT ") or
                    head.startswith(b"HEAD ") or
                    head.startswith(b"DELETE ") or
                    head.startswith(b"OPTIONS ") or
                    head.startswith(b"TRACE ") or
                    head.startswith(b"PATCH ")
            )
        except Exception:
            return False

class _ReqBody(bytes):
    """Bytes with a parsed-JSON view (dot-access for keys)."""
    def __new__(cls, data: bytes, parsed: Optional[Dict[str, Any]] = None):
        obj = super().__new__(cls, data)
        obj._parsed = parsed or {}
        return obj

    # Nice-to-have helpers
    def json(self) -> Dict[str, Any]:
        return dict(self._parsed)

    def get(self, key: str, default=None):
        return self._parsed.get(key, default)

    # Dot-access for common fields (helps static analyzers)
    @property
    def realm(self):
        return self._parsed.get("realm")

    # Generic dot-access fallback
    def __getattr__(self, name: str):
        try:
            return self._parsed[name]
        except KeyError:
            raise AttributeError(f"'_ReqBody' has no attribute '{name}'")

class _MsgTypeShim:
    def __init__(self, val: int):
        self.val = val

class _RootShim:
    def __init__(
        self,
        msgtype_val: int,
        req_body: Optional[Union[bytes, bytearray, memoryview, str, dict, list]] = None,
    ):
        self.msgType = _MsgTypeShim(msgtype_val)
        self._req_body = self._make_reqbody(req_body)

    @staticmethod
    def _to_bytes(x) -> bytes:
        if x is None:
            return b""
        if isinstance(x, (bytes, bytearray, memoryview)):
            return bytes(x)
        if isinstance(x, str):
            return x.encode("utf-8", "ignore")
        # dict/list -> JSON bytes
        try:
            return json.dumps(x, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except Exception:
            return b""

    @classmethod
    def _make_reqbody(cls, x) -> bytes:
        b = cls._to_bytes(x)
        parsed = {}
        if b:
            try:
                j = json.loads(b.decode("utf-8", "ignore"))
                if isinstance(j, dict):
                    parsed = j
            except Exception:
                parsed = {}
        return _ReqBody(b, parsed)

    # CamelCase + lowercase aliases expected by callers
    @property
    def reqBody(self) -> bytes:
        return self._req_body

    @reqBody.setter
    def reqBody(self, v):
        self._req_body = self._make_reqbody(v)

    @property
    def reqbody(self) -> bytes:
        return self._req_body

    @reqbody.setter
    def reqbody(self, v):
        self._req_body = self._make_reqbody(v)
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
            first = buf[i]
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
        first = buf[i]
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
        req_body = getattr(tgs_req, "reqBody", None)

        sname = "UNKNOWN"
        realm = "UNKNOWN"

        if req_body:
            if getattr(req_body, "sname", None) and getattr(req_body.sname, "nameString", None):
                try:
                    sname = req_body.sname.nameString[0]
                except Exception:
                    pass
            if getattr(req_body, "realm", None):
                realm = req_body.realm

        self.router_logger.log_message(
            f"[Kerberos] TGS-REQ requesting service ticket for {sname}@{realm}"
        )

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
    def __init__(self, logger, interfaces_config, packet_signer, outbound_load_balancer, arp_manager= None):
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
        self.arp_manager = arp_manager
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
    Manages periodic TCP scans, does banner grabs on sensible ports, and emits
    stateful notifications about port status changes.

    Key changes vs. previous version:
      • Uses L3 scanning (IP/TCP) so the OS routes via the gateway (no ARP to Internet hosts)
      • On banner-friendly ports, performs a real TCP connect() to "open the port" and pull a banner
      • TLS-aware probe for 443/8443/993/995/465/587 (best-effort, returns CN/cipher)
      • Quieter logging for ports where banners are not expected
    """

    # Plaintext services that commonly expose a banner on connect()
    BANNER_PORTS = {
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        80,   # HTTP
        110,  # POP3
        143,  # IMAP
        389,  # LDAP
        445,  # SMB (often no banner, but sometimes responds)
        8080, # Alt-HTTP
    }

    # Services where a direct TLS handshake can provide useful info
    TLS_PORTS = {
        443, 8443,  # HTTPS
        993, 995,   # IMAPS / POP3S
        465, 587,   # SMTPS / SMTP(STARTTLS-capable but we just try direct TLS)
        990,        # FTPS
    }

    # Minimal text probes to coax banners (only for plaintext ports)
    _PLAINTEXT_PROBES: Dict[int, bytes] = {
        21:  b"FEAT\r\n",                                                # FTP
        25:  b"EHLO scanner.local\r\nQUIT\r\n",                          # SMTP
        80:  b"HEAD / HTTP/1.0\r\nHost: example\r\n\r\n",                # HTTP
        8080:b"HEAD / HTTP/1.0\r\nHost: example\r\n\r\n",                # Alt-HTTP
        110: b"QUIT\r\n",                                                # POP3
        143: b". CAPABILITY\r\n",                                        # IMAP
        389: b"\x30\x0a\x02\x01\x01\x60\x05\x02\x01\x03\x80\x00",        # LDAP simple bind (anon) preface
        23:  b"\r\n",                                                    # Telnet
        # 445/SMB not probed with raw text; leave it passive
    }

    def __init__(
        self,
        sniffer,
        router_logger,
        packet_writer,
        arp_manager,  # kept for API parity; not used now for L3 scans
        interfaces_config: Dict[str, Any],
        notification_manager: Optional[Any],
        scan_targets: Optional[List[Tuple[str, List[int]]]] = None,
        scan_interval: int = 60,
    ):
        self.sniffer = sniffer
        self.router_logger = router_logger
        self.packet_writer = packet_writer
        self.arp_manager = arp_manager
        self.interfaces_config = interfaces_config
        self.notification_manager = notification_manager
        self.scan_targets = scan_targets if scan_targets is not None else [
            ("8.8.8.8", [53, 80]),
            ("1.1.1.1", [443, 80]),
        ]
        self.scan_interval = scan_interval

        self._scannable_interfaces: List[str] = []
        self._populate_scannable_interfaces()

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Stateful set of (ip,port) currently known-open
        self.open_ports_state: set[Tuple[str, int]] = set()

        self.router_logger.log_message("[SYNScanner] Initialized.")
        if not self._scannable_interfaces:
            self.router_logger.log_message(
                "[SYNScanner] Warning: No suitable non-loopback interfaces with an IP found for scanning."
            )

    # ---------------- lifecycle ----------------

    def _populate_scannable_interfaces(self):
        self._scannable_interfaces.clear()
        for iface_full, cfg in self.interfaces_config.items():
            ip = cfg.get("ip_addr")
            if ip and not ("loopback" in iface_full.lower() or iface_full.lower() == "lo"):
                self._scannable_interfaces.append(iface_full)
        self.router_logger.log_message(
            f"[SYNScanner] Found {len(self._scannable_interfaces)} scannable interfaces."
        )

    def start(self):
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
        if not self._thread or not self._thread.is_alive():
            return
        self.router_logger.log_message("[SYNScanner] Stopping thread...")
        self._stop_event.set()
        self._thread.join(timeout=5)
        self.router_logger.log_message("[SYNScanner] Thread stopped.")

    # ---------------- main loop ----------------

    def _run_scan_loop(self):
        self.router_logger.log_message("[SYNScanner] Scan loop started.")
        while not self._stop_event.is_set():
            if not self._scannable_interfaces:
                self.router_logger.log_message("[SYNScanner] No active scannable interfaces. Waiting...")
                self._stop_event.wait(self.scan_interval)
                self._populate_scannable_interfaces()
                continue

            iface = random.choice(self._scannable_interfaces)
            self.router_logger.log_message(f"[SYNScanner] Commencing scan cycle using {iface.split('_')[-1]}")

            for target_ip, ports in self.scan_targets:
                if self._stop_event.is_set():
                    break
                for port in ports:
                    if self._stop_event.is_set():
                        break
                    status, banner = self._scan_one(target_ip, port, iface)
                    self.router_logger.log_message(
                        f"[SYNScanner] Result for {target_ip}:{port} on {iface.split('_')[-1]} -> {status}"
                    )
                    self._handle_state_change(target_ip, port, status, banner)

            self.router_logger.log_message(f"[SYNScanner] Scan cycle completed. Waiting for {self.scan_interval}s.")
            self._stop_event.wait(self.scan_interval)

        self.router_logger.log_message("[SYNScanner] Scan loop has exited.")

    # ---------------- scanning primitives ----------------

    def _scan_one(self, ip: str, port: int, iface: str, timeout: float = 2.0) -> Tuple[str, Optional[str]]:
        """
        Returns ('OPEN'|'CLOSED'|'FILTERED'|'ERROR'|...), banner_or_None.
        Strategy:
          • If port is banner-friendly → do a real connect() probe (opens connection) and read banner
          • Else → do a L3 SYN probe with scapy (no L2 crafting)
          • On connect() failure, fall back to SYN to discriminate CLOSED vs FILTERED
        """
        # Try banner path first if sensible
        if self._is_banner_port(port):
            status, banner = self._banner_probe(ip, port, iface, timeout=timeout)
            if status != "ERROR" and (status != "CLOSED"):
                # OPEN, FILTERED, or something meaningful → return it
                return status, banner
            # else fall through to SYN to refine CLOSED/FILTERED

        # SYN probe via scapy (L3; OS routes)
        try:
            syn = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = self.sniffer.sr1(syn, timeout=timeout, verbose=0, iface=iface)
            if resp is None:
                return "FILTERED (no response)", None
            if resp.haslayer(TCP):
                f = int(resp[TCP].flags)
                if f & 0x12:  # SYN-ACK
                    # We won't send RST here; if caller wants a banner, they can connect() separately
                    return "OPEN", None
                if f & 0x04:  # RST
                    return "CLOSED", None
                return f"UNEXPECTED_TCP_FLAGS ({hex(f)})", None
            if resp.haslayer(ICMP):
                return "FILTERED (ICMP)", None
            return "UNEXPECTED_NON_TCP_RESPONSE", None
        except Exception as e:
            self.router_logger.log_message(f"[SYNScanner] Error during SYN scan of {ip}:{port}: {e}")
            return "ERROR", None

    def _is_banner_port(self, port: int) -> bool:
        return port in self.BANNER_PORTS or port in self.TLS_PORTS

    # ---------------- banner probes ----------------

    def _banner_probe(self, ip: str, port: int, iface: str, timeout: float = 3.0) -> Tuple[str, Optional[str]]:
        """
        Full-connect banner probe. Returns (status, banner/info).
          • TLS ports: attempt a TLS handshake (no hostname checking); report CN/cipher
          • Plaintext: connect, read initial bytes, optionally send a single probe
        """
        import ssl
        # --- TLS first (for known TLS ports) ---
        if port in getattr(self, "TLS_PORTS", {443, 853, 993, 995, 465, 8443, 8883, 10443}):
            try:
                ctx = ssl.create_default_context()
                # Accept any cert + don't check hostnames; we're only fingerprinting
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                # Use our robust connector that retries without binding on 10049/EADDRNOTAVAIL
                with self._create_conn(ip, port, iface, timeout) as s:
                    s.settimeout(timeout)
                    # Don't pass server_hostname to avoid SNI/hostname mismatch failures on raw IPs
                    with ctx.wrap_socket(s, server_hostname=None) as tls:
                        # Try to extract something useful
                        cert = tls.getpeercert() or {}
                        cn = None
                        for tup in cert.get("subject", []):
                            # subject is a list of tuples like ((('commonName','example.com'),), ...)
                            if tup and tup[0][0] == "commonName":
                                cn = tup[0][1]
                                break
                        # If SAN exists, prefer first DNS name as a fallback CN
                        if not cn:
                            for k, v in cert.get("subjectAltName", []):
                                if k == "DNS":
                                    cn = v
                                    break
                        cipher = tls.cipher()[0] if tls.cipher() else "unknown"
                        info = f"TLS OK; CN={cn or 'unknown'}; cipher={cipher}"
                        return "OPEN", info
            except (ssl.SSLError, TimeoutError, OSError) as e:
                # Log and fall back to plaintext probe (some services speak TLS on odd ports or require SNI)
                self.router_logger.log_message(f"[SYNScanner] TLS probe {ip}:{port} no banner ({e}).")
                # continue to plaintext path

        # --- Plaintext path ---
        try:
            with self._create_conn(ip, port, iface, timeout) as s:
                s.settimeout(timeout)
                banner = self._recv_some(s)  # should return bytes or b""
                probe = getattr(self, "_PLAINTEXT_PROBES", {}).get(port)
                if not banner and probe:
                    try:
                        s.sendall(probe)
                        banner = self._recv_some(s)
                    except Exception:
                        pass
                if banner:
                    b = banner.strip()
                    b = (b.splitlines() or [""])[0][:200]
                    return "OPEN", (b or None)
                return "OPEN", None

        except ConnectionRefusedError:
            return "CLOSED", None
        except TimeoutError:
            return "FILTERED (timeout)", None
        except OSError as e:
            # Windows 10013 (permission), treat as filtered/policy; others bubble to ERROR
            if getattr(e, "winerror", None) == 10013:
                self.router_logger.log_message(f"[SYNScanner] (info) Access blocked to {ip}:{port} (WinError 10013).")
                return "FILTERED (policy)", None
            return "ERROR", None
        except Exception as e:
            self.router_logger.log_message(f"[SYNScanner] Plain probe {ip}:{port} error: {e}")
            return "ERROR", None
    def _recv_some(self, sock: socket.socket, bufsize: int = 4096) -> bytes:
        """
        Try to receive up to bufsize bytes from the socket.
        Returns b"" on timeout or error.
        """
        try:
            data = sock.recv(bufsize)
            return data if data else b""
        except (socket.timeout, BlockingIOError):
            return b""
        except Exception:
            # don’t raise inside a scanner
            return b""
    # --- replace _iface_src_ip with this ---
    def _iface_src_ip(self, iface: str, target_ip: str) -> str | None:
        """
        Best-effort source IP for binding sockets:
          • Return the interface IP only if it exists AND matches target family (v4/v6)
          • Otherwise return None so the OS picks a valid source
        """
        cfg = self.interfaces_config.get(iface) or {}
        ip = cfg.get("ip_addr")
        if not ip:
            return None
        try:
            t_is_v6 = ipaddress.ip_address(target_ip).version == 6
            s_is_v6 = ipaddress.ip_address(str(ip)).version == 6
            return str(ip) if (t_is_v6 == s_is_v6) else None
        except Exception:
            return None

    # --- new tiny helper (use in both TLS and plaintext probes) ---
    def _create_conn(self, ip: str, port: int, iface: str, timeout: float):
        """
        Try binding to the interface IP if valid; on Windows 10049 or any bind error,
        retry with no source binding so the OS chooses the right address.
        """
        src = self._iface_src_ip(iface, ip)
        try:
            if src:
                return socket.create_connection((ip, port), timeout=timeout, source_address=(src, 0))
            else:
                return socket.create_connection((ip, port), timeout=timeout)
        except OSError as e:
            # WinError 10049: "requested address is not valid in its context" → retry unbound
            if getattr(e, "winerror", None) == 10049 or getattr(e, "errno", None) in (99,):  # EADDRNOTAVAIL
                return socket.create_connection((ip, port), timeout=timeout)
            raise
    # ---------------- state changes & notifications ----------------

    def _handle_state_change(self, ip: str, port: int, status: str, banner: Optional[str]) -> None:
        """
        Emit "new open" and "closed" events, with banner text if present.
        """
        is_open_now = status.startswith("OPEN")
        ident = (ip, port)
        was_open = ident in self.open_ports_state

        if is_open_now and not was_open:
            self.open_ports_state.add(ident)
            self.router_logger.log_message(f"[SYNScanner] ✅ NEW OPEN PORT: {ip}:{port}")
            if banner:
                self.router_logger.log_message(f"[SYNScanner]    Banner: {banner}")
            if self.notification_manager:
                self.notification_manager.send_notification({
                    "event": "Port Opened",
                    "ip": ip,
                    "port": port,
                    "banner": banner or "N/A",
                })
            return

        if (not is_open_now) and was_open:
            self.open_ports_state.remove(ident)
            self.router_logger.log_message(f"[SYNScanner] ❌ PORT CLOSED: {ip}:{port}")
            if self.notification_manager:
                self.notification_manager.send_notification({
                    "event": "Port Closed",
                    "ip": ip,
                    "port": port,
                })
            return

        # No state change → avoid noisy repeats; optionally log terse info for debugging
        if status.startswith("FILTERED"):
            # Reduce verbosity: don't spam every cycle
            return
        if status == "CLOSED":
            return
        # For unusual statuses, keep a single line
        if not was_open and not is_open_now:
            self.router_logger.log_message(f"[SYNScanner] Note: {ip}:{port} status={status}")

class ICMPManager:
    """
    Self-contained ICMP/ND/MLD manager.

    Features:
      • ICMPv4 Echo, common error logging, IPv4 reassembly of router-destined frags,
        and IPv4 reply fragmentation to fit MTU.
      • ICMPv6 Echo, DestUnreach, TimeExceeded, ParamProblem, PacketTooBig generation on oversize reply.
      • IPv6 Neighbor Discovery: learn SLLA/TLLA (even via Unknown TLV), answer NS with NA,
        answer RS with a minimal RA (if iface config has prefix).
      • MLDv1 (Query/Report/Done) & MLDv2 (Report type 143) membership tracking with timeout purge.

    Expected external contracts:
      - router_logger: has log_message(str) -> None
      - packet_writer: has queue_packet(Packet, outbound_iface: str) -> None
      - interfaces_config: dict keyed by interface name -> {
            "mac": "...",
            "ip_addr": "v4addr",
            "ipv6_addr" or "ipv6"/"ip6"/"ip_addr6": "v6addr",
            "ipv6_prefix": "2001:db8:1::",  # (optional) for RA
            "mtu": 1500
        }
    """

    # Tunables
    MLD_MEMBERSHIP_TIMEOUT = 260
    PURGE_INTERVAL_SEC = 60
    REASM_TIMEOUT_SEC = 5.0
    _EIGHT = 8

    def __init__(self, router_logger, packet_writer, interfaces_config: dict, rate_limit_pps: int = 5):
        self.log = router_logger
        self.pw = packet_writer
        self.ifaces = interfaces_config or {}

        # Rate limit Echo-Reply per (src,dst)
        self.rate_limit_pps = rate_limit_pps
        self._last_reply_time = defaultdict(float)
        self._rate_limit_lock = threading.Lock()

        # IPv4 reassembly state
        # key: (src,dst,proto,id) -> {"first_hdr": IP, "parts": {offset_bytes: bytes}, "total": int|None, "t0": ts, "iface": str}
        self._reasm: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
        self._reasm_lock = threading.Lock()

        # IPv6 ND + MLD state
        # ND neighbor cache: v6 -> { "mac": str, "seen": ts }
        self.nd_cache: Dict[str, Dict[str, Any]] = {}
        # MLD membership: (group, iface) -> {"last_report": ts, "mode": "include"/"exclude", "sources": set()}
        self._mld_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._mld_lock = threading.Lock()

        # Purge thread
        self._stop = threading.Event()
        self._purger = threading.Thread(target=self._purge_loop, daemon=True, name="ICMPPurger")
        self._purger.start()

        self.log.log_message("[ICMP] Manager initialized (IPv4 reasm/frag + ICMPv6 + ND + MLD).")

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------
    def stop(self):
        """Stops background purge thread."""
        self._stop.set()
        if self._purger.is_alive():
            self._purger.join(timeout=2)

    # -------------------------------------------------------------------------
    # Entry point
    # -------------------------------------------------------------------------
    def handle_packet(self, pkt: Packet, inbound_iface: str) -> bool:
        """
        Dispatch based on IP version.
        Return True when fully handled (consumed).
        """
        try:
            if pkt.haslayer(IPv6):
                return self._handle_ipv6(pkt, inbound_iface)
            if pkt.haslayer(IP):
                return self._handle_ipv4(pkt, inbound_iface)
        except Exception as e:
            self.log.log_message(f"[ICMP] ❗ ERROR in handle_packet: {e}\n{traceback.format_exc()}")
        return False

    # -------------------------------------------------------------------------
    # IPv6 path
    # -------------------------------------------------------------------------
    def _handle_ipv6(self, pkt: Packet, iface: str) -> bool:
        v6 = pkt[IPv6]

        # ND first (NS/NA/RS)
        if pkt.haslayer(ICMPv6ND_NS):
            self._handle_ns(pkt, iface)
            return True
        if pkt.haslayer(ICMPv6ND_NA):
            self._handle_na(pkt)
            return True
        if pkt.haslayer(ICMPv6ND_RS):
            self._handle_rs(pkt, iface)
            return True

        # MLD
        if self._handle_mld(pkt, iface):
            return True

        # Echo Request (only if addressed to us)
        if pkt.haslayer(ICMPv6EchoRequest) and self._is_for_router_v6(v6.dst):
            self._handle_echo_request_v6(pkt, iface)
            return True

        # Common ICMPv6 errors -> log (and optional sendback hook site if you add one)
        if self._handle_icmpv6_errors(pkt, iface):
            return True

        return False

    # ----- ICMPv6 echo -----
    def _handle_echo_request_v6(self, pkt: Packet, iface: str) -> None:
        v6 = pkt[IPv6]
        req = pkt[ICMPv6EchoRequest]
        src_ip, dst_ip = v6.src, v6.dst

        self.log.log_message(f"[ICMP] 📨 Echo-Request v6 {src_ip} → {dst_ip} on {iface.split('_')[-1]} (len={len(bytes(pkt))})")
        if self._is_rate_limited(src_ip, dst_ip):
            return

        l2src = self._iface_mac_by_v6(dst_ip) or "00:00:00:00:00:00"
        l2dst = pkt[Ether].src if pkt.haslayer(Ether) and not self._is_loopback_name(iface) else None

        base = IPv6(src=dst_ip, dst=src_ip)
        echo = ICMPv6EchoReply(id=int(req.id), seq=int(req.seq)) / req.payload

        reply = (Ether(src=l2src, dst=l2dst) / base / echo) if l2dst else (base / echo)

        # IPv6: cannot fragment in-source. If it doesn't fit MTU, emit PTB.
        self._maybe_queue_v6_or_too_big(reply, pkt, iface)
        self.log.log_message(f"[ICMP] ✅ Echo-Reply v6 queued on {iface.split('_')[-1]} for {src_ip}")

    # ----- ICMPv6 errors -----
    def _handle_icmpv6_errors(self, pkt: Packet, iface: str) -> bool:
        if pkt.haslayer(ICMPv6DestUnreach):
            du = pkt[ICMPv6DestUnreach]
            self.log.log_message(f"[ICMP] 🔌 v6 DestUnreach code={int(du.code)} on {iface.split('_')[-1]}; {pkt.summary()}")
            if int(du.code) == 1:  # admin prohibited
                self._log_admin_block_v6(pkt, iface)
            return True

        if pkt.haslayer(ICMPv6TimeExceeded):
            te = pkt[ICMPv6TimeExceeded]
            self.log.log_message(f"[ICMP] ⏳ v6 TimeExceeded code={int(te.code)} on {iface.split('_')[-1]}; {pkt.summary()}")
            return True

        if pkt.haslayer(ICMPv6ParamProblem):
            pp = pkt[ICMPv6ParamProblem]
            self.log.log_message(f"[ICMP] 🧩 v6 ParamProblem code={int(pp.code)} on {iface.split('_')[-1]}; {pkt.summary()}")
            return True

        return False

    def _log_admin_block_v6(self, pkt, inbound_iface: Optional[str]) -> None:
        """
        ICMPv6 Destination Unreachable (Type=1) with admin-prohibited-like codes.
        Codes of interest (RFC 4443):
          1 = Communication with destination administratively prohibited
          5 = Source address failed ingress/egress policy
          6 = Reject route to destination
        """
        try:
            if ICMPv6DestUnreach is None or not pkt.haslayer(ICMPv6DestUnreach):
                return
            ic = pkt[ICMPv6DestUnreach]
            code = int(getattr(ic, "code", -1))

            # Map a few common codes to short labels
            code_name = {
                1: "admin-prohibited",
                5: "src-policy-fail",
                6: "reject-route",
            }.get(code, f"code={code}")

            src, dst = self._v6_endpoints(pkt)
            inner = self._extract_inner_5tuple_v6(ic)

            msg = (
                f"[Transport][🛰 ICMPv6] 🚫 {code_name} "
                f"{src} → {dst} on {self._iface_suffix(inbound_iface)}"
            )
            if inner:
                msg += (
                    f" | inner={inner['proto']} "
                    f"{inner['src']}:{inner['sport']} → {inner['dst']}:{inner['dport']}"
                )
            self.log.log_message(msg)
        except Exception:
            # never let logging throw
            pass

        # ---- tiny helpers (robust, no-throw) ----

    def _v6_endpoints(self, pkt):
        try:
            if IPv6 is not None and pkt.haslayer(IPv6):
                ip6 = pkt[IPv6]
                return str(getattr(ip6, "src", "::")), str(getattr(ip6, "dst", "::"))
        except Exception:
            pass
        return "::", "::"

    def _extract_inner_5tuple_v6(self, ic_layer) -> Optional[dict]:
        """
        Try to recover the offending inner packet 5-tuple from the ICMPv6 payload.
        Returns dict with src/dst/sport/dport/proto or None.
        """
        try:
            # The ICMPv6 error should carry the invoking (truncated) packet as payload.
            inner = getattr(ic_layer, "payload", None)
            if not inner or not hasattr(inner, "haslayer"):
                return None

            # Some stacks nest IPv6 directly; others have multiple wraps—walk one step.
            ip6 = inner[IPv6] if (IPv6 is not None and inner.haslayer(IPv6)) else None
            if not ip6:
                return None

            src = str(getattr(ip6, "src", "::"))
            dst = str(getattr(ip6, "dst", "::"))

            if TCP is not None and inner.haslayer(TCP):
                l4 = inner[TCP]
                return {
                    "proto": "TCP",
                    "src": src,
                    "dst": dst,
                    "sport": int(getattr(l4, "sport", 0) or 0),
                    "dport": int(getattr(l4, "dport", 0) or 0),
                }
            if UDP is not None and inner.haslayer(UDP):
                l4 = inner[UDP]
                return {
                    "proto": "UDP",
                    "src": src,
                    "dst": dst,
                    "sport": int(getattr(l4, "sport", 0) or 0),
                    "dport": int(getattr(l4, "dport", 0) or 0),
                }

            # No TCP/UDP — fall back to proto number only
            return {"proto": f"nh={getattr(ip6, 'nh', '-')}", "src": src, "dst": dst, "sport": 0, "dport": 0}
        except Exception:
            return None

    def _iface_suffix(self, inbound_iface: Optional[str]) -> str:
        try:
            return (inbound_iface or "").split("_")[-1] or "-"
        except Exception:
            return "-"
    # ----- Neighbor Discovery -----
    def _handle_ns(self, pkt: Packet, iface: str) -> None:
        ns, v6 = pkt[ICMPv6ND_NS], pkt[IPv6]
        target_ip = getattr(ns, "tgt", None)

        # Learn SLLA (even through Unknown TLV)
        mac = self._nd_peer_mac_from_pkt(pkt) or (pkt[Ether].src if pkt.haslayer(Ether) else None)
        if mac:
            self._nd_learn_mac(v6.src, mac)

        # If NS targets one of our IPs, send NA
        if target_ip and self._is_for_router_v6(target_ip):
            self._send_neighbor_advertisement(pkt, target_ip, iface)

    def _handle_na(self, pkt: Packet) -> None:
        na, v6 = pkt[ICMPv6ND_NA], pkt[IPv6]
        who = getattr(na, "tgt", v6.src)
        mac = self._nd_peer_mac_from_pkt(pkt) or (pkt[Ether].src if pkt.haslayer(Ether) else None)
        if mac:
            self._nd_learn_mac(who, mac)
        self.log.log_message(f"[ICMP][ND] 📒 Learned neighbor {who} -> {mac or '??'}")

    def _handle_rs(self, pkt: Packet, iface: str) -> None:
        self.log.log_message(f"[ICMP][ND] 📨 Router Solicitation from {pkt[IPv6].src} on {iface.split('_')[-1]}")
        self._send_router_advertisement(iface, destination_ip=pkt[IPv6].src)

    def _send_neighbor_advertisement(self, solicitation_pkt: Packet, target_ip: str, iface: str) -> None:
        my_mac = self._iface_mac_by_v6(target_ip)
        if not my_mac:
            self.log.log_message(f"[ICMP][ND] ⚠️ Cannot find MAC for our IP {target_ip} to send NA.")
            return

        v6s = solicitation_pkt[IPv6]
        dst_ip = v6s.src
        dst_mac = solicitation_pkt[Ether].src if solicitation_pkt.haslayer(Ether) else self._solicited_node_mac_for_target(dst_ip)

        # Build NA with TLLA option (manually packed to avoid parser variance)
        tlla = self._pack_nd_lladdr_opt(opt_type=2, mac_str=my_mac)
        na = (Ether(src=my_mac, dst=dst_mac) /
              IPv6(src=target_ip, dst=dst_ip, hlim=255) /
              ICMPv6ND_NA(R=1, S=1, O=1, tgt=target_ip) /
              Raw(load=tlla))
        self.pw.queue_packet(na, iface)
        self.log.log_message(f"[ICMP][ND] ✅ NA sent for {target_ip} → {dst_ip} on {iface.split('_')[-1]} (R,S,O=1)")

    def _send_router_advertisement(self, iface: str, destination_ip: str) -> None:
        cfg = self.ifaces.get(iface, {})
        my_mac = cfg.get("mac")
        my_ll = cfg.get("ipv6_addr") or cfg.get("ipv6") or cfg.get("ip6") or cfg.get("ip_addr6")
        prefix = cfg.get("ipv6_prefix")
        if not (my_mac and my_ll):
            return

        dst_ip = destination_ip if destination_ip and destination_ip != "::" else "ff02::1"
        dst_mac = self.nd_cache.get(self._norm_v6(dst_ip), {}).get("mac") or "33:33:00:00:00:01"

        ra = (Ether(src=my_mac, dst=dst_mac) /
              IPv6(src=my_ll, dst=dst_ip, hlim=255) /
              ICMPv6ND_RA(M=0, O=0, routerlifetime=1800) /
              ICMPv6NDOptSrcLLAddr(lladdr=my_mac))

        if prefix:
            ra = ra / ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=64, L=1, A=1,
                                            validlifetime=7200, preferredlifetime=1800)

        self.pw.queue_packet(ra, iface)
        self.log.log_message(f"[ICMP][ND] ✅ RA sent to {dst_ip} on {iface.split('_')[-1]}")

    # -------------------------------------------------------------------------
    # MLD (v1/v2) membership handling
    # -------------------------------------------------------------------------
    def _handle_mld(self, pkt: Packet, inbound_iface: str) -> bool:
        if not pkt.haslayer(IPv6):
            return False

        v6 = pkt[IPv6]
        src_ip6 = v6.src
        iface_short = inbound_iface.split("_")[-1]

        # v1: 130 Query / 131 Report / 132 Done
        if pkt.haslayer(MLDReport) or pkt.haslayer(MLDDone) or pkt.haslayer(MLDQuery):
            group_ip = self._get_mld_v1_group(pkt)
            kind = "Report" if pkt.haslayer(MLDReport) else "Done" if pkt.haslayer(MLDDone) else "Query"
            self.log.log_message(f"[ICMP][MLD] v1 {kind} from {src_ip6} on {iface_short} gaddr={group_ip}")
            if pkt.haslayer(MLDReport):
                self._mld_join(group_ip, inbound_iface, mode="include", sources=None, who=src_ip6)
            elif pkt.haslayer(MLDDone):
                self._mld_leave(group_ip, inbound_iface, who=src_ip6)
            return True

        # v2 Report (type 143) – names vary across Scapy builds
        if self._looks_like_mldv2_report(pkt):
            rep = pkt.getlayer("MLDv2report") or pkt.getlayer("MLDv2Report") or pkt.getlayer("ICMPv6MLReport2")
            records = getattr(rep, "records", None) or getattr(rep, "grps", None)
            if not records:
                self.log.log_message("[ICMP][MLD] v2 report without records (parser mismatch).")
                return True

            for rec in records:
                rtype = int(getattr(rec, "rtype", getattr(rec, "type", 0)))
                group = str(getattr(rec, "mcaddr", getattr(rec, "maddr", "::")))
                srcs  = [str(s) for s in (getattr(rec, "srcaddrs", []) or getattr(rec, "sources", []))]
                if rtype in (1, 3):  # INCLUDE
                    self._mld_join(group, inbound_iface, mode="include", sources=set(srcs) if srcs else set(), who=src_ip6)
                elif rtype in (2, 4):  # EXCLUDE
                    self._mld_join(group, inbound_iface, mode="exclude", sources=set(srcs) if srcs else set(), who=src_ip6)
                elif rtype == 5:      # ALLOW_NEW_SOURCES
                    self._mld_join(group, inbound_iface, mode="include", sources=set(srcs), who=src_ip6)
                elif rtype == 6:      # BLOCK_OLD_SOURCES
                    with self._mld_lock:
                        key = (group, inbound_iface)
                        ent = self._mld_groups.get(key)
                        if ent:
                            ent["last_report"] = time.time()
                    self.log.log_message(f"[ICMP][MLD] v2 BLOCK_OLD_SOURCES group={group} srcs={srcs} on {iface_short}")
                else:
                    self.log.log_message(f"[ICMP][MLD] v2 UNKNOWN({rtype}) group={group} srcs={srcs} on {iface_short} (noop)")
            return True

        return False

    def _get_mld_v1_group(self, pkt: Packet) -> str:
        if pkt.haslayer(MLDReport):
            return str(pkt[MLDReport].mcaddr)
        if pkt.haslayer(MLDDone):
            return str(pkt[MLDDone].mcaddr)
        if pkt.haslayer(MLDQuery):
            layer = pkt[MLDQuery]
            return str(getattr(layer, "mcaddr", "::"))
        return "::"

    def _looks_like_mldv2_report(self, pkt: Packet) -> bool:
        for name in ("MLDv2report", "MLDv2Report", "ICMPv6MLReport2"):
            if pkt.haslayer(name):
                return True
        ic = pkt.getlayer("ICMPv6") or pkt.getlayer(ICMPv6Unknown)
        try:
            return int(getattr(ic, "type", 0)) == 143
        except Exception:
            return False

    def _mld_join(self, group_ip: str, ifname: str, *, mode: str, sources: Optional[Set[str]], who: str) -> None:
        with self._mld_lock:
            key = (group_ip, ifname)
            ent = self._mld_groups.get(key, {"mode": "include", "sources": set(), "last_report": 0})
            if sources:
                ent["sources"].update(sources)
            ent["mode"] = mode
            ent["last_report"] = time.time()
            self._mld_groups[key] = ent
        src_txt = f" sources={sorted(sources)}" if sources else ""
        self.log.log_message(f"[ICMP][MLD] ✅ {who} joined {group_ip} on {ifname.split('_')[-1]} ({mode}{src_txt})")

    def _mld_leave(self, group_ip: str, ifname: str, *, who: str) -> None:
        with self._mld_lock:
            key = (group_ip, ifname)
            if key in self._mld_groups:
                del self._mld_groups[key]
                self.log.log_message(f"[ICMP][MLD] 🗑️ {who} left {group_ip} on {ifname.split('_')[-1]}.")
            else:
                self.log.log_message(f"[ICMP][MLD] {who} sent Done for {group_ip}, but not in table.")

    def get_mld_memberships(self) -> Dict[Tuple[str, str], Dict[str, Any]]:
        with self._mld_lock:
            out: Dict[Tuple[str, str], Dict[str, Any]] = {}
            for (g, iface), ent in self._mld_groups.items():
                out[(g, iface)] = {
                    "last_report": ent["last_report"],
                    "mode": ent["mode"],
                    "sources": sorted(ent["sources"]) if ent["sources"] else [],
                }
            return out

    # -------------------------------------------------------------------------
    # IPv6 MTU helper
    # -------------------------------------------------------------------------
    def _maybe_queue_v6_or_too_big(self, reply_pkt: Packet, original_pkt: Packet, outbound_iface: str) -> bool:
        mtu = self._get_iface_mtu(outbound_iface)
        raw_len = len(bytes(reply_pkt))
        if raw_len <= mtu:
            self.pw.queue_packet(reply_pkt, outbound_iface)
            return True

        # Build and send Packet Too Big (type 2), include as much of the invoking packet as reasonable.
        try:
            include = bytes(original_pkt[IPv6]) if original_pkt.haslayer(IPv6) else bytes(original_pkt)
        except Exception:
            include = bytes(original_pkt) if isinstance(original_pkt, (bytes, bytearray)) else b""
        inc_slice = include[:1232]  # safe cap

        if reply_pkt.haslayer(Ether):
            eth = reply_pkt[Ether]
            ptb = Ether(src=eth.src, dst=eth.dst) / IPv6(src=reply_pkt[IPv6].src, dst=reply_pkt[IPv6].dst) / \
                  ICMPv6PacketTooBig(mtu=mtu) / Raw(inc_slice)
        else:
            ptb = IPv6(src=reply_pkt[IPv6].src, dst=reply_pkt[IPv6].dst) / ICMPv6PacketTooBig(mtu=mtu) / Raw(inc_slice)

        self.pw.queue_packet(ptb, outbound_iface)
        self.log.log_message(f"[ICMP] 📦 Sent ICMPv6 Packet-Too-Big (mtu={mtu}) on {outbound_iface}")
        return True

    # -------------------------------------------------------------------------
    # IPv4 path
    # -------------------------------------------------------------------------
    def _handle_ipv4(self, pkt: Packet, iface: str) -> bool:
        ip = pkt[IP]

        # Reassemble if router-destined and fragmented
        is_for_router, router_mac, router_ip = self._match_router_ip_v4(ip.dst)
        if self._is_ipv4_fragment(ip) and is_for_router:
            assembled = self._reassemble_ipv4(pkt, iface)
            if assembled is None:
                return True  # buffered and handled
            pkt = assembled
            ip = pkt[IP]

        if not is_for_router:
            return False

        if not pkt.haslayer(ICMP):
            return False

        icmp = pkt[ICMP]
        if icmp.type == 8:  # Echo Request
            self._handle_echo_request_v4(pkt, iface, router_mac, router_ip)
            return True

        # Common errors
        if self._handle_icmpv4_errors(pkt, iface):
            return True

        return False

    # ----- ICMPv4 echo -----
    def _handle_echo_request_v4(self, pkt: Packet, iface: str, router_mac: Optional[str], router_ip: Optional[str]) -> None:
        ip = pkt[IP]
        icmp = pkt[ICMP]
        self.log.log_message(f"[ICMP] 📨 Echo-Request v4 {ip.src} → {ip.dst} on {iface.split('_')[-1]} (len={len(bytes(pkt))})")
        if self._is_rate_limited(ip.src, ip.dst):
            return

        if pkt.haslayer(Ether) and not self._is_loopback_name(iface):
            l2dst = pkt[Ether].src
            l2src = router_mac or "00:00:00:00:00:00"
            reply = Ether(src=l2src, dst=l2dst) / IP(src=ip.dst, dst=ip.src) / ICMP(type=0, id=icmp.id, seq=icmp.seq) / icmp.payload
        else:
            reply = IP(src=ip.dst, dst=ip.src) / ICMP(type=0, id=icmp.id, seq=icmp.seq) / icmp.payload

        self._maybe_fragment_and_queue_v4(reply, iface)
        self.log.log_message(f"[ICMP] ✅ Echo-Reply v4 queued on {iface.split('_')[-1]} for {ip.src}")

    # ----- ICMPv4 errors -----
    def _handle_icmpv4_errors(self, pkt: Packet, iface: str) -> bool:
        icmp = pkt[ICMP]
        t, c = int(icmp.type), int(getattr(icmp, "code", 0))
        if t == 3:  # DestUnreach
            # c==4 is "frag needed and DF set" (Next-Hop MTU in "unused"/nexthopmtu field depending on Scapy)
            if c == 4:
                hinted_mtu = getattr(icmp, "unused", None) or getattr(icmp, "nexthopmtu", None)
                self.log.log_message(f"[ICMP] 📦 v4 Frag-needed (DF) from {pkt[IP].src} on {iface.split('_')[-1]} (mtu={hinted_mtu})")
            elif c == 13:  # admin prohibited
                self._log_admin_block(pkt, iface)
            else:
                self.log.log_message(f"[ICMP] 🔌 v4 DestUnreach code={c} on {iface.split('_')[-1]}; {pkt.summary()}")
            return True

        if t == 11:  # Time Exceeded
            self.log.log_message(f"[ICMP] ⏳ v4 TimeExceeded code={c} on {iface.split('_')[-1]}; {pkt.summary()}")
            return True

        return False

    # -------------------------------------------------------------------------
    # IPv4 fragmentation & reassembly
    # -------------------------------------------------------------------------
    def _is_ipv4_fragment(self, ip: IP) -> bool:
        try:
            mf = bool(int(ip.flags) & 0x1)  # MF
        except Exception:
            mf = getattr(ip.flags, "MF", False)
        return mf or (int(ip.frag) > 0)

    def _reassemble_ipv4(self, pkt: Packet, inbound_iface: str) -> Optional[Packet]:
        ip = pkt[IP]
        key = (ip.src, ip.dst, int(ip.proto), int(ip.id))
        now = time.time()

        self._cleanup_reasm(now)

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
                    "first_hdr": ip.copy(),
                    "parts": {},
                    "total": None,
                    "t0": now,
                    "iface": inbound_iface,
                }

            st["parts"][off_bytes] = frag_payload
            st["t0"] = now

            if not mf:
                st["total"] = off_bytes + len(frag_payload)

            total = st["total"]
            if total is None:
                return None

            covered = 0
            while covered in st["parts"]:
                covered += len(st["parts"][covered])

            if covered < total:
                return None

            # Assemble
            assembled_payload = bytearray(total)
            for off, data in st["parts"].items():
                assembled_payload[off:off + len(data)] = data

            base = st["first_hdr"].copy()
            base.flags = 0
            base.frag = 0

            full = IP(bytes(base)) / Raw(bytes(assembled_payload))
            try:
                full = IP(bytes(full))  # force re-decode (pull inner ICMP, etc.)
            except Exception:
                pass

            del self._reasm[key]
            self.log.log_message(f"[ICMP] 🔧 Reassembled IPv4 frags {ip.src}→{ip.dst} (len={len(bytes(full))}) on {inbound_iface.split('_')[-1]}")
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
                    self.log.log_message(f"[ICMP] ⏳ Reassembly timeout v4 for {src}→{dst} proto={proto} on {st.get('iface')}.")

    def _maybe_fragment_and_queue_v4(self, reply_pkt: Packet, outbound_iface: str) -> None:
        mtu = self._get_iface_mtu(outbound_iface)
        raw_len = len(bytes(reply_pkt))
        if raw_len <= mtu:
            self.pw.queue_packet(reply_pkt, outbound_iface)
            return

        l2_overhead = 14 if reply_pkt.haslayer(Ether) else 0
        ip_mtu = max(576, mtu - l2_overhead)  # conservative lower bound

        if not reply_pkt.haslayer(IP):
            self.pw.queue_packet(reply_pkt, outbound_iface)
            self.log.log_message(f"[ICMP] ⚠ Oversize non-IPv4 reply ({raw_len}B) > MTU {mtu} on {outbound_iface}; sent as-is.")
            return

        ip_part = reply_pkt[IP].copy()
        try:
            if int(ip_part.flags) & 0x2:  # DF
                ip_part.flags = int(ip_part.flags) & ~0x2
        except Exception:
            ip_part.flags = 0

        try:
            ip_frags = self._ipv4_fragment_datagram(ip_part, ip_mtu)
        except Exception as e:
            self.log.log_message(f"[ICMP] ❌ Fragmentation v4 failed ({e}); sending unfragmented.")
            self.pw.queue_packet(reply_pkt, outbound_iface)
            return

        if reply_pkt.haslayer(Ether):
            eth = reply_pkt[Ether]
            for ipf in ip_frags:
                self.pw.queue_packet(Ether(src=eth.src, dst=eth.dst) / ipf, outbound_iface)
        else:
            for ipf in ip_frags:
                self.pw.queue_packet(ipf, outbound_iface)

        self.log.log_message(f"[ICMP] ✂ Fragmented Echo-Reply v4 into {len(ip_frags)} frags for {outbound_iface} (MTU={mtu}).")

    def _ipv4_fragment_datagram(self, ip_pkt: IP, ip_mtu: int):
        ihl_bytes = int(getattr(ip_pkt, "ihl", 5)) * 4
        if ihl_bytes <= 0:
            ihl_bytes = 20

        max_payload = (max(ip_mtu - ihl_bytes, 0) // 8) * 8
        if max_payload <= 0:
            raise ValueError(f"ip_mtu too small ({ip_mtu}) for header size {ihl_bytes}")

        full_payload = bytes(ip_pkt.payload)
        total = len(full_payload)
        frags = []
        offset = 0

        while offset < total:
            chunk = full_payload[offset: offset + max_payload]
            more = (offset + len(chunk)) < total

            frag = IP(
                version=ip_pkt.version, ihl=ip_pkt.ihl, tos=ip_pkt.tos, id=ip_pkt.id,
                flags=0, frag=offset // 8, ttl=ip_pkt.ttl, proto=ip_pkt.proto,
                src=ip_pkt.src, dst=ip_pkt.dst, options=getattr(ip_pkt, "options", b"") or b"",
            ) / Raw(chunk)

            if more:
                try:
                    frag.flags = int(frag.flags) | 0x1  # MF
                except Exception:
                    frag.flags = 0x1

            try:
                del frag.len, frag.chksum
            except Exception:
                pass

            frags.append(frag)
            offset += len(chunk)

        return frags

    # -------------------------------------------------------------------------
    # ND helpers
    # -------------------------------------------------------------------------
    def _nd_peer_mac_from_pkt(self, pkt: Packet) -> Optional[str]:
        # Preferred: use concrete ND option layers
        for lname in ("ICMPv6NDOptSrcLLAddr", "ICMPv6NDOptDstLLAddr"):
            opt = pkt.getlayer(lname)
            if opt is not None and hasattr(opt, "lladdr"):
                val = getattr(opt, "lladdr", None)
                if val:
                    return str(val)

        # Some stacks send Target Link-Layer Address as an option –
        # Scapy might parse it as Unknown. Parse Unknown TLVs manually.
        opt = pkt.getlayer("ICMPv6NDOptUnknown")
        seen = set()
        while opt and id(opt) not in seen:
            seen.add(id(opt))
            try:
                raw = bytes(opt)
                if len(raw) >= 2:
                    t = raw[0]
                    l = raw[1] * 8
                    if l == 0:
                        break
                    body = raw[2:l] if len(raw) >= l else raw[2:]
                    if t in (1, 2) and len(body) >= 6:  # 1=SLLA, 2=TLLA
                        mac_bytes = body[:6]
                        return ":".join(f"{b:02x}" for b in mac_bytes)
            except Exception:
                pass
            opt = opt.payload if hasattr(opt, "payload") else None
        return None

    def _pack_nd_lladdr_opt(self, opt_type: int, mac_str: str) -> bytes:
        mac_bytes = bytes.fromhex(mac_str.replace(":", "")) if mac_str else b"\x00" * 6
        mac_bytes = mac_bytes[:6].ljust(6, b"\x00")
        return bytes([opt_type & 0xFF, 1]) + mac_bytes  # 8 bytes total (type, len=1, 6B MAC)

    def _nd_learn_mac(self, ip6: str, mac: str) -> None:
        try:
            key = str(ipaddress.IPv6Address(ip6))
        except Exception:
            key = str(ip6)
        self.nd_cache[key] = {"mac": mac, "seen": time.time()}

    def _solicited_node_mac_for_target(self, target_ip6: str) -> str:
        try:
            val = int(ipaddress.IPv6Address(target_ip6))
            last24 = val & 0xFFFFFF
            return f"33:33:ff:{(last24 >> 16) & 0xFF:02x}:{(last24 >> 8) & 0xFF:02x}:{last24 & 0xFF:02x}"
        except Exception:
            return "33:33:ff:00:00:00"

    # -------------------------------------------------------------------------
    # Misc helpers
    # -------------------------------------------------------------------------
    def _match_router_ip_v4(self, dst_ip: str) -> Tuple[bool, Optional[str], Optional[str]]:
        for _, cfg in (self.ifaces or {}).items():
            if cfg.get("ip_addr") == dst_ip:
                return True, cfg.get("mac"), cfg.get("ip_addr")
        return False, None, None

    def _iface_mac_by_v6(self, ip6: str) -> Optional[str]:
        ip6n = self._norm_v6(ip6)
        for _, cfg in (self.ifaces or {}).items():
            for k in ("ipv6_addr", "ipv6", "ip6", "ip_addr6"):
                if self._norm_v6(cfg.get(k)) == ip6n:
                    return cfg.get("mac")
        return None

    def _is_for_router_v6(self, dst_ip: str) -> bool:
        return self._norm_v6(dst_ip) in self._iface_v6_set()

    def _get_iface_mtu(self, name: str) -> int:
        try:
            return int(self.ifaces.get(name, {}).get("mtu", 1500))
        except Exception:
            return 1500

    def _is_loopback_name(self, name: str) -> bool:
        n = (name or "").lower()
        return "loopback" in n or n == "lo"

    def _norm_v6(self, addr: Any) -> Optional[str]:
        if not addr:
            return None
        try:
            return str(ipaddress.IPv6Address(addr))
        except Exception:
            return str(addr)

    def _iface_v6_set(self) -> Set[str]:
        keys = ("ipv6_addr", "ipv6", "ip6", "ip_addr6")

        # ✅ Change 'Set[str]' to 'set[str]' for the mutable local variable
        addrs: set[str] = set()

        for _, cfg in (self.ifaces or {}).items():
            for k in keys:
                nv = self._norm_v6(cfg.get(k))
                if nv:
                    # The type checker now knows `addrs` has an .add() method
                    addrs.add(nv)
        return addrs
    def _extract_inner_ipv4(self, pkt: Packet) -> Optional[IP]:
        """
        Best-effort extraction of the original IPv4 header carried inside an ICMPv4 error.
        Handles Scapy's IPerror/TCPerror/UDPerror layers or raw bytes fallback.
        """
        icmp = pkt.getlayer(ICMP)
        if not icmp:
            return None

        # 1) Scapy sometimes builds IPerror/TCPerror/UDPerror; prefer those.
        iperr = icmp.getlayer("IPerror") or pkt.getlayer("IPerror")
        if iperr:
            try:
                # IPerror behaves like IP for our purposes
                return IP(bytes(iperr))
            except Exception:
                pass

        # 2) If payload is raw bytes starting at an IPv4 header, parse it directly.
        try:
            raw_inner = bytes(icmp.payload)
        except Exception:
            raw_inner = b""

        if len(raw_inner) >= 20:
            # sanity: version=4, ihl between 5..15
            vihl = raw_inner[0]
            ver = (vihl >> 4) & 0xF
            ihl = (vihl & 0xF)
            if ver == 4 and 5 <= ihl <= 15:
                try:
                    return IP(raw_inner)
                except Exception:
                    pass

        # 3) Nothing usable
        return None

    def _proto_name_v4(self, proto_num: int) -> str:
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(proto_num), str(proto_num))


    def _log_admin_block(self, pkt: Packet, inbound_iface: str) -> None:
        icmp = pkt[ICMP]
        ip2 = self._extract_inner_ipv4(pkt)

        if ip2 is not None:
            l4 = ip2.payload
            sport = getattr(l4, "sport", None)
            dport = getattr(l4, "dport", None)
            proto = self._proto_name_v4(getattr(ip2, "proto", 0))
            self.log.log_message(
                f"[ICMP] 🔒 Admin-prohibited v4 on {inbound_iface.split('_')[-1]}: "
                f"{ip2.src}:{sport if sport is not None else '-'} → "
                f"{ip2.dst}:{dport if dport is not None else '-'} proto={proto}"
            )
            return

        # Fallback: payload too short / not captured / non-standard
        try:
            raw_inner = bytes(icmp.payload)
        except Exception:
            raw_inner = b""

        snippet = raw_inner[:32].hex(" ") if raw_inner else ""
        self.log.log_message(
            f"[ICMP] 🔒 Admin-prohibited v4 (no parsable inner IP) on {inbound_iface.split('_')[-1]} "
            f"(inner_len={len(raw_inner)}B, head={snippet})"
        )
    # -------------------------------------------------------------------------
    # Purge loop
    # -------------------------------------------------------------------------
    def _purge_loop(self):
        self.log.log_message("[ICMP] MLD/ND purge thread started.")
        while not self._stop.is_set():
            self._purge_mld_memberships()
            # (Optional) ND cache aging could be added here
            self._stop.wait(self.PURGE_INTERVAL_SEC)
        self.log.log_message("[ICMP] MLD/ND purge thread exited.")

    def _purge_mld_memberships(self) -> None:
        now = time.time()
        with self._mld_lock:
            to_del = [
                key for key, ent in self._mld_groups.items()
                if (now - ent.get("last_report", 0)) > self.MLD_MEMBERSHIP_TIMEOUT
            ]
            for key in to_del:
                g, ifn = key
                del self._mld_groups[key]
                self.log.log_message(f"[ICMP][MLD] 🧹 Timed out membership for {g} on {ifn.split('_')[-1]}.")

    # -------------------------------------------------------------------------
    # Rate limit
    # -------------------------------------------------------------------------
    def _is_rate_limited(self, src_ip: str, dst_ip: str) -> bool:
        with self._rate_limit_lock:
            now = time.time()
            key = (src_ip, dst_ip)
            if now - self._last_reply_time[key] < (1.0 / self.rate_limit_pps):
                self.log.log_message(f"[ICMP] 🚫 Rate-limiting Echo-Reply to {src_ip}.")
                return True
            self._last_reply_time[key] = now
            return False