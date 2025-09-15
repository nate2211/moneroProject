import binascii
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
from typing import Optional, List, Any, Callable, Union, OrderedDict
import ipaddress
import threading
import json
import time
import numpy as np
import zmq
from scapy.arch import get_if_hwaddr
from scapy.contrib.ikev2 import IKEv2
from scapy.fields import StrLenField
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import DHCP6, DHCP6_Solicit
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import TCP, ICMP, defrag
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6TimeExceeded, \
    ICMPv6ParamProblem, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6Unknown, ICMPv6PacketTooBig, IPv6ExtHdrHopByHop, ICMPv6ND_RA, \
    ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, ICMPv6ND_RS, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, \
    getmacbyip6, ICMPv6NDOptUnknown
from scapy.layers.isakmp import ISAKMP
from scapy.layers.l2 import ARP, Ether, Dot1Q, getmacbyip
from scapy.libs.rfc3961 import Key
from scapy.packet import Packet, Raw, NoPayload
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict
from scapy.layers.kerberos import (
    Kerberos,
    EncryptedData
)

from p2pool_router_managers_2 import TLSRecordManager, TLSRecord,ZMQReader
from p2pool_sniffer import MLDQuery, MLDReport, MLDDone, ICMPv6
from server.p2pool_tools import RandomXLoader
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
        self.RATE_LIMIT_HZ = 5  # Max 10 packets per second per source IP
        self.BURST_LIMIT = 6  # How many packets to track for rate calculation
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

    def get_field_name(self, field):
        try:
            return field.name
        except AttributeError:
            return str(field)

    def _log_ikev2_details(self, packet: Packet):
        """
        Parses an IKEv2 packet and logs rich details from its payloads.
        Now includes validation to reject malformed packets.
        """
        ike_layer = packet.getlayer(IKEv2)
        src_ip = packet[IP].src

        declared_length = ike_layer.length
        actual_length = len(packet[UDP].payload)
        # --- END NEW ---
        # --- NEW: Upfront validation for IKEv2 header ---
        # 1. Check version. High nibble must be 2.
        if ike_layer.version >> 4 != 2:
            self.log.log_message(f"[IKEv2] REJECT: Invalid IKEv2 version {hex(ike_layer.version)} from {src_ip}.")
            return

        # 2. Check length. Must match the actual UDP payload length.
        declared_length = ike_layer.length
        actual_length = len(packet[UDP].payload)
        if declared_length != actual_length:
            self.log.log_message(
                f"[IKEv2] REJECT: Length mismatch from {src_ip}. Declared: {declared_length}, Actual: {actual_length}.")
            return
        log_details = {
            # FIX: Use helper to prevent AttributeError on unknown enum values
            "exchange_type": self.get_field_name(ike_layer.exch_type),
            "message_id": ike_layer.id,
            "is_initiator": "I" in self.get_field_name(ike_layer.flags),
            "proposals": [],
            "notifications": [],
            "traffic_selectors": [],
            "identity": "N/A",
            "auth_method": "N/A"
        }

        current_payload = ike_layer.payload
        while not isinstance(current_payload, NoPayload):
            payload_name = self.get_field_name(current_payload)

            if payload_name == "IKEv2 Security Association":
                if hasattr(current_payload, 'proposals'):
                    for proposal in current_payload.proposals:
                        prop_text = []
                        if hasattr(proposal, 'transforms'):
                            for transform in proposal.transforms:
                                # FIX: Use helper for all .name accesses
                                transform_type = self.get_field_name(transform.type)
                                transform_id = self.get_field_name(transform.ID)
                                prop_text.append(f"{transform_type}={transform_id}")
                        log_details["proposals"].append(" | ".join(prop_text))

            elif payload_name == "IKEv2 Identification Initiator":
                log_details[
                    "identity"] = f"{self.get_field_name(current_payload.id_type)}: {current_payload.id.decode(errors='ignore')}"

            elif payload_name == "IKEv2 Authentication":
                log_details["auth_method"] = self.get_field_name(current_payload.auth_method)

            elif payload_name in ["IKEv2 Traffic Selector Initiator", "IKEv2 Traffic Selector Responder"]:
                if hasattr(current_payload, 'traffic_selectors'):
                    for ts in current_payload.traffic_selectors:
                        log_details["traffic_selectors"].append(
                            f"Proto:{ts.proto} Start:{ts.start_addr}/{ts.start_port} End:{ts.end_addr}/{ts.end_port}"
                        )

            elif payload_name == "IKEv2 Notify":
                log_details["notifications"].append(
                    f"{self.get_field_name(current_payload.type)} (Proto:{self.get_field_name(current_payload.proto_id)})")

            current_payload = current_payload.payload

        self.log.log_message(f"[IKEv2] From {src_ip}: {log_details}")
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


        final_packet = pkt
        if final_packet.haslayer(IKEv2):
            self.log.log_message(f"[IKEv2] 📨 Packet from {src_ip} on {inbound_iface}")
            self._log_ikev2_details(final_packet)
        if final_packet.haslayer(ISAKMP):
            self.log.log_message(f"[ISAKMP] 📨 Packet from {src_ip} on {inbound_iface}")

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
        self.pw._send_raw_packet(fwd, egress, allow_dst_ours=True)
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
        self.pw._send_raw_packet(out, lan_if, allow_dst_ours=True)
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
    """
    HTTP (cleartext) parser & logger (low-overhead).

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool

    Design goals:
      • Fast-path after first classification (no deep parsing on subsequent packets)
      • Strict byte budget; no stream reassembly
      • Per-flow rate-limited logs
      • Handle tough cases: partial headers, CONNECT, h2c preface/upgrade, WebSocket
    """

    # ---- Tunables (balanced) ----
    FLOW_TTL_SEC      = 15 * 60
    FLOW_SOFT_MAX     = 50_000
    RL_INTERVAL_SEC   = 1.0
    HEADER_PEEK_BYTES = 512        # budget per packet
    DETECT_NON80      = False      # scan off-80 only if True

    METHODS = {b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}

    def __init__(self, logger,
                 *,
                 detect_non80_http: bool = DETECT_NON80,
                 header_peek_bytes: int = HEADER_PEEK_BYTES):
        self.logger = logger
        self.detect_non80_http = bool(detect_non80_http)
        self.peek_cap = max(128, int(header_peek_bytes))

        # flow cache: canonical 4-tuple (dir-agnostic) -> {last, last_log, noinspect}
        self._flows: Dict[Tuple[str, str, str, str], Dict[str, float | bool]] = {}
        self._last_gc = time.time()

        self.logger.log_message("[Transport][🌐 HTTP] Manager ready.")

    # -------------------- Public entry --------------------
    def handle(self, pkt, src_ip: str, dst_ip: str, sport: int, dport: int, inbound_iface: Optional[str] = None) -> bool:
        try:
            if TCP is None or not pkt or not pkt.haslayer(TCP):
                return False

            on_80 = (int(sport) == 80) or (int(dport) == 80)
            if not on_80 and not self.detect_non80_http:
                # Optional lightweight signature check for off-80
                if not self._cheap_http_signature(pkt):
                    return False

            fkey = self._flow_key(src_ip, sport, dst_ip, dport)
            now = time.time()
            st = self._flows.get(fkey)
            if st is None:
                st = {"last": now, "last_log": 0.0, "noinspect": False}
                self._flows[fkey] = st
            else:
                st["last"] = now

            # Fast-path after first parse
            if st.get("noinspect", False):
                if self._should_log(st, now):
                    self._log_line(src_ip, sport, dst_ip, dport, inbound_iface, info=None, tag="fast")
                self._maybe_gc(now)
                return True

            raw = self._get_raw(pkt)
            if not raw:
                if self._should_log(st, now):
                    self._log_line(src_ip, sport, dst_ip, dport, inbound_iface, info=None, tag="hdr-only")
                self._maybe_gc(now)
                return True

            mv = memoryview(raw)
            cap = min(len(mv), self.peek_cap)
            buf = bytes(mv[:cap])

            # HTTP/2 cleartext preface (h2c)
            if buf.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
                info = {"type": "h2c", "detail": "preface"}
                if self._should_log(st, now):
                    self._log_line(src_ip, sport, dst_ip, dport, inbound_iface, info)
                st["noinspect"] = True
                self._maybe_gc(now)
                return True

            # Decide request vs response
            is_request, req = self._parse_request(buf)
            if is_request:
                if self._should_log(st, now):
                    self._log_line(src_ip, sport, dst_ip, dport, inbound_iface, req)
                st["noinspect"] = True
                self._maybe_gc(now)
                return True

            is_response, resp = self._parse_response(buf)
            if is_response:
                if self._should_log(st, now):
                    self._log_line(src_ip, sport, dst_ip, dport, inbound_iface, resp)
                st["noinspect"] = True
                self._maybe_gc(now)
                return True

            # Partial/unknown payload on port 80 (don’t overwork)
            if self._should_log(st, now):
                self._log_line(src_ip, sport, dst_ip, dport, inbound_iface, info={"type": "unknown"})
            st["noinspect"] = True
            self._maybe_gc(now)
            return True

        except Exception:
            return False

    # -------------------- Parsing (budgeted, no reassembly) --------------------
    def _parse_request(self, buf: bytes) -> Tuple[bool, dict]:
        # Look for request line
        nl = buf.find(b"\r\n")
        if nl <= 0:
            return False, {}
        line = buf[:nl]
        parts = line.split(b" ")
        if len(parts) < 2:
            return False, {}
        method = parts[0]
        if method not in self.METHODS:
            return False, {}
        path = parts[1]
        # headers (within budget)
        headers = self._parse_headers_fast(buf[nl+2:])
        host = headers.get(b"host")
        ua = headers.get(b"user-agent")
        upgrade = headers.get(b"upgrade")
        conn = headers.get(b"connection")
        expect = headers.get(b"expect")
        http2 = (upgrade == b"h2c") or (b"upgrade" in (conn or b""))
        ws = (upgrade == b"websocket")
        info = {
            "type": "req",
            "method": method.decode("ascii", "ignore"),
            "path": self._safe_ascii(path),
            "host": self._safe_ascii(host),
            "ua": self._safe_ascii(ua, 50),
            "flags": ",".join(x for x in [
                "CONNECT" if method == b"CONNECT" else None,
                "h2c" if http2 else None,
                "ws" if ws else None,
                "100-continue" if (expect == b"100-continue") else None,
            ] if x),
        }
        return True, info

    def _parse_response(self, buf: bytes) -> Tuple[bool, dict]:
        if not buf.startswith(b"HTTP/1."):
            return False, {}
        nl = buf.find(b"\r\n")
        if nl <= 0:
            return False, {}
        line = buf[:nl]
        parts = line.split(b" ", 2)
        if len(parts) < 2:
            return False, {}
        code = parts[1]
        # headers
        headers = self._parse_headers_fast(buf[nl+2:])
        ctype = headers.get(b"content-type")
        clen = headers.get(b"content-length")
        loc  = headers.get(b"location")
        enc  = headers.get(b"content-encoding")
        te   = headers.get(b"transfer-encoding")
        server = headers.get(b"server")
        info = {
            "type": "resp",
            "code": self._safe_ascii(code),
            "ctype": self._safe_ascii(ctype, 40),
            "clen": self._safe_ascii(clen, 16),
            "enc":  self._safe_ascii(enc, 16) or self._safe_ascii(te, 16),
            "loc":  self._safe_ascii(loc, 80),
            "server": self._safe_ascii(server, 32),
        }
        return True, info

    def _parse_headers_fast(self, body: bytes) -> Dict[bytes, bytes]:
        # Stop at end of headers; ignore body
        end = body.find(b"\r\n\r\n")
        if end == -1:
            end = len(body)
        hdrs = body[:end]
        out: Dict[bytes, bytes] = {}
        # Simple loop; no unfolding/reassembly; budget already enforced
        for line in hdrs.split(b"\r\n"):
            if not line:
                continue
            i = line.find(b":")
            if i <= 0:
                continue
            k = line[:i].strip().lower()
            v = line[i+1:].strip()
            # First occurrence wins (cheap)
            if k not in out:
                out[k] = v
        return out

    # -------------------- Logging --------------------
    def _log_line(self, src, sport, dst, dport, iface, info: Optional[dict], tag: Optional[str] = None):
        is_80 = (int(sport) == 80) or (int(dport) == 80)
        base = f"[Transport][🧵 TCP][🌐 HTTP] {'80' if is_80 else 'non-80'} {src}:{sport} → {dst}:{dport} on {(iface or '').split('_')[-1] if iface else ''}"
        if tag == "hdr-only":
            self.logger.log_message(f"{base} | hdr-only")
            return
        if tag == "fast":
            self.logger.log_message(f"{base} | fast")
            return
        if not info:
            self.logger.log_message(f"{base}")
            return

        if info.get("type") == "req":
            host = info.get("host") or "-"
            path = info.get("path") or "-"
            ua   = info.get("ua") or "-"
            flags = info.get("flags") or "-"
            self.logger.log_message(f"{base} | {info.get('method','?')} {path} Host={host} UA={ua} {flags}")
        elif info.get("type") == "resp":
            code = info.get("code") or "-"
            ctype = info.get("ctype") or "-"
            clen  = info.get("clen") or "-"
            enc   = info.get("enc") or "-"
            loc   = info.get("loc")
            server= info.get("server") or "-"
            line = f"{base} | HTTP {code} type={ctype} len={clen} enc={enc} server={server}"
            if loc:
                line += f" loc={loc}"
            self.logger.log_message(line)
        else:
            self.logger.log_message(f"{base} | {info.get('type')}")

    # -------------------- Utilities --------------------
    def _flow_key(self, src_ip: str, sport: int, dst_ip: str, dport: int):
        a = (str(src_ip), str(int(sport)))
        b = (str(dst_ip), str(int(dport)))
        first, second = (a, b) if a <= b else (b, a)
        return first + second  # ('ip1','port1','ip2','port2')

    def _should_log(self, st: Dict[str, float | bool], now: float) -> bool:
        last = float(st.get("last_log", 0.0) or 0.0)
        if (now - last) >= self.RL_INTERVAL_SEC:
            st["last_log"] = now
            return True
        return False

    def _maybe_gc(self, now: float):
        if now - self._last_gc < 60:
            return
        ttl = self.FLOW_TTL_SEC
        if ttl > 0:
            stale = [k for k, v in self._flows.items() if now - float(v.get("last", now)) > ttl]
            for k in stale: self._flows.pop(k, None)
        if len(self._flows) > self.FLOW_SOFT_MAX:
            excess = len(self._flows) - self.FLOW_SOFT_MAX
            victims = sorted(self._flows.items(), key=lambda kv: kv[1].get("last", 0.0))[:excess]
            for k, _ in victims: self._flows.pop(k, None)
        self._last_gc = now

    def _get_raw(self, pkt) -> bytes:
        if Raw is None or not pkt.haslayer(Raw):
            return b""
        try:
            return bytes(pkt[Raw].load) or b""
        except Exception:
            return b""

    def _cheap_http_signature(self, pkt) -> bool:
        raw = self._get_raw(pkt)
        if not raw:
            return False
        buf = raw[:64]
        if buf.startswith(b"HTTP/1."):
            return True
        if buf.startswith(b"PRI * HTTP/2.0"):
            return True
        sp = buf.split(b" ", 1)[0]
        return sp in self.METHODS

    def _safe_ascii(self, b: Optional[bytes], maxlen: int = 128) -> Optional[str]:
        if not b:
            return None
        s = b.decode("latin-1", "ignore")
        return s if len(s) <= maxlen else (s[:maxlen] + "…")
class TransportSCADAManager:
    """
    Observes common ICS/SCADA protocols with cheap signature peeks.

    Protocols/ports:
      • Modbus/TCP           : 502/tcp
      • DNP3                 : 20000/tcp, 20000/udp
      • IEC 60870-5-104      : 2404/tcp
      • Siemens S7 (S7comm)  : 102/tcp
      • OPC UA (binary)      : 4840/tcp
      • BACnet/IP            : 47808/udp

    Public API:
      - handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
      - handle_udp(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
      - snapshot_metrics() -> dict
    """

    # ---- Tunables (baked in) ----
    FLOW_TTL_SEC        = 10 * 60
    FLOW_SOFT_MAX       = 20_000
    RL_INTERVAL_SEC     = 1.0
    BYTES_BUDGET        = 256

    # Ports
    PORT_MODBUS         = 502
    PORT_DNP3           = 20000
    PORT_IEC104         = 2404
    PORT_S7COMM         = 102
    PORT_OPCUA          = 4840
    PORT_BACNET_UDP     = 47808

    def __init__(self, logger):
        self.logger = logger
        self._peek_cap = self.BYTES_BUDGET
        self.logging_enabled = True
        self.flow_cache_ttl = self.FLOW_TTL_SEC
        self.flow_cache_max = self.FLOW_SOFT_MAX

        # flow_key -> {first,last,last_log, proto, extras}
        self._flows: Dict[Tuple[str,str,str,str], Dict[str, Any]] = {}

        self._metrics = {
            "seen": 0,
            "modbus": 0,
            "dnp3": 0,
            "iec104": 0,
            "s7": 0,
            "opcua": 0,
            "bacnet": 0,
            "errors": 0,
            "flow_cache_evictions": 0,
        }

        self._safe_log("[Transport][🏭 SCADA] Manager ready")

    # ---------------------------
    # Public entrypoints
    # ---------------------------
    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool:
        """TCP observer."""
        try:
            if not self._pre_checks(packet, want_udp=False):
                return False

            proto, info = self._classify_tcp(packet, sport, dport)
            if not proto:
                return False

            now = time.time()
            key = self._flow_key(src_ip, sport, dst_ip, dport)
            st = self._flows.get(key)
            if st is None:
                st = {"first": now, "last": now, "last_log": 0.0, "proto": proto, "extras": info}
                self._flows[key] = st
            else:
                st["last"] = now
                st["proto"] = st.get("proto") or proto
                if info: st["extras"] = info

            if self._should_log(st, now):
                self._log_tcp(proto, src_ip, sport, dst_ip, dport, inbound_iface, info)

            self._metrics["seen"] += 1
            self._clean_if_needed(now)
            return True

        except Exception:
            self._metrics["errors"] += 1
            return False

    def handle_udp(self, packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool:
        """UDP observer (DNP3/BACnet)."""
        try:
            if not self._pre_checks(packet, want_udp=True):
                return False

            proto, info = self._classify_udp(packet, sport, dport)
            if not proto:
                return False

            now = time.time()
            key = self._flow_key(src_ip, sport, dst_ip, dport)
            st = self._flows.get(key)
            if st is None:
                st = {"first": now, "last": now, "last_log": 0.0, "proto": proto, "extras": info}
                self._flows[key] = st
            else:
                st["last"] = now
                st["proto"] = st.get("proto") or proto
                if info: st["extras"] = info

            if self._should_log(st, now):
                self._log_udp(proto, src_ip, sport, dst_ip, dport, inbound_iface, info)

            self._metrics["seen"] += 1
            self._clean_if_needed(now)
            return True

        except Exception:
            self._metrics["errors"] += 1
            return False

    def snapshot_metrics(self) -> dict:
        return dict(self._metrics)

    # ---------------------------
    # Classifiers (cheap peeks)
    # ---------------------------
    def _classify_tcp(self, pkt, sport, dport) -> Tuple[Optional[str], Dict[str, Any]]:
        raw = self._raw(pkt)
        ports = (sport, dport)

        # Modbus/TCP (502): MBAP header 7 bytes, then func code
        if self._port_hit(self.PORT_MODBUS, ports) and len(raw) >= 8:
            # MBAP: trans(2) proto(2=0) len(2) unit(1) + PDU
            p_proto = int.from_bytes(raw[2:4], "big", signed=False)
            if p_proto == 0:
                func = raw[7]
                self._metrics["modbus"] += 1
                return "Modbus/TCP", {"fc": func}

        # DNP3 over TCP (20000): start 0x05 0x64, then length/control/addr (little-endian CRCs follow later)
        if self._port_hit(self.PORT_DNP3, ports) and len(raw) >= 2:
            if raw[0] == 0x05 and raw[1] == 0x64:
                self._metrics["dnp3"] += 1
                return "DNP3/TCP", {}

        # IEC-104 (2404): start 0x68, length field next, then 4 control bytes
        if self._port_hit(self.PORT_IEC104, ports) and len(raw) >= 6:
            if raw[0] == 0x68:
                apdu_len = raw[1]
                self._metrics["iec104"] += 1
                return "IEC-104", {"len": apdu_len}

        # S7comm (102): often starts with COTP (0x03 0x00 ...), then S7 header (0x32)
        if self._port_hit(self.PORT_S7COMM, ports) and len(raw) >= 7:
            # Quick/loose: look for COTP TPDU (0x03 0x00) and later 0x32
            if raw[0] == 0x03 and raw[1] == 0x00:
                # seek 0x32 within first 32 bytes
                if 0x32 in raw[:32]:
                    self._metrics["s7"] += 1
                    return "S7comm", {}

        # OPC UA (4840): hello/ack with ASCII "HEL"/"ACK" in UA binary header; also often contains "opc.tcp://"
        if self._port_hit(self.PORT_OPCUA, ports) and len(raw) >= 8:
            head = raw[:8]
            if b"opc.tcp" in raw or head[:3] in (b"HEL", b"ACK"):
                self._metrics["opcua"] += 1
                return "OPC-UA", {}

        return None, {}

    def _classify_udp(self, pkt, sport, dport) -> Tuple[Optional[str], Dict[str, Any]]:
        raw = self._raw(pkt)
        ports = (sport, dport)

        # DNP3/UDP (same framing)
        if self._port_hit(self.PORT_DNP3, ports) and len(raw) >= 2:
            if raw[0] == 0x05 and raw[1] == 0x64:
                self._metrics["dnp3"] += 1
                return "DNP3/UDP", {}

        # BACnet/IP (47808/udp): BVLC type=0x81 then function
        if self._port_hit(self.PORT_BACNET_UDP, ports) and len(raw) >= 4:
            if raw[0] == 0x81:
                func = raw[1]
                self._metrics["bacnet"] += 1
                return "BACnet/IP", {"fn": func}

        return None, {}

    # ---------------------------
    # Logging
    # ---------------------------
    def _log_tcp(self, proto, sip, sport, dip, dport, iface, info):
        extras = self._fmt_info(proto, info)
        self._safe_log(
            f"[Transport][🧵 TCP][🏭 SCADA] {proto} {sip}:{sport} → {dip}:{dport} on {self._iface_suffix(iface)}{extras}"
        )

    def _log_udp(self, proto, sip, sport, dip, dport, iface, info):
        extras = self._fmt_info(proto, info)
        self._safe_log(
            f"[Transport][🚀 UDP][🏭 SCADA] {proto} {sip}:{sport} → {dip}:{dport} on {self._iface_suffix(iface)}{extras}"
        )

    def _fmt_info(self, proto: str, info: Dict[str, Any]) -> str:
        if not info:
            return ""
        try:
            if proto.startswith("Modbus") and "fc" in info:
                return f" fc={info['fc']}"
            if proto.startswith("IEC-104") and "len" in info:
                return f" apdu_len={info['len']}"
            if proto.startswith("BACnet") and "fn" in info:
                return f" fn={info['fn']}"
        except Exception:
            pass
        # generic
        try:
            kv = ",".join(f"{k}={v}" for k, v in info.items())
            return f" {kv}" if kv else ""
        except Exception:
            return ""

    # ---------------------------
    # Utilities
    # ---------------------------
    def _pre_checks(self, pkt, *, want_udp: bool) -> bool:
        if (TCP is None) or (UDP is None):
            return False
        if not pkt:
            return False
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return False
        if want_udp:
            return pkt.haslayer(UDP)
        return pkt.haslayer(TCP)

    def _raw(self, pkt) -> bytes:
        if Raw is None or not pkt.haslayer(Raw):
            return b""
        try:
            return bytes(pkt[Raw].load)[: self._peek_cap] or b""
        except Exception:
            return b""

    @staticmethod
    def _port_hit(port: int, ports: Tuple[int, int]) -> bool:
        s, d = ports
        return (s == port) or (d == port)

    def _flow_key(self, src_ip: str, sport: int, dst_ip: str, dport: int):
        a = (str(src_ip), str(int(sport)))
        b = (str(dst_ip), str(int(dport)))
        first, second = (a, b) if a <= b else (b, a)
        return first + second

    def _should_log(self, st: Dict[str, Any], now: float) -> bool:
        last = st.get("last_log", 0.0)
        if (now - last) >= self.RL_INTERVAL_SEC:
            st["last_log"] = now
            return True
        return False

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

    def _clean_if_needed(self, now_ts: float):
        # TTL cleanup (every ~2k events)
        if self._metrics["seen"] % 2048 == 0:
            ttl = self.flow_cache_ttl
            if ttl > 0:
                stale = [k for k, v in self._flows.items() if now_ts - v.get("last", now_ts) > ttl]
                for k in stale:
                    self._flows.pop(k, None)
        # Soft cap cleanup
        if len(self._flows) > self.flow_cache_max:
            excess = len(self._flows) - self.flow_cache_max
            victims = sorted(self._flows.items(), key=lambda kv: kv[1].get("last", 0.0))[:excess]
            for k, _ in victims:
                self._flows.pop(k, None)
            self._metrics["flow_cache_evictions"] += excess

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


class TransportInspectionManager:
    """
    Deep, computationally-friendly inspection with built-in token-bucket logging.

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
    """

    # -------- Tunables (sane defaults) --------
    LOG_RPS            = 0.2          # average logs per second allowed globally
    LOG_BURST          = 50           # global burst capacity
    FLOW_COOLDOWN_S    = 20.0         # min seconds between logs for the same 5-tuple
    FLOW_TRACK_MAX     = 50_000       # soft cap for the cooldown map
    ENTROPY_SAMPLE_MAX = 1536         # bytes to sample for entropy (cheap)
    SHA1_SAMPLE_MAX    = 4096         # bytes to sample for sha1_8 (cheap)
    BIG_PAYLOAD_BYTES  = 1200         # treat as "important" when payload >= this
    GC_PERIOD_S        = 60.0
    COOLDOWN_JITTER_S  = 0.50         # small random jitter to spread bursts

    class _TokenBucket:
        __slots__ = ("capacity", "refill", "tokens", "last")
        def __init__(self, capacity: int, refill_rate_per_s: float):
            self.capacity = float(max(1, capacity))
            self.refill = float(max(0.05, refill_rate_per_s))
            self.tokens = float(self.capacity)
            self.last = time.time()

        def _refill(self):
            now = time.time()
            delta = now - self.last
            if delta > 0:
                self.tokens = min(self.capacity, self.tokens + delta * self.refill)
                self.last = now

        def allow(self, cost: float = 1.0) -> bool:
            self._refill()
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False

    class InspectBucket:
        """
        One-shot container for an inspection run. Heavy metrics computed lazily
        only if we're going to log (see finalize_payload_metrics()).
        """
        __slots__ = (
            "start_ts", "end_ts", "duration_ms", "packet", "iface",
            "l2_info", "l3_info", "l4_info", "payload_info", "layers",
            "anomalies", "payload_len", "payload_sample", "entropy_cap", "sha1_cap"
        )

        def __init__(self, packet: "Packet", inbound_iface: str, entropy_cap: int, sha1_cap: int):
            self.start_ts = time.perf_counter()
            self.end_ts = self.start_ts
            self.duration_ms = 0.0
            self.packet = packet
            self.iface = inbound_iface.split("_")[-1] if inbound_iface else "?"
            self.layers: list[str] = []
            self.anomalies: list[str] = []
            self.l2_info: dict = {}
            self.l3_info: dict = {}
            self.l4_info: dict = {}
            self.payload_info: dict = {}
            self.payload_len = 0
            self.payload_sample = b""
            self.entropy_cap = int(entropy_cap)
            self.sha1_cap = int(sha1_cap)

        # ---- cheap helpers (use sample, not whole payload)
        @staticmethod
        def _byte_entropy_sample(b: bytes) -> float:
            if not b:
                return 0.0
            counts = [0]*256
            for x in b:
                counts[x] += 1
            n = len(b)
            inv_n = 1.0 / n
            ent = 0.0
            for c in counts:
                if c:
                    p = c * inv_n
                    ent -= p * math.log2(p)
            return ent

        def _pkt_len_fast(self) -> int:
            # Prefer wirelen if available; fall back to len(bytes(pkt))
            try:
                wl = getattr(self.packet, "wirelen", None)
                if wl is not None:
                    return int(wl)
            except Exception:
                pass
            try:
                return len(bytes(self.packet))
            except Exception:
                return 0

        def parse(self):
            """Walk the layers and gather cheap metadata + payload SAMPLE (no heavy math)."""
            p = self.packet
            total_size = self._pkt_len_fast() or 0

            # --- Layer 2 ---
            try:
                if Ether is not None and isinstance(getattr(p, "payload", None), Ether) or (hasattr(p, "haslayer") and p.haslayer(Ether)):  # best-effort
                    l2 = p[Ether] if hasattr(p, "__getitem__") else None
                    if l2 is not None:
                        self.layers.append("Ether")
                        self.l2_info = {
                            "src": getattr(l2, "src", None),
                            "dst": getattr(l2, "dst", None),
                            "type": hex(getattr(l2, "type", 0)) if hasattr(l2, "type") else None
                        }
            except Exception:
                pass

            # --- Layer 3 ---
            l3 = None
            try:
                l3 = (p.getlayer(IP) if hasattr(p, "getlayer") else None) or (p.getlayer(IPv6) if hasattr(p, "getlayer") else None)
            except Exception:
                l3 = None

            if l3:
                l3_name = getattr(l3, "name", "IP")
                self.layers.append(l3_name)
                try:
                    if isinstance(l3, IP):
                        self.l3_info = {
                            "src": getattr(l3, "src", "?"),
                            "dst": getattr(l3, "dst", "?"),
                            "ver": 4,
                            "len": getattr(l3, "len", None),
                            "hdr_len": (getattr(l3, "ihl", 5) or 5) * 4,
                            "ttl": getattr(l3, "ttl", None),
                            "proto": getattr(l3, "proto", None),
                            "dscp_ecn": getattr(l3, "tos", None),
                            "id": getattr(l3, "id", None),
                            "frag_off": getattr(l3, "frag", None),
                        }
                        # Fragment hint
                        try:
                            flags = getattr(l3, "flags", None)
                            mf = int(getattr(flags, "MF", 0)) if flags is not None else 0
                            frag = int(getattr(l3, "frag", 0) or 0)
                            if mf or frag:
                                self.anomalies.append("IPv4 fragment")
                        except Exception:
                            pass
                    else:  # IPv6
                        self.l3_info = {
                            "src": getattr(l3, "src", "?"),
                            "dst": getattr(l3, "dst", "?"),
                            "ver": 6,
                            "len": getattr(l3, "plen", None),
                            "hdr_len": 40,
                            "ttl": getattr(l3, "hlim", None),
                            "proto": getattr(l3, "nh", None),
                            "flow": getattr(l3, "fl", None),
                        }
                except Exception:
                    pass

            # --- Layer 4 ---
            l4 = None
            try:
                if hasattr(p, "getlayer"):
                    l4 = p.getlayer(TCP) or p.getlayer(UDP) or p.getlayer(ICMP) or p.getlayer(ICMPv6)
            except Exception:
                l4 = None

            if l4:
                l4_name = getattr(l4, "name", "L4")
                self.layers.append(l4_name)
                self.l4_info["type"] = l4_name
                if hasattr(l4, 'sport'):
                    self.l4_info.update({"sport": getattr(l4, "sport", "?"), "dport": getattr(l4, "dport", "?")})
                try:
                    if isinstance(l4, TCP):
                        # TCP options snapshot (cheap)
                        opts = getattr(l4, "options", []) or []
                        mss = wscale = None
                        sack = False
                        for name, val in opts:
                            n = (name or "").lower()
                            if n == "mss":
                                try: mss = int(val)
                                except Exception: pass
                            elif n == "wscale":
                                try: wscale = int(val)
                                except Exception: pass
                            elif n == "sackok":
                                sack = True
                        self.l4_info.update({
                            "flags": l4.flags.flagrepr() if hasattr(l4.flags, "flagrepr") else str(getattr(l4, "flags", "")),
                            "seq": getattr(l4, "seq", None),
                            "ack": getattr(l4, "ack", None),
                            "win": getattr(l4, "window", None),
                            "mss": mss, "wscale": wscale, "sack": sack
                        })
                    elif isinstance(l4, UDP):
                        self.l4_info["len"] = getattr(l4, "len", None)
                        if l3 and isinstance(l3, IP):
                            try:
                                flags = getattr(l3, "flags", None)
                                if flags and int(getattr(flags, "MF", 0)) == 1:
                                    self.anomalies.append("Fragmented UDP")
                            except Exception:
                                pass
                    elif isinstance(l4, ICMP):
                        self.l4_info.update({"icmp_type": getattr(l4, "type", None), "icmp_code": getattr(l4, "code", None)})
                    else:  # ICMPv6
                        self.l4_info.update({"icmpv6_type": getattr(l4, "type", None), "icmpv6_code": getattr(l4, "code", None)})
                except Exception:
                    pass

            # --- Payload (capture sample only; no hashing/entropy yet) ---
            payload_bytes = b""
            try:
                if Raw is not None and hasattr(p, "haslayer") and p.haslayer(Raw):
                    self.layers.append("Raw")
                    payload_bytes = bytes(getattr(p[Raw], "load", b"") or b"")
                else:
                    pl = getattr(l4, "payload", None)
                    if pl and not isinstance(pl, NoPayload):
                        try:
                            payload_bytes = bytes(pl)
                            self.layers.append(getattr(pl, "name", "Payload"))
                        except Exception:
                            payload_bytes = b""
            except Exception:
                payload_bytes = b""

            self.payload_len = len(payload_bytes)
            # Keep only a bounded sample for any heavy computation later
            sample_cap = max(self.sha1_cap, 256)
            self.payload_sample = payload_bytes[:sample_cap]

            # Tiny L7 hint (absolutely minimal; does NOT parse)
            l7 = self._guess_l7(payload_bytes, self.l4_info)

            self.payload_info = {
                "size": self.payload_len,
                "overhead_ratio": (round((total_size - self.payload_len) / total_size, 2) if total_size else 0.0),
                "l7_hint": l7,
                # lazily filled later:
                "entropy": None,
                "sha1_8": None,
            }

        def _guess_l7(self, b: bytes, l4_info: dict) -> str:
            try:
                sport = int(l4_info.get("sport", 0) or 0)
                dport = int(l4_info.get("dport", 0) or 0)
            except Exception:
                sport = dport = 0
            on_443 = (sport == 443 or dport == 443)
            if not b:
                return "none"
            # QUIC long header bit or short header heuristic (UDP path would be outside, but hint anyway)
            if on_443 and len(b) >= 1:
                first = b[0]
                if first & 0x80:
                    return "quic-long-hdr"
            # TLS record header (very cheap check)
            if len(b) >= 5:
                ct, ver = b[0], (b[1] << 8) | b[2]
                if ct in (0x14, 0x15, 0x16, 0x17) and ver in (0x0301, 0x0302, 0x0303, 0x0304):
                    return {0x14: "tls-ccs", 0x15: "tls-alert", 0x16: "tls-handshake", 0x17: "tls-appdata"}[ct]
            # SSLv2 (2- or 3-byte header; we only label as hint)
            if len(b) >= 3 and (b[0] & 0x80):
                return "sslv2-like"
            # High entropy suggests encrypted/compressed
            if len(b) >= 64:
                counts = [0]*256
                for x in b[:512]:
                    counts[x] += 1
                n = sum(counts)
                ent = 0.0
                if n:
                    inv = 1.0/n
                    for c in counts:
                        if c:
                            p = c*inv
                            ent -= p*math.log2(p)
                if ent > 7.2:
                    return "likely-encrypted"
            # Else maybe ASCII-ish?
            asciiish = sum(1 for x in b[:128] if 9 <= x <= 13 or 32 <= x <= 126)
            if asciiish >= 0.9*min(128, len(b)):
                return "cleartext-ish"
            return "unknown"

        def finalize_payload_metrics(self):
            """Compute entropy/sha1 on the SAMPLE only (cheap) — call only if we will log."""
            if self.payload_info.get("entropy") is not None:
                return
            try:
                ent_sample = self.payload_sample[: self.entropy_cap]
                sh_sample  = self.payload_sample[: self.sha1_cap]
                ent = self._byte_entropy_sample(ent_sample)
                sha1_8 = hashlib.sha1(sh_sample).hexdigest()[:8] if sh_sample else "n/a"
                self.payload_info["entropy"] = round(ent, 2)
                self.payload_info["sha1_8"] = sha1_8
            except Exception:
                self.payload_info["entropy"] = 0.0
                self.payload_info["sha1_8"] = "n/a"

        def finalize(self):
            """Stop timer."""
            self.end_ts = time.perf_counter()
            self.duration_ms = (self.end_ts - self.start_ts) * 1000.0

        def to_log_string(self) -> str:
            timing_part = f"timing={self.duration_ms:.3f}ms"
            summary_part = f"{self.l3_info.get('src', '?')}:{self.l4_info.get('sport', '?')} → " \
                           f"{self.l3_info.get('dst', '?')}:{self.l4_info.get('dport', '?')}"
            layers_part = f"layers=[{'>'.join(self.layers)}]"
            sizes_part = f"size={self.payload_info.get('size',0)+ (self.l3_info.get('hdr_len',0) or 0)}B " \
                         f"(hdr_ovh={self.payload_info.get('overhead_ratio', 0)*100:.0f}%)"

            # L4 compact
            l4_str = "n/a"
            if "flags" in self.l4_info:  # TCP
                l4_str = f"TCP flags={self.l4_info['flags']} win={self.l4_info.get('win','-')} " \
                         f"mss={self.l4_info.get('mss','-')} ws={self.l4_info.get('wscale','-')} sack={self.l4_info.get('sack',False)}"
            elif "len" in self.l4_info:  # UDP
                l4_str = f"UDP len={self.l4_info['len']}"
            elif "icmp_type" in self.l4_info:
                l4_str = f"ICMP type={self.l4_info['icmp_type']}/{self.l4_info.get('icmp_code','-')}"
            elif "icmpv6_type" in self.l4_info:
                l4_str = f"ICMPv6 type={self.l4_info['icmpv6_type']}/{self.l4_info.get('icmpv6_code','-')}"

            payload_part = f"payload={self.payload_len}B ent={self.payload_info.get('entropy',0):.2f} " \
                           f"sha1_8={self.payload_info.get('sha1_8','n/a')} l7={self.payload_info.get('l7_hint','-')}"

            # L3 extras (optional)
            l3_extra = []
            if self.l3_info.get("ver") == 4:
                if self.l3_info.get("dscp_ecn") is not None:
                    tos = int(self.l3_info["dscp_ecn"])
                    l3_extra.append(f"tos=0x{tos:02x}")
                if self.l3_info.get("id") is not None:
                    l3_extra.append(f"id={self.l3_info['id']}")
                if self.l3_info.get("frag_off"):
                    l3_extra.append(f"frag={self.l3_info['frag_off']}")
            elif self.l3_info.get("ver") == 6:
                if self.l3_info.get("flow") is not None:
                    l3_extra.append(f"flow=0x{int(self.l3_info['flow']):05x}")
            l3_part = f" | L3{{{', '.join(l3_extra)}}}" if l3_extra else ""

            anomaly_part = f" | ⚠️ Anomalies=[{', '.join(self.anomalies)}]" if self.anomalies else ""

            return (
                f"[Transport][🔬 Inspect] if={self.iface} {summary_part} | {timing_part} | "
                f"{layers_part} | {sizes_part} | {l4_str} | {payload_part}{l3_part}{anomaly_part}"
            )

    # -------- Manager --------
    def __init__(self, router_logger,
                 *,
                 log_rps: float = None,
                 log_burst: int = None,
                 flow_cooldown_s: float = None):
        self.log = router_logger
        self._tb = self._TokenBucket(
            capacity=int(log_burst or self.LOG_BURST),
            refill_rate_per_s=float(log_rps or self.LOG_RPS),
        )
        self._cooldown_until: dict[tuple, float] = {}
        self._last_gc = time.time()
        self.log.log_message("[Transport][🔬 Inspect] Manager ready.")

        # expose caps to bucket via attributes (fix self-assignment bug)
        self._sha1_cap = int(self.SHA1_SAMPLE_MAX)
        self._entropy_cap = int(self.ENTROPY_SAMPLE_MAX)
        self._flow_cool = float(flow_cooldown_s or self.FLOW_COOLDOWN_S)

    def handle(self, packet: "Packet", src_ip: str, dst_ip: str, sport: int, dport: int, inbound_iface: str) -> bool:
        try:
            bucket = self.InspectBucket(packet, inbound_iface,
                                        entropy_cap=self._entropy_cap,
                                        sha1_cap=self._sha1_cap)
            bucket.parse()

            # Decide importance BEFORE heavy metrics
            importance = self._importance(bucket)
            key = self._flow_key(src_ip, sport, dst_ip, dport, bucket.iface)

            should = self._should_log(key, importance)
            # Only compute heavy metrics if we will log
            if should:
                bucket.finalize_payload_metrics()
            bucket.finalize()

            if should:
                self._emit(bucket.to_log_string())

            self._maybe_gc()
            return True
        except Exception as e:
            try:
                self._emit(f"[Transport][🔬 Inspect] 💥 Error during inspection of {src_ip}->{dst_ip}: {e}", force=True)
            except Exception:
                pass
            return False

    # -------- Importance heuristic (cheap) --------
    def _importance(self, b: "TransportInspectionManager.InspectBucket") -> str:
        if b.anomalies:
            return "high"
        # TCP control or resets
        flags = b.l4_info.get("flags")
        if flags:
            if 'R' in flags or 'F' in flags:
                return "high"
            if 'S' in flags:
                return "med"
        # Big payloads
        if b.payload_len >= self.BIG_PAYLOAD_BYTES:
            return "med"
        # QUIC/TLS hints get a slight bump (interesting encrypted flows)
        if b.payload_info.get("l7_hint") in ("quic-long-hdr", "tls-handshake", "tls-appdata", "tls-alert", "tls-ccs", "sslv2-like", "likely-encrypted"):
            return "med"
        return "low"

    # -------- Token-bucket + per-flow cooldown --------
    def _should_log(self, fkey: tuple, importance: str) -> bool:
        now = time.time()
        # Per-flow cooldown
        last_ok = self._cooldown_until.get(fkey, 0.0)
        if now < last_ok:
            return False

        # Token cost by importance (favor high)
        cost = 1.0 if importance == "high" else (1.5 if importance == "med" else 3.0)
        if importance == "high":
            allowed = self._tb.allow(cost=1.0)
            if not allowed and (now - self._tb.last) > 0.5:
                allowed = True
        else:
            allowed = self._tb.allow(cost=cost)

        if not allowed:
            return False

        # Set cooldown + small jitter for this flow
        jitter = (random.random() - 0.5) * 2 * self.COOLDOWN_JITTER_S
        self._cooldown_until[fkey] = now + self._flow_cool + jitter
        return True

    def _emit(self, msg: str, *, force: bool = False):
        if force:
            try:
                self.log.log_message(msg)
            except Exception:
                pass
            return
        try:
            self.log.log_message(msg)
        except Exception:
            pass

    # -------- Housekeeping --------
    def _flow_key(self, src, sport, dst, dport, iface) -> tuple[str, ...]:
        """
        Canonicalize a 5-tuple so A:Sa→B:Sb and B:Sb→A:Sa map to the same key.
        Returns a flat tuple of *strings* to satisfy type checkers.
        """

        def _norm_host(h) -> str:
            return "" if h is None else str(h)

        def _norm_port(p) -> str:
            try:
                return str(int(p))
            except Exception:
                return "" if p is None else str(p)

        sa = (_norm_host(src), _norm_port(sport))
        sb = (_norm_host(dst), _norm_port(dport))

        # Lexicographic order without tuple-type complaints
        first, second = (sa, sb) if (sa < sb) else (sb, sa)

        return first + second + (_norm_host(iface),)

    def _maybe_gc(self):
        now = time.time()
        if now - self._last_gc < self.GC_PERIOD_S:
            return
        # trim cooldown map if huge
        n = len(self._cooldown_until)
        if n > self.FLOW_TRACK_MAX:
            # evict the oldest cooldowns
            victims = sorted(self._cooldown_until.items(), key=lambda kv: kv[1])[: n - self.FLOW_TRACK_MAX]
            for k, _ in victims:
                self._cooldown_until.pop(k, None)
        # expire stale cooldowns
        stale = [k for k, until in self._cooldown_until.items() if until < now - (2*self._flow_cool)]
        for k in stale:
            self._cooldown_until.pop(k, None)
        self._last_gc = now

class TransportScraperManager:
    """
    Budgeted, packet-wide scraper (TCP/UDP) for extracting useful, small facts.
    - Fast hot-path, zero blocking work (exporter should be async/queued)
    - Global token bucket + per-flow cooldown to avoid log floods
    - Tiny per-flow reassembly (c2s/s2c) with hard caps
    - Cheap, best-effort extractors for HTTP, TLS (CH SNI/ALPN), DNS, QUIC,
      SSH banners, RDP cookie peek, SSDP/WS-Discovery/NTP, NBNS/NBDS mailslot
    - Emits structured records via an exporter callback (or single-line logs if none)

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
        snapshot_metrics() -> dict

    Integration:
        In TransportManager._handle_tcp_packet / _handle_udp_packet, call:
            self.transport_scraper.handle(packet, src_ip, dst_ip, sport, dport, iface_short)
    """

    # ---------- Tunables ----------
    LOG_RPS: float          = 0.2        # avg records/second globally
    LOG_BURST: int          = 5          # global burst capacity
    FLOW_COOLDOWN_S: float  = 60.0       # min seconds between emits per 5-tuple dir
    FLOW_TTL_S: float       = 15 * 60    # idle flow eviction
    FLOW_SOFT_MAX: int      = 80_000     # soft cap on flows
    GC_PERIOD_S: float      = 30.0

    TCP_REASM_CAP: int      = 8 * 1024   # per-direction reassembly cap
    TCP_HEAD_CAP: int       = 4096       # cap for header scanning per emit
    TLS_REC_LEN_MAX: int    = 18432
    BYTES_PREVIEW: int      = 48         # small ascii/hex preview for logging

    # Fast guesses
    TLS_SERV_PORTS = {443, 8443, 9443, 853, 993, 995, 465, 8883, 10443, 2083, 2087, 2096}
    QUIC_SERV_PORTS = {443, 853, 784, 8530, 8443}
    DNS_PORTS = {53}
    WS_DISC_PORT = 3702
    SSDP_PORT = 1900
    NTP_PORT = 123
    NBNS_PORT = 137
    NBDS_PORT = 138
    KERBEROS_PORT = 88
    ZT_PORT = 9993

    _HTTP_START_RE = re.compile(
        rb"^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PATCH)\s+([^\s]+)\s+HTTP/\d\.\d\r?\n",
        re.I,
    )

    class _TokenBucket:
        __slots__ = ("cap", "rate", "tokens", "last")

        def __init__(self, cap: int, rate: float):
            self.cap = int(max(1, cap))
            self.rate = float(max(0.1, rate))
            self.tokens = float(self.cap)
            self.last = time.time()

        def _refill(self):
            now = time.time()
            dt = now - self.last
            if dt > 0:
                # keep fractional tokens for smoother shaping
                self.tokens = min(self.cap, int(self.tokens + dt * self.rate))
                self.last = now

        def take(self, cost: float = 1.0) -> bool:
            self._refill()
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False

    def __init__(self, router_logger, exporter: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.log = router_logger
        self._tb = self._TokenBucket(self.LOG_BURST, self.LOG_RPS)
        self._cooldown_until: Dict[Tuple[Any, ...], float] = {}
        self._flows: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        self._last_gc = time.time()
        self._exporter = exporter
        self._metrics = {
            "emits": 0,
            "suppressed_tokens": 0,
            "flows": 0,
            "gc_evicted": 0,
            "errors": 0,
            "hits_http": 0,
            "hits_tls": 0,
            "hits_dns": 0,
            "hits_quic": 0,
            "hits_ssh": 0,
            "hits_rdp": 0,
            "hits_other": 0,
        }
        try:
            self.log.log_message("[Transport][🧲 Scraper] Manager ready.")
        except Exception:
            pass

    # ---------- Public ----------
    def handle(
        self,
        packet: "Packet",
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        inbound_iface: str,
    ) -> bool:
        try:
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6) if Packet else None
            if not ip_layer:
                return False

            if packet.haslayer(TCP):
                proto = "tcp"
            elif packet.haslayer(UDP):
                proto = "udp"
            else:
                return False

            key = self._flow_key(src_ip, sport, dst_ip, dport, inbound_iface)
            flow = self._flows.get(key)
            if not flow:
                flow = self._new_flow(src_ip, sport, dst_ip, dport, inbound_iface, proto)
                self._flows[key] = flow
                self._metrics["flows"] = len(self._flows)

            flow["last_seen"] = time.time()
            flow["pkts"] += 1

            if proto == "tcp":
                self._scrape_tcp(packet, flow)
            else:
                self._scrape_udp(packet, flow)

            self._maybe_gc()
            return True
        except Exception:
            self._metrics["errors"] += 1
            return False

    def snapshot_metrics(self) -> dict:
        return dict(self._metrics)

    # ---------- UDP quick scanners ----------
    def _scrape_nbds(self, raw: bytes) -> tuple[str, dict]:
        """
        Very cheap NBDS detector:
          - identifies common mailslot messages (\\MAILSLOT\\BROWSE, \\MAILSLOT\\LANMAN)
          - emits size + short ascii preview
        """
        ms = None
        up = raw.upper()
        if b"\\MAILSLOT\\BROWSE" in up:
            ms = "BROWSE"
        elif b"\\MAILSLOT\\LANMAN" in up:
            ms = "LANMAN"
        preview = None
        try:
            txt = raw[:96].decode("utf-8", errors="ignore")
            preview = txt.replace("\r", " ").replace("\n", " ")[:80]
        except Exception:
            pass
        rec = {
            "size": len(raw),
            "sha8": hashlib.sha256(raw[:64]).hexdigest()[:8],
        }
        if ms:
            rec["mailslot"] = ms
        if preview:
            rec["preview"] = preview
        return ("nbds", rec)

    # ---------- TCP ----------
    def _scrape_tcp(self, pkt: "Packet", f: Dict[str, Any]):
        tcp = pkt[TCP]
        flags = tcp.sprintf("%TCP.flags%") if hasattr(tcp, "sprintf") else ""
        payload = self._get_payload(pkt)
        f["last_flags"] = flags
        f["bytes"] += len(payload)

        # Determine direction before buffering
        direction = self._dir_from_tcp(f, tcp)

        # Append payload to the appropriate reassembly buffer (capped)
        if payload:
            self._append_buf(f, direction, payload)

        # NEW: header-only signal when no payload but interesting control flags
        if not payload and flags:
            if any(ch in flags for ch in ("S", "F", "R", "P")):
                rec = self._base_rec(f, direction, kind="tcp_hdr")
                rec.update({"flags": flags})
                self._maybe_emit(f, direction, "tcp_hdr", rec, cost=0.25)

        # Tiny extractors with small budgets
        emitted = False
        if payload:
            # HTTP
            if self._looks_http(f, direction):
                rec = self._scrape_http(f, direction)
                if rec:
                    emitted |= self._maybe_emit(f, direction, "http", rec)
                    self._metrics["hits_http"] += 1
            # TLS (ClientHello)
            if not emitted and self._likely_tls(f, direction):
                rec = self._scrape_tls_clienthello(f, direction)
                if rec:
                    emitted |= self._maybe_emit(f, direction, "tls", rec)
                    self._metrics["hits_tls"] += 1
            # SSH banner
            if not emitted and self._looks_ssh_banner(f, direction):
                rec = self._scrape_ssh_banner(f, direction)
                if rec:
                    emitted |= self._maybe_emit(f, direction, "ssh", rec)
                    self._metrics["hits_ssh"] += 1
            # RDP cookie
            if not emitted and self._looks_rdp(f, direction):
                rec = self._scrape_rdp_cookie(f, direction)
                if rec:
                    emitted |= self._maybe_emit(f, direction, "rdp", rec)
                    self._metrics["hits_rdp"] += 1

        if not emitted and flags and ("R" in flags or "F" in flags):
            rec = self._base_rec(f, direction, kind="tcp_close")
            rec.update({"flags": flags, "bytes": f["bytes"], "pkts": f["pkts"]})
            self._maybe_emit(f, direction, "tcp_close", rec, cost=0.5)

    # ---------- UDP ----------
    def _scrape_udp(self, pkt: "Packet", f: Dict[str, Any]):
        udp = pkt[UDP]
        sport = int(udp.sport)
        dport = int(udp.dport)
        payload = self._get_payload(pkt)
        f["bytes"] += len(payload)

        # Direction heuristic: known service port wins; else lower port is server-ish
        if self._is_service_port(dport) and not self._is_service_port(sport):
            direction = "c2s"
        elif self._is_service_port(sport) and not self._is_service_port(dport):
            direction = "s2c"
        else:
            direction = "c2s" if sport <= dport else "s2c"

        # DNS
        if sport in self.DNS_PORTS or dport in self.DNS_PORTS:
            rec = self._scrape_dns(pkt, f, direction)
            if rec:
                self._metrics["hits_dns"] += 1
                self._maybe_emit(f, direction, "dns", rec)
            return

        # QUIC (very light)
        if sport in self.QUIC_SERV_PORTS or dport in self.QUIC_SERV_PORTS:
            rec = self._scrape_quic(payload, f, direction)
            if rec:
                self._metrics["hits_quic"] += 1
                self._maybe_emit(f, direction, "quic", rec)
            return

        # WS-Discovery
        if sport == self.WS_DISC_PORT or dport == self.WS_DISC_PORT:
            if payload:
                self._maybe_emit(
                    f,
                    direction,
                    "ws-discovery",
                    {**self._base_rec(f, direction, kind="wsd"), "size": len(payload)},
                    cost=0.5,
                )
            return

        # SSDP
        if sport == self.SSDP_PORT or dport == self.SSDP_PORT:
            host, st = self._peek_ssdp(payload)
            self._maybe_emit(
                f,
                direction,
                "ssdp",
                {**self._base_rec(f, direction, kind="ssdp"), "host": host or "-", "st": st or "-"},
                cost=0.5,
            )
            return

        # NTP
        if sport == self.NTP_PORT or dport == self.NTP_PORT:
            vn, mode, stratum = self._peek_ntp(payload)
            self._maybe_emit(
                f,
                direction,
                "ntp",
                {**self._base_rec(f, direction, kind="ntp"), "ver": vn, "mode": mode, "stratum": stratum},
                cost=0.5,
            )
            return

        # NBNS
        if sport == self.NBNS_PORT or dport == self.NBNS_PORT:
            self._maybe_emit(
                f,
                direction,
                "nbns",
                {**self._base_rec(f, direction, kind="nbns"), "size": len(payload) if payload else 0},
                cost=0.5,
            )
            return

        # Kerberos
        if sport == self.KERBEROS_PORT or dport == self.KERBEROS_PORT:
            self._maybe_emit(
                f,
                direction,
                "kerberos",
                {**self._base_rec(f, direction, kind="krb"), "size": len(payload) if payload else 0},
                cost=0.5,
            )
            return

        # ZeroTier/overlay
        if sport == self.ZT_PORT or dport == self.ZT_PORT:
            self._maybe_emit(
                f,
                direction,
                "overlay",
                {**self._base_rec(f, direction, kind="overlay"), "size": len(payload) if payload else 0},
                cost=0.5,
            )
            return

        # NBDS mailslot peeks
        if sport == self.NBDS_PORT or dport == self.NBDS_PORT:
            topic, info = self._scrape_nbds(payload)
            self._maybe_emit(f, direction, topic, {**self._base_rec(f, direction, kind=topic), **info}, cost=0.5)
            return

        # Fallback small emit for unknown UDP
        if payload:
            self._maybe_emit(
                f,
                direction,
                "udp",
                {
                    **self._base_rec(f, direction, kind="udp"),
                    "size": len(payload),
                    "sha8": hashlib.sha256(payload[:64]).hexdigest()[:8],
                    "preview": self._preview(payload),
                },
                cost=0.5,
            )
        else:
            self._metrics["hits_other"] += 1

    # ---------- Extractors (cheap) ----------
    def _scrape_http(self, f: Dict[str, Any], direction: str) -> Optional[Dict[str, Any]]:
        buf = f["c2s_buf"] if direction == "c2s" else f["s2c_buf"]
        head = bytes(buf[: self.TCP_HEAD_CAP])
        # headers end: CRLFCRLF or LFLF
        h_end = head.find(b"\r\n\r\n")
        delim = 4
        if h_end < 0:
            h_end = head.find(b"\n\n")
            delim = 2
        if h_end < 0:
            return None
        hdrs = head[:h_end]
        lines = hdrs.split(b"\r\n")
        if len(lines) <= 0:
            lines = hdrs.split(b"\n")
        start = (lines[0] if lines else b"").decode("utf-8", "ignore")

        def get(hname: str) -> Optional[str]:
            hname_b = hname.lower().encode()
            for ln in lines[1:]:
                p = ln.split(b":", 1)
                if len(p) == 2 and p[0].strip().lower() == hname_b:
                    return p[1].strip().decode("utf-8", "ignore")
            return None

        if direction == "c2s":  # request
            m = self._HTTP_START_RE.match(head)
            if not m:
                return None
            method = m.group(1).decode("ascii", "ignore")
            path = m.group(2).decode("utf-8", "ignore")
            host = get("host")
            ua = get("user-agent")
            return {
                **self._base_rec(f, direction, kind="http_req"),
                "method": method,
                "host": host or "-",
                "path": path,
                "ua": (ua[:64] if ua else None),
            }
        else:  # response
            if not start.startswith("HTTP/"):
                return None
            parts = start.split()
            status = parts[1] if len(parts) > 1 else "?"
            ctype = get("content-type")
            return {
                **self._base_rec(f, direction, kind="http_rsp"),
                "status": status,
                "ctype": (ctype[:64] if ctype else None),
            }

    def _scrape_tls_clienthello(self, f: Dict[str, Any], direction: str) -> Optional[Dict[str, Any]]:
        # Only meaningful when the buffer is going toward a known TLS service port
        a, b = f["a"], f["b"]
        if not (
            (direction == "c2s" and b[1] in self.TLS_SERV_PORTS)
            or (direction == "s2c" and a[1] in self.TLS_SERV_PORTS)
        ):
            return None

        buf = f["c2s_buf"] if direction == "c2s" else f["s2c_buf"]
        mv = memoryview(buf)
        if len(mv) < 6 or mv[0] != 0x16:
            return None
        # TLS record header
        ver = (mv[1] << 8) | mv[2]
        if ver not in (0x0301, 0x0302, 0x0303, 0x0304):
            return None
        rlen = (mv[3] << 8) | mv[4]
        if rlen <= 0 or rlen > self.TLS_REC_LEN_MAX or len(mv) < 5 + rlen:
            return None
        # Handshake type
        if mv[5] != 0x01:  # ClientHello
            return None
        p = 5 + 1 + 3  # type + len
        if len(mv) < p + 2:
            return None
        # client_version
        p += 2
        # random
        p += 32
        if len(mv) < p + 1:
            return None
        # session id
        sid_len = mv[p]
        p += 1 + sid_len
        if len(mv) < p + 2:
            return None
        # cipher suites
        cs_len = (mv[p] << 8) | mv[p + 1]
        p += 2 + cs_len
        if len(mv) < p + 1:
            return None
        # compression
        comp_len = mv[p]
        p += 1 + comp_len
        if len(mv) < p + 2:
            return None
        # extensions
        ext_total = (mv[p] << 8) | mv[p + 1]
        p += 2
        end_ext = min(len(mv), p + ext_total)

        sni = None
        alpn: list[str] = []
        while p + 4 <= end_ext:
            et = (mv[p] << 8) | mv[p + 1]
            el = (mv[p + 2] << 8) | mv[p + 3]
            p += 4
            if p + el > end_ext:
                break
            ed = mv[p : p + el]
            if et == 0x0000 and el >= 5:  # server_name (SNI)
                if len(ed) >= 2:
                    snl = (ed[0] << 8) | ed[1]
                    q = 2
                    limit = min(2 + snl, len(ed))
                    while q + 3 <= limit:
                        ntyp = ed[q]
                        nlen = (ed[q + 1] << 8) | ed[q + 2]
                        q += 3
                        if q + nlen > limit:
                            break
                        if ntyp == 0:
                            try:
                                sni = bytes(ed[q : q + nlen]).decode("idna", "ignore")
                            except Exception:
                                sni = None
                            break
                        q += nlen
            elif et == 0x0010 and el >= 2:  # ALPN
                if len(ed) >= 2:
                    ll = (ed[0] << 8) | ed[1]
                    q = 2
                    limit = min(2 + ll, len(ed))
                    while q < limit:
                        n = ed[q]
                        q += 1
                        if q + n > limit:
                            break
                        try:
                            alpn.append(bytes(ed[q : q + n]).decode("ascii", "ignore"))
                        except Exception:
                            pass
                        q += n
            p += el

        if not sni and not alpn:
            return None
        return {**self._base_rec(f, direction, kind="tls_ch"), "sni": sni or "-", "alpn": ",".join(alpn) if alpn else "-"}

    # quick banners
    def _scrape_ssh_banner(self, f: Dict[str, Any], direction: str) -> Optional[Dict[str, Any]]:
        buf = f["s2c_buf"] if direction == "s2c" else f["c2s_buf"]
        if b"SSH-" in buf[:64]:
            line = buf[:128].split(b"\n", 1)[0].decode("utf-8", "ignore").strip()
            return {**self._base_rec(f, direction, kind="ssh_banner"), "banner": line[:80]}
        return None

    def _scrape_rdp_cookie(self, f: Dict[str, Any], direction: str) -> Optional[Dict[str, Any]]:
        # Very rough: look for "Cookie: mstshash=" in early bytes (old RDP, TCP/3389)
        a, b = f["a"], f["b"]
        if 3389 not in (a[1], b[1]):
            return None
        buf = f["c2s_buf"][: self.TCP_HEAD_CAP]
        k = b"Cookie: mstshash="
        i = buf.find(k)
        if i >= 0:
            val = buf[i + len(k) : i + len(k) + 48].split(b"\r\n", 1)[0].decode("utf-8", "ignore")
            return {**self._base_rec(f, direction, kind="rdp_cookie"), "mstshash": val}
        return None

    # DNS via scapy if available, else quick parse of QNAME
    def _scrape_dns(self, pkt: "Packet", f: Dict[str, Any], direction: str) -> Optional[Dict[str, Any]]:
        try:
            if DNS is not None and pkt.haslayer(DNS):
                dns = pkt[DNS]
                q = dns.qd.qname.decode("utf-8", "ignore") if getattr(dns, "qd", None) and getattr(dns.qd, "qname", None) else None
                an = None
                if getattr(dns, "an", None) and getattr(dns.an, "rdata", None):
                    try:
                        an = str(dns.an.rdata)
                    except Exception:
                        an = None
                return {
                    **self._base_rec(f, direction, kind=("dns_rsp" if getattr(dns, "qr", 0) == 1 else "dns_req")),
                    "qname": (q[:-1] if q and q.endswith(".") else q) or "-",
                    "answer": an,
                }
        except Exception:
            pass
        # fallback: parse first qname from raw
        raw = self._get_payload(pkt)
        qname = self._dns_qname_from_raw(raw)
        if qname:
            return {**self._base_rec(f, direction, kind="dns_req"), "qname": qname}
        return None

    def _scrape_quic(self, payload: bytes, f: Dict[str, Any], direction: str) -> Optional[Dict[str, Any]]:
        if not payload or len(payload) < 6:
            return None
        b0 = payload[0]
        if b0 & 0x80:  # long header
            version = struct.unpack_from("!I", payload, 1)[0]
            dcid_len = payload[5]
            return {**self._base_rec(f, direction, kind="quic_long"), "ver": f"0x{version:08x}", "dcid_len": int(dcid_len)}
        else:  # short header
            return {**self._base_rec(f, direction, kind="quic_short"), "b0": f"0x{b0:02x}", "size": len(payload)}

    # ---------- Emits ----------
    def _maybe_emit(self, f: Dict[str, Any], direction: str, topic: str, rec: Dict[str, Any], *, cost: float = 1.0) -> bool:
        now = time.time()
        fkey = f["key"] + (direction,)
        last = self._cooldown_until.get(fkey, 0.0)
        if now < last:
            return False
        if not self._tb.take(cost=cost):
            self._metrics["suppressed_tokens"] += 1
            return False
        self._cooldown_until[fkey] = now + self.FLOW_COOLDOWN_S

        self._emit_record(topic, rec)
        self._metrics["emits"] += 1
        return True

    def _emit_record(self, topic: str, rec: Dict[str, Any]):
        rec_out = dict(rec)
        rec_out["topic"] = topic
        if callable(self._exporter):
            try:
                self._exporter(rec_out)  # should be non-blocking / queued by caller
                return
            except Exception:
                pass
        # fallback: concise one-liner
        a, b = rec_out.get("a"), rec_out.get("b")
        flow = f"{a[0]}:{a[1]} ⇄ {b[0]}:{b[1]}"
        preview = rec_out.get("preview")
        extra = {k: v for k, v in rec_out.items() if k not in {"a", "b", "dir", "kind", "topic", "preview"}}
        kv = " ".join(f"{k}={v}" for k, v in extra.items() if v is not None)
        line = f"[Transport][🧲 Scraper][{rec_out.get('kind','-')}] {flow} [{rec_out.get('dir','?')}] {kv}"
        if preview:
            line += f" preview='{preview}'"
        try:
            self.log.log_message(line)
        except Exception:
            pass

    # ---------- Flow / utils ----------
    def _new_flow(self, src, sport, dst, dport, iface, proto):
        a = (str(src), int(sport))
        b = (str(dst), int(dport))
        first, second = (a, b) if a <= b else (b, a)
        return {
            "key": (first + second + (str(iface),)),
            "a": first,
            "b": second,
            "iface": str(iface).split("_")[-1],
            "proto": proto,
            "created": time.time(),
            "last_seen": time.time(),
            "pkts": 0,
            "bytes": 0,
            "c2s_buf": bytearray(),
            "s2c_buf": bytearray(),
            "last_flags": "",
        }

    def _flow_key(self, src, sport, dst, dport, iface):
        a = (str(src), int(sport))
        b = (str(dst), int(dport))
        first, second = (a, b) if a <= b else (b, a)
        return first + second + (str(iface),)

    def _dir_from_tcp(self, f: Dict[str, Any], tcp) -> str:
        sa, da = int(tcp.sport), int(tcp.dport)
        # If one side is a “service” port, classify direction around it
        if self._is_service_port(da) and not self._is_service_port(sa):
            return "c2s"
        if self._is_service_port(sa) and not self._is_service_port(da):
            return "s2c"
        # fall back: lower port ~ server
        if sa < da:
            return "c2s"
        if da < sa:
            return "s2c"
        # tie-breaker: SYN without ACK is c2s
        try:
            flags = tcp.sprintf("%TCP.flags%")
            return "c2s" if ("S" in flags and "A" not in flags) else "s2c"
        except Exception:
            return "c2s"

    def _append_buf(self, f: Dict[str, Any], direction: str, data: bytes):
        buf = f["c2s_buf"] if direction == "c2s" else f["s2c_buf"]
        cap = self.TCP_REASM_CAP
        if not data:
            return
        # append and trim from the left if exceeding cap
        buf += data
        if len(buf) > cap:
            # keep last CAP bytes
            del buf[: len(buf) - cap]
        if direction == "c2s":
            f["c2s_buf"] = buf
        else:
            f["s2c_buf"] = buf

    def _is_service_port(self, port: int) -> bool:
        return port in self.TLS_SERV_PORTS or port in self.DNS_PORTS or port in self.QUIC_SERV_PORTS or port in {80, 22, 21, 25, 110, 143, 3389}

    def _get_payload(self, pkt) -> bytes:
        try:
            if Raw is not None and pkt.haslayer(Raw) and getattr(pkt[Raw], "load", None):
                return bytes(pkt[Raw].load)
            # fall back to bytes(payload)
            if pkt.haslayer(TCP):
                return bytes(getattr(pkt[TCP], "payload", b"") or b"")
            if pkt.haslayer(UDP):
                return bytes(getattr(pkt[UDP], "payload", b"") or b"")
        except Exception:
            pass
        return b""

    def _looks_http(self, f: Dict[str, Any], direction: str) -> bool:
        buf = f["c2s_buf"] if direction == "c2s" else f["s2c_buf"]
        if not buf:
            return False
        head = bytes(buf[: min(len(buf), 16)])
        return head.startswith(b"HTTP/") or bool(self._HTTP_START_RE.match(head + b"\r\n"))

    def _likely_tls(self, f: Dict[str, Any], direction: str) -> bool:
        buf = f["c2s_buf"] if direction == "c2s" else f["s2c_buf"]
        if len(buf) < 6:
            return False
        if buf[0] != 0x16:
            return False
        ver = (buf[1] << 8) | buf[2]
        return ver in (0x0301, 0x0302, 0x0303, 0x0304)

    def _looks_ssh_banner(self, f: Dict[str, Any], direction: str) -> bool:
        buf = f["s2c_buf"] if direction == "s2c" else f["c2s_buf"]
        return b"SSH-" in buf[:64]

    def _looks_rdp(self, f: Dict[str, Any], direction: str) -> bool:
        a, b = f["a"], f["b"]
        return 3389 in (a[1], b[1])

    def _dns_qname_from_raw(self, raw: bytes) -> Optional[str]:
        try:
            if len(raw) < 12:
                return None
            qdcount = (raw[4] << 8) | raw[5]
            if qdcount < 1:
                return None
            i = 12
            labels = []
            for _ in range(10):  # up to 10 labels
                if i >= len(raw):
                    return None
                ln = raw[i]
                i += 1
                if ln == 0:
                    break
                if i + ln > len(raw):
                    return None
                labels.append(raw[i : i + ln].decode("utf-8", "ignore"))
                i += ln
            qname = ".".join(labels)
            return qname or None
        except Exception:
            return None

    def _peek_ssdp(self, raw: bytes) -> tuple[Optional[str], Optional[str]]:
        try:
            head = raw[:512]
            host = st = None
            for line in head.split(b"\r\n"):
                if b":" not in line:
                    continue
                k, v = line.split(b":", 1)
                k = k.strip().lower()
                v = v.strip()
                if k == b"host":
                    host = v.decode("utf-8", "ignore")
                if k in (b"st", b"nt"):
                    st = v.decode("utf-8", "ignore")
            return host, st
        except Exception:
            return None, None

    def _peek_ntp(self, raw: bytes) -> tuple[int, str, int]:
        try:
            if len(raw) < 48:
                return 0, "?", 0
            b0 = raw[0]
            vn = (b0 >> 3) & 0x07
            mode_num = b0 & 0x07
            mode = {1: "sym-act", 2: "sym-pass", 3: "client", 4: "server", 5: "bcast"}.get(mode_num, "?")
            stratum = raw[1]
            return vn, mode, stratum
        except Exception:
            return 0, "?", 0

    # ---------- Housekeeping ----------
    def _maybe_gc(self):
        now = time.time()
        if now - self._last_gc < self.GC_PERIOD_S:
            return
        evicted = 0
        # evict idle flows
        dead = [k for k, f in list(self._flows.items()) if now - f.get("last_seen", now) > self.FLOW_TTL_S]
        for k in dead:
            if self._flows.pop(k, None) is not None:
                evicted += 1
        # soft cap trim (oldest first)
        if len(self._flows) > self.FLOW_SOFT_MAX:
            excess = len(self._flows) - self.FLOW_SOFT_MAX
            victims = sorted(self._flows.items(), key=lambda kv: kv[1].get("last_seen", 0.0))[:excess]
            for k, _ in victims:
                if self._flows.pop(k, None) is not None:
                    evicted += 1
        # trim cooldown map (expired entries)
        stale = [k for k, until in list(self._cooldown_until.items()) if until < now - (2 * self.FLOW_COOLDOWN_S)]
        for k in stale:
            self._cooldown_until.pop(k, None)
        self._metrics["gc_evicted"] += evicted
        self._metrics["flows"] = len(self._flows)
        self._last_gc = now

    def _base_rec(self, f: Dict[str, Any], direction: str, *, kind: str = "generic") -> Dict[str, Any]:
        """
        Build a small base record compatible with the rest of TransportScraperManager.
        direction: 'c2s' or 's2c'
        """
        a = f.get("a", ("?", 0))
        b = f.get("b", ("?", 0))
        src = a if direction == "c2s" else b
        dst = b if direction == "c2s" else a
        return {
            "ts": time.time(),
            "kind": kind,
            "dir": direction,  # scraper uses 'dir'
            "iface": f.get("iface"),
            "a": a,  # keep endpoints for the pretty flow line
            "b": b,
            "src": str(src[0]),
            "sport": int(src[1]),
            "dst": str(dst[0]),
            "dport": int(dst[1]),
            "bytes": f.get("bytes", 0),
            "pkts": f.get("pkts", 0),
        }

    def _preview(self, b: bytes) -> str:
        if not b:
            return ""
        s = b[: self.BYTES_PREVIEW]
        # ascii-ish preview; replace non-printables with '.'
        return "".join(chr(c) if 32 <= c < 127 else "." for c in s)




class TransportHTTPSManager:
    """
    HTTPS/TLS transport handler (callback-safe, single-threaded).

    Public API:
      - handle(packet, inbound_iface) -> bool
      - snapshot_metrics() -> dict
    """

    # ---------- Tunables (balanced for low overhead) ----------
    FLOW_TTL_SEC        = 15 * 60         # flow cache TTL
    FLOW_SOFT_MAX       = 50_000          # soft cap on flows (evict LRU past this)
    RL_INTERVAL_SEC     = 1.0             # rate-limit per-flow log interval
    BYTES_BUDGET        = 384             # cap bytes scanned from payload
    CHELLO_MIN_CAP      = 6               # quick reject if smaller
    RECORD_MAX_LEN      = 18432           # sane TLS record length bound
    PARSE_ON_NON443     = False           # default: do not scan off-443

    def __init__(
        self,
        logger,
        *,
        detect_non443_tls: bool = PARSE_ON_NON443,
        max_bytes_to_peek: int = BYTES_BUDGET,
        logging_enabled: bool = True,
        report_tcp_meta: bool = True,
        report_tls_record: bool = True,
        report_tls_meta: bool = True,
        compute_ja3: bool = False,
        flow_cache_ttl: int = FLOW_TTL_SEC,
        flow_cache_max: int = FLOW_SOFT_MAX,
        log_packet_prefix: bool = True,        # NEW: scapy-like prefix
        detect_quic_udp443: bool = True,        # NEW: QUIC over UDP
    ):
        self.logger = logger
        self.detect_non443_tls = bool(detect_non443_tls)
        self._peek_cap = int(max_bytes_to_peek)
        self.logging_enabled = bool(logging_enabled)
        self.report_tcp_meta = bool(report_tcp_meta)
        self.report_tls_record = bool(report_tls_record)
        self.report_tls_meta = bool(report_tls_meta)
        self.compute_ja3 = bool(compute_ja3)
        self.log_packet_prefix = bool(log_packet_prefix)
        self.detect_quic_udp443 = bool(detect_quic_udp443)

        self.flow_cache_ttl = int(flow_cache_ttl)
        self.flow_cache_max = int(flow_cache_max)

        # flow_key -> {
        #   "first": ts, "last": ts,
        #   "sni": str|None, "alpn": list|None, "ja3": str|None,
        #   "classified": bool,       # seen TLS record signature
        #   "noinspect": bool,        # stop deep parsing (post-CH or AD)
        #   "last_log": ts|0,         # rate limiting
        # }
        self._tls_flows = {}

        self._metrics = {
            "https_seen": 0,
            "tls_non443_seen": 0,
            "client_hello_seen": 0,
            "errors": 0,
            "sni_parsed": 0,
            "sni_cache_hits": 0,
            "flow_cache_evictions": 0,
            "fast_path_hits": 0,
            "noinspect_set": 0,
            "quic_seen": 0,               # NEW
            "sslv2_seen": 0,              # NEW
            "sslv2_handshake_labeled": 0, # NEW
        }
        self._peek_tcp_meta_cached = None  # per-handle cache
        self._safe_log("[Transport][🔒 HTTPS] Manager ready")

    # ---------------------------
    # Public entrypoint
    # ---------------------------
    def handle(self, packet, inbound_iface: str) -> bool:
        """
        Hot-path with budgets & fast-path:
        - QUICK QUIC detection for UDP:443 (so UDP 'Raw' lines make sense)
        - Classify (TLS?) cheaply
        - Parse ClientHello once to learn SNI/ALPN (then stop deep parsing)
        - Always log SNI once learned, rate-limited per flow
        - Mark flow 'noinspect' on first ApplicationData or after CH
        """
        try:
            # ---- QUIC (UDP:443) quick path ----
            if self.detect_quic_udp443 and UDP is not None and packet.haslayer(UDP):
                u = packet[UDP]
                sport = int(getattr(u, "sport", 0) or 0)
                dport = int(getattr(u, "dport", 0) or 0)
                if sport == 443 or dport == 443:
                    raw = self._get_raw_bytes(packet)
                    if raw and self._looks_like_quic(raw):
                        self._metrics["quic_seen"] += 1
                        if self.log_packet_prefix:
                            self._safe_log(self._format_quic_prefix(packet, inbound_iface, raw))
                        return True  # QUIC handled (we don't deep-parse here)

            if not self._pre_checks(packet):
                return False

            src_ip, dst_ip = self._resolve_ips(packet)
            sport, dport = self._resolve_ports(packet)

            on_443 = (sport == 443) or (dport == 443)
            if not on_443:
                if not self.detect_non443_tls:
                    return False

            raw = self._get_raw_bytes(packet)

            # Try TLSv1.x / TLS1.3 style first
            mv = memoryview(raw) if raw else None
            rhead = None
            sslv2 = None

            if raw:
                rhead = self._peek_tls_record_header_mv(mv)
                if not rhead:
                    # Try SSLv2 record (older servers/clients or mis-labeled dissectors)
                    sslv2 = self._peek_sslv2_header(mv)
                    if not sslv2:
                        # Not TLS/SSLv2 — bail if off-443; else we may still prefix-log TCP
                        if not on_443:
                            return False

            now = time.time()
            fkey = self._flow_key(src_ip, sport, dst_ip, dport)
            st = self._tls_flows.get(fkey)
            if st is None:
                st = {
                    "first": now, "last": now, "last_log": 0.0,
                    "sni": None, "alpn": None, "ja3": None,
                    "classified": False, "noinspect": False,
                }
                self._tls_flows[fkey] = st
            else:
                st["last"] = now

            # ----- Prefix (Scapy-like) line -----
            if self.log_packet_prefix:
                if sslv2:
                    self._metrics["sslv2_seen"] += 1
                    self._safe_log(self._format_packet_prefix_ssl2(packet, inbound_iface, sslv2))
                elif rhead:
                    # Optionally peek ClientHello for subtype in prefix as well
                    ch = None
                    if rhead["ct"] == "Handshake":
                        ch = self._peek_client_hello_rich_mv(mv)
                    self._safe_log(self._format_packet_prefix(packet, inbound_iface, rhead, ch))
                else:
                    # header-only TCP on 443 (no payload)
                    self._safe_log(self._format_packet_prefix_header_only(packet, inbound_iface))

            # ----- Flow-oriented logic only for TLSv1.x+ -----
            if not raw:
                # header-only packets: minimal log, mark classified
                if self._should_log_flow(st, now):
                    self._safe_log(f"[Transport][🧵 TCP][🔒 HTTPS] hdr-only "
                                   f"{src_ip}:{sport} → {dst_ip}:{dport} on {self._iface_suffix(inbound_iface)} "
                                   f"SNI={st.get('sni') or '-'}")
                st["classified"] = True
                self._bump_seen(on_443)
                self._clean_if_needed(now)
                return True

            if sslv2 and not rhead:
                # We detected SSLv2; we don't deep-parse beyond labeling.
                if self._should_log_flow(st, now):
                    self._safe_log(self._format_logline_sslv2(src_ip, sport, dst_ip, dport, inbound_iface, st, sslv2))
                self._bump_seen(on_443)  # count under 443 bucket
                self._clean_if_needed(now)
                return True

            # From here, rhead is present => TLSv1.x+
            st["classified"] = True

            # Fast-path after classification & post-CH:
            if st.get("noinspect", False):
                self._metrics["fast_path_hits"] += 1
                if self._should_log_flow(st, now):
                    self._safe_log(self._format_logline(src_ip, sport, dst_ip, dport, inbound_iface, st, rhead))
                self._bump_seen(on_443)
                self._clean_if_needed(now)
                return True

            # If this is ApplicationData, set noinspect immediately
            if rhead["ct"] == "ApplicationData":
                st["noinspect"] = True
                self._metrics["noinspect_set"] += 1
                if self._should_log_flow(st, now):
                    self._safe_log(self._format_logline(src_ip, sport, dst_ip, dport, inbound_iface, st, rhead))
                self._bump_seen(on_443)
                self._clean_if_needed(now)
                return True

            # Only parse CH if we don't have SNI yet and meta reporting is enabled
            ch = None
            if (st.get("sni") is None) and self.report_tls_meta and rhead["ct"] == "Handshake":
                ch = self._peek_client_hello_rich_mv(mv)
                if ch and ch.get("client_hello"):
                    self._metrics["client_hello_seen"] += 1
                    if ch.get("sni"):
                        st["sni"] = ch["sni"]
                        self._metrics["sni_parsed"] += 1
                    if ch.get("alpn"):
                        st["alpn"] = ch["alpn"]
                    if ch.get("ja3"):
                        st["ja3"] = ch["ja3"]
                    # After seeing CH, move to noinspect to avoid extra work later
                    st["noinspect"] = True
                    self._metrics["noinspect_set"] += 1

            # Flow log (rate-limited)
            if self._should_log_flow(st, now):
                self._safe_log(self._format_logline(src_ip, sport, dst_ip, dport, inbound_iface, st, rhead, ch))

            # metrics/cleanup
            self._bump_seen(on_443)
            self._clean_if_needed(now)
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
    # Prefix formatters (Scapy-like)
    # ---------------------------
    def _format_packet_prefix_header_only(self, pkt, inbound_iface: str) -> str:
        # Label with TCP flag type instead of generic "hdr-only"
        try:
            length = getattr(pkt, "wirelen", None) or len(bytes(pkt))
        except Exception:
            length = "?"
        src_ip, dst_ip = self._resolve_ips(pkt)
        sport, dport = self._resolve_ports(pkt)
        tcp_type = self._classify_tcp_flags(pkt)  # <— NEW
        return (f"[Transport][🔒 TLS][{tcp_type}] "
                f"iface={self._iface_suffix(inbound_iface)} "
                f"{src_ip}:{sport} > {dst_ip}:{dport} len={length}")

    def _format_packet_prefix(self, pkt, inbound_iface: str, rhead: dict, ch: dict | None = None) -> str:
        try:
            length = getattr(pkt, "wirelen", None) or len(bytes(pkt))
        except Exception:
            length = "?"
        src_ip, dst_ip = self._resolve_ips(pkt)
        sport, dport = self._resolve_ports(pkt)

        ver = rhead.get("version", "-")
        ver_emoji = "🔒" if ver.startswith("TLS") else ("🧾" if "SSL" in ver else "❓")

        ct = rhead.get("ct", "-")
        ct_map = {
            "Handshake": "🤝 Handshake",
            "ApplicationData": "📦 AppData",
            "Alert": "⚠️ Alert",
            "ChangeCipherSpec": "🔑 CCS",
        }
        ct_display = ct_map.get(ct, ct)

        # If Handshake, show the exact first message (ClientHello / ServerHello / …)
        hs_detail = ""
        try:
            raw = self._get_raw_bytes(pkt)
            if ct == "Handshake" and raw and len(raw) >= 6 and raw[0] == 0x16:
                first_hs = raw[5]  # first handshake msg type in the record
                hs_detail = f": {self._tls_hs_msg_name(first_hs)}"
        except Exception:
            pass

        return (f"[Transport][{ver_emoji} {ver}][{ct_display}{hs_detail}] "
                f"iface={self._iface_suffix(inbound_iface)} "
                f"{src_ip}:{sport} > {dst_ip}:{dport} len={length}")

    def _format_packet_prefix_ssl2(self, pkt, inbound_iface: str, s2: dict) -> str:
        """Scapy-like prefix for SSLv2 records."""
        try:
            length = getattr(pkt, "wirelen", None) or len(bytes(pkt))
        except Exception:
            length = "?"
        src_ip, dst_ip = self._resolve_ips(pkt)
        sport, dport = self._resolve_ports(pkt)

        msg = s2.get("msg_name") or "Handshake"
        return (f"[Transport][🧾 SSLv2][{msg}] "
                f"iface={self._iface_suffix(inbound_iface)} "
                f"{src_ip}:{sport} > {dst_ip}:{dport} len={length}")

    def _format_quic_prefix(self, pkt, inbound_iface: str, raw: bytes) -> str:
        """Minimal QUIC indicator for UDP:443 payloads."""
        try:
            length = getattr(pkt, "wirelen", None) or len(bytes(pkt))
        except Exception:
            length = "?"
        src_ip, dst_ip = self._resolve_ips_udp(pkt)
        sport, dport = self._resolve_ports_udp(pkt)

        # Very rough labeling
        label = "Initial" if (len(raw) >= 1200 and (raw[0] & 0x80)) else ("ShortHdr" if not (raw[0] & 0x80) else "LongHdr")
        return (f"[Transport][⚡ QUIC][{label}] "
                f"iface={self._iface_suffix(inbound_iface)} "
                f"{src_ip}:{sport} > {dst_ip}:{dport} len={length}")

    # ---------------------------
    # Flow log formatters
    # ---------------------------
    def _format_logline(self, src_ip, sport, dst_ip, dport, inbound_iface, st, rhead, ch=None) -> str:
        sni = st.get("sni") or "-"
        # Show whether this is 443 or non-443 and the exact TLS record type
        tls_part = "443" if (sport == 443 or dport == 443) else "non-443 TLS"

        ct = rhead.get("ct") if rhead else None
        exact = None
        if ct == "Handshake":
            try:
                exact = self._tls_hs_msg_name(
                    self._get_raw_bytes_cached[5])  # see caching trick below, or re-read payload
            except Exception:
                pass
        elif ct == "ApplicationData":
            exact = "ApplicationData"
        elif ct == "ChangeCipherSpec":
            exact = "ChangeCipherSpec"
        elif ct == "Alert":
            exact = "Alert"

        type_tag = exact or (self._classify_tcp_flags_cached if hasattr(self, "_classify_tcp_flags_cached") else "TCP")

        parts = [
            f"[Transport][🧵 TCP][🔒 HTTPS] {tls_part} "
            f"{src_ip}:{sport} → {dst_ip}:{dport} on {self._iface_suffix(inbound_iface)} "
            f"type={type_tag} SNI={sni}"
        ]
        # ... (keep your existing tcp meta / tls rec / ch summaries)
        return " | ".join(parts)

    def _format_logline_sslv2(self, src_ip, sport, dst_ip, dport, inbound_iface, st, s2) -> str:
        msg = s2.get("msg_name") or "-"
        parts = [
            f"[Transport][🧵 TCP][🧾 SSLv2] 443 "
            f"{src_ip}:{sport} → {dst_ip}:{dport} on {self._iface_suffix(inbound_iface)} "
            f"msg={msg} len={s2.get('length','?')}"
        ]
        # We keep TCP meta if present
        if self.report_tcp_meta:
            tmeta = self._peek_tcp_meta_cached
            if tmeta:
                parts.append(
                    " tcp{"
                    f"flags={tmeta.get('flags','-')},"
                    f"win={tmeta.get('win','-')},"
                    f"ws={tmeta.get('wscale','-')},"
                    f"mss={tmeta.get('mss','-')},"
                    f"sack={tmeta.get('sack_perm','-')}"
                    "}"
                )
        return " | ".join(parts)

    def _should_log_flow(self, st, now: float) -> bool:
        last = st.get("last_log", 0.0)
        if (now - last) >= self.RL_INTERVAL_SEC:
            st["last_log"] = now
            return True
        return False

    # ---------------------------
    # Flow cache mgmt
    # ---------------------------
    def _flow_key(self, src_ip: str, sport: int, dst_ip: str, dport: int):
        a = (str(src_ip), str(int(sport)))
        b = (str(dst_ip), str(int(dport)))
        first, second = (a, b) if a <= b else (b, a)
        return first + second

    def _clean_if_needed(self, now_ts: float):
        # TTL cleanup
        ttl = self.flow_cache_ttl
        if ttl > 0 and self._metrics["https_seen"] % 2048 == 0:
            stale = [k for k, v in self._tls_flows.items() if now_ts - v.get("last", now_ts) > ttl]
            for k in stale:
                self._tls_flows.pop(k, None)
        # Soft cap cleanup
        if len(self._tls_flows) > self.flow_cache_max:
            excess = len(self._tls_flows) - self.flow_cache_max
            victims = sorted(self._tls_flows.items(), key=lambda kv: kv[1].get("last", 0.0))[:excess]
            for k, _ in victims:
                self._tls_flows.pop(k, None)
            self._metrics["flow_cache_evictions"] += excess

    def _bump_seen(self, on_443: bool):
        if on_443:
            self._metrics["https_seen"] += 1
        else:
            self._metrics["tls_non443_seen"] += 1

    # --- ADD: classify TCP flags (for hdr-only packets) ---
    def _classify_tcp_flags(self, pkt) -> str:
        try:
            t = pkt[TCP]
            flags = t.sprintf("%TCP.flags%")
            # Standard combos first
            if "R" in flags:
                return "RST" if "A" not in flags else "RST-ACK"
            if "S" in flags and "A" in flags:
                return "SYN-ACK"
            if "S" in flags:
                return "SYN"
            if "F" in flags and "A" in flags:
                return "FIN-ACK"
            if "F" in flags:
                return "FIN"
            if "P" in flags and "A" in flags:
                return "PSH-ACK"
            if "P" in flags:
                return "PSH"
            if "A" in flags:
                return "ACK"
            if "U" in flags:
                return "URG"
            return f"TCP({flags})" if flags else "TCP"
        except Exception:
            return "TCP"

    # --- ADD: quick handshake message name (TLSv1.x) ---
    def _tls_hs_msg_name(self, b: int) -> str:
        table = {
            0x01: "ClientHello",
            0x02: "ServerHello",
            0x0b: "Certificate",
            0x0c: "ServerKeyExchange",
            0x0e: "ServerHelloDone",
            0x10: "ClientKeyExchange",
            0x14: "Finished",
            # TLS 1.3 notable:
            0x08: "EncryptedExtensions",
            0x0d: "CertificateRequest",
            0x15: "CertificateVerify",
            0x16: "NewSessionTicket",
            0x1c: "KeyUpdate",
        }
        return table.get(int(b), f"Handshake(0x{int(b):02x})")
    # ---------------------------
    # Hot-path helpers
    # ---------------------------
    def _pre_checks(self, pkt) -> bool:
        if TCP is None:
            return False
        return bool(pkt and (pkt.haslayer(TCP) or pkt.haslayer(UDP)) and (pkt.haslayer(IP) or pkt.haslayer(IPv6)))

    def _resolve_ips(self, pkt):
        if IP is not None and pkt.haslayer(IP):
            ip = pkt[IP]; return getattr(ip, "src", "0.0.0.0"), getattr(ip, "dst", "0.0.0.0")
        if IPv6 is not None and pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]; return getattr(ip6, "src", "::"), getattr(ip6, "dst", "::")
        return "0.0.0.0", "0.0.0.0"

    def _resolve_ips_udp(self, pkt):
        # same as above; split for clarity
        return self._resolve_ips(pkt)

    def _resolve_ports(self, pkt):
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            try: sport = int(getattr(t, "sport", 0) or 0)
            except Exception: sport = 0
            try: dport = int(getattr(t, "dport", 0) or 0)
            except Exception: dport = 0
            # cache a minimal TCP meta snapshot for logging (no rework later)
            self._peek_tcp_meta_cached = self._peek_tcp_meta(pkt) if self.report_tcp_meta else None
            return sport, dport
        return 0, 0

    def _resolve_ports_udp(self, pkt):
        if pkt.haslayer(UDP):
            u = pkt[UDP]
            try: sport = int(getattr(u, "sport", 0) or 0)
            except Exception: sport = 0
            try: dport = int(getattr(u, "dport", 0) or 0)
            except Exception: dport = 0
            return sport, dport
        return 0, 0

    def _get_raw_bytes(self, pkt) -> bytes:
        if Raw is None or not pkt.haslayer(Raw):
            return b""
        try:
            return bytes(pkt[Raw].load) or b""
        except Exception:
            return b""

    # ---------- TLS cheap signature ----------
    def _cheap_tls_signature(self, pkt) -> bool:
        raw = self._get_raw_bytes(pkt)
        if not raw or len(raw) < 2:
            return False
        mv = memoryview(raw)

        # Try TLSv1.x first
        if len(mv) >= 6:
            ct = mv[0]
            ver = (mv[1] << 8) | mv[2]
            if ver in (0x0301, 0x0302, 0x0303, 0x0304) and ct in (0x16, 0x17, 0x14, 0x15):
                # If Handshake, first hs msg should be ClientHello (0x01)
                return (ct != 0x16) or (mv[5] == 0x01)

        # Try SSLv2 header (2- or 3-byte)
        s2 = self._peek_sslv2_header(mv)
        return bool(s2)

    # Record header (memoryview) → dict or None (TLSv1.x+)
    def _peek_tls_record_header_mv(self, mv):
        if not mv or len(mv) < 5:
            return None
        ct = mv[0]
        ver = (mv[1] << 8) | mv[2]
        if ver not in (0x0301, 0x0302, 0x0303, 0x0304):
            return None
        if ct not in (0x16, 0x17, 0x14, 0x15):
            return None
        rlen = (mv[3] << 8) | mv[4]
        if not (0 < rlen <= self.RECORD_MAX_LEN):
            return None
        return {"ct": self._tls_ct_name(ct), "version": self._tls_version_name(ver), "length": int(rlen)}

    # -------- SSLv2 minimal peek ----------
    def _peek_sslv2_header(self, mv) -> Optional[dict]:
        """
        SSLv2 record header:
          - 2-byte header: MSB set in first byte => length is ((b0 & 0x7F) << 8) | b1 ; no padding
          - 3-byte header: MSB clear => length is ((b0 << 8) | b1); third byte holds padding & flags (ignored here)
        First byte after header is Handshake msg type:
            1: CLIENT_HELLO
            2: CLIENT_MASTER_KEY
            3: CLIENT_FINISHED
            4: SERVER_HELLO
            5: SERVER_VERIFY
            6: SERVER_FINISHED
            7: REQUEST_CERTIFICATE
            8: CLIENT_CERTIFICATE
        """
        try:
            if not mv or len(mv) < 3:
                return None
            b0 = mv[0]
            if b0 & 0x80:
                # 2-byte header
                if len(mv) < 3:  # need msg type too
                    return None
                length = ((b0 & 0x7F) << 8) | mv[1]
                header_len = 2
                if length < 1 or (header_len + length) > len(mv):
                    return None
                mtype = mv[2]
                mname = self._sslv2_msg_name(mtype)
                return {"sslv2": True, "header_len": header_len, "length": length, "msg_type": mtype, "msg_name": mname}
            else:
                # 3-byte header
                if len(mv) < 4:
                    return None
                length = (b0 << 8) | mv[1]
                header_len = 3
                if length < 1 or (header_len + length) > len(mv):
                    return None
                mtype = mv[3]
                mname = self._sslv2_msg_name(mtype)
                return {"sslv2": True, "header_len": header_len, "length": length, "msg_type": mtype, "msg_name": mname}
        except Exception:
            return None
        return None

    def _sslv2_msg_name(self, mtype: int) -> str:
        names = {
            1: "Handshake - Client Hello",
            2: "Handshake - Client Master Key",
            3: "Handshake - Client Finished",
            4: "Handshake - Server Hello",
            5: "Handshake - Server Verify",
            6: "Handshake - Server Finished",
            7: "Handshake - Request Certificate",
            8: "Handshake - Client Certificate",
        }
        name = names.get(int(mtype), f"Handshake - {mtype}")
        if name.startswith("Handshake"):
            self._metrics["sslv2_handshake_labeled"] += 1
        return name

    # -------- QUIC detector (very light) ----------
    def _looks_like_quic(self, raw: bytes) -> bool:
        """
        Very lightweight QUIC heuristic:
          - UDP dst/src 443 (checked elsewhere)
          - First byte: Header Form bit (0x80) set => long header
          - Version non-zero for Initial/Handshake (we don't parse version here)
          - Length >= ~1200 => likely Initial; otherwise still log as QUIC
        """
        try:
            if len(raw) < 5:
                return False
            first = raw[0]
            # If header form bit set => long header => definitely QUIC
            if first & 0x80:
                return True
            # Short header: bit not set; still could be QUIC (common)
            # Heuristic: short header + typical sizes
            return True
        except Exception:
            return False

    # -------- ClientHello peek (memoryview) with budget (TLSv1.x+) --------
    def _peek_client_hello_rich_mv(self, mv) -> Optional[dict]:
        if len(mv) < self.CHELLO_MIN_CAP or mv[0] != 0x16:  # TLS Handshake record?
            return None

        cap = min(self._peek_cap, len(mv))
        rec_len = (mv[3] << 8) | mv[4]
        if rec_len + 5 > cap:
            return {"client_hello": mv[5] == 0x01} if len(mv) > 5 else None

        p = 5
        if p + 4 > cap or mv[p] != 0x01:  # not ClientHello
            return None
        p += 1
        if p + 3 > cap: return {"client_hello": True}
        hs_len = ((mv[p] << 16) | (mv[p+1] << 8) | mv[p+2]); p += 3

        if p + 2 > cap: return {"client_hello": True}
        ver_major, ver_minor = mv[p], mv[p+1]; p += 2
        version_name = self._tls_version_tuple_name((ver_major, ver_minor))

        p += 32  # random
        if p >= cap: return {"client_hello": True, "version": version_name}

        sid_len = mv[p]; p += 1 + sid_len
        if p + 2 > cap: return {"client_hello": True, "version": version_name}

        cs_len = (mv[p] << 8) | mv[p+1]; p += 2
        cs_count = cs_len // 2
        cs_start = p; p += cs_len
        if p >= cap: return {"client_hello": True, "version": version_name, "cipher_suites_count": cs_count}

        comp_len = mv[p]; p += 1 + comp_len
        if p + 2 > cap: return {"client_hello": True, "version": version_name, "cipher_suites_count": cs_count}

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
                        if q + name_len > limit: break
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
                q = 1; limit = len(edata)
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
            "version": self._tls_version_tuple_name((ver_major, ver_minor)),
            "cipher_suites_count": cs_count,
            "extensions_count": exts_count,
            "alpn": alpn or None,
            "groups_count": groups_count,
        }
        if sni: out["sni"] = sni
        if ja3_hash: out["ja3"] = ja3_hash
        return out

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
            # Not TLSv1.x — keep hex (could be DTLS, etc.)
            if ver == 0x0002:
                return "SSLv2"
            return f"0x{ver:04x}"
        return {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}.get(ver, f"0x{ver:04x}")

    def _tls_version_tuple_name(self, tup) -> str:
        try:
            mj, mn = tup
            if mj != 3: return f"{mj}.{mn}"
            return {1: "TLS1.0", 2: "TLS1.1", 3: "TLS1.2", 4: "TLS1.3"}.get(mn, f"TLS(3,{mn})")
        except Exception:
            return "-"

    def _compact_list(self, items, max_items=4):
        try:
            if not items: return "-"
            items = [str(x) for x in items if x is not None]
            if len(items) <= max_items:
                return ",".join(items) if items else "-"
            extra = len(items) - max_items
            return ",".join(items[:max_items]) + f",+{extra}"
        except Exception:
            return "-"

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

class TransportMoneroManager:
    """
    Unified Monero transport observer + policy engine (low overhead).

    Public API:
      handle(pkt, src, dst, sport, dport, inbound_iface) -> 'allow' | 'deny'
    """

    _HTTP_EOL = b"\r\n"
    _HDR_DELIM_1 = b"\r\n\r\n"
    _HDR_DELIM_2 = b"\n\n"  # tolerate LF-only peers

    # -------- Ports --------
    DEFAULT_P2P_PORTS = {18080, 28080, 38080}
    DEFAULT_RPC_PORTS = {18081, 28081, 38081}

    # -------- Tunables / Budgets --------
    FLOW_TTL_SEC        = 15 * 60
    FLOW_SOFT_MAX       = 50_000
    RL_WINDOW_SEC       = 3.0
    GC_PERIOD_SEC       = 60
    RPC_BUF_MAX         = 256 * 1024     # per-direction buffer cap
    RPC_HDR_MAX         = 4096           # max header bytes to scan
    RPC_JSON_MAX        = 32 * 1024      # limit JSON body parse
    PROGRESS_PKT_STEP   = 50             # progress log every N pkts
    PROGRESS_BYTES_SET  = {1024, 4096, 16384, 65536, 262144}
    LEVIN_LOG_BURST_MAX = 8              # max frames to log per feed

    # -------- Levin constants --------
    _LEVIN_SIG   = 0x0101010101010101
    _LEVIN_BEGIN = 0x01
    _LEVIN_END   = 0x02
    _LEVIN_REQ   = 0x04
    _LEVIN_RSP   = 0x08
    _LEVIN_OK    = 1
    _CMD_PING    = 1000

    # -------- HTTP detection --------
    _HTTP_START_RE = re.compile(
        rb"^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PATCH)\s+([^\s]+)\s+HTTP/\d\.\d\r?\n", re.I
    )

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
                    sig, cb, _unused, cmd, ret, flags, pv = struct.unpack_from(self.HFMT, mv, off)
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
        flow_idle_timeout: int = FLOW_TTL_SEC,
        msg_rate_window: float = RL_WINDOW_SEC,
        p2p_auto_reply_ping: bool = True,
        tx_cb: Optional[callable] = None,
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
        self._tx_cb = tx_cb

        self._last_gc = time.time()

        self.logger.log_message("[Transport][🪙 Monero] Manager ready.")

    # ========== Public entrypoint ==========
    def handle(self, pkt, src, dst, sport, dport, inbound_iface) -> str:
        try:
            if not self._is_tcp(pkt):
                return 'allow'

            sport = int(sport); dport = int(dport)
            now = time.time()
            key = self._flow_key(src, sport, dst, dport)

            flow = self._flows.get(key)
            if not flow:
                ftype = self._classify_flow_type(sport, dport)
                if not ftype:
                    payload = self._get_payload_bytes(pkt)
                    ftype = self._dynamic_classify_from_payload(payload)
                if not ftype:
                    self._cleanup_idle(now)
                    return 'allow'
                flow = self._new_flow(src, sport, dst, dport, inbound_iface, now, ftype)
                self._flows[key] = flow

            self._update_flow_state(flow, pkt, now, inbound_iface)

            # Fast path after first classification
            if flow.get("noinspect", False):
                self._maybe_progress_log(flow)
                self._cleanup_idle(now)
                return 'allow'

            # Detailed logging + parsers
            self._perform_detailed_logging(flow, pkt, inbound_iface)

            # Throttle future inspection for this flow
            if flow.get("first_sample") is not None or flow.get("p2p_frames_logged", 0) > 0:
                flow["noinspect"] = True

            # Policy
            decision, reason = self._apply_policy(flow, pkt)
            if decision == 'deny':
                self._rl_log(
                    f"[Transport][🪙 Monero] ⛔ DENY {flow['type'].upper()} "
                    f"{src}:{sport} -> {dst}:{dport} | {reason}"
                )
            self._cleanup_idle(now)
            return decision
        except Exception:
            return 'allow'

    # ========== Policy ==========
    def _apply_policy(self, flow: dict, pkt) -> Tuple[str, str]:
        payload_len = len(self._get_payload_bytes(pkt))
        if flow['type'] == 'p2p':
            if flow.get('state') == 'ESTABLISHED' and not flow.get('synack_seen') and payload_len > 0:
                return 'deny', "P2P data before handshake completion"
        if flow['type'] == 'rpc':
            if flow.get('rpc_last_method') == 'get_block_template':
                self._rl_log("[Transport][🪙 Monero][POLICY] ℹ️ Mining activity detected on flow.")
        return 'allow', "default"

    # ========== Flow state ==========
    def _update_flow_state(self, f: dict, pkt, now: float, iface: str):
        flags = self._tcp_flags(pkt)
        payload_len = len(self._get_payload_bytes(pkt))

        f["last_seen"]  = now
        f["last_iface"] = iface
        f["pkts"]       = f.get("pkts", 0) + 1
        f["bytes"]      = f.get("bytes", 0) + payload_len
        f["last_flags"] = flags
        f["last_pkt"]   = pkt

        d = self._pkt_dir(f, pkt)
        if d: f["last_dir"] = d

        st = f.get("state", "INIT")
        if 'S' in flags and 'A' not in flags:
            f['state'] = 'SYN_SENT'; f['syn_seen'] = True
            self._on_syn(f, flags, iface)
        elif 'S' in flags and 'A' in flags:
            if st == 'SYN_SENT':
                f['state'] = 'ESTABLISHED'
            f['synack_seen'] = True
            self._on_syn_ack(f, flags, iface)
        elif st == 'SYN_SENT' and 'A' in flags and payload_len == 0:
            f['state'] = 'ESTABLISHED'
        elif 'F' in flags or 'R' in flags:
            f['state'] = 'CLOSED'; f['fin_or_rst'] = True
            self._on_fin_rst(f, flags, iface)

    @staticmethod
    def _new_flow(src, sport, dst, dport, iface, now_ts, ftype: str):
        return {
            "type": ftype,                     # "p2p" or "rpc"
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
            "noinspect": False,

            # RPC rolling state (budgeted)
            "rpc_buf_c2s": bytearray(),
            "rpc_buf_s2c": bytearray(),
            "rpc_seen_req": 0,
            "rpc_seen_rsp": 0,
            "rpc_last_status": None,
            "rpc_last_method": None,
            "rpc_last_path": None,
            "rpc_last_host": None,

            # P2P rolling state
            "p2p_parser": None,
            "p2p_frames_logged": 0,

            # Optional TX sockets
            "client_sock": None,
            "server_sock": None,
        }

    def _cleanup_idle(self, now_ts):
        if now_ts - self._last_gc < self.GC_PERIOD_SEC:
            return
        dead = [k for k, f in self._flows.items()
                if now_ts - f.get("last_seen", now_ts) > self.flow_idle_timeout]
        for k in dead:
            self._flows.pop(k, None)
        if len(self._flows) > self.FLOW_SOFT_MAX:
            excess = len(self._flows) - self.FLOW_SOFT_MAX
            victims = sorted(self._flows.items(), key=lambda kv: kv[1].get("last_seen", 0.0))[:excess]
            for k, _ in victims:
                self._flows.pop(k, None)
        self._last_gc = now_ts

    # ========== Logging + parsers ==========
    def _perform_detailed_logging(self, f: dict, pkt, iface: str):
        payload = self._get_payload_bytes(pkt)
        plen = len(payload)

        if plen > 0 and f["first_sample"] is None:
            sample = payload[:self.max_payload_sample]
            f["first_sample"] = sample
            f["entropy"] = self._byte_entropy(sample)
            self._log_first_data(f, sample, iface)

        if f["type"] == "rpc" and plen > 0:
            self._rpc_parse_and_log(f, pkt, iface)

        if f["type"] == "p2p" and plen > 0:
            direction = self._pkt_dir(f, pkt) or f.get("last_dir")
            if direction: f["last_dir"] = direction
            self._p2p_feed_and_log(f, payload, iface, direction)

        self._maybe_progress_log(f)

    # ---- TCP lifecycle logs ----
    def _on_syn(self, f, flags, iface):
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        self._rl_log(f"[Transport][🧵 TCP][🪙 Monero][{t}] SYN {a[0]}:{a[1]} → {b[0]}:{b[1]} on {iface} (flags={flags})")

    def _on_syn_ack(self, f, flags, iface):
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        dur_ms = (time.time() - f.get("created", time.time())) * 1000.0
        self._rl_log(
            f"[Transport][🧵 TCP][🪙 Monero][{t}] SYN/ACK {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface} "
            f"(flags={flags} rtt~{self._fmt_ms(dur_ms)})"
        )

    def _on_fin_rst(self, f, flags, iface):
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        dur = time.time() - f.get("created", time.time())
        reason = "RST" if ("R" in flags and "F" not in flags) else "FIN"
        who = f.get("last_dir", "peer?")
        self._rl_log(
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

        self._rl_log(
            f"[Transport][🧵 TCP][🪙 Monero][{t}] DATA ▶ {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface} "
            f"first={len(sample)}B ent={ent:.2f} {hint}{pv}"
        )

    def _maybe_progress_log(self, f):
        now = time.time()
        roll = f.get("rolling_sha")
        if roll:
            roll.update(b"\x00")

        pkts = f.get("pkts", 0); total = f.get("bytes", 0)
        if (pkts % self.PROGRESS_PKT_STEP != 0) and (total not in self.PROGRESS_BYTES_SET):
            return

        rate = total / max(1e-3, (now - f.get("created", now)))
        rate_str = f"{rate / 1024:.1f}KB/s" if rate >= 1024 else f"{rate:.0f}B/s"
        roll8 = (roll.hexdigest()[:8] if roll else "na")
        a, b = f["endpoints"]; t = "P2P" if f["type"] == "p2p" else "RPC"
        self._rl_log(
            f"[Transport][🧵 TCP][🪙 Monero][{t}] DATA ⏩ {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} "
            f"bytes={total} pkts={pkts} rate~{rate_str} roll8={roll8}"
        )

    # ---- RPC: budgeted split + JSON hints (no RandomX hooks) ----
    def _rpc_parse_and_log(self, f, pkt, iface_or_tag: str):
        (a_ip, a_port), (b_ip, b_port) = f["endpoints"]
        payload = self._get_payload_bytes(pkt)

        # Server direction (default RPC ports)
        c2s = "a2b" if b_port in self._rpc_ports else ("b2a" if a_port in self._rpc_ports else None)
        if c2s == "a2b":
            buf = f["rpc_buf_c2s"]; buf += payload
            if len(buf) > self.RPC_BUF_MAX: del buf[:len(buf) - self.RPC_BUF_MAX]
            msgs, remain = self._split_http_messages(buf); f["rpc_buf_c2s"] = remain
            for hdrs, body, _raw in msgs:
                f["rpc_seen_req"] += 1
                start = hdrs.get(":start", "")
                host  = hdrs.get("host")
                path  = self._extract_path_from_start(start)
                method_http = (start.split(" ", 1)[0] if start else "?")
                json_method = self._json_method_name(body) if self._looks_like_json(body) else None
                f["rpc_last_method"] = json_method or method_http
                f["rpc_last_path"] = path
                f["rpc_last_host"] = host
                self._rl_log(
                    f"[Transport][🧵 TCP][🪙 Monero][RPC] ▶REQ {method_http} {path or ''} host={host or '-'} "
                    f"json_method={json_method or '-'} body={len(body)}B"
                )
        elif c2s == "b2a":
            buf = f["rpc_buf_s2c"]; buf += payload
            if len(buf) > self.RPC_BUF_MAX: del buf[:len(buf) - self.RPC_BUF_MAX]
            msgs, remain = self._split_http_messages(buf); f["rpc_buf_s2c"] = remain
            for hdrs, body, _raw in msgs:
                f["rpc_seen_rsp"] += 1
                start = hdrs.get(":start", "")
                status = self._extract_status_from_start(start)
                jhint = "json" if self._looks_like_json(body) else "-"
                f["rpc_last_status"] = status
                self._rl_log(
                    f"[Transport][🧵 TCP][🪙 Monero][RPC] ◀RSP status={status or '?'} body={len(body)}B type={jhint}"
                )

    # ---- P2P (Levin) ----
    def _p2p_feed_and_log(self, f: dict, payload: bytes, iface: str, direction: Optional[str]) -> None:
        try:
            if direction:
                f["last_dir"] = direction
            if f.get("p2p_parser") is None:
                f["p2p_parser"] = TransportMoneroManager._LevinParser()
            frames = f["p2p_parser"].feed(payload)
            if not frames:
                return
            # Log at most LEVIN_LOG_BURST_MAX frames per call
            burst = 0
            a, b = f["endpoints"]
            for m in frames:
                if burst >= self.LEVIN_LOG_BURST_MAX:
                    self._rl_log(f"[Transport][🧵 TCP][🪙 Monero][P2P] … {len(frames)-burst} more frames suppressed")
                    break
                name = TransportMoneroManager._LevinParser.cmd_name(m.cmd)
                bits = []
                if m.begin: bits.append("BEGIN")
                if m.end:   bits.append("END")
                if m.req:   bits.append("REQ")
                if m.rsp:   bits.append("RSP")
                flags_txt = ",".join(bits) if bits else "-"
                preview = (m.payload[:24].hex() + ("…" if m.cb > 24 else "")) if m.cb else "-"
                self._rl_log(
                    f"[Transport][🧵 TCP][🪙 Monero][P2P] {m.kind()} {name} flags={flags_txt} "
                    f"ret={m.ret} pv={m.pv} len={m.cb} preview={preview} {a[0]}:{a[1]} ⇄ {b[0]}:{b[1]} on {iface}"
                )
                f["p2p_frames_logged"] = f.get("p2p_frames_logged", 0) + 1
                burst += 1
                self._maybe_reply_ping(f, m, iface)
        except Exception:
            pass

    def _maybe_reply_ping(self, f: dict, m: "_LevinMessage", iface: str):
        if not self.p2p_auto_reply_ping:
            return
        if not (m.cmd == self._CMD_PING and m.req and not m.rsp):
            return
        req_dir = f.get("last_dir") or "a2b"
        rsp_dir = "b2a" if req_dir == "a2b" else "a2b"
        pkt_bytes = self._levin_ping_rsp(m.pv)
        if self._send_bytes(f, pkt_bytes, rsp_dir):
            self._rl_log(f"[Transport][🧵 TCP][🪙 Monero][P2P] ◀ sent PING RSP (OK) pv={m.pv} on {iface}")
        else:
            self._rl_log(f"[Transport][🧵 TCP][🪙 Monero][P2P] (no-tx) would reply PING pv={m.pv} on {iface}")

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
        if callable(self._tx_cb):
            try:
                return bool(self._tx_cb(f, data, direction))
            except Exception:
                pass
        try:
            sock = f.get("server_sock") if direction == "a2b" else f.get("client_sock")
            if not sock:
                return False
            sock.sendall(data)
            return True
        except Exception:
            return False

    def attach_sockets(self, src: str, sport: int, dst: str, dport: int, *,
                       client_sock=None, server_sock=None) -> bool:
        key = self._flow_key(src, int(sport), dst, int(dport))
        f = self._flows.get(key)
        if not f:
            now = time.time()
            f = self._new_flow(src, sport, dst, dport, "sock_attach", now, "p2p")
            self._flows[key] = f
        if client_sock: f["client_sock"] = client_sock
        if server_sock: f["server_sock"] = server_sock
        self._rl_log(
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
            self._rl_log(f"[Transport][🧵 TCP][🪙 Monero][P2P] sockets detached for {src}:{sport} ⇄ {dst}:{dport}")

    # ========== Port / payload classification ==========
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
        if not payload:
            return False
        if payload.startswith(b"HTTP/1."):
            return True
        return bool(self._HTTP_START_RE.match(payload))

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

    # ========== Rate-limited logging ==========
    def _rl_log(self, msg: str):
        key = hash(msg)
        t = time.time()
        last = self._recent_msgs.get(key, 0.0)
        if t - last >= self._recent_msg_window:
            self._recent_msgs[key] = t
            try:
                self.logger.log_message(msg)
            except Exception:
                pass

    # ========== Small utils ==========
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
                or head.startswith(b"OPTI")   # OPTIONS
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

    def _decode_chunked(self, body: memoryview) -> Tuple[bytes, int]:
        """
        Minimal chunked decoder.
        Returns (decoded_bytes, total_bytes_consumed_from_input).
        If incomplete, returns (b"", 0).
        """
        pos = 0
        out = bytearray()
        mv = body
        # chunk-size [;ext] CRLF ... data ... CRLF ... 0 CRLF CRLF
        while True:
            # find CRLF after size line
            nl = mv[pos:].tobytes().find(self._HTTP_EOL)
            if nl < 0:
                return b"", 0  # incomplete
            size_line = mv[pos:pos + nl].tobytes()
            pos += nl + 2
            # size can have extensions (";")
            semi = size_line.split(b";", 1)[0]
            try:
                sz = int(semi.strip(), 16)
            except Exception:
                return b"", 0
            if sz == 0:
                # optional trailer section: read CRLF
                if len(mv) < pos + 2:
                    return b"", 0
                if mv[pos:pos + 2].tobytes() == self._HTTP_EOL:
                    pos += 2
                if len(mv) >= pos + 2 and mv[pos:pos + 2].tobytes() == self._HTTP_EOL:
                    pos += 2
                return bytes(out), pos
            # need sz bytes + CRLF
            if len(mv) < pos + sz + 2:
                return b"", 0
            out += mv[pos:pos + sz].tobytes()
            pos += sz
            # consume CRLF after data
            if mv[pos:pos + 2].tobytes() != self._HTTP_EOL:
                return b"", 0
            pos += 2

    def _parse_headers(self, raw_headers: bytes) -> dict:
        headers = {":start": raw_headers.split(self._HTTP_EOL, 1)[0].decode("utf-8", "replace")}
        for line in raw_headers.split(self._HTTP_EOL):
            if not line:
                continue
            if b":" not in line:
                # start-line (REQUEST/STATUS) or malformed; skip here
                continue
            k, v = line.split(b":", 1)
            headers[k.strip().lower().decode("utf-8", "replace")] = v.strip().decode("utf-8", "replace")
        return headers

    def _split_http_messages(self, buf: bytearray) -> Tuple[List[Tuple[dict, bytes, bytes]], bytearray]:
        """
        Splits a TCP reassembly buffer into complete HTTP messages.
        Supports:
          • Content-Length framing
          • Transfer-Encoding: chunked (minimal)
        Returns: ([(headers_dict, body_bytes, raw_bytes), ...], remaining_buf)
        """
        msgs: List[Tuple[dict, bytes, bytes]] = []
        mv = memoryview(buf)
        start = 0
        total = len(mv)

        while True:
            if total - start < 4:
                break  # not enough for headers

            # Find header delimiter (tolerate CRLFCRLF or LFLF)
            head_slice = mv[start:].tobytes()
            h_end_rel = head_slice.find(self._HDR_DELIM_1)
            delim_len = 4
            if h_end_rel < 0:
                h_end_rel = head_slice.find(self._HDR_DELIM_2)
                if h_end_rel < 0:
                    break  # no full headers yet
                delim_len = 2
            h_end_abs = start + h_end_rel
            headers_blob = mv[start:h_end_abs].tobytes()
            headers = self._parse_headers(headers_blob)

            # Determine body framing
            body_start = h_end_abs + delim_len
            cl = headers.get("content-length")
            te = headers.get("transfer-encoding")

            if cl is not None:
                want = self._parse_int_safe(cl.encode(), -1)
                if want < 0:
                    break  # malformed; wait for more
                end = body_start + want
                if total < end:
                    break  # incomplete body
                raw = mv[start:end].tobytes()
                body = mv[body_start:end].tobytes()
                msgs.append((headers, body, raw))
                start = end
                continue

            if te and ("chunked" in te.lower()):
                decoded, consumed = self._decode_chunked(mv[body_start:])
                if consumed == 0:
                    break  # incomplete
                end = body_start + consumed
                raw = mv[start:end].tobytes()
                body = decoded
                msgs.append((headers, body, raw))
                start = end
                continue

            # No body (headers only)
            raw = mv[start:body_start].tobytes()
            msgs.append((headers, b"", raw))
            start = body_start

        remaining = bytearray(mv[start:].tobytes())
        return msgs, remaining

    @staticmethod
    def _parse_int_safe(s: bytes, default: int = -1) -> int:
        try:
            return int(s.strip())
        except Exception:
            return default

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

    @staticmethod
    def _fmt_ms(v) -> str:
        try:
            if v is None: return "-"
            v = float(v)
            if v != v: return "-"
            return f"{int(round(v))}ms"
        except Exception:
            return "-"

    @staticmethod
    def _looks_like_json(b: bytes) -> bool:
        bb = b.strip()
        return (bb.startswith(b"{") and bb.endswith(b"}")) or (bb.startswith(b"[") and bb.endswith(b"]"))

    def _json_method_name(self, b: bytes):
        try:
            bb = b[: self.RPC_JSON_MAX]
            data = json.loads(bb.decode("utf-8", errors="replace"))
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

    # ========== Management ==========
    def get_active_flows(self):
        return {k: dict(v) for k, v in self._flows.items()}

    def add_candidate_p2p_port(self, port: int):
        if self._is_valid_port(port):
            self._p2p_ports.add(int(port))
            self._rl_log(f"[Transport][🪙 Monero] Added P2P port {int(port)}")

    def remove_candidate_p2p_port(self, port: int):
        try:
            self._p2p_ports.discard(int(port))
            self._rl_log(f"[Transport][🪙 Monero] Removed P2P port {int(port)}")
        except Exception:
            pass

    def add_candidate_rpc_port(self, port: int):
        if self._is_valid_port(port):
            self._rpc_ports.add(int(port))
            self._rl_log(f"[Transport][🪙 Monero] Added RPC port {int(port)}")

    def remove_candidate_rpc_port(self, port: int):
        try:
            self._rpc_ports.discard(int(port))
            self._rl_log(f"[Transport][🪙 Monero] Removed RPC port {int(port)}")
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
    QUIC (UDP/443) parser & logger (low-overhead).

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool

    Design goals:
      • Very cheap on the hot path (fast-path after classification)
      • Work-budget per packet (max bytes + max frames)
      • Minimal allocations (memoryview; no big hex unless logging)
      • De-dupe STREAM logs via time-based cache
      • Per-flow log rate-limit to avoid spam
      • Optional non-443 detection (off by default)
    """

    # --- Tunables (safe defaults) ---
    DETECT_NON443_DEFAULT = False
    FLOW_TTL_SEC = 120
    RL_INTERVAL_SEC = 1.0
    STREAM_TTL_SEC = 300
    BYTES_BUDGET = 1024            # how many payload bytes we ever scan
    FRAMES_BUDGET = 8             # max frames to parse/emit per packet
    GC_PERIOD_SEC = 60
    SHORT_DCID_LEN = 8            # common heuristic for short header DCID bytes

    def __init__(self, router_logger, *, detect_non443_quic: Optional[bool] = None,
                 bytes_budget: int = BYTES_BUDGET, frames_budget: int = FRAMES_BUDGET):
        self.logger = router_logger

        self.detect_non443_quic = self.DETECT_NON443_DEFAULT if detect_non443_quic is None else bool(detect_non443_quic)
        self.bytes_budget = max(64, int(bytes_budget))
        self.frames_budget = max(1, int(frames_budget))

        # Per-(5-tuple) flow table: classified -> bool
        self._flows: Dict[Tuple[str, str, int, int], Dict[str, float | bool]] = {}
        self._flow_ttl = self.FLOW_TTL_SEC

        # STREAM de-dupe (src,dst,stream_id) -> last_seen_ts
        self.logged_quic_streams: Dict[Tuple[str, str, int], float] = {}

        # Per-key rate limiter
        self._rl_last: Dict[Tuple, float] = {}

        # GC
        self._last_gc = time.time()

        self.logger.log_message("[Transport][🌐 QUIC] Manager ready.")

    # -------------------- Public entry --------------------
    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool:
        try:
            if UDP is None or not packet or not packet.haslayer(UDP):
                return False

            on_443 = (sport == 443) or (dport == 443)
            if not on_443 and not self.detect_non443_quic:
                return False

            raw_data = self._get_raw_bytes(packet)
            if not raw_data:
                # Header-only UDP/443 – classify once, then fast-path
                self._log_once(("hdr-only", src_ip, dst_ip, sport, dport),
                               f"[Transport][🚀 UDP][🌐 QUIC] hdr-only {src_ip}:{sport} → {dst_ip}:{dport} on {inbound_iface}")
                self._mark_classified(src_ip, dst_ip, sport, dport)
                return True

            mv = memoryview(raw_data)
            if len(mv) == 0:
                return False

            first = mv[0]
            is_long = (first & 0x80) == 0x80

            # Fast-path: if flow already classified, skip deep parsing
            if self._is_classified(src_ip, dst_ip, sport, dport):
                # Tiny bookkeeping (optional): spin bit/key phase peek for short header
                if not is_long and len(mv) >= 2 and self._rl(("quic-fast", src_ip, dst_ip, sport, dport)):
                    spin = (first >> 5) & 1
                    kp = (first >> 2) & 1
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][🌐 QUIC] fast {src_ip}:{sport} → {dst_ip}:{dport} spin={spin} kp={kp} on {inbound_iface}"
                    )
                self._maybe_gc()
                return True

            # Not classified yet: do one lightweight parse with budgets
            parts = [f"[Transport][🚀 UDP][🌐 QUIC] {src_ip}:{sport} → {dst_ip}:{dport} on {inbound_iface}"]
            hdr_len = 0

            if is_long:
                msg, hdr_len = self._format_long_header(mv)
                parts.append(msg)
            else:
                msg, hdr_len = self._format_short_header(mv, first)
                parts.append(msg)

            # Frame peek with budgets
            tail = mv[hdr_len:hdr_len + self.bytes_budget] if hdr_len < len(mv) else mv[0:0]
            frames = self._collect_quic_frames(tail, src_ip, dst_ip, self.frames_budget)

            if frames:
                parts.append(" | " + ",".join(frames))

            self.logger.log_message("".join(parts))
            self._mark_classified(src_ip, dst_ip, sport, dport)
            self._maybe_gc()
            return True

        except Exception:
            # Keep errors silent, but note once per flow (rate-limited)
            if self._rl(("quic-error", src_ip, dst_ip, sport, dport), 5.0):
                try:
                    self.logger.log_message(
                        f"[Transport][🚀 UDP][🌐 QUIC] parse-error {src_ip}:{sport} → {dst_ip}:{dport} on {inbound_iface}"
                    )
                except Exception:
                    pass
            return False

    # -------------------- Header helpers --------------------
    def _format_long_header(self, mv: memoryview) -> Tuple[str, int]:
        # Long header layout (RFC 9000): 1B first | 4B version | DCID len | DCID | SCID len | SCID | ...
        if len(mv) < 6:
            return " Long(malformed)", len(mv)
        first = mv[0]
        ptype = (first & 0x30) >> 4
        version = int.from_bytes(mv[1:5], "big")
        ver_name = self._quic_version_name(version)

        dcid_len = mv[5]
        off = 6
        if off + dcid_len > len(mv):
            return f" Long({self._quic_lh_type_name(ptype)}) v={ver_name} DCID=?", len(mv)

        dcid = mv[off:off + dcid_len].tobytes().hex()
        off += dcid_len

        if off >= len(mv):
            return f" Long({self._quic_lh_type_name(ptype)}) v={ver_name} DCID={dcid} SCID=?", len(mv)

        scid_len = mv[off]
        off += 1
        if off + scid_len > len(mv):
            return f" Long({self._quic_lh_type_name(ptype)}) v={ver_name} DCID={dcid} SCID=?", len(mv)

        scid = mv[off:off + scid_len].tobytes().hex()
        off += scid_len

        # We stop at SCID; the rest (token/PN length) varies by type and encryption stage
        msg = f" Long({self._quic_lh_type_name(ptype)}) v={ver_name} DCID:{dcid} SCID:{scid}"
        return msg, off

    def _format_short_header(self, mv: memoryview, first: int) -> Tuple[str, int]:
        # Short header (1-RTT): 1B first | DCID (impl-specific length; 8 bytes common)
        dcid_len = min(self.SHORT_DCID_LEN, max(0, len(mv) - 1))
        dcid = mv[1:1 + dcid_len].tobytes().hex() if dcid_len > 0 else "?"
        spin_bit = (first >> 5) & 1
        kp = (first >> 2) & 1
        msg = f" Short DCID:{dcid} spin:{spin_bit} kp:{('1' if kp else '0')}"
        return msg, 1 + dcid_len

    # -------------------- Frame parser (budgeted) --------------------
    def _collect_quic_frames(self, mv: memoryview, src_ip: str, dst_ip: str, frames_budget: int) -> List[str]:
        """
        Returns a small list of frame descriptors within the byte/frames budgets.
        Only cheap patterns; no CRYPTO/TLS decryption, just structure peeks.
        """
        out: List[str] = []
        i = 0
        frames_parsed = 0
        L = len(mv)

        while i < L and frames_parsed < frames_budget:
            fb = mv[i]
            # STREAM 0x08..0x0F
            if 0x08 <= fb <= 0x0F:
                has_off = bool(fb & 0x04)
                has_len = bool(fb & 0x02)
                i += 1
                stream_id, n = self._read_varint_mv(mv, i)
                if n == 0: break
                i += n
                if has_off:
                    _, n = self._read_varint_mv(mv, i)
                    if n == 0: break
                    i += n
                data_len = None
                if has_len:
                    data_len, n = self._read_varint_mv(mv, i)
                    if n == 0: break
                    i += n

                label = f"STREAM[{stream_id}]"
                key = (src_ip, dst_ip, int(stream_id))
                now = time.time()
                if key not in self.logged_quic_streams:
                    label += "*"
                self.logged_quic_streams[key] = now

                if data_len is not None:
                    label += f" len={int(data_len)}"
                    # Skip payload cheaply within budget
                    i = min(L, i + int(data_len))
                out.append(label)
                frames_parsed += 1
                continue

            # Minimal common frames
            if fb == 0x00:             # PADDING
                out.append("PADDING"); i += 1; frames_parsed += 1; continue
            if fb == 0x01:             # PING
                out.append("PING"); i += 1; frames_parsed += 1; continue
            if fb in (0x02, 0x03):     # ACK / ACK_ECN (coarse)
                out.append("ACK"); i += 1; frames_parsed += 1; continue
            if fb in (0x1C, 0x1D):     # CONNECTION_CLOSE
                out.append("CONNECTION_CLOSE"); break
            if fb == 0x06:             # CRYPTO (just note; length needs header decode)
                out.append("CRYPTO"); i += 1; frames_parsed += 1; continue
            if fb == 0x07:             # NEW_TOKEN
                out.append("NEW_TOKEN"); i += 1; frames_parsed += 1; continue
            if fb == 0x14:             # STREAMS_BLOCKED
                out.append("STREAMS_BLOCKED"); i += 1; frames_parsed += 1; continue
            if fb == 0x1e:             # DATA_BLOCKED
                out.append("DATA_BLOCKED"); i += 1; frames_parsed += 1; continue
            if fb == 0x25:             # RESET_STREAM
                out.append("RESET_STREAM"); i += 1; frames_parsed += 1; continue
            if fb == 0x1b:             # MAX_DATA
                out.append("MAX_DATA"); i += 1; frames_parsed += 1; continue
            if fb == 0x10:             # MAX_STREAMS bidi
                out.append("MAX_STREAMS"); i += 1; frames_parsed += 1; continue
            if fb == 0x12:             # DATA_BLOCKED_STREAM
                out.append("STREAM_DATA_BLOCKED"); i += 1; frames_parsed += 1; continue
            if fb == 0xa4:             # ACK_FREQUENCY (draft)
                out.append("ACK_FREQUENCY"); i += 1; frames_parsed += 1; continue

            # Unknown/rare -> stop early (keep loop cheap)
            out.append(f"0x{fb:02x}")
            break

        return out

    # -------------------- Utils --------------------
    def _get_raw_bytes(self, pkt) -> bytes:
        if Raw is None or not pkt.haslayer(Raw):
            return b""
        try:
            return bytes(pkt[Raw].load) or b""
        except Exception:
            return b""

    def _is_classified(self, src: str, dst: str, sport: int, dport: int) -> bool:
        k = (src, dst, int(sport), int(dport))
        f = self._flows.get(k)
        if not f:
            return False
        now = time.time()
        if (now - f.get("ts", 0.0)) > self._flow_ttl:
            self._flows.pop(k, None)
            return False
        f["ts"] = now
        return bool(f.get("classified", False))

    def _mark_classified(self, src: str, dst: str, sport: int, dport: int) -> None:
        now = time.time()
        k = (src, dst, int(sport), int(dport))
        self._flows[k] = {"ts": now, "classified": True}

    def _rl(self, key: Tuple, interval: float = RL_INTERVAL_SEC) -> bool:
        t = time.time()
        last = self._rl_last.get(key, 0.0)
        if (t - last) >= interval:
            self._rl_last[key] = t
            return True
        return False

    def _log_once(self, key: Tuple, line: str) -> None:
        if self._rl(key, interval=5.0):
            self.logger.log_message(line)

    def _maybe_gc(self) -> None:
        now = time.time()
        if now - self._last_gc < self.GC_PERIOD_SEC:
            return

        # Flows
        expired_flows = [k for k, v in self._flows.items() if now - v.get("ts", 0.0) > self._flow_ttl]
        for k in expired_flows:
            self._flows.pop(k, None)

        # Streams
        expired_streams = [k for k, ts in self.logged_quic_streams.items() if now - ts > self.STREAM_TTL_SEC]
        for k in expired_streams:
            self.logged_quic_streams.pop(k, None)

        if expired_flows or expired_streams:
            self.logger.log_message(
                f"[Transport][🌐 QUIC] 🧹 GC flows={len(expired_flows)} streams={len(expired_streams)}"
            )
        self._last_gc = now

    # ---------- Small helpers ----------
    def _quic_lh_type_name(self, n: int) -> str:
        return {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}.get(n, f"lh{n}")

    def _quic_version_name(self, ver: int) -> str:
        if ver == 0:
            return "VN"
        return {
            0x00000001: "v1",
            0x00000002: "v2",
            0x709A50C4: "draft-29",
        }.get(ver, f"0x{ver:08x}")

    def _read_varint_mv(self, mv: memoryview, p: int) -> Tuple[int, int]:
        """
        RFC 9000 varint from a memoryview. Returns (value, bytes_consumed).
        On failure, returns (0, 0).
        """
        L = len(mv)
        if p >= L:
            return 0, 0
        fb = mv[p]
        prefix = fb >> 6
        size = (1, 2, 4, 8)[prefix]
        if p + size > L:
            return 0, 0
        if size == 1:
            return fb & 0x3F, 1
        if size == 2:
            val = int.from_bytes(mv[p:p+2], "big") & 0x3FFF
            return val, 2
        if size == 4:
            val = int.from_bytes(mv[p:p+4], "big") & 0x3FFFFFFF
            return val, 4
        val = int.from_bytes(mv[p:p+8], "big") & 0x3FFFFFFFFFFFFFFF
        return val, 8



class TransportSSDPManager:
    """
    SSDP/UPnP logger & helper (fast-path).

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool

    Highlights:
      • Single-pass HTTPU parser (no full split/copies), tolerant to LF/CRLF
      • Handles multiple messages per datagram (rare but seen)
      • Fast NOTIFY/M-SEARCH/200 OK classification
      • De-dup + debounce: coalesce by USN (or LOCATION fallback)
      • Per-source & per-USN rate limiting to tame chatty IGD stacks
      • Background XML enrichment (bounded thread pool) for friendly/model/IGD
      • GC for stale announcements, clamped max-age
      • IPv4/IPv6 multicast detection + clean log tags
    """

    class _SSDPTokenBucket:
        """Tiny token bucket for rate-limiting (thread-safe, hot-path friendly)."""
        __slots__ = ("rate", "burst", "tokens", "ts", "lock")

        def __init__(self, rate: float, burst: int):
            self.rate = float(rate)  # tokens per second
            self.burst = int(burst)  # max tokens
            self.tokens = float(burst)
            self.ts = time.time()
            self.lock = threading.Lock()

        def allow(self, cost: float = 1.0) -> bool:
            now = time.time()
            with self.lock:
                elapsed = now - self.ts
                if elapsed > 0:
                    self.tokens = min(self.burst, int(self.tokens + elapsed * self.rate))
                    self.ts = now
                if self.tokens >= cost:
                    self.tokens -= cost
                    return True
                return False
    # Multicast constants
    _SSDP_MCAST_V4 = "239.255.255.250"
    _SSDP_MCAST_PORT = 1900
    _SSDP_MCAST_V6 = ("ff02::c", "ff05::c", "ff08::c")

    # Defaults and safety caps
    _DEFAULT_MAX_AGE = 1800               # 30 min if missing
    _MAX_AGE_CLAMP = (60, 24 * 3600)      # [1m, 24h]
    _GC_INTERVAL = 60                     # seconds
    _MAX_UDP_PARSE = 64 * 1024            # cap bytes to parse
    _XML_FETCH_TIMEOUT = 2.0              # seconds
    _XML_FETCH_MAX = 200_000              # bytes
    _ENRICH_THREADS = 2                   # small/quiet
    _PER_SRC_RATE = (0.5, 0.5)            # 10 logs/sec, burst 20
    _PER_USN_RATE = (2.0, 4)              # 2 logs/sec per USN, burst 4
    _RELOG_DEBOUNCE = 15.0                # don't re-log same USN too often

    # Precompiled regex for max-age
    _RE_MAXAGE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

    def __init__(self, router_logger):
        self.log = router_logger

        # usn_key -> info
        # info = { 'seen': ts, 'expires': ts, 'st': str, 'nt': str, 'location': str, 'server': str,
        #          'src': str, 'friendly_name': str|None, 'model_name': str|None, 'igd': dict|None,
        #          '_last_log': ts }
        self._announced: Dict[str, Dict[str, Any]] = {}

        # rate limiters
        self._rl_src: Dict[str, TransportSSDPManager._SSDPTokenBucket] = {}
        self._rl_usn: Dict[str, TransportSSDPManager._SSDPTokenBucket] = {}

        # enrichment pool (lazy)
        self._enrich_pool = None
        self._last_gc = time.time()
        self.log.log_message("[Transport][🔌 SSDP] Manager ready (fast-path).")

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
        if not hasattr(packet, "haslayer") or not packet.haslayer(UDP):
            return False
        # SSDP normally targets :1900 (mcast or unicast); allow unicast responses from 1900 too.
        if not (dport == self._SSDP_MCAST_PORT or sport == self._SSDP_MCAST_PORT):
            return False
        if not packet.haslayer(Raw):
            return False

        raw = packet[Raw].load
        if not raw:
            return False

        # Cap parse length to avoid pathological packets
        raw = raw[: self._MAX_UDP_PARSE]

        # Some stacks cram multiple HTTPU messages into one datagram; split on blank line.
        # Accept CRLF or LF-only.
        blobs = self._split_messages(raw)
        handled_any = False
        for blob in blobs:
            first, headers = self._parse_httpu_minimal(blob)
            if not first:
                continue
            handled_any = True
            kind = self._classify(first)
            if not kind:
                self._log_unknown(first, src_ip, dst_ip, sport, dport, inbound_iface)
                continue

            # Fast multicast tag and iface abbrev
            mcast = self._mcast_tag(dst_ip)
            iface = self._iface_short(inbound_iface)

            if kind == "NOTIFY":
                self._handle_notify(headers, src_ip, dst_ip, sport, dport, iface, mcast)
            elif kind == "M-SEARCH":
                self._handle_search(headers, src_ip, dst_ip, sport, dport, iface, mcast)
            else:  # HTTP/1.1 200
                self._handle_response(headers, src_ip, dst_ip, sport, dport, iface, mcast)

        if handled_any:
            self._maybe_gc()
        return handled_any

    # -------------------- Hot-path handlers --------------------

    def _handle_notify(self, h: Dict[str, str], sip, dip, sport, dport, iface, mcast):
        nt  = h.get("nt", "-")
        nts = h.get("nts", "-")
        usn = h.get("usn", "-")
        loc = h.get("location", "-")
        srv = h.get("server", "-")
        cc  = h.get("cache-control", "")
        max_age = self._clamped_max_age(self._parse_max_age(cc))

        key = self._usn_key(usn, loc)
        ent = self._announced.get(key)
        now = time.time()

        # Debounce identical NOTIFY floods
        if ent and (now - ent.get("_last_log", 0.0) < self._RELOG_DEBOUNCE):
            ent["seen"] = now
            ent["expires"] = now + max_age
            return

        if not self._allow_src(sip) or not self._allow_usn(key):
            # Still refresh internal state without logging
            self._announced[key] = {
                **(ent or {}),
                "seen": now, "expires": now + max_age,
                "nt": nt, "st": h.get("st", ""),
                "location": loc, "server": srv, "src": sip,
                "_last_log": ent.get("_last_log", 0.0) if ent else 0.0,
            }
            return

        self._announced[key] = {
            **(ent or {}),
            "seen": now, "expires": now + max_age,
            "nt": nt, "st": h.get("st", ""),
            "location": loc, "server": srv, "src": sip,
            "_last_log": now,
        }

        self.log.log_message(
            f"[Transport][🔌 SSDP][📣 NOTIFY]{mcast} if={iface} {sip}:{sport} → {dip}:{dport} "
            f"NT={nt} NTS={nts} USN={usn} LOCATION={loc} SERVER='{srv}' max-age={max_age}s"
        )

    def _handle_search(self, h: Dict[str, str], sip, dip, sport, dport, iface, mcast):
        if not self._allow_src(sip):
            return
        st   = (h.get("st") or "-").strip()
        man  = (h.get("man") or "-").strip()
        mx   = (h.get("mx") or "-").strip()
        host = (h.get("host") or "-").strip()

        self.log.log_message(
            f"[Transport][🔌 SSDP][🔎 M-SEARCH]{mcast} if={iface} {sip}:{sport} → {dip}:{dport} "
            f"ST={st} MAN={man} MX={mx} HOST={host}"
        )

    def _handle_response(self, h: Dict[str, str], sip, dip, sport, dport, iface, mcast):
        st  = (h.get("st") or "-").strip()
        usn = (h.get("usn") or "-").strip()
        loc = (h.get("location") or "-").strip()
        srv = (h.get("server") or "-").strip()
        cc  = (h.get("cache-control") or "").strip()
        max_age = self._clamped_max_age(self._parse_max_age(cc))

        key = self._usn_key(usn, loc)
        prev = self._announced.get(key)
        now = time.time()

        entry = {
            "seen": now,
            "expires": now + max_age,
            "nt": (h.get("nt") or "").strip(),
            "st": st,
            "location": loc,
            "server": srv,
            "src": sip,
            "friendly_name": prev.get("friendly_name") if prev else None,
            "model_name": prev.get("model_name") if prev else None,
            "igd": prev.get("igd") if prev else None,
            "_last_log": prev.get("_last_log", 0.0) if prev else 0.0,
        }

        materially_changed = (
            (not prev) or
            any(entry.get(k) != prev.get(k) for k in ("st", "location", "server", "src"))
        )

        # Rate limit on source and USN
        do_log = materially_changed and self._allow_src(sip) and self._allow_usn(key)
        # Debounce extremely chatty responders
        if now - entry["_last_log"] < self._RELOG_DEBOUNCE:
            do_log = False

        self._announced[key] = entry
        if do_log:
            entry["_last_log"] = now
            self.log.log_message(
                f"[Transport][🔌 SSDP][📬 Response]{mcast} if={iface} "
                f"{sip}:{sport} → {dip}:{dport} | "
                f"ST='{st}' USN='{usn}' LOCATION='{loc}' SERVER='{srv}' max-age={max_age}s"
            )
            # Background enrichment only if new/changed or first time
            if materially_changed or not entry.get("friendly_name"):
                self._schedule_fetch_description(key, loc)

    # -------------------- Helpers (parsing / utils) --------------------

    def _classify(self, first_line: str) -> Optional[str]:
        # Very cheap checks with fixed prefixes
        if first_line.startswith("NOTIFY "):
            return "NOTIFY"
        if first_line.startswith("M-SEARCH "):
            return "M-SEARCH"
        if first_line.startswith("HTTP/1.1 200"):
            return "RESP"
        return None

    def _split_messages(self, raw: bytes) -> List[bytes]:
        # Split on double newlines allowing CRLF or LF; keep minimal copies
        # Normalize CRLF->LF once to simplify; still O(n) and bounded
        if b"\r\n" in raw:
            text = raw.replace(b"\r\n", b"\n")
        else:
            text = raw
        parts = text.split(b"\n\n")
        # Filter empty/whitespace chunks
        return [p for p in parts if p.strip()]

    def _parse_httpu_minimal(self, blob: bytes) -> Tuple[str, Dict[str, str]]:
        """
        Single-pass header parser, LF-delimited. Produces lowercased keys for a
        small set we care about; ignores others (saves time/allocs).
        """
        # Keys we actually use
        WANT = {b"st", b"nt", b"nts", b"usn", b"location", b"server",
                b"host", b"man", b"mx", b"cache-control"}
        headers: Dict[str, str] = {}
        first_line = ""

        # Iterate lines manually to avoid extra splits/copies
        start = 0
        n = len(blob)
        i = 0
        line_no = 0
        while i <= n:
            if i == n or blob[i:i+1] == b"\n":
                line = blob[start:i]
                start = i + 1
                # blank line terminates headers
                if len(line) == 0:
                    break
                # strip trailing CR if present
                if line.endswith(b"\r"):
                    line = line[:-1]
                if line_no == 0:
                    try:
                        first_line = line.decode("ascii", "ignore").strip()
                    except Exception:
                        first_line = ""
                    line_no += 1
                    i += 1
                    continue
                # header lines: key: value
                colon = line.find(b":")
                if colon > 0:
                    k = line[:colon].strip().lower()
                    if k in WANT:
                        v = line[colon+1:].strip()
                        try:
                            headers[k.decode("ascii", "ignore")] = v.decode("latin-1", "ignore")
                        except Exception:
                            headers[k.decode("ascii", "ignore")] = ""
                line_no += 1
            i += 1
        return first_line, headers

    def _parse_max_age(self, cache_control: str) -> Optional[int]:
        if not cache_control:
            return None
        m = self._RE_MAXAGE.search(cache_control)
        if not m:
            return None
        try:
            return int(m.group(1))
        except Exception:
            return None

    def _clamped_max_age(self, v: Optional[int]) -> int:
        lo, hi = self._MAX_AGE_CLAMP
        if v is None:
            return self._DEFAULT_MAX_AGE
        return max(lo, min(v, hi))

    def _usn_key(self, usn: str, loc: str) -> str:
        return usn if usn and usn != "-" else f"loc:{loc or '-'}"

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
        return (name or "?").split("_")[-1]

    # -------------------- Rate limiting --------------------

    def _allow_src(self, src_ip: str) -> bool:
        tb = self._rl_src.get(src_ip)
        if tb is None:
            tb = self._rl_src.setdefault(src_ip, TransportSSDPManager._SSDPTokenBucket(*self._PER_SRC_RATE))
        return tb.allow(1.0)

    def _allow_usn(self, usn_key: str) -> bool:
        tb = self._rl_usn.get(usn_key)
        if tb is None:
            tb = self._rl_usn.setdefault(usn_key, TransportSSDPManager._SSDPTokenBucket(*self._PER_USN_RATE))
        return tb.allow(1.0)

    # -------------------- Enrichment (off hot path) --------------------

    def _ensure_pool(self):
        if self._enrich_pool is None:
            from concurrent.futures import ThreadPoolExecutor
            self._enrich_pool = ThreadPoolExecutor(
                max_workers=self._ENRICH_THREADS,
                thread_name_prefix="ssdp-enrich",
            )

    def _schedule_fetch_description(self, key: str, location_url: str) -> None:
        if not location_url or location_url == "-":
            return
        try:
            self._ensure_pool()
            self._enrich_pool.submit(self._fetch_and_enrich_description, key, location_url)
        except Exception:
            pass  # never disturb packet path

    def _fetch_and_enrich_description(self, key: str, location_url: str) -> None:
        try:
            import urllib.request
            import xml.etree.ElementTree as ET

            req = urllib.request.Request(location_url, headers={"User-Agent": "SSDP-Helper/1.0"})
            with urllib.request.urlopen(req, timeout=self._XML_FETCH_TIMEOUT) as resp:
                if getattr(resp, "status", 200) != 200:
                    return
                data = resp.read(self._XML_FETCH_MAX)

            root = ET.fromstring(data)

            # Try both namespaced and bare
            def tx(xpath: str) -> Optional[str]:
                try:
                    node = root.find(xpath)
                    if node is not None and node.text:
                        return node.text.strip()
                except Exception:
                    return None
                return None

            # Friendly/model name
            friendly = (
                tx(".//{urn:schemas-upnp-org:device-1-0}friendlyName")
                or tx(".//friendlyName")
            )
            model = (
                tx(".//{urn:schemas-upnp-org:device-1-0}modelName")
                or tx(".//modelName")
            )

            # IGD service endpoints
            igd = None
            svc_types = {
                "urn:schemas-upnp-org:service:WANIPConnection:1",
                "urn:schemas-upnp-org:service:WANIPConnection:2",
                "urn:schemas-upnp-org:service:WANPPPConnection:1",
                "urn:schemas-upnp-org:service:WANPPPConnection:2",
            }

            # urljoin helper
            def _urljoin(base: str, path: str) -> str:
                try:
                    from urllib.parse import urljoin
                    return urljoin(base or "", path or "")
                except Exception:
                    return path or ""

            # baseURL resolution
            base = tx("URLBase")
            if not base:
                try:
                    from urllib.parse import urlparse
                    u = urlparse(location_url)
                    base = f"{u.scheme}://{u.netloc}" if u.netloc else ""
                except Exception:
                    base = ""

            for svc in root.findall(".//{urn:schemas-upnp-org:device-1-0}serviceList/"
                                    "{urn:schemas-upnp-org:device-1-0}service"):
                st = (
                    (svc.find("{urn:schemas-upnp-org:device-1-0}serviceType") or {}).text
                    if hasattr(svc.find("{urn:schemas-upnp-org:device-1-0}serviceType"), "text") else None
                )
                if not st or st.strip() not in svc_types:
                    continue
                def _t(tag1, tag2):
                    node = svc.find(tag1)
                    if node is not None and getattr(node, "text", None):
                        return node.text.strip()
                    node = svc.find(tag2)
                    if node is not None and getattr(node, "text", None):
                        return node.text.strip()
                    return None
                ctrl = _t("{urn:schemas-upnp-org:device-1-0}controlURL", "controlURL")
                scpd = _t("{urn:schemas-upnp-org:device-1-0}SCPDURL", "SCPDURL")
                evt  = _t("{urn:schemas-upnp-org:device-1-0}eventSubURL", "eventSubURL")

                igd = {
                    "serviceType": st.strip(),
                    "controlURL": _urljoin(base, ctrl or ""),
                    "scpdURL": _urljoin(base, scpd or ""),
                    "eventSubURL": _urljoin(base, evt or ""),
                    "baseURL": base,
                }
                break  # take the first relevant one

            ent = self._announced.get(key)
            if ent is None:
                return
            ent["friendly_name"] = friendly
            ent["model_name"] = model
            ent["igd"] = igd

            # Nice concise enrichment line (rate-limited by per-USN limiter)
            extra = []
            if friendly: extra.append(f"friendly='{friendly}'")
            if model:    extra.append(f"model='{model}'")
            if igd:      extra.append(f"igd={igd.get('serviceType')} ctrl={igd.get('controlURL')}")
            if extra and self._allow_usn(key):
                self.log.log_message(f"[Transport][🔌 SSDP] ℹ️ Enriched USN key='{key}': " + " ".join(extra))

        except Exception:
            # Stay quiet; SSDP firmware can be very inconsistent
            pass

    # -------------------- Misc --------------------

    def _log_unknown(self, first_line: str, sip, dip, sport, dport, inbound_iface):
        iface = self._iface_short(inbound_iface)
        if not self._allow_src(sip):
            return
        self.log.log_message(
            f"[Transport][🔌 SSDP][❔ Unknown] if={iface} {sip}:{sport} → {dip}:{dport} | line='{first_line[:120]}'"
        )

    def _maybe_gc(self):
        now = time.time()
        if now - self._last_gc < self._GC_INTERVAL:
            return
        expired = [k for k, v in self._announced.items() if now >= v.get("expires", 0)]
        for k in expired:
            self._announced.pop(k, None)
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
        self._tcp_buf: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}
        self._tcp_buf_ttl_sec = 60  # flush idle TCP streams after 60s
        self._tcp_buf_hard_cap = 1 << 20  # 1 MiB safety cap per-flow
        self._last_tcp_gc = time.time()
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

    def handle_tcp_segment(self, packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool:
        """
        DNS over TCP reassembler. Consumes Raw TCP bytes, peels 2-byte length-prefixed DNS
        messages, and logs via existing query/response paths. Returns True if any DNS message handled.
        """
        if TCP is None or DNS is None or Raw is None:
            return False
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return False
        if sport != 53 and dport != 53:
            return False

        seg = bytes(packet[Raw].load or b"")
        if not seg:
            return False

        key = (src_ip, sport, dst_ip, dport)
        entry = self._tcp_buf.get(key)
        if entry is None:
            entry = {"buf": bytearray(), "ts": time.time()}
            self._tcp_buf[key] = entry

        buf = entry["buf"]
        buf.extend(seg)
        entry["ts"] = time.time()

        # Hard cap per flow to avoid unbounded memory in pathological cases
        if len(buf) > self._tcp_buf_hard_cap:
            # Drop the flow buffer; log once and move on
            self._tcp_buf.pop(key, None)
            self.log.log_message("[Transport][🧵 TCP][🔎 DNS]F buffer overflow; dropping flow state")
            return False

        handled_any = False

        # Peel off as many complete messages as present
        while True:
            if len(buf) < 2:
                break
            msg_len = (buf[0] << 8) | buf[1]
            if msg_len <= 0:
                # Defensive: discard length header and continue
                del buf[:2]
                continue
            if len(buf) < 2 + msg_len:
                break

            payload = bytes(buf[2:2 + msg_len])
            del buf[:2 + msg_len]

            # Parse one DNS message
            try:
                dns = DNS(payload)
            except Exception:
                # Skip silently if not valid DNS
                continue

            handled_any = True

            # Direction/proto info
            proto = "tcp"
            iface = inbound_iface.split("_")[-1]
            txid = int(getattr(dns, "id", 0))
            qr = int(getattr(dns, "qr", 0))  # 0=query, 1=response

            if qr == 0:
                # ---- QUERY ----
                qnames, qtypes = self._extract_questions(dns)
                self._log_query(iface, src_ip, sport, dst_ip, dport, txid, proto, dns, qnames, qtypes)
                if qnames:
                    pend_key = (src_ip, sport, txid, proto)
                    self._pending[pend_key] = {
                        "ts": time.time(),
                        "names": qnames,
                        "types": qtypes,
                        "server": dst_ip,
                    }
            else:
                # ---- RESPONSE ---- (reverse key to match original client tuple)
                pend_key = (dst_ip, dport, txid, proto)
                pend = self._pending.pop(pend_key, None)
                latency_ms = int((time.time() - pend["ts"]) * 1000) if pend else None
                self._log_response(iface, src_ip, sport, dst_ip, dport, txid, proto, dns, latency_ms)

        # Periodic GC of old flow buffers
        self._tcp_buf_gc()

        return handled_any

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

    def _tcp_buf_gc(self):
        now = time.time()
        if now - self._last_tcp_gc < 10:  # run every ~10s
            return
        expired = []
        for k, v in self._tcp_buf.items():
            if now - v.get("ts", 0) > self._tcp_buf_ttl_sec:
                expired.append(k)
        for k in expired:
            self._tcp_buf.pop(k, None)
        if expired:
            self.log.log_message(f"[Transport][🧵 TCP][🔎 DNS] 🧹 GC expired {len(expired)} stream buffers")
        self._last_tcp_gc = now

    def _extract_questions(self, dns: Any) -> Tuple[List[str], List[str]]:
        """
        Extract all question names and qtypes from a DNS packet.
        Returns (names, types) where both are lists of strings.
        """
        names: List[str] = []
        types: List[str] = []
        try:
            qdcount = int(getattr(dns, "qdcount", 0))
            qd = getattr(dns, "qd", None)

            # scapy represents multiple questions as a chain of DNSQR payloads
            cur = qd
            seen = 0
            while cur is not None and seen < qdcount:
                # Name
                qname = getattr(cur, "qname", b"")
                if isinstance(qname, (bytes, bytearray)):
                    name = qname.decode("utf-8", errors="ignore").rstrip(".")
                else:
                    name = str(qname).rstrip(".")
                names.append(name or ".")

                # QTYPE
                qtype = int(getattr(cur, "qtype", 0))
                types.append(self._QT.get(qtype, str(qtype)))

                # Advance
                cur = getattr(cur, "payload", None)
                if cur is qd:  # defensive guard against cycles
                    break
                if not isinstance(cur, DNSQR):
                    break
                seen += 1
        except Exception:
            # swallow parse errors, return what we got
            pass
        return names, types
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
class TransportMDNSManager:
    """
    mDNS (Multicast DNS) helper (UDP/5353, 224.0.0.251 / ff02::fb)

    Emits concise summaries:
      • Queries: names/types (+EDNS if present, though rare in mDNS)
      • Responses: PTR→(SRV/TXT)+A/AAAA previews
      • Dedup + cooldown to avoid floods
    """

    MDNS_PORT_V4 = 5353
    MDNS_MCAST_V4 = "224.0.0.251"
    MDNS_MCAST_V6 = "ff02::fb"

    # Common qtype strings
    _QT = {
        1:  "A", 28: "AAAA", 12: "PTR", 33: "SRV", 16: "TXT",
        5:  "CNAME", 6: "SOA", 2: "NS"
    }

    # ---------- Tunables ----------
    LOG_RPS         = .15      # ~1 line / 2s globally
    LOG_BURST       = 3
    FLOW_COOLDOWN_S = 10.0      # per (sig) cooldown
    DEDUP_TTL_S     = 120.0     # suppress identical response sets briefly
    PREVIEW_MAX     = 5

    class _TokenBucket:
        __slots__ = ("cap","rate","tokens","last")
        def __init__(self, cap: int, rate: float):
            self.cap = max(1, int(cap)); self.rate = max(0.1, float(rate))
            self.tokens = float(self.cap); self.last = time.time()
        def _refill(self):
            now = time.time(); dt = now - self.last
            if dt > 0:
                self.tokens = min(self.cap, int(self.tokens + dt * self.rate)); self.last = now
        def take(self, cost=1.0) -> bool:
            self._refill()
            if self.tokens >= cost:
                self.tokens -= cost; return True
            return False

    def __init__(self, router_logger, exporter=None):
        self.log = router_logger
        self._exporter = exporter
        self._tb = self._TokenBucket(self.LOG_BURST, self.LOG_RPS)
        # cache: signature -> next_ok_ts
        self._cooldown_until: Dict[Tuple, float] = {}
        # dedup of response sets (hash) -> expire_ts
        self._seen_resp: Dict[str, float] = {}
        self._last_gc = time.time()
        try:
            self.log.log_message("[Transport][📡 mDNS] Manager ready.")
        except Exception:
            pass

    # ---------- Public ----------
    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool:
        if DNS is None or not packet.haslayer(DNS):
            return False
        # mDNS must be UDP/5353 (scoped to link-local mcast, but we won't over-assume)
        if UDP is None or not packet.haslayer(UDP):
            return False
        if int(sport) != self.MDNS_PORT_V4 and int(dport) != self.MDNS_PORT_V4:
            return False

        dns = packet[DNS]
        qr = int(getattr(dns, "qr", 0))   # 0=query, 1=response
        iface = str(inbound_iface).split("_")[-1]
        txid  = int(getattr(dns, "id", 0))
        # scapy: qdcount/ancount/nscount/arcount
        try:
            if qr == 0:
                names, types = self._extract_questions(dns)
                if not names:
                    return True
                # Per-(name,type) cooldown to limit floods
                head = names[0]; qtype0 = types[0]
                sig = ("q", head, qtype0, iface)
                if not self._should_emit(sig):
                    return True
                line = (f"[Transport][📡 mDNS][🔎 Query] if={iface} {src_ip}:{sport} → {dst_ip}:{dport} "
                        f"name={head} type={qtype0}" +
                        (f" +{len(names)-1} more" if len(names) > 1 else ""))
                self._emit(line)
            else:
                # Response: build compact preview; dedup on RR hash
                an, ns, ar = int(getattr(dns, "ancount", 0)), int(getattr(dns, "nscount", 0)), int(getattr(dns, "arcount", 0))
                preview, resp_hash = self._preview_answers(dns, an, ns, ar)
                if not preview:
                    return True
                if not self._should_emit(("r", resp_hash, iface), dedup_hash=resp_hash):
                    return True
                head = preview[0]
                more = f" … +{len(preview)-1}" if len(preview) > 1 else ""
                line = (f"[Transport][📡 mDNS][📦 Response] if={iface} {src_ip}:{sport} → {dst_ip}:{dport} "
                        f"{head}{more}")
                self._emit(line)
        finally:
            self._maybe_gc()
            return True

    # ---------- Internals ----------
    def _should_emit(self, sig: Tuple, *, dedup_hash: Optional[str]=None) -> bool:
        now = time.time()
        # Per-signature cooldown
        nxt = self._cooldown_until.get(sig, 0.0)
        if now < nxt:
            return False
        # Global budget
        if not self._tb.take(1.0):
            return False
        # Dedup identical response sets for a bit
        if dedup_hash:
            exp = self._seen_resp.get(dedup_hash, 0.0)
            if now < exp:
                return False
            self._seen_resp[dedup_hash] = now + self.DEDUP_TTL_S
        self._cooldown_until[sig] = now + self.FLOW_COOLDOWN_S
        return True

    def _emit(self, line: str):
        if callable(self._exporter):
            try:
                self._exporter({"topic": "mdns", "line": line})
                return
            except Exception:
                pass
        try:
            self.log.log_message(line)
        except Exception:
            pass

    def _extract_questions(self, dns) -> Tuple[List[str], List[str]]:
        names, types = [], []
        try:
            qdcount = int(getattr(dns, "qdcount", 0))
            qd = getattr(dns, "qd", None)
            cur = qd; n = 0
            while cur is not None and n < qdcount:
                nm = self._safe_name(getattr(cur, "qname", b""))
                qt = self._QT.get(int(getattr(cur, "qtype", 0)), str(int(getattr(cur, "qtype", 0))))
                names.append(nm); types.append(qt)
                nxt = getattr(cur, "payload", None)
                if nxt is cur or not isinstance(nxt, DNSQR): break
                cur = nxt; n += 1
        except Exception:
            pass
        return names, types

    def _preview_answers(self, dns, an, ns, ar) -> Tuple[List[str], str]:
        items: List[str] = []

        def iter_rr(rr, count):
            cur = rr; n = 0
            while cur is not None and n < count:
                yield cur
                nxt = getattr(cur, "payload", None)
                if nxt is cur or not isinstance(nxt, DNSRR): break
                cur = nxt; n += 1

        # PTR/SRV/TXT plus A/AAAA previews, capped
        def fmt_rr(rr) -> str:
            try:
                t = self._QT.get(int(getattr(rr, "type", 0)), str(int(getattr(rr, "type", 0))))
                name = self._safe_name(getattr(rr, "rrname", b""))
                ttl = int(getattr(rr, "ttl", 0))
                if t == "PTR":
                    tgt = self._safe_name(getattr(rr, "rdata", b""))
                    return f"PTR {name} → {tgt} (ttl={ttl})"
                if t == "SRV":
                    port = getattr(rr, "port", "?")
                    tgt  = self._safe_name(getattr(rr, "target", b""))
                    return f"SRV {name} → {tgt}:{port} (ttl={ttl})"
                if t == "TXT":
                    r = getattr(rr, "rdata", b"")
                    txt = self._fmt_txt(r)
                    return f"TXT {name} {txt} (ttl={ttl})"
                if t in ("A","AAAA"):
                    v = getattr(rr, "rdata", "?")
                    return f"{t} {name} {v} (ttl={ttl})"
                # fallback terse
                v = getattr(rr, "rdata", b"")
                if isinstance(v, bytes): v = self._safe(v)
                return f"{t} {name} {v} (ttl={ttl})"
            except Exception:
                return "RR ?"

        for rr in iter_rr(getattr(dns, "an", None), an):
            items.append(fmt_rr(rr))
            if len(items) >= self.PREVIEW_MAX: break
        if len(items) < self.PREVIEW_MAX:
            for rr in iter_rr(getattr(dns, "ar", None), ar):
                # additional often carries SRV target A/AAAA or NSEC/TXT
                items.append(fmt_rr(rr))
                if len(items) >= self.PREVIEW_MAX: break

        # Build a stable hash to dedup repeated multicasts
        h = hashlib.sha1()
        try:
            h.update(bytes(getattr(dns, "an", b"") or b""))
            h.update(bytes(getattr(dns, "ar", b"") or b""))
        except Exception:
            # as a fallback, hash the joined strings
            h.update("|".join(items).encode("utf-8", "ignore"))
        resp_hash = h.hexdigest()[:16]
        return items, resp_hash

    def _fmt_txt(self, rdata: Any) -> str:
        try:
            if isinstance(rdata, (bytes, bytearray)):
                s = self._safe(rdata)
                return f"\"{s}\"" if s else "\"\""
            if isinstance(rdata, list):
                parts = [self._safe(x) for x in rdata[:3]]
                more = f" +{len(rdata)-3}" if len(rdata) > 3 else ""
                return "[" + ", ".join(f"\"{p}\"" for p in parts) + "]" + more
        except Exception:
            pass
        return "\"?\""

    def _safe_name(self, v: Any) -> str:
        if isinstance(v, (bytes, bytearray)):
            return v.decode("utf-8", "ignore").rstrip(".") or "."
        if isinstance(v, str):
            return v.rstrip(".")
        return str(v)

    def _safe(self, b: Any) -> str:
        try:
            if isinstance(b, (bytes, bytearray)):
                s = b.decode("utf-8", "ignore")
                return s if len(s) <= 80 else s[:77] + "…"
            return str(b)
        except Exception:
            return "?"

    def _maybe_gc(self):
        now = time.time()
        if now - self._last_gc < 15.0:
            return
        # purge old response hashes
        stale = [k for k,v in self._seen_resp.items() if v < now]
        for k in stale: self._seen_resp.pop(k, None)
        # trim cooldowns that are long past
        stale2 = [k for k,t in self._cooldown_until.items() if t < now - 2*self.FLOW_COOLDOWN_S]
        for k in stale2: self._cooldown_until.pop(k, None)
        self._last_gc = now
class TransportNBNSManager:
    """
    Minimal NetBIOS Name Service (NBNS, UDP/137) parser & logger.
    Avoids 'Undecoded' and surfaces who is asking/answering for which name.

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
    """

    # NBNS opcodes (top 4 bits of flags)
    _OPC = {0: "QUERY", 5: "REG", 6: "RELEASE", 7: "WACK", 8: "REFRESH"}
    # NBNS RCODEs (low 4 bits)
    _RC  = {0: "NOERROR", 1: "FMTERR", 2: "SRVFAIL", 3: "NXDOMAIN", 6: "REFUSED"}

    # QTYPE/QCLASS (common)
    _QT = {0x0020: "NB", 0x0021: "NBSTAT"}
    _QC = {0x0001: "IN"}

    def __init__(self, router_logger, *, pending_ttl_sec=10, gc_interval_sec=5):
        self.log = router_logger
        self._pending_ttl = int(pending_ttl_sec)
        self._gc_interval = int(gc_interval_sec)
        # key = (client_ip, client_port, dst_ip, txid) → ts
        self._pending = {}
        self._last_gc = time.time()
        self._recent = {}  # msg hash → last ts (simple dedup)
        self._recent_window = 2.0
        try:
            self.log.log_message("[Transport][📣 NBNS] Manager ready.")
        except Exception:
            pass

    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool:
        if UDP is None:
            return False
        if not packet.haslayer(UDP):
            return False
        if not (sport == 137 or dport == 137):
            return False

        iface = inbound_iface.split("_")[-1]
        payload = b""
        try:
            if Raw is not None and packet.haslayer(Raw) and packet[Raw].load:
                payload = bytes(packet[Raw].load)
        except Exception:
            pass

        if len(payload) < 12:  # DNS-like header size
            self._log_rate(f"[Transport][📣 NBNS] if={iface} {src_ip}:{sport} → {dst_ip}:{dport} (short)")
            return True

        txid = int.from_bytes(payload[0:2], "big")
        flags = int.from_bytes(payload[2:4], "big")
        qd, an, ns, ar = (int.from_bytes(payload[4:6], "big"),
                          int.from_bytes(payload[6:8], "big"),
                          int.from_bytes(payload[8:10], "big"),
                          int.from_bytes(payload[10:12], "big"))
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        aa = bool((flags >> 10) & 1)
        tc = bool((flags >> 9) & 1)
        rd = bool((flags >> 8) & 1)
        ra = bool((flags >> 7) & 1)
        bcast = bool((flags >> 4) & 1)
        rcode = flags & 0xF

        p = 12
        name, qtype, qclass, p2 = self._parse_question(payload, p) if qd else ("-", None, None, p)

        # direction & latency tracking
        proto = "udp"
        if qr == 0:  # query
            self._pending[(src_ip, sport, dst_ip, txid)] = time.time()
            self._log_rate(
                f"[Transport][📣 NBNS][🧭 Query] if={iface} {src_ip}:{sport} → {dst_ip}:{dport} "
                f"txid=0x{txid:04x} op={self._OPC.get(opcode,'OP'+str(opcode))} "
                f"name={name} type={self._QT.get(qtype,qtype)} "
                f"flags={'BCAST|' if bcast else ''}{'RD|' if rd else ''}{'RA|' if ra else ''}{'AA' if aa else '-'}{(' TC' if tc else '')}"
            )
        else:        # response
            lat = None
            pend_key = (dst_ip, dport, src_ip, txid)  # reverse to original client
            ts0 = self._pending.pop(pend_key, None)
            if ts0:
                lat = int((time.time() - ts0) * 1000)

            hdr = (f"[Transport][📣 NBNS][📦 Response] if={iface} {src_ip}:{sport} → {dst_ip}:{dport} "
                   f"txid=0x{txid:04x} rcode={self._RC.get(rcode, rcode)} "
                   f"an={an} ns={ns} ar={ar}{' '+str(lat)+'ms' if lat is not None else ''} "
                   f"flags={'BCAST|' if bcast else ''}{'RA|' if ra else ''}{'AA' if aa else '-'}{(' TC' if tc else '')}")
            self._log_rate(hdr)

            # Show a couple of answers
            try:
                p = p2  # after first question
                shown = 0
                for _ in range(an):
                    rr, p = self._parse_rr(payload, p)
                    if not rr:
                        break
                    if shown < 4:
                        self._log_rate(f"[Transport][📣 NBNS][📜 Answer] {rr}")
                        shown += 1
                # (We could emit NS/AR similarly if you want)
            except Exception:
                pass

        self._maybe_gc()
        return True

    # ---------- parsing helpers ----------

    def _parse_question(self, buf: bytes, p: int):
        name, p = self._read_nbns_name(buf, p)
        if p + 4 > len(buf):
            return name, None, None, p
        qtype = int.from_bytes(buf[p:p+2], "big"); p += 2
        qclass = int.from_bytes(buf[p:p+2], "big"); p += 2
        return name, qtype, qclass, p

    def _parse_rr(self, buf: bytes, p: int):
        name, p = self._read_nbns_name(buf, p)
        if p + 10 > len(buf):
            return None, p
        rtype = int.from_bytes(buf[p:p+2],"big"); p += 2
        rclass = int.from_bytes(buf[p:p+2],"big"); p += 2
        ttl   = int.from_bytes(buf[p:p+4],"big"); p += 4
        rdlen = int.from_bytes(buf[p:p+2],"big"); p += 2
        rdata = buf[p:p+rdlen]; p += rdlen

        tstr = self._QT.get(rtype, f"TYPE{rtype}")
        if rtype == 0x0020:  # NB → <num addrs, flags, ip(s)>
            # NB resource data: 2B flags + 4B IPv4 (may repeat by rdlen)
            vals = []
            q = 0
            while q + 6 <= len(rdata):
                flags = int.from_bytes(rdata[q:q+2], "big"); q += 2
                ip = ".".join(str(b) for b in rdata[q:q+4]); q += 4
                g = "GROUP" if (flags & 0x8000) else "UNIQ"
                vals.append(f"{ip} ({g})")
            val = ", ".join(vals) if vals else "?"
        elif rtype == 0x0021:  # NBSTAT
            # First byte is number of names; then 18B per entry; tail may include stats
            val = self._summarize_nbstat(rdata)
        else:
            val = (rdata.hex()[:40] + "…") if len(rdata) > 24 else rdata.hex()

        return f"🧾 {name} {tstr} {val} (ttl={ttl})", p

    def _summarize_nbstat(self, rdata: bytes) -> str:
        try:
            if not rdata:
                return "NBSTAT ?"
            n = rdata[0]
            offs = 1
            names = []
            for _ in range(min(n, 5)):
                if offs + 18 > len(rdata):
                    break
                raw = rdata[offs:offs+15]; flags = rdata[offs+15]; offs += 18
                nm = raw.rstrip(b"\x00").decode("ascii", "ignore")
                names.append(f"{nm}<{flags:02x}>")
            more = f" …+{n-5}" if n > 5 else ""
            # optional: trailing unit ID (6B MAC) at end
            if len(rdata) >= 6:
                mac = ":".join(f"{b:02x}" for b in rdata[-6:])
                return f"[{', '.join(names)}]{more} mac={mac}"
            return "[" + ", ".join(names) + "]" + more
        except Exception:
            return "NBSTAT ?"

    def _read_nbns_name(self, buf: bytes, p: int):
        """
        NBNS compresses names like DNS, but the *encoded* label for a NetBIOS
        name is a single 32-byte 'first-level encoding'. We handle:
          - 0x20 length then 32B encoded name + 0x00
          - DNS-style pointers (0xC0xx)
        """
        if p >= len(buf):
            return "?", p
        l = buf[p]
        if l == 0x00:
            return ".", p + 1
        if (l & 0xC0) == 0xC0 and p + 1 < len(buf):
            # pointer
            off = ((l & 0x3F) << 8) | buf[p+1]
            name, _ = self._read_nbns_name(buf, off)
            return name, p + 2
        if l == 0x20 and p + 1 + 32 <= len(buf):
            enc = buf[p+1:p+33]; p2 = p + 33
            name = self._decode_nb_name(enc)
            # next should be 0x00 label terminator
            if p2 < len(buf) and buf[p2] == 0x00:
                p2 += 1
            return name, p2
        # Fallback: try DNS-like labels
        return self._read_dns_like_name(buf, p)

    def _decode_nb_name(self, enc: bytes) -> str:
        # RFC 1002 first-level encoding: 16-byte NetBIOS name → 32 ASCII (A–P)
        if len(enc) != 32:
            return "?"
        out = bytearray()
        for i in range(0, 32, 2):
            c1, c2 = enc[i]-0x41, enc[i+1]-0x41
            out.append((c1 << 4) | (c2 & 0x0F))
        raw = bytes(out).rstrip(b" ")
        try:
            base = raw[:-1].decode("ascii", "ignore")
            suffix = raw[-1]
            return f"{base}<{suffix:02x}>"
        except Exception:
            return raw.hex()

    def _read_dns_like_name(self, buf: bytes, p: int):
        labels = []
        start = p
        for _ in range(10):
            if p >= len(buf):
                break
            l = buf[p]; p += 1
            if l == 0:
                break
            if (l & 0xC0) == 0xC0 and p < len(buf):
                off = ((l & 0x3F) << 8) | buf[p]; p += 1
                tail, _ = self._read_dns_like_name(buf, off)
                labels.append(tail)
                break
            if p + l > len(buf):
                break
            labels.append(buf[p:p+l].decode("utf-8", "ignore"))
            p += l
        name = ".".join(x for x in labels if x) or "?"
        return name, p

    # ---------- housekeeping ----------

    def _log_rate(self, msg: str):
        t = time.time()
        h = hash(msg)
        if t - self._recent.get(h, 0.0) >= self._recent_window:
            self._recent[h] = t
            self.log.log_message(msg)

    def _maybe_gc(self):
        now = time.time()
        if now - self._last_gc < self._gc_interval:
            return
        dead = [k for k, ts in self._pending.items() if now - ts > self._pending_ttl]
        for k in dead:
            self._pending.pop(k, None)
        self._last_gc = now
class TransportNBDSManager:
    """
    UDP/138 NetBIOS Datagram Service (NBDS) parser & logger.

    What it extracts quickly (no heavy reassembly):
      • NBDS header peek: msg_type, flags, dgm_id (best-effort)
      • SMB Trans/Trans2 mailslot path (e.g. \\MAILSLOT\\BROWSE)
      • Browser Service opcodes inside \\MAILSLOT\\BROWSE payloads
      • Short previews, rate-limited to avoid floods

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
    """

    # Browser Service opcodes (subset of the classics)
    _BROWSER_OPCODES = {
        0x01: "HostAnnouncement",
        0x02: "AnnouncementRequest",
        0x08: "DomainAnnouncement",
        0x09: "MasterAnnouncement",
        0x0B: "LocalMasterAnnouncement",
        0x0C: "Election",
        0x0D: "GetBackupListReq",
        0x0E: "GetBackupListResp",
        0x0F: "BecomeBackup",
        0x10: "DomainMasterAnnouncement",
        0x1D: "ResetBrowserState",
    }

    # Simple rate-limit for repeated lines
    _RL_WINDOW_S = 2.0

    def __init__(self, router_logger):
        self.log = router_logger
        self._recent = {}
        try:
            self.log.log_message("[Transport][📦 NBDS] Manager ready.")
        except Exception:
            pass

    # --------------- Public entry ---------------

    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool:
        """
        Recognize UDP/138 and emit compact, helpful lines.
        Always returns True when ports match, even if parsing is partial.
        """
        try:
            from scapy.all import UDP, Raw  # type: ignore
        except Exception:
            UDP = Raw = None  # scapy not available

        if sport != 138 and dport != 138:
            return False
        # Must be UDP to be NBDS
        if UDP is not None and not packet.haslayer(UDP):
            return False

        iface = str(inbound_iface).split("_")[-1]

        payload = b""
        if Raw is not None and packet.haslayer(Raw) and packet[Raw].load:
            payload = bytes(packet[Raw].load or b"")

        # Quick NBDS header peek (best-effort)
        msg_type, flags, dgm_id = self._peek_nbds_header(payload)

        # Hunt for mailslot path (SMB Trans/Trans2 over NBT Datagram)
        mailslot = self._find_mailslot_path(payload)

        # Browser Service decode if BROWSE mailslot
        br = None
        if mailslot and mailslot.upper().endswith("\\BROWSE"):
            br = self._parse_browser_message(payload)

        # Compose log
        extra = []
        if msg_type is not None:
            extra.append(f"msg={msg_type}")
        if flags is not None:
            extra.append(f"flags=0x{flags:02x}")
        if dgm_id is not None:
            extra.append(f"id=0x{dgm_id:04x}")
        if mailslot:
            extra.append(f"mailslot={mailslot}")
        if br:
            op, host, dom = br.get("op"), br.get("host"), br.get("domain")
            opn = self._BROWSER_OPCODES.get(op, f"0x{op:02x}") if isinstance(op, int) else str(op)
            details = f"op={opn}"
            if host:
                details += f" host={host}"
            if dom:
                details += f" domain={dom}"
            extra.append(f"browser[{details}]")

        size = len(payload)
        line = (f"[Transport][📦 NBDS] if={iface} {src_ip}:{sport} → {dst_ip}:{dport} "
                f"size={size}B " + (" ".join(extra) if extra else "-"))

        self._rate_log(line)

        # If nothing was recognized but we know it's 138/UDP, still claim it
        return True

    # --------------- Parsers / heuristics ---------------

    def _peek_nbds_header(self, data: bytes):
        """
        RFC 1002 NetBIOS Datagram header (simplified):
          0: MSG_TYPE (1B)
          1: FLAGS (1B)
          2-3: DGM_ID (2B)
          ... (we skip lengths/names for speed)
        Returns (msg_type, flags, dgm_id) or (None, None, None) if too short.
        """
        if len(data) < 4:
            return None, None, None
        msg_type = data[0]
        flags = data[1]
        dgm_id = (data[2] << 8) | data[3]
        return msg_type, flags, dgm_id

    def _find_mailslot_path(self, data: bytes) -> str | None:
        """
        Look for SMB mailslot name inside NBDS payload.
        We scan for ASCII '\\MAILSLOT\\...' up to a terminator (NUL or non-printable run).
        """
        # Try both single & double backslash encodings
        needles = (b"\\MAILSLOT\\", b"\\\\MAILSLOT\\\\")
        idx = -1
        needle = None
        for n in needles:
            idx = data.find(n)
            if idx >= 0:
                needle = n
                break
        if idx < 0:
            return None

        # Read until NUL or newline or non-ASCII
        j = idx + len(needle)
        while j < len(data):
            b = data[j]
            if b == 0 or b in (10, 13) or b < 0x20:
                break
            # stop at a space after the path
            if b == 0x20:
                break
            j += 1

        raw = data[idx:j]
        try:
            s = raw.decode("utf-8", "ignore")
        except Exception:
            s = "\\MAILSLOT\\?"
        # Normalize double slashes
        s = s.replace("\\\\", "\\")
        return s

    def _parse_browser_message(self, data: bytes) -> dict | None:
        """
        Very light Browser Service decoder inside \\MAILSLOT\\BROWSE payloads.
        SMB Trans mailslot payload layout varies; we heuristically locate:
          [opcode (1B)] [minor_ver (1B)] [major_ver (1B)] [...] then ASCII strings.
        We try to extract opcode, host name, and domain/workgroup name.
        """
        # Find start of mailslot content: right after the mailslot path string
        mi = data.find(b"\\MAILSLOT\\BROWSE")
        if mi < 0:
            mi = data.find(b"\\\\MAILSLOT\\\\BROWSE")
        if mi < 0:
            return None

        # Skip path bytes + a small safety window to jump into payload
        # Often you see: path\0 then payload
        start = data.find(b"\x00", mi)
        if start < 0:
            start = mi + len("\\MAILSLOT\\BROWSE")
        else:
            start += 1

        # We’ll scan forward a bit to find a plausible opcode
        view = memoryview(data[start:start+256])
        if len(view) < 1:
            return None

        op = view[0]  # heuristic: many messages place opcode immediately
        # Try to pull ASCII tokens that look like NetBIOS names
        tail = bytes(view[1:])
        toks = self._pick_ascii_tokens(tail, max_tokens=6)

        host = None
        domain = None
        # Common patterns: host and domain appear early
        for t in toks:
            tU = t.upper()
            if not host and t and tU not in ("BROWSE", "ELECTION", "DOMAIN", "WORKGROUP"):
                host = t
                continue
            if not domain and (t.endswith("$") or t.isupper()):
                domain = t
                break

        return {"op": op, "host": host, "domain": domain}

    # --------------- Helpers ---------------

    def _pick_ascii_tokens(self, b: bytes, max_tokens: int = 6) -> list[str]:
        """
        Extract a few printable tokens (A..Z, a..z, 0..9, _-. $) separated by NULs or control chars.
        """
        out = []
        cur = []
        for ch in b:
            if 32 <= ch <= 126:
                cur.append(chr(ch))
            else:
                if cur:
                    out.append("".join(cur))
                    cur = []
                    if len(out) >= max_tokens:
                        break
        if cur and len(out) < max_tokens:
            out.append("".join(cur))
        return out

    def _rate_log(self, line: str):
        try:
            now = time.time()
            h = hash(line)
            last = self._recent.get(h, 0.0)
            if now - last >= self._RL_WINDOW_S:
                self._recent[h] = now
                self.log.log_message(line)
        except Exception:
            # Fall back to best effort
            try:
                self.log.log_message(line)
            except Exception:
                pass
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

        if 546 in (sport, dport) or 547 in (sport, dport):
            if DHCP6 is not None and (
                packet.haslayer(DHCP6_Solicit) or
                (packet.haslayer(DHCP6) and getattr(packet[DHCP6], "msgtype", None) == 1)
            ):
                self.logger.log_message("[Transport][🚀 UDP][⚙️ DHCPv6] 🛰️ SOLICIT seen;")
                return False
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
                    return True

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
        return False

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

    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool:
        if Raw is None:
            return False
        is_udp = UDP is not None and packet.haslayer(UDP)
        is_tcp = TCP is not None and packet.haslayer(TCP)
        if not (is_udp or is_tcp):
            return False
        if not (sport == 88 or dport == 88):
            return False

        iface = inbound_iface.split("_")[-1]
        direction = "REQ" if dport == 88 else "RSP"

        if not packet.haslayer(Raw):
            self._rate_log(f"[Transport][🚀 UDP][🔑 Kerberos] {direction} if={iface} "
                           f"{src_ip}:{sport} → {dst_ip}:{dport} (no payload)")
            return True

        payload = bytes(packet[Raw].load or b"")

        # TCP: strip the 4-byte length (RFC 4120 §7.2.2)
        if is_tcp:
            if len(payload) < 4:
                return True
            frag_len = int.from_bytes(payload[:4], "big", signed=False)
            payload = payload[4:4 + frag_len] if frag_len and 4 + frag_len <= len(payload) else payload[4:]

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
        sample = data[:800]
        for m in self._REALM_RE.finditer(sample):
            tok = m.group(0)
            if b"." not in tok:  # must have at least one dot
                continue
            if tok.count(b".") > 5:  # avoid huge dotted noise
                continue
            if tok.startswith(b".") or tok.endswith(b"."):
                continue
            # avoid obvious IPs like 1.2.3.4
            if all(part.isdigit() and 0 <= int(part) <= 255 for part in tok.split(b".") if part.isdigit()):
                continue
            try:
                s = tok.decode("ascii", "ignore")
                if s.isupper():
                    return s
            except Exception:
                pass
        return None

    def _guess_spn(self, data: bytes) -> Optional[str]:
        sample = data[:1200].lower()
        for hint in self._SPN_HINTS:
            i = sample.find(hint)
            if i < 0:
                continue
            j = i
            # read printable run
            while j < len(sample) and 32 <= sample[j] <= 126:
                j += 1
            cand = data[i:j].decode("utf-8", "ignore").strip(",; ")
            # quick cleanups
            cand = cand.replace("\\", "/")
            if len(cand) >= 6 and "/" in cand:
                return cand
        # fallback: look for '@REALM'
        at = sample.find(b"@")
        if at > 0:
            # back up a bit for the service/host
            start = max(0, at - 64)
            seg = data[start: min(len(data), at + 80)].decode("utf-8", "ignore")
            # pick last token containing '@'
            for token in seg.split():
                if "@" in token and "/" in token and len(token) >= 6:
                    return token.strip(",;")
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
    Optimized for low CPU: budgets, rate-limits, fast-path after first parse.
    """

    # Tunables
    FLOW_TTL_SEC      = 10 * 60
    FLOW_SOFT_MAX     = 50000
    RL_INTERVAL_SEC   = 1.0
    EH_DEPTH_LIMIT    = 16
    HBH_OPT_BUDGET    = 8
    DEST_OPT_BUDGET   = 8
    TAIL_PREVIEW_LEN  = 8
    GC_PERIOD_SEC     = 60

    # NEW: light telemetry toggles (cheap fields only)
    SHOW_TC_DSCP      = True     # IPv6 traffic class / DSCP
    SHOW_PLEN         = True     # IPv6 payload length
    SHOW_ADDR_SCOPE   = True     # LL/ULA/GUA flags

    def __init__(self, router_logger, early_claim_hop_by_hop: bool = True, ext_depth_limit: int = EH_DEPTH_LIMIT):
        self.log = router_logger
        self.early_claim_hbh = bool(early_claim_hop_by_hop)
        self.ext_depth_limit = max(4, int(ext_depth_limit))

        # flow_key -> {"last": ts, "noinspect": bool, "last_log": ts}
        self._flows: Dict[Tuple[str, str, str, str, str], Dict[str, float | bool]] = {}

        # rate-limit cache for ad-hoc messages
        self._rl_last: dict[str, float] = {}
        self._last_gc = time.time()

        self.log.log_message("[Transport][🌍 IPv6] Manager ready.")

    # -------------------- Public entrypoint --------------------
    def handle(self, packet: Packet, inbound_iface: Optional[str] = None) -> bool:
        try:
            if IPv6 is None or not hasattr(packet, "haslayer") or not packet.haslayer(IPv6):
                return False

            ip6 = packet[IPv6]
            src_ip = getattr(ip6, "src", "?")
            dst_ip = getattr(ip6, "dst", "?")
            hlim   = getattr(ip6, "hlim", None)
            flow   = getattr(ip6, "fl", None)
            nh     = getattr(ip6, "nh", None)
            tc     = getattr(ip6, "tc", None)
            plen   = getattr(ip6, "plen", None)
            iface_short = (inbound_iface or "").split("_")[-1] if inbound_iface else "?"

            # Compute flow key cheaply (includes NH & iface to keep logs tidy)
            fkey = (src_ip, dst_ip, str(nh), str(hlim), iface_short)
            now = time.time()
            st = self._flows.get(fkey)
            if st is None:
                st = {"last": now, "last_log": 0.0, "noinspect": False}
                self._flows[fkey] = st
            else:
                st["last"] = now

            # Fast-path: if flow already marked noinspect, emit minimal periodic line and bail
            if st.get("noinspect", False):
                if self._should_log_flow(st, now):
                    extras = [f"NH={self._nh_name(nh)}", f"hlim={hlim}", f"fl={self._fmt_flow(flow)}"]
                    if self.SHOW_TC_DSCP and tc is not None:
                        extras.append(self._fmt_tc(tc))
                    if self.SHOW_PLEN and plen is not None:
                        extras.append(f"plen={int(plen)}")
                    if self.SHOW_ADDR_SCOPE:
                        extras.append(self._fmt_scope(src_ip, dst_ip))
                    msg = f"[Transport][🌍 IPv6] {src_ip} → {dst_ip} on {iface_short} | " + " ".join(extras)
                    self._safe_log(msg)
                self._maybe_gc(now)
                return True

            # Walk extension headers (bounded)
            chain, l4 = self._walk_ipv6_chain(ip6, self.ext_depth_limit)

            # Compose concise line
            head = [f"[Transport][🌍 IPv6] {src_ip} → {dst_ip} on {iface_short}"]

            # Small, cheap header extras (won't allocate big buffers)
            hdrbits: List[str] = []
            hdrbits.append(f"NH={self._nh_name(nh)}")
            if self.SHOW_TC_DSCP and tc is not None:
                hdrbits.append(self._fmt_tc(tc))
            if self.SHOW_PLEN and plen is not None:
                hdrbits.append(f"plen={int(plen)}")
            hdrbits.append(f"hlim={hlim}")
            hdrbits.append(f"fl={self._fmt_flow(flow)}")
            if self.SHOW_ADDR_SCOPE:
                hdrbits.append(self._fmt_scope(src_ip, dst_ip))
            head.append(" | " + " ".join(hdrbits))

            if chain:
                head.append(" | EH: " + ", ".join(self._summarize_eh(h) for h in chain))

            if l4 is not None:
                head.append(" | L4: " + self._summarize_l4(l4))
            else:
                # No recognized L4 — quick opaque tail hint (no bytes rebuild)
                tail = self._get_tail_bytes(ip6)
                tail_len = len(tail)
                tail_kind = "none" if nh == 59 or tail_len == 0 else "raw"
                extras: List[str] = []
                if tail_len:
                    try:
                        hex_preview = tail[:self.TAIL_PREVIEW_LEN].hex()
                        extras.append(f"hex={hex_preview}{'…' if tail_len > self.TAIL_PREVIEW_LEN else ''}")
                    except Exception:
                        pass
                head.append(f" | tail={tail_kind}={tail_len}B" + (f" ({', '.join(extras)})" if extras else ""))

            # Emit (rate-limited per flow)
            if self._should_log_flow(st, now):
                self._safe_log("".join(head))

            # Early-claim/fast-path when HBH present (and optionally after any EH parse)
            if self.early_claim_hbh and any(self._isinstance_safe(h, IPv6ExtHdrHopByHop) for h in chain):
                st["noinspect"] = True
            elif chain:
                st["noinspect"] = True

            self._maybe_gc(now)
            return True

        except Exception as e:
            self._rl_log(f"[Transport][🌍 IPv6] error: {e}", interval=3.0)
            return False

    # -------------------- Rate-limited logger --------------------
    def _should_log_flow(self, st: Dict[str, float | bool], now: float) -> bool:
        last = float(st.get("last_log", 0.0) or 0.0)
        if (now - last) >= self.RL_INTERVAL_SEC:
            st["last_log"] = now
            return True
        return False

    def _rl_log(self, msg: str, *, key: Optional[str] = None, interval: float = 3.0, ret=False):
        k = key or msg
        now = time.time()
        last = self._rl_last.get(k, 0.0)
        if (now - last) >= interval:
            self._rl_last[k] = now
            self._safe_log(msg)
        return ret

    def _safe_log(self, msg: str):
        try:
            self.log.log_message(msg)
        except Exception:
            pass

    # -------------------- GC / flow hygiene --------------------
    def _maybe_gc(self, now: float):
        if now - self._last_gc < self.GC_PERIOD_SEC:
            return
        ttl = self.FLOW_TTL_SEC
        if ttl > 0:
            stale = [k for k, v in self._flows.items() if now - float(v.get("last", now)) > ttl]
            for k in stale:
                self._flows.pop(k, None)
        if len(self._flows) > self.FLOW_SOFT_MAX:
            excess = len(self._flows) - self.FLOW_SOFT_MAX
            victims = sorted(self._flows.items(), key=lambda kv: kv[1].get("last", 0.0))[:excess]
            for k, _ in victims:
                self._flows.pop(k, None)
        self._last_gc = now

    # -------------------- Helpers: chain walking --------------------
    def _walk_ipv6_chain(self, ip6: Packet, depth_limit: int) -> Tuple[List[Packet], Optional[Packet]]:
        chain: List[Packet] = []
        layer = getattr(ip6, "payload", None)
        hops = max(1, int(depth_limit))

        while hops > 0 and layer is not None and hasattr(layer, "payload"):
            hops -= 1

            if self._isinstance_safe(layer, (IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment)):
                chain.append(layer)
                layer = getattr(layer, "payload", None)
                continue

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
                lst = getattr(h, "addresses", None)
                naddr = 0
                if lst:
                    try:
                        naddr = len(list(lst))
                    except Exception:
                        naddr = 0
                return f"Routing(type={rtype},segs_left={segs_left},addr={naddr})"
            if self._isinstance_safe(h, IPv6ExtHdrDestOpt):
                return self._summarize_destopt(h)
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
            if not opts:
                return " ".join(items)
            names = []
            count = 0
            for o in opts:
                if count >= self.HBH_OPT_BUDGET:
                    names.append("…")
                    break
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
                    typ = getattr(o, "otype", None)
                    names.append(name if typ is None else f"{name}(t={typ})")
                count += 1
            if names:
                items.append("[" + ",".join(names) + "]")
        except Exception:
            pass
        return " ".join(items)

    def _summarize_destopt(self, dopt: Packet) -> str:
        try:
            opts = getattr(dopt, "options", None)
            if not opts:
                return "DestOpt"
            names = []
            count = 0
            for o in opts:
                if count >= self.DEST_OPT_BUDGET:
                    names.append("…")
                    break
                name = getattr(o, "name", None) or o.__class__.__name__
                if "Pad" in name:
                    plen = getattr(o, "optlen", None) or getattr(o, "len", None)
                    names.append(f"Pad{'' if plen is None else f'={plen}'}")
                else:
                    typ = getattr(o, "otype", None)
                    names.append(name if typ is None else f"{name}(t={typ})")
                count += 1
            return "DestOpt[" + ",".join(names) + "]"
        except Exception:
            return "DestOpt"

    # ---- L4 summary (richer, but still cheap) ---------------------------------
    def _summarize_l4(self, l4: Packet) -> str:
        try:
            # TCP
            if TCP and self._isinstance_safe(l4, TCP):
                flags = getattr(l4, "flags", 0)
                sport = getattr(l4, "sport", "?"); dport = getattr(l4, "dport", "?")
                fstr = self._tcp_flags_str(flags)
                # Try to expose light extras without bytes() building
                win = getattr(l4, "window", None)
                opt_cnt = 0
                try:
                    opts = getattr(l4, "options", None)
                    if isinstance(opts, list):
                        opt_cnt = len(opts)
                except Exception:
                    pass
                extras = [f"flags={fstr or flags}"]
                if win is not None:
                    extras.append(f"win={win}")
                if opt_cnt:
                    extras.append(f"opts={opt_cnt}")
                return f"TCP {sport}→{dport} " + " ".join(extras)

            # UDP
            if UDP and self._isinstance_safe(l4, UDP):
                sport = getattr(l4, "sport", "?"); dport = getattr(l4, "dport", "?")
                tag = self._udp_tag(int(sport) if isinstance(sport, int) else sport,
                                    int(dport) if isinstance(dport, int) else dport,
                                    l4)
                return f"UDP {sport}→{dport}{(' ' + tag) if tag else ''}"

            # ICMPv6
            if ICMPv6 and self._isinstance_safe(l4, ICMPv6):
                t = getattr(l4, "type", "?"); c = getattr(l4, "code", "?")
                name = self._icmp6_name(int(t) if isinstance(t, int) else None, int(c) if isinstance(c, int) else None)
                # Neighbor Discovery tiny hint (options count)
                nd_hint = ""
                try:
                    # Scapy models ND as specific ICMPv6 subclasses; we only show count if cheaply available
                    opts = getattr(l4, "options", None)
                    if isinstance(opts, list) and opts:
                        nd_hint = f" opts={len(opts)}"
                except Exception:
                    pass
                return f"ICMPv6 type={t} code={c} {name}{nd_hint}".rstrip()

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

    def _fmt_tc(self, tc_val: int) -> str:
        try:
            v = int(tc_val) & 0xFF
            dscp = (v >> 2) & 0x3F
            ecn  = v & 0x03
            return f"tc=0x{v:02x} dscp={dscp} ecn={ecn}"
        except Exception:
            return "tc=?"

    def _fmt_scope(self, src: str, dst: str) -> str:
        try:
            def _scope(ip: str) -> str:
                s = ip.lower()
                if s.startswith("fe80:"): return "LL"   # link-local
                if s.startswith("fc") or s.startswith("fd"): return "ULA"
                return "GUA"
            return f"scope={_scope(src)}→{_scope(dst)}"
        except Exception:
            return "scope=?"

    def _tcp_flags_str(self, flags: int) -> str:
        # scapy may give int; map to letters: CWR/ECE/URG/ACK/PSH/RST/SYN/FIN
        try:
            f = int(flags)
            bits = [
                ("CWR","C"), ("ECE","E"), ("URG","U"), ("ACK","A"),
                ("PSH","P"), ("RST","R"), ("SYN","S"), ("FIN","F"),
            ]
            # scapy packs as bits; we test by numeric mask if available, else fall back
            # Standard order: C E U A P R S F = 0x80..0x01
            masks = [0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01]
            out = []
            for (name, letter), m in zip(bits, masks):
                if f & m:
                    out.append(letter)
            return "".join(out)
        except Exception:
            return ""

    def _udp_tag(self, sport, dport, l4: Packet) -> str:
        """
        Very cheap recognizer for common UDP apps (no parsing). Also tries QUIC? sniff.
        """
        try:
            s = int(sport) if isinstance(sport, int) or str(sport).isdigit() else -1
            d = int(dport) if isinstance(dport, int) or str(dport).isdigit() else -1
        except Exception:
            s, d = -1, -1

        well = {
            53:  "DNS",
            5353:"mDNS",
            546: "DHCPv6-Client",
            547: "DHCPv6-Server",
            123: "NTP",
            1900:"SSDP",
            500: "IKE",
            4500:"IPsec-NAT-T",
            443: "HTTPS/QUIC?",
        }
        label = ""
        for p in (s, d):
            if p in well:
                label = well[p]
                break

        # Tiny QUIC sniff: if UDP:443 and first byte present, print 1-byte preview & '?' tag.
        if (s == 443 or d == 443):
            try:
                raw = getattr(l4, "payload", None)
                lb = getattr(raw, "load", None)
                if isinstance(lb, (bytes, bytearray)) and len(lb) >= 1:
                    # do not parse—just show 1 byte to help triage
                    label = (label or "QUIC?") + f" b0=0x{lb[0]:02x}"
            except Exception:
                pass

        return f"[{label}]" if label else ""

    def _icmp6_name(self, t: Optional[int], c: Optional[int]) -> str:
        if t is None:
            return ""
        names = {
            128: "EchoReq", 129: "EchoReply",
            133: "RS", 134: "RA", 135: "NS", 136: "NA",
            130: "MLDv1-Query", 131: "MLDv1-Report", 132: "MLDv1-Done",
            143: "MLDv2-Report",
            1:   "DstUnreach", 2: "PktTooBig", 3: "TimeExceed", 4: "ParmProb",
        }
        base = names.get(t, "")
        if t in (1, 3, 4) and c is not None:
            # add a tiny code hint for classic errors
            base = f"{base}(code={c})"
        return base

    def _get_tail_bytes(self, ip6: Packet) -> bytes:
        """
        Extract trailing bytes *without* forcing a full build.
        Preference order: .payload.original -> .payload.load -> b"".
        """
        try:
            tail = getattr(ip6, "payload", None)
            if tail is None or isinstance(tail, NoPayload):
                return b""
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

class TransportFileManager:
    """
    File/Device transport observer (low-overhead, best-effort parsing).

    Recognizes:
      • SMB2/3 over TCP/445 (microsoft_ds) and TCP/139 (NetBIOS Session Service)
      • SMB1 signature (legacy)
      • NetBIOS Session Service framing (NBSS) in front of SMB
      • Apple Lockdown / usbmuxd (TCP/62078) — metadata only

    Public API:
      - handle(packet, src_ip, dst_ip, sport, dport, inbound_iface) -> bool
      - snapshot_metrics() -> dict
    """

    # ---- Tunables ----
    FLOW_TTL_SEC        = 10 * 60
    FLOW_SOFT_MAX       = 40_000
    RL_INTERVAL_SEC     = 1.0
    BYTES_BUDGET        = 512
    SMB2_HDR_SIZE       = 64          # canonical SMB2 header size
    NBSS_HDR_SIZE       = 4           # 1 type + 3 length
    LOG_APPLE_LOCKDOWN  = True

    # Known ports
    PORT_SMB            = 445
    PORT_NETBIOS_SSN    = 139
    PORT_APPLE_LOCKDOWN = 62078

    # Minimal SMB2 command map
    _SMB2_CMD = {
        0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
        4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH",
        8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL",
        13: "ECHO", 14: "QUERY_DIR", 15: "CHANGE_NOTIFY", 16: "QUERY_INFO",
        17: "SET_INFO", 18: "OPLOCK_BREAK"
    }

    def __init__(
        self,
        logger,
        *,
        max_bytes_to_peek: int = BYTES_BUDGET,
        logging_enabled: bool = True,
        flow_cache_ttl: int = FLOW_TTL_SEC,
        flow_cache_max: int = FLOW_SOFT_MAX,
        log_lockdown: bool = LOG_APPLE_LOCKDOWN,
    ):
        self.logger = logger
        self._peek_cap = int(max_bytes_to_peek)
        self.logging_enabled = bool(logging_enabled)
        self.flow_cache_ttl = int(flow_cache_ttl)
        self.flow_cache_max = int(flow_cache_max)
        self.log_lockdown = bool(log_lockdown)

        # flow_key -> {first,last,last_log, proto:'SMB2'|'SMB1'|'LOCKDOWN', extras:dict}
        self._flows: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

        self._metrics = {
            "smb_seen": 0,
            "smb1_seen": 0,
            "smb2_seen": 0,
            "smb_cmd_count": 0,
            "lockdown_seen": 0,
            "fast_path_hits": 0,
            "errors": 0,
            "flow_cache_evictions": 0,
        }

        self._safe_log("[Transport][📁 File] Manager ready")

    def snapshot_metrics(self) -> dict:
        return dict(self._metrics)

    # ---------------------------
    # Public entrypoint
    # ---------------------------
    def handle(self, packet, src_ip, dst_ip, sport, dport, inbound_iface: str) -> bool:
        try:
            if not self._pre_checks(packet):
                return False

            now = time.time()
            fkey = self._flow_key(src_ip, sport, dst_ip, dport)
            st = self._flows.get(fkey)
            if st is None:
                st = {"first": now, "last": now, "last_log": 0.0, "proto": None, "extras": {}}
                self._flows[fkey] = st
            else:
                st["last"] = now

            # ---- Apple Lockdown (62078): light classification + logging
            if self._is_lockdown(sport, dport):
                st["proto"] = "LOCKDOWN"
                self._metrics["lockdown_seen"] += 1
                if self.log_lockdown and self._should_log_flow(st, now):
                    self._safe_log(self._fmt_basic("🔌 Lockdown", src_ip, sport, dst_ip, dport, inbound_iface))
                self._clean_if_needed(now)
                return True

            # ---- SMB / NetBIOS (139/445)
            if not self._is_smbish_port(sport, dport):
                return False

            raw = self._get_raw_bytes(packet)
            if not raw:
                st["proto"] = st.get("proto") or "SMB?"
                if self._should_log_flow(st, now):
                    self._safe_log(self._fmt_basic("📁 SMB", src_ip, sport, dst_ip, dport, inbound_iface))
                self._metrics["smb_seen"] += 1
                self._clean_if_needed(now)
                return True

            mv = memoryview(raw)
            # Strip NBSS header if present
            offset = 0
            if len(mv) >= 4 and mv[0] in (0x00, 0x81, 0x82, 0x83):
                offset = self.NBSS_HDR_SIZE

            # SMB2 magic
            if len(mv) >= offset + 4 and mv[offset] == 0xFE and mv[offset+1:offset+4].tobytes() == b"SMB":
                st["proto"] = "SMB2"
                self._metrics["smb2_seen"] += 1
                cmd = self._peek_smb2_command(mv, offset)
                if cmd is not None:
                    st["extras"]["cmd"] = cmd
                    self._metrics["smb_cmd_count"] += 1

                if self._should_log_flow(st, now):
                    cmd_name = self._SMB2_CMD.get(cmd, str(cmd)) if cmd is not None else "-"
                    self._safe_log(
                        self._fmt_basic("📁 SMB2", src_ip, sport, dst_ip, dport, inbound_iface) +
                        f" cmd={cmd_name}"
                    )
                self._metrics["smb_seen"] += 1
                self._clean_if_needed(now)
                return True

            # SMB1 signature
            if len(mv) >= offset + 4 and mv[offset] == 0xFF and mv[offset+1:offset+4].tobytes() == b"SMB":
                st["proto"] = "SMB1"
                self._metrics["smb1_seen"] += 1
                if self._should_log_flow(st, now):
                    self._safe_log(self._fmt_basic("📁 SMB1", src_ip, sport, dst_ip, dport, inbound_iface))
                self._metrics["smb_seen"] += 1
                self._clean_if_needed(now)
                return True

            return False

        except Exception:
            self._metrics["errors"] += 1
            return False

    # ---------------------------
    # Internals
    # ---------------------------
    def _peek_smb2_command(self, mv: memoryview, base: int) -> Optional[int]:
        # Command at +12 (2 bytes, LE)
        if len(mv) < base + 16:
            return None
        return int(mv[base + 12] | (mv[base + 13] << 8))

    def _is_smbish_port(self, sport: int, dport: int) -> bool:
        return (sport in (self.PORT_SMB, self.PORT_NETBIOS_SSN) or
                dport in (self.PORT_SMB, self.PORT_NETBIOS_SSN))

    def _is_lockdown(self, sport: int, dport: int) -> bool:
        return (sport == self.PORT_APPLE_LOCKDOWN) or (dport == self.PORT_APPLE_LOCKDOWN)

    # Utilities (mirror style of your managers)
    def _pre_checks(self, pkt) -> bool:
        if TCP is None:
            return False
        return bool(pkt and pkt.haslayer(TCP) and (pkt.haslayer(IP) or pkt.haslayer(IPv6)))

    def _get_raw_bytes(self, pkt) -> bytes:
        if Raw is None or not pkt.haslayer(Raw):
            return b""
        try:
            return bytes(pkt[Raw].load)[: self._peek_cap] or b""
        except Exception:
            return b""

    def _flow_key(self, src_ip: str, sport: int, dst_ip: str, dport: int):
        a = (str(src_ip), str(int(sport)))
        b = (str(dst_ip), str(int(dport)))
        first, second = (a, b) if a <= b else (b, a)
        return first + second

    def _should_log_flow(self, st: Dict[str, Any], now: float) -> bool:
        last = st.get("last_log", 0.0)
        if (now - last) >= self.RL_INTERVAL_SEC:
            st["last_log"] = now
            return True
        return False

    def _fmt_basic(self, tag: str, src_ip, sport, dst_ip, dport, inbound_iface) -> str:
        return (f"[Transport][🧵 TCP][{tag}] "
                f"{src_ip}:{sport} → {dst_ip}:{dport} on {self._iface_suffix(inbound_iface)}")

    def _iface_suffix(self, inbound_iface: str) -> str:
        try:    return inbound_iface.split("_")[-1]
        except: return inbound_iface or ""

    def _safe_log(self, msg: str):
        if not self.logging_enabled:
            return
        try:    self.logger.log_message(msg)
        except: pass

    def _clean_if_needed(self, now_ts: float):
        total = self._metrics["smb_seen"] + self._metrics["lockdown_seen"]
        if total % 2048 == 0:
            ttl = self.flow_cache_ttl
            if ttl > 0:
                stale = [k for k, v in self._flows.items() if now_ts - v.get("last", now_ts) > ttl]
                for k in stale:
                    self._flows.pop(k, None)
        if len(self._flows) > self.flow_cache_max:
            excess = len(self._flows) - self.flow_cache_max
            victims = sorted(self._flows.items(), key=lambda kv: kv[1].get("last", 0.0))[:excess]
            for k, _ in victims:
                self._flows.pop(k, None)
            self._metrics["flow_cache_evictions"] += excess
class TransportOverlayManager:
    """
    Overlay / virtual-network control traffic (e.g., mesh/overlay controllers).

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool

    Design goals:
      • Hot path stays branchy but O(1) with tiny, bounded structures
      • Zero-copy reads via memoryview for classification
      • Aggressive but cheap GC by wall-clock
      • Token-bucket + per-flow cooldown to avoid log storms
    """

    # -------- Tunables (kept small to avoid cache thrash) --------
    OVERLAY_PORTS          = {9993}      # ZeroTier by default; extend if needed
    PEER_TTL_S             = 600.0       # age-out for peer_seen entries
    GC_PERIOD_S            = 60.0        # housekeeping cadence
    HELLO_FP_TTL_S         = 300.0       # hash "hello-ish" payloads TTL
    HELLO_FP_MAX           = 1024        # max distinct "hello" fingerprints kept
    HELLO_FP_PREFIX_BYTES  = 32          # prefix to hash for hello/data FP
    MIN_KEEPALIVE_BYTES    = 8           # under this is considered keepalive
    SMALL_CTRL_MAX_BYTES   = 160         # small control packets likely <~160B

    # logging governors
    LOG_RPS                = 2.0         # avg logs/sec globally
    LOG_BURST              = 40          # burst
    FLOW_COOLDOWN_S        = 15.0        # per 5-tuple min seconds between logs
    FLOW_TRACK_MAX         = 20000       # soft cap for cooldown map

    def __init__(self, router_logger, peer_timeout: int = 600):
        self.logger = router_logger
        self.PEER_TTL_S = float(peer_timeout) if peer_timeout else self.PEER_TTL_S

        # Peer last-seen (direction-agnostic)
        self._peer_seen: Dict[Tuple[str, str], float] = {}

        # Hello fingerprint cache: fp -> last_ts (Ordered LRU with TTL)
        self._hello_fp = OrderedDict()

        # Token bucket + cooldown
        self._tokens = float(self.LOG_BURST)
        self._last_refill = time.time()
        self._cooldown_until: Dict[Tuple[str, int, str, int, str], float] = {}

        # Overlay/ZeroTier peer table (thread-safe; used by optional helpers)
        self._zt_peers_lock = threading.RLock()
        self._zt_peers: Dict[str, Dict[str, Union[set, dict, float]]] = {}  # peer_id -> {ips,set; meta,dict; last_seen,float}
        self._zt_ip_index: set[str] = set()
        self._zt_ttl: float = 60.0

        self._last_gc = self._last_refill
        self.logger.log_message("[Transport][🛰️ Overlay] Manager ready.")

    # -------------------- Public entry point --------------------
    def handle(
        self,
        packet: "Packet",
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        inbound_iface: Optional[str] = None,
    ) -> bool:
        """Returns True if considered overlay traffic (and possibly logged), else False."""
        if not self._is_overlay_port(sport, dport):
            return False
        if self._zt_is_peer(src_ip) or self._zt_is_peer(dst_ip):
            self.logger.log_message(
                f"[Transport][🚀 UDP][🛰️ Overlay] P2P data {src_ip}:{sport} → {dst_ip}:{dport}"
            )
        # Fast path: raw payload?
        has_raw = (Raw is not None) and packet.haslayer(Raw)
        raw_data = packet[Raw].load if has_raw else b""
        payload_len = len(raw_data) if raw_data else 0

        # Build 5-tuple key once (include iface suffix for locality)
        iface = self._iface_suffix(inbound_iface)
        fkey = (str(src_ip), int(sport), str(dst_ip), int(dport), iface)

        # Summarize classification cheaply (zero-copy)
        kind, fp8 = self._classify_payload(raw_data) if payload_len else ("NoPayload", None)

        # Track peer (direction-agnostic)
        self._note_peer(src_ip, dst_ip)

        # Decide logging (skip ack/no-payload spam unless first time in a while)
        if not self._should_log(fkey, payload_len, kind):
            self._maybe_gc()
            return True

        # Emit concise one-liner
        parts = [f"[Transport][🚀 UDP][🛰️ Overlay] {src_ip}:{sport} → {dst_ip}:{dport} if={iface}"]
        parts.append(f"| Kind={kind}")
        if fp8:
            parts.append(f"fp={fp8}")
        if payload_len:
            parts.append(f"len={payload_len}")
        self.logger.log_message(" ".join(parts))

        self._maybe_gc()
        return True

    # -------------------- Helpers & classifiers --------------------
    def _is_overlay_port(self, sport: int, dport: int) -> bool:
        # Branchless membership checks are cheap; keep set small
        return (sport in self.OVERLAY_PORTS) or (dport in self.OVERLAY_PORTS)

    def _iface_suffix(self, inbound_iface: Optional[str]) -> str:
        try:
            return (inbound_iface or "").split("_")[-1]
        except Exception:
            return inbound_iface or ""

    def _note_peer(self, a_ip: str, b_ip: str) -> None:
        # Order deterministically; avoid tuple churn in hot path
        s, d = (str(a_ip), str(b_ip))
        key = (s, d) if s <= d else (d, s)
        self._peer_seen[key] = time.time()

    def _classify_payload(self, raw: bytes) -> Tuple[str, Optional[str]]:
        """
        Heuristic classification:
          • len < MIN_KEEPALIVE_BYTES -> Keepalive
          • small, repeating prefixes -> Control/Hello (fingerprinted)
          • else -> Data or Control (size-based)
        Returns (kind, fp8_or_None).
        """
        try:
            mv = memoryview(raw)
            n = len(mv)
            if n < self.MIN_KEEPALIVE_BYTES:
                return ("Keepalive", None)

            # Compute a tiny prefix hash (first 32B) for stable identity
            pref = mv[:self.HELLO_FP_PREFIX_BYTES]
            fp8 = hashlib.sha1(pref).hexdigest()[:8]

            now = time.time()
            # Small controls are often highly repetitive; LRU/TTL them
            if n <= self.SMALL_CTRL_MAX_BYTES:
                self._hello_fp[fp8] = now
                self._hello_fp.move_to_end(fp8, last=True)
                # trim if beyond max
                if len(self._hello_fp) > self.HELLO_FP_MAX:
                    self._hello_fp.popitem(last=False)
                return ("Control/Hello", fp8)

            # Larger than "small control"
            # Some overlays encrypt control after bootstrap; still useful to tag Data/Control-ish
            # If we have seen the same fp recently, call it Control (encrypted/control)
            last = self._hello_fp.get(fp8)
            if last and (now - last) <= self.HELLO_FP_TTL_S:
                return ("Control", fp8)
            return ("Data", fp8)
        except Exception:
            return ("Unknown", None)

    # -------------------- Log throttling --------------------
    def _should_log(self, fkey: Tuple[str, int, str, int, str], payload_len: int, kind: str) -> bool:
        """
        Global token-bucket + per-flow cooldown.
        Priority bump for Control/Hello or bigger payloads (informative).
        """
        now = time.time()

        # Per-flow cooldown
        until = self._cooldown_until.get(fkey, 0.0)
        if now < until:
            return False

        # Refill global tokens
        dt = max(0.0, now - self._last_refill)
        if dt:
            self._tokens = min(self.LOG_BURST, int(self._tokens + dt * self.LOG_RPS))
            self._last_refill = now

        # Base cost
        base_cost = 1.0

        # Importance bump
        important = (kind != "NoPayload") and (kind.startswith("Control") or payload_len >= self.SMALL_CTRL_MAX_BYTES)
        cost = 0.5 if important else 1.0  # cheaper for important so they fit more often

        if self._tokens >= cost:
            self._tokens -= cost
            # Set cooldown (shorter for important, longer for noise)
            cd = self.FLOW_COOLDOWN_S * (0.5 if important else 1.0)
            self._cooldown_until[fkey] = now + cd
            # Soft-cap map
            if len(self._cooldown_until) > self.FLOW_TRACK_MAX:
                # Drop ~1% oldest
                # (avoid O(n log n): scan linear and remove earliest few)
                threshold = now - self.FLOW_COOLDOWN_S
                removed = 0
                for k, t in list(self._cooldown_until.items()):
                    if t < threshold:
                        self._cooldown_until.pop(k, None)
                        removed += 1
                        if removed >= max(1, self.FLOW_TRACK_MAX // 100):
                            break
            return True

        # No tokens—skip
        return False

    # -------------------- Housekeeping --------------------
    def _maybe_gc(self) -> None:
        now = time.time()
        if now - self._last_gc < self.GC_PERIOD_S:
            return

        # Peer TTL
        cutoff = now - self.PEER_TTL_S
        for k, ts in list(self._peer_seen.items()):
            if ts < cutoff:
                self._peer_seen.pop(k, None)

        # Hello FP TTL
        fp_cut = now - self.HELLO_FP_TTL_S
        for fp, ts in list(self._hello_fp.items()):
            if ts < fp_cut:
                self._hello_fp.pop(fp, None)

        self._last_gc = now

    # -------------------- Optional ZeroTier helpers (fixed & safe) --------------------
    @property
    def zt_ttl(self) -> float:
        return self._zt_ttl

    def set_zt_ttl(self, seconds: Union[int, float]) -> None:
        self._zt_ttl = max(1.0, float(seconds))
        self.logger.log_message(f"[Transport][🛰️ Overlay] TTL set to {self._zt_ttl:.0f}s")

    def _zt__ensure_state(self):
        """Create/repair overlay containers (safe across interpreters/hot-reloads)."""
        # Figure out the concrete RLock instance type on this interpreter
        try:
            _RLOCK_TYPE = type(threading.RLock())
        except Exception:
            _RLOCK_TYPE = None  # fall back to duck-typing

        # Ensure lock
        lk = getattr(self, "_zt_peers_lock", None)
        if not (lk and hasattr(lk, "acquire") and hasattr(lk, "release")):
            self._zt_peers_lock = threading.RLock()

        # Ensure peer tables
        if not hasattr(self, "_zt_peers") or not isinstance(self._zt_peers, dict):
            self._zt_peers = {}

        if not hasattr(self, "_zt_ip_index") or not isinstance(self._zt_ip_index, set):
            self._zt_ip_index = set()

        # Optional: TTL default
        if not hasattr(self, "_zt_ttl"):
            self._zt_ttl = 60.0

    def _zt_set_peers(self, peers: Optional[Dict[str, dict]]) -> None:
        """
        Replace the overlay peer table safely.
        Expected: {peer_id: {"ips": iterable[str], ...}, ...}
        """
        self._zt__ensure_state()
        with self._zt_peers_lock:
            self._zt_peers.clear()
            self._zt_ip_index.clear()
            if not peers:
                return
            now = time.time()
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
                self._zt_peers[pid] = {"ips": ips, "meta": rec, "last_seen": now}
                self._zt_ip_index.update(ips)

    def _zt_add_peer(self, peer_id: str, ips: Union[list, set, tuple]) -> None:
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

    def _zt_remove_peer(self, peer_id: str) -> None:
        self._zt__ensure_state()
        with self._zt_peers_lock:
            rec = self._zt_peers.pop(peer_id, None)
            if not rec:
                return
            ips = rec.get("ips") or set()
            # Remove IPs that aren't referenced by any other peer
            still_used = set()
            for r in self._zt_peers.values():
                still_used.update(r.get("ips") or set())
            for ip in ips:
                if ip not in still_used and ip in self._zt_ip_index:
                    self._zt_ip_index.remove(ip)

    # --- Convenience: path for recognized overlay types (e.g., ZeroTier hello) ---
    def _handle_overlay_packet(self, pkt, src, dst, sport, dport, iface):
        """If your higher-level detector says 'this is ZeroTier', call this."""
        self._zt_note_peer(src, sport)
        self._zt_note_peer(dst, dport)
        self.logger.log_message(f"[Transport][🚀 UDP][🛰️ Overlay] {src}:{sport} → {dst}:{dport} | Control/Hello")

    def _zt_note_peer(self, ip: str, port: int) -> None:
        self._zt__ensure_state()
        ip = str(ip)
        port = int(port)
        with self._zt_peers_lock:
            e = self._zt_peers.get(ip)
            if not e:
                e = {"ports": set(), "ts": 0.0}
                self._zt_peers[ip] = e
            e["ports"].add(port)
            e["ts"] = time.time()

    def _zt_is_peer(self, ip: str) -> bool:
        self._zt__ensure_state()
        now = time.time()
        with self._zt_peers_lock:
            for k, v in list(self._zt_peers.items()):
                if now - v.get("ts", 0.0) > self._zt_ttl:
                    self._zt_peers.pop(k, None)
            return ip in self._zt_peers
class TransportWireGuardManager:
    """
    Passive WireGuard observer. Detects WG v1 messages on UDP:
      • Type 1: Handshake Initiation
      • Type 2: Handshake Response
      • Type 3: Cookie Reply
      • Type 4: Transport Data (incl. keepalives)

    Notes:
      - WG can run on ANY UDP port (not just 51820).
      - We don't decrypt; we only parse public header fields.
      - Purely observational: never blocks or mutates packets.
    """

    # Typical lengths (not strict; vendors differ slightly):
    #   Initiation: ~148 bytes
    #   Response:   ~92 bytes
    #   Cookie:     ~64 bytes
    #   Data:       >= 32 bytes (header 16 + encrypted payload)
    #
    # We'll be tolerant—only header fields are required for detection.
    RL_WINDOW_SEC = 2.0  # rate-limit identical messages
    FLOW_TTL_SEC  = 300

    def __init__(self, router_logger):
        self.log = router_logger
        self._flows = {}  # key -> {last_seen, pkts, bytes}
        self._recent = defaultdict(float)
        self.log.log_message("[Transport][🔐 WireGuard] Manager ready.")

    # -------- public API --------
    def handle(self, pkt, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool:
        """
        Returns True if this packet was recognized/logged as WireGuard.
        """
        raw = self._payload(pkt)
        if not raw:
            return False

        mtype = self._peek_type(raw)
        if mtype is None:
            return False  # not WG

        # keep minimal per-flow stats
        key = self._key(src_ip, sport, dst_ip, dport)
        f = self._flows.get(key)
        now = time.time()
        if not f:
            f = self._flows[key] = {"last_seen": now, "pkts": 0, "bytes": 0}
        f["last_seen"] = now
        f["pkts"] += 1
        f["bytes"] += len(raw)

        # parse & log
        if mtype == 1:
            info = self._parse_initiation(raw)
            self._rl_log(
                f"[Transport][🚀 UDP][🔐 WireGuard] Handshake Initiation "
                f"{src_ip}:{sport} → {dst_ip}:{dport} | sender_idx={info.get('sender_idx','?')} "
                f"len={len(raw)} on {inbound_iface or '-'}"
            )
            handled = True
        elif mtype == 2:
            info = self._parse_response(raw)
            self._rl_log(
                f"[Transport][🚀 UDP][🔐 WireGuard] Handshake Response "
                f"{src_ip}:{sport} → {dst_ip}:{dport} | sender_idx={info.get('sender_idx','?')} "
                f"receiver_idx={info.get('receiver_idx','?')} len={len(raw)} on {inbound_iface or '-'}"
            )
            handled = True
        elif mtype == 3:
            info = self._parse_cookie(raw)
            self._rl_log(
                f"[Transport][🚀 UDP][🔐 WireGuard] Cookie Reply "
                f"{src_ip}:{sport} → {dst_ip}:{dport} | receiver_idx={info.get('receiver_idx','?')} "
                f"len={len(raw)} on {inbound_iface or '-'}"
            )
            handled = True
        elif mtype == 4:
            info = self._parse_data(raw)
            # keepalives are type=4 with zero-length encrypted payload (header-only)
            keepalive = " keepalive" if info.get("is_keepalive") else ""
            self._rl_log(
                f"[Transport][🚀 UDP][🔐 WireGuard] Data{keepalive} "
                f"{src_ip}:{sport} → {dst_ip}:{dport} | receiver_idx={info.get('receiver_idx','?')} "
                f"counter={info.get('counter','?')} len={len(raw)} on {inbound_iface or '-'}"
            )
            handled = True
        else:
            handled = False
        self._gc()
        return handled

    # -------- detection & parsing --------
    @staticmethod
    def _payload(pkt):
        try:
            from scapy.packet import Raw
            if pkt.haslayer(Raw):
                return bytes(pkt[Raw].load or b"")
        except Exception:
            pass
        return b""

    @staticmethod
    def _peek_type(b: bytes):
        # WG v1 messages start with 1 byte type (1..4) then 3 reserved bytes (zeros).
        if len(b) < 4:
            return None
        mtype = b[0]
        if mtype not in (1, 2, 3, 4):
            return None
        # reserved must be zero most of the time; be tolerant but check common case
        if b[1] == 0 and b[2] == 0 and b[3] == 0:
            return mtype
        # Some implementations preserve zeros; if not zero, treat as not WG to avoid FPs
        return None

    @staticmethod
    def _u32(b, off):
        try:
            return struct.unpack_from("<I", b, off)[0]
        except struct.error:
            return None

    @staticmethod
    def _u64(b, off):
        try:
            return struct.unpack_from("<Q", b, off)[0]
        except struct.error:
            return None

    def _parse_initiation(self, b: bytes) -> dict:
        # layout: type(1) + rsv(3) + sender_idx(4) + ... (rest opaque)
        return {"sender_idx": self._u32(b, 4)}

    def _parse_response(self, b: bytes) -> dict:
        # layout: type(1)+rsv(3)+sender_idx(4)+receiver_idx(4)+...
        return {
            "sender_idx":   self._u32(b, 4),
            "receiver_idx": self._u32(b, 8),
        }

    def _parse_cookie(self, b: bytes) -> dict:
        # layout: type(1)+rsv(3)+receiver_idx(4)+nonce(24)+cookie(16)+...
        return {"receiver_idx": self._u32(b, 4)}

    def _parse_data(self, b: bytes) -> dict:
        # layout: type(1)+rsv(3)+receiver_idx(4)+counter(8)+encrypted...
        info = {
            "receiver_idx": self._u32(b, 4),
            "counter":      self._u64(b, 8),
            "is_keepalive": False
        }
        # minimal header is 16 bytes; keepalive often has exactly header and zero payload
        info["is_keepalive"] = (len(b) == 16)
        return info

    # -------- utils --------
    @staticmethod
    def _key(a_ip, a_p, b_ip, b_p):
        A, B = (a_ip, int(a_p)), (b_ip, int(b_p))
        return (A, B) if A <= B else (B, A)

    def _rl_log(self, msg: str):
        t = time.time()
        last = self._recent.get(msg, 0.0)
        if (t - last) >= self.RL_WINDOW_SEC:
            self._recent[msg] = t
            try:
                self.log.log_message(msg)
            except Exception:
                pass

    def _gc(self):
        now = time.time()
        for k, f in list(self._flows.items()):
            if (now - f.get("last_seen", now)) > self.FLOW_TTL_SEC:
                self._flows.pop(k, None)
class TransportWSDiscoveryManager:
    """
    WS-Discovery (UDP/3702) handler with low-latency parsing and concise logging.

    Public API:
        handle(packet, src_ip, dst_ip, sport, dport, inbound_iface=None) -> bool
    """

    # -------- Tunables (kept conservative for low overhead) --------
    WSD_PORTS = {3702}
    BYTES_BUDGET = 4096  # scan at most this many bytes from payload
    FP_PREFIX_BYTES = 48  # for tiny content fingerprint
    LOG_RPS = 0.1  # average logs per second allowed globally
    LOG_BURST = 1  # global burst capacity
    FLOW_COOLDOWN_S = 10.0  # min seconds between logs for the same 5-tuple
    FLOW_TRACK_MAX = 20000  # soft cap for cooldown map
    GC_PERIOD_S = 60.0  # housekeeping cadence
    PEER_TTL_S = 600.0  # track who talked to whom (light telemetry)

    # Known action suffixes (we look for these inside <wsa:Action>)
    _KNOWN_ACTIONS = (
        b"Probe",
        b"ProbeMatches",
        b"Hello",
        b"Bye",
        b"Resolve",
        b"ResolveMatches",
    )

    def __init__(self, router_logger):
        self.logger = router_logger

        # Token bucket state
        self._tokens = float(self.LOG_BURST)
        self._last_refill = time.time()

        # Per-flow cooldown: (src, sport, dst, dport, iface_suffix) -> next_allowed_ts
        self._cooldown_until: Dict[Tuple[str, int, str, int, str], float] = {}

        # Lightweight peer graph (direction-agnostic)
        self._peer_seen: Dict[Tuple[str, str], float] = {}

        self._last_gc = self._last_refill
        self.logger.log_message("[Transport][🔍 WS-Discovery] Manager ready.")

    # -------------------- Public entry point --------------------
    def handle(
            self,
            packet: "Packet",
            src_ip: str,
            dst_ip: str,
            sport: int,
            dport: int,
            inbound_iface: Optional[str] = None,
    ) -> bool:
        """Return True if handled/logged as WS-Discovery; else False."""
        if not self._is_wsd_port(sport, dport):
            return False

        # Must be UDP with a payload to be interesting
        if Raw is None or not packet.haslayer(Raw):
            return True  # it's WS-D UDP but no payload; nothing to parse

        raw = packet[Raw].load or b""
        if not raw:
            return True

        # Build flow key and cheap classification (zero-copy)
        iface = self._iface_suffix(inbound_iface)
        fkey = (str(src_ip), int(sport), str(dst_ip), int(dport), iface)

        # Parse a few key fields from the SOAP envelope using budgeted scanning
        kind, action, epr, mid = self._parse_wsd_envelope(raw)

        # Decide if we should log (global + per-flow throttle)
        if not self._should_log(fkey, important=(kind != "Unknown")):
            self._note_peer(src_ip, dst_ip)
            self._maybe_gc()
            return True

        # Produce a concise, stable one-liner
        parts = [
            f"[Transport][🚀 UDP][🔍 WS-Discovery] {src_ip}:{sport} → {dst_ip}:{dport} if={iface}",
            f"| Kind={kind}"
        ]
        if action:
            parts.append(f"Action={action}")
        if epr:
            parts.append(f"EPR={epr}")
        if mid:
            parts.append(f"MsgID={mid}")

        # Optional tiny fingerprint (helps collapse near-duplicates)
        fp8 = self._fp8(raw)
        if fp8:
            parts.append(f"fp={fp8}")

        self.logger.log_message(" ".join(parts))

        self._note_peer(src_ip, dst_ip)
        self._maybe_gc()
        return True

    # -------------------- Classifiers / parsers (budgeted) --------------------
    def _parse_wsd_envelope(self, raw: bytes) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
        """
        Budgeted, zero-copy-ish WS-Discovery SOAP dig:
          - Determine Kind (Hello/Bye/Probe/ProbeMatches/Resolve/ResolveMatches/Unknown)
          - Extract Action (string tail, e.g. 'Probe')
          - Extract EPR Address (wsa:Address)
          - Extract MessageID (wsa:MessageID)
        No full XML parse; we just search in a bounded prefix.
        """
        try:
            mv = memoryview(raw)
            cap = min(len(mv), self.BYTES_BUDGET)
            if cap < 16:
                return ("Unknown", None, None, None)

            # Common WS-* elements appear as ASCII/UTF-8 text; be tolerant to whitespace.
            # We scan for <wsa:Action> or <Action ...> first.
            action_text = self._find_tag_text(mv, b"wsa:Action", cap) \
                          or self._find_tag_text(mv, b"Action", cap)

            # Normalize action kind from the tail token (e.g., .../Probe)
            kind = "Unknown"
            action_name = None
            if action_text:
                # Take the last path segment or the QName tail
                tail = action_text.rsplit("/", 1)[-1]
                tail_b = tail.encode("utf-8", "ignore")
                for k in self._KNOWN_ACTIONS:
                    if tail_b.endswith(k):
                        action_name = k.decode("ascii", "ignore")
                        kind = action_name
                        break

            # EndpointReference (Address) and MessageID are handy
            epr = self._find_tag_text(mv, b"wsa:Address", cap) \
                  or self._find_tag_text(mv, b"Address", cap)
            mid = self._find_tag_text(mv, b"wsa:MessageID", cap) \
                  or self._find_tag_text(mv, b"MessageID", cap)

            # If we didn’t find Action but we see typical WS-D namespaces, infer rough kind
            if kind == "Unknown":
                # Look for Probe-like terms in Types/Scopes (best-effort)
                if self._memfind(mv, b":Probe", cap) != -1:
                    kind = "Probe"
                elif self._memfind(mv, b":Hello", cap) != -1:
                    kind = "Hello"
                elif self._memfind(mv, b":Bye", cap) != -1:
                    kind = "Bye"

            return (kind, action_name, epr, mid)
        except Exception:
            return ("Unknown", None, None, None)

    def _find_tag_text(self, mv: memoryview, tag: bytes, cap: int) -> Optional[str]:
        """
        Find <tag> ... </tag> inside the first `cap` bytes (case-insensitive),
        skipping attributes. Returns stripped inner text or None.
        """
        # Lowercase search window (no copy: compare lowercased bytes via casefold-ish trick)
        # We’ll just do case-sensitive search on expected casing first (fast path).
        open_pat = b"<" + tag
        i = self._memfind(mv, open_pat, cap)
        if i == -1:
            # fallback to uppercase WSA (some stacks)
            open_pat2 = b"<" + tag.capitalize()
            i = self._memfind(mv, open_pat2, cap)
            if i == -1:
                return None

        # Move to '>' (end of start tag)
        j = self._memfind(mv, b">", cap, start=i)
        if j == -1 or j + 1 >= cap:
            return None

        # Find closing tag
        close_pat = b"</" + tag + b">"
        k = self._memfind(mv, close_pat, cap, start=j + 1)
        if k == -1:
            # Try capitalized close
            close_pat2 = b"</" + tag.capitalize() + b">"
            k = self._memfind(mv, close_pat2, cap, start=j + 1)
            if k == -1:
                return None

        # Slice inner text safely
        inner = mv[j + 1:min(k, cap)]
        try:
            txt = bytes(inner).decode("utf-8", "ignore").strip()
            # Collapse whitespace
            return " ".join(txt.split()) if txt else None
        except Exception:
            return None

    @staticmethod
    def _memfind(mv: memoryview, sub: bytes, cap: int, start: int = 0) -> int:
        """Like bytes.find but bounded to `cap` without copying."""
        # Convert only the small window to bytes once (bounded)
        # Cap & start guards
        start = max(0, start)
        end = min(len(mv), cap)
        if start >= end:
            return -1
        try:
            return bytes(mv[start:end]).find(sub) + (start if sub in mv[start:end] else 0)
        except Exception:
            # Very defensive fallback
            blk = bytes(mv[:end])
            pos = blk.find(sub, start)
            return pos

    def _fp8(self, raw: bytes) -> Optional[str]:
        """Tiny 8-hex fingerprint of the first FP_PREFIX_BYTES (cheap uniqueness)."""
        try:
            pref = memoryview(raw)[:self.FP_PREFIX_BYTES]
            return hashlib.sha1(pref).hexdigest()[:8]
        except Exception:
            return None

    # -------------------- Throttling & housekeeping --------------------
    def _should_log(self, fkey: Tuple[str, int, str, int, str], important: bool) -> bool:
        """Global token-bucket + per-flow cooldown. 'important' spends fewer tokens."""
        now = time.time()

        # Per-flow cooldown
        until = self._cooldown_until.get(fkey, 0.0)
        if now < until:
            return False

        # Refill tokens
        dt = max(0.0, now - self._last_refill)
        if dt:
            self._tokens = min(self.LOG_BURST, int(self._tokens + dt * self.LOG_RPS))
            self._last_refill = now

        # Spend tokens (important logs are cheaper)
        cost = 0.5 if important else 1.0
        if self._tokens >= cost:
            self._tokens -= cost
            # Shorter cooldown for important items to keep visibility
            cd = self.FLOW_COOLDOWN_S * (0.5 if important else 1.0)
            self._cooldown_until[fkey] = now + cd

            # Soft-cap cooldown map
            if len(self._cooldown_until) > self.FLOW_TRACK_MAX:
                # Drop ~1% oldest by timestamp
                threshold = now - self.FLOW_COOLDOWN_S
                dropped = 0
                for k, t in list(self._cooldown_until.items()):
                    if t < threshold:
                        self._cooldown_until.pop(k, None)
                        dropped += 1
                        if dropped >= max(1, self.FLOW_TRACK_MAX // 100):
                            break
            return True

        return False

    def _maybe_gc(self):
        now = time.time()
        if now - self._last_gc < self.GC_PERIOD_S:
            return

        # Expire peers
        cutoff = now - self.PEER_TTL_S
        for k, ts in list(self._peer_seen.items()):
            if ts < cutoff:
                self._peer_seen.pop(k, None)

        # Expire ancient cooldowns
        stale = [k for k, until in self._cooldown_until.items() if until < now - (2 * self.FLOW_COOLDOWN_S)]
        for k in stale:
            self._cooldown_until.pop(k, None)

        self._last_gc = now

    # -------------------- Tiny utilities --------------------
    def _is_wsd_port(self, sport: int, dport: int) -> bool:
        return (sport in self.WSD_PORTS) or (dport in self.WSD_PORTS)

    def _iface_suffix(self, inbound_iface: Optional[str]) -> str:
        try:
            return (inbound_iface or "").split("_")[-1]
        except Exception:
            return inbound_iface or ""

    def _note_peer(self, a_ip: str, b_ip: str) -> None:
        s, d = (str(a_ip), str(b_ip))
        key = (s, d) if s <= d else (d, s)
        self._peer_seen[key] = time.time()
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

    def __init__(self, router_logger, packet_signer, code_output_manager, parallel_python, packet_writer):
        """
        Initializes the TransportManager with a logger and a packet signer.
        """


        self.logger = router_logger
        self.parallel_python = parallel_python
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
        self.packet_writer = packet_writer
        self.transport_dhcp = TransportDHCPManager(self.logger)
        self.transport_dns = TransportDNSManager(self.logger)
        self.transport_mdns = TransportMDNSManager(self.logger)
        self.transport_nbns = TransportNBNSManager(self.logger)
        self.transport_nbds = TransportNBDSManager(self.logger)
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
        self.transport_wireguard = TransportWireGuardManager(self.logger)
        self.transport_tcp_ephemeral = TransportEphemeralTCPManager(self.logger)
        self.transport_udp_ephemeral = TransportEphemeralUDPManager(self.logger)
        self.transport_steam = TransportSteamManager(self.logger)
        self.transport_tcp_high_Level = TransportHighServerTCPManager
        self.transport_files = TransportFileManager(self.logger)
        self.transport_https = TransportHTTPSManager(self.logger)
        self.transport_ws_discovery = TransportWSDiscoveryManager(self.logger)
        self.transport_inspect = TransportInspectionManager(self.logger)
        self.transport_scraper = TransportScraperManager(self.logger)
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
        self.transport_monero = TransportMoneroManager(
            self.logger,
            extra_p2p_ports=self._MONERO_P2P_PORTS,
            extra_rpc_ports=self._MONERO_RPC_PORTS,
        )
        self.transport_scada = TransportSCADAManager(self.logger)
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
            ([502, 2404, 102, 4840, 20000], self._handle_scada_tcp_packet),
            ([80], self._handle_http_packet),
            ([443, 8443, 9443, 2087, 2096, 2083], self._handle_https_packet),
            ([53], self._handle_dns_tcp_packet),
            ([22], self._handle_ssh_packet),
            ([21], self._handle_ftp_packet),
            ([88], self._handle_kerberos_packet),
            ([3389], self._handle_rdp_packet),
            ([*self._MONERO_P2P_PORTS, *self._MONERO_RPC_PORTS], self._handle_monero_packet),
            ([(27014, 27050)], self._handle_tcp_steam_packet),
            ([(33981, 59713), (60000, 61000)], self._handle_tcp_ephemeral_packet),  # range example
            ([(1024, 65535)], self._handle_high_server_packet),  # high server port observer
            ([445, 139, 62078], self._handle_files_packet),
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
            self.packet_writer._send_raw_packet(packet, iface_short, allow_dst_ours=True, no_consume=True)
            return True
        else:
            self.code_output_manager.submit_packet(
                packet, inbound_iface=iface_short, phase="tls-feed", component="tcp"
            )
            if not self._feed_to_tls_manager(packet, src_ip, dst_ip, sport, dport):
                self.logger.log_message(
                    f"[Transport][🧵 TCP][❔ Undecoded] Unknown TCP protocol on ports {sport} → {dport}."
                )
                self.packet_writer._send_raw_packet(packet, iface_short, allow_dst_ours=True, no_consume=False)
            return True

    def _handle_monero_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles Monero P2P traffic on port 18080."""
        self.transport_monero.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_dns_tcp_packet(self, packet, src_ip, dst_ip, sport, dport, iface_short):
        self.transport_dns.handle_tcp_segment(packet, src_ip, dst_ip, sport, dport, iface_short)
    def _handle_files_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """
        SMB/NetBIOS (445/139) and Apple Lockdown (62078).
        Uses low-overhead peeks; logs command names for SMB2 when possible.
        Also feeds TLS analyzer *only if* a TLS-looking record is present (rare on these ports).
        """
        self.transport_files.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_high_server_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_tcp_high_Level.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
    def _handle_tcp_steam_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Steam TCP (CM/content/friends; 27014–27050). Observation only."""
        self.transport_steam.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_scada_tcp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_scada.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
    def _handle_http_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_http.handle(packet, src_ip, dst_ip, sport, dport)
    def _handle_https_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_https.handle(packet, inbound_iface)
        self._feed_to_tls_manager(packet, src_ip, dst_ip, sport, dport)
    def _handle_ssh_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_ssh.handle(packet, src_ip, dst_ip, sport, dport)
    def _handle_ftp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_ftp.handle(packet, src_ip, dst_ip, sport, dport)
    def _handle_rdp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_rdp.handle(packet, src_ip, dst_ip, sport, dport)
    def _handle_tcp_ephemeral_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_tcp_ephemeral.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
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
        # Handle packets with extension headers that were permitted by the firewall
        if isinstance(transport_layer, TCP):
            yield_no_gil(0.5)
            self.parallel_python.run_parallel(self.transport_inspect.handle, packet, src_ip, dst_ip,
                                              transport_layer.sport,
                                              transport_layer.dport, iface_short,
                                              return_type="void",
                                              queue_name="transport_inspect_tcp_packets")
            self.parallel_python.run_parallel(self.transport_scraper.handle, packet, src_ip, dst_ip,
                                              transport_layer.sport,
                                              transport_layer.dport, iface_short,
                                              return_type="void",
                                              queue_name="transport_scrape_tcp_packets")
            return self.parallel_python.run_parallel(self._handle_tcp_packet, packet, src_ip, dst_ip, transport_layer.sport, transport_layer.dport, iface_short,
                                      return_type="bool", queue_name="transport_tcp_packets")
        elif isinstance(transport_layer, UDP):
            yield_no_gil(0.5)
            self.parallel_python.run_parallel(self.transport_inspect.handle, packet, src_ip, dst_ip,
                                              transport_layer.sport,
                                              transport_layer.dport, iface_short,
                                              return_type="void",
                                              queue_name="transport_inspect_udp_packets")
            self.parallel_python.run_parallel(self.transport_scraper.handle, packet, src_ip, dst_ip,
                                              transport_layer.sport,
                                              transport_layer.dport, iface_short,
                                              return_type="void",
                                              queue_name="transport_scrape_udp_packets")
            return self.parallel_python.run_parallel(self._handle_udp_packet, packet, src_ip, dst_ip, transport_layer.sport, transport_layer.dport, iface_short,
                                      return_type="bool", queue_name="transport_udp_packets")

        self.transport_ipv6.handle(packet, inbound_iface)
        return False

    def _handle_udp_packet(self, packet, src_ip, dst_ip, sport, dport, iface_short):
        """Dispatches UDP packets to the correct handler based on port (supports singles + ranges)."""


        # Rules: list of (ports_or_ranges, handler)
        # A "range" is a (lo, hi) tuple, inclusive.
        if sport == 500 or dport == 500:
            return False
        rules = [
            ([53], self._handle_dns_packet),
            ([5353], self._handle_mdns_packet),
            ([137], self._handle_nbns_packet),
            ([138], self._handle_nbds_packet),
            ([67, 68], self._handle_dhcp_packet),
            ([51820, 88, 59385, 59636, 59637, 59638, 61138], self._handle_wireguard_packet),
            ([443], self._handle_quic_packet),
            ([123], self._handle_ntp_packet),
            ([69], self._handle_tftp_packet),
            ([88], self._handle_kerberos_packet),
            ([5060], self._handle_sip_packet),
            ([9993, 19300], self._handle_overlay_packet),
            ([1900], self._handle_ssdp_packet),
            ([3702], self._handle_ws_discovery_packet),
            ([19337, 19307], self._handle_rtp_packet),
            ([20000, 47808], self._handle_scada_udp_packet),
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
            if handler == self._handle_dhcp_packet:
                return handler(packet, src_ip, dst_ip, sport, dport, iface_short)
            elif handler == self._handle_dns_packet:
                handler(packet, src_ip, dst_ip, sport, dport, iface_short)
                if packet.haslayer(DNS) and packet[DNS].qr == 1:
                    return True
                return False
            elif handler == self._handle_mdns_packet:
                handler(packet, src_ip, dst_ip, sport, dport, iface_short)
                return False
            elif handler == self._handle_ws_discovery_packet:
                handler(packet, src_ip, dst_ip, sport, dport, iface_short)
                self.packet_writer._send_raw_packet(packet, iface_short, allow_dst_ours=True, no_consume=False)
                return True
            elif handler == self._handle_ssdp_packet:
                handler(packet, src_ip, dst_ip, sport, dport, iface_short)
                self.packet_writer._send_raw_packet(packet, iface_short, allow_dst_ours=True, no_consume=False)
                return True
            else:
                handler(packet, src_ip, dst_ip, sport, dport, iface_short)
                self.packet_writer._send_raw_packet(packet, iface_short, allow_dst_ours=True, no_consume=True)
                return True

        # RTP/VoIP dynamic range as a fallback
        try:
            if sport in self.voip_port_range or dport in self.voip_port_range:
                self._handle_rtp_packet(packet, src_ip, dst_ip, sport, dport, iface_short)
                return True
        except Exception:
            # If voip_port_range isn’t iterable (e.g., misconfigured), just skip
            pass
        self.code_output_manager.submit_packet(
            packet, inbound_iface=iface_short, phase="unhandled", component="udp"
        )
        self.logger.log_message(
            f"[Transport][🚀 UDP][❔ Undecoded] Unknown UDP protocol on ports {sport} → {dport}."
        )
        self.packet_writer._send_raw_packet(packet, iface_short, allow_dst_ours=True, no_consume=False)
        return True

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
    def _handle_udp_ephemeral_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_udp_ephemeral.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_scada_udp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        self.transport_scada.handle_udp(packet, src_ip, dst_ip, sport, dport, inbound_iface)
    def _handle_dns_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for DNS packets."""
        self.transport_dns.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_mdns_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """mDNS on UDP/5353 – summarize PTR/SRV/TXT/A(AAA) with dedup + cooldown."""
        self.transport_mdns.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_nbns_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """mDNS on UDP/5353 – summarize PTR/SRV/TXT/A(AAA) with dedup + cooldown."""
        self.transport_nbns.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
    def _handle_nbds_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """mDNS on UDP/5353 – summarize PTR/SRV/TXT/A(AAA) with dedup + cooldown."""
        self.transport_nbds.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)
    def _handle_dhcp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for DHCP packets."""
        return self.transport_dhcp.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_quic_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for QUIC packets."""
        self.transport_quic.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

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
    def _handle_wireguard_packet(self, packet, src_ip, dst_ip, sport, dport, iface_short):
        self.transport_wireguard.handle(packet, src_ip, dst_ip, sport, dport, iface_short)
    def _handle_ssdp_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for SSDP/UPnP packets on UDP port 1900."""
        self.transport_ssdp.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_ws_discovery_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for WS-Discovery packets on UDP port 3702."""
        self.transport_ws_discovery.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

    def _handle_kerberos_packet(self, packet, src_ip, dst_ip, sport, dport, inbound_iface):
        """Handles and logs details for WS-Discovery packets on UDP port 3702."""
        self.transport_kerberos.handle(packet, src_ip, dst_ip, sport, dport, inbound_iface)

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

class KerberosManager:
    """
    Manages Kerberos protocol traffic within the router.
    Can be used for passive analysis, logging, or active intervention/proxying.
    """

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
            self.msgType = KerberosManager._MsgTypeShim(msgtype_val)
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
            return KerberosManager._ReqBody(b, parsed)

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
            return KerberosManager._RootShim(mt if mt is not None else -1)

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
    TOKEN_BUCKET_CAPACITY = 4  # Allows bursts of up to 20 packets
    TOKEN_REFILL_RATE_HZ = 6  # Sustainable rate of 100 packets per second
    # --- MAC normalization helpers ---
    _HEX = "0123456789abcdef"

    class TokenBucketManager:
        """Manages token buckets for rate limiting on a per-key basis (e.g., per IP)."""

        def __init__(self, capacity: int, refill_rate: float, logger):
            self.capacity = capacity  # Max tokens in a bucket
            self.refill_rate = refill_rate  # Tokens added per second
            self.buckets = {}  # key -> {"tokens": float, "last_refill": float}
            self.lock = threading.Lock()
            self.logger = logger

        def consume(self, key: str) -> bool:
            """
            Attempts to consume one token for a given key. Returns True if successful,
            False if the bucket is empty (rate limit exceeded).
            """
            with self.lock:
                now = time.time()
                bucket = self.buckets.setdefault(key, {
                    "tokens": self.capacity,
                    "last_refill": now
                })

                # Refill tokens based on elapsed time
                elapsed = now - bucket["last_refill"]
                refill_amount = elapsed * self.refill_rate
                bucket["tokens"] = min(self.capacity, int(bucket["tokens"] + refill_amount))
                bucket["last_refill"] = now

                # Check if there are enough tokens to consume
                if bucket["tokens"] >= 1.0:
                    bucket["tokens"] -= 1.0
                    return True
                else:
                    # Not enough tokens, rate limit is active
                    return False
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

    def _ipv6_mcast_mac(self, group_ip6: str) -> str:
        try:
            v = int(ipaddress.IPv6Address(group_ip6))
            lo32 = v & 0xffffffff
            return (
                f"33:33:{(lo32 >> 24) & 0xff:02x}:"
                f"{(lo32 >> 16) & 0xff:02x}:"
                f"{(lo32 >> 8) & 0xff:02x}:"
                f"{lo32 & 0xff:02x}"
            )
        except Exception:
            return "33:33:00:00:00:00"

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


    def __init__(self, logger, interfaces_config, packet_signer, outbound_load_balancer, arp_manager= None,ndp_manager= None):
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
        self.ndp_manager = ndp_manager
        # Destination throttling
        self.packet_writing_table = defaultdict(lambda: {
            "timestamps": deque(maxlen=10),
            "last_sent": 0,
            "count": 0
        })
        self.rate_limiter = self.TokenBucketManager(
            capacity=self.TOKEN_BUCKET_CAPACITY,
            refill_rate=self.TOKEN_REFILL_RATE_HZ,
            logger=self.logger
        )
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

    def _send_raw_packet(self, packet, interface: str, allow_dst_ours: bool = False, no_consume: bool = False):
        """
        Uses the sniffer's sendp to send a Layer 2 packet. The 'interface' string
        is now the correct system name, thanks to translation in queue_packet.
        """
        chosen = False
        if not interface:
            interface = self.outbound_load_balancer.get_next_interface(packet)
            self.logger.log_message(f"[PacketWriter] 📤 Choosing early!")
            chosen = True
            return
        if not packet.haslayer(Ether):
            packet = self._ensure_l2_with_arp_manager(packet, interface)
            if packet is None:
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
        if dst_ip in router_ips and not (allow_local_dest or allow_dst_ours):
            self.logger.log_message(
                f"[PacketWriter] 🚫 Dropped packet: Destination IP ({dst_ip}) is our own. Summary: {packet.summary()}")
            return
        if not no_consume:
            if not self.rate_limiter.consume(dst_ip):
                self.logger.log_message(f"[PacketWriter] 🚫 Rate limit exceeded for {dst_ip}. Dropping packet.")
                return

        try:
            if chosen:
                egress_iface = interface
            else:
                egress_iface = self.outbound_load_balancer.get_next_interface(packet)
            self.logger.log_message(
                RouterRandomMessages(
                    name="PacketWriter",
                    message=f"Sending packet on '{egress_iface}': {packet.summary()}",
                    emoticons=["📫", "📪", "📬", "📭"]
                )
            )
            self.packet_signer.sign_packet(packet)
            self.sniffer.sendp(packet, iface=egress_iface, verbose=0)
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

        self._send_raw_packet(out_frame, egress_iface)

    def send_icmp_time_exceeded(self, original_packet, inbound_iface: str):
        """
        Constructs and sends an ICMP 'Time Exceeded' message back to the sender.

        This function implements RFC 792 requirements for when a packet's
        Time-To-Live (TTL) expires. It sends an ICMP Type 11, Code 0 message
        to the original packet's source.

        Args:
            original_packet: The full Scapy packet that was discarded due to an
                             expired TTL.
            inbound_iface: The friendly or system name of the interface on which
                           the original_packet was received.
        """
        # 1. Validate the original packet to ensure it's eligible for an ICMP error message.
        if not IP in original_packet:
            self.logger.log_message(
                "[PacketWriter] ⚠️ Cannot send ICMP Time Exceeded: Original packet has no IP layer.")
            return

        if ICMP in original_packet:
            if original_packet[ICMP].type in [3, 4, 5, 11, 12]:
                self.logger.log_message(
                    "[PacketWriter] 🚫 Suppressing ICMP Time Exceeded for an existing ICMP error packet.")
                return

        original_src_ip = original_packet[IP].src
        if ipaddress.ip_address(original_src_ip).is_multicast or original_src_ip == "255.255.255.255":
            self.logger.log_message(f"[PacketWriter] 🚫 Suppressing ICMP Time Exceeded for broadcast/multicast source.")
            return
        if ipaddress.ip_address(original_src_ip).is_loopback or original_src_ip == "0.0.0.0":
            self.logger.log_message(
                f"[PacketWriter] 🚫 Suppressing ICMP Time Exceeded for invalid source IP {original_src_ip}.")
            return

        # 2. Determine the source IP for the ICMP reply.
        # First, try to use the IP of the interface on which the packet arrived (the ideal case).
        system_inbound_iface = self.iface_map.get(inbound_iface, inbound_iface)
        iface_config = self._interfaces_config.get(system_inbound_iface)
        router_src_ip = iface_config.get("ip_addr") if iface_config else None

        # If the inbound interface is not in the config OR it has no IP, synthesize a source IP.
        if not router_src_ip:
            log_reason = "is not in the configuration or has no assigned IP"
            self.logger.log_message(
                f"[PacketWriter] ⚠️ Inbound iface '{inbound_iface}' {log_reason}. Synthesizing source IP from egress route.")

            # Determine the egress interface for the reply packet by checking the route back.
            temp_packet_for_routing = IP(dst=original_src_ip)
            egress_iface_name = self.outbound_load_balancer.get_next_interface(temp_packet_for_routing)

            if not egress_iface_name:
                self.logger.log_message(
                    f"[PacketWriter] ❌ Cannot determine egress route to {original_src_ip}. Cannot send ICMP reply.")
                return

            # Get the IP of that egress interface to use as the source.
            system_egress_iface = self.iface_map.get(egress_iface_name, egress_iface_name)
            egress_config = self._interfaces_config.get(system_egress_iface)
            router_src_ip = egress_config.get("ip_addr") if egress_config else None

            if not router_src_ip:
                self.logger.log_message(
                    f"[PacketWriter] ❌ Egress interface '{egress_iface_name}' has no IP. Cannot send ICMP reply.")
                return

            self.logger.log_message(
                f"[PacketWriter] ✅ Synthesized source IP {router_src_ip} from egress interface '{egress_iface_name}'.")

        # 3. Construct the ICMP Time Exceeded packet.
        icmp_payload = original_packet[IP]
        reply_packet = IP(src=router_src_ip, dst=original_src_ip, ttl=64) / ICMP(type=11, code=0) / icmp_payload

        self.logger.log_message(f"[PacketWriter] ⌛ Sending ICMP Time Exceeded to {original_src_ip} from {router_src_ip}.")

        # 4. Send the packet using the main method that handles routing and L2 framing.
        self._send_raw_packet(reply_packet,system_inbound_iface )

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

    def _is_ipv4_multicast(self,ip: str) -> bool:
        try:
            first = int(ip.split(".")[0])
            return 224 <= first <= 239
        except Exception:
            return False

    def get_interface_mac(self, iface_full_name: str) -> str:
        """
        Always returns a usable MAC address for the given interface.
        - Prefers Scapy's get_if_hwaddr()
        - Falls back to OS interface lists (Windows / netifaces)
        - Final fallback: generates a deterministic synthetic MAC
          (locally administered, unicast, stable per interface name)
        """
        mac = None

        # --- Try Scapy ---
        try:
            from scapy.all import get_if_hwaddr
            mac = get_if_hwaddr(iface_full_name)
            if mac and mac.lower() != "00:00:00:00:00:00":
                return mac.lower()
        except Exception:
            pass

        # --- Try Windows API ---
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                if iface_full_name in (
                        iface.get("name"), iface.get("win_name"), iface.get("friendlyname"),
                        iface.get("description"), iface.get("guid")
                ):
                    mac = (iface.get("mac") or "").lower()
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
        except Exception:
            pass

        # --- Try netifaces ---
        try:
            import netifaces as ni
            if iface_full_name in ni.interfaces():
                addrs = ni.ifaddresses(iface_full_name).get(ni.AF_LINK, [{}])
                if addrs and "addr" in addrs[0]:
                    mac = addrs[0]["addr"].lower()
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
        except Exception:
            pass

        # --- Last resort: generate a synthetic MAC ---
        h = abs(hash(iface_full_name)) & 0xFFFFFFFFFFFF
        fake_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
            (h >> 32) & 0xFF,
            (h >> 24) & 0xFF,
            (h >> 16) & 0xFF,
            (h >> 8) & 0xFF,
            h & 0xFF,
        )
        return fake_mac
    def _ensure_l2_with_arp_manager(self, packet, final_iface: str):
        """
        If the packet has no Ether layer, create one:
          - src = interface MAC
          - dst = resolved via ARPManager for IPv4, or mapped for broadcast/multicast
          - IPv6: map multicast, try NDP (if available), else drop (safe)
        Returns the (possibly wrapped) packet, or None if we can’t safely send.
        """
        if packet.haslayer(Ether):
            return packet

        # interface MAC for source
        try:
            src_mac = self._normalize_mac(get_if_hwaddr(final_iface))
        except Exception:
            src_mac = None
        if not src_mac:
            src_mac = self.get_interface_mac(final_iface)
            if not src_mac:
                self.logger.log_message(f"[PacketWriter] ❌ No interface MAC for '{final_iface}' to synthesize L2.")
                return None

        dst_mac = None

        # IPv4 path
        if IP in packet:
            dip = packet[IP].dst

            # broadcast
            if dip == "255.255.255.255":
                dst_mac = "ff:ff:ff:ff:ff:ff"
            # multicast
            elif self._is_ipv4_multicast(dip):
                dst_mac = self._ipv4_mcast_mac(dip)
            else:
                # unicast: pick next-hop, resolve via ARPManager
                nh_ip, _af = self._infer_next_hop(final_iface, packet)  # already in your class
                nh_ip = nh_ip or dip
                if self.arp_manager:
                    mac = self.arp_manager.resolve(nh_ip, final_iface)
                else:
                    mac = None
                dst_mac = self._normalize_mac(mac) if mac else None
                if not dst_mac:
                    dst_mac = getmacbyip(nh_ip)
                    if not dst_mac:
                        self.logger.log_message(f"[PacketWriter] 🚫 ARP unresolved for {nh_ip} on {final_iface}.")
                        return None

        # IPv6 path
        elif IPv6 in packet:
            dip6 = packet[IPv6].dst
            if dip6.lower().startswith("ff"):  # multicast
                dst_mac = self._ipv6_mcast_mac(dip6)
            else:
                # Try scapy NDP helper if present. Otherwise, we avoid guessing.
                mac6 = None
                if getmacbyip6:
                    try:
                        mac6 = getmacbyip6(dip6, iface=final_iface)
                    except Exception:
                        mac6 = None
                if mac6:
                    dst_mac = self._normalize_mac(mac6)
                else:
                    dst_mac = self.ndp_manager.resolve(dip6, iface=final_iface)
                    if dst_mac is None:
                        self.logger.log_message(
                            f"[PacketWriter] 🚫 No IPv6 resolver available for {dip6} on {final_iface}.")
                        return None
        else:
            self.logger.log_message("[PacketWriter] 🚫 No IP/IPv6 layer; cannot synthesize L2.")
            return None

        ether = Ether(src=src_mac, dst=dst_mac)
        return ether / packet
class ForwardingManager:
    """
    Tracks recently forwarded flows and considers them duplicates only after
    a certain threshold has been reached within a timeout period.
    """

    def __init__(self, function_call_tracker, router_logger=None,timeout: int = 5, max_entries: int = 10000, duplicate_threshold: int = 20):
        self.logger = router_logger or (lambda x: None)
        self.timeout = timeout
        self.duplicate_threshold = duplicate_threshold  # NEW: Configurable threshold
        self._forwarded_cache = deque(maxlen=max_entries)
        self.function_call_tracker = function_call_tracker
        # CHANGED: from a set to a dictionary to store (count, timestamp)
        self._flow_counts: Dict[Tuple, Tuple[int, float]] = {}
        self.ban_duration = 60  # seconds
        self.max_consecutive_rate = 100  # e.g., more than 10 packets/sec = ban
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
        self.sniffer = None
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
            self.sniffer.send(frame, target_iface)

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
                    self.sniffer.send(frame.copy(), iface)
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
    # ------------------------------ Tuning -----------------------------------
    VERBOSE_ICMPV6_UNFOLD = True
    VERBOSE_ICMPV4_UNFOLD = True
    VERBOSE_HEX_PREVIEW   = True
    HEX_PREVIEW_BYTES     = 96
    TLV_MAX_ITEMS         = 32
    HBH_MAX_BYTES         = 2048
    EXT_MAX_BYTES         = 4096
    RAW_SAFE_CAP          = 16384
    MLD_MAX_RECORDS       = 512
    MLD_MAX_SRCS_PER_REC  = 4096
    DNS_MAX_Q             = 16
    DNS_MAX_ANS           = 32
    DNS_MAX_AUTH          = 32
    DNS_MAX_ADD           = 32
    DNS_NAME_PREVIEW      = 128

    # Active-mirror knob (mirrors the *captured* ICMP packet during UNFOLD)
    ACTIVE_MIRROR_ICMP    = True         # set True to enable mirroring during UNFOLD
    MIRROR_IFACE          = "WinDivertBridge"         # if None, mirrors back out the inbound iface

    MLD_MEMBERSHIP_TIMEOUT = 260
    PURGE_INTERVAL_SEC     = 60
    REASM_TIMEOUT_SEC      = 5.0
    _EIGHT                 = 8

    V3_MAX_RESP_CODE = 100  # encoded MRC (see RFC; 100 ~ 10s plain code)
    V3_QRV = 2  # robustness value in query
    V3_QQIC = 125  # query interval code (~125s)
    V3_SUPPRESS = 0  # S bit (1=do not send reports immediately)

    TRANSIT_ECHO_POLICY = "mirror"  # "reject" | "mirror" | "none"
    TRANSIT_ECHO_RATE_LIMIT_PPS = 2  # rate-limit our synthetic ICMP errors/mirrors
    def __init__(self, router_logger, packet_writer, interfaces_config: dict, rate_limit_pps: int = 5):
        self.log   = router_logger
        self.pw    = packet_writer
        self.ifaces = interfaces_config or {}
        self.rate_limit_pps = rate_limit_pps

        # TX stats (visible in logs)
        self._tx_counter = 0

        # rate-limit state
        self._last_reply_time = defaultdict(float)
        self._rate_limit_lock = threading.Lock()

        # IPv4 reassembly state
        self._reasm: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
        self._reasm_lock = threading.Lock()

        # ND cache
        self.nd_cache: Dict[str, Dict[str, Any]] = {}

        # MLD state
        self._mld_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._mld_lock = threading.Lock()
        self._mld_querier: Dict[str, Dict[str, Any]] = {}
        self._mldq_lock = threading.Lock()

        # purger thread
        self._stop_event = threading.Event()
        self._purge_thread = threading.Thread(target=self._purge_loop, daemon=True, name="ICMPPurger")
        self._purge_thread.start()

        self._transit_rl = defaultdict(float)

        self.log.log_message("[ICMP] Manager initialized (ultra-verbose IPv6+IPv4 UNFOLD + TX-aware).")

    # --------------------------------------------------------------------------
    # Central TX wrapper (logs every send)
    # --------------------------------------------------------------------------
    def pw_send_raw_packet(self, pkt: Packet, iface: str, *, allow_dst_ours: bool = True, reason: str = "") -> None:
        """
        Unified send with strong logging. Use this everywhere we transmit.
        """
        try:
            rawlen = len(bytes(pkt))
        except Exception:
            rawlen = -1
        summary = ""
        try:
            summary = pkt.summary()
        except Exception:
            summary = "<no-summary>"
        self._tx_counter += 1
        tag = f"#{self._tx_counter:06d}"
        self.log.log_message(f"[ICMP][TX]{tag} ✈️ iface={self._iface_suffix(iface)} bytes={rawlen} reason='{reason}' pkt={summary}")
        try:
            # Prefer packet_writer._send_raw_packet; support alternative attr names if needed.
            if hasattr(self.pw, "_send_raw_packet"):
                self.pw._send_raw_packet(pkt, iface, allow_dst_ours=allow_dst_ours)
            elif hasattr(self.pw, "send_raw_packet"):
                self.pw.send_raw_packet(pkt, iface, allow_dst_ours=allow_dst_ours)  # type: ignore
            else:
                # Fallback: attach to self; some codebases mount writer directly
                if hasattr(self, "_send_raw_packet"):
                    self._send_raw_packet(pkt, iface, allow_dst_ours=allow_dst_ours)  # type: ignore
                else:
                    self.log.log_message(f"[ICMP][TX]{tag} ⚠️ No sender available; drop.")
        except Exception as e:
            self.log.log_message(f"[ICMP][TX]{tag} ❌ send failed: {e}")

    # --------------------------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------------------------
    def stop(self):
        self._stop_event.set()
        if self._purge_thread.is_alive():
            self._purge_thread.join(timeout=2)

    # --------------------------------------------------------------------------
    # Entry
    # --------------------------------------------------------------------------
    def handle_packet(self, pkt: Packet, inbound_iface: str) -> bool:
        try:
            if pkt.haslayer(IPv6):
                handled = self._handle_ipv6(pkt, inbound_iface)
                return handled
            if pkt.haslayer(IP):
                handled = self._handle_ipv4(pkt, inbound_iface)
                return handled
        except Exception as e:
            self.log.log_message(f"[ICMP] ❗ ERROR in handle_packet: {e}\n{traceback.format_exc()}")
        return False

    # --------------------------------------------------------------------------
    # IPv6 Path
    # --------------------------------------------------------------------------
    def _handle_ipv6(self, pkt: Packet, iface: str) -> bool:
        # ND first
        if pkt.haslayer(ICMPv6ND_NS):
            self._handle_ns(pkt, iface);   return True
        if pkt.haslayer(ICMPv6ND_NA):
            self._handle_na(pkt);          return True
        if pkt.haslayer(ICMPv6ND_RS):
            self._handle_rs(pkt, iface);   return True

        try:
            v6 = pkt[IPv6]
            dst_l = str(v6.dst).lower()
            # ff02::16 — All MLDv2 Routers
            if dst_l == "ff02::16":
                if self.VERBOSE_ICMPV6_UNFOLD:
                    self._unfold_v6_chain(pkt, iface, purpose="MLDv2 routers (ff02::16)")
                if self._mld_dispatch(pkt, iface):
                    self._maybe_mirror_unfold(pkt, iface, family="v6", why="MLDv2 ff02::16")
                    return True
                self.log.log_message(f"[ICMP][MLD] 🔒 Consumed (unrecognized) to ff02::16 on {self._iface_suffix(iface)}")
                self._maybe_mirror_unfold(pkt, iface, family="v6", why="LLMCAST other")
                return True
            # Any other link-local multicast
            if dst_l.startswith("ff02:"):
                if self.VERBOSE_ICMPV6_UNFOLD:
                    self._unfold_v6_chain(pkt, iface, purpose="link-local multicast (ff02::/16)")
                if self._mld_dispatch(pkt, iface):
                    self._maybe_mirror_unfold(pkt, iface, family="v6", why="LLMCAST generic")
                    return True
                self.log.log_message(
                    f"[ICMP] 🔒 Dropped unrecognized link-local multicast {v6.src}→{v6.dst} on {self._iface_suffix(iface)}")
                self._maybe_mirror_unfold(pkt, iface, family="v6", why="LLMCAST drop")
                return True
        except Exception:
            pass

        # Echo?
        if pkt.haslayer(ICMPv6EchoRequest) and self._is_for_router_v6(pkt[IPv6].dst):
            self._handle_echo_request_v6(pkt, iface); return True

        # Errors?
        if self._handle_icmpv6_errors(pkt, iface):
            self._maybe_mirror_unfold(pkt, iface, family="v6", why="ICMPv6 error")
            return True

        # Otherwise, nothing to do
        return False

    def _handle_echo_request_v6(self, pkt: Packet, iface: str) -> None:
        v6 = pkt[IPv6]
        req = pkt[ICMPv6EchoRequest]
        src_ip, dst_ip = v6.src, v6.dst
        self.log.log_message(f"[ICMP] 📨 Echo-Request v6 {src_ip} → {dst_ip} on {self._iface_suffix(iface)}")
        if self._is_rate_limited(src_ip, dst_ip):
            return

        l2src = self._iface_mac_by_v6(dst_ip) or "00:00:00:00:00:00"
        l2dst = pkt[Ether].src if pkt.haslayer(Ether) and not self._is_loopback_name(iface) else None

        base = IPv6(src=dst_ip, dst=src_ip)
        echo_reply = ICMPv6EchoReply(id=req.id, seq=req.seq) / req.payload
        reply = (Ether(src=l2src, dst=l2dst) / base / echo_reply) if l2dst else (base / echo_reply)

        self._maybe_queue_v6_or_too_big(reply, pkt, iface, reason="Echo-Reply v6")
        self.log.log_message(f"[ICMP] ✅ Echo-Reply v6 queued on {self._iface_suffix(iface)} for {src_ip}")

    def _handle_icmpv6_errors(self, pkt: Packet, iface: str) -> bool:
        """Logs common incoming ICMPv6 error messages."""
        try:
            if pkt.haslayer(ICMPv6DestUnreach):
                du = pkt[ICMPv6DestUnreach]
                code = int(getattr(du, 'code', -1))
                self.log.log_message(f"[ICMP] 🔌 v6 DestUnreach code={code} on {self._iface_suffix(iface)}; {pkt.summary()}")
                if code in (1, 5, 6):  # Admin Prohibited / Policy Fail / Reject Route
                    self._log_admin_block_v6(pkt, iface)
                return True

            if pkt.haslayer(ICMPv6TimeExceeded):
                self.log.log_message(f"[ICMP] ⏳ v6 TimeExceeded on {self._iface_suffix(iface)}; {pkt.summary()}")
                return True

            if pkt.haslayer(ICMPv6ParamProblem):
                self.log.log_message(f"[ICMP] 🧩 v6 ParamProblem on {self._iface_suffix(iface)}; {pkt.summary()}")
                return True
        except Exception:
            pass
        return False

    # --------------------------------------------------------------------------
    # ND (NS/NA/RS)
    # --------------------------------------------------------------------------
    def _handle_ns(self, pkt: Packet, iface: str) -> None:
        try:
            ns = pkt[ICMPv6ND_NS]
            v6 = pkt[IPv6]
        except Exception:
            return

        target_ip = getattr(ns, "tgt", None)

        # Learn peer MAC (SLLA) or fall back to L2 src
        mac = None
        try:
            if pkt.haslayer(ICMPv6NDOptSrcLLAddr) and pkt[ICMPv6NDOptSrcLLAddr].lladdr:
                mac = pkt[ICMPv6NDOptSrcLLAddr].lladdr
        except Exception:
            mac = None
        if mac is None and pkt.haslayer(Ether):
            mac = getattr(pkt[Ether], "src", None)
        if mac:
            self._nd_learn_mac(str(v6.src), mac)

        # If they’re asking for one of our addresses, send NA
        if target_ip and self._is_for_router_v6(str(target_ip)):
            self._send_neighbor_advertisement(pkt, str(target_ip), iface)

    def _handle_na(self, pkt: Packet) -> None:
        try:
            na = pkt[ICMPv6ND_NA]
            v6 = pkt[IPv6]
        except Exception:
            return

        R = int(getattr(na, "R", 0))
        S = int(getattr(na, "S", 0))
        O = int(getattr(na, "O", 0))

        target_ip = str(getattr(na, "tgt", v6.src))
        src_ip = str(getattr(v6, "src", "::"))
        hop_limit = int(getattr(v6, "hlim", -1))

        mac = self._nd_peer_mac_from_pkt(pkt) or (pkt[Ether].src if pkt.haslayer(Ether) else None)

        if hop_limit != 255:
            self.log.log_message(f"[ICMP][ND] ⚠️ NA HLIM={hop_limit} (expected 255) from {src_ip} for {target_ip}")

        self.log.log_message(f"[ICMP][ND] 📨 NA {src_ip} ⇒ {target_ip} (R={R} S={S} O={O})")

        if mac:
            key = self._norm_v6(target_ip) or target_ip
            old = self.nd_cache.get(key, {}).get("mac")
            if old and old.lower() != mac.lower():
                self.log.log_message(f"[ICMP][ND] 🔄 MAC change for {key}: {old} → {mac} (S={S} O={O})")
            elif not old:
                self.log.log_message(f"[ICMP][ND] 📒 Learned neighbor {key} -> {mac} (S={S} O={O})")
            else:
                self.log.log_message(f"[ICMP][ND] 🔁 Refreshed neighbor {key} (mac {mac}) (S={S} O={O})")
            self._nd_learn_mac(key, mac)

        try:
            if self._is_for_router_v6(target_ip):
                note = "solicited" if S else "unsolicited"
                self.log.log_message(f"[ICMP][ND] 🛡️ NA {note} for our address {target_ip} (O={O}, R={R})")
        except Exception:
            pass

    def _handle_rs(self, pkt: Packet, iface: str) -> None:
        try:
            src = str(pkt[IPv6].src)
        except Exception:
            src = "::"
        self.log.log_message(f"[ICMP][ND] 📨 Router Solicitation from {src} on {self._iface_suffix(iface)}")
        self._send_router_advertisement(iface, destination_ip=src)

    def _send_neighbor_advertisement(self, solicitation_pkt: Packet, target_ip: str, iface: str) -> None:
        cfg = self.ifaces.get(iface, {})
        my_mac = self._iface_mac_by_v6(target_ip) or cfg.get("mac")
        if not my_mac:
            self.log.log_message(f"[ICMP][ND] ⚠️ Cannot find MAC for our IP {target_ip} to send NA.")
            return

        v6s = solicitation_pkt[IPv6]
        dst_ip = v6s.src
        dst_mac = (solicitation_pkt[Ether].src if solicitation_pkt.haslayer(Ether)
                   else self._solicited_node_mac_for_target(target_ip))

        # Type 2 = Target LL Address (simple 8B opt: type=2, len=1, 6B MAC)
        tlla = self._pack_nd_lladdr_opt(opt_type=2, mac_str=my_mac)
        na = (
            Ether(src=my_mac, dst=dst_mac) /
            IPv6(src=target_ip, dst=dst_ip, hlim=255) /
            ICMPv6ND_NA(R=1, S=1, O=1, tgt=target_ip) /
            bytes(tlla)
        )
        self.pw_send_raw_packet(na, iface, allow_dst_ours=True, reason="ND: Neighbor Advertisement")

    def _send_router_advertisement(self, iface: str, destination_ip: str) -> None:
        cfg = self.ifaces.get(iface, {})
        my_mac = cfg.get("mac")
        my_ll = self._get_iface_ipv6(iface)
        prefix = cfg.get("ipv6_prefix")
        if not (my_mac and my_ll):
            return

        dst_ip = destination_ip if destination_ip and destination_ip != "::" else "ff02::1"
        dst_mac = self.nd_cache.get(self._norm_v6(dst_ip), {}).get("mac") or "33:33:00:00:00:01"

        ra = (
            Ether(src=my_mac, dst=dst_mac) /
            IPv6(src=my_ll, dst=dst_ip, hlim=255) /
            ICMPv6ND_RA(M=0, O=0, routerlifetime=1800) /
            ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
        )
        if prefix:
            ra /= ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=64, L=1, A=1,
                                        validlifetime=7200, preferredlifetime=1800)

        self.pw_send_raw_packet(ra, iface, allow_dst_ours=True, reason="ND: Router Advertisement")

    # --------------------------------------------------------------------------
    # IPv6 Unfold (HBH, Dest, Routing, Frag, AH, ESP, upper-layer)
    # --------------------------------------------------------------------------
    def _unfold_v6_chain(self, pkt: Packet, iface: str, *, purpose: str) -> None:
        def hexdump(label: str, blob: bytes, cap: int = 96):
            if not blob:
                return
            preview = binascii.hexlify(blob[:cap]).decode("ascii")
            more = "" if len(blob) <= cap else f"...(+{len(blob)-cap}B)"
            self.log.log_message(f"[ICMP][UNFOLD]     {label} hex[:{cap}]={preview}{more}")

        def scan_hbh_options_layer(hbh_layer: IPv6ExtHdrHopByHop) -> None:
            try:
                raw = bytes(hbh_layer)
                hexdump("HBH", raw)
                self._scan_hbh_options_bytes(raw)
            except Exception:
                pass

        try:
            v6 = pkt[IPv6]
            self.log.log_message(f"[ICMP][UNFOLD] v6 {purpose} on {self._iface_suffix(iface)}")
            self.log.log_message(f"[ICMP][UNFOLD]   IPv6 src={v6.src} dst={v6.dst} hlim={getattr(v6,'hlim',None)} nh={getattr(v6,'nh',None)} plen={getattr(v6,'plen',None)}")
        except Exception:
            self.log.log_message("[ICMP][UNFOLD] ⚠️ no IPv6 layer; abort")
            return

        try:
            if pkt.haslayer(IPv6ExtHdrHopByHop):
                scan_hbh_options_layer(pkt[IPv6ExtHdrHopByHop])
            if pkt.haslayer(IPv6ExtHdrDestOpt):
                raw = bytes(pkt[IPv6ExtHdrDestOpt])
                self.log.log_message(f"[ICMP][UNFOLD]   DestOpts len={len(raw)}"); hexdump("DestOpts", raw)
            if pkt.haslayer(IPv6ExtHdrRouting):
                raw = bytes(pkt[IPv6ExtHdrRouting])
                self.log.log_message(f"[ICMP][UNFOLD]   Routing len={len(raw)}"); hexdump("Routing", raw)
            if pkt.haslayer(IPv6ExtHdrFragment):
                fr = pkt[IPv6ExtHdrFragment]
                next_nh = getattr(fr, "nh", None)
                frag_off = int(getattr(fr, "offset", 0)) * 8
                mf = bool(getattr(fr, "m", 0))
                ident = getattr(fr, "id", 0)
                self.log.log_message(f"[ICMP][UNFOLD]   Fragment next={next_nh} off={frag_off} MF={int(mf)} id={ident}")

            # Upper layer preview
            for L in (ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach, ICMPv6ParamProblem, ICMPv6TimeExceeded, ICMPv6PacketTooBig, ICMPv6Unknown):
                if pkt.haslayer(L):
                    raw = bytes(pkt[L])
                    self.log.log_message(f"[ICMP][UNFOLD]   ICMPv6 layer={L.__name__} len={len(raw)}")
                    hexdump("ICMPv6", raw)
                    break
        except Exception:
            # Fallback to byte walker
            self._unfold_v6_bytes_fallback(pkt, iface)

    def _scan_hbh_options_bytes(self, hbh: bytes) -> None:
        try:
            if not hbh or len(hbh) < 2:
                return
            off, seen = 2, 0
            while off < len(hbh) and seen < self.TLV_MAX_ITEMS:
                opt_type = hbh[off]
                if opt_type == 0:  # Pad1
                    self.log.log_message(f"[ICMP][HBH] Pad1 @+{off}")
                    off += 1; seen += 1; continue
                if off + 2 > len(hbh): break
                opt_len = hbh[off + 1]
                val_start, val_end = off + 2, off + 2 + opt_len
                if val_end > len(hbh):
                    self.log.log_message(f"[ICMP][HBH] ⚠️ TLV overruns: type=0x{opt_type:02x} len={opt_len} @+{off}; stop")
                    break
                if opt_type == 0x05 and opt_len >= 2:
                    val = struct.unpack("!H", hbh[val_start:val_start + 2])[0]
                    self.log.log_message(f"[ICMP][HBH] Router-Alert value={val} @+{off} (0 means MLD)")
                else:
                    pv = binascii.hexlify(hbh[val_start:val_start + min(opt_len, 8)]).decode("ascii")
                    self.log.log_message(f"[ICMP][HBH] TLV type=0x{opt_type:02x} len={opt_len} @+{off} val[:8]={pv}")
                off = val_end; seen += 1
        except Exception:
            pass

    def _unfold_v6_bytes_fallback(self, pkt: Packet, iface: str) -> None:
        try:
            b = bytes(pkt[IPv6])
        except Exception:
            return
        if len(b) < 40:
            self.log.log_message("[ICMP][UNFOLD]   ⚠️ truncated IPv6 header (<40B)")
            return

        nh = b[6]
        payload_len = struct.unpack("!H", b[4:6])[0]
        idx = 40

        EXT_HBH, EXT_DEST, EXT_ROUTING, EXT_FRAG, EXT_ESP, EXT_AH = 0, 60, 43, 44, 50, 51
        steps = 0

        def hexdump(label: str, blob: bytes, cap: int = 96):
            if not blob:
                return
            preview = binascii.hexlify(blob[:cap]).decode("ascii")
            more = "" if len(blob) <= cap else f"...(+{len(blob)-cap}B)"
            self.log.log_message(f"[ICMP][UNFOLD]     {label} hex[:{cap}]={preview}{more}")

        while steps < 64:
            steps += 1
            if nh in (EXT_HBH, EXT_DEST, EXT_ROUTING):
                if idx + 2 > len(b):
                    self.log.log_message(f"[ICMP][UNFOLD]   ⚠️ truncated ext hdr @+{idx}")
                    return
                next_nh = b[idx]
                hdr_ext_len = b[idx+1]
                ext_total_len = (hdr_ext_len + 1) * 8
                end = min(idx + ext_total_len, len(b))
                kind = {EXT_HBH: "HopByHop", EXT_DEST: "DestOpts", EXT_ROUTING: "Routing"}[nh]
                self.log.log_message(f"[ICMP][UNFOLD]   {kind} @+{idx}:{end} next={next_nh} hdrlen={ext_total_len}")
                hexdump(kind, b[idx:end])
                if nh == EXT_HBH:
                    self._scan_hbh_options_bytes(b[idx:end])
                idx, nh = end, next_nh
                continue

            if nh == EXT_FRAG:
                if idx + 8 > len(b):
                    self.log.log_message(f"[ICMP][UNFOLD]   ⚠️ truncated Fragment hdr @+{idx}")
                    return
                next_nh = b[idx]
                of = struct.unpack("!H", b[idx+2:idx+4])[0]
                frag_off = (of >> 3) & 0x1FFF
                mf = bool(of & 0x1)
                ident = struct.unpack("!I", b[idx+4:idx+8])[0]
                self.log.log_message(f"[ICMP][UNFOLD]   Fragment @+{idx}:{idx+8} next={next_nh} off={frag_off*8} MF={int(mf)} id={ident}")
                idx, nh = idx + 8, next_nh
                continue

            if nh == EXT_AH:
                if idx + 2 > len(b):
                    self.log.log_message(f"[ICMP][UNFOLD]   ⚠️ truncated AH hdr @+{idx}")
                    return
                next_nh = b[idx]
                paylen_words = b[idx+1]
                ah_len = (paylen_words + 2) * 4
                end = min(idx + ah_len, len(b))
                self.log.log_message(f"[ICMP][UNFOLD]   AH @+{idx}:{end} next={next_nh} len={ah_len}")
                hexdump("AH", b[idx:end])
                idx, nh = end, next_nh
                continue

            if nh == EXT_ESP:
                ul_end = min(len(b), 40 + payload_len)
                self.log.log_message(f"[ICMP][UNFOLD]   ESP @+{idx}:{ul_end} (opaque)")
                hexdump("ESP", b[idx:ul_end])
                return

            ul_end = min(len(b), 40 + payload_len)
            ul = b[idx:ul_end]
            if nh == 58 and len(ul) >= 4:
                icmp_type, icmp_code = ul[0], ul[1]
                self.log.log_message(f"[ICMP][UNFOLD]   ICMPv6 @+{idx}:{ul_end} type={icmp_type} code={icmp_code} len={len(ul)}")
                hexdump("ICMPv6", ul)
            else:
                self.log.log_message(f"[ICMP][UNFOLD]   L4 nh={nh} @+{idx}:{ul_end} len={len(ul)}")
                hexdump("L4", ul)
            return

    # --------------------------------------------------------------------------
    # MLD Dispatch (v1 via scapy if available, v2 best-effort raw)
    # --------------------------------------------------------------------------
    def _mld_dispatch(self, pkt: Packet, iface: str) -> bool:
        def extract_icmpv6_bytes(p: Packet) -> Optional[bytes]:
            try:
                b = bytes(p[IPv6])
                if len(b) < 40: return None
                nh = b[6]; idx = 40
                while True:
                    if nh in (0, 60, 43):  # HBH, Dest, Routing
                        if idx + 2 > len(b): return None
                        hdr_ext_len = b[idx+1]
                        ext_total_len = (hdr_ext_len + 1) * 8
                        nh = b[idx]
                        idx += ext_total_len
                        continue
                    if nh == 44:
                        if idx + 8 > len(b): return None
                        nh = b[idx]
                        idx += 8
                        continue
                    if nh in (50, 51):
                        return None
                    plen = struct.unpack("!H", b[4:6])[0]
                    ul_end = min(len(b), 40 + plen)
                    return b[idx:ul_end] if nh == 58 else None
            except Exception:
                return None

        try:
            v6 = pkt[IPv6]; iface_short = self._iface_suffix(iface)


            if pkt.haslayer(MLDQuery):
                q = pkt[MLDQuery]
                g = str(getattr(q, "mcaddr", "::"))
                kind = "general" if g in ("::", "0::") else f"group={g}"
                self.log.log_message(f"[ICMP][MLD] v1 Query ({kind}) from {v6.src} on {iface_short}")
                self._send_mldv1_reports_for_iface(iface, specific_group=None if g in ("::", "0::") else g)
                return True
            if pkt.haslayer(MLDReport) or pkt.haslayer(MLDDone):
                g = self._get_mld_v1_group(pkt)
                if pkt.haslayer(MLDReport):
                    self.log.log_message(f"[ICMP][MLD] v1 Report {v6.src} on {iface_short} gaddr={g}")
                    self._mld_join(g, iface, mode="include", sources=None, who=str(v6.src))
                else:
                    self.log.log_message(f"[ICMP][MLD] v1 Done {v6.src} on {iface_short} gaddr={g}")
                    self._mld_leave(g, iface, who=str(v6.src))
                return True

            icmp_bytes = extract_icmpv6_bytes(pkt)
            if not icmp_bytes or len(icmp_bytes) < 8:
                return True

            icmp_type = icmp_bytes[0]
            if icmp_type != 143:
                return True

            mcount = struct.unpack("!H", icmp_bytes[6:8])[0]
            self.log.log_message(f"[ICMP][MLD] v2 Report from {v6.src} on {iface_short} (records={mcount})")

            off = 8
            rec_idx = 0
            while rec_idx < mcount and off + 20 <= len(icmp_bytes) and rec_idx < self.MLD_MAX_RECORDS:
                rtype = icmp_bytes[off]
                aux_words = icmp_bytes[off+1]
                nsrc = struct.unpack("!H", icmp_bytes[off+2:off+4])[0]
                maddr = ipaddress.IPv6Address(icmp_bytes[off+4:off+20])
                off += 20

                # sources
                srcs = []
                for _ in range(min(nsrc, self.MLD_MAX_SRCS_PER_REC)):
                    if off + 16 > len(icmp_bytes): break
                    srcs.append(str(ipaddress.IPv6Address(icmp_bytes[off:off+16])))
                    off += 16

                # aux
                aux_len_bytes = aux_words * 4
                if off + aux_len_bytes <= len(icmp_bytes):
                    off += aux_len_bytes

                rname = {
                    1: "MODE_IS_INCLUDE", 2: "MODE_IS_EXCLUDE",
                    3: "CHANGE_TO_INCLUDE", 4: "CHANGE_TO_EXCLUDE",
                    5: "ALLOW_NEW_SOURCES", 6: "BLOCK_OLD_SOURCES"
                }.get(rtype, f"RTYPE_{rtype}")

                self.log.log_message(f"[ICMP][MLD]   rec#{rec_idx} {rname} group={maddr} nsrc={nsrc} aux={aux_len_bytes}B")
                if srcs:
                    show = ", ".join(srcs[:8]); more = "" if len(srcs) <= 8 else f", ...(+{len(srcs)-8})"
                    self.log.log_message(f"[ICMP][MLD]     sources: {show}{more}")

                # Update memberships
                if rtype in (1, 3, 5):
                    self._mld_join(str(maddr), iface, mode="include", sources=set(srcs), who=str(v6.src))
                elif rtype in (2, 4):
                    self._mld_join(str(maddr), iface, mode="exclude", sources=set(srcs), who=str(v6.src))
                elif rtype == 6:
                    self._mld_block_sources(str(maddr), iface, sources=set(srcs), who=str(v6.src))

                rec_idx += 1

            return True
        except Exception:
            return True

    def _send_mldv1_reports_for_iface(self, iface: str, specific_group: Optional[str] = None) -> None:
        cfg = self.ifaces.get(iface, {})
        src_ll = self._get_iface_ipv6(iface)
        src_mac = cfg.get("mac")
        if not (src_ll and src_mac):
            return

        with self._mld_lock:
            groups = [g for (g, ifn) in self._mld_groups.keys()
                      if ifn == iface and (specific_group is None or g == specific_group)]
        for g in groups:
            dst_mac = self._ipv6_mcast_mac(g)
            report = (Ether(src=src_mac, dst=dst_mac) /
                      IPv6(src=src_ll, dst=g, hlim=1) /
                      MLDReport(mcaddr=g))
            self.pw_send_raw_packet(report, iface, allow_dst_ours=True, reason=f"MLDv1 Report {g}")

    # --------------------------------------------------------------------------
    # IPv4 Path — deep UNFOLD (IP/ICMP/IPerror/UDPerror/DNS)
    # --------------------------------------------------------------------------
    def _handle_ipv4(self, pkt: Packet, iface: str) -> bool:
        ip = pkt[IP]
        is_for_router, router_mac, router_ip = self._match_router_ip_v4(ip.dst)

        if is_for_router and self._is_ipv4_fragment(ip):
            assembled_pkt = self._reassemble_ipv4(pkt, iface)
            if assembled_pkt is None:
                return True
            pkt = assembled_pkt
            ip = pkt[IP]

        if not pkt.haslayer(ICMP):
            return False

        icmp = pkt[ICMP]
        t = int(getattr(icmp, "type", 255))

        # Echo-requests
        if t == 8:
            if not is_for_router:
                # Transit: unfold + act per policy
                handled = self._handle_transit_echo_v4(pkt, iface)
                return handled
            # Ours: reply normally
            self._handle_echo_request_v4(pkt, iface, router_mac, router_ip)
            return True

        # Errors: unfold (even for transit) for diagnostics
        unfolded = self._icmpv4_unfold(pkt, iface)
        if unfolded:
            self._maybe_mirror_unfold(pkt, iface, family="v4", why="ICMPv4 error")
            return True

        return self._handle_icmpv4_errors_generic(pkt, iface)
    def _icmpv4_unfold(self, pkt: Packet, iface: str) -> bool:
        """
        UNFOLD path for ICMPv4 errors.
        """
        try:
            icmp = pkt[ICMP]
            t, c = int(icmp.type), int(getattr(icmp, "code", 0))
            if t not in (3, 11, 12):  # DestUnreach / TimeExceeded / ParamProblem
                return False

            ip_outer = pkt[IP]
            raw_payload = bytes(icmp.payload) if hasattr(icmp, "payload") else b""
            inner_ip, ihl_bytes, ext_len, inner_proto, (sport, dport) = self._icmpv4_extract_inner(pkt)

            self.log.log_message(
                f"[ICMP][UNFOLD] v4 err on {self._iface_suffix(iface)} "
                f"outer={ip_outer.src}→{ip_outer.dst} type={t} code={c} "
                f"inner_proto={inner_proto} ihl={ihl_bytes} ext={ext_len}"
            )
            self._hex_preview("ICMPv4.payload", raw_payload)

            # If inner IP is present, show key fields
            if inner_ip:
                self.log.log_message(
                    f"[ICMP][UNFOLD]   inner IP {inner_ip.src}→{inner_ip.dst} proto={inner_proto} ttl={getattr(inner_ip,'ttl',None)}"
                )

            # UDP inner?
            is_udp = (inner_proto == 17)
            if is_udp:
                self.log.log_message(f"[ICMP][UNFOLD]   inner UDP {sport}→{dport}")
                udp_payload_off = ihl_bytes + 8
                dns_bytes = raw_payload[udp_payload_off:] if len(raw_payload) >= udp_payload_off else b""
                if (sport == 53 or dport == 53 or self._looks_like_dns(dns_bytes)):
                    self._unfold_dns_from_udp_error(pkt, iface, dns_bytes)
                else:
                    self._hex_preview("UDP.payload", dns_bytes)

            # ICMP type-specific note
            if t == 3 and c == 3:
                self.log.log_message("[ICMP][UNFOLD]   note: Destination Unreachable — Port Unreachable")
            elif t == 3 and c == 4:
                mtu_hint = getattr(icmp, "unused", 0) or getattr(icmp, "nexthopmtu", 0)
                self.log.log_message(f"[ICMP][UNFOLD]   note: Frag needed + DF set (mtu={mtu_hint})")
            elif t == 11:
                self.log.log_message("[ICMP][UNFOLD]   note: Time Exceeded")
            elif t == 12:
                self.log.log_message("[ICMP][UNFOLD]   note: Parameter Problem")

            # RFC 4884-like extensions present?
            if ext_len > 0:
                self._log_icmpv4_extensions(pkt, expected_inner_len=ihl_bytes + 8)

            return True
        except Exception as e:
            self.log.log_message(f"[ICMP][UNFOLD] v4 error decode failed: {e}")
            return True  # still consume as error

    def _handle_icmpv4_errors_generic(self, pkt: Packet, iface: str) -> bool:
        try:
            icmp = pkt[ICMP]
            t, c = int(icmp.type), int(getattr(icmp, "code", 0))
            if t == 3:
                self.log.log_message(f"[ICMP] 🔌 v4 DestUnreach code={c} on {self._iface_suffix(iface)}")
                return True
            if t == 11:
                self.log.log_message(f"[ICMP] ⏳ v4 TimeExceeded on {self._iface_suffix(iface)}")
                return True
            if t == 12:
                self.log.log_message(f"[ICMP] 🧩 v4 ParamProblem on {self._iface_suffix(iface)}")
                return True
            return False
        except Exception:
            return True

    # --- DNS UNFOLD helpers ---------------------------------------------------
    def _unfold_dns_from_udp_error(self, pkt: Packet, iface: str, dns_bytes: bytes) -> None:
        try:
            if not dns_bytes or len(dns_bytes) < 12:
                self.log.log_message("[ICMP][UNFOLD] ⚠️ too short for DNS header")
                self._hex_preview("DNS.bytes", dns_bytes); return

            dns_obj = None
            try:
                dns_obj = DNS(dns_bytes)
            except Exception:
                dns_obj = None

            if dns_obj is None or not hasattr(dns_obj, "qdcount"):
                tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", dns_bytes[:12])
                self.log.log_message(f"[ICMP][UNFOLD] id=0x{tid:04x} flags=0x{flags:04x} qd={qd} an={an} ns={ns} ar={ar}")
                self._hex_preview("DNS.bytes", dns_bytes)
                return

            f = dns_obj
            fl_txt = self._dns_flags_text(f)
            self.log.log_message(
                f"[ICMP][UNFOLD] id=0x{int(f.id):04x} {fl_txt} "
                f"qd={int(f.qdcount)} an={int(f.ancount)} ns={int(f.nscount)} ar={int(f.arcount)}"
            )

            # Questions
            if int(f.qdcount) > 0:
                qlist = []
                q = f.qd
                while q and len(qlist) < self.DNS_MAX_Q:
                    try:
                        nm = self._dns_name(q.qname)
                        qlist.append(f"{nm} (QTYPE={int(q.qtype)})")
                    except Exception:
                        break
                    q = q.payload if hasattr(q, "payload") else None
                    if q and not isinstance(q, DNSQR): break
                if qlist:
                    self.log.log_message(f"[ICMP][UNFOLD]   Questions: " + "; ".join(qlist))

            # Answers (highlight common MS identity domain example)
            if int(f.ancount) > 0:
                # lightweight sniff for "login.mso.msidentity.com." to spotlight
                try:
                    a = f.an
                    i, spotlighted = 0, False
                    while a and i < self.DNS_MAX_ANS and isinstance(a, DNSRR):
                        nm = self._dns_name(getattr(a, "rrname", b""))
                        if "login.mso.msidentity.com." in nm:
                            self.log.log_message("[ICMP][UNFOLD]   ⭐ Highlight: answer for login.mso.msidentity.com.")
                            spotlighted = True
                            break
                        a = a.payload if hasattr(a, "payload") else None
                        if a and not isinstance(a, DNSRR): break
                        i += 1
                    if not spotlighted:
                        pass
                except Exception:
                    pass

                self._dns_dump_rr_chain("Answers", f.an, max_items=self.DNS_MAX_ANS)

            # Authority
            if int(f.nscount) > 0:
                self._dns_dump_rr_chain("Authority", f.ns, max_items=self.DNS_MAX_AUTH)
            # Additional
            if int(f.arcount) > 0:
                self._dns_dump_rr_chain("Additional", f.ar, max_items=self.DNS_MAX_ADD)

        except Exception as e:
            self.log.log_message(f"[ICMP][UNFOLD] ❗ decode error: {e}")
            self._hex_preview("DNS.bytes", dns_bytes)

    def _dns_dump_rr_chain(self, label: str, rr, *, max_items: int) -> None:
        i = 0
        cur = rr
        out_lines: List[str] = []
        while cur and i < max_items and isinstance(cur, DNSRR):
            try:
                nm = self._dns_name(cur.rrname)
                typ = int(cur.type)
                ttl = int(getattr(cur, "ttl", 0))
                rdtxt = self._dns_rr_to_text(typ, cur)
                out_lines.append(f"{nm} {ttl}s TYPE={typ} {rdtxt}")
            except Exception:
                break
            i += 1
            cur = cur.payload if hasattr(cur, "payload") else None
            if cur and not isinstance(cur, DNSRR): break
        if out_lines:
            joined = " | ".join(out_lines[:8])
            more = "" if len(out_lines) <= 8 else f" | ...(+{len(out_lines)-8})"
            self.log.log_message(f"[ICMP][UNFOLD]   {label}: {joined}{more}")

    def _dns_rr_to_text(self, typ: int, rr: DNSRR) -> str:
        try:
            if typ == 1:    return f"A={rr.rdata}"
            if typ == 28:   return f"AAAA={rr.rdata}"
            if typ == 5:    return f"CNAME={self._dns_name(rr.rdata)}"
            if typ == 16:
                txt = rr.rdata
                s = txt.decode("utf-8", "replace") if isinstance(txt, (bytes, bytearray)) else str(txt)
                if len(s) > 120: s = s[:120] + "…"
                return f"TXT=\"{s}\""
            if typ == 15:
                try:
                    pref = getattr(rr, "pref", None)
                    exch = getattr(rr, "exchange", rr.rdata)
                    return f"MX={pref} {self._dns_name(exch)}"
                except Exception:
                    return f"MX={rr.rdata}"
            if typ == 33:
                try:
                    prio = getattr(rr, "prio", None)
                    weight = getattr(rr, "weight", None)
                    port = getattr(rr, "port", None)
                    target = self._dns_name(getattr(rr, "target", rr.rdata))
                    return f"SRV prio={prio} weight={weight} port={port} target={target}"
                except Exception:
                    return f"SRV={rr.rdata}"
            raw = rr.rdata
            if isinstance(raw, (bytes, bytearray)):
                preview = binascii.hexlify(raw[:24]).decode("ascii")
                more = "" if len(raw) <= 24 else f"...(+{len(raw)-24}B)"
                return f"RDATA[{len(raw)}B] hex[:24]={preview}{more}"
            return f"RDATA={raw}"
        except Exception:
            return "RDATA(?)"

    def _dns_flags_text(self, d: DNS) -> str:
        try:
            qr = "QR" if int(d.qr) else "Q"
            aa = "AA" if int(d.aa) else "aa0"
            tc = "TC" if int(d.tc) else "tc0"
            rd = "RD" if int(d.rd) else "rd0"
            ra = "RA" if int(d.ra) else "ra0"
            ad = "AD" if int(getattr(d, "ad", 0)) else "ad0"
            cd = "CD" if int(getattr(d, "cd", 0)) else "cd0"
            rcode = int(getattr(d, "rcode", 0))
            return f"flags={qr},{aa},{tc},{rd},{ra},{ad},{cd} rcode={rcode}"
        except Exception:
            return "flags=?"

    def _dns_name(self, raw_name: Any) -> str:
        try:
            if raw_name is None: return "."
            if isinstance(raw_name, (bytes, bytearray)):
                s = raw_name.decode("utf-8", "replace")
            else:
                s = str(raw_name)
            if len(s) > self.DNS_NAME_PREVIEW:
                s = s[:self.DNS_NAME_PREVIEW] + "…"
            return s
        except Exception:
            return "<name?>"

    def _looks_like_dns(self, buf: bytes) -> bool:
        if len(buf) < 12: return False
        try:
            qd = struct.unpack("!H", buf[4:6])[0]
            an = struct.unpack("!H", buf[6:8])[0]
            return qd <= 64 and an <= 256
        except Exception:
            return False

    # --- ICMPv4 error helpers -------------------------------------------------
    def _icmpv4_extract_inner(self, pkt: Packet) -> Tuple[Optional[IP], int, int, int, Tuple[int, int]]:
        """
        Return (inner_ip, ihl_bytes, ext_len, inner_proto, (sport,dport))
        ext_len is any RFC4884 bytes length after the quoted (ihl+8).
        """
        try:
            icmp = pkt[ICMP]
            raw_payload = bytes(icmp.payload) if hasattr(icmp, "payload") else b""

            # Preferred path using Scapy's *error* layers
            if pkt.haslayer("IPerror"):
                inner = pkt["IPerror"]
                ihl_bytes = int(getattr(inner, "ihl", 5)) * 4
                inner_proto = int(getattr(inner, "proto", 0))
                sport = dport = 0

                # If Scapy made UDPerror/TCPerror, take ports from there
                if inner_proto == 17 and pkt.haslayer("UDPerror"):
                    sport = int(getattr(pkt["UDPerror"], "sport", 0))
                    dport = int(getattr(pkt["UDPerror"], "dport", 0))
                elif inner_proto == 6 and pkt.haslayer("TCPerror"):
                    sport = int(getattr(pkt["TCPerror"], "sport", 0))
                    dport = int(getattr(pkt["TCPerror"], "dport", 0))
                else:
                    # Fallback: read ports directly from bytes (quoted L4 header)
                    try:
                        quoted = raw_payload[ihl_bytes:ihl_bytes + 4]
                        if len(quoted) >= 4 and inner_proto in (6, 17):
                            sport = int.from_bytes(quoted[0:2], "big")
                            dport = int.from_bytes(quoted[2:4], "big")
                    except Exception:
                        pass

                min_quoted = ihl_bytes + 8  # RFC says at least 8 bytes of L4 should be quoted
                ext_len = max(0, len(raw_payload) - min_quoted)
                return inner, ihl_bytes, ext_len, inner_proto, (sport, dport)

            # Raw-only fallback: try to decode inner IP straight from bytes
            if len(raw_payload) >= 20 and (raw_payload[0] >> 4) == 4:
                inner = IP(raw_payload)
                ihl_bytes = int(getattr(inner, "ihl", 5)) * 4
                inner_proto = int(getattr(inner, "proto", 0))
                sport = dport = 0
                try:
                    if len(raw_payload) >= ihl_bytes + 4 and inner_proto in (6, 17):
                        l4 = raw_payload[ihl_bytes:ihl_bytes + 4]
                        sport = int.from_bytes(l4[0:2], "big")
                        dport = int.from_bytes(l4[2:4], "big")
                except Exception:
                    pass
                min_quoted = ihl_bytes + 8
                ext_len = max(0, len(raw_payload) - min_quoted)
                return inner, ihl_bytes, ext_len, inner_proto, (sport, dport)

            # Worst-case: no inner IP decoded
            return None, 20, max(0, len(raw_payload) - (20 + 8)), 0, (0, 0)
        except Exception:
            return None, 20, 0, 0, (0, 0)

    def _log_icmpv4_extensions(self, pkt: Packet, expected_inner_len: int) -> None:
        try:
            icmp = pkt[ICMP]
            buf = bytes(icmp.payload)
            if len(buf) <= expected_inner_len: return
            ext = buf[expected_inner_len:]
            if len(ext) < 4:
                self._hex_preview("ICMPv4.ext", ext); return
            version = (ext[0] >> 4) & 0xF
            hex_preview = binascii.hexlify(ext[:self.HEX_PREVIEW_BYTES]).decode("ascii")
            if version != 2:
                self.log.log_message(f"[ICMP] 📎 v4 ext present (ver={version}) hex[:{self.HEX_PREVIEW_BYTES}]={hex_preview}")
                return
            self.log.log_message(f"[ICMP] 📎 v4 RFC4884 ext ver=2 bytes={len(ext)} hex[:{self.HEX_PREVIEW_BYTES}]={hex_preview}")
            off = 4; idx = 0
            while off + 4 <= len(ext) and idx < 16:
                klass = ext[off]; t = ext[off + 1]
                L = int.from_bytes(ext[off + 2:off + 4], "big")
                if L < 4 or off + L > len(ext):
                    self.log.log_message(f"[ICMP] ⚠️ RFC4884 TLV malformed at off={off} len={L}; stop."); break
                self.log.log_message(f"[ICMP] • ext TLV class={klass} type={t} len={L}")
                off += L; idx += 1
        except Exception:
            pass

    def _hex_preview(self, label: str, blob: bytes) -> None:
        if not self.VERBOSE_HEX_PREVIEW or not blob: return
        preview = binascii.hexlify(blob[:self.HEX_PREVIEW_BYTES]).decode("ascii")
        more = "" if len(blob) <= self.HEX_PREVIEW_BYTES else f"...(+{len(blob)-self.HEX_PREVIEW_BYTES}B)"
        self.log.log_message(f"[ICMP][HEX] {label}[:{self.HEX_PREVIEW_BYTES}]={preview}{more}")

    # --------------------------------------------------------------------------
    # IPv4 echo + frag + reassembly
    # --------------------------------------------------------------------------
    def _handle_echo_request_v4(self, pkt: Packet, iface: str, router_mac: str, router_ip: str) -> None:
        ip, icmp = pkt[IP], pkt[ICMP]
        self.log.log_message(f"[ICMP] 📨 Echo-Request v4 {ip.src} → {ip.dst} on {self._iface_suffix(iface)}")
        if self._is_rate_limited(ip.src, ip.dst): return
        if pkt.haslayer(Ether) and not self._is_loopback_name(iface):
            reply = (Ether(src=router_mac, dst=pkt[Ether].src) /
                     IP(src=router_ip, dst=ip.src) / ICMP(type=0, id=icmp.id, seq=icmp.seq) / icmp.payload)
        else:
            reply = (IP(src=router_ip, dst=ip.src) / ICMP(type=0, id=icmp.id, seq=icmp.seq) / icmp.payload)
        self._maybe_fragment_and_queue_v4(reply, iface, reason="Echo-Reply v4")
        self.log.log_message(f"[ICMP] ✅ Echo-Reply v4 queued on {self._iface_suffix(iface)} for {ip.src}")

    def _maybe_fragment_and_queue_v4(self, reply_pkt: Packet, outbound_iface: str, *, reason: str) -> None:
        mtu = self._get_iface_mtu(outbound_iface)
        if len(bytes(reply_pkt)) <= mtu:
            self.pw_send_raw_packet(reply_pkt, outbound_iface, allow_dst_ours=True, reason=reason)
            return
        l2_overhead = 14 if reply_pkt.haslayer(Ether) else 0
        ip_mtu = mtu - l2_overhead
        try:
            ip_frags = self._ipv4_fragment_datagram(reply_pkt[IP], ip_mtu)
            if reply_pkt.haslayer(Ether):
                eth = reply_pkt[Ether]
                for frag in ip_frags:
                    self.pw_send_raw_packet(Ether(src=eth.src, dst=eth.dst) / frag, outbound_iface,
                                            allow_dst_ours=True, reason=f"{reason} (frag)")
            else:
                for frag in ip_frags:
                    self.pw_send_raw_packet(frag, outbound_iface, allow_dst_ours=True, reason=f"{reason} (frag)")
            self.log.log_message(f"[ICMP] ✂ Fragmented {reason} into {len(ip_frags)} parts for {outbound_iface}.")
        except Exception as e:
            self.log.log_message(f"[ICMP] ❌ IPv4 fragmentation failed: {e}. Sending oversized packet.")
            self.pw_send_raw_packet(reply_pkt, outbound_iface, allow_dst_ours=True, reason=f"{reason} (oversize)")

    def _ipv4_fragment_datagram(self, ip_pkt: IP, ip_mtu: int) -> List[IP]:
        ihl_bytes = ip_pkt.ihl * 4
        max_payload = (ip_mtu - ihl_bytes) // 8 * 8
        payload = bytes(ip_pkt.payload)
        frags, offset = [], 0
        while offset < len(payload):
            chunk = payload[offset: offset + max_payload]
            is_more = (offset + len(chunk)) < len(payload)
            frag = ip_pkt.copy()
            frag.flags = "MF" if is_more else 0
            frag.frag = offset // 8
            if hasattr(frag, "payload"): del frag.payload
            if hasattr(frag, "chksum"):  del frag.chksum
            if hasattr(frag, "len"):     del frag.len
            frags.append(frag / chunk)
            offset += len(chunk)
        return frags

    # ---------------- IPv4 reassembly -----------------------------
    def _is_ipv4_fragment(self, ip: IP) -> bool:
        mf_flag = bool(int(ip.flags) & 0x1)
        return mf_flag or (int(ip.frag) > 0)

    def _reassemble_ipv4(self, pkt: Packet, iface: str) -> Optional[Packet]:
        ip = pkt[IP]; key = (ip.src, ip.dst, int(ip.proto), int(ip.id)); now = time.time()
        offset_bytes = int(ip.frag) * self._EIGHT
        is_last_frag = not (int(ip.flags) & 0x1)
        frag_payload = bytes(ip.payload)
        with self._reasm_lock:
            state = self._reasm.setdefault(key, {"first_hdr": ip, "parts": {}, "total": None, "t0": now, "iface": iface})
            state["parts"][offset_bytes] = frag_payload
            state["t0"] = now
            if is_last_frag:
                state["total"] = offset_bytes + len(frag_payload)
            if state["total"] is None: return None
            offsets = sorted(state["parts"].keys()); cur = 0
            for off in offsets:
                if off != cur: return None
                cur += len(state["parts"][off])
            if cur < state["total"]: return None
            full_payload = b"".join(state["parts"][off] for off in offsets)
            base = state["first_hdr"]; base.flags = 0; base.frag = 0
            full_pkt = IP(bytes(base) / full_payload)
            del self._reasm[key]
        self.log.log_message(f"[ICMP] 🔧 Reassembled IPv4 packet {ip.src}→{ip.dst} (len={len(bytes(full_pkt))})")
        return full_pkt

    # --------------------------------------------------------------------------
    # Admin-block logging for ICMPv6
    # --------------------------------------------------------------------------
    def _log_admin_block_v6(self, pkt: Packet, inbound_iface: str) -> None:
        try:
            ic = pkt[ICMPv6DestUnreach]
            code = int(getattr(ic, "code", -1))
            code_name = {1: "admin-prohibited", 5: "src-policy-fail", 6: "reject-route"}.get(code, f"code={code}")
            src = str(pkt[IPv6].src) if pkt.haslayer(IPv6) else "::"
            dst = str(pkt[IPv6].dst) if pkt.haslayer(IPv6) else "::"

            inner = None
            try:
                inner_payload = ic.payload
                if inner_payload and inner_payload.haslayer(IPv6):
                    ip6 = inner_payload[IPv6]
                    nh = int(getattr(ip6, "nh", 0))
                    if nh == 6 and inner_payload.haslayer(TCP):
                        inner = {"proto": "TCP", "src": str(ip6.src), "dst": str(ip6.dst),
                                 "sport": int(inner_payload[TCP].sport), "dport": int(inner_payload[TCP].dport)}
                    elif nh == 17 and inner_payload.haslayer(UDP):
                        inner = {"proto": "UDP", "src": str(ip6.src), "dst": str(ip6.dst),
                                 "sport": int(inner_payload[UDP].sport), "dport": int(inner_payload[UDP].dport)}
                    else:
                        inner = {"proto": str(nh), "src": str(ip6.src), "dst": str(ip6.dst), "sport": 0, "dport": 0}
            except Exception:
                inner = None

            msg = f"[ICMP] 🚫 v6 {code_name} {src} → {dst} on {self._iface_suffix(inbound_iface)}"
            if inner:
                msg += f" | inner={inner['proto']} {inner['src']}:{inner['sport']} → {inner['dst']}:{inner['dport']}"
            self.log.log_message(msg)
        except Exception:
            pass

    # --------------------------------------------------------------------------
    # Purger loop and helpers
    # --------------------------------------------------------------------------
    def _maybe_queue_v6_or_too_big(self, reply_pkt: Packet, original_pkt: Packet, iface: str, *, reason: str) -> None:
        mtu = self._get_iface_mtu(iface)
        if len(bytes(reply_pkt)) <= mtu:
            self.pw_send_raw_packet(reply_pkt, iface, allow_dst_ours=True, reason=reason)
            return
        v6_orig = original_pkt[IPv6]; v6_reply = reply_pkt[IPv6]
        ptb = IPv6(src=v6_reply.src, dst=v6_orig.src) / ICMPv6PacketTooBig(mtu=mtu) / bytes(v6_orig)[:1232]
        if reply_pkt.haslayer(Ether):
            eth = reply_pkt[Ether]; ptb_pkt = Ether(src=eth.src, dst=eth.dst) / ptb
        else:
            ptb_pkt = ptb
        self.pw_send_raw_packet(ptb_pkt, iface, allow_dst_ours=True, reason="ICMPv6 Packet-Too-Big")

    def _is_rate_limited(self, src_ip: str, dst_ip: str) -> bool:
        with self._rate_limit_lock:
            now = time.time(); key = (src_ip, dst_ip)
            if (now - self._last_reply_time[key]) < (1.0 / self.rate_limit_pps):
                self.log.log_message(f"[ICMP] 🚫 Rate-limiting Echo-Reply to {src_ip}."); return True
            self._last_reply_time[key] = now; return False

    def _purge_loop(self):
        self.log.log_message("[ICMP] Purge thread started.")
        while not self._stop_event.is_set():
            now = time.time()
            self._purge_mld_memberships(now)
            self._cleanup_reasm(now)
            self._stop_event.wait(self.PURGE_INTERVAL_SEC)
        self.log.log_message("[ICMP] Purge thread exited.")

    def _purge_mld_memberships(self, now: float) -> None:
        with self._mld_lock:
            expired = [key for key, val in self._mld_groups.items()
                       if (now - val.get("last_report", 0)) > self.MLD_MEMBERSHIP_TIMEOUT]
            for key in expired:
                g, ifn = key
                del self._mld_groups[key]
                self.log.log_message(f"[ICMP][MLD] 🧹 Timed out membership for {g} on {self._iface_suffix(ifn)}.")

    def _cleanup_reasm(self, now: float) -> None:
        with self._reasm_lock:
            expired = [key for key, state in self._reasm.items()
                       if (now - state.get("t0", 0)) > self.REASM_TIMEOUT_SEC]
            for key in expired:
                src, dst, proto, _ = key
                self.log.log_message(f"[ICMP] ⏳ Reassembly timeout v4 for {src}→{dst} proto={proto}")
                del self._reasm[key]

    # ---------------- utils / ND / addressing ---------------------
    def _match_router_ip_v4(self, dst_ip: str) -> Tuple[bool, Optional[str], Optional[str]]:
        for cfg in self.ifaces.values():
            if cfg.get("ip_addr") == dst_ip:
                return True, cfg.get("mac"), cfg.get("ip_addr")
        return False, None, None

    def _get_iface_mtu(self, name: str) -> int:
        return self.ifaces.get(name, {}).get("mtu", 1500)

    def _is_loopback_name(self, name: str) -> bool:
        n = (name or "").lower()
        return "loopback" in n or n == "lo"

    def _iface_suffix(self, iface_name: Optional[str]) -> str:
        return (iface_name or "").split("_")[-1] or "-"

    def _get_iface_ipv6(self, iface: str) -> Optional[str]:
        cfg = self.ifaces.get(iface, {})
        for key in ("ipv6_addr", "ipv6", "ip6", "ip_addr6"):
            if key in cfg: return cfg[key]
        return None

    def _iface_v6_set(self) -> set[str]:
        addrs: set[str] = set()
        for iface_name in self.ifaces:
            addr = self._norm_v6(self._get_iface_ipv6(iface_name))
            if addr: addrs.add(addr)
        return addrs

    def _norm_v6(self, addr: Any) -> Optional[str]:
        if not addr: return None
        try: return str(ipaddress.IPv6Address(addr))
        except Exception: return str(addr)

    def _is_for_router_v6(self, dst_ip: str) -> bool:
        return self._norm_v6(dst_ip) in self._iface_v6_set()

    def _iface_mac_by_v6(self, ip6: str) -> Optional[str]:
        norm_ip6 = self._norm_v6(ip6)
        for cfg in self.ifaces.values():
            for key in ("ipv6_addr", "ipv6", "ip6", "ip_addr6"):
                if self._norm_v6(cfg.get(key)) == norm_ip6:
                    return cfg.get("mac")
        return None

    def _nd_peer_mac_from_pkt(self, pkt: Packet) -> Optional[str]:
        try:
            if pkt.haslayer(ICMPv6NDOptSrcLLAddr) and pkt[ICMPv6NDOptSrcLLAddr].lladdr:
                return pkt[ICMPv6NDOptSrcLLAddr].lladdr
        except Exception:
            pass
        if pkt.haslayer(Ether):
            return pkt[Ether].src
        return None

    def _pack_nd_lladdr_opt(self, opt_type: int, mac_str: str) -> bytes:
        mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
        # Note: This simplified 8B option encodes just type/len + 6B MAC (common practice for LL addr opts)
        return bytes([opt_type & 0xFF, 1]) + mac_bytes

    def _solicited_node_mac_for_target(self, target_ip6: str) -> str:
        try:
            last24 = int(ipaddress.IPv6Address(target_ip6)) & 0xFFFFFF
            return f"33:33:ff:{(last24 >> 16) & 0xff:02x}:{(last24 >> 8) & 0xff:02x}:{last24 & 0xff:02x}"
        except Exception:
            return "33:33:ff:00:00:00"

    def _get_mld_v1_group(self, pkt: Packet) -> str:
        for layer_cls in (MLDReport, MLDDone, MLDQuery):
            if pkt.haslayer(layer_cls):
                return str(getattr(pkt[layer_cls], "mcaddr", "::"))
        return "::"

    def _ipv6_mcast_mac(self, group_ip6: str) -> str:
        try:
            v = int(ipaddress.IPv6Address(group_ip6))
            lo32 = v & 0xffffffff
            return (
                f"33:33:{(lo32 >> 24) & 0xff:02x}:"
                f"{(lo32 >> 16) & 0xff:02x}:"
                f"{(lo32 >> 8) & 0xff:02x}:"
                f"{lo32 & 0xff:02x}"
            )
        except Exception:
            return "33:33:00:00:00:00"

    # --------------------------------------------------------------------------
    # Neighbor cache update
    # --------------------------------------------------------------------------
    def _nd_learn_mac(self, ipv6_addr: str, mac_addr) -> None:
        now = time.time()
        try:
            key = str(ipaddress.IPv6Address(ipv6_addr))
        except Exception:
            key = str(ipv6_addr)

        mac_norm = None
        try:
            if isinstance(mac_addr, (bytes, bytearray)) and len(mac_addr) == 6:
                mac_norm = ":".join(f"{b:02x}" for b in mac_addr)
            elif isinstance(mac_addr, str):
                s = mac_addr.strip().lower()
                if "." in s and s.count(".") == 2:  # aabb.ccdd.eeff
                    s = s.replace(".", "")
                hexonly = "".join(ch for ch in s if ch in "0123456789abcdef")
                if len(hexonly) == 12:
                    mac_norm = ":".join(hexonly[i:i + 2] for i in range(0, 12, 2))
        except Exception:
            mac_norm = None

        if not mac_norm:
            self.log.log_message(f"[ICMP][ND] ⚠️ Ignoring invalid MAC '{mac_addr}' for {key}")
            return

        old = self.nd_cache.get(key, {}).get("mac")
        if old is None:
            self.log.log_message(f"[ICMP][ND] 📒 Learned neighbor {key} -> {mac_norm}")
        elif old.lower() != mac_norm:
            self.log.log_message(f"[ICMP][ND] 🔄 MAC change for {key}: {old} → {mac_norm}")
        self.nd_cache[key] = {"mac": mac_norm, "seen": now}

    # --------------------------------------------------------------------------
    # Active mirror (debug) during UNFOLD
    # --------------------------------------------------------------------------
    def _maybe_mirror_unfold(self, pkt: Packet, iface: str, *, family: str, why: str) -> None:
        """
        If ACTIVE_MIRROR_ICMP is True, mirror the original ICMP packet when we UNFOLD it.
        Useful with WinDivert-based capture bridges to tee ICMP to a diagnostics path.
        """
        if not self.ACTIVE_MIRROR_ICMP:
            return
        out_if = self.MIRROR_IFACE or iface
        try:
            shadow = pkt.copy()
        except Exception:
            shadow = pkt
        self.pw_send_raw_packet(shadow, out_if, allow_dst_ours=True, reason=f"UNFOLD mirror {family}: {why}")

    def _mld_join(
            self,
            group_ip: str,
            ifname: str,
            *,
            mode: str,
            sources: Optional[Set[str]],
            who: str,
    ) -> None:
        """
        Create or update an MLD membership for (group, iface).

        mode: "include" or "exclude" (others coerced to "include")
        sources: optional set of IPv6 source addresses (strings)
        """
        now = time.time()

        # Normalize group and sources defensively
        try:
            g_norm = str(ipaddress.IPv6Address(group_ip))
        except Exception:
            g_norm = str(group_ip)

        src_norm: Set[str] = set()
        if sources:
            for s in list(sources)[: self.MLD_MAX_SRCS_PER_REC]:
                try:
                    src_norm.add(str(ipaddress.IPv6Address(s)))
                except Exception:
                    src_norm.add(str(s))

        mode = "exclude" if str(mode).lower() == "exclude" else "include"

        with self._mld_lock:
            key = (g_norm, ifname)
            entry = self._mld_groups.get(key)
            if entry is None:
                entry = {"mode": mode, "sources": set(), "last_report": now}
                self._mld_groups[key] = entry

            # Update entry
            entry["mode"] = mode
            if src_norm:
                # Cap the total sources to MLD_MAX_SRCS_PER_REC
                combined = entry["sources"].union(src_norm)
                if len(combined) > self.MLD_MAX_SRCS_PER_REC:
                    # keep the first N deterministically
                    combined = set(list(sorted(combined))[: self.MLD_MAX_SRCS_PER_REC])
                entry["sources"] = combined
            entry["last_report"] = now

        # Log summary (truncate long source sets for readability)
        src_txt = ""
        if src_norm:
            show = sorted(list(src_norm))[:8]
            more = "" if len(src_norm) <= 8 else f", ...(+{len(src_norm) - 8})"
            src_txt = f" sources={show}{more}"

        self.log.log_message(
            f"[ICMP][MLD] ✅ {who} joined {g_norm} on {self._iface_suffix(ifname)} "
            f"(mode={mode}{src_txt})"
        )

    def _mld_leave(self, group_ip: str, ifname: str, *, who: str) -> None:
        """
        Remove a membership for (group, iface) if present.
        """
        try:
            g_norm = str(ipaddress.IPv6Address(group_ip))
        except Exception:
            g_norm = str(group_ip)

        with self._mld_lock:
            key = (g_norm, ifname)
            if key in self._mld_groups:
                del self._mld_groups[key]
                self.log.log_message(
                    f"[ICMP][MLD] 🗑️ {who} left {g_norm} on {self._iface_suffix(ifname)}"
                )
            else:
                # Silent if not present; you can log for debugging if you prefer:
                # self.log.log_message(f"[ICMP][MLD] (noop) leave for {g_norm} on {self._iface_suffix(ifname)}")
                pass

    def _mld_block_sources(
            self,
            group_ip: str,
            ifname: str,
            *,
            sources: Set[str],
            who: str,
    ) -> None:
        """
        Handle MLDv2 BLOCK_OLD_SOURCES. For INCLUDE-mode groups we remove sources.
        For EXCLUDE-mode groups the spec semantics are different; we just log.
        """
        try:
            g_norm = str(ipaddress.IPv6Address(group_ip))
        except Exception:
            g_norm = str(group_ip)

        src_norm: Set[str] = set()
        for s in list(sources)[: self.MLD_MAX_SRCS_PER_REC]:
            try:
                src_norm.add(str(ipaddress.IPv6Address(s)))
            except Exception:
                src_norm.add(str(s))

        with self._mld_lock:
            key = (g_norm, ifname)
            entry = self._mld_groups.get(key)
            if entry is None:
                # No membership to modify; log and return.
                self.log.log_message(
                    f"[ICMP][MLD] ℹ️ BLOCK for {g_norm} on {self._iface_suffix(ifname)} but no membership exists"
                )
                return

            if entry.get("mode", "include") == "include":
                before = len(entry["sources"])
                entry["sources"].difference_update(src_norm)
                entry["last_report"] = time.time()
                after = len(entry["sources"])
                self.log.log_message(
                    f"[ICMP][MLD] 🔄 {who} blocked {len(src_norm)} source(s) for {g_norm} on "
                    f"{self._iface_suffix(ifname)} (include-mode {before}→{after})"
                )
            else:
                # EXCLUDE semantics are not simply "remove"; log visibility only.
                self.log.log_message(
                    f"[ICMP][MLD] 📘 {who} BLOCK sources for {g_norm} on {self._iface_suffix(ifname)} "
                    f"(exclude-mode; no change applied)"
                )

    def _transit_rl_ok(self, src: str, dst: str) -> bool:
        now = time.time()
        key = (src, dst)
        last = self._transit_rl.get(key, 0.0)
        if (now - last) < (1.0 / max(1, self.TRANSIT_ECHO_RATE_LIMIT_PPS)):
            return False
        self._transit_rl[key] = now
        return True

    def _handle_transit_echo_v4(self, pkt: Packet, iface: str) -> bool:
        """
        Unfold a transit echo-request and optionally act:
          - 'reject' : send ICMP dest-unreach (admin-prohibited) back to sender
          - 'mirror' : tee the exact packet to MIRROR_IFACE (or inbound iface)
          - 'none'   : just unfold/log
        Returns True if we transmitted something or fully handled it.
        """
        ip = pkt[IP];
        icmp = pkt[ICMP]
        if int(icmp.type) != 8:
            return False

        # --- Unfold/log details
        try:
            ihl_bytes = int(getattr(ip, "ihl", 5)) * 4
        except Exception:
            ihl_bytes = 20
        icmp_id = int(getattr(icmp, "id", 0))
        icmp_seq = int(getattr(icmp, "seq", 0))
        ttl = int(getattr(ip, "ttl", -1))
        total = int(getattr(ip, "len", len(bytes(ip))))
        df = bool(int(getattr(ip, "flags", 0)) & 0x2)
        payload = bytes(icmp.payload) if hasattr(icmp, "payload") else b""

        self.log.log_message(
            f"[ICMP][UNFOLD][ECHO] transit v4 {ip.src}→{ip.dst} "
            f"id={icmp_id} seq={icmp_seq} ttl={ttl} len={total} df={int(df)} "
            f"payload={len(payload)}B on {self._iface_suffix(iface)}"
        )
        self._hex_preview("ICMPv4.echo.payload", payload)

        # --- Action policy
        policy = (self.TRANSIT_ECHO_POLICY or "none").lower()
        if policy == "none":
            return False

        # Mirror-only path
        if policy == "mirror":
            if not self._transit_rl_ok(ip.src, ip.dst):
                return True
            out_if = self.MIRROR_IFACE or iface
            try:
                shadow = pkt.copy()
            except Exception:
                shadow = pkt
            self.pw_send_raw_packet(shadow, out_if, allow_dst_ours=True, reason="mirror transit echo v4")
            return True

        # Reject path: send ICMP DestUnreach(code=13) back to sender
        if policy == "reject":
            if not self._transit_rl_ok(ip.src, ip.dst):
                return True

            cfg = self.ifaces.get(iface, {})
            my_ip = cfg.get("ip_addr")
            my_mac = cfg.get("mac")
            if not my_ip:
                self.log.log_message(
                    f"[ICMP][UNFOLD][ECHO] ⚠️ no iface IPv4 on {self._iface_suffix(iface)}; cannot reject.")
                return True

            # Quote original IP header + 8 bytes of its payload (RFC 792)
            raw_ip = bytes(ip)
            quote_len = min(len(raw_ip), ihl_bytes + 8)
            quoted = Raw(raw_ip[:quote_len])

            base = IP(src=my_ip, dst=ip.src, ttl=64)
            du = ICMP(type=3, code=13)  # admin-prohibited

            if pkt.haslayer(Ether) and not self._is_loopback_name(iface) and my_mac:
                out = Ether(src=my_mac, dst=pkt[Ether].src) / base / du / quoted
            else:
                out = base / du / quoted

            self.pw_send_raw_packet(out, iface, allow_dst_ours=True, reason="ICMPv4 reject (transit echo)")
            self.log.log_message(
                f"[ICMP] 🚫 Sent v4 admin-prohibited to {ip.src} (for transit echo to {ip.dst}) "
                f"on {self._iface_suffix(iface)}"
            )
            return True

        return False
