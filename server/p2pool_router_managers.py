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
from typing import Optional, List, Any
import ipaddress
import threading
import json
import time
import numpy as np
from scapy.arch import get_if_hwaddr
from scapy.contrib.ikev2 import IKEv2
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import  DNS
from scapy.layers.inet import TCP, ICMP, defrag
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoReply
from scapy.layers.l2 import ARP, Ether, Dot1Q, getmacbyip
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
        self.logged_quic_streams = {}
        self.QUIC_STREAM_TIMEOUT = 300
        self.last_quic_cleanup_time = time.time()

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
                f"[Transport][🧵 TCP] Packet on {iface_short}: {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport} | "
                f"Flags: {','.join(flag_details)} | Payload: {payload_len}"
            )
            if packet.haslayer(TLS):
                self._handle_tls_handshake(packet)
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

            return True

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

            return True

        return False

    def _handle_tls_handshake(self, packet: Packet):
        """
        Dissects and logs various TLS handshake messages to provide a more
        complete view of the handshake process.
        """
        current_layer = packet
        while current_layer:
            layer_name = current_layer.__class__.__name__

            if hasattr(current_layer, "msg_type") and "TLSHandshake" in layer_name:
                try:
                    for handshake_msg in current_layer.msg:
                        msg_type_name = handshake_msg.msg_type.name
                        self.logger.log_message(
                            f"[Transport][🧵 TCP][🔐 TLS] Handshake Message: {msg_type_name}")
                except Exception as e:
                    self.logger.log_message(f"[Transport][🧵 TCP][⚠️ TLS] Failed to read msg_type on {layer_name}: {e}")

            current_layer = current_layer.payload

        if packet.haslayer(TLSServerHello):
            self.logger.log_message("[Transport][🧵 TCP][🤝 TLS] Server Hello message detected.")
        if packet.haslayer(TLSCertificate):
            self.logger.log_message("[Transport][🧵 TCP][🤝 TLS] Certificate message detected.")
        if packet.haslayer(TLSServerKeyExchange):
            self.logger.log_message("[Transport][🧵 TCP][🤝 TLS] Server Key Exchange message detected.")
            self._dissect_server_key_exchange(packet)
        if packet.haslayer(TLSServerHelloDone):
            self.logger.log_message("[Transport][🧵 TCP][🤝 TLS] Server Hello Done message detected.")
        if packet.haslayer(TLSClientKeyExchange):
            self.logger.log_message("[Transport][🧵 TCP][🤝 TLS] Client Key Exchange message detected.")
            self._dissect_client_key_exchange(packet)
        if packet.haslayer(TLSChangeCipherSpec):
            self.logger.log_message("[Transport][🧵 TCP][🤝 TLS] Change Cipher Spec message detected.")

    def _dissect_server_key_exchange(self, packet: Packet):
        """Dissects the parameters within a TLSServerKeyExchange message."""
        ske = packet[TLSServerKeyExchange]

        if packet.haslayer(ServerECDHNamedCurveParams):
            params = packet[ServerECDHNamedCurveParams]
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] Key Exchange: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)"
            )
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] Curve: {params.named_curve.name} (ID: {params.named_curve})"
            )
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] Server Public Point (Yc): 0x{params.point.hex()}"
            )
        elif packet.haslayer(ServerDHParams):
            params = packet[ServerDHParams]
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] Key Exchange: DHE (Diffie-Hellman Ephemeral)"
            )
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] DH Prime (p) length: {len(params.dh_p)} bytes"
            )
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] DH Generator (g) length: {len(params.dh_g)} bytes"
            )
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] Server Public Value (Ys) length: {len(params.dh_Ys)} bytes"
            )
        if ske.sig_len > 0:
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] Signature Algorithm: {ske.sig_hash_alg.name}"
            )
            self.logger.log_message(
                f"[Transport][🧵 TCP]   [+] Signature Length: {ske.sig_len} bytes"
            )
        else:
            self.logger.log_message("[Transport][🧵 TCP]   [+] No signature present in this message.")

    def _dissect_client_key_exchange(self, packet: Packet):
        """Dissects the data within a TLSClientKeyExchange message."""
        try:
            if packet.haslayer(ClientECDiffieHellmanPublic):
                params = packet[ClientECDiffieHellmanPublic]
                self.logger.log_message(
                    f"[Transport][🧵 TCP]   [+] Client Public Point (Yc) Length: {len(params.ecdh_Yc)} bytes"
                )
            elif packet.haslayer(ClientDiffieHellmanPublic):
                params = packet[ClientDiffieHellmanPublic]
                self.logger.log_message(
                    f"[Transport][🧵 TCP]   [+] Client Public Value (Yc) Length: {len(params.dh_Yc)} bytes"
                )
            elif packet.haslayer(EncryptedPreMasterSecret):
                self.logger.log_message(
                    f"[Transport][🧵 TCP]   [+] Encrypted Pre-Master Secret found (RSA Key Exchange)."
                )
        except Exception as e:
            self.logger.log_message(f"[Transport][🧵 TCP] Error dissecting TLS Client Key Exchange: {e}")

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

        Returns:
            A tuple containing (the integer value, number of bytes consumed).
            Returns (0, 0) if data is invalid or insufficient.
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
    Manages passive monitoring of HTTPS/TLS and TCP traffic.
    This enhanced version provides detailed logging for TLS 1.2 and 1.3 handshakes,
    and now includes a comprehensive analysis of TCP connection establishment,
    termination, and key options.
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.cipher_map = self.build_cipher_suite_map()
        self.router_logger.log_message("[HTTPS] 🔒 Initialized for passive TLS/TCP monitoring.")
        self.router_logger.log_message(f"[HTTPS] 🗺️  Built map with {len(self.cipher_map)} cipher suites.")

        self.TLS_VERSIONS = {
            0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"
        }

        # Updated to include TLS 1.2 handshake messages
        self.TLS_HANDSHAKE_TYPES = {
            0: "hello_request_RESERVED", 1: "client_hello", 2: "server_hello",
            3: "hello_verify_request_RESERVED", 4: "new_session_ticket",
            5: "end_of_early_data", 6: "hello_retry_request_RESERVED",
            8: "encrypted_extensions", 11: "certificate",
            12: "server_key_exchange", 13: "certificate_request",
            14: "server_hello_done", 15: "certificate_verify",
            16: "client_key_exchange", 20: "finished",
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
        # Primarily focus on modern, secure cipher suites
        cipher_map = {
            # TLS 1.3 Cipher Suites
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384",
            0x1303: "TLS_CHACHA20_POLY1305_SHA256",
            # TLS 1.2 ECDHE Cipher Suites
            0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        }
        # Add more cipher suites from Scapy's dictionaries if needed
        if 'tls_ciphersuites' in globals():
            cipher_map.update(globals()['tls_ciphersuites'])
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
            # A single TCP packet can contain multiple TLS records
            while tls_layer:
                if isinstance(tls_layer, TLS):
                    # Handle different record types
                    if tls_layer.type == 22 and tls_layer.payload:  # Handshake
                        # A single handshake record can contain multiple messages
                        handshake_payload = tls_layer.payload
                        while handshake_payload and isinstance(handshake_payload, Packet) and hasattr(handshake_payload,'msg_type'):
                            processed = self._handle_tls_handshake_payload(handshake_payload,
                                                                           inbound_iface) or processed
                            handshake_payload = handshake_payload.payload
                    elif tls_layer.type == 21:  # Alert
                        processed = self._handle_tls_alert(tls_layer.payload, inbound_iface) or processed
                    elif tls_layer.type == 23:  # Application Data
                        processed = self._handle_tls_app_data(inbound_iface) or processed

                # Move to the next potential TLS record in the same TCP packet
                tls_layer = tls_layer.payload if hasattr(tls_layer, 'payload') and isinstance(tls_layer.payload,
                                                                                              TLS) else None

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
        elif flags == 16 and current_state == "SYN-RECEIVED":  # ACK of SYN-ACK
            self.router_logger.log_message(
                f"[TCP] Handshake Completed: Client {src_ip}:{src_port} sent ACK. ✅ Connection ESTABLISHED.")
            self.tcp_state_map[conn_key] = "ESTABLISHED"

        # Connection Termination
        elif 'F' in str(flags):
            if current_state == "ESTABLISHED":
                self.router_logger.log_message(
                    f"[TCP] Termination Started: {src_ip}:{src_port} sent FIN. ✂️ State: FIN-WAIT-1.")
                self.tcp_state_map[conn_key] = "FIN-WAIT-1"
        elif 'R' in str(flags):
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

    def _handle_tls_handshake_payload(self, payload: Packet, iface_short: str) -> bool:
        """
        Processes a single TLS handshake message from within a TLS record.
        """
        processed = False
        handshake_type_val = payload.msg_type
        handshake_type_str = self.TLS_HANDSHAKE_TYPES.get(handshake_type_val, f"Unknown ({handshake_type_val})")

        self.router_logger.log_message(
            f"[HTTPS] 🤝 TLS Handshake Message: {handshake_type_str} detected on {iface_short}.")

        if isinstance(payload, TLSClientHello):
            self._handle_client_hello(payload, iface_short)
            processed = True
        elif isinstance(payload, TLSServerHello):
            self._handle_server_hello(payload, iface_short)
            processed = True
        elif isinstance(payload, TLSCertificate):
            self._handle_certificate(payload, iface_short)
            processed = True
        elif isinstance(payload, TLSServerKeyExchange):
            self.router_logger.log_message("[HTTPS]   - 🔑 Server Key Exchange received (parameters for DH/ECDH).")
            processed = True
        elif isinstance(payload, TLSCertificateRequest):
            self.router_logger.log_message("[HTTPS]   - 🤝 Server requested a client certificate (Mutual TLS).")
            processed = True
        elif isinstance(payload, TLSServerHelloDone):
            self.router_logger.log_message("[HTTPS]   - 👉 Server Hello Done. Server is awaiting client's response.")
            processed = True
        elif isinstance(payload, TLSClientKeyExchange):
            self.router_logger.log_message("[HTTPS]   - 🔑 Client Key Exchange received (contains premaster secret).")
            processed = True
        elif isinstance(payload, TLSFinished):
            self.router_logger.log_message("[HTTPS]   - 🎉 Handshake Finished message. Connection keys established.")
            processed = True
        # TLS 1.3 specific messages
        elif isinstance(payload, TLSEncryptedExtensions):
            self.router_logger.log_message("[HTTPS]   - 📝 Encrypted extensions received. Server's final parameters.")
            self._handle_extensions_from_payload(payload)
            processed = True
        elif isinstance(payload, TLSNewSessionTicket):
            self.router_logger.log_message("[HTTPS]   - 🎟️ New session ticket issued, enabling session resumption.")
            processed = True

        return processed

    def _handle_client_hello(self, client_hello: TLSClientHello, iface_short: str):
        """Processes and logs details from a TLS ClientHello message."""
        version_str = self.TLS_VERSIONS.get(client_hello.version, f"Unknown (0x{client_hello.version:04x})")
        self.router_logger.log_message(f"[HTTPS]   - Version Offered: {version_str}")
        if hasattr(client_hello, 'ciphers'):
            self.router_logger.log_message(f"[HTTPS]   - Ciphers Offered: {len(client_hello.ciphers)}")

        self._handle_extensions_from_payload(client_hello)

    def _handle_server_hello(self, server_hello: TLSServerHello, iface_short: str):
        """Processes and logs details from a TLS ServerHello message."""
        version_str = self.TLS_VERSIONS.get(server_hello.version, f"Unknown (0x{server_hello.version:04x})")
        self.router_logger.log_message(f"[HTTPS]   - Version Negotiated: {version_str}")
        cipher_suite = server_hello.cipher
        cipher_name = self.cipher_map.get(cipher_suite, f"Unknown (ID: 0x{cipher_suite:04x})")
        self.router_logger.log_message(f"[HTTPS]   - Cipher Suite Chosen: {cipher_name}")

        self._handle_extensions_from_payload(server_hello)

    def _handle_extensions_from_payload(self, payload: Packet):
        """Parses and logs details from TLS extensions in a handshake message."""
        if hasattr(payload, 'ext') and payload.ext:
            self.router_logger.log_message(f"[HTTPS]   - Extensions ({len(payload.ext)} total):")
            for ext in payload.ext:
                ext_type = getattr(ext, 'type', None)
                ext_name = self.TLS_EXTENSIONS.get(ext_type, f"Unknown (ID: {ext_type})")
                self.router_logger.log_message(f"[HTTPS]     - Found Extension: {ext_name}")

                # Identify specific extensions by their numeric type ID
                if ext_type == 0 and hasattr(ext, 'servernames'):  # server_name (SNI)
                    sni_name = ext.servernames[0].servername.decode('utf-8', 'ignore')
                    self.router_logger.log_message(f"[HTTPS]       - SNI: {sni_name} 🌐")
                elif ext_type == 16 and hasattr(ext, 'protocols'):  # application_layer_protocol_negotiation (ALPN)
                    alpn_list = [self.ALPN_PROTOCOLS.get(p, p.decode('utf-8', 'ignore')) for p in ext.protocols]
                    self.router_logger.log_message(f"[HTTPS]       - ALPN Protocols: {', '.join(alpn_list)} 💬")
                elif ext_type == 43 and hasattr(ext, 'versions'):  # supported_versions
                    version_list = [self.TLS_VERSIONS.get(v, f"Unknown (0x{v:04x})") for v in ext.versions]
                    self.router_logger.log_message(f"[HTTPS]       - Supported Versions: {', '.join(version_list)} 📜")

    def _handle_certificate(self, cert_payload: TLSCertificate, iface_short: str):
        """Processes and logs details from a TLS Certificate message."""
        num_certs = len(cert_payload.certs)
        self.router_logger.log_message(
            f"[HTTPS] 📜 Certificate message detected on {iface_short} with {num_certs} certificate(s).")
        if num_certs > 0:
            # Scapy wraps the ASN.1 cert in an X509Cert object
            server_cert = cert_payload.certs[0].cert
            # The subject commonName is often a good identifier
            if hasattr(server_cert, 'tbsCertificate') and hasattr(server_cert.tbsCertificate, 'subject'):
                subject_rdn = server_cert.tbsCertificate.subject.rdnSequence
                for rdn in subject_rdn:
                    # Look for the commonName attribute
                    if rdn[0].type.val == '2.5.4.3':
                        cn = rdn[0].value.val.decode('utf-8', 'ignore')
                        self.router_logger.log_message(f"[HTTPS]   - Certificate CN: {cn} 👨‍💻")
                        break
            # Log validity period
            if hasattr(server_cert, 'tbsCertificate') and hasattr(server_cert.tbsCertificate, 'validity'):
                valid_from = server_cert.tbsCertificate.validity.notBefore.val
                valid_to = server_cert.tbsCertificate.validity.notAfter.val
                self.router_logger.log_message(f"[HTTPS]   - Validity: {valid_from} to {valid_to} 📅")

    def _handle_tls_alert(self, alert_payload: Packet, iface_short: str) -> bool:
        """Processes and logs details from a TLS Alert message."""
        if isinstance(alert_payload, TLSAlert):
            level = self.TLS_ALERT_LEVEL.get(alert_payload.level, "Unknown")
            description = self.TLS_ALERT_DESCRIPTION.get(alert_payload.descr, "Unknown")
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

    def handle_kerberos_packet(self, packet: Packet, inbound_iface: str, interfaces_config: Dict[str, Any]) -> bool:
        """
        Attempts to extract and handle a Kerberos packet.
        """
        iface_short = inbound_iface.split('_')[-1]

        try:
            # Try to extract or reparse Kerberos layer manually from UDP payload
            if Kerberos not in packet:
                if packet.haslayer(UDP) and packet.haslayer(Raw):
                    raw_data = bytes(packet[Raw].load)
                    first_tag = raw_data[0]

                    # Valid Kerberos tags (context-specific constructed)
                    valid_kerberos_tags = [96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
                                           106, 107, 108, 109, 110, 111, 126]  # as per RFC 4120

                    if first_tag in valid_kerberos_tags:
                        try:
                            kerb_layer = Kerberos(raw_data)
                            packet[UDP].remove_payload()
                            packet = packet / kerb_layer
                        except Exception as decode_error:
                            return True
                    else:
                        return True

            kerb_layer = packet[Kerberos]
            self.router_logger.log_message(f"[KerberosManager] 🔑 Kerberos packet detected on {iface_short}.")

            # Identify message type
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
                if item is None: continue
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

        router_ips = [cfg["ip_addr"] for cfg in self._interfaces_config.values() if "ip_addr" in cfg]
        dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else None

        allow_local_dest = bool(getattr(packet, "_pw_allow_local_dest", False))
        if dst_ip in router_ips and not allow_local_dest:
            self.logger.log_message(
                f"[PacketWriter] 🚫 Dropped packet: Destination IP ({dst_ip}) is our own. Summary: {packet.summary()}")
            return

        try:
            self.packet_signer.sign_packet(packet)
            # This call now receives the correct system name
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

        dst_mac = "ff:ff:ff:ff:ff:ff" if allow_broadcast and pkt.haslayer(
            Ether) and pkt.dst.lower() == "ff:ff:ff:ff:ff:ff" else getmacbyip(
            nh_ip) if nh_ip else pkt.dst if pkt.haslayer(Ether) and pkt.dst else None
        if not dst_mac and nh_ip:
            self.logger.log_message(f"[PacketWriter] forward_l2: ARP failed for next-hop {nh_ip} on {egress_iface}")
            return
        if not dst_mac:
            self.logger.log_message("[PacketWriter] forward_l2: No next-hop and no Ether dst to use")
            return

        payload = pkt.payload if pkt.haslayer(Ether) else pkt
        out_frame = Ether(src=src_mac, dst=dst_mac) / (
            Dot1Q(vlan=pkt[Dot1Q].vlan) / payload if preserve_vlan and pkt.haslayer(Dot1Q) else payload)

        is_ike_packet = UDP in pkt and (pkt[UDP].sport in [500, 4500] or pkt[UDP].dport in [500, 4500])
        if is_ike_packet:
            self.logger.log_message(f"[PacketWriter] 🛡️ IKE packet detected, applying forwarding overrides.")

        final_allow_local = allow_local_dest or is_ike_packet
        final_allow_broadcast = allow_broadcast or is_ike_packet

        setattr(out_frame, "_pw_tx", True)
        if final_allow_local: setattr(out_frame, "_pw_allow_local_dest", True)
        if final_allow_broadcast: setattr(out_frame, "_pw_allow_broadcast", True)

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
        """
        if self._stop_event.is_set():
            self.logger.log_message("[PacketWriter] ⚠️ Warning: Cannot queue packet — writer is stopping.")
            return

        target_iface_name = interface or self.outbound_load_balancer.get_next_interface(packet)
        if not target_iface_name:
            self.logger.log_message("[PacketWriter] ⚠️ Dropped packet: No outbound interface determined.")
            return

        # --- FIX: Translate the friendly name to the required system name using the map ---
        final_iface = self.iface_map.get(target_iface_name, target_iface_name)
        if final_iface == target_iface_name:
            if not target_iface_name.startswith("\\Device\\NPF_"):
                self.logger.log_message(
                    f"[PacketWriter] ⚠️ Warning: No system name found for '{target_iface_name}'. Sending may fail.")
        # ---------------------------------------------------------------------------------

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