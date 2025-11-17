# ========================================================
# ================  packet_analysis_pipeline.py  =========
# ========================================================
#
# A "block & pipeline" system for parsing Scapy packets
# into a structured "analysis" dictionary.
#
# This version is designed for "side effects" (logging and memory save)
# and is stateless, built to run forever in a background process.
#
# ========================================================

from __future__ import annotations

import json
import os
import struct
import sys
import time
import re
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Callable

# --- Scapy Imports ---------------------------------------------------
try:
    from scapy.packet import Packet, Raw
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dot11 import Dot11
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS
    from scapy.layers.dhcp import DHCP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    # [FIXED] Removed TLSExtension_ServerName and SSDP
    from scapy.layers.ntp import NTP

except ImportError:
    print("CRITICAL: 'scapy' library not found. Packet analysis blocks will fail.", file=sys.stderr)
    # Use a real dummy class for isinstance() checks
    DummyPacket = type("DummyPacket", (object,), {})
    Packet = Raw = DummyPacket
    Ether = ARP = Dot11 = IP = IPv6 = TCP = UDP = ICMP = DNS = DHCP = DummyPacket
    HTTP = HTTPRequest = HTTPResponse = TLSClientHello = TLSServerHello = DummyPacket
    NTP = DummyPacket  # [FIXED] Removed TLSExtension_ServerName and SSDP


# ========================================================
# 1. BLOCK REGISTRY
# ========================================================

@dataclass
class BlockRegistry:
    _registry: Dict[str, Tuple[type["BaseBlock"], str]] = field(default_factory=dict)

    def register(self, name: str, *, help: str) -> Callable[[type["BaseBlock"]], type["BaseBlock"]]:
        key = name.strip().lower()
        if key in self._registry:
            raise ValueError(f"Duplicate block name: {name}")

        def _decorator(cls: type["BaseBlock"]) -> type["BaseBlock"]:
            self._registry[key] = (cls, help)
            return cls

        return _decorator

    def create(self, name: str) -> "BaseBlock":
        key = name.strip().lower()
        if key not in self._registry:
            available = ", ".join(self.names()) or "(none)"
            raise KeyError(f"Unknown block '{name}'. Available: {available}")
        cls, _ = self._registry[key]
        return cls()

    def names(self) -> List[str]:
        return sorted(self._registry.keys())


BLOCKS = BlockRegistry()


# ========================================================
# 2. BASE BLOCK CLASS
# ========================================================

@dataclass
class BaseBlock:
    logger: Any = None

    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        raise NotImplementedError

    def get_params_info(self) -> Dict[str, Any]:
        return {}

    def log(self, message: str):
        if self.logger and hasattr(self.logger, 'log_message'):
            self.logger.log_message(message)
        else:
            print(message, file=sys.stderr)


# ========================================================
# 3. MEMORY & HELPERS
# ========================================================

APP_DIR = os.path.join(os.path.expanduser("~"), ".promptchat")
MEMORY_PATH = os.path.join(APP_DIR, "memory.json")


def ensure_app_dirs() -> None:
    os.makedirs(APP_DIR, exist_ok=True)
    if not os.path.exists(MEMORY_PATH):
        with open(MEMORY_PATH, "w", encoding="utf-8") as f:
            f.write("{}")


class Memory:
    @staticmethod
    def load() -> Dict[str, Any]:
        try:
            with open(MEMORY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    @staticmethod
    def save(data: Dict[str, Any]) -> None:
        try:
            ensure_app_dirs()
            with open(MEMORY_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving memory: {e}", file=sys.stderr)


def parse_extras(items: List[str]) -> Dict[str, Dict[str, Any]]:
    def _coerce(v: str) -> Any:
        s = v.strip()
        low = s.lower()
        if low in ("true", "false"): return low == "true"
        try:
            if s.isdigit(): return int(s)
            return float(s)
        except Exception:
            pass
        if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
            return s[1:-1]
        return s

    out: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if "=" not in item: continue
        k, v = item.split("=", 1)
        if "." in k:
            group, key = k.split(".", 1)
        else:
            group, key = "all", k
        group, key = group.strip().lower(), key.strip()
        out.setdefault(group, {})[key] = _coerce(v)
    return out


def create_pipeline_extras(
        *,
        logger: Any = None,
        stages: str = "init_packet|parse_l2|parse_arp|parse_l3|parse_l4|parse_app|analyze_payload|tee",
        memory_key: str = "last_packet_info",
        debug: bool = False,
        stop_on_error: bool = True,
) -> Dict[str, Any]:
    """
    Convenience helper: build an "extras" dict for PacketPipelineBlock.
    """
    extras: Dict[str, Any] = {
        "logger": logger,
        "pipeline": {
            "stages": stages,
            "debug": bool(debug),
            "stop_on_error": bool(stop_on_error),
        },
        "tee": {
            "key": memory_key,
        },
    }
    return extras


# ========================================================
# 4. PACKET-SPECIFIC BLOCKS
# ========================================================

@BLOCKS.register("init_packet", help="Initialize the analysis dict from a raw Scapy Packet.")
@dataclass
class InitializePacketInfoBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        if not isinstance(payload, Packet):
            err = "Input payload was not a Scapy Packet"
            self.log(f"[Analysis][init_packet] ERROR: {err}")
            info_dict = {
                "packet": None, "analysis": {"error": err},
                "metadata": {"timestamp": time.time(), "summary": str(payload)},
            }
            return info_dict, {"status": "error", "error": err}
        info_dict = {
            "packet": payload, "analysis": {},
            "metadata": {"timestamp": time.time(), "summary": payload.summary()},
        }
        return info_dict, {"status": "initialized", "summary": info_dict["metadata"]["summary"]}


@BLOCKS.register("parse_l2", help="Parse L2 (Ethernet/WiFi) information.")
@dataclass
class ParseL2Block(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        if not isinstance(payload, dict) or "packet" not in payload:
            return payload, {"error": "Invalid payload, expected analysis dict."}
        packet = payload.get("packet")
        if not packet: return payload, {"error": "No packet found in payload."}

        l2_info: Dict[str, Any] = {}
        log_msg = ""

        if packet.haslayer(Ether):
            l2_layer = packet[Ether]
            l2_info = {
                "layer": "ethernet",
                "src_mac": l2_layer.src,
                "dst_mac": l2_layer.dst,
                "type": l2_layer.type,
            }
            log_msg = f"[Analysis][parse_l2] Found L2: {l2_info.get('src_mac')} -> {l2_info.get('dst_mac')}"

        elif packet.haslayer(Dot11):
            l2_layer = packet[Dot11]
            l2_info = {
                "layer": "wifi_dot11",
                "addr1": l2_layer.addr1,  # Receiver
                "addr2": l2_layer.addr2,  # Transmitter
                "addr3": l2_layer.addr3,  # BSSID
                "type": l2_layer.type,
                "subtype": l2_layer.subtype,
            }
            log_msg = f"[Analysis][parse_l2] Found L2: WiFi {l2_info.get('addr2')} -> {l2_info.get('addr1')}"

        if l2_info:
            payload.setdefault("analysis", {})["l2"] = l2_info
            if log_msg: self.log(log_msg)
            return payload, {"l2_parsed": True}

        return payload, {"l2_parsed": False}


@BLOCKS.register("parse_arp", help="Parse L2 (ARP) information.")
@dataclass
class ParseARPBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        if not isinstance(payload, dict) or "packet" not in payload:
            return payload, {"error": "Invalid payload, expected analysis dict."}
        packet = payload.get("packet")
        if not packet: return payload, {"error": "No packet found in payload."}

        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            arp_info = {
                "op": arp_layer.op,  # 1=who-has, 2=is-at
                "hwsrc": arp_layer.hwsrc, "psrc": arp_layer.psrc,
                "hwdst": arp_layer.hwdst, "pdst": arp_layer.pdst,
            }
            payload.setdefault("analysis", {})["arp"] = arp_info

            op_str = "Who-has" if arp_layer.op == 1 else "Is-at"
            log_msg = f"[Analysis][parse_arp] Found ARP: {op_str} {arp_layer.psrc} -> {arp_layer.pdst}"
            self.log(log_msg)
            return payload, {"arp_parsed": True, "op": op_str}

        return payload, {"arp_parsed": False}


@BLOCKS.register("parse_l3", help="Parse L3 (IPv4/IPv6) information.")
@dataclass
class ParseL3Block(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        if not isinstance(payload, dict) or "packet" not in payload:
            return payload, {"error": "Invalid payload, expected analysis dict."}
        packet = payload.get("packet")
        if not packet: return payload, {"error": "No packet found in payload."}

        l3_info: Dict[str, Any] = {}
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            l3_info = {
                "version": 4, "src": ip_layer.src, "dst": ip_layer.dst,
                "proto": ip_layer.proto, "ttl": ip_layer.ttl,
                "flags": str(ip_layer.flags), "len": ip_layer.len,
            }
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
            l3_info = {
                "version": 6, "src": ip_layer.src, "dst": ip_layer.dst,
                "proto": ip_layer.nh, "hlim": ip_layer.hlim, "len": ip_layer.plen,
            }

        if l3_info:
            payload.setdefault("analysis", {})["l3"] = l3_info
            self.log(
                f"[Analysis][parse_l3] Found L3: v{l3_info.get('version')} {l3_info.get('src')} -> {l3_info.get('dst')}")
            return payload, {"l3_parsed": True, "version": l3_info.get("version")}
        return payload, {"l3_parsed": False}


@BLOCKS.register("parse_l4", help="Parse L4 (TCP/UDP/ICMP) information.")
@dataclass
class ParseL4Block(BaseBlock):
    def _get_tcp_flags(self, flag_val: Any) -> str:
        flags_map = {
            'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
            'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR',
        }
        flag_str = str(flag_val)
        human_flags = [flags_map[f] for f in flag_str if f in flags_map]
        return f"[{', '.join(human_flags)}]" if human_flags else f"[{flag_str}]"

    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        if not isinstance(payload, dict) or "packet" not in payload:
            return payload, {"error": "Invalid payload, expected analysis dict."}
        packet = payload.get("packet")
        if not packet: return payload, {"error": "No packet found in payload."}

        l4_info: Dict[str, Any] = {}
        proto_name: Optional[str] = None
        log_msg = ""

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            proto_name = "tcp"
            human_flags = self._get_tcp_flags(tcp_layer.flags)
            l4_info = {
                "proto": "tcp", "sport": tcp_layer.sport, "dport": tcp_layer.dport,
                "seq": tcp_layer.seq, "ack": tcp_layer.ack,
                "flags_raw": str(tcp_layer.flags), "flags": human_flags,
                "window": tcp_layer.window,
            }
            log_msg = f"[Analysis][parse_l4] Found L4: TCP {l4_info['sport']} -> {l4_info['dport']} Flags: {human_flags}"

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            proto_name = "udp"
            l4_info = {
                "proto": "udp", "sport": udp_layer.sport,
                "dport": udp_layer.dport, "len": udp_layer.len,
            }
            log_msg = f"[Analysis][parse_l4] Found L4: UDP {l4_info['sport']} -> {l4_info['dport']}"

        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            proto_name = "icmp"
            l4_info = {
                "proto": "icmp", "type": icmp_layer.type, "code": icmp_layer.code,
            }
            log_msg = f"[Analysis][parse_l4] Found L4: ICMP type={l4_info['type']} code={l4_info['code']}"

        if l4_info:
            payload.setdefault("analysis", {})["l4"] = l4_info
            if log_msg: self.log(log_msg)
            return payload, {"l4_parsed": True, "proto": proto_name}

        return payload, {"l4_parsed": False}


@BLOCKS.register("parse_app", help="Parse App Layer (DNS, DHCP, TLS, HTTP, etc.) info.")
@dataclass
class ParseAppBlock(BaseBlock):

    # [FIXED] Removed _get_sni_from_tls helper

    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        if not isinstance(payload, dict) or "packet" not in payload:
            return payload, {"error": "Invalid payload, expected analysis dict."}
        packet = payload.get("packet")
        if not packet: return payload, {"error": "No packet found in payload."}

        analysis = payload.setdefault("analysis", {})
        app_info = analysis.setdefault("app", {})
        parsed_kind: Optional[str] = None
        log_msg = ""

        if packet.haslayer(DNS):
            parsed_kind = "dns"
            dns_layer = packet[DNS]
            dns_info: Dict[str, Any] = {
                "id": dns_layer.id, "qr": dns_layer.qr, "opcode": dns_layer.opcode,
                "qdcount": dns_layer.qdcount, "ancount": dns_layer.ancount, "queries": [],
            }
            try:
                if dns_layer.qd:
                    for i in range(int(dns_layer.qdcount)):
                        try:
                            q = dns_layer.qd[i]
                            qname = q.qname.decode("utf-8") if isinstance(q.qname, bytes) else q.qname
                            dns_info["queries"].append({"qname": qname, "qtype": q.qtype})
                        except Exception:
                            pass
            except Exception:
                pass
            app_info["dns"] = dns_info
            try:
                if dns_info.get("qr") == 0 and dns_info.get("queries"):
                    log_msg = f"[Analysis][parse_app] Found DNS Query for {dns_info['queries'][0].get('qname')}"
                elif dns_info.get("qr") == 1:
                    log_msg = f"[Analysis][parse_app] Found DNS Response (AN: {dns_info.get('ancount')})"
            except Exception:
                pass

        elif packet.haslayer(DHCP):
            parsed_kind = "dhcp"
            dhcp_layer = packet[DHCP]
            msg_type: Any = "unknown"
            try:
                for opt in getattr(dhcp_layer, "options", []):
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        msg_type = opt[1];
                        break
            except Exception:
                pass
            app_info["dhcp"] = {"message_type": msg_type}
            log_msg = f"[Analysis][parse_app] Found DHCP Message (Type: {msg_type})"

        elif packet.haslayer(TLSClientHello):
            parsed_kind = "tls"
            # [FIXED] Removed SNI logic
            app_info["tls"] = {"type": "ClientHello"}
            log_msg = f"[Analysis][parse_app] Found TLS ClientHello"

        elif packet.haslayer(TLSServerHello):
            parsed_kind = "tls"
            app_info["tls"] = {"type": "ServerHello"}
            log_msg = f"[Analysis][parse_app] Found TLS ServerHello"

        elif packet.haslayer(HTTPRequest):
            parsed_kind = "http"
            http_layer = packet[HTTPRequest]
            try:
                req_line = f"{http_layer.Method.decode('utf-8')} {http_layer.Path.decode('utf-8')} {http_layer.Http_Version.decode('utf-8')}"
                host = http_layer.Host.decode('utf-8') if http_layer.Host else "Unknown"
            except Exception:
                req_line = "HTTPRequest (decode error)"
                host = "Unknown"
            app_info["http"] = {"type": "Request", "request_line": req_line, "host": host}
            log_msg = f"[Analysis][parse_app] Found HTTP Request: {req_line}"

        elif packet.haslayer(HTTPResponse):
            parsed_kind = "http"
            http_layer = packet[HTTPResponse]
            try:
                status_line = f"{http_layer.Http_Version.decode('utf-8')} {http_layer.Status_Code.decode('utf-8')} {http_layer.Reason_Phrase.decode('utf-8')}"
            except Exception:
                status_line = "HTTPResponse (decode error)"
            app_info["http"] = {"type": "Response", "status_line": status_line}
            log_msg = f"[Analysis][parse_app] Found HTTP Response: {status_line}"

        elif packet.haslayer(NTP):
            parsed_kind = "ntp"
            app_info["ntp"] = {"version": packet[NTP].version}
            log_msg = f"[Analysis][parse_app] Found NTP Packet"

        # [FIXED] Removed SSDP block

        if parsed_kind:
            if log_msg: self.log(log_msg)
            return payload, {"app_parsed": parsed_kind}

        return payload, {"app_parsed": False}

    def get_params_info(self) -> Dict[str, Any]:
        return {"info": "Adds 'analysis.app' (DNS, DHCP, TLS, HTTP, etc.) and logs it."}


@BLOCKS.register("analyze_payload", help="Analyze the raw data (entropy, size, structure, protocol-ish hints).")
@dataclass
class AnalyzePayloadBlock(BaseBlock):
    """
    Analyzes the Raw payload and tries to say something *meaningful* about it:
      • size, entropy, snippet
      • ASCII/printable ratio
      • JSON-ish vs generic text
      • TLS / QUIC / STUN signatures
      • ZeroTier / overlay-ish hints (e.g., UDP/9993, common lengths)
    """

    # Heuristic length hints for overlay-ish control packets (ZeroTier etc.)
    OVERLAY_LEN_HINTS = {59, 67, 77, 98, 121, 137}
    # Not strictly needed here, but handy if you want “both high ports” logic later
    HIGH_EPHEMERAL = (49152, 65535)

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts: Dict[int, int] = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        data_len = float(len(data))
        entropy = 0.0
        for count in counts.values():
            p = count / data_len
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _printable_ratio(self, data: bytes) -> float:
        if not data:
            return 0.0
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)  # basic ASCII + \t\n\r
        return printable / float(len(data))

    def _looks_like_json(self, text: str) -> bool:
        s = text.strip()
        if not s:
            return False
        if not ((s[0] in "{[") and (s[-1] in "}]")):
            return False
        # Cheap guard: must contain colon or comma if it's more than a couple chars
        if len(s) > 4 and (":" not in s and "," not in s):
            return False
        return True

    def _looks_like_tls_record(self, data: bytes) -> bool:
        """
        Minimal TLS record header check:
          • content_type in {0x14,0x16,0x17}
          • version in {0x0301..0x0304}
          • sane length
        """
        if len(data) < 5:
            return False
        ct = data[0]
        if ct not in (0x14, 0x16, 0x17):
            return False
        ver = (data[1] << 8) | data[2]
        if ver not in (0x0301, 0x0302, 0x0303, 0x0304):
            return False
        rec_len = (data[3] << 8) | data[4]
        return 0 < rec_len <= (16384 + 2048)

    def _looks_like_quic_udp(self, data: bytes) -> bool:
        """
        Very cheap QUIC long-header hint:
          • first byte 0x80 bit set
          • non-zero version
        """
        if len(data) < 7:
            return False
        b0 = data[0]
        if not (b0 & 0x80):
            return False
        try:
            ver = struct.unpack_from("!I", data, 1)[0]
        except Exception:
            return False
        return ver != 0

    def _looks_like_stun(self, data: bytes) -> bool:
        """
        STUN: magic cookie 0x2112A442 at bytes 4..7
        """
        if len(data) < 8:
            return False
        return data[4:8] == b"\x21\x12\xA4\x42"

    def _looks_like_zerotier_overlay(self, l4: Dict[str, Any], payload_len: int) -> bool:
        """
        Very rough heuristic for ZeroTier-like overlay (UDP/9993).
        Uses port 9993 and common control-packet lengths.
        """
        if not l4 or l4.get("proto") != "udp":
            return False
        sport = int(l4.get("sport", 0))
        dport = int(l4.get("dport", 0))
        if sport == 9993 or dport == 9993:
            if payload_len in self.OVERLAY_LEN_HINTS:
                return True
        return False

    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        if not isinstance(payload, dict) or "packet" not in payload:
            return payload, {"error": "Invalid payload, expected analysis dict."}

        packet = payload.get("packet")
        if not packet:
            return payload, {"error": "No packet found in payload."}

        if not packet.haslayer(Raw):
            return payload, {"payload_analysis": False, "reason": "No Raw layer"}

        raw_bytes: bytes = packet[Raw].load
        payload_len = len(raw_bytes)
        if payload_len == 0:
            return payload, {"payload_analysis": True, "status": "Empty Raw layer"}

        # Base stats
        entropy = self._calculate_entropy(raw_bytes)
        printable_ratio = self._printable_ratio(raw_bytes)

        # Basic content category
        if entropy > 7.5:
            content_type = "Encrypted/Compressed"
        elif entropy > 6.0:
            content_type = "Binary"
        elif entropy > 2.0:
            content_type = "Text/Mixed"
        else:
            content_type = "Text (Low Entropy)"

        # Try to get a decoded text view for more refined guesses
        decoded_text: Optional[str] = None
        snippet: Optional[str] = None
        if entropy < 7.2 or printable_ratio > 0.7:
            try:
                decoded_text = raw_bytes.decode("utf-8", errors="ignore")
                clean = re.sub(r'[\x00-\x1F\x7F-\xFF]', '.', decoded_text)
                snippet = clean[:100]
                if len(clean) > 100:
                    snippet += "..."
            except Exception:
                snippet = "(decode error)"

        # Look at L4 context (proto/ports)
        l4 = payload.get("analysis", {}).get("l4", {}) or {}
        proto = l4.get("proto")
        sport = l4.get("sport")
        dport = l4.get("dport")

        # Higher-level "kind" + tags
        kind = "generic"
        tags: List[str] = []
        reasons: List[str] = []

        # 1) Overlay / ZeroTier-ish
        if self._looks_like_zerotier_overlay(l4, payload_len):
            kind = "overlay"
            tags.append("overlay")
            reasons.append("udp_port_9993 + overlay_length_hint")

        # 2) QUIC-ish on UDP
        elif proto == "udp" and self._looks_like_quic_udp(raw_bytes):
            kind = "quic"
            tags.append("quic_long_header")
            reasons.append("long_header_bit + nonzero_version")

        # 3) STUN-ish on UDP
        elif proto == "udp" and self._looks_like_stun(raw_bytes):
            kind = "stun"
            tags.append("stun")
            reasons.append("magic_cookie_0x2112A442")

        # 4) TLS record on TCP
        elif proto == "tcp" and self._looks_like_tls_record(raw_bytes):
            kind = "tls"
            tags.append("tls_record")
            reasons.append("tls_record_header")

        # 5) JSON-ish text
        elif decoded_text is not None and self._looks_like_json(decoded_text):
            kind = "json_text"
            tags.append("json")
            reasons.append("json_braces + text")

        # 6) Highly printable generic text
        elif printable_ratio > 0.85 and entropy < 6.5:
            kind = "ascii_text"
            tags.append("ascii")
            reasons.append("high_printable_ratio")

        # 7) High-entropy generic binary/crypto
        elif entropy > 7.5:
            kind = "high_entropy_binary"
            tags.append("crypto_or_compressed")
            reasons.append("entropy>7.5")

        # Build analysis record
        analysis_data: Dict[str, Any] = {
            "size_bytes": payload_len,
            "entropy": round(entropy, 4),
            "content_type": content_type,
            "printable_ratio": round(printable_ratio, 3),
            "kind": kind,
            "tags": tags,
            "reasons": reasons,
            "snippet": snippet,
            "l4_proto": proto,
            "l4_sport": sport,
            "l4_dport": dport,
        }

        payload.setdefault("analysis", {})["payload_analysis"] = analysis_data

        # Logging
        tag_str = ",".join(tags) if tags else "-"
        reason_str = ";".join(reasons) if reasons else "-"
        log_msg = (
            f"[Analysis][payload] {payload_len}B ent={entropy:.2f} "
            f"type={content_type} kind={kind} tags={tag_str} reasons={reason_str}"
        )
        if snippet:
            log_msg += f' Snippet: "{snippet}"'
        self.log(log_msg)

        return payload, {"payload_analysis": True, **analysis_data}

    def get_params_info(self) -> Dict[str, Any]:
        return {
            "info": (
                "Analyzes the raw packet payload for size, entropy, printable ratio, "
                "and protocol-ish hints (TLS/QUIC/STUN/overlay/JSON/etc.)."
            )
        }



@BLOCKS.register("tee", help="Save the current analysis dict to memory.json.")
@dataclass
class TeeToMemoryBlock(BaseBlock):
    """
    Serializes a JSON-safe snapshot of the analysis dict to memory.json
    under Memory[key]. The raw Scapy packet object is stripped.
    """

    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        key = str(params.get("key", "last_packet_info"))
        if not isinstance(payload, dict) or "analysis" not in payload:
            err = "Payload is not a valid analysis dict, cannot save."
            self.log(f"[Analysis][tee] ERROR: {err}")
            return payload, {"error": err}
        try:
            serializable = json.loads(json.dumps(payload, default=str))
            serializable.pop("packet", None)
        except Exception as e:
            err = f"Failed to serialize payload: {e}"
            self.log(f"[Analysis][tee] ERROR: {err}")
            return payload, {"error": err}
        try:
            store = Memory.load()
            store[key] = serializable
            Memory.save(store)
            self.log(f"[Analysis][tee] Saved analysis snapshot to memory key '{key}'")
            return payload, {"saved_to_memory": key, "size": len(str(serializable))}
        except Exception as e:
            err = f"Failed to save to memory: {e}"
            self.log(f"[Analysis][tee] ERROR: {err}")
            return payload, {"error": err}

    def get_params_info(self) -> Dict[str, Any]:
        return {"key": "last_packet_info"}


# ========================================================
# 5. PIPELINE RUNNER BLOCK
# ========================================================

@BLOCKS.register("pipeline", help="Run a sequence of registered blocks by name.")
@dataclass
class PacketPipelineBlock(BaseBlock):
    """
    Orchestrates a sequence of stages (blocks) defined in extras["pipeline"]["stages"].
    This block is designed to be called for its side-effects (logging, memory save).
    """
    _meta_chain: List[Dict[str, Any]] = field(default_factory=list)

    def _pipeline_params(self, extras: Dict[str, Any]) -> Dict[str, Any]:
        pipeline_config = extras.get("pipeline", {})
        if isinstance(pipeline_config, dict):
            return dict(pipeline_config)
        return {}

    def _resolve_stages(self, pipe_params: Dict[str, Any]) -> List[str]:
        stages_str = pipe_params.get("stages") or pipe_params.get("pipeline") or pipe_params.get("pipe")
        if not isinstance(stages_str, str) or not stages_str.strip():
            raise ValueError("Missing pipeline.stages (e.g. 'init_packet|parse_l3|...')")
        return [s.strip() for s in stages_str.split("|") if s.strip()]

    def _stage_params(
            self,
            stage: str,
            extras: Dict[str, Any],
            pipe_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}
        if isinstance(extras.get("all"), dict):
            merged.update(extras.get("all", {}))
        if isinstance(extras.get(stage.lower()), dict):
            merged.update(extras.get(stage.lower(), {}))
        prefix = f"{stage}."
        for k, v in pipe_params.items():
            if k.startswith(prefix):
                merged[k[len(prefix):]] = v
        return merged

    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        extras: Dict[str, Any] = params or {}
        self.logger = extras.get("logger")

        pipe_params = self._pipeline_params(extras)
        stages = self._resolve_stages(pipe_params)

        stop_on_error = bool(pipe_params.get("stop_on_error", True))
        debug = bool(pipe_params.get("debug", False))

        current = payload
        self._meta_chain.clear()

        if debug:
            self.log(f"[Analysis][Pipeline] Starting with {len(stages)} stages: {' | '.join(stages)}")

        for stage_name in stages:
            stage_meta: Dict[str, Any] = {"stage": stage_name}
            start = time.time()
            try:
                blk = BLOCKS.create(stage_name)
                blk.logger = self.logger
                stage_params = self._stage_params(stage_name, extras, pipe_params)

                if debug:
                    preview_in = str(current)
                    stage_meta["in_len"] = len(preview_in)
                    stage_meta["in_preview"] = preview_in[:160]
                    self.log(f"[Analysis][Pipeline] > Running stage '{stage_name}'...")

                out, meta = blk.execute(current, params=stage_params)
                elapsed = time.time() - start
                stage_meta.update(meta or {})
                stage_meta["elapsed_sec"] = round(elapsed, 6)

                if debug:
                    preview_out = str(out)
                    stage_meta["out_len"] = len(preview_out)
                    stage_meta["out_preview"] = preview_out[:200]

                self._meta_chain.append(stage_meta)
                current = out

                if stop_on_error and stage_meta.get("error"):
                    self.log(
                        f"[Analysis][Pipeline] ERROR in stage '{stage_name}': {stage_meta.get('error')}. Stopping pipeline.")
                    break

            except Exception as e:
                elapsed = time.time() - start
                stage_meta.update({
                    "error": "stage_failed", "exception": repr(e), "elapsed_sec": round(elapsed, 6),
                })
                self._meta_chain.append(stage_meta)
                self.log(f"[Analysis][Pipeline] CRITICAL ERROR in stage '{stage_name}': {e}")
                if stop_on_error:
                    break

        if debug:
            self.log(f"[Analysis][Pipeline] Pipeline finished.")

        meta_out = {
            "type": "packet-pipeline",
            "stages": stages,
            "chain": self._meta_chain,
            "stop_on_error": stop_on_error,
            "debug": debug,
        }

        return None, meta_out

    def get_params_info(self) -> Dict[str, Any]:
        return {
            "stages": "init_packet|parse_l2|parse_arp|parse_l3|parse_l4|parse_app|analyze_payload|tee",
            "stop_on_error": True,
            "debug": False,
            "example": "Use create_pipeline_extras(...) to build the 'params' dict.",
        }