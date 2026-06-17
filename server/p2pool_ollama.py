
"""
p2pool_ollama.py

Local Ollama integration for the P2Pool/PythonRouter GUI stack.

What this gives you:
- OllamaClient: safe local REST calls to Ollama (/api/tags, /api/chat, /api/generate)
- RouterPacketMemory: rolling, sanitized packet/router memory
- OllamaRouterBridge: non-invasive hook into PythonRouterManager.CodeOutputManager.submit_packet()
- OllamaModelAssistant: chat backend that injects router memory into Ollama prompts
- OllamaChatWorker + OllamaModelTab: PyQt5 GUI tab classes

Install/runtime:
    pip install requests PyQt5
    ollama serve
    ollama pull llama3.1:8b

Security:
- This does NOT fine-tune or modify model weights.
- It gives the model a short, sanitized rolling context about router traffic.
- Raw packet payloads are not sent by default. Only lengths, layers, endpoints, ports,
  flags, DNS query names, summaries, and hashes are retained.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import html
import json
import queue
import re
import threading
import time
import traceback
from collections import Counter, deque, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple

import requests

# Scapy is optional at import time so the GUI can still load if packet modules are unavailable.
try:
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
    from scapy.layers.dns import DNS, DNSQR
    from scapy.packet import Raw
except Exception:  # pragma: no cover - project runtime may not have scapy in every process.
    Ether = ARP = IP = TCP = UDP = ICMP = IPv6 = ICMPv6EchoRequest = ICMPv6EchoReply = DNS = DNSQR = Raw = None


# PyQt5 is optional so the backend can be imported headless.
try:
    from PyQt5.QtCore import QObject, QThread, QTimer, Qt, pyqtSignal, pyqtSlot
    from PyQt5.QtGui import QTextCursor
    from PyQt5.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFormLayout,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSizePolicy,
        QSplitter,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except Exception:  # pragma: no cover
    QObject = object
    QThread = QTimer = Qt = QTextCursor = None
    pyqtSignal = pyqtSlot = None
    QApplication = QCheckBox = QComboBox = QFormLayout = QGridLayout = QGroupBox = QHBoxLayout = QLabel = QLineEdit = None
    QMessageBox = QPlainTextEdit = QPushButton = QSizePolicy = QSplitter = QTabWidget = QTextEdit = QVBoxLayout = QWidget = None


# ---------------------------------------------------------------------------
# Small compatibility logger
# ---------------------------------------------------------------------------

class _NullLogger:
    def log_message(self, msg: str, *args: Any, **kwargs: Any) -> None:
        print(str(msg))


def _safe_log(logger: Any, msg: str, message_type: str = "info") -> None:
    try:
        fn = getattr(logger, "log_message", None)
        if callable(fn):
            try:
                fn(str(msg), message_type)
            except TypeError:
                fn(str(msg))
            return
    except Exception:
        pass
    print(str(msg))


# ---------------------------------------------------------------------------
# Ollama REST client
# ---------------------------------------------------------------------------

@dataclass
class OllamaConfig:
    base_url: str = "http://127.0.0.1:11434"
    default_model: str = "llama3.1:8b"
    timeout_s: float = 120.0
    stream: bool = False
    keep_alive: str = "10m"
    temperature: float = 0.25
    num_ctx: int = 8192
    max_context_chars: int = 14000
    extract_visible_thinking: bool = True
    max_visible_thinking_chars: int = 12000
    system_prompt: str = (
        "You are a local router assistant for Nate's Python P2Pool router project. "
        "Use the router context only as evidence. Do not invent packet facts. "
        "Prefer practical code, direct diagnosis, and safe networking guidance. "
        "Never expose raw payload secrets; reason from sanitized metadata."
    )

    def normalized_base_url(self) -> str:
        return str(self.base_url or "http://127.0.0.1:11434").rstrip("/")


class OllamaClient:
    """
    Minimal Ollama REST client with no external dependencies except requests.

    Uses:
      GET  /api/tags
      POST /api/chat
      POST /api/generate
      GET  /api/ps        (optional health/runtime)
      GET  /api/version   (optional health)
    """

    def __init__(self, config: Optional[OllamaConfig] = None, logger: Any = None) -> None:
        self.config = config or OllamaConfig()
        self.logger = logger or _NullLogger()
        self._session = requests.Session()

    @property
    def base_url(self) -> str:
        return self.config.normalized_base_url()

    def set_base_url(self, base_url: str) -> None:
        self.config.base_url = str(base_url or "").strip() or "http://127.0.0.1:11434"

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def health(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": False, "base_url": self.base_url}
        started = time.time()
        try:
            r = self._session.get(self._url("/api/version"), timeout=min(8.0, self.config.timeout_s))
            out["status_code"] = r.status_code
            out["latency_ms"] = round((time.time() - started) * 1000.0, 2)
            if r.ok:
                out["ok"] = True
                try:
                    out["version"] = r.json()
                except Exception:
                    out["version"] = r.text[:200]
            else:
                out["error"] = r.text[:500]
        except Exception as ex:
            out["latency_ms"] = round((time.time() - started) * 1000.0, 2)
            out["error"] = f"{type(ex).__name__}: {ex}"
        return out

    def list_models(self) -> List[Dict[str, Any]]:
        r = self._session.get(self._url("/api/tags"), timeout=min(20.0, self.config.timeout_s))
        r.raise_for_status()
        data = r.json()
        models = data.get("models", [])
        return models if isinstance(models, list) else []

    def running_models(self) -> List[Dict[str, Any]]:
        try:
            r = self._session.get(self._url("/api/ps"), timeout=min(20.0, self.config.timeout_s))
            r.raise_for_status()
            data = r.json()
            models = data.get("models", [])
            return models if isinstance(models, list) else []
        except Exception:
            return []

    def generate(self, model: str, prompt: str, *, system: Optional[str] = None, stream: Optional[bool] = None,
                 options: Optional[Dict[str, Any]] = None) -> str:
        payload: Dict[str, Any] = {
            "model": model or self.config.default_model,
            "prompt": prompt or "",
            "stream": self.config.stream if stream is None else bool(stream),
            "keep_alive": self.config.keep_alive,
            "options": self._default_options(options),
        }
        if system:
            payload["system"] = system

        r = self._session.post(self._url("/api/generate"), json=payload, timeout=self.config.timeout_s, stream=bool(payload["stream"]))
        r.raise_for_status()

        if payload["stream"]:
            return self._consume_generate_stream(r)

        data = r.json()
        return str(data.get("response", ""))

    def chat(self, model: str, messages: List[Dict[str, str]], *, stream: Optional[bool] = None,
             options: Optional[Dict[str, Any]] = None, format_json: bool = False) -> str:
        payload: Dict[str, Any] = {
            "model": model or self.config.default_model,
            "messages": messages or [],
            "stream": self.config.stream if stream is None else bool(stream),
            "keep_alive": self.config.keep_alive,
            "options": self._default_options(options),
        }
        if format_json:
            payload["format"] = "json"

        r = self._session.post(self._url("/api/chat"), json=payload, timeout=self.config.timeout_s, stream=bool(payload["stream"]))
        r.raise_for_status()

        if payload["stream"]:
            return self._consume_chat_stream(r)

        data = r.json()
        msg = data.get("message") or {}
        content = msg.get("content", "")
        return str(content)

    def _default_options(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        merged = {
            "temperature": float(self.config.temperature),
            "num_ctx": int(self.config.num_ctx),
        }
        if isinstance(options, dict):
            merged.update(options)
        return merged

    @staticmethod
    def _consume_chat_stream(resp: requests.Response) -> str:
        parts: List[str] = []
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                obj = json.loads(line)
                msg = obj.get("message") or {}
                if "content" in msg:
                    parts.append(str(msg.get("content") or ""))
            except Exception:
                continue
        return "".join(parts)

    @staticmethod
    def _consume_generate_stream(resp: requests.Response) -> str:
        parts: List[str] = []
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "response" in obj:
                    parts.append(str(obj.get("response") or ""))
            except Exception:
                continue
        return "".join(parts)


# ---------------------------------------------------------------------------
# Router memory / learning
# ---------------------------------------------------------------------------

@dataclass
class RouterPacketFact:
    ts: float
    iface: str = ""
    phase: str = ""
    component: str = ""
    proto: str = ""
    family: str = ""
    src: str = ""
    dst: str = ""
    sport: Optional[int] = None
    dport: Optional[int] = None
    length: int = 0
    flags: str = ""
    summary: str = ""
    dns_qname: str = ""
    digest: str = ""

    def compact_line(self) -> str:
        ep = f"{self.src or '?'}"
        if self.sport is not None:
            ep += f":{self.sport}"
        ep += " -> "
        ep += f"{self.dst or '?'}"
        if self.dport is not None:
            ep += f":{self.dport}"
        extras = []
        if self.flags:
            extras.append(f"flags={self.flags}")
        if self.dns_qname:
            extras.append(f"dns={self.dns_qname}")
        if self.component:
            extras.append(f"component={self.component}")
        if self.phase:
            extras.append(f"phase={self.phase}")
        suffix = (" " + " ".join(extras)) if extras else ""
        return f"{self.proto or self.family or 'packet'} {ep} len={self.length} iface={self.iface or '?'}{suffix}"


class RouterPacketMemory:
    """
    Rolling router memory for Ollama.

    This is deliberately NOT a fine-tuner. It stores sanitized, structured facts so
    they can be injected into a prompt as RAG-style context.
    """

    def __init__(self, *, max_events: int = 768, max_flow_events: int = 64, logger: Any = None) -> None:
        self.max_events = int(max_events)
        self.max_flow_events = int(max_flow_events)
        self.logger = logger or _NullLogger()
        self._lock = threading.RLock()
        self._events: Deque[RouterPacketFact] = deque(maxlen=self.max_events)
        self._seen_digest_ts: Dict[str, float] = {}
        self._proto_counts: Counter = Counter()
        self._iface_counts: Counter = Counter()
        self._port_counts: Counter = Counter()
        self._component_counts: Counter = Counter()
        self._flow_counts: Counter = Counter()
        self._last_router_snapshot: Dict[str, Any] = {}
        self._last_snapshot_ts: float = 0.0
        self._packet_total = 0
        self._packet_dropped = 0

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._seen_digest_ts.clear()
            self._proto_counts.clear()
            self._iface_counts.clear()
            self._port_counts.clear()
            self._component_counts.clear()
            self._flow_counts.clear()
            self._last_router_snapshot.clear()
            self._last_snapshot_ts = 0.0
            self._packet_total = 0
            self._packet_dropped = 0

    def ingest_packet(self, packet: Any, inbound_iface: Optional[str] = None, **context: Any) -> Optional[RouterPacketFact]:
        fact = self._packet_to_fact(packet, inbound_iface=inbound_iface, **context)
        if fact is None:
            with self._lock:
                self._packet_dropped += 1
            return None

        now = time.time()
        with self._lock:
            old = self._seen_digest_ts.get(fact.digest)
            if old is not None and (now - old) < 0.75:
                self._packet_dropped += 1
                return None
            self._seen_digest_ts[fact.digest] = now
            if len(self._seen_digest_ts) > 4096:
                cutoff = now - 90.0
                self._seen_digest_ts = {k: v for k, v in self._seen_digest_ts.items() if v >= cutoff}

            self._events.append(fact)
            self._packet_total += 1
            if fact.proto:
                self._proto_counts[fact.proto] += 1
            if fact.iface:
                self._iface_counts[fact.iface] += 1
            if fact.component:
                self._component_counts[fact.component] += 1
            for port in (fact.sport, fact.dport):
                if port is not None:
                    self._port_counts[str(port)] += 1
            flow = self._flow_key(fact)
            if flow:
                self._flow_counts[flow] += 1
        return fact

    def learn_from_code_output_manager(self, manager: Any) -> Dict[str, Any]:
        """
        Pulls safe high-level knowledge from CodeOutputManager if available:
        stats, health_snapshot(), correlation_snapshot(), export_knowledge() topic names only.
        """
        snapshot: Dict[str, Any] = {"ok": False}
        if manager is None:
            return snapshot

        try:
            if callable(getattr(manager, "get_stats", None)):
                snapshot["stats"] = manager.get_stats()
            if callable(getattr(manager, "health_snapshot", None)):
                snapshot["health"] = manager.health_snapshot()
            if callable(getattr(manager, "correlation_snapshot", None)):
                snapshot["correlation"] = manager.correlation_snapshot()
            if callable(getattr(manager, "export_knowledge", None)):
                exported = manager.export_knowledge()
                if isinstance(exported, dict):
                    snapshot["knowledge_topics"] = sorted(map(str, exported.keys()))[:32]
                    snapshot["topic_event_counts"] = {
                        str(k): len(v) if hasattr(v, "__len__") else 1
                        for k, v in list(exported.items())[:32]
                    }
            snapshot["ok"] = True
        except Exception as ex:
            snapshot["error"] = f"{type(ex).__name__}: {ex}"

        with self._lock:
            self._last_router_snapshot = self._compact_obj(snapshot, max_chars=6000)
            self._last_snapshot_ts = time.time()
        return snapshot

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "packet_total": self._packet_total,
                "packet_dropped": self._packet_dropped,
                "stored_events": len(self._events),
                "top_protocols": self._proto_counts.most_common(12),
                "top_ifaces": self._iface_counts.most_common(12),
                "top_ports": self._port_counts.most_common(16),
                "top_components": self._component_counts.most_common(12),
                "top_flows": self._flow_counts.most_common(16),
                "last_router_snapshot_ts": self._last_snapshot_ts,
                "last_router_snapshot": copy.deepcopy(self._last_router_snapshot),
            }

    def context_text(self, *, max_events: int = 48, max_chars: int = 14000) -> str:
        with self._lock:
            events = list(self._events)[-int(max_events):]
            snap = self.snapshot()

        lines: List[str] = []
        lines.append("SANITIZED ROUTER MEMORY")
        lines.append("This context contains packet metadata only, not raw payload secrets.")
        lines.append("")
        lines.append("Counters:")
        lines.append(f"- stored_events={snap['stored_events']} total_seen={snap['packet_total']} dropped={snap['packet_dropped']}")
        lines.append(f"- top_protocols={snap['top_protocols']}")
        lines.append(f"- top_ports={snap['top_ports'][:12]}")
        lines.append(f"- top_ifaces={snap['top_ifaces'][:8]}")
        lines.append(f"- top_components={snap['top_components'][:8]}")
        lines.append(f"- top_flows={snap['top_flows'][:8]}")
        if snap.get("last_router_snapshot"):
            lines.append("")
            lines.append("Router learned snapshot:")
            lines.append(json.dumps(snap["last_router_snapshot"], indent=2, sort_keys=True, default=str)[:5000])
        if events:
            lines.append("")
            lines.append("Recent packet facts:")
            for ev in events:
                lines.append("- " + ev.compact_line())

        text = "\n".join(lines)
        if len(text) > max_chars:
            text = text[-max_chars:]
            text = "[context truncated to most recent data]\n" + text
        return text

    def _packet_to_fact(self, packet: Any, inbound_iface: Optional[str] = None, **context: Any) -> Optional[RouterPacketFact]:
        if packet is None:
            return None

        summary = ""
        try:
            summary = str(packet.summary())
        except Exception:
            summary = str(type(packet).__name__)

        length = 0
        try:
            length = len(bytes(packet))
        except Exception:
            try:
                length = len(packet)
            except Exception:
                length = 0

        fact = RouterPacketFact(
            ts=time.time(),
            iface=str(inbound_iface or context.get("inbound_iface") or context.get("iface") or ""),
            phase=str(context.get("phase") or context.get("path_stage") or ""),
            component=str(context.get("component") or context.get("component_name") or ""),
            length=int(length or 0),
            summary=summary[:240],
        )

        try:
            if Ether is not None and hasattr(packet, "haslayer") and packet.haslayer(Ether):
                fact.family = "ether"
        except Exception:
            pass

        try:
            if ARP is not None and packet.haslayer(ARP):
                arp = packet[ARP]
                fact.proto = "ARP"
                fact.src = str(getattr(arp, "psrc", "") or "")
                fact.dst = str(getattr(arp, "pdst", "") or "")
        except Exception:
            pass

        try:
            if IP is not None and packet.haslayer(IP):
                ip = packet[IP]
                fact.family = "ipv4"
                fact.src = str(ip.src)
                fact.dst = str(ip.dst)
                fact.proto = str(getattr(ip, "proto", "") or "IP")
        except Exception:
            pass

        try:
            if IPv6 is not None and packet.haslayer(IPv6):
                ip6 = packet[IPv6]
                fact.family = "ipv6"
                fact.src = str(ip6.src)
                fact.dst = str(ip6.dst)
                fact.proto = str(getattr(ip6, "nh", "") or "IPv6")
        except Exception:
            pass

        try:
            if TCP is not None and packet.haslayer(TCP):
                tcp = packet[TCP]
                fact.proto = "TCP"
                fact.sport = int(tcp.sport)
                fact.dport = int(tcp.dport)
                fact.flags = str(tcp.flags)
        except Exception:
            pass

        try:
            if UDP is not None and packet.haslayer(UDP):
                udp = packet[UDP]
                fact.proto = "UDP"
                fact.sport = int(udp.sport)
                fact.dport = int(udp.dport)
        except Exception:
            pass

        try:
            if ICMP is not None and packet.haslayer(ICMP):
                fact.proto = "ICMP"
        except Exception:
            pass

        try:
            if DNS is not None and packet.haslayer(DNS):
                dns = packet[DNS]
                fact.proto = "DNS"
                if getattr(dns, "qd", None) is not None:
                    qd = dns.qd
                    if hasattr(qd, "qname"):
                        qn = qd.qname
                        if isinstance(qn, bytes):
                            qn = qn.decode("utf-8", "ignore")
                        fact.dns_qname = str(qn).rstrip(".")[:180]
        except Exception:
            pass

        digest_src = "|".join([
            fact.iface,
            fact.phase,
            fact.component,
            fact.proto,
            fact.src,
            str(fact.sport),
            fact.dst,
            str(fact.dport),
            str(fact.length),
            fact.flags,
            fact.dns_qname,
            fact.summary,
        ])
        fact.digest = hashlib.blake2b(digest_src.encode("utf-8", "replace"), digest_size=12).hexdigest()
        return fact

    @staticmethod
    def _flow_key(fact: RouterPacketFact) -> str:
        if not fact.src or not fact.dst:
            return ""
        a = f"{fact.src}:{fact.sport or 0}"
        b = f"{fact.dst}:{fact.dport or 0}"
        left, right = sorted([a, b])
        return f"{fact.proto}:{left}<->{right}"

    @classmethod
    def _compact_obj(cls, obj: Any, *, max_chars: int = 6000) -> Any:
        try:
            text = json.dumps(obj, sort_keys=True, default=str)
        except Exception:
            return str(obj)[:max_chars]
        if len(text) <= max_chars:
            try:
                return json.loads(text)
            except Exception:
                return text
        # Keep a JSON-ish compact object instead of storing a huge structure.
        return {"truncated": True, "preview": text[:max_chars]}


# ---------------------------------------------------------------------------
# Router bridge
# ---------------------------------------------------------------------------



class OllamaRouterBridge:
    """
    Hooks Ollama memory into PythonRouterManager without requiring router rewrites.

    Crash-safe changes:
    - The wrapper is transparent: it accepts *args/**kwargs and calls the original
      submit_packet() with the exact same arguments.
    - Packet-memory ingest is best-effort only. It can never change the return code
      of the router packet path.
    - Binding is idempotent and refuses to stack wrappers on top of wrappers.
    - Unbind only restores the original method when this bridge owns the wrapper.
    """

    _WRAPPED_ATTR = "_ollama_bridge_wrapped"
    _OWNER_ATTR = "_ollama_bridge_owner"
    _ORIGINAL_ATTR = "_ollama_bridge_original_submit_packet"

    def __init__(self, memory: RouterPacketMemory, logger: Any = None) -> None:
        self.memory = memory
        self.logger = logger or _NullLogger()
        self._lock = threading.RLock()
        self._router_ref: Any = None
        self._co_ref: Any = None
        self._orig_submit_packet: Optional[Callable[..., Any]] = None
        self._bound = False
        self._owns_wrapper = False
        self._stop_event = threading.Event()
        self._snapshot_thread: Optional[threading.Thread] = None
        self.snapshot_every_s = 8.0

    @property
    def bound(self) -> bool:
        return bool(self._bound)

    def bind_to_router(self, router_manager: Any) -> bool:
        if router_manager is None:
            _safe_log(self.logger, "[OllamaBridge] Router manager is None; init-managed bind skipped.", "info")
            return False

        co = getattr(router_manager, "code_output_manager", None)
        submit = getattr(co, "submit_packet", None) if co is not None else None
        if co is None or not callable(submit):
            _safe_log(self.logger, "[OllamaBridge] Router has no usable code_output_manager.submit_packet; bind skipped.", "error")
            return False

        with self._lock:
            if self._bound and self._co_ref is co:
                return True

            if self._bound:
                self.unbind()

            current_submit = getattr(co, "submit_packet", None)
            owner = getattr(current_submit, self._OWNER_ATTR, None)
            already_wrapped = bool(getattr(current_submit, self._WRAPPED_ATTR, False))

            self._router_ref = router_manager
            self._co_ref = co

            # Another Ollama bridge already owns the hot-path wrapper. Do not stack
            # another wrapper; stacked wrappers are exactly how exit-code crashes and
            # odd packet-path behavior start.
            if already_wrapped and owner is not self:
                self._orig_submit_packet = getattr(current_submit, self._ORIGINAL_ATTR, current_submit)
                self._bound = True
                self._owns_wrapper = False
                self._start_snapshot_thread_locked()
                _safe_log(self.logger, "[OllamaBridge] Existing Ollama packet wrapper detected; reusing init-managed bridge without double wrapping.", "info")
                return True

            original_submit = current_submit
            self._orig_submit_packet = original_submit

            def wrapped_submit_packet(*args: Any, **kwargs: Any) -> Any:
                packet = None
                inbound_iface = None
                context: Dict[str, Any] = {}
                try:
                    packet, inbound_iface, context = self._extract_packet_call(args, kwargs)
                    if packet is not None:
                        self.memory.ingest_packet(packet, inbound_iface=inbound_iface, **context)
                except Exception as ex:
                    # Never let Ollama memory affect routing success/exit code.
                    _safe_log(self.logger, f"[OllamaBridge] packet memory ingest skipped safely: {type(ex).__name__}: {ex}", "error")

                # Preserve original submit_packet behavior exactly. If the original
                # method raises, let the original error surface rather than masking it.
                return original_submit(*args, **kwargs)

            try:
                setattr(wrapped_submit_packet, self._WRAPPED_ATTR, True)
                setattr(wrapped_submit_packet, self._OWNER_ATTR, self)
                setattr(wrapped_submit_packet, self._ORIGINAL_ATTR, original_submit)
                setattr(co, "submit_packet", wrapped_submit_packet)
            except Exception as ex:
                self._bound = False
                self._owns_wrapper = False
                self._orig_submit_packet = None
                _safe_log(self.logger, f"[OllamaBridge] Failed to install safe wrapper: {type(ex).__name__}: {ex}", "error")
                return False

            self._bound = True
            self._owns_wrapper = True
            self._start_snapshot_thread_locked()

        _safe_log(self.logger, "[OllamaBridge] ✅ Init-managed safe packet bridge installed.", "info")
        return True

    def unbind(self) -> None:
        with self._lock:
            self._stop_event.set()
            co = self._co_ref
            orig = self._orig_submit_packet
            owns_wrapper = self._owns_wrapper
            current_submit = getattr(co, "submit_packet", None) if co is not None else None

            if co is not None and orig is not None and owns_wrapper:
                try:
                    if getattr(current_submit, self._OWNER_ATTR, None) is self:
                        setattr(co, "submit_packet", orig)
                except Exception:
                    pass

            t = self._snapshot_thread
            self._bound = False
            self._owns_wrapper = False
            self._router_ref = None
            self._co_ref = None
            self._orig_submit_packet = None
            self._snapshot_thread = None

        if t and t.is_alive() and threading.current_thread() is not t:
            t.join(timeout=1.5)
        _safe_log(self.logger, "[OllamaBridge] Unbound safely.", "info")

    def _start_snapshot_thread_locked(self) -> None:
        if self._snapshot_thread is not None and self._snapshot_thread.is_alive():
            return
        self._stop_event.clear()
        self._snapshot_thread = threading.Thread(
            target=self._snapshot_loop,
            name="OllamaRouterSnapshotLoop",
            daemon=True,
        )
        self._snapshot_thread.start()

    def _extract_packet_call(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Tuple[Any, Optional[str], Dict[str, Any]]:
        context = dict(kwargs or {})
        inbound_iface = (
            context.pop("inbound_iface", None)
            or context.get("iface")
            or context.get("interface")
            or context.get("in_iface")
        )

        packet = None
        if args:
            # Normal instance-attribute function call after monkey patch:
            #     co.submit_packet(packet, inbound_iface=...)
            packet = args[0]

            # Defensive support for unusual class-style call:
            #     CodeOutputManager.submit_packet(co, packet, ...)
            if packet is self._co_ref and len(args) > 1:
                packet = args[1]
                if inbound_iface is None and len(args) > 2 and isinstance(args[2], str):
                    inbound_iface = args[2]
            elif inbound_iface is None and len(args) > 1 and isinstance(args[1], str):
                inbound_iface = args[1]

        if packet is None:
            packet = context.get("packet") or context.get("pkt") or context.get("frame")

        if inbound_iface is not None:
            inbound_iface = str(inbound_iface)

        # Keep only lightweight contextual values so hot path stays cheap.
        safe_context: Dict[str, Any] = {}
        for key in (
            "phase", "path_stage", "component", "component_name", "direction",
            "route", "source", "reason", "verdict", "iface", "interface",
        ):
            if key in context:
                try:
                    safe_context[key] = str(context.get(key))[:180]
                except Exception:
                    pass

        return packet, inbound_iface, safe_context

    def _snapshot_loop(self) -> None:
        while not self._stop_event.wait(self.snapshot_every_s):
            try:
                co = self._co_ref
                if co is not None:
                    self.memory.learn_from_code_output_manager(co)
            except Exception as ex:
                _safe_log(self.logger, f"[OllamaBridge] snapshot skipped safely: {type(ex).__name__}: {ex}", "error")


# ---------------------------------------------------------------------------
# Assistant backend
# ---------------------------------------------------------------------------


class OllamaModelAssistant:
    """
    Stateful assistant backend. It keeps message history, attaches router memory,
    and talks to the local Ollama server.
    """

    _THINK_RE = re.compile(r"<think(?:ing)?[^>]*>(.*?)</think(?:ing)?>", re.IGNORECASE | re.DOTALL)

    def __init__(self, logger: Any = None, config: Optional[OllamaConfig] = None) -> None:
        self.logger = logger or _NullLogger()
        self.config = config or OllamaConfig()
        self.client = OllamaClient(self.config, logger=self.logger)
        self.memory = RouterPacketMemory(logger=self.logger)
        self.bridge = OllamaRouterBridge(self.memory, logger=self.logger)
        self._lock = threading.RLock()
        self.messages: List[Dict[str, str]] = []
        self._last_model_list: List[Dict[str, Any]] = []
        self.last_visible_thinking: str = ""
        self.last_response_raw: str = ""
        self.last_response_text: str = ""
        self.last_context_preview: str = ""
        self.last_latency_s: float = 0.0
        self.last_model: str = ""

    def set_base_url(self, base_url: str) -> None:
        self.client.set_base_url(base_url)

    def set_model(self, model: str) -> None:
        if model:
            self.config.default_model = model

    def bind_router(self, router_manager: Any) -> bool:
        ok = self.bridge.bind_to_router(router_manager)
        if ok:
            try:
                co = getattr(router_manager, "code_output_manager", None)
                if co:
                    self.memory.learn_from_code_output_manager(co)
            except Exception:
                pass
        return ok

    def unbind_router(self) -> None:
        self.bridge.unbind()

    def clear_history(self) -> None:
        with self._lock:
            self.messages.clear()
            self.last_visible_thinking = ""
            self.last_response_raw = ""
            self.last_response_text = ""

    def clear_router_memory(self) -> None:
        self.memory.clear()

    def refresh_models(self) -> List[str]:
        models = self.client.list_models()
        self._last_model_list = models
        names = []
        for m in models:
            name = m.get("name") or m.get("model")
            if name:
                names.append(str(name))
        return names

    def health_text(self) -> str:
        health = self.client.health()
        running = self.client.running_models()
        model_names = []
        try:
            model_names = self.refresh_models()
        except Exception as ex:
            model_names = [f"model refresh error: {ex}"]

        mem = self.memory.snapshot()
        bridge = {
            "bound": bool(getattr(self.bridge, "bound", False)),
            "owns_wrapper": bool(getattr(self.bridge, "_owns_wrapper", False)),
            "snapshot_every_s": getattr(self.bridge, "snapshot_every_s", None),
        }
        return (
            "Ollama health:\n"
            + json.dumps(health, indent=2, default=str)
            + "\n\nRunning models:\n"
            + json.dumps(running[:16], indent=2, default=str)
            + "\n\nInstalled models:\n"
            + "\n".join(f"- {m}" for m in model_names[:64])
            + "\n\nRouter bridge:\n"
            + json.dumps(bridge, indent=2, default=str)
            + "\n\nRouter memory:\n"
            + json.dumps(mem, indent=2, default=str)[:6000]
        )

    def router_context_text(self, router_manager: Any = None) -> str:
        # If the actual router was already initialized with use_ollama=True, prefer
        # its init-managed memory instead of making the GUI install another wrapper.
        if router_manager is not None:
            try:
                router_memory = getattr(router_manager, "ollama_packet_memory", None)
                if router_memory is not None and router_memory is not self.memory and callable(getattr(router_memory, "context_text", None)):
                    return str(router_memory.context_text(max_chars=self.config.max_context_chars))
            except Exception:
                pass
            try:
                co = getattr(router_manager, "code_output_manager", None)
                if co:
                    self.memory.learn_from_code_output_manager(co)
            except Exception:
                pass
        return self.memory.context_text(max_chars=self.config.max_context_chars)

    def send_message(self, user_message: str, *, model: Optional[str] = None, router_manager: Any = None,
                     use_router_context: bool = True) -> str:
        user_message = str(user_message or "").strip()
        if not user_message:
            return ""

        model_name = model or self.config.default_model
        self.last_model = model_name

        system = self.config.system_prompt
        context_preview = ""
        if use_router_context:
            ctx = self.router_context_text(router_manager)
            context_preview = ctx
            system = f"{system}\n\n{ctx}"

        with self._lock:
            # Keep history bounded so the GUI does not explode context length.
            if len(self.messages) > 24:
                self.messages = self.messages[-24:]
            outbound = [{"role": "system", "content": system}] + list(self.messages)
            outbound.append({"role": "user", "content": user_message})

        started = time.time()
        try:
            response_raw = self.client.chat(model_name, outbound, stream=False)
        except requests.exceptions.ConnectionError as ex:
            raise RuntimeError(
                f"Cannot connect to Ollama at {self.client.base_url}. Start it with `ollama serve` "
                f"or fix the base URL. Underlying error: {ex}"
            ) from ex
        except Exception:
            raise

        elapsed = time.time() - started
        visible_thinking, response = self._split_visible_thinking(response_raw)

        with self._lock:
            self.last_visible_thinking = visible_thinking
            self.last_response_raw = response_raw
            self.last_response_text = response
            self.last_context_preview = context_preview[-self.config.max_context_chars:] if context_preview else ""
            self.last_latency_s = elapsed
            self.messages.append({"role": "user", "content": user_message})
            self.messages.append({"role": "assistant", "content": response})

        _safe_log(self.logger, f"[Ollama] model={model_name} answered in {elapsed:.2f}s chars={len(response)} think_chars={len(visible_thinking)}", "info")
        return response

    def runtime_summary(self) -> Dict[str, Any]:
        with self._lock:
            mem = self.memory.snapshot()
            return {
                "model": self.last_model or self.config.default_model,
                "base_url": self.client.base_url,
                "bridge_bound": bool(self.bridge.bound),
                "bridge_owns_wrapper": bool(getattr(self.bridge, "_owns_wrapper", False)),
                "last_latency_s": round(float(self.last_latency_s or 0.0), 3),
                "last_answer_chars": len(self.last_response_text or ""),
                "last_thinking_chars": len(self.last_visible_thinking or ""),
                "memory": {
                    "stored_events": mem.get("stored_events", 0),
                    "packet_total": mem.get("packet_total", 0),
                    "packet_dropped": mem.get("packet_dropped", 0),
                    "top_protocols": mem.get("top_protocols", [])[:8],
                    "top_ports": mem.get("top_ports", [])[:8],
                    "top_ifaces": mem.get("top_ifaces", [])[:8],
                },
            }

    def _split_visible_thinking(self, response: str) -> Tuple[str, str]:
        response = str(response or "")
        if not getattr(self.config, "extract_visible_thinking", True):
            return "", response

        chunks: List[str] = []
        def repl(match: Any) -> str:
            part = str(match.group(1) or "").strip()
            if part:
                chunks.append(part)
            return ""

        cleaned = self._THINK_RE.sub(repl, response).strip()
        thinking = "\n\n".join(chunks).strip()

        # Some reasoning models stream an opening <think> and omit a closing tag
        # when interrupted. Surface it without crashing and keep the answer part clean.
        lower = cleaned.lower()
        idx = lower.find("<think>")
        if idx >= 0:
            before = cleaned[:idx].strip()
            after = cleaned[idx + len("<think>"):].strip()
            if after:
                thinking = (thinking + "\n\n" + after).strip()
            cleaned = before

        max_think = int(getattr(self.config, "max_visible_thinking_chars", 12000) or 12000)
        if len(thinking) > max_think:
            thinking = "[visible model thinking truncated]\n" + thinking[-max_think:]

        return thinking, cleaned or response.strip()


# ---------------------------------------------------------------------------
# GUI classes
# ---------------------------------------------------------------------------


if pyqtSignal is not None:
    class OllamaLogger(QObject):
        message_signal = pyqtSignal(str, str)

        def log_message(self, msg: str, message_type: str = "info") -> None:
            self.message_signal.emit(str(msg).rstrip(), str(message_type or "info"))
else:
    class OllamaLogger:  # type: ignore[no-redef]
        def log_message(self, msg: str, message_type: str = "info") -> None:
            print(str(msg))


if pyqtSignal is not None:
    class OllamaChatWorker(QObject):
        response_received = pyqtSignal(str)
        error_occurred = pyqtSignal(str)
        thinking_started = pyqtSignal()
        thinking_finished = pyqtSignal()
        thinking_trace_received = pyqtSignal(str, str)
        runtime_received = pyqtSignal(dict)
        models_received = pyqtSignal(list)
        health_received = pyqtSignal(str)

        def __init__(self, assistant: OllamaModelAssistant, logger: Any = None) -> None:
            super().__init__()
            self.assistant = assistant
            self.logger = logger or _NullLogger()
            self._router_provider: Optional[Callable[[], Any]] = None

        def set_assistant(self, assistant: OllamaModelAssistant) -> None:
            if assistant is not None:
                self.assistant = assistant

        def set_router_provider(self, provider: Optional[Callable[[], Any]]) -> None:
            self._router_provider = provider

        def _router(self) -> Any:
            try:
                return self._router_provider() if callable(self._router_provider) else None
            except Exception:
                return None

        @pyqtSlot(dict)
        def process_message(self, payload: Dict[str, Any]) -> None:
            self.thinking_started.emit()
            try:
                base_url = str(payload.get("base_url") or "").strip()
                model = str(payload.get("model") or "").strip()
                text = str(payload.get("message") or "").strip()
                use_context = bool(payload.get("use_router_context", True))

                if base_url:
                    self.assistant.set_base_url(base_url)
                if model:
                    self.assistant.set_model(model)

                router = self._router()

                # Important: no GUI-triggered binding here. Binding is init-managed by
                # PythonRouterManager only when use_ollama=True. The GUI may adopt that
                # existing assistant, but it never hot-patches submit_packet itself.
                response = self.assistant.send_message(
                    text,
                    model=model or None,
                    router_manager=router,
                    use_router_context=use_context,
                )
                self.thinking_trace_received.emit(
                    str(getattr(self.assistant, "last_visible_thinking", "") or ""),
                    str(getattr(self.assistant, "last_context_preview", "") or ""),
                )
                self.runtime_received.emit(self.assistant.runtime_summary())
                self.response_received.emit(response)
            except Exception as ex:
                err = f"{type(ex).__name__}: {ex}"
                _safe_log(self.logger, "[OllamaWorker] " + err + "\n" + traceback.format_exc(), "error")
                self.error_occurred.emit(err)
            finally:
                self.thinking_finished.emit()

        @pyqtSlot(str)
        def refresh_models(self, base_url: str = "") -> None:
            try:
                if base_url:
                    self.assistant.set_base_url(base_url)
                self.models_received.emit(self.assistant.refresh_models())
                self.runtime_received.emit(self.assistant.runtime_summary())
            except Exception as ex:
                self.error_occurred.emit(f"Model refresh failed: {type(ex).__name__}: {ex}")

        @pyqtSlot(str)
        def health_check(self, base_url: str = "") -> None:
            try:
                if base_url:
                    self.assistant.set_base_url(base_url)
                self.health_received.emit(self.assistant.health_text())
                self.runtime_received.emit(self.assistant.runtime_summary())
            except Exception as ex:
                self.error_occurred.emit(f"Health check failed: {type(ex).__name__}: {ex}")

        @pyqtSlot()
        def clear_history(self) -> None:
            self.assistant.clear_history()
            self.runtime_received.emit(self.assistant.runtime_summary())

        @pyqtSlot()
        def clear_router_memory(self) -> None:
            self.assistant.clear_router_memory()
            self.runtime_received.emit(self.assistant.runtime_summary())


    class OllamaModelTab(QWidget):
        send_message_requested = pyqtSignal(dict)
        refresh_models_requested = pyqtSignal(str)
        health_requested = pyqtSignal(str)
        clear_history_requested = pyqtSignal()
        clear_router_memory_requested = pyqtSignal()

        def __init__(self, ollama_logger: Any = None, router_provider: Optional[Callable[[], Any]] = None,
                     parent: Any = None) -> None:
            super().__init__(parent)
            self.ollama_logger = ollama_logger or OllamaLogger()
            self.router_provider = router_provider
            self.assistant = OllamaModelAssistant(logger=self.ollama_logger)
            self.worker_thread: Optional[QThread] = None
            self.worker: Optional[OllamaChatWorker] = None
            self.thinking_timer = QTimer(self)
            self.thinking_animation_state = 0
            self._adopted_router_assistant = False
            self._last_runtime: Dict[str, Any] = {}

            self._create_widgets()
            self._configure_layout()
            self._connect_signals()
            self._setup_worker_thread()

            self.router_attach_timer = QTimer(self)
            self.router_attach_timer.setInterval(1500)
            self.router_attach_timer.timeout.connect(self._adopt_router_assistant_if_ready)
            self.router_attach_timer.start()

            QTimer.singleShot(100, self._adopt_router_assistant_if_ready)
            QTimer.singleShot(250, self._refresh_models_clicked)
            QTimer.singleShot(500, self._health_clicked)

        def _create_widgets(self) -> None:
            self.base_url_input = QLineEdit("http://127.0.0.1:11434")
            self.base_url_input.setToolTip("Local Ollama API base URL. Default is http://127.0.0.1:11434")

            self.model_combo = QComboBox()
            self.model_combo.setEditable(True)
            self.model_combo.addItem("llama3.1:8b")

            self.refresh_models_button = QPushButton("🔄 Refresh Models")
            self.health_button = QPushButton("🩺 Health")
            self.clear_history_button = QPushButton("🧹 Clear Chat")
            self.clear_router_memory_button = QPushButton("🧠 Clear Router Memory")

            # Deprecated compatibility attributes. They are intentionally not added
            # to the layout, so there is no manual bind/unbind button in the GUI.
            self.bind_router_button = QPushButton("Init-managed")
            self.bind_router_button.setVisible(False)
            self.auto_bind_router_checkbox = QCheckBox("Init-managed router binding")
            self.auto_bind_router_checkbox.setChecked(False)
            self.auto_bind_router_checkbox.setVisible(False)

            self.use_router_context_checkbox = QCheckBox("Use sanitized router packet memory")
            self.use_router_context_checkbox.setChecked(True)
            self.use_router_context_checkbox.setToolTip("Uses metadata only: layers/endpoints/ports/DNS names/summaries/hashes. No raw payload secrets.")

            self.status_label = QLabel("Ready")
            self.status_label.setStyleSheet("color: #dcdcdc; font-style: italic;")

            self.connection_status_label = QLabel("Ollama: unknown")
            self.model_status_label = QLabel("Model: llama3.1:8b")
            self.router_status_label = QLabel("Router bridge: init-managed / waiting")
            self.memory_status_label = QLabel("Memory: 0 packets")
            self.latency_status_label = QLabel("Latency: -")

            self.chat_output = QTextEdit()
            self.chat_output.setReadOnly(True)
            self.chat_output.setAcceptRichText(True)
            self.chat_output.setPlaceholderText("Ollama chat will appear here. Model-provided <think> traces are surfaced separately.")

            self.thinking_output = QPlainTextEdit()
            self.thinking_output.setReadOnly(True)
            self.thinking_output.setPlaceholderText(
                "Visible model thinking appears here only when the local model returns <think>...</think> text. "
                "This is not hidden system reasoning."
            )
            self.thinking_output.setMaximumBlockCount(2000)

            self.context_output = QPlainTextEdit()
            self.context_output.setReadOnly(True)
            self.context_output.setPlaceholderText("Router memory/context preview used for the latest request.")
            self.context_output.setMaximumBlockCount(3000)

            self.telemetry_output = QPlainTextEdit()
            self.telemetry_output.setReadOnly(True)
            self.telemetry_output.setPlaceholderText("Runtime telemetry, bridge state, packet memory counters.")
            self.telemetry_output.setMaximumBlockCount(3000)

            self.user_input = QPlainTextEdit()
            self.user_input.setPlaceholderText(
                "Ask the local model about router behavior, packet flow, NAT, DNS, p2pool, Ollama logs, or recent packet memory."
            )

            self.send_button = QPushButton("Send to Ollama")
            self.send_button.setObjectName("send_button")

        def _configure_layout(self) -> None:
            main_layout = QVBoxLayout(self)
            main_layout.setContentsMargins(8, 8, 8, 8)

            top_group = QGroupBox("Enterprise Ollama Control Plane")
            top_layout = QGridLayout(top_group)
            top_layout.addWidget(QLabel("Base URL:"), 0, 0)
            top_layout.addWidget(self.base_url_input, 0, 1, 1, 3)
            top_layout.addWidget(QLabel("Model:"), 1, 0)
            top_layout.addWidget(self.model_combo, 1, 1)
            top_layout.addWidget(self.refresh_models_button, 1, 2)
            top_layout.addWidget(self.health_button, 1, 3)
            top_layout.addWidget(self.use_router_context_checkbox, 2, 0, 1, 2)
            top_layout.addWidget(self.clear_history_button, 2, 2)
            top_layout.addWidget(self.clear_router_memory_button, 2, 3)
            main_layout.addWidget(top_group)

            status_group = QGroupBox("Live Status")
            status_layout = QGridLayout(status_group)
            status_layout.addWidget(self.connection_status_label, 0, 0)
            status_layout.addWidget(self.model_status_label, 0, 1)
            status_layout.addWidget(self.router_status_label, 1, 0)
            status_layout.addWidget(self.memory_status_label, 1, 1)
            status_layout.addWidget(self.latency_status_label, 2, 0)
            status_layout.addWidget(self.status_label, 2, 1)
            main_layout.addWidget(status_group)

            self.outer_splitter = QSplitter(Qt.Horizontal)
            self.outer_splitter.setHandleWidth(8)
            self.outer_splitter.setStyleSheet("""
                QSplitter::handle {
                    background-color: #444;
                    border: 1px solid #222;
                }
                QSplitter::handle:hover {
                    background-color: #666;
                }
            """)

            left_widget = QWidget()
            left_layout = QVBoxLayout(left_widget)
            left_layout.setContentsMargins(0, 0, 0, 0)

            self.chat_splitter = QSplitter(Qt.Vertical)
            self.chat_splitter.setHandleWidth(8)
            self.chat_splitter.addWidget(self.chat_output)

            input_widget = QWidget()
            input_layout = QVBoxLayout(input_widget)
            input_layout.setContentsMargins(0, 0, 0, 0)
            input_layout.addWidget(self.user_input)

            bottom = QHBoxLayout()
            bottom.addStretch()
            bottom.addWidget(self.send_button)
            input_layout.addLayout(bottom)

            self.chat_splitter.addWidget(input_widget)
            self.chat_splitter.setSizes([650, 170])
            left_layout.addWidget(self.chat_splitter)

            right_widget = QWidget()
            right_layout = QVBoxLayout(right_widget)
            right_layout.setContentsMargins(0, 0, 0, 0)

            self.side_tabs = QTabWidget()
            self.side_tabs.addTab(self.thinking_output, "🧠 Visible Thinking")
            self.side_tabs.addTab(self.context_output, "📡 Router Context")
            self.side_tabs.addTab(self.telemetry_output, "📊 Telemetry")
            right_layout.addWidget(self.side_tabs)

            self.outer_splitter.addWidget(left_widget)
            self.outer_splitter.addWidget(right_widget)
            self.outer_splitter.setSizes([760, 420])
            self.outer_splitter.setStretchFactor(0, 3)
            self.outer_splitter.setStretchFactor(1, 2)
            main_layout.addWidget(self.outer_splitter, 1)

        def _connect_signals(self) -> None:
            self.send_button.clicked.connect(self._send_clicked)
            self.refresh_models_button.clicked.connect(self._refresh_models_clicked)
            self.health_button.clicked.connect(self._health_clicked)
            self.clear_history_button.clicked.connect(self._clear_history_clicked)
            self.clear_router_memory_button.clicked.connect(self._clear_router_memory_clicked)
            self.thinking_timer.timeout.connect(self._update_thinking_animation)

        def _setup_worker_thread(self) -> None:
            self.worker_thread = QThread()
            self.worker = OllamaChatWorker(self.assistant, logger=self.ollama_logger)
            self.worker.set_router_provider(self.router_provider)
            self.worker.moveToThread(self.worker_thread)

            self.send_message_requested.connect(self.worker.process_message)
            self.refresh_models_requested.connect(self.worker.refresh_models)
            self.health_requested.connect(self.worker.health_check)
            self.clear_history_requested.connect(self.worker.clear_history)
            self.clear_router_memory_requested.connect(self.worker.clear_router_memory)

            self.worker.response_received.connect(self._on_response)
            self.worker.error_occurred.connect(self._on_error)
            self.worker.thinking_started.connect(self._on_thinking_started)
            self.worker.thinking_finished.connect(self._on_thinking_finished)
            self.worker.thinking_trace_received.connect(self._on_thinking_trace)
            self.worker.runtime_received.connect(self._on_runtime)
            self.worker.models_received.connect(self._on_models)
            self.worker.health_received.connect(self._on_health)

            self.worker_thread.start()

        def shutdown(self) -> None:
            try:
                if getattr(self, "router_attach_timer", None):
                    self.router_attach_timer.stop()
            except Exception:
                pass
            try:
                # Only unbind wrappers owned by this GUI assistant. The normal router
                # init-managed assistant remains controlled by router lifecycle.
                if not self._adopted_router_assistant:
                    self.assistant.unbind_router()
            except Exception:
                pass
            try:
                if self.worker_thread and self.worker_thread.isRunning():
                    self.worker_thread.quit()
                    self.worker_thread.wait(5000)
            except Exception:
                pass

        def _payload(self) -> Dict[str, Any]:
            return {
                "base_url": self.base_url_input.text().strip(),
                "model": self.model_combo.currentText().strip(),
                "message": self.user_input.toPlainText().strip(),
                "use_router_context": self.use_router_context_checkbox.isChecked(),
                "auto_bind_router": False,
            }

        def _send_clicked(self) -> None:
            self._adopt_router_assistant_if_ready()
            payload = self._payload()
            if not payload["message"]:
                return
            self.log_message(payload["message"], "user")
            self.user_input.clear()
            self.send_message_requested.emit(payload)

        def _refresh_models_clicked(self) -> None:
            self.refresh_models_requested.emit(self.base_url_input.text().strip())

        def _health_clicked(self) -> None:
            self.health_requested.emit(self.base_url_input.text().strip())

        def _bind_router_clicked(self) -> None:
            # Kept as a no-op compatibility method. The button is not displayed.
            self.log_message(
                "Manual router binding is disabled. Start the router with use_ollama=True so binding happens once during router init.",
                "info",
            )

        def _clear_history_clicked(self) -> None:
            self.clear_history_requested.emit()
            self.chat_output.clear()
            self.thinking_output.clear()
            self.log_message("Chat history cleared.", "info")

        def _clear_router_memory_clicked(self) -> None:
            self.clear_router_memory_requested.emit()
            self.context_output.clear()
            self.telemetry_output.clear()
            self.log_message("Router packet memory cleared.", "info")

        def _adopt_router_assistant_if_ready(self) -> None:
            try:
                router = self.router_provider() if callable(self.router_provider) else None
                router_assistant = getattr(router, "ollama_assistant", None) if router is not None else None
                if isinstance(router_assistant, OllamaModelAssistant) and router_assistant is not self.assistant:
                    self.assistant = router_assistant
                    self._adopted_router_assistant = True
                    if self.worker is not None:
                        self.worker.set_assistant(router_assistant)
                    self.log_message("Adopted init-managed router Ollama assistant. No GUI bind action was run.", "info")
                self._update_router_status(router)
            except Exception as ex:
                self.router_status_label.setText(f"Router bridge: status error {type(ex).__name__}")

        def _update_router_status(self, router: Any = None) -> None:
            try:
                if router is None:
                    router = self.router_provider() if callable(self.router_provider) else None
                bridge = getattr(router, "ollama_router_bridge", None) if router is not None else None
                memory = getattr(router, "ollama_packet_memory", None) if router is not None else None
                if bridge is not None:
                    bound = bool(getattr(bridge, "bound", False))
                    self.router_status_label.setText(f"Router bridge: {'bound on init' if bound else 'installed / not bound'}")
                elif router is not None:
                    self.router_status_label.setText("Router bridge: not installed; start router with use_ollama=True")
                else:
                    self.router_status_label.setText("Router bridge: waiting for router")
                if memory is not None and callable(getattr(memory, "snapshot", None)):
                    snap = memory.snapshot()
                    self.memory_status_label.setText(
                        f"Memory: {snap.get('stored_events', 0)} stored / {snap.get('packet_total', 0)} seen"
                    )
            except Exception:
                pass

        @pyqtSlot(str)
        def _on_response(self, text: str) -> None:
            self.log_message(text, "ollama")

        @pyqtSlot(str)
        def _on_error(self, text: str) -> None:
            self.log_message(text, "error")

        @pyqtSlot(str, str)
        def _on_thinking_trace(self, thinking: str, context: str) -> None:
            thinking = str(thinking or "").strip()
            context = str(context or "").strip()

            if thinking:
                self.thinking_output.setPlainText(thinking)
                self.log_message(thinking, "thinking")
            else:
                self.thinking_output.setPlainText(
                    "No explicit <think>...</think> trace was returned by this local model for the last answer."
                )

            if context:
                self.context_output.setPlainText(context)
            else:
                self.context_output.setPlainText("No router context was attached to the last request.")

        @pyqtSlot(dict)
        def _on_runtime(self, runtime: Dict[str, Any]) -> None:
            self._last_runtime = runtime or {}
            try:
                self.model_status_label.setText(f"Model: {self._last_runtime.get('model', '-')}")
                self.connection_status_label.setText(f"Ollama: {self._last_runtime.get('base_url', '-')}")
                latency = self._last_runtime.get("last_latency_s", 0.0)
                self.latency_status_label.setText(f"Latency: {latency}s")
                mem = self._last_runtime.get("memory", {}) or {}
                self.memory_status_label.setText(
                    f"Memory: {mem.get('stored_events', 0)} stored / {mem.get('packet_total', 0)} seen"
                )
                self.telemetry_output.setPlainText(json.dumps(self._last_runtime, indent=2, default=str))
            except Exception:
                pass

        @pyqtSlot(list)
        def _on_models(self, models: List[str]) -> None:
            current = self.model_combo.currentText().strip()
            self.model_combo.blockSignals(True)
            self.model_combo.clear()
            for name in models:
                self.model_combo.addItem(str(name))
            if current:
                idx = self.model_combo.findText(current)
                if idx >= 0:
                    self.model_combo.setCurrentIndex(idx)
                else:
                    self.model_combo.setEditText(current)
            elif models:
                self.model_combo.setCurrentIndex(0)
            self.model_combo.blockSignals(False)
            self.log_message(f"Loaded {len(models)} Ollama model(s).", "info")

        @pyqtSlot(str)
        def _on_health(self, text: str) -> None:
            self.log_message(text, "info")
            self.telemetry_output.setPlainText(str(text or ""))

        @pyqtSlot()
        def _on_thinking_started(self) -> None:
            self.send_button.setEnabled(False)
            self.user_input.setEnabled(False)
            self.status_label.setStyleSheet("color: #ffff00; font-style: italic;")
            self.thinking_animation_state = 0
            self._update_thinking_animation()
            self.thinking_timer.start(450)

        @pyqtSlot()
        def _on_thinking_finished(self) -> None:
            self.thinking_timer.stop()
            self.send_button.setEnabled(True)
            self.user_input.setEnabled(True)
            self.status_label.setText("Ready")
            self.status_label.setStyleSheet("color: #dcdcdc; font-style: italic;")
            self.send_button.setText("Send to Ollama")
            self._adopt_router_assistant_if_ready()

        def _update_thinking_animation(self) -> None:
            dots = "." * ((self.thinking_animation_state % 3) + 1)
            self.status_label.setText(f"Ollama thinking{dots}")
            self.send_button.setText(f"Thinking{dots}")
            self.thinking_animation_state += 1

        @pyqtSlot(str, str)
        def log_message(self, content: str, message_type: str = "info") -> None:
            content = str(content or "")
            if not content:
                return

            label = {
                "user": "You",
                "ollama": "Ollama",
                "thinking": "Visible model thinking",
                "error": "ERROR",
                "info": "Info",
            }.get(message_type, "Info")

            color = {
                "user": "#87CEEB",
                "ollama": "#90EE90",
                "thinking": "#d7b8ff",
                "error": "#FF6347",
                "info": "#dcdcdc",
            }.get(message_type, "#dcdcdc")

            safe = html.escape(content).replace("\n", "<br>")
            final_html = (
                f"<div style='color:{color}; margin-bottom: 12px;'>"
                f"<b>{label}:</b> {safe}</div><br>"
            )
            self.chat_output.moveCursor(QTextCursor.End)
            self.chat_output.insertHtml(final_html)
            self.chat_output.insertHtml("<br>")
            self.chat_output.moveCursor(QTextCursor.End)
else:
    # Headless placeholders, so `from p2pool_ollama import *` does not fail.
    class OllamaChatWorker:  # type: ignore[no-redef]
        pass

    class OllamaModelTab:  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# Router helper functions
# ---------------------------------------------------------------------------

def install_ollama_on_router(router_manager: Any, logger: Any = None,
                             config: Optional[OllamaConfig] = None) -> OllamaModelAssistant:
    """
    Attach an Ollama assistant directly to a PythonRouterManager instance.

    This is intentionally safe to call from router init when use_ollama=True:
    - no new patches outside this file are required
    - no manual GUI bind button is required
    - binding failures are logged and returned as an unbound assistant instead of
      throwing through the router startup path
    """
    actual_logger = logger or getattr(router_manager, "router_logger", None)
    existing = getattr(router_manager, "ollama_assistant", None) if router_manager is not None else None

    if isinstance(existing, OllamaModelAssistant):
        assistant = existing
        if config is not None:
            assistant.config = config
            assistant.client.config = config
    else:
        assistant = OllamaModelAssistant(logger=actual_logger, config=config)

    ok = False
    try:
        ok = assistant.bind_router(router_manager)
    except Exception as ex:
        _safe_log(actual_logger, f"[Ollama] ⚠️ Init-managed bridge bind failed safely: {type(ex).__name__}: {ex}", "error")
        ok = False

    try:
        setattr(router_manager, "ollama_assistant", assistant)
        setattr(router_manager, "ollama_packet_memory", assistant.memory)
        setattr(router_manager, "ollama_router_bridge", assistant.bridge)
    except Exception:
        pass

    if ok:
        _safe_log(actual_logger, "[Ollama] ✅ Init-managed router bridge ready.", "info")
    else:
        _safe_log(actual_logger, "[Ollama] ⚠️ Assistant created, but router bridge is not bound. Chat still works without packet learning.", "error")

    return assistant


__all__ = [
    "OllamaConfig",
    "OllamaClient",
    "RouterPacketFact",
    "RouterPacketMemory",
    "OllamaRouterBridge",
    "OllamaModelAssistant",
    "OllamaLogger",
    "OllamaChatWorker",
    "OllamaModelTab",
    "install_ollama_on_router",
]
