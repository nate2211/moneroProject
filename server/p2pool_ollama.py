
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
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except Exception:  # pragma: no cover
    QObject = object
    QThread = QTimer = Qt = QTextCursor = None
    pyqtSignal = pyqtSlot = None
    QApplication = QCheckBox = QComboBox = QFormLayout = QGridLayout = QGroupBox = QHBoxLayout = QLabel = QLineEdit = None
    QMessageBox = QPlainTextEdit = QPushButton = QSizePolicy = QSplitter = QTextEdit = QVBoxLayout = QWidget = None


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
    Hooks Ollama memory into PythonRouterManager without requiring you to rewrite
    the router packet hot path.

    Strategy:
    - Wrap router.code_output_manager.submit_packet().
    - First send a sanitized fact to RouterPacketMemory.
    - Then call the original submit_packet() unchanged.
    - Periodically pull manager.health_snapshot()/correlation_snapshot()/export_knowledge().
    """

    def __init__(self, memory: RouterPacketMemory, logger: Any = None) -> None:
        self.memory = memory
        self.logger = logger or _NullLogger()
        self._lock = threading.RLock()
        self._router_ref: Any = None
        self._co_ref: Any = None
        self._orig_submit_packet: Optional[Callable[..., Any]] = None
        self._bound = False
        self._stop_event = threading.Event()
        self._snapshot_thread: Optional[threading.Thread] = None
        self.snapshot_every_s = 8.0

    @property
    def bound(self) -> bool:
        return bool(self._bound)

    def bind_to_router(self, router_manager: Any) -> bool:
        if router_manager is None:
            _safe_log(self.logger, "[OllamaBridge] Router manager is None; cannot bind.", "error")
            return False

        co = getattr(router_manager, "code_output_manager", None)
        if co is None or not callable(getattr(co, "submit_packet", None)):
            _safe_log(self.logger, "[OllamaBridge] Router has no usable code_output_manager.submit_packet.", "error")
            return False

        with self._lock:
            if self._bound and self._co_ref is co:
                return True
            if self._bound:
                self.unbind()

            self._router_ref = router_manager
            self._co_ref = co
            self._orig_submit_packet = co.submit_packet

            def wrapped_submit_packet(packet: Any, inbound_iface: Optional[str] = None, **context: Any) -> Any:
                try:
                    self.memory.ingest_packet(packet, inbound_iface=inbound_iface, **context)
                except Exception as ex:
                    _safe_log(self.logger, f"[OllamaBridge] packet memory ingest failed: {ex}", "error")
                return self._orig_submit_packet(packet, inbound_iface=inbound_iface, **context)

            co.submit_packet = wrapped_submit_packet
            self._bound = True
            self._stop_event.clear()
            self._snapshot_thread = threading.Thread(
                target=self._snapshot_loop,
                name="OllamaRouterSnapshotLoop",
                daemon=True,
            )
            self._snapshot_thread.start()

        _safe_log(self.logger, "[OllamaBridge] ✅ Bound to router CodeOutputManager.submit_packet().", "info")
        return True

    def unbind(self) -> None:
        with self._lock:
            self._stop_event.set()
            co = self._co_ref
            if co is not None and self._orig_submit_packet is not None:
                try:
                    co.submit_packet = self._orig_submit_packet
                except Exception:
                    pass
            t = self._snapshot_thread
            self._bound = False
            self._router_ref = None
            self._co_ref = None
            self._orig_submit_packet = None
            self._snapshot_thread = None

        if t and t.is_alive():
            t.join(timeout=1.5)
        _safe_log(self.logger, "[OllamaBridge] Unbound.", "info")

    def _snapshot_loop(self) -> None:
        while not self._stop_event.wait(self.snapshot_every_s):
            try:
                co = self._co_ref
                if co is not None:
                    self.memory.learn_from_code_output_manager(co)
            except Exception as ex:
                _safe_log(self.logger, f"[OllamaBridge] snapshot failed: {ex}", "error")


# ---------------------------------------------------------------------------
# Assistant backend
# ---------------------------------------------------------------------------

class OllamaModelAssistant:
    """
    Stateful assistant backend. It keeps message history, attaches router memory,
    and talks to the local Ollama server.
    """

    def __init__(self, logger: Any = None, config: Optional[OllamaConfig] = None) -> None:
        self.logger = logger or _NullLogger()
        self.config = config or OllamaConfig()
        self.client = OllamaClient(self.config, logger=self.logger)
        self.memory = RouterPacketMemory(logger=self.logger)
        self.bridge = OllamaRouterBridge(self.memory, logger=self.logger)
        self._lock = threading.RLock()
        self.messages: List[Dict[str, str]] = []
        self._last_model_list: List[Dict[str, Any]] = []

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
        model_names = []
        try:
            model_names = self.refresh_models()
        except Exception as ex:
            model_names = [f"model refresh error: {ex}"]

        mem = self.memory.snapshot()
        return (
            "Ollama health:\n"
            + json.dumps(health, indent=2, default=str)
            + "\n\nModels:\n"
            + "\n".join(f"- {m}" for m in model_names[:64])
            + "\n\nRouter memory:\n"
            + json.dumps(mem, indent=2, default=str)[:4000]
        )

    def router_context_text(self, router_manager: Any = None) -> str:
        if router_manager is not None:
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

        system = self.config.system_prompt
        if use_router_context:
            ctx = self.router_context_text(router_manager)
            system = f"{system}\n\n{ctx}"

        with self._lock:
            # Keep history bounded so the GUI does not explode context length.
            if len(self.messages) > 24:
                self.messages = self.messages[-24:]
            outbound = [{"role": "system", "content": system}] + list(self.messages)
            outbound.append({"role": "user", "content": user_message})

        started = time.time()
        try:
            response = self.client.chat(model_name, outbound, stream=False)
        except requests.exceptions.ConnectionError as ex:
            raise RuntimeError(
                f"Cannot connect to Ollama at {self.client.base_url}. Start it with `ollama serve` "
                f"or fix the base URL. Underlying error: {ex}"
            ) from ex
        except Exception:
            raise

        elapsed = time.time() - started
        with self._lock:
            self.messages.append({"role": "user", "content": user_message})
            self.messages.append({"role": "assistant", "content": response})
        _safe_log(self.logger, f"[Ollama] model={model_name} answered in {elapsed:.2f}s chars={len(response)}", "info")
        return response


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
        models_received = pyqtSignal(list)
        health_received = pyqtSignal(str)

        def __init__(self, assistant: OllamaModelAssistant, logger: Any = None) -> None:
            super().__init__()
            self.assistant = assistant
            self.logger = logger or _NullLogger()
            self._router_provider: Optional[Callable[[], Any]] = None

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
                auto_bind = bool(payload.get("auto_bind_router", True))

                if base_url:
                    self.assistant.set_base_url(base_url)
                if model:
                    self.assistant.set_model(model)

                router = self._router()
                if auto_bind and router is not None:
                    self.assistant.bind_router(router)

                response = self.assistant.send_message(
                    text,
                    model=model or None,
                    router_manager=router,
                    use_router_context=use_context,
                )
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
            except Exception as ex:
                self.error_occurred.emit(f"Model refresh failed: {type(ex).__name__}: {ex}")

        @pyqtSlot(str)
        def health_check(self, base_url: str = "") -> None:
            try:
                if base_url:
                    self.assistant.set_base_url(base_url)
                self.health_received.emit(self.assistant.health_text())
            except Exception as ex:
                self.error_occurred.emit(f"Health check failed: {type(ex).__name__}: {ex}")

        @pyqtSlot()
        def clear_history(self) -> None:
            self.assistant.clear_history()

        @pyqtSlot()
        def clear_router_memory(self) -> None:
            self.assistant.clear_router_memory()


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

            self._create_widgets()
            self._configure_layout()
            self._connect_signals()
            self._setup_worker_thread()

            QTimer.singleShot(250, self._refresh_models_clicked)

        def _create_widgets(self) -> None:
            self.base_url_input = QLineEdit("http://127.0.0.1:11434")
            self.base_url_input.setToolTip("Local Ollama API base URL. Default is http://127.0.0.1:11434")

            self.model_combo = QComboBox()
            self.model_combo.setEditable(True)
            self.model_combo.addItem("llama3.1:8b")

            self.refresh_models_button = QPushButton("🔄 Refresh Models")
            self.health_button = QPushButton("🩺 Health")
            self.bind_router_button = QPushButton("🔗 Bind Router")
            self.clear_history_button = QPushButton("Clear Chat")
            self.clear_router_memory_button = QPushButton("Clear Router Memory")

            self.use_router_context_checkbox = QCheckBox("Use router packet memory/context")
            self.use_router_context_checkbox.setChecked(True)
            self.auto_bind_router_checkbox = QCheckBox("Auto-bind to running router")
            self.auto_bind_router_checkbox.setChecked(True)

            self.status_label = QLabel("Ready")
            self.status_label.setStyleSheet("color: #dcdcdc; font-style: italic;")

            self.chat_output = QTextEdit()
            self.chat_output.setReadOnly(True)
            self.chat_output.setAcceptRichText(True)
            self.chat_output.setPlaceholderText("Ollama responses and router-learning status will appear here...")

            self.user_input = QPlainTextEdit()
            self.user_input.setPlaceholderText(
                "Ask your local Ollama model about router behavior, packet flow, NAT, DNS, p2pool, etc."
            )

            self.send_button = QPushButton("Send to Ollama")
            self.send_button.setObjectName("send_button")

        def _configure_layout(self) -> None:
            main_layout = QVBoxLayout(self)
            main_layout.setContentsMargins(6, 6, 6, 6)

            config_group = QGroupBox("Ollama Model")
            config_layout = QGridLayout(config_group)
            config_layout.addWidget(QLabel("Base URL:"), 0, 0)
            config_layout.addWidget(self.base_url_input, 0, 1, 1, 3)
            config_layout.addWidget(QLabel("Model:"), 1, 0)
            config_layout.addWidget(self.model_combo, 1, 1)
            config_layout.addWidget(self.refresh_models_button, 1, 2)
            config_layout.addWidget(self.health_button, 1, 3)
            config_layout.addWidget(self.use_router_context_checkbox, 2, 0, 1, 2)
            config_layout.addWidget(self.auto_bind_router_checkbox, 2, 2)
            config_layout.addWidget(self.bind_router_button, 2, 3)
            config_layout.addWidget(self.clear_history_button, 3, 0)
            config_layout.addWidget(self.clear_router_memory_button, 3, 1)
            config_layout.addWidget(self.status_label, 3, 2, 1, 2)
            main_layout.addWidget(config_group)

            self.splitter = QSplitter(Qt.Vertical)
            self.splitter.setHandleWidth(8)
            self.splitter.setStyleSheet("""
                QSplitter::handle {
                    background-color: #444;
                    border: 1px solid #222;
                }
                QSplitter::handle:hover {
                    background-color: #666;
                }
            """)

            self.splitter.addWidget(self.chat_output)

            input_widget = QWidget()
            input_layout = QVBoxLayout(input_widget)
            input_layout.setContentsMargins(0, 0, 0, 0)
            input_layout.addWidget(self.user_input)
            bottom = QHBoxLayout()
            bottom.addStretch()
            bottom.addWidget(self.send_button)
            input_layout.addLayout(bottom)
            self.splitter.addWidget(input_widget)
            self.splitter.setSizes([620, 180])

            main_layout.addWidget(self.splitter, 1)

        def _connect_signals(self) -> None:
            self.send_button.clicked.connect(self._send_clicked)
            self.refresh_models_button.clicked.connect(self._refresh_models_clicked)
            self.health_button.clicked.connect(self._health_clicked)
            self.bind_router_button.clicked.connect(self._bind_router_clicked)
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
            self.worker.models_received.connect(self._on_models)
            self.worker.health_received.connect(self._on_health)

            self.worker_thread.start()

        def shutdown(self) -> None:
            try:
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
                "auto_bind_router": self.auto_bind_router_checkbox.isChecked(),
            }

        def _send_clicked(self) -> None:
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
            try:
                router = self.router_provider() if callable(self.router_provider) else None
                if router is None:
                    self.log_message("Router manager is not available yet. Start the router first or pass a router_provider.", "error")
                    return
                ok = self.assistant.bind_router(router)
                if ok:
                    self.log_message("Bound to router. Ollama will now learn from sanitized packet metadata.", "info")
                else:
                    self.log_message("Failed to bind to router.", "error")
            except Exception as ex:
                self.log_message(f"Bind failed: {type(ex).__name__}: {ex}", "error")

        def _clear_history_clicked(self) -> None:
            self.clear_history_requested.emit()
            self.chat_output.clear()
            self.log_message("Chat history cleared.", "info")

        def _clear_router_memory_clicked(self) -> None:
            self.clear_router_memory_requested.emit()
            self.log_message("Router packet memory cleared.", "info")

        @pyqtSlot(str)
        def _on_response(self, text: str) -> None:
            self.log_message(text, "ollama")

        @pyqtSlot(str)
        def _on_error(self, text: str) -> None:
            self.log_message(text, "error")

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
                "error": "ERROR",
                "info": "Info",
            }.get(message_type, "Info")

            color = {
                "user": "#87CEEB",
                "ollama": "#90EE90",
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

    Usage inside PythonRouterManager.start_routing or GUI start_router:
        from p2pool_ollama import install_ollama_on_router
        self.ollama_assistant = install_ollama_on_router(self, self.router_logger)
    """
    assistant = OllamaModelAssistant(logger=logger or getattr(router_manager, "router_logger", None), config=config)
    ok = assistant.bind_router(router_manager)
    if ok:
        try:
            setattr(router_manager, "ollama_assistant", assistant)
            setattr(router_manager, "ollama_packet_memory", assistant.memory)
            setattr(router_manager, "ollama_router_bridge", assistant.bridge)
        except Exception:
            pass
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
