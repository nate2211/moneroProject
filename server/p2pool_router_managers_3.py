import inspect
import json
import queue
import threading
import time
import re
import traceback
from collections import deque, defaultdict, Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Union, Tuple

# NumPy for analysis (only used during analysis; raw values stay as Python lists)
import numpy as np


# ---------- Knowledge model ----------

@dataclass
class KnowledgePacket:
    """
    A transient 'packet' of knowledge.
    - topic: logical channel (e.g., "tls", "dns", "dhcp", "router", "transport", ...)
    - payload: dict; may include {"attributes": {...}, "methods": {...}}
    - ttl: seconds until it expires and is purged
    """
    topic: str
    payload: Dict[str, Any]
    ttl: float = 120.0
    source: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    importance: int = 0
    ts: float = field(default_factory=time.time)

    @property
    def expires_at(self) -> float:
        return self.ts + self.ttl

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at


# ---------- CodeOutputManager (drop-in, protocol-agnostic, self-wired bus) ----------

@dataclass
class EmitterConfig:
    """
    Runtime-configurable auto-emitter settings.

    - every_s: emit period in seconds (<=0 disables)
    - jitter_s: random +/- jitter added to the period
    - min_new_packets: do not emit unless at least this many new packets ingested since last emit
    - to_file: path template for writing snapshots (str.format variables: {ts}, {seq}, {name})
    """
    every_s: float = 10.0
    jitter_s: float = 2.0
    min_new_packets: int = 1
    to_file: Optional[str] = None


@dataclass
class Stats:
    """
    Rolling counters for observability. All updates guarded by the manager's lock.
    """
    packets_ingested: int = 0
    packets_dropped: int = 0
    emits: int = 0
    emit_duplicates: int = 0
    errors: int = 0
    by_topic: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def snapshot(self) -> Dict[str, Any]:
        return {
            "packets_ingested": self.packets_ingested,
            "packets_dropped": self.packets_dropped,
            "emits": self.emits,
            "emit_duplicates": self.emit_duplicates,
            "errors": self.errors,
            "by_topic": dict(self.by_topic),
        }


class MiniTemplateEngine:
    """
    Tiny helper to render a Python class with attributes/methods. Keeps generation deterministic.
    """

    @staticmethod
    def render_class(class_name: str,
                     attributes: Dict[str, Any],
                     methods: Dict[str, Any],
                     doc: Optional[str] = "A generated class.") -> str:
        lines: List[str] = []
        lines.append(f"class {class_name}:")
        lines.append(f'    """{doc}"""')
        lines.append("")
        lines.append("    def __init__(self):")
        if not attributes:
            lines.append("        pass")
        else:
            for name, val in sorted(attributes.items()):
                # Keep snapshots pure-Python (no np.ndarray literals)
                lines.append(f"        self.{name} = {repr(val)}")
        lines.append("")

        for mname, mdef in sorted(methods.items()):
            lines.append(f"    def {mname}(self, *args, **kwargs):")
            body = mdef.get("body") if isinstance(mdef, dict) else mdef
            if isinstance(body, str) and body.strip():
                for ln in body.splitlines():
                    lines.append(f"        {ln}")
            else:
                lines.append(f"        return {repr(body)}")
            lines.append("")
        return "\n".join(lines)


# ============================================================
#   CodeOutputManager (drop-in, protocol-agnostic, self-wired)
# ============================================================

class CodeOutputManager:
    """
    Protocol-agnostic, transient learning manager.

    • Accepts ANY "packet" (scapy packet, dict, list/tuple, bytes/str JSON or logs).
    • Normalizes into KnowledgePacket(s) and stores them with TTL.
    • Provides a built-in packet bus so you can simply call `submit_packet(...)`.
    • Can also attach external queues via `attach_external_source(...)`.
    • Generates Python classes from current transient knowledge.
    • Periodically (and/or conditionally) emits code snapshots via the auto-emitter.
    • Recognizes TLSRecord objects (duck-typed) and summarizes them.
    • 🔊 Loud, toggleable debug logging for end-to-end visibility.
    • 🧠 Adaptive learning and NumPy-powered statistics.
    • 🔌 Built-in wiring helper for TLSRecordManager.
    """

    # Limits & cadence
    MAX_PACKETS_PER_TOPIC = 256
    CLEANUP_INTERVAL_S = 5.0

    # Topic helpers
    TOPIC_ALIASES: Dict[str, set] = {
        "tls": {"tls", "ssl", "handshake", "https"},
        "dns": {"dns", "mdns"},
        "dhcp": {"dhcp", "dhcpv6"},
        "arp": {"arp"},
        "http": {"http"},
        "quic": {"quic"},
        "vpn": {"ipsec", "isakmp", "natt", "esp", "ah", "vpn", "gre"},
        "kerberos": {"kerberos", "krb5"},
        "ntp": {"ntp"},
        "ssh": {"ssh"},
        "smtp": {"smtp", "submission"},
        "imap": {"imap", "imaps"},
        "pop": {"pop3", "pop3s"},
        "snmp": {"snmp"},
        "ldap": {"ldap", "ldaps"},
        "smb": {"smb", "cifs"},
        "rdp": {"rdp"},
        "mqtt": {"mqtt"},
        "transport": {"tcp", "udp", "icmp"},
        "router": {"router", "l2", "ether", "forward"},
        "misc": set(),
    }
    DEFAULT_TTLS: Dict[str, float] = {
        "tls": 300.0, "dns": 180.0, "dhcp": 180.0, "arp": 60.0, "http": 180.0, "quic": 180.0,
        "vpn": 240.0, "kerberos": 300.0, "ntp": 300.0, "ssh": 300.0, "smtp": 300.0, "imap": 300.0,
        "pop": 300.0, "snmp": 300.0, "ldap": 300.0, "smb": 300.0, "rdp": 300.0, "mqtt": 300.0,
        "transport": 180.0, "router": 180.0, "misc": 120.0,
    }

    # Common ports → topics (heuristic)
    PORT_TOPIC_HINTS = {
        443: "tls", 8443: "tls", 4443: "tls",
        80: "http", 8080: "http", 8000: "http",
        53: "dns", 5353: "dns",
        67: "dhcp", 68: "dhcp",
        500: "vpn", 4500: "vpn",
        88: "kerberos",
        123: "ntp",
        22: "ssh",
        25: "smtp", 587: "smtp",
        143: "imap", 993: "imap",
        110: "pop", 995: "pop",
        161: "snmp",
        389: "ldap", 636: "ldap",
        445: "smb",
        3389: "rdp",
        1883: "mqtt", 8883: "mqtt",
    }

    # TLS handshake type names (best-effort)
    TLS_HANDSHAKE_TYPES = {
        0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
        11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest",
        14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange",
        20: "Finished", 22: "CertificateStatus", 23: "SupplementalData",
        # TLS 1.3 (best-effort names)
        8: "EncryptedExtensions", 13: "CertificateRequest",
    }

    BRACKET_TAG_RE = re.compile(r"\[([A-Za-z0-9_ \-:#/]+)\]")
    KV_TOKEN_RE = re.compile(r"(\b[\w\./:-]+)=(\".*?\"|\'.*?\'|[^\s]+)")
    NDJSON_SPLIT_RE = re.compile(r"\r?\n+")
    TOKEN_SPLIT_RE = re.compile(r"[^\w]+")

    # --------------------------- lifecycle ---------------------------

    def __init__(self, router_logger: Any):
        # Expect a logger with .log_message(...)
        self.logger = router_logger
        self._verbose = 1

        # lifecycle
        self._stop_event = threading.Event()
        self._gen_thread: Optional[threading.Thread] = None
        self._clean_thread: Optional[threading.Thread] = None
        self._bus_thread: Optional[threading.Thread] = None
        self._emit_thread: Optional[threading.Thread] = None

        # work queues
        self._generation_queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._bus_queue: "queue.Queue[Any]" = queue.Queue()

        # transient knowledge store
        self._knowledge_by_topic: Dict[str, Deque[KnowledgePacket]] = {}
        self._k_lock = threading.Lock()

        # external packet sources
        self._external_sources: List[
            Tuple[queue.Queue, Optional[Callable[[Any], KnowledgePacket]], threading.Thread]] = []
        self._custom_aliases: Dict[str, set] = {}

        # Auto-emitter config & state
        self._emitter_cfg = EmitterConfig()
        self._emit_builder: Callable[[], Dict[str, Any]] = self._default_emit_builder
        self._emit_sink: Callable[[str, Dict[str, Any]], None] = self._default_emit_sink
        self._ingest_since_emit = 0
        self._last_emitted_hash: Optional[str] = None
        self._emit_seq = 0

        # Observability
        self._stats = Stats()
        self._hooks: Dict[str, List[Callable[..., None]]] = defaultdict(
            list)  # pre_ingest, post_ingest, pre_emit, post_emit

        # Adaptive learning
        self._adaptive = True
        self._concept_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._ttl_boost_threshold = 8
        self._ttl_boost_factor = 1.5
        self._insights_max = 15

        # One-time IPsec warning control
        self._ipsec_warned = False

        # ---------- NumPy-powered knowledge growth ----------
        # Numeric vectors per topic: feature -> list[float]
        self._num_vectors: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        # Categorical counts per topic: feature -> Counter(value -> count)
        self._cat_counters: Dict[str, Dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
        # Hard caps to avoid unbounded memory
        self._per_feature_cap = 8192  # recent N numeric values remembered per feature

        self.log_message("[CodeOutput] Manager initialized (drop-in, protocol-agnostic, NumPy stats ready).")

    # --------------------------- logging helpers ---------------------------

    def set_verbose(self, level: int = 1) -> None:
        """0=quiet, 1=info, 2=debug."""
        self._verbose = int(level)
        self.log_message(f"[CodeOutput] Verbose set to {self._verbose} (0=quiet,1=info,2=debug).")

    def log_message(self, msg: str) -> None:
        try:
            if self.logger and hasattr(self.logger, "log_message"):
                self.logger.log_message(msg)
            else:
                print(msg)
        except Exception:
            print(msg)

    def _log(self, msg: str, level: int = 1) -> None:
        if self._verbose >= level:
            self.log_message(msg)

    # --------------------------- auto-emitter config ---------------------------

    def set_auto_emit_config(self,
                             every_s: Optional[float] = None,
                             jitter_s: Optional[float] = None,
                             min_new_packets: Optional[int] = None,
                             to_file: Optional[str] = None) -> None:
        with self._k_lock:
            if every_s is not None:
                self._emitter_cfg.every_s = float(every_s)
            if jitter_s is not None:
                self._emitter_cfg.jitter_s = float(jitter_s)
            if min_new_packets is not None:
                self._emitter_cfg.min_new_packets = int(min_new_packets)
            if to_file is not None:
                self._emitter_cfg.to_file = to_file
        self._log(f"[CodeOutput] Auto-emitter config updated: {self._emitter_cfg}", 1)

    def add_sink(self, sink: Callable[[str, Dict[str, Any]], None]) -> None:
        if not callable(sink):
            self._log(f"[CodeOutput] ⚠️ Sink not callable.\n{traceback.format_exc()}", 1)
        self._hooks["post_emit"].append(lambda code, cfg: sink(code, cfg))
        self._log("[CodeOutput] Added post-emit sink.", 1)

    def add_hook(self, event: str, callback: Callable[..., None]) -> None:
        if event not in ("pre_ingest", "post_ingest", "pre_emit", "post_emit"):
            self._log(f"[CodeOutput] ⚠️ Unknown hook '{event}'.\n{traceback.format_exc()}", 1)
        self._hooks[event].append(callback)
        self._log(f"[CodeOutput] Hook registered for '{event}'.", 2)

    def _fire_hooks(self, event: str, **kwargs) -> None:
        for cb in list(self._hooks.get(event, [])):
            try:
                cb(**kwargs)
            except Exception as ex:
                self._stats.errors += 1
                self._log(f"[CodeOutput] ⚠️ Hook error ({event}): {ex}\n{traceback.format_exc()}", 1)

    # --------------------------- lifecycle threads ---------------------------

    def start(self):
        if self._gen_thread and self._gen_thread.is_alive():
            self._log("[CodeOutput] Manager is already running.", 1)
            return

        self._stop_event.clear()

        self._bus_thread = threading.Thread(target=self._bus_consumer_loop, daemon=True, name="CodeOutputBus")
        self._bus_thread.start()

        self._gen_thread = threading.Thread(target=self._generation_loop, daemon=True, name="CodeOutputGen")
        self._gen_thread.start()

        self._clean_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="CodeOutputCleanup")
        self._clean_thread.start()

        self._emit_thread = threading.Thread(target=self._auto_emit_loop, daemon=True, name="CodeOutputEmit")
        self._emit_thread.start()

        self._log("[CodeOutput] Threads started (bus + generation + cleanup + auto-emit).", 1)

    def stop(self):
        if not any([self._gen_thread, self._clean_thread, self._bus_thread, self._emit_thread]):
            return
        self._log("[CodeOutput] Stopping manager...", 1)
        self._stop_event.set()

        for q in (self._generation_queue, self._bus_queue):
            try:
                q.put_nowait(None)
            except Exception:
                pass

        for q, _, t in list(self._external_sources):
            try:
                q.put_nowait(None)  # sentinel
            except Exception:
                pass
            if t.is_alive():
                t.join(timeout=1.5)
        self._external_sources.clear()

        for t in (self._bus_thread, self._gen_thread, self._clean_thread, self._emit_thread):
            if t and t.is_alive():
                t.join(timeout=2)

        self._log("[CodeOutput] Manager stopped.", 1)

    # --------------------------- auto-emitter ---------------------------

    def _auto_emit_loop(self):
        """Periodically generates and emits a snapshot class from current knowledge."""
        import random
        import hashlib

        self._log("[CodeOutput] ⏱️ Auto-emitter loop started.", 1)

        while not self._stop_event.is_set():
            with self._k_lock:
                period = float(self._emitter_cfg.every_s)
                jitter = float(self._emitter_cfg.jitter_s)
                min_new = int(self._emitter_cfg.min_new_packets)

            if period <= 0:
                self._log("[CodeOutput] ⏸️ Auto-emitter disabled (every_s <= 0).", 1)
                break

            delay = period + (random.uniform(0.0, jitter) if jitter > 0 else 0.0)

            if self._stop_event.wait(delay):
                break

            with self._k_lock:
                gated = (min_new > 0 and self._ingest_since_emit < min_new)

            if gated:
                self._log(f"[CodeOutput] ⏭️ Skipping emit (ingested {self._ingest_since_emit} < min {min_new}).", 2)
                continue

            try:
                self._fire_hooks("pre_emit")
                cfg = self._emit_builder()
                code = self.generate_class_from_config(cfg)

                h = hashlib.sha256(code.encode("utf-8")).hexdigest()
                self._log(f"[CodeOutput] 🔁 Auto-emitter produced hash={h[:10]}… len={len(code)} bytes.", 1)
                self._log(f"[CodeOutput] 🔁 {code}", 2)
                if h != self._last_emitted_hash:
                    self._emit_sink(code, cfg)
                    self._fire_hooks("post_emit", code=code, cfg=cfg)
                    with self._k_lock:
                        self._last_emitted_hash = h
                        self._ingest_since_emit = 0
                        self._stats.emits += 1
                else:
                    with self._k_lock:
                        self._stats.emit_duplicates += 1
                    self._log("[CodeOutput] 🔁 Skipped emit (duplicate snapshot hash).", 1)
            except Exception as ex:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] ⚠️ auto-emit error: {ex}\n{traceback.format_exc()}", 1)

        self._log("[CodeOutput] ⏹️ Auto-emitter loop stopped.", 1)

    def _default_emit_builder(self, *_ignored) -> Dict[str, Any]:
        """Default snapshot config."""
        from datetime import datetime
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return {
            "class_name": f"Snapshot_{ts}",
            "topics": [],  # ALL topics
            "attr_policy": "merge",  # merge or override
            "method_policy": "merge",
            "include_insights": True,
            # Attribute aggregation
            "attr_aggregate": "list",  # "list" or "last"
            "listify_singletons": True,
            "max_list_values": 12,
            "prefer_order": "observed",  # "observed" or "sorted"
            # NumPy statistics
            "include_statistics": True,
            "percentiles": [5, 25, 50, 75, 95],
            "topk_categorical": 10,
            "min_count_for_stats": 2,
        }

    def _default_emit_sink(self, code: str, cfg: Dict[str, Any]) -> None:
        """
        Emit to file if configured; otherwise just log success.
        """
        from pathlib import Path
        from datetime import datetime

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        name = cfg.get("class_name", "Snapshot")
        with self._k_lock:
            self._emit_seq += 1
            template = self._emitter_cfg.to_file

        if template:
            path_str = None
            try:
                path_str = template.format(ts=ts, seq=self._emit_seq, name=name)
                p = Path(path_str)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(code, encoding="utf-8")
                self._log(f"[CodeOutput] 🧾 Wrote snapshot '{name}' to {p}", 1)
            except Exception as ex:
                loc = path_str or template
                self._log(f"[CodeOutput] ❌ Failed to write snapshot to {loc}: {ex}", 1)
                self._log(f"[CodeOutput] ✅ Fallback (no file) emit completed for '{name}'.", 1)
        else:
            self._log(f"[CodeOutput] ✅ Emit (no file sink) for '{name}' complete.", 1)

    # --------------------------- public bus API ---------------------------

    def submit_packet(self, packet: Any, inbound_iface: Optional[str] = None, **context) -> None:
        """Push ANY packet or event into the learning bus."""
        try:
            self._bus_queue.put_nowait({"_kind": "packet", "value": packet, "iface": inbound_iface, "ctx": context})
            self._log(
                f"[CodeOutput] ➡️ submit_packet type={type(packet).__name__} iface={inbound_iface} ctx_keys={list(context.keys())}",
                2)
        except Exception as e:
            self._log(f"[CodeOutput] ⚠️ submit_packet failed: {e}", 1)

    def submit_event(self, topic: str, attributes: Dict[str, Any] | None = None,
                     methods: Dict[str, Any] | None = None, ttl: Optional[float] = None,
                     source: Optional[str] = None, tags: Optional[List[str]] = None, importance: int = 0) -> None:
        """Directly submit a normalized knowledge event."""
        payload: Dict[str, Any] = {}
        if attributes:
            payload["attributes"] = dict(attributes)
        if methods:
            payload["methods"] = dict(methods)
        pkt = KnowledgePacket(
            topic=topic or "misc",
            payload=payload or {"attributes": {}},
            ttl=float(ttl if ttl is not None else self.DEFAULT_TTLS.get(topic or "misc", 120.0)),
            source=source,
            tags=list(tags or []),
            importance=int(importance),
        )
        try:
            self._bus_queue.put_nowait({"_kind": "packet", "value": pkt, "iface": None, "ctx": {}})
            self._log(
                f"[CodeOutput] ➡️ submit_event topic={topic} tags={tags} attrs={len((attributes or {}))} methods={len((methods or {}))}",
                2)
        except Exception as e:
            self._log(f"[CodeOutput] ⚠️ submit_event failed: {e}", 1)

    def attach_external_source(
            self,
            src_queue: "queue.Queue[Any]",
            transform: Optional[Callable[[Any], KnowledgePacket]] = None,
            name: str = "ExternalCodeOutputSource",
    ) -> None:
        """Consume packets from an external queue."""

        def _consume():
            self._log(f"[CodeOutput] 🔌 External source '{name}' consumer started.", 1)
            while not self._stop_event.is_set():
                try:
                    item = src_queue.get(timeout=1.0)
                    if item is None:
                        self._log(f"[CodeOutput] 🔌 External source '{name}' sentinel received; stopping.", 1)
                        break
                    if transform:
                        try:
                            pkt = transform(item)
                            self._bus_queue.put_nowait({"_kind": "packet", "value": pkt, "iface": None, "ctx": {}})
                            self._log(f"[CodeOutput] 🔌 '{name}' forwarded transformed item.", 2)
                        except Exception as ex:
                            self._log(f"[CodeOutput] ⚠️ External transform error: {ex}", 1)
                    else:
                        self._bus_queue.put_nowait({"_kind": "packet", "value": item, "iface": None, "ctx": {}})
                        self._log(f"[CodeOutput] 🔌 '{name}' forwarded raw item.", 2)
                except queue.Empty:
                    continue
                except Exception as e:
                    self._log(f"[CodeOutput] ❌ External source consumer error: {e}", 1)
                    break
            self._log(f"[CodeOutput] 🔌 External source '{name}' consumer stopped.", 1)

        t = threading.Thread(target=_consume, daemon=True, name=name)
        t.start()
        self._external_sources.append((src_queue, transform, t))
        self._log(f"[CodeOutput] Attached external source '{name}'.", 1)

    # --------------------------- configuration helpers ---------------------------

    def set_topic_aliases(self, aliases: Dict[str, Iterable[str]]) -> None:
        """Extend or override topic aliases at runtime."""
        self._custom_aliases = {k.lower(): set(map(lambda s: str(s).lower(), v)) for k, v in aliases.items()}
        self._log(f"[CodeOutput] Custom topic aliases updated: {list(self._custom_aliases.keys())}", 1)

    # --------------------------- generation API ---------------------------

    def queue_code_generation(self, config: Dict[str, Any]):
        """Adds a code generation request to the queue (async)."""
        if self._gen_thread and self._gen_thread.is_alive():
            self._generation_queue.put(config)
            self._log(f"[CodeOutput] 📬 Queued code generation for '{config.get('class_name', 'UnnamedClass')}'.", 2)
        else:
            self._log("[CodeOutput] ❌ Manager is not running. Cannot queue request.", 1)

    def _insights_for_topics(self, topics: Iterable[str]) -> Dict[str, List[Tuple[str, int]]]:
        sel = list(topics) if topics else list(self._concept_counts.keys())
        out: Dict[str, List[Tuple[str, int]]] = {}
        for t in sel:
            freq = self._concept_counts.get(t, {})
            if not freq:
                continue
            out[t] = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[: self._insights_max]
        return out

    def generate_class_from_config(self, config: Dict[str, Any]) -> str:
        """
        Build Python code for a class from config + merged transient knowledge.
        """
        class_name = config.get("class_name", "GeneratedClass")
        base_attrs: Dict[str, Any] = dict(config.get("attributes", {}))
        base_methods: Dict[str, Any] = dict(config.get("methods", {}))
        topics: List[str] = config.get("topics") or []
        attr_policy = (config.get("attr_policy") or "merge").lower()
        method_policy = (config.get("method_policy") or "merge").lower()
        include_insights = bool(config.get("include_insights", False))

        # Aggregation controls
        attr_aggregate = (config.get("attr_aggregate") or "last").lower()  # "list" or "last"
        listify_singletons = bool(config.get("listify_singletons", False))
        max_list_values = int(config.get("max_list_values", 12))
        prefer_order = (config.get("prefer_order") or "observed").lower()  # "observed" or "sorted"

        # Gather knowledge
        k_attrs, k_methods = (
            self._gather_knowledge_aggregate(topics, max_list_values, prefer_order)
            if attr_aggregate == "list"
            else self._gather_knowledge(topics)
        )

        # Merge attrs
        if attr_policy == "override":
            merged_attrs = (k_attrs or {}) or base_attrs
        else:
            merged_attrs = {**base_attrs, **(k_attrs or {})}

        # Optionally listify singletons
        if attr_aggregate == "list" and listify_singletons:
            for k, v in list(merged_attrs.items()):
                if not isinstance(v, list):
                    merged_attrs[k] = [v]

        # Merge methods
        if method_policy == "override":
            merged_methods = (k_methods or {}) or base_methods
        else:
            merged_methods = {**base_methods, **(k_methods or {})}

        # Insights
        if include_insights:
            insights = self._insights_for_topics(topics)
            if insights:
                merged_attrs["_insights"] = insights

        # ---------- NumPy statistics ----------
        if config.get("include_statistics", False):
            stats = self._compute_statistics_with_numpy(
                topics=topics,
                percentiles=list(config.get("percentiles", [5, 25, 50, 75, 95])),
                topk_categorical=int(config.get("topk_categorical", 10)),
                min_count_for_stats=int(config.get("min_count_for_stats", 2)),
            )
            if stats:
                merged_attrs["_statistics"] = stats

        # Inject helper methods into the snapshot
        merged_methods.update(self._default_snapshot_methods(stats))

        # Loud info
        self._log(
            f"[CodeOutput] 🧩 Generating class '{class_name}' topics={topics or 'ALL'} "
            f"attrs={len(merged_attrs)} methods={len(merged_methods)} "
            f"aggregate={attr_aggregate}", 1
        )

        doc = "A generated class."
        return MiniTemplateEngine.render_class(class_name, merged_attrs, merged_methods, doc=doc)

    # --------------------------- internal loops ---------------------------

    def _scapy_layers(self):
        """
        Robustly import Scapy layers with optional IPsec/TLS support.
        Returns a dict of layer classes (missing ones set to None).
        """
        try:
            from scapy.packet import Packet as ScapyPacket  # type: ignore
            from scapy.layers.l2 import Ether, ARP, Dot1Q  # type: ignore
            from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
            try:
                from scapy.layers.inet import GRE  # type: ignore
            except Exception:
                GRE = None
            try:
                from scapy.layers.inet6 import IPv6  # type: ignore
            except Exception:
                IPv6 = None
        except Exception as ex:
            self._log(f"[CodeOutput] 🟥 Scapy base imports failed: {ex}", 1)
            return None

        TLS = None
        try:
            from scapy.layers.tls.all import TLS as _TLS  # type: ignore
            TLS = _TLS
        except Exception:
            pass

        ESP = AH = None
        try:
            from scapy.layers.ipsec import ESP as _ESP, AH as _AH  # type: ignore
            ESP, AH = _ESP, _AH
        except Exception:
            try:
                from scapy.all import load_layer  # type: ignore
                load_layer("ipsec")
                from scapy.layers.ipsec import ESP as _ESP, AH as _AH  # type: ignore
                ESP, AH = _ESP, _AH
            except Exception as ex:
                if not self._ipsec_warned:
                    self._log(f"[CodeOutput] 🟨 IPsec layers not available (ESP/AH). "
                              f"Continuing without IPsec decode. Details: {ex}", 1)
                    self._ipsec_warned = True

        return {
            "Packet": ScapyPacket, "Ether": Ether, "ARP": ARP, "Dot1Q": Dot1Q,
            "IP": IP, "TCP": TCP, "UDP": UDP, "ICMP": ICMP, "IPv6": IPv6,
            "GRE": GRE, "ESP": ESP, "AH": AH, "TLS": TLS,
        }

    def _bus_consumer_loop(self):
        """Consumes items from the built-in bus, normalizes and stores knowledge."""
        self._log("[CodeOutput] ▶️ Bus consumer loop started.", 1)
        while not self._stop_event.is_set():
            try:
                item = self._bus_queue.get(timeout=1.0)
                if item is None or item.get("_kind") != "packet":
                    continue

                raw = item.get("value")
                iface = item.get("iface")
                ctx = item.get("ctx") or {}

                self._fire_hooks("pre_ingest", raw=raw, iface=iface, ctx=ctx)
                self._log(f"[CodeOutput] 📥 Ingesting type={type(raw).__name__} iface={iface}", 2)

                packets: List[KnowledgePacket] = []

                # TLSRecord (duck-typed)
                try:
                    if self._is_tls_record(raw):
                        packets = self._normalize_tls_record(raw)
                        self._log(f"[CodeOutput] 🔎 Normalized via TLSRecord path → {len(packets)} pkt(s).", 2)
                except Exception:
                    packets = []
                    self._log("[CodeOutput] ⚠️ TLSRecord normalization failed; will try other paths.", 1)

                # Scapy, then generic
                if not packets:
                    spkt = self._coerce_to_scapy_packet(raw)
                    if spkt is not None:
                        packets = self._maybe_summarize_scapy(spkt, inbound_iface=iface, ctx=ctx)
                        if packets:
                            self._log(f"[CodeOutput] 🔎 Normalized via Ether→Scapy path → {len(packets)} pkt(s).", 2)

                if not packets:
                    packets = self._normalize_any(raw)
                    if packets:
                        self._log(f"[CodeOutput] 🔎 Normalized via generic path → {len(packets)} pkt(s).", 2)

                if not packets:
                    self._log("[CodeOutput] 🚫 No packets produced from input.", 2)
                    continue

                with self._k_lock:
                    for pkt in packets:
                        if not pkt.topic or not isinstance(pkt.payload, dict):
                            self._stats.packets_dropped += 1
                            self._log(f"[CodeOutput] 🟥 Dropped packet (bad payload/topic).", 1)
                            continue
                        dq = self._knowledge_by_topic.setdefault(pkt.topic, deque(maxlen=self.MAX_PACKETS_PER_TOPIC))
                        dq.append(pkt)
                        self._stats.packets_ingested += 1
                        self._stats.by_topic[pkt.topic] += 1

                        # Learning hooks
                        self._learn_from_packet(pkt)
                        self._update_feature_stores(pkt)  # numeric + categorical

                    self._ingest_since_emit += len(packets)
                    self._log(f"[CodeOutput] 📈 IngCount+={len(packets)} total_since_emit={self._ingest_since_emit}", 2)

                self._fire_hooks("post_ingest", packets=packets)

            except queue.Empty:
                continue
            except Exception as e:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] ❌ Bus consumer error: {e}\n{traceback.format_exc()}", 1)

        self._log("[CodeOutput] ⏹️ Bus consumer loop stopped.", 1)

    def _generation_loop(self):
        """Processes code generation requests from the queue."""
        self._log("[CodeOutput] ▶️ Generation loop started.", 2)
        while not self._stop_event.is_set():
            try:
                config = self._generation_queue.get(timeout=1)
                if config is None:
                    continue
                cls_name = config.get("class_name", "UnnamedClass")
                self._log(f"[CodeOutput] 🛠️ Processing generation request for '{cls_name}'.", 1)
                code = self.generate_class_from_config(config)
                self._log(f"[CodeOutput] ✅ Generated class '{cls_name}' ({len(code)} bytes).", 1)
                self._generation_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] ❌ Error in generation loop: {e}\n{traceback.format_exc()}", 1)
        self._log("[CodeOutput] ⏹️ Generation loop stopped.", 2)

    def _cleanup_loop(self):
        """Periodically drops expired knowledge packets."""
        self._log("[CodeOutput] ▶️ Cleanup loop started.", 2)
        while not self._stop_event.is_set():
            try:
                now = time.time()
                with self._k_lock:
                    for topic, dq in list(self._knowledge_by_topic.items()):
                        removed = 0
                        # pop left while expired
                        while dq and dq[0].is_expired(now):
                            dq.popleft()
                            removed += 1
                        if not dq:
                            self._knowledge_by_topic.pop(topic, None)
                        if removed:
                            self._log(f"[CodeOutput] 🧹 Purged {removed} expired packets from '{topic}'.", 1)
            except Exception as e:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] ❌ Cleanup error: {e}\n{traceback.format_exc()}", 1)
            finally:
                self._stop_event.wait(self.CLEANUP_INTERVAL_S)
        self._log("[CodeOutput] ⏹️ Cleanup loop stopped.", 2)

    # --------------------------- knowledge merge ---------------------------

    def _gather_knowledge(self, topics: Iterable[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Last-wins merge across packets for selected topics.
        """
        now = time.time()
        attrs: Dict[str, Any] = {}
        methods: Dict[str, Any] = {}

        with self._k_lock:
            topic_list = list(topics) if topics else list(self._knowledge_by_topic.keys())
            for topic in topic_list:
                dq = self._knowledge_by_topic.get(topic)
                if not dq:
                    continue
                for pkt in dq:
                    if pkt.is_expired(now):
                        continue
                    p = pkt.payload or {}
                    if isinstance(p.get("attributes"), dict):
                        attrs.update(p["attributes"])
                    if isinstance(p.get("methods"), dict):
                        methods.update(p["methods"])
        self._log(
            f"[CodeOutput] 📦 Gathered (last-wins) topics={topic_list} → attrs={len(attrs)} methods={len(methods)}", 2)
        return attrs, methods

    def _gather_knowledge_aggregate(self,
                                    topics: Iterable[str],
                                    max_per_attr: int = 12,
                                    prefer_order: str = "observed") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Aggregate attributes into lists of unique values across packets.
        """
        now = time.time()
        agg: Dict[str, List[Any]] = defaultdict(list)
        methods: Dict[str, Any] = {}

        def _maybe_add(k, v):
            if v is None:
                return
            lst = agg[k]
            if v not in lst:
                lst.append(v)
                if len(lst) > max_per_attr:
                    del lst[0:len(lst) - max_per_attr]  # keep most recent N

        with self._k_lock:
            topic_list = list(topics) if topics else list(self._knowledge_by_topic.keys())
            for topic in topic_list:
                dq = self._knowledge_by_topic.get(topic)
                if not dq:
                    continue
                for pkt in dq:
                    if pkt.is_expired(now):
                        continue
                    p = pkt.payload or {}
                    if isinstance(p.get("attributes"), dict):
                        for k, v in p["attributes"].items():
                            _maybe_add(k, v)
                    if isinstance(p.get("methods"), dict):
                        methods.update(p["methods"])

        if prefer_order == "sorted":
            for k, lst in agg.items():
                try:
                    lst.sort(key=lambda x: str(x))
                except Exception:
                    pass

        self._log(
            f"[CodeOutput] 📦 Gathered (aggregate) topics={topic_list} → attrs={len(agg)} (lists) methods={len(methods)}",
            2)
        return dict(agg), methods

    # --------------------------- ANY-packet normalization ---------------------------

    def _try_decode_ether_bytes(self, b: bytes) -> List[KnowledgePacket]:
        """Decode raw Ethernet frame bytes using scapy (if available)."""
        try:
            from scapy.layers.l2 import Ether
            frame = Ether(b)
            return self._maybe_summarize_scapy(frame, inbound_iface=None, ctx={}) if frame else []
        except Exception:
            return []

    def _is_tls_record(self, obj: Any) -> bool:
        """
        Duck-typing check for a TLSRecord-like object without importing its class.
        Required attributes:
          content_type, version(tuple), length, payload(bytes),
          ts, src, dst, src_port, dst_port, direction
        """
        fields = ("content_type", "version", "length", "payload",
                  "ts", "src", "dst", "src_port", "dst_port", "direction")
        return all(hasattr(obj, f) for f in fields)

    def _normalize_tls_record(self, rec: Any) -> List[KnowledgePacket]:
        """Summarize a TLSRecord into a KnowledgePacket (topic='tls')."""
        try:
            vmaj, vmin = rec.version
        except Exception:
            vmaj, vmin = (None, None)

        attrs: Dict[str, Any] = {
            "content_type": getattr(rec, "content_type", None),
            "version": f"{vmaj}.{vmin}" if vmaj is not None else None,
            "version_tuple": (int(vmaj), int(vmin)) if vmaj is not None else None,
            "length": int(getattr(rec, "length", 0) or 0),
            "direction": str(getattr(rec, "direction", "")),
            "ts": float(getattr(rec, "ts", time.time())),
            "src": str(getattr(rec, "src", "")),
            "dst": str(getattr(rec, "dst", "")),
            "sport": int(getattr(rec, "src_port", 0) or 0),
            "dport": int(getattr(rec, "dst_port", 0) or 0),
        }

        try:
            payload = getattr(rec, "payload", b"") or b""
            if isinstance(payload, (bytes, bytearray)):
                payload = bytes(payload)
                if attrs["content_type"] == 22 and len(payload) >= 1:  # Handshake
                    attrs["hs_type"] = payload[0]
                    attrs["hs_type_name"] = self.TLS_HANDSHAKE_TYPES.get(payload[0], f"Type{payload[0]}")
                    if len(payload) >= 4:
                        attrs["hs_len"] = int.from_bytes(payload[1:4], "big")
                elif attrs["content_type"] == 21 and len(payload) >= 2:  # Alert
                    attrs["alert_level"] = payload[0]
                    attrs["alert_desc"] = payload[1]
                elif attrs["content_type"] == 23:
                    attrs["app_len"] = attrs["length"]
        except Exception:
            pass

        pkt = KnowledgePacket(
            topic="tls",
            payload={"attributes": attrs},
            ttl=self.DEFAULT_TTLS.get("tls", 300.0),
            source="bus/tlsrecord",
            tags=["TLSRecord", f"ct={attrs.get('content_type')}"]
        )
        return [self._finalize_packet(pkt)]

    def _normalize_any(self, obj: Any) -> List[KnowledgePacket]:
        # TLSRecord (duck-typed) first
        try:
            if self._is_tls_record(obj):
                return self._normalize_tls_record(obj)
        except Exception:
            pass

        # Try Scapy packet coercion
        spkt = self._coerce_to_scapy_packet(obj)
        if spkt is not None:
            return self._maybe_summarize_scapy(spkt, inbound_iface=None, ctx={}) or []

        # KnowledgePacket direct
        if isinstance(obj, KnowledgePacket):
            return [self._finalize_packet(obj)]

        # List / tuple
        if isinstance(obj, (list, tuple)):
            out: List[KnowledgePacket] = []
            for item in obj:
                out.extend(self._normalize_any(item))
            return out

        # Dict
        if isinstance(obj, dict):
            return self._normalize_dict(obj)

        # Bytes/bytearray
        if isinstance(obj, (bytes, bytearray)):
            b = bytes(obj)
            stripped = b.lstrip()
            if stripped.startswith((b'{', b'[')):
                try:
                    return self._normalize_any(json.loads(stripped.decode("utf-8", "ignore")))
                except Exception:
                    pass
            ether_pkts = self._try_decode_ether_bytes(b)
            if ether_pkts:
                return ether_pkts
            try:
                text = b.decode("utf-8", "ignore").strip()
                return self._normalize_tagged_line(text) if text else []
            except Exception:
                return []

        # Str
        if isinstance(obj, str):
            text = obj.strip()
            if not text:
                return []
            # Try JSON/NDJSON
            pkts = self._try_parse_ndjson(text)
            return pkts if pkts else self._normalize_tagged_line(text)

        # Custom object -> shallow snapshot
        try:
            if hasattr(obj, "__dict__"):
                return self._normalize_dict(vars(obj))
        except Exception:
            pass

        self._log(f"[CodeOutput] ⚠️ Unsupported packet type: {type(obj)}", 1)
        return []

    def _normalize_dict(self, d: Dict[str, Any]) -> List[KnowledgePacket]:
        if "topic" in d and isinstance(d.get("payload"), dict):
            topic = str(d.get("topic") or "misc").lower()
            return [self._finalize_packet(KnowledgePacket(
                topic=topic,
                payload=self._extract_payload(d.get("payload") or {}),
                ttl=float(d.get("ttl", self.DEFAULT_TTLS.get(topic, 120.0))),
                source=d.get("source"),
                tags=list(d.get("tags") or []),
                importance=int(d.get("importance", 0)),
            ))]

        topic = self._detect_topic_from_dict(d)
        payload = self._extract_payload_from_unknown(d)
        return [self._finalize_packet(
            KnowledgePacket(topic=topic, payload=payload, ttl=self.DEFAULT_TTLS.get(topic, 120.0)))]

    def _try_parse_ndjson(self, text: str) -> List[KnowledgePacket]:
        if text.startswith(('{', '[')):
            try:
                return self._normalize_any(json.loads(text))
            except json.JSONDecodeError:
                pass
        packets = []
        parsed_any = False
        for ln in self.NDJSON_SPLIT_RE.split(text):
            s = ln.strip()
            if s.startswith(('{', '[')):
                try:
                    packets.extend(self._normalize_any(json.loads(s)))
                    parsed_any = True
                except json.JSONDecodeError:
                    continue
        return packets if parsed_any else []

    def _normalize_tagged_line(self, text: str) -> List[KnowledgePacket]:
        tags = [m.group(1).strip() for m in self.BRACKET_TAG_RE.finditer(text)]
        tag_topic = tags[0].lower() if tags else None
        topic = self._map_alias_to_topic(tag_topic) if tag_topic else self._detect_topic_from_text(text)
        kv = {k: v.strip("\"'") for k, v in self.KV_TOKEN_RE.findall(text)}
        message = self.BRACKET_TAG_RE.sub("", text).strip()
        payload = {"attributes": {"message": message, **kv}}
        return [self._finalize_packet(
            KnowledgePacket(topic=topic, payload=payload, ttl=self.DEFAULT_TTLS.get(topic, 120.0), tags=tags))]

    # --------------------------- topic detection & payload extraction ---------------------------

    def _map_alias_to_topic(self, alias: Optional[str]) -> str:
        if not alias:
            return "misc"
        a = alias.lower().strip()
        for store in (self._custom_aliases, self.TOPIC_ALIASES):
            for canonical, alset in store.items():
                if a == canonical or a in alset:
                    return canonical
        for canonical in set(self.TOPIC_ALIASES.keys()) | set(self._custom_aliases.keys()):
            if canonical in a:
                return canonical
        return "misc"

    def _detect_topic_from_text(self, text: str) -> str:
        low = text.lower()
        for store in (self._custom_aliases, self.TOPIC_ALIASES):
            for canonical, alset in store.items():
                if canonical in low or any(kw in low for kw in alset):
                    return canonical
        return "misc"

    def _detect_topic_from_dict(self, d: Dict[str, Any]) -> str:
        for key in ("topic", "protocol", "proto", "layer", "service", "kind", "type", "component"):
            if isinstance(d.get(key), str):
                return self._map_alias_to_topic(d[key])
        try:
            for p_val in (d.get("dport"), d.get("sport")):
                if p_val and p_val in self.PORT_TOPIC_HINTS:
                    return self.PORT_TOPIC_HINTS[p_val]
        except Exception:
            pass
        joined = " ".join(map(str, d.keys())) + " " + " ".join(str(v)[:80] for v in d.values())
        return self._detect_topic_from_text(joined)

    def _extract_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if "attributes" in payload or "methods" in payload:
            return payload
        attrs, methods = {}, {}
        for k, v in payload.items():
            if k in ("code", "body", "function", "method") and isinstance(v, str):
                methods[f"{k}_snippet"] = {"body": v}
            elif isinstance(v, (str, int, float, bool)):
                attrs[k] = v
            elif isinstance(v, dict):
                for kk, vv in v.items():
                    if isinstance(vv, (str, int, float, bool)):
                        attrs[kk] = vv
        out = {}
        if attrs:
            out["attributes"] = attrs
        if methods:
            out["methods"] = methods
        return out or {"attributes": dict(payload)}

    def _extract_payload_from_unknown(self, d: Dict[str, Any]) -> Dict[str, Any]:
        attrs, methods = {}, {}
        for k, v in d.items():
            if k in (
            "src", "dst", "saddr", "daddr", "sport", "dport", "proto", "protocol", "ttl", "length") and isinstance(v, (
            str, int, float, bool)):
                attrs[k] = v
            elif k in ("code", "body") and isinstance(v, str):
                methods[f"{k}_snippet"] = {"body": v}
        payload = {}
        if attrs:
            payload["attributes"] = attrs
        if methods:
            payload["methods"] = methods
        return payload or {"attributes": {k: v for k, v in d.items() if isinstance(v, (str, int, float, bool))}}

    def _finalize_packet(self, pkt: KnowledgePacket) -> KnowledgePacket:
        if not pkt.ttl or pkt.ttl <= 0:
            pkt.ttl = self.DEFAULT_TTLS.get(pkt.topic, 120.0)
        if not pkt.payload:
            pkt.payload = {"attributes": {}}
        return pkt

    # --------------------------- scapy summarization (optional) ---------------------------

    def _maybe_summarize_scapy(self, raw: Any, inbound_iface: Optional[str], ctx: Dict[str, Any]) -> List[
        KnowledgePacket]:
        # Coerce anything Ether-ish to a Scapy Packet first
        pkt = self._coerce_to_scapy_packet(raw)
        if pkt is None:
            return []

        layers = self._scapy_layers()
        if not layers:
            return []

        ScapyPacket = layers["Packet"]
        Ether = layers["Ether"];
        ARP = layers["ARP"];
        Dot1Q = layers["Dot1Q"]
        IP = layers["IP"];
        TCP = layers["TCP"];
        UDP = layers["UDP"];
        ICMP = layers["ICMP"]
        IPv6 = layers["IPv6"];
        GRE = layers["GRE"];
        ESP = layers["ESP"];
        AH = layers["AH"];
        TLS = layers["TLS"]

        if not isinstance(pkt, ScapyPacket):
            self._log(f"[CodeOutput] 🟥 Coerced object is not a Scapy Packet instance.", 1)
            return []

        raw = pkt
        a: Dict[str, Any] = {}
        topic = "router"

        if Ether and raw.haslayer(Ether):
            eth = raw[Ether]
            a.update(eth_src=getattr(eth, "src", None),
                     eth_dst=getattr(eth, "dst", None),
                     eth_type=getattr(eth, "type", None))
        if Dot1Q and raw.haslayer(Dot1Q):
            a.update(vlan=raw[Dot1Q].vlan, vlan_prio=raw[Dot1Q].prio)

        ipL = (IP and raw.getlayer(IP)) or (IPv6 and raw.getlayer(IPv6))
        if ipL:
            a.update(saddr=getattr(ipL, "src", None),
                     daddr=getattr(ipL, "dst", None),
                     ttl=getattr(ipL, "ttl", getattr(ipL, "hlim", None)))

        if TCP and raw.haslayer(TCP):
            topic = self.PORT_TOPIC_HINTS.get(raw[TCP].dport, self.PORT_TOPIC_HINTS.get(raw[TCP].sport, "transport"))
            if TLS and raw.haslayer(TLS):
                topic = "tls"
            a.update(proto="TCP", sport=raw[TCP].sport, dport=raw[TCP].dport)
        elif UDP and raw.haslayer(UDP):
            topic = self.PORT_TOPIC_HINTS.get(raw[UDP].dport, self.PORT_TOPIC_HINTS.get(raw[UDP].sport, "transport"))
            if 5353 in (raw[UDP].sport, raw[UDP].dport):
                a["mdns"] = True
            a.update(proto="UDP", sport=raw[UDP].sport, dport=raw[UDP].dport)
        elif ICMP and raw.haslayer(ICMP):
            topic = "transport"
            a["proto"] = "ICMP"
            try:
                a["icmp_type"] = raw[ICMP].type
            except Exception:
                pass
        elif ARP and raw.haslayer(ARP):
            topic = "arp"
            a["proto"] = "ARP"
            a.update(arp_op=raw[ARP].op, arp_psrc=raw[ARP].psrc, arp_pdst=raw[ARP].pdst)
        else:
            a["proto"] = "L2" if (Ether and raw.haslayer(Ether)) else "misc"

        # IPsec support (ESP/AH)
        ipsec_hit = False
        if ESP and raw.haslayer(ESP):
            ipsec_hit = True
            try:
                esp = raw[ESP]
                a["esp_spi"] = getattr(esp, "spi", None)
                a["esp_seq"] = getattr(esp, "seq", None)
            except Exception:
                pass
        if AH and raw.haslayer(AH):
            ipsec_hit = True
            try:
                ah = raw[AH]
                a["ah_spi"] = getattr(ah, "spi", None)
                a["ah_seq"] = getattr(ah, "seq", None)
            except Exception:
                pass
        if ipsec_hit:
            a["ipsec"] = True
            topic = "vpn"

        # GRE check (optional)
        if GRE and raw.haslayer(GRE):
            a["gre_like"] = True
            topic = "vpn"

        if inbound_iface:
            a["iface_in"] = inbound_iface
        a.update(ctx or {})
        try:
            a["summary"] = raw.summary()
        except Exception:
            pass

        return [self._finalize_packet(KnowledgePacket(
            topic=topic, payload={"attributes": a},
            ttl=self.DEFAULT_TTLS.get(topic, 120.0), source="bus/scapy"
        ))]

    # --------------------------- adaptive learning ---------------------------

    def _learn_from_packet(self, pkt: KnowledgePacket) -> None:
        """
        Tokenize attribute keys & string values to capture frequent concepts per topic.
        """
        attrs = (pkt.payload or {}).get("attributes", {})
        tokens: List[str] = []
        for k, v in attrs.items():
            tokens.extend(self._tokenize(str(k)))
            if isinstance(v, str) and v:
                tokens.extend(self._tokenize(v))
        if not tokens:
            return

        cc = self._concept_counts[pkt.topic]
        for t in tokens:
            cc[t] = int(cc.get(t, 0)) + 1

        dominant = max(cc.values()) if cc else 0
        if dominant >= self._ttl_boost_threshold and pkt.ttl < self.DEFAULT_TTLS.get(pkt.topic,
                                                                                     120.0) * self._ttl_boost_factor:
            old = pkt.ttl
            pkt.ttl = min(self.DEFAULT_TTLS.get(pkt.topic, 120.0) * self._ttl_boost_factor,
                          old * self._ttl_boost_factor)
            self._log(f"[CodeOutput] ⏫ TTL boosted for topic='{pkt.topic}' ({old:.1f} -> {pkt.ttl:.1f}).", 2)

    def _tokenize(self, s: str) -> List[str]:
        return [t for t in self.TOKEN_SPLIT_RE.split(s.lower()) if t and not t.isdigit()]

    # --------------------------- NumPy snapshot learning ---------------------------

    def _update_feature_stores(self, pkt: KnowledgePacket) -> None:
        """Extract numeric & categorical features for later NumPy analysis."""
        attrs = (pkt.payload or {}).get("attributes", {})
        if not attrs:
            return
        topic = pkt.topic

        # Numeric features -> lists of floats
        for k, v in attrs.items():
            if isinstance(v, (int, float)):
                arr = self._num_vectors[topic][k]
                arr.append(float(v))
                # Cap the list length
                if len(arr) > self._per_feature_cap:
                    del arr[0:len(arr) - self._per_feature_cap]
            # Categorical features -> counters
            elif isinstance(v, (str, bool)):
                self._cat_counters[topic][k][v] += 1

    def _compute_statistics_with_numpy(
            self,
            topics: Iterable[str],
            percentiles: List[int],
            topk_categorical: int,
            min_count_for_stats: int,
    ) -> Dict[str, Any]:
        """
        Build a dictionary with numeric & categorical statistics per topic.

        Numeric per feature:
            mean, std, min, max, median, count, percentiles{p:value}

        Categorical per feature:
            unique_count, top_k: [(value, count), ...]
        """
        stats: Dict[str, Any] = {}
        with self._k_lock:
            topic_list = list(topics) if topics else list(
                set(self._num_vectors.keys()) | set(self._cat_counters.keys()))
            for topic in topic_list:
                tnum = self._num_vectors.get(topic, {})
                tcat = self._cat_counters.get(topic, {})

                topic_stats: Dict[str, Any] = {}

                # Numeric features
                num_stats: Dict[str, Any] = {}
                for feat, values in tnum.items():
                    if len(values) < min_count_for_stats:
                        continue
                    vec = np.asarray(values, dtype=float)
                    valid = vec[~np.isnan(vec)]
                    if valid.size < min_count_for_stats:
                        continue
                    entry = {
                        "count": int(valid.size),
                        "mean": float(np.mean(valid)),
                        "std": float(np.std(valid)),
                        "min": float(np.min(valid)),
                        "max": float(np.max(valid)),
                        "median": float(np.median(valid)),
                        "percentiles": {int(p): float(np.percentile(valid, p)) for p in percentiles},
                    }
                    num_stats[feat] = entry
                if num_stats:
                    topic_stats["numeric"] = num_stats

                # Categorical features
                cat_stats: Dict[str, Any] = {}
                for feat, counter in tcat.items():
                    if not counter:
                        continue
                    total = sum(counter.values())
                    top = counter.most_common(topk_categorical)
                    entry = {
                        "unique_count": int(len(counter)),
                        "total_count": int(total),
                        "top_k": [(val, int(cnt)) for val, cnt in top],
                    }
                    cat_stats[feat] = entry
                if cat_stats:
                    topic_stats["categorical"] = cat_stats

                if topic_stats:
                    stats[topic] = topic_stats

        return stats

    # --------------------------- utilities ---------------------------

    def get_stats(self) -> Dict[str, Any]:
        with self._k_lock:
            snap = self._stats.snapshot()
        self._log(f"[CodeOutput] 📊 Stats: {snap}", 1)
        return snap

    def export_knowledge(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Export non-expired packets grouped by topic (attributes only, compact).
        """
        now = time.time()
        out: Dict[str, List[Dict[str, Any]]] = {}
        with self._k_lock:
            for topic, dq in self._knowledge_by_topic.items():
                arr: List[Dict[str, Any]] = []
                for pkt in dq:
                    if pkt.is_expired(now):
                        continue
                    attrs = (pkt.payload or {}).get("attributes", {})
                    arr.append({"ts": pkt.ts, "source": pkt.source, "tags": pkt.tags, **attrs})
                if arr:
                    out[topic] = arr
        self._log(f"[CodeOutput] 📤 Exported knowledge topics={list(out.keys())}", 1)
        return out

    def purge_topic(self, topic: str) -> int:
        """Remove all packets for a topic. Returns number removed. Also clears feature stores."""
        with self._k_lock:
            dq = self._knowledge_by_topic.pop(topic, None)
            self._num_vectors.pop(topic, None)
            self._cat_counters.pop(topic, None)
        n = len(dq or ())
        self._log(f"[CodeOutput] 🗑️ Purged topic '{topic}' count={n}", 1)
        return n

    def _coerce_to_packet(self, obj: Union[KnowledgePacket, Dict[str, Any], bytes, str]) -> Optional[KnowledgePacket]:
        packets = self._normalize_any(obj)
        return packets[0] if packets else None

    def _coerce_to_scapy_packet(self, raw: Any):
        """
        Try to view 'raw' as a Scapy Packet:
          1) already a Packet instance → return it
          2) class (e.g., Ether) → warn & give up
          3) Ether-like object → derive bytes and parse with Ether(...)
        """
        try:
            from scapy.packet import Packet as _ScapyPacket  # type: ignore
            if isinstance(raw, _ScapyPacket):
                return raw
        except Exception:
            pass

        if inspect.isclass(raw):
            self._log(f"[CodeOutput] 🟨 Got a Packet CLASS '{getattr(raw, '__name__', raw)}' – expected an instance.", 1)
            return None

        def _as_bytes(obj):
            for attr in ("original", "raw", "raw_packet", "packet", "data"):
                try:
                    v = getattr(obj, attr, None)
                    if isinstance(v, (bytes, bytearray, memoryview)):
                        return bytes(v)
                except Exception:
                    pass
            for meth in ("to_bytes", "tobytes", "get_raw_packet", "pack", "build"):
                try:
                    fn = getattr(obj, meth, None)
                    if callable(fn):
                        b = fn()
                        if isinstance(b, (bytes, bytearray, memoryview)):
                            return bytes(b)
                except Exception:
                    pass
            try:
                return bytes(obj)
            except Exception:
                return None

        b = _as_bytes(raw)
        if not b:
            self._log(f"[CodeOutput] 🟥 Could not coerce {type(raw).__name__} to bytes for Scapy parse.", 1)
            return None

        try:
            from scapy.layers.l2 import Ether  # type: ignore
            return Ether(b)
        except Exception as ex:
            self._log(f"[CodeOutput] 🟥 Scapy Ether(...) parse failed: {ex}", 1)
            return None

    # --------------------------- TLSRecordManager wiring ---------------------------

    def register_tls_manager(self, tls_mgr: Any) -> Callable[[], None]:
        """
        Wire a TLSRecordManager to this CodeOutputManager.
        Returns a detach() callable to restore previous callbacks.
        """
        detach = wire_tls_to_code_output(tls_mgr, self)
        self._log("[CodeOutput] 🔗 TLSRecordManager wired into CodeOutputManager.", 1)
        return detach

    # --------------------------- snapshot helper methods ---------------------------

    def _default_snapshot_methods(self, stats) -> Dict[str, Any]:
        """
        Generates methods with dynamic, multi-line Python code bodies.

        This creates more powerful, self-contained methods that can perform
        logic like filtering or selecting specific metrics, rather than just
        proxying a call to another helper.
        """
        methods = {}
        for topic, kinds in stats.items():
            for kind, features in kinds.items():
                for feature in features.keys():
                    # Sanitize names for valid Python method syntax
                    safe_topic = re.sub(r'[^a-zA-Z0-9_]', '', topic)
                    safe_feature = re.sub(r'[^a-zA-Z0-9_]', '', feature)

                    # --- Generate Dynamic Code for NUMERIC Features ---
                    if kind == 'numeric':
                        m_name = f"get_{safe_topic}_{safe_feature}_stats"

                        # This is a string containing the actual Python code for the method body.
                        body = f"""
        metric = kwargs.get('metric')
        stats = self.stat(topic='{topic}', feature='{feature}', kind='numeric') or {{}}
        if not metric:
            return stats
        # Return a specific metric like 'mean', 'std', 'median', etc.
        return stats.get(metric)
        """
                        docstring = f"""
        Provides numeric statistics for the '{feature}' feature in topic '{topic}'.

        Args:
            metric (str, optional): If provided, returns only the value for this
                specific metric (e.g., 'mean', 'std', 'median').
                Defaults to returning the entire statistics dictionary.

        Returns:
            dict or float: The full stats dictionary or a single numeric value.
        """
                        methods[m_name] = {"body": body.strip(), "doc": docstring.strip()}

                    # --- Generate Dynamic Code for CATEGORICAL Features ---
                    elif kind == 'categorical':
                        m_name = f"get_{safe_topic}_{safe_feature}_top_values"

                        # This generated code can either return the full list of top
                        # values or the specific count for a requested value.
                        body = f"""
        value = kwargs.get('value')
        top_list = self.top_values(topic='{topic}', feature='{feature}') or []
        if not value:
            return top_list
        # If a specific value is requested, find its count in the list.
        return dict(top_list).get(value, 0)
        """
                        docstring = f"""
        Provides top categorical values for the '{feature}' feature in topic '{topic}'.

        Args:
            value (str, optional): If provided, returns the count for this specific
                value instead of the whole list. Defaults to 0 if not found.

        Returns:
            list or int: A list of (value, count) tuples, or a single integer count.
        """
                        methods[m_name] = {"body": body.strip(), "doc": docstring.strip()}

        return methods


def wire_tls_to_code_output(tls_mgr: Any, co_mgr: CodeOutputManager) -> Callable[[], None]:
    """
    Connect a TLSRecordManager instance to a CodeOutputManager.

    - Forwards every TLSRecord via submit_packet (recognized by duck-typing).
    - Pushes richer handshake/server info and policy decisions as 'tls' events.

    Returns:
        detach(): call to undo the wiring and restore previous callbacks.
    """
    prev_on_record = getattr(tls_mgr, "on_record", None) or (lambda rec: None)

    def _on_record(rec):
        try:
            co_mgr.submit_packet(rec)  # handled by _normalize_tls_record
        finally:
            try:
                prev_on_record(rec)
            except Exception:
                pass

    tls_mgr.on_record = _on_record

    prev_on_event = getattr(tls_mgr, "on_event", None)

    def _on_event(evt: dict):
        kind = (evt or {}).get("kind", "")
        data = (evt or {}).get("data") or {}
        flow = (evt or {}).get("flow")
        base_attrs = {"flow": str(flow)} if flow is not None else {}

        attrs: Dict[str, Any] = {"event": kind, **base_attrs}
        for key in ("sni", "alpn", "ja3", "ja3_md5", "ja3s", "ja3s_md5",
                    "version", "version_tuple", "cipher_suite", "cipher_suite_int", "extensions"):
            if key in data:
                attrs[key] = data[key]

        info = data.get("info") or {}
        msgs = info.get("messages") or []
        if msgs:
            for k in ("sni", "alpn", "ja3", "ja3_md5", "version", "version_tuple",
                      "cipher_suite", "cipher_suite_int", "extensions"):
                if k in msgs[0] and msgs[0][k]:
                    attrs[k] = msgs[0][k]

        if kind == "alert" and "alert" in data:
            alert = data.get("alert") or {}
            attrs.update({f"alert_{k}": v for k, v in alert.items()})

        co_mgr.submit_event("tls", attributes=attrs, tags=[kind] if kind else [])

        if callable(prev_on_event):
            try:
                prev_on_event(evt)
            except Exception:
                pass

    tls_mgr.on_event = _on_event

    prev_on_decision = getattr(tls_mgr, "on_decision", None)

    def _on_decision(flow_key, rec, decision):
        attrs = {
            "flow": str(flow_key),
            "decision": getattr(decision, "action", None),
            "reason": getattr(decision, "reason", ""),
            "tags": getattr(decision, "tags", []),
            "ct": getattr(rec, "content_type", None),
            "sport": getattr(rec, "src_port", None),
            "dport": getattr(rec, "dst_port", None),
        }
        tag = getattr(decision, "action", "decision")
        co_mgr.submit_event("tls", attributes=attrs, tags=["policy", tag])

        if callable(prev_on_decision):
            try:
                prev_on_decision(flow_key, rec, decision)
            except Exception:
                pass

    tls_mgr.on_decision = _on_decision

    def detach():
        try:
            tls_mgr.on_record = prev_on_record
            tls_mgr.on_event = prev_on_event
            tls_mgr.on_decision = prev_on_decision
        except Exception:
            pass

    return detach


