import collections
import inspect
import json
import math
import os
import queue
import random
import threading
import time
import re
import traceback
from collections import deque, defaultdict, Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Union, Tuple, Mapping, Iterator, Sequence, \
    DefaultDict

# NumPy for analysis (only used during analysis; raw values stay as Python lists)
import numpy as np
import tiktoken
from scapy.packet import Raw


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

        self._chat_mode = True
        self._chat_history: Deque[Dict[str, Any]] = deque(maxlen=200)  # rolling memory
        self._chat_ttl_s = 600.0  # chat turns stick around for 10 minutes
        self._max_context_snippets = 6  # retrieval budget
        self._chat_persona = "crisp, technical, friendly"  # style hint

        # Seed a small starter so Markov text won’t be empty at first
        self._chat_seed_corpus = [
            "acknowledged","noted","let us inspect the observed attributes","computing statistics","deriving insight","analyzing traffic snapshot",
            "parsing headers","validating checksums","normalizing fields","estimating baselines","detecting anomalies","flagging outliers","correlating sessions","mapping flows",
            "tracking latencies","sampling payloads","applying heuristics","scoring risk","summarizing evidence","cross-referencing indicators","triaging alerts","escalating incident",
            "probing endpoints","queuing retries","caching results","rotating logs",
            "rotating keys","syncing state","reconciling counters","replaying capture",
            "learning patterns","auto-tuning thresholds","estimating entropy","hashing fingerprints","classifying protocols",
            "labeling streams","reassembling fragments",
            "decoding asn.1","decoding gss-api",
            "decoding kerberos","validating tickets","tracking nonces","checking replay","measuring jitter","accounting bandwidth","dropping malformed","quarantining sources",
            "whitelisting peers", "blacklisting hosts","closing sockets","opening circuit","backing off","resuming flow",
            "writing pcap","emitting metrics","updating dashboard","acknowledging event","compiling signature","testing hypothesis",
            "verifying fix","rolling update","committing change","synchronizing clocks","aligning windows","applying policy","enforcing rules",
        ]
        self.ask_manager = AskManager(rng_seed=9999)
        self.chatgen = ChatGenManager(
            ask_manager=self.ask_manager,
            format_kv=lambda attrs, limit=8: self._format_kv(attrs, limit=8),
            history_getter=lambda: self._chat_history,
            persona=self._chat_persona,
            seed_corpus=self._chat_seed_corpus,
            max_chars=250,
        )

        self.packet_learner = PacketLearnerManager(
            keep_raw_samples=True, log_level=2
        )

        self.method_generator = SnapshotMethodGenerator()
        self.stats_manager = StatisticsManager()
        self.snapshot_builder = SnapshotBuilder(logger=self._log, ask_manager=self.ask_manager, rng_seed=2342)

        self.log_message("[CodeOutput] Manager initialized (drop-in, protocol-agnostic, NumPy stats ready).")

    def ask(self, prompt: str) -> str:
        return self.ask_manager.ask(prompt)
    # ---------- Chatbot core ----------

    def _chat_now(self) -> float:
        return time.time()

    def _expire_chat_history(self) -> None:
        now = self._chat_now()
        while self._chat_history and now - self._chat_history[0]["ts"] > self._chat_ttl_s:
            self._chat_history.popleft()

    def _infer_intent(self, text: str) -> str:
        """
        Trivial, fast intent labeling:
          - 'gen' => needs generative explanation
          - 'stats' => wants numbers/stats
          - 'emit' => wants a snapshot
          - 'purge' => wants to forget
          - 'inspect' => wants current knowledge
        """
        t = text.lower()
        if any(k in t for k in ("emit class", "generate class", "snapshot", "emit code")):
            return "emit"
        if any(k in t for k in ("stats", "statistics", "percentile", "z-score", "mean", "median")):
            return "stats"
        if any(k in t for k in ("forget", "purge", "clear", "erase")):
            return "purge"
        if any(k in t for k in ("what do you know", "show knowledge", "dump", "inspect", "list topics")):
            return "inspect"
        return "gen"

    def ask_file_cleartext(self, filepath: str, *, encoding: str = "utf-8",
                           sensitive: bool = True, do_stats: bool = False) -> str:
        """
        Read a file as cleartext, feed it to the chatbot, then run inspect (and optional stats).
        Returns a compact, log-friendly summary string.

        Usage (inside auto-emit loop or anywhere):
            s = self.ask_file_cleartext("/path/to/file.py", sensitive=True, do_stats=False)
            self._log(f"[CodeOutput] 🔁 {s}", 1)
        """
        try:
            with open(filepath, "r", encoding=encoding, errors="replace") as f:
                text = f.read()
        except Exception as ex:
            return f"ask_file_cleartext: failed to read '{filepath}': {ex}"

        # 1) Feed the raw file content
        try:
            r_ingest = self.ask_manager.ask(text)
        except Exception as ex:
            return f"ask_file_cleartext: ask(ingest) error: {ex}"

        # 2) Inspect (redacted vs sensitive)
        try:
            inspect_cmd = "inspect sensitive" if sensitive else "inspect"
            r_inspect = self.ask_manager.ask(inspect_cmd)
        except Exception as ex:
            return f"ask_file_cleartext: ask({inspect_cmd}) error: {ex}"

        # 3) Optional stats
        r_stats = None
        if do_stats:
            try:
                r_stats = self.ask_manager.ask("stats")
            except Exception as ex:
                r_stats = f"(stats error: {ex})"

        # Compact the outputs for logging
        def _clip(s: str, n: int = 200) -> str:
            s = (s or "").strip().replace("\n", " ")
            return (s[:n] + "…") if len(s) > n else s

        fed_len = len(text)
        mode = "sensitive" if sensitive else "redacted"
        parts = [
            f"fed={fed_len} chars",
            f"inspect={mode}: {_clip(r_inspect)}",
        ]
        if do_stats and r_stats:
            parts.append(f"stats: {_clip(r_stats)}")

        # Include a tiny hint of the initial ingest reply (often a friendly summary)
        if r_ingest:
            parts.append(f"ingest: {_clip(r_ingest, 120)}")

        return " | ".join(parts)
    def _retrieve_snippets(self, query: str) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Very small retrieval: pick most frequent concepts overlapping the query
        and pull freshest packets across topics. Returns [(topic, attrs), ...]
        """
        self._expire_chat_history()
        q_tokens = set(self._tokenize(query))
        if not q_tokens:
            q_tokens = set(["default"])

        # Score topics by overlap with learned concept counts
        scores: List[Tuple[float, str]] = []
        for topic, cc in self._concept_counts.items():
            overlap = sum(cc.get(tok, 0) for tok in q_tokens)
            if overlap > 0:
                scores.append((float(overlap), topic))
        scores.sort(reverse=True)
        top_topics = [t for _, t in scores[:5]] or list(self._knowledge_by_topic.keys())[:3]

        # Take freshest packets from top topics
        now = time.time()
        results: List[Tuple[str, Dict[str, Any]]] = []
        for topic in top_topics:
            dq = self._knowledge_by_topic.get(topic) or deque()
            for pkt in reversed(dq):
                if pkt.is_expired(now):
                    continue
                attrs = (pkt.payload or {}).get("attributes", {})
                if attrs:
                    results.append((topic, attrs))
                    if len(results) >= self._max_context_snippets:
                        return results
        return results

    def _format_kv(self, d: Dict[str, Any], limit: int = 10) -> str:
        items = []
        for i, (k, v) in enumerate(d.items()):
            if i >= limit:
                items.append("…")
                break
            items.append(f"{k}={v!r}")
        return ", ".join(items)

    def _chat_generate(self, prompt: str, retrieved: List[Tuple[str, Dict[str, Any]]]) -> str:
        return self.chatgen.generate(prompt, retrieved)

    def submit_message(self, text: str, role: str = "user", tags: Optional[List[str]] = None) -> None:
        """
        Push a chat message into the bus and transient store.
        - role: "user" | "system" | "assistant"
        """
        text = (text or "").strip()
        if not text:
            return
        self._chat_history.append({"role": role, "text": text, "ts": time.time()})
        attrs = {"role": role, "text": text}
        self.submit_event(topic="misc", attributes=attrs, tags=(tags or ["chat"]), ttl=self._chat_ttl_s)
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
                self.ask("sensitive")
                self.ask("stats")
                self.ask("emit")
                self.ask(self.ask_file_cleartext("p2pool_managers.py",
                                                sensitive=True, do_stats=False))
                self._log(f"[CodeOutput] 🔁 Reading Managers ", 1)
                self.ask(self.ask_file_cleartext("p2pool_router_managers.py",
                                                sensitive=True, do_stats=False))
                self._log(f"[CodeOutput] 🔁 Reading Router Managers ", 1)
                self.ask(self.ask_file_cleartext("p2pool_router_managers_2.py",
                                                sensitive=True, do_stats=False))
                self._log(f"[CodeOutput] 🔁 Reading Router Managers 2", 1)
                self.ask(self.ask_file_cleartext("p2pool_router_managers_3.py",
                                                sensitive=True, do_stats=False))
                self._log(f"[CodeOutput] 🔁 Reading Router Managers 3", 1)

                self._log(f"[CodeOutput] 🔁 {self.ask("output everything you know")}")
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
        Builds Python code for a class by delegating to the SnapshotBuilder.
        """
        # Determine which knowledge gathering function to use based on config
        attr_aggregate = (config.get("attr_aggregate") or "last").lower()
        gatherer = (
            self._gather_knowledge_aggregate
            if attr_aggregate == "list"
            else self._gather_knowledge
        )

        # Create lambdas to pass the necessary stats/method computer functions
        # This ensures they are called with the right parameters inside the builder.
        stats_computer = lambda: self._compute_statistics_with_numpy(
            topics=config.get("topics") or [],
            percentiles=list(config.get("percentiles", [5, 25, 50, 75, 95])),
            topk_categorical=int(config.get("topk_categorical", 10)),
            min_count_for_stats=int(config.get("min_count_for_stats", 2)),
        )

        method_generator = lambda stats: self._default_snapshot_methods(stats)

        # Call the builder with the config and data-providing functions
        return self.snapshot_builder.build(
            config=config,
            knowledge_gatherer=gatherer,
            insights_fetcher=self._insights_for_topics,
            stats_computer=stats_computer,
            method_generator=method_generator,
        )

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
                if isinstance(raw, KnowledgePacket):
                    packets = [self._finalize_packet(raw)]
                    self._log(f"[CodeOutput] 🔎 Normalized via direct KnowledgePacket path → 1 pkt(s).", 2)

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
       self.packet_learner.learn_from_packet(pkt)

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
        return self.stats_manager.compute(
        num_vectors=self._num_vectors,
        cat_counters=self._cat_counters,
        topics=topics,
        percentiles=list(percentiles),
        topk_categorical=int(topk_categorical),
        min_count_for_stats=int(min_count_for_stats),
    )

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

        # NEW: accept dicts as-is
        if isinstance(raw, dict):
            try:
                import json as _json
                data = _json.dumps(raw, default=str, ensure_ascii=False).encode("utf-8")
                return Raw(load=data)
            except Exception as e:
                self._log(f"[CodeOutput] 🟥 Could not JSON-wrap dict as Raw: {e}", 1)
                return None

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
        return self.method_generator.generate(stats)


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


class SnapshotMethodGenerator:
    """
    Synthesizes small analysis methods from snapshot statistics.

    Robustness improvements over the original:
      - Defensive parsing of stats (supports str/int/float, rejects NaN/inf).
      - Treats tiny std as zero via epsilon (configurable).
      - Sanitizes names deterministically (lowercase, collapses underscores, letter-prefixed).
      - Optional topic prefixing to avoid collisions across topics.
      - Runtime guards in generated methods (type coercion, NaN checks).
      - Clear, concise docstrings; consistent return format.
    """

    def __init__(
        self,
        *,
        include_topic_in_name: bool = True,
        std_epsilon: float = 1e-12,
        z1: float = 1.0,
        z2: float = 2.0,
        z3: float = 3.0,
        float_precision: int = 4,
    ) -> None:
        self.include_topic_in_name = include_topic_in_name
        self.std_epsilon = float(std_epsilon)
        self.z1, self.z2, self.z3 = float(z1), float(z2), float(z3)
        self.float_precision = int(float_precision)

        if not (0 < self.z1 < self.z2 < self.z3):
            raise ValueError("Expected 0 < z1 < z2 < z3.")

    # --------------------------- Public API ---------------------------

    def generate(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates synthesized method definitions.

        Input schema (example):
        {
          "latency": {
            "numeric": {
              "p95": {"mean": 112.3, "std": 30.1},
              "p50": {"mean": "81.0", "std": "9.7"}
            }
          },
          "throughput": {
            "numeric": {
              "rps": {"mean": 950.0, "std": 210.0}
            }
          }
        }

        Returns:
            Dict[str, Any]: { method_name: {"args": "...", "body": "...", "doc": "..."} }
        """
        methods: Dict[str, Any] = {}
        if not isinstance(stats, dict) or not stats:
            return methods

        for topic, kinds in stats.items():
            if not isinstance(kinds, dict):
                continue

            numeric_block = kinds.get("numeric")
            if not isinstance(numeric_block, dict):
                continue

            for feature, feature_stats in numeric_block.items():
                if not isinstance(feature_stats, dict):
                    continue

                m_name, m_def = self._synthesize_scorer_method(topic, feature, feature_stats)
                if m_name and m_def:
                    # Avoid accidental collisions by uniquifying names
                    unique_name = m_name
                    suffix = 2
                    while unique_name in methods:
                        unique_name = f"{m_name}_{suffix}"
                        suffix += 1
                    methods[unique_name] = m_def

        return methods

    # --------------------------- Core Code Synthesis Engine ---------------------------

    def _synthesize_scorer_method(
        self, topic: str, feature: str, feature_stats: Dict[str, Any]
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        mean = self._as_finite_float(feature_stats.get("mean"))
        std = self._as_finite_float(feature_stats.get("std"))

        if mean is None or std is None:
            return None, None

        safe_feature = self._sanitize_name(feature)
        safe_topic = self._sanitize_name(topic)

        base_name = f"analyze_{safe_feature}_value"
        if self.include_topic_in_name and safe_topic:
            base_name = f"{safe_topic}__{base_name}"

        method_name = base_name

        # --- Begin Code Synthesis ---
        p = self.float_precision
        eps = self.std_epsilon

        code_lines = []
        code_lines.append("# This method was synthesized to analyze normality using a Z-score.")
        code_lines.append(f"MEAN = {mean:.{p}f}")
        code_lines.append(f"STD = {std:.{p}f}")
        code_lines.append(f"STD_EPS = {eps:.{p}g}")
        code_lines.append("")
        code_lines.append("# --- Runtime guards & coercion ---")
        code_lines.append("try:")
        code_lines.append("    v = float(value)")
        code_lines.append("except (TypeError, ValueError):")
        code_lines.append('    return "Invalid: value is not numeric/coercible."')
        code_lines.append("if math.isnan(v) or math.isinf(v):")
        code_lines.append('    return "Invalid: value is NaN/Inf."')
        code_lines.append("")
        code_lines.append("# --- Handle constant / near-constant data ---")
        code_lines.append("if abs(STD) <= STD_EPS:")
        code_lines.append("    if abs(v - MEAN) <= STD_EPS:")
        code_lines.append('        return "(Z-Score: 0.00) This value is typical; data was effectively constant."')
        code_lines.append('    return "Anomalous for a constant feature: value deviates from the only observed level."')
        code_lines.append("")
        code_lines.append("# --- Standard Z-score path ---")
        code_lines.append("z = (v - MEAN) / STD")
        code_lines.append("az = abs(z)")
        code_lines.append("")
        code_lines.append("# Threshold interpretation")
        code_lines.append(f"if az >= {self.z3:.{p}f}:")
        code_lines.append('    bucket = "a highly unusual outlier."')
        code_lines.append(f"elif az >= {self.z2:.{p}f}:")
        code_lines.append('    bucket = "uncommon and a potential outlier."')
        code_lines.append(f"elif az >= {self.z1:.{p}f}:")
        code_lines.append('    bucket = "common, but moderately away from average."')
        code_lines.append("else:")
        code_lines.append('    bucket = "very typical and close to the average."')
        code_lines.append("")
        code_lines.append(f'return f"(Z-Score: {{z:.2f}}) This value is {{bucket}}"')
        # --- End Code Synthesis ---

        final_body = "\n".join(f"    {line}" for line in code_lines)

        docstring = f"""
Analyzes a new numeric value for the '{feature}' feature using Z-score buckets.

Guards:
  - Coerces input to float; rejects NaN/Inf.
  - Treats tiny STD (≤ {eps}) as constant data.

Args:
    value (int|float|str): The value to analyze.

Returns:
    str: A human-readable assessment, including the Z-score when applicable.
""".strip()

        method_definition = {
            "args": "self, value",
            "body": final_body,
            "doc": docstring,
        }
        return method_name, method_definition

    # --------------------------- Utilities ---------------------------

    def _as_finite_float(self, x: Any) -> Optional[float]:
        """Return a finite float or None."""
        try:
            v = float(x)
        except (TypeError, ValueError):
            return None
        if math.isnan(v) or math.isinf(v):
            return None
        return v

    def _sanitize_name(self, name: str) -> str:
        """
        Make a safe, deterministic identifier:
          - lowercase
          - non [a-z0-9_] -> '_'
          - collapse multiple '_' and strip edges
          - ensure starts with a letter; if not, prefix 'f_'
        """
        if not isinstance(name, str):
            name = str(name)
        s = name.lower()
        s = re.sub(r"[^a-z0-9_]+", "_", s)
        s = re.sub(r"_+", "_", s).strip("_")
        if not s or not s[0].isalpha():
            s = f"f_{s}" if s else "f"
        return s

class StatisticsManager:
    """
    A stateless manager to compute numeric and categorical statistics from
    feature data stores using NumPy.

    This class is designed to be a drop-in replacement for the original
    _compute_statistics_with_numpy function. It takes raw data vectors
    and counters and returns a structured dictionary of computed stats.
    """

    def compute(
            self,
            num_vectors: Dict[str, Dict[str, List[float]]],
            cat_counters: Dict[str, Dict[str, Counter]],
            topics: Iterable[str],
            percentiles: List[int],
            topk_categorical: int,
            min_count_for_stats: int,
    ) -> Dict[str, Any]:
        """
        Builds a dictionary with statistics for the specified topics.

        This is the main public method that orchestrates the computation.

        Args:
            num_vectors: Numeric features, as {topic: {feature: [values]}}.
            cat_counters: Categorical features, as {topic: {feature: Counter()}}.
            topics: A list of topics to process. If empty, all available
                    topics from the data will be used.
            percentiles: A list of integers for percentile calculations (e.g., [25, 50, 75]).
            topk_categorical: The number of top items to return for categorical features.
            min_count_for_stats: The minimum number of data points required to
                                 compute statistics for a feature.

        Returns:
            A dictionary containing the computed statistics.
        """
        stats: Dict[str, Any] = {}

        # If no specific topics are provided, use all topics present in the data.
        topic_list = list(topics) if topics else list(set(num_vectors.keys()) | set(cat_counters.keys()))

        for topic in topic_list:
            topic_stats: Dict[str, Any] = {}

            # Compute stats for numeric features for the current topic
            numeric_stats = self._compute_numeric_stats_for_topic(
                num_vectors.get(topic, {}), percentiles, min_count_for_stats
            )
            if numeric_stats:
                topic_stats["numeric"] = numeric_stats

            # Compute stats for categorical features for the current topic
            categorical_stats = self._compute_categorical_stats_for_topic(
                cat_counters.get(topic, {}), topk_categorical
            )
            if categorical_stats:
                topic_stats["categorical"] = categorical_stats

            # Add the topic's stats to the main dictionary if any were generated
            if topic_stats:
                stats[topic] = topic_stats

        return stats

    # --------------------------- Private Helper Methods ---------------------------

    def _compute_numeric_stats_for_topic(
            self,
            topic_num_vectors: Dict[str, List[float]],
            percentiles: List[int],
            min_count: int,
    ) -> Dict[str, Any]:
        """Helper to process all numeric features for a single topic."""
        stats: Dict[str, Any] = {}
        for feature, values in topic_num_vectors.items():
            if len(values) >= min_count:
                feature_stats = self._calculate_numeric_feature(values, percentiles, min_count)
                if feature_stats:
                    stats[feature] = feature_stats
        return stats

    def _calculate_numeric_feature(
            self, values: List[float], percentiles: List[int], min_count: int
    ) -> Optional[Dict[str, Any]]:
        """Helper to calculate all statistics for a single numeric feature vector."""
        try:
            vec = np.asarray(values, dtype=float)
            valid_vec = vec[~np.isnan(vec)]  # Filter out any NaN values

            if valid_vec.size < min_count:
                return None

            return {
                "count": int(valid_vec.size),
                "mean": float(np.mean(valid_vec)),
                "std": float(np.std(valid_vec)),
                "min": float(np.min(valid_vec)),
                "max": float(np.max(valid_vec)),
                "median": float(np.median(valid_vec)),
                "percentiles": {
                    int(p): float(np.percentile(valid_vec, p)) for p in percentiles
                },
            }
        except Exception:
            # In case of any unexpected numpy errors, fail gracefully for this feature
            return None

    def _compute_categorical_stats_for_topic(
            self, topic_cat_counters: Dict[str, Counter], top_k: int
    ) -> Dict[str, Any]:
        """Helper to process all categorical features for a single topic."""
        stats: Dict[str, Any] = {}
        for feature, counter in topic_cat_counters.items():
            if counter:
                stats[feature] = self._calculate_categorical_feature(counter, top_k)
        return stats

    def _calculate_categorical_feature(
            self, counter: Counter, top_k: int
    ) -> Dict[str, Any]:
        """Helper to calculate all statistics for a single categorical counter."""
        total_count = sum(counter.values())
        top_values = counter.most_common(top_k)

        return {
            "unique_count": int(len(counter)),
            "total_count": int(total_count),
            "top_k": [(str(val), int(cnt)) for val, cnt in top_values],
        }


class SnapshotBuilder:
    """
    SnapshotBuilder (AskManager-aware)

    An advanced manager that builds a Python class by learning from observed code
    examples and AskManager knowledge to procedurally generate new,
    descriptive docstrings.

    Key differences vs. your original:
      • Uses AskManager for tokenization, topic detection, redaction & retrieval
      • Trains the Markov generator from (a) provided code examples,
        (b) AskManager token bank lines, and (c) live knowledge payloads
      • Optionally includes AskManager insights & statistics
      • Produces a compact, readable class string using AskManager’s payload
        formatter and redaction where appropriate
    """

    def __init__(
        self,
        logger: Callable[[str, int], None],
        *,
        ask_manager: Optional[object] = None,
        rng_seed: Optional[int] = None,
        max_corpus_lines: int = 200,
        max_payload_chars: int = 1200,
        doc_max_len: int = 28,
    ):
        self._log = logger
        self._am = ask_manager
        self._rng = random.Random(rng_seed)
        self._np_rng = np.random.default_rng(rng_seed)
        self._markov_model: Dict[str, Dict[str, int]] = {}
        self._starters: List[str] = []
        self._max_corpus_lines = int(max_corpus_lines)
        self._max_payload_chars = int(max_payload_chars)
        self._doc_max_len = int(doc_max_len)

        # fallbacks if AskManager absent
        self._fallback_token_re = re.compile(r"[A-Za-z0-9_]+")

    # -------------------------------------------------------------------------
    # Public API (unchanged signature)
    # -------------------------------------------------------------------------
    def build(
        self,
        config: Dict[str, Any],
        knowledge_gatherer: Callable[..., Tuple[Dict, Dict]],
        insights_fetcher: Callable[..., Dict],
        stats_computer: Callable[..., Dict],
        method_generator: Callable[..., Dict],
    ) -> str:
        """
        The main public method to generate the class code string.
        """
        # 1) Parse config and gather knowledge (base + external)
        class_name, base_attrs, base_methods, topics, policies = self._parse_config(config)
        k_attrs, k_methods = self._gather_external_knowledge(
            knowledge_gatherer, base_attrs, base_methods, topics, policies
        )

        # 2) Ingest AskManager knowledge (if present) and merge
        am_attrs, am_methods, code_examples = self._ingest_from_ask_manager(topics, policies)
        merged_attrs = self._merge_attrs(base_attrs, k_attrs, am_attrs, policies)
        merged_methods = self._merge_methods(base_methods, k_methods, am_methods, policies)

        # 3) Learn from code examples + token bank + payloads
        self._train_generative_model(code_examples)

        # 4) Add insights, stats, and standard methods
        if policies.get("include_insights"):
            insights = self._fetch_insights(insights_fetcher, topics)
            if insights:
                merged_attrs["_insights"] = insights

        stats = {}
        if policies.get("include_statistics"):
            stats = self._compute_stats(stats_computer)
            if stats:
                merged_attrs["_statistics"] = stats

        merged_methods.update(method_generator(stats=stats))

        # 5) Use the generative model to write a unique class docstring
        generative_docstring = self._generate_text(max_length=self._doc_max_len)

        # 6) Log and render
        self._log_summary(class_name, topics, merged_attrs, merged_methods, policies)
        return self._render_class(class_name, merged_attrs, merged_methods, generative_docstring)

    # -------------------------------------------------------------------------
    # AskManager synergy
    # -------------------------------------------------------------------------
    def _ingest_from_ask_manager(
        self,
        topics: List[str],
        policies: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
        """
        Pulls material from AskManager for attributes/methods and a corpus for the generator.
        """
        if not self._am:
            return {}, {}, []

        # 1) Export live knowledge (redacted text used to build summaries)
        try:
            knowledge = self._am._export_knowledge()  # {topic: [{payload,...}, ...]}
        except Exception:
            knowledge = {}

        # 2) Build attributes/methods from knowledge (compact)
        attrs: Dict[str, Any] = {}
        methods: Dict[str, Any] = {}
        corpus: List[str] = []

        # Include per-topic payload previews and tags
        for topic, rows in (knowledge or {}).items():
            # respect requested topics if provided
            if topics and topic not in topics:
                continue

            previews: List[str] = []
            tags: List[str] = []
            for row in rows[:12]:
                payload = row.get("payload") or {}
                # textual preview via AskManager formatter (redacted by default)
                preview = self._payload_to_text(payload, redact=True)
                if preview:
                    preview = preview if len(preview) <= self._max_payload_chars else preview[: self._max_payload_chars] + "…"
                    previews.append(preview)
                    corpus.append(preview)
                tg = row.get("tags") or []
                if tg: tags.extend(tg[:4])

            if previews:
                attrs[f"{topic}_previews"] = previews[:20]
            if tags:
                attrs[f"{topic}_tags"] = list(dict.fromkeys(tags))[:20]  # dedupe-preserve order

        # 3) Mine token-bank lines from AskManager for Markov training
        #    The token bank structure: token -> deque[(role, raw, ts), ...]
        try:
            token_bank = getattr(self._am, "_token_bank", {})
            # favor newest lines across the whole bank
            merged_lines: List[Tuple[float, str]] = []
            for dq in token_bank.values():
                for role, line, ts in dq:
                    if role == "user" and line and not self._is_boilerplate(line):
                        merged_lines.append((ts, line))
            merged_lines.sort(key=lambda x: x[0], reverse=True)
            for _, line in merged_lines[: self._max_corpus_lines]:
                corpus.append(line)
        except Exception:
            pass

        # 4) Add a small helper method that surfaces an AskManager tip for a topic
        def _tip_body(topic_var: str = "topic"):
            return (
                "t = topic or 'misc'\n"
                "try:\n"
                "    return self._am._actionable_tip('snapshot', t) if hasattr(self, '_am') and self._am else 'No tip.'\n"
                "except Exception:\n"
                "    return 'No tip.'"
            )
        methods["ask_tip"] = {"body": _tip_body()}

        # 5) Add a helper to list top keywords seen recently (via token bank density)
        def _kw_body():
            return (
                "from collections import Counter\n"
                "if not hasattr(self, '_am') or not self._am:\n"
                "    return []\n"
                "tb = getattr(self._am, '_token_bank', {}) or {}\n"
                "cnt = Counter({k: len(v) for k, v in tb.items()})\n"
                "return [w for w,_ in cnt.most_common(16)]"
            )
        methods["top_tokens"] = {"body": _kw_body()}

        return attrs, methods, corpus

    # -------------------------------------------------------------------------
    # Generative Model (unchanged interface, richer inputs)
    # -------------------------------------------------------------------------
    def _train_generative_model(self, texts: List[str]):
        """Builds a word-level Markov Chain model from example code/text."""
        self._markov_model = {}
        self._starters = []
        if not texts:
            return

        # lightweight cleanup & cap
        cap = min(len(texts), self._max_corpus_lines)
        for text in texts[:cap]:
            words = (text or "").strip().split()
            if not words:
                continue
            self._starters.append(words[0].lower())
            for i in range(len(words) - 1):
                cur = words[i].lower()
                nxt = words[i + 1].lower()
                self._markov_model.setdefault(cur, {})
                self._markov_model[cur][nxt] = self._markov_model[cur].get(nxt, 0) + 1

    def _generate_text(self, max_length: int = 15, seed_word: Optional[str] = None) -> str:
        """Generates a new text string using the trained probabilistic model."""
        if not self._markov_model:
            return "A generated class snapshot."

        # Choose a starting word with a bias toward AskManager topic guess
        if seed_word and seed_word in self._markov_model:
            current_word = seed_word
        else:
            # try to pick a plausible starter from AskManager topic guess words
            if self._am:
                try:
                    candidates = ["dns", "tls", "esp", "router", "kerberos", "quic", "dhcp", "misc"]
                    self._rng.shuffle(candidates)
                    for c in candidates:
                        if c in self._markov_model:
                            current_word = c
                            break
                    else:
                        current_word = self._rng.choice(self._starters or list(self._markov_model.keys()))
                except Exception:
                    current_word = self._rng.choice(self._starters or list(self._markov_model.keys()))
            else:
                current_word = self._rng.choice(self._starters or list(self._markov_model.keys()))

        sentence = [current_word.capitalize()]
        for _ in range(max_length - 1):
            nxts = self._markov_model.get(current_word)
            if not nxts:
                break
            words = list(nxts.keys())
            counts = np.array(list(nxts.values()), dtype=np.float32)
            probs = counts / counts.sum()
            next_word = str(self._np_rng.choice(words, p=probs))
            sentence.append(next_word)
            current_word = next_word

        out = " ".join(sentence)
        if not out.endswith("."):
            out += "."
        return out

    # -------------------------------------------------------------------------
    # Private helper methods (AskManager-aware)
    # -------------------------------------------------------------------------
    def _payload_to_text(self, payload: Dict[str, Any], *, redact: bool) -> str:
        if self._am and hasattr(self._am, "_payload_to_text"):
            try:
                return self._am._payload_to_text(payload, redact=redact, include_raw=not redact)  # type: ignore[attr-defined]
            except Exception:
                pass
        # fallback compact flattener
        parts = []
        for k, v in (payload or {}).items():
            if k == "raw_text" and redact:
                continue
            s = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
            if redact:
                s = self._redact_text(s)
            parts.append(f"{k}:{s if len(s) <= 80 else s[:77] + '…'}")
        return " ".join(parts)

    def _redact_text(self, s: str) -> str:
        if self._am and hasattr(self._am, "_redact_text"):
            try:
                return self._am._redact_text(s)  # type: ignore[attr-defined]
            except Exception:
                pass
        # simple fallback
        s = re.sub(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|$)){4}\b", "[IP]", s)
        s = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "[MAC]", s)
        s = re.sub(r"\b(?:0x)?[0-9a-fA-F]{16,}\b", "[HEX]", s)
        return s

    def _is_boilerplate(self, s: str) -> bool:
        if not s:
            return True
        bp = re.compile(
            r"^(using token matches|pulled context|found relevant raw lines|here’s what i’m seeing|got it — here’s a quick take|alright, quick technical readout|okay, here’s the gist)",
            re.IGNORECASE,
        )
        return bool(bp.match(s.strip()))

    # -------------------------------------------------------------------------
    # Original helpers (adapted)
    # -------------------------------------------------------------------------
    def _parse_config(self, config: Dict[str, Any]) -> Tuple:
        class_name = config.get("class_name", "GeneratedClass")
        base_attrs = dict(config.get("attributes", {}))
        base_methods = dict(config.get("methods", {}))
        topics = config.get("topics") or []
        policies = {
            "attr_policy": (config.get("attr_policy") or "merge").lower(),
            "method_policy": (config.get("method_policy") or "merge").lower(),
            "attr_aggregate": (config.get("attr_aggregate") or "last").lower(),
            "listify_singletons": bool(config.get("listify_singletons", False)),
            "include_insights": bool(config.get("include_insights", False)),
            "include_statistics": bool(config.get("include_statistics", False)),
        }
        return class_name, base_attrs, base_methods, topics, policies

    def _gather_external_knowledge(
        self,
        gatherer: Callable,
        base_attrs: Dict,
        base_methods: Dict,
        topics: List,
        policies: Dict
    ) -> Tuple[Dict, Dict]:
        try:
            k_attrs, k_methods = gatherer(topics=topics)
        except Exception:
            k_attrs, k_methods = {}, {}

        # Extract code example bodies (string) for training
        self._external_code_examples = [
            m.get("body") for m in (k_methods or {}).values() if isinstance(m, dict) and isinstance(m.get("body"), str)
        ]
        return k_attrs, k_methods

    def _merge_attrs(self, base: Dict, ext: Dict, am: Dict, policies: Dict) -> Dict:
        merged = {**base, **(ext or {}), **(am or {})}
        if policies["attr_policy"] == "override":
            merged = (am or {}) or (ext or {}) or base
        if policies["attr_aggregate"] == "list" and policies["listify_singletons"]:
            for k, v in list(merged.items()):
                if not isinstance(v, list):
                    merged[k] = [v]
        return merged

    def _merge_methods(self, base: Dict, ext: Dict, am: Dict, policies: Dict) -> Dict:
        merged = {**base, **(ext or {}), **(am or {})}
        if policies["method_policy"] == "override":
            merged = (am or {}) or (ext or {}) or base
        return merged

    def _fetch_insights(self, fetcher: Callable[..., Dict], topics: List[str]) -> Dict:
        try:
            return fetcher(topics=topics) or {}
        except Exception:
            return {}

    def _compute_stats(self, compute: Callable[..., Dict]) -> Dict:
        try:
            return compute() or {}
        except Exception:
            return {}

    def _log_summary(self, name: str, topics: List, attrs: Dict, methods: Dict, policies: Dict):
        n_attrs, n_methods = len(attrs), len(methods)
        t_str = ",".join(topics) if topics else "ALL"
        flags = []
        if policies.get("include_insights"): flags.append("insights")
        if policies.get("include_statistics"): flags.append("stats")
        self._log(
            f"[CodeOutput] 🧠 Generating class '{name}' (topics={t_str}; attrs={n_attrs}; methods={n_methods}; opts={'+'.join(flags) or 'none'})",
            1,
        )

    @staticmethod
    def _render_class(class_name: str, attributes: Dict, methods: Dict, doc: str) -> str:
        lines = [f"class {class_name}:", f'    """{doc}"""', "", "    def __init__(self, ask_manager=None):", "        self._am = ask_manager"]
        if not attributes:
            lines.append("        pass")
        else:
            for name, val in sorted(attributes.items()):
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

    # -------------------------------------------------------------------------
    # Corpus construction source
    # -------------------------------------------------------------------------
    def _train_from_sources(self, extra_texts: List[str]) -> None:
        texts = list(extra_texts or [])
        texts.extend(self._external_code_examples or [])
        self._train_generative_model(texts)

class ChatGenManager:
    """
    A snapshot/line generator that *synergizes* with AskManager.

    Key integrations when an AskManager instance is provided:
      - Token-first context: uses AskManager._tokenize and _fetch_token_lines
      - Retrieval: uses AskManager._retrieve_snippets (respects TTL/importance)
      - Redaction: uses AskManager._redact_text
      - Topic guess & actionable tip: uses AskManager._guess_topic and _actionable_tip
      - Payload preview: uses AskManager._payload_to_text (to align formatting)

    If AskManager is not provided, the class gracefully falls back to
    internal minimal implementations.

    Variety features preserved/improved from your prior version:
      • Randomizes style choice and order per call
      • Randomizes which attributes are shown, and how many
      • Slightly varies quoting/compaction (e.g., shorten long values)
      • Occasionally paraphrases the tail text
      • Per-line soft character caps with word-aware truncation
    """
    # ------------------------ Utilities ------------------------

    def _identity(self, x: str) -> str:
        return x

    def _default_history_getter(self) -> Iterable[Dict[str, Any]]:
        return ()
    # -------- Construction --------
    def __init__(
        self,
        *,
        ask_manager: Optional[object] = None,
        format_kv: Optional[Callable[[Dict[str, Any]], str]] = None,
        history_getter: Callable[[], Iterable[Dict[str, Any]]] = _default_history_getter,
        persona: str = "Assistant",
        seed_corpus: Iterable[str] = (),
        max_chars: int = 250,
        max_history: int = 8,
        sample_len: int = 24,
        state_size: int = 2,  # 2-word context by default
        config_styles: Sequence[str] = ("kv", "yaml", "ini", "shell", "json"),
        preview_pairs: int = 8,        # nominal max k/v pairs per line
        per_line_char_max: int = 160,  # soft cap per rendered line
        # variety knobs
        min_pairs: int = 3,
        vary_styles: bool = True,
        shuffle_pairs: bool = True,
        style_weights: Optional[Dict[str, float]] = None,
        paraphrase_tail_prob: float = 0.30,
        compact_value_prob: float = 0.35,
        redact_by_default: bool = True,
        rng_seed: Optional[int] = None,
    ) -> None:
        self._am = ask_manager
        self._format_kv = format_kv
        self._get_history = history_getter
        self._persona = persona
        self._seed_corpus = list(seed_corpus)
        self._max_chars = int(max_chars)
        self._max_history = int(max_history)
        self._sample_len = int(sample_len)
        self._state_size = max(1, int(state_size))
        self._np_rng = np.random.default_rng(rng_seed)
        self._config_styles = tuple(config_styles) or ("kv",)
        self._preview_pairs = max(1, int(preview_pairs))
        self._per_line_char_max = max(40, int(per_line_char_max))
        # variety
        self._min_pairs = max(1, int(min_pairs))
        self._vary_styles = bool(vary_styles)
        self._shuffle_pairs = bool(shuffle_pairs)
        self._style_weights = dict(style_weights or {})
        self._paraphrase_tail_prob = float(paraphrase_tail_prob)
        self._compact_value_prob = float(compact_value_prob)
        self._redact_default = bool(redact_by_default)
        # local fallbacks if AskManager is absent
        self._fallback_token_re = re.compile(r"[A-Za-z0-9_]+")

    # -------- Public API --------
    def generate(self, prompt: str, redact: Optional[bool] = None) -> str:
        """High-level one-shot generation using token-first + retrieval."""
        redact = self._redact_default if redact is None else bool(redact)

        # Tail text (Markov) built from history + seed corpus
        corpus = self._build_corpus()
        model, starters = self._train_markov(corpus)
        tail = self._sample(model, starters)

        # Token-first context and retrieval
        token_lines: List[str] = []
        retrieved: List[Any] = []
        topic = "misc"
        redactor = self._identity
        payload_to_text = None
        actionable_tip = None

        if self._am is not None:
            try:
                q_toks = [t for t in self._am._tokenize(prompt) if t and not t.isdigit()]  # type: ignore[attr-defined]
                token_lines = self._am._fetch_token_lines(q_toks, per_token_limit=6)       # type: ignore[attr-defined]
                retrieved = self._am._retrieve_snippets(prompt, topk=12, per_topic_limit=6)  # type: ignore[attr-defined]
                topic = self._am._guess_topic(prompt)                                      # type: ignore[attr-defined]
                redactor = (self._am._redact_text if redact else _identity)               # type: ignore[attr-defined]
                payload_to_text = self._am._payload_to_text                                # type: ignore[attr-defined]
                actionable_tip = lambda: self._am._actionable_tip(prompt, topic)          # type: ignore[attr-defined]
            except Exception:
                # If any private AskManager API changes, fall back silently
                token_lines, retrieved, topic = [], [], "misc"
                redactor, payload_to_text, actionable_tip = self._identity, None, None
        else:
            # local fallbacks
            q_toks = [t for t in self._fallback_tokenize(prompt) if t and not t.isdigit()]
            # no token bank available without AskManager
            token_lines = []
            retrieved = []
            topic = self._fallback_guess_topic(prompt)
            redactor = self._fallback_redact if redact else self._identity
            payload_to_text = None
            actionable_tip = None

        # Stitch, preferring token-first evidence
        if token_lines:
            lines = [self._np_rng.choice([
                "Using token matches from history:",
                "Pulled context from your recent tokens:",
                "Found relevant raw lines via tokens:",
            ])]
            for s in token_lines[:8]:
                s = redactor(s)
                if len(s) > 240:
                    s = s[:237] + "..."
                lines.append(f"• {s}")
            lines.append("")
            if actionable_tip is not None:
                lines.append(actionable_tip())
            # add a compacted tail for variety
            if self._np_rng.random() < 0.6:
                lines.append(self._rephrase_tail(tail) if self._np_rng.random() < self._paraphrase_tail_prob else tail)
            return self._truncate("\n".join(lines), self._max_chars)

        # Otherwise, render retrieved payloads in one-line multi-style format
        one_lines: List[str] = []
        if retrieved:
            # Shuffle which records render first
            order = list(range(len(retrieved)))
            self._np_rng.shuffle(order)

            for out_idx, i in enumerate(order):
                pkt = retrieved[i]
                payload = getattr(pkt, "payload", None) or {}

                # style choice
                style = self._choose_style(out_idx)

                # how many pairs this line will show
                n_pairs = int(self._np_rng.integers(self._min_pairs, self._preview_pairs + 1))

                line = self._format_attrs_one_line(
                    payload,
                    style,
                    n_pairs,
                    line_index=out_idx,
                    shuffle_pairs=self._shuffle_pairs,
                )
                one_lines.append(self._limit_line(line, self._per_line_char_max))

        # Header + lines + tail
        lines = [f"({self._persona})"]
        if one_lines:
            lines.append(self._np_rng.choice([
                "Here’s what I’m seeing right now:",
                "Current snapshot:",
                "Live view:",
                "Latest extract:",
            ]))
            lines.extend(one_lines)
        else:
            lines.append(self._np_rng.choice([
                "No retrieved context; reasoning from prompt.",
                "No live records matched; continuing with prompt only.",
                "Still waiting on inputs; using context and prompt for now.",
            ]))

        # Occasionally paraphrase the tail
        if self._np_rng.random() < self._paraphrase_tail_prob:
            tail = self._rephrase_tail(tail)

        # Respect redaction for tail too (conservative)
        lines.append(redactor(tail))

        # Optional actionable tip when available
        if actionable_tip is not None:
            lines.append("")
            lines.append(actionable_tip())

        return self._truncate("\n".join(lines), self._max_chars)

    # -------- Helpers: corpus / model --------
    def _build_corpus(self) -> List[str]:
        history = list(self._get_history())[-self._max_history:]
        lines = [h.get("text", "") for h in history if h.get("text")]
        lines.extend(self._seed_corpus)
        return lines

    def _train_markov(
        self, corpus: List[str]
    ) -> Tuple[Dict[Tuple[str, ...], Dict[str, int]], List[Tuple[str, ...]]]:
        model: DefaultDict[Tuple[str, ...], DefaultDict[str, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
        starters: List[Tuple[str, ...]] = []
        for text in corpus:
            words = text.strip().lower().split()
            if len(words) <= self._state_size:
                continue
            starters.append(tuple(words[: self._state_size]))
            for i in range(len(words) - self._state_size):
                state = tuple(words[i : i + self._state_size])
                nxt = words[i + self._state_size]
                model[state][nxt] += 1
        return model, starters or [("acknowledged",)]

    def _sample(
        self,
        model: Dict[Tuple[str, ...], Dict[str, int]],
        starters: List[Tuple[str, ...]],
    ) -> str:
        if not model:
            return (self._np_rng.choice(self._seed_corpus) if self._seed_corpus else "Acknowledged. I'm awaiting more data to analyze.")

        current_state = starters[self._np_rng.integers(0, len(starters))]
        words = list(current_state)

        for _ in range(self._sample_len - self._state_size):
            next_opts = model.get(tuple(current_state))
            if not next_opts and self._state_size > 1:
                shorter = current_state[-(self._state_size - 1):]
                next_opts = model.get(tuple(shorter))
            if next_opts:
                options = list(next_opts.keys())
                counts = np.array(list(next_opts.values()), dtype=np.float32)
                probs = counts / counts.sum()
                nxt = str(self._np_rng.choice(options, p=probs))
                words.append(nxt)
                current_state = tuple(words[-self._state_size:])
            else:
                current_state = starters[self._np_rng.integers(0, len(starters))]

        sentence = " ".join(words).capitalize()
        if sentence and sentence[-1].isalnum():
            sentence += "."
        return sentence

    # -------- Helpers: style selection & formatting --------
    def _choose_style(self, line_index: int) -> str:
        # Weighted random style selection if vary_styles=True; otherwise round-robin
        if not self._vary_styles:
            return self._config_styles[line_index % len(self._config_styles)]
        styles = list(self._config_styles)
        if not styles:
            return "kv"
        weights = np.array([self._style_weights.get(s, 1.0) for s in styles], dtype=np.float32)
        if np.all(weights <= 0):
            weights[:] = 1.0
        weights = weights / weights.sum()
        return str(self._np_rng.choice(styles, p=weights))

    def _format_attrs_one_line(
        self,
        attrs: Mapping[str, Any],
        style: str,
        limit: int,
        *,
        line_index: int = 0,
        shuffle_pairs: bool = False,
    ) -> str:
        flat = self._flatten(attrs, compact_prob=self._compact_value_prob)
        pairs = self._select_pairs(flat, limit, line_index, shuffle_pairs=shuffle_pairs)

        if style == "kv":
            parts = []
            for k, v in pairs:
                if self._np_rng.random() < 0.5 and not self._needs_quotes(v):
                    parts.append(f"{k}={v}")
                else:
                    parts.append(f"{k}='{v}'")
            return ", ".join(parts)

        elif style == "yaml":  # flow-style YAML on one line
            items = [f"{k}: {self._yaml_scalar(v)}" for k, v in pairs]
            return "{ " + ", ".join(items) + " }"

        elif style == "ini":   # INI-ish inline
            return "; ".join(f"{k}={v}" for k, v in pairs)

        elif style == "shell": # shell env-style
            return " ".join(f"{k.upper()}={self._shell_quote(v)}" for k, v in pairs)

        elif style == "json":
            obj = {k: v for k, v in pairs}
            tight = (self._np_rng.random() < 0.5)
            seps = (",", ":") if tight else (", ", ": ")
            return json.dumps(obj, separators=seps, ensure_ascii=False)

        elif style == "ext" and self._format_kv:
            return self._format_kv(dict(pairs))

        else:
            return ", ".join(f"{k}={v}" for k, v in pairs)

    def _flatten(self, obj: Any, prefix: str = "", *, compact_prob: float = 0.0) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        if isinstance(obj, Mapping):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                out.extend(self._flatten(v, key, compact_prob=compact_prob))
        elif isinstance(obj, (list, tuple)):
            for i, v in enumerate(obj):
                key = f"{prefix}[{i}]"
                out.extend(self._flatten(v, key, compact_prob=compact_prob))
        else:
            sval = self._to_scalar(obj, compact_prob=compact_prob)
            if prefix:
                out.append((prefix, sval))
        return out

    def _to_scalar(self, v: Any, *, compact_prob: float = 0.0) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v)
        if self._np_rng.random() < compact_prob:
            s = self._compact_value(s)
        else:
            if len(s) > 64:
                s = s[:61] + "…"
        return s

    def _compact_value(self, s: str) -> str:
        # hex-ish long strings
        if len(s) > 40 and all(ch in "0123456789abcdefABCDEF:" for ch in s if ch.isalnum() or ch == ":"):
            return s[:16] + "…" + s[-8:]
        # MAC like 'aa:bb:cc:dd:ee:ff'
        if s.count(":") == 5 and all(len(part) == 2 for part in s.split(":")):
            parts = s.split(":")
            return f"{parts[0]}:{parts[1]}:..:{parts[-2]}:{parts[-1]}"
        # Very long file path / uri / text
        if len(s) > 48:
            return s[:20] + "…" + s[-12:]
        return s

    def _select_pairs(
        self,
        flat: List[Tuple[str, str]],
        limit: int,
        line_index: int,
        *,
        shuffle_pairs: bool = False,
    ) -> List[Tuple[str, str]]:
        if not flat:
            return []
        items = list(flat)
        if shuffle_pairs:
            self._np_rng.shuffle(items)
        else:
            items.sort(key=lambda kv: kv[0])
            offset = (line_index * 3) % len(items)
            items = items[offset:] + items[:offset]
        return items[:max(1, limit)]

    # -------- Small formatting helpers --------
    def _needs_quotes(self, v: str) -> bool:
        if not v:
            return True
        for ch in v:
            if not (ch.isalnum() or ch in "-._:/"):
                return True
        return False

    def _yaml_scalar(self, v: str) -> str:
        if not v or any(ch in v for ch in " \t,:{}[]#&*!|>'\"%@`"):
            return '"' + v.replace('"', '\\"') + '"'
        return v

    def _shell_quote(self, v: str) -> str:
        if v and v.replace("_", "").replace("-", "").isalnum():
            return v
        return "'" + v.replace("'", "'\\''") + "'"

    # -------- Tail paraphrase & truncation --------
    def _rephrase_tail(self, s: str) -> str:
        if not s:
            return s
        candidates = [
            lambda x: x.replace("i'm", "i am"),
            lambda x: x.replace("we're", "we are"),
            lambda x: x.replace("let's", "let us"),
            lambda x: x.replace("acknowledged", "noted"),
            lambda x: x.replace("observing", "seeing"),
        ]
        fn = self._np_rng.choice(candidates)
        out = fn(s.lower())
        if out:
            out = out[0].upper() + out[1:]
        return out

    def _limit_line(self, s: str, maxlen: int) -> str:
        if len(s) <= maxlen:
            return s
        cut = s.rfind(" ", 0, maxlen - 1)
        if cut == -1 or cut < maxlen // 2:
            cut = maxlen - 1
        return s[:cut].rstrip() + "…"

    def _truncate(self, s: str, maxlen: int) -> str:
        if len(s) <= maxlen:
            return s
        cut = s.rfind(" ", 0, maxlen - 1)
        if cut == -1 or cut < maxlen // 2:
            cut = maxlen - 1
        return s[:cut].rstrip() + "…"

    # -------- Local fallbacks when AskManager is absent --------
    def _fallback_tokenize(self, text: str) -> List[str]:
        return [t.lower() for t in self._fallback_token_re.findall(text or "")]

    def _fallback_guess_topic(self, text: str) -> str:
        toks = set(self._fallback_tokenize(text))
        for t in ("tls", "dns", "dhcp", "router", "transport", "quic", "esp", "kerberos"):
            if t in toks:
                return t
        return "misc"

    _RE_IPv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
    _RE_MAC  = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
    _RE_SPI  = re.compile(r"\bspi=([0-9]{1,10})\b", re.IGNORECASE)
    _RE_HEX  = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")

    def _fallback_redact(self, s: str) -> str:
        out = s
        out = self._RE_IPv4.sub("[IP]", out)
        out = self._RE_MAC.sub("[MAC]", out)
        out = self._RE_SPI.sub("spi=[SPI]", out)
        out = self._RE_HEX.sub("[HEX]", out)
        return out

class PacketLearnerManager:
    # --------------------- Regexes & constants ---------------------
    _TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{1,31}", re.IGNORECASE)  # 1–32 chars, starts alpha
    _STOPWORDS = {
        "the","a","an","of","and","or","to","in","on","for","with","by","at","as",
        "is","are","was","were","be","been","being","this","that","these","those",
        "it","its","from","into","over","under","about","via","per","not","no",
    }

    _IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _MAC_RE  = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
    _PORT_RE = re.compile(r"\b(?:port|sport|dport|src_port|dst_port)\s*[:=]?\s*(\d{1,5})\b", re.IGNORECASE)
    _PROTO_RE= re.compile(r"\b(tcp|udp|icmp|igmp|quic|tls|http|https|dns|dhcp|ssh)\b", re.IGNORECASE)

    DEFAULT_BINS = tuple(2**k for k in range(5, 17))  # 32..65536
    EWMA_ALPHA = 0.25

    # --------------------- Online helpers ---------------------
    @dataclass
    class _OnlineStats:
        n: int = 0
        mean: float = 0.0
        M2: float = 0.0
        min: float = float("inf")
        max: float = float("-inf")

        def add(self, x: float) -> None:
            self.n += 1
            d = x - self.mean
            self.mean += d / self.n
            self.M2 += d * (x - self.mean)
            if x < self.min: self.min = x
            if x > self.max: self.max = x

        def std(self) -> float:
            return math.sqrt(self.M2 / (self.n - 1)) if self.n > 1 else 0.0

    class _EWMA:
        __slots__ = ("alpha", "value", "last_t")
        def __init__(self, alpha: float = 0.25) -> None:
            self.alpha = float(alpha)
            self.value = 0.0
            self.last_t: Optional[float] = None
        def tick(self, now: float) -> float:
            if self.last_t is None:
                self.last_t = now
                return self.value
            dt = max(1e-3, now - self.last_t)
            inst = 1.0 / dt
            self.value = self.alpha * inst + (1 - self.alpha) * self.value
            self.last_t = now
            return self.value

    # --------------------- Static utilities ---------------------
    @staticmethod
    def _now() -> float:
        return time.time()

    @staticmethod
    def _safe_decode(buf: Union[bytes, bytearray, memoryview, str]) -> str:
        if isinstance(buf, str):
            return buf
        if isinstance(buf, memoryview):
            buf = buf.tobytes()
        try:
            return bytes(buf).decode("utf-8", errors="strict")
        except Exception:
            # latin-1 never fails and preserves byte values
            return bytes(buf).decode("latin-1", errors="replace")

    @staticmethod
    def _byte_entropy(b: bytes) -> float:
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

    # --------------------- Init ---------------------
    def __init__(
        self,
        *,
        keep_raw_samples: bool = True,
        max_samples_per_topic: int = 32,
        max_sample_chars: int = 2000,
        spike_z_threshold: float = 3.0,
        logger: Optional[Callable[[str], None]] = None,
        log_level: int = 1,
    ) -> None:
        self.keep_raw_samples = bool(keep_raw_samples)
        self.max_samples_per_topic = int(max_samples_per_topic)
        self.max_sample_chars = int(max_sample_chars)
        self.spike_z_threshold = float(spike_z_threshold)
        self._logger = logger or (lambda s: None)
        self._log_level = int(log_level)

        # Learned state
        self._vocab: Dict[str, Dict[str, int]] = defaultdict(dict)  # topic -> token -> count
        self._cats: Dict[str, Dict[str, Counter]] = defaultdict(lambda: {
            "ip": Counter(), "mac": Counter(), "port": Counter(), "proto": Counter()
        })
        self._num: Dict[str, Dict[str, PacketLearnerManager._OnlineStats]] = defaultdict(lambda: {
            "length": self._OnlineStats(), "entropy": self._OnlineStats()
        })
        self._hist: Dict[str, List[int]] = defaultdict(lambda: [0]*len(self.DEFAULT_BINS))
        self._rate: Dict[str, PacketLearnerManager._EWMA] = defaultdict(lambda: self._EWMA(self.EWMA_ALPHA))
        self._rate_mean: Dict[str, PacketLearnerManager._OnlineStats] = defaultdict(self._OnlineStats)
        self._rate_std: Dict[str, PacketLearnerManager._OnlineStats] = defaultdict(self._OnlineStats)
        self._raw_samples: Dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=self.max_samples_per_topic))

        self._lock = threading.Lock()

    # --------------------- Public API ---------------------
    def learn_from_packet(self, pkt: Any) -> Any:
        """
        Accepts KnowledgePacket-like, Scapy Packet, dict, bytes/bytearray/memoryview, or str.
        Decodes raw bytes -> text, learns tokens & signals from the raw text only.
        Returns the input pkt for chaining.
        """
        topic, raw_bytes = self._coerce_input(pkt)
        if raw_bytes is None:
            return pkt

        raw_len = len(raw_bytes)
        raw_text = self._safe_decode(raw_bytes)

        tokens = self._tokens_from_text(raw_text)
        ips, macs, ports, protos = self._signals_from_text(raw_text)

        ent = self._byte_entropy(raw_bytes)

        now = self._now()
        with self._lock:
            # vocab
            v = self._vocab[topic]
            for t in tokens:
                v[t] = v.get(t, 0) + 1

            # categoricals
            cats = self._cats[topic]
            for ip in ips: cats["ip"][ip] += 1
            for mac in macs: cats["mac"][mac] += 1
            for p in ports: cats["port"][str(p)] += 1
            for pr in protos: cats["proto"][pr.lower()] += 1

            # numerics
            stats = self._num[topic]
            stats["length"].add(float(raw_len))
            stats["entropy"].add(float(ent))

            # histogram (length in bytes)
            self._bump_hist(topic, raw_len)

            # rate & spike
            rate = self._rate[topic].tick(now)
            self._rate_mean[topic].add(rate)
            self._rate_std[topic].add(rate)
            z = 0.0
            stdev = self._rate_std[topic].std()
            if self._rate_mean[topic].n > 10 and stdev > 1e-6:
                z = (rate - self._rate_mean[topic].mean) / stdev
                if z >= self.spike_z_threshold and self._log_level >= 2:
                    self._logger(f"[RawLearner] spike topic='{topic}' rate={rate:.2f}/s z={z:.2f}")

            # raw samples (optional)
            if self.keep_raw_samples and raw_text:
                if len(raw_text) > self.max_sample_chars:
                    raw_text = raw_text[: self.max_sample_chars] + "…"
                self._raw_samples[topic].append(raw_text)

        return pkt

    # --------------------- Input coercion ---------------------
    def _coerce_input(self, pkt: Any) -> Tuple[str, Optional[bytes]]:
        """
        Returns (topic, raw_bytes or None).
        Known forms:
          - KnowledgePacket-like: .topic and .payload dict containing 'raw'|'bytes'|'data'
          - Scapy Packet: bytes(pkt) if scapy is installed; otherwise ignored
          - dict: {'raw'|'bytes'|'data': bytes|bytearray|memoryview|str}
          - bytes/bytearray/memoryview/str: direct, topic='default'
        """
        # KnowledgePacket-like
        if hasattr(pkt, "payload"):
            topic = getattr(pkt, "topic", "default") or "default"
            pl = getattr(pkt, "payload", None)
            if isinstance(pl, Mapping):
                for k in ("raw", "bytes", "data"):
                    if k in pl:
                        val = pl[k]
                        if isinstance(val, str):
                            return topic, val.encode("utf-8", errors="replace")
                        if isinstance(val, (bytes, bytearray, memoryview)):
                            return topic, bytes(val if not isinstance(val, memoryview) else val.tobytes())
            return topic, None

        # Scapy Packet (duck-typed) — optional
        try:
            from scapy.packet import Packet as ScapyPacket  # type: ignore
            if isinstance(pkt, ScapyPacket):
                try:
                    return "default", bytes(pkt)
                except Exception:
                    return "default", None
        except Exception:
            pass

        # dict-like
        if isinstance(pkt, Mapping):
            for k in ("raw", "bytes", "data"):
                if k in pkt:
                    val = pkt[k]
                    if isinstance(val, str):
                        return "default", val.encode("utf-8", errors="replace")
                    if isinstance(val, (bytes, bytearray, memoryview)):
                        return "default", bytes(val if not isinstance(val, memoryview) else val.tobytes())
            return "default", None

        # raw buffers & strings
        if isinstance(pkt, str):
            return "default", pkt.encode("utf-8", errors="replace")
        if isinstance(pkt, (bytes, bytearray, memoryview)):
            return "default", bytes(pkt if not isinstance(pkt, memoryview) else pkt.tobytes())

        # unknown
        return "default", None

    # --------------------- Text mining ---------------------
    def _tokens_from_text(self, text: str) -> Iterable[str]:
        for t in self._TOKEN_RE.findall(text or ""):
            tl = t.lower()
            if tl not in self._STOPWORDS:
                yield tl

    def _signals_from_text(self, text: str) -> Tuple[List[str], List[str], List[int], List[str]]:
        ips = self._IP_RE.findall(text or "") or []
        macs = [m.lower() for m in self._MAC_RE.findall(text or "")] or []
        ports: List[int] = []
        for m in self._PORT_RE.finditer(text or ""):
            try:
                p = int(m.group(1))
                if 0 < p < 65536:
                    ports.append(p)
            except Exception:
                pass
        protos = [m.group(1).lower() for m in self._PROTO_RE.finditer(text or "")]
        return ips, macs, ports, protos

    def _bump_hist(self, topic: str, length: int) -> None:
        hist = self._hist[topic]
        for i, b in enumerate(self.DEFAULT_BINS):
            if length <= b:
                hist[i] += 1
                return
        hist[-1] += 1

    # --------------------- Snapshots ---------------------
    def snapshot_vocab(self, topic: Optional[str] = None, top_k: int = 20) -> List[Tuple[str, int]]:
        with self._lock:
            if topic is not None:
                v = self._vocab.get(topic, {})
                return sorted(v.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
            merged: Dict[str, int] = defaultdict(int)
            for v in self._vocab.values():
                for k, c in v.items():
                    merged[k] += c
            return sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:top_k]

    def snapshot_categoricals(self, topic: str, top_k: int = 10) -> Dict[str, List[Tuple[str, int]]]:
        with self._lock:
            cats = self._cats.get(topic, {})
            return {
                k: cats.get(k, Counter()).most_common(top_k)
                for k in ("ip", "mac", "port", "proto")
            }

    def snapshot_numeric(self, topic: str) -> Dict[str, Dict[str, float]]:
        with self._lock:
            ns = self._num.get(topic, {})
            out: Dict[str, Dict[str, float]] = {}
            for k, st in ns.items():
                out[k] = {"n": st.n, "mean": st.mean, "std": st.std(), "min": st.min, "max": st.max}
            return out

    def snapshot_histogram(self, topic: str) -> List[Tuple[int, int]]:
        with self._lock:
            hist = list(self._hist.get(topic, []))
        return list(zip(self.DEFAULT_BINS, hist))

    def snapshot_rate(self, topic: str) -> Dict[str, float]:
        with self._lock:
            mean = self._rate_mean[topic].mean
            std = self._rate_std[topic].std()
            cur = self._rate[topic].value
        return {"current_rps": cur, "mean_rps": mean, "std_rps": std}

    def snapshot_raw(self, topic: str, limit: int = 10) -> List[str]:
        """Return recent decoded raw samples (bounded ring)."""
        if not self.keep_raw_samples:
            return []
        with self._lock:
            dq = self._raw_samples.get(topic, deque())
            return list(list(dq)[-max(0, int(limit)):])

    # --------------------- Persistence ---------------------
    def save_state(self, *, persist_raw: bool = False) -> Dict[str, Any]:
        with self._lock:
            state: Dict[str, Any] = {
                "vocab": {t: dict(v) for t, v in self._vocab.items()},
                "cats": {t: {k: dict(c) for k, c in cats.items()} for t, cats in self._cats.items()},
                "num": {
                    t: {k: {"n": st.n, "mean": st.mean, "M2": st.M2, "min": st.min, "max": st.max}
                        for k, st in stats.items()}
                    for t, stats in self._num.items()
                },
                "hist": {t: list(h) for t, h in self._hist.items()},
                "rate": {t: {"value": ew.value, "last_t": ew.last_t} for t, ew in self._rate.items()},
                "rate_mean": {t: {"n": s.n, "mean": s.mean, "M2": s.M2, "min": s.min, "max": s.max} for t, s in self._rate_mean.items()},
                "rate_std":  {t: {"n": s.n, "mean": s.mean, "M2": s.M2, "min": s.min, "max": s.max} for t, s in self._rate_std.items()},
            }
            if persist_raw and self.keep_raw_samples:
                state["raw_samples"] = {t: list(dq) for t, dq in self._raw_samples.items()}
            return state

    def load_state(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            self._vocab = defaultdict(dict, {t: dict(v) for t, v in state.get("vocab", {}).items()})
            self._cats = defaultdict(lambda: {"ip": Counter(), "mac": Counter(), "port": Counter(), "proto": Counter()})
            for t, cats in state.get("cats", {}).items():
                self._cats[t] = {k: Counter(v) for k, v in cats.items()}

            self._num = defaultdict(lambda: {"length": self._OnlineStats(), "entropy": self._OnlineStats()})
            for t, stats in state.get("num", {}).items():
                inner: Dict[str, PacketLearnerManager._OnlineStats] = {}
                for k, d in stats.items():
                    st = self._OnlineStats(
                        n=int(d.get("n", 0)),
                        mean=float(d.get("mean", 0.0)),
                        M2=float(d.get("M2", 0.0)),
                        min=float(d.get("min", float("inf"))),
                        max=float(d.get("max", float("-inf"))),
                    )
                    inner[k] = st
                self._num[t] = inner

            self._hist = defaultdict(lambda: [0]*len(self.DEFAULT_BINS),
                                     {t: list(h) for t, h in state.get("hist", {}).items()})

            self._rate.clear()
            for t, d in state.get("rate", {}).items():
                ew = self._EWMA(self.EWMA_ALPHA)
                ew.value = float(d.get("value", 0.0))
                ew.last_t = d.get("last_t", None)
                self._rate[t] = ew

            self._rate_mean.clear()
            for t, d in state.get("rate_mean", {}).items():
                self._rate_mean[t] = self._OnlineStats(
                    n=int(d.get("n", 0)),
                    mean=float(d.get("mean", 0.0)),
                    M2=float(d.get("M2", 0.0)),
                    min=float(d.get("min", float("inf"))),
                    max=float(d.get("max", float("-inf"))),
                )

            self._rate_std.clear()
            for t, d in state.get("rate_std", {}).items():
                self._rate_std[t] = self._OnlineStats(
                    n=int(d.get("n", 0)),
                    mean=float(d.get("mean", 0.0)),
                    M2=float(d.get("M2", 0.0)),
                    min=float(d.get("min", float("inf"))),
                    max=float(d.get("max", float("-inf"))),
                )

            raw_samples = state.get("raw_samples")
            self._raw_samples = defaultdict(lambda: deque(maxlen=self.max_samples_per_topic))
            if isinstance(raw_samples, Mapping):
                for t, arr in raw_samples.items():
                    dq: Deque[str] = deque(maxlen=self.max_samples_per_topic)
                    for s in arr or []:
                        if isinstance(s, str):
                            dq.append(s)
                    self._raw_samples[t] = dq

class AskManager:
    """
    Public API:
        ask(prompt: str) -> str

    Examples:
        mgr = AskManager()
        mgr.ask("inspect")              # redacted snapshot
        mgr.ask("inspect sensitive")    # UNREDACTED snapshot
        mgr.ask("sensitive dump")       # UNREDACTED snapshot
        mgr.ask("stats")                # pure-Python stats

    This version prioritizes token-first cleartext retrieval in _chat_generate().
    """

    # Redaction regexes (applied unless `sensitive` intent)
    _RE_IPv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
    _RE_MAC  = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
    _RE_SPI  = re.compile(r"\bspi=([0-9]{1,10})\b", re.IGNORECASE)
    _RE_HEX  = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
    _RE_KEY  = re.compile(r"(?:psk|key|secret|token|auth|cookie|session_id)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE)

    # Tokenizer for features & token-bank
    _TOKEN_RE = re.compile(r"[A-Za-z0-9_]+", re.UNICODE)

    def __init__(
        self,
        *,
        max_messages: int = 500,
        max_per_topic: int = 250,
        default_ttl: float = 180.0,
        rng_seed: Optional[int] = None,
        allow_sensitive_by_default: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        self._messages: Deque[Tuple[str, str]] = deque(maxlen=max_messages)
        self._knowledge_by_topic: Dict[str, Deque["KnowledgePacket"]] = defaultdict(
            lambda: deque(maxlen=max_per_topic)
        )
        self._default_ttl = float(default_ttl)
        self._stats = type("Stats", (), {"errors": 0, "asks": 0, "last_error": "", "last_ask_time": 0.0})()
        self._rng = random.Random(rng_seed if rng_seed is not None else os.getpid() ^ int(time.time()))
        self._allow_sensitive_by_default = bool(allow_sensitive_by_default)

        # Simple intent lexicon
        self._intent_map = {
            "purge": {"purge", "clear", "forget", "flush", "erase"},
            "inspect": {"inspect", "dump", "show", "summary", "summarize", "status"},
            "stats": {"stats", "statistics", "numbers", "metrics"},
            "emit": {"emit", "snapshot", "generate snapshot", "codegen"},
            "sensitive": {"sensitive", "unredacted", "no redaction", "full details", "raw"},
            "tokens": {"tokens", "token dump", "token lines"},
        }
        self._known_topics = {"tls", "dns", "dhcp", "router", "transport", "quic", "esp", "kerberos", "misc"}

        # ---------- Token bank (PRIORITY CONTEXT) ----------
        # token -> recent raw lines (user/assistant/system), unredacted; newest last
        self._token_bank: Dict[str, Deque[Tuple[str, str, float]]] = defaultdict(lambda: deque(maxlen=50000))

        # 2) add boilerplate detector
        self._BOILERPLATE_RE = re.compile(
            r"^(using token matches|pulled context|found relevant raw lines|here’s what i’m seeing|got it — here’s a quick take|alright, quick technical readout|okay, here’s the gist)",
            re.IGNORECASE,
        )
        self._max_raw_line_len = 2000  # cap per raw line stored
        self.ask_manager_chat_generator = AskManagerChatGenerator(token_store=self._token_bank, rng_seed=42)

    # ----------------- Public entrypoint -----------------

    def ask(self, prompt: str) -> str:
        """
        Single public entrypoint:
          - stores the user message (and indexes to token bank),
          - tiny intent detection,
          - separate handling for 'inspect' (redacted) vs 'sensitive' (unredacted),
          - token-first generation in _chat_generate(),
          - robust error handling.
        """
        with self._lock:
            self._stats.asks += 1
            self._stats.last_ask_time = time.time()

        prompt = (prompt or "").strip()
        if not prompt:
            return "Say something and I’ll analyze it."

        # Ingest message so it participates in learning (even if error later)
        self._submit_message(prompt, role="user")

        intent = self._infer_intent(prompt)

        try:
            if intent == "purge":
                topic = self._detect_topic_for_purge(prompt)
                n_removed = self._purge_topic(topic)
                reply = f"Purged topic '{topic}' (removed {n_removed} item{'s' if n_removed != 1 else ''})."

            elif intent == "inspect":
                # Always REDACTED
                snap = self._export_knowledge()
                reply = self._format_inspect_reply(
                    snap, max_topics=8, max_items_per_topic=6, max_payload_chars=1000, redact=True
                )

            elif intent == "sensitive":
                # Always UNREDACTED
                snap = self._export_knowledge()
                reply = self._format_inspect_reply(
                    snap, max_topics=8, max_items_per_topic=6, max_payload_chars=1000, redact=False
                )

            elif intent == "stats":
                stats = self._compute_statistics(
                    topics=[],  # all topics
                    percentiles=(5, 25, 50, 75, 95),
                    topk_categorical=8,
                    min_count_for_stats=2,
                )
                reply = (
                    self._format_stats_headlines(stats, limit=8)
                    if stats
                    else "No numeric feature has enough samples to compute stats yet."
                )

            elif intent == "emit":
                cfg = self._default_emit_builder()
                code = self._generate_class_from_config(cfg)
                self._submit_message("[snapshot emitted]", role="assistant")
                reply = f"Emitted snapshot class '{cfg.get('class_name')}' ({len(code)} bytes)."

            elif intent == "tokens":
                reply = self._raw_from_tokens(prompt, limit=12)

            else:
                # Retrieval (packet-based) is computed, but _chat_generate will try token bank first.
                retrieved = self._retrieve_snippets(prompt, topk=12, per_topic_limit=8)
                # default behavior for 'gen' keeps things redacted (safe)
                reply = self._chat_generate(prompt, retrieved, redact=True)

        except Exception as ex:
            with self._lock:
                self._stats.errors += 1
                self._stats.last_error = f"{type(ex).__name__}: {ex}"
            reply = f"Internal error while answering: {ex}"

        # Store and return assistant message (and index to token bank)
        self._submit_message(reply, role="assistant")
        return reply

    # ----------------- Inspect (redaction-aware) -----------------

    def _format_inspect_reply(
        self,
        snap: Dict[str, List[Dict[str, Any]]],
        *,
        max_topics: int = 8,
        max_items_per_topic: int = 6,
        max_payload_chars: int = 240,
        redact: bool = True,
    ) -> str:
        if not snap:
            return "I don’t have non-expired knowledge yet."

        header = "Knowledge snapshot (redacted):" if redact else "Knowledge snapshot (UNREDACTED):"
        lines: List[str] = [header]
        for topic, items in sorted(snap.items(), key=lambda kv: kv[0])[:max_topics]:
            lines.append(f"[{topic}] {len(items)} item(s)")
            # newest first
            ordered = sorted(items, key=lambda r: -r.get("age_sec", 0.0))[:max_items_per_topic]
            for i, row in enumerate(ordered, 1):
                age = row.get("age_sec", 0.0)
                tags = row.get("tags") or []
                imp = row.get("importance", 0)
                payload = row.get("payload") or {}

                common = self._format_common_net_fields(payload, redact=redact)
                preview = self._payload_to_text(payload, redact=redact, include_raw=not redact)
                if len(preview) > max_payload_chars:
                    preview = preview[: max_payload_chars - 3] + "..."

                lines.append(f"  {i}. age={age:.1f}s, importance={imp}, tags={tags[:6]}")
                if common:
                    lines.append(f"     net: {common}")
                lines.append(f"     payload: {preview}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _format_common_net_fields(self, payload: Dict[str, Any], *, redact: bool) -> str:
        def R(x: str) -> str:
            return self._redact_text(x) if redact else x

        parts = []
        for k in ("src_ip", "dst_ip", "client_ip", "server_ip", "ip"):
            if k in payload:
                parts.append(f"{k}={R(str(payload[k]))}")

        if "ips" in payload:
            parts.append("ips=[" + ", ".join(R(x) for x in payload["ips"][:8]) + "]")
        if "macs" in payload:
            parts.append("macs=[" + ", ".join(R(x) for x in payload["macs"][:8]) + "]")
        if "spis" in payload:
            parts.append("spis=[" + ", ".join(R(str(x)) for x in payload["spis"][:8]) + "]")

        for k in ("src_port", "dst_port", "port", "proto", "protocol", "spi"):
            if k in payload:
                parts.append(f"{k}={R(str(payload[k]))}")

        return " | ".join(parts)

    # ----------------- Core helpers -----------------
    def _is_boilerplate(self, s: str) -> bool:
        s = (s or "").strip()
        if not s:
            return True
        if self._BOILERPLATE_RE.match(s):
            return True
        # also ignore our standard tip
        if "ask ‘inspect sensitive’" in s.lower() or "ask 'inspect sensitive'" in s.lower():
            return True
        return False

    def _submit_message(self, text: str, *, role: str) -> None:
        role = "user" if role not in {"user", "assistant", "system"} else role
        with self._lock:
            self._messages.append((role, text))
        # index USER ONLY to avoid echo loops
        if role == "user":
            self._index_tokens(text, role=role)
        topic = self._guess_topic(text)
        pkt = KnowledgePacket(
            topic=topic,
            payload=self._extract_features(text),
            ttl=self._default_ttl,
            source=role,
            tags=self._infer_tags(text),
            importance=self._importance_score(text),
        )
        self._add_packet(pkt)
    def _infer_intent(self, prompt: str) -> str:
        p = prompt.lower().strip()
        if p in {"purge", "inspect", "stats", "emit", "sensitive", "tokens"}:
            return p
        for name, words in self._intent_map.items():
            if any(w in p for w in words):
                return name
        return "gen"

    def _detect_topic_for_purge(self, prompt: str) -> str:
        toks = self._tokenize(prompt)
        with self._lock:
            candidates = [t for t in toks if t in self._knowledge_by_topic]
        return candidates[0] if candidates else "misc"

    def _add_packet(self, pkt: "KnowledgePacket") -> None:
        now = time.time()
        with self._lock:
            dq = self._knowledge_by_topic[pkt.topic]
            dq.append(pkt)
            self._expire_topic_locked(pkt.topic, now)

    def _expire_topic_locked(self, topic: str, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        dq = self._knowledge_by_topic.get(topic)
        if not dq:
            return
        while dq and dq[0].is_expired(now):
            dq.popleft()

    def _purge_topic(self, topic: str) -> int:
        with self._lock:
            dq = self._knowledge_by_topic.get(topic)
            if not dq:
                return 0
            n = len(dq)
            dq.clear()
            return n

    def _export_knowledge(self) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        now = time.time()
        with self._lock:
            for topic, dq in self._knowledge_by_topic.items():
                items = []
                for pkt in list(dq):
                    if pkt.is_expired(now):
                        continue
                    items.append({
                        "source": pkt.source,
                        "tags": pkt.tags,
                        "importance": pkt.importance,
                        "payload": pkt.payload,
                        "ttl": pkt.ttl,
                        "age_sec": max(0.0, now - pkt.ts),
                    })
                if items:
                    out[topic] = items
        return out

    # ----------------- Retrieval & Generation -----------------

    def _retrieve_snippets(self, prompt: str, *, topk: int = 6, per_topic_limit: int = 3) -> List["KnowledgePacket"]:
        query_toks = set(self._tokenize(prompt))
        scored: List[Tuple[float, "KnowledgePacket"]] = []
        now = time.time()
        with self._lock:
            for topic, dq in self._knowledge_by_topic.items():
                self._expire_topic_locked(topic, now)
                if not dq:
                    continue
                topic_bonus = 0.5 if topic in query_toks else 0.0
                for pkt in list(dq)[-per_topic_limit:]:
                    if pkt.is_expired(now):
                        continue
                    payload_text = self._payload_to_text(pkt.payload, redact=True)  # score on redacted text
                    toks = set(self._tokenize(payload_text))
                    overlap = len(query_toks & toks)
                    recency = 1.0 / (1.0 + (now - pkt.ts) / 60.0)
                    imp = max(0, pkt.importance)
                    score = overlap + recency + (0.25 * imp) + topic_bonus
                    scored.append((score, pkt))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [pkt for _, pkt in scored[:topk]]

    # ---------- TOKEN-FIRST CHAT GENERATION ----------

    def _index_tokens(self, text: str, *, role: str) -> None:
        if not text:
            return
        # drop boilerplate-like content before tokenizing
        if self._is_boilerplate(text):
            return
        raw = text if len(text) <= self._max_raw_line_len else (text[: self._max_raw_line_len] + "...")
        ts = time.time()
        for tok in self._tokenize(text):
            if tok and not tok.isdigit():
                self._token_bank[tok].append((role, raw, ts))

    def _fetch_token_lines(self, query_toks: Iterable[str], *, per_token_limit: int = 6) -> List[str]:
        seen = set()
        out: List[str] = []
        for tok in query_toks:
            dq = self._token_bank.get(tok)
            if not dq:
                continue
            # newest-first from tail
            for role, line, _ts in list(dq)[-per_token_limit:][::-1]:
                if role != "user":
                    continue  # only user-originated lines
                if self._is_boilerplate(line):
                    continue
                if line in seen:
                    continue
                seen.add(line)
                out.append(line)
        return out

    def _raw_from_tokens(self, query: str, *, limit: int = 12) -> str:
        qtok = [t for t in self._tokenize(query) if t and not t.isdigit()]
        if not qtok:
            return "No tokens in query."
        lines = self._fetch_token_lines(qtok, per_token_limit=limit)
        if not lines:
            return "No raw lines matched those tokens yet."
        head = "Raw token matches (unredacted):"
        body = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(lines[:limit]))
        return f"{head}\n{body}"

    def _chat_generate(self, prompt: str, retrieved: List["KnowledgePacket"], *, redact: bool) -> str:
       return self.ask_manager_chat_generator._chat_generate(prompt, retrieved, redact=True)

    # ----------------- Stats (pure-Python) -----------------

    def _maybe_collect(
        self,
        num_vals: Dict[str, List[float]],
        cat_vals: Dict[str, Counter],
        feat: str,
        value: Any,
    ) -> None:
        MAX_NUM_PER_FEAT = 10000
        MAX_CAT_UNIQUE = 10000
        MAX_CAT_TOKEN_LEN = 64

        if value is None:
            return

        def _num_room() -> bool:
            return len(num_vals[feat]) < MAX_NUM_PER_FEAT

        def _cat_room() -> bool:
            return len(cat_vals[feat]) < MAX_CAT_UNIQUE

        if isinstance(value, bool):
            if _num_room(): num_vals[feat].append(1.0 if value else 0.0)
            if _cat_room(): cat_vals[feat].update([str(value)])
            return

        if isinstance(value, (int, float)) and self._is_finite_number(value):
            if _num_room(): num_vals[feat].append(float(value))
            return

        try:
            ts = getattr(value, "timestamp", None)
            if callable(ts):
                val = float(ts())
                if self._is_finite_number(val) and _num_room():
                    num_vals[feat].append(val)
                return
        except Exception:
            pass

        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                value = repr(value)

        if isinstance(value, str):
            s = value.strip()
            if not s:
                return
            s_plain = s.replace(",", "")
            is_percent = s_plain.endswith("%")
            s_num = s_plain[:-1].strip() if is_percent else s_plain

            if re.fullmatch(r"[+-]?((\d+(\.\d+)?)|(\.\d+))", s_num or ""):
                try:
                    val = float(s_num)
                    if is_percent: val /= 100.0
                    if self._is_finite_number(val) and _num_room():
                        num_vals[feat].append(val)
                        return
                except Exception:
                    pass

            if _cat_room():
                cat = " ".join(s.lower().split())
                if len(cat) > MAX_CAT_TOKEN_LEN: cat = cat[: MAX_CAT_TOKEN_LEN - 1] + "…"
                cat_vals[feat].update([cat])
            return

        if _cat_room():
            r = repr(value)
            if len(r) > MAX_CAT_TOKEN_LEN: r = r[: MAX_CAT_TOKEN_LEN - 1] + "…"
            cat_vals[feat].update([r])

    def _compute_statistics(
        self,
        *,
        topics: Iterable[str],
        percentiles: Tuple[int, ...] = (5, 25, 50, 75, 95),
        topk_categorical: int = 5,
        min_count_for_stats: int = 2,
    ) -> Dict[str, Dict[str, Any]]:
        now = time.time()
        with self._lock:
            topic_list = list(self._knowledge_by_topic.keys()) if not topics else list(topics)

        result: Dict[str, Dict[str, Any]] = {}
        for topic in topic_list:
            num_vals: Dict[str, List[float]] = defaultdict(list)
            cat_vals: Dict[str, Counter] = defaultdict(Counter)

            with self._lock:
                dq = self._knowledge_by_topic.get(topic)
                rows = [pkt for pkt in (list(dq) if dq else []) if not pkt.is_expired(now)]
            if not rows:
                continue

            for pkt in rows:
                pl = pkt.payload or {}
                for k, v in pl.items():
                    if isinstance(v, dict):
                        for kk, vv in v.items():
                            self._maybe_collect(num_vals, cat_vals, f"{k}.{kk}", vv)
                    elif isinstance(v, (list, tuple)):
                        for idx, vv in enumerate(v[:8]):
                            self._maybe_collect(num_vals, cat_vals, f"{k}[{idx}]", vv)
                    else:
                        self._maybe_collect(num_vals, cat_vals, k, v)

            numeric_stats: Dict[str, Any] = {}
            for feat, vals in num_vals.items():
                clean = [float(x) for x in vals if self._is_finite_number(x)]
                if len(clean) < min_count_for_stats:
                    continue
                n = len(clean)
                s = sum(clean)
                mu = s / n
                std = math.sqrt(sum((x - mu) ** 2 for x in clean) / (n - 1)) if n > 1 else 0.0
                numeric_stats[feat] = {
                    "count": n,
                    "mean": mu,
                    "std": std,
                    "min": min(clean),
                    "max": max(clean),
                    **self._percentiles_py(clean, percentiles),
                }

            categorical_stats: Dict[str, Any] = {}
            for feat, counter in cat_vals.items():
                if not counter:
                    continue
                categorical_stats[feat] = {"top": counter.most_common(topk_categorical), "unique": len(counter)}

            if numeric_stats or categorical_stats:
                result[topic] = {"numeric": numeric_stats, "categorical": categorical_stats}
        return result

    def _format_stats_headlines(self, stats: Dict[str, Dict[str, Any]], *, limit: int = 8) -> str:
        lines = ["Statistics (headlines):"]
        shown = 0
        for topic, blocks in stats.items():
            for feat, fs in (blocks.get("numeric") or {}).items():
                try:
                    lines.append(f"• [{topic}.{feat}] count={fs.get('count')} mean={fs.get('mean'):.3g} std={fs.get('std'):.3g}")
                    shown += 1
                except Exception:
                    continue
                if shown >= limit:
                    break
            if shown >= limit:
                break
        return "\n".join(lines) if shown else "No numeric feature has enough samples to compute stats yet."

    # ----------------- Feature extraction & utilities -----------------

    def _extract_features(self, text: str) -> Dict[str, Any]:
        toks = self._tokenize(text)
        numeric = [self._safe_float(tok) for tok in toks]
        numeric = [x for x in numeric if x is not None]

        features = {
            "summary": self._summarize_text(text, max_len=160),
            "length": len(text),
            "digits.count": sum(ch.isdigit() for ch in text),
            "keywords": list(self._top_keywords(toks, k=10)),
            "numeric.values": numeric[:8],
            "attributes": {"uppercase_ratio": self._uppercase_ratio(text)},
            "methods": {"has_question": "?" in text, "has_code_block": "```" in text or "    " in text},
        }
        # raw + extracted sensitive tokens
        features["raw_text"] = text if len(text) <= 2000 else (text[:2000] + "...")
        features.update(self._gather_sensitive_tokens(text))
        return features

    def _gather_sensitive_tokens(self, text: str) -> Dict[str, Any]:
        ips = self._RE_IPv4.findall(text) or []
        macs = self._RE_MAC.findall(text) or []
        spis = [m.group(1) if m.lastindex else m.group(0) for m in self._RE_SPI.finditer(text)]
        hexs = self._RE_HEX.findall(text) or []
        keys = [m.group(1) for m in self._RE_KEY.finditer(text)]
        out: Dict[str, Any] = {}
        if ips:  out["ips"] = ips
        if macs: out["macs"] = macs
        if spis: out["spis"] = spis
        if hexs: out["hex_tokens"] = hexs
        if keys: out["keys"] = keys
        return out

    def _infer_tags(self, text: str) -> List[str]:
        tags = []
        l = text.lower()
        for tag in ("error", "fix", "bug", "design", "code", "stats", "emit", "purge", "inspect", "sensitive"):
            if tag in l: tags.append(tag)
        for t in ("tls", "dns", "dhcp", "quic", "esp", "kerberos"):
            if t in l: tags.append(t)
        return tags[:8]

    def _importance_score(self, text: str) -> int:
        score = 0
        l = text.lower()
        score += min(5, len(text) // 120)
        if "```" in text or "class " in l or "def " in l: score += 2
        if any(t in l for t in self._known_topics): score += 1
        return min(score, 9)

    def _guess_topic(self, text: str) -> str:
        toks = set(self._tokenize(text))
        for t in sorted(self._known_topics):
            if t in toks:
                return t
        return "misc"

    def _tokenize(self, text: str) -> List[str]:
        toks = [t.lower() for t in self._TOKEN_RE.findall(text or "")]
        out = []
        for t in toks:
            t = re.sub(r"_+", "_", t).strip("_")
            if t: out.append(t)
        return out

    def _payload_to_text(self, payload: Dict[str, Any], *, redact: bool = False, include_raw: bool = False) -> str:
        parts = []
        for k, v in (payload or {}).items():
            if k == "raw_text" and not include_raw:
                continue
            if isinstance(v, dict):
                pv = ",".join(f"{kk}={v[kk]}" for kk in list(v)[:4])
            elif isinstance(v, (list, tuple, set)):
                pv = ",".join(map(str, list(v)[:6]))
            else:
                pv = str(v)
            if redact:
                pv = self._redact_text(pv)
            parts.append(f"{k}:{pv if len(pv) <= 80 else pv[:77] + '...'}")
        return " ".join(parts)

    def _redact_text(self, s: str) -> str:
        out = s
        out = self._RE_IPv4.sub("[IP]", out)
        out = self._RE_MAC.sub("[MAC]", out)
        out = self._RE_SPI.sub("spi=[SPI]", out)
        out = self._RE_HEX.sub("[HEX]", out)
        out = self._RE_KEY.sub(lambda m: m.group(0).split(m.group(1))[0] + "[SECRET]", out)
        return out

    def _uppercase_ratio(self, text: str) -> float:
        if not text: return 0.0
        upp = sum(1 for ch in text if ch.isupper())
        letters = sum(1 for ch in text if ch.isalpha())
        return upp / letters if letters else 0.0

    def _summarize_text(self, text: str, *, max_len: int = 160) -> str:
        text = (text or "").strip()
        if len(text) <= max_len: return text
        cut = text[:max_len]
        cut = re.sub(r"\s+\S*$", "", cut).rstrip(",.;:-")
        return cut + "..."

    def _safe_float(self, token: str) -> Optional[float]:
        try:
            if re.fullmatch(r"[+-]?\d+(\.\d+)?", token):
                return float(token)
        except Exception:
            return None
        return None

    def _top_keywords(self, toks: Iterable[str], k: int = 10) -> Iterable[str]:
        c = Counter(t for t in toks if len(t) >= 3)
        for w, _ in c.most_common(k):
            yield w

    def _is_finite_number(self, v: Any) -> bool:
        try:
            x = float(v)
            return math.isfinite(x)
        except Exception:
            return False

    def _percentiles_py(self, values: List[float], pcts: Iterable[int]) -> Dict[str, float]:
        if not values:
            return {f"p{p}": math.nan for p in pcts}
        arr = sorted(values)
        n = len(arr)
        out = {}
        for p in pcts:
            if n == 1:
                out[f"p{p}"] = arr[0]
            else:
                rank = (p / 100) * (n - 1)
                lo = int(math.floor(rank))
                hi = int(math.ceil(rank))
                if lo == hi:
                    out[f"p{p}"] = arr[lo]
                else:
                    frac = rank - lo
                    out[f"p{p}"] = arr[lo] * (1 - frac) + arr[hi] * frac
        return out

    def _actionable_tip(self, prompt: str, topic: str) -> str:
        if topic == "dns":
            return "Tip: Capture both the query and retries; high RTTs or NXDOMAIN spikes can look like timeouts."
        if topic == "tls":
            return "Tip: Track ClientHello SNI and JA3/JA4 fingerprints to correlate flows without decryption."
        if topic == "esp":
            return "Tip: With IPsec/ESP over UDP/4500, watch NAT-T keepalives and SPI churn if tunnels flap."
        if topic == "router":
            return "Tip: Validate L2/L3 with a minimal synthetic path before enabling advanced managers."
        return "If you want, ask ‘inspect sensitive’ to see unredacted details."

    # ----------------- Emit/codegen (toy) -----------------

    def _default_emit_builder(self) -> Dict[str, Any]:
        return {
            "class_name": "SnapshotModel",
            "fields": {"ts": "float", "topic": "str", "payload": "dict", "tags": "list", "importance": "int"},
            "doc": "Auto-emitted snapshot model (toy example).",
        }

    def _generate_class_from_config(self, cfg: Dict[str, Any]) -> str:
        name = cfg.get("class_name", "SnapshotModel")
        fields: Dict[str, str] = cfg.get("fields", {})
        doc = cfg.get("doc", "")
        need_field_import = any(v in {"dict", "list"} for v in fields.values())
        lines = []
        if need_field_import:
            lines.append("from dataclasses import dataclass, field")
        else:
            lines.append("from dataclasses import dataclass")
        lines.append("from typing import Any, Dict, List, Optional")
        lines.append("")
        lines.append("@dataclass")
        lines.append(f"class {name}:")
        if doc:
            lines.append(f'    """{doc}"""')
        if not fields:
            lines.append("    pass")
        else:
            for k, v in fields.items():
                default = "0.0" if v == "float" else ("0" if v == "int" else ("None" if v == "Optional[Any]" else "None"))
                if v == "dict": default = "field(default_factory=dict)"
                if v == "list": default = "field(default_factory=list)"
                lines.append(f"    {k}: {v} = {default}")
        return "\n".join(lines)

class AskManagerChatGenerator:
    """
    A focused helper around chat generation that:
      - tokenizes queries
      - fetches lines by tokens from a pluggable token store
      - redacts sensitive bits (IPs, MACs, emails, keys)
      - guesses topic heuristically
      - emits short actionable tips per topic
    """

    # Default openers / phrases (extend freely)
    OPENERS_TOKEN = [
        "Using token matches from history:",
        "Pulled context from your recent tokens:",
        "Found relevant raw lines via tokens:",
    ]
    OPENERS_HINTS = [
        "Here’s what I’m seeing.",
        "Got it — here’s a quick take.",
        "Alright, quick technical readout:",
        "Okay, here’s the gist:",
    ]

    # Simple topic dictionary -> tip templates
    TOPIC_TIPS = {
        "dns": "If you’re debugging DNS, capture both query and response and compare TXID; also check for EDNS(0) and truncation.",
        "dhcp": "For DHCP issues, compare Discover/Offer/Request/Ack and ensure the relay (giaddr) and option 82 are consistent.",
        "tls": "For TLS, verify the SNI and ALPN; mismatches or version intolerance often hint at middlebox interference.",
        "esp": "For IPsec ESP over UDP/4500, confirm NAT-T keepalives and SPI mapping on both ends.",
        "quic": "QUIC oddities? Confirm version negotiation and retry; track by 5-tuple plus DCID.",
        "kerberos": "Kerberos: confirm clock skew (<5 minutes), and watch AS-REQ/TGS-REQ error codes for hints.",
        "router": "Router path: check ARP/ND cache, RIB vs FIB, then NAT and firewall counters.",
        "default": "Try to reproduce with a minimal path; capture both directions and compare sequence/state transitions.",
    }

    # Redaction regexes (ordered)
    DEFAULT_REDACTIONS: List[Tuple[re.Pattern, str]] = [
        # IPv4
        (re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|$)){4}\b"), "<IP4>"),
        # IPv6 (very permissive)
        (re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b"), "<IP6>"),
        # MAC
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<MAC>"),
        # Emails
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<EMAIL>"),
        # Keys / secrets-ish (very rough)
        (re.compile(r"\b(sk|pk|key|secret|token|bearer)[=:]\s*[A-Za-z0-9_\-+/=]{12,}\b", re.I), r"\1:<SECRET>"),
    ]

    # Basic tokenization pattern (words, hex-like, dotted labels)
    TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_./:-]+")

    def __init__(
        self,
        token_store: Optional[Callable[[str, int], Sequence[str]]] = None,
        *,
        per_token_limit: int = 6,
        max_token_lines: int = 8,
        max_hint_lines: int = 8,
        rng_seed: Optional[int] = None,
        redactions: Optional[List[Tuple[re.Pattern, str]]] = None,
    ) -> None:
        """
        Args:
          token_store: callable(token: str, limit: int) -> Sequence[str]
                       Return raw lines associated with a token. Required for token path.
          per_token_limit: max lines to fetch per token.
          max_token_lines: max lines to include from token-based path.
          max_hint_lines: max hint lines from packets.
          rng_seed: seed for deterministic opener selection (tests).
          redactions: optional custom redaction patterns (pattern, replacement).
        """
        self._token_store = token_store
        self._per_token_limit = int(per_token_limit)
        self._max_token_lines = int(max_token_lines)
        self._max_hint_lines = int(max_hint_lines)
        self._rng = random.Random(rng_seed)
        self._redactions = redactions or list(self.DEFAULT_REDACTIONS)

    # --- Public entry point (your original function, now a method) -----------------

    def _chat_generate(
        self,
        prompt: str,
        retrieved: List["KnowledgePacket"],
        *,
        redact: bool,
    ) -> str:
        """
        Prioritize token-bank cleartext first; if nothing is found, fall back
        to packet-snippet hints.
        """
        # 1) Token-first path (UNREDACTED lines; redact at presentation if needed)
        q_toks = [t for t in self._tokenize(prompt) if t and not t.isdigit()]
        token_lines = self._fetch_token_lines(q_toks, per_token_limit=self._per_token_limit)

        if token_lines:
            def R(s: str) -> str:
                return self._redact_text(s) if redact else s

            opener = self._rng.choice(self.OPENERS_TOKEN)
            lines = [opener]
            for i, s in enumerate(token_lines[: self._max_token_lines], 1):
                s = R(self._clip(s, 240))
                lines.append(f"• {s}")
            lines.append("")
            topic = self._guess_topic(prompt)
            lines.append(self._actionable_tip(prompt, topic))
            return "\n".join(lines)

        # 2) Fallback: packet-based hints (redacted by default)
        topic = self._guess_topic(prompt)
        hints = self._collect_packet_hints(retrieved, redact=redact)

        opener = self._rng.choice(self.OPENERS_HINTS)
        lines = [opener]
        if hints:
            lines.append(f"Topic guess: {topic}")
            lines.append("Relevant bits I can use:")
            lines += [f"• {h}" for h in hints[: self._max_hint_lines]]
            lines.append("")
        lines.append(self._actionable_tip(prompt, topic))
        return "\n".join(lines)

    # --- Helpers ---------------------------------------------------------------

    def _tokenize(self, text: str) -> List[str]:
        """Lightweight tokenizer that keeps protocol-ish tokens (dns, tls1.3, 192.168.0.1, etc.)."""
        return self.TOKEN_PATTERN.findall(text.lower())

    def _fetch_token_lines(self, tokens: Iterable[str], *, per_token_limit: int) -> List[str]:
        """
        Fetch lines from the token store and deduplicate while preserving order.
        Most-repeated tokens are queried first to bias toward salient terms.
        """
        if not self._token_store:
            return []

        # Count frequency to prioritize
        freq = Counter(tokens)
        ordered_tokens = [t for t, _ in freq.most_common()]

        seen = set()
        out: List[str] = []
        for tok in ordered_tokens:
            try:
                candidates = self._token_store(tok, per_token_limit) or []
            except Exception:
                # Token store is user-provided; be defensive
                candidates = []
            for line in candidates:
                if not line or line in seen:
                    continue
                seen.add(line)
                out.append(line)
                if len(out) >= self._max_token_lines:
                    return out
        return out

    def _collect_packet_hints(self, retrieved: List["KnowledgePacket"], *, redact: bool) -> List[str]:
        """Extract short, readable hints from retrieved packets."""
        hints: List[str] = []
        for pkt in retrieved or []:
            payload = pkt.payload or {}
            for k in ("summary", "attributes", "methods", "keywords"):
                v = payload.get(k)
                if not v:
                    continue
                if isinstance(v, dict):
                    keys = list(v)[:4]
                    hints.append(self._maybe_redact(f"{k}: {', '.join(map(str, keys))}", redact))
                elif isinstance(v, (list, tuple, set)):
                    vals = list(v)[:6]
                    hints.append(self._maybe_redact(f"{k}: {', '.join(map(str, vals))}", redact))
                elif isinstance(v, str):
                    s = v.strip()
                    s = self._clip(s, 160)
                    hints.append(self._maybe_redact(f"{k}: {s}", redact))
        return hints

    def _maybe_redact(self, s: str, redact: bool) -> str:
        return self._redact_text(s) if redact else s

    def _redact_text(self, s: str) -> str:
        """Apply all redaction patterns in sequence."""
        out = s
        for pat, repl in self._redactions:
            out = pat.sub(repl, out)
        return out

    def _guess_topic(self, text: str) -> str:
        """
        Heuristic topic guesser. Extend this as you see fit.
        """
        t = text.lower()

        def has(*words: str) -> bool:
            return any(w in t for w in words)

        if has("dns", "resolver", "edns", "rr", "nslookup", "bind"):
            return "dns"
        if has("dhcp", "lease", "offer", "discover", "option 82"):
            return "dhcp"
        if has("tls", "alpn", "sni", "handshake", "cipher", "quic-tls"):
            return "tls"
        if has("esp", "ipsec", "spi", "nat-t", "ike", "isakmp"):
            return "esp"
        if has("quic", "http/3", "hq-interop", "dcid", "scid"):
            return "quic"
        if has("krb", "kerberos", "as-req", "tgs-req", "kdc"):
            return "kerberos"
        if has("route", "rib", "fib", "bgp", "ospf", "rip"):
            return "router"
        return "default"

    def _actionable_tip(self, prompt: str, topic: str) -> str:
        """Return a short, concrete next step per topic."""
        tip = self.TOPIC_TIPS.get(topic) or self.TOPIC_TIPS["default"]
        return f"Next step: {tip}"

    @staticmethod
    def _clip(s: str, max_len: int) -> str:
        if len(s) <= max_len:
            return s
        return s[: max_len - 3] + "..."

    # --- Optional extension points --------------------------------------------

    def set_token_store(self, token_store: Callable[[str, int], Sequence[str]]) -> None:
        """Swap in a different token store at runtime."""
        self._token_store = token_store

    def add_redaction(self, pattern: Union[str, re.Pattern], replacement: str) -> None:
        """Append a redaction rule."""
        pat = re.compile(pattern) if isinstance(pattern, str) else pattern
        self._redactions.append((pat, replacement))

    def set_rng_seed(self, seed: Optional[int]) -> None:
        """Set RNG seed for deterministic opener selection (tests)."""
        self._rng.seed(seed if seed is not None else random.randrange(1 << 30))