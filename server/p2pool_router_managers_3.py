import collections
import inspect
import json
import math
import queue
import random
import threading
import time
import re
import traceback
from collections import deque, defaultdict, Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Union, Tuple, Mapping, Iterator

# NumPy for analysis (only used during analysis; raw values stay as Python lists)
import numpy as np
import tiktoken


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
        self.chatgen = ChatGenManager(
            format_kv=lambda attrs, limit=8: self._format_kv(attrs, limit=8),
            history_getter=lambda: self._chat_history,
            persona=self._chat_persona,
            seed_corpus=self._chat_seed_corpus,
            max_chars=1000,
        )

        self.packet_learner = PacketLearnerManager(
            default_ttls={"kerberos": 180.0, "dns": 60.0},
            ttl_boost_factor=1.5,
            ttl_boost_threshold=20,
            logger=lambda s: print(s),
        )

        self.method_generator = SnapshotMethodGenerator()
        self.stats_manager = StatisticsManager()
        self.snapshot_builder = SnapshotBuilder(self._log)
        self.log_message("[CodeOutput] Manager initialized (drop-in, protocol-agnostic, NumPy stats ready).")

    def ask(self, prompt: str) -> str:
        """
        Chat-style interface:
          - stores the user message,
          - does tiny intent detection,
          - retrieves relevant transient knowledge,
          - answers in a friendly technical tone,
          - may call stats/snapshot paths when asked.
        """
        prompt = (prompt or "").strip()
        if not prompt:
            return "Say something and I’ll analyze it."

        # Ingest the message so it participates in learning
        self.submit_message(prompt, role="user")
        intent = self._infer_intent(prompt)

        try:
            if intent == "purge":
                # try to detect a topic to purge; fallback 'misc'
                toks = self._tokenize(prompt)
                candidates = [t for t in toks if t in self._knowledge_by_topic]
                topic = candidates[0] if candidates else "misc"
                n = self.purge_topic(topic)
                reply = f"Purged topic '{topic}' (removed {n} items)."
            elif intent == "inspect":
                snap = self.export_knowledge()
                if not snap:
                    reply = "I don’t have non-expired knowledge yet."
                else:
                    # Summarize compactly
                    parts = []
                    for t, arr in snap.items():
                        parts.append(f"[{t}] {len(arr)} item(s)")
                    reply = "Knowledge summary: " + ", ".join(parts)
            elif intent == "stats":
                # quick stats over all topics; reuse your manager
                stats = self._compute_statistics_with_numpy(
                    topics=[], percentiles=[5, 25, 50, 75, 95], topk_categorical=8, min_count_for_stats=2
                )
                if not stats:
                    reply = "No numeric feature has enough samples to compute stats yet."
                else:
                    # pick a few headline numbers
                    lines = ["Statistics (headlines):"]
                    shown = 0
                    for topic, blocks in stats.items():
                        num = blocks.get("numeric") or {}
                        for feat, fs in num.items():
                            lines.append(
                                f"• [{topic}.{feat}] count={fs.get('count')} mean={fs.get('mean'):.3g} std={fs.get('std'):.3g}")
                            shown += 1
                            if shown >= 8:
                                break
                        if shown >= 8:
                            break
                    reply = "\n".join(lines)
            elif intent == "emit":
                cfg = self._default_emit_builder()
                code = self.generate_class_from_config(cfg)
                # Store assistant reply
                self.submit_message("[snapshot emitted]", role="assistant")
                reply = f"Emitted snapshot class '{cfg.get('class_name')}' ({len(code)} bytes)."
            else:
                # 'gen' fallback: retrieval + tiny generation
                retrieved = self._retrieve_snippets(prompt)
                reply = self._chat_generate(prompt, retrieved)
        except Exception as ex:
            self._stats.errors += 1
            reply = f"Internal error while answering: {ex}"

        # Store and return assistant message
        self.submit_message(reply, role="assistant")
        return reply
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
                self._log(f"[CodeOutput] 🔁 {self.ask("Output some code")}")
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
    An advanced manager that builds a Python class by learning from observed
    code examples to procedurally generate new, descriptive docstrings.

    This class uses a NumPy-powered Markov Chain model to function like a
    mini "code chatbot," creating unique summaries for each generated snapshot.
    """

    def __init__(self, logger: Callable[[str, int], None]):
        self._log = logger
        self._markov_model: Dict[str, Dict[str, int]] = {}
        self._starters: List[str] = []

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
        # 1. Parse config and gather all knowledge
        class_name, base_attrs, base_methods, topics, policies = self._parse_config(config)
        merged_attrs, merged_methods = self._gather_and_merge_knowledge(
            knowledge_gatherer, base_attrs, base_methods, topics, policies
        )

        # 2. Learn from existing code to power the generator
        # We extract text from method bodies to learn from
        code_examples = [
            m.get("body") for m in knowledge_gatherer(topics=topics)[1].values()
            if isinstance(m.get("body"), str)
        ]
        self._train_generative_model(code_examples)

        # 3. Add insights, stats, and standard methods
        if policies.get("include_insights"):
            insights = insights_fetcher(topics=topics)
            if insights:
                merged_attrs["_insights"] = insights

        stats = {}
        if policies.get("include_statistics"):
            stats = stats_computer()
            if stats:
                merged_attrs["_statistics"] = stats

        merged_methods.update(method_generator(stats=stats))

        # 4. Use the generative model to write a unique class docstring
        generative_docstring = self._generate_text(max_length=20)

        # 5. Log and render the final class string with the new docstring
        self._log_summary(class_name, topics, merged_attrs, merged_methods, policies)
        return self._render_class(class_name, merged_attrs, merged_methods, generative_docstring)

    # --------------------------- Generative Model Methods ---------------------------

    def _train_generative_model(self, texts: List[str]):
        """Builds a word-level Markov Chain model from example code/text."""
        self._markov_model = {}
        self._starters = []
        if not texts:
            return

        for text in texts:
            words = text.strip().lower().split()
            if not words:
                continue

            self._starters.append(words[0])

            for i in range(len(words) - 1):
                current_word = words[i]
                next_word = words[i+1]

                if current_word not in self._markov_model:
                    self._markov_model[current_word] = {}

                transitions = self._markov_model[current_word]
                transitions[next_word] = transitions.get(next_word, 0) + 1

    def _generate_text(self, max_length: int = 15, seed_word: Optional[str] = None) -> str:
        """Generates a new text string using the trained probabilistic model."""
        if not self._markov_model:
            return "A generated class snapshot."

        # Choose a starting word
        if seed_word and seed_word in self._markov_model:
            current_word = seed_word
        elif self._starters:
            current_word = random.choice(self._starters)
        else:
            return "A generated class snapshot."

        sentence = [current_word.capitalize()]

        for _ in range(max_length - 1):
            if current_word not in self._markov_model:
                break

            # Use NumPy to probabilistically choose the next word
            next_word_options = self._markov_model[current_word]
            words = list(next_word_options.keys())
            counts = np.array(list(next_word_options.values()), dtype=np.float32)
            probabilities = counts / counts.sum()

            # The core of the generative logic
            next_word = np.random.choice(words, p=probabilities)

            sentence.append(next_word)
            current_word = next_word

        return " ".join(sentence) + "."

    # --------------------------- Private Helper Methods (Unchanged) ---------------------------

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

    def _gather_and_merge_knowledge(self, gatherer: Callable, base_attrs: Dict, base_methods: Dict, topics: List, policies: Dict) -> Tuple[Dict, Dict]:
        k_attrs, k_methods = gatherer(topics=topics)
        merged_attrs = {**base_attrs, **(k_attrs or {})}
        if policies["attr_policy"] == "override":
            merged_attrs = (k_attrs or {}) or base_attrs
        if policies["attr_aggregate"] == "list" and policies["listify_singletons"]:
            for k, v in list(merged_attrs.items()):
                if not isinstance(v, list):
                    merged_attrs[k] = [v]
        merged_methods = {**base_methods, **(k_methods or {})}
        if policies["method_policy"] == "override":
            merged_methods = (k_methods or {}) or base_methods
        return merged_attrs, merged_methods

    def _log_summary(self, name: str, topics: List, attrs: Dict, methods: Dict, policies: Dict):
        self._log(
            f"[CodeOutput] 🧠 Generating class '{name}' with a unique docstring, "
            f"attrs={len(attrs)}, methods={len(methods)}", 1
        )

    @staticmethod
    def _render_class(class_name: str, attributes: Dict, methods: Dict, doc: str) -> str:
        lines = [f"class {class_name}:", f'    """{doc}"""', "", "    def __init__(self):"]
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


class ChatGenManager:
    """
    Higher-order Markov generator with contextual backoff and multi-config,
    one-line renderings for each retrieved record. Each line uses a different
    style and a rotated subset of attributes to avoid repetition.
    """

    def __init__(
        self,
        format_kv: Callable[[Dict[str, Any]], str] | None,
        history_getter: Callable[[], Iterable[Dict[str, Any]]],
        persona: str = "Assistant",
        seed_corpus: Iterable[str] = (),
        max_chars: int = 250,
        max_history: int = 8,
        sample_len: int = 24,
        state_size: int = 2,  # 2-word context by default
        config_styles: tuple[str, ...] = ("kv", "yaml", "ini", "shell", "json"),
        preview_pairs: int = 8,        # how many k/v pairs per line
        per_line_char_max: int = 160,  # soft cap per rendered line
    ):
        self._format_kv = format_kv
        self._get_history = history_getter
        self._persona = persona
        self._seed_corpus = list(seed_corpus)
        self._max_chars = max_chars
        self._max_history = max_history
        self._sample_len = sample_len
        self._state_size = max(1, state_size)
        self._np_rng = np.random.default_rng()
        self._config_styles = config_styles or ("kv",)
        self._preview_pairs = max(1, preview_pairs)
        self._per_line_char_max = max(40, per_line_char_max)

    # ---------- Public ----------
    def generate(self, prompt: str, retrieved: List[Tuple[str, Dict[str, Any]]]) -> str:
        corpus = self._build_corpus()
        model, starters = self._train_markov(corpus)
        tail = self._sample(model, starters)
        text = self._stitch(retrieved, tail)
        return self._truncate(text, self._max_chars)

    # ---------- Helpers: corpus / model ----------
    def _build_corpus(self) -> List[str]:
        history = list(self._get_history())[-self._max_history:]
        lines = [h.get("text", "") for h in history if h.get("text")]
        lines.extend(self._seed_corpus)
        return lines

    def _train_markov(
        self, corpus: List[str]
    ) -> Tuple[Dict[Tuple[str, ...], Dict[str, int]], List[Tuple[str, ...]]]:
        model = collections.defaultdict(lambda: collections.defaultdict(int))
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
        return model, starters

    def _sample(
        self,
        model: Dict[Tuple[str, ...], Dict[str, int]],
        starters: List[Tuple[str, ...]],
    ) -> str:
        if not model:
            return random.choice(self._seed_corpus) if self._seed_corpus else "Acknowledged. I'm awaiting more data to analyze."

        current_state = random.choice(starters)
        words = list(current_state)

        for _ in range(self._sample_len - self._state_size):
            next_opts = model.get(current_state)
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
                current_state = random.choice(starters)

        sentence = " ".join(words).capitalize()
        if sentence and sentence[-1].isalnum():
            sentence += "."
        return sentence

    # ---------- Helpers: multi-config stitching ----------
    def _stitch(self, retrieved: List[Tuple[str, Dict[str, Any]]], tail: str) -> str:
        lines = [f"({self._persona})"]
        if retrieved:
            lines.append("Here’s what I’m seeing right now:")
            for i, (_topic, attrs) in enumerate(retrieved):
                style = self._config_styles[i % len(self._config_styles)]
                line = self._format_attrs_one_line(attrs, style, self._preview_pairs, line_index=i)
                lines.append(self._limit_line(line, self._per_line_char_max))
        else:
            lines.append("I don’t have fresh packets yet; I’ll reason from the prompt.")
        lines.append(tail)
        return "\n".join(lines)

    def _format_attrs_one_line(
        self,
        attrs: Mapping[str, Any],
        style: str,
        limit: int,
        line_index: int = 0,
    ) -> str:
        flat = self._flatten(attrs)
        pairs = self._select_pairs(flat, limit, line_index)

        if style == "kv":
            return ", ".join(f"{k}='{v}'" for k, v in pairs)
        elif style == "yaml":  # flow-style YAML on one line
            return "{ " + ", ".join(f"{k}: {self._yaml_scalar(v)}" for k, v in pairs) + " }"
        elif style == "ini":   # INI-ish inline
            return "; ".join(f"{k}={v}" for k, v in pairs)
        elif style == "shell": # shell env-style
            return " ".join(f"{k.upper()}={self._shell_quote(v)}" for k, v in pairs)
        elif style == "json":
            obj = {k: v for k, v in pairs}
            return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        elif style == "ext" and self._format_kv:
            # user-provided formatter if you want to plug your own
            return self._format_kv(dict(pairs))
        else:
            # fallback
            return ", ".join(f"{k}={v}" for k, v in pairs)

    # ---------- Helpers: attribute selection & formatting ----------
    def _flatten(self, obj: Any, prefix: str = "") -> List[Tuple[str, str]]:
        """
        Flattens nested mappings/lists into dot/bracket paths: a.b[0].c
        Converts values to compact strings.
        """
        out: List[Tuple[str, str]] = []
        if isinstance(obj, Mapping):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                out.extend(self._flatten(v, key))
        elif isinstance(obj, (list, tuple)):
            for i, v in enumerate(obj):
                key = f"{prefix}[{i}]"
                out.extend(self._flatten(v, key))
        else:
            # leaf
            sval = self._to_scalar(obj)
            if prefix:
                out.append((prefix, sval))
        return out

    def _to_scalar(self, v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, (int, float, bool)):
            return str(v).lower() if isinstance(v, bool) else str(v)
        s = str(v)
        # tiny compaction (e.g., long MAC/IP strings still visible but shorter)
        if len(s) > 64:
            s = s[:61] + "…"
        return s

    def _select_pairs(self, flat: List[Tuple[str, str]], limit: int, line_index: int) -> List[Tuple[str, str]]:
        """
        Deterministic rotation so each line gets a different slice of attributes:
        sort by key, then rotate by line_index, then take 'limit' pairs.
        """
        if not flat:
            return []
        flat_sorted = sorted(flat, key=lambda kv: kv[0])
        offset = line_index % len(flat_sorted)
        rotated = flat_sorted[offset:] + flat_sorted[:offset]
        return rotated[:limit]

    def _yaml_scalar(self, v: str) -> str:
        # quote only when necessary
        if not v or any(ch in v for ch in " \t,:{}[]#&*!|>'\"%@`"):
            return '"' + v.replace('"', '\\"') + '"'
        return v

    def _shell_quote(self, v: str) -> str:
        if v and v.isalnum():
            return v
        return "'" + v.replace("'", "'\\''") + "'"

    def _limit_line(self, s: str, maxlen: int) -> str:
        if len(s) <= maxlen:
            return s
        cut = s.rfind(" ", 0, maxlen - 1)
        if cut == -1 or cut < maxlen // 2:
            cut = maxlen - 1
        return s[:cut].rstrip() + "…"

    # ---------- Helpers: final truncation ----------
    def _truncate(self, s: str, maxlen: int) -> str:
        if len(s) <= maxlen:
            return s
        cut = s.rfind(" ", 0, maxlen - 1)
        if cut == -1 or cut < maxlen // 2:
            cut = maxlen - 1
        return s[:cut].rstrip() + "…"


class PacketLearnerManager:
    """
    Learns concept frequencies & structure from packet attributes and adjusts TTL.

    Additions over basic version:
      • Heuristic extraction of IP/MAC/ports/proto/VLAN/TTL/length.
      • Counters for categorical fields (ips, macs, ports, protos).
      • Online numeric stats for ttl/length.
      • Size histogram (power-of-two buckets).
      • Per-topic EWMA rate + spike detection (z-score).
      • Hot/cold TTL adjustment (boost on spikes/hot tokens, decay when cold).
      • Accepts KnowledgePacket OR raw Scapy Packet (duck-typed) OR plain dict.
      • Snapshot/restore of learned state.
    """

    class OnlineStats:
        """Welford online variance + min/max."""
        __slots__ = ("n", "mean", "M2", "min", "max")

        def __init__(self) -> None:
            self.n = 0;
            self.mean = 0.0;
            self.M2 = 0.0;
            self.min = float("inf");
            self.max = float("-inf")

        def add(self, x: float) -> None:
            self.n += 1
            delta = x - self.mean
            self.mean += delta / self.n
            self.M2 += delta * (x - self.mean)
            if x < self.min: self.min = x
            if x > self.max: self.max = x

        def std(self) -> float:
            return math.sqrt(self.M2 / (self.n - 1)) if self.n > 1 else 0.0

    class EWMA:
        """Exponentially weighted moving average of event rate (events/sec)."""
        __slots__ = ("alpha", "value", "last_t")

        def __init__(self, alpha: float = 0.3) -> None:
            self.alpha = float(alpha);
            self.value = 0.0;
            self.last_t = None

        def tick(self, now: float) -> float:
            if self.last_t is None:
                self.last_t = now;
                return self.value
            dt = max(1e-3, now - self.last_t)
            inst_rate = 1.0 / dt
            self.value = self.alpha * inst_rate + (1 - self.alpha) * self.value
            self.last_t = now
            return self.value
    # ---------------- Configuration ----------------
    DEFAULT_BASE_TTL = 120.0
    DEFAULT_TTL_BOOST_FACTOR = 1.5
    DEFAULT_TTL_BOOST_THRESHOLD = 20      # dominant token count
    DEFAULT_MAX_VOCAB_PER_TOPIC = 5000
    DEFAULT_DECAY_ON_OVERFLOW = 0.5
    DEFAULT_RATE_SPIKE_Z = 3.0            # z-score threshold for spikes
    DEFAULT_COLD_SECONDS = 180.0          # if no events > this, treat cold
    DEFAULT_MIN_TTL = 10.0
    DEFAULT_MAX_TTL_MULT = 3.0            # cap TTL at default * MAX_TTL_MULT
    DEFAULT_BINS = tuple(2**k for k in range(5, 17))  # 32..65536
    EWMA_ALPHA = 0.25

    _STOPWORDS = {
        "the","a","an","of","and","or","to","in","on","for","with","by","at","as",
        "is","are","was","were","be","been","being","this","that","these","those",
        "it","its","from","into","over","under","about","via","per","not","no",
    }
    _TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{1,31}")  # 2–32 chars, starts alpha
    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")

    def _now(self) -> float:
        return time.time()
    def __init__(
        self,
        *,
        default_ttls: Optional[Mapping[str, float]] = None,
        ttl_boost_factor: float = DEFAULT_TTL_BOOST_FACTOR,
        ttl_boost_threshold: int = DEFAULT_TTL_BOOST_THRESHOLD,
        max_vocab_per_topic: int = DEFAULT_MAX_VOCAB_PER_TOPIC,
        decay_on_overflow: float = DEFAULT_DECAY_ON_OVERFLOW,
        rate_spike_z: float = DEFAULT_RATE_SPIKE_Z,
        cold_seconds: float = DEFAULT_COLD_SECONDS,
        min_ttl: float = DEFAULT_MIN_TTL,
        max_ttl_mult: float = DEFAULT_MAX_TTL_MULT,
        logger: Optional[Callable[[str], None]] = None,
        log_level: int = 2,
    ) -> None:
        self.default_ttls: Dict[str, float] = dict(default_ttls or {})
        self.ttl_boost_factor = float(ttl_boost_factor)
        self.ttl_boost_threshold = int(ttl_boost_threshold)
        self.max_vocab_per_topic = int(max_vocab_per_topic)
        self.decay_on_overflow = float(decay_on_overflow)
        self.rate_spike_z = float(rate_spike_z)
        self.cold_seconds = float(cold_seconds)
        self.min_ttl = float(min_ttl)
        self.max_ttl_mult = float(max_ttl_mult)

        self._concept_counts: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._cat_counts: Dict[str, Dict[str, Counter]] = defaultdict(lambda: {
            "ip": Counter(), "mac": Counter(), "proto": Counter(), "port": Counter(), "vlan": Counter()
        })
        self._num_stats: Dict[str, Dict[str, PacketLearnerManager.OnlineStats]] = defaultdict(lambda: {
            "ttl": self.OnlineStats(), "length": self.OnlineStats()
        })
        self._size_hist: Dict[str, List[int]] = defaultdict(lambda: [0]*len(self.DEFAULT_BINS))
        self._rate: Dict[str, PacketLearnerManager.EWMA] = defaultdict(lambda: self.EWMA(self.EWMA_ALPHA))
        self._rate_mean_std: Dict[str, Tuple[PacketLearnerManager.OnlineStats, PacketLearnerManager.OnlineStats]] = defaultdict(lambda: (self.OnlineStats(), self.OnlineStats()))
        self._last_seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._logger = logger or (lambda s: None)
        self._log_level = log_level

    # --------------- Public API ----------------
    def learn_from_packet(self, pkt: Any) -> Any:
        """
        Accepts KnowledgePacket, Scapy Packet, or dict-like payload.
        Learns features and (if KnowledgePacket) may adjust pkt.ttl.
        Returns the same object for chaining.
        """
        topic, attrs, initial_ttl, is_kp = self._coerce_input(pkt)
        if not attrs:
            return pkt

        now = self._now()
        tokens = self._collect_tokens(attrs)
        signals = self._extract_signals(attrs)

        if not tokens and not any(signals.values()):
            return pkt

        with self._lock:
            # 1) token vocab
            cc = self._concept_counts[topic]
            self._update_counts(cc, tokens)
            self._maybe_compact_vocab(cc)
            dominant = max(cc.values()) if cc else 0

            # 2) categorical tallies
            self._update_categoricals(topic, signals)

            # 3) numeric stats & histograms
            self._update_numeric(topic, signals)
            self._update_histogram(topic, signals)

            # 4) rate tracking & spike detection
            rate = self._rate[topic].tick(now)
            mean_s, std_s = self._rate_mean_std[topic]
            mean_s.add(rate)
            std_s.add(rate)  # reuse container to track dispersion similarly
            z = 0.0
            if mean_s.n > 10 and std_s.std() > 1e-6:
                z = (rate - mean_s.mean) / std_s.std()

            # 5) TTL logic (KnowledgePacket only)
            if is_kp:
                default_ttl = float(self.default_ttls.get(topic, self.DEFAULT_BASE_TTL))
                old_ttl = float(initial_ttl if initial_ttl is not None else default_ttl)

                new_ttl = self._ttl_adjust(
                    current_ttl=old_ttl,
                    dominant=dominant,
                    default_ttl=default_ttl,
                    last_seen=self._last_seen.get(topic),
                    now=now,
                    spike_z=z,
                )
                if new_ttl != old_ttl:
                    try:
                        pkt.ttl = new_ttl
                    except Exception:
                        pass  # be defensive if caller object is immutable
                    self._log(
                        f"[PacketLearner] TTL {'boosted' if new_ttl>old_ttl else 'adjusted'} "
                        f"topic='{topic}' ({old_ttl:.1f} -> {new_ttl:.1f}); "
                        f"dominant={dominant}, rate={rate:.2f}/s z={z:.2f}", 2
                    )

            # 6) housekeeping
            self._last_seen[topic] = now

        return pkt

    # --------------- Input coercion ----------------
    def _coerce_input(self, pkt: Any) -> Tuple[str, Dict[str, Any], Optional[float], bool]:
        """
        Returns: (topic, attrs, ttl, is_knowledge_packet)
        Accepts:
          - KnowledgePacket: use pkt.topic, pkt.payload['attributes']
          - Scapy Packet: builds attributes from typical fields (best-effort)
          - dict: treat as {'attributes': {...}} or raw attrs mapping
        """
        # KnowledgePacket-like?
        topic = "default"
        ttl = None
        is_kp = False
        if hasattr(pkt, "topic") and hasattr(pkt, "payload"):
            is_kp = True
            topic = getattr(pkt, "topic", "default") or "default"
            ttl = getattr(pkt, "ttl", None)
            attrs = self._extract_attributes(getattr(pkt, "payload", None))
            return topic, attrs, ttl, True

        # Scapy Packet (duck-typed): use .fields / layers if present
        try:
            from scapy.packet import Packet as ScapyPacket  # type: ignore
            from scapy.layers.inet import IP, TCP, UDP  # type: ignore
            from scapy.layers.l2 import Ether, Dot1Q  # type: ignore
            is_scapy = isinstance(pkt, ScapyPacket)
        except Exception:
            is_scapy = False

        if is_scapy:
            attrs: Dict[str, Any] = {}
            try:
                if pkt.haslayer("Ether"):
                    eth = pkt.getlayer("Ether")
                    attrs["eth_src"] = getattr(eth, "src", None)
                    attrs["eth_dst"] = getattr(eth, "dst", None)
                if pkt.haslayer("Dot1Q"):
                    q = pkt.getlayer("Dot1Q")
                    attrs["vlan"] = getattr(q, "vlan", None)
                    attrs["vlan_prio"] = getattr(q, "prio", None)
                if pkt.haslayer("IP"):
                    ip = pkt.getlayer("IP")
                    attrs["saddr"] = getattr(ip, "src", None)
                    attrs["daddr"] = getattr(ip, "dst", None)
                    attrs["ttl"] = getattr(ip, "ttl", None)
                    attrs["length"] = getattr(ip, "len", None)
                if pkt.haslayer("TCP"):
                    tcp = pkt.getlayer("TCP")
                    attrs["proto"] = "tcp"
                    attrs["sport"] = getattr(tcp, "sport", None)
                    attrs["dport"] = getattr(tcp, "dport", None)
                elif pkt.haslayer("UDP"):
                    udp = pkt.getlayer("UDP")
                    attrs["proto"] = "udp"
                    attrs["sport"] = getattr(udp, "sport", None)
                    attrs["dport"] = getattr(udp, "dport", None)
            except Exception:
                pass
            return "default", {k: v for k, v in attrs.items() if v is not None}, None, False

        # dict-like
        if isinstance(pkt, Mapping):
            attrs = self._extract_attributes(pkt)
            return "default", attrs, None, False

        # fallback
        return "default", {}, None, False

    # --------------- Helpers: attributes & tokens ----------------
    def _extract_attributes(self, payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        if not isinstance(payload, Mapping):
            return {}
        attrs = payload.get("attributes") if isinstance(payload, Mapping) else None
        return attrs if isinstance(attrs, Mapping) else {}

    def _collect_tokens(self, attrs: Mapping[str, Any]) -> List[str]:
        tokens: List[str] = []
        # keys
        for k in attrs.keys():
            tokens.extend(self._tokenize(str(k)))
        # values (strings anywhere within nested structures)
        for s in self._iter_string_values(attrs):
            tokens.extend(self._tokenize(s))
        return tokens

    def _iter_string_values(self, obj: Any, _depth: int = 0, _max_depth: int = 3) -> Iterator[str]:
        if _depth > _max_depth:
            return
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, Mapping):
            for v in obj.values():
                yield from self._iter_string_values(v, _depth + 1, _max_depth)
        elif isinstance(obj, (list, tuple, set)):
            for v in obj:
                yield from self._iter_string_values(v, _depth + 1, _max_depth)

    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        toks = [t for t in self._TOKEN_RE.findall(text) if t not in self._STOPWORDS]
        return toks

    # --------------- Helpers: signals extraction ----------------
    def _extract_signals(self, attrs: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Pull common fields out of typical network attrs. Best-effort heuristics.
        """
        as_str = lambda k: str(attrs.get(k)) if attrs.get(k) is not None else ""
        sig: Dict[str, Any] = {
            "ips": [],
            "macs": [],
            "proto": None,
            "ports": [],
            "vlan": None,
            "ttl": None,
            "length": None,
        }

        # IPs
        for k in ("saddr","src","source","ip_src","daddr","dst","dest","ip_dst"):
            v = attrs.get(k)
            if isinstance(v, str):
                for ip in self._IP_RE.findall(v): sig["ips"].append(ip)

        # MACs
        for k in ("eth_src","ether_src","mac_src","eth_dst","ether_dst","mac_dst"):
            v = as_str(k)
            if v:
                for m in self._MAC_RE.findall(v): sig["macs"].append(m.lower())

        # Proto
        proto = attrs.get("proto") or attrs.get("l4_proto") or attrs.get("protocol")
        if isinstance(proto, str): sig["proto"] = proto.lower()
        elif isinstance(proto, int): sig["proto"] = str(proto)

        # Ports
        for k in ("sport","src_port","source_port","dport","dst_port","dest_port"):
            v = attrs.get(k)
            if isinstance(v, (int, str)) and str(v).isdigit():
                val = int(v)
                if 0 < val < 65536: sig["ports"].append(val)

        # VLAN
        vlan = attrs.get("vlan")
        if isinstance(vlan, int): sig["vlan"] = vlan

        # TTL & length
        ttl = attrs.get("ttl")
        if isinstance(ttl, int): sig["ttl"] = ttl
        length = attrs.get("length") or attrs.get("len") or attrs.get("payload_len")
        if isinstance(length, int): sig["length"] = length

        return sig

    # --------------- Helpers: counts & vocab mgmt ----------------
    def _update_counts(self, cc: Dict[str, int], tokens: Iterable[str]) -> None:
        for t in tokens:
            cc[t] = cc.get(t, 0) + 1

    def _maybe_compact_vocab(self, cc: Dict[str, int]) -> None:
        if len(cc) <= self.max_vocab_per_topic:
            return
        # Decay counts
        if 0.0 < self.decay_on_overflow < 1.0:
            for k in list(cc.keys()):
                cc[k] = max(1, int(cc[k] * self.decay_on_overflow))
        # Drop the tail if still too big
        if len(cc) > self.max_vocab_per_topic:
            items = sorted(cc.items(), key=lambda kv: kv[1], reverse=True)[: self.max_vocab_per_topic]
            cc.clear()
            cc.update(items)

    def _update_categoricals(self, topic: str, sig: Dict[str, Any]) -> None:
        cats = self._cat_counts[topic]
        for ip in sig.get("ips", []): cats["ip"][ip] += 1
        for mac in sig.get("macs", []): cats["mac"][mac] += 1
        if sig.get("proto"): cats["proto"][sig["proto"]] += 1
        for p in sig.get("ports", []): cats["port"][str(p)] += 1
        if sig.get("vlan") is not None: cats["vlan"][str(sig["vlan"])] += 1

    def _update_numeric(self, topic: str, sig: Dict[str, Any]) -> None:
        stats = self._num_stats[topic]
        if sig.get("ttl") is not None: stats["ttl"].add(float(sig["ttl"]))
        if sig.get("length") is not None: stats["length"].add(float(sig["length"]))

    def _update_histogram(self, topic: str, sig: Dict[str, Any]) -> None:
        length = sig.get("length")
        if length is None: return
        bins = self.DEFAULT_BINS
        hist = self._size_hist[topic]
        # place into first bucket >= length
        for i, b in enumerate(bins):
            if length <= b:
                hist[i] += 1
                return
        # overflow: ignore or extend (keep simple)
        hist[-1] += 1

    # --------------- Helpers: TTL logic ----------------
    def _ttl_adjust(
        self,
        *,
        current_ttl: float,
        dominant: int,
        default_ttl: float,
        last_seen: Optional[float],
        now: float,
        spike_z: float,
    ) -> float:
        limit = default_ttl * self.max_ttl_mult
        ttl = max(self.min_ttl, current_ttl)

        # Boost for hot tokens
        if dominant >= self.ttl_boost_threshold and ttl < default_ttl * self.ttl_boost_factor:
            ttl = min(limit, ttl * self.ttl_boost_factor)

        # Boost for spikes
        if spike_z >= self.rate_spike_z:
            ttl = min(limit, ttl * self.ttl_boost_factor)

        # Decay when cold (no events recently)
        if last_seen is not None and (now - last_seen) > self.cold_seconds:
            ttl = max(self.min_ttl, ttl / self.ttl_boost_factor)

        return ttl

    # --------------- Logging ----------------
    def _log(self, msg: str, level: int = 2) -> None:
        if self._log_level >= level:
            self._logger(msg)

    # --------------- Inspection APIs ----------------
    def snapshot_counts(self, topic: Optional[str] = None, top_k: int = 20) -> List[Tuple[str, int]]:
        with self._lock:
            if topic is not None:
                cc = self._concept_counts.get(topic, {})
                return sorted(cc.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
            merged: Dict[str, int] = defaultdict(int)
            for cc in self._concept_counts.values():
                for k, v in cc.items():
                    merged[k] += v
            return sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:top_k]

    def snapshot_categoricals(self, topic: str, top_k: int = 10) -> Dict[str, List[Tuple[str, int]]]:
        with self._lock:
            cats = self._cat_counts.get(topic, {})
            return {k: cats.get(k, Counter()).most_common(top_k) for k in ("ip","mac","proto","port","vlan")}

    def snapshot_numeric(self, topic: str) -> Dict[str, Dict[str, float]]:
        with self._lock:
            ns = self._num_stats.get(topic, {})
            out = {}
            for k, st in ns.items():
                out[k] = {"n": st.n, "mean": st.mean, "std": st.std(), "min": st.min, "max": st.max}
            return out

    def snapshot_histogram(self, topic: str) -> List[Tuple[int, int]]:
        """Return (upper_bound, count) pairs for size histogram."""
        with self._lock:
            hist = list(self._size_hist.get(topic, []))
        return list(zip(self.DEFAULT_BINS, hist))

    def save_state(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "concept_counts": {t: dict(cc) for t, cc in self._concept_counts.items()},
                "cat_counts": {t: {k: dict(v) for k, v in cats.items()} for t, cats in self._cat_counts.items()},
                "num_stats": {t: {k: {"n": st.n, "mean": st.mean, "M2": st.M2, "min": st.min, "max": st.max}
                                  for k, st in stats.items()} for t, stats in self._num_stats.items()},
                "size_hist": {t: list(h) for t, h in self._size_hist.items()},
                "rate": {t: {"value": ew.value, "last_t": ew.last_t} for t, ew in self._rate.items()},
                "last_seen": dict(self._last_seen),
            }

    def load_state(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            self._concept_counts.clear()
            for t, cc in state.get("concept_counts", {}).items():
                self._concept_counts[t] = dict(cc)

            self._cat_counts.clear()
            for t, cats in state.get("cat_counts", {}).items():
                self._cat_counts[t] = {k: Counter(v) for k, v in cats.items()}

            self._num_stats.clear()
            for t, stats in state.get("num_stats", {}).items():
                self._num_stats[t] = {}
                for k, d in stats.items():
                    st = self.OnlineStats()
                    st.n, st.mean, st.M2 = int(d.get("n", 0)), float(d.get("mean", 0.0)), float(d.get("M2", 0.0))
                    st.min, st.max = float(d.get("min", float("inf"))), float(d.get("max", float("-inf")))
                    self._num_stats[t][k] = st

            self._size_hist = defaultdict(lambda: [0]*len(self.DEFAULT_BINS),
                                          {t: list(h) for t, h in state.get("size_hist", {}).items()})
            self._rate.clear()
            for t, d in state.get("rate", {}).items():
                ew = self.EWMA(self.EWMA_ALPHA); ew.value = float(d.get("value", 0.0)); ew.last_t = d.get("last_t", None)
                self._rate[t] = ew

            self._last_seen = dict(state.get("last_seen", {}))