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
    - source: Optional string indicating where the packet originated (e.g., "bus/scapy", "user/chat").
    - tags: List of strings for additional categorization (e.g., ["alert", "critical"]).
    - importance: Integer score for ranking/prioritization.
    - ts: Timestamp of packet creation.
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


class PacketLearnerManager:
    # --------------------- Regexes & constants ---------------------
    _TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{1,31}", re.IGNORECASE)
    _STOPWORDS = {
        "the", "a", "an", "of", "and", "or", "to", "in", "on", "for", "with", "by", "at", "as",
        "is", "are", "was", "were", "be", "been", "being", "this", "that", "these", "those",
        "it", "its", "from", "into", "over", "under", "about", "via", "per", "not", "no",
    }

    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
    _PORT_RE = re.compile(r"\b(?:port|sport|dport|src_port|dst_port)\s*[:=]?\s*(\d{1,5})\b", re.IGNORECASE)
    # --- ADVANCED ---
    # Expanded regex to include protocols seen in your sample output (mDNS, LLMNR)
    # and other common ones (WireGuard).
    _PROTO_RE = re.compile(
        r"\b(tcp|udp|icmp|igmp|quic|tls|http|https|dns|dhcp|ssh|mdns|llmnr|wireguard)\b",
        re.IGNORECASE
    )
    _TLS_HS_TYPE_RE = re.compile(r"\b(ClientHello|ServerHello|Certificate|Finished)\b", re.IGNORECASE)
    _DNS_QUERY_RE = re.compile(r"\b(?:query|qname|qtype)\s*[:=]?\s*([\w\d\-\.]+)\b", re.IGNORECASE)

    DEFAULT_BINS = tuple(2 ** k for k in range(5, 17))  # 32..65536
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

        def z_score(self, x: float) -> float:
            """Calculates the Z-score of x against the current stats."""
            if self.n < 2:
                return 0.0
            stdev = self.std()
            if stdev < 1e-9:
                return 0.0  # Avoid division by zero for constant data
            return (x - self.mean) / stdev

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

    # --- ADVANCED ---
    # New inner class to track conversations
    @dataclass
    class _ConversationStats:
        """Tracks simple stats for a conversation (e.g., 5-tuple)."""
        key: str
        n: int = 0
        total_bytes: int = 0
        first_seen: float = field(default_factory=time.time)
        last_seen: float = field(default_factory=time.time)

        def add(self, length: int, now: float):
            self.n += 1
            self.total_bytes += length
            self.last_seen = now

    # --------------------- Static utilities ---------------------
    @staticmethod
    def _now() -> float:
        return time.time()

    @staticmethod
    def _safe_decode(buf: Union[bytes, bytearray, memoryview, str]) -> str:
        if isinstance(buf, str): return buf
        if isinstance(buf, memoryview): buf = buf.tobytes()
        try:
            return bytes(buf).decode("utf-8", errors="strict")
        except Exception:
            return bytes(buf).decode("latin-1", errors="replace")

    @staticmethod
    def _byte_entropy(b: bytes) -> float:
        if not b: return 0.0
        counts = [0] * 256
        for x in b: counts[x] += 1
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
            logger: Optional[Callable[[str, int], None]] = None,
            log_level: int = 1,
            # --- ADVANCED ---
            # New configuration parameters with defaults
            max_conversations_per_topic: int = 256,
            max_anomalies_per_topic: int = 100,
            recent_stats_window_sec: float = 60.0,
            recent_stats_max_samples: int = 1000,
    ) -> None:
        self.keep_raw_samples = bool(keep_raw_samples)
        self.max_samples_per_topic = int(max_samples_per_topic)
        self.max_sample_chars = int(max_sample_chars)
        self.spike_z_threshold = float(spike_z_threshold)
        self._logger = logger or (lambda s, l: None)
        self._log_level = int(log_level)

        # --- ADVANCED ---
        # New parameters
        self._max_conversations = int(max_conversations_per_topic)
        self._max_anomalies = int(max_anomalies_per_topic)
        self._recent_window_sec = float(recent_stats_window_sec)
        self._recent_max_samples = int(recent_stats_max_samples)

        # Learned state (Original)
        self._vocab: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._cats: Dict[str, Dict[str, Counter]] = defaultdict(lambda: {
            "ip": Counter(), "mac": Counter(), "port": Counter(), "proto": Counter(),
            "tls_hs_type": Counter(), "dns_query": Counter(), "tcp_flags": Counter()
        })
        self._num: Dict[str, Dict[str, PacketLearnerManager._OnlineStats]] = defaultdict(lambda: {
            "length": self._OnlineStats(), "entropy": self._OnlineStats()
        })
        self._hist: Dict[str, List[int]] = defaultdict(lambda: [0] * len(self.DEFAULT_BINS))
        self._rate: Dict[str, PacketLearnerManager._EWMA] = defaultdict(lambda: self._EWMA(self.EWMA_ALPHA))
        self._rate_mean: Dict[str, PacketLearnerManager._OnlineStats] = defaultdict(self._OnlineStats)
        self._rate_std: Dict[str, PacketLearnerManager._OnlineStats] = defaultdict(self._OnlineStats)
        self._raw_samples: Dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=self.max_samples_per_topic))
        self._tls_handshakes: Dict[str, Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=100))
        self._dns_queries: Dict[str, Deque[Tuple[float, str]]] = defaultdict(lambda: deque(maxlen=100))

        # --- ADVANCED ---
        # New state variables

        # Tracks conversations (e.g., 5-tuples)
        self._conversations: Dict[str, Dict[str, PacketLearnerManager._ConversationStats]] = defaultdict(dict)

        # Stores recent hashes to de-duplicate raw samples
        self._sample_hashes: Dict[str, Deque[int]] = defaultdict(lambda: deque(maxlen=self.max_samples_per_topic * 2))

        # Stores (ts, value) for recent numeric stats calculation
        self._recent_numeric_samples: Dict[str, Dict[str, Deque[Tuple[float, float]]]] = \
            defaultdict(lambda: defaultdict(lambda: deque(maxlen=self._recent_max_samples)))

        # Stores (ts, topic, rate, z_score)
        self._spike_events: Deque[Tuple[float, str, float, float]] = deque(maxlen=self._max_anomalies)

        # Stores (ts, topic, feature, value, z_score)
        self._numeric_anomalies: Deque[Tuple[float, str, str, float, float]] = deque(maxlen=self._max_anomalies)

        self._lock = threading.Lock()

    # --------------------- Public API (Original) ---------------------

    def learn_from_packet(self, pkt: KnowledgePacket) -> KnowledgePacket:
        topic = pkt.topic
        raw_bytes = self._extract_raw_bytes_from_payload(pkt.payload)
        raw_len = len(raw_bytes) if raw_bytes is not None else 0
        raw_text = self._safe_decode(raw_bytes) if raw_bytes is not None else ""

        tokens = list(self._tokens_from_text(raw_text))
        ips, macs, ports, protos, tls_hs_types, dns_queries, tcp_flags = self._signals_from_text(raw_text, pkt.payload)

        ent = self._byte_entropy(raw_bytes) if raw_bytes is not None else 0.0
        now = self._now()

        # --- ADVANCED ---
        # Get a stable conversation key
        convo_key = self._get_convo_key(ips, ports, protos)

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
            for hs_type in tls_hs_types: cats["tls_hs_type"][hs_type] += 1
            for query in dns_queries: cats["dns_query"][query] += 1
            for flag in tcp_flags: cats["tcp_flags"][flag] += 1

            # numerics (all-time)
            stats = self._num[topic]
            stats_len = stats["length"]
            stats_ent = stats["entropy"]

            # --- ADVANCED ---
            # Check for numeric anomalies *before* adding the new value
            if stats_len.n > 10:  # Wait for stats to stabilize
                z_len = stats_len.z_score(float(raw_len))
                if abs(z_len) > self.spike_z_threshold:
                    self._record_numeric_anomaly(now, topic, "length", float(raw_len), z_len)
            if stats_ent.n > 10:
                z_ent = stats_ent.z_score(float(ent))
                if abs(z_ent) > self.spike_z_threshold:
                    self._record_numeric_anomaly(now, topic, "entropy", float(ent), z_ent)

            stats_len.add(float(raw_len))
            stats_ent.add(float(ent))

            # --- ADVANCED ---
            # Update recent samples (for sliding window stats)
            self._update_recent_samples(now, topic, "length", float(raw_len))
            self._update_recent_samples(now, topic, "entropy", float(ent))

            # histogram (length in bytes)
            self._bump_hist(topic, raw_len)

            # rate & spike
            rate = self._rate[topic].tick(now)
            self._rate_mean[topic].add(rate)
            self._rate_std[topic].add(rate)
            z_rate = 0.0
            stdev = self._rate_std[topic].std()
            if self._rate_mean[topic].n > 10 and stdev > 1e-6:
                z_rate = (rate - self._rate_mean[topic].mean) / stdev
                if z_rate >= self.spike_z_threshold:
                    # --- ADVANCED ---
                    # Record spike event instead of just logging
                    self._record_spike_event(now, topic, rate, z_rate)
                    if self._log_level >= 2:
                        self._logger(f"[RawLearner] spike topic='{topic}' rate={rate:.2f}/s z={z_rate:.2f}", 2)

            # --- ADVANCED ---
            # raw samples (with de-duplication)
            if self.keep_raw_samples and raw_text:
                h = hash(raw_text)
                if h not in self._sample_hashes[topic]:
                    if len(raw_text) > self.max_sample_chars:
                        raw_text = raw_text[: self.max_sample_chars] + "…"
                    self._raw_samples[topic].append(raw_text)
                    self._sample_hashes[topic].append(h)

            # Specific event tracking for tips/questions
            if topic == "tls":
                for hs_type in tls_hs_types:
                    self._tls_handshakes[topic].append((now, hs_type))
            elif topic == "dns":
                for query in dns_queries:
                    self._dns_queries[topic].append((now, query))

            # --- ADVANCED ---
            # Update conversation tracking
            if convo_key:
                self._update_conversations(topic, convo_key, raw_len, now)

        return pkt

    def _extract_raw_bytes_from_payload(self, payload: Dict[str, Any]) -> Optional[bytes]:
        for k in ("raw", "bytes", "data", "raw_text"):
            val = payload.get(k)
            if isinstance(val, str): return val.encode("utf-8", errors="replace")
            if isinstance(val, (bytes, bytearray, memoryview)):
                return bytes(val if not isinstance(val, memoryview) else val.tobytes())
        return None

    # --------------------- Text mining ---------------------
    def _tokens_from_text(self, text: str) -> Iterable[str]:
        for t in self._TOKEN_RE.findall(text or ""):
            tl = t.lower()
            if tl not in self._STOPWORDS:
                yield tl

    def _signals_from_text(self, text: str, payload: Dict[str, Any]) -> Tuple[
        List[str], List[str], List[int], List[str], List[str], List[str], List[str]]:
        ips = self._IP_RE.findall(text or "") or []
        macs = [m.lower() for m in self._MAC_RE.findall(text or "")] or []
        ports: List[int] = []
        for m in self._PORT_RE.finditer(text or ""):
            try:
                p = int(m.group(1))
                if 0 < p < 65536: ports.append(p)
            except Exception:
                pass
        protos = [m.group(1).lower() for m in self._PROTO_RE.finditer(text or "")]

        tls_hs_types: List[str] = []
        if payload.get("attributes", {}).get("hs_type_name"):
            tls_hs_types.append(payload["attributes"]["hs_type_name"])
        else:
            tls_hs_types = [m.group(1) for m in self._TLS_HS_TYPE_RE.finditer(text or "")]

        dns_queries: List[str] = []
        if payload.get("attributes", {}).get("dns_query"):
            dns_queries.append(payload["attributes"]["dns_query"])
        else:
            dns_queries = [m.group(1) for m in self._DNS_QUERY_RE.finditer(text or "")]

        tcp_flags: List[str] = []
        if payload.get("attributes", {}).get("tcp_flags"):
            tcp_flags = payload["attributes"]["tcp_flags"]

        return ips, macs, ports, protos, tls_hs_types, dns_queries, tcp_flags

    def _bump_hist(self, topic: str, length: int) -> None:
        hist = self._hist[topic]
        for i, b in enumerate(self.DEFAULT_BINS):
            if length <= b:
                hist[i] += 1
                return
        hist[-1] += 1

    # --------------------- (Original) Snapshots ---------------------

    # All these methods remain compatible
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
                for k in ("ip", "mac", "port", "proto", "tls_hs_type", "dns_query", "tcp_flags")
            }

    def snapshot_numeric(self, topic: str) -> Dict[str, Dict[str, float]]:
        """Returns ALL-TIME stats."""
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
        if not self.keep_raw_samples: return []
        with self._lock:
            dq = self._raw_samples.get(topic, deque())
            return list(list(dq)[-max(0, int(limit)):])

    def get_all_categorical_counters(self) -> Dict[str, Dict[str, Counter]]:
        with self._lock:
            return {
                topic: {feat: counter.copy() for feat, counter in features.items()}
                for topic, features in self._cats.items()
            }

    def get_all_online_numeric_stats(self) -> Dict[str, Dict[str, '_OnlineStats']]:
        """Returns ALL-TIME online stats objects (for StatisticsManager)."""
        with self._lock:
            copied_stats = defaultdict(dict)
            for topic, features in self._num.items():
                for feature_name, stats_obj in features.items():
                    copied_stats[topic][feature_name] = PacketLearnerManager._OnlineStats(
                        n=stats_obj.n, mean=stats_obj.mean, M2=stats_obj.M2,
                        min=stats_obj.min, max=stats_obj.max
                    )
            return copied_stats

    def get_concept_counts(self) -> Dict[str, Dict[str, int]]:
        with self._lock:
            return {topic: v.copy() for topic, v in self._vocab.items()}

    def get_tls_handshakes(self, topic: str) -> Deque[Tuple[float, str]]:
        with self._lock:
            return self._tls_handshakes.get(topic, deque()).copy()

    def get_dns_queries(self, topic: str) -> Deque[Tuple[float, str]]:
        with self._lock:
            return self._dns_queries.get(topic, deque()).copy()

    def purge_topic(self, topic: str) -> None:
        with self._lock:
            self._vocab.pop(topic, None)
            self._cats.pop(topic, None)
            self._num.pop(topic, None)
            self._hist.pop(topic, None)
            self._rate.pop(topic, None)
            self._rate_mean.pop(topic, None)
            self._rate_std.pop(topic, None)
            self._raw_samples.pop(topic, None)
            self._tls_handshakes.pop(topic, None)
            self._dns_queries.pop(topic, None)
            # --- ADVANCED ---
            # Purge new state
            self._conversations.pop(topic, None)
            self._sample_hashes.pop(topic, None)
            self._recent_numeric_samples.pop(topic, None)
            # Note: spike/anomaly logs are global, not per-topic,
            # but we can filter them if needed. For now, we leave them.
            # Or, let's filter them:
            self._spike_events = deque((t, top, r, z) for t, top, r, z in self._spike_events if top != topic)
            self._numeric_anomalies = deque(
                (t, top, f, v, z) for t, top, f, v, z in self._numeric_anomalies if top != topic)

    # --------------------- (NEW) Advanced Public APIs ---------------------

    def snapshot_conversations(self, topic: str, top_k: int = 10,
                               sort_by: str = "packets") -> List[_ConversationStats]:
        """
        Returns the top_k active conversations for a topic.
        sort_by: 'packets' (n), 'bytes' (total_bytes), 'recent' (last_seen)
        """
        with self._lock:
            topic_convos = list(self._conversations.get(topic, {}).values())

        if sort_by == "bytes":
            sorter = lambda c: c.total_bytes
        elif sort_by == "recent":
            sorter = lambda c: c.last_seen
        else:  # default to packets
            sorter = lambda c: c.n

        return sorted(topic_convos, key=sorter, reverse=True)[:top_k]

    def snapshot_recent_numeric(self, topic: str,
                                window_sec: Optional[float] = None) -> Dict[str, _OnlineStats]:
        """
        Computes and returns _OnlineStats for numeric features within the
        recent time window.
        """
        now = self._now()
        window = window_sec if window_sec is not None else self._recent_window_sec
        cutoff = now - window

        recent_stats: Dict[str, PacketLearnerManager._OnlineStats] = {
            "length": self._OnlineStats(),
            "entropy": self._OnlineStats()
        }

        with self._lock:
            for feature, dq in self._recent_numeric_samples.get(topic, {}).items():
                # Iterate from the right (newest)
                for ts, value in reversed(dq):
                    if ts < cutoff:
                        break  # Stop when we go past the window
                    recent_stats[feature].add(value)
        return recent_stats

    def get_spike_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns the most recent spike events across all topics."""
        with self._lock:
            events = list(self._spike_events)

        return [{
            "ts": ts, "topic": topic, "rate_rps": rate, "z_score": z
        } for ts, topic, rate, z in list(events)[-limit:]]

    def get_numeric_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns the most recent numeric anomalies across all topics."""
        with self._lock:
            anomalies = list(self._numeric_anomalies)

        return [{
            "ts": ts, "topic": topic, "feature": feature, "value": value, "z_score": z
        } for ts, topic, feature, value, z in list(anomalies)[-limit:]]

    # --------------------- (NEW) Advanced Private Helpers ---------------------

    def _get_convo_key(self, ips: List[str], ports: List[int], protos: List[str]) -> str:
        """Creates a stable, sorted conversation key."""
        try:
            proto = protos[0] if protos else "ip"
            ip_pair = tuple(sorted(ips[:2])) if len(ips) >= 2 else (ips[0] if ips else "0.0.0.0", "0.0.0.0")
            port_pair = tuple(sorted(ports[:2])) if len(ports) >= 2 else (ports[0] if ports else 0, 0)

            # Create a key like: tcp:[1.1.1.1:80]-[2.2.2.2:12345]
            return f"{proto}:[{ip_pair[0]}:{port_pair[0]}]-[{ip_pair[1]}:{port_pair[1]}]"
        except Exception:
            return ""  # Failed to create a key

    def _update_conversations(self, topic: str, convo_key: str, length: int, now: float):
        """Updates the conversation stats for a given topic and key."""
        topic_convos = self._conversations[topic]
        if convo_key not in topic_convos:
            # --- Eviction logic ---
            # If we're at our limit, find the oldest (least recently seen) and remove it.
            if len(topic_convos) >= self._max_conversations:
                try:
                    oldest_key = min(topic_convos.keys(), key=lambda k: topic_convos[k].last_seen)
                    topic_convos.pop(oldest_key, None)
                except Exception:
                    pass  # Failsafe

            topic_convos[convo_key] = self._ConversationStats(key=convo_key, first_seen=now, last_seen=now)

        topic_convos[convo_key].add(length, now)

    def _update_recent_samples(self, now: float, topic: str, feature: str, value: float):
        """Adds a new sample to the recent stats deque and prunes old ones."""
        dq = self._recent_numeric_samples[topic][feature]
        cutoff = now - self._recent_window_sec

        # Prune from the left (oldest)
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        dq.append((now, value))  # Add to the right (newest)

    def _record_spike_event(self, now: float, topic: str, rate: float, z_score: float):
        """Records a rate spike event."""
        self._spike_events.append((now, topic, rate, z_score))

    def _record_numeric_anomaly(self, now: float, topic: str, feature: str, value: float, z_score: float):
        """Records a numeric (e.g., length, entropy) anomaly."""
        self._numeric_anomalies.append((now, topic, feature, value, z_score))

    # This method is not part of the original, but it's needed for the
    # `get_all_numeric_vectors` placeholder. We'll keep the placeholder
    # implementation as it's not used by the new StatisticsManager.
    def get_all_numeric_vectors(self) -> Dict[str, Dict[str, List[float]]]:
        """Placeholder for compatibility. Not meaningfully used."""
        return {}

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
            online_num_stats: Dict[str, Dict[str, PacketLearnerManager._OnlineStats]],
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
            online_num_stats: Numeric features, as {topic: {feature: _OnlineStats}}.
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
        topic_list = list(topics) if topics else list(set(online_num_stats.keys()) | set(cat_counters.keys()))

        for topic in topic_list:
            topic_stats: Dict[str, Any] = {}

            # Compute stats for numeric features for the current topic
            numeric_stats = self._compute_numeric_stats_for_topic(
                online_num_stats.get(topic, {}), percentiles, min_count_for_stats
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
            topic_num_stats: Dict[str, PacketLearnerManager._OnlineStats],
            percentiles: List[int],
            min_count: int,
    ) -> Dict[str, Any]:
        """Helper to process all numeric features for a single topic."""
        stats: Dict[str, Any] = {}
        for feature, online_stats in topic_num_stats.items():
            if online_stats.n >= min_count:
                # Note: _OnlineStats does not store raw values, so percentiles cannot be computed directly.
                # For "advanced" version, we assume _OnlineStats could be extended to store a sample,
                # or that percentiles are less critical for online stats.
                # For now, we'll compute mean/std/min/max from _OnlineStats.
                # If full percentiles are critical, PacketLearnerManager would need to store raw samples.
                feature_stats = {
                    "count": online_stats.n,
                    "mean": online_stats.mean,
                    "std": online_stats.std(),
                    "min": online_stats.min if online_stats.min != float('inf') else 0.0,
                    "max": online_stats.max if online_stats.max != float('-inf') else 0.0,
                    # Median and percentiles require raw data or a more complex online algorithm.
                    # For simplicity, we omit them here given _OnlineStats structure.
                }
                stats[feature] = feature_stats
        return stats

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
        self.include_topic_in_name = bool(include_topic_in_name)
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
        "transport": "For transport issues, check TCP flags (SYN, ACK, FIN, RST) and window sizes for anomalies.",
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
            token_store: Callable[[str, int], Sequence[str]],  # Now required
            knowledge_retriever: Callable[[str, int, int], List[KnowledgePacket]], # New dependency
            knowledge_exporter: Callable[[], Dict[str, List[Dict[str, Any]]]], # New dependency
            payload_formatter: Callable[[Dict[str, Any], bool, bool, Optional[str]], str], # New dependency
            packet_learner_ref: Any, # Reference to PacketLearnerManager
            stats_manager_ref: Any, # Reference to StatisticsManager
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
          knowledge_retriever: callable(prompt: str, topk: int, per_topic_limit: int) -> List[KnowledgePacket]
                               Retrieves relevant knowledge packets.
          knowledge_exporter: callable() -> Dict[str, List[Dict[str, Any]]]
                              Exports all current knowledge.
          payload_formatter: callable(payload: Dict[str, Any], redact: bool, include_raw: bool, topic: Optional[str]) -> str
                             Formats a payload into a string.
          packet_learner_ref: Reference to PacketLearnerManager for learned stats.
          stats_manager_ref: Reference to StatisticsManager for computing stats.
          per_token_limit: max lines to fetch per token.
          max_token_lines: max lines to include from token-based path.
          max_hint_lines: max hint lines from packets.
          rng_seed: seed for deterministic opener selection (tests).
          redactions: optional custom redaction patterns (pattern, replacement).
        """
        self._token_store = token_store
        self._knowledge_retriever = knowledge_retriever
        self._knowledge_exporter = knowledge_exporter
        self._payload_formatter = payload_formatter
        self._pl = packet_learner_ref
        self._sm = stats_manager_ref
        self._per_token_limit = int(per_token_limit)
        self._max_token_lines = int(max_token_lines)
        self._max_hint_lines = int(max_hint_lines)
        self._rng = random.Random(rng_seed)
        self._redactions = redactions or list(self.DEFAULT_REDACTIONS)

    # --- Public entry point (your original function, now a method) -----------------

    def generate(
            self,
            prompt: str,
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
            lines.append(self._actionable_tip(prompt, topic, [], {})) # No packets/stats for token path
            return "\n".join(lines)

        # 2) Fallback: packet-based hints (redacted by default)
        topic = self._guess_topic(prompt)
        retrieved_packets = self._knowledge_retriever(prompt, topk=12, per_topic_limit=8)
        hints = self._collect_packet_hints(retrieved_packets, redact=redact)

        # Get learned statistics for the topic
        online_num_stats = self._pl.get_all_online_numeric_stats()
        cat_counters = self._pl.get_all_categorical_counters()
        learned_stats = self._sm.compute(
            online_num_stats=online_num_stats,
            cat_counters=cat_counters,
            topics=[topic],
            percentiles=[50], # Only need mean for now
            topk_categorical=5,
            min_count_for_stats=2,
        )
        topic_learned_stats = learned_stats.get(topic, {})

        opener = self._rng.choice(self.OPENERS_HINTS)
        lines = [opener]
        if hints:
            lines.append(f"Topic guess: {topic.upper()}")
            lines.append("Relevant bits I can use:")
            lines += [f"• {h}" for h in hints[: self._max_hint_lines]]
            lines.append("")

        # Add statistical insights
        stat_insights = self._add_statistical_insights(topic, topic_learned_stats)
        if stat_insights:
            lines.append("Key Observations:")
            lines.extend(stat_insights)
            lines.append("")

        # Add actionable tip
        lines.append(self._actionable_tip(prompt, topic, retrieved_packets, topic_learned_stats))

        # Add proactive questions
        proactive_questions = self._generate_proactive_questions(topic, retrieved_packets, topic_learned_stats)
        if proactive_questions:
            lines.append("\nConsider these questions:")
            lines.extend(proactive_questions)

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

    def _collect_packet_hints(self, retrieved: List[KnowledgePacket], *, redact: bool) -> List[str]:
        """Extract short, readable hints from retrieved packets."""
        hints: List[str] = []
        for pkt in retrieved or []:
            payload = pkt.payload or {}
            # Use the injected payload formatter, passing the topic
            formatted_payload = self._payload_formatter(payload, redact=redact, include_raw=not redact, topic=pkt.topic)
            if formatted_payload:
                hints.append(self._clip(formatted_payload, 160))
        return hints

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
        if has("kerb", "kerberos", "as-req", "tgs-req", "kdc"):
            return "kerberos"
        if has("route", "rib", "fib", "bgp", "ospf", "rip"):
            return "router"
        if has("tcp", "udp", "icmp", "transport", "syn", "ack", "fin", "rst"):
            return "transport"
        return "default"

    def _add_statistical_insights(self, topic: str, learned_stats: Dict[str, Any]) -> List[str]:
        insights = []
        numeric_stats = learned_stats.get("numeric", {})
        categorical_stats = learned_stats.get("categorical", {})

        # Numeric insights
        if "length" in numeric_stats:
            length_stats = numeric_stats["length"]
            if length_stats["count"] > 0:
                insights.append(f"Average packet length: {length_stats['mean']:.1f} bytes (min: {length_stats['min']:.0f}, max: {length_stats['max']:.0f}).")
        if "entropy" in numeric_stats:
            entropy_stats = numeric_stats["entropy"]
            if entropy_stats["count"] > 0:
                insights.append(f"Average byte entropy: {entropy_stats['mean']:.2f} (range: {entropy_stats['min']:.2f}-{entropy_stats['max']:.2f}).")

        # Categorical insights
        if "ip" in categorical_stats:
            top_ips = categorical_stats["ip"].get("top_k")
            if top_ips:
                insights.append(f"Most frequent IPs: {', '.join([f'{ip} ({count})' for ip, count in top_ips[:3]])}.")
        if "port" in categorical_stats:
            top_ports = categorical_stats["port"].get("top_k")
            if top_ports:
                insights.append(f"Common ports: {', '.join([f'{port} ({count})' for port, count in top_ports[:3]])}.")
        if "proto" in categorical_stats:
            top_protos = categorical_stats["proto"].get("top_k")
            if top_protos:
                insights.append(f"Observed protocols: {', '.join([f'{proto} ({count})' for proto, count in top_protos[:3]])}.")

        # Topic-specific categorical insights
        if topic == "tls" and "tls_hs_type" in categorical_stats:
            top_hs_types = categorical_stats["tls_hs_type"].get("top_k")
            if top_hs_types:
                insights.append(f"Dominant TLS handshake types: {', '.join([f'{hs_type} ({count})' for hs_type, count in top_hs_types[:3]])}.")
        if topic == "dns" and "dns_query" in categorical_stats:
            top_dns_queries = categorical_stats["dns_query"].get("top_k")
            if top_dns_queries:
                insights.append(f"Frequent DNS queries: {', '.join([f'{query} ({count})' for query, count in top_dns_queries[:3]])}.")
        if topic == "transport" and "tcp_flags" in categorical_stats:
            top_tcp_flags = categorical_stats["tcp_flags"].get("top_k")
            if top_tcp_flags:
                insights.append(f"Common TCP flags observed: {', '.join([f'{flag} ({count})' for flag, count in top_tcp_flags[:3]])}.")

        # Rate insights
        rate_stats = self._pl.snapshot_rate(topic)
        if rate_stats and rate_stats["current_rps"] > 0:
            insights.append(f"Current activity rate for '{topic}': {rate_stats['current_rps']:.2f} packets/sec (mean: {rate_stats['mean_rps']:.2f}).")

        return insights

    def _actionable_tip(self, prompt: str, topic: str, retrieved_packets: List[KnowledgePacket], learned_stats: Dict[str, Any]) -> str:
        """Return a short, concrete next step per topic, enhanced with context."""
        tip = self.TOPIC_TIPS.get(topic) or self.TOPIC_TIPS["default"]

        # Context-aware tips
        if topic == "tls":
            hs_types = [p.payload.get("attributes", {}).get("hs_type_name") for p in retrieved_packets if p.payload.get("attributes", {}).get("hs_type_name")]
            client_hellos = hs_types.count("ClientHello")
            server_hellos = hs_types.count("ServerHello")
            if client_hellos > 0 and server_hellos == 0:
                tip = "Many ClientHello messages but no ServerHello? Check firewall rules, server availability, or TLS version compatibility."
            elif "alert" in [tag.lower() for pkt in retrieved_packets for tag in pkt.tags]:
                tip = "An TLS alert was observed. Investigate the alert description and level for potential issues like certificate problems or protocol errors."
        elif topic == "dns":
            dns_queries = self._pl.get_dns_queries(topic)
            if dns_queries:
                query_counts = Counter([q for _, q in dns_queries])
                most_common_query, _ = query_counts.most_common(1)[0]
                if query_counts[most_common_query] > 5: # Arbitrary threshold
                    tip = f"Many queries for '{most_common_query}' observed. Verify if this is expected or if there's a misconfiguration or excessive lookups."
            top_ips = learned_stats.get("categorical", {}).get("ip", {}).get("top_k")
            if top_ips and len(top_ips) == 1:
                tip = f"All DNS traffic is going to {top_ips[0][0]}. Is this the intended resolver? Check for single point of failure."
        elif topic == "transport":
            length_stats = learned_stats.get("numeric", {}).get("length", {})
            if length_stats and length_stats["mean"] > 1400: # Heuristic for large packets
                tip = "Average packet length is high. Consider MTU issues or large data transfers that might be causing fragmentation or retransmissions."
            tcp_flags_counts = learned_stats.get("categorical", {}).get("tcp_flags", {}).get("top_k", [])
            syn_count = next((c for f, c in tcp_flags_counts if 'S' in f), 0)
            ack_count = next((c for f, c in tcp_flags_counts if 'A' in f), 0)
            if syn_count > 0 and ack_count < syn_count * 0.5: # Many SYNs, few ACKs
                tip = "Many SYN packets observed without corresponding ACKs. This could indicate connection failures or a blocked port."

        return f"Next step: {tip}"

    def _generate_proactive_questions(self, topic: str, retrieved_packets: List[KnowledgePacket], learned_stats: Dict[str, Any]) -> List[str]:
        questions = []
        now = time.time()

        # General questions based on numeric stats
        numeric_stats = learned_stats.get("numeric", {})
        if "entropy" in numeric_stats:
            entropy_mean = numeric_stats["entropy"].get("mean", 0.0)
            if topic not in ["tls", "vpn"] and entropy_mean > 6.0: # High entropy in non-encrypted traffic
                questions.append("Is high byte entropy in this traffic expected, or could it indicate encrypted/obfuscated data where it shouldn't be?")
        if "length" in numeric_stats:
            length_mean = numeric_stats["length"].get("mean", 0.0)
            if length_mean > 0 and length_mean < 60: # Very small packets
                questions.append("Are these unusually small packets indicative of keepalives, acknowledgements, or potentially malformed traffic?")

        # Topic-specific questions
        if topic == "tls":
            hs_types_deque = self._pl.get_tls_handshakes(topic)
            recent_client_hellos = [hs_type for ts, hs_type in hs_types_deque if now - ts < 60] # last 60 seconds
            if recent_client_hellos.count("ClientHello") > 5 and recent_client_hellos.count("ServerHello") == 0:
                questions.append("Are there any firewalls or proxies between the client and server that might be interfering with the TLS handshake?")
            if "Certificate" in recent_client_hellos and "CertificateVerify" not in recent_client_hellos:
                questions.append("Is the client failing to verify the server's certificate? Check certificate chains and trust anchors.")

        if topic == "dns":
            dns_queries_deque = self._pl.get_dns_queries(topic)
            recent_queries = [query for ts, query in dns_queries_deque if now - ts < 60]
            query_counts = Counter(recent_queries)
            if query_counts:
                most_common_query, count = query_counts.most_common(1)[0]
                if count > 10: # Many queries for the same domain
                    questions.append(f"Why are there so many DNS queries for '{most_common_query}'? Is there a caching issue or an application misbehaving?")
            top_ips = learned_stats.get("categorical", {}).get("ip", {}).get("top_k")
            if top_ips and len(top_ips) > 1:
                questions.append(f"Are all these different DNS servers ({', '.join([ip for ip, _ in top_ips[:3]])}) expected, or is there an unexpected resolver in use?")

        if topic == "transport":
            top_tcp_flags = learned_stats.get("categorical", {}).get("tcp_flags", {}).get("top_k", [])
            syn_only_count = next((c for f, c in top_tcp_flags if f == 'S'), 0)
            rst_count = next((c for f, c in top_tcp_flags if 'R' in f), 0)
            if syn_only_count > 0 and rst_count > syn_only_count * 0.5:
                questions.append("Is there a high rate of TCP RST packets after SYN? This often indicates connection refusals or resets.")

        # Questions based on MAC addresses
        top_macs = learned_stats.get("categorical", {}).get("mac", {}).get("top_k")
        if top_macs and len(top_macs) > 1:
            questions.append(f"Are these multiple MAC addresses ({', '.join([mac for mac, _ in top_macs[:3]])}) expected on this segment, or could it indicate a misconfigured bridge/switch or ARP issues?")

        return questions

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


class AskManager:
    """
    AskManager: The conversational interface and knowledge query engine.

    This manager handles user prompts, infers intent, retrieves relevant knowledge,
    computes statistics, and generates responses. It acts as a facade to
    CodeOutputManager's core knowledge store and learning components.

    Public API:
        ask(prompt: str) -> str

    Examples:
        mgr = AskManager(co_manager)
        mgr.ask("inspect")              # redacted snapshot
        mgr.ask("inspect sensitive")    # UNREDACTED snapshot
        mgr.ask("sensitive dump")       # UNREDACTED snapshot
        mgr.ask("stats")                # pure-Python stats
    """

    # Redaction regexes (applied unless `sensitive` intent)
    _RE_IPv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
    _RE_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
    _RE_SPI = re.compile(r"\bspi=([0-9]{1,10})\b", re.IGNORECASE)
    _RE_HEX = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
    _RE_KEY = re.compile(r"(?:psk|key|secret|token|auth|cookie|session_id)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE)

    # Tokenizer for features & token-bank
    _TOKEN_RE = re.compile(r"[A-Za-z0-9_]+", re.UNICODE)

    def __init__(
            self,
            co_manager_ref: Any,  # Reference to the CodeOutputManager instance
            *,
            max_messages: int = 500,
            default_ttl: float = 180.0,
            rng_seed: Optional[int] = None,
            allow_sensitive_by_default: bool = False,
    ) -> None:
        self._co_manager = co_manager_ref  # Store reference to the parent manager
        self._lock = threading.RLock()
        self._messages: Deque[Tuple[str, str]] = deque(maxlen=max_messages)
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

        # Initialize ChatGenManager with necessary callbacks
        self.chat_generator = AskManagerChatGenerator(
            token_store=self._fetch_token_lines_for_chatgen,
            knowledge_retriever=self._retrieve_snippets,
            knowledge_exporter=self._export_knowledge,
            payload_formatter=self._payload_to_text,
            packet_learner_ref=self._co_manager.packet_learner, # Pass PacketLearnerManager
            stats_manager_ref=self._co_manager.stats_manager, # Pass StatisticsManager
            rng_seed=rng_seed
        )

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
                n_removed = self._co_manager.purge_topic(topic) # Delegate to COManager
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
                    percentiles=[5, 25, 50, 75, 95],
                    topk_categorical=8,
                    min_count_for_stats=2,
                )
                reply = (
                    self._format_stats_headlines(stats, limit=8)
                    if stats
                    else "No numeric feature has enough samples to compute stats yet."
                )

            elif intent == "emit":
                cfg = self._co_manager._default_emit_builder() # Delegate to COManager
                code = self._co_manager.generate_class_from_config(cfg) # Delegate to COManager
                self._submit_message("[snapshot emitted]", role="assistant")
                reply = f"Emitted snapshot class '{cfg.get('class_name')}' ({len(code)} bytes)."

            elif intent == "tokens":
                reply = self._raw_from_tokens(prompt, limit=12)

            else:
                # Default behavior for 'gen' keeps things redacted (safe)
                reply = self.chat_generator.generate(prompt, redact=True)

        except Exception as ex:
            with self._lock:
                self._stats.errors += 1
                self._stats.last_error = f"{type(ex).__name__}: {ex}"
            reply = f"Internal error while answering: {ex}"
            self._co_manager._log(f"[AskManager] Error: {ex}\n{traceback.format_exc()}", 1)


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
                preview = self._payload_to_text(payload, redact=redact, include_raw=not redact, topic=topic)
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
        for k in ("src_ip", "dst_ip", "client_ip", "server_ip", "ip", "saddr", "daddr"):
            if k in payload:
                parts.append(f"{k}={R(str(payload[k]))}")

        if "ips" in payload:
            parts.append("ips=[" + ", ".join(R(x) for x in payload["ips"][:8]) + "]")
        if "macs" in payload:
            parts.append("macs=[" + ", ".join(R(x) for x in payload["macs"][:8]) + "]")
        if "spis" in payload:
            parts.append("spis=[" + ", ".join(R(str(x)) for x in payload["spis"][:8]) + "]")

        for k in ("src_port", "dport", "sport", "port", "proto", "protocol", "spi"):
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
        self._co_manager.submit_event(
            topic=pkt.topic,
            attributes=pkt.payload.get("attributes"),
            methods=pkt.payload.get("methods"),
            ttl=pkt.ttl,
            source=pkt.source,
            tags=pkt.tags,
            importance=pkt.importance
        ) # Delegate to COManager's bus

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
        with self._co_manager._k_lock: # Access COManager's lock for knowledge
            candidates = [t for t in toks if t in self._co_manager._knowledge_by_topic]
        return candidates[0] if candidates else "misc"

    def _export_knowledge(self) -> Dict[str, List[Dict[str, Any]]]:
        return self._co_manager.export_knowledge() # Delegate to COManager

    # ----------------- Retrieval & Generation -----------------

    def _retrieve_snippets(self, prompt: str, *, topk: int = 6, per_topic_limit: int = 3) -> List[KnowledgePacket]:
        query_toks = set(self._tokenize(prompt))
        scored: List[Tuple[float, KnowledgePacket]] = []
        now = time.time()
        with self._co_manager._k_lock: # Access COManager's lock for knowledge
            for topic, dq in self._co_manager._knowledge_by_topic.items():
                if not dq:
                    continue
                topic_bonus = 0.5 if topic in query_toks else 0.0
                for pkt in list(dq)[-per_topic_limit:]:
                    if pkt.is_expired(now):
                        continue
                    payload_text = self._payload_to_text(pkt.payload, redact=True, topic=topic)  # score on redacted text
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

    def _fetch_token_lines_for_chatgen(self, token: str, limit: int) -> Sequence[str]:
        """Callback for ChatGenManager to fetch lines from AskManager's token bank."""
        dq = self._token_bank.get(token)
        if not dq:
            return []
        # newest-first from tail, only user-originated lines
        lines = [line for role, line, _ts in list(dq)[-limit:][::-1] if role == "user" and not self._is_boilerplate(line)]
        return lines

    def _raw_from_tokens(self, query: str, *, limit: int = 12) -> str:
        qtok = [t for t in self._tokenize(query) if t and not t.isdigit()]
        if not qtok:
            return "No tokens in query."
        lines = []
        seen = set()
        for tok in qtok:
            for line in self._fetch_token_lines_for_chatgen(tok, limit):
                if line not in seen:
                    lines.append(line)
                    seen.add(line)
                if len(lines) >= limit:
                    break
            if len(lines) >= limit:
                break

        if not lines:
            return "No raw lines matched those tokens yet."
        head = "Raw token matches (unredacted):"
        body = "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(lines[:limit]))
        return f"{head}\n{body}"

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
            percentiles: List[int] = [5, 25, 50, 75, 95],
            topk_categorical: int = 5,
            min_count_for_stats: int = 2,
    ) -> Dict[str, Dict[str, Any]]:
        # Delegate to CodeOutputManager's PacketLearnerManager and StatisticsManager
        return self._co_manager.compute_statistics_from_learned_data(
            topics=topics,
            percentiles=percentiles,
            topk_categorical=topk_categorical,
            min_count_for_stats=min_count_for_stats
        )

    def _format_stats_headlines(self, stats: Dict[str, Dict[str, Any]], *, limit: int = 8) -> str:
        lines = ["Statistics (headlines):"]
        shown = 0
        for topic, blocks in stats.items():
            for feat, fs in (blocks.get("numeric") or {}).items():
                try:
                    lines.append(
                        f"• [{topic}.{feat}] count={fs.get('count')} mean={fs.get('mean'):.3g} std={fs.get('std'):.3g}")
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
        if ips: out["ips"] = ips
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
        for t in ("tls", "dns", "dhcp", "quic", "esp", "kerberos", "transport"):
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

    def _payload_to_text(self, payload: Dict[str, Any], *, redact: bool = False, include_raw: bool = False, topic: Optional[str] = None) -> str:
        parts = []
        attrs = payload.get("attributes", {})

        # Semantic interpretation for common network fields
        if topic == "tls":
            hs_type = attrs.get("hs_type_name")
            sni = attrs.get("sni")
            version = attrs.get("version")
            cipher = attrs.get("cipher_suite")
            if hs_type:
                part = f"TLS {hs_type}"
                if sni: part += f" for {sni}"
                if version: part += f" ({version})"
                if cipher: part += f" using {cipher}"
                parts.append(part)
        elif topic == "dns":
            dns_query = attrs.get("dns_query")
            dns_qtype = attrs.get("dns_qtype")
            dns_rcode = attrs.get("dns_rcode")
            if dns_query:
                part = f"DNS query for {dns_query}"
                if dns_qtype: part += f" ({dns_qtype})"
                if dns_rcode: part += f" (RCODE: {dns_rcode})"
                parts.append(part)
        elif topic == "transport":
            proto = attrs.get("proto")
            sport = attrs.get("sport")
            dport = attrs.get("dport")
            tcp_flags = attrs.get("tcp_flags")
            if proto:
                part = f"{proto.upper()} packet"
                if sport and dport: part += f" {sport} -> {dport}"
                if tcp_flags: part += f" (Flags: {','.join(tcp_flags)})"
                parts.append(part)

        # Generic attribute formatting
        for k, v in (attrs or {}).items():
            if k in ["raw", "raw_text", "hs_type_name", "sni", "version", "cipher_suite", "dns_query", "dns_qtype", "dns_rcode", "proto", "sport", "dport", "tcp_flags"]:
                continue # Already handled or not for generic display
            if isinstance(v, dict):
                pv = ",".join(f"{kk}={v[kk]}" for kk in list(v)[:4])
            elif isinstance(v, (list, tuple, set)):
                pv = ",".join(map(str, list(v)[:6]))
            else:
                pv = str(v)
            if redact:
                pv = self._redact_text(pv)
            parts.append(f"{k}:{pv if len(pv) <= 80 else pv[:77] + '...'}")

        if include_raw and payload.get("raw_text"):
            raw_text = payload["raw_text"]
            if redact:
                raw_text = self._redact_text(raw_text)
            parts.append(f"raw_text:{raw_text if len(raw_text) <= 80 else raw_text[:77] + '...'}")

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
            ask_manager_ref: AskManager,  # Reference to the AskManager instance
            packet_learner_ref: PacketLearnerManager, # Reference to PacketLearnerManager
            rng_seed: Optional[int] = None,
            max_corpus_lines: int = 200,
            max_payload_chars: int = 1200,
            doc_max_len: int = 28,
    ):
        self._log = logger
        self._am = ask_manager_ref
        self._pl = packet_learner_ref
        self._rng = random.Random(rng_seed)
        self._np_rng = np.random.default_rng(rng_seed)
        self._markov_model: Dict[str, Dict[str, int]] = {}
        self._starters: List[str] = []
        self._max_corpus_lines = int(max_corpus_lines)
        self._max_payload_chars = int(max_payload_chars)
        self._doc_max_len = int(doc_max_len)

        # fallbacks if AskManager absent (though now it's required)
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
            stats = stats_computer() # Call the provided stats_computer
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
                preview = self._am._payload_to_text(payload, redact=True, include_raw=False, topic=topic)
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
                    if role == "user" and line and not self._am._is_boilerplate(line):
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
                "    # Pass empty lists/dicts for packets/stats as this method is for generated class, not live chat\n"
                "    return self._am.chat_generator._actionable_tip(f'tip for {{t}}', t, [], {}) if hasattr(self, '_am') and self._am else 'No tip.'\n"
                "except Exception:\n"
                "    return 'No tip.'"
            )

        methods["ask_tip"] = {"args": "self, topic: Optional[str] = None", "body": _tip_body()}

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
            try:
                candidates = ["dns", "tls", "esp", "router", "kerberos", "quic", "dhcp", "misc", "transport"]
                self._rng.shuffle(candidates)
                for c in candidates:
                    if c in self._markov_model:
                        current_word = c
                        break
                else:
                    current_word = self._rng.choice(self._starters or list(self._markov_model.keys()))
            except Exception:
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
    def _payload_to_text(self, payload: Dict[str, Any], *, redact: bool, include_raw: bool, topic: Optional[str]) -> str:
        # Delegate to AskManager's payload formatter
        return self._am._payload_to_text(payload, redact=redact, include_raw=include_raw, topic=topic)

    def _redact_text(self, s: str) -> str:
        # Delegate to AskManager's redaction
        return self._am._redact_text(s)

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
        # Insights are now derived from PacketLearnerManager's concept counts
        return fetcher(topics=topics) or {}

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
        lines = [f"class {class_name}:", f'    """{doc}"""', "", "    def __init__(self, ask_manager=None):",
                 "        self._am = ask_manager"]
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
        51820: "vpn", 9993: "misc",

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
        self._k_lock = threading.Lock() # Lock for _knowledge_by_topic and _ingest_since_emit

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
        self._insights_max = 15

        # One-time IPsec warning control
        self._ipsec_warned = False

        # Chat mode and history (now managed by AskManager and ChatGenManager)
        self._chat_history: Deque[Dict[str, Any]] = deque(maxlen=200)  # rolling memory for chat
        self._chat_ttl_s = 600.0  # chat turns stick around for 10 minutes
        self._max_context_snippets = 6  # retrieval budget
        self._chat_persona = "crisp, technical, friendly"  # style hint

        # Seed a small starter so Markov text won’t be empty at first
        self._chat_seed_corpus = [
            "acknowledged", "noted", "let us inspect the observed attributes", "computing statistics",
            "deriving insight", "analyzing traffic snapshot",
            "parsing headers", "validating checksums", "normalizing fields", "estimating baselines",
            "detecting anomalies", "flagging outliers", "correlating sessions", "mapping flows",
            "tracking latencies", "sampling payloads", "applying heuristics", "scoring risk",
            "summarizing evidence", "cross-referencing indicators", "triaging alerts", "escalating incident",
            "probing endpoints", "queuing retries", "caching results", "rotating logs",
            "rotating keys", "syncing state", "reconciling counters", "replaying capture",
            "learning patterns", "auto-tuning thresholds", "estimating entropy", "hashing fingerprints",
            "classifying protocols",
            "labeling streams", "reassembling fragments",
            "decoding asn.1", "decoding gss-api",
            "decoding kerberos", "validating tickets", "tracking nonces", "checking replay", "measuring jitter",
            "accounting bandwidth", "dropping malformed", "quarantining sources",
            "whitelisting peers", "blacklisting hosts", "closing sockets", "opening circuit", "backing off",
            "resuming flow",
            "writing pcap", "emitting metrics", "updating dashboard", "acknowledging event", "compiling signature",
            "testing hypothesis",
            "verifying fix", "rolling update", "committing change", "synchronizing clocks", "aligning windows",
            "applying policy", "enforcing rules",
        ]

        # Initialize sub-managers, passing self as reference for callbacks/delegation
        self.packet_learner = PacketLearnerManager(
            keep_raw_samples=True, logger=self._log, log_level=2
        )
        self.stats_manager = StatisticsManager()
        self.method_generator = SnapshotMethodGenerator()
        self.ask_manager = AskManager(co_manager_ref=self, rng_seed=9999)
        self.snapshot_builder = SnapshotBuilder(
            logger=self._log,
            ask_manager_ref=self.ask_manager,
            packet_learner_ref=self.packet_learner,
            rng_seed=2342
        )

        self.log_message("[CodeOutput] Manager initialized (drop-in, protocol-agnostic, NumPy stats ready).")

    def ask(self, prompt: str) -> str:
        """Delegate to AskManager."""
        return self.ask_manager.ask(prompt)

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
        Also generates a chat summary of the emitted snapshot.
        """
        from pathlib import Path
        from datetime import datetime

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        name = cfg.get("class_name", "Snapshot")
        with self._k_lock:
            self._emit_seq += 1
            template = self._emitter_cfg.to_file

        # 1. Handle file writing (existing logic)
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

        # 2. Generate chat summary for the emitted snapshot
        try:
            # Construct a prompt for the chat generator
            topics_in_cfg = cfg.get("topics")
            if topics_in_cfg:
                topic_str = ", ".join(topics_in_cfg)
                chat_prompt = f"Summarize the recently emitted snapshot '{name}' focusing on topics: {topic_str}."
            else:
                chat_prompt = f"Summarize the recently emitted snapshot '{name}'."

            # Call the chat generator directly, ensuring it doesn't feed back into the bus
            # We want a summary of the *current* state, not to trigger new learning from the summary itself.
            chat_response = self.ask_manager.chat_generator.generate(prompt=chat_prompt, redact=True)

            self._log(f"[CodeOutput] 💬 Chat summary for snapshot '{name}':\n{chat_response}", 1)

        except Exception as ex:
            self._log(f"[CodeOutput] ⚠️ Error generating chat summary for snapshot '{name}': {ex}\n{traceback.format_exc()}", 1)

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
        # Delegate to PacketLearnerManager for concept counts
        concept_counts = self.packet_learner.get_concept_counts()
        sel = list(topics) if topics else list(concept_counts.keys())
        out: Dict[str, List[Tuple[str, int]]] = {}
        for t in sel:
            freq = concept_counts.get(t, {})
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
        stats_computer = lambda: self.compute_statistics_from_learned_data(
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

                        # Learning hooks - delegate to PacketLearnerManager
                        self.packet_learner.learn_from_packet(pkt)

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
                            # Also purge from PacketLearnerManager
                            self.packet_learner.purge_topic(topic)
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
            payload={"attributes": attrs, "raw": payload}, # Include raw payload for PacketLearner
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
                return self._normalize_tagged_line(text, raw_bytes=b) if text else []
            except Exception:
                return []

        # Str
        if isinstance(obj, str):
            text = obj.strip()
            if not text:
                return []
            # Try JSON/NDJSON
            pkts = self._try_parse_ndjson(text)
            return pkts if pkts else self._normalize_tagged_line(text, raw_bytes=text.encode("utf-8", "ignore"))

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
        # Add raw_text to payload if available in dict
        if "raw_text" not in payload and "raw" in d:
            payload["raw_text"] = d["raw"]
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

    def _normalize_tagged_line(self, text: str, raw_bytes: Optional[bytes] = None) -> List[KnowledgePacket]:
        tags = [m.group(1).strip() for m in self.BRACKET_TAG_RE.finditer(text)]
        tag_topic = tags[0].lower() if tags else None
        topic = self._map_alias_to_topic(tag_topic) if tag_topic else self._detect_topic_from_text(text)
        kv = {k: v.strip("\"'") for k, v in self.KV_TOKEN_RE.findall(text)}
        message = self.BRACKET_TAG_RE.sub("", text).strip()
        payload = {"attributes": {"message": message, **kv}}
        if raw_bytes:
            payload["raw"] = raw_bytes # Include raw bytes for PacketLearner
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
                    "src", "dst", "saddr", "daddr", "sport", "dport", "proto", "protocol", "ttl", "length") and isinstance(
                v, (str, int, float, bool)):
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

        raw_scapy_pkt = pkt
        a: Dict[str, Any] = {}
        topic = "router"

        if Ether and raw_scapy_pkt.haslayer(Ether):
            eth = raw_scapy_pkt[Ether]
            a.update(eth_src=getattr(eth, "src", None),
                     eth_dst=getattr(eth, "dst", None),
                     eth_type=getattr(eth, "type", None))
        if Dot1Q and raw_scapy_pkt.haslayer(Dot1Q):
            a.update(vlan=raw_scapy_pkt[Dot1Q].vlan, vlan_prio=raw_scapy_pkt[Dot1Q].prio)

        ipL = (IP and raw_scapy_pkt.getlayer(IP)) or (IPv6 and raw_scapy_pkt.getlayer(IPv6))
        if ipL:
            a.update(saddr=getattr(ipL, "src", None),
                     daddr=getattr(ipL, "dst", None),
                     ttl=getattr(ipL, "ttl", getattr(ipL, "hlim", None)))

        if TCP and raw_scapy_pkt.haslayer(TCP):
            topic = self.PORT_TOPIC_HINTS.get(raw_scapy_pkt[TCP].dport,
                                              self.PORT_TOPIC_HINTS.get(raw_scapy_pkt[TCP].sport, "transport"))
            if TLS and raw_scapy_pkt.haslayer(TLS):
                topic = "tls"
            a.update(proto="TCP", sport=raw_scapy_pkt[TCP].sport, dport=raw_scapy_pkt[TCP].dport)
            # Add TCP flags
            flags = raw_scapy_pkt[TCP].flags
            tcp_flags_list = []
            if flags.S: tcp_flags_list.append('S')
            if flags.A: tcp_flags_list.append('A')
            if flags.F: tcp_flags_list.append('F')
            if flags.R: tcp_flags_list.append('R')
            if flags.P: tcp_flags_list.append('P')
            if flags.U: tcp_flags_list.append('U')
            if flags.E: tcp_flags_list.append('E')
            if flags.C: tcp_flags_list.append('C')
            if flags.N: tcp_flags_list.append('N')
            a["tcp_flags"] = tcp_flags_list
        elif UDP and raw_scapy_pkt.haslayer(UDP):
            topic = self.PORT_TOPIC_HINTS.get(raw_scapy_pkt[UDP].dport,
                                              self.PORT_TOPIC_HINTS.get(raw_scapy_pkt[UDP].sport, "transport"))
            if 5353 in (raw_scapy_pkt[UDP].sport, raw_scapy_pkt[UDP].dport):
                a["mdns"] = True
            a.update(proto="UDP", sport=raw_scapy_pkt[UDP].sport, dport=raw_scapy_pkt[UDP].dport)
        elif ICMP and raw_scapy_pkt.haslayer(ICMP):
            topic = "transport"
            a["proto"] = "ICMP"
            try:
                a["icmp_type"] = raw_scapy_pkt[ICMP].type
            except Exception:
                pass
        elif ARP and raw_scapy_pkt.haslayer(ARP):
            topic = "arp"
            a["proto"] = "ARP"
            a.update(arp_op=raw_scapy_pkt[ARP].op, arp_psrc=raw_scapy_pkt[ARP].psrc, arp_pdst=raw_scapy_pkt[ARP].pdst)
        else:
            a["proto"] = "L2" if (Ether and raw_scapy_pkt.haslayer(Ether)) else "misc"

        # IPsec support (ESP/AH)
        ipsec_hit = False
        if ESP and raw_scapy_pkt.haslayer(ESP):
            ipsec_hit = True
            try:
                esp = raw_scapy_pkt[ESP]
                a["esp_spi"] = getattr(esp, "spi", None)
                a["esp_seq"] = getattr(esp, "seq", None)
            except Exception:
                pass
        if AH and raw_scapy_pkt.haslayer(AH):
            ipsec_hit = True
            try:
                ah = raw_scapy_pkt[AH]
                a["ah_spi"] = getattr(ah, "spi", None)
                a["ah_seq"] = getattr(ah, "seq", None)
            except Exception:
                pass
        if ipsec_hit:
            a["ipsec"] = True
            topic = "vpn"

        # GRE check (optional)
        if GRE and raw_scapy_pkt.haslayer(GRE):
            a["gre_like"] = True
            topic = "vpn"

        if inbound_iface:
            a["iface_in"] = inbound_iface
        a.update(ctx or {})
        try:
            a["summary"] = raw_scapy_pkt.summary()
        except Exception:
            pass

        # Include raw bytes of the Scapy packet for PacketLearner
        raw_bytes = bytes(raw_scapy_pkt)
        return [self._finalize_packet(KnowledgePacket(
            topic=topic, payload={"attributes": a, "raw": raw_bytes},
            ttl=self.DEFAULT_TTLS.get(topic, 120.0), source="bus/scapy"
        ))]

    # --------------------------- NumPy snapshot learning ---------------------------

    def compute_statistics_from_learned_data(
            self,
            topics: Iterable[str],
            percentiles: List[int],
            topk_categorical: int,
            min_count_for_stats: int,
    ) -> Dict[str, Any]:
        """
        Computes statistics by delegating to PacketLearnerManager and StatisticsManager.
        """
        online_num_stats = self.packet_learner.get_all_online_numeric_stats()
        cat_counters = self.packet_learner.get_all_categorical_counters()

        return self.stats_manager.compute(
            online_num_stats=online_num_stats,
            cat_counters=cat_counters,
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
                    arr.append({"ts": pkt.ts, "source": pkt.source, "tags": pkt.tags, "payload": pkt.payload, **attrs})
                if arr:
                    out[topic] = arr
        self._log(f"[CodeOutput] 📤 Exported knowledge topics={list(out.keys())}", 1)
        return out

    def purge_topic(self, topic: str) -> int:
        """Remove all packets for a topic. Returns number removed. Also clears feature stores."""
        with self._k_lock:
            dq = self._knowledge_by_topic.pop(topic, None)
            # Delegate purging from PacketLearnerManager
            self.packet_learner.purge_topic(topic)
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


