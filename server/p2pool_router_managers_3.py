
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
import hashlib
import copy
from collections import deque, defaultdict, Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Union, Tuple, Sequence, Mapping

import numpy as np
from scapy.packet import Raw


@dataclass
class KnowledgePacket:
    topic: str
    payload: Dict[str, Any]
    ttl: float = 120.0
    source: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    importance: int = 0
    ts: float = field(default_factory=time.time)
    flow_key: str = ""
    session_key: str = ""
    route_key: str = ""
    iface: Optional[str] = None
    path_stage: Optional[str] = None
    component_name: Optional[str] = None
    direction: Optional[str] = None
    confidence: float = 0.5
    evidence: List[str] = field(default_factory=list)
    parents: List[str] = field(default_factory=list)
    related_topics: List[str] = field(default_factory=list)

    @property
    def expires_at(self) -> float:
        return self.ts + self.ttl

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at

    def semantic_hash(self) -> str:
        stable = {
            "topic": self.topic,
            "iface": self.iface,
            "direction": self.direction,
            "path_stage": self.path_stage,
            "component_name": self.component_name,
            "flow_key": self.flow_key,
            "session_key": self.session_key,
            "route_key": self.route_key,
            "tags": sorted(set(map(str, self.tags))),
            "payload": self._normalize_for_hash(self.payload),
        }
        return hashlib.sha256(
            json.dumps(stable, sort_keys=True, default=str).encode("utf-8", "replace")
        ).hexdigest()

    @classmethod
    def _normalize_for_hash(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return {str(k): cls._normalize_for_hash(x) for k, x in sorted(v.items(), key=lambda kv: str(kv[0]))}
        if isinstance(v, (list, tuple)):
            return [cls._normalize_for_hash(x) for x in v]
        if isinstance(v, (bytes, bytearray, memoryview)):
            b = bytes(v)
            return {"_bytes_len": len(b), "_sha1": hashlib.sha1(b).hexdigest()}
        return v


@dataclass
class EmitterConfig:
    every_s: float = 10.0
    jitter_s: float = 2.0
    min_new_packets: int = 4
    min_semantic_delta: int = 1
    to_file: Optional[str] = None
    emit_only_if_topics_changed: bool = False
    max_emit_rate_per_minute: int = 6


@dataclass
class Stats:
    packets_ingested: int = 0
    packets_dropped: int = 0
    emits: int = 0
    emit_duplicates: int = 0
    errors: int = 0
    by_topic: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_iface: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_component: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_stage: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_source: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def snapshot(self) -> Dict[str, Any]:
        return {
            "packets_ingested": self.packets_ingested,
            "packets_dropped": self.packets_dropped,
            "emits": self.emits,
            "emit_duplicates": self.emit_duplicates,
            "errors": self.errors,
            "by_topic": dict(self.by_topic),
            "by_iface": dict(self.by_iface),
            "by_component": dict(self.by_component),
            "by_stage": dict(self.by_stage),
            "by_source": dict(self.by_source),
        }


class MiniTemplateEngine:
    @staticmethod
    def render_class(class_name: str, attributes: Dict[str, Any], methods: Dict[str, Any], doc: str = "A generated class.") -> str:
        lines: List[str] = []
        lines.append(f"class {class_name}:")
        lines.append(f'    """{doc}"""')
        lines.append("")
        lines.append("    def __init__(self, ask_manager=None):")
        lines.append("        self._am = ask_manager")
        if not attributes:
            lines.append("        pass")
        else:
            for name, val in sorted(attributes.items(), key=lambda kv: kv[0]):
                lines.append(f"        self.{name} = {repr(val)}")
        lines.append("")
        for mname, mdef in sorted(methods.items(), key=lambda kv: kv[0]):
            args = "self, *args, **kwargs"
            body = mdef
            if isinstance(mdef, dict):
                args = mdef.get("args", args)
                body = mdef.get("body", "return None")
            lines.append(f"    def {mname}({args}):")
            if isinstance(body, str) and body.strip():
                for ln in body.splitlines():
                    lines.append(f"        {ln}")
            else:
                lines.append(f"        return {repr(body)}")
            lines.append("")
        return "\n".join(lines)


class PacketLearnerManager:
    _TOKEN_RE = re.compile(r"[a-z][a-z0-9_./:-]{1,63}", re.IGNORECASE)
    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
    _HOST_RE = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9._\-]+\.[a-zA-Z]{2,}\b")
    _PROTO_RE = re.compile(
        r"\b(tcp|udp|icmp|igmp|quic|tls|http|https|dns|dhcp|ssh|mdns|llmnr|wireguard|esp|ah|gre|ntp|arp)\b",
        re.IGNORECASE,
    )
    DEFAULT_BINS = tuple(2 ** k for k in range(5, 17))
    EWMA_ALPHA = 0.25
    _STOPWORDS = {
        "the", "a", "an", "of", "and", "or", "to", "in", "on", "for", "with", "by", "at", "as",
        "is", "are", "was", "were", "be", "been", "being", "this", "that", "these", "those",
        "it", "its", "from", "into", "over", "under", "about", "via", "per", "not", "no",
        "phase", "component", "summary", "processing", "handled", "queue", "forwarding",
        "packet", "packets", "output", "codeoutput",
    }

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
            if x < self.min:
                self.min = x
            if x > self.max:
                self.max = x

        def std(self) -> float:
            return math.sqrt(self.M2 / (self.n - 1)) if self.n > 1 else 0.0

        def z_score(self, x: float) -> float:
            if self.n < 2:
                return 0.0
            sd = self.std()
            if sd < 1e-12:
                return 0.0
            return (x - self.mean) / sd

        def snapshot(self) -> Dict[str, float]:
            return {
                "count": self.n,
                "mean": self.mean,
                "std": self.std(),
                "min": 0.0 if self.min == float("inf") else self.min,
                "max": 0.0 if self.max == float("-inf") else self.max,
            }

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
            self.value = self.alpha * inst + (1.0 - self.alpha) * self.value
            self.last_t = now
            return self.value

    @dataclass
    class _ConversationStats:
        key: str
        topic: str
        iface: Optional[str] = None
        n: int = 0
        total_bytes: int = 0
        total_entropy: float = 0.0
        first_seen: float = field(default_factory=time.time)
        last_seen: float = field(default_factory=time.time)
        peers: Counter = field(default_factory=Counter)
        ports: Counter = field(default_factory=Counter)
        protocols: Counter = field(default_factory=Counter)
        components: Counter = field(default_factory=Counter)
        stages: Counter = field(default_factory=Counter)

        def add(self, *, now: float, length: int, entropy: float, src: Optional[str], dst: Optional[str], sport: Optional[int], dport: Optional[int], proto: Optional[str], component: Optional[str], stage: Optional[str]) -> None:
            self.n += 1
            self.total_bytes += int(length or 0)
            self.total_entropy += float(entropy or 0.0)
            self.last_seen = now
            if src:
                self.peers[str(src)] += 1
            if dst:
                self.peers[str(dst)] += 1
            if sport:
                self.ports[str(sport)] += 1
            if dport:
                self.ports[str(dport)] += 1
            if proto:
                self.protocols[str(proto).lower()] += 1
            if component:
                self.components[str(component)] += 1
            if stage:
                self.stages[str(stage)] += 1

        def avg_entropy(self) -> float:
            return self.total_entropy / self.n if self.n else 0.0

    def __init__(self, *, keep_raw_samples: bool = True, max_samples_per_topic: int = 48, max_sample_chars: int = 2000, spike_z_threshold: float = 3.0, logger: Optional[Callable[[str, int], None]] = None, log_level: int = 1, max_conversations_per_topic: int = 512, recent_window_sec: float = 90.0, recent_max_samples: int = 2048, anomaly_limit: int = 200) -> None:
        self.keep_raw_samples = bool(keep_raw_samples)
        self.max_samples_per_topic = int(max_samples_per_topic)
        self.max_sample_chars = int(max_sample_chars)
        self.spike_z_threshold = float(spike_z_threshold)
        self._logger = logger or (lambda s, l: None)
        self._log_level = int(log_level)
        self._max_conversations = int(max_conversations_per_topic)
        self._recent_window_sec = float(recent_window_sec)
        self._recent_max_samples = int(recent_max_samples)
        self._anomaly_limit = int(anomaly_limit)
        self._vocab: Dict[str, Dict[str, int]] = defaultdict(dict)
        self._cats: Dict[str, Dict[str, Counter]] = defaultdict(self._make_categorical_bucket)
        self._num: Dict[str, Dict[str, PacketLearnerManager._OnlineStats]] = defaultdict(self._make_numeric_bucket)
        self._hist: Dict[str, List[int]] = defaultdict(lambda: [0] * len(self.DEFAULT_BINS))
        self._rate: Dict[str, PacketLearnerManager._EWMA] = defaultdict(lambda: self._EWMA(self.EWMA_ALPHA))
        self._raw_samples: Dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=self.max_samples_per_topic))
        self._sample_hashes: Dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=self.max_samples_per_topic * 4))
        self._conversations: Dict[str, Dict[str, PacketLearnerManager._ConversationStats]] = defaultdict(dict)
        self._recent_numeric: Dict[str, Dict[str, Deque[Tuple[float, float]]]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=self._recent_max_samples)))
        self._recent_packets: Dict[str, Deque[KnowledgePacket]] = defaultdict(lambda: deque(maxlen=96))
        self._topic_semantic_hashes: Dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=256))
        self._spike_events: Deque[Tuple[float, str, float, float]] = deque(maxlen=self._anomaly_limit)
        self._numeric_anomalies: Deque[Tuple[float, str, str, float, float]] = deque(maxlen=self._anomaly_limit)
        self._lock = threading.Lock()

    def _make_categorical_bucket(self) -> Dict[str, Counter]:
        return {
            "ip": Counter(), "mac": Counter(), "port": Counter(), "proto": Counter(), "host": Counter(),
            "iface": Counter(), "flow_key": Counter(), "session_key": Counter(), "route_key": Counter(),
            "tags": Counter(), "phase": Counter(), "component": Counter(), "topic_hint": Counter(),
            "direction": Counter(), "source": Counter(), "dns_query": Counter(), "tls_hs_type": Counter(),
            "tcp_flags": Counter(),
        }

    def _make_numeric_bucket(self) -> Dict[str, "_OnlineStats"]:
        return {
            "length": self._OnlineStats(),
            "entropy": self._OnlineStats(),
            "confidence": self._OnlineStats(),
            "rps": self._OnlineStats(),
            "topic_diversity": self._OnlineStats(),
        }

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
            return bytes(buf).decode("latin-1", errors="replace")

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

    def learn_from_packet(self, pkt: KnowledgePacket) -> KnowledgePacket:
        topic = pkt.topic or "misc"
        raw_bytes = self._extract_raw_bytes(pkt.payload)
        raw_len = len(raw_bytes)
        raw_text = self._safe_decode(raw_bytes) if raw_bytes else self._payload_text(pkt.payload)
        entropy = self._byte_entropy(raw_bytes) if raw_bytes else 0.0
        now = self._now()
        attrs = pkt.payload.get("attributes", {}) if isinstance(pkt.payload, dict) else {}
        tokens = list(self._tokens_from_text(raw_text))
        ips = set(self._IP_RE.findall(raw_text))
        macs = set(m.lower() for m in self._MAC_RE.findall(raw_text))
        hosts = set(h.lower() for h in self._HOST_RE.findall(raw_text))
        protos = set(m.group(1).lower() for m in self._PROTO_RE.finditer(raw_text))
        src = self._first_nonempty(attrs, "src", "saddr", "src_ip")
        dst = self._first_nonempty(attrs, "dst", "daddr", "dst_ip")
        sport = self._safe_int(self._first_nonempty(attrs, "sport", "src_port"))
        dport = self._safe_int(self._first_nonempty(attrs, "dport", "dst_port"))
        proto = self._first_nonempty(attrs, "proto", "protocol")
        iface = pkt.iface or attrs.get("iface_in")
        phase = pkt.path_stage or attrs.get("phase")
        component = pkt.component_name or attrs.get("component")
        direction = pkt.direction or attrs.get("direction")
        flow_key = pkt.flow_key or self._make_flow_key(topic, src, dst, sport, dport, proto)
        session_key = pkt.session_key or self._make_session_key(flow_key, iface, component)
        route_key = pkt.route_key or self._make_route_key(src, dst, iface, phase)
        dns_query = attrs.get("dns_query")
        tls_hs_type = attrs.get("hs_type_name")
        tcp_flags = attrs.get("tcp_flags") or []
        semantic_hash = pkt.semantic_hash()

        with self._lock:
            vocab = self._vocab[topic]
            for t in tokens:
                vocab[t] = vocab.get(t, 0) + 1
            cats = self._cats[topic]
            for ip in ips:
                cats["ip"][ip] += 1
            for mac in macs:
                cats["mac"][mac] += 1
            for host in hosts:
                cats["host"][host] += 1
            for pr in protos:
                cats["proto"][pr] += 1
            if sport:
                cats["port"][str(sport)] += 1
            if dport:
                cats["port"][str(dport)] += 1
            if iface:
                cats["iface"][str(iface)] += 1
            if flow_key:
                cats["flow_key"][flow_key] += 1
            if session_key:
                cats["session_key"][session_key] += 1
            if route_key:
                cats["route_key"][route_key] += 1
            if phase:
                cats["phase"][str(phase)] += 1
            if component:
                cats["component"][str(component)] += 1
            if direction:
                cats["direction"][str(direction)] += 1
            if pkt.source:
                cats["source"][str(pkt.source)] += 1
            if dns_query:
                cats["dns_query"][str(dns_query)] += 1
            if tls_hs_type:
                cats["tls_hs_type"][str(tls_hs_type)] += 1
            for flag in tcp_flags:
                cats["tcp_flags"][str(flag)] += 1
            for tag in pkt.tags:
                cats["tags"][str(tag)] += 1
            for rel in pkt.related_topics:
                cats["topic_hint"][str(rel)] += 1

            num = self._num[topic]
            self._check_numeric_anomaly(now, topic, "length", float(raw_len), num["length"])
            self._check_numeric_anomaly(now, topic, "entropy", float(entropy), num["entropy"])
            self._check_numeric_anomaly(now, topic, "confidence", float(pkt.confidence), num["confidence"])
            num["length"].add(float(raw_len))
            num["entropy"].add(float(entropy))
            num["confidence"].add(float(pkt.confidence))
            rate = self._rate[topic].tick(now)
            self._check_numeric_anomaly(now, topic, "rps", float(rate), num["rps"])
            num["rps"].add(float(rate))
            topic_diversity = float(len(cats["component"]) + len(cats["iface"]) + len(cats["flow_key"]))
            num["topic_diversity"].add(topic_diversity)
            if num["rps"].n > 10 and num["rps"].std() > 1e-9:
                z = num["rps"].z_score(rate)
                if z >= self.spike_z_threshold:
                    self._spike_events.append((now, topic, rate, z))
                    if self._log_level >= 2:
                        self._logger(f"[PacketLearner] spike topic='{topic}' rate={rate:.2f}/s z={z:.2f}", 2)
            self._update_recent(topic, "length", now, float(raw_len))
            self._update_recent(topic, "entropy", now, float(entropy))
            self._update_recent(topic, "confidence", now, float(pkt.confidence))
            self._update_recent(topic, "rps", now, float(rate))
            self._update_recent(topic, "topic_diversity", now, float(topic_diversity))
            self._bump_hist(topic, raw_len)
            if self.keep_raw_samples and raw_text:
                h = hashlib.sha1(raw_text[:4096].encode("utf-8", "replace")).hexdigest()
                if h not in self._sample_hashes[topic]:
                    clipped = raw_text[: self.max_sample_chars]
                    self._raw_samples[topic].append(clipped)
                    self._sample_hashes[topic].append(h)
            convos = self._conversations[topic]
            if flow_key:
                if flow_key not in convos and len(convos) >= self._max_conversations:
                    oldest_key = min(convos.keys(), key=lambda k: convos[k].last_seen)
                    convos.pop(oldest_key, None)
                if flow_key not in convos:
                    convos[flow_key] = self._ConversationStats(key=flow_key, topic=topic, iface=iface, first_seen=now, last_seen=now)
                convos[flow_key].add(now=now, length=raw_len, entropy=entropy, src=src, dst=dst, sport=sport, dport=dport, proto=proto, component=component, stage=phase)
            self._recent_packets[topic].append(pkt)
            self._topic_semantic_hashes[topic].append(semantic_hash)
        return pkt

    def _extract_raw_bytes(self, payload: Dict[str, Any]) -> bytes:
        if not isinstance(payload, dict):
            return b""
        for k in ("raw", "bytes", "data", "payload_bytes"):
            v = payload.get(k)
            if isinstance(v, (bytes, bytearray, memoryview)):
                return bytes(v)
        raw_text = payload.get("raw_text")
        if isinstance(raw_text, str):
            return raw_text.encode("utf-8", "replace")
        attrs = payload.get("attributes", {})
        if isinstance(attrs, dict):
            summary = attrs.get("summary")
            if isinstance(summary, str):
                return summary.encode("utf-8", "replace")
        return b""

    def _payload_text(self, payload: Dict[str, Any]) -> str:
        if not isinstance(payload, dict):
            return ""
        attrs = payload.get("attributes", {})
        if isinstance(attrs, dict):
            parts = []
            for k, v in attrs.items():
                if isinstance(v, (str, int, float, bool)):
                    parts.append(f"{k}={v}")
                elif isinstance(v, (list, tuple)):
                    parts.append(f"{k}=" + ",".join(map(str, list(v)[:8])))
            return " ".join(parts)
        return ""

    def _tokens_from_text(self, text: str) -> Iterable[str]:
        for t in self._TOKEN_RE.findall(text or ""):
            tl = t.lower()
            if tl not in self._STOPWORDS:
                yield tl

    def _bump_hist(self, topic: str, length: int) -> None:
        hist = self._hist[topic]
        for i, b in enumerate(self.DEFAULT_BINS):
            if length <= b:
                hist[i] += 1
                return
        hist[-1] += 1

    def _update_recent(self, topic: str, feature: str, now: float, value: float) -> None:
        dq = self._recent_numeric[topic][feature]
        cutoff = now - self._recent_window_sec
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        dq.append((now, value))

    def _check_numeric_anomaly(self, now: float, topic: str, feature: str, value: float, stats: "_OnlineStats") -> None:
        if stats.n < 10:
            return
        z = stats.z_score(value)
        if abs(z) >= self.spike_z_threshold:
            self._numeric_anomalies.append((now, topic, feature, value, z))

    @staticmethod
    def _first_nonempty(d: Dict[str, Any], *keys: str) -> Optional[Any]:
        for k in keys:
            if k in d and d[k] not in (None, "", [], (), {}):
                return d[k]
        return None

    @staticmethod
    def _safe_int(v: Any) -> Optional[int]:
        try:
            if v is None or v == "":
                return None
            return int(v)
        except Exception:
            return None

    @staticmethod
    def _make_flow_key(topic: str, src: Optional[str], dst: Optional[str], sport: Optional[int], dport: Optional[int], proto: Optional[str]) -> str:
        proto_s = str(proto or "ip").lower()
        a = (str(src or "0.0.0.0"), int(sport or 0))
        b = (str(dst or "0.0.0.0"), int(dport or 0))
        lo, hi = sorted([a, b])
        return f"{topic}:{proto_s}:[{lo[0]}:{lo[1]}]-[{hi[0]}:{hi[1]}]"

    @staticmethod
    def _make_session_key(flow_key: str, iface: Optional[str], component: Optional[str]) -> str:
        return f"{flow_key}|iface={iface or 'unknown'}|component={component or 'unknown'}"

    @staticmethod
    def _make_route_key(src: Optional[str], dst: Optional[str], iface: Optional[str], stage: Optional[str]) -> str:
        return f"route:{src or '0.0.0.0'}->{dst or '0.0.0.0'}@{iface or 'unknown'}:{stage or 'unknown'}"

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
            return {k: cats.get(k, Counter()).most_common(top_k) for k in cats.keys()}

    def snapshot_numeric(self, topic: str) -> Dict[str, Dict[str, float]]:
        with self._lock:
            ns = self._num.get(topic, {})
            return {k: st.snapshot() for k, st in ns.items()}

    def snapshot_histogram(self, topic: str) -> List[Tuple[int, int]]:
        with self._lock:
            hist = list(self._hist.get(topic, []))
        return list(zip(self.DEFAULT_BINS, hist))

    def snapshot_rate(self, topic: str) -> Dict[str, float]:
        with self._lock:
            num = self._num.get(topic, {})
            rps = num.get("rps", self._OnlineStats())
            cur = self._rate.get(topic, self._EWMA()).value if topic in self._rate else 0.0
        return {"current_rps": cur, "mean_rps": rps.mean, "std_rps": rps.std()}

    def snapshot_recent_numeric(self, topic: str, window_sec: Optional[float] = None) -> Dict[str, Dict[str, float]]:
        now = self._now()
        window = self._recent_window_sec if window_sec is None else float(window_sec)
        cutoff = now - window
        out: Dict[str, Dict[str, float]] = {}
        with self._lock:
            for feature, dq in self._recent_numeric.get(topic, {}).items():
                vals = [v for ts, v in dq if ts >= cutoff]
                if not vals:
                    continue
                arr = sorted(vals)
                out[feature] = {
                    "count": len(arr),
                    "mean": sum(arr) / len(arr),
                    "min": arr[0],
                    "max": arr[-1],
                    "p50": self._percentile(arr, 50),
                    "p95": self._percentile(arr, 95),
                }
        return out

    def snapshot_conversations(self, topic: str, top_k: int = 10, sort_by: str = "packets") -> List[_ConversationStats]:
        with self._lock:
            convs = list(self._conversations.get(topic, {}).values())
        if sort_by == "bytes":
            keyf = lambda c: c.total_bytes
        elif sort_by == "recent":
            keyf = lambda c: c.last_seen
        elif sort_by == "entropy":
            keyf = lambda c: c.avg_entropy()
        else:
            keyf = lambda c: c.n
        return sorted(convs, key=keyf, reverse=True)[:top_k]

    def snapshot_flows(self, topic: str, top_k: int = 10) -> List[Dict[str, Any]]:
        flows = self.snapshot_conversations(topic, top_k=top_k, sort_by="packets")
        out = []
        for c in flows:
            out.append({
                "key": c.key,
                "iface": c.iface,
                "packets": c.n,
                "bytes": c.total_bytes,
                "avg_entropy": c.avg_entropy(),
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "top_ports": c.ports.most_common(4),
                "top_protocols": c.protocols.most_common(4),
                "top_components": c.components.most_common(4),
                "top_stages": c.stages.most_common(4),
            })
        return out

    def get_recent_packets(self, topic: str, limit: int = 16) -> List[KnowledgePacket]:
        with self._lock:
            return list(self._recent_packets.get(topic, deque()))[-limit:]

    def get_spike_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._spike_events)[-limit:]
        return [{"ts": ts, "topic": topic, "rate_rps": rate, "z_score": z} for ts, topic, rate, z in items]

    def get_numeric_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._numeric_anomalies)[-limit:]
        return [{"ts": ts, "topic": topic, "feature": feat, "value": val, "z_score": z} for ts, topic, feat, val, z in items]

    def topic_semantic_density(self, topic: str) -> float:
        with self._lock:
            dq = self._topic_semantic_hashes.get(topic, deque())
            if not dq:
                return 0.0
            unique = len(set(dq))
            return unique / max(1, len(dq))

    def get_all_categorical_counters(self) -> Dict[str, Dict[str, Counter]]:
        with self._lock:
            return {topic: {feat: counter.copy() for feat, counter in features.items()} for topic, features in self._cats.items()}

    def get_all_online_numeric_stats(self) -> Dict[str, Dict[str, "_OnlineStats"]]:
        with self._lock:
            out = defaultdict(dict)
            for topic, features in self._num.items():
                for feat, st in features.items():
                    out[topic][feat] = self._OnlineStats(n=st.n, mean=st.mean, M2=st.M2, min=st.min, max=st.max)
            return out

    def get_recent_numeric_vectors(self) -> Dict[str, Dict[str, List[float]]]:
        now = self._now()
        cutoff = now - self._recent_window_sec
        out: Dict[str, Dict[str, List[float]]] = defaultdict(dict)
        with self._lock:
            for topic, features in self._recent_numeric.items():
                for feat, dq in features.items():
                    out[topic][feat] = [v for ts, v in dq if ts >= cutoff]
        return out

    def get_concept_counts(self) -> Dict[str, Dict[str, int]]:
        with self._lock:
            return {topic: v.copy() for topic, v in self._vocab.items()}

    def purge_topic(self, topic: str) -> None:
        with self._lock:
            self._vocab.pop(topic, None)
            self._cats.pop(topic, None)
            self._num.pop(topic, None)
            self._hist.pop(topic, None)
            self._rate.pop(topic, None)
            self._raw_samples.pop(topic, None)
            self._sample_hashes.pop(topic, None)
            self._conversations.pop(topic, None)
            self._recent_numeric.pop(topic, None)
            self._recent_packets.pop(topic, None)
            self._topic_semantic_hashes.pop(topic, None)
            self._spike_events = deque(((t, top, r, z) for t, top, r, z in self._spike_events if top != topic), maxlen=self._anomaly_limit)
            self._numeric_anomalies = deque(((t, top, f, v, z) for t, top, f, v, z in self._numeric_anomalies if top != topic), maxlen=self._anomaly_limit)

    @staticmethod
    def _percentile(arr: List[float], p: int) -> float:
        if not arr:
            return 0.0
        if len(arr) == 1:
            return arr[0]
        rank = (p / 100.0) * (len(arr) - 1)
        lo = int(math.floor(rank))
        hi = int(math.ceil(rank))
        if lo == hi:
            return arr[lo]
        frac = rank - lo
        return arr[lo] * (1.0 - frac) + arr[hi] * frac


class StatisticsManager:
    def compute(self, online_num_stats: Dict[str, Dict[str, PacketLearnerManager._OnlineStats]], cat_counters: Dict[str, Dict[str, Counter]], recent_numeric_vectors: Dict[str, Dict[str, List[float]]], topics: Iterable[str], percentiles: List[int], topk_categorical: int, min_count_for_stats: int) -> Dict[str, Any]:
        stats: Dict[str, Any] = {}
        topic_list = list(topics) if topics else sorted(set(online_num_stats.keys()) | set(cat_counters.keys()) | set(recent_numeric_vectors.keys()))
        for topic in topic_list:
            topic_stats: Dict[str, Any] = {}
            numeric_stats = self._compute_numeric_stats_for_topic(online_num_stats.get(topic, {}), recent_numeric_vectors.get(topic, {}), percentiles, min_count_for_stats)
            if numeric_stats:
                topic_stats["numeric"] = numeric_stats
            categorical_stats = self._compute_categorical_stats_for_topic(cat_counters.get(topic, {}), topk_categorical)
            if categorical_stats:
                topic_stats["categorical"] = categorical_stats
            if topic_stats:
                stats[topic] = topic_stats
        return stats

    def _compute_numeric_stats_for_topic(self, topic_num_stats: Dict[str, PacketLearnerManager._OnlineStats], recent_vectors: Dict[str, List[float]], percentiles: List[int], min_count: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for feature, online_stats in topic_num_stats.items():
            if online_stats.n < min_count:
                continue
            feature_stats = {
                "count": online_stats.n,
                "mean": online_stats.mean,
                "std": online_stats.std(),
                "min": online_stats.min if online_stats.min != float("inf") else 0.0,
                "max": online_stats.max if online_stats.max != float("-inf") else 0.0,
            }
            recent_vals = list(recent_vectors.get(feature, []))
            if recent_vals:
                arr = sorted(recent_vals)
                for p in percentiles:
                    feature_stats[f"p{p}"] = self._percentile(arr, p)
            out[feature] = feature_stats
        return out

    def _compute_categorical_stats_for_topic(self, topic_cat_counters: Dict[str, Counter], top_k: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for feature, counter in topic_cat_counters.items():
            if counter:
                out[feature] = self._calculate_categorical_feature(counter, top_k)
        return out

    def _calculate_categorical_feature(self, counter: Counter, top_k: int) -> Dict[str, Any]:
        total_count = sum(counter.values())
        top_values = counter.most_common(top_k)
        return {"unique_count": int(len(counter)), "total_count": int(total_count), "top_k": [(str(val), int(cnt)) for val, cnt in top_values]}

    @staticmethod
    def _percentile(arr: List[float], p: int) -> float:
        if not arr:
            return 0.0
        if len(arr) == 1:
            return arr[0]
        rank = (p / 100.0) * (len(arr) - 1)
        lo = int(math.floor(rank))
        hi = int(math.ceil(rank))
        if lo == hi:
            return arr[lo]
        frac = rank - lo
        return arr[lo] * (1.0 - frac) + arr[hi] * frac


class SnapshotMethodGenerator:
    def __init__(self, *, include_topic_in_name: bool = True, std_epsilon: float = 1e-12, z1: float = 1.0, z2: float = 2.0, z3: float = 3.0, float_precision: int = 4) -> None:
        self.include_topic_in_name = bool(include_topic_in_name)
        self.std_epsilon = float(std_epsilon)
        self.z1 = float(z1)
        self.z2 = float(z2)
        self.z3 = float(z3)
        self.float_precision = int(float_precision)

    def generate(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        methods: Dict[str, Any] = {}
        if not isinstance(stats, dict):
            return methods
        for topic, block in stats.items():
            numeric = block.get("numeric", {})
            if not isinstance(numeric, dict):
                continue
            for feature, fs in numeric.items():
                mean = self._finite_float(fs.get("mean"))
                std = self._finite_float(fs.get("std"))
                if mean is None or std is None:
                    continue
                topic_name = self._safe_name(topic)
                feat_name = self._safe_name(feature)
                mname = f"analyze_{feat_name}"
                if self.include_topic_in_name:
                    mname = f"{topic_name}__{mname}"
                methods[mname] = {"args": "self, value", "body": self._render_zscore_body(mean, std), "doc": f"Analyze '{feature}' for topic '{topic}' using z-score buckets."}
        methods["describe_numeric_feature"] = {"args": "self, mean, std, value", "body": "\\n".join([
            "try:",
            "    v = float(value)",
            "    m = float(mean)",
            "    s = float(std)",
            "except (TypeError, ValueError):",
            "    return 'Invalid numeric inputs.'",
            "if math.isnan(v) or math.isinf(v) or math.isnan(m) or math.isinf(m) or math.isnan(s) or math.isinf(s):",
            "    return 'Invalid numeric inputs.'",
            "if abs(s) <= 1e-12:",
            "    return 'Constant baseline.' if abs(v - m) <= 1e-12 else 'Outlier against constant baseline.'",
            "z = (v - m) / s",
            "return f'z={z:.2f}'",
        ])}
        return methods

    def _render_zscore_body(self, mean: float, std: float) -> str:
        p = self.float_precision
        return "\\n".join([
            f"MEAN = {mean:.{p}f}",
            f"STD = {std:.{p}f}",
            f"EPS = {self.std_epsilon:.{p}g}",
            "try:",
            "    v = float(value)",
            "except (TypeError, ValueError):",
            "    return 'Invalid numeric value.'",
            "if math.isnan(v) or math.isinf(v):",
            "    return 'Invalid numeric value.'",
            "if abs(STD) <= EPS:",
            "    return 'Constant baseline.' if abs(v - MEAN) <= EPS else 'Outlier against constant baseline.'",
            "z = (v - MEAN) / STD",
            "az = abs(z)",
            f"if az >= {self.z3:.{p}f}:",
            "    bucket = 'severe outlier'",
            f"elif az >= {self.z2:.{p}f}:",
            "    bucket = 'moderate outlier'",
            f"elif az >= {self.z1:.{p}f}:",
            "    bucket = 'mild deviation'",
            "else:",
            "    bucket = 'typical'",
            "return f'(z={z:.2f}) {bucket}'",
        ])

    @staticmethod
    def _finite_float(v: Any) -> Optional[float]:
        try:
            x = float(v)
            if not math.isfinite(x):
                return None
            return x
        except Exception:
            return None

    @staticmethod
    def _safe_name(name: str) -> str:
        s = re.sub(r"[^a-zA-Z0-9_]+", "_", str(name).lower()).strip("_")
        if not s:
            s = "f"
        if not s[0].isalpha():
            s = f"f_{s}"
        return s


@dataclass
class AskDialogueState:
    active_topic: str = "misc"
    active_flow_key: Optional[str] = None
    last_intent: str = "general"
    compared_topics: List[str] = field(default_factory=list)
    last_prompt: str = ""
    last_reply: str = ""
    last_packets: List[KnowledgePacket] = field(default_factory=list)
    last_ts: float = field(default_factory=time.time)


@dataclass
class AskEvidenceBundle:
    topic: str = "misc"
    prompt: str = ""
    packets: List[KnowledgePacket] = field(default_factory=list)
    flows: List[Dict[str, Any]] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    token_lines: List[str] = field(default_factory=list)
    related_topics: List[str] = field(default_factory=list)


@dataclass
class AskAnalysis:
    topic: str = "misc"
    answer_mode: str = "general"
    observations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    concise_summary: str = ""
    confidence: float = 0.5


class AskTokenMemory:
    TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+", re.UNICODE)

    def __init__(self, max_per_token: int = 50000) -> None:
        self._token_bank: Dict[str, Deque[Tuple[str, str, float]]] = defaultdict(
            lambda: deque(maxlen=max_per_token)
        )
        self._lock = threading.RLock()

    def index(self, text: str, role: str) -> None:
        now = time.time()
        seen = set()
        for tok in self.TOKEN_RE.findall(text or ""):
            tok = tok.lower()
            if len(tok) < 2 or tok in seen:
                continue
            seen.add(tok)
            with self._lock:
                self._token_bank[tok].append((role, text, now))

    def fetch(self, token: str, limit: int = 6) -> List[str]:
        with self._lock:
            rows = list(self._token_bank.get((token or "").lower(), ()))
        rows = rows[-limit:]
        return [f"{role}: {text}" for role, text, _ in rows if text]


class AskMessageStore:
    def __init__(self, max_messages: int = 500) -> None:
        self._messages: Deque[Tuple[str, str]] = deque(maxlen=max_messages)
        self._lock = threading.RLock()

    def add(self, role: str, text: str) -> None:
        with self._lock:
            self._messages.append((role, text))

    def all(self) -> List[Tuple[str, str]]:
        with self._lock:
            return list(self._messages)

    def tail(self, limit: int = 20) -> List[Tuple[str, str]]:
        with self._lock:
            return list(self._messages)[-limit:]


class AskIntentRouter:
    _TOPIC_HINTS: Dict[str, Tuple[str, ...]] = {
        "dns": ("dns", "resolver", "qname", "llmnr", "mdns"),
        "dhcp": ("dhcp", "lease", "offer", "discover", "ack"),
        "tls": ("tls", "ssl", "sni", "alpn", "certificate", "clienthello", "serverhello"),
        "http": ("http", "https", "request", "response"),
        "vpn": ("vpn", "wireguard", "ipsec", "gre", "tunnel", "natt"),
        "quic": ("quic", "http/3", "dcid", "scid"),
        "transport": ("tcp", "udp", "syn", "ack", "rst", "fin", "port"),
        "router": ("router", "forward", "bridge", "interface", "iface", "phase", "component", "windivert", "wintun"),
        "arp": ("arp", "who-has", "is-at"),
    }

    def classify(self, prompt: str, state: AskDialogueState) -> Tuple[str, str]:
        low = (prompt or "").strip().lower()
        if not low:
            return "empty", state.active_topic

        if any(x in low for x in ("purge", "clear", "forget")):
            return "purge", self.guess_topic(prompt, state)
        if any(x in low for x in ("inspect sensitive", "sensitive dump", "unredacted")):
            return "inspect_sensitive", self.guess_topic(prompt, state)
        if any(x in low for x in ("inspect", "dump", "summary", "status")):
            return "inspect", self.guess_topic(prompt, state)
        if any(x in low for x in ("stats", "metrics", "statistics")):
            return "stats", self.guess_topic(prompt, state)
        if "tokens" in low:
            return "tokens", self.guess_topic(prompt, state)
        if any(x in low for x in ("emit", "snapshot")):
            return "emit", self.guess_topic(prompt, state)
        if any(x in low for x in ("compare", "versus", "vs ")):
            return "compare", self.guess_topic(prompt, state)
        if any(x in low for x in ("trace flow", "trace", "follow flow", "flow ")):
            return "trace_flow", self.guess_topic(prompt, state)
        if any(x in low for x in ("why", "explain", "diagnose", "what changed", "what is happening")):
            return "explain", self.guess_topic(prompt, state)
        return "general", self.guess_topic(prompt, state)

    def guess_topic(self, prompt: str, state: AskDialogueState) -> str:
        low = (prompt or "").lower()
        scores = Counter()
        for topic, words in self._TOPIC_HINTS.items():
            for w in words:
                if w in low:
                    scores[topic] += 3
        if "that flow" in low or "same flow" in low:
            if state.active_topic:
                scores[state.active_topic] += 2
        if scores:
            return scores.most_common(1)[0][0]
        return state.active_topic or "misc"


class AskKnowledgeRetriever:
    def __init__(self, ask_manager: "AskManager") -> None:
        self._am = ask_manager

    def retrieve(self, prompt: str, topic: str, intent: str) -> AskEvidenceBundle:
        token_lines = self._token_match_lines(prompt, limit=10)
        packets = self._am._retrieve_snippets(prompt, topk=18, per_topic_limit=10)
        flows = self._am._co_manager.packet_learner.snapshot_flows(topic, top_k=5)
        anomalies = [a for a in self._am._co_manager.packet_learner.get_numeric_anomalies(limit=24) if a["topic"] == topic][:6]
        stats = self._am._co_manager.compute_statistics_from_learned_data(
            topics=[topic],
            percentiles=[5, 25, 50, 75, 95],
            topk_categorical=8,
            min_count_for_stats=2,
        ).get(topic, {})
        related_topics = self._infer_related_topics(packets)
        if intent == "trace_flow" and self._am.state.active_flow_key:
            flow_key = self._am.state.active_flow_key
            packets = [pkt for pkt in packets if pkt.flow_key == flow_key or pkt.session_key == flow_key or pkt.route_key == flow_key] or packets
        return AskEvidenceBundle(
            topic=topic,
            prompt=prompt,
            packets=packets,
            flows=flows,
            anomalies=anomalies,
            stats=stats,
            token_lines=token_lines,
            related_topics=related_topics,
        )

    def _token_match_lines(self, prompt: str, limit: int) -> List[str]:
        tokens = [t for t in self._am._tokenize(prompt) if t and not t.isdigit()]
        seen = set()
        out: List[str] = []
        for tok, _ in Counter(tokens).most_common():
            for line in self._am._token_memory.fetch(tok, limit=4):
                if line in seen:
                    continue
                seen.add(line)
                out.append(line)
                if len(out) >= limit:
                    return out
        return out

    @staticmethod
    def _infer_related_topics(packets: List[KnowledgePacket]) -> List[str]:
        c = Counter()
        for pkt in packets:
            c[pkt.topic] += 1
            for rel in pkt.related_topics:
                c[str(rel)] += 1
        return [k for k, _ in c.most_common(5)]


class AskAnalysisEngine:
    TOPIC_TIPS = {
        "dns": "Compare query bursts, repeated qnames, resolver spread, LLMNR/mDNS leakage, and response pairing.",
        "dhcp": "Track Discover→Offer→Request→Ack continuity, relay metadata, lease reuse, and option consistency.",
        "tls": "Check ClientHello→ServerHello progression, SNI/ALPN, certificate timing, alert emissions, and half-open handshakes.",
        "http": "Compare request/response timing, port patterns, persistent connection reuse, and reset-heavy edges.",
        "vpn": "Watch NAT-T continuity, SPI stability, tunnel keepalives, path MTU clues, and stage drift across interfaces.",
        "quic": "Track connection IDs, retry/version negotiation, path migration, and repeated small-packet control loops.",
        "transport": "Check SYN/ACK completion, reset ratio, same-flow stage drift, tiny-packet storms, and unusual port concentration.",
        "router": "Compare iface-local behavior, forwarding stages, TTL spread, route reuse, and per-component flow transitions.",
        "arp": "Look for repeated who-has storms, unresolved peers, MAC churn, and route/interface mismatch.",
        "misc": "Reduce to one interface and one flow, then compare direction, TTL, stage, component, and repeat density.",
    }

    def analyze(self, intent: str, evidence: AskEvidenceBundle, state: AskDialogueState) -> AskAnalysis:
        topic = evidence.topic or "misc"
        stats = evidence.stats or {}
        numeric = stats.get("numeric", {})
        categorical = stats.get("categorical", {})
        obs: List[str] = []
        warns: List[str] = []
        steps: List[str] = []

        if "length" in numeric:
            st = numeric["length"]
            obs.append(f"avg length={st.get('mean', 0):.1f}B p95={st.get('p95', st.get('max', 0)):.1f}B")
        if "entropy" in numeric:
            st = numeric["entropy"]
            obs.append(f"avg entropy={st.get('mean', 0):.2f} max={st.get('max', 0):.2f}")
            if st.get("mean", 0.0) > 6.5:
                warns.append("payloads are generally high entropy, so expect encrypted or compressed traffic patterns")
        if "confidence" in numeric:
            st = numeric["confidence"]
            obs.append(f"avg confidence={st.get('mean', 0):.2f}")
        if "rps" in numeric:
            st = numeric["rps"]
            obs.append(f"activity mean={st.get('mean', 0):.2f}/s p95={st.get('p95', st.get('max', 0)):.2f}/s")
        if "topic_diversity" in numeric:
            st = numeric["topic_diversity"]
            obs.append(f"diversity mean={st.get('mean', 0):.2f}")

        for feat in ("port", "iface", "component", "phase", "proto"):
            top = categorical.get(feat, {}).get("top_k", [])
            if top:
                obs.append(f"{feat}=" + ", ".join(f"{v}({c})" for v, c in top[:4]))

        if evidence.anomalies:
            top_anom = evidence.anomalies[0]
            warns.append(
                f"recent anomaly: {top_anom['feature']} deviated (value={top_anom['value']:.2f}, z={top_anom['z_score']:.2f})"
            )

        if topic in ("router", "transport"):
            if categorical.get("iface", {}).get("unique_count", 0) > 2:
                warns.append("same topic is spanning several interfaces, which can indicate mirroring, rebroadcast, or path duplication")
            if categorical.get("phase", {}).get("unique_count", 0) > 2:
                warns.append("same topic spans many phases, which can indicate queue/forward/handled drift")
        if topic == "tls":
            steps.append("check whether ClientHello-like events are progressing into ServerHello / certificate stages")
        if topic == "dns":
            top_ports = categorical.get("port", {}).get("top_k", [])
            if any(p in {"137", "1900", "3702"} for p, _ in top_ports):
                warns.append("name-resolution side traffic may be mixed into the DNS topic")
        if evidence.flows:
            busiest = evidence.flows[0]
            steps.append(
                f"inspect busiest flow {busiest['key']} across iface={busiest.get('iface')} and stages={busiest.get('top_stages')}"
            )

        tip = self.TOPIC_TIPS.get(topic, self.TOPIC_TIPS["misc"])
        steps.append(tip)

        summary = self._make_summary(intent, topic, evidence, obs, warns)
        confidence = self._estimate_confidence(evidence, warns)

        return AskAnalysis(
            topic=topic,
            answer_mode=intent,
            observations=obs[:10],
            warnings=warns[:6],
            next_steps=steps[:5],
            concise_summary=summary,
            confidence=confidence,
        )

    @staticmethod
    def _make_summary(
        intent: str,
        topic: str,
        evidence: AskEvidenceBundle,
        observations: List[str],
        warnings: List[str],
    ) -> str:
        packet_count = len(evidence.packets)
        flow_count = len(evidence.flows)
        anomaly_count = len(evidence.anomalies)
        base = f"Topic {topic.upper()} with {packet_count} retrieved evidence item(s), {flow_count} active flow summary item(s)"
        if anomaly_count:
            base += f", and {anomaly_count} recent anomaly marker(s)"
        if intent == "compare":
            base += ". Comparison mode is active."
        elif intent == "trace_flow":
            base += ". Flow-trace mode is active."
        elif intent == "explain":
            base += ". Explanation mode is active."
        if warnings:
            base += f" Primary caution: {warnings[0]}."
        elif observations:
            base += f" Primary observation: {observations[0]}."
        return base

    @staticmethod
    def _estimate_confidence(evidence: AskEvidenceBundle, warnings: List[str]) -> float:
        score = 0.25
        if evidence.packets:
            score += min(0.25, 0.02 * len(evidence.packets))
        if evidence.stats:
            score += 0.20
        if evidence.flows:
            score += 0.15
        if warnings:
            score += 0.05
        return max(0.05, min(0.95, score))


class AskResponseComposer:
    DEFAULT_REDACTIONS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|$)){4}\b"), "<IP4>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<MAC>"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<EMAIL>"),
    ]

    def __init__(self, ask_manager: "AskManager") -> None:
        self._am = ask_manager

    def compose(
        self,
        intent: str,
        evidence: AskEvidenceBundle,
        analysis: AskAnalysis,
        *,
        redact: bool = True,
    ) -> str:
        if intent == "general" and evidence.token_lines and not evidence.packets:
            lines = ["Using token matches from history:"]
            for s in evidence.token_lines[:8]:
                lines.append(f"• {self._present(s, redact=redact, max_len=220)}")
            return "\n".join(lines)

        lines: List[str] = [f"Topic: {analysis.topic.upper()}"]
        lines.append(f"Mode: {analysis.answer_mode}")
        lines.append(f"Confidence: {analysis.confidence:.2f}")
        lines.append("")
        lines.append(analysis.concise_summary)

        if evidence.token_lines:
            lines.append("")
            lines.append("Token matches from history:")
            for s in evidence.token_lines[:6]:
                lines.append(f"• {self._present(s, redact=redact, max_len=220)}")

        if evidence.packets:
            lines.append("")
            lines.append("Relevant evidence:")
            for pkt in evidence.packets[:8]:
                rendered = self._am._payload_to_text(pkt.payload, redact=redact, include_raw=False, topic=pkt.topic)
                if rendered:
                    lines.append(f"• {self._present(rendered, redact=False, max_len=220)}")

        if analysis.observations:
            lines.append("")
            lines.append("Observations:")
            for row in analysis.observations[:8]:
                lines.append(f"• {row}")

        if evidence.flows:
            lines.append("")
            lines.append("Busy flows:")
            for flow in evidence.flows[:4]:
                lines.append(
                    "• "
                    + self._present(flow["key"], redact=redact, max_len=120)
                    + f" (packets={flow['packets']}, bytes={flow['bytes']}, iface={flow.get('iface')})"
                )

        if analysis.warnings:
            lines.append("")
            lines.append("Warnings:")
            for row in analysis.warnings[:5]:
                lines.append(f"• {row}")

        if analysis.next_steps:
            lines.append("")
            lines.append("Next step:")
            lines.append(f"• {analysis.next_steps[0]}")
            if len(analysis.next_steps) > 1:
                lines.append("Consider checking:")
                for row in analysis.next_steps[1:4]:
                    lines.append(f"• {row}")

        return "\n".join(lines)

    def _present(self, s: str, *, redact: bool, max_len: int) -> str:
        out = s
        if redact:
            for pat, repl in self.DEFAULT_REDACTIONS:
                out = pat.sub(repl, out)
        if len(out) > max_len:
            out = out[: max_len - 3] + "..."
        return out


class AskCommandDispatcher:
    def __init__(self, ask_manager: "AskManager") -> None:
        self._am = ask_manager

    def maybe_handle(self, intent: str, prompt: str, topic: str) -> Optional[str]:
        if intent == "empty":
            return "Say something and I’ll analyze it."
        if intent == "purge":
            removed = self._am._co_manager.purge_topic(topic)
            return f"Purged topic '{topic}' ({removed} item(s))."
        if intent == "inspect_sensitive":
            return self._am._format_inspect(redact=False)
        if intent == "inspect":
            return self._am._format_inspect(redact=True)
        if intent == "stats":
            stats = self._am._co_manager.compute_statistics_from_learned_data(
                topics=[],
                percentiles=[5, 25, 50, 75, 95],
                topk_categorical=8,
                min_count_for_stats=2,
            )
            return self._am._format_stats(stats)
        if intent == "tokens":
            return self._am._raw_from_tokens(prompt, limit=12)
        if intent == "emit":
            cfg = self._am._co_manager._default_emit_builder()
            code = self._am._co_manager.generate_class_from_config(cfg)
            return f"Emitted snapshot class '{cfg.get('class_name')}' ({len(code)} bytes)."
        return None


class AskManagerChatGenerator:
    """
    Backward-compatible chat generator wrapper.
    It preserves the original constructor signature while delegating to the
    split retrieval / analysis / composition pipeline when bound to an
    AskManager instance.
    """

    TOPIC_TIPS = AskAnalysisEngine.TOPIC_TIPS

    def __init__(
        self,
        token_store: Callable[[str, int], Sequence[str]],
        knowledge_retriever: Callable[[str, int, int], List[KnowledgePacket]],
        knowledge_exporter: Callable[[], Dict[str, List[Dict[str, Any]]]],
        payload_formatter: Callable[[Dict[str, Any], bool, bool, Optional[str]], str],
        packet_learner_ref: PacketLearnerManager,
        stats_manager_ref: StatisticsManager,
        *,
        per_token_limit: int = 6,
        max_token_lines: int = 8,
        max_hint_lines: int = 8,
        rng_seed: Optional[int] = None,
        redactions: Optional[List[Tuple[re.Pattern, str]]] = None,
    ) -> None:
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
        self._redactions = list(redactions or AskResponseComposer.DEFAULT_REDACTIONS)
        self._am = getattr(knowledge_retriever, "__self__", None)

    def generate(self, prompt: str, *, redact: bool) -> str:
        if self._am is not None and hasattr(self._am, '_intent_router'):
            intent, topic = self._am._intent_router.classify(prompt, self._am.state)
            evidence = self._am._retriever.retrieve(prompt, topic, intent)
            analysis = self._am._analysis_engine.analyze(intent, evidence, self._am.state)
            return self._am._composer.compose(intent, evidence, analysis, redact=redact)

        tokens = [t for t in AskManager._TOKEN_RE.findall((prompt or '').lower()) if t and not t.isdigit()]
        token_lines: List[str] = []
        seen = set()
        for tok, _ in Counter(tokens).most_common():
            try:
                lines = self._token_store(tok, self._per_token_limit) or []
            except Exception:
                lines = []
            for line in lines:
                if not line or line in seen:
                    continue
                seen.add(line)
                token_lines.append(line)
                if len(token_lines) >= self._max_token_lines:
                    break
            if len(token_lines) >= self._max_token_lines:
                break
        if token_lines:
            lines = ["Using token matches from history:"]
            for s in token_lines[: self._max_token_lines]:
                lines.append(f"• {s[:220]}")
            return "\n".join(lines)
        packets = self._knowledge_retriever(prompt, topk=12, per_topic_limit=8)
        topic = packets[0].topic if packets else 'misc'
        stats = self._sm.compute(
            online_num_stats=self._pl.get_all_online_numeric_stats(),
            cat_counters=self._pl.get_all_categorical_counters(),
            recent_numeric_vectors=self._pl.get_recent_numeric_vectors(),
            topics=[topic],
            percentiles=[50, 95],
            topk_categorical=6,
            min_count_for_stats=2,
        ).get(topic, {})
        numeric = stats.get('numeric', {})
        categorical = stats.get('categorical', {})
        lines = [f"Topic: {topic.upper()}"]
        if packets:
            lines.append('Relevant evidence:')
            for pkt in packets[: self._max_hint_lines]:
                try:
                    s = self._payload_formatter(pkt.payload, redact=redact, include_raw=False, topic=pkt.topic)
                except Exception:
                    s = ''
                if s:
                    lines.append(f"• {s[:220]}")
        obs = []
        if 'length' in numeric:
            st = numeric['length']
            obs.append(f"avg length={st.get('mean', 0):.1f}B p95={st.get('p95', st.get('max', 0)):.1f}B")
        if 'entropy' in numeric:
            st = numeric['entropy']
            obs.append(f"avg entropy={st.get('mean', 0):.2f} max={st.get('max', 0):.2f}")
        for feat in ('port', 'iface', 'component', 'phase', 'proto'):
            top = categorical.get(feat, {}).get('top_k', [])
            if top:
                obs.append(f"{feat}=" + ", ".join(f"{v}({c})" for v, c in top[:4]))
        if obs:
            lines.append('')
            lines.append('Observations:')
            for row in obs[:8]:
                lines.append(f"• {row}")
        flows = self._pl.snapshot_flows(topic, top_k=3)
        if flows:
            lines.append('')
            lines.append('Busy flows:')
            for flow in flows[:3]:
                lines.append(f"• {flow['key'][:120]} (packets={flow['packets']}, bytes={flow['bytes']}, iface={flow['iface']})")
        lines.append('')
        lines.append(f"Next step: {self.TOPIC_TIPS.get(topic, self.TOPIC_TIPS['misc'])}")
        return "\n".join(lines)

    def _tokenize(self, text: str) -> List[str]:
        return [t.lower() for t in AskManager._TOKEN_RE.findall((text or ""))]

    def _fetch_token_lines(self, tokens: Iterable[str], per_token_limit: Optional[int] = None) -> List[str]:
        limit = self._per_token_limit if per_token_limit is None else int(per_token_limit)
        freq = Counter([t for t in tokens if t])
        seen = set()
        out: List[str] = []
        for tok, _ in freq.most_common():
            try:
                lines = self._token_store(tok, limit) or []
            except Exception:
                lines = []
            for line in lines:
                if not line or line in seen:
                    continue
                seen.add(line)
                out.append(line)
                if len(out) >= self._max_token_lines:
                    return out
        return out

    def _guess_topic(self, prompt: str, packets: List[KnowledgePacket]) -> str:
        if self._am is not None and hasattr(self._am, '_intent_router'):
            try:
                return self._am._intent_router.guess_topic(prompt, self._am.state)
            except Exception:
                pass
        low = (prompt or "").lower()
        score = Counter()
        lex = {
            "dns": ["dns", "resolver", "qname", "llmnr", "mdns", "port 53", "port 1900", "port 3702", "port 137"],
            "dhcp": ["dhcp", "lease", "offer", "discover", "ack", "option"],
            "tls": ["tls", "ssl", "sni", "alpn", "certificate", "handshake", "clienthello", "serverhello"],
            "http": ["http", "https", "request", "response", "18080"],
            "vpn": ["vpn", "wireguard", "ipsec", "esp", "ah", "gre", "natt", "tunnel"],
            "quic": ["quic", "http/3", "dcid", "scid"],
            "transport": ["tcp", "udp", "icmp", "syn", "ack", "rst", "fin", "port"],
            "router": ["router", "forward", "interface", "iface", "bridge", "wintun", "windivert", "phase", "component"],
            "arp": ["arp", "who-has", "is-at"],
        }
        for topic, words in lex.items():
            for w in words:
                if w in low:
                    score[topic] += 5
        for pkt in packets:
            score[pkt.topic] += 4
            attrs = pkt.payload.get("attributes", {}) if isinstance(pkt.payload, dict) else {}
            if attrs.get("iface_in"):
                score["router"] += 1
            if attrs.get("mdns"):
                score["dns"] += 2
            if attrs.get("hs_type_name"):
                score["tls"] += 3
            if attrs.get("tcp_flags"):
                score["transport"] += 1
            if attrs.get("arp_op") is not None:
                score["arp"] += 3
        return score.most_common(1)[0][0] if score else "misc"

    def _collect_packet_hints(self, packets: List[KnowledgePacket], *, redact: bool) -> List[str]:
        out: List[str] = []
        for pkt in packets:
            try:
                s = self._payload_formatter(pkt.payload, redact=redact, include_raw=False, topic=pkt.topic)
            except Exception:
                s = ""
            if s:
                out.append(self._present(s, redact=False, max_len=180))
        return out

    def _observations(self, topic: str, learned_stats: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        numeric = learned_stats.get("numeric", {}) if isinstance(learned_stats, dict) else {}
        categorical = learned_stats.get("categorical", {}) if isinstance(learned_stats, dict) else {}
        if "length" in numeric:
            st = numeric["length"]
            out.append(f"avg length={st.get('mean', 0):.1f}B p95={st.get('p95', st.get('max', 0)):.1f}B")
        if "entropy" in numeric:
            st = numeric["entropy"]
            out.append(f"avg entropy={st.get('mean', 0):.2f} max={st.get('max', 0):.2f}")
        if "confidence" in numeric:
            st = numeric["confidence"]
            out.append(f"avg confidence={st.get('mean', 0):.2f}")
        if "rps" in numeric:
            st = numeric["rps"]
            out.append(f"activity mean={st.get('mean', 0):.2f}/s p95={st.get('p95', st.get('max', 0)):.2f}/s")
        if "topic_diversity" in numeric:
            st = numeric["topic_diversity"]
            out.append(f"diversity mean={st.get('mean', 0):.2f}")
        for feat in ("port", "iface", "component", "phase", "proto"):
            top = categorical.get(feat, {}).get("top_k", [])
            if top:
                out.append(f"{feat}=" + ", ".join(f"{v}({c})" for v, c in top[:4]))
        return out

    def _followup_questions(self, topic: str, learned_stats: Dict[str, Any], recent_flows: List[Dict[str, Any]]) -> List[str]:
        qs: List[str] = []
        categorical = learned_stats.get("categorical", {}) if isinstance(learned_stats, dict) else {}
        if topic in ("router", "transport"):
            if categorical.get("iface", {}).get("unique_count", 0) > 2:
                qs.append("Does the same flow appear on multiple interfaces, suggesting mirroring, rebroadcast, or path duplication?")
            if categorical.get("phase", {}).get("unique_count", 0) > 2:
                qs.append("Do the same packets drift across phases in the wrong order, suggesting queue/forward/handled overlap?")
        if topic == "dns":
            top_ports = categorical.get("port", {}).get("top_k", [])
            if any(p in {"1900", "3702", "137"} for p, _ in top_ports):
                qs.append("Is non-classic name resolution traffic being mixed into your DNS topic and muddying the chat summaries?")
        if topic == "tls":
            qs.append("Are there repeated ClientHello-like events without stable ServerHello progression?")
        if recent_flows:
            qs.append("Can you isolate one of the busiest flows and compare it across iface, phase, and component?")
        return qs

    def _present(self, s: str, *, redact: bool, max_len: int) -> str:
        out = s
        if redact:
            for pat, repl in self._redactions:
                out = pat.sub(repl, out)
        if len(out) > max_len:
            out = out[: max_len - 3] + "..."
        return out


class AskManager:
    _RE_IPv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
    _RE_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
    _RE_HEX = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
    _TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+", re.UNICODE)

    def __init__(self, co_manager_ref: Any, *, max_messages: int = 500, default_ttl: float = 180.0, rng_seed: Optional[int] = None) -> None:
        self._co_manager = co_manager_ref
        self._lock = threading.RLock()
        self._messages: Deque[Tuple[str, str]] = deque(maxlen=max_messages)
        self._default_ttl = float(default_ttl)
        self._rng = random.Random(rng_seed if rng_seed is not None else int(time.time()))
        self._token_bank: Dict[str, Deque[Tuple[str, str, float]]] = defaultdict(lambda: deque(maxlen=50000))
        self._token_memory = AskTokenMemory()
        self._message_store = AskMessageStore(max_messages=max_messages)
        self.state = AskDialogueState()
        self._intent_router = AskIntentRouter()
        self._retriever = AskKnowledgeRetriever(self)
        self._analysis_engine = AskAnalysisEngine()
        self._composer = AskResponseComposer(self)
        self._dispatcher = AskCommandDispatcher(self)
        self.chat_generator = AskManagerChatGenerator(
            token_store=self._fetch_token_lines_for_chatgen,
            knowledge_retriever=self._retrieve_snippets,
            knowledge_exporter=self._export_knowledge,
            payload_formatter=self._payload_to_text,
            packet_learner_ref=self._co_manager.packet_learner,
            stats_manager_ref=self._co_manager.stats_manager,
            rng_seed=rng_seed,
        )

    def ask(self, prompt: str) -> str:
        prompt = (prompt or "").strip()
        if not prompt:
            return "Say something and I’ll analyze it."

        self._submit_message(prompt, role="user")
        intent, topic = self._intent_router.classify(prompt, self.state)

        try:
            reply = self._dispatcher.maybe_handle(intent, prompt, topic)
            if reply is None:
                evidence = self._retriever.retrieve(prompt, topic, intent)
                analysis = self._analysis_engine.analyze(intent, evidence, self.state)
                reply = self._composer.compose(intent, evidence, analysis, redact=True)
                self._update_state(prompt, reply, intent, topic, evidence)
            else:
                self._update_state(prompt, reply, intent, topic, None)
        except Exception as ex:
            reply = f"Internal error while answering: {type(ex).__name__}: {ex}"
            self._co_manager._log(f"[AskManager] Error: {ex}\n{traceback.format_exc()}", 1)

        self._submit_message(reply, role="assistant")
        return reply

    def _update_state(
        self,
        prompt: str,
        reply: str,
        intent: str,
        topic: str,
        evidence: Optional[AskEvidenceBundle],
    ) -> None:
        self.state.active_topic = topic or self.state.active_topic or "misc"
        self.state.last_intent = intent
        self.state.last_prompt = prompt
        self.state.last_reply = reply
        self.state.last_ts = time.time()
        if evidence:
            self.state.last_packets = list(evidence.packets[:12])
            if evidence.flows:
                self.state.active_flow_key = evidence.flows[0]["key"]
            if intent == "compare":
                self.state.compared_topics = evidence.related_topics[:2]

    def _submit_message(self, text: str, *, role: str) -> None:
        with self._lock:
            self._messages.append((role, text))
        self._message_store.add(role, text)
        if role == "user":
            self._index_tokens(text, role=role)

        topic = self._guess_topic(text)
        pkt = KnowledgePacket(
            topic=topic,
            payload={
                "attributes": {
                    "summary": self._summarize(text, 220),
                    "length": len(text),
                    "uppercase_ratio": self._uppercase_ratio(text),
                    "tokens": self._tokenize(text)[:20],
                },
                "raw_text": text[:2000],
            },
            ttl=self._default_ttl,
            source=role,
            tags=self._infer_tags(text),
            importance=min(9, 1 + len(text) // 180),
            confidence=0.75,
            component_name="ask-manager",
            path_stage="chat",
        )
        self._co_manager.submit_event(
            topic=pkt.topic,
            attributes=pkt.payload.get("attributes"),
            ttl=pkt.ttl,
            source=pkt.source,
            tags=pkt.tags,
            importance=pkt.importance,
        )

    def _format_inspect(self, *, redact: bool) -> str:
        snap = self._export_knowledge()
        if not snap:
            return "I don’t have non-expired knowledge yet."
        lines = ["Knowledge snapshot:"]
        for topic, items in sorted(snap.items(), key=lambda kv: kv[0])[:8]:
            lines.append(f"[{topic}] {len(items)} item(s)")
            for row in items[:6]:
                payload = row.get("payload") or {}
                iface = row.get("iface")
                source = row.get("source")
                summary = self._payload_to_text(payload, redact=redact, include_raw=False, topic=topic)
                bits = [f"source={source}", f"iface={iface}"] if iface or source else []
                prefix = f"  - {' '.join(bits)} ".rstrip()
                lines.append(f"{prefix}{summary}" if summary else f"{prefix}(no summary)")
        return "\n".join(lines)

    def _format_stats(self, stats: Dict[str, Any]) -> str:
        if not stats:
            return "No statistics available yet."
        lines = ["Statistics snapshot:"]
        for topic, block in sorted(stats.items(), key=lambda kv: kv[0])[:10]:
            lines.append(f"[{topic}]")
            numeric = block.get("numeric", {})
            categorical = block.get("categorical", {})
            if numeric:
                for feat, st in sorted(numeric.items()):
                    lines.append(
                        f"  - {feat}: count={st.get('count', 0)} mean={st.get('mean', 0):.3f} "
                        f"std={st.get('std', 0):.3f} min={st.get('min', 0):.3f} max={st.get('max', 0):.3f}"
                    )
            if categorical:
                for feat, info in sorted(categorical.items()):
                    top_k = info.get("top_k", [])[:4]
                    rendered = ", ".join(f"{v}({c})" for v, c in top_k)
                    lines.append(
                        f"  - {feat}: unique={info.get('unique_count', 0)} total={info.get('total_count', 0)} top={rendered}"
                    )
        return "\n".join(lines)

    def _index_tokens(self, text: str, *, role: str) -> None:
        raw = text[:2000]
        ts = time.time()
        self._token_memory.index(text, role=role)
        for tok in self._tokenize(text):
            if tok and not tok.isdigit():
                self._token_bank[tok].append((role, raw, ts))

    def _raw_from_tokens(self, query: str, *, limit: int = 12) -> str:
        hits = []
        seen = set()
        for tok in self._tokenize(query):
            for line in self._token_memory.fetch(tok, limit=3):
                if line in seen:
                    continue
                seen.add(line)
                hits.append(line)
                if len(hits) >= limit:
                    break
            if len(hits) >= limit:
                break
        if not hits:
            return "No token hits found."
        return "Token hits:\n" + "\n".join(f"- {line}" for line in hits)

    def _fetch_token_lines_for_chatgen(self, token: str, limit: int) -> Sequence[str]:
        dq = self._token_bank.get(token)
        if not dq:
            return []
        lines = [line for role, line, _ts in list(dq)[-limit:][::-1] if role == "user"]
        if lines:
            return lines
        return self._token_memory.fetch(token, limit=limit)

    def _retrieve_snippets(self, prompt: str, *, topk: int = 6, per_topic_limit: int = 3) -> List[KnowledgePacket]:
        tokens = [t.lower() for t in self._tokenize(prompt) if t]
        topic = self._guess_topic(prompt)
        now = time.time()

        scored: List[Tuple[float, KnowledgePacket]] = []
        export = self._co_manager._export_nonexpired_packets()
        topic_counter = Counter()

        for pkt in export:
            pkt_text = self._payload_to_text(pkt.payload, redact=False, include_raw=True, topic=pkt.topic).lower()
            score = 0.0
            if pkt.topic == topic:
                score += 3.0
            if pkt.topic == self.state.active_topic:
                score += 1.0
            for tok in tokens:
                if tok and tok in pkt_text:
                    score += 1.0
                if tok and tok in " ".join(map(str, pkt.tags)).lower():
                    score += 0.75
                if tok and tok == str(pkt.iface).lower():
                    score += 0.5
                if tok and tok in str(pkt.flow_key).lower():
                    score += 1.25
            if self.state.active_flow_key and self.state.active_flow_key in (
                pkt.flow_key,
                pkt.session_key,
                pkt.route_key,
            ):
                score += 2.5
            score += min(1.0, float(pkt.importance) * 0.1)
            score += min(1.0, float(pkt.confidence) * 0.5)
            age_s = max(0.0, now - pkt.ts)
            score += max(0.0, 1.0 - (age_s / 600.0))
            if score > 0.0:
                topic_counter[pkt.topic] += 1
                scored.append((score, pkt))

        scored.sort(key=lambda x: (x[0], x[1].importance, x[1].ts), reverse=True)

        out: List[KnowledgePacket] = []
        topic_seen: Counter = Counter()
        for _, pkt in scored:
            if topic_seen[pkt.topic] >= per_topic_limit:
                continue
            out.append(pkt)
            topic_seen[pkt.topic] += 1
            if len(out) >= topk:
                break

        if not out and topic:
            out = self._co_manager.packet_learner.get_recent_packets(topic, limit=min(topk, 8))

        return out

    def _export_knowledge(self) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for pkt in self._co_manager._export_nonexpired_packets():
            out[pkt.topic].append(
                {
                    "topic": pkt.topic,
                    "source": pkt.source,
                    "iface": pkt.iface,
                    "payload": copy.deepcopy(pkt.payload),
                    "importance": pkt.importance,
                    "confidence": pkt.confidence,
                    "flow_key": pkt.flow_key,
                    "session_key": pkt.session_key,
                    "route_key": pkt.route_key,
                    "ts": pkt.ts,
                }
            )
        return dict(out)

    def _payload_to_text(self, payload: Dict[str, Any], *, redact: bool, include_raw: bool, topic: Optional[str]) -> str:
        if not isinstance(payload, dict):
            return ""
        attrs = payload.get("attributes", {}) if isinstance(payload.get("attributes"), dict) else {}
        methods = payload.get("methods", {}) if isinstance(payload.get("methods"), dict) else {}
        parts: List[str] = []

        for k, v in sorted(attrs.items(), key=lambda kv: str(kv[0])):
            if isinstance(v, (str, int, float, bool)):
                parts.append(f"{k}={v}")
            elif isinstance(v, (list, tuple)):
                parts.append(f"{k}=" + ",".join(map(str, list(v)[:8])))

        if methods:
            parts.append("methods=" + ",".join(sorted(map(str, methods.keys()))[:12]))

        if include_raw:
            raw_text = payload.get("raw_text")
            if isinstance(raw_text, str) and raw_text.strip():
                parts.append("raw=" + raw_text[:220])

        text = " ".join(parts)
        if redact:
            text = self._RE_IPv4.sub("<IP4>", text)
            text = self._RE_MAC.sub("<MAC>", text)
            text = self._RE_HEX.sub("<HEX>", text)
        return text[:1200]

    def _guess_topic(self, text: str) -> str:
        return self._intent_router.guess_topic(text, self.state)

    @staticmethod
    def _summarize(text: str, max_len: int) -> str:
        text = re.sub(r"\s+", " ", text or "").strip()
        return text if len(text) <= max_len else text[: max_len - 3] + "..."

    @staticmethod
    def _uppercase_ratio(text: str) -> float:
        letters = [c for c in (text or "") if c.isalpha()]
        if not letters:
            return 0.0
        return sum(1 for c in letters if c.isupper()) / len(letters)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return [t.lower() for t in AskManager._TOKEN_RE.findall(text or "")]

    def _infer_tags(self, text: str) -> List[str]:
        low = (text or "").lower()
        tags = []
        for tag in ("dns", "dhcp", "tls", "http", "vpn", "quic", "router", "transport", "arp", "flow", "compare", "stats", "snapshot"):
            if tag in low:
                tags.append(tag)
        return tags[:12]


# ======================================================================================
# Snapshot builder
# ======================================================================================


class SnapshotBuilder:
    def __init__(self, logger: Callable[[str, int], None], ask_manager_ref: AskManager, packet_learner_ref: PacketLearnerManager, rng_seed: Optional[int] = None) -> None:
        self._log = logger
        self._am = ask_manager_ref
        self._pl = packet_learner_ref
        self._rng = random.Random(rng_seed)
        self._np_rng = np.random.default_rng(rng_seed)

    def build(self, config: Dict[str, Any], knowledge_gatherer: Callable[..., Tuple[Dict, Dict]], insights_fetcher: Callable[..., Dict], stats_computer: Callable[..., Dict], method_generator: Callable[..., Dict]) -> str:
        class_name = config.get("class_name", "GeneratedSnapshot")
        topics = config.get("topics") or []
        attrs, methods = knowledge_gatherer(topics=topics)
        if config.get("include_insights", True):
            attrs["_insights"] = insights_fetcher(topics=topics)
        stats = {}
        if config.get("include_statistics", True):
            stats = stats_computer()
            attrs["_statistics"] = stats
            methods.update(method_generator(stats=stats))
        topic_list = topics or list(stats.keys())[:8] or list(self._pl.get_concept_counts().keys())[:8]
        attrs["_flow_overview"] = {topic: self._pl.snapshot_flows(topic, top_k=3) for topic in topic_list}
        attrs["_recent_numeric"] = {topic: self._pl.snapshot_recent_numeric(topic) for topic in topic_list}
        attrs["_semantic_density"] = {topic: self._pl.topic_semantic_density(topic) for topic in topic_list}
        methods["ask_tip"] = {
            "args": "self, topic=None",
            "body": "\\n".join([
                "t = topic or 'misc'",
                "if not getattr(self, '_am', None):",
                "    return 'No AskManager bound.'",
                "return self._am.chat_generator.TOPIC_TIPS.get(t, self._am.chat_generator.TOPIC_TIPS['misc'])",
            ]),
        }
        methods["top_observed_topics"] = {
            "args": "self",
            "body": "\\n".join([
                "stats = getattr(self, '_statistics', {}) if hasattr(self, '_statistics') else {}",
                "return list(stats.keys())",
            ]),
        }
        doc = self._build_docstring(class_name, topic_list, stats)
        self._log(f"[CodeOutput] 🧠 Generating class '{class_name}' (topics={topic_list or 'ALL'}; attrs={len(attrs)}; methods={len(methods)})", 1)
        return MiniTemplateEngine.render_class(class_name, attrs, methods, doc=doc)

    def _build_docstring(self, class_name: str, topics: List[str], stats: Dict[str, Any]) -> str:
        if not topics:
            topics = ["misc"]
        seed_words = []
        for topic in topics[:6]:
            seed_words.append(topic)
            vocab = self._pl.snapshot_vocab(topic, top_k=3)
            seed_words.extend([w for w, _ in vocab[:2]])
        seed_words = [w for w in seed_words if w]
        if not seed_words:
            return f"{class_name}: generated from live network knowledge."
        words = [seed_words[0].capitalize()]
        for _ in range(min(20, len(seed_words) * 2)):
            words.append(self._rng.choice(seed_words))
        sentence = " ".join(words)
        return f"{class_name}: generated from live network knowledge; topics={', '.join(topics[:8])}; {sentence}."


class CodeOutputManager:
    MAX_PACKETS_PER_TOPIC = 256
    CLEANUP_INTERVAL_S = 5.0
    TOPIC_ALIASES: Dict[str, set] = {
        "tls": {"tls", "ssl", "handshake", "https"},
        "dns": {"dns", "mdns", "llmnr"},
        "dhcp": {"dhcp", "dhcpv6"},
        "arp": {"arp"},
        "http": {"http"},
        "quic": {"quic"},
        "vpn": {"ipsec", "isakmp", "natt", "esp", "ah", "vpn", "gre", "wireguard"},
        "kerberos": {"kerberos", "krb5"},
        "ntp": {"ntp"},
        "ssh": {"ssh"},
        "transport": {"tcp", "udp", "icmp"},
        "router": {"router", "l2", "ether", "forward", "wintun", "windivert", "bridge"},
        "misc": set(),
    }
    DEFAULT_TTLS: Dict[str, float] = {
        "tls": 300.0, "dns": 180.0, "dhcp": 180.0, "arp": 60.0, "http": 180.0, "quic": 180.0,
        "vpn": 240.0, "kerberos": 300.0, "ntp": 300.0, "ssh": 300.0,
        "transport": 180.0, "router": 180.0, "misc": 120.0,
    }
    PORT_TOPIC_HINTS = {
        443: "tls", 8443: "tls", 4443: "tls",
        80: "http", 8080: "http", 8000: "http", 18080: "http",
        53: "dns", 5353: "dns", 3702: "dns", 1900: "dns", 137: "dns",
        67: "dhcp", 68: "dhcp",
        500: "vpn", 4500: "vpn", 51820: "vpn",
        88: "kerberos",
        123: "ntp",
        22: "ssh",
        445: "router",
    }
    TLS_HANDSHAKE_TYPES = {0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate", 13: "CertificateRequest", 15: "CertificateVerify", 20: "Finished"}
    BRACKET_TAG_RE = re.compile(r"\[([A-Za-z0-9_ :#/-]+)\]")
    KV_TOKEN_RE = re.compile(r'(\b[\w\./:-]+)=(".*?"|\'.*?\'|[^\s]+)')
    NDJSON_SPLIT_RE = re.compile(r"\\r?\\n+")

    def __init__(self, router_logger: Any):
        self.logger = router_logger
        self._verbose = 1
        self._stop_event = threading.Event()
        self._bus_thread: Optional[threading.Thread] = None
        self._gen_thread: Optional[threading.Thread] = None
        self._clean_thread: Optional[threading.Thread] = None
        self._emit_thread: Optional[threading.Thread] = None
        self._generation_queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._bus_queue: "queue.Queue[Any]" = queue.Queue()
        self._knowledge_by_topic: Dict[str, Deque[KnowledgePacket]] = {}
        self._recent_packet_hashes: Deque[str] = deque(maxlen=4096)
        self._emit_history: Deque[Tuple[float, str]] = deque(maxlen=64)
        self._recent_emit_semantic_hash: Optional[str] = None
        self._k_lock = threading.Lock()
        self._external_sources: List[Tuple[queue.Queue, Optional[Callable[[Any], KnowledgePacket]], threading.Thread]] = []
        self._custom_aliases: Dict[str, set] = {}
        self._emitter_cfg = EmitterConfig()
        self._emit_builder: Callable[[], Dict[str, Any]] = self._default_emit_builder
        self._emit_sink: Callable[[str, Dict[str, Any]], None] = self._default_emit_sink
        self._ingest_since_emit = 0
        self._emit_seq = 0
        self._stats = Stats()
        self._hooks: Dict[str, List[Callable[..., None]]] = defaultdict(list)
        self.packet_learner = PacketLearnerManager(keep_raw_samples=True, logger=self._log, log_level=2)
        self.stats_manager = StatisticsManager()
        self.method_generator = SnapshotMethodGenerator()
        self.ask_manager = AskManager(co_manager_ref=self, rng_seed=9999)
        self.snapshot_builder = SnapshotBuilder(logger=self._log, ask_manager_ref=self.ask_manager, packet_learner_ref=self.packet_learner, rng_seed=2342)
        self.log_message("[CodeOutput] Manager initialized (advanced rewrite).")

    def ask(self, prompt: str) -> str:
        return self.ask_manager.ask(prompt)

    def set_verbose(self, level: int = 1) -> None:
        self._verbose = int(level)
        self.log_message(f"[CodeOutput] Verbose set to {self._verbose}.")

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

    def set_auto_emit_config(self, every_s: Optional[float] = None, jitter_s: Optional[float] = None, min_new_packets: Optional[int] = None, to_file: Optional[str] = None, min_semantic_delta: Optional[int] = None) -> None:
        with self._k_lock:
            if every_s is not None:
                self._emitter_cfg.every_s = float(every_s)
            if jitter_s is not None:
                self._emitter_cfg.jitter_s = float(jitter_s)
            if min_new_packets is not None:
                self._emitter_cfg.min_new_packets = int(min_new_packets)
            if to_file is not None:
                self._emitter_cfg.to_file = to_file
            if min_semantic_delta is not None:
                self._emitter_cfg.min_semantic_delta = int(min_semantic_delta)
        self._log(f"[CodeOutput] Auto-emitter config updated: {self._emitter_cfg}", 1)

    def add_sink(self, sink: Callable[[str, Dict[str, Any]], None]) -> None:
        self._hooks["post_emit"].append(lambda code, cfg: sink(code, cfg))

    def add_hook(self, event: str, callback: Callable[..., None]) -> None:
        self._hooks[event].append(callback)

    def _fire_hooks(self, event: str, **kwargs) -> None:
        for cb in list(self._hooks.get(event, [])):
            try:
                cb(**kwargs)
            except Exception as ex:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] Hook error ({event}): {ex}", 1)

    def start(self):
        if self._bus_thread and self._bus_thread.is_alive():
            return
        self._stop_event.clear()
        self._bus_thread = threading.Thread(target=self._bus_consumer_loop, daemon=True, name="CodeOutputBus")
        self._gen_thread = threading.Thread(target=self._generation_loop, daemon=True, name="CodeOutputGen")
        self._clean_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="CodeOutputCleanup")
        self._emit_thread = threading.Thread(target=self._auto_emit_loop, daemon=True, name="CodeOutputEmit")
        self._bus_thread.start()
        self._gen_thread.start()
        self._clean_thread.start()
        self._emit_thread.start()
        self._log("[CodeOutput] Threads started.", 1)

    def stop(self):
        self._stop_event.set()
        for q in (self._generation_queue, self._bus_queue):
            try:
                q.put_nowait(None)
            except Exception:
                pass
        for q, _, t in list(self._external_sources):
            try:
                q.put_nowait(None)
            except Exception:
                pass
            if t.is_alive():
                t.join(timeout=1.5)
        for t in (self._bus_thread, self._gen_thread, self._clean_thread, self._emit_thread):
            if t and t.is_alive():
                t.join(timeout=2.0)
        self._log("[CodeOutput] Manager stopped.", 1)

    def submit_packet(self, packet: Any, inbound_iface: Optional[str] = None, **context) -> None:
        try:
            self._bus_queue.put_nowait({"_kind": "packet", "value": packet, "iface": inbound_iface, "ctx": context})
        except Exception as ex:
            self._log(f"[CodeOutput] submit_packet failed: {ex}", 1)

    def submit_event(self, topic: str, attributes: Optional[Dict[str, Any]] = None, methods: Optional[Dict[str, Any]] = None, ttl: Optional[float] = None, source: Optional[str] = None, tags: Optional[List[str]] = None, importance: int = 0) -> None:
        payload: Dict[str, Any] = {}
        if attributes:
            payload["attributes"] = dict(attributes)
        if methods:
            payload["methods"] = dict(methods)
        pkt = KnowledgePacket(topic=topic or "misc", payload=payload or {"attributes": {}}, ttl=float(ttl if ttl is not None else self.DEFAULT_TTLS.get(topic or "misc", 120.0)), source=source, tags=list(tags or []), importance=int(importance), confidence=0.8)
        try:
            self._bus_queue.put_nowait({"_kind": "packet", "value": pkt, "iface": None, "ctx": {}})
        except Exception as ex:
            self._log(f"[CodeOutput] submit_event failed: {ex}", 1)

    def attach_external_source(self, src_queue: "queue.Queue[Any]", transform: Optional[Callable[[Any], KnowledgePacket]] = None, name: str = "ExternalCodeOutputSource") -> None:
        def _consume():
            while not self._stop_event.is_set():
                try:
                    item = src_queue.get(timeout=1.0)
                    if item is None:
                        break
                    if transform:
                        pkt = transform(item)
                        self._bus_queue.put_nowait({"_kind": "packet", "value": pkt, "iface": None, "ctx": {}})
                    else:
                        self._bus_queue.put_nowait({"_kind": "packet", "value": item, "iface": None, "ctx": {}})
                except queue.Empty:
                    continue
                except Exception as ex:
                    self._log(f"[CodeOutput] External source consumer error: {ex}", 1)
                    break
        t = threading.Thread(target=_consume, daemon=True, name=name)
        t.start()
        self._external_sources.append((src_queue, transform, t))

    def set_topic_aliases(self, aliases: Dict[str, Iterable[str]]) -> None:
        self._custom_aliases = {str(k).lower(): set(map(lambda x: str(x).lower(), v)) for k, v in aliases.items()}

    def queue_code_generation(self, config: Dict[str, Any]):
        self._generation_queue.put(config)

    def _auto_emit_loop(self):
        self._log("[CodeOutput] Auto-emitter loop started.", 1)
        while not self._stop_event.is_set():
            with self._k_lock:
                cfg = copy.deepcopy(self._emitter_cfg)
                delay = cfg.every_s + (random.uniform(0.0, cfg.jitter_s) if cfg.jitter_s > 0 else 0.0)
            if self._stop_event.wait(delay):
                break
            with self._k_lock:
                if cfg.min_new_packets > 0 and self._ingest_since_emit < cfg.min_new_packets:
                    continue
            if not self._can_emit_now(cfg):
                continue
            try:
                semantic_hash, semantic_delta = self._semantic_state_digest()
                if self._recent_emit_semantic_hash == semantic_hash:
                    with self._k_lock:
                        self._stats.emit_duplicates += 1
                    continue
                if semantic_delta < max(1, cfg.min_semantic_delta):
                    with self._k_lock:
                        self._stats.emit_duplicates += 1
                    continue
                self._fire_hooks("pre_emit")
                build_cfg = self._emit_builder()
                code = self.generate_class_from_config(build_cfg)
                code_hash = hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()
                self._emit_sink(code, build_cfg)
                self._fire_hooks("post_emit", code=code, cfg=build_cfg)
                with self._k_lock:
                    self._recent_emit_semantic_hash = semantic_hash
                    self._ingest_since_emit = 0
                    self._stats.emits += 1
                    self._emit_history.append((time.time(), code_hash))
                self._log(f"[CodeOutput] Auto-emitter produced hash={code_hash[:10]}… len={len(code)} bytes.", 1)
            except Exception as ex:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] auto-emit error: {ex}\\n{traceback.format_exc()}", 1)
        self._log("[CodeOutput] Auto-emitter loop stopped.", 1)

    def _can_emit_now(self, cfg: EmitterConfig) -> bool:
        if cfg.max_emit_rate_per_minute <= 0:
            return True
        now = time.time()
        cutoff = now - 60.0
        with self._k_lock:
            recent = [ts for ts, _ in self._emit_history if ts >= cutoff]
        return len(recent) < cfg.max_emit_rate_per_minute

    def _semantic_state_digest(self) -> Tuple[str, int]:
        with self._k_lock:
            snapshot = {
                topic: [
                    {"hash": pkt.semantic_hash(), "ts_bucket": int(pkt.ts // 5), "importance": pkt.importance, "iface": pkt.iface}
                    for pkt in list(dq)[-32:]
                    if not pkt.is_expired()
                ]
                for topic, dq in sorted(self._knowledge_by_topic.items())
            }
            prev = self._recent_emit_semantic_hash or ""
            raw = json.dumps(snapshot, sort_keys=True, default=str).encode("utf-8", "replace")
            cur = hashlib.sha256(raw).hexdigest()
            delta = 1
            if prev:
                hashes = set()
                for rows in snapshot.values():
                    for row in rows:
                        hashes.add(row["hash"])
                delta = len(hashes)
        return cur, delta

    def _default_emit_builder(self) -> Dict[str, Any]:
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        return {
            "class_name": f"Snapshot_{ts}",
            "topics": [],
            "attr_policy": "merge",
            "method_policy": "merge",
            "include_insights": True,
            "attr_aggregate": "list",
            "listify_singletons": True,
            "include_statistics": True,
            "percentiles": [5, 25, 50, 75, 95],
            "topk_categorical": 10,
            "min_count_for_stats": 2,
        }

    def _default_emit_sink(self, code: str, cfg: Dict[str, Any]) -> None:
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        name = cfg.get("class_name", "Snapshot")
        with self._k_lock:
            self._emit_seq += 1
            template = self._emitter_cfg.to_file
        if template:
            try:
                path = template.format(ts=ts, seq=self._emit_seq, name=name)
                folder = os.path.dirname(path)
                if folder:
                    os.makedirs(folder, exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(code)
                self._log(f"[CodeOutput] Wrote snapshot '{name}' to {path}", 1)
            except Exception as ex:
                self._log(f"[CodeOutput] Failed to write snapshot '{name}': {ex}", 1)
        else:
            self._log(f"[CodeOutput] Emit (no file sink) for '{name}' complete.", 1)
        try:
            summary = self.ask_manager.chat_generator.generate(prompt=f"Summarize the snapshot {name} and the most active network patterns.", redact=True)
            self._log(f"[CodeOutput] Chat summary for snapshot '{name}':\\n{summary}", 1)
        except Exception as ex:
            self._log(f"[CodeOutput] Chat summary failed for '{name}': {ex}", 1)

    def _insights_for_topics(self, topics: Iterable[str]) -> Dict[str, List[Tuple[str, int]]]:
        concepts = self.packet_learner.get_concept_counts()
        selected = list(topics) if topics else list(concepts.keys())
        return {topic: sorted(concepts.get(topic, {}).items(), key=lambda kv: (-kv[1], kv[0]))[:15] for topic in selected if concepts.get(topic)}

    def _default_snapshot_methods(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        return self.method_generator.generate(stats)

    def generate_class_from_config(self, config: Dict[str, Any]) -> str:
        attr_aggregate = (config.get("attr_aggregate") or "last").lower()
        gatherer = self._gather_knowledge_aggregate if attr_aggregate == "list" else self._gather_knowledge
        stats_computer = lambda: self.compute_statistics_from_learned_data(topics=config.get("topics") or [], percentiles=list(config.get("percentiles", [5, 25, 50, 75, 95])), topk_categorical=int(config.get("topk_categorical", 10)), min_count_for_stats=int(config.get("min_count_for_stats", 2)))
        method_generator = lambda stats: self._default_snapshot_methods(stats)
        return self.snapshot_builder.build(config=config, knowledge_gatherer=gatherer, insights_fetcher=self._insights_for_topics, stats_computer=stats_computer, method_generator=method_generator)

    def _generation_loop(self):
        while not self._stop_event.is_set():
            try:
                config = self._generation_queue.get(timeout=1)
                if config is None:
                    continue
                cls_name = config.get("class_name", "UnnamedClass")
                code = self.generate_class_from_config(config)
                self._log(f"[CodeOutput] Generated class '{cls_name}' ({len(code)} bytes).", 1)
            except queue.Empty:
                continue
            except Exception as ex:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] Generation loop error: {ex}\\n{traceback.format_exc()}", 1)

    def _cleanup_loop(self):
        while not self._stop_event.is_set():
            try:
                now = time.time()
                with self._k_lock:
                    for topic, dq in list(self._knowledge_by_topic.items()):
                        removed = 0
                        while dq and dq[0].is_expired(now):
                            dq.popleft()
                            removed += 1
                        if removed:
                            self._log(f"[CodeOutput] Purged {removed} expired packets from '{topic}'.", 1)
                        if not dq:
                            self._knowledge_by_topic.pop(topic, None)
                            self.packet_learner.purge_topic(topic)
            except Exception as ex:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] Cleanup error: {ex}\\n{traceback.format_exc()}", 1)
            finally:
                self._stop_event.wait(self.CLEANUP_INTERVAL_S)

    def _bus_consumer_loop(self):
        self._log("[CodeOutput] Bus consumer loop started.", 1)
        while not self._stop_event.is_set():
            try:
                item = self._bus_queue.get(timeout=1.0)
                if item is None or item.get("_kind") != "packet":
                    continue
                raw = item.get("value")
                iface = item.get("iface")
                ctx = item.get("ctx") or {}
                packets: List[KnowledgePacket] = []
                if isinstance(raw, KnowledgePacket):
                    packets = [self._finalize_packet(raw)]
                elif self._is_tls_record(raw):
                    packets = self._normalize_tls_record(raw)
                else:
                    spkt = self._coerce_to_scapy_packet(raw)
                    if spkt is not None:
                        packets = self._maybe_summarize_scapy(spkt, inbound_iface=iface, ctx=ctx)
                    if not packets:
                        packets = self._normalize_any(raw)
                if not packets:
                    continue
                with self._k_lock:
                    for pkt in packets:
                        if not pkt.topic or not isinstance(pkt.payload, dict):
                            self._stats.packets_dropped += 1
                            continue
                        sem = pkt.semantic_hash()
                        if sem in self._recent_packet_hashes:
                            pkt.importance = max(0, pkt.importance - 1)
                            pkt.confidence = max(0.1, pkt.confidence - 0.1)
                        self._recent_packet_hashes.append(sem)
                        dq = self._knowledge_by_topic.setdefault(pkt.topic, deque(maxlen=self.MAX_PACKETS_PER_TOPIC))
                        dq.append(pkt)
                        self._stats.packets_ingested += 1
                        self._stats.by_topic[pkt.topic] += 1
                        if pkt.iface:
                            self._stats.by_iface[str(pkt.iface)] += 1
                        if pkt.component_name:
                            self._stats.by_component[str(pkt.component_name)] += 1
                        if pkt.path_stage:
                            self._stats.by_stage[str(pkt.path_stage)] += 1
                        if pkt.source:
                            self._stats.by_source[str(pkt.source)] += 1
                        self.packet_learner.learn_from_packet(pkt)
                    self._ingest_since_emit += len(packets)
            except queue.Empty:
                continue
            except Exception as ex:
                with self._k_lock:
                    self._stats.errors += 1
                self._log(f"[CodeOutput] Bus consumer error: {ex}\\n{traceback.format_exc()}", 1)
        self._log("[CodeOutput] Bus consumer loop stopped.", 1)

    def _gather_knowledge(self, topics: Iterable[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
                    payload = pkt.payload or {}
                    if isinstance(payload.get("attributes"), dict):
                        attrs.update(payload["attributes"])
                    if isinstance(payload.get("methods"), dict):
                        methods.update(payload["methods"])
        return attrs, methods

    def _gather_knowledge_aggregate(self, topics: Iterable[str], max_per_attr: int = 12, prefer_order: str = "observed") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        now = time.time()
        agg: Dict[str, List[Any]] = defaultdict(list)
        methods: Dict[str, Any] = {}
        def add_attr(k: str, v: Any) -> None:
            if v is None:
                return
            lst = agg[k]
            if v not in lst:
                lst.append(v)
            if len(lst) > max_per_attr:
                del lst[: len(lst) - max_per_attr]
        with self._k_lock:
            topic_list = list(topics) if topics else list(self._knowledge_by_topic.keys())
            for topic in topic_list:
                dq = self._knowledge_by_topic.get(topic)
                if not dq:
                    continue
                for pkt in dq:
                    if pkt.is_expired(now):
                        continue
                    payload = pkt.payload or {}
                    attrs = payload.get("attributes", {})
                    if isinstance(attrs, dict):
                        for k, v in attrs.items():
                            add_attr(k, v)
                    if isinstance(payload.get("methods"), dict):
                        methods.update(payload["methods"])
        if prefer_order == "sorted":
            for k in agg:
                try:
                    agg[k] = sorted(agg[k], key=lambda x: str(x))
                except Exception:
                    pass
        return dict(agg), methods

    def _is_tls_record(self, obj: Any) -> bool:
        required = ("content_type", "version", "length", "payload", "ts", "src", "dst", "src_port", "dst_port", "direction")
        return all(hasattr(obj, f) for f in required)

    def _normalize_tls_record(self, rec: Any) -> List[KnowledgePacket]:
        try:
            vmaj, vmin = rec.version
        except Exception:
            vmaj, vmin = (None, None)
        payload_bytes = bytes(getattr(rec, "payload", b"") or b"")
        attrs: Dict[str, Any] = {
            "content_type": getattr(rec, "content_type", None),
            "version": f"{vmaj}.{vmin}" if vmaj is not None else None,
            "length": int(getattr(rec, "length", 0) or 0),
            "direction": str(getattr(rec, "direction", "")),
            "src": str(getattr(rec, "src", "")),
            "dst": str(getattr(rec, "dst", "")),
            "sport": int(getattr(rec, "src_port", 0) or 0),
            "dport": int(getattr(rec, "dst_port", 0) or 0),
        }
        if attrs["content_type"] == 22 and payload_bytes:
            hs_type = payload_bytes[0]
            attrs["hs_type"] = hs_type
            attrs["hs_type_name"] = self.TLS_HANDSHAKE_TYPES.get(hs_type, f"Type{hs_type}")
        flow_key = self.packet_learner._make_flow_key("tls", attrs["src"], attrs["dst"], attrs["sport"], attrs["dport"], "tcp")
        pkt = KnowledgePacket(topic="tls", payload={"attributes": attrs, "raw": payload_bytes}, ttl=self.DEFAULT_TTLS["tls"], source="bus/tlsrecord", tags=["TLSRecord", f"ct={attrs.get('content_type')}"], flow_key=flow_key, direction=attrs.get("direction"), confidence=0.95, evidence=["tlsrecord"], component_name="tls-manager", path_stage="record")
        return [self._finalize_packet(pkt)]

    def _normalize_any(self, obj: Any) -> List[KnowledgePacket]:
        if isinstance(obj, KnowledgePacket):
            return [self._finalize_packet(obj)]
        if isinstance(obj, (list, tuple)):
            out: List[KnowledgePacket] = []
            for item in obj:
                out.extend(self._normalize_any(item))
            return out
        if isinstance(obj, dict):
            return self._normalize_dict(obj)
        if isinstance(obj, (bytes, bytearray, memoryview)):
            b = bytes(obj)
            spkt = self._coerce_to_scapy_packet(b)
            if spkt is not None:
                return self._maybe_summarize_scapy(spkt, inbound_iface=None, ctx={})
            try:
                text = b.decode("utf-8", "ignore").strip()
            except Exception:
                text = ""
            return self._normalize_tagged_line(text, raw_bytes=b) if text else []
        if isinstance(obj, str):
            text = obj.strip()
            if not text:
                return []
            parsed = self._try_parse_ndjson(text)
            return parsed if parsed else self._normalize_tagged_line(text, raw_bytes=text.encode("utf-8", "ignore"))
        try:
            if hasattr(obj, "__dict__"):
                return self._normalize_dict(vars(obj))
        except Exception:
            pass
        return []

    def _normalize_dict(self, d: Dict[str, Any]) -> List[KnowledgePacket]:
        if "topic" in d and isinstance(d.get("payload"), dict):
            pkt = KnowledgePacket(topic=str(d.get("topic") or "misc").lower(), payload=dict(d.get("payload") or {}), ttl=float(d.get("ttl", self.DEFAULT_TTLS.get(str(d.get("topic") or "misc").lower(), 120.0))), source=d.get("source"), tags=list(d.get("tags") or []), importance=int(d.get("importance", 0)), confidence=float(d.get("confidence", 0.7)), iface=d.get("iface"), flow_key=str(d.get("flow_key") or ""))
            return [self._finalize_packet(pkt)]
        topic = self._detect_topic_from_dict(d)
        attrs = {}
        for k, v in d.items():
            if isinstance(v, (str, int, float, bool)):
                attrs[k] = v
        payload = {"attributes": attrs}
        if "raw" in d:
            payload["raw_text"] = str(d["raw"])[:2000]
        pkt = KnowledgePacket(topic=topic, payload=payload, ttl=self.DEFAULT_TTLS.get(topic, 120.0), confidence=0.65)
        return [self._finalize_packet(pkt)]

    def _normalize_tagged_line(self, text: str, raw_bytes: Optional[bytes] = None) -> List[KnowledgePacket]:
        tags = [m.group(1).strip() for m in self.BRACKET_TAG_RE.finditer(text)]
        topic = self._map_alias_to_topic(tags[0]) if tags else self._detect_topic_from_text(text)
        kv = {k: v.strip("\"'") for k, v in self.KV_TOKEN_RE.findall(text)}
        message = self.BRACKET_TAG_RE.sub("", text).strip()
        payload: Dict[str, Any] = {"attributes": {"message": message, **kv}}
        if raw_bytes:
            payload["raw"] = raw_bytes
        pkt = KnowledgePacket(topic=topic, payload=payload, ttl=self.DEFAULT_TTLS.get(topic, 120.0), tags=tags, confidence=0.6, evidence=["tagged-line"])
        return [self._finalize_packet(pkt)]

    def _try_parse_ndjson(self, text: str) -> List[KnowledgePacket]:
        if text.startswith(("{", "[")):
            try:
                return self._normalize_any(json.loads(text))
            except Exception:
                pass
        out: List[KnowledgePacket] = []
        parsed_any = False
        for ln in self.NDJSON_SPLIT_RE.split(text):
            s = ln.strip()
            if not s:
                continue
            if s.startswith(("{", "[")):
                try:
                    out.extend(self._normalize_any(json.loads(s)))
                    parsed_any = True
                except Exception:
                    continue
        return out if parsed_any else []

    def _map_alias_to_topic(self, alias: Optional[str]) -> str:
        if not alias:
            return "misc"
        a = alias.lower().strip()
        for store in (self._custom_aliases, self.TOPIC_ALIASES):
            for canonical, aliases in store.items():
                if a == canonical or a in aliases:
                    return canonical
        return "misc"

    def _detect_topic_from_text(self, text: str) -> str:
        low = text.lower()
        score = Counter()
        for store in (self._custom_aliases, self.TOPIC_ALIASES):
            for canonical, aliases in store.items():
                if canonical in low:
                    score[canonical] += 3
                for kw in aliases:
                    if kw in low:
                        score[canonical] += 2
        return score.most_common(1)[0][0] if score else "misc"

    def _detect_topic_from_dict(self, d: Dict[str, Any]) -> str:
        for key in ("topic", "protocol", "proto", "layer", "service", "kind", "type", "component"):
            if isinstance(d.get(key), str):
                return self._map_alias_to_topic(d[key])
        for key in ("dport", "sport"):
            try:
                p = int(d.get(key))
                if p in self.PORT_TOPIC_HINTS:
                    return self.PORT_TOPIC_HINTS[p]
            except Exception:
                pass
        joined = " ".join(map(str, d.keys())) + " " + " ".join(str(v)[:80] for v in d.values())
        return self._detect_topic_from_text(joined)

    def _finalize_packet(self, pkt: KnowledgePacket) -> KnowledgePacket:
        if not pkt.ttl or pkt.ttl <= 0:
            pkt.ttl = self.DEFAULT_TTLS.get(pkt.topic, 120.0)
        if not pkt.payload:
            pkt.payload = {"attributes": {}}
        attrs = pkt.payload.get("attributes", {})
        if not pkt.iface and isinstance(attrs, dict):
            pkt.iface = attrs.get("iface_in")
        if not pkt.path_stage and isinstance(attrs, dict):
            pkt.path_stage = attrs.get("phase")
        if not pkt.component_name and isinstance(attrs, dict):
            pkt.component_name = attrs.get("component")
        if not pkt.direction and isinstance(attrs, dict):
            pkt.direction = attrs.get("direction")
        if not pkt.flow_key and isinstance(attrs, dict):
            src = attrs.get("src") or attrs.get("saddr")
            dst = attrs.get("dst") or attrs.get("daddr")
            sport = attrs.get("sport")
            dport = attrs.get("dport")
            proto = attrs.get("proto") or attrs.get("protocol")
            pkt.flow_key = self.packet_learner._make_flow_key(pkt.topic, src, dst, self._safe_int(sport), self._safe_int(dport), proto)
        if not pkt.session_key:
            pkt.session_key = self.packet_learner._make_session_key(pkt.flow_key, pkt.iface, pkt.component_name)
        if not pkt.route_key and isinstance(attrs, dict):
            src = attrs.get("src") or attrs.get("saddr")
            dst = attrs.get("dst") or attrs.get("daddr")
            pkt.route_key = self.packet_learner._make_route_key(src, dst, pkt.iface, pkt.path_stage)
        return pkt

    def _coerce_to_scapy_packet(self, raw: Any):
        try:
            from scapy.packet import Packet as ScapyPacket  # type: ignore
            if isinstance(raw, ScapyPacket):
                return raw
        except Exception:
            pass
        if isinstance(raw, dict):
            try:
                blob = json.dumps(raw, default=str, ensure_ascii=False).encode("utf-8")
                return Raw(load=blob)
            except Exception:
                return None
        if inspect.isclass(raw):
            return None
        b = None
        if isinstance(raw, (bytes, bytearray, memoryview)):
            b = bytes(raw)
        else:
            for attr in ("original", "raw", "raw_packet", "packet", "data"):
                try:
                    v = getattr(raw, attr, None)
                    if isinstance(v, (bytes, bytearray, memoryview)):
                        b = bytes(v)
                        break
                except Exception:
                    pass
            if b is None:
                for meth in ("to_bytes", "tobytes", "get_raw_packet", "pack", "build"):
                    try:
                        fn = getattr(raw, meth, None)
                        if callable(fn):
                            v = fn()
                            if isinstance(v, (bytes, bytearray, memoryview)):
                                b = bytes(v)
                                break
                    except Exception:
                        pass
            if b is None:
                try:
                    b = bytes(raw)
                except Exception:
                    b = None
        if not b:
            return None
        try:
            from scapy.layers.l2 import Ether  # type: ignore
            from scapy.layers.inet import IP  # type: ignore
            try:
                from scapy.layers.inet6 import IPv6  # type: ignore
            except Exception:
                IPv6 = None
            first_nibble = (b[0] >> 4) if b else 0
            if first_nibble == 4:
                return IP(b)
            if first_nibble == 6 and IPv6 is not None:
                return IPv6(b)
            return Ether(b)
        except Exception:
            try:
                from scapy.layers.l2 import Ether  # type: ignore
                return Ether(b)
            except Exception:
                return None

    def _maybe_summarize_scapy(self, raw: Any, inbound_iface: Optional[str], ctx: Dict[str, Any]) -> List[KnowledgePacket]:
        pkt = self._coerce_to_scapy_packet(raw)
        if pkt is None:
            return []
        try:
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
            try:
                from scapy.layers.ipsec import ESP, AH  # type: ignore
            except Exception:
                ESP = AH = None
            try:
                from scapy.layers.tls.all import TLS  # type: ignore
            except Exception:
                TLS = None
        except Exception:
            return []
        attrs: Dict[str, Any] = {}
        topic = "router"
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            attrs.update(eth_src=getattr(eth, "src", None), eth_dst=getattr(eth, "dst", None), eth_type=getattr(eth, "type", None))
        if Dot1Q and pkt.haslayer(Dot1Q):
            attrs["vlan"] = getattr(pkt[Dot1Q], "vlan", None)
        ip_layer = pkt.getlayer(IP) or (IPv6 and pkt.getlayer(IPv6))
        if ip_layer is not None:
            attrs.update(saddr=getattr(ip_layer, "src", None), daddr=getattr(ip_layer, "dst", None), ttl=getattr(ip_layer, "ttl", getattr(ip_layer, "hlim", None)))
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            topic = self.PORT_TOPIC_HINTS.get(int(tcp.dport), self.PORT_TOPIC_HINTS.get(int(tcp.sport), "transport"))
            if TLS and pkt.haslayer(TLS):
                topic = "tls"
            attrs.update(proto="tcp", sport=int(tcp.sport), dport=int(tcp.dport))
            flags = getattr(tcp, "flags", 0)
            flag_list = []
            for letter in ("S", "A", "F", "R", "P", "U", "E", "C", "N"):
                try:
                    if getattr(flags, letter):
                        flag_list.append(letter)
                except Exception:
                    pass
            attrs["tcp_flags"] = flag_list
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            topic = self.PORT_TOPIC_HINTS.get(int(udp.dport), self.PORT_TOPIC_HINTS.get(int(udp.sport), "transport"))
            attrs.update(proto="udp", sport=int(udp.sport), dport=int(udp.dport))
            if 5353 in (int(udp.sport), int(udp.dport)):
                attrs["mdns"] = True
        elif pkt.haslayer(ICMP):
            topic = "transport"
            attrs["proto"] = "icmp"
        elif pkt.haslayer(ARP):
            topic = "arp"
            arp = pkt[ARP]
            attrs.update(proto="arp", arp_op=getattr(arp, "op", None), arp_psrc=getattr(arp, "psrc", None), arp_pdst=getattr(arp, "pdst", None))
        else:
            attrs["proto"] = "l2"
        if GRE and pkt.haslayer(GRE):
            topic = "vpn"
            attrs["gre_like"] = True
        if ESP and pkt.haslayer(ESP):
            topic = "vpn"
            esp = pkt[ESP]
            attrs["esp_spi"] = getattr(esp, "spi", None)
        if AH and pkt.haslayer(AH):
            topic = "vpn"
            ah = pkt[AH]
            attrs["ah_spi"] = getattr(ah, "spi", None)
        if inbound_iface:
            attrs["iface_in"] = inbound_iface
        attrs.update(ctx or {})
        try:
            attrs["summary"] = pkt.summary()
        except Exception:
            pass
        flow_key = self.packet_learner._make_flow_key(topic, attrs.get("saddr"), attrs.get("daddr"), self._safe_int(attrs.get("sport")), self._safe_int(attrs.get("dport")), attrs.get("proto"))
        raw_bytes = bytes(pkt)
        knowledge = KnowledgePacket(topic=topic, payload={"attributes": attrs, "raw": raw_bytes}, ttl=self.DEFAULT_TTLS.get(topic, 120.0), source="bus/scapy", iface=inbound_iface, flow_key=flow_key, confidence=0.9 if attrs.get("proto") in ("tcp", "udp", "icmp", "arp") else 0.7, evidence=["scapy"], component_name=ctx.get("component") if isinstance(ctx, dict) else None, path_stage=ctx.get("phase") if isinstance(ctx, dict) else None)
        return [self._finalize_packet(knowledge)]

    def compute_statistics_from_learned_data(self, topics: Iterable[str], percentiles: List[int], topk_categorical: int, min_count_for_stats: int) -> Dict[str, Any]:
        return self.stats_manager.compute(online_num_stats=self.packet_learner.get_all_online_numeric_stats(), cat_counters=self.packet_learner.get_all_categorical_counters(), recent_numeric_vectors=self.packet_learner.get_recent_numeric_vectors(), topics=topics, percentiles=list(percentiles), topk_categorical=int(topk_categorical), min_count_for_stats=int(min_count_for_stats))

    def _export_nonexpired_packets(self) -> List[KnowledgePacket]:
        """
        Compatibility helper used by older AskManager/summary paths.

        Returns a shallow snapshot list of non-expired KnowledgePacket objects
        across all topics, newest-first within each topic insertion order.
        """
        now = time.time()
        out: List[KnowledgePacket] = []
        with self._k_lock:
            for _, dq in self._knowledge_by_topic.items():
                for pkt in dq:
                    if pkt.is_expired(now):
                        continue
                    out.append(pkt)
        out.sort(key=lambda p: p.ts, reverse=True)
        return out

    def export_knowledge(self) -> Dict[str, List[Dict[str, Any]]]:
        now = time.time()
        out: Dict[str, List[Dict[str, Any]]] = {}
        with self._k_lock:
            for topic, dq in self._knowledge_by_topic.items():
                rows = []
                for pkt in dq:
                    if pkt.is_expired(now):
                        continue
                    rows.append({
                        "ts": pkt.ts,
                        "source": pkt.source,
                        "tags": pkt.tags,
                        "iface": pkt.iface,
                        "flow_key": pkt.flow_key,
                        "session_key": pkt.session_key,
                        "route_key": pkt.route_key,
                        "confidence": pkt.confidence,
                        "payload": pkt.payload,
                    })
                if rows:
                    out[topic] = rows
        return out

    def purge_topic(self, topic: str) -> int:
        with self._k_lock:
            dq = self._knowledge_by_topic.pop(topic, None)
            self.packet_learner.purge_topic(topic)
        n = len(dq or ())
        self._log(f"[CodeOutput] Purged topic '{topic}' count={n}", 1)
        return n

    def get_stats(self) -> Dict[str, Any]:
        with self._k_lock:
            return self._stats.snapshot()

    def register_tls_manager(self, tls_mgr: Any) -> Callable[[], None]:
        return wire_tls_to_code_output(tls_mgr, self)

    @staticmethod
    def _safe_int(v: Any) -> Optional[int]:
        try:
            if v is None or v == "":
                return None
            return int(v)
        except Exception:
            return None


def wire_tls_to_code_output(tls_mgr: Any, co_mgr: CodeOutputManager) -> Callable[[], None]:
    prev_on_record = getattr(tls_mgr, "on_record", None) or (lambda rec: None)
    def _on_record(rec):
        try:
            co_mgr.submit_packet(rec)
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
        attrs = {"event": kind}
        if flow is not None:
            attrs["flow"] = str(flow)
        for key in ("sni", "alpn", "ja3", "ja3_md5", "ja3s", "ja3s_md5", "version", "version_tuple", "cipher_suite", "cipher_suite_int", "extensions"):
            if key in data:
                attrs[key] = data[key]
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
        attrs = {"flow": str(flow_key), "decision": getattr(decision, "action", None), "reason": getattr(decision, "reason", ""), "tags": getattr(decision, "tags", []), "ct": getattr(rec, "content_type", None), "sport": getattr(rec, "src_port", None), "dport": getattr(rec, "dst_port", None)}
        co_mgr.submit_event("tls", attributes=attrs, tags=["policy", getattr(decision, "action", "decision")])
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



# =============================================================================
# Extended health / decision scaffolding
# =============================================================================

@dataclass
class InterfaceHealthRecord:
    iface: str
    packets: int = 0
    bytes_seen: int = 0
    errors: int = 0
    resets: int = 0
    tls_events: int = 0
    dns_events: int = 0
    arp_events: int = 0
    transport_events: int = 0
    router_events: int = 0
    last_seen: float = field(default_factory=time.time)
    last_ok: float = 0.0
    last_fail: float = 0.0
    score: float = 0.0
    notes: List[str] = field(default_factory=list)

    def mark_ok(self) -> None:
        self.last_ok = time.time()

    def mark_fail(self) -> None:
        self.last_fail = time.time()


@dataclass
class HealthDecision:
    label: str
    severity: str
    confidence: float
    reasons: List[str] = field(default_factory=list)
    related_ifaces: List[str] = field(default_factory=list)
    related_topics: List[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "related_ifaces": list(self.related_ifaces),
            "related_topics": list(self.related_topics),
            "ts": self.ts,
        }


class NetworkHealthManager:
    """
    Consumes learned CodeOutput state and produces health decisions.

    This layer is intentionally verbose and split into many focused helpers so it
    feels closer to the earlier large-manager style instead of a tiny utility.
    """

    def __init__(self, co_manager: CodeOutputManager, logger: Optional[Callable[[str], None]] = None) -> None:
        self._co = co_manager
        self._log = logger or (lambda s: None)
        self._lock = threading.RLock()
        self._iface_health: Dict[str, InterfaceHealthRecord] = {}
        self._decision_history: Deque[HealthDecision] = deque(maxlen=500)
        self._last_snapshot: Dict[str, Any] = {}
        self._last_evaluation_ts: float = 0.0

    def evaluate(self) -> List[HealthDecision]:
        with self._lock:
            self._rebuild_interface_health()
            decisions: List[HealthDecision] = []
            decisions.extend(self._detect_router_phase_drift())
            decisions.extend(self._detect_duplicate_flow_mirroring())
            decisions.extend(self._detect_dns_leakage())
            decisions.extend(self._detect_tls_half_open())
            decisions.extend(self._detect_broadcast_noise())
            decisions.extend(self._detect_interface_imbalance())
            decisions.extend(self._detect_entropy_mismatch())
            decisions.extend(self._detect_reset_pressure())
            decisions.extend(self._detect_small_packet_storm())
            decisions.extend(self._detect_flow_hotspots())
            self._decision_history.extend(decisions)
            self._last_evaluation_ts = time.time()
            self._last_snapshot = self.snapshot()
            return decisions

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "interfaces": {k: vars(v).copy() for k, v in self._iface_health.items()},
                "recent_decisions": [d.as_dict() for d in list(self._decision_history)[-20:]],
                "last_evaluation_ts": self._last_evaluation_ts,
            }

    def recent_decisions(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            return [d.as_dict() for d in list(self._decision_history)[-limit:]]

    def _rebuild_interface_health(self) -> None:
        stats = self._co.get_stats()
        by_iface = stats.get("by_iface", {})
        topics = ["dns", "tls", "arp", "transport", "router"]
        fresh: Dict[str, InterfaceHealthRecord] = {}
        for iface, count in by_iface.items():
            rec = InterfaceHealthRecord(iface=iface, packets=int(count))
            rec.bytes_seen = self._estimate_iface_bytes(iface)
            rec.dns_events = self._estimate_iface_topic_count(iface, "dns")
            rec.tls_events = self._estimate_iface_topic_count(iface, "tls")
            rec.arp_events = self._estimate_iface_topic_count(iface, "arp")
            rec.transport_events = self._estimate_iface_topic_count(iface, "transport")
            rec.router_events = self._estimate_iface_topic_count(iface, "router")
            rec.score = self._score_interface(rec)
            if rec.score >= 0.65:
                rec.mark_ok()
            else:
                rec.mark_fail()
            fresh[iface] = rec
        self._iface_health = fresh

    def _estimate_iface_bytes(self, iface: str) -> int:
        total = 0
        for topic in ("dns", "tls", "arp", "transport", "router", "http", "vpn", "misc"):
            flows = self._co.packet_learner.snapshot_flows(topic, top_k=25)
            for flow in flows:
                if flow.get("iface") == iface:
                    total += int(flow.get("bytes", 0))
        return total

    def _estimate_iface_topic_count(self, iface: str, topic: str) -> int:
        flows = self._co.packet_learner.snapshot_flows(topic, top_k=25)
        return sum(int(flow.get("packets", 0)) for flow in flows if flow.get("iface") == iface)

    def _score_interface(self, rec: InterfaceHealthRecord) -> float:
        score = 0.0
        score += min(1.0, rec.packets / 100.0) * 0.20
        score += min(1.0, rec.bytes_seen / 200000.0) * 0.20
        score += min(1.0, rec.router_events / 50.0) * 0.15
        score += min(1.0, rec.transport_events / 50.0) * 0.15
        score += min(1.0, rec.dns_events / 25.0) * 0.10
        score += min(1.0, rec.tls_events / 25.0) * 0.10
        score += min(1.0, rec.arp_events / 15.0) * 0.10
        return max(0.0, min(1.0, score))

    def _detect_router_phase_drift(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        stats = self._co.compute_statistics_from_learned_data(
            topics=["router", "transport"],
            percentiles=[50, 95],
            topk_categorical=10,
            min_count_for_stats=2,
        )
        for topic in ("router", "transport"):
            phase_info = stats.get(topic, {}).get("categorical", {}).get("phase", {})
            phases = phase_info.get("top_k", [])
            if len(phases) >= 3:
                labels = [p for p, _ in phases[:4]]
                decisions.append(
                    HealthDecision(
                        label="phase_drift",
                        severity="medium",
                        confidence=0.72,
                        reasons=[f"{topic} has many active phases: {labels}"],
                        related_topics=[topic],
                    )
                )
        return decisions

    def _detect_duplicate_flow_mirroring(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        for topic in ("transport", "router", "dns", "tls"):
            flows = self._co.packet_learner.snapshot_flows(topic, top_k=12)
            by_key = defaultdict(set)
            for flow in flows:
                by_key[flow["key"]].add(flow.get("iface"))
            mirrored = [k for k, ifaces in by_key.items() if len([x for x in ifaces if x]) > 1]
            if mirrored:
                decisions.append(
                    HealthDecision(
                        label="duplicate_flow_mirroring",
                        severity="medium",
                        confidence=0.78,
                        reasons=[f"{topic} flow observed on multiple interfaces", *mirrored[:3]],
                        related_topics=[topic],
                    )
                )
        return decisions

    def _detect_dns_leakage(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        stats = self._co.compute_statistics_from_learned_data(
            topics=["dns"],
            percentiles=[50, 95],
            topk_categorical=12,
            min_count_for_stats=2,
        )
        ports = stats.get("dns", {}).get("categorical", {}).get("port", {}).get("top_k", [])
        noisy = [p for p, _ in ports if p in ("1900", "3702", "137")]
        if noisy:
            decisions.append(
                HealthDecision(
                    label="resolver_leakage_or_mixed_name_resolution",
                    severity="medium",
                    confidence=0.80,
                    reasons=[f"DNS topic also carries ports {', '.join(noisy)}"],
                    related_topics=["dns"],
                )
            )
        return decisions

    def _detect_tls_half_open(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        stats = self._co.compute_statistics_from_learned_data(
            topics=["tls"],
            percentiles=[50, 95],
            topk_categorical=10,
            min_count_for_stats=2,
        )
        hs_types = stats.get("tls", {}).get("categorical", {}).get("tls_hs_type", {}).get("top_k", [])
        counts = {k: v for k, v in hs_types}
        if counts.get("ClientHello", 0) >= 3 and counts.get("ServerHello", 0) == 0:
            decisions.append(
                HealthDecision(
                    label="tls_half_open",
                    severity="high",
                    confidence=0.86,
                    reasons=["ClientHello observed repeatedly without ServerHello"],
                    related_topics=["tls"],
                )
            )
        return decisions

    def _detect_broadcast_noise(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        dns_stats = self._co.compute_statistics_from_learned_data(
            topics=["dns", "arp"],
            percentiles=[50],
            topk_categorical=12,
            min_count_for_stats=2,
        )
        dns_ports = dns_stats.get("dns", {}).get("categorical", {}).get("port", {}).get("top_k", [])
        arp_ips = dns_stats.get("arp", {}).get("categorical", {}).get("ip", {}).get("top_k", [])
        if dns_ports and any(p in {"1900", "5353", "3702", "137"} for p, _ in dns_ports):
            decisions.append(
                HealthDecision(
                    label="broadcast_noise_storm",
                    severity="low",
                    confidence=0.67,
                    reasons=["broadcast-style ports dominate name-resolution traffic"],
                    related_topics=["dns", "arp"],
                )
            )
        return decisions

    def _detect_interface_imbalance(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        if len(self._iface_health) < 2:
            return decisions
        ranked = sorted(self._iface_health.values(), key=lambda r: r.packets, reverse=True)
        if ranked and ranked[0].packets > max(10, ranked[-1].packets * 4):
            decisions.append(
                HealthDecision(
                    label="interface_imbalance",
                    severity="medium",
                    confidence=0.74,
                    reasons=[f"{ranked[0].iface} is far busier than {ranked[-1].iface}"],
                    related_ifaces=[ranked[0].iface, ranked[-1].iface],
                )
            )
        return decisions

    def _detect_entropy_mismatch(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        stats = self._co.compute_statistics_from_learned_data(
            topics=["dns", "transport", "http"],
            percentiles=[50, 95],
            topk_categorical=8,
            min_count_for_stats=2,
        )
        for topic in ("dns", "transport", "http"):
            ent = stats.get(topic, {}).get("numeric", {}).get("entropy", {})
            if ent and ent.get("mean", 0.0) > 6.0:
                decisions.append(
                    HealthDecision(
                        label="high_entropy_in_cleartextish_topic",
                        severity="medium",
                        confidence=0.69,
                        reasons=[f"{topic} entropy mean is high: {ent.get('mean', 0.0):.2f}"],
                        related_topics=[topic],
                    )
                )
        return decisions

    def _detect_reset_pressure(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        stats = self._co.compute_statistics_from_learned_data(
            topics=["transport"],
            percentiles=[50],
            topk_categorical=12,
            min_count_for_stats=2,
        )
        flags = stats.get("transport", {}).get("categorical", {}).get("tcp_flags", {}).get("top_k", [])
        reset_count = sum(c for f, c in flags if "R" in f)
        syn_count = sum(c for f, c in flags if "S" in f)
        if syn_count > 0 and reset_count > syn_count * 0.5:
            decisions.append(
                HealthDecision(
                    label="reset_pressure",
                    severity="medium",
                    confidence=0.77,
                    reasons=[f"RST volume {reset_count} is high relative to SYN volume {syn_count}"],
                    related_topics=["transport"],
                )
            )
        return decisions

    def _detect_small_packet_storm(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        stats = self._co.compute_statistics_from_learned_data(
            topics=["transport", "dns", "router"],
            percentiles=[50, 95],
            topk_categorical=8,
            min_count_for_stats=2,
        )
        for topic in ("transport", "dns", "router"):
            length = stats.get(topic, {}).get("numeric", {}).get("length", {})
            rps = stats.get(topic, {}).get("numeric", {}).get("rps", {})
            if length and rps and length.get("mean", 9999) < 80 and rps.get("mean", 0) > 1.5:
                decisions.append(
                    HealthDecision(
                        label="small_packet_storm",
                        severity="low",
                        confidence=0.71,
                        reasons=[f"{topic} has small average packets and elevated activity"],
                        related_topics=[topic],
                    )
                )
        return decisions

    def _detect_flow_hotspots(self) -> List[HealthDecision]:
        decisions: List[HealthDecision] = []
        for topic in ("transport", "router", "dns", "tls"):
            flows = self._co.packet_learner.snapshot_flows(topic, top_k=5)
            if flows and flows[0]["packets"] >= 10:
                decisions.append(
                    HealthDecision(
                        label="flow_hotspot",
                        severity="low",
                        confidence=0.65,
                        reasons=[f"top {topic} flow is unusually busy: {flows[0]['key']}"],
                        related_topics=[topic],
                        related_ifaces=[flows[0].get("iface")] if flows[0].get("iface") else [],
                    )
                )
        return decisions



# =============================================================================
# Correlation / diagnostics scaffolding
# =============================================================================

@dataclass
class FlowCorrelationRecord:
    flow_key: str
    topics: Counter = field(default_factory=Counter)
    ifaces: Counter = field(default_factory=Counter)
    components: Counter = field(default_factory=Counter)
    stages: Counter = field(default_factory=Counter)
    packets: int = 0
    bytes_seen: int = 0
    last_seen: float = field(default_factory=time.time)

    def add(self, *, topic: str, iface: Optional[str], component: Optional[str], stage: Optional[str], packets: int, bytes_seen: int) -> None:
        self.topics[str(topic)] += 1
        if iface:
            self.ifaces[str(iface)] += 1
        if component:
            self.components[str(component)] += 1
        if stage:
            self.stages[str(stage)] += 1
        self.packets += int(packets or 0)
        self.bytes_seen += int(bytes_seen or 0)
        self.last_seen = time.time()


class FlowCorrelationManager:
    def __init__(self, co_manager: CodeOutputManager) -> None:
        self._co = co_manager
        self._lock = threading.RLock()
        self._records: Dict[str, FlowCorrelationRecord] = {}
        self._last_build_ts: float = 0.0

    def rebuild(self) -> None:
        with self._lock:
            self._records.clear()
            for topic in ("dns", "tls", "arp", "transport", "router", "http", "vpn", "misc"):
                flows = self._co.packet_learner.snapshot_flows(topic, top_k=128)
                for flow in flows:
                    key = str(flow.get("key"))
                    rec = self._records.setdefault(key, FlowCorrelationRecord(flow_key=key))
                    rec.add(
                        topic=topic,
                        iface=flow.get("iface"),
                        component=self._best_component(topic, key),
                        stage=self._best_stage(topic, key),
                        packets=int(flow.get("packets", 0)),
                        bytes_seen=int(flow.get("bytes", 0)),
                    )
            self._last_build_ts = time.time()

    def snapshot(self, top_k: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            rows = sorted(self._records.values(), key=lambda r: (r.packets, r.bytes_seen, r.last_seen), reverse=True)[:top_k]
        return [
            {
                "flow_key": r.flow_key,
                "topics": r.topics.most_common(6),
                "ifaces": r.ifaces.most_common(6),
                "components": r.components.most_common(6),
                "stages": r.stages.most_common(6),
                "packets": r.packets,
                "bytes_seen": r.bytes_seen,
                "last_seen": r.last_seen,
            }
            for r in rows
        ]

    def find_cross_topic_flows(self, min_topics: int = 2, top_k: int = 25) -> List[Dict[str, Any]]:
        with self._lock:
            rows = [r for r in self._records.values() if len(r.topics) >= min_topics]
            rows.sort(key=lambda r: (len(r.topics), r.packets, r.bytes_seen), reverse=True)
        return [
            {
                "flow_key": r.flow_key,
                "topic_count": len(r.topics),
                "topics": r.topics.most_common(8),
                "ifaces": r.ifaces.most_common(8),
                "packets": r.packets,
                "bytes_seen": r.bytes_seen,
            }
            for r in rows[:top_k]
        ]

    def _best_component(self, topic: str, flow_key: str) -> Optional[str]:
        flows = self._co.packet_learner.snapshot_flows(topic, top_k=64)
        for flow in flows:
            if flow.get("key") == flow_key:
                comps = flow.get("top_components") or []
                if comps:
                    return comps[0][0]
        return None

    def _best_stage(self, topic: str, flow_key: str) -> Optional[str]:
        flows = self._co.packet_learner.snapshot_flows(topic, top_k=64)
        for flow in flows:
            if flow.get("key") == flow_key:
                stages = flow.get("top_stages") or []
                if stages:
                    return stages[0][0]
        return None


class DiagnosticsFormatter:
    def __init__(self, co_manager: CodeOutputManager) -> None:
        self._co = co_manager

    def summarize_topic(self, topic: str) -> str:
        stats = self._co.compute_statistics_from_learned_data(
            topics=[topic],
            percentiles=[50, 95],
            topk_categorical=8,
            min_count_for_stats=2,
        ).get(topic, {})
        lines = [f"Topic summary: {topic}"]
        numeric = stats.get("numeric", {})
        categorical = stats.get("categorical", {})
        for feat, fs in numeric.items():
            lines.append(
                f"- numeric {feat}: count={fs.get('count')} mean={fs.get('mean', 0):.3g} std={fs.get('std', 0):.3g}"
            )
        for feat, fs in categorical.items():
            top = fs.get("top_k", [])
            if top:
                lines.append(f"- categorical {feat}: " + ", ".join(f"{v}({c})" for v, c in top[:5]))
        return "\n".join(lines)

    def summarize_all(self, topics: Optional[List[str]] = None) -> str:
        topics = topics or list(self._co.packet_learner.get_concept_counts().keys())
        return "\n\n".join(self.summarize_topic(topic) for topic in topics[:12])

    def format_health_decisions(self, decisions: List[HealthDecision]) -> str:
        if not decisions:
            return "No health decisions."
        lines = ["Health decisions:"]
        for d in decisions:
            lines.append(f"- {d.label} [{d.severity}] conf={d.confidence:.2f}")
            for reason in d.reasons[:4]:
                lines.append(f"  • {reason}")
        return "\n".join(lines)


class DecisionEngine:
    """
    Thin orchestration layer that ties health, correlation, and formatting
    together so the big file has a clear place where 'smart' system behavior
    would live.
    """

    def __init__(self, co_manager: CodeOutputManager) -> None:
        self._co = co_manager
        self._health = NetworkHealthManager(co_manager)
        self._corr = FlowCorrelationManager(co_manager)
        self._fmt = DiagnosticsFormatter(co_manager)
        self._last_decisions: List[HealthDecision] = []

    def run(self) -> Dict[str, Any]:
        self._corr.rebuild()
        decisions = self._health.evaluate()
        self._last_decisions = decisions
        return {
            "health": self._health.snapshot(),
            "correlations": self._corr.snapshot(top_k=20),
            "cross_topic_flows": self._corr.find_cross_topic_flows(min_topics=2, top_k=20),
            "decision_text": self._fmt.format_health_decisions(decisions),
        }

    def summarize(self) -> str:
        state = self.run()
        parts = [state["decision_text"], "", "Cross-topic flows:"]
        for row in state["cross_topic_flows"][:8]:
            parts.append(
                f"- {row['flow_key']} topics={row['topics']} ifaces={row['ifaces']} packets={row['packets']}"
            )
        return "\n".join(parts)

    def last_decisions(self) -> List[Dict[str, Any]]:
        return [d.as_dict() for d in self._last_decisions]



class ProtocolAdvisor:
    def __init__(self, co_manager: CodeOutputManager) -> None:
        self._co = co_manager

    def _topic_summary(self, topic: str) -> Dict[str, Any]:
        return self._co.compute_statistics_from_learned_data(
            topics=[topic],
            percentiles=[50, 95],
            topk_categorical=10,
            min_count_for_stats=2,
        ).get(topic, {})

    def summarize_many(self, topics: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        topics = topics or ['dns', 'dhcp', 'tls', 'http', 'vpn', 'quic', 'transport', 'router', 'arp', 'kerberos', 'ntp', 'ssh', 'misc']
        return {topic: self._topic_summary(topic) for topic in topics}

    def advice_many(self, topics: Optional[List[str]] = None) -> Dict[str, str]:
        topics = topics or ['dns', 'dhcp', 'tls', 'http', 'vpn', 'quic', 'transport', 'router', 'arp', 'kerberos', 'ntp', 'ssh', 'misc']
        out: Dict[str, str] = {}
        for topic in topics:
            fn = getattr(self, f"advice_{topic}", None)
            if callable(fn):
                out[topic] = fn()
        return out

    def summarize_dns(self) -> Dict[str, Any]:
        return self._topic_summary("dns")

    def diagnose_dns(self) -> List[str]:
        summary = self._topic_summary("dns")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("dns: small average packet length")
            if mean_len > 1300:
                notes.append("dns: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("dns: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("dns: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("dns: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("dns: phase spread is wide")
        return notes

    def advice_dns(self) -> str:
        notes = self.diagnose_dns()
        if notes:
            return "; ".join(notes[:4])
        return "No strong dns advice."


    def summarize_dhcp(self) -> Dict[str, Any]:
        return self._topic_summary("dhcp")

    def diagnose_dhcp(self) -> List[str]:
        summary = self._topic_summary("dhcp")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("dhcp: small average packet length")
            if mean_len > 1300:
                notes.append("dhcp: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("dhcp: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("dhcp: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("dhcp: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("dhcp: phase spread is wide")
        return notes

    def advice_dhcp(self) -> str:
        notes = self.diagnose_dhcp()
        if notes:
            return "; ".join(notes[:4])
        return "No strong dhcp advice."


    def summarize_tls(self) -> Dict[str, Any]:
        return self._topic_summary("tls")

    def diagnose_tls(self) -> List[str]:
        summary = self._topic_summary("tls")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("tls: small average packet length")
            if mean_len > 1300:
                notes.append("tls: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("tls: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("tls: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("tls: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("tls: phase spread is wide")
        return notes

    def advice_tls(self) -> str:
        notes = self.diagnose_tls()
        if notes:
            return "; ".join(notes[:4])
        return "No strong tls advice."


    def summarize_http(self) -> Dict[str, Any]:
        return self._topic_summary("http")

    def diagnose_http(self) -> List[str]:
        summary = self._topic_summary("http")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("http: small average packet length")
            if mean_len > 1300:
                notes.append("http: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("http: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("http: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("http: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("http: phase spread is wide")
        return notes

    def advice_http(self) -> str:
        notes = self.diagnose_http()
        if notes:
            return "; ".join(notes[:4])
        return "No strong http advice."


    def summarize_vpn(self) -> Dict[str, Any]:
        return self._topic_summary("vpn")

    def diagnose_vpn(self) -> List[str]:
        summary = self._topic_summary("vpn")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("vpn: small average packet length")
            if mean_len > 1300:
                notes.append("vpn: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("vpn: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("vpn: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("vpn: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("vpn: phase spread is wide")
        return notes

    def advice_vpn(self) -> str:
        notes = self.diagnose_vpn()
        if notes:
            return "; ".join(notes[:4])
        return "No strong vpn advice."


    def summarize_quic(self) -> Dict[str, Any]:
        return self._topic_summary("quic")

    def diagnose_quic(self) -> List[str]:
        summary = self._topic_summary("quic")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("quic: small average packet length")
            if mean_len > 1300:
                notes.append("quic: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("quic: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("quic: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("quic: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("quic: phase spread is wide")
        return notes

    def advice_quic(self) -> str:
        notes = self.diagnose_quic()
        if notes:
            return "; ".join(notes[:4])
        return "No strong quic advice."


    def summarize_transport(self) -> Dict[str, Any]:
        return self._topic_summary("transport")

    def diagnose_transport(self) -> List[str]:
        summary = self._topic_summary("transport")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("transport: small average packet length")
            if mean_len > 1300:
                notes.append("transport: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("transport: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("transport: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("transport: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("transport: phase spread is wide")
        return notes

    def advice_transport(self) -> str:
        notes = self.diagnose_transport()
        if notes:
            return "; ".join(notes[:4])
        return "No strong transport advice."


    def summarize_router(self) -> Dict[str, Any]:
        return self._topic_summary("router")

    def diagnose_router(self) -> List[str]:
        summary = self._topic_summary("router")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("router: small average packet length")
            if mean_len > 1300:
                notes.append("router: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("router: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("router: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("router: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("router: phase spread is wide")
        return notes

    def advice_router(self) -> str:
        notes = self.diagnose_router()
        if notes:
            return "; ".join(notes[:4])
        return "No strong router advice."


    def summarize_arp(self) -> Dict[str, Any]:
        return self._topic_summary("arp")

    def diagnose_arp(self) -> List[str]:
        summary = self._topic_summary("arp")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("arp: small average packet length")
            if mean_len > 1300:
                notes.append("arp: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("arp: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("arp: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("arp: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("arp: phase spread is wide")
        return notes

    def advice_arp(self) -> str:
        notes = self.diagnose_arp()
        if notes:
            return "; ".join(notes[:4])
        return "No strong arp advice."


    def summarize_kerberos(self) -> Dict[str, Any]:
        return self._topic_summary("kerberos")

    def diagnose_kerberos(self) -> List[str]:
        summary = self._topic_summary("kerberos")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("kerberos: small average packet length")
            if mean_len > 1300:
                notes.append("kerberos: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("kerberos: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("kerberos: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("kerberos: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("kerberos: phase spread is wide")
        return notes

    def advice_kerberos(self) -> str:
        notes = self.diagnose_kerberos()
        if notes:
            return "; ".join(notes[:4])
        return "No strong kerberos advice."


    def summarize_ntp(self) -> Dict[str, Any]:
        return self._topic_summary("ntp")

    def diagnose_ntp(self) -> List[str]:
        summary = self._topic_summary("ntp")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("ntp: small average packet length")
            if mean_len > 1300:
                notes.append("ntp: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("ntp: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("ntp: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("ntp: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("ntp: phase spread is wide")
        return notes

    def advice_ntp(self) -> str:
        notes = self.diagnose_ntp()
        if notes:
            return "; ".join(notes[:4])
        return "No strong ntp advice."


    def summarize_ssh(self) -> Dict[str, Any]:
        return self._topic_summary("ssh")

    def diagnose_ssh(self) -> List[str]:
        summary = self._topic_summary("ssh")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("ssh: small average packet length")
            if mean_len > 1300:
                notes.append("ssh: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("ssh: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("ssh: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("ssh: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("ssh: phase spread is wide")
        return notes

    def advice_ssh(self) -> str:
        notes = self.diagnose_ssh()
        if notes:
            return "; ".join(notes[:4])
        return "No strong ssh advice."


    def summarize_misc(self) -> Dict[str, Any]:
        return self._topic_summary("misc")

    def diagnose_misc(self) -> List[str]:
        summary = self._topic_summary("misc")
        notes: List[str] = []
        numeric = summary.get("numeric", {})
        categorical = summary.get("categorical", {})
        if "length" in numeric:
            mean_len = numeric["length"].get("mean", 0.0)
            if mean_len < 90:
                notes.append("misc: small average packet length")
            if mean_len > 1300:
                notes.append("misc: large average packet length")
        if "entropy" in numeric and numeric["entropy"].get("mean", 0.0) > 6.0:
            notes.append("misc: elevated entropy")
        if "port" in categorical and categorical["port"].get("top_k"):
            notes.append("misc: active ports=" + ", ".join(p for p, _ in categorical["port"]["top_k"][:5]))
        if "iface" in categorical and categorical["iface"].get("unique_count", 0) > 1:
            notes.append("misc: seen on multiple interfaces")
        if "phase" in categorical and categorical["phase"].get("unique_count", 0) > 2:
            notes.append("misc: phase spread is wide")
        return notes

    def advice_misc(self) -> str:
        notes = self.diagnose_misc()
        if notes:
            return "; ".join(notes[:4])
        return "No strong misc advice."



class TemporalReportManager:
    def __init__(self, co_manager: CodeOutputManager) -> None:
        self._co = co_manager

    def _report_window(self, seconds: int) -> Dict[str, Any]:
        now = time.time()
        topics = 0
        packets = 0
        interfaces = set()
        for topic in self._co.packet_learner.get_concept_counts().keys():
            recent = self._co.packet_learner.get_recent_packets(topic, limit=256)
            if not recent:
                continue
            topic_packets = [pkt for pkt in recent if now - pkt.ts <= seconds]
            if topic_packets:
                topics += 1
                packets += len(topic_packets)
                for pkt in topic_packets:
                    if pkt.iface:
                        interfaces.add(pkt.iface)
        return {
            "seconds": int(seconds),
            "topics": topics,
            "packets": packets,
            "interfaces": sorted(interfaces),
        }

    def summarize(self) -> Dict[str, Any]:
        return {
            "10s": self.report_window_1(),
            "30s": self.report_window_3(),
            "60s": self.report_window_6(),
            "120s": self.report_window_12(),
            "300s": self.report_window_30(),
        }

    def report_window_1(self) -> Dict[str, Any]:
        return self._report_window(seconds=10)

    def explain_window_1(self) -> str:
        snap = self.report_window_1()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_2(self) -> Dict[str, Any]:
        return self._report_window(seconds=20)

    def explain_window_2(self) -> str:
        snap = self.report_window_2()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_3(self) -> Dict[str, Any]:
        return self._report_window(seconds=30)

    def explain_window_3(self) -> str:
        snap = self.report_window_3()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_4(self) -> Dict[str, Any]:
        return self._report_window(seconds=40)

    def explain_window_4(self) -> str:
        snap = self.report_window_4()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_5(self) -> Dict[str, Any]:
        return self._report_window(seconds=50)

    def explain_window_5(self) -> str:
        snap = self.report_window_5()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_6(self) -> Dict[str, Any]:
        return self._report_window(seconds=60)

    def explain_window_6(self) -> str:
        snap = self.report_window_6()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_7(self) -> Dict[str, Any]:
        return self._report_window(seconds=70)

    def explain_window_7(self) -> str:
        snap = self.report_window_7()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_8(self) -> Dict[str, Any]:
        return self._report_window(seconds=80)

    def explain_window_8(self) -> str:
        snap = self.report_window_8()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_9(self) -> Dict[str, Any]:
        return self._report_window(seconds=90)

    def explain_window_9(self) -> str:
        snap = self.report_window_9()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_10(self) -> Dict[str, Any]:
        return self._report_window(seconds=100)

    def explain_window_10(self) -> str:
        snap = self.report_window_10()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_11(self) -> Dict[str, Any]:
        return self._report_window(seconds=110)

    def explain_window_11(self) -> str:
        snap = self.report_window_11()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_12(self) -> Dict[str, Any]:
        return self._report_window(seconds=120)

    def explain_window_12(self) -> str:
        snap = self.report_window_12()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_13(self) -> Dict[str, Any]:
        return self._report_window(seconds=130)

    def explain_window_13(self) -> str:
        snap = self.report_window_13()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_14(self) -> Dict[str, Any]:
        return self._report_window(seconds=140)

    def explain_window_14(self) -> str:
        snap = self.report_window_14()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_15(self) -> Dict[str, Any]:
        return self._report_window(seconds=150)

    def explain_window_15(self) -> str:
        snap = self.report_window_15()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_16(self) -> Dict[str, Any]:
        return self._report_window(seconds=160)

    def explain_window_16(self) -> str:
        snap = self.report_window_16()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_17(self) -> Dict[str, Any]:
        return self._report_window(seconds=170)

    def explain_window_17(self) -> str:
        snap = self.report_window_17()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_18(self) -> Dict[str, Any]:
        return self._report_window(seconds=180)

    def explain_window_18(self) -> str:
        snap = self.report_window_18()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_19(self) -> Dict[str, Any]:
        return self._report_window(seconds=190)

    def explain_window_19(self) -> str:
        snap = self.report_window_19()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_20(self) -> Dict[str, Any]:
        return self._report_window(seconds=200)

    def explain_window_20(self) -> str:
        snap = self.report_window_20()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_21(self) -> Dict[str, Any]:
        return self._report_window(seconds=210)

    def explain_window_21(self) -> str:
        snap = self.report_window_21()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_22(self) -> Dict[str, Any]:
        return self._report_window(seconds=220)

    def explain_window_22(self) -> str:
        snap = self.report_window_22()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_23(self) -> Dict[str, Any]:
        return self._report_window(seconds=230)

    def explain_window_23(self) -> str:
        snap = self.report_window_23()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_24(self) -> Dict[str, Any]:
        return self._report_window(seconds=240)

    def explain_window_24(self) -> str:
        snap = self.report_window_24()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_25(self) -> Dict[str, Any]:
        return self._report_window(seconds=250)

    def explain_window_25(self) -> str:
        snap = self.report_window_25()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_26(self) -> Dict[str, Any]:
        return self._report_window(seconds=260)

    def explain_window_26(self) -> str:
        snap = self.report_window_26()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_27(self) -> Dict[str, Any]:
        return self._report_window(seconds=270)

    def explain_window_27(self) -> str:
        snap = self.report_window_27()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_28(self) -> Dict[str, Any]:
        return self._report_window(seconds=280)

    def explain_window_28(self) -> str:
        snap = self.report_window_28()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_29(self) -> Dict[str, Any]:
        return self._report_window(seconds=290)

    def explain_window_29(self) -> str:
        snap = self.report_window_29()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )


    def report_window_30(self) -> Dict[str, Any]:
        return self._report_window(seconds=300)

    def explain_window_30(self) -> str:
        snap = self.report_window_30()
        return "window={seconds}s topics={topics} packets={packets} interfaces={interfaces}".format(
            seconds=snap["seconds"],
            topics=snap["topics"],
            packets=snap["packets"],
            interfaces=snap["interfaces"],
        )



class ProbeLibrary:
    def __init__(self, co_manager: CodeOutputManager) -> None:
        self._co = co_manager

    def _probe(self, keyword: str) -> Dict[str, Any]:
        topics = []
        packets = 0
        ifaces = Counter()
        for topic in self._co.packet_learner.get_concept_counts().keys():
            recent = self._co.packet_learner.get_recent_packets(topic, limit=128)
            matches = []
            for pkt in recent:
                attrs = pkt.payload.get("attributes", {}) if isinstance(pkt.payload, dict) else {}
                blob = " ".join(str(v) for v in attrs.values())
                if keyword.lower() in blob.lower() or keyword.lower() in topic.lower():
                    matches.append(pkt)
            if matches:
                topics.append(topic)
                packets += len(matches)
                for pkt in matches:
                    if pkt.iface:
                        ifaces[pkt.iface] += 1
        return {
            "keyword": keyword,
            "topics": topics,
            "packets": packets,
            "ifaces": [k for k, _ in ifaces.most_common(8)],
        }

    def probe_wan(self) -> Dict[str, Any]:
        return self._probe("wan")

    def explain_wan(self) -> str:
        snap = self.probe_wan()
        return "wan: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_lan(self) -> Dict[str, Any]:
        return self._probe("lan")

    def explain_lan(self) -> str:
        snap = self.probe_lan()
        return "lan: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_bridge(self) -> Dict[str, Any]:
        return self._probe("bridge")

    def explain_bridge(self) -> str:
        snap = self.probe_bridge()
        return "bridge: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_resolver(self) -> Dict[str, Any]:
        return self._probe("resolver")

    def explain_resolver(self) -> str:
        snap = self.probe_resolver()
        return "resolver: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_tls(self) -> Dict[str, Any]:
        return self._probe("tls")

    def explain_tls(self) -> str:
        snap = self.probe_tls()
        return "tls: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_quic(self) -> Dict[str, Any]:
        return self._probe("quic")

    def explain_quic(self) -> str:
        snap = self.probe_quic()
        return "quic: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_arp(self) -> Dict[str, Any]:
        return self._probe("arp")

    def explain_arp(self) -> str:
        snap = self.probe_arp()
        return "arp: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_dhcp(self) -> Dict[str, Any]:
        return self._probe("dhcp")

    def explain_dhcp(self) -> str:
        snap = self.probe_dhcp()
        return "dhcp: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_transport(self) -> Dict[str, Any]:
        return self._probe("transport")

    def explain_transport(self) -> str:
        snap = self.probe_transport()
        return "transport: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_snapshot(self) -> Dict[str, Any]:
        return self._probe("snapshot")

    def explain_snapshot(self) -> str:
        snap = self.probe_snapshot()
        return "snapshot: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_emit(self) -> Dict[str, Any]:
        return self._probe("emit")

    def explain_emit(self) -> str:
        snap = self.probe_emit()
        return "emit: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_flow(self) -> Dict[str, Any]:
        return self._probe("flow")

    def explain_flow(self) -> str:
        snap = self.probe_flow()
        return "flow: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_route(self) -> Dict[str, Any]:
        return self._probe("route")

    def explain_route(self) -> str:
        snap = self.probe_route()
        return "route: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_mirror(self) -> Dict[str, Any]:
        return self._probe("mirror")

    def explain_mirror(self) -> str:
        snap = self.probe_mirror()
        return "mirror: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_broadcast(self) -> Dict[str, Any]:
        return self._probe("broadcast")

    def explain_broadcast(self) -> str:
        snap = self.probe_broadcast()
        return "broadcast: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_entropy(self) -> Dict[str, Any]:
        return self._probe("entropy")

    def explain_entropy(self) -> str:
        snap = self.probe_entropy()
        return "entropy: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_rps(self) -> Dict[str, Any]:
        return self._probe("rps")

    def explain_rps(self) -> str:
        snap = self.probe_rps()
        return "rps: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_interface(self) -> Dict[str, Any]:
        return self._probe("interface")

    def explain_interface(self) -> str:
        snap = self.probe_interface()
        return "interface: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_component(self) -> Dict[str, Any]:
        return self._probe("component")

    def explain_component(self) -> str:
        snap = self.probe_component()
        return "component: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


    def probe_phase(self) -> Dict[str, Any]:
        return self._probe("phase")

    def explain_phase(self) -> str:
        snap = self.probe_phase()
        return "phase: topics={topics} packets={packets} hot_ifaces={ifaces}".format(
            topics=snap["topics"],
            packets=snap["packets"],
            ifaces=snap["ifaces"],
        )


ROADMAP_NOTES = '''
001. Extension slot 1: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
002. Extension slot 2: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
003. Extension slot 3: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
004. Extension slot 4: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
005. Extension slot 5: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
006. Extension slot 6: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
007. Extension slot 7: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
008. Extension slot 8: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
009. Extension slot 9: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
010. Extension slot 10: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
011. Extension slot 11: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
012. Extension slot 12: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
013. Extension slot 13: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
014. Extension slot 14: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
015. Extension slot 15: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
016. Extension slot 16: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
017. Extension slot 17: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
018. Extension slot 18: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
019. Extension slot 19: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
020. Extension slot 20: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
021. Extension slot 21: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
022. Extension slot 22: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
023. Extension slot 23: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
024. Extension slot 24: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
025. Extension slot 25: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
026. Extension slot 26: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
027. Extension slot 27: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
028. Extension slot 28: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
029. Extension slot 29: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
030. Extension slot 30: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
031. Extension slot 31: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
032. Extension slot 32: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
033. Extension slot 33: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
034. Extension slot 34: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
035. Extension slot 35: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
036. Extension slot 36: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
037. Extension slot 37: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
038. Extension slot 38: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
039. Extension slot 39: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
040. Extension slot 40: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
041. Extension slot 41: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
042. Extension slot 42: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
043. Extension slot 43: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
044. Extension slot 44: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
045. Extension slot 45: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
046. Extension slot 46: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
047. Extension slot 47: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
048. Extension slot 48: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
049. Extension slot 49: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
050. Extension slot 50: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
051. Extension slot 51: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
052. Extension slot 52: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
053. Extension slot 53: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
054. Extension slot 54: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
055. Extension slot 55: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
056. Extension slot 56: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
057. Extension slot 57: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
058. Extension slot 58: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
059. Extension slot 59: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
060. Extension slot 60: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
061. Extension slot 61: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
062. Extension slot 62: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
063. Extension slot 63: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
064. Extension slot 64: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
065. Extension slot 65: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
066. Extension slot 66: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
067. Extension slot 67: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
068. Extension slot 68: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
069. Extension slot 69: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
070. Extension slot 70: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
071. Extension slot 71: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
072. Extension slot 72: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
073. Extension slot 73: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
074. Extension slot 74: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
075. Extension slot 75: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
076. Extension slot 76: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
077. Extension slot 77: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
078. Extension slot 78: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
079. Extension slot 79: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
080. Extension slot 80: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
081. Extension slot 81: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
082. Extension slot 82: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
083. Extension slot 83: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
084. Extension slot 84: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
085. Extension slot 85: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
086. Extension slot 86: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
087. Extension slot 87: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
088. Extension slot 88: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
089. Extension slot 89: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
090. Extension slot 90: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
091. Extension slot 91: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
092. Extension slot 92: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
093. Extension slot 93: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
094. Extension slot 94: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
095. Extension slot 95: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
096. Extension slot 96: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
097. Extension slot 97: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
098. Extension slot 98: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
099. Extension slot 99: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
100. Extension slot 100: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
101. Extension slot 101: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
102. Extension slot 102: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
103. Extension slot 103: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
104. Extension slot 104: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
105. Extension slot 105: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
106. Extension slot 106: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
107. Extension slot 107: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
108. Extension slot 108: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
109. Extension slot 109: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
110. Extension slot 110: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
111. Extension slot 111: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
112. Extension slot 112: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
113. Extension slot 113: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
114. Extension slot 114: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
115. Extension slot 115: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
116. Extension slot 116: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
117. Extension slot 117: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
118. Extension slot 118: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
119. Extension slot 119: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
120. Extension slot 120: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
121. Extension slot 121: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
122. Extension slot 122: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
123. Extension slot 123: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
124. Extension slot 124: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
125. Extension slot 125: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
126. Extension slot 126: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
127. Extension slot 127: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
128. Extension slot 128: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
129. Extension slot 129: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
130. Extension slot 130: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
131. Extension slot 131: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
132. Extension slot 132: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
133. Extension slot 133: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
134. Extension slot 134: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
135. Extension slot 135: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
136. Extension slot 136: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
137. Extension slot 137: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
138. Extension slot 138: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
139. Extension slot 139: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
140. Extension slot 140: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
141. Extension slot 141: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
142. Extension slot 142: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
143. Extension slot 143: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
144. Extension slot 144: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
145. Extension slot 145: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
146. Extension slot 146: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
147. Extension slot 147: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
148. Extension slot 148: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
149. Extension slot 149: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
150. Extension slot 150: reserve this line for future network-specific heuristics, protocol-specific tuning, or interface correlation notes.
'''

# =============================================================================
# Better rewrite layer
# =============================================================================

class TopicInferenceEngine:
    """
    Stronger topic inference than the base chat generator.

    Goals:
    - Stop collapsing mixed router/transport/dns evidence into DEFAULT/misc.
    - Weight prompt intent, packet evidence, ports, phases, and components together.
    - Recognize noisy local-discovery traffic separately from classic resolver DNS.
    """

    TOPIC_LEXICON: Dict[str, List[str]] = {
        "dns": ["dns", "resolver", "qname", "llmnr", "mdns", "port 53", "port 5353", "port 5355", "port 137", "port 1900", "port 3702", "multicast"],
        "dhcp": ["dhcp", "lease", "offer", "discover", "request", "ack", "option 82"],
        "tls": ["tls", "ssl", "sni", "alpn", "certificate", "handshake", "clienthello", "serverhello", "finished", "alert"],
        "http": ["http", "https", "request", "response", "headers", "18080"],
        "vpn": ["vpn", "wireguard", "ipsec", "esp", "ah", "gre", "nat-t", "tunnel"],
        "quic": ["quic", "http/3", "dcid", "scid", "version negotiation", "retry"],
        "transport": ["tcp", "udp", "icmp", "syn", "ack", "rst", "fin", "window", "retransmit"],
        "router": ["router", "forward", "forwarding", "iface", "interface", "bridge", "wintun", "windivert", "phase", "component", "path"],
        "arp": ["arp", "who-has", "is-at", "gratuitous arp"],
        "misc": [],
    }

    PORT_HINTS: Dict[int, str] = {
        53: "dns", 5353: "dns", 5355: "dns", 137: "dns", 1900: "dns", 3702: "dns",
        67: "dhcp", 68: "dhcp",
        443: "tls", 8443: "tls",
        80: "http", 8080: "http", 18080: "http",
        500: "vpn", 4500: "vpn", 51820: "vpn",
        22: "transport",
    }

    def infer(
        self,
        prompt: str,
        packets: List[KnowledgePacket],
        learned_stats: Dict[str, Any],
        health_snapshot: Optional[Dict[str, Any]] = None,
        correlation_snapshot: Optional[Dict[str, Any]] = None,
    ) -> str:
        score = Counter()
        low = (prompt or "").lower()

        for topic, words in self.TOPIC_LEXICON.items():
            for w in words:
                if w in low:
                    score[topic] += 6

        categorical = learned_stats.get("categorical", {}) if isinstance(learned_stats, dict) else {}
        for feat in ("port", "proto", "component", "phase", "iface"):
            for val, cnt in categorical.get(feat, {}).get("top_k", []):
                sval = str(val).lower()
                if feat == "port":
                    try:
                        port = int(sval)
                        hinted = self.PORT_HINTS.get(port)
                        if hinted:
                            score[hinted] += 3 + min(4, int(cnt))
                    except Exception:
                        pass
                if "handshake" in sval or "tls" in sval:
                    score["tls"] += 3
                if "forward" in sval or "packet-writer" in sval or "packet-catch" in sval or "windivert" in sval or "wintun" in sval:
                    score["router"] += 2
                if sval in ("tcp", "udp", "icmp"):
                    score["transport"] += 2

        for pkt in packets:
            score[pkt.topic] += 4
            attrs = pkt.payload.get("attributes", {}) if isinstance(pkt.payload, dict) else {}
            if attrs.get("hs_type_name"):
                score["tls"] += 5
            if attrs.get("dns_query"):
                score["dns"] += 5
            if attrs.get("mdns"):
                score["dns"] += 4
            if attrs.get("arp_op") is not None:
                score["arp"] += 5
            if attrs.get("iface_in"):
                score["router"] += 1
            for pkey in ("sport", "dport"):
                try:
                    port = int(attrs.get(pkey))
                    hinted = self.PORT_HINTS.get(port)
                    if hinted:
                        score[hinted] += 2
                except Exception:
                    pass
            if attrs.get("tcp_flags"):
                score["transport"] += 2
            if attrs.get("phase") or attrs.get("component"):
                score["router"] += 1

        if health_snapshot:
            if health_snapshot.get("resolver_noise"):
                score["dns"] += 2
            if health_snapshot.get("half_open_pressure"):
                score["transport"] += 2
            if health_snapshot.get("interface_spread"):
                score["router"] += 2

        if correlation_snapshot:
            if correlation_snapshot.get("stage_drift_count", 0) > 0:
                score["router"] += 3
            if correlation_snapshot.get("cross_iface_flow_count", 0) > 0:
                score["router"] += 2

        if score:
            return score.most_common(1)[0][0]
        return "misc"


class NetworkHealthManager:
    """
    Derives higher-level health signals from the manager state without changing
    the ingest pipeline. This keeps the rewrite safer while still making the
    file more useful for real decisions.
    """

    DISCOVERY_PORTS = {137, 1900, 3702, 5353, 5355}

    def snapshot_from_manager(self, manager: 'CodeOutputManager') -> Dict[str, Any]:
        stats = manager.get_stats()
        exported = manager.export_knowledge()
        pkt = manager.packet_learner

        transport_cat = pkt.snapshot_categoricals("transport", top_k=10)
        dns_cat = pkt.snapshot_categoricals("dns", top_k=10)
        router_cat = pkt.snapshot_categoricals("router", top_k=10)

        syn_count = self._tcp_flag_count(transport_cat, 'S')
        ack_count = self._tcp_flag_count(transport_cat, 'A')
        rst_count = self._tcp_flag_count(transport_cat, 'R')
        half_open_pressure = syn_count > 0 and ack_count < max(1, syn_count * 0.6)

        noisy_ports = []
        for port, count in dns_cat.get("port", []):
            try:
                p = int(port)
            except Exception:
                continue
            if p in self.DISCOVERY_PORTS:
                noisy_ports.append((p, count))

        resolver_noise = len(noisy_ports) > 0
        interface_spread = len(stats.get("by_iface", {})) > 2
        emit_dup_pressure = stats.get("emit_duplicates", 0) >= max(2, stats.get("emits", 0))

        top_ifaces = sorted(stats.get("by_iface", {}).items(), key=lambda kv: kv[1], reverse=True)[:6]
        top_components = sorted(stats.get("by_component", {}).items(), key=lambda kv: kv[1], reverse=True)[:6]
        top_stages = sorted(stats.get("by_stage", {}).items(), key=lambda kv: kv[1], reverse=True)[:6]

        return {
            "half_open_pressure": bool(half_open_pressure),
            "resolver_noise": bool(resolver_noise),
            "interface_spread": bool(interface_spread),
            "emit_dup_pressure": bool(emit_dup_pressure),
            "syn_count": syn_count,
            "ack_count": ack_count,
            "rst_count": rst_count,
            "noisy_ports": noisy_ports,
            "top_ifaces": top_ifaces,
            "top_components": top_components,
            "top_stages": top_stages,
            "topics_present": list(exported.keys()),
            "router_iface_top": router_cat.get("iface", []),
        }

    @staticmethod
    def _tcp_flag_count(transport_cat: Dict[str, List[Tuple[str, int]]], flag_char: str) -> int:
        total = 0
        for flags, count in transport_cat.get("tcp_flags", []):
            if flag_char in str(flags):
                total += int(count)
        return total


class CorrelationManager:
    """
    Scans exported knowledge and extracts cross-interface and cross-stage flow patterns.
    """

    def snapshot_from_manager(self, manager: 'CodeOutputManager') -> Dict[str, Any]:
        exported = manager.export_knowledge()
        flow_index: Dict[str, Dict[str, set]] = defaultdict(lambda: {
            "ifaces": set(),
            "stages": set(),
            "components": set(),
            "topics": set(),
        })

        for topic, rows in exported.items():
            for row in rows:
                flow = str(row.get("flow_key") or "")
                if not flow:
                    continue
                flow_index[flow]["topics"].add(topic)
                if row.get("iface"):
                    flow_index[flow]["ifaces"].add(str(row["iface"]))
                payload = row.get("payload") or {}
                attrs = payload.get("attributes", {}) if isinstance(payload, dict) else {}
                if attrs.get("phase"):
                    flow_index[flow]["stages"].add(str(attrs["phase"]))
                if attrs.get("component"):
                    flow_index[flow]["components"].add(str(attrs["component"]))

        cross_iface = []
        stage_drift = []
        component_spread = []
        for flow, meta in flow_index.items():
            if len(meta["ifaces"]) > 1:
                cross_iface.append((flow, sorted(meta["ifaces"])))
            if len(meta["stages"]) > 2:
                stage_drift.append((flow, sorted(meta["stages"])))
            if len(meta["components"]) > 2:
                component_spread.append((flow, sorted(meta["components"])))

        return {
            "cross_iface_flow_count": len(cross_iface),
            "stage_drift_count": len(stage_drift),
            "component_spread_count": len(component_spread),
            "cross_iface_examples": cross_iface[:5],
            "stage_drift_examples": stage_drift[:5],
            "component_spread_examples": component_spread[:5],
        }


class BetterAskManagerChatGenerator(AskManagerChatGenerator):
    def __init__(
        self,
        *args,
        topic_inference_engine: Optional[TopicInferenceEngine] = None,
        health_manager: Optional[NetworkHealthManager] = None,
        correlation_manager: Optional[CorrelationManager] = None,
        co_manager_ref: Optional['CodeOutputManager'] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._topic_inference_engine = topic_inference_engine or TopicInferenceEngine()
        self._health_manager = health_manager or NetworkHealthManager()
        self._correlation_manager = correlation_manager or CorrelationManager()
        self._co_manager_ref = co_manager_ref

    def generate(self, prompt: str, *, redact: bool) -> str:
        tokens = [t for t in self._tokenize(prompt) if t and not t.isdigit()]
        token_lines = self._fetch_token_lines(tokens, per_token_limit=self._per_token_limit)
        if token_lines:
            lines = ["Using token matches from history:"]
            for s in token_lines[: self._max_token_lines]:
                lines.append(f"• {self._present(s, redact=redact, max_len=220)}")
            return "\n".join(lines)

        packets = self._knowledge_retriever(prompt, topk=12, per_topic_limit=8)
        preliminary_topic = super()._guess_topic(prompt, packets)

        learned_stats_all = self._sm.compute(
            online_num_stats=self._pl.get_all_online_numeric_stats(),
            cat_counters=self._pl.get_all_categorical_counters(),
            recent_numeric_vectors=self._pl.get_recent_numeric_vectors(),
            topics=[],
            percentiles=[50, 95],
            topk_categorical=6,
            min_count_for_stats=2,
        )

        health_snapshot = None
        correlation_snapshot = None
        if self._co_manager_ref is not None:
            health_snapshot = self._health_manager.snapshot_from_manager(self._co_manager_ref)
            correlation_snapshot = self._correlation_manager.snapshot_from_manager(self._co_manager_ref)

        topic = self._topic_inference_engine.infer(
            prompt=prompt,
            packets=packets,
            learned_stats=learned_stats_all.get(preliminary_topic, {}),
            health_snapshot=health_snapshot,
            correlation_snapshot=correlation_snapshot,
        )
        learned_stats = learned_stats_all.get(topic, {})

        lines = [f"Topic: {topic.upper()}"]
        hints = self._collect_packet_hints(packets, redact=redact)
        if hints:
            lines.append("Relevant evidence:")
            lines.extend(f"• {h}" for h in hints[: self._max_hint_lines])

        observations = self._observations(topic, learned_stats)
        if observations:
            lines.append("")
            lines.append("Observations:")
            lines.extend(f"• {x}" for x in observations)

        if health_snapshot:
            health_lines = self._health_lines(health_snapshot)
            if health_lines:
                lines.append("")
                lines.append("Health signals:")
                lines.extend(f"• {x}" for x in health_lines)

        if correlation_snapshot:
            corr_lines = self._correlation_lines(correlation_snapshot)
            if corr_lines:
                lines.append("")
                lines.append("Correlation:")
                lines.extend(f"• {x}" for x in corr_lines)

        recent_flows = self._pl.snapshot_flows(topic, top_k=3)
        if recent_flows:
            lines.append("")
            lines.append("Busy flows:")
            for flow in recent_flows:
                lines.append(
                    f"• {self._present(flow['key'], redact=redact, max_len=120)} "
                    f"(packets={flow['packets']}, bytes={flow['bytes']}, iface={flow['iface']})"
                )

        anomalies = [a for a in self._pl.get_numeric_anomalies(limit=16) if a["topic"] == topic][:3]
        if anomalies:
            lines.append("")
            lines.append("Anomalies:")
            for a in anomalies:
                lines.append(f"• {a['feature']} deviated (value={a['value']:.2f}, z={a['z_score']:.2f})")

        lines.append("")
        lines.append(f"Next step: {self.TOPIC_TIPS.get(topic, self.TOPIC_TIPS['misc'])}")
        return "\n".join(lines)

    def _health_lines(self, health_snapshot: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        if health_snapshot.get("half_open_pressure"):
            out.append(
                f"half-open TCP pressure: SYN={health_snapshot.get('syn_count', 0)} ACK={health_snapshot.get('ack_count', 0)}"
            )
        if health_snapshot.get("resolver_noise"):
            ports = ", ".join(f"{p}({c})" for p, c in health_snapshot.get("noisy_ports", [])[:5])
            out.append(f"local-discovery noise is strong on ports {ports}")
        if health_snapshot.get("interface_spread"):
            out.append("traffic is spread across multiple interfaces")
        if health_snapshot.get("emit_dup_pressure"):
            out.append("auto-emitter is seeing high duplicate pressure")
        return out

    def _correlation_lines(self, correlation_snapshot: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        if correlation_snapshot.get("cross_iface_flow_count", 0) > 0:
            out.append(f"{correlation_snapshot['cross_iface_flow_count']} flows appear across multiple interfaces")
        if correlation_snapshot.get("stage_drift_count", 0) > 0:
            out.append(f"{correlation_snapshot['stage_drift_count']} flows span more than two stages")
        if correlation_snapshot.get("component_spread_count", 0) > 0:
            out.append(f"{correlation_snapshot['component_spread_count']} flows span many components")
        return out


class BetterCodeOutputManager(CodeOutputManager):
    """
    Compatibility-preserving upgrade layer.

    It keeps the existing class name pattern and external behavior, but improves:
    - semantic delta calculation for the auto-emitter
    - chat topic inference
    - surfaced health / correlation insights
    - generated snapshot richness
    """

    def __init__(self, router_logger: Any):
        super().__init__(router_logger)
        self.health_manager = NetworkHealthManager()
        self.correlation_manager = CorrelationManager()
        self.topic_inference_engine = TopicInferenceEngine()
        self._last_emit_inventory: Dict[str, set] = {}

        self.ask_manager.chat_generator = BetterAskManagerChatGenerator(
            token_store=self.ask_manager._fetch_token_lines_for_chatgen,
            knowledge_retriever=self.ask_manager._retrieve_snippets,
            knowledge_exporter=self.ask_manager._export_knowledge,
            payload_formatter=self.ask_manager._payload_to_text,
            packet_learner_ref=self.packet_learner,
            stats_manager_ref=self.stats_manager,
            rng_seed=9999,
            topic_inference_engine=self.topic_inference_engine,
            health_manager=self.health_manager,
            correlation_manager=self.correlation_manager,
            co_manager_ref=self,
        )
        self._log("[CodeOutput] Better rewrite layer enabled.", 1)

    def _semantic_state_digest(self) -> Tuple[str, int]:
        """
        Better delta: compare the current semantic inventory to the previous one
        rather than just counting the current unique hashes.
        """
        with self._k_lock:
            inventory: Dict[str, set] = {}
            for topic, dq in sorted(self._knowledge_by_topic.items()):
                inventory[topic] = {
                    pkt.semantic_hash()
                    for pkt in list(dq)[-48:]
                    if not pkt.is_expired()
                }

            serializable = {topic: sorted(vals) for topic, vals in inventory.items()}
            raw = json.dumps(serializable, sort_keys=True, default=str).encode("utf-8", "replace")
            cur = hashlib.sha256(raw).hexdigest()

            delta = 0
            previous_topics = set(self._last_emit_inventory.keys())
            current_topics = set(inventory.keys())
            for topic in sorted(previous_topics | current_topics):
                before = self._last_emit_inventory.get(topic, set())
                after = inventory.get(topic, set())
                delta += len(before.symmetric_difference(after))

            if delta == 0 and serializable:
                delta = 1

            self._last_emit_inventory = {k: set(v) for k, v in inventory.items()}

        return cur, delta

    def _insights_for_topics(self, topics: Iterable[str]) -> Dict[str, List[Tuple[str, int]]]:
        base = super()._insights_for_topics(topics)
        health = self.health_manager.snapshot_from_manager(self)
        corr = self.correlation_manager.snapshot_from_manager(self)

        extra: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
        for topic in (list(topics) if topics else list(base.keys()) or list(self.export_knowledge().keys())):
            if health.get("resolver_noise") and topic == "dns":
                extra[topic].append(("resolver_noise", 1))
            if health.get("half_open_pressure") and topic == "transport":
                extra[topic].append(("half_open_pressure", 1))
            if corr.get("stage_drift_count", 0) and topic == "router":
                extra[topic].append(("stage_drift", int(corr["stage_drift_count"])))
            if corr.get("cross_iface_flow_count", 0) and topic == "router":
                extra[topic].append(("cross_iface_flows", int(corr["cross_iface_flow_count"])))

        out = dict(base)
        for topic, pairs in extra.items():
            out.setdefault(topic, [])
            out[topic].extend(pairs)
        return out

    def health_snapshot(self) -> Dict[str, Any]:
        return self.health_manager.snapshot_from_manager(self)

    def correlation_snapshot(self) -> Dict[str, Any]:
        return self.correlation_manager.snapshot_from_manager(self)


# Export the upgraded class under the original public name.
CodeOutputManager = BetterCodeOutputManager
