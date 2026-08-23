"""Pool identity helpers shared by the GUI and miner.

The GUI keeps the actual wallet value separate from an optional fixed-difficulty
suffix.  The effective XMRig ``user`` value is composed only when the config is
written, so saved profiles never accidentally bake a stale difficulty into the
wallet field.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DIFFICULTY_SUFFIX = re.compile(r"^(?P<wallet>.+?)\+(?P<difficulty>[1-9]\d*)$")


@dataclass(frozen=True)
class MiningIdentity:
    pool_url: str = "gulf.moneroocean.stream:10128"
    wallet: str = ""
    append_difficulty: bool = False
    difficulty: int = 10000
    raw_user: str = ""


def split_wallet_difficulty(value: Any) -> tuple[str, int | None]:
    text = str(value or "").strip()
    match = _DIFFICULTY_SUFFIX.fullmatch(text)
    if not match:
        return text, None
    return match.group("wallet").strip(), int(match.group("difficulty"))


def compose_wallet_user(wallet: Any, append_difficulty: bool, difficulty: Any) -> str:
    base, _ = split_wallet_difficulty(wallet)
    base = base.strip()
    if not base:
        return ""
    if append_difficulty:
        try:
            parsed = int(difficulty)
        except (TypeError, ValueError):
            parsed = 0
        if parsed > 0:
            return f"{base}+{parsed}"
    return base


def is_gulf_moneroocean_pool(pool_url: Any) -> bool:
    text = str(pool_url or "").strip().lower()
    text = text.removeprefix("stratum+tcp://").removeprefix("stratum+ssl://")
    return text.startswith("gulf.moneroocean.stream:") or text == "gulf.moneroocean.stream"


def read_mining_identity(config_path: str | Path) -> MiningIdentity:
    path = Path(config_path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError, TypeError):
        return MiningIdentity()

    pools = config.get("pools")
    if not isinstance(pools, list):
        return MiningIdentity()

    first = next((item for item in pools if isinstance(item, dict)), None)
    if first is None:
        return MiningIdentity()

    pool_url = str(first.get("url") or "gulf.moneroocean.stream:10128").strip()
    raw_user = str(first.get("user") or "").strip()
    wallet, parsed_difficulty = split_wallet_difficulty(raw_user)
    return MiningIdentity(
        pool_url=pool_url,
        wallet=wallet,
        append_difficulty=parsed_difficulty is not None,
        difficulty=parsed_difficulty or 10000,
        raw_user=raw_user,
    )
