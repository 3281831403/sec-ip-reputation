"""IP reputation primitives.

The public state is a mapping from normalized address to a record with an event
map, a running score, and the timestamp of the last update.  Policies use the
keys block_threshold, half_life, and allowlist.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

MAX_SCORE = 1000.0
DEFAULT_HALF_LIFE = 3600.0
DEFAULT_BLOCK_THRESHOLD = 100.0


def normalize_addr(addr: str) -> str:
    """Return the canonical spelling used as the state key for an address."""
    text = str(addr).strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass

    if ":" in text:
        return text.lower()

    # IPv4 written with leading zeros (e.g. 192.168.000.010) is rejected by
    # ipaddress; normalize each octet numerically.
    parts = text.split(".")
    if len(parts) == 4:
        try:
            octets = [int(part, 10) for part in parts]
        except ValueError:
            return text
        if all(0 <= octet <= 255 for octet in octets):
            return ".".join(str(octet) for octet in octets)

    return text


def _lookup(state: dict[str, Any], addr: str) -> dict[str, Any] | None:
    if not isinstance(state, dict):
        return None
    record = state.get(normalize_addr(addr))
    if record is None:
        record = state.get(str(addr).strip())
    return record


def add_event(
    state: dict[str, Any],
    addr: str,
    event: Any,
    now: float,
    weight: float,
) -> dict[str, Any]:
    """Add one event to an address record and return the state."""
    if not isinstance(state, dict):
        raise TypeError("state must be a mapping")

    key = normalize_addr(addr)
    record = state.get(key)
    if record is None:
        record = {
            "events": {},
            "score": 0.0,
            "last": float(now),
            "updated_at": float(now),
        }
        state[key] = record

    record.setdefault("events", {})
    record.setdefault("score", 0.0)

    if event in record["events"]:
        # Same event reported again for the same address: count it once.
        return state

    record["events"][event] = float(weight)
    record["score"] = float(record["score"]) + float(weight)
    record["last"] = float(now)
    record["updated_at"] = float(now)
    return state


def decay(
    state: dict[str, Any],
    addr: str,
    now: float,
    half_life: float,
) -> float:
    """Reduce a record toward zero and return the resulting score."""
    record = _lookup(state, addr)
    if record is None:
        return 0.0

    current = float(record.get("score", 0.0))
    last = float(record.get("last", now))
    elapsed = max(0.0, float(now) - last)
    try:
        half_life_value = float(half_life)
    except (TypeError, ValueError):
        return current

    if elapsed == 0.0 or half_life_value <= 0.0:
        record["last"] = float(now)
        return current

    remaining = current * (0.5 ** (elapsed / half_life_value))
    record["score"] = remaining
    record["last"] = float(now)
    record["updated_at"] = float(now)
    return remaining


def score(state: dict[str, Any], addr: str, now: float) -> float:
    """Return the current score for an address, constrained to the score range."""
    record = _lookup(state, addr)
    if record is None:
        return 0.0

    current = float(record.get("score", 0.0))
    if current > MAX_SCORE:
        current = MAX_SCORE
    if current < 0.0:
        current = 0.0
    return current


def is_blocked(
    state: dict[str, Any],
    addr: str,
    now: float,
    policy: Mapping[str, Any] | None,
) -> bool:
    """Return whether an address is blocked under the policy.

    The allowlist always wins over any block decision.  Blocking applies at
    network granularity: an explicit blocklist entry (single address or CIDR)
    blocks every matching address, and otherwise an address is blocked when
    its score reaches the threshold (score >= threshold).
    """
    policy = policy or {}
    if allowlisted(addr, policy.get("allowlist")):
        return False

    if _matches_any(addr, policy.get("blocklist")):
        return True

    threshold = float(policy.get("block_threshold", DEFAULT_BLOCK_THRESHOLD))
    current = score(state, addr, now)
    return current >= threshold


def _matches_any(addr: str, entries: Any) -> bool:
    """Return whether an address matches any literal entry or network."""
    if not entries:
        return False

    target = normalize_addr(addr)
    for entry in entries:
        raw = str(entry).strip()
        if not raw:
            continue

        if "/" in raw:
            try:
                network = ipaddress.ip_network(raw, strict=False)
                if ipaddress.ip_address(target) in network:
                    return True
            except ValueError:
                continue
            continue

        if target == normalize_addr(raw):
            return True
    return False


def allowlisted(addr: str, allowlist: Any) -> bool:
    """Return whether an address matches a literal allowlist entry or network."""
    return _matches_any(addr, allowlist)


def validate_policy(policy: Mapping[str, Any] | None) -> list[str]:
    """Return a list of policy problems, or an empty list when valid."""
    if not isinstance(policy, Mapping):
        return ["policy must be a mapping"]

    issues: list[str] = []

    threshold = policy.get("block_threshold")
    if threshold is None:
        issues.append("block threshold is required")
    else:
        try:
            threshold_value = float(threshold)
        except (TypeError, ValueError):
            issues.append("block threshold must be numeric")
        else:
            if threshold_value < 0:
                issues.append("block threshold must not be negative")

    half_life = policy.get("half_life")
    if half_life is None:
        issues.append("half life is required")
    else:
        try:
            half_life_value = float(half_life)
        except (TypeError, ValueError):
            issues.append("half life must be numeric")
        else:
            if half_life_value <= 0:
                issues.append("half life must be positive")

    if not policy.get("allowlist"):
        issues.append("allowlist must not be empty")

    return issues


def _read_event(item: Any) -> tuple[str, Any, float, float]:
    if isinstance(item, Mapping):
        addr = item["addr"]
        event = item["event"]
        now = item.get("now", 0.0)
        weight = item.get("weight", 0.0)
    else:
        addr, event, now, weight = item
    return normalize_addr(addr), event, float(now), float(weight)


def reputation_batch(events: Any, policy: Mapping[str, Any] | None) -> dict[str, float]:
    """Score a batch of events, keeping the score state of each address separate."""
    policy = policy or {}
    half_life = float(policy.get("half_life", DEFAULT_HALF_LIFE))
    state: dict[str, Any] = {}
    results: dict[str, float] = {}

    for item in events or []:
        addr, event, now, weight = _read_event(item)
        if half_life > 0:
            decay(state, addr, now, half_life)
        add_event(state, addr, event, now, weight)
        results[addr] = score(state, addr, now)

    return results