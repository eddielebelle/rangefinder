"""Offline objective scorer.

Consumes a telemetry log (the same JSON-lines the facades emit — full logs are kept, the
scorer is just another reader) and evaluates each objective's ``detect`` signals against
the events. An objective is MET when any signal matches any single event. Reports the
first match (when, source IP, action) plus how many events matched and which sources.

Single-event matching only in v1 — a signal's conditions must all hold on one event.
Cross-event sequences ("authenticated THEN read file") are a future enhancement.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class ObjectiveResult:
    id: str
    title: str
    scoreable: bool
    met: bool = False
    kind: str = "signal"  # "signal" (single-event) or "sequence" (kill chain)
    signal: str | None = None
    timestamp: str | None = None
    source_ip: str | None = None
    action: str | None = None
    match_count: int = 0
    source_ips: list[str] = field(default_factory=list)
    # For a sequence match: the ordered chain of steps that fired.
    chain: list[dict] = field(default_factory=list)


def parse_events(lines: Iterable[str]) -> list[dict]:
    """Parse JSON events from log lines, tolerating a `docker compose logs` prefix.

    Each line may be raw JSON or `container-name  | {json}`; we take the substring from
    the first '{'. Non-JSON lines are skipped. Events are returned sorted by @timestamp.
    """
    events: list[dict] = []
    for line in lines:
        start = line.find("{")
        if start < 0:
            continue
        try:
            obj = json.loads(line[start:])
        except ValueError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    events.sort(key=lambda e: e.get("@timestamp", ""))
    return events


def _get(event: dict, dotted: str):
    cur = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _condition_matches(cond, event: dict) -> bool:
    value = _get(event, cond.field)
    if value is None:
        return False
    candidates = value if isinstance(value, list) else [value]
    for v in candidates:
        s = str(v)
        if cond.equals is not None and s == cond.equals:
            return True
        if cond.contains is not None and cond.contains.lower() in s.lower():
            return True
        if cond.regex is not None and re.search(cond.regex, s):
            return True
    return False


def _signal_matches(signal, event: dict) -> bool:
    return all(_condition_matches(c, event) for c in signal.all)


def score(config, events: list[dict]) -> list[ObjectiveResult]:
    results: list[ObjectiveResult] = []
    for obj in config.objectives:
        has_detect = bool(obj.detect)
        has_sequence = obj.sequence is not None
        if not has_detect and not has_sequence:
            results.append(ObjectiveResult(obj.id, obj.title, scoreable=False))
            continue

        result = None
        if has_detect:
            result = _eval_detect(obj, events)
        if result is None and has_sequence:
            result = _eval_sequence(obj, events)
        results.append(result or ObjectiveResult(obj.id, obj.title, scoreable=True, met=False))
    return results


def _eval_detect(obj, events: list[dict]) -> ObjectiveResult | None:
    first: dict | None = None
    first_label: str | None = None
    sources: set[str] = set()
    count = 0
    for event in events:
        for signal in obj.detect:
            if _signal_matches(signal, event):
                count += 1
                ip = _get(event, "source.ip")
                if ip:
                    sources.add(ip)
                if first is None:
                    first, first_label = event, (signal.label or "")
                break
    if first is None:
        return None
    return ObjectiveResult(
        obj.id, obj.title, scoreable=True, met=True, kind="signal",
        signal=first_label,
        timestamp=first.get("@timestamp"),
        source_ip=_get(first, "source.ip"),
        action=_get(first, "event.action"),
        match_count=count,
        source_ips=sorted(sources),
    )


def _eval_sequence(obj, events: list[dict]) -> ObjectiveResult | None:
    seq = obj.sequence
    steps = seq.steps
    within_s = _parse_duration(seq.within)

    # Per-source (or a single global) state machine: (step_index, first_ts, chain).
    def blank():
        return [0, None, []]

    states: dict[str | None, list] = {}
    for event in events:
        src = _get(event, "source.ip") if seq.same_source else None
        if seq.same_source and src is None:
            continue  # steps must correlate by source; unattributed events can't
        st = states.setdefault(src, blank())
        idx, first_ts, chain = st
        if idx >= len(steps):
            continue
        if not _signal_matches(steps[idx], event):
            continue
        ts = _epoch(event.get("@timestamp"))
        if idx == 0:
            first_ts = ts
        elif within_s is not None and first_ts is not None and ts is not None and (ts - first_ts) > within_s:
            # too slow — drop progress, but this event may still open a new chain
            if _signal_matches(steps[0], event):
                states[src] = [1, ts, [_step(steps[0], event)]]
            else:
                states[src] = blank()
            continue
        chain = chain + [_step(steps[idx], event)]
        idx += 1
        states[src] = [idx, first_ts, chain]
        if idx == len(steps):
            return ObjectiveResult(
                obj.id, obj.title, scoreable=True, met=True, kind="sequence",
                timestamp=event.get("@timestamp"),
                source_ip=src if seq.same_source else _get(event, "source.ip"),
                action=_get(event, "event.action"),
                source_ips=[src] if (seq.same_source and src) else [],
                chain=chain,
            )
    return None


def _step(signal, event: dict) -> dict:
    return {
        "label": signal.label or "",
        "action": _get(event, "event.action"),
        "timestamp": event.get("@timestamp"),
        "source_ip": _get(event, "source.ip"),
    }


def _parse_duration(value: str | None) -> float | None:
    if not value:
        return None
    m = re.fullmatch(r"(\d+)\s*([smhd])", value.strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def _epoch(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        from datetime import datetime

        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
