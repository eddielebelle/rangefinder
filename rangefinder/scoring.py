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
    signal: str | None = None
    timestamp: str | None = None
    source_ip: str | None = None
    action: str | None = None
    match_count: int = 0
    source_ips: list[str] = field(default_factory=list)


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
        if not obj.detect:
            results.append(ObjectiveResult(obj.id, obj.title, scoreable=False))
            continue

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
                    break  # one event satisfies at most one signal for counting

        if first is not None:
            results.append(
                ObjectiveResult(
                    obj.id, obj.title, scoreable=True, met=True,
                    signal=first_label,
                    timestamp=first.get("@timestamp"),
                    source_ip=_get(first, "source.ip"),
                    action=_get(first, "event.action"),
                    match_count=count,
                    source_ips=sorted(sources),
                )
            )
        else:
            results.append(ObjectiveResult(obj.id, obj.title, scoreable=True, met=False))
    return results
