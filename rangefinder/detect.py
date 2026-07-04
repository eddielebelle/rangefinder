"""Detection engineering over range telemetry.

The range emits ground-truth-labelled ECS telemetry: run an attack and you get the
malicious events; leave it idle / use it normally and you get a benign baseline. That makes
detection rules *measurable* — a Sigma rule can be scored for true positives (fires on the
attack), false positives (fires on benign traffic), and overfitting (keys on ephemeral,
attacker-specific values instead of the technique).

This module is the deterministic core:
- a minimal Sigma evaluator (selection maps + a condition expression) over ECS events,
- ``validate()`` which grades a rule against labelled attack/benign logs,
- a small template generator so ``rangefinder detect`` produces a validated baseline with no
  agent in the loop.

A blue-team agent can write richer rules; this harness is what makes its output trustworthy
rather than plausible — every rule is run back over the ground-truth telemetry.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from rangefinder.scoring import _get, parse_events  # dotted-path getter + log parser

# Fields whose *values* are specific to one attack instance, not the technique. A detection
# that keys on these is overfit — it would miss the same attack from a different source/time.
EPHEMERAL_FIELDS = frozenset(
    {"source.ip", "source.port", "@timestamp", "rangefinder.conn_id"}
)


# --------------------------------------------------------------------- Sigma evaluator

def _match_field(event: dict, key: str, spec) -> bool:
    """Match one ``field[|modifier...]: value(s)`` entry against an event.

    Supports dotted ECS paths and the common Sigma value modifiers (contains/startswith/
    endswith/re). A list of values is an OR; comparison is case-insensitive like real SIEMs.
    """
    field_name, *mods = key.split("|")
    value = _get(event, field_name)
    if value is None:
        return False
    candidates = value if isinstance(value, list) else [value]
    wanted = spec if isinstance(spec, list) else [spec]
    for cand in candidates:
        s = str(cand)
        for w in wanted:
            ws = str(w)
            if "re" in mods:
                if re.search(ws, s):
                    return True
            elif "contains" in mods:
                if ws.lower() in s.lower():
                    return True
            elif "startswith" in mods:
                if s.lower().startswith(ws.lower()):
                    return True
            elif "endswith" in mods:
                if s.lower().endswith(ws.lower()):
                    return True
            elif s.lower() == ws.lower():
                return True
    return False


def _selection_matches(event: dict, selection) -> bool:
    """A selection is a map (all entries must match) or a list of maps (any map matches)."""
    if isinstance(selection, list):
        return any(_selection_matches(event, s) for s in selection)
    if not isinstance(selection, dict):
        return False
    return all(_match_field(event, k, v) for k, v in selection.items())


def _tokenize_condition(condition: str) -> list[str]:
    return re.findall(r"[()]|[\w*]+", condition.lower())


def _eval_condition(condition: str, matched: dict[str, bool]) -> bool:
    """Evaluate a Sigma ``condition`` over precomputed per-selection booleans.

    Supports and/or/not, parentheses, ``N of them`` / ``all of them`` / ``N of <glob>`` /
    ``all of <glob>`` — the subset real rules use.
    """
    tokens = _tokenize_condition(condition)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def advance():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or():
        val = parse_and()
        while peek() == "or":
            advance()
            val = parse_and() or val
        return val

    def parse_and():
        val = parse_not()
        while peek() == "and":
            advance()
            val = parse_not() and val
        return val

    def parse_not():
        if peek() == "not":
            advance()
            return not parse_not()
        return parse_atom()

    def parse_atom():
        tok = peek()
        if tok == "(":
            advance()
            val = parse_or()
            if peek() == ")":
                advance()
            return val
        if tok == "all" or (tok is not None and tok.isdigit()):
            advance()
            if peek() == "of":
                advance()
            target = advance()
            names = list(matched) if target == "them" else [
                n for n in matched if fnmatch.fnmatch(n, target)]
            hits = sum(1 for n in names if matched[n])
            need = len(names) if tok == "all" else int(tok)
            return hits >= need
        advance()
        return matched.get(tok, False)

    result = parse_or()
    return bool(result)


def rule_matches(rule: dict, event: dict) -> bool:
    detection = rule.get("detection", {})
    selections = {k.lower(): v for k, v in detection.items() if k != "condition"}
    matched = {name: _selection_matches(event, sel) for name, sel in selections.items()}
    condition = detection.get("condition", "")
    if not condition:  # no condition => any selection matching counts (lenient default)
        return any(matched.values())
    return _eval_condition(condition, matched)


def matched_indices(rule: dict, events: list[dict]) -> list[int]:
    return [i for i, e in enumerate(events) if rule_matches(rule, e)]


def rule_fields(rule: dict) -> set[str]:
    """Every ECS field a rule's detection references (modifiers stripped)."""
    fields: set[str] = set()
    for key, sel in rule.get("detection", {}).items():
        if key == "condition":
            continue
        for entry in (sel if isinstance(sel, list) else [sel]):
            if isinstance(entry, dict):
                for field_key in entry:
                    fields.add(field_key.split("|")[0])
    return fields


# ------------------------------------------------------------------------- validation

@dataclass
class Validation:
    title: str
    true_positives: int
    attack_total: int
    false_positives: int
    benign_total: int
    overfit_fields: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.true_positives > 0 and self.false_positives == 0 and not self.overfit_fields

    @property
    def verdict(self) -> str:
        if self.true_positives == 0:
            return "MISS (never fires on the attack)"
        if self.false_positives > 0:
            return f"NOISY ({self.false_positives} false positive(s) on benign traffic)"
        if self.overfit_fields:
            return f"OVERFIT (keys on {', '.join(self.overfit_fields)})"
        return "VALID"


def validate(rule: dict, attack_events: list[dict], benign_events: list[dict] | None = None) -> Validation:
    benign_events = benign_events or []
    return Validation(
        title=str(rule.get("title", "<untitled>")),
        true_positives=len(matched_indices(rule, attack_events)),
        attack_total=len(attack_events),
        false_positives=len(matched_indices(rule, benign_events)),
        benign_total=len(benign_events),
        overfit_fields=sorted(rule_fields(rule) & EPHEMERAL_FIELDS),
    )


# ------------------------------------------------------------- template rule generator

# Minimal technique library: when an attack event matches ``when``, emit ``sigma``. Deliberately
# single-event techniques with clean signatures; a blue-team agent covers the rest.
_TECHNIQUES: list[dict] = [
    {
        "when": {"event.action": "smb_auth", "rangefinder.auth.method": "anonymous"},
        "sigma": {
            "title": "Anonymous (null-session) SMB logon",
            "status": "experimental",
            "description": "An SMB session established with no credentials — used to enumerate "
                           "shares and accounts. Legitimate access authenticates.",
            "logsource": {"product": "rangefinder", "service": "smb"},
            "detection": {
                "selection": {"event.action": "smb_auth", "rangefinder.auth.method": "anonymous"},
                "condition": "selection",
            },
            "level": "medium",
            "tags": ["attack.discovery", "attack.t1135"],
        },
    },
    {
        "when": {"event.action": "kerberos_as_rep"},
        "sigma": {
            "title": "Kerberos AS-REP roasting",
            "status": "experimental",
            "description": "An AS-REP issued for a pre-auth-disabled account — offline-crackable.",
            "logsource": {"product": "rangefinder", "service": "kerberos"},
            "detection": {
                "selection": {"event.action": "kerberos_as_rep", "event.outcome": "success"},
                "condition": "selection",
            },
            "level": "high",
            "tags": ["attack.credential_access", "attack.t1558.004"],
        },
    },
    {
        "when": {"event.kind": "alert", "rangefinder.vuln_id|re": ".+"},
        "sigma": {
            "title": "Planted vulnerability hit",
            "status": "experimental",
            "description": "A request matched a known-vulnerable route/resource.",
            "logsource": {"product": "rangefinder"},
            "detection": {
                "selection": {"event.kind": "alert", "rangefinder.vuln_id|re": ".+"},
                "condition": "selection",
            },
            "level": "high",
            "tags": ["attack.initial_access"],
        },
    },
]


def generate(attack_events: list[dict]) -> list[dict]:
    """Emit template Sigma rules for every known technique present in the attack log."""
    rules = []
    for tech in _TECHNIQUES:
        if any(_selection_matches(e, tech["when"]) for e in attack_events):
            rules.append(tech["sigma"])
    return rules


__all__ = [
    "EPHEMERAL_FIELDS", "Validation", "generate", "matched_indices",
    "parse_events", "rule_fields", "rule_matches", "validate",
]
