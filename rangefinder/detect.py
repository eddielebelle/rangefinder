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
  agent in the loop,
- ``from_objectives()`` which compiles the range's own objectives — themselves declarative ECS
  detection specs — straight into Sigma, so the range-specific finding becomes a deployable rule
  and not just a scoreboard entry. Every compiled rule runs the same ``validate()`` gauntlet, so
  one that keys on a field the range never emits is caught as a MISS, never shipped dead.

A blue-team agent can write richer rules; this harness is what makes its output trustworthy
rather than plausible — every rule is run back over the ground-truth telemetry.
"""

from __future__ import annotations

import fnmatch
import re
import uuid
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
            elif "cased" in mods:
                # Sigma 'cased' modifier: exact, case-SENSITIVE match. Compiled objective rules use
                # it for `equals` so they fire on exactly the event set the objective scores as MET
                # (scoring._condition_matches compares equals with a case-sensitive `==`).
                if s == ws:
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


# ------------------------------------------------------- objective -> Sigma compiler

# A range author declares each Objective as a set of ECS field predicates — exactly a detection
# spec. Compile those straight into Sigma so the *range-specific* finding (the planted leak, the
# roastable account) becomes a deployable rule, not just a scoreboard entry. Every compiled rule
# still runs the gauntlet of validate() against ground-truth telemetry before it is trusted, so a
# rule that keys on a field the range never emits is caught as a MISS rather than shipped dead.
#
# uuid5 (a stable hash, no randomness) gives each rule a deterministic id: the same objective in
# the same range always compiles to the same rule id, so redeploys don't churn SIEM content.
_RULE_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "rangefinder.detections")


def _condition_selection(cond) -> tuple[str, object]:
    """Compile one Objective Condition into a Sigma ``field[|modifier]`` key and its value.

    The modifier is chosen so the Sigma rule matches *exactly* the events the objective scores as
    MET (scoring._condition_matches): ``equals`` is case-sensitive there, so it compiles to the
    Sigma ``|cased`` modifier — a plain (case-insensitive) selection would over-fire on case
    variants the objective never marks met.
    """
    if cond.equals is not None:
        return f"{cond.field}|cased", cond.equals
    if cond.contains is not None:
        return f"{cond.field}|contains", cond.contains
    if cond.regex is not None:
        return f"{cond.field}|re", cond.regex
    # The config model guarantees exactly one matcher is set; fail loud rather than emit a
    # selection that silently matches nothing.
    raise ValueError(f"condition on {cond.field!r} has no matcher")


def compile_objective(obj, range_name: str) -> dict | None:
    """Compile one Objective's single-event ``detect`` signals into a Sigma rule dict.

    Signals are OR-ed (any signal met satisfies the objective); the conditions within a signal are
    AND-ed. Each condition becomes its own selection so two conditions on the *same* field stay an
    AND (a single selection map would collapse them into an OR value list — the wrong semantics).

    Returns None when there is nothing single-event to compile: a descriptive-only objective, or a
    sequence-only one. Ordered kill chains (``sequence``) map to Sigma *correlation* rules, which
    the single-event validator here cannot yet grade — so rather than emit an unvalidated rule that
    merely looks deployable, the caller surfaces them as not-yet-compiled.
    """
    if not obj.detect:
        return None
    detection: dict = {}
    signal_groups: list[str] = []
    for si, signal in enumerate(obj.detect):
        names = []
        for ci, cond in enumerate(signal.all):
            name = f"sig{si}cond{ci}"
            field_key, value = _condition_selection(cond)
            detection[name] = {field_key: value}
            names.append(name)
        signal_groups.append("(" + " and ".join(names) + ")")
    detection["condition"] = " or ".join(signal_groups)
    return {
        "title": obj.title,
        "id": str(uuid.uuid5(_RULE_NS, f"{range_name}:{obj.id}")),
        "status": "experimental",
        "description": obj.description,
        "logsource": {"product": "rangefinder"},
        "detection": detection,
        "level": "medium",
        # Provenance: trace a deployed rule back to the objective it came from. Sigma tolerates
        # custom top-level fields; this one lets `score` and a reviewer tie rule <-> objective.
        "rangefinder_objective": obj.id,
    }


def from_objectives(config) -> list[dict]:
    """Compile every objective with single-event ``detect`` signals into a Sigma rule."""
    rules = []
    for obj in config.objectives:
        rule = compile_objective(obj, config.name)
        if rule is not None:
            rules.append(rule)
    return rules


def uncompiled_objectives(config) -> list[str]:
    """Ids of objectives whose ``sequence`` (kill-chain) detection intent this compiler cannot yet
    emit as a validated rule — Sigma correlation support is a follow-on. This includes an objective
    that *also* has single-event ``detect`` signals (its detect half compiles; the sequence half
    does not), so the ordered-chain intent is surfaced rather than silently dropped. Descriptive-
    only objectives (no detect, no sequence) are omitted: nothing to detect, nothing missing."""
    return [obj.id for obj in config.objectives if obj.sequence is not None]


__all__ = [
    "EPHEMERAL_FIELDS", "Validation", "compile_objective", "from_objectives", "generate",
    "matched_indices", "parse_events", "rule_fields", "rule_matches", "uncompiled_objectives",
    "validate",
]
