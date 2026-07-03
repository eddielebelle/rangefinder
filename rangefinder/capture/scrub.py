"""Best-effort secret/PII redaction for captured content (``--scrub``).

A ``Scrubber`` instance is created once per capture and applied to every captured value, so
pseudonymized entities stay consistent across the whole capture (the same email maps to the
same synthetic address, keeping references intact). Detectors run specific-first so a
key/value secret is redacted as a unit before the generic high-entropy pass sees it.

This is a heuristic, not a guarantee: it substantially reduces the chance of leaking
secrets/PII when a captured config leaves the owning org, but review before sharing.
"""

from __future__ import annotations

import re

_REDACTED = "REDACTED"

# --- specific, low-false-positive detectors (run first) --------------------------------
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", re.DOTALL)
_URL_CRED = re.compile(r"\b([a-z][a-z0-9+.\-]*://)([^\s:@/]+):([^\s@/]+)@")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")
_PROVIDER = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{35}|"
    r"sk_live_[0-9a-zA-Z]{16,}|glpat-[0-9A-Za-z_\-]{20,})\b"
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-=/+]{8,}")

# key = value / "key": "value" where the key names a secret
_KV = re.compile(
    r"(?i)(password|passwd|pwd|pass|secret|api[_-]?key|apikey|token|auth(?:orization)?|"
    r"access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|credential|"
    r"connection[_-]?string|session[_-]?id|cookie)"
    r"(\s*[:=]\s*|\s*[\"']\s*:\s*[\"']?)"
    r"([^\s\"'<>&,;]+)"
)

# --- PII -------------------------------------------------------------------------------
_EMAIL = re.compile(r"\b[\w.+\-]+@[\w\-]+\.[\w.\-]+\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# --- generic high-entropy tokens (last; may catch non-secret hashes) -------------------
_HEXTOKEN = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_B64TOKEN = re.compile(
    r"\b(?=[A-Za-z0-9+/]*[0-9])(?=[A-Za-z0-9+/]*[A-Za-z])[A-Za-z0-9+/]{40,}={0,2}\b"
)


def _luhn(number: str) -> bool:
    if not (13 <= len(number) <= 19) or not number.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class Scrubber:
    """Redacts secrets/PII from text with consistent entity pseudonymization."""

    def __init__(self) -> None:
        self._emails: dict[str, str] = {}

    def text(self, value: str) -> str:
        if not value:
            return value
        value = _PEM.sub("-----BEGIN PRIVATE KEY-----\nREDACTED\n-----END PRIVATE KEY-----", value)
        value = _URL_CRED.sub(rf"\1{_REDACTED}:{_REDACTED}@", value)
        value = _JWT.sub(_REDACTED, value)
        value = _PROVIDER.sub(_REDACTED, value)
        value = _BEARER.sub(lambda m: f"{m.group(1)} {_REDACTED}", value)
        value = _KV.sub(lambda m: m.group(1) + m.group(2) + _REDACTED, value)
        value = _EMAIL.sub(self._email, value)
        value = _SSN.sub(_REDACTED, value)
        value = _CC.sub(self._cc, value)
        value = _HEXTOKEN.sub(_REDACTED, value)
        value = _B64TOKEN.sub(_REDACTED, value)
        return value

    def _email(self, m: re.Match) -> str:
        original = m.group(0)
        if original.startswith(_REDACTED):
            return original  # already-redacted "REDACTED@host" — leave the host intact
        if original not in self._emails:
            self._emails[original] = f"user{len(self._emails) + 1}@example.invalid"
        return self._emails[original]

    def _cc(self, m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        return _REDACTED if _luhn(digits) else m.group(0)


def apply(scrubber: Scrubber | None, value: str) -> str:
    """Scrub *value* if a scrubber is active, else return it unchanged."""
    return scrubber.text(value) if scrubber is not None else value
