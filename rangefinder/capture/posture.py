"""Capture provenance — shared across every protocol captor.

A faithful twin is only as trustworthy as the twin is faithful, so every capture must be honest
about *which* facts it actually measured. This module carries that provenance. Each captor builds
a :class:`CaptureReport` classifying every security-relevant fact about the real host into one of
three confidence tiers, and the CLI writes it beside the config as a ``*.capture-report.md``
sidecar so a reviewer sees exactly what the twin reproduces from measurement vs. assumption.

The fidelity contract this supports, for *any* facade in the network twin (not just SMB):

    measure the posture -> reproduce it -> fail closed on the unmeasured -> surface the provenance.

Tiers:
  measured      — actively probed against the real host; captured truth that transfers.
  assumed       — could not measure; the facade uses a FAIL-CLOSED default and says so here. A
                  fail-open default would fabricate findings, so the unmeasured must never make
                  the twin *more* exposed than the real host.
  unmeasurable  — the answer only exists from an access level the capture did not have (e.g. an
                  authenticated read when captured anonymously); no default is right — a human
                  decides, or re-captures with the access level named.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MEASURED = "measured"
ASSUMED = "assumed"
UNMEASURABLE = "unmeasurable"


def _fmt(value: object) -> str:
    # Booleans render as true/false (matches the JSON config), everything else as its str().
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@dataclass
class PostureItem:
    """One security-relevant fact about the captured host, with its provenance tier."""

    field: str
    status: str
    value: str
    note: str = ""


@dataclass
class CaptureReport:
    """Provenance for one capture: measured vs assumed vs unmeasurable facts about the host."""

    target: str
    perspective: str
    protocol: str = ""
    items: list[PostureItem] = field(default_factory=list)

    # Fluent adders keep captor code terse: report.measured("signing_required", True, "negotiate").
    def measured(self, field: str, value: object, note: str = "") -> "CaptureReport":
        self.items.append(PostureItem(field, MEASURED, _fmt(value), note))
        return self

    def assumed(self, field: str, value: object, note: str = "") -> "CaptureReport":
        self.items.append(PostureItem(field, ASSUMED, _fmt(value), note))
        return self

    def unmeasurable(self, field: str, value: object, note: str = "") -> "CaptureReport":
        self.items.append(PostureItem(field, UNMEASURABLE, _fmt(value), note))
        return self

    def tier(self, status: str) -> list[PostureItem]:
        return [i for i in self.items if i.status == status]

    def to_markdown(self) -> str:
        head = f"# Capture report — {self.target}"
        if self.protocol:
            head += f" ({self.protocol})"
        lines = [head, f"_Perspective: {self.perspective}_", ""]
        tiers = [
            ("✓ MEASURED", MEASURED,
             "captured truth — transfers to the real host"),
            ("⚠ ASSUMED", ASSUMED,
             "could not measure — fail-closed default in use; CONFIRM against the real host"),
            ("✗ UNMEASURABLE at this access level", UNMEASURABLE,
             "no default can be right — decide, or re-capture with the access level named"),
        ]
        for title, status, blurb in tiers:
            items = self.tier(status)
            lines.append(f"## {title}")
            lines.append(f"_{blurb}_")
            if not items:
                lines.append("\n- (none)\n")
                continue
            lines.append("")
            width = max(len(i.field) for i in items)
            for i in items:
                row = f"- `{i.field.ljust(width)}`  {i.value}"
                if i.note:
                    row += f"  — {i.note}"
                lines.append(row)
            lines.append("")
        return "\n".join(lines)
