"""Cross-service coherence checking for a range twin.

Per-service posture is measured and locked by ``verify``; this module is the estate-level
counterpart — it surfaces the *relationships* between services, because a real misconfiguration is
usually a chain across services (a credential reused across accounts; a secret leaked in an SMB
file or LDAP description that is actually a live login).

Two design rules, both learned the hard way:

1. **Observe-and-report, never wire.** It never mutates the config or invents a linkage. Wiring an
   edge into the twin only ever comes from measurement (credentialed capture); this pass just
   surfaces what is already there.
2. **Advisory, never fail-closed on inference.** A *username* is not a *principal*: a local ``root``
   on two hosts, or a local vs. a domain ``administrator``, legitimately hold different passwords.
   Static analysis cannot certify two logins are the same principal, so it must not turn that guess
   into a hard error that blocks a valid merge — that would fabricate a contradiction. Every output
   here is an advisory edge or warning; the only fail-closed in the pipeline is the structural
   ``RangeConfig`` validation (duplicate id/ip/hostname) and the per-field posture contract.

Honest limits it must not overstep: it reports **reuse** (a secret shared by ≥2 distinct owners) and
a **possible exploitable leak** (a credential value appearing in leaked text). Both are surfaced for
a human/agent to judge, never asserted as certain. The leak heuristic is deliberately conservative
(whole-token match, minimum secret length) so a short/common password can't fabricate a critical
finding — the fail-open failure mode the posture contract forbids.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache

from rangefinder.config.model import RangeConfig
from rangefinder.config.services import KerberosConfig

# LDAP/directory attributes that conventionally carry free text where a secret gets leaked.
_LEAKY_ATTRS = frozenset({"description", "comment", "info"})
# Below this length a coincidental substring match (a common word used as a password) is too likely
# to be a false leak, so we don't assert one — conservative by design (never fabricate).
_MIN_LEAK_SECRET_LEN = 8
# The schema's placeholder krbtgt key is not a captured credential, so it must not seed a reuse edge.
_KRBTGT_DEFAULT = KerberosConfig.model_fields["krbtgt_password"].default


@dataclass
class Linkage:
    """A discovered cross-service relationship, surfaced for review (never a certainty)."""

    kind: str          # credential-reuse | exploitable-leak
    label: str         # human anchor (masked secret id) — never the raw secret
    locations: list[str]
    tier: str          # reuse | possible-leak
    note: str


@dataclass
class CoherenceReport:
    edges: list[Linkage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return bool(self.edges or self.warnings)


def _secret_id(secret: str) -> str:
    """A stable, non-revealing token so identical secrets group in a report without exposing them."""
    return "secret#" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]


@lru_cache(maxsize=4096)
def _leak_pattern(secret: str):
    return re.compile(r"(?<!\w)" + re.escape(secret) + r"(?!\w)")


def leak_contains(secret: str, text: str) -> bool:
    """Whether *secret* appears as a whole token in *text* — the conservative match coherence and
    verify both use so a short/common password can't produce a spurious leak hit. The compiled
    pattern is cached per secret (called once per secret×leak pair on large estates)."""
    if not secret or len(secret) < _MIN_LEAK_SECRET_LEN:
        return False
    return _leak_pattern(secret).search(text) is not None


def iter_leaks(cfg: RangeConfig):
    """Yield ``(text, location)`` for every free-text field a credential can leak into: SMB share
    comments + files, LDAP entry description/comment/info, HTTP bodies, identity/group descriptions.
    Shared by check_coherence and verify_estate so both scan exactly the same surfaces."""
    for host in cfg.hosts:
        for svc in host.services:
            where = f"{svc.type}@{host.id}:{svc.port}"
            if svc.type == "http":
                if svc.default_body:
                    yield str(svc.default_body), f"{where} default_body"
                for path, hp in svc.paths.items():
                    if hp.body:
                        yield str(hp.body), f"{where}{path} body"
            elif svc.type == "smb":
                for share in svc.shares:
                    if share.comment:
                        yield str(share.comment), f"{where}/{share.name} (comment)"
                    for fname, content in share.files.items():
                        if content:
                            yield str(content), f"{where}/{share.name}/{fname}"
            elif svc.type == "ldap":
                for entry in svc.entries:
                    for attr, values in entry.attributes.items():
                        if attr.lower() in _LEAKY_ATTRS:
                            for v in values:
                                if v:
                                    yield str(v), f"{where} {entry.dn or 'RootDSE'}/{attr}"
    if cfg.identities:
        for u in cfg.identities.users:
            if u.description:
                yield str(u.description), f"identities:{u.sam}.description"
        for g in cfg.identities.groups:
            if g.description:
                yield str(g.description), f"identities:group:{g.name}.description"


def iter_credentials(cfg: RangeConfig):
    """Yield the concrete login credentials embedded in the config as dicts
    ``{kind, host_id, port, username, secret, domain, origin, path?}`` — the claims `verify estate`
    tries against the live estate. A directory account's password is tested against every ldap
    (bind) and smb (logon) facade in the range; a planted ssh/http login against its own service."""
    ldap_hosts = [(h, s) for h in cfg.hosts for s in h.services if s.type == "ldap"]
    smb_hosts = [(h, s) for h in cfg.hosts for s in h.services if s.type == "smb"]
    for host in cfg.hosts:
        for svc in host.services:
            if svc.type == "ssh":
                for user, pw in svc.accept_creds.items():
                    if pw:
                        yield {"kind": "ssh", "host_id": host.id, "port": svc.port,
                               "username": user, "secret": pw, "domain": "",
                               "origin": f"ssh accept_creds[{user}]"}
            elif svc.type == "http":
                for path, hp in svc.paths.items():
                    for user, pw in hp.auth_users.items():
                        if pw:
                            yield {"kind": "http", "host_id": host.id, "port": svc.port,
                                   "username": user, "secret": pw, "domain": "", "path": path,
                                   "origin": f"http {path} auth_users[{user}]"}
    if cfg.identities:
        domain = cfg.identities.domain
        netbios = cfg.identities.netbios or domain
        for u in cfg.identities.users:
            if not (u.password and u.enabled):
                continue
            dn = u.upn or f"{u.sam}@{domain}"
            for host, svc in ldap_hosts:
                yield {"kind": "ldap", "host_id": host.id, "port": svc.port,
                       "username": dn, "secret": u.password, "domain": "", "tls": svc.tls,
                       "origin": f"identities:{u.sam}.password"}
            for host, svc in smb_hosts:
                yield {"kind": "smb", "host_id": host.id, "port": svc.port,
                       "username": u.sam, "secret": u.password, "domain": netbios,
                       "origin": f"identities:{u.sam}.password"}


def check_coherence(cfg: RangeConfig) -> CoherenceReport:
    report = CoherenceReport()

    # secret value -> list of (owner, location); owner distinguishes real reuse (≥2 owners) from an
    # account backed by its own directory entry (1 owner, not reuse).
    secrets: dict[str, list[tuple[str, str]]] = {}
    logins: list[tuple[str, str, str]] = []   # (username, password, location) for backing checks
    leaks = list(iter_leaks(cfg))             # (leaked_text, location); shared with verify estate

    def add_secret(value: str, owner: str, location: str) -> None:
        if value:  # an empty password is "reject all" / capture-only, not a credential
            secrets.setdefault(value, []).append((owner, location))

    for host in cfg.hosts:
        for svc in host.services:
            where = f"{svc.type}@{host.id}:{svc.port}"
            if svc.type == "ssh":
                for user, pw in svc.accept_creds.items():
                    logins.append((user, pw, where))
                    add_secret(pw, user, f"{where} accept_creds[{user}]")
            elif svc.type == "http":
                for path, hp in svc.paths.items():
                    for user, pw in hp.auth_users.items():
                        logins.append((user, pw, f"{where}{path}"))
                        add_secret(pw, user, f"{where}{path} auth_users[{user}]")
            elif svc.type == "kerberos":
                if svc.krbtgt_password != _KRBTGT_DEFAULT:
                    add_secret(svc.krbtgt_password, f"krbtgt@{host.id}", f"{where} krbtgt")

    known: set[str] = set()
    if cfg.identities:
        for u in cfg.identities.users:
            for handle in (u.sam, u.upn):
                if handle:
                    known.add(handle.lower())
            add_secret(u.password, u.sam, f"identities:{u.sam}.password")

    _check_login_backing(cfg, logins, known, report)
    _check_reuse(secrets, report)
    _check_exploitable_leaks(secrets, leaks, report)
    _check_role_completeness(cfg, report)
    return report


def _check_login_backing(cfg, logins, known, report) -> None:
    """A login user with no directory identity is likely a local account — surfaced, never fatal
    (local accounts are legitimate, and a same-named local/domain pair is a real configuration)."""
    if not cfg.identities:
        return  # nothing to reconcile against
    flagged: set[str] = set()
    for user, _pw, loc in logins:
        if user.lower() not in known and user.lower() not in flagged:
            flagged.add(user.lower())
            report.warnings.append(
                f"login {user!r} (first seen at {loc}) has no backing directory identity "
                f"— likely a local account; confirm it isn't a missing directory entry")


def _check_reuse(secrets, report) -> None:
    """A secret shared by ≥2 *distinct owners* is genuine cross-account reuse. One owner whose
    password also appears in its own directory entry is correct backing, not reuse."""
    for value, entries in secrets.items():
        owners = {owner for owner, _loc in entries}
        if len(owners) >= 2:
            report.edges.append(Linkage(
                kind="credential-reuse", label=_secret_id(value),
                locations=sorted(loc for _owner, loc in entries), tier="reuse",
                note=f"the same secret backs {len(owners)} distinct accounts — a reuse path an "
                     f"attacker can pivot along"))


def _check_exploitable_leaks(secrets, leaks, report) -> None:
    """A leaked blob (SMB file/comment, LDAP/identity/group description, HTTP body) that *contains*
    a live credential is the classic transferable finding. Conservative match (whole token, min
    length) so a short/common password can't fabricate one."""
    for value, entries in secrets.items():
        cred_locs = {loc for _owner, loc in entries}
        for blob, leak_loc in leaks:
            if leak_loc not in cred_locs and leak_contains(value, blob):
                report.edges.append(Linkage(
                    kind="exploitable-leak", label=_secret_id(value),
                    locations=sorted([leak_loc, *cred_locs]), tier="possible-leak",
                    note=f"a live credential value appears in leaked text at {leak_loc} — if this "
                         f"is the real credential, reading the leak yields a working login (verify)"))


def _check_role_completeness(cfg, report) -> None:
    """Identities imply facades that expose them; a missing one silently under-reports surface."""
    if not cfg.identities or not cfg.identities.users:
        return
    types = {svc.type for host in cfg.hosts for svc in host.services}
    if "ldap" not in types:
        report.warnings.append(
            "identities are defined but no ldap facade exposes them (enumeration surface under-reported)")
    roastable = any(u.no_preauth or u.spn for u in cfg.identities.users)
    if roastable and "kerberos" not in types:
        report.warnings.append(
            "identities include AS-REP/Kerberoastable accounts but no kerberos facade exposes them "
            "(credential-access surface under-reported)")


def format_report(report: CoherenceReport) -> str:
    """A compact multi-line summary for the terminal / capture-report sidecar."""
    lines: list[str] = []
    for e in report.edges:
        mark = "‼ possible-leak" if e.kind == "exploitable-leak" else "↔ credential-reuse"
        lines.append(f"{mark} [{e.label}]: {e.note}")
        for loc in e.locations:
            lines.append(f"    - {loc}")
    for w in report.warnings:
        lines.append(f"⚠ {w}")
    if not lines:
        return "no cross-service issues found"
    return "\n".join(lines)


__all__ = ["CoherenceReport", "Linkage", "check_coherence", "format_report",
           "iter_credentials", "iter_leaks", "leak_contains"]
