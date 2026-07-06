"""Estate attack-path composition — walk the credential graph without executing anything.

`coherence` surfaces individual cross-service edges (a reused secret, a leaked credential);
`verify estate` measures whether each edge is live. This module composes those edges into
multi-hop *reachability paths*: starting from what an unauthenticated attacker can read, it loots
the credentials leaked there, uses them to reach further hosts, loots the credentials gated behind
*those*, and repeats to a fixpoint — the holistic "read here → recover this login → it opens that
host → recover the next" picture a lateral-movement test wants, produced entirely from the twin's
captured/declared data with no code execution.

Two edge kinds, both already primitives elsewhere:

- **LOOT** (location → credential): a credential value appears as a whole token in a readable blob
  (SMB file/comment, LDAP/identity description, HTTP body). Uses ``coherence.leak_contains`` — the
  same conservative match (whole token, min length) so a short/common password can't fabricate a
  path.
- **ACCESS** (credential → locations): holding a credential unlocks the locations a matching service
  on its host gates behind auth (a ``restrict_anonymous`` SMB share, a non-anonymous LDAP bind, an
  auth-gated HTTP route).

The discipline is inherited wholesale from ``coherence`` — **never fabricate an edge**:

- Reachability *roots* come from measured gating: a location is anon-readable only when the captured
  posture says so (SMB ``restrict_anonymous`` false, LDAP ``allow_anonymous_bind`` true, an HTTP
  route with no Basic/NTLM auth gate).
  Fail-closed defaults mean an *unmeasured* gate reads as closed, so an unmeasured location needs a
  foothold rather than being handed to anon — the graph under-reports rather than inventing reach.
- Every path is **advisory**: a leaked string matching a credential is not certified to *be* that
  principal (a username is not a principal), exactly as coherence warns. The graph shows the paths
  that exist *if the leaks are the real credentials*; ``verify estate`` is what promotes an edge from
  possible to measured-live. Raw secrets never appear in the output — only masked ids and usernames.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rangefinder.coherence import _secret_id, iter_credentials, iter_leaks, leak_contains
from rangefinder.config.model import RangeConfig


@dataclass(frozen=True)
class _Location:
    """A readable blob and the access it takes to reach it."""

    host_id: str
    kind: str          # smb | ldap | http — the service type that gates this blob
    qualifier: str     # http path (auth is per-route); "" for smb/ldap
    anon: bool         # readable by an unauthenticated attacker (measured gating)
    label: str         # human anchor for the blob's location
    text: str          # the blob itself, matched against credential values (never printed)


@dataclass
class _Principal:
    """A distinct secret and everything it grants — credentials are grouped by value so one password
    reused across accounts/hosts is a single principal with several access targets."""

    secret_id: str
    secret: str                                   # internal, for leak matching; never printed
    usernames: set = field(default_factory=set)
    grants: set = field(default_factory=set)      # (host_id, kind, qualifier) this secret unlocks
    origins: set = field(default_factory=set)     # where the credential is declared (not a loot site)


@dataclass
class ReachableCredential:
    """A credential an attacker can recover, and the multi-hop path that gets there."""

    secret_id: str
    usernames: list[str]
    grants: list[str]          # "kind@host" targets this credential unlocks
    steps: list[str]           # ordered human-readable path from anonymous to the loot
    hops: int                  # number of authentication pivots (0 = recovered from anonymous text)
    # Structured views used by live verification (annotate_live); empty until then.
    pivots: list = field(default_factory=list)         # {host_id,kind,username} — each auth step on the path
    grant_targets: list = field(default_factory=list)  # {host_id,kind,qualifier,username} this cred unlocks
    grant_verdicts: dict = field(default_factory=dict) # "kind@host" -> measured-live | refuted | untested
    path_verdict: str | None = None                    # confirmed-live | refuted | untested | anonymous


@dataclass
class UnreachableCredential:
    secret_id: str
    usernames: list[str]
    grants: list[str]
    reason: str


@dataclass
class AclEscalation:
    """A privilege-escalation reachable by combining a credential path with captured ACL control."""

    target: str            # object an attacker can take control of
    right: str             # the ACL right that grants the final step (or "DCSync")
    steps: list[str]       # full chain from a reachable credential to the target
    domain_compromise: bool = False


@dataclass
class AttackGraph:
    reachable: list[ReachableCredential] = field(default_factory=list)
    unreachable: list[UnreachableCredential] = field(default_factory=list)
    hosts_reached: list[str] = field(default_factory=list)   # hosts an anon-rooted path can access
    escalations: list[AclEscalation] = field(default_factory=list)  # filled by escalate_via_acls
    notes: list[str] = field(default_factory=list)

    @property
    def has_paths(self) -> bool:
        return bool(self.reachable)


# --------------------------------------------------------------------- graph inputs


def _principals(cfg: RangeConfig) -> dict[str, _Principal]:
    """Group the estate's declared credentials by secret value into principals with access targets."""
    principals: dict[str, _Principal] = {}
    for c in iter_credentials(cfg):
        secret = c["secret"]
        if not secret:
            continue
        sid = _secret_id(secret)
        p = principals.get(sid)
        if p is None:
            p = principals[sid] = _Principal(secret_id=sid, secret=secret)
        p.usernames.add(c["username"])
        # Carry the username on the grant: a secret reused across accounts groups into one principal,
        # but each grant must remember which account authenticates it, so an auth step names the right
        # login rather than an arbitrary one of the shared-password accounts.
        p.grants.add((c["host_id"], c["kind"], c.get("path", ""), c["username"]))
        p.origins.add(c["origin"])
    return principals


def _locations(cfg: RangeConfig) -> list[_Location]:
    """Every readable blob in the estate, tagged with the access (anon vs. auth) it takes to reach.

    Parallels ``iter_leaks`` but carries the gating each blob sits behind, which the flat leak scan
    does not need. Anonymity is read from the *measured* posture fields, so an unmeasured gate (which
    fails closed) yields a non-anon location — a foothold is required rather than handed to anon."""
    locs: list[_Location] = []
    ldap_hosts: list[tuple[str, bool]] = []  # (host_id, allow_anonymous_bind) for identity exposure
    for host in cfg.hosts:
        for svc in host.services:
            where = f"{svc.type}@{host.id}:{svc.port}"
            if svc.type == "smb":
                for share in svc.shares:
                    anon = not share.restrict_anonymous
                    if share.comment:
                        locs.append(_Location(host.id, "smb", "", anon,
                                              f"{where}/{share.name} (comment)", str(share.comment)))
                    for fname, content in share.files.items():
                        if content:
                            locs.append(_Location(host.id, "smb", "", anon,
                                                  f"{where}/{share.name}/{fname}", str(content)))
            elif svc.type == "ldap":
                ldap_hosts.append((host.id, svc.allow_anonymous_bind))
                for entry in svc.entries:
                    for attr, values in entry.attributes.items():
                        if attr.lower() in {"description", "comment", "info"}:
                            for v in values:
                                if v:
                                    locs.append(_Location(
                                        host.id, "ldap", "", svc.allow_anonymous_bind,
                                        f"{where} {entry.dn or 'RootDSE'}/{attr}", str(v)))
            elif svc.type == "http":
                if svc.default_body:
                    locs.append(_Location(host.id, "http", "", True,
                                          f"{where} default_body", str(svc.default_body)))
                for path, hp in svc.paths.items():
                    if hp.body:
                        # A route is anonymously readable only when NONE of HTTP's three auth gates
                        # apply. auth_users can be empty while the route is still gated by an NTLM
                        # challenge or a reject-all Basic realm — treating those as anon would
                        # fabricate an anonymous path into a body the real server refuses.
                        anon = not hp.auth_users and not hp.auth_ntlm and hp.auth_realm is None
                        locs.append(_Location(host.id, "http", path, anon,
                                              f"{where}{path} body", str(hp.body)))
    # Identity/group descriptions are directory data — reachable only where an LDAP facade exposes
    # them, anon iff that facade allows an anonymous bind.
    if cfg.identities and ldap_hosts:
        for hid, anon in ldap_hosts:
            for u in cfg.identities.users:
                if u.description:
                    locs.append(_Location(hid, "ldap", "", anon,
                                          f"ldap@{hid} identities:{u.sam}.description", str(u.description)))
            for g in cfg.identities.groups:
                if g.description:
                    locs.append(_Location(hid, "ldap", "", anon,
                                          f"ldap@{hid} identities:group:{g.name}.description",
                                          str(g.description)))
    return locs


def _unlocks(grant: tuple, loc: _Location) -> bool:
    host_id, kind, qualifier, _username = grant
    if host_id != loc.host_id or kind != loc.kind:
        return False
    # HTTP auth is per-route: a credential for one path does not unlock another route's body.
    return kind != "http" or qualifier == loc.qualifier


# --------------------------------------------------------------------- traversal


def compose_paths(cfg: RangeConfig) -> AttackGraph:
    """Compose the estate's LOOT and ACCESS edges into anon-rooted multi-hop reachability paths."""
    principals = _principals(cfg)
    locations = _locations(cfg)

    readable: set[_Location] = {loc for loc in locations if loc.anon}
    # loc -> None (anon-readable) or (principal sid, the username whose grant unlocked it)
    unlocked_by: dict[_Location, tuple[str, str] | None] = {loc: None for loc in readable}
    looted_at: dict[str, _Location] = {}                                        # sid -> loot location
    ordered_sids = sorted(principals)  # stable principal + location iteration -> reproducible paths

    changed = True
    while changed:
        changed = False
        # LOOT: any not-yet-held principal whose secret sits in a readable blob (not its own site).
        for sid in ordered_sids:
            if sid in looted_at:
                continue
            p = principals[sid]
            for loc in locations:  # stable order so the recorded loot site is deterministic
                if loc not in readable or loc.label in p.origins:
                    continue
                if leak_contains(p.secret, loc.text):
                    looted_at[sid] = loc
                    changed = True
                    break
        # ACCESS: held principals unlock the gated locations their grants reach.
        for sid in ordered_sids:
            if sid not in looted_at:
                continue
            for grant in principals[sid].grants:
                for loc in locations:
                    if loc not in readable and _unlocks(grant, loc):
                        readable.add(loc)
                        unlocked_by[loc] = (sid, grant[3])  # sid + the username that authenticated
                        changed = True

    graph = AttackGraph()
    for sid, p in sorted(principals.items(), key=lambda kv: kv[0]):
        grants = sorted(f"{kind}@{host}" + (qual or "") for host, kind, qual, _u in p.grants)
        usernames = sorted(p.usernames)
        if sid in looted_at:
            steps = _steps_to_principal(sid, looted_at, unlocked_by, principals)
            pivots = _pivots_to_principal(sid, looted_at, unlocked_by)
            grant_targets = [{"host_id": h, "kind": k, "qualifier": q, "username": u}
                             for h, k, q, u in sorted(p.grants)]
            # hops = number of authentication pivots (0 = recovered from anonymously-readable text).
            graph.reachable.append(ReachableCredential(
                secret_id=sid, usernames=usernames, grants=grants,
                steps=steps, hops=len(pivots), pivots=pivots, grant_targets=grant_targets))
        else:
            graph.unreachable.append(UnreachableCredential(
                secret_id=sid, usernames=usernames, grants=grants,
                reason="no anonymous-rooted path leaks this credential; needs an initial foothold"))

    graph.reachable.sort(key=lambda r: (r.hops, r.secret_id))
    graph.hosts_reached = sorted({loc.host_id for loc, by in unlocked_by.items() if by is not None})
    if not locations:
        graph.notes.append("estate exposes no readable text — no leak/loot surface to compose")
    return graph


def _steps_to_location(loc: _Location, looted_at, unlocked_by, principals, seen: set) -> list[str]:
    by = unlocked_by.get(loc)
    if by is None:
        return ["(anonymous access)"]
    if loc in seen:  # cycle guard — BFS order makes this unreachable, but never loop
        return ["(anonymous access)"]
    seen = seen | {loc}
    sid, who = by  # the principal that unlocked this location, and the account that authenticated
    prefix = _steps_to_principal(sid, looted_at, unlocked_by, principals, seen)
    return prefix + [f"authenticate to {loc.host_id} ({loc.kind}) as {who}"]


def _steps_to_principal(sid, looted_at, unlocked_by, principals, seen: set | None = None) -> list[str]:
    seen = seen if seen is not None else set()
    loc = looted_at[sid]
    usernames = sorted(principals[sid].usernames)
    # A secret backing several accounts recovers the credential, not a single presumed principal.
    if len(usernames) == 1:
        recover = f"recover {usernames[0]} [{sid}]"
    else:
        recover = f"recover credential [{sid}] (backs {', '.join(usernames)})"
    return _steps_to_location(loc, looted_at, unlocked_by, principals, seen) + [
        f"read {loc.label}", recover]


def _pivots_to_principal(sid, looted_at, unlocked_by, seen=None) -> list[dict]:
    """The ordered authentication pivots on the path to *sid* — each an iter_credentials claim
    ``(host_id, kind, username)`` that live verification can probe with validate_credential."""
    seen = seen if seen is not None else set()
    return _pivots_to_location(looted_at[sid], looted_at, unlocked_by, seen)


def _pivots_to_location(loc: _Location, looted_at, unlocked_by, seen) -> list[dict]:
    by = unlocked_by.get(loc)
    if by is None or loc in seen:
        return []
    seen = seen | {loc}
    sid, who = by  # authenticated to loc.host_id (loc.kind) as `who` to read this location
    return _pivots_to_location(looted_at[sid], looted_at, unlocked_by, seen) + [
        {"host_id": loc.host_id, "kind": loc.kind, "qualifier": loc.qualifier, "username": who}]


_VERDICT_PRECEDENCE = {"measured-live": 3, "refuted": 2, "untested": 1}


def collapse_verdicts(edges) -> dict:
    """Collapse per-service edge verdicts into one per ``(host_id, kind, username, qualifier)``,
    keeping the strongest. A host may expose the same kind on several ports (ldap 389 AND 636), so
    verify_estate yields several results per credential; the grant is measured-live if the credential
    authenticates on ANY matching service, refuted only when nothing was live. The ``qualifier`` (the
    HTTP route) MUST stay in the key: HTTP auth is per-route, so a live cred on one route must not
    mask a refuted cred sharing the username on another. ``edges`` is an iterable of
    ``(host_id, kind, username, qualifier, verdict)``."""
    out: dict = {}
    for host_id, kind, username, qualifier, verdict in edges:
        key = (host_id, kind, username, qualifier)
        if key not in out or _VERDICT_PRECEDENCE[verdict] > _VERDICT_PRECEDENCE[out[key]]:
            out[key] = verdict
    return out


def annotate_live(graph: AttackGraph, verdicts: dict) -> None:
    """Promote the graph from advisory to measured, in place, using live edge verdicts.

    ``verdicts`` maps ``(host_id, kind, username, qualifier)`` -> "measured-live" | "refuted" |
    "untested" (exactly the tiers ``verify_estate`` produces per credential; qualifier is the HTTP
    route, "" otherwise). Each reachable credential's grants and each authentication pivot on its
    path are tagged, and the path gets an overall verdict:

    - **confirmed-live**: every pivot authenticates on the live estate — the chain really works.
    - **refuted**: a pivot was rejected live — the composed path does not exist on the real estate.
    - **untested**: a pivot could not be probed (no target / unreachable) and none was refuted.
    - **anonymous**: no authentication pivot (recovered from anonymously-readable text); the auth
      chain is trivially satisfied, though anonymous *readability* itself is not probed by this pass.
    """
    for r in graph.reachable:
        for g in r.grant_targets:
            key = (g["host_id"], g["kind"], g["username"], g.get("qualifier", ""))
            label = f'{g["kind"]}@{g["host_id"]}' + (g.get("qualifier") or "")
            r.grant_verdicts[label] = verdicts.get(key, "untested")
        pv = [verdicts.get((p["host_id"], p["kind"], p["username"], p.get("qualifier", "")), "untested")
              for p in r.pivots]
        if not pv:
            r.path_verdict = "anonymous"
        elif any(v == "refuted" for v in pv):
            r.path_verdict = "refuted"
        elif all(v == "measured-live" for v in pv):
            r.path_verdict = "confirmed-live"
        else:
            r.path_verdict = "untested"


def _princ_norm(name: str) -> str:
    """Normalise a login/principal handle to a bare account name for matching (UPN/DOMAIN\\ stripped)."""
    n = name.strip().lower()
    if "@" in n:
        n = n.split("@", 1)[0]
    if "\\" in n:
        n = n.split("\\", 1)[1]
    return n


def _group_membership(cfg) -> dict:
    """principal (lowercased label) -> set of group labels it is (directly) a member of.

    A member acts with the rights of the groups it belongs to, so controlling a principal extends
    control through its group memberships. Built from captured ``memberOf`` (resolved group DN ->
    the group entry's label) and from authored ``identities`` membership."""
    from rangefinder.acl import entry_label, norm_dn

    dn_label: dict = {}
    entries: list = []
    for host in cfg.hosts:
        for svc in host.services:
            if svc.type == "ldap":
                for e in svc.entries:
                    entries.append(e)
                    dn_label[norm_dn(e.dn)] = entry_label(e).lower()

    membership: dict = {}
    for e in entries:
        label = entry_label(e).lower()
        if not label:
            continue
        for attr, vals in e.attributes.items():
            if attr.lower() == "memberof":
                for gdn in vals:
                    g = dn_label.get(norm_dn(str(gdn)))
                    if g:
                        membership.setdefault(label, set()).add(g)
    if cfg.identities:
        for u in cfg.identities.users:
            for g in u.groups:
                if u.sam and g:
                    membership.setdefault(u.sam.lower(), set()).add(g.lower())
        for g in cfg.identities.groups:
            for m in g.members:
                if m and g.name:
                    membership.setdefault(m.lower(), set()).add(g.name.lower())
    return membership


def escalate_via_acls(graph: AttackGraph, cfg) -> list[AclEscalation]:
    """Extend the reachable credentials through captured ACL control edges.

    Controlling a principal (a reachable credential) lets an attacker act with the rights of every
    group it is transitively a member of, and any ``GenericAll`` / ``WriteDacl`` / ``WriteOwner`` /
    ``Owns`` / ``ForceChangePassword`` / ``AddMember`` / ``GenericWrite`` / ``AllExtendedRights`` edge
    from a controlled principal takes control of its target — which expands again to a fixpoint.
    ``DCSync`` on the domain is full compromise.

    Advisory, same discipline as the credential graph: only *reachable-credential* seeds and *measured*
    ACL edges feed it, and the principal match (login handle -> captured object label) is inferred, not
    certified. Populates and returns ``graph.escalations``."""
    from rangefinder.acl import analyze_acls

    edges = analyze_acls(cfg).edges
    if not edges or not graph.reachable:
        return []
    membership = _group_membership(cfg)

    def with_groups(label: str, into: set) -> None:
        stack = [label]
        while stack:
            p = stack.pop()
            for g in membership.get(p, ()):
                if g not in into:
                    into.add(g)
                    stack.append(g)

    # Seed: every reachable credential's account names, plus the groups they belong to.
    controlled: set = set()
    origin: dict = {}  # label -> (kind, ...) for chain reconstruction; seed principals map to a cred
    for r in graph.reachable:
        for u in r.usernames:
            p = _princ_norm(u)
            if not p:
                continue  # a degenerate handle ("@dom", "DOM\\", "") must never seed control
            if p not in origin:
                origin[p] = ("seed", u)
            controlled.add(p)
    seeds = set(controlled)
    for s in seeds:
        before = set(controlled)
        with_groups(s, controlled)
        for g in controlled - before:
            origin.setdefault(g, ("member", s))  # controlled by membership of a seed

    escalations: list[AclEscalation] = []
    dcsync_done = False
    changed = True
    while changed:
        changed = False
        for e in edges:
            trustee = e.trustee.lower()
            target = e.object_name.lower()
            if not trustee or not target:
                continue  # an empty-labelled principal (blank sAMAccountName) is not a real match
            if trustee not in controlled:
                continue
            if e.right == "DCSync":
                if not dcsync_done:
                    dcsync_done = True
                    changed = True
                    escalations.append(AclEscalation(
                        target="<domain>", right="DCSync", domain_compromise=True,
                        steps=_esc_chain(trustee, origin) + ["[DCSync] replicate domain secrets — full compromise"]))
                continue
            if target in controlled:
                continue
            controlled.add(target)
            origin[target] = ("acl", trustee, e.right, e.object_name)
            escalations.append(AclEscalation(
                target=e.object_name, right=e.right,
                steps=_esc_chain(target, origin)))
            before = set(controlled)
            with_groups(target, controlled)
            for g in controlled - before:
                origin.setdefault(g, ("member", target))
            changed = True

    graph.escalations = escalations
    return escalations


def _esc_chain(label: str, origin: dict, seen: set | None = None) -> list[str]:
    seen = seen if seen is not None else set()
    entry = origin.get(label)
    if entry is None or label in seen:
        return [f"control {label}"]
    seen = seen | {label}
    if entry[0] == "seed":
        return [f"control {entry[1]} (reachable credential)"]
    if entry[0] == "member":
        return _esc_chain(entry[1], origin, seen) + [f"acts as group {label}"]
    _, via, right, disp = entry
    return _esc_chain(via, origin, seen) + [f"[{right}] control {disp}"]


def format_graph(graph: AttackGraph) -> str:
    lines: list[str] = []
    verified = any(r.path_verdict for r in graph.reachable)
    if graph.reachable:
        header = ("Reachable credentials — live-verified against the estate:" if verified
                  else "Reachable credentials — advisory paths, confirm with `verify estate` or `paths --verify`:")
        lines.append(f"{header}  ({len(graph.reachable)})")
        for r in graph.reachable:
            names = ", ".join(r.usernames)
            verdict = f"  [{r.path_verdict}]" if r.path_verdict else ""
            unlocks = ", ".join(
                g + (f"({r.grant_verdicts[g]})" if g in r.grant_verdicts else "") for g in r.grants)
            lines.append(f"\n  ‣ {names} [{r.secret_id}]  ({r.hops}-hop){verdict}  unlocks: {unlocks}")
            for i, step in enumerate(r.steps):
                lines.append(f"      {'└─' if i == len(r.steps) - 1 else '├─'} {step}")
    else:
        lines.append("No credentials are reachable from an anonymous start.")
    if graph.unreachable:
        lines.append(f"\nDeclared but not anonymously reachable ({len(graph.unreachable)}) — need a foothold:")
        for u in graph.unreachable:
            lines.append(f"  · {', '.join(u.usernames)} [{u.secret_id}]  unlocks: {', '.join(u.grants)}")
    if graph.escalations:
        lines.append(f"\nACL privilege escalations ({len(graph.escalations)}) — control extended via captured ACLs (advisory):")
        for e in graph.escalations:
            head = "‼ DOMAIN COMPROMISE" if e.domain_compromise else f"→ control {e.target}  [{e.right}]"
            lines.append(f"\n  {head}")
            for i, step in enumerate(e.steps):
                lines.append(f"      {'└─' if i == len(e.steps) - 1 else '├─'} {step}")
    for n in graph.notes:
        lines.append(f"\nnote: {n}")
    return "\n".join(lines)


__all__ = [
    "AclEscalation", "AttackGraph", "ReachableCredential", "UnreachableCredential",
    "annotate_live", "collapse_verdicts", "compose_paths", "escalate_via_acls", "format_graph",
]
