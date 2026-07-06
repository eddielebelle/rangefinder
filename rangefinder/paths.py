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
    hops: int                  # number of authenticate-and-loot rounds (0 = anonymously readable)


@dataclass
class UnreachableCredential:
    secret_id: str
    usernames: list[str]
    grants: list[str]
    reason: str


@dataclass
class AttackGraph:
    reachable: list[ReachableCredential] = field(default_factory=list)
    unreachable: list[UnreachableCredential] = field(default_factory=list)
    hosts_reached: list[str] = field(default_factory=list)   # hosts an anon-rooted path can access
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
            # hops = number of authentication pivots (0 = recovered from anonymously-readable text).
            graph.reachable.append(ReachableCredential(
                secret_id=sid, usernames=usernames, grants=grants,
                steps=steps, hops=sum(1 for s in steps if s.startswith("authenticate to "))))
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


def format_graph(graph: AttackGraph) -> str:
    lines: list[str] = []
    if graph.reachable:
        lines.append(f"Reachable credentials ({len(graph.reachable)}) — advisory paths, confirm with `verify estate`:")
        for r in graph.reachable:
            names = ", ".join(r.usernames)
            lines.append(f"\n  ‣ {names} [{r.secret_id}]  ({r.hops}-hop)  unlocks: {', '.join(r.grants)}")
            for i, step in enumerate(r.steps):
                lines.append(f"      {'└─' if i == len(r.steps) - 1 else '├─'} {step}")
    else:
        lines.append("No credentials are reachable from an anonymous start.")
    if graph.unreachable:
        lines.append(f"\nDeclared but not anonymously reachable ({len(graph.unreachable)}) — need a foothold:")
        for u in graph.unreachable:
            lines.append(f"  · {', '.join(u.usernames)} [{u.secret_id}]  unlocks: {', '.join(u.grants)}")
    for n in graph.notes:
        lines.append(f"\nnote: {n}")
    return "\n".join(lines)


__all__ = [
    "AttackGraph", "ReachableCredential", "UnreachableCredential",
    "compose_paths", "format_graph",
]
