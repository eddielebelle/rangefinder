"""Identity-plane privilege-escalation edges from captured directory ACLs.

Credentialed LDAP capture (PR #21) carries each object's ``nTSecurityDescriptor`` — the owner and the
DACL whose ACEs decide who can do what to the object. Those ACEs are the edges BloodHound-style
tooling walks to find control paths: a non-privileged principal holding ``GenericAll`` / ``WriteDacl``
/ ``WriteOwner`` over a user or group, or ``DCSync`` over the domain, can escalate to owning it. This
module parses the captured descriptors into those control edges so ``rangefinder acl`` surfaces the
privilege-escalation surface the twin captured — the identity-plane counterpart to the credential
attack paths ``rangefinder paths`` composes.

Honesty, same contract as coherence/paths:

- **Measured, never fabricated.** An edge exists only because it is present in a *captured* security
  descriptor. Malformed / unreadable descriptors are skipped, not guessed. A trustee that resolves to
  a raw SID (no matching captured object) is reported as that SID, not invented into a name.
- **Signal over noise, not fail-open.** The always-privileged default trustees (Domain/Enterprise
  Admins, Administrators, SYSTEM, …) legitimately hold control over everything, so an edge from them
  is expected, not a finding — they are excluded. Everything else (a regular user/group with a
  control right) is surfaced. Excluding the expected is the safe direction: it can only *under*-report.

Uses impacket's ldaptypes (already a dependency) to parse the descriptor — no hand-rolled binary.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from rangefinder.config.model import RangeConfig

# Access-mask bits that confer control over the whole object (MS-ADTS / well-known ADS rights).
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_WRITE_DACL = 0x00040000
_WRITE_OWNER = 0x00080000
_WRITE_PROP = 0x00000020    # ADS_RIGHT_DS_WRITE_PROP
_CONTROL_ACCESS = 0x00000100  # ADS_RIGHT_DS_CONTROL_ACCESS (extended right)

# Extended-right / property GUIDs whose grant is a named attack primitive.
_GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"       # DS-Replication-Get-Changes
_GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes-All
_GUID_FORCE_CHANGE_PW = "00299570-246d-11d0-a768-00aa006e0529"   # User-Force-Change-Password
_GUID_WRITE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"      # writes 'member' -> AddMember

_ALLOW_TYPES = {0, 5}  # ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE (deny/audit ACEs are not grants)

# Trustees that are *expected* to hold control everywhere — an edge from them is not a finding.
_BENIGN_SIDS = {
    "S-1-5-18",        # LOCAL SYSTEM
    "S-1-5-9",         # Enterprise Domain Controllers
    "S-1-5-10",        # SELF (the object over itself)
    "S-1-3-0",         # Creator Owner
    "S-1-5-32-544",    # BUILTIN\Administrators
    "S-1-5-32-548",    # Account Operators
    "S-1-5-32-549",    # Server Operators
    "S-1-5-32-550",    # Print Operators
    "S-1-5-32-551",    # Backup Operators
}
# Domain RIDs of always-privileged groups/accounts (SID ends with -<RID>).
_BENIGN_RIDS = {"500", "512", "516", "517", "518", "519", "520"}

_WELLKNOWN_NAMES = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-7": "Anonymous",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
}


@dataclass
class AclEdge:
    trustee: str        # resolved principal name / DN, or raw SID if unresolved
    trustee_sid: str
    right: str          # GenericAll | GenericWrite | WriteDacl | WriteOwner | Owns | DCSync | ...
    object_name: str    # target object's readable name
    object_dn: str


@dataclass
class AclReport:
    edges: list[AclEdge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    entries_with_sd: int = 0

    @property
    def has_findings(self) -> bool:
        return bool(self.edges)


def _canonical_sid(raw: bytes) -> str | None:
    from impacket.ldap.ldaptypes import LDAP_SID

    try:
        return LDAP_SID(data=raw).formatCanonical()
    except Exception:
        return None


def _bin_attr(entry, name: str) -> list[bytes]:
    """Decode an entry's base64 binary attribute (case-insensitive), skipping corrupt values."""
    out: list[bytes] = []
    for k, vals in entry.binary_attributes.items():
        if k.lower() == name.lower():
            for v in vals:
                try:
                    out.append(base64.b64decode(v, validate=True))
                except Exception:
                    continue
    return out


def _entry_label(entry) -> str:
    for attr in ("sAMAccountName", "cn", "name"):
        for k, vals in entry.attributes.items():
            if k.lower() == attr.lower() and vals:
                return str(vals[0])
    return entry.dn or "(RootDSE)"


def _norm_dn(dn: str) -> str:
    return ",".join(p.strip().lower() for p in dn.split(","))


def _domain_ncs(cfg: RangeConfig) -> set:
    """DNs that are a domain naming-context head — the only objects on which replication rights mean
    DCSync. Taken from the configured base DN(s) plus the shortest all-DC entry DN (the domain root).
    Gating DCSync to these is what stops a Full-Control ACE on an ordinary user/OU (which carries the
    all-extended-rights bit) from fabricating a domain-compromise finding."""
    ncs: set = set()
    if cfg.identities:
        ncs.add(_norm_dn(cfg.identities.base_dn))
    all_dc: list[str] = []
    for host in cfg.hosts:
        for svc in host.services:
            if svc.type != "ldap":
                continue
            if svc.base_dn:
                ncs.add(_norm_dn(svc.base_dn))
            for e in svc.entries:
                if e.dn and all(r.strip().lower().startswith("dc=") for r in e.dn.split(",")):
                    all_dc.append(e.dn)
    if all_dc:
        ncs.add(_norm_dn(min(all_dc, key=lambda d: d.count(","))))  # shortest all-DC = domain head
    return ncs


def _sid_map(cfg: RangeConfig) -> dict:
    """objectSid (canonical) -> (dn, readable label) for every captured entry that carries one."""
    out: dict = {}
    for host in cfg.hosts:
        for svc in host.services:
            if svc.type != "ldap":
                continue
            for entry in svc.entries:
                for raw in _bin_attr(entry, "objectSid"):
                    sid = _canonical_sid(raw)
                    if sid:
                        out[sid] = (entry.dn, _entry_label(entry))
    return out


def _resolve(sid: str, sid_map: dict) -> str:
    if sid in sid_map:
        return sid_map[sid][1]
    return _WELLKNOWN_NAMES.get(sid, sid)


def _is_benign(sid: str) -> bool:
    if sid in _BENIGN_SIDS:
        return True
    return sid.rsplit("-", 1)[-1] in _BENIGN_RIDS if sid.startswith("S-1-5-21-") else False


def _parse_aces(blob: bytes):
    """Yield ``(ace_type, mask, trustee_sid, object_type_guid|None)`` for each allow ACE in the DACL,
    plus the owner SID. Returns (owner_sid_or_None, list_of_aces). Robust: a descriptor that does not
    parse yields no ACEs rather than raising."""
    import uuid

    from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, SR_SECURITY_DESCRIPTOR

    try:
        sd = SR_SECURITY_DESCRIPTOR(data=blob)
    except Exception:
        return None, []
    owner = None
    try:
        if sd["OwnerSid"]:
            owner = sd["OwnerSid"].formatCanonical()
    except Exception:
        owner = None
    aces = []
    dacl = sd["Dacl"]
    if not dacl:
        return owner, aces
    for ace in getattr(dacl, "aces", []):
        try:
            # INHERIT_ONLY_ACE (0x08) does not apply to this object — it only propagates to
            # descendants (whose own DACLs carry the effective, INHERITED_ACE copies). Emitting it
            # would fabricate a control edge on the container itself.
            if ace["AceFlags"] & 0x08:
                continue
            atype = ace["AceType"]
            if atype not in _ALLOW_TYPES:
                continue
            inner = ace["Ace"]
            mask = inner["Mask"]["Mask"]
            trustee = inner["Sid"].formatCanonical()
            guid = None
            if atype == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and inner["ObjectType"]:
                guid = str(uuid.UUID(bytes_le=inner["ObjectType"])).lower()
            aces.append((atype, mask, trustee, guid))
        except Exception:
            continue
    return owner, aces


def _rights_for(mask: int, guid: str | None) -> list[str]:
    """The named control primitives a single ACE grants (a mask can carry several)."""
    rights: list[str] = []
    if mask & _GENERIC_ALL:
        rights.append("GenericAll")
    if mask & _WRITE_DACL:
        rights.append("WriteDacl")
    if mask & _WRITE_OWNER:
        rights.append("WriteOwner")
    if mask & _GENERIC_WRITE:
        rights.append("GenericWrite")
    # Object ACEs: an extended/property right scoped to a GUID (or unscoped = all rights of that
    # class). The two replication rights are tracked distinctly — DCSync needs BOTH.
    if mask & _CONTROL_ACCESS:
        if guid == _GUID_FORCE_CHANGE_PW:
            rights.append("ForceChangePassword")
        elif guid == _GUID_GET_CHANGES:
            rights.append("GetChanges")
        elif guid == _GUID_GET_CHANGES_ALL:
            rights.append("GetChangesAll")
        elif guid is None:
            rights.append("AllExtendedRights")
    if mask & _WRITE_PROP and guid == _GUID_WRITE_MEMBER:
        rights.append("AddMember")
    return rights


def analyze_acls(cfg: RangeConfig) -> AclReport:
    """Parse captured nTSecurityDescriptors into privilege-escalation control edges."""
    report = AclReport()
    sid_map = _sid_map(cfg)
    domain_ncs = _domain_ncs(cfg)

    for host in cfg.hosts:
        for svc in host.services:
            if svc.type != "ldap":
                continue
            for entry in svc.entries:
                sds = _bin_attr(entry, "nTSecurityDescriptor")
                if not sds:
                    continue
                report.entries_with_sd += 1
                obj_name = _entry_label(entry)
                owner, aces = _parse_aces(sds[0])
                # Ownership is itself a control primitive (owner can rewrite the DACL).
                if owner and not _is_benign(owner):
                    report.edges.append(AclEdge(
                        _resolve(owner, sid_map), owner, "Owns", obj_name, entry.dn))
                # Accumulate the replication rights per trustee; DCSync is emitted only when a
                # trustee holds BOTH Get-Changes and Get-Changes-All (or all-extended-rights) —
                # exactly what a DCSync attack requires — instead of one edge per half-right.
                repl: dict = {}
                for _atype, mask, trustee, guid in aces:
                    if _is_benign(trustee):
                        continue
                    for right in _rights_for(mask, guid):
                        if right in ("GetChanges", "GetChangesAll", "AllExtendedRights"):
                            repl.setdefault(trustee, set()).add(right)
                            continue
                        report.edges.append(AclEdge(
                            _resolve(trustee, sid_map), trustee, right, obj_name, entry.dn))
                is_domain = _norm_dn(entry.dn) in domain_ncs
                for trustee, got in repl.items():
                    # Replication rights (or all-extended-rights) mean DCSync ONLY on the domain
                    # naming-context head. Elsewhere, all-extended-rights is still real control over
                    # that object (e.g. ForceChangePassword on a user), but it is NOT DCSync.
                    has_repl = "AllExtendedRights" in got or {"GetChanges", "GetChangesAll"} <= got
                    if is_domain and has_repl:
                        right = "DCSync"
                    elif "AllExtendedRights" in got:
                        right = "AllExtendedRights"
                    else:
                        continue  # a lone half replication right off-domain is not exploitable
                    report.edges.append(AclEdge(
                        _resolve(trustee, sid_map), trustee, right, obj_name, entry.dn))

    if not sid_map and report.entries_with_sd:
        report.warnings.append(
            "no objectSid captured, so ACE trustees resolve to raw SIDs — re-capture with binary "
            "attributes to name principals")
    return report


def format_acl_report(report: AclReport) -> str:
    if not report.edges:
        if report.entries_with_sd:
            return (f"no privilege-escalation ACLs found ({report.entries_with_sd} descriptor(s) "
                    "parsed; only default-privileged trustees hold control)")
        return "no nTSecurityDescriptor captured — re-capture LDAP with credentials to analyse ACLs"
    lines = [f"Privilege-escalation ACL edges ({len(report.edges)}) — non-default principals with "
             "control over an object:"]
    by_trustee: dict = {}
    for e in report.edges:
        by_trustee.setdefault(e.trustee, []).append(e)
    for trustee in sorted(by_trustee):
        lines.append(f"\n  ‣ {trustee}")
        for e in sorted(by_trustee[trustee], key=lambda x: (x.right, x.object_name)):
            lines.append(f"      └─ {e.right} → {e.object_name}  ({e.object_dn})")
    for w in report.warnings:
        lines.append(f"\n⚠ {w}")
    return "\n".join(lines)


def entry_label(entry) -> str:
    """Public alias — the readable name (sAMAccountName/cn) other modules use to match principals."""
    return _entry_label(entry)


def norm_dn(dn: str) -> str:
    return _norm_dn(dn)


__all__ = ["AclEdge", "AclReport", "analyze_acls", "entry_label", "format_acl_report", "norm_dn"]
