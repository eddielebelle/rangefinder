"""Privilege-escalation ACL edges parsed from captured nTSecurityDescriptors.

Builds real Windows security descriptors with impacket (the same format capture carries), encodes
them base64 into LDAP entries, and asserts analyze_acls extracts the BloodHound-style control edges —
resolving trustee SIDs, collapsing replication rights to DCSync, and excluding default-privileged
trustees (which are expected to hold control, not findings).
"""

import base64
import uuid

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACL, ACE,
    LDAP_SID, SR_SECURITY_DESCRIPTOR)

from rangefinder.acl import analyze_acls
from rangefinder.config.model import RangeConfig

_GENERIC_ALL = 0x10000000
_WRITE_DACL = 0x00040000
_WRITE_OWNER = 0x00080000
_WRITE_PROP = 0x00000020
_CONTROL_ACCESS = 0x00000100
_GC = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_GC_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
_FORCE_PW = "00299570-246d-11d0-a768-00aa006e0529"
_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"


def _sid(canon):
    s = LDAP_SID()
    s.fromCanonical(canon)
    return s


def _sid_b64(canon):
    return base64.b64encode(_sid(canon).getData()).decode()


def _allow(mask, trustee, flags=0):
    inner = ACCESS_ALLOWED_ACE()
    inner["Mask"] = ACCESS_MASK()
    inner["Mask"]["Mask"] = mask
    inner["Sid"] = _sid(trustee)
    ace = ACE()
    ace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = flags
    ace["Ace"] = inner
    return ace


def _allow_object(mask, trustee, guid, flags=0):
    inner = ACCESS_ALLOWED_OBJECT_ACE()
    inner["Mask"] = ACCESS_MASK()
    inner["Mask"]["Mask"] = mask
    inner["Flags"] = 1 if guid else 0  # ACE_OBJECT_TYPE_PRESENT
    inner["ObjectType"] = uuid.UUID(guid).bytes_le if guid else b""
    inner["InheritedObjectType"] = b""
    inner["Sid"] = _sid(trustee)
    ace = ACE()
    ace["AceType"] = ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    ace["AceFlags"] = flags
    ace["Ace"] = inner
    return ace


def _sd_b64(owner, aces):
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004  # SE_DACL_PRESENT | SE_SELF_RELATIVE
    sd["OwnerSid"] = _sid(owner)
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    dacl = ACL()
    dacl["AclRevision"] = 4
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = aces
    sd["Dacl"] = dacl
    return base64.b64encode(sd.getData()).decode()


def _entry(dn, sam, *, sid=None, owner="S-1-5-21-1-2-3-512", aces=None, sd=True):
    binary = {}
    if sid:
        binary["objectSid"] = [_sid_b64(sid)]
    if sd:
        binary["nTSecurityDescriptor"] = [_sd_b64(owner, aces or [])]
    return {"dn": dn, "attributes": {"sAMAccountName": [sam]}, "binary_attributes": binary}


def _cfg(entries):
    return RangeConfig.model_validate({
        "name": "e", "network": {"subnet": "10.0.0.0/24"},
        "hosts": [{"id": "dc", "hostname": "dc", "ip": "10.0.0.10",
                   "services": [{"type": "ldap", "port": 389, "entries": entries}]}]})


def _edges(report):
    return {(e.trustee, e.right, e.object_name) for e in report.edges}


def test_generic_all_edge_resolves_trustee():
    cfg = _cfg([
        _entry("CN=bob,DC=c,DC=l", "bob", aces=[_allow(_GENERIC_ALL, "S-1-5-21-1-2-3-1105")]),
        _entry("CN=alice,DC=c,DC=l", "alice", sid="S-1-5-21-1-2-3-1105", sd=False),
    ])
    assert ("alice", "GenericAll", "bob") in _edges(analyze_acls(cfg))


def test_writedacl_and_writeowner():
    cfg = _cfg([
        _entry("CN=grp,DC=c,DC=l", "grp",
               aces=[_allow(_WRITE_DACL | _WRITE_OWNER, "S-1-5-21-1-2-3-1200")]),
        _entry("CN=eve,DC=c,DC=l", "eve", sid="S-1-5-21-1-2-3-1200", sd=False),
    ])
    e = _edges(analyze_acls(cfg))
    assert ("eve", "WriteDacl", "grp") in e and ("eve", "WriteOwner", "grp") in e


def test_dcsync_needs_both_replication_rights():
    attacker = "S-1-5-21-1-2-3-1105"
    # both rights -> one DCSync edge
    both = _cfg([_entry("DC=c,DC=l", "CORP", aces=[
        _allow_object(_CONTROL_ACCESS, attacker, _GC),
        _allow_object(_CONTROL_ACCESS, attacker, _GC_ALL)])])
    rights = {(e.right) for e in analyze_acls(both).edges}
    assert "DCSync" in rights
    assert "GetChanges" not in rights and "GetChangesAll" not in rights  # collapsed, not leaked

    # only one replication right -> NOT DCSync (a half-right can't replicate secrets)
    half = _cfg([_entry("DC=c,DC=l", "CORP", aces=[_allow_object(_CONTROL_ACCESS, attacker, _GC)])])
    assert "DCSync" not in {e.right for e in analyze_acls(half).edges}


def test_force_change_password_and_add_member():
    cfg = _cfg([
        _entry("CN=u,DC=c,DC=l", "u", aces=[_allow_object(_CONTROL_ACCESS, "S-1-5-21-1-2-3-1300", _FORCE_PW)]),
        _entry("CN=g,DC=c,DC=l", "g", aces=[_allow_object(_WRITE_PROP, "S-1-5-21-1-2-3-1300", _MEMBER)]),
    ])
    e = {(x.right, x.object_name) for x in analyze_acls(cfg).edges}
    assert ("ForceChangePassword", "u") in e and ("AddMember", "g") in e


def test_default_privileged_trustee_is_not_a_finding():
    # Domain Admins (RID 512) holding GenericAll is expected, not an attack path -> no edge.
    cfg = _cfg([_entry("CN=bob,DC=c,DC=l", "bob", aces=[_allow(_GENERIC_ALL, "S-1-5-21-1-2-3-512")])])
    assert analyze_acls(cfg).edges == []


def test_ownership_by_nondefault_principal_is_an_edge():
    cfg = _cfg([
        _entry("CN=bob,DC=c,DC=l", "bob", owner="S-1-5-21-1-2-3-1400", aces=[]),
        _entry("CN=mallory,DC=c,DC=l", "mallory", sid="S-1-5-21-1-2-3-1400", sd=False),
    ])
    assert ("mallory", "Owns", "bob") in _edges(analyze_acls(cfg))


def test_unresolved_trustee_reported_as_raw_sid_not_invented():
    cfg = _cfg([_entry("CN=bob,DC=c,DC=l", "bob", aces=[_allow(_GENERIC_ALL, "S-1-5-21-9-9-9-1500")])])
    edges = analyze_acls(cfg).edges
    assert len(edges) == 1 and edges[0].trustee == "S-1-5-21-9-9-9-1500"


def test_malformed_descriptor_is_skipped_not_crashed():
    entry = {"dn": "CN=x,DC=c,DC=l", "attributes": {"cn": ["x"]},
             "binary_attributes": {"nTSecurityDescriptor": [base64.b64encode(b"\x01\x02garbage").decode()]}}
    report = analyze_acls(_cfg([entry]))
    assert report.edges == []  # unparseable SD yields no fabricated edges


# ------------------------------------------------- review regressions: no fabricated DCSync / inherit-only

_FULL_CONTROL = 0x000F01FF  # canonical on-disk "Full Control" mask: WriteDacl+WriteOwner+CONTROL_ACCESS, no GENERIC_ALL
_INHERIT_ONLY = 0x08
_INHERITED = 0x10
_ALL_EXT = 0x00000100  # CONTROL_ACCESS with no GUID = all extended rights


def test_full_control_on_ordinary_object_is_not_dcsync():
    # A Full-Control delegation over a USER carries the all-extended-rights bit, but DCSync only
    # exists on the domain object -> must NOT fabricate DCSync on bob.
    cfg = _cfg([
        _entry("CN=bob,DC=c,DC=l", "bob", aces=[_allow(_FULL_CONTROL, "S-1-5-21-1-2-3-1105")]),
        _entry("CN=alice,DC=c,DC=l", "alice", sid="S-1-5-21-1-2-3-1105", sd=False),
    ])
    rights = {e.right for e in analyze_acls(cfg).edges}
    assert "DCSync" not in rights                       # the fabricated critical is gone
    assert {"WriteDacl", "WriteOwner", "AllExtendedRights"} <= rights  # real control still reported


def test_all_extended_rights_on_domain_head_is_dcsync():
    # The SAME all-extended-rights ACE, but on the domain NC head, genuinely is DCSync.
    cfg = _cfg([_entry("DC=c,DC=l", "CORP", aces=[
        _allow_object(_ALL_EXT, "S-1-5-21-1-2-3-1105", None)])])
    assert "DCSync" in {e.right for e in analyze_acls(cfg).edges}


def test_inherit_only_ace_is_not_an_effective_edge():
    # An inherit-only GenericAll on an OU applies to children, not the OU itself -> no edge on the OU.
    cfg = _cfg([_entry("OU=staff,DC=c,DC=l", "staff",
                       aces=[_allow(_GENERIC_ALL, "S-1-5-21-1-2-3-1105", flags=_INHERIT_ONLY)])])
    assert analyze_acls(cfg).edges == []


def test_inherited_ace_is_still_effective():
    # An INHERITED (not inherit-only) ACE is the effective copy on the object -> still an edge.
    cfg = _cfg([_entry("CN=bob,DC=c,DC=l", "bob",
                       aces=[_allow(_GENERIC_ALL, "S-1-5-21-1-2-3-1105", flags=_INHERITED)])])
    assert ("S-1-5-21-1-2-3-1105", "GenericAll", "bob") in {
        (e.trustee_sid, e.right, e.object_name) for e in analyze_acls(cfg).edges}
